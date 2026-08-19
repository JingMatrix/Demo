// Native isolated probe (android:nativeService). On Android 17 this is forked by
// zygote_next and runs in init's GLOBAL mount namespace, so its own
// /proc/self/mountinfo still lists module mounts. We scan the WHOLE rendered line
// (root/source/options included, not just the mountpoint) for a wide marker set,
// emit a compact JSON document over the AIDL getResult() transaction, and log
// everything to logcat under tag "DemoProbe".
//
// No ART here: libc + dlsym'd log/binder only. Binder plumbing mirrors the classic
// ZygoteNextProbe: dlsym libbinder_ndk, define a class, answer getResult (code 1).

#include <ctype.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "recon.hpp"

#define LOG_TAG "DemoProbe"
#define STATUS_OK 0

typedef void (*log_print_fn)(int, const char*, const char*, ...);
static log_print_fn g_log_print = NULL;
static char* g_report = NULL;      // JSON, heap
static size_t g_report_len = 0;

static void logmsg(const char* fmt, ...) {
    if (!g_log_print) return;
    va_list ap;
    va_start(ap, fmt);
    char buf[2048];
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    g_log_print(6 /* INFO */, LOG_TAG, "%s", buf);
}

// ---- wide marker catalogue (needle, label, confidence, wordBoundary) ----
// wordBoundary avoids false positives like "sui" inside "nosuid" or "ksu" inside
// a random token; short alpha needles must set it.
struct Marker { const char* needle; const char* label; int confidence; bool wb; };
static const Marker MARKERS[] = {
    {"/data/adb", "data/adb", 3, false}, {"/adb/", "adb", 3, false},
    {"kernelsu", "KernelSU", 3, false}, {"ksud", "ksud", 3, false},
    {"magisk", "Magisk", 3, false}, {"zygisk", "Zygisk", 3, false},
    {"susfs", "susfs", 3, false}, {"/debug_ramdisk", "debug_ramdisk", 3, false},
    {"meta-overlayfs", "meta-overlayfs", 3, false}, {"apatch", "APatch", 3, false},
    {"sui", "Sui", 2, true}, {"riru", "Riru", 2, true}, {"lsp", "LSP", 2, true},
    // Dropped worker/lowerdir/upperdir/data_mirror at MEDIUM: the overlay option
    // words ride on every stock overlayfs mount and /data_mirror is a stock AOSP
    // tree (installd CE/DE + profile mirrors), so at conf 2 they only produced
    // benign LEAK lines on clean devices. A module overlay is still caught by
    // "/data/adb" in its lowerdir value (conf 3) and by meta-overlayfs/magisk/etc.
    {"overlay", "overlay", 1, false}, {"/dev/block/loop", "loop-dev", 1, false},
    {"tmpfs", "tmpfs", 1, false},
};
static const int MARKER_COUNT = sizeof(MARKERS) / sizeof(MARKERS[0]);

static bool is_word(int c) { return isalnum(c) || c == '_'; }

static bool ci_contains(const char* hay, const char* needle, bool wb) {
    if (!*needle) return true;
    size_t nlen = strlen(needle);
    for (const char* start = hay; *start; start++) {
        const char* h = start;
        const char* n = needle;
        while (*h && *n && tolower((unsigned char)*h) == tolower((unsigned char)*n)) { h++; n++; }
        if (!*n) {
            if (!wb) return true;
            bool sb = start == hay || !is_word((unsigned char)start[-1]);
            bool eb = !is_word((unsigned char)start[nlen]);
            if (sb && eb) return true;
        }
    }
    return false;
}

static char* read_all(const char* path, size_t* out_len) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return NULL;
    size_t cap = 65536, total = 0;
    char* data = (char*)malloc(cap);
    if (!data) { close(fd); return NULL; }
    for (;;) {
        if (total + 16384 >= cap) {
            cap *= 2;
            char* bigger = (char*)realloc(data, cap);
            if (!bigger) { free(data); close(fd); return NULL; }
            data = bigger;
        }
        ssize_t n = read(fd, data + total, cap - 1 - total);
        if (n <= 0) break;
        total += (size_t)n;
    }
    close(fd);
    data[total] = '\0';
    if (out_len) *out_len = total;
    return data;
}

static uint64_t read_ns_inode(const char* path) {
    char buf[256];
    ssize_t n = readlink(path, buf, sizeof(buf) - 1);
    if (n <= 0) return 0;
    buf[n] = '\0';
    char* b = strrchr(buf, '[');
    return b ? strtoull(b + 1, NULL, 10) : 0;
}

// root-mount propagation token from /proc/self/mountinfo
static void root_propagation(char* out, size_t out_size) {
    out[0] = '\0';
    size_t len = 0;
    char* buf = read_all("/proc/self/mountinfo", &len);
    if (!buf) return;
    char* save;
    for (char* line = strtok_r(buf, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
        char* sep = strstr(line, " - ");
        if (!sep) continue;
        *sep = '\0';
        int field = 1; bool is_root = false;
        char* s;
        for (char* tok = strtok_r(line, " ", &s); tok; tok = strtok_r(NULL, " ", &s), field++) {
            if (field == 5) is_root = (strcmp(tok, "/") == 0);
            else if (is_root && field >= 7 &&
                     (strncmp(tok, "shared:", 7) == 0 || strncmp(tok, "master:", 7) == 0)) {
                strncpy(out, tok, out_size - 1);
                out[out_size - 1] = '\0';
            }
        }
        if (is_root) break;
    }
    free(buf);
}

// JSON string escaping into a fixed buffer
static void json_escape(const char* in, char* out, size_t out_size) {
    size_t o = 0;
    for (const char* p = in; *p && o + 2 < out_size; p++) {
        char c = *p;
        if (c == '"' || c == '\\') { out[o++] = '\\'; out[o++] = c; }
        else if (c == '\n') { out[o++] = '\\'; out[o++] = 'n'; }
        else if (c == '\t') { out[o++] = ' '; }
        else if ((unsigned char)c < 0x20) { out[o++] = ' '; }
        else out[o++] = c;
    }
    out[o] = '\0';
}

static void run_probe(void) {
    pid_t pid = getpid();
    uid_t uid = getuid();
    uint64_t ns = read_ns_inode("/proc/self/ns/mnt");
    char prop[64];
    root_propagation(prop, sizeof(prop));

    logmsg("==================== NATIVE PROBE (zygote_next) ====================");
    logmsg("pid=%d uid=%d nsMnt=%" PRIu64 " rootPropagation=%s", pid, uid, ns, prop);
    logmsg("propagation classification: %s",
           strncmp(prop, "shared:", 7) == 0 ? "shared => init GLOBAL view (zygote_next signature)"
           : strncmp(prop, "master:", 7) == 0 ? "master => private slave ns (classic zygote)"
           : "unclassified");

    size_t cap = 262144;
    g_report = (char*)malloc(cap);
    if (!g_report) return;
    size_t o = 0;
    o += snprintf(g_report + o, cap - o,
                  "{\"technique\":\"native-zygote_next\",\"self\":{\"pid\":%d,\"uid\":%d,"
                  "\"isolated\":true,\"nsMnt\":%" PRIu64 ",\"selfPropagation\":\"%s\"},",
                  pid, uid, ns, prop);

    // scan /proc/self/mountinfo, full lines
    size_t len = 0;
    char* buf = read_all("/proc/self/mountinfo", &len);
    o += snprintf(g_report + o, cap - o, "\"markerHits\":[");
    int total_lines = 0, hit_lines = 0, high_hits = 0;
    bool first_hit = true;

    if (buf) {
        char* save;
        for (char* line = strtok_r(buf, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
            total_lines++;
            char labels[256] = "";
            int line_high = 0;
            int line_conf = 0;
            for (int i = 0; i < MARKER_COUNT; i++) {
                if (ci_contains(line, MARKERS[i].needle, MARKERS[i].wb)) {
                    if (labels[0]) strncat(labels, "+", sizeof(labels) - strlen(labels) - 1);
                    strncat(labels, MARKERS[i].label, sizeof(labels) - strlen(labels) - 1);
                    if (MARKERS[i].confidence > line_conf) line_conf = MARKERS[i].confidence;
                    if (MARKERS[i].confidence >= 3) { high_hits++; line_high++; }
                }
            }
            // only surface MEDIUM+ lines; LOW-only (tmpfs/overlay/loop on stock) is counted but not logged
            if (labels[0] && line_conf >= 2) {
                hit_lines++;
                logmsg("  LEAK [%s] %s", labels, line);
                char esc[1024];
                json_escape(line, esc, sizeof(esc));
                char lab[256];
                json_escape(labels, lab, sizeof(lab));
                if (o + strlen(esc) + strlen(lab) + 64 < cap) {
                    o += snprintf(g_report + o, cap - o, "%s{\"labels\":\"%s\",\"high\":%d,\"line\":\"%s\"}",
                                  first_hit ? "" : ",", lab, line_high, esc);
                    first_hit = false;
                }
            }
        }
        free(buf);
    }
    o += snprintf(g_report + o, cap - o, "],");

    o += snprintf(g_report + o, cap - o,
                  "\"stats\":{\"mountinfoLines\":%d,\"markerLines\":%d,\"highHits\":%d},",
                  total_lines, hit_lines, high_hits);

    // include the full (bounded) mountinfo for display
    char* full = read_all("/proc/self/mountinfo", &len);
    o += snprintf(g_report + o, cap - o, "\"mountinfo\":[");
    if (full) {
        char* save;
        bool first = true;
        int emitted = 0;
        for (char* line = strtok_r(full, "\n", &save); line && emitted < 400;
             line = strtok_r(NULL, "\n", &save), emitted++) {
            char esc[1024];
            json_escape(line, esc, sizeof(esc));
            if (o + strlen(esc) + 8 >= cap) break;
            o += snprintf(g_report + o, cap - o, "%s\"%s\"", first ? "" : ",", esc);
            first = false;
        }
        free(full);
    }
    o += snprintf(g_report + o, cap - o, "],");

    // Mount reconciliation: kernel stat ground truth vs mountinfo text. Survives
    // kernel-side mountinfo filtering, so it fires even when every marker line was
    // erased from this process's view.
    char recon_json[8192];
    int recon_findings = recon_run_json(recon_json, sizeof(recon_json));
    o += snprintf(g_report + o, cap - o, "\"reconcile\":%s,", recon_json);

    // Verdict combines the module markers with the reconciliation (hidden mounts AND
    // structural anomalies). shared:N propagation stays informational: a native
    // zygote_next child is forked without CLONE_NEWNS on STOCK Android 17 too, so
    // "shared:1" is expected here and hiding it would be the real anomaly.
    bool detected = high_hits > 0 || recon_findings > 0;
    bool global_view = strncmp(prop, "shared:", 7) == 0;
    o += snprintf(g_report + o, cap - o,
                  "\"verdict\":{\"detected\":%s,\"highHits\":%d,\"reconFindings\":%d,"
                  "\"propagation\":\"%s\",\"globalViewSignature\":%s}}",
                  detected ? "true" : "false", high_hits, recon_findings, prop,
                  global_view ? "true" : "false");

    g_report_len = o;
    logmsg("native verdict: detected=%s highHits=%d lines=%d json=%zuB",
           detected ? "true" : "false", high_hits, total_lines, g_report_len);
    logmsg("==================== NATIVE PROBE END ====================");
}

// ---- libbinder_ndk (dlsym'd) ----
typedef struct AIBinder_Class AIBinder_Class;
typedef struct AIBinder AIBinder;
typedef struct AParcel AParcel;
typedef void (*oncreate_fn)(void*);
typedef void (*ondestroy_fn)(void*);
typedef int (*ontransact_fn)(AIBinder*, uint32_t, const AParcel*, AParcel*);
typedef AIBinder_Class* (*class_define_fn)(const char*, oncreate_fn, ondestroy_fn, ontransact_fn);
typedef AIBinder* (*aibinder_new_fn)(const AIBinder_Class*, void*);
typedef int (*write_string_fn)(AParcel*, const char*, uint32_t);
typedef int (*write_int32_fn)(AParcel*, int32_t);

static class_define_fn g_class_define;
static aibinder_new_fn g_aibinder_new;
static write_string_fn g_write_string;
static write_int32_fn g_write_int32;
static const AIBinder_Class* g_class;

static void cls_create(void* a) { (void)a; }
static void cls_destroy(void* a) { (void)a; }

static int cls_transact(AIBinder* b, uint32_t code, const AParcel* in, AParcel* out) {
    (void)b; (void)in;
    if (code == 1 && g_write_string && g_write_int32 && g_report) {
        if (g_write_int32(out, STATUS_OK) != STATUS_OK) return -22;
        int rc = g_write_string(out, g_report, (uint32_t)g_report_len);
        return rc == STATUS_OK ? STATUS_OK : -22;
    }
    return -2;
}

static void resolve_binder(void) {
    void* dl = dlopen("libbinder_ndk.so", RTLD_NOW);
    if (!dl) { logmsg("dlopen libbinder_ndk failed"); return; }
    g_class_define = (class_define_fn)dlsym(dl, "AIBinder_Class_define");
    g_aibinder_new = (aibinder_new_fn)dlsym(dl, "AIBinder_new");
    g_write_string = (write_string_fn)dlsym(dl, "AParcel_writeString");
    g_write_int32 = (write_int32_fn)dlsym(dl, "AParcel_writeInt32");
    if (g_class_define) {
        g_class = g_class_define("org.matrix.demo.IDemoProbeService",
                                 cls_create, cls_destroy, cls_transact);
    }
}

static AIBinder* onbind(void* s, uint64_t t, const char* a, const char* d) {
    (void)s; (void)t; (void)a; (void)d;
    if (g_aibinder_new && g_class) return g_aibinder_new(g_class, NULL);
    return NULL;
}

extern "C" __attribute__((visibility("default"))) void ANativeService_onCreate(void* service) {
    void* dl = dlopen("liblog.so", RTLD_NOW);
    if (dl) g_log_print = (log_print_fn)dlsym(dl, "__android_log_print");
    resolve_binder();
    run_probe();
    void* android = dlopen("libandroid.so", RTLD_NOW);
    if (android) {
        void* set_bind = dlsym(android, "ANativeService_setOnBindCallback");
        if (set_bind) ((void (*)(void*, void*))set_bind)(service, (void*)&onbind);
    }
}
