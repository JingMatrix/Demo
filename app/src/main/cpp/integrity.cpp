// Integrity detections (injection + mount tamper) that run in the app's MAIN process
// and report each check as JSON, so MainActivity can render them alongside the
// isolated-process mount probes.

#include "atexit.hpp"
#include "dlphdr.hpp"
#include "logging.h"
#include "mount.hpp"
#include "recon.hpp"
#include "solist.hpp"
#include "statfs.hpp"
#include "vmap.hpp"

#include <jni.h>
#include <string>
#include <vector>

static std::string jesc(const std::string &in) {
    std::string o;
    for (char c : in) {
        switch (c) {
        case '"':
            o += "\\\"";
            break;
        case '\\':
            o += "\\\\";
            break;
        case '\n':
            o += "\\n";
            break;
        default:
            if ((unsigned char)c < 0x20)
                o += ' ';
            else
                o += c;
        }
    }
    return o;
}

// type is the detection family: "injection" (linker solist / process memory) or
// "mount" (mount-namespace tampering). The dashboard groups checks by it.
static void add(std::string &arr, bool &first, const char *type, const char *name, bool detected, const std::string &detail) {
    LOGI("[%s] %s: %s", detected ? "DETECTED" : "clean", name, detail.c_str());
    if (!first)
        arr += ",";
    first = false;
    arr += "{\"type\":\"";
    arr += type;
    arr += "\",\"name\":\"";
    arr += name;
    arr += "\",\"detected\":";
    arr += detected ? "true" : "false";
    arr += ",\"detail\":\"";
    arr += jesc(detail);
    arr += "\"}";
}

extern "C" JNIEXPORT jstring JNICALL Java_org_matrix_demo_MainActivity_runIntegrityChecks(JNIEnv *env, jobject) {
    logging::capture().clear();

    std::string arr;
    bool first = true;
    bool any = false;

    // 1. injected shared library, found by walking the linker's solist. This is the
    //    only check that can name the library: it reads the soname and realpath the
    //    linker itself recorded, which /proc/self/maps does not carry.
    std::vector<SoList::Finding> sos = SoList::DetectAll();
    if (!sos.empty()) {
        any = true;
        std::string d = sos.front().info->get_name();
        if (d.empty())
            d = "<unnamed>";
        d += " -- " + sos.front().reason;
        if (sos.size() > 1)
            d += " (+" + std::to_string(sos.size() - 1) + " more)";
        add(arr, first, "injection", "Solist injection", true, d);
    } else {
        add(arr, first, "injection", "Solist injection", false,
            "every library in the linker's list has a real path on disk");
    }

    // 2. anonymous executable mapping shadowing a file (from /proc/self/maps)
    VirtualMap::MapInfo *vm = VirtualMap::DetectInjection();
    if (vm) {
        any = true;
        add(arr, first, "injection", "Virtual-map injection", true, vm->path);
    } else {
        add(arr, first, "injection", "Virtual-map injection", false, "no anonymous exec mapping over a file");
    }

    // 3. g_module_unload_counter. Informational only, never a verdict: a stock
    //    Pixel 7 on Android 17 reports 7 here because zygote genuinely unloads that
    //    many libraries during preload, and Samsung and OnePlus are worse. The
    //    number becomes evidence only once it is cross-checked against the
    //    allocator's free list, which is what "Soinfo block gaps" below does.
    size_t mods = SoList::DetectModules();
    add(arr, first, "injection", "Module counter", false,
        std::to_string(mods) +
            " library unload(s) recorded by the linker -- a count alone proves nothing; see Soinfo block gaps");

    // 4. linker state reached through dl_iterate_phdr only -- no /linker symbol
    //    table, no guessed soinfo offsets, so these hold on every Android release.
    //    (a) the accounting identity between the enumerated objects and the
    //    linker's own load/unload counters, plus the second opinion the r_debug
    //    link_map chain gives on the same list;
    //    (b) holes and recycled blocks in the fixed-stride soinfo allocation, the
    //    trace an unlinked library leaves behind;
    //    (c) whether the ledger still tracks a live load we perform ourselves;
    //    (d) executable pages the linker vouches for versus what is really mapped.
    DlPhdr::Result dp = DlPhdr::Run();

    bool ledger_bad = dp.ledger < 0 || dp.chainMismatch != 0 || dp.unmatched != 0;
    if (ledger_bad)
        any = true;
    add(arr, first, "injection", "Linker ledger", ledger_bad,
        dp.countersValid
            ? std::to_string(dp.entries) + " object(s), link_map chain " +
                  std::to_string(dp.chainLength) + ", dlpi_adds-dlpi_subs " +
                  std::to_string((long long)(dp.adds - dp.subs)) +
                  (ledger_bad ? " -- the linker's own accounting does not add up"
                              : " -- all three agree")
            : "dlpi_adds/dlpi_subs unavailable on this platform");

    bool gaps_bad = dp.unaccountedFrees > 0;
    if (gaps_bad)
        any = true;
    if (dp.stride == 0) {
        add(arr, first, "injection", "Soinfo block gaps", false,
            dp.chainAvailable ? "too few objects to resolve the allocator stride"
                              : "DT_DEBUG unavailable, link_map chain not reachable");
    } else {
        std::string d = std::to_string(dp.blocksCovered) + " block(s) at stride " +
                        std::to_string(dp.stride) + ": " + std::to_string(dp.freeBlocks) +
                        " on the free list in " + std::to_string(dp.gapRuns) + " hole(s), " +
                        std::to_string(dp.inversions) + " reclaimed out of load order, against " +
                        std::to_string((unsigned long long)dp.subs) + " unload(s) the linker admits";
        d += gaps_bad ? " -- " + std::to_string(dp.unaccountedFrees) +
                            " freed block(s) the unload counter does not account for"
                      : (dp.unloadTrace() ? " -- consistent, every freed block is accounted for"
                                          : " -- the allocation sequence is unbroken");
        add(arr, first, "injection", "Soinfo block gaps", gaps_bad, d);
    }

    if (dp.calibFailed)
        any = true;
    add(arr, first, "injection", "Ledger calibration", dp.calibFailed, dp.calibNote);

    int space_bad = dp.ghostExec + dp.anonBacked + dp.extentHoles + dp.phdrMismatch + dp.badName;
    if (space_bad > 0)
        any = true;
    add(arr, first, "injection", "Unclaimed executable pages", space_bad > 0,
        (space_bad > 0 ? std::to_string(dp.ghostExec) + " private anonymous exec mapping(s), " +
                             std::to_string(dp.anonBacked) + " anonymous text, " +
                             std::to_string(dp.extentHoles) + " hole(s) in a reservation, " +
                             std::to_string(dp.phdrMismatch) + " phdr mismatch(es), " +
                             std::to_string(dp.badName) + " bad name(s)"
                       : "no private anonymous executable memory outside the linker's objects") +
            "; " + std::to_string(dp.foreignExec) +
            " executable mapping(s) outside them are file-backed or shared, which is what "
            "the runtime's oat files and code caches look like");

    // 5. whether this sandbox even permits executable memory the linker never saw.
    //    Informational: it is what decides how much the check above proves.
    add(arr, first, "injection", "Executable memory policy", false, dp.execMemory);

    // 6. libc atexit array state (informational integrity signal)
    Atexit::AtexitArray *g = Atexit::findAtexitArray();
    add(arr, first, "injection", "libc atexit array", false, g ? g->format_state_string() : "unavailable");

    // 7. /system remounted by a module (overlay over the real partition)
    std::string fs = get_filesystem_type("/system/bin");
    bool fs_bad = fs == "OverlayFS";
    if (fs_bad)
        any = true;
    add(arr, first, "mount", "/system filesystem", fs_bad, "/system/bin on " + fs);

    // 8. injected bind mounts visible in this process's mountinfo (heuristic,
    //    secondary: defeated by kernel-side mountinfo filtering, kept for roots
    //    that do not hide).
    std::vector<Mount::MountInfo> ms = Mount::DetectInjection();
    if (!ms.empty()) {
        any = true;
        add(arr, first, "mount", "Mountinfo injection", true, ms[0].target);
    } else {
        add(arr, first, "mount", "Mountinfo injection", false, "no injected bind mounts in mountinfo");
    }

    // 9. mount reconciliation: kernel stat ground truth vs mountinfo text. This is
    //    the authoritative mount check -- statx/statfs are not on the seq_file path
    //    a hider hooks, so mounts erased from mountinfo still show up here.
    Recon::Result rc = Recon::Run();
    if (rc.hidden > 0) {
        any = true;
        add(arr, first, "mount", "Mount reconciliation", true,
            std::to_string(rc.hidden) + " mount(s) hidden from mountinfo but confirmed by the kernel");
    } else {
        add(arr, first, "mount", "Mount reconciliation", false, "mountinfo matches kernel stat ground truth");
    }
    if (rc.structural > 0) {
        any = true;
        add(arr, first, "mount", "Mount structure", true,
            std::to_string(rc.structural) + " tree anomaly(ies): orphaned mount or peer-group gap from an erased record");
    } else {
        add(arr, first, "mount", "Mount structure", false, "mountinfo tree and peer groups are internally consistent");
    }

    // raw toolkit log captured during the checks -> "log" array
    std::string logJson;
    bool lf = true;
    const std::string &cap = logging::capture();
    for (size_t start = 0; start < cap.size();) {
        size_t nl = cap.find('\n', start);
        if (nl == std::string::npos)
            nl = cap.size();
        std::string line = cap.substr(start, nl - start);
        if (!line.empty()) {
            if (!lf)
                logJson += ",";
            lf = false;
            logJson += "\"" + jesc(line) + "\"";
        }
        start = nl + 1;
    }

    std::string json = "{\"technique\":\"native-integrity\",\"checks\":[" + arr +
                       "],\"dlphdr\":" + dp.json + ",\"reconcile\":" + rc.json + ",\"log\":[" + logJson +
                       "],\"verdict\":{\"detected\":" + (any ? "true" : "false") + "}}";
    return env->NewStringUTF(json.c_str());
}
