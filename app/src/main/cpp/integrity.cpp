// Integrity detections (injection + mount tamper) that run in the app's MAIN process
// and report each check as JSON, so MainActivity can render them alongside the
// isolated-process mount probes.

#include "atexit.hpp"
#include "logging.h"
#include "mount.hpp"
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

static void add(std::string &arr, bool &first, const char *name, bool detected, const std::string &detail) {
    LOGI("[%s] %s: %s", detected ? "DETECTED" : "clean", name, detail.c_str());
    if (!first)
        arr += ",";
    first = false;
    arr += "{\"name\":\"";
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

    // 1. injected shared library, found by walking the linker's solist
    SoList::SoInfo *so = SoList::DetectInjection();
    if (so) {
        any = true;
        std::string d = so->get_name() ? so->get_name() : "?";
        if (const char *p = so->get_path())
            d += std::string(" @ ") + p;
        add(arr, first, "Solist injection", true, d);
    } else {
        add(arr, first, "Solist injection", false, "no injected soinfo in linker list");
    }

    // 2. anonymous executable mapping shadowing a file (from /proc/self/maps)
    VirtualMap::MapInfo *vm = VirtualMap::DetectInjection();
    if (vm) {
        any = true;
        add(arr, first, "Virtual-map injection", true, vm->path);
    } else {
        add(arr, first, "Virtual-map injection", false, "no anonymous exec mapping over a file");
    }

    // 3. libraries unloaded after injection (module counter)
    size_t mods = SoList::DetectModules();
    if (mods > 0)
        any = true;
    add(arr, first, "Module counter", mods > 0, std::to_string(mods) + " shared libraries unloaded");

    // 4. libc atexit array state (informational integrity signal)
    Atexit::AtexitArray *g = Atexit::findAtexitArray();
    add(arr, first, "libc atexit array", false, g ? g->format_state_string() : "unavailable");

    // 5. /system remounted by a module (overlay over the real partition)
    std::string fs = get_filesystem_type("/system/bin");
    bool fs_bad = fs == "OverlayFS";
    if (fs_bad)
        any = true;
    add(arr, first, "/system filesystem", fs_bad, "/system/bin on " + fs);

    // 6. injected bind mounts visible in this process's mountinfo
    std::vector<Mount::MountInfo> ms = Mount::DetectInjection();
    if (!ms.empty()) {
        any = true;
        add(arr, first, "Mountinfo injection", true, ms[0].target);
    } else {
        add(arr, first, "Mountinfo injection", false, "no injected bind mounts in mountinfo");
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

    std::string json = "{\"technique\":\"native-integrity\",\"checks\":[" + arr + "],\"log\":[" + logJson +
                       "],\"verdict\":{\"detected\":" + (any ? "true" : "false") + "}}";
    return env->NewStringUTF(json.c_str());
}
