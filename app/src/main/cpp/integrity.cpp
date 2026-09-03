// Integrity detections (injection + mount tamper) that run in the app's MAIN process
// and report each check as JSON, so MainActivity can render them alongside the
// isolated-process mount probes.

#include <optional>

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

    // 1. injected shared library, named from the linker's own soname and realpath
    bool solist_ready = SoList::Initialize();
    std::vector<SoList::Finding> sos = solist_ready ? SoList::DetectAll() : std::vector<SoList::Finding>();
    if (!solist_ready) {
        add(arr, first, "injection", "Solist injection", false,
            "unavailable: the linker's object list could not be located on this build "
            "(this is not a clean result)");
    } else if (!sos.empty()) {
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
    std::optional<VirtualMap::MapInfo> vm = VirtualMap::DetectInjection();
    if (vm) {
        any = true;
        add(arr, first, "injection", "Virtual-map injection", true, VirtualMap::Describe(*vm));
    } else {
        add(arr, first, "injection", "Virtual-map injection", false, "no anonymous exec mapping over a file");
    }

    // 3. g_module_unload_counter. Informational: a stock Pixel 7 reports 7 from zygote's
    //    own preload. It becomes evidence only cross-checked against the free list.
    size_t mods = SoList::DetectModules();
    add(arr, first, "injection", "Module counter", false,
        std::to_string(mods) +
            " library unload(s) recorded by the linker -- a count alone proves nothing; see Soinfo block gaps");

    // 4. linker state through dl_iterate_phdr only -- no symbols, no guessed offsets.
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

    // A reclaimed block counts: unlike the counter, the allocator's memory of the event
    // is not the injector's to edit. Weaker, though -- an ordinary dlopen/dlclose/dlopen
    // produces one too, so the detail keeps the two apart.
    bool gaps_bad = dp.unaccountedFrees > 0 || dp.unloadTrace();
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
        if (dp.unaccountedFrees > 0)
            d += " -- " + std::to_string(dp.unaccountedFrees) +
                 " freed block(s) the unload counter does not account for, which no unmodified "
                 "linker can produce";
        else if (dp.unloadTrace())
            d += " -- the count matches dlpi_subs, but a block was still handed back out of "
                 "load order, which a process that never unloaded anything cannot show";
        else
            d += " -- the allocation sequence is unbroken";
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
            "; " + std::to_string(dp.volatileExec) +
            " executable mapping(s) on no real device (anonymous, shmem or memfd -- ART's two "
            "code caches live here and cannot be told apart by any key a process cannot forge), " +
            std::to_string(dp.foreignExec) + " on a real device the linker did not load");

    // 5. informational: decides how much the check above proves.
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
