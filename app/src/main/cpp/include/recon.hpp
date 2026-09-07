#pragma once

// Mount reconciliation: the one mount detector that survives kernel-side
// /proc/<pid>/mountinfo filtering (e.g. KSU's mount_hide, which erases marker
// records from the seq_file output while leaving the mounts active).
//
// The filter hooks the mountinfo/mounts/mountstats seq_file path only. The stat
// family (statx / statfs / stat) is untouched and is ground truth. So instead of
// trusting the text of mountinfo, we ask the kernel -- via statx STATX_ATTR_
// MOUNT_ROOT and statfs f_type -- what is REALLY mounted at a set of probe paths,
// and report every mount the kernel confirms but mountinfo omits.
//
// A third check needs neither the text nor a reachable path: every filesystem
// without a block device draws its dev_t from one kernel-GLOBAL pool, handed out
// lowest-free-first (fs/super.c get_anon_bdev), so a minor missing from our
// mountinfo is a superblock that is alive but invisible here -- including one
// mounted only in some daemon's private mount namespace, which no per-namespace
// check can reach.
//
// The same core runs in the app's main process (libdemo / integrity.cpp), the
// native isolated probe (libmain / probe.cpp), and the classic isolated Java
// probe (ProcScanner, via the JNI entry point) so detection is identical in all
// three contexts. The anonymous-device check needs external storage to fix its
// upper bound, so it is skipped (not failed) in the isolated probes.

#include <cstddef>
#include <string>

namespace Recon {

struct Result {
  int hidden;      // mounts the kernel confirms but mountinfo hides (HIGH signal)
  int structural;  // mountinfo tree anomalies from record erasure: an orphaned
                   // mount, a peer-group id missing from the run, or an
                   // anonymous device minor no mount here accounts for.
                   // Counts only "high" findings -- a low-confidence one is
                   // listed in the JSON but never moves the verdict.
  std::string json; // {"hidden":N,"structural":N,"findings":[...],"probes":[...],
                    //  "anonDev":{floor,floorPath,ceil,ceilPath,visible,
                    //              holes,wide}|null}
};

// Reconcile /proc/self/mountinfo against kernel stat ground truth in the CURRENT
// process's mount namespace. Safe to call from any of the three contexts.
Result Run();

} // namespace Recon

extern "C" {
// C entry point for the native probe (probe.cpp). Writes the JSON object from
// Recon::Run() into out (truncated to cap) and returns the total finding count
// (hidden mounts + structural anomalies), so an int-only caller still reacts to a
// structural-only hide. The hidden/structural split is in the JSON.
int recon_run_json(char *out, size_t cap);
}
