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
// The same core runs in the app's main process (libdemo / integrity.cpp), the
// native isolated probe (libmain / probe.cpp), and the classic isolated Java
// probe (ProcScanner, via the JNI entry point) so detection is identical in all
// three contexts.

#include <cstddef>
#include <string>

namespace Recon {

struct Result {
  int hidden;      // mounts the kernel confirms but mountinfo hides (HIGH signal)
  int structural;  // mountinfo tree anomalies from record erasure: an orphaned
                   // mount, or a peer-group id missing from the run
  std::string json; // {"hidden":N,"structural":N,"findings":[...],"probes":[...]}
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
