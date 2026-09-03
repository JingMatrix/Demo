#pragma once

// Linker state reached through dl_iterate_phdr alone: no /linker symbol table, no guessed
// soinfo offsets, so it holds on every Android release.
//
// dlpi_adds/dlpi_subs are the linker's own module counters. Scanning any object's
// PT_DYNAMIC for DT_DEBUG reaches r_debug, whose link_map nodes are soinfo::link_map_head
// -- so the chain yields every live soinfo address, and soinfo comes from a fixed-stride
// block allocator handed out front to back.
//
//   LEDGER      entries == dlpi_adds - dlpi_subs. Only a NEGATIVE residual is evidence: a
//               dlopen that reads its ELF but fails to link bumps subs without ever
//               bumping adds, leaving a benign +1.
//   FREE LIST   a hole of k*stride means k-1 blocks are free; a block below its
//               predecessor in enumeration order was reclaimed from the free list. Both
//               are cross-checked against dlpi_subs, which counts the same events:
//               observing more than the linker admits to is a contradiction.
//   MAPS        dlpi_addr + dlpi_phdr[] give every reservation the linker vouches for.
//               Classify what is left by the DEVICE it is backed by -- the one property
//               the caller does not pick. Names, the sharing bit, memfd pathnames and ELF
//               headers are all attacker-chosen.
//
// Everything runs inside one dl_iterate_phdr callback, which holds g_dl_mutex, so the
// object list, the counters and the chain are one consistent snapshot.

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace DlPhdr {

// One object as dl_iterate_phdr reports it, plus what we derived.
struct Object {
  uintptr_t base = 0;     // dlpi_addr, the load bias
  uintptr_t lo = 0;       // page-aligned PT_LOAD reservation
  uintptr_t hi = 0;
  uintptr_t phdr = 0;     // dlpi_phdr
  uintptr_t namePtr = 0;  // dlpi_name, which is soinfo::link_map_head.l_name
  uintptr_t block = 0;    // &soinfo::link_map_head, matched from the r_debug chain
  int region = -1;        // which allocator run that block belongs to
  size_t phnum = 0;
  size_t tlsModId = 0;
  bool kernelMapped = false;  // main executable / interpreter / vdso
  std::string name;
};

struct Finding {
  const char *check;  // stable id, doubles as the JSON tag
  std::string detail;
};

struct Result {
  // ---- ledger identity ----
  bool countersValid = false;
  long entries = 0;
  unsigned long long adds = 0, subs = 0;
  long ledger = 0;  // entries - (adds - subs); zero on a clean linker, never negative

  // ---- soinfo block gaps ----
  bool chainAvailable = false;
  long chainLength = 0;
  long chainMismatch = 0;  // chainLength - entries; the two views must agree
  long unmatched = 0;      // objects with no link_map node (the views disagree per-object)
  size_t stride = 0;       // soinfo block stride, discovered at runtime
  int blocksCovered = 0;   // objects whose block took part in the analysis
  int gapRuns = 0;         // holes in the sorted block sequence
  int freeBlocks = 0;      // total soinfo blocks missing across those holes
  int inversions = 0;      // objects whose block sits below the one loaded before it
  long unaccountedFrees = 0;  // (freeBlocks + inversions) - dlpi_subs, when positive

  // ---- calibration ----
  bool calibrated = false;   // the probe library loaded and the ledger moved
  bool calibFailed = false;  // it loaded but the linker did not account for it
  long dEntries = 0, dAdds = 0, dSubs = 0, dChain = 0;
  std::string calibNote;

  // ---- address-space reconciliation ----
  int ghostExec = 0;    // private anonymous executable pages no object claims
  int foreignExec = 0;   // unclaimed exec on a real device
  int volatileExec = 0;  // unclaimed exec on no device: anonymous, shmem or memfd
  int anonBacked = 0;    // an enumerated object whose text is anonymous
  int extentHoles = 0;   // unmapped holes inside a reservation
  int phdrMismatch = 0;  // dlpi_phdr disagrees with the mapped ELF header
  int badName = 0;       // empty or relative dlpi_name

  // Whether this process may create executable memory at all; calibrates ghostExec.
  std::string execMemory;

  std::vector<Finding> findings;
  std::vector<Object> objects;
  std::string json;

  bool injected() const {
    return ledger < 0 || chainMismatch != 0 || unmatched != 0 || ghostExec > 0 ||
           anonBacked > 0 || extentHoles > 0 || phdrMismatch > 0 || badName > 0 ||
           unaccountedFrees > 0 || calibFailed;
  }
  bool unloadTrace() const { return freeBlocks > 0 || inversions > 0; }
};

// Run every tier in the CURRENT process. Only libdl, /proc/self/maps and our own
// probe library are touched, so this is safe from the main process and from either
// isolated probe.
Result Run();

}  // namespace DlPhdr

extern "C" {
// C entry point mirroring recon_run_json, so the pure-C native probe can run the
// identical check. Writes the JSON document into out and returns the number of
// hard findings (the ones Result::injected() is built from).
int dlphdr_run_json(char *out, size_t cap);
}
