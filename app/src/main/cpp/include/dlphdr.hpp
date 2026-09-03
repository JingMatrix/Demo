#pragma once

// Linker-ledger and soinfo-gap detection reached entirely through dl_iterate_phdr.
//
// solist.cpp already finds injections by walking the linker's soinfo list and
// looking for holes in it, but to get there it has to parse /linker's symbol
// table for __dl__ZL6solist (renamed to solinker in Android 16), strip LLVM
// suffixes off the symbol name, and then guess struct field offsets at runtime.
// Every one of those steps is a portability liability.
//
// None of it is necessary. dl_iterate_phdr is a public libdl ABI, and from it the
// same linker state is reachable on every Android release:
//
//   * dl_phdr_info::dlpi_adds / dlpi_subs ARE g_module_load_counter and
//     g_module_unload_counter, handed over without a symbol lookup;
//   * scanning any enumerated object's PT_DYNAMIC for DT_DEBUG yields the address
//     of struct r_debug, whose r_map is the linker's link_map chain;
//   * in bionic a link_map node is not a separate allocation -- it is the
//     soinfo::link_map_head field -- so the chain leaks the address of every live
//     soinfo, and soinfo comes from a fixed-stride block allocator.
//
// That last point is what turns this into a gap detector. soinfo comes out of a
// LinkerBlockAllocator: one large run of address space carved into fixed-size
// blocks, handed out strictly front to back, with freed blocks pushed onto a LIFO
// free list. dl_iterate_phdr enumerates in solist order, and solist is appended in
// soinfo_alloc, so on a process that has never unloaded anything the enumeration
// order and the block addresses rise together in lockstep, one stride at a time.
// Measured on a KernelSU device with no modules that is exactly what happens:
// 361 blocks, 360 deltas, every one of them exactly one stride, and enumeration
// order strictly ascending. Two things can disturb it:
//
//   FREE BLOCK  a hole of k*stride between two live blocks means k-1 blocks are
//               sitting on the free list: libraries that were allocated and freed.
//               This is the signal solist.cpp looks for, without a linker symbol.
//   INVERSION   the free list is LIFO, so a hole is refilled by the next load,
//               which then sits BELOW its predecessor in enumeration order. An
//               inversion survives exactly the case where the hole does not, so the
//               two are counted together -- between them they catch an unload
//               whether or not anything reclaimed the slot afterwards.
//
// Neither number is a verdict on its own: a process that legitimately dlclosed
// something has both. What makes them conclusive is that the SAME events are
// counted a second time, independently, by the linker itself:
//
//     free blocks + inversions  <=  dlpi_subs
//
// bionic calls soinfo_free from exactly two places. One is soinfo_unload_impl,
// immediately after ++g_module_unload_counter -- so every ordinary unload is on
// both sides. The other is load_library, when soinfo_alloc has already run and
// ElfReader::Read then fails, which frees a block without touching the counter;
// but that block is the frontier at the moment it is freed and the next allocation
// takes it straight back, so it leaves neither a hole nor an inversion. Everything
// visible is therefore accounted for, and the inequality can only be slack (an
// unload whose block was immediately handed back leaves no trace), never violated.
// Observing more free-list activity than the linker admits to having unloaded is a
// contradiction, and the practical way to produce one is to edit the counter.
//
// That is exactly what a hider that balances its bookkeeping does. NeoZygisk
// subtracts equally from both counters so the ledger identity above still holds --
// and measurably it does, dlpi_adds - dlpi_subs matched the object count on the
// test device to the unit. But it drives dlpi_subs BELOW the number of unloads that
// physically happened, and the allocator's free list still remembers them. Measured
// on a Pixel 6 running NeoZygisk v2.4: dlpi_subs = 0, "nothing has ever been
// unloaded", while the app's own libdemo.so sits on a reclaimed block.
//
// Note that the r_debug chain must be used only as a set of block addresses, never
// as an ordering: bionic inserts a link_map when a library finishes LINKING, not
// when its soinfo is allocated, so a batch load reorders the chain relative to the
// allocation sequence. Load order comes from dl_iterate_phdr; the chain supplies
// only the addresses, matched to objects by dlpi_name pointer identity.
//
// Two more tiers back that up, both also symbol-free:
//
//   LEDGER     bionic bumps the load counter at the tail of soinfo::link_image()
//              and the unload counter in soinfo_unload_impl(), so
//                  (objects enumerated) - (dlpi_adds - dlpi_subs)
//              is zero in a pristine process, and measurably is. It is not
//              symmetric, though, and only one side of it is evidence:
//                * a dlopen that reads its ELF but fails to link is unloaded
//                  through soinfo_unload_impl, which bumps subs for a load that
//                  never bumped adds. That leaves the residual permanently +1 per
//                  occurrence, entirely benignly.
//                * nothing legitimate drives it negative. An soinfo unlinked by
//                  pointer surgery (entries down, neither counter moving) and a
//                  counter edited downwards both do exactly that.
//              So only a NEGATIVE residual is reported. Unlike a bare "unload
//              counter > 0" test the check is indifferent to benign dlclose
//              traffic, which is what makes that test false-positive on Samsung and
//              OnePlus -- and on a stock Pixel 7.
//   CALIBRATION a frozen ledger still satisfies the identity, so we dlopen a
//              dependency-free library we ship ourselves and require the linker to
//              account for it: the object must appear in the enumeration and in the
//              chain, dlpi_adds must advance, and the identity must still hold. The
//              deltas are not required to be exactly one -- another thread may load
//              something while we look -- only to be self-consistent.
//   MAPS       dlpi_addr plus dlpi_phdr[] give the exact PT_LOAD reservation of
//              every object the linker admits to, so /proc/self/maps can be
//              reconciled against it in both directions: executable pages no
//              object claims, enumerated text that is anonymous rather than
//              file-backed, unmapped holes inside a reservation, and program
//              headers that disagree with the ELF header actually mapped there.
//              This is a whitelist of pages the linker vouches for, so unlike
//              vmap.cpp's blacklist it cannot be dodged by renaming a mapping.
//              Almost everything about a mapping is chosen by whoever created it, and
//              is therefore worthless as evidence: prctl(PR_SET_VMA_ANON_NAME) sets the
//              name and clears it again, memfd_create supplies a pathname, MAP_SHARED is
//              an argument, and manually mapped code need not keep an ELF header. The
//              one property the caller does not pick is the DEVICE the mapping is backed
//              by, which the filesystem assigns: anonymous memory, shmem and memfd are
//              all major 0, and no unprivileged process can place its memory on a real
//              block device. Measured on an app process: 380 executable mappings, every
//              one on a real device except [vdso] and ART's two code caches.
//              So executable memory on major 0 that no object claims is reported in
//              full, with its device, inode and name; and the verdict fires only on the
//              subset that has no legitimate instance at all -- private and anonymous.
//
// The whole check runs inside one dl_iterate_phdr callback, which holds the
// linker's g_dl_mutex, so the object list, the counters and the link_map chain are
// all read from the same instant and cannot be raced by a concurrent dlopen.

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
  int foreignExec = 0;   // unclaimed executable pages on a real device: a file the
                         // linker did not load
  int volatileExec = 0;  // unclaimed executable pages on no device at all -- anonymous,
                         // shmem or memfd. Reported, not a verdict: ART's two code
                         // caches live here too and cannot be told apart by any key the
                         // process is unable to forge.
  int anonBacked = 0;
  int extentHoles = 0;
  int phdrMismatch = 0;
  int badName = 0;

  // Whether this process is even allowed to create executable memory the linker never
  // saw. Reported, never a verdict: it calibrates how much weight ghostExec carries.
  std::string execMemory;

  std::vector<Finding> findings;
  std::vector<Object> objects;
  std::string json;

  // Signals that cannot fire on a clean linker. Recycling and late gaps are real
  // but a legitimate dlclose produces them too, so they stay out of the verdict and
  // are reported as their own line.
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
