// See include/dlphdr.hpp for what this detects and why dl_iterate_phdr, rather
// than the linker's symbol table, is the right place to ask.

#include "dlphdr.hpp"

#include <dlfcn.h>
#include <elf.h>
#include <inttypes.h>
#include <link.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include <algorithm>

#include "logging.h"

namespace DlPhdr {

namespace {

// Consecutive sorted blocks belong to the same allocator run while they stay an
// exact multiple of the stride apart and the multiple is small. The linker's own
// soinfo is a static, megabytes away from the run, and lands in a run of its own.
constexpr size_t kMaxGapBlocks = 64;

struct RawNode {
  uintptr_t addr = 0;
  uintptr_t namePtr = 0;
};

struct Snapshot {
  std::vector<Object> objects;
  std::vector<RawNode> nodes;
  bool countersValid = false;
  unsigned long long adds = 0, subs = 0;
  bool chainAvailable = false;
  std::string interp;  // PT_INTERP of the main executable, i.e. the linker's path
};

size_t pageSize() {
  static const size_t ps = (size_t)sysconf(_SC_PAGESIZE);
  return ps;
}

// Walk the link_map chain hanging off r_debug. Called from inside the
// dl_iterate_phdr callback, so the linker's g_dl_mutex is held and neither the
// chain nor the counters can move while we read them.
void walkDebugMap(uintptr_t rdebug, Snapshot *snap) {
  auto *rd = reinterpret_cast<struct r_debug *>(rdebug);
  if (rd->r_version != 1 && rd->r_version != 2) return;
  snap->chainAvailable = true;
  size_t guard = 0;
  for (struct link_map *m = rd->r_map; m != nullptr && guard < 8192; m = m->l_next, guard++) {
    snap->nodes.push_back({reinterpret_cast<uintptr_t>(m), reinterpret_cast<uintptr_t>(m->l_name)});
  }
}

int collect(struct dl_phdr_info *info, size_t size, void *data) {
  auto *snap = static_cast<Snapshot *>(data);

  // dlpi_adds/dlpi_subs exist only if the struct the caller sees reaches that far.
  // bionic always passes the full size; a shim passing a short one to hide the
  // counters is itself worth reporting.
  if (size >= offsetof(struct dl_phdr_info, dlpi_subs) + sizeof(info->dlpi_subs)) {
    snap->countersValid = true;
    snap->adds = info->dlpi_adds;
    snap->subs = info->dlpi_subs;
  }

  Object o;
  o.base = static_cast<uintptr_t>(info->dlpi_addr);
  o.phdr = reinterpret_cast<uintptr_t>(info->dlpi_phdr);
  o.phnum = info->dlpi_phnum;
  o.namePtr = reinterpret_cast<uintptr_t>(info->dlpi_name);
  o.name = info->dlpi_name ? info->dlpi_name : "";
  o.tlsModId = size >= offsetof(struct dl_phdr_info, dlpi_tls_modid) + sizeof(size_t)
                   ? info->dlpi_tls_modid
                   : 0;

  const size_t ps = pageSize();
  uintptr_t lo = UINTPTR_MAX, hi = 0;
  for (size_t i = 0; i < o.phnum; i++) {
    const ElfW(Phdr) &ph = info->dlpi_phdr[i];
    if (ph.p_type == PT_INTERP) {
      // Only the main executable carries one, and it names the ELF interpreter.
      // Both of them are mapped by the kernel, not by the linker, so neither obeys
      // the linker's one-reservation-per-object rule.
      o.kernelMapped = true;
      if (snap->interp.empty())
        snap->interp = reinterpret_cast<const char *>(o.base + ph.p_vaddr);
    }
    if (ph.p_type == PT_DYNAMIC && !snap->chainAvailable) {
      // DT_DEBUG is filled in by the linker at startup with the address of r_debug.
      auto *dyn = reinterpret_cast<ElfW(Dyn) *>(o.base + ph.p_vaddr);
      for (; dyn->d_tag != DT_NULL; dyn++) {
        if (dyn->d_tag == DT_DEBUG && dyn->d_un.d_ptr != 0) {
          walkDebugMap(static_cast<uintptr_t>(dyn->d_un.d_ptr), snap);
          break;
        }
      }
    }
    if (ph.p_type != PT_LOAD) continue;
    uintptr_t a = o.base + ph.p_vaddr;
    uintptr_t b = a + ph.p_memsz;
    lo = std::min(lo, a & ~static_cast<uintptr_t>(ps - 1));
    hi = std::max(hi, (b + ps - 1) & ~static_cast<uintptr_t>(ps - 1));
  }
  if (lo != UINTPTR_MAX) {
    o.lo = lo;
    o.hi = hi;
  }
  snap->objects.push_back(std::move(o));
  return 0;
}

Snapshot enumerate() {
  Snapshot s;
  dl_iterate_phdr(collect, &s);
  // The interpreter and the vdso are placed by the kernel too.
  for (auto &o : s.objects)
    if (o.name == "[vdso]" || (!s.interp.empty() && o.name == s.interp)) o.kernelMapped = true;
  // dlpi_name IS soinfo::link_map_head.l_name, so pointer identity ties each object
  // to its block without relying on names being unique or on either order.
  for (auto &o : s.objects) {
    for (const auto &n : s.nodes) {
      if (n.namePtr == o.namePtr && o.namePtr != 0) {
        o.block = n.addr;
        break;
      }
    }
  }
  return s;
}

// ------------------------------------------------------------------ /proc maps

struct Region {
  uintptr_t start = 0, end = 0;
  int perms = 0;
  bool shared = false;
  unsigned devMajor = 0, devMinor = 0;
  unsigned long inode = 0;
  std::string path;
};

std::vector<Region> scanMaps() {
  std::vector<Region> out;
  FILE *f = fopen("/proc/self/maps", "re");
  if (!f) return out;
  char *line = nullptr;
  size_t cap = 0;
  ssize_t n;
  while ((n = getline(&line, &cap, f)) > 0) {
    if (line[n - 1] == '\n') line[n - 1] = '\0';
    uintptr_t start = 0, end = 0;
    char perm[8] = {0};
    unsigned major = 0, minor = 0;
    unsigned long inode = 0;
    int pathOff = 0;
    if (sscanf(line, "%" SCNxPTR "-%" SCNxPTR " %7s %*x %x:%x %lu %n", &start, &end, perm, &major,
               &minor, &inode, &pathOff) < 6)
      continue;
    Region r;
    r.start = start;
    r.end = end;
    r.devMajor = major;
    r.devMinor = minor;
    r.inode = inode;
    if (perm[0] == 'r') r.perms |= PROT_READ;
    if (perm[1] == 'w') r.perms |= PROT_WRITE;
    if (perm[2] == 'x') r.perms |= PROT_EXEC;
    r.shared = perm[3] == 's';
    if (pathOff > 0 && pathOff < n) {
      const char *p = line + pathOff;
      while (*p == ' ') p++;
      r.path = p;
    }
    out.push_back(std::move(r));
  }
  free(line);
  return out;
}

bool readableAt(const std::vector<Region> &maps, uintptr_t addr, size_t len) {
  for (const auto &r : maps)
    if (addr >= r.start && addr + len <= r.end) return (r.perms & PROT_READ) != 0;
  return false;
}

// Is this run of mappings an ELF image? A dlopen'd library always has its ELF
// header at the start of its first segment; ART's JIT code caches, signal
// trampolines and stubs never do. Testing the shape rather than the pathname
// matters here, because a loader that wants to blend in simply calls its memfd
// "jit-cache" -- which is exactly what Zygisk implementations do.
bool looksLikeElf(const std::vector<Region> &maps, uintptr_t addr) {
  if (!readableAt(maps, addr, SELFMAG)) return false;
  return memcmp(reinterpret_cast<const void *>(addr), ELFMAG, SELFMAG) == 0;
}

// Walk back from an executable mapping to the start of the contiguous run it
// belongs to: the ELF header sits in the read-only segment before the text.
uintptr_t runStart(const std::vector<Region> &maps, size_t idx) {
  uintptr_t start = maps[idx].start;
  for (size_t i = idx; i-- > 0;) {
    if (maps[i].end != start) break;
    if (!maps[i].path.empty() && maps[i].path != maps[idx].path) break;
    start = maps[i].start;
  }
  return start;
}

std::string hex(uintptr_t v) {
  char b[32];
  snprintf(b, sizeof(b), "0x%" PRIxPTR, v);
  return b;
}

void jesc(const std::string &in, std::string &out) {
  for (char c : in) {
    if (c == '"' || c == '\\') {
      out += '\\';
      out += c;
    } else if (static_cast<unsigned char>(c) < 0x20) {
      out += ' ';
    } else {
      out += c;
    }
  }
}

// Can this process create executable memory that is not backed by a file? The answer
// decides how much the reconciliation above is worth: where the sandbox forbids it,
// any anonymous executable page at all is conclusive, and where it does not, an
// injector can hold its code in memory the linker was never told about.
std::string probeExecMemory() {
  const size_t ps = pageSize();
  std::string out;
  void *a = mmap(nullptr, ps, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (a != MAP_FAILED) {
    out += mprotect(a, ps, PROT_READ | PROT_EXEC) == 0 ? "mprotect anon +x allowed"
                                                       : "mprotect anon +x denied";
    munmap(a, ps);
  }
  void *b = mmap(nullptr, ps, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS,
                 -1, 0);
  out += b != MAP_FAILED ? ", anonymous rwx map allowed" : ", anonymous rwx map denied";
  if (b != MAP_FAILED) munmap(b, ps);
  return out;
}

}  // namespace

Result Run() {
  Result res;

  Snapshot snap = enumerate();
  res.countersValid = snap.countersValid;
  res.entries = static_cast<long>(snap.objects.size());
  res.adds = snap.adds;
  res.subs = snap.subs;
  res.ledger =
      snap.countersValid ? res.entries - static_cast<long>(snap.adds - snap.subs) : 0;
  res.objects = snap.objects;
  res.chainAvailable = snap.chainAvailable;
  res.chainLength = static_cast<long>(snap.nodes.size());

  res.execMemory = probeExecMemory();
  LOGI("exec-memory policy: %s", res.execMemory.c_str());
  LOGI("dl_iterate_phdr: %ld objects, link_map chain %ld, adds=%llu subs=%llu, ledger residual %ld",
       res.entries, res.chainLength, res.adds, res.subs, res.ledger);

  // ------------------------------------------------------------- ledger identity
  if (!snap.countersValid) {
    res.findings.push_back({"ledger", "dl_phdr_info was too short to carry dlpi_adds/dlpi_subs"});
  } else if (res.ledger < 0) {
    // Only the negative side is evidence: a dlopen that failed to link raises the
    // residual benignly, but nothing legitimate lowers it.
    char b[256];
    snprintf(b, sizeof(b),
             "%ld object(s) enumerated but the linker's ledger says %lld (adds %llu - subs %llu): "
             "%ld soinfo left the list with neither counter following, or the unload counter was "
             "edited upwards",
             res.entries, static_cast<long long>(res.adds - res.subs), res.adds, res.subs,
             -res.ledger);
    res.findings.push_back({"ledger", b});
  } else if (res.ledger > 0) {
    LOGI("ledger residual is +%ld, consistent with %ld dlopen(s) that failed to link", res.ledger,
         res.ledger);
  }

  if (!res.chainAvailable) {
    res.findings.push_back({"chain", "DT_DEBUG did not resolve; soinfo gap analysis unavailable"});
  } else {
    res.chainMismatch = res.chainLength - res.entries;
    for (const auto &o : res.objects)
      if (o.block == 0) res.unmatched++;
    if (res.chainMismatch != 0 || res.unmatched != 0) {
      char b[224];
      snprintf(b, sizeof(b),
               "the r_debug chain lists %ld object(s) against dl_iterate_phdr's %ld, and %ld "
               "enumerated object(s) have no chain entry: two views of one list disagree",
               res.chainLength, res.entries, res.unmatched);
      res.findings.push_back({"chain", b});
    }
  }

  // --------------------------------------------------------- soinfo block gaps
  // Enumeration order is solist order, which is the order soinfo_alloc handed the
  // blocks out. On a process that has never unloaded anything the two rise together.
  std::vector<const Object *> withBlock;
  for (const auto &o : res.objects)
    if (o.block != 0) withBlock.push_back(&o);

  if (withBlock.size() >= 8) {
    std::vector<uintptr_t> sorted;
    sorted.reserve(withBlock.size());
    for (const auto *o : withBlock) sorted.push_back(o->block);
    std::sort(sorted.begin(), sorted.end());

    std::vector<std::pair<uintptr_t, int>> hist;
    for (size_t i = 1; i < sorted.size(); i++) {
      uintptr_t d = sorted[i] - sorted[i - 1];
      if (d == 0 || d > 0x10000) continue;
      auto it = std::find_if(hist.begin(), hist.end(), [d](const auto &p) { return p.first == d; });
      if (it == hist.end())
        hist.emplace_back(d, 1);
      else
        it->second++;
    }
    int best = 0;
    for (const auto &p : hist)
      if (p.second > best) {
        best = p.second;
        res.stride = p.first;
      }

    if (res.stride != 0 && best >= 8) {
      // Split the sorted blocks into allocator runs, counting the holes inside each.
      std::vector<std::pair<uintptr_t, int>> regionOf;
      int region = 0;
      regionOf.emplace_back(sorted[0], region);
      for (size_t i = 1; i < sorted.size(); i++) {
        uintptr_t d = sorted[i] - sorted[i - 1];
        if (d % res.stride != 0 || d / res.stride > kMaxGapBlocks) {
          region++;
        } else if (d > res.stride) {
          int missing = static_cast<int>(d / res.stride) - 1;
          res.gapRuns++;
          res.freeBlocks += missing;
          res.findings.push_back({"gap", std::to_string(missing) +
                                             " soinfo block(s) on the linker's free list between " +
                                             hex(sorted[i - 1]) + " and " + hex(sorted[i])});
        }
        regionOf.emplace_back(sorted[i], region);
      }

      auto regionFor = [&regionOf](uintptr_t a) {
        auto it = std::find_if(regionOf.begin(), regionOf.end(),
                               [a](const auto &p) { return p.first == a; });
        return it == regionOf.end() ? -1 : it->second;
      };

      // Within one run, later-loaded means higher-addressed -- unless the block was
      // handed back off the free list, which only happens after an unload.
      std::vector<std::pair<int, const Object *>> lastInRegion;
      for (const auto *o : withBlock) {
        int reg = regionFor(o->block);
        res.blocksCovered++;
        auto it = std::find_if(lastInRegion.begin(), lastInRegion.end(),
                               [reg](const auto &p) { return p.first == reg; });
        if (it == lastInRegion.end()) {
          lastInRegion.emplace_back(reg, o);
          continue;
        }
        if (o->block < it->second->block) {
          res.inversions++;
          // Name the objects that bracket the reclaimed block. Their position in the
          // enumeration says WHEN the hole was made: neighbours from early in zygote's
          // preload mean the free happened long before this process was forked.
          std::string below = "?", above = "?";
          long belowIdx = -1, aboveIdx = -1;
          for (size_t k = 0; k < withBlock.size(); k++) {
            if (withBlock[k]->block == o->block - res.stride) {
              below = withBlock[k]->name;
              belowIdx = static_cast<long>(k);
            }
            if (withBlock[k]->block == o->block + res.stride) {
              above = withBlock[k]->name;
              aboveIdx = static_cast<long>(k);
            }
          }
          res.findings.push_back(
              {"inversion", o->name + " was loaded after " + it->second->name +
                                " but took the lower soinfo block " + hex(o->block) + " < " +
                                hex(it->second->block) + ": it was reclaimed from the free list"});
          res.findings.push_back(
              {"inversion-context",
               "the reclaimed block sits between load #" + std::to_string(belowIdx) + " " + below +
                   " and load #" + std::to_string(aboveIdx) + " " + above +
                   "; the freed object was allocated in that window"});
        }
        it->second = o;
      }

      // Cross-check the allocator's memory of what was freed against the linker's.
      // Slack is fine: an unload whose block is handed straight back leaves nothing
      // behind. An excess is not: it means the counter was edited downwards.
      if (res.countersValid) {
        long observed = res.freeBlocks + res.inversions;
        long admitted = static_cast<long>(res.subs);
        if (observed > admitted) {
          res.unaccountedFrees = observed - admitted;
          char b[256];
          snprintf(b, sizeof(b),
                   "%ld soinfo block(s) were freed and are still visible in the allocator, but "
                   "dlpi_subs reports only %ld unload(s): the unload counter was edited after "
                   "the fact",
                   observed, admitted);
          res.findings.push_back({"unaccounted", b});
        }
      }

      LOGI("soinfo blocks: stride 0x%zx over %d block(s), %d free block(s) in %d hole(s), "
           "%d inversion(s), %ld unaccounted for by dlpi_subs=%llu",
           res.stride, res.blocksCovered, res.freeBlocks, res.gapRuns, res.inversions,
           res.unaccountedFrees, res.subs);
    } else {
      LOGI("soinfo stride not resolvable (modal delta 0x%zx seen %d times)", res.stride, best);
      res.stride = 0;
    }
  }

  // ----------------------------------------------------------------- calibration
  // libcalib.so is ours: no dependencies, no constructors, no TLS. The linker has to
  // account for it. We do not demand exact deltas -- another thread may load
  // something while we look -- only that the object shows up in both views and that
  // the ledger still balances.
  void *h = dlopen("libcalib.so", RTLD_NOW | RTLD_LOCAL);
  if (h == nullptr) {
    const char *e = dlerror();
    res.calibNote = std::string("probe library did not load: ") + (e ? e : "unknown");
    LOGI("calibration skipped: %s", res.calibNote.c_str());
  } else {
    Snapshot after = enumerate();
    res.dEntries = static_cast<long>(after.objects.size()) - res.entries;
    res.dAdds = static_cast<long>(after.adds - snap.adds);
    res.dSubs = static_cast<long>(after.subs - snap.subs);
    res.dChain = static_cast<long>(after.nodes.size()) - res.chainLength;
    res.calibrated = true;

    bool listed = false, hasBlock = false;
    for (const auto &o : after.objects) {
      if (o.name.find("libcalib.so") == std::string::npos) continue;
      listed = true;
      hasBlock = o.block != 0;
      break;
    }
    long afterLedger = after.countersValid
                           ? static_cast<long>(after.objects.size()) -
                                 static_cast<long>(after.adds - after.subs)
                           : 0;
    // Same asymmetry as above: a concurrent failed dlopen may raise it, never lower it.
    if (afterLedger > 0) afterLedger = 0;
    dlclose(h);

    LOGI("calibration: dlopen moved (objects %+ld, chain %+ld, adds %+ld, subs %+ld), listed=%d",
         res.dEntries, res.dChain, res.dAdds, res.dSubs, (int)listed);

    if (!listed || !hasBlock || res.dAdds < 1 || res.dEntries < 1 || afterLedger != 0) {
      char b[256];
      snprintf(b, sizeof(b),
               "the linker did not account for a library we loaded ourselves: listed=%s block=%s "
               "deltas (objects %+ld, chain %+ld, adds %+ld, subs %+ld), residual %ld",
               listed ? "yes" : "no", hasBlock ? "yes" : "no", res.dEntries, res.dChain, res.dAdds,
               res.dSubs, afterLedger);
      res.calibFailed = true;
      res.calibNote = b;
      res.findings.push_back({"calibration", b});
    } else {
      char b[192];
      snprintf(b, sizeof(b),
               "a library we loaded ourselves appeared in both views and the ledger stayed "
               "balanced (objects %+ld, adds %+ld, subs %+ld)",
               res.dEntries, res.dAdds, res.dSubs);
      res.calibNote = b;
    }
  }

  // ------------------------------------------------------ address-space reconcile
  // Bracket the maps scan with a second enumeration: a library loaded by another
  // thread while we read /proc/self/maps would otherwise look like a ghost.
  std::vector<Region> maps = scanMaps();
  Snapshot later = enumerate();

  auto claimed = [&](uintptr_t s, uintptr_t e) {
    for (const auto &o : res.objects)
      if (o.hi != 0 && s < o.hi && o.lo < e) return true;
    for (const auto &o : later.objects)
      if (o.hi != 0 && s < o.hi && o.lo < e) return true;
    return false;
  };

  for (size_t i = 0; i < maps.size(); i++) {
    const Region &r = maps[i];
    if (!(r.perms & PROT_EXEC)) continue;
    if (r.path == "[vdso]" || r.path == "[sigpage]" || r.path == "[vectors]") continue;
    if (claimed(r.start, r.end)) continue;

    // Classify by the device the mapping is backed by. That number comes from the
    // filesystem, not from the caller, so unlike the pathname, the sharing bit and the
    // page contents it cannot be chosen: an unprivileged process cannot make its memory
    // appear to live on /dev/block/dm-6. Anonymous memory, shmem and memfd all land on
    // major 0; every real library is on a real device (measured: 380 executable mappings
    // in an app process, all on fe:xx or 07:xx but [vdso] and ART's two code caches).
    //
    // Do NOT try to excuse the code caches by name, by the sharing bit or by looking for
    // a writable view of the same inode. The first two are arguments the caller picks --
    // memfd_create takes the name, mmap takes MAP_SHARED -- and the third was measured
    // false: /memfd:jit-zygote-cache is mapped r--s and r-xs only, with no writable
    // sibling, so that rule would flag a clean device. Executable memory on major 0 is
    // therefore reported in full and left for a human, while the verdict stays on the
    // one shape that has no legitimate instance at all.
    const bool elf = looksLikeElf(maps, runStart(maps, i));
    char dev[32];
    snprintf(dev, sizeof(dev), "%02x:%02x", r.devMajor, r.devMinor);
    std::string d = hex(r.start) + "-" + hex(r.end) + " " + (r.shared ? "shared " : "private ") +
                    dev + " ino " + std::to_string(r.inode) + " " +
                    (r.path.empty() ? "<anonymous>" : r.path) + (elf ? " [ELF image]" : "");
    if (r.devMajor != 0) {
      // A real file the linker did not load. ART's compiled code is dlopen'd, so it is
      // already claimed; anything here is worth a look but is not by itself anomalous.
      res.foreignExec++;
      LOGD("executable mapping outside the linker's objects: %s", d.c_str());
      continue;
    }
    res.volatileExec++;
    LOGI("executable memory on no real device, claimed by no linker object: %s", d.c_str());
    res.findings.push_back({"volatile-exec", d});
    if (!r.shared && r.path.empty()) {
      res.ghostExec++;
      res.findings.push_back({"ghost", "private anonymous executable memory: " + d});
    }
  }

  for (const auto &o : res.objects) {
    if (o.name.empty() || (o.name[0] != '/' && o.name[0] != '[')) {
      res.badName++;
      res.findings.push_back(
          {"name", "object at " + hex(o.base) + " reports the name \"" + o.name + "\""});
    }
    if (o.hi == 0) continue;

    // The main executable, the interpreter and the vdso are placed by the kernel,
    // which does not reserve one contiguous range per object, so the reservation
    // rules below simply do not apply to them.
    if (!o.kernelMapped) {
      uintptr_t cursor = o.lo;
      for (const auto &r : maps) {
        if (r.end <= o.lo || r.start >= o.hi) continue;
        if (r.start > cursor) {
          res.extentHoles++;
          res.findings.push_back({"hole", o.name + ": " + hex(cursor) + "-" + hex(r.start) +
                                              " inside its reservation is not mapped at all"});
        }
        // Spoofing works by mremap'ing an anonymous copy over a library, leaving the
        // linker pointing at pages the kernel attributes to no file.
        if ((r.perms & PROT_EXEC) && r.path.empty()) {
          res.anonBacked++;
          res.findings.push_back({"anon", o.name + ": executable " + hex(r.start) + "-" +
                                              hex(r.end) + " is anonymous, not file-backed"});
        }
        cursor = std::max(cursor, r.end);
      }
      if (cursor < o.hi) {
        res.extentHoles++;
        res.findings.push_back({"hole", o.name + ": " + hex(cursor) + "-" + hex(o.hi) +
                                            " at the end of its reservation is not mapped"});
      }
    }

    if (!readableAt(maps, o.lo, sizeof(ElfW(Ehdr)))) continue;
    const auto *eh = reinterpret_cast<const ElfW(Ehdr) *>(o.lo);
    if (memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0) continue;
    uintptr_t fromLo = o.lo + eh->e_phoff;
    uintptr_t fromBase = o.base + eh->e_phoff;
    if ((o.phdr != fromLo && o.phdr != fromBase) || o.phnum != eh->e_phnum) {
      res.phdrMismatch++;
      res.findings.push_back({"phdr", o.name + ": the linker reports phdr " + hex(o.phdr) + "/" +
                                          std::to_string(o.phnum) +
                                          " but the ELF header mapped there says " + hex(fromLo) +
                                          "/" + std::to_string(eh->e_phnum)});
    }
  }

  // ---------------------------------------------------------------------- report
  char head[896];
  snprintf(head, sizeof(head),
           "{\"entries\":%ld,\"chain\":%ld,\"chainMismatch\":%ld,\"unmatched\":%ld,\"adds\":%llu,"
           "\"subs\":%llu,\"ledger\":%ld,\"countersValid\":%s,\"stride\":%zu,"
           "\"blocksCovered\":%d,\"gapRuns\":%d,\"freeBlocks\":%d,\"inversions\":%d,"
           "\"unaccountedFrees\":%ld,"
           "\"calibrated\":%s,\"calibFailed\":%s,\"calib\":[%ld,%ld,%ld,%ld],\"ghostExec\":%d,"
           "\"anonBacked\":%d,\"extentHoles\":%d,\"foreignExec\":%d,\"volatileExec\":%d,"
           "\"phdrMismatch\":%d,"
           "\"badName\":%d,\"execMemory\":\"%s\",\"findings\":[",
           res.entries, res.chainLength, res.chainMismatch, res.unmatched, res.adds, res.subs,
           res.ledger, res.countersValid ? "true" : "false", res.stride, res.blocksCovered,
           res.gapRuns, res.freeBlocks, res.inversions, res.unaccountedFrees,
           res.calibrated ? "true" : "false",
           res.calibFailed ? "true" : "false", res.dEntries, res.dChain, res.dAdds, res.dSubs,
           res.ghostExec, res.anonBacked, res.extentHoles, res.foreignExec, res.volatileExec,
           res.phdrMismatch,
           res.badName, res.execMemory.c_str());
  std::string j = head;
  bool first = true;
  for (const auto &f : res.findings) {
    if (!first) j += ",";
    first = false;
    j += "{\"check\":\"";
    j += f.check;
    j += "\",\"detail\":\"";
    jesc(f.detail, j);
    j += "\"}";
  }
  j += "]}";
  res.json = std::move(j);

  for (const auto &f : res.findings) LOGI("dlphdr[%s] %s", f.check, f.detail.c_str());

  return res;
}

}  // namespace DlPhdr

#include <jni.h>

extern "C" JNIEXPORT jstring JNICALL
Java_org_matrix_demo_ProcScanner_nativeLinkerCheck(JNIEnv *env, jclass) {
  DlPhdr::Result r = DlPhdr::Run();
  return env->NewStringUTF(r.json.c_str());
}

extern "C" int dlphdr_run_json(char *out, size_t cap) {
  DlPhdr::Result r = DlPhdr::Run();
  snprintf(out, cap, "%s", r.json.c_str());
  return (r.ledger < 0 ? 1 : 0) + (r.chainMismatch != 0 ? 1 : 0) +
         static_cast<int>(r.unmatched) + static_cast<int>(r.unaccountedFrees) + r.ghostExec +
         r.anonBacked + r.extentHoles + r.phdrMismatch + r.badName + (r.calibFailed ? 1 : 0);
}
