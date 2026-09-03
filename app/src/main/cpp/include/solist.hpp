#pragma once

// Read-only walk of the dynamic linker's soinfo list.
//
// This is the low-level counterpart to dlphdr.hpp. dl_iterate_phdr gives a
// portable, unprivileged view of the same list and needs no symbols at all, so it
// carries the ledger and gap invariants; what it cannot give is the linker's own
// strings -- the per-object soname and realpath as the linker recorded them, not
// as /proc/self/maps renders them. That is what this file is for, and it is why a
// finding here names the offending library.
//
// Everything below is strictly read-only. The offsets come from a real AOSP
// `struct soinfo` declaration (linker_soinfo.h) rather than per-ABI magic numbers,
// and are then re-derived at runtime against the linker's own soinfo, so a vendor
// build that reorders or pads fields is corrected for instead of misread. There is
// deliberately no ProtectedDataGuard here: it exists to make the linker's data
// pages writable, a detector never writes, and requiring it is what made the
// previous version of this file fail outright on Android 17, where the C2/D2
// mangled variants of its constructor were dropped.

#include <string>
#include <vector>

#include "elf_parser.hpp"
#include "linker_soinfo.h"

namespace SoList {

class SoInfo {
public:
  // Seeded from the AOSP struct, then confirmed or corrected by
  // findHeuristicOffsets() against the linker's own soinfo.
  inline static size_t solist_size_offset = soinfo::get_size_offset();
  inline static size_t solist_next_offset = soinfo::get_next_offset();
  inline static size_t solist_constructors_called_offset =
      soinfo::get_constructors_called_offset();
  inline static size_t solist_realpath_offset = soinfo::get_realpath_offset();

  inline static const char *(*get_realpath_sym)(SoInfo *) = nullptr;
  inline static const char *(*get_soname_sym)(SoInfo *) = nullptr;

  inline size_t get_size() const {
    return *reinterpret_cast<const size_t *>((uintptr_t)this + solist_size_offset);
  }

  inline SoInfo *get_next() const {
    return *reinterpret_cast<SoInfo *const *>((uintptr_t)this + solist_next_offset);
  }

  inline bool get_constructor_called() const {
    return *reinterpret_cast<const bool *>((uintptr_t)this +
                                           solist_constructors_called_offset);
  }

  // realpath_ is the last of the two std::strings at the tail of soinfo; soname_
  // is the one immediately before it.
  inline const char *get_path() {
    if (get_realpath_sym) return get_realpath_sym(this);
    return reinterpret_cast<std::string *>((uintptr_t)this + solist_realpath_offset)->c_str();
  }

  inline const char *get_name() {
    if (get_soname_sym) return get_soname_sym(this);
    return reinterpret_cast<std::string *>((uintptr_t)this + solist_realpath_offset -
                                           sizeof(std::string))
        ->c_str();
  }
};

// A library the walk considers foreign, and why.
struct Finding {
  SoInfo *info;
  std::string reason;
};

// Resolve the linker's symbols and pin down the soinfo layout. Idempotent; every
// symbol except the list head itself is optional, so a build that hides one
// degrades the walk instead of disabling it.
bool Initialize();

// Walk the list and return the first library that does not belong, or nullptr.
SoInfo *DetectInjection();

// Same walk, but every finding with the reason it was flagged.
std::vector<Finding> DetectAll();

// g_module_unload_counter, or the dl_iterate_phdr dlpi_subs equivalent when the
// symbol is not resolvable. Kept for the "Module counter" check; dlphdr.cpp is
// what turns this number into a verdict.
size_t DetectModules();

} // namespace SoList
