#pragma once

// Read-only walk of the linker's soinfo list. Offsets come from a real AOSP struct
// soinfo and are re-derived at runtime. No ProtectedDataGuard: a detector never writes,
// and requiring that symbol is what made this fail outright on Android 17.

#include <string>
#include <vector>

#include "elf_parser.hpp"
#include "linker_soinfo.h"

namespace SoList {

class SoInfo {
public:
  inline static size_t solist_size_offset = soinfo::get_size_offset();
  inline static size_t solist_next_offset = soinfo::get_next_offset();
  inline static size_t solist_constructors_called_offset =
      soinfo::get_constructors_called_offset();
  inline static size_t solist_realpath_offset = soinfo::get_realpath_offset();

  inline static const char *(*get_realpath_sym)(SoInfo *) = nullptr;
  inline static const char *(*get_soname_sym)(SoInfo *) = nullptr;

  // Set only once the heuristic has matched the linker's own realpath at that offset.
  // Until then the compile-time value is a guess, and dereferencing it as a std::string
  // means calling c_str() on whatever soinfo word happens to sit there.
  inline static bool realpath_offset_confirmed = false;

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

  inline const char *get_path() {
    if (get_realpath_sym) return get_realpath_sym(this);
    if (!realpath_offset_confirmed) return nullptr;
    return reinterpret_cast<std::string *>((uintptr_t)this + solist_realpath_offset)->c_str();
  }

  // soname_ sits directly before realpath_ in soinfo, so the confirmed realpath offset
  // locates it -- but only that offset does.
  inline const char *get_name() {
    if (get_soname_sym) return get_soname_sym(this);
    if (!realpath_offset_confirmed) return nullptr;
    return reinterpret_cast<std::string *>((uintptr_t)this + solist_realpath_offset -
                                           sizeof(std::string))
        ->c_str();
  }
};

struct Finding {
  SoInfo *info;
  std::string reason;
};

// Idempotent. Every symbol but the list head is optional, so a build that hides one
// weakens the walk instead of disabling it.
bool Initialize();

SoInfo *DetectInjection();

std::vector<Finding> DetectAll();

// Informational only; dlphdr.cpp is what turns this number into a verdict.
size_t DetectModules();

} // namespace SoList
