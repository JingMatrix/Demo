#include "solist.hpp"

#include <sys/stat.h>

#include <vector>

#include "logging.h"

namespace SoList {

namespace {

SoInfo *solinker = nullptr;
SoInfo *somain = nullptr;
SoInfo *vdso = nullptr;
uint64_t *g_module_unload_counter = nullptr;

bool initialized = false;
bool initialize_failed = false;

constexpr size_t kSearchBytes = 1024;
constexpr size_t kSizeMax = 0x100000;
constexpr size_t kSizeMin = 0x100;

std::string suffixed(const char *prefix, const std::string &suffix) {
  return std::string(prefix) + suffix;
}

// Confirm the compile-time offsets against the linker's own soinfo, which is
// recognisable independently: next points at somain or vdso, and its link_map names
// the linker.
bool findHeuristicOffsets(const std::string &linker_path) {
  LOGD("compile-time offsets [size, next, constructors_called, realpath]: "
       "[%zu, %zu, %zu, %zu]",
       SoInfo::solist_size_offset, SoInfo::solist_next_offset,
       SoInfo::solist_constructors_called_offset, SoInfo::solist_realpath_offset);

  bool size_found = false, next_found = false, ctor_found = false;
  // get_realpath answers for every soinfo, so with the symbol there is nothing to
  // search for. Decide this BEFORE the loop: the search below only reaches its
  // realpath step after the constructors_called step has matched, and on a build
  // where that never matches the symbol would otherwise go unnoticed.
  bool realpath_found = SoInfo::get_realpath_sym != nullptr;
  const size_t linker_path_size = linker_path.size();

  for (size_t i = 0; i < kSearchBytes / sizeof(void *); i++) {
    const uintptr_t field_of_solinker = (uintptr_t)solinker + i * sizeof(void *);

    if (!size_found && somain != nullptr) {
      size_t size_of_somain = *reinterpret_cast<size_t *>((uintptr_t)somain + i * sizeof(void *));
      if (size_of_somain < kSizeMax && size_of_somain > kSizeMin) {
        SoInfo::solist_size_offset = i * sizeof(void *);
        LOGI("heuristic size offset is %zu", SoInfo::solist_size_offset);
        size_found = true;
        continue;
      }
    }
    if (!size_found && somain != nullptr) continue;

    if (!next_found) {
      void *next_of_solinker = *reinterpret_cast<void **>(field_of_solinker);
      if (next_of_solinker == somain || (vdso != nullptr && next_of_solinker == vdso)) {
        SoInfo::solist_next_offset = i * sizeof(void *);
        LOGI("heuristic next offset is %zu", SoInfo::solist_next_offset);
        next_found = true;
        continue;
      }
    }
    if (!next_found) continue;

    if (!ctor_found) {
      auto *link_map_head = reinterpret_cast<link_map *>(field_of_solinker);
      const size_t index_gap = (sizeof(link_map) + sizeof(void *) - 1) / sizeof(void *);
      const uintptr_t look_forward = field_of_solinker + index_gap * sizeof(void *);
      if (*reinterpret_cast<bool *>(look_forward) && link_map_head->l_addr != 0 &&
          link_map_head->l_name != nullptr &&
          strcmp(linker_path.c_str(), link_map_head->l_name) == 0) {
        SoInfo::solist_constructors_called_offset = look_forward - (uintptr_t)solinker;
        LOGI("heuristic constructors_called offset is %zu",
             SoInfo::solist_constructors_called_offset);
        ctor_found = true;
        i += index_gap;
        continue;
      }
    }
    if (!ctor_found) continue;

    // Once realpath is resolved there is nothing left to search for, and every
    // further step would reinterpret raw soinfo words (phdr, base, dynamic...) as
    // a std::string and call size()/c_str() on them.
    if (realpath_found) break;

    auto *realpath_of_solinker = reinterpret_cast<std::string *>(field_of_solinker);
    if (realpath_of_solinker->size() == linker_path_size &&
        strcmp(linker_path.c_str(), realpath_of_solinker->c_str()) == 0) {
      SoInfo::solist_realpath_offset = i * sizeof(void *);
      SoInfo::realpath_offset_confirmed = true;
      LOGI("heuristic realpath offset is %zu", SoInfo::solist_realpath_offset);
      realpath_found = true;
      break;
    }
  }

  if (!next_found) {
    LOGE("could not locate soinfo::next; the solist walk is not safe on this build");
    return false;
  }
  // Every finding this file produces is a sentence built from get_path()/get_name(),
  // and both reinterpret raw soinfo words as a std::string. Confirmed nowhere, the
  // compile-time offset would have us call c_str() on whatever word sits there --
  // a segfault in the app's own main process for a walk that could not have named
  // anything anyway. Report the walk as unavailable instead.
  if (!realpath_found) {
    LOGE("neither soinfo::get_realpath nor the realpath offset could be confirmed; "
         "the walk cannot name a library without reading arbitrary words as std::string");
    return false;
  }
  if (!ctor_found)
    LOGW("falling back to the compile-time constructors_called offset %zu",
         SoInfo::solist_constructors_called_offset);
  return true;
}

bool fileExists(const char *path) {
  struct stat st;
  return path != nullptr && path[0] == '/' && stat(path, &st) == 0;
}

} // namespace

bool Initialize() {
  if (initialized) return true;
  if (initialize_failed) return false;

  ElfParser::ElfImage linker("/linker");
  if (!linker.isValid()) {
    LOGE("could not parse the dynamic linker image");
    initialize_failed = true;
    return false;
  }

  // Every file-local linker symbol carries the same .llvm.<hash> suffix, or none.
  // somain is the one whose unsuffixed spelling is known, so learn it from there.
  std::string_view somain_sym = linker.findSymbolNameByPrefix("__dl__ZL6somain");
  if (somain_sym.empty()) {
    LOGE("could not find the somain symbol in %s", linker.getLibraryPath().c_str());
    initialize_failed = true;
    return false;
  }
  // LTO appends a ".llvm.<hash>" tag to file-local symbols. The hash has no fixed
  // width -- a 20-digit one shows up on Android 17 -- so take the whole remainder;
  // truncating it produces a name that resolves to nothing and the walk fails open.
  std::string suffix;
  if (somain_sym.length() > strlen("__dl__ZL6somain"))
    suffix.assign(somain_sym.substr(strlen("__dl__ZL6somain")));
  LOGI("linker symbol suffix is \"%s\"", suffix.c_str());

  solinker = ElfParser::resolveSymbolPointer<SoInfo>(linker, suffixed("__dl__ZL8solinker", suffix));
  if (solinker == nullptr)
    solinker = ElfParser::resolveSymbolPointer<SoInfo>(linker, suffixed("__dl__ZL6solist", suffix));
  if (solinker == nullptr) {
    LOGE("could not find the head of the linker's soinfo list");
    initialize_failed = true;
    return false;
  }
  LOGI("found the soinfo list head at %p", solinker);

  somain = ElfParser::resolveSymbolPointer<SoInfo>(linker, std::string(somain_sym));
  vdso = ElfParser::resolveSymbolPointer<SoInfo>(linker, suffixed("__dl__ZL4vdso", suffix));
  LOGI("somain %p, vdso %p", somain, vdso);

  SoInfo::get_realpath_sym = ElfParser::findDirectSymbol<decltype(SoInfo::get_realpath_sym)>(
      linker, "__dl__ZNK6soinfo12get_realpathEv");
  SoInfo::get_soname_sym = ElfParser::findDirectSymbol<decltype(SoInfo::get_soname_sym)>(
      linker, "__dl__ZNK6soinfo10get_sonameEv");

  g_module_unload_counter = ElfParser::findDirectSymbol<uint64_t>(
      linker, suffixed("__dl__ZL23g_module_unload_counter", suffix));
  if (g_module_unload_counter == nullptr)
    g_module_unload_counter =
        ElfParser::findDirectSymbol<uint64_t>(linker, "__dl__ZL23g_module_unload_counter");

  if (!findHeuristicOffsets(linker.getLibraryPath())) {
    initialize_failed = true;
    return false;
  }
  initialized = true;
  return true;
}

std::vector<Finding> DetectAll() {
  std::vector<Finding> out;
  if (!Initialize()) return out;

  size_t walked = 0;
  for (SoInfo *iter = solinker; iter != nullptr && walked < 8192; iter = iter->get_next()) {
    walked++;
    const char *path = iter->get_path();
    const char *name = iter->get_name();
    // Initialize() guarantees a readable path; the soname needs its own symbol, so
    // fall back to the path rather than reporting every library as "<unnamed>".
    const std::string label = (name != nullptr && name[0] != '\0')  ? name
                              : (path != nullptr && path[0] != '\0') ? path
                                                                     : "<unnamed>";

    if (path == nullptr || path[0] == '\0') {
      out.push_back({iter, label + " has no recorded path"});
      continue;
    }
    if (path[0] != '/' && path[0] != '[') {
      out.push_back({iter, label + " has the relative path \"" + path + "\""});
      continue;
    }

    bool flagged = false;
    for (const char *needle : {"/memfd:", "(deleted)", "jit-cache-zygisk", "zygisk", "/data/adb",
                               "/debug_ramdisk"}) {
      if (strstr(path, needle) != nullptr) {
        out.push_back({iter, label + " was loaded from " + path});
        flagged = true;
        break;
      }
    }
    if (flagged) continue;

    if (path[0] == '/' && !fileExists(path))
      out.push_back({iter, label + " records the path " + path + ", which does not exist"});
  }
  LOGI("walked %zu soinfo record(s), %zu suspicious", walked, out.size());
  return out;
}

SoInfo *DetectInjection() {
  std::vector<Finding> all = DetectAll();
  for (const auto &f : all) LOGI("suspicious soinfo %p: %s", f.info, f.reason.c_str());
  return all.empty() ? nullptr : all.front().info;
}

size_t DetectModules() {
  if (!Initialize()) return 0;
  if (g_module_unload_counter == nullptr) {
    LOGI("g_module_unload_counter is not resolvable; see the dl_iterate_phdr ledger instead");
    return 0;
  }
  return *g_module_unload_counter;
}

} // namespace SoList
