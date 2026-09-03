#include "solist.hpp"

#include <sys/stat.h>

#include <vector>

#include "logging.h"

namespace SoList {

namespace {

// The linker's static list head, main-executable soinfo, and vdso soinfo. Kept in
// this translation unit only: the previous header declared them at namespace scope
// so every including file got its own always-null copy.
SoInfo *solinker = nullptr;
SoInfo *somain = nullptr;
SoInfo *vdso = nullptr;
uint64_t *g_module_unload_counter = nullptr;

bool initialized = false;
bool initialize_failed = false;

// How far into soinfo the heuristics are willing to look, and the window a
// plausible mapped-image size falls in.
constexpr size_t kSearchBytes = 1024;
constexpr size_t kSizeMax = 0x100000;
constexpr size_t kSizeMin = 0x100;

// Build "<prefix><llvm suffix>" for a file-local linker symbol. The suffix is
// learned once from somain, whose unsuffixed name we know.
std::string suffixed(const char *prefix, const std::string &suffix) {
  return std::string(prefix) + suffix;
}

// Re-derive the soinfo layout against the linker's own soinfo, which we can
// recognise independently: its next pointer is somain (or vdso), its link_map
// carries the linker's path, and somain's size is a plausible image size. Starting
// from the AOSP offsets means a stock build confirms them on the first probe and a
// vendor build that shifted a field is corrected rather than misread.
bool findHeuristicOffsets(const std::string &linker_path) {
  LOGD("compile-time offsets [size, next, constructors_called, realpath]: "
       "[%zu, %zu, %zu, %zu]",
       SoInfo::solist_size_offset, SoInfo::solist_next_offset,
       SoInfo::solist_constructors_called_offset, SoInfo::solist_realpath_offset);

  bool size_found = false, next_found = false, ctor_found = false, realpath_found = false;
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
      // constructors_called sits one link_map after the list pointers, and the
      // link_map of the linker names the linker itself.
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

    // Once get_realpath is callable there is nothing to search for, and every
    // further step would reinterpret raw soinfo words (phdr, base, dynamic...) as
    // a std::string and call size()/c_str() on them.
    if (SoInfo::get_realpath_sym != nullptr) {
      realpath_found = true;
      break;
    }

    auto *realpath_of_solinker = reinterpret_cast<std::string *>(field_of_solinker);
    if (realpath_of_solinker->size() == linker_path_size &&
        strcmp(linker_path.c_str(), realpath_of_solinker->c_str()) == 0) {
      SoInfo::solist_realpath_offset = i * sizeof(void *);
      LOGI("heuristic realpath offset is %zu", SoInfo::solist_realpath_offset);
      realpath_found = true;
      break;
    }
  }

  // next is the only field the walk cannot do without.
  if (!next_found) {
    LOGE("could not locate soinfo::next; the solist walk is not safe on this build");
    return false;
  }
  if (!realpath_found)
    LOGW("falling back to the compile-time realpath offset %zu", SoInfo::solist_realpath_offset);
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

  // Android 16 renamed solist to solinker; try the new name first.
  solinker = ElfParser::resolveSymbolPointer<SoInfo>(linker, suffixed("__dl__ZL8solinker", suffix));
  if (solinker == nullptr)
    solinker = ElfParser::resolveSymbolPointer<SoInfo>(linker, suffixed("__dl__ZL6solist", suffix));
  if (solinker == nullptr) {
    LOGE("could not find the head of the linker's soinfo list");
    initialize_failed = true;
    return false;
  }
  LOGI("found the soinfo list head at %p", solinker);

  // Everything from here down is optional: a build that hides one of these should
  // weaken the walk, never disable it.
  somain = ElfParser::resolveSymbolPointer<SoInfo>(linker, std::string(somain_sym));
  vdso = ElfParser::resolveSymbolPointer<SoInfo>(linker, suffixed("__dl__ZL4vdso", suffix));
  LOGI("somain %p, vdso %p", somain, vdso);

  SoInfo::get_realpath_sym = ElfParser::findDirectSymbol<decltype(SoInfo::get_realpath_sym)>(
      linker, "__dl__ZNK6soinfo12get_realpathEv");
  SoInfo::get_soname_sym = ElfParser::findDirectSymbol<decltype(SoInfo::get_soname_sym)>(
      linker, "__dl__ZNK6soinfo10get_sonameEv");

  // The counters are file-local too, so they take the suffix like everything else.
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
    const std::string label = (name != nullptr && name[0] != '\0') ? name : "<unnamed>";

    // The linker records a realpath for everything it loads from a file, and a
    // bracketed pseudo-name ("[vdso]") for what it does not. An empty one means
    // somebody built an soinfo by hand or blanked the record.
    if (path == nullptr || path[0] == '\0') {
      out.push_back({iter, label + " has no recorded path"});
      continue;
    }
    if (path[0] != '/' && path[0] != '[') {
      out.push_back({iter, label + " has the relative path \"" + path + "\""});
      continue;
    }

    // A library loaded from an anonymous file, or out of a root solution's private
    // tree: the standard ways to inject code without leaving it on disk.
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

    // A path the linker recorded but that no longer resolves on disk.
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
