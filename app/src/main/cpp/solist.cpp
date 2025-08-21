#include "solist.hpp"
#include "logging.h"

namespace SoList {

ProtectedDataGuard::FuncType ProtectedDataGuard::ctor = NULL;
ProtectedDataGuard::FuncType ProtectedDataGuard::dtor = NULL;

size_t DetectModules() {
  if (g_module_unload_counter == NULL) {
    LOGI("g_module_unload_counter not found");
    return 0;
  } else {
    return *g_module_unload_counter;
  }
}

SoInfo *DetectInjection() {
  if (solinker == NULL && !Initialize()) {
    LOGE("Failed to initialize solist");
    return NULL;
  }
  SoInfo *prev = solinker;
  size_t gap = 0;
  auto gap_repeated = 0;
  bool app_process_loaded = false;
  bool app_specialized = false;
  const char *libraries_after_specialization[2] = {"libart.so",
                                                   "libdexfile.so"};
  bool nativehelper_loaded =
      false; // Not necessarily loaded after AppSpecialize

  for (auto iter = solinker; iter; iter = iter->get_next()) {
    // No soinfo has empty path name
    if (iter->get_path() == NULL || iter->get_path()[0] == '\0') {
      return iter;
    }

    if (iter->get_name() == NULL && app_process_loaded) {
      return iter;
    }

    if (iter->get_name() == NULL &&
        strstr(iter->get_path(), "/system/bin/app_proces")) {
      app_process_loaded = true;
      // /system/bin/app_process64 maybe set null name
      LOGD("Skip %s, gap size", iter, iter->get_path());
      continue;
    }

    if (iter - prev != gap && gap_repeated < 1) {
      gap = iter - prev;
      gap_repeated = 0;
    } else if (iter - prev == gap) {
      LOGD("Skip soinfo %p: %s", iter, iter->get_name());
      gap_repeated++;
    } else if (iter - prev == 2 * gap) {
      // A gap appears, indicating that one library was unloaded
      auto dropped = (SoInfo *)((uintptr_t)prev + gap);

      if (!nativehelper_loaded || !app_specialized) {
        // gap cannot appear before libnativehelper is loaded
        return dropped;
      } else {
        // gap may appear after any of these libraries is loaded
        LOGW("%p is dropped between %s and %s", dropped, prev->get_path(),
             iter->get_path());
      }
    } else {
      gap_repeated--;
      if (gap != 0)
        LOGI("Suspicious gap 0x%lx or 0x%lx != 0x%lx between %s and %s",
             iter - prev, prev - iter, gap, prev->get_name(), iter->get_name());
    }

    auto name = iter->get_name();
    if (!app_specialized) {
      for (int i = 0; i < 2; i++) {
        if (strcmp(name, libraries_after_specialization[i]) == 0) {
          app_specialized = true;
          break;
        }
      }
    }

    if (!nativehelper_loaded && strcmp(name, "libnativehelper.so") == 0) {
      nativehelper_loaded = true;
    }

    prev = iter;
  }

  return nullptr;
}

bool Initialize() {
  SandHook::ElfImg linker("/linker");
  if (!ProtectedDataGuard::setup(linker))
    return false;
  LOGI("found symbol ProtectedDataGuard");

  std::string_view somain_sym_name =
      linker.findSymbolNameByPrefix("__dl__ZL6somain");
  if (somain_sym_name.empty())
    return false;
  LOGI("found symbol name %s", somain_sym_name.data());

  /* INFO: The size isn't a magic number, it's the size for the string:
   * .llvm.7690929523238822858 */
  char llvm_sufix[25 + 1];

  if (somain_sym_name.length() != strlen("__dl__ZL6somain")) {
    strncpy(llvm_sufix, somain_sym_name.data() + strlen("__dl__ZL6somain"),
            sizeof(llvm_sufix));
  } else {
    llvm_sufix[0] = '\0';
  }

  char solinker_sym_name[sizeof("__dl__ZL8solinker") + sizeof(llvm_sufix)];
  snprintf(solinker_sym_name, sizeof(solinker_sym_name), "__dl__ZL8solinker%s",
           llvm_sufix);

  // for SDK < 36 (Android 16), the linker binary is loaded with name solist
  char solist_sym_name[sizeof("__dl__ZL6solist") + sizeof(llvm_sufix)];
  snprintf(solist_sym_name, sizeof(solist_sym_name), "__dl__ZL6solist%s",
           llvm_sufix);

  char sonext_sym_name[sizeof("__dl__ZL6sonext") + sizeof(llvm_sufix)];
  snprintf(sonext_sym_name, sizeof(sonext_sym_name), "__dl__ZL6sonext%s",
           llvm_sufix);

  solinker = getStaticPointer<SoInfo>(linker, solinker_sym_name);
  if (solinker == nullptr) {
    solinker = getStaticPointer<SoInfo>(linker, solist_sym_name);
    if (solinker == nullptr)
      return false;
    LOGI("found symbol solist at %p", solinker);
  } else {
    LOGI("found symbol solinker at %p", solinker);
  }

  SoInfo::get_realpath_sym =
      reinterpret_cast<decltype(SoInfo::get_realpath_sym)>(
          linker.getSymbAddress("__dl__ZNK6soinfo12get_realpathEv"));
  if (SoInfo::get_realpath_sym != nullptr)
    LOGI("found symbol get_realpath_sym");

  g_module_unload_counter = reinterpret_cast<decltype(g_module_unload_counter)>(
      linker.getSymbAddress("__dl__ZL23g_module_unload_counter"));
  if (g_module_unload_counter != nullptr)
    LOGI("found symbol g_module_unload_counter");

  somain = getStaticPointer<SoInfo>(linker, somain_sym_name.data());
  if (solinker == nullptr)
    return false;
  LOGI("found symbol somain at %p", somain);

  return findHeuristicOffsets(linker.name());
}

bool findHeuristicOffsets(std::string linker_name) {
  const size_t size_block_range = 1024;
  const size_t linker_realpath_size = linker_name.size();

  bool field_realpath_found = false;
  for (size_t i = 0; i < size_block_range / sizeof(void *); i++) {
    auto field_of_solinker =
        reinterpret_cast<uintptr_t>(solinker) + i * sizeof(void *);
    auto size_of_somain = *reinterpret_cast<size_t *>(
        reinterpret_cast<uintptr_t>(somain) + i * sizeof(void *));

    std::string *realpath_of_solinker =
        reinterpret_cast<std::string *>(field_of_solinker);
    if (realpath_of_solinker->size() == linker_realpath_size) {
      if (strcmp(linker_name.c_str(), realpath_of_solinker->c_str()) == 0) {
        SoInfo::solist_realpath_offset = i * sizeof(void *);
        LOGI("heuristic field_realpath_offset is %zu * %zu = %p", i,
             sizeof(void *),
             reinterpret_cast<void *>(SoInfo::solist_realpath_offset));
        field_realpath_found = true;
        break;
      }
    }
  }

  return field_realpath_found;
}

} // namespace SoList
