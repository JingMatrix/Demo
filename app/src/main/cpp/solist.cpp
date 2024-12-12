#include "solist.hpp"
#include "logging.h"

namespace SoList {

ProtectedDataGuard::FuncType ProtectedDataGuard::ctor = NULL;
ProtectedDataGuard::FuncType ProtectedDataGuard::dtor = NULL;

SoInfo *DetectInjection() {
  if (solist == NULL && !Initialize()) {
    LOGE("Failed to initialize solist");
    return NULL;
  }
  SoInfo *prev = solist;
  size_t gap = 0;
  auto gap_repeated = 0;
  bool app_process_loaded = false;
  bool app_specialized = false;
  const char *libraries_after_specialization[2] = {"libart.so",
                                                   "libdexfile.so"};
  bool nativehelper_loaded =
      false; // Not necessarily loaded after AppSpecialize

  for (auto iter = solist; iter; iter = iter->get_next()) {
    // No soinfo has empty path name
    if (iter->get_path() == NULL || iter->get_path()[0] == '\0') {
      return iter;
    }

    if (iter->get_name() == NULL && app_process_loaded) {
      return iter;
    }

    if (iter->get_name() == NULL &&
        strstr(iter->get_path(), "/system/bin/app_process")) {
      app_process_loaded = true;
      // /system/bin/app_process64 maybe set null name
      LOGD("Skip %s, gap size", iter, iter->get_path());
      continue;
    }

    if (
      strncmp(iter->get_path(), "/system/", strlen("/system/")) != 0 &&
      strncmp(iter->get_path(), "/apex/", strlen("/apex/")) != 0 &&
      strcmp(iter->get_path(), "[vdso]") != 0
    ) {
      LOGW("Found suspicious library: 0x%lx (%s)", iter, iter->get_path());

      return iter;
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
        LOGD("Suspicious gap 0x%lx or 0x%lx != 0x%lx between %s and %s",
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

  std::string_view solist_sym_name =
      linker.findSymbolNameByPrefix("__dl__ZL6solist");
  if (solist_sym_name.empty())
    return false;

  /* INFO: The size isn't a magic number, it's the size for the string:
   * .llvm.7690929523238822858 */
  char llvm_sufix[25 + 1];

  if (solist_sym_name.length() != strlen("__dl__ZL6solist")) {
    strncpy(llvm_sufix, solist_sym_name.data() + strlen("__dl__ZL6solist"),
            sizeof(llvm_sufix));
  } else {
    llvm_sufix[0] = '\0';
  }

  solist = getStaticPointer<SoInfo>(linker, solist_sym_name.data());
  if (solist == NULL)
    return false;

  char somain_sym_name[sizeof("__dl__ZL6somain") + sizeof(llvm_sufix)];
  snprintf(somain_sym_name, sizeof(somain_sym_name), "__dl__ZL6somain%s",
           llvm_sufix);

  char sonext_sym_name[sizeof("__dl__ZL6sonext") + sizeof(llvm_sufix)];
  snprintf(sonext_sym_name, sizeof(somain_sym_name), "__dl__ZL6sonext%s",
           llvm_sufix);

  char vsdo_sym_name[sizeof("__dl__ZL4vdso") + sizeof(llvm_sufix)];
  snprintf(vsdo_sym_name, sizeof(vsdo_sym_name), "__dl__ZL4vdso%s", llvm_sufix);

  somain = getStaticPointer<SoInfo>(linker, somain_sym_name);
  if (somain == NULL)
    return false;

  sonext = linker.getSymbAddress<SoInfo **>(sonext_sym_name);
  if (sonext == NULL)
    return false;

  SoInfo *vsdo = getStaticPointer<SoInfo>(linker, vsdo_sym_name);
  if (vsdo == NULL)
    return false;

  SoInfo::get_realpath_sym =
      reinterpret_cast<decltype(SoInfo::get_realpath_sym)>(
          linker.getSymbAddress("__dl__ZNK6soinfo12get_realpathEv"));
  SoInfo::get_soname_sym = reinterpret_cast<decltype(SoInfo::get_soname_sym)>(
      linker.getSymbAddress("__dl__ZNK6soinfo10get_sonameEv"));

  for (size_t i = 0; i < 1024 / sizeof(void *); i++) {
    auto *possible_next = *(void **)((uintptr_t)solist + i * sizeof(void *));
    if (possible_next == somain || (vsdo != NULL && possible_next == vsdo)) {
      SoInfo::solist_next_offset = i * sizeof(void *);

      break;
    }
  }

  return (SoInfo::get_realpath_sym != NULL && SoInfo::get_soname_sym != NULL);
}
} // namespace SoList
