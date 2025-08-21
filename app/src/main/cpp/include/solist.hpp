#pragma once

#include "elf_util.h"
#include <string>

namespace SoList {
class SoInfo {
public:
#ifdef __LP64__
  inline static size_t solist_next_offset = 0x28;
  inline static size_t solist_realpath_offset = 0x1a0;
#else
  inline static size_t solist_next_offset = 0xa4;
  inline static size_t solist_realpath_offset = 0x17c;
#endif

  inline static const char *(*get_realpath_sym)(SoInfo *) = NULL;

  inline SoInfo *get_next() {
    return *(SoInfo **)((uintptr_t)this + solist_next_offset);
  }

  inline const char *get_path() {
    if (get_realpath_sym)
      return get_realpath_sym(this);

    return ((std::string *)((uintptr_t)this + solist_realpath_offset))->c_str();
  }

  inline const char *get_name() {
    return ((std::string *)((uintptr_t)this + solist_realpath_offset -
                            sizeof(std::string)))
        ->c_str();
  }

  void set_next(SoInfo *si) {
    *(SoInfo **)((uintptr_t)this + solist_next_offset) = si;
  }
};

class ProtectedDataGuard {
public:
  ProtectedDataGuard() {
    if (ctor != nullptr)
      (this->*ctor)();
  }

  ~ProtectedDataGuard() {
    if (dtor != nullptr)
      (this->*dtor)();
  }

  static bool setup(const SandHook::ElfImg &linker) {
    ctor = MemFunc{.data = {.p = reinterpret_cast<void *>(linker.getSymbAddress(
                                "__dl__ZN18ProtectedDataGuardC2Ev")),
                            .adj = 0}}
               .f;
    dtor = MemFunc{.data = {.p = reinterpret_cast<void *>(linker.getSymbAddress(
                                "__dl__ZN18ProtectedDataGuardD2Ev")),
                            .adj = 0}}
               .f;
    return ctor != nullptr && dtor != nullptr;
  }

  ProtectedDataGuard(const ProtectedDataGuard &) = delete;

  void operator=(const ProtectedDataGuard &) = delete;

private:
  using FuncType = void (ProtectedDataGuard::*)();

  static FuncType ctor;
  static FuncType dtor;

  union MemFunc {
    FuncType f;

    struct {
      void *p;
      std::ptrdiff_t adj;
    } data;
  };
};

static SoInfo *solinker = NULL;
static SoInfo *somain = NULL;
static SoInfo **sonext = NULL;
static uint64_t *g_module_unload_counter = NULL;

static bool Initialize();

template <typename T>
inline T *getStaticPointer(const SandHook::ElfImg &linker, const char *name) {
  auto *addr = reinterpret_cast<T **>(linker.getSymbAddress(name));

  return addr == NULL ? NULL : *addr;
}

SoInfo *DetectInjection();
size_t DetectModules();
bool findHeuristicOffsets(std::string linker_name);

bool Initialize();

} // namespace SoList
