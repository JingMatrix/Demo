# Detecting library injection in memory

## Detection using `solist`

In Bionic linker, the [soinfo](https://cs.android.com/android/platform/superproject/main/+/main:bionic/linker/linker_soinfo.h) structure has a [field next](https://cs.android.com/android/platform/superproject/main/+/main:bionic/linker/linker_soinfo.h;l=186), which points to the next loaded library in a linked list consisting of all loaded libraries.

Hence, an injected application can easily find all loaded libraries.

### Detection criteria

The following cases are considered as injections:
1. some `soinfo` object has empty pathname;
2. the linked list of all `soinfo` has gaps between elements, and such gap appears before [specializeAppProcess](https://cs.android.com/android/platform/superproject/main/+/main:frameworks/base/core/java/com/android/internal/os/Zygote.java;l=436).

## Detection using `virtual maps`

See blog [Android 用户态注入隐藏已死](https://nullptr.icu/index.php/archives/182/).

## Detection using `module counter`

A call to `dlclose` will increase the counter [g_module_unload_counter](https://cs.android.com/android/platform/superproject/main/+/main:bionic/linker/linker.cpp;l=1956).

This detection highly depends on Android OS and vendor customization, which is shown to be false positive on Samsung and OnePlus.

# Detecting mount hiding

Root managers hide their module mounts from an app by filtering `/proc/<pid>/{mountinfo,mounts,mountstats}` at the kernel `seq_file` layer (e.g. KernelSU's [`mount_hide`](https://github.com/JingMatrix/KernelSU/commit/80a3ab31eb108a5515ecaea0f4799a035b7d1ce1)), erasing records that carry a module marker, match the umount list, or whose root dentry is under `/data/adb`. The mounts stay active; only their text is removed, and the filter keys on the *reader*, so every mount view the app can read is scrubbed consistently — defeating marker scans and cross-view differentials alike.

The `stat` syscall family is not on that path, so it is ground truth. A shared core (`recon.cpp`, run identically in the main process and both isolated probes) reconciles the filtered `mountinfo` against the kernel.

## Reconciliation (`statx` / `statfs`)

For a small curated set of systemless-root targets, ask the kernel `statx(STATX_ATTR_MOUNT_ROOT)` whether the path is a mount root and `statfs` for its filesystem. A path the kernel confirms as a mount root — or a single file backed by the userdata filesystem where a read-only partition is expected — that `mountinfo` does not list is a hidden record.

## Structural consistency

These read only from `mountinfo`, so they fire even where the hidden path itself is unreachable:
1. an orphaned mount whose parent id is absent — a record was erased between the root and this mount;
2. a gap in the peer-group id run — the kernel numbers peer groups (`shared:N` in a master/global view, `master:N` in an app's slave view) as a gap-free sequence, so a missing interior id means a group's last visible member was hidden.

## Limitation

A bind over `/apex/com.android.art/bin/dex2oat*` (the LSPosed/Vector ART-compile hook) is not detectable this way: SELinux denies apps `getattr` on `dex2oat_exec`, so `stat` cannot reach it, and it never propagates into the app's own mount namespace.

## State of bypassing current test

- [ ] [Zygisk of Magisk](https://github.com/topjohnwu/Magisk)
- [ ] [ZygiskNext](https://github.com/Dr-TSNG/ZygiskNext)
- [x] [ReZygisk](https://github.com/PerformanC/ReZygisk) (fixed by JingMatrix in https://github.com/PerformanC/ReZygisk/pull/101)
- [x] [KernelSU `mount_hide`](https://github.com/JingMatrix/KernelSU/commit/80a3ab31eb108a5515ecaea0f4799a035b7d1ce1) (defeated by mount reconciliation via `statx`/`statfs`)
