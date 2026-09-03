# Demo

An Android app that asks whether anything is being hidden from it: a library
injected into its own address space, or a root module's mounts erased from its
mount table.

It is one half of a pair. The other is
[NeoZygisk](https://github.com/JingMatrix/NeoZygisk), which sets out to close
every detection point listed here. The two are developed together: a check that
lands in this app is a bug report against NeoZygisk, and a technique that
survives it belongs here.

Everything runs on device. The app shows a report and a log, either of which can
be exported from the toolbar. The full trace goes to logcat: `adb logcat -s
Demo,DemoProbe`.

## Build

```
./gradlew :app:assembleDebug
```

Needs JDK 21, the Android SDK (API 37) and the NDK. Builds for `arm64-v8a` and
`x86_64`; minSdk 29.

## Library injection

### Through `dl_iterate_phdr`

[`dl_iterate_phdr`](https://man7.org/linux/man-pages/man3/dl_iterate_phdr.3.html)
is a public libdl entry point, so this needs no linker symbols and no guess at
where the fields of `soinfo` sit. It works on every Android release, and the same
code runs in the main process and in both isolated probes.

It hands over three things:

* `dlpi_adds` and `dlpi_subs` are the linker's own load and unload counters.
* An object's `PT_DYNAMIC` holds `DT_DEBUG`, which points at `r_debug`, whose
  `r_map` is the linker's `link_map` chain.
* In Bionic a `link_map` node is a field of
  [`soinfo`](https://cs.android.com/android/platform/superproject/main/+/main:bionic/linker/linker_soinfo.h),
  not a separate allocation, so the chain yields the address of every live
  `soinfo`. Those come from a fixed-stride
  [block allocator](https://cs.android.com/android/platform/superproject/main/+/main:bionic/linker/linker_block_allocator.h)
  that hands blocks out front to back.

*Ledger.* `objects - (dlpi_adds - dlpi_subs)` should be zero. A `dlopen` that
reads its ELF and then fails to link bumps `subs` without ever bumping `adds`, so
a positive residual is ordinary and is ignored. A negative one is not: unlinking
an `soinfo` by hand, or raising the unload counter, is what produces it.

*Allocation order.* Blocks rise with load order until something is freed. A
hole of `k` strides means `k-1` blocks sit on the free list, and an object below
its predecessor took one back.

*Free list against the counter.* Neither of those proves anything alone; an
ordinary `dlclose` produces both. But the linker counts the same events itself,
so free and reclaimed blocks can never outnumber `dlpi_subs`. Bionic frees an
`soinfo` in two places: in `soinfo_unload_impl`, right after
`++g_module_unload_counter`, and in `load_library` when `ElfReader::Read` fails.
The second frees the block at the allocation frontier, which the next allocation
takes straight back, leaving no hole and no inversion. Slack is therefore
expected; an excess is not.

*Calibration.* A frozen ledger still satisfies the first check, so the app
`dlopen`s a dependency-free library it ships itself and requires the linker to
account for it in both views.

*Address space.* `dlpi_addr` and `dlpi_phdr[]` describe every mapping the
linker vouches for, which turns `/proc/self/maps` into something checkable
against a whitelist: executable ELF images no object claims, object text that is
anonymous rather than file-backed, holes inside a reservation, and program
headers that disagree with the ELF header mapped at the base. Renaming a mapping
does not help here, which matters because Zygisk implementations name their
`memfd` after ART's JIT cache.

### Through `solist`

`soinfo` has a
[`next`](https://cs.android.com/android/platform/superproject/main/+/main:bionic/linker/linker_soinfo.h;l=186)
field linking every loaded library, so walking it lists them all. Two cases count
as injection: an `soinfo` with no pathname, and a gap in the list appearing before
[`specializeAppProcess`](https://cs.android.com/android/platform/superproject/main/+/main:frameworks/base/core/java/com/android/internal/os/Zygote.java;l=436).

This one does need the linker's private symbols and the field offsets of
`soinfo`, which it re-derives at runtime. That makes it the most fragile check
here: `__dl__ZL6solist` became `solinker` in Android 16, and the mangled
`ProtectedDataGuard` constructors it used to rely on are gone in Android 17.

### Through virtual maps

See the blog post
[Android 用户态注入隐藏已死](https://nullptr.icu/index.php/archives/182/).

### Through the module counter

`dlclose` increments
[`g_module_unload_counter`](https://cs.android.com/android/platform/superproject/main/+/main:bionic/linker/linker.cpp;l=1956).
On its own the count says very little: it is non-zero on stock Samsung and
OnePlus builds, and on a stock Pixel 7 running Android 17, whose zygote unloads
seven libraries during preload. The app reports it for information only. What
matters is not that libraries were unloaded, but that fewer unloads are admitted
than the allocator still accounts for, which is the free-list check above.

## Mount hiding

Root managers hide their module mounts by filtering
`/proc/<pid>/{mountinfo,mounts,mountstats}` in the kernel's `seq_file` path.
KernelSU's
[`mount_hide`](https://github.com/JingMatrix/KernelSU/commit/80a3ab31eb108a5515ecaea0f4799a035b7d1ce1),
for instance, drops records that carry a module marker, match the umount list, or
are rooted under `/data/adb`. The mounts stay active and only their text
disappears. Because the filter keys on the reader, every view the app can reach is
scrubbed the same way, which defeats marker scans and cross-view differentials
alike.

The `stat` family is not on that path. `recon.cpp` reconciles the filtered
`mountinfo` against what the kernel actually reports, and runs identically in the
main process and in both isolated probes.

*Reconciliation.* For a curated set of paths that root modules graft onto, ask
`statx(STATX_ATTR_MOUNT_ROOT)` whether the path is a mount root and `statfs` what
filesystem backs it. A confirmed mount root that `mountinfo` does not list is a
hidden record, and so is a single file under a read-only partition that turns out
to be backed by userdata.

*Structure.* Two checks read only `mountinfo`, so they fire even where the
hidden path itself is unreachable: a mount whose parent id is absent from the
file, and a gap in the peer-group id run.

### Looking from an isolated process

Two services look from where an ordinary app cannot:

* a classic isolated service, after
  [Privisolated](https://github.com/LSPosed/Privisolated). Isolated processes
  inherit `AID_READPROC`, so it reads the mount files of every peer it is allowed
  to and compares them.
* a native `zygote_next` service, after
  [ZygoteNextProbe](https://github.com/XiaoTong6666/ZygoteNextProbe). On
  Android 17 it is forked into init's global mount namespace, where module mounts
  are still listed in its own `/proc/self/mountinfo`.

## Known limitation

A bind over `/apex/com.android.art/bin/dex2oat*`, the ART-compile hook used by
[Vector](https://github.com/JingMatrix/Vector), is out of reach. SELinux denies apps `getattr` on
`dex2oat_exec`, so `stat` cannot see it, and it never propagates into the app's
own mount namespace.
