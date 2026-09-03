# Detecting library injection in memory

## Detection using `dl_iterate_phdr`

Everything below this section needs the linker's private symbols: `__dl__ZL6solist`
(renamed `solinker` in Android 16), its LLVM suffix, `ProtectedDataGuard` (whose `C2`/`D2`
mangled variants Android 17 removed), and a guess at where the fields of `soinfo` sit.
None of that is necessary. [`dl_iterate_phdr`](https://man7.org/linux/man-pages/man3/dl_iterate_phdr.3.html)
is a public, stable libdl ABI, and it reaches the same linker state on every Android release:

* `dl_phdr_info::dlpi_adds` and `dlpi_subs` **are** `g_module_load_counter` and
  `g_module_unload_counter`, handed over without a symbol lookup;
* scanning any enumerated object's `PT_DYNAMIC` for `DT_DEBUG` yields the address of
  `struct r_debug`, whose `r_map` is the linker's `link_map` chain;
* in Bionic a `link_map` node is not a separate allocation, it is the
  [`soinfo::link_map_head`](https://cs.android.com/android/platform/superproject/main/+/main:bionic/linker/linker_soinfo.h)
  field, so the chain hands out the address of every live `soinfo` — and `soinfo` comes
  from a fixed-stride [block allocator](https://cs.android.com/android/platform/superproject/main/+/main:bionic/linker/linker_block_allocator.h).

### Detection criteria

1. **Ledger identity.** The load counter is bumped at the tail of
   [`soinfo::link_image()`](https://cs.android.com/android/platform/superproject/main/+/main:bionic/linker/linker.cpp)
   and the unload counter inside `soinfo_unload_impl()`, so
   `enumerated objects - (dlpi_adds - dlpi_subs)` is zero in a pristine process. The
   residual is not symmetric and only one side of it is evidence: a `dlopen` that reads its
   ELF but then fails to link is torn down through `soinfo_unload_impl`, bumping `subs` for
   a load that never bumped `adds`, which leaves the residual permanently `+1` — entirely
   benign. Nothing legitimate drives it negative, while both an `soinfo` unlinked by pointer
   surgery and an unload counter edited upwards do. **Only a negative residual is reported.**
   Unlike a bare `g_module_unload_counter > 0` test it is indifferent to benign `dlclose`
   traffic, which is what makes that test false-positive on Samsung and OnePlus.
2. **Gaps in the `soinfo` allocation.** Blocks are handed out strictly front to back and
   freed ones are pushed onto a LIFO free list, so on a process that has never unloaded
   anything the enumeration order and the block addresses rise together, one stride at a
   time. A hole of `k*stride` means `k-1` blocks are on the free list; an object whose
   block sits *below* its predecessor reclaimed one. Between them the two catch an unload
   whether or not anything reclaimed the slot afterwards.
3. **Free-list versus unload counter.** Neither number above is a verdict on its own — a
   process that legitimately unloaded something has them too. What is conclusive is that
   the same events are counted a second time, independently, by the linker:

   ```
   free blocks + reclaimed blocks  <=  dlpi_subs
   ```

   Bionic calls `soinfo_free` from exactly two places. One is `soinfo_unload_impl`,
   immediately after `++g_module_unload_counter`, so every ordinary unload lands on both
   sides. The other is `load_library`, when `soinfo_alloc` has run and `ElfReader::Read`
   then fails — that frees a block without touching the counter, but the block is the
   allocation frontier at that moment and the next allocation takes it straight back, so it
   leaves neither a hole nor an inversion. Slack is therefore expected (an unload whose
   block is handed straight back leaves no trace) and an excess is not, the practical way
   to produce one being to edit the counter.
4. **Live-fire calibration.** A frozen ledger still satisfies (1), so the app `dlopen`s a
   dependency-free library it ships itself and requires the linker to account for it in
   both views.
5. **Address-space reconciliation.** `dlpi_addr` plus `dlpi_phdr[]` give the exact
   `PT_LOAD` reservation of every object the linker admits to, so `/proc/self/maps` can be
   reconciled against it: ELF images mapped executable that no object claims, enumerated
   text that is anonymous instead of file-backed, unmapped holes inside a reservation, and
   program headers that disagree with the ELF header actually mapped at the base. This is
   a whitelist of pages the linker vouches for, so unlike the virtual-map scan below it
   cannot be dodged by renaming a mapping — a point that matters, because Zygisk
   implementations name their `memfd` after ART's JIT cache.

Because it needs no symbols, the same code runs unchanged in the main process, the classic
isolated process and the `zygote_next` native service.

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

This detection highly depends on Android OS and vendor customization, which is shown to be
false positive on Samsung and OnePlus — and on a stock Pixel 7 running Android 17, whose
zygote unloads seven libraries during preload. The raw count is therefore reported for
information only. It becomes evidence when it is reconciled against the `soinfo` free list,
as described under `dl_iterate_phdr` above: what matters is not that libraries were
unloaded, but that fewer unloads are admitted than the allocator can still account for.

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
- [ ] [NeoZygisk](https://github.com/JingMatrix/NeoZygisk) — passes every other check in this
  suite, including the `solist` walk, the virtual-map scan and the module counter, because
  it unloads through the real linker functions and then subtracts the same amount from both
  module counters, leaving the ledger identity intact. The free-list-versus-`dlpi_subs`
  contradiction still fires: on a Pixel 6 (Android 17, NeoZygisk v2.4) `dlpi_subs` reports
  zero unloads while the app's own library sits on a reclaimed `soinfo` block.

Measured against two baselines that must stay clean, and do: a Pixel 7a on Android 16 rooted
with KernelSU and no modules installed, and a stock Pixel 7 on Android 17 whose zygote
genuinely unloads seven libraries during preload.
