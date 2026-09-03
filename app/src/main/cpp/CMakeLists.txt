cmake_minimum_required(VERSION 3.22.1)
project(demo_native)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# "librecon.so": the mount-reconciliation core (statx/statfs vs mountinfo). Self
# contained (libc + log only) so it can be shared by every context: the main
# process (libdemo), the native isolated probe (libmain), and the classic isolated
# Java probe (loaded directly via System.loadLibrary("recon")).
# dlphdr.cpp rides along: it is the linker-ledger / soinfo-gap detector and needs
# nothing beyond libdl and /proc/self/maps, so every context gets it for free.
add_library(recon SHARED recon.cpp dlphdr.cpp)
target_include_directories(recon PRIVATE include)
target_compile_options(recon PRIVATE -O2)
target_link_libraries(recon log dl)

# "libcalib.so": the calibration probe dlphdr.cpp loads to prove the linker's
# ledger still moves. Empty on purpose -- no dependencies, no constructors -- so a
# clean linker answers with exactly one new object and one increment of dlpi_adds.
add_library(calib SHARED calib.cpp)
target_compile_options(calib PRIVATE -O2)

# Framework loads "libmain.so" for android:nativeService components (the
# zygote_next native isolated probe).
add_library(main SHARED probe.cpp)
target_include_directories(main PRIVATE include)
target_compile_options(main PRIVATE -O2 -Wall)
target_link_libraries(main recon log)

# "libdemo.so": main-process integrity detections (injection via solist/vmap,
# module counter, libc atexit array, /system remount, mountinfo injection,
# mount reconciliation).
# Loaded by MainActivity.
add_library(demo SHARED
        integrity.cpp atexit.cpp elf_parser.cpp smap.cpp solist.cpp statfs.cpp vmap.cpp mount.cpp)
target_include_directories(demo PRIVATE include)
# linker_soinfo.h takes offsetof() of a non-standard-layout type on purpose: it is a
# transcription of AOSP's struct soinfo, and its unused private members are what put
# the public ones at the right offsets.
target_compile_options(demo PRIVATE -O2 -Wall -Wno-invalid-offsetof -Wno-unused-private-field)
target_link_libraries(demo android log recon)
