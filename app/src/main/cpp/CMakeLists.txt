cmake_minimum_required(VERSION 3.22.1)
project(demo_native)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Framework loads "libmain.so" for android:nativeService components (the
# zygote_next native isolated probe).
add_library(main SHARED probe.cpp)
target_compile_options(main PRIVATE -O2 -Wall)

# "libdemo.so": main-process integrity detections (injection via solist/vmap,
# module counter, libc atexit array, /system remount, mountinfo injection).
# Loaded by MainActivity.
add_library(demo SHARED
        integrity.cpp atexit.cpp elf_util.cpp smap.cpp solist.cpp statfs.cpp vmap.cpp mount.cpp)
target_include_directories(demo PRIVATE include)
target_compile_options(demo PRIVATE -O2)
target_link_libraries(demo android log)
