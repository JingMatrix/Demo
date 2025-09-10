#pragma once

#include <cerrno>       // For errno
#include <cstring>      // For strerror
#include <dirent.h>     // For opendir, readdir, closedir
#include <sys/statfs.h> // For fstatfs
#include <unistd.h>     // For readlink

/**
 * @brief Iterates through all open file descriptors for the current process.
 *
 * For each file descriptor that is a symbolic link to a path starting with
 * "/system/", this function performs an fstatfs() call on the descriptor itself
 * (not the path). It logs the file descriptor number, its resolved path, and
 * the filesystem type, specifically highlighting if an overlayfs is detected.
 * This is designed to find traces of overlayfs mounts that have been hidden
 * from the current mount namespace but persist through inherited file
 * descriptors.
 */
void check_system_fds();
