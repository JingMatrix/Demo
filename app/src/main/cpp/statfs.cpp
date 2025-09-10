#include "statfs.hpp"

#include <cerrno>  // For errno
#include <cstring> // For strerror
#include <iomanip> // For std::hex and std::setw
#include <iostream>
#include <linux/magic.h> // Provides standard magic number definitions
#include <sstream>       // For converting hex
#include <sys/vfs.h>     // For statfs

/**
 * @brief Get the filesystem type for a given mount path.
 *
 * This function uses statfs() to retrieve the filesystem magic number
 * and returns a human-readable string representation (e.g., "EXT4",
 * "OverlayFS"). If the filesystem type is unknown, it returns the magic number
 * in hex.
 *
 * @param path The mount path to check (e.g., "/system").
 * @return A std::string containing the name of the filesystem or an error
 * message.
 */
std::string get_filesystem_type(const std::string &path) {
  struct statfs statfs_buf;

  // Call statfs to get filesystem statistics
  if (statfs(path.c_str(), &statfs_buf) != 0) {
    // If statfs fails, return an error string with the reason
    return "Error checking filesystem: " + std::string(strerror(errno));
  }

  // Check the f_type field against known magic numbers
  switch (statfs_buf.f_type) {
  case EXT4_SUPER_MAGIC:
    return "EXT4";
  case OVERLAYFS_SUPER_MAGIC:
    return "OverlayFS";
  case F2FS_SUPER_MAGIC:
    return "F2FS";
  case TMPFS_MAGIC:
    return "tmpfs";
  case PROC_SUPER_MAGIC:
    return "procfs";
  // case SQUASHFS_MAGIC:
  //     return "SquashFS";
  // case EROFS_SUPER_MAGIC_V1:
  //     return "EROFS";
  default: {
    // If the type is unknown, format it as a hex string for logging
    std::stringstream ss;
    ss << "Unknown (0x" << std::hex << std::setw(8) << std::setfill('0')
       << statfs_buf.f_type << ")";
    return ss.str();
  }
  }
}
