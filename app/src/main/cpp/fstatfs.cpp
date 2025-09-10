#include "fstatfs.hpp"

#include "logging.h"
#include <dirent.h>
#include <string>
#include <sys/vfs.h>
#include <sys/stat.h>
#include <unistd.h>

// The magic number for OverlayFS, defined in kernel headers (e.g.,
// linux/magic.h) We define it here to avoid dependency on kernel headers in the
// build environment.
#define OVERLAYFS_SUPER_MAGIC 0x794c7630

// For comparison, the magic number for EXT4
#define EXT4_SUPER_MAGIC 0xEF53

void check_system_fds() {
  const std::string fd_dir_path = "/proc/self/fd";
  DIR *dir = opendir(fd_dir_path.c_str());

  if (!dir) {
    LOGD("Error: Could not open %s: %s", fd_dir_path.c_str(), strerror(errno));
    return;
  }

  LOGD("Starting scan of inherited file descriptors...");

  struct dirent *entry;
  while ((entry = readdir(dir)) != nullptr) {
    // Each entry name is a file descriptor number
    const std::string fd_str = entry->d_name;

    // Skip '.' and '..' directories
    if (fd_str == "." || fd_str == "..") {
      continue;
    }

    int fd = -1;
    try {
      fd = std::stoi(fd_str);
    } catch (const std::invalid_argument &e) {
      LOGD("Warning: Could not parse FD: %s", fd_str.c_str());
      continue;
    }

    // Construct the full path to the symbolic link
    char symlink_path[PATH_MAX];
    snprintf(symlink_path, sizeof(symlink_path), "%s/%s", fd_dir_path.c_str(),
             fd_str.c_str());

    // Use readlink to find out what file this FD points to
    char real_path[PATH_MAX];
    ssize_t len = readlink(symlink_path, real_path, sizeof(real_path) - 1);

    if (len == -1) {
      // This can happen for sockets, pipes, etc. It's normal.
      continue;
    }

    // readlink does not null-terminate, so we must do it ourselves.
    real_path[len] = '\0';
    std::string real_path_str(real_path);

    // This is the filter you requested: only check files from /system
    if (real_path_str.rfind("/system/", 0) == 0) {

      LOGD("Checking FD %d -> %s", fd, real_path_str.c_str());

      struct stat stat_from_fstat;
      if (fstat(fd, &stat_from_fstat) == -1) {
        LOGD("  -> fstat() failed. Skipping.");
        continue;
      }

      struct stat stat_from_stat;
      if (stat(real_path, &stat_from_stat) == -1) {
        LOGD("  -> stat() failed. Skipping.");
        continue;
      }

      LOGD("  -> fstat() dev:inode = %llu:%llu",
           (unsigned long long)stat_from_fstat.st_dev,
           (unsigned long long)stat_from_fstat.st_ino);
      LOGD("  -> stat()  dev:inode = %llu:%llu",
           (unsigned long long)stat_from_stat.st_dev,
           (unsigned long long)stat_from_stat.st_ino);

      struct statfs fs_info;
      // The CRITICAL part: call fstatfs on the integer FD, not statfs on the
      // path.
      if (fstatfs(fd, &fs_info) == -1) {
        LOGD("  -> fstatfs failed: %s", strerror(errno));
        continue;
      }

      // Analyze the result
      if (fs_info.f_type == OVERLAYFS_SUPER_MAGIC) {
        LOGD("  -> Filesystem type: 0x%lX.  *** OVERLAYFS DETECTED! ***",
             fs_info.f_type);
      } else if (fs_info.f_type == EXT4_SUPER_MAGIC) {
        LOGD("  -> Filesystem type: 0x%lX. (This is ext4)", fs_info.f_type);
      } else {
        LOGD("  -> Filesystem type: 0x%lX. (Unknown)", fs_info.f_type);
      }
    }
  }

  closedir(dir);
  LOGD("File descriptor scan complete.");
}
