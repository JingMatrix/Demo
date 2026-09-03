#include "mount.hpp"
#include "logging.h"
#include <sys/sysmacros.h>

using namespace std::string_view_literals;
namespace Mount {
static inline sFILE open_file(const char *path, const char *mode) {
  return MakeFile(fopen(path, mode));
}

sFILE MakeFile(FILE *fp) {
  return sFILE(fp, [](FILE *fp) { return fp ? fclose(fp) : 1; });
}

void ReadLine(bool trim, FILE *fp,
              const std::function<bool(std::string_view)> &fn) {
  size_t len = 1024;
  char *buf = (char *)malloc(len);
  char *start;
  ssize_t read;
  while ((read = getline(&buf, &len, fp)) >= 0) {
    start = buf;
    if (trim) {
      while (read && "\n\r "sv.find(buf[read - 1]) != std::string::npos)
        --read;
      buf[read] = '\0';
      while (*start == ' ')
        ++start;
    }
    if (!fn(start))
      break;
  }
  free(buf);
}

void ReadLine(bool trim, const char *file,
              const std::function<bool(std::string_view)> &fn) {
  if (auto fp = open_file(file, "re"))
    ReadLine(trim, fp.get(), fn);
}

void ReadLine(const char *file,
              const std::function<bool(std::string_view)> &fn) {
  ReadLine(false, file, fn);
}

std::vector<MountInfo> ParseMountInfo(const char *pid) {
  char buf[PATH_MAX] = {};
  snprintf(buf, sizeof(buf), "/proc/%s/mountinfo", pid);
  std::vector<MountInfo> result;

  ReadLine(buf, [&result](std::string_view line) -> bool {
    int root_start = 0, root_end = 0;
    int target_start = 0, target_end = 0;
    int vfs_option_start = 0, vfs_option_end = 0;
    int type_start = 0, type_end = 0;
    int source_start = 0, source_end = 0;
    int fs_option_start = 0, fs_option_end = 0;
    int optional_start = 0, optional_end = 0;
    unsigned int id, parent, maj, min;
    sscanf(line.data(),
           "%u "           // (1) id
           "%u "           // (2) parent
           "%u:%u "        // (3) maj:min
           "%n%*s%n "      // (4) mountroot
           "%n%*s%n "      // (5) target
           "%n%*s%n"       // (6) vfs options (fs-independent)
           "%n%*[^-]%n - " // (7) optional fields
           "%n%*s%n "      // (8) FS type
           "%n%*s%n "      // (9) source
           "%n%*s%n",      // (10) fs options (fs specific)
           &id, &parent, &maj, &min, &root_start, &root_end, &target_start,
           &target_end, &vfs_option_start, &vfs_option_end, &optional_start,
           &optional_end, &type_start, &type_end, &source_start, &source_end,
           &fs_option_start, &fs_option_end);

    auto root = line.substr(root_start, root_end - root_start);
    auto target = line.substr(target_start, target_end - target_start);
    auto vfs_option =
        line.substr(vfs_option_start, vfs_option_end - vfs_option_start);
    ++optional_start;
    --optional_end;
    auto optional = line.substr(
        optional_start,
        optional_end - optional_start > 0 ? optional_end - optional_start : 0);

    auto type = line.substr(type_start, type_end - type_start);
    auto source = line.substr(source_start, source_end - source_start);
    auto fs_option =
        line.substr(fs_option_start, fs_option_end - fs_option_start);

    unsigned int shared = 0;
    unsigned int master = 0;
    unsigned int propagate_from = 0;
    if (auto pos = optional.find("shared:"); pos != std::string_view::npos) {
      shared = ParseInt(optional.substr(pos + 7));
    }
    if (auto pos = optional.find("master:"); pos != std::string_view::npos) {
      master = ParseInt(optional.substr(pos + 7));
    }
    if (auto pos = optional.find("propagate_from:");
        pos != std::string_view::npos) {
      propagate_from = ParseInt(optional.substr(pos + 15));
    }

    result.emplace_back(MountInfo{
        .id = id,
        .parent = parent,
        .device = static_cast<dev_t>(makedev(maj, min)),
        .root{root},
        .target{target},
        .vfs_option{vfs_option},
        .optional{
            .shared = shared,
            .master = master,
            .propagate_from = propagate_from,
        },
        .type{type},
        .source{source},
        .fs_option{fs_option},
    });
    return true;
  });
  return result;
}

int ParseInt(std::string_view s) {
  int val = 0;
  for (char c : s) {
    if (!c)
      break;
    if (c > '9' || c < '0')
      return -1;
    val = val * 10 + c - '0';
  }
  return val;
}

std::vector<MountInfo> DetectInjection() {
  std::vector<MountInfo> sus_mount = {};
  auto infos = ParseMountInfo("self");

  // Root-hiding frameworks leave a fingerprint in a bind mount's source or
  // root/target path. Mount IDs are NOT a reliable signal: the kernel does not
  // hand an app's namespace a gap-free, file-order-consecutive block of IDs (nor
  // a root mount whose ID is parent+1), so the previous ID-arithmetic heuristics
  // flagged clean devices -- and did so inconsistently between runs on the same
  // phone. Scan the inherited mounts for genuine root-tool artefacts instead.
  for (auto &info : infos) {
    if (info.target == "/data/data")
      // Reached the app-specific mounts; nothing root-owned lives past here.
      break;
    if (info.root.starts_with("/adb") ||
        info.target.starts_with("/debug_magisk") || info.source == "magisk" ||
        info.source == "KSU" || info.source == "APatch") {
      LOGD("Found root mounting points");
      sus_mount.emplace_back(info);
      break;
    }
  }

  // The peer-group consistency check (a gap in the shared:N / master:N id run) now
  // lives in the shared reconciliation core (Recon::Run, recon.cpp) so it runs
  // identically in the main process, the native probe, and the classic isolated
  // probe -- not just here.
  return sus_mount;
}
} // namespace Mount
