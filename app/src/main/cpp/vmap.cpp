#include "vmap.hpp"
#include "logging.h"
#include <cinttypes>
#include <cstring>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <vector>

namespace VirtualMap {

void logPossibleStrings(const char *start, size_t size,
                        size_t min_string_length = 4) {
  const char *end = start + size;
  const char *ptr = start;

  LOGD("--- Starting String Dump (min length: %zu, range size: %zu) ---",
       min_string_length, size);

  while (ptr < end) {
    // Find the beginning of a potential string (a printable character)
    if (isprint(static_cast<unsigned char>(*ptr))) {
      const char *string_start = ptr;
      const char *string_end = ptr + 1;

      // Find the end of the sequence of printable characters
      while (string_end < end &&
             isprint(static_cast<unsigned char>(*string_end))) {
        string_end++;
      }

      size_t length = string_end - string_start;

      // If the sequence meets our minimum length, log it
      if (length >= min_string_length) {
        // Safely create a std::string from the non-null-terminated segment
        std::string found_str(string_start, length);

        // Log the string and its memory offset using LOGD's format string
        LOGI("Offset 0x%zx: \"%s\"", (size_t)(string_start - start),
             found_str.c_str());
      }

      // Advance the main pointer past the sequence we just processed
      ptr = string_end;
    } else {
      // Not a printable character, just move to the next byte
      ptr++;
    }
  }
  LOGD("--- Finished String Dump ---");
}

void DumpStackStrings() {
  for (auto &map : MapInfo::Scan()) {
    if (map.dev == 0 && map.inode == 0 && map.offset == 0 &&
        map.path == "[anon:stack_and_tls:main]") {
      logPossibleStrings(reinterpret_cast<const char *>(map.start),
                         map.end - map.start, 3);
    }
  }
}

MapInfo *DetectInjection() {
  int jit_cache_count = 0;
  int jit_zygote_cache_count = 0;

  for (auto &info : MapInfo::Scan()) {
    if (info.perms & PROT_EXEC) {
      // Executable memory blocks are suspicious
      if (info.path == "[vdso]")
        continue;

      if (!info.path.starts_with("/")) {
        LOGI("Executable block with path %s", info.path.data());
        return &info;
      }

      if (info.path.starts_with("/dev/zero")) {
        LOGI("Shared anonymous executable block found");
        return &info;
      }

      if (info.path.starts_with("/memfd:jit-cache")) {
        jit_cache_count++;
      } else if (info.path.starts_with("/memfd:jit-zygote-cache")) {
        jit_zygote_cache_count++;
      } else {
        LOGD("Checking inode for %s", info.path.c_str());
        struct stat sb_buf;
        if (stat(info.path.data(), &sb_buf) != 0 ||
            sb_buf.st_ino != info.inode) {
          LOGI("Executable block with inconsistent inode %s", info.path.data());
          return &info;
        }
      }

      if (jit_cache_count > 1 || jit_zygote_cache_count > 1) {
        LOGI("Futile renaming to jit blocks");
        return &info;
      }
    }
  }

  return nullptr;
}

std::vector<MapInfo> MapInfo::Scan() {
  constexpr static auto kPermLength = 5;
  constexpr static auto kMapEntry = 7;
  std::vector<MapInfo> info;
  auto maps = std::unique_ptr<FILE, decltype(&fclose)>{
      fopen("/proc/self/maps", "r"), &fclose};
  if (maps) {
    char *line = nullptr;
    size_t len = 0;
    ssize_t read;
    while ((read = getline(&line, &len, maps.get())) > 0) {
      line[read - 1] = '\0';
      uintptr_t start = 0;
      uintptr_t end = 0;
      uintptr_t off = 0;
      ino_t inode = 0;
      unsigned int dev_major = 0;
      unsigned int dev_minor = 0;
      std::array<char, kPermLength> perm{'\0'};
      int path_off;
      if (sscanf(line,
                 "%" PRIxPTR "-%" PRIxPTR " %4s %" PRIxPTR " %x:%x %lu %n%*s",
                 &start, &end, perm.data(), &off, &dev_major, &dev_minor,
                 &inode, &path_off) != kMapEntry) {
        continue;
      }
      while (path_off < read && isspace(line[path_off]))
        path_off++;
      auto &ref = info.emplace_back(
          MapInfo{start, end, 0, perm[3] == 'p', off,
                  static_cast<dev_t>(makedev(dev_major, dev_minor)), inode,
                  line + path_off});
      if (perm[0] == 'r')
        ref.perms |= PROT_READ;
      if (perm[1] == 'w')
        ref.perms |= PROT_WRITE;
      if (perm[2] == 'x')
        ref.perms |= PROT_EXEC;
    }
    free(line);
  }
  return info;
}

} // namespace VirtualMap
