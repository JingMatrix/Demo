#include <cstdint>
#include <string>
namespace VirtualMap {

struct MapInfo {
  /// \brief The start address of the memory region.
  uintptr_t start;
  /// \brief The end address of the memory region.
  uintptr_t end;
  /// \brief The permissions of the memory region. This is a bit mask of the
  /// following values:
  /// - PROT_READ
  /// - PROT_WRITE
  /// - PROT_EXEC
  uint8_t perms;
  /// \brief Whether the memory region is private.
  bool is_private;
  /// \brief The offset of the memory region.
  uintptr_t offset;
  /// \brief The device number of the memory region.
  /// Major can be obtained by #major()
  /// Minor can be obtained by #minor()
  dev_t dev;
  /// \brief The inode number of the memory region.
  ino_t inode;
  /// \brief The path of the memory region.
  std::string path;

  /// \brief Scans /proc/self/maps and returns a list of \ref MapInfo entries.
  /// This is useful to find out the inode of the library to hook.
  /// \return A list of \ref MapInfo entries.
  [[maybe_unused, gnu::visibility("default")]] static std::vector<MapInfo>
  Scan();
};

MapInfo *DetectInjection();

void DumpStackStrings();
} // namespace VirtualMap
