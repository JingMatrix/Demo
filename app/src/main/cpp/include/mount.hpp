#include <functional>
#include <string>
#include <sys/types.h>
namespace Mount {
using sFILE = std::unique_ptr<FILE, decltype(&fclose)>;
sFILE MakeFile(FILE *fp);

struct MountInfo {
  unsigned int id;
  unsigned int parent;
  dev_t device;
  std::string root;
  std::string target;
  std::string vfs_option;
  struct {
    unsigned int shared;
    unsigned int master;
    unsigned int propagate_from;
  } optional;
  std::string type;
  std::string source;
  std::string fs_option;
};

void ReadLine(bool trim, FILE *fp,
              const std::function<bool(std::string_view)> &fn);
void ReadLine(bool trim, const char *file,
              const std::function<bool(std::string_view)> &fn);
void ReadLine(const char *file,
              const std::function<bool(std::string_view)> &fn);
int ParseInt(std::string_view s);
std::vector<MountInfo> ParseMountInfo(const char *pid);
std::vector<MountInfo> DetectInjection();
} // namespace Mount
