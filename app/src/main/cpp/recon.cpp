#include "recon.hpp"
#include "logging.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <set>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/vfs.h>
#include <unistd.h>
#include <vector>

// This file is linked into libmain (native probe) as well, which has no LOG*.
// Fall back to no-ops when logging.h's macros are absent.
#ifndef LOGD
#define LOGD(...)
#endif
#ifndef LOGI
#define LOGI(...)
#endif

namespace Recon {
namespace {

// ---- filesystem magics (subset that matters for systemless root). Named with a
// k-prefix so they don't collide with the <linux/magic.h> macros of the same fs. ----
constexpr unsigned long kOverlayfs = 0x794c7630;
constexpr unsigned long kTmpfs = 0x01021994;
constexpr unsigned long kExt4 = 0xEF53;
constexpr unsigned long kF2fs = 0xF2F52010;
constexpr unsigned long kErofs = 0xE0F5E1E2;
constexpr unsigned long kSquashfs = 0x73717368;

#ifndef STATX_ATTR_MOUNT_ROOT
#define STATX_ATTR_MOUNT_ROOT 0x00002000
#endif

const char *fs_name(unsigned long t) {
  switch (t) {
  case kOverlayfs:
    return "overlay";
  case kTmpfs:
    return "tmpfs";
  case kExt4:
    return "ext4";
  case kF2fs:
    return "f2fs";
  case kErofs:
    return "erofs";
  case kSquashfs:
    return "squashfs";
  default:
    return "other";
  }
}

// A real mount points at a real filesystem; pseudo/virtual ones are noise for a
// systemless-root hunt and their magics collide across paths.
bool is_real_fs(unsigned long t) {
  return t == kOverlayfs || t == kExt4 || t == kF2fs || t == kErofs ||
         t == kSquashfs || t == kTmpfs;
}

// ---- one parsed mountinfo record (only the fields reconciliation needs) ----
struct MRec {
  int id = 0;
  int parent = 0;
  int master = 0; // peer group this mount is a slave of (0 = none), from master:N
  int shared = 0; // peer group this mount shares (0 = none), from shared:N
  std::string root;
  std::string target;
  std::string type;
};

struct Finding {
  const char *check; // "mount-reconciliation" | "mount-structure"
  std::string path;
  std::string detail;
  bool high; // true => confirmed hidden mount; false => structural anomaly
};

// Parse /proc/self/mountinfo. Field layout (kernel proc.rst):
//   id parent maj:min root target options... - type source superopts
std::vector<MRec> parse_self_mountinfo() {
  std::vector<MRec> out;
  FILE *fp = fopen("/proc/self/mountinfo", "re");
  if (!fp)
    return out;
  char *line = nullptr;
  size_t cap = 0;
  ssize_t n;
  while ((n = getline(&line, &cap, fp)) >= 0) {
    MRec r;
    char root[4096] = {};
    char target[4096] = {};
    int consumed =
        sscanf(line, "%d %d %*d:%*d %4095s %4095s", &r.id, &r.parent, root, target);
    if (consumed < 4)
      continue;
    r.root = root;
    r.target = target;
    // Everything after " - " is type/source/superopts; before it are the optional
    // propagation tokens (shared:N / master:N / propagate_from:N).
    char *dash = strstr(line, " - ");
    if (dash) {
      char type[128] = {};
      if (sscanf(dash + 3, "%127s", type) == 1)
        r.type = type;
      for (char *p = line; p < dash; ++p) {
        if (strncmp(p, "master:", 7) == 0)
          r.master = atoi(p + 7);
        else if (strncmp(p, "shared:", 7) == 0)
          r.shared = atoi(p + 7);
      }
    }
    out.push_back(std::move(r));
  }
  free(line);
  fclose(fp);
  return out;
}

// statx wrapper via raw syscall so we don't depend on the NDK libc version.
bool statx_mount_root(const char *path, bool &is_mount, bool &supported) {
  struct statx stx;
  memset(&stx, 0, sizeof(stx));
  long rc = syscall(SYS_statx, AT_FDCWD, path,
                    AT_NO_AUTOMOUNT | AT_SYMLINK_NOFOLLOW, STATX_BASIC_STATS,
                    &stx);
  if (rc != 0)
    return false; // path not statable (missing / no permission)
  supported = (stx.stx_attributes_mask & STATX_ATTR_MOUNT_ROOT) != 0;
  is_mount = (stx.stx_attributes & STATX_ATTR_MOUNT_ROOT) != 0;
  return true;
}

// Fallback mount-point test: a path whose device differs from its parent dir is
// a mount root. (Bind mounts across partitions differ in st_dev too.)
bool stdev_is_mount(const char *path) {
  struct stat a, b;
  if (stat(path, &a) != 0)
    return false;
  std::string parent(path);
  auto slash = parent.find_last_of('/');
  if (slash == std::string::npos || slash == 0)
    return false;
  parent.resize(slash);
  if (stat(parent.c_str(), &b) != 0)
    return false;
  return a.st_dev != b.st_dev;
}

unsigned long statfs_magic(const char *path) {
  struct statfs sfs;
  if (statfs(path, &sfs) != 0)
    return 0;
  return static_cast<unsigned long>(sfs.f_type);
}

// The probe set is deliberately small: only the paths root modules actually graft
// onto. Confirmed against a rooted device's /proc/1/mountinfo -- module footprints
// are either single-file binds (e.g. a hosts file) or systemless overlays on a
// fixed set of partition subdirs. We do NOT enumerate every dir under /system: a
// stat per path is a syscall, and a probe on a path nothing ever mounts is wasted.
void build_probe_set(std::vector<std::string> &paths) {
  static const char *curated[] = {
      // --- single-file bind mounts (seen active; hiders erase the record) ---
      // AD-blocking / hosts modules (AdAway, bindhosts) bind a custom hosts file.
      "/system/etc/hosts",
      // NOTE: dex2oat (LSPosed/Vector's ART-compile hook) is intentionally NOT
      // probed. Its files are labelled dex2oat_exec, which SELinux denies apps
      // (and isolated processes) getattr on -- statx/statfs always EACCES, so the
      // probe can never succeed and only emits avc-denial spam. It is also absent
      // from the app's own namespace. dex2oat hiding needs a non-stat vector.
      // --- systemless overlay targets (KSU/Magisk re-host these subdirs) ---
      "/system",          "/system/etc",   "/system/app",
      "/system/priv-app", "/system/framework", "/system/fonts",
      "/system/lib64",    "/system_ext/etc", "/product/etc",
      "/product/overlay", "/product/priv-app", "/vendor/etc",
      "/vendor/overlay",
  };
  std::set<std::string> seen;
  for (const char *c : curated) {
    if (seen.insert(c).second)
      paths.push_back(c);
  }
}

std::string jesc(const std::string &in) {
  std::string o;
  for (char c : in) {
    if (c == '"' || c == '\\') {
      o += '\\';
      o += c;
    } else if ((unsigned char)c < 0x20) {
      o += ' ';
    } else {
      o += c;
    }
  }
  return o;
}

// Single-file bind targets we always report a raw probe outcome for, so a false
// negative is diagnosable from the report, and where an f2fs (userdata) backing fs
// is proof of a module bind regardless of the STATX_ATTR_MOUNT_ROOT attribute.
bool is_diag_target(const std::string &p) {
  return p == "/system/etc/hosts";
}

void collect(std::vector<Finding> &findings, std::string &diag) {
  std::vector<MRec> recs = parse_self_mountinfo();

  // Index by mount id and by target path.
  std::set<int> ids;
  std::set<std::string> targets;
  for (const MRec &r : recs) {
    ids.insert(r.id);
    targets.insert(r.target);
  }

  // --- structural: erasing an interior record orphans its children. Every
  // non-root mount's parent must appear in the same file; exactly one mount (the
  // namespace root, target "/") may reference a parent from the outer namespace.
  for (const MRec &r : recs) {
    if (r.target == "/")
      continue;
    if (ids.find(r.parent) == ids.end()) {
      findings.push_back({"mount-structure", r.target,
                          "parent mount id " + std::to_string(r.parent) +
                              " absent (record erased between root and here)",
                          true});
      LOGD("recon: orphaned mount %s parent=%d", r.target.c_str(), r.parent);
    }
  }

  // --- peer-group consistency: the kernel numbers peer groups (mnt_group_id) from
  // a global counter, and a namespace's mountinfo references a GAP-FREE run of them
  // (verified on a device: ids 1..51 with no holes). The SAME group appears as
  // shared:N in a master/global view (e.g. init, the zygote_next probe) and as
  // master:N in a slave view (an app) -- so we collect the id regardless of role.
  // If a hider erases the last mount that referenced group N, N disappears and the
  // set gains a hole: a mount was unmounted/hidden from this view. Reads only
  // mountinfo, so it works even where the hidden path itself is unreachable.
  {
    std::set<int> groups;
    for (const MRec &r : recs) {
      // Skip app-private mounts, whose peer groups need not join the global run.
      if (r.target.rfind("/data/data", 0) == 0 ||
          r.target.rfind("/data/user", 0) == 0 ||
          r.root.find("org.matrix.demo") != std::string::npos)
        continue;
      if (r.shared > 0)
        groups.insert(r.shared);
      if (r.master > 0)
        groups.insert(r.master);
    }
    // Start from the lowest id actually present, not a hardcoded 1: the kernel's
    // global counter need not begin this namespace's groups at 1, and a missing
    // endpoint is a numbering artefact, not hiding. Only an INTERIOR hole -- an id
    // that vanished from an otherwise contiguous run -- means a group's last member
    // was erased from the view.
    int expected = groups.empty() ? 0 : *groups.begin();
    for (int g : groups) { // std::set iterates ascending
      if (g > expected) {
        findings.push_back(
            {"mount-structure", "peer-group:" + std::to_string(expected),
             "peer group " + std::to_string(expected) +
                 " is absent from the mount table (its last member was "
                 "unmounted/hidden from this view)",
             true});
        LOGD("recon: peer group %d missing (next present is %d)", expected, g);
        break;
      }
      expected = g + 1;
    }
  }

  // --- reconciliation: kernel stat vs mountinfo text.
  std::vector<std::string> probes;
  build_probe_set(probes);
  for (const std::string &p : probes) {
    bool is_mount = false, supported = false;
    bool statx_ok = statx_mount_root(p.c_str(), is_mount, supported);
    // Existence and mount-point ground truth via stat() -- a DIFFERENT syscall to
    // statx, so it can still answer when statx is unavailable/blocked.
    bool exists = statx_ok ||
                  faccessat(AT_FDCWD, p.c_str(), F_OK, AT_SYMLINK_NOFOLLOW) == 0;
    bool kernel_mount = statx_ok && supported ? is_mount
                        : exists              ? stdev_is_mount(p.c_str())
                                              : false;
    unsigned long magic = exists ? statfs_magic(p.c_str()) : 0;
    bool in_mountinfo = targets.find(p) != targets.end();

    // Record the raw outcome for the high-value single-file targets, so a miss is
    // visible (reachable? mount root? what fs? in mountinfo?) instead of silent.
    if (is_diag_target(p)) {
      if (!diag.empty())
        diag += ",";
      diag += "{\"path\":\"" + jesc(p) + "\",\"exists\":" +
              (exists ? "true" : "false") + ",\"statx\":" +
              (statx_ok ? "true" : "false") + ",\"mountRoot\":" +
              (kernel_mount ? "true" : "false") + ",\"fs\":\"" + fs_name(magic) +
              "\",\"inMountinfo\":" + (in_mountinfo ? "true" : "false") + "}";
    }

    if (in_mountinfo)
      continue; // visible -> not hidden

    // Two independent signals that a record was erased:
    //  (a) the kernel says P is a mount root but mountinfo omits it;
    //  (b) P is a single-file bind whose backing fs is f2fs -- the userdata fs.
    //      Nothing under /system legitimately lives on userdata, so a module bind
    //      is the only explanation. Catches a hidden hosts bind even when
    //      STATX_ATTR_MOUNT_ROOT is unavailable, as long as statfs is reachable.
    bool hidden_mount = kernel_mount && is_real_fs(magic);
    bool data_bind = is_diag_target(p) && magic == kF2fs;
    if (!hidden_mount && !data_bind)
      continue;

    findings.push_back(
        {"mount-reconciliation", p,
         std::string("kernel reports a ") + fs_name(magic) +
             " mount here, but it is absent from mountinfo (hidden record)",
         true});
    LOGI("recon: HIDDEN mount at %s (%s) not in mountinfo", p.c_str(),
         fs_name(magic));
  }
}

std::string to_json(const std::vector<Finding> &findings, const std::string &diag,
                    int &hidden, int &structural) {
  hidden = 0;
  structural = 0;
  std::string arr;
  bool first = true;
  for (const Finding &f : findings) {
    if (strcmp(f.check, "mount-reconciliation") == 0)
      hidden++;
    else
      structural++;
    if (!first)
      arr += ",";
    first = false;
    arr += "{\"check\":\"";
    arr += f.check;
    arr += "\",\"path\":\"";
    arr += jesc(f.path);
    arr += "\",\"detail\":\"";
    arr += jesc(f.detail);
    arr += "\",\"severity\":\"";
    arr += f.high ? "high" : "med";
    arr += "\"}";
  }
  std::string json = "{\"hidden\":" + std::to_string(hidden) +
                     ",\"structural\":" + std::to_string(structural) +
                     ",\"findings\":[" + arr + "],\"probes\":[" + diag + "]}";
  return json;
}

} // namespace

Result Run() {
  std::vector<Finding> findings;
  std::string diag;
  collect(findings, diag);
  Result r;
  r.json = to_json(findings, diag, r.hidden, r.structural);
  return r;
}

} // namespace Recon

extern "C" int recon_run_json(char *out, size_t cap) {
  Recon::Result r = Recon::Run();
  if (out && cap) {
    strncpy(out, r.json.c_str(), cap - 1);
    out[cap - 1] = '\0';
  }
  // Total high-signal findings (hidden mounts + structural anomalies) so a caller
  // that only reads the int still reacts to a structural-only hide.
  return r.hidden + r.structural;
}

// JNI entry for the classic isolated Java probe (ProcScanner). Returns the same
// reconciliation JSON object as a string.
#include <jni.h>
extern "C" JNIEXPORT jstring JNICALL
Java_org_matrix_demo_ProcScanner_nativeReconcile(JNIEnv *env, jclass) {
  Recon::Result r = Recon::Run();
  return env->NewStringUTF(r.json.c_str());
}
