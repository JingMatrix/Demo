#include "recon.hpp"
#include "logging.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <map>
#include <set>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/vfs.h>
#include <unistd.h>
#include <vector>

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
  int maj = -1;   // field 3 of mountinfo: the superblock's dev_t...
  int min = -1;   // ...maj 0 means an anonymous dev from get_anon_bdev()
  int master = 0; // peer group this mount is a slave of (0 = none), from master:N
  int shared = 0; // peer group this mount shares (0 = none), from shared:N
  std::string root;
  std::string target;
  std::string type;
};

struct Finding {
  // The hidden/structural split is carried here, not by `high`: to_json counts a
  // finding as hidden iff its check is "mount-reconciliation".
  const char *check; // "mount-reconciliation" | "mount-structure" | "mount-anon-dev"
  std::string path;
  std::string detail;
  bool high; // reported severity; every finding this file raises is high-signal
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
    int consumed = sscanf(line, "%d %d %d:%d %4095s %4095s", &r.id, &r.parent,
                          &r.maj, &r.min, root, target);
    if (consumed < 6)
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
  if (slash == std::string::npos)
    return false;
  // A top-level probe target ("/system") has "/" as its parent, not "". Bailing out
  // here left every depth-1 overlay target -- the ones a systemless root actually
  // re-hosts -- with no fallback at all when statx cannot answer.
  parent.resize(slash == 0 ? 1 : slash);
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

// ---- anonymous block-device minors -----------------------------------------
// Filesystems with no real block device -- tmpfs, fuse, proc, sysfs, cgroup,
// functionfs, incremental-fs -- draw their dev_t from ONE kernel-global pool:
// fs/super.c get_anon_bdev() calls ida_alloc_range(&unnamed_dev_ida, 1, ...),
// which returns the LOWEST free id, and the id is held for the superblock's whole
// lifetime, released only by kill_anon_super() -> free_anon_bdev().
//
// Two consequences, and together they are the check. The live set is dense from
// below, so a minor missing from OUR mountinfo is not a free slot: it is a
// superblock that is alive but invisible from here. And the pool is global to the
// kernel rather than per namespace -- a private mount namespace hides the MOUNT,
// never the superblock -- so a root daemon keeping a tmpfs in a namespace of its
// own still spends a minor and still leaves the hole, with no cooperation from
// mountinfo at all. (Bind mounts share a superblock and allocate nothing, so a
// hide built purely from binds does not surface here; it is the worker tmpfs or
// overlay that leaks.)

// A path's anonymous-device minor, straight from the kernel. Like the statx probe
// above, stat() does not travel the mountinfo seq_file path that a hider filters,
// so the window's endpoints cannot be moved by editing the mount table.
bool stat_anon_minor(const char *path, int &out) {
  struct stat st;
  if (stat(path, &st) != 0)
    return false;
  if (major(st.st_dev) != 0)
    return false; // backed by a real block device: not from the anon pool
  out = static_cast<int>(minor(st.st_dev));
  return true;
}

// This process's package name, from argv[0] of /proc/self/cmdline. Used only to
// reach the app's own external-storage directory, which every app may stat
// without holding a storage permission.
std::string self_package() {
  char buf[256] = {};
  FILE *fp = fopen("/proc/self/cmdline", "re");
  if (!fp)
    return {};
  size_t n = fread(buf, 1, sizeof(buf) - 1, fp);
  fclose(fp);
  if (n == 0)
    return {};
  std::string s(buf); // cmdline is NUL-separated; this takes argv[0]
  if (auto colon = s.find(':'); colon != std::string::npos)
    s.resize(colon); // "pkg:probe" -> "pkg"
  return s;
}

// installd hands every app PROCESS its own tmpfs for /data/data, /data/user,
// /data/user_de and the two profile dirs. They are allocated and freed as apps
// come and go, and the ones belonging to other apps are invisible here by design
// -- noise for the peer-group run and the anonymous-device run alike, so both
// exclude them. (Their children are binds onto userdata, major 254, and never
// enter the anonymous pool at all.)
bool is_app_private(const MRec &r, const std::string &pkg) {
  return r.target.rfind("/data/data", 0) == 0 ||
         r.target.rfind("/data/user", 0) == 0 ||
         r.target.rfind("/data/misc/profiles", 0) == 0 ||
         // Only match the root against a package-shaped name: in the native
         // probe argv[0] is a process name, and a short generic token would
         // match roots that have nothing to do with this app.
         (pkg.find('.') != std::string::npos &&
          r.root.find(pkg) != std::string::npos);
}

// The window to scan. Both endpoints come from stat(), never from mountinfo.
//
// FLOOR. Minor order is not boot order once anything has been freed. AOSP's first
// stage (system/core/init/first_stage_init.cpp) mounts /dev, /dev/pts, /proc,
// /sys, /mnt, /debug_ramdisk and /second_stage_resources and then loads kernel
// modules; second stage (init.cpp SecondStageMain) umounts /debug_ramdisk and
// /second_stage_resources and only afterwards calls MountExtraFilesystems(),
// whose /apex and /bootstrap-apex land in those two RECYCLED minors. So a
// pseudo-filesystem that a module loaded in between pinned with simple_pin_fs()
// -- drm_fs_inode_new() is the usual one -- keeps its minor for good while
// appearing in no mountinfo on the device, and that stretch legitimately contains
// holes. Everything below the floor is therefore out of scope.
//
// /tmp (init.rc, "on early-init") is the first mount past that whole window that
// an app can also stat. /linkerconfig would do on timing but is denied to
// untrusted_app, so its minor is readable only from mountinfo -- the very text
// this check exists to distrust. /tmp is Android 15+; /dev/cpuset and
// /sys/fs/cgroup come from CgroupSetup(), which also runs after
// MountExtraFilesystems(), and cover the older releases.
//
// CEILING. The fuse superblock behind /storage/emulated, which is created once at
// user start and so sits above every boot-time mount. It is an upper bound, not
// the end of the scan: the per-app churn region can reach BELOW it (this app's own
// tmpfs were seen at 0:131..135 with the fuse sb at 0:206), which is why the scan
// set also drops app-private mounts and then only reports INTERIOR holes. What is
// actually checked is the run of boot-era minors, and it ends at the last one this
// namespace can see.
bool anon_window(int &floor, std::string &floor_path, int &ceil,
                 std::string &ceil_path) {
  static const char *kFloors[] = {"/tmp", "/dev/cpuset", "/sys/fs/cgroup"};
  bool have_floor = false;
  for (const char *p : kFloors) {
    int m = 0;
    if (!stat_anon_minor(p, m))
      continue;
    if (!have_floor || m > floor) {
      floor = m;
      floor_path = p;
      have_floor = true;
    }
  }
  if (!have_floor)
    return false;

  std::vector<std::string> ceilings = {
      "/storage/emulated/0/Android/data/.nomedia",
      "/storage/emulated/0/Android/obb/.nomedia"};
  if (std::string own = self_package(); !own.empty())
    ceilings.push_back("/storage/emulated/0/Android/data/" + own);
  ceilings.push_back("/storage/emulated/0");
  ceilings.push_back("/storage/emulated");
  for (const std::string &p : ceilings) {
    int m = 0;
    if (stat_anon_minor(p.c_str(), m)) {
      ceil = m;
      ceil_path = p;
      return ceil > floor;
    }
  }
  // No external storage in this namespace: an isolated process sees none, so the
  // check simply does not run there rather than guessing a ceiling.
  return false;
}

// At most this many hole findings; a run of missing minors is one finding, and
// past a handful the report says nothing more than the first few already did.
constexpr int kMaxAnonHoles = 4;

// A run longer than this is REPORTED but not COUNTED as a detection. A hider
// spends one anonymous minor per worker superblock it keeps alive outside our
// namespace -- one to a few. A long run is the signature of something we simply
// cannot see into: the per-app tmpfs churn region, where the zygote takes five
// minors per app process (isolateAppData / isolateJitProfile), all of them in
// other namespaces. The floor and the app-private filter already keep that region
// out of the set in the cases we know about; this is the backstop for the ones we
// do not, so an unfamiliar device shape degrades to a low-confidence note instead
// of a false accusation.
constexpr int kWideAnonRun = 10;

void anon_dev_gaps(const std::vector<MRec> &recs, const std::string &pkg,
                   std::vector<Finding> &findings, std::string &window) {
  int floor = 0, ceil = 0;
  std::string floor_path, ceil_path;
  if (!anon_window(floor, floor_path, ceil, ceil_path)) {
    LOGD("recon: anon-dev window unavailable (no floor or no storage), skipping");
    return;
  }

  // Visible minors in the window, each with the mount that owns it, so a hole is
  // reported with the neighbours it sits between: position is what separates a
  // daemon's private tmpfs from an ordinary boot-time mount.
  std::map<int, std::string> present;
  for (const MRec &r : recs) {
    if (r.maj != 0 || r.min <= floor || r.min >= ceil)
      continue;
    if (is_app_private(r, pkg))
      continue;
    present.emplace(r.min, r.target);
  }

  int holes = 0; // counted: runs short enough to be a hidden mount
  int wide = 0;  // reported only: runs too long to attribute
  if (present.size() >= 2) {
    int expected = present.begin()->first;
    const std::string *prev = &present.begin()->second;
    for (const auto &entry : present) {
      int m = entry.first;
      if (m > expected) {
        const int len = m - expected;
        const bool too_wide = len > kWideAnonRun;
        std::string range = (len == 1) ? std::to_string(expected)
                                       : std::to_string(expected) + "-" +
                                             std::to_string(m - 1);
        std::string detail =
            "anonymous device minor " + range +
            " is allocated but no mount in this namespace uses it -- the kernel "
            "hands these out lowest-free-first, so it is a live superblock "
            "hidden from this view (between 0:" + std::to_string(expected - 1) +
            " " + *prev + " and 0:" + std::to_string(m) + " " + entry.second +
            ")";
        if (too_wide)
          detail += "; a run of " + std::to_string(len) +
                    " is far wider than the one or two superblocks a hidden "
                    "mount costs and matches per-app tmpfs churn (5 minors per "
                    "app process), so this is listed but not counted";
        findings.push_back(
            {"mount-anon-dev", "anon-dev:" + range, detail, !too_wide});
        LOGI("recon: anon dev minor(s) %s missing between %s and %s%s",
             range.c_str(), prev->c_str(), entry.second.c_str(),
             too_wide ? " (too wide to attribute, not counted)" : "");
        if (too_wide)
          ++wide;
        else
          ++holes;
        if (holes + wide >= kMaxAnonHoles)
          break;
      }
      expected = m + 1;
      prev = &entry.second;
    }
  }

  LOGD("recon: anon-dev window %s 0:%d .. %s 0:%d, %zu visible, %d hole(s), %d "
       "wide run(s)",
       floor_path.c_str(), floor, ceil_path.c_str(), ceil, present.size(), holes,
       wide);

  window = "{\"floor\":" + std::to_string(floor) + ",\"floorPath\":\"" +
           jesc(floor_path) + "\",\"ceil\":" + std::to_string(ceil) +
           ",\"ceilPath\":\"" + jesc(ceil_path) +
           "\",\"visible\":" + std::to_string(present.size()) +
           ",\"holes\":" + std::to_string(holes) + ",\"wide\":" +
           std::to_string(wide) + "}";
}

void collect(std::vector<Finding> &findings, std::string &diag,
             std::string &window) {
  std::vector<MRec> recs = parse_self_mountinfo();
  const std::string pkg = self_package();

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
      if (is_app_private(r, pkg))
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

  // --- anonymous-device continuity: the only check here that sees mounts living
  // outside this namespace entirely, because the dev_t pool they draw from is
  // kernel-global while the mount table is not.
  anon_dev_gaps(recs, pkg, findings, window);

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
                    const std::string &window, int &hidden, int &structural) {
  hidden = 0;
  structural = 0;
  std::string arr;
  bool first = true;
  for (const Finding &f : findings) {
    // A finding raised at "med" is evidence too weak to accuse on: it goes into
    // the findings array and the report table, but drives neither counter, so it
    // cannot on its own turn the verdict to DETECTED.
    if (!f.high)
      ;
    else if (strcmp(f.check, "mount-reconciliation") == 0)
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
                     ",\"findings\":[" + arr + "],\"probes\":[" + diag +
                     "],\"anonDev\":" + (window.empty() ? "null" : window) + "}";
  return json;
}

} // namespace

Result Run() {
  std::vector<Finding> findings;
  std::string diag, window;
  collect(findings, diag, window);
  Result r;
  r.json = to_json(findings, diag, window, r.hidden, r.structural);
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
