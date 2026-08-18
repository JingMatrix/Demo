package org.matrix.demo;

import android.os.Process;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;

/**
 * The wide-radius cross-process mount scanner (Privisolated technique, extended).
 *
 * <p>Runs inside the classic isolated service. Because a classic isolated process
 * inherits zygote's AID_READPROC, it can traverse and read every process's
 * {@code /proc/<pid>/{mountinfo,mounts,mountstats}}. This scanner reads all three
 * for every visible PID and then runs several independent leak analyses:
 * <ul>
 *   <li>marker scan over every field of every record;
 *   <li>the Privisolated differential (distinct views vs propagation classes) run
 *       separately for each of the three files;
 *   <li>a cross-file differential (a mount present in mountinfo but not mounts, or
 *       vice versa — catches a filter that only patches one of the three);
 *   <li>self-vs-init symmetric diff (the global view a filter cannot unmount);
 *   <li>mount-count and namespace-inode grouping.
 * </ul>
 *
 * <p>Everything is logged verbatim to logcat (tag {@code DemoProbe}); the JSON
 * handed back over binder is a bounded summary sized to stay under the ~1&nbsp;MB
 * transaction limit.
 */
final class ProcScanner {

    static final String TAG = "DemoProbe";
    private static final int JSON_BUDGET = 700_000;   // keep well under binder 1MB
    private static final int MAX_FULL_VIEWS = 10;      // full record dumps in JSON
    private static final int MAX_LINES_PER_VIEW = 400;

    private ProcScanner() {
    }

    // Progress log mirrored into the JSON ("log" array) so the app can show it on a
    // Logs page. Milestones only (not the per-record dumps), to stay small.
    private static List<String> gLog = new ArrayList<>();

    private static void plog(String s) {
        gLog.add(s);
        Log.i(TAG, s);
    }

    private static void pwarn(String s) {
        gLog.add(s);
        Log.w(TAG, s);
    }

    // ---- one scanned process ----
    private static final class Proc {
        int pid;
        String comm = "?";
        String cmdline = "";
        int uid = -1;
        long nsMnt;
        String propagation = "";
        final Map<String, FileView> files = new LinkedHashMap<>();
    }

    private static final class FileView {
        boolean readable;
        String error = "";
        int lineCount;
        List<String> lines = Collections.emptyList();  // raw
        String normalized = "";                         // sorted normalized keys, for view-equality
        List<String> normalizedLines = Collections.emptyList();  // Privisolated-style keys
        final List<Markers.Hit> hits = new ArrayList<>();
        final List<String> hitLines = new ArrayList<>();
    }

    static JSONObject scan(String technique) {
        long t0 = System.currentTimeMillis();
        gLog = new ArrayList<>();
        plog("SCAN START (" + technique + ")");

        JSONObject out = new JSONObject();
        try {
            out.put("technique", technique);
            out.put("apiTimeMs", 0);

            // ---- self identity ----
            int selfPid = Process.myPid();
            JSONObject self = new JSONObject();
            self.put("pid", selfPid);
            self.put("uid", Process.myUid());
            self.put("isolated", Process.isIsolated());
            boolean readproc = hasReadproc(selfPid);
            self.put("hasReadproc", readproc);
            self.put("nsMnt", readNsInode("/proc/self/ns/mnt"));
            self.put("proc1Readable", isReadable("/proc/1/comm"));
            self.put("selfPropagation", propagationOf("/proc/self/mountinfo"));
            out.put("self", self);
            plog("SELF pid=" + selfPid + " uid=" + Process.myUid()
                    + " isolated=" + Process.isIsolated() + " readproc(3009)=" + readproc
                    + " nsMnt=" + readNsInode("/proc/self/ns/mnt")
                    + " proc1Readable=" + isReadable("/proc/1/comm"));

            // ---- enumerate & read every visible pid ----
            List<Proc> procs = new ArrayList<>();
            int visible = 0;
            int readable = 0;
            try (var stream = Files.newDirectoryStream(Path.of("/proc"))) {
                for (Path p : stream) {
                    String name = p.getFileName().toString();
                    if (!isNumeric(name)) {
                        continue;
                    }
                    visible++;
                    Proc proc = readProc(name);
                    if (proc != null) {
                        procs.add(proc);
                        if (proc.files.get("mountinfo") != null
                                && proc.files.get("mountinfo").readable) {
                            readable++;
                        }
                    }
                }
            }
            procs.sort((a, b) -> Integer.compare(a.pid, b.pid));
            out.put("visiblePids", visible);
            out.put("readableMountinfoPids", readable);
            plog("ENUMERATION: visiblePids=" + visible
                    + " readableMountinfoPids=" + readable
                    + "  (few readable => hidepid intact; many => AID_READPROC leak active)");

            // ---- analyses ----
            JSONArray markerSummary = markerSummary(procs);
            out.put("markerHits", markerSummary);

            out.put("differential", differentialByFile(procs));
            out.put("crossFile", crossFileDiff(procs));
            out.put("selfVsInit", selfVsInit(procs, selfPid));
            out.put("namespaceGroups", namespaceGroups(procs));
            out.put("fileAccess", probeFileAccess(procs, selfPid));
            out.put("fileAccessAggregate", aggregateFileAccess(procs));

            // full record dumps for the interesting pids (bounded)
            out.put("processes", processDump(procs, selfPid, markerSummary));

            out.put("verdict", buildVerdict(out));

            out.put("apiTimeMs", System.currentTimeMillis() - t0);
        } catch (Exception e) {
            Log.e(TAG, "scan failed", e);
            try {
                out.put("error", Log.getStackTraceString(e));
            } catch (JSONException ignored) {
            }
        }

        String rendered = out.toString();
        if (rendered.length() > JSON_BUDGET) {
            Log.w(TAG, "JSON " + rendered.length() + " bytes exceeds budget; trimming record dumps");
            try {
                out.remove("processes");
                out.put("trimmed", true);
            } catch (JSONException ignored) {
            }
        }
        plog("SCAN END " + (System.currentTimeMillis() - t0) + "ms");
        try {
            out.put("log", new JSONArray(gLog));
        } catch (JSONException ignored) {
        }
        return out;
    }

    // ------------------------------------------------------------------
    // per-process read
    // ------------------------------------------------------------------
    private static Proc readProc(String pid) {
        Proc proc = new Proc();
        proc.pid = Integer.parseInt(pid);
        proc.comm = readTrim("/proc/" + pid + "/comm");
        proc.cmdline = readCmdline("/proc/" + pid + "/cmdline");
        proc.uid = readUid("/proc/" + pid + "/status");
        proc.nsMnt = readNsInode("/proc/" + pid + "/ns/mnt");

        for (String file : new String[] {"mountinfo", "mounts", "mountstats"}) {
            FileView v = readMountFile("/proc/" + pid + "/" + file, file);
            proc.files.put(file, v);
        }
        FileView mi = proc.files.get("mountinfo");
        if (mi != null && mi.readable && !mi.lines.isEmpty()) {
            for (String line : mi.lines) {
                try {
                    MountInfo m = MountInfo.parseLine(line);
                    if (m.point.equals("/")) {
                        proc.propagation = m.propagation();
                        break;
                    }
                } catch (RuntimeException ignored) {
                }
            }
        }

        // verbose per-pid log
        StringBuilder fs = new StringBuilder();
        for (Map.Entry<String, FileView> e : proc.files.entrySet()) {
            FileView v = e.getValue();
            fs.append(' ').append(e.getKey()).append('=')
                    .append(v.readable ? (v.lineCount + "L") : ("X[" + v.error + "]"));
            if (!v.hits.isEmpty()) {
                fs.append("!MARK").append(v.hits.size());
            }
        }
        String pidLine = String.format("PID %-6d uid=%-6d ns=%-11d prop=%-9s comm=%-20s%s",
                proc.pid, proc.uid, proc.nsMnt, blank(proc.propagation), proc.comm, fs);
        // only readable processes go into the in-app log; the rest stay in logcat only
        FileView mif = proc.files.get("mountinfo");
        if (mif != null && mif.readable) {
            plog(pidLine);
        } else {
            Log.i(TAG, pidLine);
        }

        // and dump each marker hit line in full
        for (Map.Entry<String, FileView> e : proc.files.entrySet()) {
            FileView v = e.getValue();
            for (int i = 0; i < v.hitLines.size(); i++) {
                Log.w(TAG, "  LEAK pid=" + proc.pid + " file=" + e.getKey()
                        + " :: " + v.hitLines.get(i));
            }
        }
        return proc;
    }

    private static FileView readMountFile(String path, String kind) {
        FileView v = new FileView();
        try (BufferedReader r = Files.newBufferedReader(Path.of(path), StandardCharsets.UTF_8)) {
            List<String> lines = new ArrayList<>();
            String line;
            while ((line = r.readLine()) != null) {
                lines.add(line);
            }
            v.readable = true;
            v.lines = lines;
            v.lineCount = lines.size();

            // Normalize each record to a Privisolated-style key BEFORE comparing views.
            // The real Privisolated builds its key from source+root+point+type+options+
            // superOptions and deliberately omits the mount id, parent id, and the optional
            // (shared:N / master:N) field. Those differ between ANY two separately-unshared
            // namespaces, so comparing raw lines invents differences that no probe sees.
            List<String> keys = new ArrayList<>(lines.size());
            for (String l : lines) {
                keys.add(normalizeKey(l, kind));
            }
            Collections.sort(keys);
            v.normalizedLines = keys;
            v.normalized = String.join("\n", keys);

            for (String l : lines) {
                List<Markers.Hit> hits;
                if (kind.equals("mountinfo")) {
                    try {
                        hits = Markers.scan(MountInfo.parseLine(l));
                    } catch (RuntimeException ex) {
                        hits = Markers.scanRaw(l);
                    }
                } else {
                    hits = Markers.scanRaw(l);
                }
                if (!hits.isEmpty()) {
                    v.hits.addAll(hits);
                    v.hitLines.add(l);
                }
            }
        } catch (IOException e) {
            v.readable = false;
            v.error = e.getClass().getSimpleName();
        }
        return v;
    }

    /**
     * Privisolated's comparison key for one record: the logical mount content only, with
     * the per-namespace-varying mount id / parent id / peer-group fields removed.
     * mountinfo -> "source root point type options superOptions"; mounts -> id-free already,
     * drop the trailing dump/pass; mountstats -> raw (already id-free).
     */
    private static String normalizeKey(String line, String kind) {
        if (kind.equals("mountinfo")) {
            try {
                MountInfo m = MountInfo.parseLine(line);
                return m.source + " " + m.root + " " + m.point + " " + m.type + " "
                        + m.options + " " + m.superOptions;
            } catch (RuntimeException e) {
                return line;
            }
        }
        if (kind.equals("mounts")) {
            String[] p = line.split(" ");
            if (p.length >= 4) {
                return p[0] + " " + p[1] + " " + p[2] + " " + p[3];
            }
        }
        return line;
    }

    // ------------------------------------------------------------------
    // analyses
    // ------------------------------------------------------------------

    /** All HIGH/MEDIUM/LOW hits flattened, deduped by (pid,file,label). */
    private static JSONArray markerSummary(List<Proc> procs) throws JSONException {
        JSONArray arr = new JSONArray();
        TreeSet<String> seen = new TreeSet<>();
        for (Proc p : procs) {
            for (Map.Entry<String, FileView> e : p.files.entrySet()) {
                FileView v = e.getValue();
                for (int i = 0; i < v.hits.size(); i++) {
                    Markers.Hit h = v.hits.get(i);
                    String key = p.pid + "|" + e.getKey() + "|" + h.label + "|" + h.field;
                    if (!seen.add(key)) {
                        continue;
                    }
                    JSONObject o = new JSONObject();
                    o.put("pid", p.pid);
                    o.put("comm", p.comm);
                    o.put("file", e.getKey());
                    o.put("label", h.label);
                    o.put("field", h.field);
                    o.put("confidence", h.confidence);
                    arr.put(o);
                }
            }
        }
        plog("MARKER SUMMARY: " + arr.length() + " distinct (pid,file,label,field) hits");
        return arr;
    }

    /** Privisolated differential, run independently for each of the three files. */
    private static JSONObject differentialByFile(List<Proc> procs) throws JSONException {
        JSONObject out = new JSONObject();
        for (String file : new String[] {"mountinfo", "mounts", "mountstats"}) {
            // group readable pids by their normalized (id-stripped) view
            Map<String, List<Integer>> byView = new LinkedHashMap<>();
            Map<String, List<String>> viewLines = new LinkedHashMap<>();
            int classesMask = 0;
            for (Proc p : procs) {
                FileView v = p.files.get(file);
                if (v == null || !v.readable) {
                    continue;
                }
                byView.computeIfAbsent(v.normalized, k -> new ArrayList<>()).add(p.pid);
                viewLines.putIfAbsent(v.normalized, v.normalizedLines);
                if (p.propagation.startsWith("shared")) {
                    classesMask |= 1;
                } else if (p.propagation.startsWith("master")) {
                    classesMask |= 2;
                }
            }
            int distinct = byView.size();
            int classes = Integer.bitCount(classesMask);
            boolean mismatch = distinct != classes && distinct > 0;

            JSONObject o = new JSONObject();
            o.put("distinctViews", distinct);
            o.put("propagationClasses", classes);
            o.put("mismatch", mismatch);
            JSONArray groups = new JSONArray();
            for (Map.Entry<String, List<Integer>> e : byView.entrySet()) {
                JSONObject g = new JSONObject();
                g.put("pidCount", e.getValue().size());
                g.put("samplePids", new JSONArray(e.getValue().subList(0,
                        Math.min(6, e.getValue().size()))));
                g.put("lineCount", viewLines.get(e.getKey()).size());
                groups.put(g);
            }
            o.put("groups", groups);
            plog("DIFFERENTIAL[" + file + "] distinctViews=" + distinct
                    + " propagationClasses=" + classes + " => "
                    + (mismatch ? "MISMATCH (Privisolated fires)" : "consistent"));

            // When >1 distinct view, log the exact normalized lines that differ between the
            // two largest groups -- this is the precise leak Privisolated keys on.
            if (byView.size() > 1) {
                List<Map.Entry<String, List<Integer>>> big = new ArrayList<>(byView.entrySet());
                big.sort((a, b) -> Integer.compare(b.getValue().size(), a.getValue().size()));
                List<String> a = viewLines.get(big.get(0).getKey());
                List<String> b = viewLines.get(big.get(1).getKey());
                TreeSet<String> onlyA = new TreeSet<>(a);
                b.forEach(onlyA::remove);
                TreeSet<String> onlyB = new TreeSet<>(b);
                a.forEach(onlyB::remove);
                JSONArray da = new JSONArray(new ArrayList<>(onlyA));
                JSONArray db = new JSONArray(new ArrayList<>(onlyB));
                o.put("diffOnlyInGroupA", da);
                o.put("diffOnlyInGroupB", db);
                pwarn("DIFFERENTIAL[" + file + "] groupA(pids " + big.get(0).getValue()
                        + ") vs groupB(pids " + big.get(1).getValue() + "):");
                for (String l : onlyA) {
                    pwarn("  onlyA: " + l);
                }
                for (String l : onlyB) {
                    pwarn("  onlyB: " + l);
                }
            }
            out.put(file, o);
        }
        return out;
    }

    /** For each pid: mountpoints present in mountinfo but not in mounts (and vice versa). */
    private static JSONArray crossFileDiff(List<Proc> procs) throws JSONException {
        JSONArray arr = new JSONArray();
        for (Proc p : procs) {
            FileView mi = p.files.get("mountinfo");
            FileView mo = p.files.get("mounts");
            if (mi == null || mo == null || !mi.readable || !mo.readable) {
                continue;
            }
            TreeSet<String> miPoints = mountinfoPoints(mi.lines);
            TreeSet<String> moPoints = mountsPoints(mo.lines);
            TreeSet<String> onlyMi = new TreeSet<>(miPoints);
            onlyMi.removeAll(moPoints);
            TreeSet<String> onlyMo = new TreeSet<>(moPoints);
            onlyMo.removeAll(miPoints);
            if (onlyMi.isEmpty() && onlyMo.isEmpty()) {
                continue;
            }
            JSONObject o = new JSONObject();
            o.put("pid", p.pid);
            o.put("comm", p.comm);
            o.put("onlyInMountinfo", new JSONArray(new ArrayList<>(onlyMi)));
            o.put("onlyInMounts", new JSONArray(new ArrayList<>(onlyMo)));
            arr.put(o);
            pwarn("CROSS-FILE pid=" + p.pid + " onlyInMountinfo=" + onlyMi
                    + " onlyInMounts=" + onlyMo
                    + "  (asymmetry => a filter patched one file but not the other)");
        }
        return arr;
    }

    /** Symmetric diff of self's mountinfo against init(pid 1)'s — the global view. */
    private static JSONObject selfVsInit(List<Proc> procs, int selfPid) throws JSONException {
        JSONObject out = new JSONObject();
        FileView self = null;
        FileView init = null;
        for (Proc p : procs) {
            if (p.pid == selfPid) {
                self = p.files.get("mountinfo");
            }
            if (p.pid == 1) {
                init = p.files.get("mountinfo");
            }
        }
        out.put("initReadable", init != null && init.readable);
        out.put("selfReadable", self != null && self.readable);
        if (self == null || init == null || !self.readable || !init.readable) {
            plog("SELF-vs-INIT: not comparable (init readable="
                    + (init != null && init.readable) + ")");
            return out;
        }
        TreeSet<String> selfP = mountinfoPoints(self.lines);
        TreeSet<String> initP = mountinfoPoints(init.lines);
        TreeSet<String> onlyInit = new TreeSet<>(initP);
        onlyInit.removeAll(selfP);
        TreeSet<String> onlySelf = new TreeSet<>(selfP);
        onlySelf.removeAll(initP);
        out.put("selfMounts", selfP.size());
        out.put("initMounts", initP.size());
        out.put("onlyInInit", new JSONArray(new ArrayList<>(onlyInit)));
        out.put("onlyInSelf", new JSONArray(new ArrayList<>(onlySelf)));
        pwarn("SELF-vs-INIT selfMounts=" + selfP.size() + " initMounts=" + initP.size()
                + " onlyInInit=" + onlyInit.size() + " onlyInSelf=" + onlySelf.size());
        return out;
    }

    private static JSONObject namespaceGroups(List<Proc> procs) throws JSONException {
        Map<Long, List<Integer>> byNs = new LinkedHashMap<>();
        for (Proc p : procs) {
            if (p.nsMnt != 0) {
                byNs.computeIfAbsent(p.nsMnt, k -> new ArrayList<>()).add(p.pid);
            }
        }
        JSONObject out = new JSONObject();
        out.put("distinctNamespaces", byNs.size());
        JSONArray arr = new JSONArray();
        for (Map.Entry<Long, List<Integer>> e : byNs.entrySet()) {
            JSONObject o = new JSONObject();
            o.put("nsMnt", e.getKey());
            o.put("pidCount", e.getValue().size());
            arr.put(o);
        }
        out.put("groups", arr);
        plog("NAMESPACE GROUPS: distinct mnt namespaces readable = " + byNs.size());
        return out;
    }

    /** Bounded full-record dump: self, init, and any pid carrying a HIGH hit. */
    private static JSONArray processDump(List<Proc> procs, int selfPid, JSONArray markerSummary)
            throws JSONException {
        TreeSet<Integer> priority = new TreeSet<>();
        priority.add(selfPid);
        priority.add(1);
        for (Proc p : procs) {
            if (p.comm.contains("zygote")) {
                priority.add(p.pid);
            }
            for (Map.Entry<String, FileView> e : p.files.entrySet()) {
                for (Markers.Hit h : e.getValue().hits) {
                    if (h.confidence >= Markers.HIGH) {
                        priority.add(p.pid);
                    }
                }
            }
        }

        JSONArray arr = new JSONArray();
        int dumped = 0;
        for (Proc p : procs) {
            if (!priority.contains(p.pid) || dumped >= MAX_FULL_VIEWS) {
                continue;
            }
            dumped++;
            JSONObject o = new JSONObject();
            o.put("pid", p.pid);
            o.put("comm", p.comm);
            o.put("cmdline", p.cmdline);
            o.put("uid", p.uid);
            o.put("nsMnt", p.nsMnt);
            o.put("propagation", p.propagation);
            JSONObject files = new JSONObject();
            for (Map.Entry<String, FileView> e : p.files.entrySet()) {
                FileView v = e.getValue();
                JSONObject fo = new JSONObject();
                fo.put("readable", v.readable);
                fo.put("error", v.error);
                fo.put("lineCount", v.lineCount);
                JSONArray lines = new JSONArray();
                int limit = Math.min(v.lines.size(), MAX_LINES_PER_VIEW);
                for (int i = 0; i < limit; i++) {
                    lines.put(v.lines.get(i));
                }
                fo.put("lines", lines);
                fo.put("truncated", v.lines.size() > limit);
                files.put(e.getKey(), fo);
            }
            o.put("files", files);
            arr.put(o);
        }
        return arr;
    }

    private static JSONObject buildVerdict(JSONObject scan) throws JSONException {
        List<String> reasons = new ArrayList<>();
        int highHits = 0;
        JSONArray hits = scan.optJSONArray("markerHits");
        if (hits != null) {
            for (int i = 0; i < hits.length(); i++) {
                if (hits.getJSONObject(i).optInt("confidence") >= Markers.HIGH) {
                    highHits++;
                }
            }
        }
        if (highHits > 0) {
            reasons.add(highHits + " high-confidence root marker(s) in mount records");
        }
        JSONObject diff = scan.optJSONObject("differential");
        if (diff != null) {
            for (String f : new String[] {"mountinfo", "mounts", "mountstats"}) {
                JSONObject d = diff.optJSONObject(f);
                if (d != null && d.optBoolean("mismatch")) {
                    reasons.add("differential mismatch in " + f + " (distinctViews="
                            + d.optInt("distinctViews") + " != classes="
                            + d.optInt("propagationClasses") + ")");
                }
            }
        }
        JSONArray cross = scan.optJSONArray("crossFile");
        if (cross != null && cross.length() > 0) {
            reasons.add(cross.length() + " process(es) with mountinfo/mounts asymmetry");
        }
        JSONObject svi = scan.optJSONObject("selfVsInit");
        if (svi != null && svi.optJSONArray("onlyInInit") != null
                && svi.optJSONArray("onlyInInit").length() > 0) {
            reasons.add("init exposes " + svi.optJSONArray("onlyInInit").length()
                    + " mount(s) hidden from self");
        }

        JSONObject verdict = new JSONObject();
        verdict.put("detected", !reasons.isEmpty());
        verdict.put("reasons", new JSONArray(reasons));
        pwarn("VERDICT detected=" + !reasons.isEmpty() + " reasons=" + reasons);
        return verdict;
    }

    // ------------------------------------------------------------------
    // Empirically probe the sensitive /proc/<pid> entries (not just the mount files)
    // to see, from inside the isolated process, exactly which are readable and which
    // fault -- and with what error. Targets: self, up to 3 readable peers, and init(1).
    // ------------------------------------------------------------------
    private static final String[] SENSITIVE_FILES = {
        "cmdline", "comm", "stat", "status", "statm", "cgroup", "wchan", "sched", "limits",
        "personality", "io", "syscall", "maps", "smaps", "smaps_rollup", "pagemap", "auxv",
        "environ", "mem", "mountinfo", "mounts", "mountstats", "attr/current",
    };
    private static final String[] SENSITIVE_LINKS = {"ns/mnt", "ns/pid", "ns/net", "ns/user", "root", "cwd", "exe"};
    private static final String[] SENSITIVE_DIRS = {"fd", "fdinfo"};

    private static JSONObject probeFileAccess(List<Proc> procs, int selfPid) throws JSONException {
        List<Integer> targets = new ArrayList<>();
        targets.add(selfPid);
        for (Proc p : procs) {
            if (p.pid == selfPid) {
                continue;
            }
            FileView mi = p.files.get("mountinfo");
            if (mi != null && mi.readable) {
                targets.add(p.pid);
                if (targets.size() >= 4) {
                    break;
                }
            }
        }
        targets.add(1); // init: expected fully denied

        JSONObject out = new JSONObject();
        for (int pid : targets) {
            String base = "/proc/" + pid + "/";
            JSONObject r = new JSONObject();
            for (String f : SENSITIVE_FILES) {
                r.put(f, tryRead(base + f));
            }
            for (String f : SENSITIVE_LINKS) {
                r.put(f, tryReadlink(base + f));
            }
            for (String f : SENSITIVE_DIRS) {
                r.put(f, tryListDir(base + f));
            }
            out.put(String.valueOf(pid), r);

            // compact per-target summary into the log: which of the sensitive set opened
            StringBuilder ok = new StringBuilder();
            StringBuilder no = new StringBuilder();
            String[][] all = {SENSITIVE_FILES, SENSITIVE_LINKS, SENSITIVE_DIRS};
            for (String[] group : all) {
                for (String f : group) {
                    String v = r.optString(f);
                    (v.startsWith("ok") || v.startsWith("->") ? ok : no).append(f).append(' ');
                }
            }
            plog("FILEACCESS pid=" + pid + (pid == selfPid ? "(self)" : pid == 1 ? "(init)" : "(peer)")
                    + " READ: " + ok + "| DENIED: " + no);
        }
        return out;
    }

    /**
     * Readability of each sensitive entry across EVERY visible pid (not just the sampled
     * matrix): for each entry, how many pids the isolated reader can actually open/read,
     * and the distinct uids that were readable. Uses a light open+1-byte test so a large
     * file (maps/mem) is not fully read.
     */
    private static JSONObject aggregateFileAccess(List<Proc> procs) throws JSONException {
        JSONObject out = new JSONObject();
        java.util.Set<String> links = new java.util.HashSet<>(Arrays.asList(SENSITIVE_LINKS));
        java.util.Set<String> dirs = new java.util.HashSet<>(Arrays.asList(SENSITIVE_DIRS));
        List<String> entries = new ArrayList<>();
        entries.addAll(Arrays.asList(SENSITIVE_FILES));
        entries.addAll(Arrays.asList(SENSITIVE_LINKS));
        entries.addAll(Arrays.asList(SENSITIVE_DIRS));

        for (String f : entries) {
            int readable = 0;
            TreeSet<Integer> uids = new TreeSet<>();
            for (Proc p : procs) {
                String path = "/proc/" + p.pid + "/" + f;
                boolean ok = links.contains(f) ? canReadlink(path) : dirs.contains(f) ? canList(path) : canRead(path);
                if (ok) {
                    readable++;
                    if (uids.size() < 16) {
                        uids.add(p.uid);
                    }
                }
            }
            JSONObject o = new JSONObject();
            o.put("readable", readable);
            o.put("tested", procs.size());
            o.put("readableUids", new JSONArray(new ArrayList<>(uids)));
            out.put(f, o);
        }
        plog("FILEACCESS-ALL tested " + procs.size() + " visible pids; readable counts:");
        for (String f : entries) {
            JSONObject o = out.getJSONObject(f);
            plog("  " + f + ": " + o.getInt("readable") + "/" + o.getInt("tested")
                    + " uids=" + o.getJSONArray("readableUids"));
        }
        return out;
    }

    private static boolean canRead(String path) {
        try (var in = Files.newInputStream(Path.of(path))) {
            in.read();
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private static boolean canReadlink(String path) {
        try {
            Files.readSymbolicLink(Path.of(path));
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private static boolean canList(String path) {
        try (var s = Files.newDirectoryStream(Path.of(path))) {
            s.iterator();
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private static String tryRead(String path) {
        try {
            byte[] b = Files.readAllBytes(Path.of(path));
            return "ok(" + b.length + ")";
        } catch (Exception e) {
            return e.getClass().getSimpleName();
        }
    }

    private static String tryReadlink(String path) {
        try {
            return "-> " + Files.readSymbolicLink(Path.of(path));
        } catch (Exception e) {
            return e.getClass().getSimpleName();
        }
    }

    private static String tryListDir(String path) {
        try (var s = Files.newDirectoryStream(Path.of(path))) {
            int n = 0;
            for (Path ignored : s) {
                n++;
            }
            return "ok(" + n + " entries)";
        } catch (Exception e) {
            return e.getClass().getSimpleName();
        }
    }

    // ------------------------------------------------------------------
    // low-level readers
    // ------------------------------------------------------------------
    private static TreeSet<String> mountinfoPoints(List<String> lines) {
        TreeSet<String> s = new TreeSet<>();
        for (String l : lines) {
            try {
                s.add(MountInfo.parseLine(l).point);
            } catch (RuntimeException ignored) {
            }
        }
        return s;
    }

    private static TreeSet<String> mountsPoints(List<String> lines) {
        // /proc/pid/mounts: "source mountpoint type options 0 0"
        TreeSet<String> s = new TreeSet<>();
        for (String l : lines) {
            String[] parts = l.split(" ");
            if (parts.length >= 2) {
                s.add(parts[1]);
            }
        }
        return s;
    }

    private static boolean hasReadproc(int selfPid) {
        try {
            for (String line : Files.readAllLines(Path.of("/proc/" + selfPid + "/status"))) {
                if (line.startsWith("Groups:")) {
                    for (String g : line.substring(7).trim().split("\\s+")) {
                        if (g.equals("3009")) {
                            return true;
                        }
                    }
                    return false;
                }
            }
        } catch (IOException ignored) {
        }
        return false;
    }

    private static int readUid(String statusPath) {
        try {
            for (String line : Files.readAllLines(Path.of(statusPath))) {
                if (line.startsWith("Uid:")) {
                    return Integer.parseInt(line.substring(4).trim().split("\\s+")[0]);
                }
            }
        } catch (Exception ignored) {
        }
        return -1;
    }

    private static long readNsInode(String path) {
        try {
            String target = Files.readSymbolicLink(Path.of(path)).toString();
            int a = target.indexOf('[');
            int b = target.indexOf(']');
            if (a >= 0 && b > a) {
                return Long.parseLong(target.substring(a + 1, b));
            }
        } catch (Exception ignored) {
        }
        return 0;
    }

    private static String propagationOf(String mountinfoPath) {
        try (BufferedReader r = Files.newBufferedReader(Path.of(mountinfoPath))) {
            String line;
            while ((line = r.readLine()) != null) {
                try {
                    MountInfo m = MountInfo.parseLine(line);
                    if (m.point.equals("/")) {
                        return m.propagation();
                    }
                } catch (RuntimeException ignored) {
                }
            }
        } catch (IOException ignored) {
        }
        return "";
    }

    private static boolean isReadable(String path) {
        try {
            Files.readAllBytes(Path.of(path));
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private static String readTrim(String path) {
        try {
            return new String(Files.readAllBytes(Path.of(path)), StandardCharsets.UTF_8).trim();
        } catch (Exception e) {
            return "?";
        }
    }

    private static String readCmdline(String path) {
        try {
            byte[] b = Files.readAllBytes(Path.of(path));
            return new String(b, StandardCharsets.UTF_8).replace('\0', ' ').trim();
        } catch (Exception e) {
            return "";
        }
    }

    private static boolean isNumeric(String s) {
        for (int i = 0; i < s.length(); i++) {
            if (!Character.isDigit(s.charAt(i))) {
                return false;
            }
        }
        return !s.isEmpty();
    }

    private static String blank(String s) {
        return s == null || s.isEmpty() ? "-" : s;
    }
}
