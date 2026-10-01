package org.matrix.demo;

import android.app.ZygotePreload;
import android.content.pm.ApplicationInfo;
import android.os.Build;
import android.system.ErrnoException;
import android.system.Os;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;

/**
 * ZygotePreload for the "dirty sepolicy" probe, ported from LSPosed/DirtySepolicy's
 * {@code AppZygote.java} (https://github.com/LSPosed/DirtySepolicy). App Zygote must be able
 * to transition into the restricted context of the isolated service it forks, so it needs
 * SELinux permission to query and check access rules -- a vantage point an ordinary
 * untrusted app does not have. See {@link #doCheck()} for the kernel interfaces this relies
 * on, and README.md's "Dirty sepolicy" section for the theory and credit.
 *
 * <p>Unlike DirtySepolicy's own single concatenated "OK:/WARNING:/ERROR:" string, this stores
 * a Demo-shaped JSON document in {@link #result} (verdict/self/log, same as the other probes),
 * which {@link SepolicyProbeService} hands back over binder.
 */
public final class SepolicyZygote implements ZygotePreload {
    static String result = "{\"technique\":\"sepolicy\",\"error\":\"app zygote not called\"}";

    // Progress log mirrored into the JSON ("log" array), same convention as ProcScanner.
    private static List<String> gLog = new ArrayList<>();

    private static void plog(String s) {
        gLog.add(s);
        Log.i(ProcScanner.TAG, s);
    }

    private static void pwarn(String s) {
        gLog.add(s);
        Log.w(ProcScanner.TAG, s);
    }

    private static int parseVersion(String release, int start) {
        int end = start;
        while (end < release.length()) {
            char c = release.charAt(end);
            if (c < '0' || c > '9') break;
            end++;
        }
        return Integer.parseInt(release.substring(start, end));
    }

    private static boolean isNewKernel() {
        var release = Os.uname().release;
        int major = parseVersion(release, 0);
        int dot = release.indexOf('.');
        int minor = parseVersion(release, dot + 1);
        // https://github.com/torvalds/linux/commit/fc983171e4c8
        return major > 6 || (major == 6 && minor >= 10);
    }

    /** Record one {label, detail} finding into both the JSON findings array and the log. */
    private static void finding(List<JSONObject> findings, List<String> reasons, String label, String detail)
            throws JSONException {
        JSONObject f = new JSONObject();
        f.put("label", label);
        f.put("detail", detail);
        findings.add(f);
        reasons.add(label);
        pwarn("FOUND " + label + ": " + detail);
    }

    /**
     * Build the ERROR/inconclusive document. Distinct from a clean "nothing found" pass
     * ("verdict":{"detected":false}) so a crashed or blocked probe never renders as CLEAN in
     * the UI -- MainActivity's VerdictCard checks top-level "error" before looking at verdict.
     */
    private static String error(String context, int pid, String message) {
        pwarn("ERROR: " + message);
        JSONObject out = new JSONObject();
        try {
            out.put("technique", "sepolicy");
            JSONObject self = new JSONObject();
            self.put("context", context);
            self.put("pid", pid);
            out.put("self", self);
            out.put("error", message);
            JSONObject verdict = new JSONObject();
            verdict.put("detected", false);
            verdict.put("reasons", new JSONArray());
            out.put("verdict", verdict);
            out.put("log", new JSONArray(gLog));
        } catch (JSONException ignored) {
        }
        return out.toString();
    }

    private String doCheck() throws JSONException {
        if (!SELinux.isSELinuxEnabled()) {
            return error(null, Os.getpid(), "SELinux is disabled");
        }
        var context = SELinux.getContext();
        plog("context=" + context);
        if (context == null || !context.startsWith("u:r:app_zygote:s0")) {
            return error(context, Os.getpid(), "unexpected SELinux context: " + context);
        }
        var pid = Os.getpid();
        var pidContext = SELinux.getPidContext(pid);
        if (!context.equals(pidContext)) {
            return error(context, pid, "PID context mismatch: " + pidContext);
        }
        var procContext = SELinux.getFileContext("/proc/self");
        if (!context.equals(procContext)) {
            return error(context, pid, "/proc/self context mismatch: " + procContext);
        }
        plog("sanity checks passed: pid=" + pid + " context matches /proc/self and task attr/current");

        if (!SELinux.checkSELinuxAccess("u:r:app_zygote:s0", "u:r:app_zygote:s0", "process", "setcurrent")) {
            return error(context, pid, "cannot check SELinux access (process:setcurrent denied)");
        }
        if (!SELinux.checkSELinuxAccess("u:r:app_zygote:s0", "u:r:kernel:s0", "security", "check_context")) {
            return error(context, pid, "cannot check SELinux context (security:check_context denied)");
        }
        plog("app_zygote has process:setcurrent and security:check_context access");

        List<JSONObject> findings = new ArrayList<>();
        List<String> reasons = new ArrayList<>();

        if (!SELinux.isSELinuxEnforced()) {
            finding(findings, reasons, "SELinux permissive", "/sys/fs/selinux/enforce == 0");
        }
        if (SELinux.checkSELinuxAccess("u:r:system_server:s0", "u:r:system_server:s0", "process", "execmem")) {
            finding(findings, reasons, "system_server can execmem",
                    "process:execmem allowed system_server -> system_server");
        }
        if (Build.TYPE.equals("user")
                && SELinux.checkSELinuxAccess("u:r:shell:s0", "u:r:su:s0", "process", "transition")) {
            finding(findings, reasons, "AOSP su in user build",
                    "process:transition allowed shell -> su on a user build");
        }
        plog("checked permissive/execmem/AOSP-su");

        if (SELinux.contextExists("u:r:adbroot:s0")) {
            finding(findings, reasons, "adb_root", "context u:r:adbroot:s0 exists");
        }
        if (SELinux.contextExists("u:r:magisk:s0") || SELinux.contextExists("u:object_r:magisk_file:s0")
                || SELinux.checkSELinuxAccess("u:object_r:rootfs:s0", "u:object_r:tmpfs:s0", "filesystem", "associate")
                || SELinux.checkSELinuxAccess("u:r:kernel:s0", "u:object_r:tmpfs:s0", "fifo_file", "open")) {
            finding(findings, reasons, "Magisk",
                    "magisk context/type, or rootfs<->tmpfs filesystem:associate / kernel->tmpfs fifo_file:open rule present");
        }
        if (SELinux.contextExists("u:r:ksu:s0") || SELinux.contextExists("u:object_r:ksu_file:s0")
                || SELinux.checkSELinuxAccess("u:r:kernel:s0", "u:object_r:adb_data_file:s0", "file", "read")) {
            finding(findings, reasons, "KernelSU",
                    "ksu context/type, or kernel->adb_data_file file:read rule present");
        }
        if (SELinux.contextExists("u:object_r:lsposed_file:s0")
                || SELinux.contextExists("u:object_r:xposed_data:s0") || SELinux.contextExists("u:object_r:xposed_file:s0")
                || SELinux.checkSELinuxAccess("u:r:system_server:s0", "u:object_r:apk_data_file:s0", "file", "execute")
                || SELinux.checkSELinuxAccess("u:r:dex2oat:s0", "u:object_r:dex2oat_exec:s0", "file", "execute_no_trans")) {
            finding(findings, reasons, "Xposed",
                    "lsposed_file/xposed_data/xposed_file type, or system_server->apk_data_file file:execute, "
                            + "or dex2oat->dex2oat_exec file:execute_no_trans rule present");
        }
        if (SELinux.checkSELinuxAccess("u:r:zygote:s0", "u:object_r:adb_data_file:s0", "dir", "search")) {
            finding(findings, reasons, "Zygisk Implementation", "zygote->adb_data_file dir:search rule present");
        }
        plog("checked root/hook fingerprints: " + findings.size() + " finding(s) so far");

        var buffer = SELinux.readStatus();
        int version = buffer.getInt(0);
        if (version != 1) {
            return error(context, pid, "unknown status version: " + version);
        }
        int sequence = buffer.getInt(4);
        int enforcing = buffer.getInt(8);
        int policyload = buffer.getInt(12);
        int deny_unknown = buffer.getInt(16);
        boolean newKernel = isNewKernel();
        plog("status: sequence=" + sequence + " enforcing=" + enforcing + " policyload=" + policyload
                + " deny_unknown=" + deny_unknown + " newKernel=" + newKernel);
        if (enforcing != 1) {
            finding(findings, reasons, "enforcing=" + enforcing,
                    "/sys/fs/selinux/status enforcing field != 1");
        }
        if (deny_unknown != 1) {
            finding(findings, reasons, "deny_unknown=" + deny_unknown,
                    "/sys/fs/selinux/status deny_unknown field != 1");
        }
        if (!(newKernel ? policyload == 1 && sequence == 4 : policyload == 0 && sequence == 0)) {
            finding(findings, reasons, "unexpected sequence/policyload",
                    "sequence=" + sequence + " policyload=" + policyload + " (newKernel=" + newKernel + ")");
        }

        int avdSeqNo;
        try {
            var avd = SELinux.access("u:r:untrusted_app:s0", "u:r:untrusted_app:s0", 0);
            avdSeqNo = Integer.parseUnsignedInt(avd[4]);
            plog("untrusted_app avc sequence number=" + avdSeqNo);
            if (avdSeqNo != 1) {
                finding(findings, reasons, "avdSeqNo=" + avdSeqNo,
                        "untrusted_app avc-sequence cross-check mismatch");
            }
        } catch (ErrnoException e) {
            return error(context, pid, "cannot cross-check untrusted_app avc sequence: " + e.getMessage());
        }

        JSONObject baseline = new JSONObject();
        baseline.put("enforcing", enforcing);
        baseline.put("deny_unknown", deny_unknown);
        baseline.put("sequence", sequence);
        baseline.put("policyload", policyload);
        baseline.put("avdSeqNo", avdSeqNo);
        baseline.put("newKernel", newKernel);

        JSONObject sepolicy = new JSONObject();
        sepolicy.put("baseline", baseline);
        sepolicy.put("findings", new JSONArray(findings));

        JSONObject self = new JSONObject();
        self.put("context", context);
        self.put("pid", pid);

        JSONObject verdict = new JSONObject();
        verdict.put("detected", !reasons.isEmpty());
        verdict.put("reasons", new JSONArray(reasons));
        pwarn("VERDICT detected=" + !reasons.isEmpty() + " reasons=" + reasons);

        JSONObject out = new JSONObject();
        out.put("technique", "sepolicy");
        out.put("self", self);
        out.put("sepolicy", sepolicy);
        out.put("verdict", verdict);
        out.put("log", new JSONArray(gLog));
        return out.toString();
    }

    @Override
    public void doPreload(ApplicationInfo appInfo) {
        gLog = new ArrayList<>();
        plog("SEPOLICY PRELOAD START");
        try {
            var uid = Os.getuid();
            if (uid != appInfo.uid) {
                result = error(null, Os.getpid(), "UID mismatch: " + uid + " != app uid " + appInfo.uid);
                return;
            }
            result = doCheck();
        } catch (JSONException | RuntimeException e) {
            Log.e(ProcScanner.TAG, Log.getStackTraceString(e));
            result = error(null, Os.getpid(), "exception: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }
}
