package org.matrix.demo;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * The marker catalogue. Deliberately WIDE: this is a diagnostic instrument, not a
 * clean detector, so it errs toward surfacing candidates. Each marker carries a
 * confidence so the UI can separate "definitely root" from "worth a look".
 *
 * <p>Crucially, matching is applied to the WHOLE rendered record and every field
 * of it (mount root / source / options / super-options), not just the mountpoint,
 * because bind- and overlay-based module mounts leak in the root and lowerdir
 * fields, which a mountpoint-only scan misses.
 */
final class Markers {

    static final int HIGH = 3;   // only exists on a rooted/modified device
    static final int MEDIUM = 2; // strongly associated with hiding frameworks
    static final int LOW = 1;    // common on stock too; context for differentials

    static final class Marker {
        final String needle;
        final String label;
        final int confidence;
        final boolean wordBoundary;

        Marker(String needle, String label, int confidence, boolean wordBoundary) {
            this.needle = needle;
            this.label = label;
            this.confidence = confidence;
            this.wordBoundary = wordBoundary;
        }
    }

    // Order matters only for display; scanning checks all of them.
    static final Marker[] CATALOGUE = new Marker[] {
        // --- HIGH: unambiguous root/module artefacts ---
        new Marker("/data/adb", "data/adb", HIGH, false),
        new Marker("/adb/", "adb", HIGH, false),
        new Marker("kernelsu", "KernelSU", HIGH, false),
        new Marker("ksu", "ksu", HIGH, true),
        new Marker("ksud", "ksud", HIGH, false),
        new Marker("magisk", "Magisk", HIGH, false),
        new Marker("zygisk", "Zygisk", HIGH, false),
        new Marker("susfs", "susfs", HIGH, false),
        new Marker("/debug_ramdisk", "debug_ramdisk", HIGH, false),
        new Marker("meta-overlayfs", "meta-overlayfs", HIGH, false),
        // Anchored to "/adb/modules": root modules live under /data/adb/modules, so this
        // still catches Magisk/KSU/APatch module bind mounts (their root is /adb/modules/...)
        // while no longer matching benign OEM paths that merely contain "modules" -- e.g.
        // OnePlus/Oppo's com.oplus.moduleservices, which the bare needle flagged HIGH.
        new Marker("/adb/modules", "adb-modules", HIGH, false),
        new Marker("apatch", "APatch", HIGH, false),
        new Marker("/sbin/su", "su-bin", HIGH, false),

        // --- MEDIUM: hiding-framework markers (word-bounded to avoid substring FPs) ---
        // Dropped the generic overlay-option words (workdir/upperdir/lowerdir), "gsi"
        // and "worker": they also appear in stock overlays/paths. A module overlay is
        // still caught by "/data/adb" inside its lowerdir value, so nothing is lost.
        // Also dropped "data_mirror": /data_mirror is a stock AOSP top-level mount
        // (vold/installd stage CE/DE storage and ART profile mirrors under it since
        // Android 11), so the needle fired on every unmodified device. A module's
        // mirror is still caught by "/data/adb" inside its root/lowerdir value.
        new Marker("sui", "Sui", MEDIUM, true),
        new Marker("lsp", "LSP", MEDIUM, true),
        new Marker("riru", "Riru", MEDIUM, true),
        new Marker("zn", "ZN", MEDIUM, true),
    };

    static final class Hit {
        final String label;
        final int confidence;
        final String field;   // which mountinfo field the needle was found in
        final String needle;

        Hit(String label, int confidence, String field, String needle) {
            this.label = label;
            this.confidence = confidence;
            this.field = field;
            this.needle = needle;
        }
    }

    /** Scan every field of a parsed record; return each distinct marker hit. */
    static List<Hit> scan(MountInfo m) {
        List<Hit> hits = new ArrayList<>();
        String[][] fields = {
            {"mountpoint", m.point},
            {"root", m.root},
            {"source", m.source},
            {"type", m.type},
            {"super-options", m.superOptions},
            {"options", m.options},
        };
        for (Marker marker : CATALOGUE) {
            String matchedField = null;
            for (String[] f : fields) {
                if (contains(f[1], marker.needle, marker.wordBoundary)) {
                    matchedField = f[0];
                    break;
                }
            }
            if (matchedField != null) {
                hits.add(new Hit(marker.label, marker.confidence, matchedField, marker.needle));
            }
        }
        return hits;
    }

    /** Fallback for raw strings (e.g. /proc/pid/mounts lines that we do not field-split). */
    static List<Hit> scanRaw(String raw) {
        List<Hit> hits = new ArrayList<>();
        for (Marker marker : CATALOGUE) {
            if (contains(raw, marker.needle, marker.wordBoundary)) {
                hits.add(new Hit(marker.label, marker.confidence, "line", marker.needle));
            }
        }
        return hits;
    }

    private static boolean contains(String haystack, String needle, boolean wordBoundary) {
        if (haystack == null || haystack.isEmpty()) {
            return false;
        }
        String hay = haystack.toLowerCase(Locale.ROOT);
        String nee = needle.toLowerCase(Locale.ROOT);
        int from = 0;
        while (true) {
            int idx = hay.indexOf(nee, from);
            if (idx < 0) {
                return false;
            }
            if (!wordBoundary) {
                return true;
            }
            boolean startOk = idx == 0 || !Character.isLetterOrDigit(hay.charAt(idx - 1));
            int end = idx + nee.length();
            boolean endOk = end == hay.length() || !Character.isLetterOrDigit(hay.charAt(end));
            if (startOk && endOk) {
                return true;
            }
            from = idx + 1;
        }
    }
}
