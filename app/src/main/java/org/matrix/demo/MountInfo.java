package org.matrix.demo;

/**
 * One parsed line of {@code /proc/<pid>/mountinfo}.
 *
 * <p>Format (kernel Documentation/filesystems/proc.rst):
 * <pre>
 * 36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw,errors=continue
 * (1)(2)(3:4)  (5)   (6)      (7)      (8)    (9)  (10)   (11)      (12)
 *  id parent maj:min root mount-point options optional... - type source superopts
 * </pre>
 * Field 8 ("optional") is variable-length and terminated by " - ".
 */
final class MountInfo {

    final int id;
    final int parent;
    final int major;
    final int minor;
    final String root;
    final String point;
    final String options;
    final String optional;
    final String type;
    final String source;
    final String superOptions;
    final String raw;

    private MountInfo(int id, int parent, int major, int minor, String root, String point,
                      String options, String optional, String type, String source,
                      String superOptions, String raw) {
        this.id = id;
        this.parent = parent;
        this.major = major;
        this.minor = minor;
        this.root = root;
        this.point = point;
        this.options = options;
        this.optional = optional;
        this.type = type;
        this.source = source;
        this.superOptions = superOptions;
        this.raw = raw;
    }

    /** The {@code shared:N} / {@code master:N} propagation token, or "" if none. */
    String propagation() {
        for (String tok : optional.split(" ")) {
            if (tok.startsWith("shared:") || tok.startsWith("master:")
                    || tok.startsWith("propagate_from:") || tok.startsWith("unbindable")) {
                return tok;
            }
        }
        return "";
    }

    static MountInfo parseLine(String line) {
        int cursor = 0;

        int next = line.indexOf(' ', cursor);
        int id = Integer.parseInt(line.substring(cursor, next));
        cursor = next + 1;

        next = line.indexOf(' ', cursor);
        int parent = Integer.parseInt(line.substring(cursor, next));
        cursor = next + 1;

        next = line.indexOf(' ', cursor);
        int colon = line.indexOf(':', cursor);
        int major = Integer.parseInt(line.substring(cursor, colon));
        int minor = Integer.parseInt(line.substring(colon + 1, next));
        cursor = next + 1;

        next = line.indexOf(' ', cursor);
        String root = line.substring(cursor, next);
        cursor = next + 1;

        next = line.indexOf(' ', cursor);
        String point = line.substring(cursor, next);
        cursor = next + 1;

        next = line.indexOf(' ', cursor);
        String options = line.substring(cursor, next);
        cursor = next;

        int sep = line.indexOf(" - ", cursor);
        String optional = line.substring(cursor, sep).trim();
        cursor = sep + 3;

        next = line.indexOf(' ', cursor);
        String type = line.substring(cursor, next);
        cursor = next + 1;

        next = line.indexOf(' ', cursor);
        String source = line.substring(cursor, next);
        cursor = next + 1;

        String superOptions = line.substring(cursor);

        return new MountInfo(id, parent, major, minor, root, point, options, optional,
                type, source, superOptions, line);
    }
}
