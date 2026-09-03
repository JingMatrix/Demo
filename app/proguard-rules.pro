# The release build enables R8 with `keepRules.includeDefault = false`, so none of
# the usual defaults apply -- including the one that protects JNI.
#
# Every native method here is bound by implicit registration: the linker looks up
# the C symbol whose name is derived from the fully qualified Java class and method
# (Java_org_matrix_demo_ProcScanner_nativeReconcile). Renaming either half makes the
# call throw UnsatisfiedLinkError, which the callers swallow -- so the shipped APK
# would silently drop the integrity, reconciliation and linker checks while still
# rendering a "CLEAN" verdict. Keep the names on both sides of the boundary.
-keepclasseswithmembernames,includedescriptorclasses class * {
    native <methods>;
}
