#include <jni.h>

#include "hardware.hpp"
#include "prop.hpp"

extern "C" JNIEXPORT jstring JNICALL
Java_org_matrix_demo_MainActivity_stringFromJNI(JNIEnv *env, jobject /* this */) {
    Prop::ListProp();

    Hardware::DumpClockMode();
    Hardware::DumpCpuCores();
    Hardware::DumpGpu();
    Hardware::DumpMemInfo();

    return env->NewStringUTF("Inspect logs with tag Demo.");
}
