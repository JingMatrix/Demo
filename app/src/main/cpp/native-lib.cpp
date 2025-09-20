#include "atexit.hpp"
#include "logging.h"
#include "smap.h"
#include "solist.hpp"
#include "statfs.hpp"
#include "vmap.hpp"
#include <format>
#include <jni.h>
#include <string>

extern "C" JNIEXPORT jstring JNICALL
Java_org_matrix_demo_MainActivity_stringFromJNI(JNIEnv *env,
                                                jobject /* this */) {

  std::string solist_detection = "No injection found using solist";
  std::string vmap_detection = "No injection found using vitrual map";
  std::string counter_detection = "No injection found using module counter";
  std::string system_mount_detection =
      "No traces found for /system re-mounting";
  SoList::SoInfo *abnormal_soinfo = SoList::DetectInjection();
  VirtualMap::MapInfo *abnormal_vmap = VirtualMap::DetectInjection();
  size_t module_injected = SoList::DetectModules();
  VirtualMap::DumpStackStrings();
  auto g_array = Atexit::findAtexitArray();
  if (g_array != nullptr) {
    LOGD("g_array status: %s", g_array->format_state_string().c_str());
  }
  auto mount_type = get_filesystem_type("/proc/self/exe");

  if (abnormal_soinfo != nullptr) {
    solist_detection =
        std::format("Solist: injection at {}", (void *)abnormal_soinfo);
    LOGE("Abnormal soinfo %p: %s loaded at %s", abnormal_soinfo,
         abnormal_soinfo->get_name(), abnormal_soinfo->get_path());
  }

  if (abnormal_vmap != nullptr) {
    vmap_detection =
        std::format("Virtual map: injection at {}", abnormal_vmap->path);
    LOGE("Abnormal vmap %s: [0x%lx-0x%lx]", abnormal_vmap->path.data(),
         abnormal_vmap->start, abnormal_vmap->end);
  }

  if (module_injected > 0) {
    counter_detection = std::format(
        "Module counter: {} shared libraries unloaded", module_injected);
  }

  if (mount_type != "EXT4") {
    system_mount_detection =
        std::format("/system/bin was mounted with type {}", mount_type);
  }

  return env->NewStringUTF((solist_detection + "\n" + vmap_detection + "\n" +
                            counter_detection + "\n" + system_mount_detection)
                               .c_str());
}
