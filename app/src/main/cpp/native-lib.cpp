#include "logging.h"
#include "smap.h"
#include "solist.hpp"
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
  SoList::SoInfo *abnormal_soinfo = SoList::DetectInjection();
  VirtualMap::MapInfo *abnormal_vmap = VirtualMap::DetectInjection();
  size_t module_injected = SoList::DetectModules();
  VirtualMap::DumpStackStrings();

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

  return env->NewStringUTF(
      (solist_detection + "\n" + vmap_detection + "\n" + counter_detection)
          .c_str());
}
