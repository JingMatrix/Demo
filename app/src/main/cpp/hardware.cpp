#include "hardware.hpp"

#include <EGL/egl.h>
#include <GLES2/gl2.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <unistd.h>

#include <algorithm>
#include <cinttypes>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

#include "logging.h"

#ifndef AT_HWCAP
#define AT_HWCAP 16
#endif
#ifndef AT_HWCAP2
#define AT_HWCAP2 26
#endif

namespace Hardware {
// Parses BogoMIPS from /proc/cpuinfo
double parse_bogomips() {
    std::ifstream file("/proc/cpuinfo");
    std::string line;
    if (!file.is_open()) return 0.0;

    while (std::getline(file, line)) {
        std::string lower_line = line;
        std::transform(lower_line.begin(), lower_line.end(), lower_line.begin(), ::tolower);
        if (lower_line.find("bogomips") != std::string::npos) {
            size_t colon_pos = line.find(':');
            if (colon_pos != std::string::npos) {
                std::string val_str = line.substr(colon_pos + 1);
                val_str.erase(std::remove_if(val_str.begin(), val_str.end(), ::isspace),
                              val_str.end());
                try {
                    return std::stod(val_str);
                } catch (...) {
                }
            }
        }
    }
    return 0.0;
}

uint64_t read_midr_from_sysfs(int core_id) {
    char path[256];
    snprintf(path, sizeof(path), "/sys/devices/system/cpu/cpu%d/regs/identification/midr_el1",
             core_id);
    std::ifstream file(path);
    if (!file.is_open()) return 0;

    std::string line;
    if (std::getline(file, line)) {
        try {
            return std::stoull(line, nullptr, 16);
        } catch (...) {
        }
    }
    return 0;
}

uint64_t read_midr_assembly() {
    uint64_t midr = 0;
#if defined(__aarch64__)
    asm volatile("mrs %0, midr_el1" : "=r"(midr));
#endif
    return midr;
}

uint64_t get_midr_for_core(int core_id) {
    uint64_t midr = read_midr_from_sysfs(core_id);
    if (midr != 0) {
        return midr;
    }

    cpu_set_t old_set;
    cpu_set_t new_set;

    if (sched_getaffinity(0, sizeof(cpu_set_t), &old_set) == -1) {
        return read_midr_assembly();
    }

    CPU_ZERO(&new_set);
    CPU_SET(core_id, &new_set);

    if (sched_setaffinity(0, sizeof(cpu_set_t), &new_set) == 0) {
        usleep(1000);
        midr = read_midr_assembly();
        sched_setaffinity(0, sizeof(cpu_set_t), &old_set);
    }

    return midr;
}

void DumpCpuCores() {
    // 1. Fetch values
    double bogomips_raw = parse_bogomips();
    unsigned long bogomips_scaled = static_cast<unsigned long>(bogomips_raw * 100.0 + 0.5);

    unsigned long hwcap = getauxval(AT_HWCAP);
    unsigned long hwcap2 = getauxval(AT_HWCAP2);

    int num_cores = sysconf(_SC_NPROCESSORS_CONF);
    std::vector<CpuCore> cores;

    for (int i = 0; i < num_cores; ++i) {
        uint64_t midr = get_midr_for_core(i);
        cores.push_back({i, midr});
    }

    // Post-process offline cores if necessary
    for (size_t i = 0; i < cores.size(); ++i) {
        if (cores[i].midr == 0) {
            for (int j = static_cast<int>(i) - 1; j >= 0; --j) {
                if (cores[j].midr != 0) {
                    cores[i].midr = cores[j].midr;
                    break;
                }
            }
        }
        if (cores[i].midr == 0) {
            for (size_t j = i + 1; j < cores.size(); ++j) {
                if (cores[j].midr != 0) {
                    cores[i].midr = cores[j].midr;
                    break;
                }
            }
        }
    }

    // Grouping
    std::vector<CpuCluster> clusters;
    if (!cores.empty()) {
        CpuCluster current = {cores[0].id, cores[0].id, cores[0].midr};
        for (size_t i = 1; i < cores.size(); ++i) {
            if (cores[i].midr == current.midr && cores[i].id == current.end_core + 1) {
                current.end_core = cores[i].id;
            } else {
                clusters.push_back(current);
                current = {cores[i].id, cores[i].id, cores[i].midr};
            }
        }
        clusters.push_back(current);
    }

    // Fetch kernel release and version
    struct utsname uts;
    std::string kernel_release = "Unknown";
    std::string kernel_version = "Unknown";
    if (uname(&uts) == 0) {
        kernel_release = uts.release;
        kernel_version = uts.version;
    }

    LOGD("--- CPU INFORMATION DUMP ---");
    LOGD("Kernel_Release: %s", kernel_release.c_str());
    LOGD("Kernel_Version: %s", kernel_version.c_str());
    LOGD("BogoMIPS_Scaled: %lu", bogomips_scaled);
    LOGD("HWCAP_Val: 0x%lx", hwcap);
    LOGD("HWCAP2_Val: 0x%lx", hwcap2);
    LOGD("Total_Physical_Cores: %d", num_cores);

    LOGD("Detected_Core_Clusters:");
    for (const auto& cluster : clusters) {
        if (cluster.start_core == cluster.end_core) {
            LOGD("  CoreRange: %d | MIDR: 0x%08llx", cluster.start_core,
                 static_cast<unsigned long long>(cluster.midr));
        } else {
            LOGD("  CoreRange: %d-%d | MIDR: 0x%08llx", cluster.start_core, cluster.end_core,
                 static_cast<unsigned long long>(cluster.midr));
        }
    }
    LOGD("----------------------------");
}

void DumpClockMode() {
    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) {
        perror("Failed to open /proc/self/maps");
        return;
    }

    char line[512];
    uintptr_t vvar_base = 0;

    // 1. Search for the [vvar] memory mapping
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "[vvar]")) {
            // Extract the starting hex address
            sscanf(line, "%" SCNxPTR "-", &vvar_base);
            break;
        }
    }
    fclose(fp);

    if (vvar_base == 0) {
        LOGD("Could not find [vvar] region in memory maps.\n");
        return;
    }

    LOGD("[vvar] base address mapped at: 0x%lx\n", vvar_base);

    // 2. Cast the vvar memory address to our recreated struct
    // The [vvar] page starts exactly with an array of struct vdso_data
    struct vdso_data* vdata = (struct vdso_data*) vvar_base;

    // 3. Read out the values!
    // Note: [vvar] is mapped read-only, so accessing it is perfectly safe.
    LOGD("--- vDSO VVAR Dump ---\n");
    LOGD("Sequence (seq): %u\n", vdata->seq);
    LOGD("Clock Mode: %d\n", vdata->clock_mode);
    LOGD("Cycle Last: %llu\n", (unsigned long long) vdata->cycle_last);

    // Interpret the clock_mode (specific to ARM64 / AArch64)
    // VDSO_CLOCKMODE_NONE = 0, VDSO_CLOCKMODE_ARCHTIMER = 1
    if (vdata->clock_mode == 1) {
        LOGD("Status: Using ARM64 Hardware Architectural Timer (Fast User-space time)\n");
    } else if (vdata->clock_mode == 0) {
        LOGD("Status: Fallback to System Call (VDSO_CLOCKMODE_NONE)\n");
    }
}

void DumpGpu() {
    // 1. Get the default EGL display
    EGLDisplay display = eglGetDisplay(EGL_DEFAULT_DISPLAY);
    if (display == EGL_NO_DISPLAY) {
        LOGE("Failed to get EGL display.");
        return;
    }

    // 2. Initialize EGL
    EGLint major, minor;
    if (!eglInitialize(display, &major, &minor)) {
        LOGE("Failed to initialize EGL.");
        return;
    }

    // 3. Define and choose EGL Configuration
    EGLint configAttribs[] = {EGL_RENDERABLE_TYPE,
                              EGL_OPENGL_ES2_BIT,
                              EGL_RED_SIZE,
                              8,
                              EGL_GREEN_SIZE,
                              8,
                              EGL_BLUE_SIZE,
                              8,
                              EGL_NONE};

    EGLConfig config;
    EGLint numConfigs;
    if (!eglChooseConfig(display, configAttribs, &config, 1, &numConfigs) || numConfigs < 1) {
        LOGE("Failed to choose EGL config.");
        eglTerminate(display);
        return;
    }

    // 4. Create an EGL Context
    EGLint contextAttribs[] = {EGL_CONTEXT_CLIENT_VERSION, 2, EGL_NONE};

    EGLContext context = eglCreateContext(display, config, EGL_NO_CONTEXT, contextAttribs);
    if (context == EGL_NO_CONTEXT) {
        LOGE("Failed to create EGL context.");
        eglTerminate(display);
        return;
    }

    // 5. Create a 1x1 dummy Pbuffer surface
    EGLint pbufferAttribs[] = {EGL_WIDTH, 1, EGL_HEIGHT, 1, EGL_NONE};

    EGLSurface surface = eglCreatePbufferSurface(display, config, pbufferAttribs);
    if (surface == EGL_NO_SURFACE) {
        LOGE("Failed to create EGL pbuffer surface.");
        eglDestroyContext(display, context);
        eglTerminate(display);
        return;
    }

    // 6. Make the context current
    if (!eglMakeCurrent(display, surface, surface, context)) {
        LOGE("Failed to make EGL context current.");
        eglDestroySurface(display, surface);
        eglDestroyContext(display, context);
        eglTerminate(display);
        return;
    }

    // 7. Query GPU properties
    const char* vendor = reinterpret_cast<const char*>(glGetString(GL_VENDOR));
    const char* renderer = reinterpret_cast<const char*>(glGetString(GL_RENDERER));
    const char* version = reinterpret_cast<const char*>(glGetString(GL_VERSION));
    const char* glsl_ver = reinterpret_cast<const char*>(glGetString(GL_SHADING_LANGUAGE_VERSION));
    const char* extensions = reinterpret_cast<const char*>(glGetString(GL_EXTENSIONS));

    // 8. Log the gathered fingerprint information
    LOGI("================ GPU FINGERPRINT INFO ================");
    LOGI("GPU Vendor:       %s", vendor ? vendor : "N/A");
    LOGI("GPU Renderer:     %s", renderer ? renderer : "N/A");
    LOGI("GLES Version:     %s", version ? version : "N/A");
    LOGI("GLSL Version:     %s", glsl_ver ? glsl_ver : "N/A");

    if (extensions) {
        LOGI("GLES Extensions: %s", extensions);
    } else {
        LOGI("GLES Extensions: N/A");
    }
    LOGI("======================================================");

    // 9. Clean up resources
    eglMakeCurrent(display, EGL_NO_SURFACE, EGL_NO_SURFACE, EGL_NO_CONTEXT);
    eglDestroySurface(display, surface);
    eglDestroyContext(display, context);
    eglTerminate(display);
}

void DumpMemInfo() {
    std::ifstream file("/proc/meminfo");
    std::string line;
    if (!file.is_open()) {
        LOGE("Stealth: Failed to open /proc/meminfo");
        return;
    }

    LOGD("--- SYSTEM MEMORY INFORMATION DUMP ---");

    while (std::getline(file, line)) {
        std::stringstream ss(line);
        std::string key;
        uint64_t value_kb = 0;
        std::string unit = "";

        if (ss >> key >> value_kb) {
            ss >> unit; // Read the optional unit (e.g., "kB")

            if (unit == "kB") {
                uint64_t bytes = value_kb * 1024ULL; // 1 kB = 1024 bytes
                double formatted_val = 0.0;
                char unit_char = 'K';

                // Intelligent unit selector (Binary base 1024 scaling)
                if (bytes >= (1024ULL * 1024ULL * 1024ULL)) {
                    formatted_val = static_cast<double>(bytes) / (1024.0 * 1024.0 * 1024.0);
                    unit_char = 'G';
                } else if (bytes >= (1024ULL * 1024ULL)) {
                    formatted_val = static_cast<double>(bytes) / (1024.0 * 1024.0);
                    unit_char = 'M';
                } else {
                    formatted_val = static_cast<double>(bytes) / 1024.0;
                    unit_char = 'K';
                }

                // Format double values to 2 decimal places
                std::stringstream formatted_str;
                formatted_str << std::fixed << std::setprecision(2) << formatted_val;

                // Print as: MemTotal: 7.28 G (7824695296 bytes)
                LOGD("%s %s %c (%llu bytes)", key.c_str(), formatted_str.str().c_str(), unit_char,
                     (unsigned long long) bytes);
            } else {
                // Non-standard metrics with no kB units are logged as raw values
                LOGD("%s %llu", key.c_str(), (unsigned long long) value_kb);
            }
        } else {
            if (!line.empty()) {
                LOGD("%s", line.c_str());
            }
        }
    }

    LOGD("--------------------------------------");
}

} // namespace Hardware
