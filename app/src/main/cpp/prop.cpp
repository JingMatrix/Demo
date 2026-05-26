#include "prop.hpp"

#include <android/log.h>
#include <jni.h>
#include <sys/system_properties.h>

#include "logging.h"

namespace Prop {
// Callback triggered to read the actual string name and value of each property
void read_prop_callback(void* cookie, const char* name, const char* value, uint32_t serial) {
    // Log the property name and value to logcat
    LOGI("[%s] = [%s]", name, value);

    // Optional: If you want to count them or pass them back to Java,
    // you can cast the 'cookie' pointer to a C++ std::vector or similar structure.
}

// Callback triggered for each property node found in the mapped tries
void foreach_prop_callback(const prop_info* pi, void* cookie) {
    // We must use the read_callback to safely extract the data from the prop_info struct
    // because properties can technically be updated concurrently by init.
    __system_property_read_callback(pi, read_prop_callback, cookie);
}

void ListProp() {
    LOGI("==================================================");
    LOGI("Starting organic system property enumeration...");
    LOGI("Domain: untrusted_app (Assuming standard APK execution)");
    LOGI("==================================================");

    // Iterate through all system properties mapped into this process's memory space
    int result = __system_property_foreach(foreach_prop_callback, nullptr);

    LOGI("==================================================");
    LOGI("Property enumeration finished. Result code: %d", result);
    LOGI("==================================================");
}
} // namespace Prop
