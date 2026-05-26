#include <stdint.h>
#include <stdlib.h>

namespace Hardware {
// Recreate the beginning of the Linux kernel's generic 'vdso_data' struct.
// Found in the kernel source at: include/vdso/datapage.h
struct vdso_data {
    uint32_t seq;        // Timebase sequence counter
    int32_t clock_mode;  // Clock mode (What you are looking for)
    uint64_t cycle_last; // Timebase at clocksource init
    uint64_t mask;       // Clocksource mask
    uint32_t mult;       // Clocksource multiplier
    uint32_t shift;      // Clocksource shift
    // ... remaining fields are omitted because we only need the top part.
};

struct CpuCore {
    int id;
    uint64_t midr;
};

struct CpuCluster {
    int start_core;
    int end_core;
    uint64_t midr;
};

void DumpCpuCores();

void DumpClockMode();

void DumpGpu();

void DumpMemInfo();
} // namespace Hardware
