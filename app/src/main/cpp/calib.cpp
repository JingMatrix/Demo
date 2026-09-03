// Calibration probe for the dl_iterate_phdr ledger check (see include/dlphdr.hpp).
//
// Deliberately empty: no dependencies beyond libc, no constructors, no TLS. A
// dlopen of this file must move the linker's ledger by exactly one object and one
// dlpi_adds, and nothing else, so any other delta is the injector's, not ours.
extern "C" [[gnu::visibility("default")]] int demo_calibration_probe(void) { return 0; }
