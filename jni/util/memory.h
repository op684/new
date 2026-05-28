#pragma once
#include <cstdint>
#include <string>

namespace mem {

// Returns the load address of the given library in the current process,
// or 0 if not mapped. Read from /proc/self/maps.
uintptr_t module_base(const char *soname);

// Wait (busy-polling /proc/self/maps with backoff) until `soname` is mapped.
// Returns its base, or 0 if it never shows up within `timeout_ms`.
uintptr_t wait_for_module(const char *soname, int timeout_ms = 30000);

// Resolve a symbol by name in a loaded library, using dlsym after dlopen.
void *resolve(const char *soname, const char *symbol);

// Scan readable executable mapped pages of `soname` for `pattern` ("48 8B ?? ?? CC")
// and return the absolute address of the first match, or 0.
uintptr_t pattern_scan(const char *soname, const char *pattern);

} // namespace mem
