#include "memory.h"
#include "logger.h"

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <dlfcn.h>
#include <unistd.h>
#include <vector>

namespace mem {

uintptr_t module_base(const char *soname) {
    FILE *f = fopen("/proc/self/maps", "re");
    if (!f) return 0;

    char line[1024];
    uintptr_t base = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, soname) == nullptr) continue;
        uintptr_t start;
        if (sscanf(line, "%lx-", &start) == 1) {
            base = start;
            break;
        }
    }
    fclose(f);
    return base;
}

uintptr_t wait_for_module(const char *soname, int timeout_ms) {
    int waited = 0;
    int step = 50;
    while (waited < timeout_ms) {
        uintptr_t b = module_base(soname);
        if (b) return b;
        usleep(step * 1000);
        waited += step;
        if (step < 500) step += 50;
    }
    return 0;
}

void *resolve(const char *soname, const char *symbol) {
    void *h = dlopen(soname, RTLD_NOW | RTLD_NOLOAD);
    if (!h) h = dlopen(soname, RTLD_NOW);
    if (!h) {
        LOGE("dlopen failed for %s: %s", soname, dlerror());
        return nullptr;
    }
    void *p = dlsym(h, symbol);
    if (!p) LOGW("dlsym(%s, %s) returned null", soname, symbol);
    return p;
}

static bool parse_pattern(const char *pattern, std::vector<int> &out) {
    out.clear();
    const char *p = pattern;
    while (*p) {
        while (*p == ' ') ++p;
        if (!*p) break;
        if (p[0] == '?' || p[0] == '?') {
            out.push_back(-1);
            ++p;
            if (*p == '?') ++p;
        } else {
            char buf[3] = { p[0], p[1], 0 };
            char *end = nullptr;
            long v = strtol(buf, &end, 16);
            if (end != buf + 2) return false;
            out.push_back(int(v));
            p += 2;
        }
    }
    return !out.empty();
}

uintptr_t pattern_scan(const char *soname, const char *pattern) {
    std::vector<int> bytes;
    if (!parse_pattern(pattern, bytes)) {
        LOGE("Bad pattern: %s", pattern);
        return 0;
    }
    FILE *f = fopen("/proc/self/maps", "re");
    if (!f) return 0;

    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        if (!strstr(line, soname)) continue;
        if (!strstr(line, " r-xp ") && !strstr(line, " r--p ")) continue;
        uintptr_t s, e;
        if (sscanf(line, "%lx-%lx", &s, &e) != 2) continue;
        const uint8_t *base = reinterpret_cast<const uint8_t *>(s);
        size_t span = e - s;
        size_t plen = bytes.size();
        if (span < plen) continue;
        for (size_t i = 0; i + plen <= span; ++i) {
            size_t k = 0;
            for (; k < plen; ++k) {
                if (bytes[k] == -1) continue;
                if (base[i + k] != uint8_t(bytes[k])) break;
            }
            if (k == plen) {
                fclose(f);
                return uintptr_t(base + i);
            }
        }
    }
    fclose(f);
    return 0;
}

} // namespace mem
