#include "orbis_compat.h"

#include <cstdarg>
#include <cstdio>
#include <cstring>

#include "../core/ringlog.h"

#if defined(OSH_HOST_BUILD)
#include <pthread.h>
#include <time.h>
#include <unistd.h>
#else
// OpenOrbis PS4 Toolchain headers.
#include <orbis/libkernel.h>
#include <pthread.h>
#endif

namespace osh::orbis {

#if !defined(OSH_HOST_BUILD)

namespace {

// sceKernelGetModuleInfo fills this for the main executable (handle 0). Segment
// 0 is the code segment; the toolchain's own struct is used when available, but
// the shape is stable enough to rely on.
constexpr int kMainModuleHandle = 0;

// GoldHEN exposes the notification helper; declare it weakly so the plugin still
// links if it is unavailable.
extern "C" __attribute__((weak)) int sceKernelSendNotificationRequest(int device, char* data,
                                                                     std::size_t size, int blocking);

struct NotificationRequest {
  char padding[45];
  char message[3075];
};

}  // namespace

ModuleRange main_executable_segment() {
  OrbisKernelModuleInfo info;
  std::memset(&info, 0, sizeof(info));
  info.size = sizeof(info);

  if (sceKernelGetModuleInfo(kMainModuleHandle, &info) != 0) {
    OSH_LOG("sceKernelGetModuleInfo(0) failed");
    return {};
  }
  if (info.segmentCount == 0) {
    OSH_LOG("main module reports no segments");
    return {};
  }

  // Prefer an explicitly executable segment; fall back to segment 0.
  for (std::uint32_t i = 0; i < info.segmentCount; ++i) {
    if ((info.segmentInfo[i].prot & 0x4) != 0) {
      return {static_cast<std::uint8_t*>(info.segmentInfo[i].address),
              static_cast<std::size_t>(info.segmentInfo[i].size)};
    }
  }
  return {static_cast<std::uint8_t*>(info.segmentInfo[0].address),
          static_cast<std::size_t>(info.segmentInfo[0].size)};
}

std::uint64_t monotonic_ms() { return sceKernelGetProcessTime() / 1000ull; }

void sleep_ms(std::uint32_t ms) { sceKernelUsleep(ms * 1000); }

void notify(const char* format, ...) {
  if (sceKernelSendNotificationRequest == nullptr) return;
  NotificationRequest request;
  std::memset(&request, 0, sizeof(request));
  std::va_list args;
  va_start(args, format);
  std::vsnprintf(request.message, sizeof(request.message), format, args);
  va_end(args);
  sceKernelSendNotificationRequest(0, reinterpret_cast<char*>(&request), sizeof(request), 0);
}

int load_module(const char* path) {
  const int handle = sceKernelLoadStartModule(path, 0, nullptr, 0, nullptr, nullptr);
  if (handle < 0) {
    OSH_LOG("sceKernelLoadStartModule(%s) failed: 0x%x", path, handle);
  }
  return handle;
}

bool unload_module(int handle) {
  if (handle < 0) return false;
  const int result = sceKernelStopUnloadModule(handle, 0, nullptr, 0, nullptr, nullptr);
  if (result < 0) {
    OSH_LOG("sceKernelStopUnloadModule(%d) failed: 0x%x", handle, result);
    return false;
  }
  return true;
}

#else  // ---------------------------------------------------------- host build

ModuleRange main_executable_segment() { return {}; }

std::uint64_t monotonic_ms() {
  timespec now{};
  clock_gettime(CLOCK_MONOTONIC, &now);
  return static_cast<std::uint64_t>(now.tv_sec) * 1000ull + now.tv_nsec / 1000000ull;
}

void sleep_ms(std::uint32_t ms) { usleep(ms * 1000); }

void notify(const char* format, ...) {
  std::va_list args;
  va_start(args, format);
  RingLog::instance().vwritef(format, args);
  va_end(args);
}

int load_module(const char* path) {
  OSH_LOG("host build cannot load %s", path);
  return -1;
}

bool unload_module(int handle) { return false; }

#endif

namespace {

struct ThreadStart {
  void (*entry)(void*);
  void* user;
};

void* thread_trampoline(void* raw) {
  ThreadStart start = *static_cast<ThreadStart*>(raw);
  delete static_cast<ThreadStart*>(raw);
  start.entry(start.user);
  return nullptr;
}

}  // namespace

bool spawn_thread(const char* name, void (*entry)(void*), void* user) {
  auto* start = new ThreadStart{entry, user};
  pthread_t thread;
  if (pthread_create(&thread, nullptr, &thread_trampoline, start) != 0) {
    OSH_LOG("could not spawn thread '%s'", name);
    delete start;
    return false;
  }
  pthread_detach(thread);
  OSH_LOG("spawned thread '%s'", name);
  return true;
}

}  // namespace osh::orbis
