// The script scheduler.
//
// Mod scripts are ordinary functions that loop forever and call scriptWait() to
// give the game its thread back. Each one owns a fiber; the manager resumes the
// ones whose wait has expired, once per game tick, from inside the hook on the
// game's own script thread. That is the same shape as ScriptHookV, and it is why
// mod code can call natives safely: it runs where the engine expects script code
// to run.

#pragma once

#include <cstddef>
#include <cstdint>

#include "fiber.h"

namespace osh {

using ScriptMain = void (*)();

// Milliseconds since an arbitrary epoch. Supplied by the platform layer so the
// core stays testable off-console.
using ClockFn = std::uint64_t (*)();

struct ScriptInfo {
  const char* name;
  bool running;
  bool finished;
  std::uint64_t ticks;
  std::uint64_t wake_at;
};

class ScriptManager {
 public:
  static constexpr std::size_t kMaxScripts = 32;
  static constexpr std::size_t kNameLength = 64;

  void set_clock(ClockFn clock) { clock_ = clock; }

  // Registers a script. `name` is copied. Returns false when full or when the
  // name is already registered.
  bool add(const char* name, ScriptMain main, std::size_t stack_size = Fiber::kDefaultStackSize);

  // Stops a script and releases its fiber. Returns false if not found.
  bool remove(const char* name);

  // Resumes every due script exactly once. Call from the game tick hook.
  void tick();

  // Called from inside a script fiber: suspend for at least `ms` milliseconds.
  // Calling this outside a script fiber is a no-op (it would deadlock the game).
  void wait(std::uint32_t ms);

  std::size_t count() const { return count_; }
  bool info(std::size_t index, ScriptInfo* out) const;
  std::uint64_t tick_count() const { return tick_count_; }

  void shutdown();

  static ScriptManager& instance();

 private:
  struct Script {
    char name[kNameLength] = {};
    ScriptMain main = nullptr;
    Fiber fiber;
    std::uint64_t wake_at = 0;
    std::uint64_t ticks = 0;
    bool used = false;
  };

  static void entry(void* user);
  std::uint64_t now() const { return clock_ != nullptr ? clock_() : 0; }
  Script* find(const char* name);

  Script scripts_[kMaxScripts];
  std::size_t count_ = 0;
  std::uint64_t tick_count_ = 0;
  ClockFn clock_ = nullptr;
  // The script the manager is currently resuming, so wait() knows who to suspend.
  Script* running_ = nullptr;
};

// The API mod scripts use. Mirrors ScriptHookV so ports are mechanical.
void scriptRegister(const char* name, ScriptMain main);
void scriptUnregister(const char* name);
void scriptWait(std::uint32_t ms);

}  // namespace osh
