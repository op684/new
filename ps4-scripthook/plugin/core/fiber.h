// Cooperative fibers for the script runtime.
//
// ScriptHookV on Windows leans on Win32 fibers so that a mod script can call
// scriptWait() in the middle of its logic and be resumed on a later game tick.
// Orbis OS is FreeBSD-derived and has no fiber API we can rely on inside a
// GoldHEN plugin, so we do the context switch ourselves.
//
// This is plain System V AMD64: callee-saved registers are rbx, rbp and r12-r15,
// so a switch is "push those six, swap rsp, pop those six, ret". The PS4 CPU is
// x86-64 like any desktop, which means this file builds and runs identically on
// a Linux host — see ../tests/test_fiber.cpp.

#pragma once

#include <cstddef>
#include <cstdint>

namespace osh {

using FiberEntry = void (*)(void* user);

class Fiber {
 public:
  Fiber() = default;
  ~Fiber();

  Fiber(const Fiber&) = delete;
  Fiber& operator=(const Fiber&) = delete;

  // Allocates a stack and prepares the context. `stack_size` is rounded up to a
  // page. Returns false if the stack could not be allocated.
  bool create(FiberEntry entry, void* user, std::size_t stack_size = kDefaultStackSize);

  // Switches from the current context into this fiber. Returns when the fiber
  // calls yield() or finishes.
  void resume();

  // Switches from this fiber back to whoever resumed it. Only valid on the
  // currently running fiber.
  void yield();

  // Tears down the stack. Safe to call on a fiber that never ran.
  void destroy();

  bool alive() const { return stack_ != nullptr && !finished_; }
  bool finished() const { return finished_; }
  bool started() const { return started_; }

  // The fiber currently executing on this thread, or nullptr on the main context.
  static Fiber* current();

  static constexpr std::size_t kDefaultStackSize = 256 * 1024;

 private:
  static void trampoline();

  void* stack_ = nullptr;          // base of the mapping
  std::size_t stack_size_ = 0;
  void* sp_ = nullptr;             // saved stack pointer while suspended
  void* caller_sp_ = nullptr;      // saved stack pointer of whoever resumed us
  FiberEntry entry_ = nullptr;
  void* user_ = nullptr;
  bool started_ = false;
  bool finished_ = false;
};

}  // namespace osh
