#include "fiber.h"

#include <sys/mman.h>

#include <cstring>
#include <new>

namespace osh {
namespace {

// Which fiber is running on this thread. RAGE calls our tick from one thread, so
// thread_local is belt-and-braces rather than strictly required.
thread_local Fiber* g_current = nullptr;

constexpr std::size_t kPageSize = 0x4000;  // Orbis pages are 16 KiB.

std::size_t round_up(std::size_t value, std::size_t align) {
  return (value + align - 1) & ~(align - 1);
}

}  // namespace

// void osh_fiber_switch(void** save_sp, void* new_sp);
//
// Saves the six System V callee-saved registers on the current stack, records
// the resulting rsp through `save_sp`, then adopts `new_sp` and unwinds the
// mirror image. The `ret` at the end jumps to whatever the new context has
// sitting where a return address belongs.
extern "C" void osh_fiber_switch(void** save_sp, void* new_sp);

__asm__(
    ".text\n"
    ".globl osh_fiber_switch\n"
#if defined(__ELF__)
    ".type osh_fiber_switch,@function\n"
#endif
    "osh_fiber_switch:\n"
    "  pushq %rbp\n"
    "  pushq %rbx\n"
    "  pushq %r12\n"
    "  pushq %r13\n"
    "  pushq %r14\n"
    "  pushq %r15\n"
    "  movq  %rsp, (%rdi)\n"
    "  movq  %rsi, %rsp\n"
    "  popq  %r15\n"
    "  popq  %r14\n"
    "  popq  %r13\n"
    "  popq  %r12\n"
    "  popq  %rbx\n"
    "  popq  %rbp\n"
    "  ret\n"
#if defined(__ELF__)
    ".size osh_fiber_switch,.-osh_fiber_switch\n"
#endif
);

Fiber::~Fiber() { destroy(); }

bool Fiber::create(FiberEntry entry, void* user, std::size_t stack_size) {
  destroy();
  if (entry == nullptr) return false;

  stack_size_ = round_up(stack_size, kPageSize);
  void* mapping = mmap(nullptr, stack_size_, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (mapping == MAP_FAILED) {
    stack_size_ = 0;
    return false;
  }
  stack_ = mapping;
  entry_ = entry;
  user_ = user;
  started_ = false;
  finished_ = false;

  // Build the initial frame the switch routine will unwind.
  //
  // System V requires rsp % 16 == 8 on entry to a function (the call pushed a
  // return address). We reserve one slot for a return address that must never be
  // taken -- trampoline() never returns -- and lay the entry point above it.
  auto top = reinterpret_cast<std::uint8_t*>(stack_) + stack_size_;
  top = reinterpret_cast<std::uint8_t*>(reinterpret_cast<std::uintptr_t>(top) & ~std::uintptr_t{15});

  top -= sizeof(void*);
  *reinterpret_cast<void**>(top) = nullptr;  // unreachable return address

  top -= sizeof(void*);
  *reinterpret_cast<void**>(top) = reinterpret_cast<void*>(&Fiber::trampoline);

  top -= 6 * sizeof(void*);  // r15, r14, r13, r12, rbx, rbp
  std::memset(top, 0, 6 * sizeof(void*));

  sp_ = top;
  return true;
}

void Fiber::resume() {
  if (stack_ == nullptr || finished_) return;
  Fiber* previous = g_current;
  g_current = this;
  started_ = true;
  osh_fiber_switch(&caller_sp_, sp_);
  g_current = previous;
}

void Fiber::yield() {
  // Save where we are inside the fiber and hand control back to resume().
  osh_fiber_switch(&sp_, caller_sp_);
}

void Fiber::destroy() {
  if (stack_ != nullptr) {
    munmap(stack_, stack_size_);
    stack_ = nullptr;
    stack_size_ = 0;
  }
  sp_ = nullptr;
  caller_sp_ = nullptr;
  started_ = false;
  finished_ = false;
}

Fiber* Fiber::current() { return g_current; }

void Fiber::trampoline() {
  Fiber* self = g_current;
  self->entry_(self->user_);
  self->finished_ = true;
  // The fiber body returned. Hand control back for the last time; resume() will
  // refuse to re-enter because finished_ is set, so this never comes back.
  for (;;) self->yield();
}

}  // namespace osh
