// Minimal x86-64 inline detour.
//
// We overwrite the first bytes of a target function with an absolute jump to our
// replacement, after copying the displaced instructions into a trampoline so the
// original can still be called. This is the standard technique; the only Orbis
// wrinkle is that code pages must be made writable first, which needs the
// GoldHEN/libkernel mprotect wrapper rather than plain mprotect.
//
// The instruction-length decoder here is deliberately small: it understands the
// prologue encodings GTA V's compiler actually emits (push/mov/sub/lea/test/jmp
// forms) and refuses anything it does not recognise instead of guessing. A
// refusal is a loud log line, not a silent corruption.

#pragma once

#include <cstddef>
#include <cstdint>

namespace osh {

class Detour {
 public:
  Detour() = default;
  ~Detour();

  Detour(const Detour&) = delete;
  Detour& operator=(const Detour&) = delete;

  // Redirects `target` to `replacement`. Returns false and logs if the prologue
  // could not be decoded or memory could not be made writable.
  bool install(void* target, void* replacement);

  // Restores the original bytes.
  void remove();

  // Call the original function through the trampoline.
  template <typename Fn>
  Fn original() const {
    return reinterpret_cast<Fn>(trampoline_);
  }

  bool installed() const { return installed_; }

 private:
  static constexpr std::size_t kJumpSize = 14;   // FF 25 00000000 + 8-byte target
  static constexpr std::size_t kMaxStolen = 32;

  void* target_ = nullptr;
  void* trampoline_ = nullptr;
  std::uint8_t original_[kMaxStolen] = {};
  std::size_t stolen_ = 0;
  bool installed_ = false;
};

// Length of the instruction at `code`, or 0 if this decoder does not know it.
std::size_t instruction_length(const std::uint8_t* code);

// Makes [address, address+size) writable and executable. Returns false on failure.
bool unprotect(void* address, std::size_t size);

// Writes an absolute `jmp [rip+0]; .quad destination` at `at` (14 bytes).
void write_absolute_jump(std::uint8_t* at, const void* destination);

}  // namespace osh
