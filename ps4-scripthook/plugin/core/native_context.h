// rage::scrNativeCallContext — the ABI every GTA V script native is called with.
//
// A native handler is `void(*)(NativeContext*)`. Arguments and the return value
// both live in a 64-bit slot array owned by the context; the engine reads
// m_args for inputs and writes through m_return for outputs, and ScriptHookV
// points both at the same scratch buffer. We keep that arrangement because it is
// what the handlers expect.
//
// Layout note: the first four members must stay at offsets 0x00/0x08/0x10/0x18.
// Everything after that is ours.

#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>

namespace osh {

struct Vector3 {
  float x = 0.0f;
  float y = 0.0f;
  float z = 0.0f;
};

class NativeContext {
 public:
  static constexpr std::uint32_t kMaxArgs = 32;
  static constexpr std::uint32_t kMaxVectorFixups = 4;

  NativeContext() { reset(); }

  void reset() {
    std::memset(stack_, 0, sizeof(stack_));
    std::memset(vector_targets_, 0, sizeof(vector_targets_));
    std::memset(vector_values_, 0, sizeof(vector_values_));
    m_return = stack_;
    m_args = stack_;
    m_arg_count = 0;
    m_data_count = 0;
  }

  // Pushes one argument. Values narrower than 8 bytes are zero-extended into
  // their slot, which is what the engine's own script VM does.
  template <typename T>
  bool push(T value) {
    static_assert(sizeof(T) <= sizeof(std::uint64_t), "native arguments are at most 8 bytes");
    if (m_arg_count >= kMaxArgs) return false;
    stack_[m_arg_count] = 0;
    std::memcpy(&stack_[m_arg_count], &value, sizeof(T));
    ++m_arg_count;
    return true;
  }

  // Natives that take a Vector3 by value receive three consecutive float args.
  bool push_vector(const Vector3& v) {
    return push<float>(v.x) && push<float>(v.y) && push<float>(v.z);
  }

  template <typename T>
  T result() const {
    T value{};
    std::memcpy(&value, stack_, sizeof(T));
    return value;
  }

  // Vector3 returns are written one component per 64-bit slot, low dword first.
  Vector3 vector_result() const {
    Vector3 v;
    std::memcpy(&v.x, &stack_[0], sizeof(float));
    std::memcpy(&v.y, &stack_[1], sizeof(float));
    std::memcpy(&v.z, &stack_[2], sizeof(float));
    return v;
  }

  std::uint32_t arg_count() const { return m_arg_count; }
  const std::uint64_t* slots() const { return stack_; }

  // The engine reads these four fields at fixed offsets. If a compiler ever
  // reorders or pads them differently, every native call would read garbage —
  // so fail the build instead.
  static void verify_layout() {
    static_assert(offsetof(NativeContext, m_return) == 0x00, "m_return must be at 0x00");
    static_assert(offsetof(NativeContext, m_arg_count) == 0x08, "m_arg_count must be at 0x08");
    static_assert(offsetof(NativeContext, m_args) == 0x10, "m_args must be at 0x10");
    static_assert(offsetof(NativeContext, m_data_count) == 0x18, "m_data_count must be at 0x18");
  }

 private:
  // --- engine-visible layout, do not reorder -------------------------------
  void* m_return;              // 0x00
  std::uint32_t m_arg_count;   // 0x08
  [[maybe_unused]] std::uint32_t m_pad0 = 0;  // 0x0C — explicit, never implicit
  void* m_args;                // 0x10
  std::uint32_t m_data_count;  // 0x18
  [[maybe_unused]] std::uint32_t m_pad1 = 0;  // 0x1C
  void* vector_targets_[kMaxVectorFixups];        // 0x20
  float vector_values_[kMaxVectorFixups][4];      // 0x40
  // --- ours ----------------------------------------------------------------
  std::uint64_t stack_[kMaxArgs];
};

using NativeHandler = void (*)(NativeContext*);

}  // namespace osh
