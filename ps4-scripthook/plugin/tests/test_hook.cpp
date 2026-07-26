// Host tests for the inline detour.
//
// Rather than hooking a compiler-generated function (whose prologue varies with
// optimisation level, so a failure would tell you nothing), these tests build
// machine code byte by byte in an RWX mapping and hook that. The bytes are the
// same on a PS4 — it is the same instruction set.

#include <sys/mman.h>

#include <cstdint>
#include <cstdio>
#include <cstring>

#include "../orbis/hook.h"

namespace {

int g_failures = 0;
int g_checks = 0;

void check(bool condition, const char* what, int line) {
  ++g_checks;
  if (condition) return;
  ++g_failures;
  std::printf("  FAIL (line %d): %s\n", line, what);
}

#define CHECK(cond) check((cond), #cond, __LINE__)

void section(const char* name) { std::printf("== %s\n", name); }

using IntFn = int (*)();

// A complete little function:
//   55                 push rbp
//   48 89 e5           mov  rbp, rsp
//   48 83 ec 20        sub  rsp, 0x20
//   b8 34 12 00 00     mov  eax, 0x1234
//   48 83 c4 20        add  rsp, 0x20
//   5d                 pop  rbp
//   c3                 ret
//
// The first five instructions total 17 bytes, so the detour has room for its
// 14-byte jump and every displaced instruction is position-independent, which is
// what makes the trampoline valid.
const std::uint8_t kFunctionBody[] = {
    0x55,
    0x48, 0x89, 0xe5,
    0x48, 0x83, 0xec, 0x20,
    0xb8, 0x34, 0x12, 0x00, 0x00,
    0x48, 0x83, 0xc4, 0x20,
    0x5d,
    0xc3,
};

void* map_code(const std::uint8_t* bytes, std::size_t length) {
  void* page = mmap(nullptr, 0x4000, PROT_READ | PROT_WRITE | PROT_EXEC,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (page == MAP_FAILED) return nullptr;
  std::memcpy(page, bytes, length);
  return page;
}

int replacement() { return 0x5678; }

void test_instruction_length() {
  section("instruction length decoding");

  struct Case {
    const char* what;
    std::uint8_t bytes[16];
    std::size_t expected;
  };

  const Case cases[] = {
      {"push rbp", {0x55}, 1},
      {"pop rbp", {0x5d}, 1},
      {"ret", {0xc3}, 1},
      {"nop", {0x90}, 1},
      {"mov rbp, rsp", {0x48, 0x89, 0xe5}, 3},
      {"sub rsp, 0x20", {0x48, 0x83, 0xec, 0x20}, 4},
      {"mov eax, imm32", {0xb8, 0x34, 0x12, 0x00, 0x00}, 5},
      {"mov rax, imm64", {0x48, 0xb8, 1, 2, 3, 4, 5, 6, 7, 8}, 10},
      {"mov [rsp+8], rbx", {0x48, 0x89, 0x5c, 0x24, 0x08}, 5},
      {"lea rcx, [rip+disp32]", {0x48, 0x8d, 0x0d, 0x11, 0x22, 0x33, 0x44}, 7},
      {"mov rax, [rip+disp32]", {0x48, 0x8b, 0x05, 0x11, 0x22, 0x33, 0x44}, 7},
      {"test rax, rax", {0x48, 0x85, 0xc0}, 3},
      {"xor eax, eax", {0x31, 0xc0}, 2},
      {"cmp byte [rcx+8], 0", {0x80, 0x79, 0x08, 0x00}, 4},
      {"mov dword [rsp+0x10], imm32", {0xc7, 0x44, 0x24, 0x10, 1, 0, 0, 0}, 8},
      {"jmp rel32", {0xe9, 0x11, 0x22, 0x33, 0x44}, 5},
      {"call rel32", {0xe8, 0x11, 0x22, 0x33, 0x44}, 5},
      {"jmp rel8", {0xeb, 0x10}, 2},
      {"jz rel32", {0x0f, 0x84, 0x11, 0x22, 0x33, 0x44}, 6},
      {"movzx eax, byte [rcx]", {0x0f, 0xb6, 0x01}, 3},
      {"sub rsp, imm32", {0x48, 0x81, 0xec, 0x00, 0x01, 0x00, 0x00}, 7},
      {"push r15", {0x41, 0x57}, 2},
  };

  for (const auto& item : cases) {
    const std::size_t got = osh::instruction_length(item.bytes);
    if (got != item.expected) {
      std::printf("  FAIL: %s decoded as %zu bytes, expected %zu\n", item.what, got,
                  item.expected);
      ++g_failures;
    }
    ++g_checks;
  }

  // Unknown opcodes must report 0 so the detour refuses rather than guessing.
  const std::uint8_t unknown[] = {0x62, 0xf1, 0x7c, 0x48};  // EVEX-prefixed AVX-512
  CHECK(osh::instruction_length(unknown) == 0);
}

void test_absolute_jump_encoding() {
  section("absolute jump encoding");

  std::uint8_t buffer[16] = {};
  const void* destination = reinterpret_cast<const void*>(0x0123456789abcdefULL);
  osh::write_absolute_jump(buffer, destination);

  const std::uint8_t expected_prefix[] = {0xff, 0x25, 0x00, 0x00, 0x00, 0x00};
  CHECK(std::memcmp(buffer, expected_prefix, sizeof(expected_prefix)) == 0);

  std::uint64_t encoded = 0;
  std::memcpy(&encoded, buffer + 6, sizeof(encoded));
  CHECK(encoded == 0x0123456789abcdefULL);
}

void test_detour_round_trip() {
  section("detour install / call original / remove");

  void* code = map_code(kFunctionBody, sizeof(kFunctionBody));
  CHECK(code != nullptr);
  if (code == nullptr) return;

  auto function = reinterpret_cast<IntFn>(code);
  CHECK(function() == 0x1234);

  osh::Detour detour;
  CHECK(detour.install(code, reinterpret_cast<void*>(&replacement)));
  CHECK(detour.installed());

  // The hooked function now runs our replacement...
  CHECK(function() == 0x5678);
  // ...and the trampoline still runs the original body.
  CHECK(detour.original<IntFn>()() == 0x1234);

  detour.remove();
  CHECK(!detour.installed());
  CHECK(function() == 0x1234);
  // The original bytes are back verbatim.
  CHECK(std::memcmp(code, kFunctionBody, sizeof(kFunctionBody)) == 0);

  // Re-installing after removal works.
  CHECK(detour.install(code, reinterpret_cast<void*>(&replacement)));
  CHECK(function() == 0x5678);
  detour.remove();
  CHECK(function() == 0x1234);

  munmap(code, 0x4000);
}

void test_detour_refuses_undecodable_prologue() {
  section("detour refuses what it cannot decode");

  // Starts with an EVEX prefix the decoder does not know.
  const std::uint8_t opaque[] = {0x62, 0xf1, 0x7c, 0x48, 0x28, 0xc1, 0xc3};
  void* code = map_code(opaque, sizeof(opaque));
  CHECK(code != nullptr);
  if (code == nullptr) return;

  osh::Detour detour;
  CHECK(!detour.install(code, reinterpret_cast<void*>(&replacement)));
  CHECK(!detour.installed());
  // Refusing must leave the target untouched.
  CHECK(std::memcmp(code, opaque, sizeof(opaque)) == 0);

  // Null arguments are rejected too.
  CHECK(!detour.install(nullptr, reinterpret_cast<void*>(&replacement)));
  CHECK(!detour.install(code, nullptr));

  munmap(code, 0x4000);
}

}  // namespace

int main() {
  test_instruction_length();
  test_absolute_jump_encoding();
  test_detour_round_trip();
  test_detour_refuses_undecodable_prologue();

  std::printf("\n%d checks, %d failure(s)\n", g_checks, g_failures);
  return g_failures == 0 ? 0 : 1;
}
