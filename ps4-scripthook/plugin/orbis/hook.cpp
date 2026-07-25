#include "hook.h"

#include <sys/mman.h>

#include <cstring>

#include "../core/ringlog.h"

namespace osh {
namespace {

constexpr std::size_t kPageSize = 0x4000;

bool has_rex(std::uint8_t byte) { return byte >= 0x40 && byte <= 0x4f; }

// ModRM decoding: returns the total length of the ModRM byte plus SIB and
// displacement, given the byte at `modrm`.
std::size_t modrm_length(const std::uint8_t* modrm) {
  const std::uint8_t mod = (*modrm >> 6) & 3;
  const std::uint8_t rm = *modrm & 7;
  std::size_t length = 1;
  if (mod != 3 && rm == 4) ++length;  // SIB present
  switch (mod) {
    case 0:
      // [rip+disp32] and SIB-with-no-base both carry a disp32.
      if (rm == 5) length += 4;
      else if (rm == 4 && (modrm[1] & 7) == 5) length += 4;
      break;
    case 1:
      length += 1;
      break;
    case 2:
      length += 4;
      break;
    default:
      break;
  }
  return length;
}

}  // namespace

std::size_t instruction_length(const std::uint8_t* code) {
  std::size_t offset = 0;

  // Legacy prefixes we might plausibly meet in a prologue.
  while (code[offset] == 0x66 || code[offset] == 0x67 || code[offset] == 0xf2 ||
         code[offset] == 0xf3) {
    ++offset;
    if (offset > 4) return 0;
  }
  std::uint8_t rex = 0;
  if (has_rex(code[offset])) {
    rex = code[offset];
    ++offset;
  }

  const std::uint8_t opcode = code[offset];
  switch (opcode) {
    case 0x50: case 0x51: case 0x52: case 0x53:  // push r64
    case 0x54: case 0x55: case 0x56: case 0x57:
    case 0x58: case 0x59: case 0x5a: case 0x5b:  // pop r64
    case 0x5c: case 0x5d: case 0x5e: case 0x5f:
    case 0x90:                                   // nop
    case 0xc3:                                   // ret
      return offset + 1;

    case 0x88: case 0x89: case 0x8a: case 0x8b:  // mov r/m,r and r,r/m
    case 0x8d:                                   // lea
    case 0x84: case 0x85:                        // test
    case 0x30: case 0x31: case 0x32: case 0x33:  // xor
    case 0x28: case 0x29: case 0x2a: case 0x2b:  // sub
    case 0x00: case 0x01: case 0x02: case 0x03:  // add
    case 0x38: case 0x39: case 0x3a: case 0x3b:  // cmp
      return offset + 1 + modrm_length(code + offset + 1);

    case 0x80:                                   // group1 r/m8, imm8
    case 0x83:                                   // group1 r/m, imm8
      return offset + 1 + modrm_length(code + offset + 1) + 1;

    case 0x81:                                   // group1 r/m, imm32
      return offset + 1 + modrm_length(code + offset + 1) + 4;

    case 0xc6:                                   // mov r/m8, imm8
      return offset + 1 + modrm_length(code + offset + 1) + 1;

    case 0xc7:                                   // mov r/m32/64, imm32
      return offset + 1 + modrm_length(code + offset + 1) + 4;

    case 0xb8: case 0xb9: case 0xba: case 0xbb:  // mov r32, imm32 — imm64 under REX.W
    case 0xbc: case 0xbd: case 0xbe: case 0xbf:
      return offset + 1 + ((rex & 0x08) != 0 ? 8 : 4);

    case 0xe9:                                   // jmp rel32
    case 0xe8:                                   // call rel32
      return offset + 5;

    case 0xeb:                                   // jmp rel8
      return offset + 2;

    default:
      if (opcode == 0x0f) {
        const std::uint8_t second = code[offset + 1];
        // Two-byte jcc rel32.
        if (second >= 0x80 && second <= 0x8f) return offset + 6;
        // movzx/movsx and setcc.
        if (second == 0xb6 || second == 0xb7 || second == 0xbe || second == 0xbf ||
            (second >= 0x90 && second <= 0x9f)) {
          return offset + 2 + modrm_length(code + offset + 2);
        }
      }
      return 0;  // unknown — caller must refuse to hook
  }
}

bool unprotect(void* address, std::size_t size) {
  auto base = reinterpret_cast<std::uintptr_t>(address) & ~(kPageSize - 1);
  const auto end = reinterpret_cast<std::uintptr_t>(address) + size;
  const std::size_t length = end - base;
  if (mprotect(reinterpret_cast<void*>(base), length,
               PROT_READ | PROT_WRITE | PROT_EXEC) == 0) {
    return true;
  }
  OSH_LOG("mprotect(%p, %zu) failed — cannot patch this page", address, size);
  return false;
}

void write_absolute_jump(std::uint8_t* at, const void* destination) {
  // ff 25 00 00 00 00     jmp qword ptr [rip+0]
  // <8-byte absolute target>
  at[0] = 0xff;
  at[1] = 0x25;
  at[2] = 0x00;
  at[3] = 0x00;
  at[4] = 0x00;
  at[5] = 0x00;
  std::memcpy(at + 6, &destination, sizeof(destination));
}

Detour::~Detour() { remove(); }

bool Detour::install(void* target, void* replacement) {
  if (installed_ || target == nullptr || replacement == nullptr) return false;

  auto* code = static_cast<std::uint8_t*>(target);

  // Steal whole instructions until we have room for the jump.
  stolen_ = 0;
  while (stolen_ < kJumpSize) {
    const std::size_t length = instruction_length(code + stolen_);
    if (length == 0 || stolen_ + length > kMaxStolen) {
      OSH_LOG("refusing to hook %p: undecodable instruction at +%zu (%02x %02x %02x)", target,
              stolen_, code[stolen_], code[stolen_ + 1], code[stolen_ + 2]);
      stolen_ = 0;
      return false;
    }
    stolen_ += length;
  }

  // Trampoline: displaced instructions, then a jump back to the remainder.
  const std::size_t trampoline_size = stolen_ + kJumpSize;
  void* trampoline = mmap(nullptr, kPageSize, PROT_READ | PROT_WRITE | PROT_EXEC,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (trampoline == MAP_FAILED) {
    OSH_LOG("could not allocate a trampoline page for %p", target);
    stolen_ = 0;
    return false;
  }
  auto* tramp = static_cast<std::uint8_t*>(trampoline);
  std::memcpy(tramp, code, stolen_);
  write_absolute_jump(tramp + stolen_, code + stolen_);
  (void)trampoline_size;

  if (!unprotect(target, kJumpSize)) {
    munmap(trampoline, kPageSize);
    stolen_ = 0;
    return false;
  }

  std::memcpy(original_, code, stolen_);
  write_absolute_jump(code, replacement);
  // Anything left over from the displaced instructions becomes int3 so a stray
  // jump into the middle traps instead of executing half an instruction.
  for (std::size_t i = kJumpSize; i < stolen_; ++i) code[i] = 0xcc;

  target_ = target;
  trampoline_ = trampoline;
  installed_ = true;
  OSH_LOG("hooked %p -> %p (stole %zu bytes, trampoline %p)", target, replacement, stolen_,
          trampoline);
  return true;
}

void Detour::remove() {
  if (!installed_) return;
  if (unprotect(target_, stolen_)) {
    std::memcpy(target_, original_, stolen_);
  }
  if (trampoline_ != nullptr) munmap(trampoline_, kPageSize);
  trampoline_ = nullptr;
  target_ = nullptr;
  stolen_ = 0;
  installed_ = false;
}

}  // namespace osh
