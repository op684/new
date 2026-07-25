// In-process signature scanning.
//
// The MCP server can scan over the wire while you are working things out; once a
// pattern is known good it moves in here so the plugin resolves it by itself at
// load time. That matters because module addresses shift with ASLR, so nothing
// can be hardcoded as an absolute address.

#pragma once

#include <cstddef>
#include <cstdint>

namespace osh {

// A compiled IDA-style pattern: `48 8B 05 ?? ?? ?? ?? 48 85 C0`.
class Pattern {
 public:
  static constexpr std::size_t kMaxBytes = 64;

  // Returns false if the text is malformed or longer than kMaxBytes.
  bool compile(const char* text);

  std::size_t size() const { return size_; }
  bool empty() const { return size_ == 0; }

  // Scans [begin, begin + length) and returns the first match, or nullptr.
  const std::uint8_t* find(const std::uint8_t* begin, std::size_t length) const;

  // Scans for the nth match (0-based).
  const std::uint8_t* find_nth(const std::uint8_t* begin, std::size_t length, std::size_t n) const;

  // Number of matches in the range, capped at `limit` so a bad pattern cannot
  // stall the game for seconds.
  std::size_t count(const std::uint8_t* begin, std::size_t length, std::size_t limit) const;

  bool matches_at(const std::uint8_t* at) const;

 private:
  std::uint8_t bytes_[kMaxBytes] = {};
  bool wildcard_[kMaxBytes] = {};
  std::size_t size_ = 0;
};

// Resolves a RIP-relative operand. `operand` points at the disp32; `next_insn`
// is the address of the following instruction.
inline std::uint8_t* resolve_rip(const std::uint8_t* operand, const std::uint8_t* next_insn) {
  std::int32_t displacement = 0;
  __builtin_memcpy(&displacement, operand, sizeof(displacement));
  return const_cast<std::uint8_t*>(next_insn) + displacement;
}

// Convenience: pattern hit -> RIP-relative target, where the disp32 sits
// `operand_offset` bytes into the match and the instruction is `insn_length` long.
inline std::uint8_t* rip_target(const std::uint8_t* hit, std::size_t operand_offset,
                                std::size_t insn_length) {
  return resolve_rip(hit + operand_offset, hit + insn_length);
}

}  // namespace osh
