// RAGE's Jenkins one-at-a-time string hash.
//
// This is what GET_HASH_KEY computes and what model/weapon/anim names hash to.
// It is NOT how native hashes are derived — see ../orbis/crossmap.h.

#pragma once

#include <cstdint>

namespace osh {

constexpr char to_lower(char c) { return (c >= 'A' && c <= 'Z') ? static_cast<char>(c + 32) : c; }

constexpr std::uint32_t joaat(const char* text) {
  std::uint32_t hash = 0;
  for (; *text != '\0'; ++text) {
    hash += static_cast<std::uint8_t>(to_lower(*text));
    hash += hash << 10;
    hash ^= hash >> 6;
  }
  hash += hash << 3;
  hash ^= hash >> 11;
  hash += hash << 15;
  return hash;
}

}  // namespace osh
