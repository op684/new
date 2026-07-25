#include "pattern.h"

namespace osh {
namespace {

int hex_value(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

bool is_space(char c) { return c == ' ' || c == '\t' || c == '\n' || c == '\r'; }

}  // namespace

bool Pattern::compile(const char* text) {
  size_ = 0;
  if (text == nullptr) return false;

  for (const char* cursor = text; *cursor != '\0';) {
    while (is_space(*cursor)) ++cursor;
    if (*cursor == '\0') break;
    if (size_ >= kMaxBytes) return false;

    if (*cursor == '?') {
      ++cursor;
      if (*cursor == '?') ++cursor;
      bytes_[size_] = 0;
      wildcard_[size_] = true;
      ++size_;
      continue;
    }

    const int high = hex_value(cursor[0]);
    if (high < 0) return false;
    const int low = hex_value(cursor[1]);
    if (low < 0) return false;  // single-nibble tokens are a typo, not a feature
    bytes_[size_] = static_cast<std::uint8_t>((high << 4) | low);
    wildcard_[size_] = false;
    ++size_;
    cursor += 2;
  }
  return size_ > 0;
}

bool Pattern::matches_at(const std::uint8_t* at) const {
  for (std::size_t i = 0; i < size_; ++i) {
    if (!wildcard_[i] && at[i] != bytes_[i]) return false;
  }
  return true;
}

const std::uint8_t* Pattern::find(const std::uint8_t* begin, std::size_t length) const {
  return find_nth(begin, length, 0);
}

const std::uint8_t* Pattern::find_nth(const std::uint8_t* begin, std::size_t length,
                                      std::size_t n) const {
  if (size_ == 0 || length < size_) return nullptr;
  const std::size_t last = length - size_;
  std::size_t seen = 0;
  for (std::size_t i = 0; i <= last; ++i) {
    if (!matches_at(begin + i)) continue;
    if (seen == n) return begin + i;
    ++seen;
  }
  return nullptr;
}

std::size_t Pattern::count(const std::uint8_t* begin, std::size_t length, std::size_t limit) const {
  if (size_ == 0 || length < size_) return 0;
  const std::size_t last = length - size_;
  std::size_t hits = 0;
  for (std::size_t i = 0; i <= last && hits < limit; ++i) {
    if (matches_at(begin + i)) ++hits;
  }
  return hits;
}

}  // namespace osh
