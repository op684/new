#include "ringlog.h"

#include <cstdio>
#include <cstring>

namespace osh {

void RingLog::write(const char* text) {
  if (text == nullptr) return;
  const std::size_t slot = count_ % kLines;
  if (count_ >= kLines) ++dropped_;
  std::snprintf(lines_[slot], kLineLength, "%s", text);
  ++count_;
}

void RingLog::writef(const char* format, ...) {
  std::va_list args;
  va_start(args, format);
  vwritef(format, args);
  va_end(args);
}

void RingLog::vwritef(const char* format, std::va_list args) {
  const std::size_t slot = count_ % kLines;
  if (count_ >= kLines) ++dropped_;
  std::vsnprintf(lines_[slot], kLineLength, format, args);
  ++count_;
}

std::size_t RingLog::tail(char* out, std::size_t max_lines) const {
  const std::size_t available = size();
  const std::size_t wanted = max_lines < available ? max_lines : available;
  // Oldest line of the window we are returning.
  const std::size_t first = count_ - wanted;
  for (std::size_t i = 0; i < wanted; ++i) {
    const std::size_t slot = (first + i) % kLines;
    std::memcpy(out + i * kLineLength, lines_[slot], kLineLength);
  }
  return wanted;
}

RingLog& RingLog::instance() {
  static RingLog log;
  return log;
}

}  // namespace osh
