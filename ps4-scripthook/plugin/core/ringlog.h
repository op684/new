// Fixed-size in-memory log.
//
// There is no console to print to inside a game process, and writing to disk on
// every line would stall the render thread. Lines land in a ring buffer that
// `scripthook_log` drains over the control channel.

#pragma once

#include <cstdarg>
#include <cstddef>

namespace osh {

class RingLog {
 public:
  static constexpr std::size_t kLines = 256;
  static constexpr std::size_t kLineLength = 192;

  void write(const char* text);
  void writef(const char* format, ...) __attribute__((format(printf, 2, 3)));
  void vwritef(const char* format, std::va_list args);

  // Copies up to `max_lines` of the most recent history, oldest first, into
  // `out` (an array of at least max_lines * kLineLength bytes). Returns the
  // number of lines written.
  std::size_t tail(char* out, std::size_t max_lines) const;

  // Lines lost to overwrite since the log started.
  std::size_t dropped() const { return dropped_; }
  std::size_t size() const { return count_ < kLines ? count_ : kLines; }

  static RingLog& instance();

 private:
  char lines_[kLines][kLineLength] = {};
  std::size_t count_ = 0;    // total lines ever written
  std::size_t dropped_ = 0;
};

}  // namespace osh

#define OSH_LOG(...) ::osh::RingLog::instance().writef(__VA_ARGS__)
