// A small JSON reader/writer for the control channel.
//
// The plugin runs inside a game process with no allocator we want to lean on
// during a frame, so this parses into a fixed-size node pool and writes into a
// caller-supplied buffer. It handles the subset the control protocol uses:
// objects, arrays, strings, numbers, booleans and null. No unicode escapes
// beyond passing them through as a placeholder.

#pragma once

#include <cstddef>
#include <cstdint>

namespace osh {

class Json {
 public:
  enum class Type : std::uint8_t { kNull, kBool, kNumber, kString, kArray, kObject };

  static constexpr int kNone = -1;
  static constexpr std::size_t kMaxNodes = 256;

  // Parses `text` in place: string values are unescaped into the same buffer, so
  // the buffer must stay alive and writable for as long as the Json is used.
  bool parse(char* text, std::size_t length);

  int root() const { return root_; }
  Type type(int node) const;

  // Object lookup. Returns kNone when absent or when `node` is not an object.
  int find(int node, const char* key) const;

  // Array/object iteration.
  int first_child(int node) const;
  int next_sibling(int node) const;
  int size(int node) const;

  // Accessors. Each returns the fallback when the node is missing or the wrong
  // type, so callers can treat malformed input as "field absent".
  const char* string(int node, const char* fallback = "") const;
  double number(int node, double fallback = 0.0) const;
  bool boolean(int node, bool fallback = false) const;

  // Convenience: look up a key and read it in one step.
  const char* string_field(int node, const char* key, const char* fallback = "") const {
    return string(find(node, key), fallback);
  }
  double number_field(int node, const char* key, double fallback = 0.0) const {
    return number(find(node, key), fallback);
  }
  bool bool_field(int node, const char* key, bool fallback = false) const {
    return boolean(find(node, key), fallback);
  }

  const char* error() const { return error_; }

 private:
  struct Node {
    Type type = Type::kNull;
    const char* text = nullptr;   // string value, NUL-terminated in place
    double number = 0.0;
    bool boolean = false;
    const char* key = nullptr;    // for object members
    int first_child = kNone;
    int next_sibling = kNone;
  };

  int allocate(Type type);
  int parse_value();
  int parse_object();
  int parse_array();
  int parse_string_node();
  int parse_number();
  int parse_literal();
  char* parse_string_raw();
  void skip_space();
  bool fail(const char* message);

  Node nodes_[kMaxNodes];
  std::size_t used_ = 0;
  char* cursor_ = nullptr;
  char* end_ = nullptr;
  int root_ = kNone;
  const char* error_ = "";
};

// Append-only JSON writer with escaping. Truncates rather than overflowing;
// `overflowed()` reports whether anything was lost.
class JsonWriter {
 public:
  JsonWriter(char* buffer, std::size_t capacity) : buffer_(buffer), capacity_(capacity) {
    if (capacity_ > 0) buffer_[0] = '\0';
  }

  void begin_object();
  void end_object();
  void begin_array();
  void end_array();

  void key(const char* name);
  void value_string(const char* text);
  void value_number(double value);
  void value_bool(bool value);
  void value_null();

  void field_string(const char* name, const char* text);
  void field_number(const char* name, double value);
  void field_bool(const char* name, bool value);

  std::size_t length() const { return length_; }
  bool overflowed() const { return overflowed_; }
  const char* c_str() const { return buffer_; }

 private:
  void raw(const char* text);
  void raw_char(char c);
  void separator();

  char* buffer_;
  std::size_t capacity_;
  std::size_t length_ = 0;
  bool overflowed_ = false;
  bool need_comma_ = false;
};

}  // namespace osh
