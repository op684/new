#include "json.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace osh {

// ------------------------------------------------------------------ reader

bool Json::fail(const char* message) {
  error_ = message;
  root_ = kNone;
  return false;
}

int Json::allocate(Type type) {
  if (used_ >= kMaxNodes) return kNone;
  const int index = static_cast<int>(used_++);
  nodes_[index] = Node{};
  nodes_[index].type = type;
  return index;
}

void Json::skip_space() {
  while (cursor_ < end_ && (*cursor_ == ' ' || *cursor_ == '\t' || *cursor_ == '\n' ||
                            *cursor_ == '\r')) {
    ++cursor_;
  }
}

// Reads a quoted string, unescaping in place and NUL-terminating it. Returns a
// pointer to the first character, or nullptr on malformed input.
char* Json::parse_string_raw() {
  if (cursor_ >= end_ || *cursor_ != '"') return nullptr;
  ++cursor_;

  char* out = cursor_;
  char* start = cursor_;
  while (cursor_ < end_ && *cursor_ != '"') {
    if (*cursor_ != '\\') {
      *out++ = *cursor_++;
      continue;
    }
    ++cursor_;
    if (cursor_ >= end_) return nullptr;
    switch (*cursor_) {
      case '"': *out++ = '"'; break;
      case '\\': *out++ = '\\'; break;
      case '/': *out++ = '/'; break;
      case 'b': *out++ = '\b'; break;
      case 'f': *out++ = '\f'; break;
      case 'n': *out++ = '\n'; break;
      case 'r': *out++ = '\r'; break;
      case 't': *out++ = '\t'; break;
      case 'u':
        // The control protocol is ASCII; keep the placeholder rather than
        // pulling in a UTF-8 encoder.
        if (cursor_ + 4 >= end_) return nullptr;
        cursor_ += 4;
        *out++ = '?';
        break;
      default:
        return nullptr;
    }
    ++cursor_;
  }
  if (cursor_ >= end_) return nullptr;  // unterminated
  ++cursor_;                            // consume the closing quote
  *out = '\0';
  return start;
}

int Json::parse_string_node() {
  char* text = parse_string_raw();
  if (text == nullptr) return kNone;
  const int node = allocate(Type::kString);
  if (node == kNone) return kNone;
  nodes_[node].text = text;
  return node;
}

int Json::parse_number() {
  char* parse_end = nullptr;
  const double value = std::strtod(cursor_, &parse_end);
  if (parse_end == cursor_) return kNone;
  cursor_ = parse_end;
  const int node = allocate(Type::kNumber);
  if (node == kNone) return kNone;
  nodes_[node].number = value;
  return node;
}

int Json::parse_literal() {
  const std::size_t remaining = static_cast<std::size_t>(end_ - cursor_);
  if (remaining >= 4 && std::strncmp(cursor_, "true", 4) == 0) {
    cursor_ += 4;
    const int node = allocate(Type::kBool);
    if (node != kNone) nodes_[node].boolean = true;
    return node;
  }
  if (remaining >= 5 && std::strncmp(cursor_, "false", 5) == 0) {
    cursor_ += 5;
    const int node = allocate(Type::kBool);
    if (node != kNone) nodes_[node].boolean = false;
    return node;
  }
  if (remaining >= 4 && std::strncmp(cursor_, "null", 4) == 0) {
    cursor_ += 4;
    return allocate(Type::kNull);
  }
  return kNone;
}

int Json::parse_array() {
  ++cursor_;  // '['
  const int node = allocate(Type::kArray);
  if (node == kNone) return kNone;

  int last = kNone;
  skip_space();
  if (cursor_ < end_ && *cursor_ == ']') {
    ++cursor_;
    return node;
  }
  for (;;) {
    skip_space();
    const int child = parse_value();
    if (child == kNone) return kNone;
    if (last == kNone) nodes_[node].first_child = child;
    else nodes_[last].next_sibling = child;
    last = child;

    skip_space();
    if (cursor_ >= end_) return kNone;
    if (*cursor_ == ',') {
      ++cursor_;
      continue;
    }
    if (*cursor_ == ']') {
      ++cursor_;
      return node;
    }
    return kNone;
  }
}

int Json::parse_object() {
  ++cursor_;  // '{'
  const int node = allocate(Type::kObject);
  if (node == kNone) return kNone;

  int last = kNone;
  skip_space();
  if (cursor_ < end_ && *cursor_ == '}') {
    ++cursor_;
    return node;
  }
  for (;;) {
    skip_space();
    char* key = parse_string_raw();
    if (key == nullptr) return kNone;
    skip_space();
    if (cursor_ >= end_ || *cursor_ != ':') return kNone;
    ++cursor_;
    skip_space();

    const int child = parse_value();
    if (child == kNone) return kNone;
    nodes_[child].key = key;
    if (last == kNone) nodes_[node].first_child = child;
    else nodes_[last].next_sibling = child;
    last = child;

    skip_space();
    if (cursor_ >= end_) return kNone;
    if (*cursor_ == ',') {
      ++cursor_;
      continue;
    }
    if (*cursor_ == '}') {
      ++cursor_;
      return node;
    }
    return kNone;
  }
}

int Json::parse_value() {
  skip_space();
  if (cursor_ >= end_) return kNone;
  switch (*cursor_) {
    case '{': return parse_object();
    case '[': return parse_array();
    case '"': return parse_string_node();
    case 't': case 'f': case 'n': return parse_literal();
    default: return parse_number();
  }
}

bool Json::parse(char* text, std::size_t length) {
  used_ = 0;
  root_ = kNone;
  error_ = "";
  if (text == nullptr || length == 0) return fail("empty document");

  cursor_ = text;
  end_ = text + length;
  root_ = parse_value();
  if (root_ == kNone) {
    return fail(used_ >= kMaxNodes ? "document too large" : "malformed JSON");
  }
  skip_space();
  if (cursor_ != end_ && *cursor_ != '\0') return fail("trailing data after the value");
  return true;
}

Json::Type Json::type(int node) const {
  if (node < 0 || static_cast<std::size_t>(node) >= used_) return Type::kNull;
  return nodes_[node].type;
}

int Json::find(int node, const char* key) const {
  if (node < 0 || static_cast<std::size_t>(node) >= used_) return kNone;
  if (nodes_[node].type != Type::kObject || key == nullptr) return kNone;
  for (int child = nodes_[node].first_child; child != kNone; child = nodes_[child].next_sibling) {
    if (nodes_[child].key != nullptr && std::strcmp(nodes_[child].key, key) == 0) return child;
  }
  return kNone;
}

int Json::first_child(int node) const {
  if (node < 0 || static_cast<std::size_t>(node) >= used_) return kNone;
  return nodes_[node].first_child;
}

int Json::next_sibling(int node) const {
  if (node < 0 || static_cast<std::size_t>(node) >= used_) return kNone;
  return nodes_[node].next_sibling;
}

int Json::size(int node) const {
  int count = 0;
  for (int child = first_child(node); child != kNone; child = next_sibling(child)) ++count;
  return count;
}

const char* Json::string(int node, const char* fallback) const {
  if (type(node) != Type::kString) return fallback;
  return nodes_[node].text;
}

double Json::number(int node, double fallback) const {
  const Type kind = type(node);
  if (kind == Type::kNumber) return nodes_[node].number;
  // Numbers arriving as strings ("0x1234") are common in this protocol.
  if (kind == Type::kString) {
    const char* text = nodes_[node].text;
    char* parse_end = nullptr;
    const bool is_hex = text[0] == '0' && (text[1] == 'x' || text[1] == 'X');
    const double value = is_hex
                             ? static_cast<double>(std::strtoull(text + 2, &parse_end, 16))
                             : std::strtod(text, &parse_end);
    if (parse_end != text && parse_end != nullptr && *parse_end == '\0') return value;
  }
  return fallback;
}

bool Json::boolean(int node, bool fallback) const {
  const Type kind = type(node);
  if (kind == Type::kBool) return nodes_[node].boolean;
  if (kind == Type::kNumber) return nodes_[node].number != 0.0;
  return fallback;
}

// ------------------------------------------------------------------ writer

void JsonWriter::raw_char(char c) {
  if (length_ + 1 >= capacity_) {
    overflowed_ = true;
    return;
  }
  buffer_[length_++] = c;
  buffer_[length_] = '\0';
}

void JsonWriter::raw(const char* text) {
  for (const char* c = text; *c != '\0'; ++c) raw_char(*c);
}

void JsonWriter::separator() {
  if (need_comma_) raw_char(',');
  need_comma_ = true;
}

void JsonWriter::begin_object() {
  separator();
  raw_char('{');
  need_comma_ = false;
}

void JsonWriter::end_object() {
  raw_char('}');
  need_comma_ = true;
}

void JsonWriter::begin_array() {
  separator();
  raw_char('[');
  need_comma_ = false;
}

void JsonWriter::end_array() {
  raw_char(']');
  need_comma_ = true;
}

void JsonWriter::key(const char* name) {
  separator();
  need_comma_ = false;
  value_string(name);
  raw_char(':');
  need_comma_ = false;
}

void JsonWriter::value_string(const char* text) {
  separator();
  raw_char('"');
  for (const char* c = text; *c != '\0'; ++c) {
    switch (*c) {
      case '"': raw("\\\""); break;
      case '\\': raw("\\\\"); break;
      case '\n': raw("\\n"); break;
      case '\r': raw("\\r"); break;
      case '\t': raw("\\t"); break;
      default:
        if (static_cast<unsigned char>(*c) < 0x20) {
          char escape[8];
          std::snprintf(escape, sizeof(escape), "\\u%04x", static_cast<unsigned char>(*c));
          raw(escape);
        } else {
          raw_char(*c);
        }
    }
  }
  raw_char('"');
}

void JsonWriter::value_number(double value) {
  separator();
  char text[40];
  // Integral values print without a decimal point so hashes and handles read
  // the way callers expect.
  if (value == static_cast<double>(static_cast<long long>(value))) {
    std::snprintf(text, sizeof(text), "%lld", static_cast<long long>(value));
  } else {
    std::snprintf(text, sizeof(text), "%.6f", value);
  }
  raw(text);
}

void JsonWriter::value_bool(bool value) {
  separator();
  raw(value ? "true" : "false");
}

void JsonWriter::value_null() {
  separator();
  raw("null");
}

void JsonWriter::field_string(const char* name, const char* text) {
  key(name);
  value_string(text);
}

void JsonWriter::field_number(const char* name, double value) {
  key(name);
  value_number(value);
}

void JsonWriter::field_bool(const char* name, bool value) {
  key(name);
  value_bool(value);
}

}  // namespace osh
