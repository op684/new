#include "crossmap.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "../core/ringlog.h"

namespace osh {
namespace {

// A deliberately tiny seed set: the b323 PC hashes for natives every trainer
// touches. They are here so a fresh install has something to smoke-test with,
// NOT because they are guaranteed correct for a PS4 build. If these resolve on
// your console, the build shares b323's table; if they do not, supply
// natives.txt. Either way scripthook_log tells you which happened.
struct Builtin {
  const char* name;
  std::uint64_t hash;
};

constexpr Builtin kBuiltins[] = {
    {"GET_PLAYER_PED", 0x43A66C31},
    {"PLAYER_PED_ID", 0xD80958FC},
    {"PLAYER_ID", 0x4F8644AF},
    {"SET_ENTITY_HEALTH", 0x6B76DC1F},
    {"GET_ENTITY_HEALTH", 0xEEF059FA},
    {"SET_ENTITY_COORDS", 0x06843DA7},
    {"GET_ENTITY_COORDS", 0x3FEF770D},
    {"SET_ENTITY_INVINCIBLE", 0x3882114B},
    {"GET_HASH_KEY", 0xD24D37CC},
    {"WAIT", 0x4EDE34FB},
};

}  // namespace

bool Crossmap::insert(const char* name, std::uint64_t hash) {
  if (name == nullptr || name[0] == '\0' || hash == 0) return false;

  // Replace an existing entry so natives.txt can override a built-in.
  for (std::size_t i = 0; i < size_; ++i) {
    if (std::strncmp(entries_[i].name, name, kNameLength) == 0) {
      entries_[i].hash = hash;
      return true;
    }
  }
  if (size_ >= kCapacity) return false;
  std::snprintf(entries_[size_].name, kNameLength, "%s", name);
  entries_[size_].hash = hash;
  ++size_;
  return true;
}

void Crossmap::load_builtin() {
  for (const auto& entry : kBuiltins) insert(entry.name, entry.hash);
  OSH_LOG("crossmap: %zu built-in entries", size_);
}

std::size_t Crossmap::load(const char* path) {
  std::FILE* file = std::fopen(path, "r");
  if (file == nullptr) {
    OSH_LOG("crossmap: %s not found; using built-ins only", path);
    return 0;
  }

  char line[256];
  std::size_t loaded = 0;
  std::size_t line_number = 0;
  while (std::fgets(line, sizeof(line), file) != nullptr) {
    ++line_number;
    char* text = line;
    while (*text == ' ' || *text == '\t') ++text;
    if (*text == '#' || *text == ';' || *text == '\n' || *text == '\r' || *text == '\0') continue;

    char* separator = std::strchr(text, '=');
    if (separator == nullptr) {
      OSH_LOG("crossmap: %s:%zu has no '='; skipping", path, line_number);
      continue;
    }
    *separator = '\0';

    // Trim trailing whitespace from the name.
    for (char* c = separator - 1; c >= text && (*c == ' ' || *c == '\t'); --c) *c = '\0';

    char* value = separator + 1;
    while (*value == ' ' || *value == '\t') ++value;
    char* parse_end = nullptr;
    const std::uint64_t hash = std::strtoull(value, &parse_end, 0);
    if (parse_end == value || hash == 0) {
      OSH_LOG("crossmap: %s:%zu has an unparseable hash; skipping", path, line_number);
      continue;
    }
    if (insert(text, hash)) ++loaded;
  }
  std::fclose(file);
  OSH_LOG("crossmap: loaded %zu entries from %s (%zu total)", loaded, path, size_);
  return loaded;
}

std::uint64_t Crossmap::lookup(const char* name) const {
  if (name == nullptr) return 0;
  for (std::size_t i = 0; i < size_; ++i) {
    if (std::strncmp(entries_[i].name, name, kNameLength) == 0) return entries_[i].hash;
  }
  return 0;
}

Crossmap& Crossmap::instance() {
  static Crossmap crossmap;
  return crossmap;
}

}  // namespace osh
