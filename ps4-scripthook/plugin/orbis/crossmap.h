// Native name -> hash for this build.
//
// GTA V native hashes are not joaat of the native's name, and Rockstar rotated
// them on most builds, so there is no way to compute the hash a given build uses
// from the name alone. A crossmap is just a table someone produced for that
// build.
//
// Two sources, checked in order:
//   1. /data/GoldHEN/scripthook/natives.txt, one "NAME=0xHASH" per line. This is
//      the one you will actually use — no rebuild needed to add natives.
//   2. The small built-in table below, as a smoke test.
//
// Deriving a crossmap for an unmapped build is the long pole of this project;
// docs/natives.md describes how to go about it.

#pragma once

#include <cstddef>
#include <cstdint>

namespace osh {

class Crossmap {
 public:
  static constexpr std::size_t kCapacity = 4096;
  static constexpr std::size_t kNameLength = 64;

  // Loads "NAME=0xHASH" lines from `path`, on top of the built-in entries.
  // Returns the number of entries loaded, or 0 if the file was absent.
  std::size_t load(const char* path);

  // Seeds the built-in entries. Called once at startup.
  void load_builtin();

  // Returns 0 when the name is unknown.
  std::uint64_t lookup(const char* name) const;

  std::size_t size() const { return size_; }

  static Crossmap& instance();

 private:
  struct Entry {
    char name[kNameLength];
    std::uint64_t hash;
  };

  bool insert(const char* name, std::uint64_t hash);

  Entry entries_[kCapacity] = {};
  std::size_t size_ = 0;
};

}  // namespace osh
