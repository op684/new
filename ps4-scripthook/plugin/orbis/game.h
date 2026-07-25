// Locating the pieces of GTA V that the script runtime needs.
//
// Nothing here can be a hardcoded address: the eboot is loaded at a different
// base every boot. Everything is resolved at plugin load time by scanning the
// executable segment for the signatures in game_offsets.h and following
// RIP-relative operands from the hits.
//
// The signatures themselves are the part that is build-specific. Use the MCP
// server (gta_scan_seeds / gta_scan_pattern / gta_resolve_rip) to derive them
// against your own console, then paste what works into game_offsets.h.

#pragma once

#include <cstddef>
#include <cstdint>

#include "../core/native_context.h"

namespace osh {

// rage::scrNativeRegistration — a linked list of small blocks, each holding up
// to seven hash/handler pairs. Walking it once at startup gives us the whole
// native table without calling into the engine.
struct NativeRegistration {
  NativeRegistration* next;
  NativeHandler handlers[7];
  std::uint32_t count;
  std::uint32_t pad;
  std::uint64_t hashes[7];
};

// Signature of the engine's own lookup, used when the table layout does not
// match (it changes between builds more often than this function does).
using GetNativeHandlerFn = NativeHandler (*)(std::uint64_t hash);

class NativeTable {
 public:
  static constexpr std::size_t kCapacity = 8192;  // power of two, > native count

  void clear();

  // Walks the registration list and indexes every entry. Returns the number of
  // natives found, or 0 if the list looked implausible (which usually means the
  // signature resolved to the wrong place).
  std::size_t build_from_registrations(const NativeRegistration* head);

  // Falls back to the engine's lookup for hashes we did not index.
  void set_engine_lookup(GetNativeHandlerFn fn) { engine_lookup_ = fn; }

  NativeHandler find(std::uint64_t hash) const;

  std::size_t size() const { return size_; }
  bool empty() const { return size_ == 0; }

 private:
  struct Entry {
    std::uint64_t hash;
    NativeHandler handler;
  };

  Entry entries_[kCapacity] = {};
  std::size_t size_ = 0;
  GetNativeHandlerFn engine_lookup_ = nullptr;
};

struct ModuleRange {
  std::uint8_t* base = nullptr;
  std::size_t size = 0;
  bool valid() const { return base != nullptr && size != 0; }
};

class Game {
 public:
  // Finds the main executable and resolves every signature. Returns false if
  // the executable could not be located at all; partial signature failures are
  // logged and leave the corresponding pointer null.
  bool initialise();

  bool resolved() const { return module_.valid(); }
  const ModuleRange& module() const { return module_; }
  NativeTable& natives() { return natives_; }
  const NativeTable& natives() const { return natives_; }

  // Address of the script-thread function we hook to get a per-frame tick.
  void* script_tick() const { return script_tick_; }

  // Invokes a native by hash. Returns false if the hash has no handler.
  bool invoke(std::uint64_t hash, NativeContext* context);

  static Game& instance();

 private:
  // Locates the main module's executable segment.
  bool find_module();
  void resolve_signatures();

  ModuleRange module_;
  NativeTable natives_;
  void* script_tick_ = nullptr;
};

}  // namespace osh
