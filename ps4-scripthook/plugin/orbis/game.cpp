#include "game.h"

#include <cstring>

#include "../core/pattern.h"
#include "../core/ringlog.h"
#include "game_offsets.h"
#include "orbis_compat.h"

namespace osh {
namespace {

// Open addressing with linear probing. The table is sized well above the ~6000
// natives GTA V registers, so load factor stays low and probes stay short.
constexpr std::uint64_t kEmpty = 0;

std::size_t slot_for(std::uint64_t hash) {
  // The hashes are already well mixed; a mask is enough.
  return static_cast<std::size_t>(hash) & (NativeTable::kCapacity - 1);
}

// A registration block with an implausible count means we followed a bad
// pointer, and walking further would fault.
bool plausible(const NativeRegistration* node) {
  return node != nullptr && node->count <= 7;
}

}  // namespace

void NativeTable::clear() {
  std::memset(entries_, 0, sizeof(entries_));
  size_ = 0;
}

std::size_t NativeTable::build_from_registrations(const NativeRegistration* head) {
  clear();
  if (!plausible(head)) {
    OSH_LOG("native registration head %p is not a plausible block", head);
    return 0;
  }

  std::size_t blocks = 0;
  for (const NativeRegistration* node = head; plausible(node); node = node->next) {
    // A corrupt list can be circular; bound the walk.
    if (++blocks > 4096) {
      OSH_LOG("native registration walk exceeded %zu blocks; aborting", blocks);
      break;
    }
    for (std::uint32_t i = 0; i < node->count; ++i) {
      const std::uint64_t hash = node->hashes[i];
      NativeHandler handler = node->handlers[i];
      if (hash == kEmpty || handler == nullptr) continue;
      if (size_ + 1 >= kCapacity) {
        OSH_LOG("native table full at %zu entries", size_);
        return size_;
      }
      std::size_t slot = slot_for(hash);
      while (entries_[slot].hash != kEmpty && entries_[slot].hash != hash) {
        slot = (slot + 1) & (kCapacity - 1);
      }
      if (entries_[slot].hash == kEmpty) ++size_;
      entries_[slot].hash = hash;
      entries_[slot].handler = handler;
    }
  }

  OSH_LOG("indexed %zu natives from %zu registration blocks", size_, blocks);
  return size_;
}

NativeHandler NativeTable::find(std::uint64_t hash) const {
  if (hash != kEmpty && size_ != 0) {
    std::size_t slot = slot_for(hash);
    for (std::size_t probe = 0; probe < kCapacity; ++probe) {
      const Entry& entry = entries_[slot];
      if (entry.hash == kEmpty) break;
      if (entry.hash == hash) return entry.handler;
      slot = (slot + 1) & (kCapacity - 1);
    }
  }
  return engine_lookup_ != nullptr ? engine_lookup_(hash) : nullptr;
}

bool Game::find_module() {
  module_ = orbis::main_executable_segment();
  if (!module_.valid()) {
    OSH_LOG("could not locate the main executable segment");
    return false;
  }
  OSH_LOG("executable segment at %p, %zu bytes", module_.base, module_.size);
  return true;
}

namespace {

// Resolves one signature to an address, refusing ambiguous matches.
std::uint8_t* resolve(const ModuleRange& module, const offsets::Signature& signature) {
  Pattern pattern;
  if (!pattern.compile(signature.pattern)) {
    OSH_LOG("signature '%s' is malformed: %s", signature.id, signature.pattern);
    return nullptr;
  }

  const std::size_t hits = pattern.count(module.base, module.size, 2);
  if (hits == 0) {
    OSH_LOG("signature '%s' found nothing%s", signature.id,
            signature.optional ? " (optional)" : " — this build needs a new pattern");
    return nullptr;
  }
  if (hits > 1) {
    OSH_LOG("signature '%s' is ambiguous (%zu+ matches); refusing to guess", signature.id, hits);
    return nullptr;
  }

  const std::uint8_t* hit = pattern.find(module.base, module.size);
  if (signature.instruction_length == 0) {
    OSH_LOG("signature '%s' -> %p", signature.id, hit);
    return const_cast<std::uint8_t*>(hit);
  }

  std::uint8_t* target = rip_target(hit, signature.operand_offset, signature.instruction_length);
  if (target < module.base || target >= module.base + module.size) {
    // Data can legitimately live outside .text, so this is a warning rather than
    // a hard failure — but it is the first thing to check if a native call
    // crashes.
    OSH_LOG("signature '%s' -> %p (outside the executable segment)", signature.id, target);
  } else {
    OSH_LOG("signature '%s' -> %p (+0x%zx)", signature.id, target,
            static_cast<std::size_t>(target - module.base));
  }
  return target;
}

}  // namespace

void Game::resolve_signatures() {
  if (std::uint8_t* head = resolve(module_, offsets::kNativeRegistrationTable)) {
    // The signature points at the pointer to the list head, not the head itself.
    auto* list = *reinterpret_cast<NativeRegistration**>(head);
    natives_.build_from_registrations(list);
  }

  if (std::uint8_t* lookup = resolve(module_, offsets::kGetNativeHandler)) {
    natives_.set_engine_lookup(reinterpret_cast<GetNativeHandlerFn>(lookup));
  }

  script_tick_ = resolve(module_, offsets::kScriptTick);

  // Best-effort extras. Their addresses are logged for the sample scripts and
  // for anyone poking around with the MCP server.
  resolve(module_, offsets::kPedPool);
  resolve(module_, offsets::kScriptGlobals);

  if (natives_.empty()) {
    OSH_LOG("no natives resolved — scripts can run but native calls will fail. "
            "Derive new signatures with the MCP server and update game_offsets.h.");
  }
  if (script_tick_ == nullptr) {
    OSH_LOG("no script tick resolved — falling back to a standalone thread, which is "
            "NOT safe for native calls. Fix the script_tick signature.");
  }
}

bool Game::initialise() {
  if (!find_module()) return false;
  resolve_signatures();
  return true;
}

bool Game::invoke(std::uint64_t hash, NativeContext* context) {
  NativeHandler handler = natives_.find(hash);
  if (handler == nullptr) {
    OSH_LOG("unresolved native 0x%016llx", static_cast<unsigned long long>(hash));
    return false;
  }
  handler(context);
  return true;
}

Game& Game::instance() {
  static Game game;
  return game;
}

}  // namespace osh
