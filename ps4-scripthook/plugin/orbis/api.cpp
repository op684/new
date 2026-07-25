// Implementation of the public mod-author API declared in
// ../include/orbis_scripthook.h.
//
// Native calls made from a script run on the script thread by construction —
// scripts only execute inside ScriptManager::tick(), which is itself called from
// the tick hook — so there is no queue here, unlike the control channel's path.

#include <cstdarg>

#include "../core/joaat.h"
#include "../core/native_context.h"
#include "../core/ringlog.h"
#include "../core/scriptmgr.h"
#include "../include/orbis_scripthook.h"
#include "crossmap.h"
#include "game.h"

namespace osh {
namespace {

// One context per thread: scripts share the game's script thread, but a native
// call never spans a scriptWait(), so a single buffer per thread is enough.
thread_local NativeContext g_context;
thread_local std::uint64_t g_hash = 0;
thread_local bool g_resolved = false;

}  // namespace

void nativeInit(std::uint64_t hash) {
  g_context.reset();
  g_hash = hash;
  g_resolved = true;
}

bool nativeByName(const char* name) {
  const std::uint64_t hash = Crossmap::instance().lookup(name);
  nativeInit(hash);
  if (hash == 0) {
    g_resolved = false;
    OSH_LOG("native '%s' is not in the crossmap", name);
  }
  return hash != 0;
}

void nativePush(std::int32_t value) { g_context.push<std::int64_t>(value); }
void nativePush(std::uint32_t value) { g_context.push<std::uint64_t>(value); }
void nativePush(std::int64_t value) { g_context.push<std::int64_t>(value); }
void nativePush(std::uint64_t value) { g_context.push<std::uint64_t>(value); }
void nativePush(float value) { g_context.push<float>(value); }
void nativePush(bool value) { g_context.push<std::int64_t>(value ? 1 : 0); }
void nativePush(const char* value) { g_context.push<const char*>(value); }
void nativePush(void* value) { g_context.push<void*>(value); }

std::uint64_t* nativeCall() {
  if (!g_resolved || g_hash == 0) return nullptr;
  if (!Game::instance().invoke(g_hash, &g_context)) return nullptr;
  return const_cast<std::uint64_t*>(g_context.slots());
}

Vector3 nativeVectorResult() { return g_context.vector_result(); }

void scriptLog(const char* format, ...) {
  std::va_list args;
  va_start(args, format);
  RingLog::instance().vwritef(format, args);
  va_end(args);
}

std::uint32_t stringHash(const char* text) { return joaat(text); }

}  // namespace osh
