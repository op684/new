// OrbisScriptHook — the API a mod script uses.
//
// Deliberately shaped like ScriptHookV's so that porting a PC script is mostly
// mechanical: register a main function, loop, call scriptWait, invoke natives
// through nativeInit/nativePush/nativeCall.
//
// The one unavoidable difference is native identification. ScriptHookV lets you
// write nativeInit(0x43A66C31) because the PC hashes are public knowledge. On a
// PS4 build you either supply the hash for *that* build or look it up by name
// through the crossmap — nativeByName() does the latter.
//
// Build a script as a .prx against this header, upload it to
// /data/GoldHEN/scripthook/scripts/, and load it with the MCP server's
// scripthook_manage_scripts tool. See ../samples/ for a worked example.

#pragma once

#include <cstdint>

#define OSH_VERSION "0.1.0"

namespace osh {

struct Vector3;

// --------------------------------------------------------------- scripting

using ScriptMain = void (*)();

// Registers `main` under `name`. Call this from your module's entry point.
// `main` runs on its own fiber, on the game's script thread.
void scriptRegister(const char* name, ScriptMain main);

// Stops a script. Calling this on yourself defers teardown to the next tick.
void scriptUnregister(const char* name);

// Suspends the calling script for at least `ms` milliseconds and returns control
// to the game. Every script loop must call this — a script that never yields
// freezes the game.
void scriptWait(std::uint32_t ms);

// ----------------------------------------------------------------- natives

// Begins a native call. `hash` must be the hash for the build you are running on.
void nativeInit(std::uint64_t hash);

// Looks the native up in the crossmap by name and begins the call. Returns false
// if the name is unknown, in which case nativeCall() will fail too.
bool nativeByName(const char* name);

// Pushes one argument. Overloads cover the types natives actually take.
void nativePush(std::int32_t value);
void nativePush(std::uint32_t value);
void nativePush(std::int64_t value);
void nativePush(std::uint64_t value);
void nativePush(float value);
void nativePush(bool value);
void nativePush(const char* value);
void nativePush(void* value);

// Executes the call. Returns a pointer to the return slot, or nullptr if the
// native could not be resolved. Read it as the type the native documents:
//
//   nativeByName("GET_PLAYER_PED");
//   nativePush(playerIndex);
//   int ped = *reinterpret_cast<int*>(nativeCall());
//
std::uint64_t* nativeCall();

// Convenience wrappers around the above.
template <typename Result, typename... Args>
Result invoke(std::uint64_t hash, Args... args) {
  nativeInit(hash);
  (nativePush(args), ...);
  std::uint64_t* result = nativeCall();
  return result != nullptr ? *reinterpret_cast<Result*>(result) : Result{};
}

template <typename... Args>
void invokeVoid(std::uint64_t hash, Args... args) {
  nativeInit(hash);
  (nativePush(args), ...);
  nativeCall();
}

// The Vector3 a native returned, valid immediately after nativeCall().
Vector3 nativeVectorResult();

// ------------------------------------------------------------------- misc

// Appends a line to the plugin log, readable with the MCP server's
// scripthook_log tool. printf-style.
void scriptLog(const char* format, ...) __attribute__((format(printf, 1, 2)));

// The hash of a string, as GET_HASH_KEY would compute it (model names, weapon
// names, animation dictionaries).
std::uint32_t stringHash(const char* text);

}  // namespace osh
