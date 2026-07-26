// The only file that knows about Orbis OS specifics.
//
// Everything the plugin needs from the platform — where the game's code is, what
// time it is, how to spawn a thread — goes through here, so the rest of the code
// stays ordinary C++ and stays testable on a desktop.
//
// Built against the OpenOrbis PS4 Toolchain, which is what the GoldHEN Plugin
// SDK targets. When OSH_HOST_BUILD is defined the implementations fall back to
// POSIX so the tests can link.

#pragma once

#include <cstddef>
#include <cstdint>

#include "game.h"

namespace osh::orbis {

// The main executable's code segment (the eboot's .text), located via the
// module info the kernel keeps for handle 0. Returns an invalid range on
// failure rather than guessing.
ModuleRange main_executable_segment();

// Monotonic milliseconds. Backed by the process timer, so it does not jump when
// the console's wall clock changes.
std::uint64_t monotonic_ms();

// Spawns a detached thread. Returns false if the thread could not be created.
bool spawn_thread(const char* name, void (*entry)(void*), void* user);

// Sleeps the calling thread.
void sleep_ms(std::uint32_t ms);

// Shows a notification on the console's screen. Used sparingly — once at load,
// once on failure — because it interrupts the player.
void notify(const char* format, ...) __attribute__((format(printf, 1, 2)));

// Loads and starts a .prx (a mod script). Returns a module handle, or a negative
// value on failure. The module's entry point is expected to call scriptRegister.
int load_module(const char* path);

// Stops and unloads a module previously returned by load_module().
bool unload_module(int handle);

}  // namespace osh::orbis
