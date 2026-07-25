// Build-specific signatures.
//
// THIS IS THE FILE YOU EDIT to bring OrbisScriptHook up on a particular GTA V
// build. Everything else in the plugin is build-independent.
//
// The patterns below are the well-known PC signatures. They are seeds, not
// answers: the PS4 build is the same RAGE engine and the same instruction set,
// so the surrounding code shapes survive, but register allocation and inlining
// differ enough that some of these will not match byte for byte.
//
// Workflow for deriving your own, using the MCP server:
//   1. gta_attach                          — get the module range
//   2. gta_scan_seeds                      — see what each signature is for
//   3. gta_scan_pattern (pattern=<seed>)   — try the seed; note hits
//   4. shorten the pattern / add wildcards until you get exactly one hit
//   5. gta_resolve_rip                     — follow the operand to the target
//   6. paste the working pattern here, rebuild, redeploy
//
// A signature that resolves to more than one address is worse than none: the
// plugin refuses ambiguous matches rather than picking the first.

#pragma once

#include <cstddef>

namespace osh::offsets {

struct Signature {
  const char* id;
  const char* pattern;
  // Byte offset of the RIP-relative disp32 within the match, and the total
  // length of that instruction. Set both to 0 when the match address itself is
  // the answer (e.g. a function start).
  std::size_t operand_offset;
  std::size_t instruction_length;
  // When true, the plugin logs loudly and carries on if this one fails.
  bool optional;
};

// The head of the rage::scrNativeRegistration linked list. This is the primary
// path: walking it gives us every hash/handler pair up front.
inline constexpr Signature kNativeRegistrationTable{
    "native_registration_table", "76 32 48 8B 53 40 48 8D 0D", 9, 13, false};

// rage::scrEngine::GetNativeHandler. Used as a fallback for hashes missing from
// the table walk, and as a cross-check that the table is the right one.
inline constexpr Signature kGetNativeHandler{
    "get_native_handler", "48 89 5C 24 ?? 57 48 83 EC 20 8B D9 8B FA", 0, 0, true};

// The per-frame script dispatcher. Hooking this is what gives mod scripts a
// tick on the thread the engine expects script code to run on.
inline constexpr Signature kScriptTick{
    "script_tick", "80 B9 ?? ?? ?? ?? ?? 8B FA 48 8B D9 74 ??", 0, 0, false};

// Optional extras that make the sample scripts more useful. Nothing depends on
// them; they are resolved best-effort.
inline constexpr Signature kPedPool{
    "ped_pool", "4C 8B 0D ?? ?? ?? ?? 44 8B C1 49 8B 41 ??", 3, 7, true};

inline constexpr Signature kScriptGlobals{
    "script_globals", "4C 8D 05 ?? ?? ?? ?? 4D 8B 08 4D 85 C9 74 ??", 3, 7, true};

}  // namespace osh::offsets
