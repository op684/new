#pragma once
#include <cstdint>

namespace mcpe {

// Opaque game pointers. Real types live inside libminecraftpe.so; we only
// pass them around as void* and let mod code interpret them after offsets
// are known.
using ClientInstance = void;
using LocalPlayer    = void;
using Level          = void;
using BlockSource    = void;
using GameMode       = void;
using BlockPos       = void;
using BlockLegacy    = void;

struct Vec3 { float x, y, z; };

// Filled in after hooks land. Null until the first hook fires.
extern ClientInstance *g_client;
extern LocalPlayer    *g_player;
extern Level          *g_level;
extern BlockSource    *g_region;
extern GameMode       *g_gamemode;

// Called once after libminecraftpe.so is mapped. Looks up symbols / patterns
// and installs Dobby hooks on the targets each mod needs.
void install();

// Per-tick callback invoked from the game thread (LocalPlayer::tick hook).
// Mods register tick listeners that get fanned out here.
void on_player_tick();

// Per-block-render-face callback. Returning false hides the face.
// Used by xray.
bool on_should_render_face(BlockLegacy *block, int face);

// Destroy the block at `pos` if survival rules permit. Wraps the resolved
// GameMode::destroyBlock signature so nuker doesn't have to repeat ABI.
bool destroy_block(const Vec3 &pos);

} // namespace mcpe
