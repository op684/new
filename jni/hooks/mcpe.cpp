#include "mcpe.h"
#include "../util/logger.h"
#include "../util/memory.h"
#include "../mods/manager.h"

#include <dobby.h>

namespace mcpe {

ClientInstance *g_client   = nullptr;
LocalPlayer    *g_player   = nullptr;
Level          *g_level    = nullptr;
BlockSource    *g_region   = nullptr;
GameMode       *g_gamemode = nullptr;

// ---- Symbols we want to hook ---------------------------------------------
// MCPE strips most symbols; these mangled names work for some older builds
// and are placeholders for newer ones where you'll swap in a pattern scan.
//
// To find the right symbol or pattern for your installed MCPE version:
//   1. Pull /data/app/.../com.mojang.minecraftpe-*/lib/arm64/libminecraftpe.so
//   2. Open in Ghidra/IDA, locate ClientInstance::update,
//      LocalPlayer::tick, GameMode::destroyBlock,
//      Block::shouldRenderFace.
//   3. Either put the mangled name in *_SYM below, or replace the resolve()
//      call with mem::pattern_scan() and a byte signature.
// --------------------------------------------------------------------------

static const char *kClientUpdateSym =
    "_ZN14ClientInstance6_updateEv";
static const char *kPlayerTickSym =
    "_ZN11LocalPlayer14normalTickEv";
static const char *kShouldRenderFaceSym =
    "_ZNK5Block16shouldRenderFaceERK11BlockSourceRK8BlockPosi";
static const char *kDestroyBlockSym =
    "_ZN8GameMode13destroyBlockERK8BlockPosa";

// ---- Trampolines ---------------------------------------------------------
using ClientUpdateFn   = void (*)(ClientInstance *self);
using PlayerTickFn     = void (*)(LocalPlayer *self);
using ShouldRenderFn   = bool (*)(BlockLegacy *self, BlockSource *region, BlockPos *pos, int face);
using DestroyBlockFn   = bool (*)(GameMode *self, BlockPos *pos, signed char face);

static ClientUpdateFn  orig_client_update   = nullptr;
static PlayerTickFn    orig_player_tick     = nullptr;
static ShouldRenderFn  orig_should_render   = nullptr;
static DestroyBlockFn  orig_destroy_block   = nullptr;

// ---- Hook bodies ---------------------------------------------------------
static void hk_client_update(ClientInstance *self) {
    g_client = self;
    orig_client_update(self);
}

static void hk_player_tick(LocalPlayer *self) {
    g_player = self;
    on_player_tick();
    orig_player_tick(self);
}

static bool hk_should_render(BlockLegacy *self, BlockSource *region, BlockPos *pos, int face) {
    g_region = region;
    if (!on_should_render_face(self, face)) return false;
    return orig_should_render(self, region, pos, face);
}

// ---- Public API ----------------------------------------------------------
void install() {
    uintptr_t base = mem::wait_for_module("libminecraftpe.so");
    if (!base) {
        LOGE("libminecraftpe.so never mapped");
        return;
    }
    LOGI("libminecraftpe.so base = %p", reinterpret_cast<void *>(base));

    auto hook_named = [&](const char *sym, void *replacement, void **backup) -> bool {
        void *p = mem::resolve("libminecraftpe.so", sym);
        if (!p) {
            LOGW("symbol %s not found; skipping (add a pattern scan)", sym);
            return false;
        }
        if (DobbyHook(p, replacement, backup)) {
            LOGE("DobbyHook(%s) failed", sym);
            return false;
        }
        LOGI("hooked %s @ %p", sym, p);
        return true;
    };

    hook_named(kClientUpdateSym,
               reinterpret_cast<void *>(hk_client_update),
               reinterpret_cast<void **>(&orig_client_update));
    hook_named(kPlayerTickSym,
               reinterpret_cast<void *>(hk_player_tick),
               reinterpret_cast<void **>(&orig_player_tick));
    hook_named(kShouldRenderFaceSym,
               reinterpret_cast<void *>(hk_should_render),
               reinterpret_cast<void **>(&orig_should_render));

    orig_destroy_block = reinterpret_cast<DestroyBlockFn>(
        mem::resolve("libminecraftpe.so", kDestroyBlockSym));
    if (!orig_destroy_block) {
        LOGW("GameMode::destroyBlock not resolved; nuker will be a no-op");
    }
}

void on_player_tick() {
    mods::dispatch_tick();
}

bool on_should_render_face(BlockLegacy *block, int face) {
    return mods::dispatch_should_render_face(block, face);
}

bool destroy_block(const Vec3 &pos) {
    if (!orig_destroy_block || !g_gamemode) return false;
    // BlockPos layout on MCPE is { int x, y, z }. Build it on the stack.
    int bp[3] = { int(pos.x), int(pos.y), int(pos.z) };
    return orig_destroy_block(g_gamemode, reinterpret_cast<BlockPos *>(bp), 1);
}

} // namespace mcpe
