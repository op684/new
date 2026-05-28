#include "chest_finder.h"
#include "../util/logger.h"

namespace mods {

// Real implementation: every N ticks, walk the loaded chunks via
// BlockSource::getChunkAt and iterate LevelChunk::mBlockEntities, filtering
// for chest / trapped chest / ender chest tile-entity ids. Stash positions
// in `hits_`. Render side reads `hits_` and draws ESP boxes through the EGL
// hook. All of that needs MCPE offsets you'll add as you reverse them.
//
// Scaffold below records nothing and never draws — it just keeps the plumbing
// alive so the menu and tick path link cleanly.

void ChestFinder::on_tick() {
    if (++ticks_ % 20 != 0) return;
    // TODO: scan loaded chunks for chest tile entities.
}

void ChestFinder::on_render() {
    // TODO: project world positions to screen using the game's view matrix
    // (Camera::getViewMatrix / getProjectionMatrix), then draw with ImGui's
    // ImDrawList::AddRect on the background draw list.
}

std::vector<ChestHit> ChestFinder::snapshot() {
    std::lock_guard<std::mutex> g(mu_);
    return hits_;
}

} // namespace mods
