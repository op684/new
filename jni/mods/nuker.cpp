#include "nuker.h"
#include "../util/logger.h"

#include <cstdint>

namespace mods {

// LocalPlayer position lives inside Actor (the engine's entity base) at a
// known offset. Look up Actor::getPos and either call it, or read the
// Vec3 at the offset it returns. Placeholder offset below.
static bool player_pos(mcpe::Vec3 *out) {
    if (!mcpe::g_player) return false;
    constexpr size_t kPosOffset = 0x40;
    auto *p = reinterpret_cast<float *>(
        reinterpret_cast<uint8_t *>(mcpe::g_player) + kPosOffset);
    out->x = p[0];
    out->y = p[1];
    out->z = p[2];
    return true;
}

void Nuker::on_tick() {
    mcpe::Vec3 origin;
    if (!player_pos(&origin)) return;

    for (int dx = -radius; dx <= radius; ++dx)
    for (int dy = -radius; dy <= radius; ++dy)
    for (int dz = -radius; dz <= radius; ++dz) {
        if (dx*dx + dy*dy + dz*dz > radius*radius) continue;
        mcpe::Vec3 pos{ origin.x + dx, origin.y + dy, origin.z + dz };
        mcpe::destroy_block(pos);
    }
}

} // namespace mods
