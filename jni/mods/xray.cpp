#include "xray.h"
#include "../util/logger.h"

#include <cstdint>
#include <unordered_set>

namespace mods {

// BlockLegacy carries a numeric id at a known offset. Find it once for your
// MCPE build (typically 0xB8 on 1.20.x arm64) and pull it through a helper.
static int block_id(mcpe::BlockLegacy *block) {
    if (!block) return -1;
    constexpr size_t kIdOffset = 0xB8;
    return *reinterpret_cast<int *>(reinterpret_cast<uint8_t *>(block) + kIdOffset);
}

// Numeric ids worth seeing through walls.
// 14 gold, 15 iron, 16 coal, 21 lapis, 56 diamond, 73/74 redstone, 129 emerald,
// 153 nether quartz, 525 deepslate diamond, 526 deepslate gold, etc.
static const std::unordered_set<int> kVisible = {
    14, 15, 16, 21, 56, 73, 74, 129, 153,
    525, 526, 527, 528, 529, 530, 531
};

bool Xray::on_should_render_face(mcpe::BlockLegacy *block, int /*face*/) {
    int id = block_id(block);
    return kVisible.count(id) > 0;
}

} // namespace mods
