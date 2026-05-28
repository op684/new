#pragma once
#include "mod.h"

namespace mods {

class Xray : public Mod {
public:
    Xray() : Mod("Xray") {}
    bool on_should_render_face(mcpe::BlockLegacy *block, int face) override;
};

} // namespace mods
