#pragma once
#include "mod.h"

namespace mods {

class Nuker : public Mod {
public:
    Nuker() : Mod("Nuker") {}
    void on_tick() override;

    int   radius   = 4;
    bool  creative_only = false;
};

} // namespace mods
