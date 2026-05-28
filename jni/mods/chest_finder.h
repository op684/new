#pragma once
#include "mod.h"
#include <mutex>
#include <vector>

namespace mods {

struct ChestHit {
    float x, y, z;
    bool  trapped;
};

class ChestFinder : public Mod {
public:
    ChestFinder() : Mod("ChestFinder") {}
    void on_tick() override;
    void on_render() override;

    std::vector<ChestHit> snapshot();

private:
    std::mutex            mu_;
    std::vector<ChestHit> hits_;
    int                   ticks_ = 0;
};

} // namespace mods
