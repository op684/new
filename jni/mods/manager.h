#pragma once
#include "mod.h"
#include <memory>
#include <vector>

namespace mods {

void init();
std::vector<Mod *> &all();
void dispatch_tick();
void dispatch_render();
bool dispatch_should_render_face(mcpe::BlockLegacy *block, int face);

} // namespace mods
