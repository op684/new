#include "manager.h"
#include "xray.h"
#include "chest_finder.h"
#include "nuker.h"

namespace mods {

static std::vector<std::unique_ptr<Mod>> g_owned;
static std::vector<Mod *> g_view;

void init() {
    g_owned.emplace_back(std::make_unique<Xray>());
    g_owned.emplace_back(std::make_unique<ChestFinder>());
    g_owned.emplace_back(std::make_unique<Nuker>());
    g_view.clear();
    for (auto &m : g_owned) g_view.push_back(m.get());
}

std::vector<Mod *> &all() { return g_view; }

void dispatch_tick() {
    for (Mod *m : g_view) if (m->enabled()) m->on_tick();
}

void dispatch_render() {
    for (Mod *m : g_view) if (m->enabled()) m->on_render();
}

bool dispatch_should_render_face(mcpe::BlockLegacy *block, int face) {
    for (Mod *m : g_view) {
        if (!m->enabled()) continue;
        if (!m->on_should_render_face(block, face)) return false;
    }
    return true;
}

} // namespace mods
