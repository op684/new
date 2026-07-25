// GoldHEN plugin entry point.
//
// Load order:
//   1. GoldHEN loads this .prx into the game process (see plugins.ini).
//   2. We locate the executable segment and resolve the build signatures.
//   3. We hook the script dispatcher so we get a tick on the script thread.
//   4. We start the control server so the MCP tools can talk to us.
//   5. Any .prx in the autoload directory is loaded and registers its scripts.

#include <cstdio>

#include "../core/ringlog.h"
#include "../core/scriptmgr.h"
#include "../include/orbis_scripthook.h"
#include "crossmap.h"
#include "game.h"
#include "hook.h"
#include "ipc.h"
#include "orbis_compat.h"

#if !defined(OSH_HOST_BUILD)
#include <orbis/libkernel.h>
#define attr_public __attribute__((visibility("default")))
#else
#define attr_public
#endif

namespace {

constexpr const char* kCrossmapPath = "/data/GoldHEN/scripthook/natives.txt";
constexpr const char* kAutoloadList = "/data/GoldHEN/scripthook/autoload.txt";

osh::Detour g_tick_detour;
bool g_fallback_thread = false;

// Runs once per game tick, on the game's script thread. Everything mod-facing
// happens from here: this is the only place where calling a native is safe.
void on_script_tick() {
  osh::ScriptManager::instance().tick();
  osh::ControlServer::instance().pump();
}

using ScriptTickFn = void (*)(void*, void*);

// The detour replacement. The signature of the hooked function is not fully
// known on an unmapped build, so we take two register arguments (which covers
// the common `this`/thread shapes) and pass them straight through. Doing our
// work before the original keeps mod state consistent with what the frame is
// about to render.
void hooked_script_tick(void* a, void* b) {
  on_script_tick();
  g_tick_detour.original<ScriptTickFn>()(a, b);
}

// Used only when the tick signature could not be resolved. Native calls from
// this thread are NOT safe; it exists so the plugin still reports status and
// runs non-native scripts instead of appearing dead.
void fallback_tick_thread(void*) {
  OSH_LOG("running the fallback tick thread — native calls from scripts are unsafe");
  for (;;) {
    on_script_tick();
    osh::orbis::sleep_ms(16);
  }
}

void load_autoload_list() {
  std::FILE* file = std::fopen(kAutoloadList, "r");
  if (file == nullptr) return;

  char line[256];
  while (std::fgets(line, sizeof(line), file) != nullptr) {
    char* path = line;
    while (*path == ' ' || *path == '\t') ++path;
    if (*path == '#' || *path == ';' || *path == '\n' || *path == '\r' || *path == '\0') continue;
    // Strip the newline.
    for (char* c = path; *c != '\0'; ++c) {
      if (*c == '\n' || *c == '\r') {
        *c = '\0';
        break;
      }
    }
    const int handle = osh::orbis::load_module(path);
    OSH_LOG("autoload %s -> handle %d", path, handle);
  }
  std::fclose(file);
}

}  // namespace

extern "C" {

attr_public const char* g_pluginName = "OrbisScriptHook";
attr_public const char* g_pluginDesc = "Script runtime for GTA V on PS4 (single-player)";
attr_public const char* g_pluginAuth = "OrbisScriptHook contributors";
attr_public unsigned int g_pluginVersion = 0x00000100;  // 0.1.0

attr_public int plugin_load(int argc, const char* argv[]) {
  (void)argc;
  (void)argv;

  OSH_LOG("OrbisScriptHook %s loading", OSH_VERSION);

  auto& manager = osh::ScriptManager::instance();
  manager.set_clock(&osh::orbis::monotonic_ms);

  auto& crossmap = osh::Crossmap::instance();
  crossmap.load_builtin();
  crossmap.load(kCrossmapPath);

  auto& game = osh::Game::instance();
  if (!game.initialise()) {
    OSH_LOG("could not locate the game executable; the plugin is inert");
    osh::orbis::notify("OrbisScriptHook: could not find the game module");
    // Still start the control server so the log can be read remotely.
    osh::ControlServer::instance().start();
    return 0;
  }

  if (void* tick = game.script_tick()) {
    if (g_tick_detour.install(tick, reinterpret_cast<void*>(&hooked_script_tick))) {
      OSH_LOG("script tick hooked at %p", tick);
    } else {
      OSH_LOG("could not hook the script tick; falling back to a thread");
      g_fallback_thread = osh::orbis::spawn_thread("osh-tick", &fallback_tick_thread, nullptr);
    }
  } else {
    g_fallback_thread = osh::orbis::spawn_thread("osh-tick", &fallback_tick_thread, nullptr);
  }

  osh::ControlServer::instance().start();
  load_autoload_list();

  osh::orbis::notify("OrbisScriptHook %s\n%zu natives, %zu crossmap entries", OSH_VERSION,
                     game.natives().size(), crossmap.size());
  OSH_LOG("load complete: %zu natives, tick %s", game.natives().size(),
          g_tick_detour.installed() ? "hooked" : (g_fallback_thread ? "threaded" : "absent"));
  return 0;
}

attr_public int plugin_unload(int argc, const char* argv[]) {
  (void)argc;
  (void)argv;

  OSH_LOG("OrbisScriptHook unloading");
  osh::ControlServer::instance().stop();
  // Drop the hook before tearing down the scripts it would otherwise resume.
  g_tick_detour.remove();
  osh::ScriptManager::instance().shutdown();
  return 0;
}

}  // extern "C"
