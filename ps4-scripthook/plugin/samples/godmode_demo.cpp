// A worked example mod script.
//
// Build it as a .prx, upload to /data/GoldHEN/scripthook/scripts/, then either
// list it in autoload.txt or load it live with the MCP server:
//
//   ps4_upload_file local_path=godmode_demo.prx \
//                   remote_path=/data/GoldHEN/scripthook/scripts/godmode_demo.prx
//   scripthook_manage_scripts action=load \
//                   path=/data/GoldHEN/scripthook/scripts/godmode_demo.prx
//
// Single-player only. Do not run this with GTA Online loaded — see ../../README.md.

#include <cstddef>

#include "../include/orbis_scripthook.h"

namespace {

// Every native this script uses is looked up by name through the crossmap, so
// the script itself is build-independent. If a name is missing, nativeByName
// logs it and the call is skipped rather than jumping into nowhere.
bool call_void(const char* name) {
  if (!osh::nativeByName(name)) return false;
  return osh::nativeCall() != nullptr;
}

int player_ped() {
  if (!osh::nativeByName("PLAYER_PED_ID")) return 0;
  std::uint64_t* result = osh::nativeCall();
  return result != nullptr ? *reinterpret_cast<int*>(result) : 0;
}

void set_invincible(int ped, bool enabled) {
  if (!osh::nativeByName("SET_ENTITY_INVINCIBLE")) return;
  osh::nativePush(ped);
  osh::nativePush(enabled);
  osh::nativeCall();
}

void script_main() {
  osh::scriptLog("godmode_demo starting");

  // Give the game a moment to finish loading into gameplay before touching any
  // entity — natives called during a load screen tend to return 0.
  osh::scriptWait(5000);

  bool enabled = false;
  int ticks = 0;

  for (;;) {
    const int ped = player_ped();
    if (ped != 0) {
      // Toggle every 10 seconds so the effect is visible without any input
      // handling. A real trainer would read the pad here instead.
      if (++ticks % 20 == 0) {
        enabled = !enabled;
        set_invincible(ped, enabled);
        osh::scriptLog("godmode %s for ped %d", enabled ? "on" : "off", ped);
      }
    } else if (ticks % 20 == 0) {
      osh::scriptLog("no player ped yet (still loading?)");
      ++ticks;
    } else {
      ++ticks;
    }

    // Yield. Without this the game thread never returns and the console hangs.
    osh::scriptWait(500);
  }
}

}  // namespace

// The module entry point GoldHEN calls after sceKernelLoadStartModule. Register
// and return promptly — the script itself runs on its own fiber.
extern "C" __attribute__((visibility("default"))) int module_start(std::size_t argc, const void* argv) {
  (void)argc;
  (void)argv;
  osh::scriptRegister("godmode_demo", &script_main);
  return 0;
}

extern "C" __attribute__((visibility("default"))) int module_stop(std::size_t argc, const void* argv) {
  (void)argc;
  (void)argv;
  osh::scriptUnregister("godmode_demo");
  return 0;
}
