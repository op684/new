#include "scriptmgr.h"

#include <cstdio>
#include <cstring>

#include "ringlog.h"

namespace osh {

bool ScriptManager::add(const char* name, ScriptMain main, std::size_t stack_size) {
  if (name == nullptr || main == nullptr) return false;
  if (find(name) != nullptr) {
    OSH_LOG("script '%s' is already registered", name);
    return false;
  }

  for (auto& script : scripts_) {
    if (script.used) continue;
    std::snprintf(script.name, kNameLength, "%s", name);
    script.main = main;
    script.wake_at = 0;
    script.ticks = 0;
    if (!script.fiber.create(&ScriptManager::entry, &script, stack_size)) {
      OSH_LOG("could not allocate a %zu byte stack for script '%s'", stack_size, name);
      script.main = nullptr;
      return false;
    }
    script.used = true;
    ++count_;
    OSH_LOG("registered script '%s'", name);
    return true;
  }

  OSH_LOG("script table full (%zu), refusing '%s'", kMaxScripts, name);
  return false;
}

bool ScriptManager::remove(const char* name) {
  Script* script = find(name);
  if (script == nullptr) return false;
  if (script == running_) {
    // Unregistering yourself from inside your own fiber would free the stack we
    // are standing on. Mark it done; tick() reaps it after the switch back.
    script->wake_at = ~std::uint64_t{0};
    OSH_LOG("script '%s' asked to unregister itself; deferring teardown", name);
    return true;
  }
  script->fiber.destroy();
  script->used = false;
  script->main = nullptr;
  script->name[0] = '\0';
  --count_;
  OSH_LOG("unregistered script '%s'", name);
  return true;
}

void ScriptManager::tick() {
  ++tick_count_;
  const std::uint64_t current = now();

  for (auto& script : scripts_) {
    if (!script.used) continue;

    if (script.fiber.finished()) {
      OSH_LOG("script '%s' returned; reaping", script.name);
      script.fiber.destroy();
      script.used = false;
      script.main = nullptr;
      --count_;
      continue;
    }
    if (script.wake_at > current) continue;

    ++script.ticks;
    running_ = &script;
    script.fiber.resume();
    running_ = nullptr;
  }
}

void ScriptManager::wait(std::uint32_t ms) {
  Script* script = running_;
  if (script == nullptr) {
    // Not inside a script fiber — yielding here would suspend the game thread.
    OSH_LOG("scriptWait(%u) called outside a script; ignoring", ms);
    return;
  }
  script->wake_at = now() + ms;
  script->fiber.yield();
}

bool ScriptManager::info(std::size_t index, ScriptInfo* out) const {
  if (out == nullptr) return false;
  std::size_t seen = 0;
  for (const auto& script : scripts_) {
    if (!script.used) continue;
    if (seen++ != index) continue;
    out->name = script.name;
    out->running = script.fiber.started() && !script.fiber.finished();
    out->finished = script.fiber.finished();
    out->ticks = script.ticks;
    out->wake_at = script.wake_at;
    return true;
  }
  return false;
}

void ScriptManager::shutdown() {
  for (auto& script : scripts_) {
    if (!script.used) continue;
    script.fiber.destroy();
    script.used = false;
    script.main = nullptr;
  }
  count_ = 0;
  running_ = nullptr;
}

void ScriptManager::entry(void* user) {
  auto* script = static_cast<Script*>(user);
  script->main();
}

ScriptManager::Script* ScriptManager::find(const char* name) {
  if (name == nullptr) return nullptr;
  for (auto& script : scripts_) {
    if (script.used && std::strncmp(script.name, name, kNameLength) == 0) return &script;
  }
  return nullptr;
}

ScriptManager& ScriptManager::instance() {
  static ScriptManager manager;
  return manager;
}

void scriptRegister(const char* name, ScriptMain main) { ScriptManager::instance().add(name, main); }
void scriptUnregister(const char* name) { ScriptManager::instance().remove(name); }
void scriptWait(std::uint32_t ms) { ScriptManager::instance().wait(ms); }

}  // namespace osh
