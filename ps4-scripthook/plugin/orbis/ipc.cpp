#include "ipc.h"

#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdio>
#include <cstring>

#include "../core/json.h"
#include "../core/native_context.h"
#include "../core/ringlog.h"
#include "../core/scriptmgr.h"
#include "crossmap.h"
#include "game.h"
#include "orbis_compat.h"

namespace osh {
namespace {

// Single-slot hand-off between the network thread and the script thread. One
// slot is enough: the MCP client is request/response and does one thing at a
// time, and a deeper queue would only hide mistakes.
struct NativeRequest {
  volatile bool pending = false;
  volatile bool complete = false;
  bool ok = false;
  char error[96] = {};

  std::uint64_t hash = 0;
  NativeContext context;
  char return_type[16] = {};

  // Filled in by the script thread.
  std::int64_t integer_result = 0;
  float float_result = 0.0f;
  Vector3 vector_result;
};

NativeRequest g_native_request;

constexpr std::uint32_t kNativeTimeoutMs = 3000;

bool read_exact(int fd, void* buffer, std::size_t length) {
  auto* out = static_cast<std::uint8_t*>(buffer);
  std::size_t done = 0;
  while (done < length) {
    const ssize_t got = recv(fd, out + done, length - done, 0);
    if (got <= 0) return false;
    done += static_cast<std::size_t>(got);
  }
  return true;
}

bool write_exact(int fd, const void* buffer, std::size_t length) {
  const auto* data = static_cast<const std::uint8_t*>(buffer);
  std::size_t done = 0;
  while (done < length) {
    const ssize_t sent = send(fd, data + done, length - done, 0);
    if (sent <= 0) return false;
    done += static_cast<std::size_t>(sent);
  }
  return true;
}

// Fills a NativeContext from the JSON "args" array.
bool build_arguments(const Json& json, int args_node, NativeContext* context, char* error,
                     std::size_t error_size) {
  for (int arg = json.first_child(args_node); arg != Json::kNone; arg = json.next_sibling(arg)) {
    const char* type = json.string_field(arg, "type", "int");
    const int value = json.find(arg, "value");

    bool pushed = false;
    if (std::strcmp(type, "int") == 0 || std::strcmp(type, "pointer") == 0) {
      pushed = context->push<std::int64_t>(static_cast<std::int64_t>(json.number(value)));
    } else if (std::strcmp(type, "float") == 0) {
      pushed = context->push<float>(static_cast<float>(json.number(value)));
    } else if (std::strcmp(type, "bool") == 0) {
      pushed = context->push<std::int64_t>(json.boolean(value) ? 1 : 0);
    } else if (std::strcmp(type, "string") == 0) {
      // The parsed string lives in the request buffer, which stays alive until
      // the reply is sent — long enough for the native to copy it.
      pushed = context->push<const char*>(json.string(value));
    } else {
      std::snprintf(error, error_size, "unknown argument type '%s'", type);
      return false;
    }
    if (!pushed) {
      std::snprintf(error, error_size, "too many arguments (max %u)", NativeContext::kMaxArgs);
      return false;
    }
  }
  return true;
}

void write_native_result(JsonWriter& writer, const NativeRequest& request) {
  writer.key("result");
  const char* type = request.return_type;
  if (std::strcmp(type, "void") == 0) {
    writer.value_null();
  } else if (std::strcmp(type, "float") == 0) {
    writer.value_number(request.float_result);
  } else if (std::strcmp(type, "bool") == 0) {
    writer.value_bool(request.integer_result != 0);
  } else if (std::strcmp(type, "vector3") == 0) {
    writer.begin_object();
    writer.field_number("x", request.vector_result.x);
    writer.field_number("y", request.vector_result.y);
    writer.field_number("z", request.vector_result.z);
    writer.end_object();
  } else {
    writer.value_number(static_cast<double>(request.integer_result));
  }
}

// Tracks modules loaded through load_script so unload_script can undo them.
struct LoadedScript {
  char name[64] = {};
  char path[256] = {};
  int handle = -1;
  bool used = false;
};

constexpr std::size_t kMaxLoadedScripts = 16;
LoadedScript g_loaded[kMaxLoadedScripts];

const char* basename_of(const char* path) {
  const char* slash = std::strrchr(path, '/');
  return slash != nullptr ? slash + 1 : path;
}

}  // namespace

bool ControlServer::start(std::uint16_t port) {
  if (running_) return true;

  listen_fd_ = socket(AF_INET, SOCK_STREAM, 0);
  if (listen_fd_ < 0) {
    OSH_LOG("control server: socket() failed");
    return false;
  }

  int reuse = 1;
  setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_ANY);
  address.sin_port = htons(port);

  if (bind(listen_fd_, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
    OSH_LOG("control server: bind(%u) failed — is another instance running?", port);
    close(listen_fd_);
    listen_fd_ = -1;
    return false;
  }
  if (listen(listen_fd_, 4) != 0) {
    OSH_LOG("control server: listen() failed");
    close(listen_fd_);
    listen_fd_ = -1;
    return false;
  }

  stopping_ = false;
  running_ = true;
  if (!orbis::spawn_thread("osh-control", &ControlServer::thread_entry, this)) {
    close(listen_fd_);
    listen_fd_ = -1;
    running_ = false;
    return false;
  }
  OSH_LOG("control server listening on port %u", port);
  return true;
}

void ControlServer::stop() {
  stopping_ = true;
  if (listen_fd_ >= 0) {
    close(listen_fd_);
    listen_fd_ = -1;
  }
  running_ = false;
}

void ControlServer::thread_entry(void* user) { static_cast<ControlServer*>(user)->accept_loop(); }

void ControlServer::accept_loop() {
  static char request[kMaxMessage];
  static char reply[kMaxMessage];

  while (!stopping_) {
    const int client = accept(listen_fd_, nullptr, nullptr);
    if (client < 0) {
      if (stopping_) break;
      orbis::sleep_ms(100);
      continue;
    }

    std::uint32_t length = 0;
    if (read_exact(client, &length, sizeof(length)) && length > 0 && length < kMaxMessage &&
        read_exact(client, request, length)) {
      request[length] = '\0';
      const std::size_t reply_length = handle(request, length, reply, sizeof(reply));
      const std::uint32_t header = static_cast<std::uint32_t>(reply_length);
      if (write_exact(client, &header, sizeof(header))) {
        write_exact(client, reply, reply_length);
      }
    } else {
      OSH_LOG("control server: malformed frame (length %u)", length);
    }
    close(client);
  }
  OSH_LOG("control server stopped");
}

std::size_t ControlServer::handle(char* request, std::size_t length, char* reply,
                                  std::size_t capacity) {
  JsonWriter writer(reply, capacity);
  Json json;

  if (!json.parse(request, length)) {
    writer.begin_object();
    writer.field_bool("ok", false);
    writer.field_string("error", json.error());
    writer.end_object();
    return writer.length();
  }

  const int root = json.root();
  const char* op = json.string_field(root, "op", "");
  auto& manager = ScriptManager::instance();
  auto& game = Game::instance();

  if (std::strcmp(op, "ping") == 0) {
    writer.begin_object();
    writer.field_bool("ok", true);
    writer.field_string("pong", "OrbisScriptHook");
    writer.end_object();
    return writer.length();
  }

  if (std::strcmp(op, "status") == 0) {
    writer.begin_object();
    writer.field_bool("ok", true);
    writer.field_string("version", OSH_VERSION);
    writer.field_bool("module_resolved", game.resolved());
    writer.field_number("module_base", static_cast<double>(
                                           reinterpret_cast<std::uintptr_t>(game.module().base)));
    writer.field_number("module_size", static_cast<double>(game.module().size));
    writer.field_bool("natives_resolved", !game.natives().empty());
    writer.field_number("native_count", static_cast<double>(game.natives().size()));
    writer.field_number("crossmap_entries", static_cast<double>(Crossmap::instance().size()));
    writer.field_bool("script_tick_hooked", game.script_tick() != nullptr);
    writer.field_number("ticks", static_cast<double>(manager.tick_count()));
    writer.field_number("script_count", static_cast<double>(manager.count()));
    writer.end_object();
    return writer.length();
  }

  if (std::strcmp(op, "log") == 0) {
    const int wanted = static_cast<int>(json.number_field(root, "lines", 100));
    static char lines[64][RingLog::kLineLength];
    const std::size_t max = wanted > 64 ? 64 : (wanted < 1 ? 1 : static_cast<std::size_t>(wanted));
    const std::size_t got = RingLog::instance().tail(&lines[0][0], max);

    writer.begin_object();
    writer.field_bool("ok", true);
    writer.field_number("dropped", static_cast<double>(RingLog::instance().dropped()));
    writer.key("lines");
    writer.begin_array();
    for (std::size_t i = 0; i < got; ++i) writer.value_string(lines[i]);
    writer.end_array();
    writer.end_object();
    return writer.length();
  }

  if (std::strcmp(op, "list_scripts") == 0) {
    writer.begin_object();
    writer.field_bool("ok", true);
    writer.key("scripts");
    writer.begin_array();
    ScriptInfo info{};
    for (std::size_t i = 0; manager.info(i, &info); ++i) {
      writer.begin_object();
      writer.field_string("name", info.name);
      writer.field_bool("running", info.running);
      writer.field_bool("finished", info.finished);
      writer.field_number("ticks", static_cast<double>(info.ticks));
      writer.end_object();
    }
    writer.end_array();
    writer.end_object();
    return writer.length();
  }

  if (std::strcmp(op, "resolve") == 0) {
    const char* name = json.string_field(root, "name", "");
    std::uint64_t hash = static_cast<std::uint64_t>(json.number_field(root, "hash", 0));
    if (hash == 0 && name[0] != '\0') hash = Crossmap::instance().lookup(name);

    writer.begin_object();
    writer.field_bool("ok", hash != 0);
    writer.field_number("hash", static_cast<double>(hash));
    const NativeHandler handler = hash != 0 ? game.natives().find(hash) : nullptr;
    writer.field_number("handler",
                        static_cast<double>(reinterpret_cast<std::uintptr_t>(handler)));
    if (hash == 0) writer.field_string("error", "name is not in the crossmap");
    else if (handler == nullptr) writer.field_string("error", "no handler for that hash");
    writer.end_object();
    return writer.length();
  }

  if (std::strcmp(op, "load_script") == 0) {
    const char* path = json.string_field(root, "path", "");
    if (path[0] == '\0') {
      writer.begin_object();
      writer.field_bool("ok", false);
      writer.field_string("error", "load_script needs a \"path\"");
      writer.end_object();
      return writer.length();
    }
    const int handle = orbis::load_module(path);
    bool recorded = false;
    if (handle >= 0) {
      for (auto& slot : g_loaded) {
        if (slot.used) continue;
        std::snprintf(slot.name, sizeof(slot.name), "%s", basename_of(path));
        std::snprintf(slot.path, sizeof(slot.path), "%s", path);
        slot.handle = handle;
        slot.used = true;
        recorded = true;
        break;
      }
    }
    writer.begin_object();
    writer.field_bool("ok", handle >= 0);
    writer.field_number("handle", handle);
    writer.field_string("name", basename_of(path));
    if (handle < 0) writer.field_string("error", "sceKernelLoadStartModule failed; see the log");
    else if (!recorded) writer.field_string("warning", "loaded, but the unload table is full");
    writer.end_object();
    return writer.length();
  }

  if (std::strcmp(op, "unload_script") == 0) {
    const char* name = json.string_field(root, "name", "");
    // Stop the script first so its fiber is gone before the code disappears.
    manager.remove(name);
    bool unloaded = false;
    for (auto& slot : g_loaded) {
      if (!slot.used || std::strcmp(slot.name, name) != 0) continue;
      unloaded = orbis::unload_module(slot.handle);
      if (unloaded) slot.used = false;
      break;
    }
    writer.begin_object();
    writer.field_bool("ok", unloaded);
    writer.field_string("name", name);
    if (!unloaded) writer.field_string("error", "no such loaded script, or the unload failed");
    writer.end_object();
    return writer.length();
  }

  if (std::strcmp(op, "native") == 0) {
    if (g_native_request.pending) {
      writer.begin_object();
      writer.field_bool("ok", false);
      writer.field_string("error", "a native call is already in flight");
      writer.end_object();
      return writer.length();
    }

    const char* name = json.string_field(root, "name", "");
    std::uint64_t hash = static_cast<std::uint64_t>(json.number_field(root, "hash", 0));
    if (hash == 0 && name[0] != '\0') hash = Crossmap::instance().lookup(name);
    if (hash == 0) {
      writer.begin_object();
      writer.field_bool("ok", false);
      writer.field_string("error",
                          "unresolved native: pass a 0x hash, or add the name to natives.txt");
      writer.end_object();
      return writer.length();
    }

    g_native_request.context.reset();
    g_native_request.error[0] = '\0';
    if (!build_arguments(json, json.find(root, "args"), &g_native_request.context,
                         g_native_request.error, sizeof(g_native_request.error))) {
      writer.begin_object();
      writer.field_bool("ok", false);
      writer.field_string("error", g_native_request.error);
      writer.end_object();
      return writer.length();
    }

    g_native_request.hash = hash;
    std::snprintf(g_native_request.return_type, sizeof(g_native_request.return_type), "%s",
                  json.string_field(root, "return_type", "int"));
    g_native_request.complete = false;
    g_native_request.ok = false;
    g_native_request.pending = true;

    // Wait for the script thread to run it.
    std::uint32_t waited = 0;
    while (!g_native_request.complete && waited < kNativeTimeoutMs) {
      orbis::sleep_ms(2);
      waited += 2;
    }

    writer.begin_object();
    if (!g_native_request.complete) {
      g_native_request.pending = false;
      writer.field_bool("ok", false);
      writer.field_string("error",
                          "the script tick did not run within 3s — is the game paused, or did "
                          "the script_tick signature fail to resolve?");
    } else if (!g_native_request.ok) {
      writer.field_bool("ok", false);
      writer.field_string("error", g_native_request.error);
    } else {
      writer.field_bool("ok", true);
      writer.field_number("hash", static_cast<double>(hash));
      write_native_result(writer, g_native_request);
    }
    writer.end_object();
    return writer.length();
  }

  writer.begin_object();
  writer.field_bool("ok", false);
  writer.field_string("error", "unknown op");
  writer.field_string("op", op);
  writer.end_object();
  return writer.length();
}

void ControlServer::pump() {
  if (!g_native_request.pending) return;

  auto& game = Game::instance();
  if (game.invoke(g_native_request.hash, &g_native_request.context)) {
    const char* type = g_native_request.return_type;
    if (std::strcmp(type, "float") == 0) {
      g_native_request.float_result = g_native_request.context.result<float>();
    } else if (std::strcmp(type, "vector3") == 0) {
      g_native_request.vector_result = g_native_request.context.vector_result();
    } else {
      g_native_request.integer_result = g_native_request.context.result<std::int64_t>();
    }
    g_native_request.ok = true;
  } else {
    g_native_request.ok = false;
    std::snprintf(g_native_request.error, sizeof(g_native_request.error),
                  "no handler registered for hash 0x%llx on this build",
                  static_cast<unsigned long long>(g_native_request.hash));
  }

  g_native_request.pending = false;
  g_native_request.complete = true;
}

ControlServer& ControlServer::instance() {
  static ControlServer server;
  return server;
}

}  // namespace osh
