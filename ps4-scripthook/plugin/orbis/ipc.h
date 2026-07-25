// The control channel the MCP server talks to.
//
// A background thread accepts connections on TCP 9028 and reads length-prefixed
// JSON. Requests that only read plugin state are answered on that thread;
// requests that touch the game (native calls) are parked in a single-slot queue
// and executed by pump() from inside the script tick, because RAGE script state
// must not be touched from an arbitrary thread.

#pragma once

#include <cstddef>
#include <cstdint>

namespace osh {

class ControlServer {
 public:
  static constexpr std::uint16_t kDefaultPort = 9028;
  static constexpr std::size_t kMaxMessage = 16 * 1024;

  bool start(std::uint16_t port = kDefaultPort);
  void stop();

  // Runs any queued game-thread work. Called once per script tick.
  void pump();

  bool running() const { return running_; }

  static ControlServer& instance();

 private:
  static void thread_entry(void* user);
  void accept_loop();
  // Builds the reply for one request. Returns the number of bytes written.
  std::size_t handle(char* request, std::size_t length, char* reply, std::size_t capacity);

  int listen_fd_ = -1;
  bool running_ = false;
  volatile bool stopping_ = false;
};

}  // namespace osh
