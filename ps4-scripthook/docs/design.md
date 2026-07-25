# Design notes

## Why two components

A ps4debug connection can read, write, allocate and call into the game from outside the process.
That is enough to find things and to patch code, and it is the right tool while you are working out
where anything is: patterns can be iterated on without rebuilding or redeploying.

What it cannot do is call script natives correctly. GTA V's natives expect to run inside the
engine's script tick, on the script thread, with the VM in a consistent state. `CMD_PROC_CALL`
hijacks an arbitrary thread; using it for a native works often enough to be dangerous and crashes
often enough to be useless.

Hence OrbisScriptHook: a plugin loaded into the game process that hooks the tick and gives mod code
a place to run where natives are safe. The MCP server keeps its ps4debug tools for reverse
engineering, and gains a control channel to the plugin for anything that has to happen in-process.

## The script runtime

ScriptHookV's central idea is that a mod script should be able to write

```cpp
for (;;) {
  doSomething();
  scriptWait(100);
}
```

and have that "just work" against a game engine that owns the thread. On Windows it does that with
Win32 fibers. Orbis has no equivalent we can rely on inside a plugin, so `plugin/core/fiber.*`
implements the switch directly: push the six System V callee-saved registers, swap `rsp`, pop them
back, `ret`. Roughly twenty instructions, and `plugin/tests/test_core.cpp` exercises it — including
that a fiber's stack survives a round trip through the host context untouched, and that two fibers
interleave without corrupting each other's locals.

`ScriptManager::tick()` resumes each script whose wait has expired, once per game tick, from inside
the hook. Scripts that return are reaped. A script that unregisters itself defers teardown to the
next tick, because freeing a fiber's stack while standing on it is not recoverable.

The clock is injected (`set_clock`) rather than called directly, which is what lets the scheduler
tests drive time forward deterministically instead of sleeping.

## The tick hook

`Detour` (`plugin/orbis/hook.*`) is a standard inline detour: decode enough whole instructions at
the target to make room for a 14-byte absolute jump, copy them into a trampoline followed by a jump
back, then overwrite.

The instruction-length decoder deliberately understands only the encodings a compiler emits in a
function prologue, and returns 0 for anything else. `Detour::install` treats 0 as "refuse", logs
what it saw, and leaves the target untouched. Guessing here corrupts the game in a way that
manifests hours later.

`plugin/tests/test_hook.cpp` assembles a small function byte by byte in an RWX mapping, hooks it,
checks the replacement runs, calls the original through the trampoline, removes the hook and
verifies the original bytes are back. Same instruction set as the console, so this is real coverage
of the mechanism — what it cannot cover is whether the *target* is the right function on your build.

## Signature resolution

Nothing is a hardcoded address: ASLR moves the eboot every boot. `Game::initialise()` locates the
executable segment through the kernel's module info, then resolves each signature in
`game_offsets.h` by scanning that range.

Two deliberate behaviours:

- **Ambiguous matches are refused.** A pattern with two or more hits produces a log line and a null
  pointer, not the first hit. A signature that is not unique is not a signature.
- **Failures are survivable where they can be.** Optional signatures log and carry on. A missing
  native table means scripts still run but native calls fail with a clear message. A missing tick
  signature falls back to a standalone thread, which reports status and runs non-native scripts —
  and says loudly that natives from it are unsafe.

## The control channel

TCP 9028 inside the game process, length-prefixed JSON both ways. Read-only requests (status, log,
script list) are answered on the network thread. Anything that touches the game is parked in a
single-slot queue and executed by `ControlServer::pump()` from inside the tick — the same rule the
scripts follow.

One slot, not a ring buffer: the client is strictly request/response, and a deeper queue would hide
the case where the tick has stopped running. Instead, a native call that is not picked up within
three seconds fails with a message naming the two likely causes.

`plugin/core/json.*` is a fixed-node-pool parser and an append-only writer, both bounded, because
this runs during a frame. The parser accepts hex strings where numbers are expected, which is how
hashes arrive from the MCP server.

## Testing strategy

The PS4 is x86-64 running a FreeBSD-derived kernel. Everything in `plugin/core/` and the detour in
`plugin/orbis/hook.cpp` is ordinary user-mode code that behaves identically on a Linux host, so it
is built and run there (`plugin/tests/`). The platform-specific parts are quarantined in
`orbis_compat.*` behind an `OSH_HOST_BUILD` switch.

On the server side, `mcp-server/test/protocol.test.mjs` stands up a mock console that decodes every
packet the client sends and asserts on the exact bytes — magic, command id, argument blob layout,
chunk boundaries, the two-phase write handshake. That is how the 68-byte `CMD_PROC_CALL` blob and
the 32 KiB read chunking are verified without hardware.

What no amount of host testing can tell you is whether a signature points at the right function on
your build. That check only exists on the console, which is why `scripthook_status` and
`scripthook_log` report exactly what resolved and what did not.
