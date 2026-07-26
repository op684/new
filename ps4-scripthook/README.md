# ps4-scripthook

Two halves of a GTA V modding stack for a jailbroken PlayStation 4 on firmware 11.00:

- **`mcp-server/`** — an MCP server that drives the console over ps4debug: process and memory
  inspection, patching, allocation, remote calls, signature scanning, payload and file deployment,
  plus a control surface for the plugin below. This is complete and tested.
- **`plugin/`** — **OrbisScriptHook**, a ScriptHookV-equivalent script runtime built from scratch
  for Orbis OS: a GoldHEN plugin that hooks the game's script dispatcher, resolves the native
  table, and runs mod scripts on fibers so they can `scriptWait()` mid-logic. The architecture is
  complete and the portable half is tested; the build-specific signatures are not, and cannot be,
  filled in without your console. See [What is and isn't done](#what-is-and-isnt-done).

## Scope

This is for **single-player** modification of a game you own on hardware you own. GTA Online is
explicitly out of scope: script mods in an online session affect other players, and Rockstar bans
for it. Nothing here targets online, and the sample script is offline-only.

## Quick start

### 1. Console side

You need GoldHEN running and the ps4debug payload loaded. From a machine on the same network:

```bash
cd mcp-server
npm install && npm run build
export PS4_HOST=192.168.1.42          # your console's LAN IP
node dist/index.js                    # speaks MCP over stdio
```

Register it with your MCP client, then:

```
ps4_connect       host=192.168.1.42
ps4_notify        message="hello from MCP"     # confirms the link end to end
gta_attach                                     # finds the running game
```

If `ps4_connect` fails, ps4debug is not running — send it with `ps4_send_payload`
(`path=/path/to/ps4debug.bin`), wait a second, and retry.

### 2. Reverse-engineering loop

The signatures in `plugin/orbis/game_offsets.h` are PC seeds. Deriving the PS4 equivalents is what
the MCP server exists for:

```
gta_scan_seeds                                  # what each signature is for
gta_scan_pattern  pattern="48 8B 05 ?? ?? ?? ??"
gta_resolve_rip   operand_address=... instruction_end=...
ps4_read_memory   address=... length=64 format=hexdump
```

Narrow each pattern until it yields exactly one hit, then paste it into `game_offsets.h`. The
plugin refuses ambiguous matches rather than picking the first, so a sloppy signature fails loudly
at load time instead of crashing mid-session.

### 3. Plugin side

```bash
export OO_PS4_TOOLCHAIN=/opt/OpenOrbis/PS4Toolchain
cd plugin
make test          # host tests: fibers, scheduler, patterns, JSON, detour
make               # -> build/orbis_scripthook.prx
make sample        # -> build/godmode_demo.prx
```

Deploy and run:

```
ps4_upload_file  local_path=plugin/build/orbis_scripthook.prx \
                 remote_path=/data/GoldHEN/plugins/orbis_scripthook.prx
```

Add it to `/data/GoldHEN/plugins.ini` under your title id, restart the game, then:

```
scripthook_status                                # did it resolve anything?
scripthook_log   lines=100                       # what happened at load
scripthook_call_native native="PLAYER_PED_ID"
```

## How it fits together

```
  your MCP client
        │  stdio
  ┌─────▼─────────────┐   TCP 744  (ps4debug)   ┌──────────────────────────┐
  │ ps4-scripthook    │────────────────────────▶│ PS4 / GoldHEN            │
  │ mcp-server        │   TCP 9090 (payloads)   │                          │
  │                   │   TCP 2121 (FTP)        │  ┌────────────────────┐  │
  │                   │   TCP 9028 (control)    │  │ eboot.bin (GTA V)  │  │
  └───────────────────┘────────────────────────▶│  │  OrbisScriptHook   │  │
                                                 │  │   ├ tick hook      │  │
                                                 │  │   ├ native table   │  │
                                                 │  │   ├ fiber sched.   │  │
                                                 │  │   └ control server │  │
                                                 │  └────────────────────┘  │
                                                 └──────────────────────────┘
```

The split matters: ps4debug can read, write and call into the process from outside, which is
everything you need to *find* things. It cannot safely call script natives, because those must run
on the engine's script thread inside a tick. That is what the in-process plugin is for.

## What is and isn't done

**Done and verified here:**

- The ps4debug protocol client — framing, chunked reads, two-phase writes, the 68-byte RPC blob,
  status decoding. Tested against an in-process mock console that decodes every packet the client
  emits (`mcp-server/test/protocol.test.mjs`, 11 tests).
- 18 MCP tools across connection, memory, RE and plugin control, building clean under
  `tsc --strict`.
- The plugin's portable core: the hand-rolled x86-64 fiber switch, the script scheduler, the
  pattern matcher, the native-call ABI, the JSON codec, and the inline detour — which is exercised
  by actually hooking machine code assembled at runtime, calling through the trampoline, and
  restoring (`plugin/tests/`, 206 checks across two suites).

**Not done, and honestly not doable without the hardware:**

- **The build signatures.** `game_offsets.h` ships the public PC patterns as seeds. Some will hit
  on your build and some will not; that is the reverse-engineering work, and it needs your console
  in the loop. Everything else in the plugin is build-independent so that this is the only file
  that changes.
- **The native crossmap.** GTA V native hashes are not `joaat` of the native's name and are rotated
  per build, so a name→hash table has to be produced for your specific build. See
  [docs/natives.md](docs/natives.md). The plugin reads one from
  `/data/GoldHEN/scripthook/natives.txt` so you can iterate without rebuilding.
- **Compiling the .prx.** That needs the OpenOrbis toolchain, which is not installed here. The
  Makefile is written against the GoldHEN Plugin SDK's conventions but has not been run.
- **Anything on real hardware.** No part of the console-side code has executed on a PS4.

## Layout

```
mcp-server/
  src/services/     protocol codec, ps4debug client, FTP/payload transfer,
                    scanning, GTA helpers, plugin control client
  src/tools/        connection, memory, modding — 18 MCP tools
  test/             mock-console round-trip tests
plugin/
  core/             portable: fibers, scheduler, patterns, JSON, native ABI, log
  orbis/            Orbis-specific: plugin entry, detour, signature resolution,
                    crossmap, control server, platform glue
  include/          the API mod scripts compile against
  samples/          a worked example script
  tests/            host build of everything portable
docs/
```

## Legal

Console jailbreaking and modifying single-player games you own is legal in many jurisdictions, but
that is not universal and this is not legal advice. Running unsigned code voids your warranty, can
brick a console, and will get the account banned from PSN. Use a console you have already accepted
those consequences for.
