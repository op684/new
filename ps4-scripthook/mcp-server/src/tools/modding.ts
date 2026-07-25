/** GTA V reverse-engineering helpers and the OrbisScriptHook control surface. */

import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { consoleContext } from "../services/context.js";
import { findExecutableSegment, joaat, SCAN_SEEDS } from "../services/gta.js";
import { resolveRipRelative, scanRange } from "../services/scan.js";
import { guarded, hex, toAddress, toolResult } from "../services/format.js";

export function registerModdingTools(server: McpServer): void {
  server.registerTool(
    "gta_attach",
    {
      title: "Find the running game",
      description: `Detect the running game process and its executable segment. Everything else in the
gta_* family defaults to what this finds, so call it after the game is loaded into gameplay.

Args:
  - refresh (boolean): re-detect instead of using the cached process (default false)

Returns: { pid, title_id, recognised, module: { name, start, end, size } }

"recognised": false just means the title id is not in the built-in GTA V table — the tools still
work, you are simply attached to a different game than expected.`,
      inputSchema: {
        refresh: z.boolean().default(false).describe("Force re-detection of the game process"),
      },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    guarded(async ({ refresh }) => {
      const api = await consoleContext.api();
      const game = await consoleContext.gameProcess(refresh);
      const module = await findExecutableSegment(api, game.pid);
      const output = {
        pid: game.pid,
        title_id: game.titleId,
        recognised: game.recognised,
        module: {
          name: module.name,
          start: hex(module.start),
          end: hex(module.end),
          size: Number(module.size),
        },
      };
      const text = [
        `Attached to pid ${game.pid} (${game.titleId}${game.recognised ? ", known GTA V SKU" : ", unrecognised title id"})`,
        `Executable segment: ${hex(module.start)}–${hex(module.end)} (${(Number(module.size) / 1024 / 1024).toFixed(1)} MiB)`,
        `Path: ${game.path}`,
      ].join("\n");
      return toolResult(text, output);
    }),
  );

  server.registerTool(
    "gta_scan_pattern",
    {
      title: "Signature-scan the game",
      description: `Scan the game's executable segment for an IDA-style byte pattern and return the
matching addresses. This is the workhorse for locating engine structures on a build nobody has
mapped yet.

Args:
  - pattern (string): e.g. "48 8B 05 ?? ?? ?? ?? 48 85 C0" ("??" is a wildcard)
  - limit (number): stop after this many hits (default 8, max 64)
  - start / end (string|number, optional): restrict the range; defaults to the whole .text segment
  - pid (number, optional)

Returns: { pattern, count, hits: [{ address, module_offset }] }

Scanning the full segment pulls tens of MiB over the network and takes minutes on Wi-Fi. Narrow the
range once you have a rough idea where something lives.`,
      inputSchema: {
        pattern: z.string().min(2).describe('Byte pattern, e.g. "48 8B 05 ?? ?? ?? ??"'),
        limit: z.number().int().min(1).max(64).default(8).describe("Maximum hits to return"),
        start: z.union([z.string(), z.number()]).optional().describe("Start address; defaults to .text start"),
        end: z.union([z.string(), z.number()]).optional().describe("End address; defaults to .text end"),
        pid: z.number().int().min(1).optional().describe("Target pid; omit to use the running game"),
      },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    guarded(async ({ pattern, limit, start, end, pid }) => {
      const api = await consoleContext.api();
      const target = await consoleContext.resolvePid(pid);
      const module = await findExecutableSegment(api, target);
      const from = start !== undefined ? toAddress(start) : module.start;
      const to = end !== undefined ? toAddress(end) : module.end;
      const hits = await scanRange(api, { pid: target, start: from, end: to, pattern, limit });
      const rows = hits.map((address) => ({
        address: hex(address),
        module_offset: hex(address - module.start),
      }));
      const text = rows.length
        ? [`# ${rows.length} hit(s) for "${pattern}"`, "", ...rows.map((r) => `${r.address}  (+${r.module_offset})`)].join("\n")
        : `No matches for "${pattern}" in ${hex(from)}–${hex(to)}. Widen the wildcards or try a shorter pattern.`;
      return toolResult(text, { pattern, count: rows.length, hits: rows }, "lower the limit");
    }),
  );

  server.registerTool(
    "gta_resolve_rip",
    {
      title: "Resolve a RIP-relative operand",
      description: `Given the address of a 4-byte RIP-relative displacement and the length of the
remainder of the instruction, read the displacement out of the game and compute the absolute target.

Typical use: a hit from gta_scan_pattern lands on "48 8D 0D <disp32>"; the displacement is at
hit+3 and the instruction ends at hit+7, so call with operand_address=hit+3, instruction_end=hit+7.

Args:
  - operand_address (string|number): address of the disp32
  - instruction_end (string|number): address of the next instruction
  - pid (number, optional)

Returns: { operand_address, displacement, target }`,
      inputSchema: {
        operand_address: z.union([z.string(), z.number()]).describe("Address of the 4-byte displacement"),
        instruction_end: z.union([z.string(), z.number()]).describe("Address of the following instruction"),
        pid: z.number().int().min(1).optional().describe("Target pid; omit to use the running game"),
      },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    guarded(async ({ operand_address, instruction_end, pid }) => {
      const api = await consoleContext.api();
      const target = await consoleContext.resolvePid(pid);
      const operandAddr = toAddress(operand_address);
      const endAddr = toAddress(instruction_end);
      const displacement = (await api.readMemory(target, operandAddr, 4)).readInt32LE(0);
      const resolved = resolveRipRelative(displacement, endAddr);
      return toolResult(
        `disp32 = ${displacement} (${hex(displacement >>> 0)}) → target ${hex(resolved)}`,
        { operand_address: hex(operandAddr), displacement, target: hex(resolved) },
      );
    }),
  );

  server.registerTool(
    "gta_joaat",
    {
      title: "Compute a RAGE string hash",
      description: `Compute the RAGE joaat (Jenkins one-at-a-time, lowercased) hash of a string.

This is the hash the game uses for *string* identifiers: model names ("adder", "a_m_y_skater_01"),
weapon names ("weapon_pistol"), animation dictionaries — everything GET_HASH_KEY returns. It is
stable across every platform and build, so it is computed locally.

It is NOT how native hashes work: GTA V native hashes are not joaat of the native's name, and they
are rotated on every game build. To call a native by name, pass the name to scripthook_call_native
and let the plugin resolve it through the build's crossmap.

Args:
  - strings (array of string): values to hash, e.g. ["adder", "weapon_pistol"]

Returns: { hashes: [{ value, hash, hash_hex }] }`,
      inputSchema: {
        strings: z.array(z.string().min(1)).min(1).max(64).describe("Strings to hash"),
      },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    guarded(async ({ strings }) => {
      const hashes = strings.map((value) => {
        const hash = joaat(value);
        return { value, hash, hash_hex: hex(hash, 8) };
      });
      return toolResult(hashes.map((h) => `${h.value} = ${h.hash_hex}`).join("\n"), { hashes });
    }),
  );

  server.registerTool(
    "gta_scan_seeds",
    {
      title: "List candidate engine signatures",
      description: `List the seed signatures OrbisScriptHook needs resolved (native registration
table, GetNativeHandler, the script tick, the ped pool, the script global block table), with notes
on what each one is for.

These are the known *PC* patterns. Feed each into gta_scan_pattern against your PS4 build: the ones
that hit are free wins, the ones that miss need shortening or re-deriving from a dump. Record what
resolves in plugin/orbis/game_offsets.h.

Args: none
Returns: { seeds: [{ id, what, pattern, note }] }`,
      inputSchema: {},
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    guarded(async () => {
      const text = SCAN_SEEDS.map(
        (s) => `## ${s.id}\n${s.what}\npattern: ${s.pattern}\n${s.note}`,
      ).join("\n\n");
      return toolResult(text, { seeds: SCAN_SEEDS });
    }),
  );

  // -------------------------------------------------------- OrbisScriptHook

  server.registerTool(
    "scripthook_status",
    {
      title: "Query the OrbisScriptHook plugin",
      description: `Ask the in-game OrbisScriptHook plugin what state it is in: build, whether it
resolved the native table, how many scripts are loaded and how many ticks it has run.

Requires the plugin to be installed and the game running. If this errors with "did not answer",
the plugin is not loaded — check /data/GoldHEN/plugins.ini.

Args: none
Returns: { version, game_build, natives_resolved, native_count, scripts: [...], ticks }`,
      inputSchema: {},
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    guarded(async () => {
      const response = await consoleContext.scriptHook().request({ op: "status" });
      return toolResult(JSON.stringify(response, null, 2), response);
    }),
  );

  server.registerTool(
    "scripthook_call_native",
    {
      title: "Call a script native",
      description: `Invoke a GTA V script native inside the game, on the game's own script thread.

The plugin queues the call and runs it during the next script tick, which is the only safe place to
touch RAGE script state. Use this — not ps4_call_function — for anything native-shaped.

Names are resolved by the plugin through its build crossmap (native hashes differ per game build,
so they cannot be computed host-side). A 0x-prefixed value is passed through as a literal hash for
this build.

Args:
  - native (string): native name (e.g. "GET_PLAYER_PED") or a 0x-prefixed hash for this build
  - args (array): each { type: "int"|"float"|"bool"|"string"|"pointer", value }
  - return_type ("void"|"int"|"bool"|"float"|"string"|"vector3"|"pointer"): default "int"

Returns: { native, hash, result }

Example: pin the player's health
  native="SET_ENTITY_HEALTH", args=[{type:"int",value:<ped>},{type:"int",value:328}], return_type="void"

Errors:
  - "unresolved native" — the name is not in this build's crossmap, or the hash has no handler.
    Resolve it with gta_scan_pattern / gta_resolve_rip and add it to plugin/orbis/crossmap.h.`,
      inputSchema: {
        native: z.string().min(1).describe('Native name, or a 0x-prefixed hash for this build'),
        args: z
          .array(
            z.object({
              type: z.enum(["int", "float", "bool", "string", "pointer"]),
              value: z.union([z.number(), z.string(), z.boolean()]),
            }),
          )
          .max(16)
          .default([])
          .describe("Typed native arguments, in order"),
        return_type: z
          .enum(["void", "int", "bool", "float", "string", "vector3", "pointer"])
          .default("int")
          .describe("How to interpret the native's return value"),
      },
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
    },
    guarded(async ({ native, args, return_type }) => {
      const isHash = /^0x[0-9a-f]+$/i.test(native);
      const response = await consoleContext.scriptHook().request({
        op: "native",
        ...(isHash ? { hash: hex(Number(toAddress(native)), 8) } : { name: native }),
        args,
        return_type,
      });
      const hash = (response.hash as string | undefined) ?? (isHash ? native : "(resolved by plugin)");
      return toolResult(`${native} (${hash}) → ${JSON.stringify(response.result ?? null)}`, {
        native,
        hash,
        result: response.result ?? null,
      });
    }),
  );

  server.registerTool(
    "scripthook_manage_scripts",
    {
      title: "List, load or unload mod scripts",
      description: `Manage the mod scripts running inside OrbisScriptHook.

Args:
  - action ("list"|"load"|"unload"): what to do
  - path (string): for "load", the on-console path of the script .prx
    (convention: /data/GoldHEN/scripthook/scripts/<name>.prx)
  - name (string): for "unload", the script's registered name

Returns:
  - list:   { scripts: [{ name, path, state, ticks }] }
  - load:   { loaded: true, name }
  - unload: { unloaded: true, name }

Upload the .prx first with ps4_upload_file. Loading is hot — no game restart needed.`,
      inputSchema: {
        action: z.enum(["list", "load", "unload"]).describe("Operation to perform"),
        path: z.string().optional().describe('For "load": on-console path to the script .prx'),
        name: z.string().optional().describe('For "unload": the script name to stop'),
      },
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
    },
    guarded(async ({ action, path, name }) => {
      const client = consoleContext.scriptHook();
      if (action === "list") {
        const response = await client.request({ op: "list_scripts" });
        return toolResult(JSON.stringify(response, null, 2), response);
      }
      if (action === "load") {
        if (!path) throw new Error('action="load" requires a "path" — upload the .prx first with ps4_upload_file');
        const response = await client.request({ op: "load_script", path });
        return toolResult(`Loaded ${path}`, response);
      }
      if (!name) throw new Error('action="unload" requires a "name" — see scripthook_manage_scripts action="list"');
      const response = await client.request({ op: "unload_script", name });
      return toolResult(`Unloaded ${name}`, response);
    }),
  );

  server.registerTool(
    "scripthook_log",
    {
      title: "Read the plugin log",
      description: `Tail OrbisScriptHook's in-memory ring log — plugin startup, signature resolution
results, script registration and native call failures all land here. This is the first thing to read
when a script is not doing what you expect.

Args:
  - lines (number): how many recent lines to return (default 100, max 1000)

Returns: { lines: [...], dropped }`,
      inputSchema: {
        lines: z.number().int().min(1).max(1000).default(100).describe("Number of recent log lines"),
      },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    guarded(async ({ lines }) => {
      const response = await consoleContext.scriptHook().request({ op: "log", lines });
      const rows = Array.isArray(response.lines) ? (response.lines as string[]) : [];
      return toolResult(rows.join("\n") || "(log empty)", response, "request fewer lines");
    }),
  );
}
