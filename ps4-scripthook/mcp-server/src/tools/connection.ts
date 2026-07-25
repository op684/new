/** Console connection, discovery and payload/plugin deployment tools. */

import { readFile } from "node:fs/promises";
import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { consoleContext } from "../services/context.js";
import { formatProt, PAYLOAD_PORT, PS4DEBUG_PORT, SCRIPTHOOK_PORT } from "../services/protocol.js";
import { ftpUpload, sendPayload } from "../services/transfer.js";
import { guarded, hex, toolResult } from "../services/format.js";

export function registerConnectionTools(server: McpServer): void {
  server.registerTool(
    "ps4_connect",
    {
      title: "Connect to the console",
      description: `Point the server at a jailbroken PS4 running the ps4debug payload and verify the link.

Call this once per session before any other ps4_* / gta_* tool. The host is remembered for
subsequent calls. If PS4_HOST is set in the environment the server auto-configures at startup and
this tool only needs to be called to change consoles.

Args:
  - host (string): the console's LAN IP, e.g. "192.168.1.42"
  - debug_port (number): ps4debug command port (default 744)
  - scripthook_port (number): OrbisScriptHook control port (default 9028)

Returns: { host, debug_port, ps4debug_version, process_count }

Errors:
  - "could not reach ps4debug" — the payload is not running. Send ps4debug.bin to port 9090 first
    (ps4_send_payload), usually via the GoldHEN payload menu or a host like /data/ps4debug.bin.`,
      inputSchema: {
        host: z.string().min(3).describe('Console LAN IP address, e.g. "192.168.1.42"'),
        debug_port: z.number().int().min(1).max(65535).default(PS4DEBUG_PORT)
          .describe("ps4debug command port (default 744)"),
        scripthook_port: z.number().int().min(1).max(65535).default(SCRIPTHOOK_PORT)
          .describe("OrbisScriptHook control port (default 9028)"),
      },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    guarded(async ({ host, debug_port, scripthook_port }) => {
      consoleContext.configure(host, debug_port, scripthook_port);
      const api = await consoleContext.api();
      const version = await api.version();
      const processes = await api.processes();
      const output = {
        host,
        debug_port,
        ps4debug_version: version,
        process_count: processes.length,
      };
      return toolResult(
        `Connected to ${host}:${debug_port}\nps4debug version: ${version}\n${processes.length} processes running`,
        output,
      );
    }),
  );

  server.registerTool(
    "ps4_list_processes",
    {
      title: "List console processes",
      description: `List every process on the console with its pid, and resolve title ids for game processes.

Games always appear as "eboot.bin"; the CUSA title id distinguishes them.

Args:
  - resolve_title_ids (boolean): also issue CMD_PROC_INFO per eboot.bin (default true, slightly slower)

Returns: { count, processes: [{ pid, name, title_id?, path? }] }`,
      inputSchema: {
        resolve_title_ids: z.boolean().default(true)
          .describe("Query CMD_PROC_INFO for each eboot.bin to get its CUSA title id"),
      },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    guarded(async ({ resolve_title_ids }) => {
      const api = await consoleContext.api();
      const procs = await api.processes();
      const rows = [];
      for (const proc of procs) {
        const row: { pid: number; name: string; title_id?: string; path?: string } = {
          pid: proc.pid,
          name: proc.name,
        };
        if (resolve_title_ids && proc.name === "eboot.bin") {
          try {
            const info = await api.processInfo(proc.pid);
            row.title_id = info.titleId;
            row.path = info.path;
          } catch {
            // Process may have exited; leave the fields unset.
          }
        }
        rows.push(row);
      }
      const text = [
        `# Processes (${rows.length})`,
        "",
        ...rows.map((r) => `- ${r.pid}\t${r.name}${r.title_id ? `\t${r.title_id}` : ""}`),
      ].join("\n");
      return toolResult(text, { count: rows.length, processes: rows }, "filter with resolve_title_ids=false");
    }),
  );

  server.registerTool(
    "ps4_memory_map",
    {
      title: "List memory regions",
      description: `Dump a process's virtual memory map (CMD_PROC_MAPS): every mapped region with
address range, size and protection.

Use this to locate the game executable's .text segment before signature scanning.

Args:
  - pid (number, optional): target pid; defaults to the detected game process
  - executable_only (boolean): only regions with the execute bit set (default false)

Returns: { pid, count, regions: [{ name, start, end, size, prot }] } with addresses as hex strings`,
      inputSchema: {
        pid: z.number().int().min(1).optional().describe("Target pid; omit to use the running game"),
        executable_only: z.boolean().default(false).describe("Only list regions with +x protection"),
      },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    guarded(async ({ pid, executable_only }) => {
      const api = await consoleContext.api();
      const target = await consoleContext.resolvePid(pid);
      const maps = await api.maps(target);
      const filtered = executable_only ? maps.filter((m) => (m.prot & 4) !== 0) : maps;
      const regions = filtered.map((m) => ({
        name: m.name,
        start: hex(m.start),
        end: hex(m.end),
        size: Number(m.size),
        prot: formatProt(m.prot),
      }));
      const text = [
        `# Memory map for pid ${target} (${regions.length} regions)`,
        "",
        ...regions.map(
          (r) => `${r.start}-${r.end}  ${r.prot}  ${(r.size / 1024).toFixed(0).padStart(8)} KiB  ${r.name}`,
        ),
      ].join("\n");
      return toolResult(text, { pid: target, count: regions.length, regions }, "set executable_only=true");
    }),
  );

  server.registerTool(
    "ps4_notify",
    {
      title: "Show an on-screen notification",
      description: `Pop a notification on the console's screen. Handy for confirming the link works
and for marking progress during a long reverse-engineering session.

Args:
  - message (string): text to display

Returns: { sent: true, message }`,
      inputSchema: {
        message: z.string().min(1).max(512).describe("Text to show on the console"),
      },
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
    },
    guarded(async ({ message }) => {
      const api = await consoleContext.api();
      await api.notify(message);
      return toolResult(`Notification sent: ${message}`, { sent: true, message });
    }),
  );

  server.registerTool(
    "ps4_send_payload",
    {
      title: "Send a payload to the loader",
      description: `Upload a payload binary (ps4debug.bin, goldhen.bin, …) to the console's payload
loader on port 9090. The loader executes the blob once the socket closes.

This is how you (re)start ps4debug after a console reboot. It does NOT need an existing ps4debug
connection.

Args:
  - host (string, optional): console IP; defaults to the connected console
  - path (string): local filesystem path to the .bin payload
  - port (number): loader port (default 9090)

Returns: { sent: true, bytes, path }

Note: sending a payload runs unsigned code on the console. Only send payloads you trust.`,
      inputSchema: {
        host: z.string().optional().describe("Console IP; omit to use the connected console"),
        path: z.string().min(1).describe("Local path to the payload binary"),
        port: z.number().int().min(1).max(65535).default(PAYLOAD_PORT).describe("Loader port (default 9090)"),
      },
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
    },
    guarded(async ({ host, path, port }) => {
      const target = host ?? consoleContext.requireHost();
      const payload = await readFile(path);
      await sendPayload(target, payload, port);
      return toolResult(
        `Sent ${payload.length} bytes from ${path} to ${target}:${port}. Give the console a second, then call ps4_connect.`,
        { sent: true, bytes: payload.length, path },
      );
    }),
  );

  server.registerTool(
    "ps4_upload_file",
    {
      title: "Upload a file over FTP",
      description: `Copy a local file to the console over GoldHEN's anonymous FTP server (port 2121),
creating parent directories as needed.

Primary use: installing the OrbisScriptHook plugin and its scripts.
  - plugin  -> /data/GoldHEN/plugins/orbis_scripthook.prx
  - scripts -> /data/GoldHEN/scripthook/scripts/<name>.prx

Args:
  - local_path (string): file to upload
  - remote_path (string): absolute destination path on the console
  - port (number): FTP port (default 2121)

Returns: { uploaded: true, bytes, remote_path }`,
      inputSchema: {
        local_path: z.string().min(1).describe("Local file to upload"),
        remote_path: z.string().min(1).startsWith("/").describe("Absolute destination path on the console"),
        port: z.number().int().min(1).max(65535).default(2121).describe("GoldHEN FTP port (default 2121)"),
      },
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true },
    },
    guarded(async ({ local_path, remote_path, port }) => {
      const host = consoleContext.requireHost();
      const data = await readFile(local_path);
      await ftpUpload(host, remote_path, data, port);
      return toolResult(`Uploaded ${data.length} bytes to ${remote_path}`, {
        uploaded: true,
        bytes: data.length,
        remote_path,
      });
    }),
  );
}
