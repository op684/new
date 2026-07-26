/** Memory inspection, patching, allocation and remote procedure calls. */

import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { consoleContext } from "../services/context.js";
import { protFromString } from "../services/protocol.js";
import { guarded, hex, hexDump, toAddress, toBytes, toolResult } from "../services/format.js";

const AddressSchema = z
  .union([z.string(), z.number()])
  .describe('Address as 0x-prefixed hex (e.g. "0x00400000") or a decimal number');

export function registerMemoryTools(server: McpServer): void {
  server.registerTool(
    "ps4_read_memory",
    {
      title: "Read process memory",
      description: `Read bytes out of a process. Reads larger than 32 KiB are chunked automatically.

Args:
  - address (string|number): start address
  - length (number): bytes to read, 1..65536
  - pid (number, optional): defaults to the detected game process
  - format ("hexdump"|"hex"|"base64"|"u32"|"u64"|"f32"): how to present the bytes (default "hexdump")

Returns: { pid, address, length, format, data } where data is the rendered bytes; for the numeric
formats data is an array of decoded little-endian values.

Errors:
  - "no data" — the region is unmapped; check ps4_memory_map first.`,
      inputSchema: {
        address: AddressSchema,
        length: z.number().int().min(1).max(65536).describe("Number of bytes to read (max 65536)"),
        pid: z.number().int().min(1).optional().describe("Target pid; omit to use the running game"),
        format: z
          .enum(["hexdump", "hex", "base64", "u32", "u64", "f32"])
          .default("hexdump")
          .describe("Presentation of the returned bytes"),
      },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
    },
    guarded(async ({ address, length, pid, format }) => {
      const api = await consoleContext.api();
      const target = await consoleContext.resolvePid(pid);
      const addr = toAddress(address);
      const data = await api.readMemory(target, addr, length);

      let rendered: string;
      let structured: unknown;
      switch (format) {
        case "hex":
          rendered = data.toString("hex");
          structured = rendered;
          break;
        case "base64":
          rendered = data.toString("base64");
          structured = rendered;
          break;
        case "u32": {
          const values = [];
          for (let i = 0; i + 4 <= data.length; i += 4) values.push(data.readUInt32LE(i));
          structured = values;
          rendered = values.map((v, i) => `+${(i * 4).toString(16)}: ${v} (${hex(v)})`).join("\n");
          break;
        }
        case "u64": {
          const values = [];
          for (let i = 0; i + 8 <= data.length; i += 8) values.push(data.readBigUInt64LE(i).toString());
          structured = values;
          rendered = values
            .map((v, i) => `+${(i * 8).toString(16)}: ${v} (${hex(BigInt(v))})`)
            .join("\n");
          break;
        }
        case "f32": {
          const values = [];
          for (let i = 0; i + 4 <= data.length; i += 4) values.push(data.readFloatLE(i));
          structured = values;
          rendered = values.map((v, i) => `+${(i * 4).toString(16)}: ${v}`).join("\n");
          break;
        }
        default:
          rendered = hexDump(data, addr);
          structured = data.toString("hex");
      }

      return toolResult(
        rendered,
        { pid: target, address: hex(addr), length: data.length, format, data: structured },
        "read fewer bytes",
      );
    }),
  );

  server.registerTool(
    "ps4_write_memory",
    {
      title: "Write process memory",
      description: `Patch bytes into a running process. This is the primitive behind every code patch
and every "poke" style mod.

Args:
  - address (string|number): destination address
  - data (string): bytes as "90 90 90", "909090", or "base64:<data>"
  - pid (number, optional): defaults to the detected game process
  - verify (boolean): read the region back and compare (default true)

Returns: { pid, address, bytes_written, verified }

Writing to code pages requires them to be writable — use ps4_protect_memory first if the write
fails or silently does not stick.`,
      inputSchema: {
        address: AddressSchema,
        data: z.string().min(1).describe('Bytes to write: "90 90", "9090", or "base64:kJA="'),
        pid: z.number().int().min(1).optional().describe("Target pid; omit to use the running game"),
        verify: z.boolean().default(true).describe("Read back and confirm the write landed"),
      },
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true },
    },
    guarded(async ({ address, data, pid, verify }) => {
      const api = await consoleContext.api();
      const target = await consoleContext.resolvePid(pid);
      const addr = toAddress(address);
      const bytes = toBytes(data);
      await api.writeMemory(target, addr, bytes);

      let verified: boolean | null = null;
      if (verify) {
        const readBack = await api.readMemory(target, addr, bytes.length);
        verified = readBack.equals(bytes);
      }
      const note =
        verified === false
          ? "\nWARNING: read-back does not match. The page is probably read-only " +
            "(call ps4_protect_memory with prot=\"rwx\") or the game rewrote it immediately."
          : "";
      return toolResult(`Wrote ${bytes.length} bytes to ${hex(addr)}${note}`, {
        pid: target,
        address: hex(addr),
        bytes_written: bytes.length,
        verified,
      });
    }),
  );

  server.registerTool(
    "ps4_protect_memory",
    {
      title: "Change page protection",
      description: `Change the protection of a memory range (mprotect in the target).

Args:
  - address (string|number), length (number): the range
  - prot (string): any of "r", "w", "x" combined, e.g. "rx", "rwx"
  - pid (number, optional)

Returns: { pid, address, length, prot }`,
      inputSchema: {
        address: AddressSchema,
        length: z.number().int().min(1).describe("Length of the range in bytes"),
        prot: z.string().regex(/^[rwx-]{1,3}$/).describe('Protection flags, e.g. "rwx"'),
        pid: z.number().int().min(1).optional().describe("Target pid; omit to use the running game"),
      },
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true },
    },
    guarded(async ({ address, length, prot, pid }) => {
      const api = await consoleContext.api();
      const target = await consoleContext.resolvePid(pid);
      const addr = toAddress(address);
      await api.protect(target, addr, BigInt(length), protFromString(prot));
      return toolResult(`Set ${hex(addr)}+${length} to ${prot}`, {
        pid: target,
        address: hex(addr),
        length,
        prot,
      });
    }),
  );

  server.registerTool(
    "ps4_allocate_memory",
    {
      title: "Allocate memory in the target",
      description: `Allocate RWX memory inside a process — where you stage shellcode, trampolines and
mod data before patching a jump to it.

Args:
  - length (number): bytes to allocate
  - pid (number, optional)

Returns: { pid, address, length }. Free it with ps4_free_memory when done.`,
      inputSchema: {
        length: z.number().int().min(1).max(64 * 1024 * 1024).describe("Bytes to allocate"),
        pid: z.number().int().min(1).optional().describe("Target pid; omit to use the running game"),
      },
      annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
    },
    guarded(async ({ length, pid }) => {
      const api = await consoleContext.api();
      const target = await consoleContext.resolvePid(pid);
      const address = await api.allocate(target, length);
      return toolResult(`Allocated ${length} bytes at ${hex(address)}`, {
        pid: target,
        address: hex(address),
        length,
      });
    }),
  );

  server.registerTool(
    "ps4_free_memory",
    {
      title: "Free memory in the target",
      description: `Release a region previously returned by ps4_allocate_memory.

Args: address (string|number), length (number), pid (number, optional)
Returns: { pid, address, length, freed: true }`,
      inputSchema: {
        address: AddressSchema,
        length: z.number().int().min(1).describe("Length originally allocated"),
        pid: z.number().int().min(1).optional().describe("Target pid; omit to use the running game"),
      },
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true },
    },
    guarded(async ({ address, length, pid }) => {
      const api = await consoleContext.api();
      const target = await consoleContext.resolvePid(pid);
      const addr = toAddress(address);
      await api.free(target, addr, length);
      return toolResult(`Freed ${length} bytes at ${hex(addr)}`, {
        pid: target,
        address: hex(addr),
        length,
        freed: true,
      });
    }),
  );

  server.registerTool(
    "ps4_call_function",
    {
      title: "Call a function in the target",
      description: `Execute a function inside the game process with up to six integer/pointer
arguments and read back rax. ps4debug's RPC stub is installed on first use and cached.

This runs on a hijacked thread, NOT the game's script thread. It is the right tool for
one-shot engine calls while reverse-engineering, and the wrong tool for calling script natives
that expect to run inside a script tick — use scripthook_call_native for those.

Args:
  - address (string|number): function to call
  - args (array of string|number): up to 6 integer/pointer arguments (default [])
  - pid (number, optional)

Returns: { pid, address, rax, rax_hex }`,
      inputSchema: {
        address: AddressSchema,
        args: z.array(z.union([z.string(), z.number()])).max(6).default([])
          .describe("Up to six integer or pointer arguments"),
        pid: z.number().int().min(1).optional().describe("Target pid; omit to use the running game"),
      },
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
    },
    guarded(async ({ address, args, pid }) => {
      const api = await consoleContext.api();
      const target = await consoleContext.resolvePid(pid);
      const stub = await api.installRpc(target);
      const addr = toAddress(address);
      const rax = await api.call(target, stub, addr, args.map(toAddress));
      return toolResult(`${hex(addr)}(...) returned ${rax} (${hex(rax)})`, {
        pid: target,
        address: hex(addr),
        rax: rax.toString(),
        rax_hex: hex(rax),
      });
    }),
  );

  server.registerTool(
    "ps4_raw_command",
    {
      title: "Send a raw ps4debug command",
      description: `Escape hatch for ps4debug opcodes this server does not model (debugger
attach/breakpoints, kernel read/write, scan). Sends a header plus your argument blob, checks the
status word, then reads a fixed number of response bytes.

Args:
  - cmd (string|number): command id, e.g. "0xBDCC0001" for CMD_KERN_BASE
  - payload (string): argument blob as hex or "base64:…" (default empty)
  - response_bytes (number): how many bytes to read after the status word (default 0)

Returns: { cmd, response_hex, response_bytes }

Get the framing wrong and the socket desynchronises; call ps4_connect again to resync.`,
      inputSchema: {
        cmd: z.union([z.string(), z.number()]).describe('Command id, e.g. "0xBDCC0001"'),
        payload: z.string().default("").describe("Argument blob as hex or base64:…"),
        response_bytes: z.number().int().min(0).max(65536).default(0)
          .describe("Bytes to read after the status word"),
      },
      annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
    },
    guarded(async ({ cmd, payload, response_bytes }) => {
      const api = await consoleContext.api();
      const command = Number(toAddress(cmd));
      const body = payload ? toBytes(payload) : Buffer.alloc(0);
      const response = await api.raw(command, body, response_bytes);
      return toolResult(
        `Command ${hex(command)} ok; ${response.length} bytes back: ${response.toString("hex") || "(none)"}`,
        { cmd: hex(command), response_hex: response.toString("hex"), response_bytes: response.length },
      );
    }),
  );
}
