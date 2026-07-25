#!/usr/bin/env node
/**
 * ps4-scripthook-mcp-server
 *
 * Drives a jailbroken PlayStation 4 (firmware 11.00, GoldHEN + ps4debug) for
 * single-player game modification and reverse engineering, and controls the
 * OrbisScriptHook runtime that lives inside the game process.
 *
 * Transport: stdio (this is a local tool that talks to hardware on your LAN).
 * Configure PS4_HOST to skip the explicit ps4_connect call.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { consoleContext } from "./services/context.js";
import { registerConnectionTools } from "./tools/connection.js";
import { registerMemoryTools } from "./tools/memory.js";
import { registerModdingTools } from "./tools/modding.js";

const server = new McpServer({
  name: "ps4-scripthook-mcp-server",
  version: "0.1.0",
});

registerConnectionTools(server);
registerMemoryTools(server);
registerModdingTools(server);

async function main(): Promise<void> {
  if (process.argv.includes("--help") || process.argv.includes("-h")) {
    process.stdout.write(
      [
        "ps4-scripthook-mcp-server — MCP server for a jailbroken PS4 (GoldHEN + ps4debug)",
        "",
        "Usage: ps4-scripthook-mcp-server            (speaks MCP over stdio)",
        "",
        "Environment:",
        "  PS4_HOST             console IP; pre-configures the connection",
        "  PS4_DEBUG_PORT       ps4debug port (default 744)",
        "  PS4_SCRIPTHOOK_PORT  OrbisScriptHook control port (default 9028)",
        "",
      ].join("\n"),
    );
    return;
  }

  if (process.env.PS4_HOST) {
    consoleContext.configure(
      process.env.PS4_HOST,
      process.env.PS4_DEBUG_PORT ? Number(process.env.PS4_DEBUG_PORT) : undefined,
      process.env.PS4_SCRIPTHOOK_PORT ? Number(process.env.PS4_SCRIPTHOOK_PORT) : undefined,
    );
  }

  const transport = new StdioServerTransport();
  await server.connect(transport);
  // stdout is the MCP channel; diagnostics must go to stderr.
  console.error(
    `ps4-scripthook-mcp-server ready${process.env.PS4_HOST ? ` (console ${process.env.PS4_HOST})` : ""}`,
  );
}

main().catch((error: unknown) => {
  console.error("fatal:", error instanceof Error ? error.message : error);
  process.exit(1);
});
