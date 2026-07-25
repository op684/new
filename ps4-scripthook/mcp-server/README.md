# ps4-scripthook-mcp-server

MCP server for a jailbroken PS4 (firmware 11.00, GoldHEN + ps4debug) and the OrbisScriptHook
runtime. stdio transport — it talks to hardware on your LAN, so it runs locally.

```bash
npm install
npm run build
npm test                       # mock-console round-trip tests
PS4_HOST=192.168.1.42 node dist/index.js
```

## Environment

| Variable | Default | Meaning |
| --- | --- | --- |
| `PS4_HOST` | – | Console IP; pre-configures the connection so `ps4_connect` is optional |
| `PS4_DEBUG_PORT` | 744 | ps4debug command port |
| `PS4_SCRIPTHOOK_PORT` | 9028 | OrbisScriptHook control port |

## Tools

**Connection and deployment**

| Tool | Does |
| --- | --- |
| `ps4_connect` | Point at a console and verify ps4debug answers |
| `ps4_list_processes` | Every process, with CUSA title ids resolved for games |
| `ps4_memory_map` | A process's regions with ranges and protection |
| `ps4_notify` | On-screen notification — the fastest end-to-end check |
| `ps4_send_payload` | Push a payload to the loader on port 9090 |
| `ps4_upload_file` | Copy a file over GoldHEN's FTP (plugins, scripts, crossmaps) |

**Memory**

| Tool | Does |
| --- | --- |
| `ps4_read_memory` | Read bytes; hexdump, hex, base64, u32, u64 or f32 |
| `ps4_write_memory` | Patch bytes, with read-back verification |
| `ps4_protect_memory` | mprotect a range |
| `ps4_allocate_memory` / `ps4_free_memory` | RWX scratch inside the target |
| `ps4_call_function` | Call a function via the RPC stub (not for script natives) |
| `ps4_raw_command` | Escape hatch for unmodelled ps4debug opcodes |

**Reverse engineering**

| Tool | Does |
| --- | --- |
| `gta_attach` | Find the running game and its executable segment |
| `gta_scan_pattern` | IDA-style signature scan over the game's `.text` |
| `gta_resolve_rip` | Follow a RIP-relative operand to its target |
| `gta_scan_seeds` | The signatures the plugin needs, with notes |
| `gta_joaat` | RAGE string hash (model/weapon names — *not* native hashes) |

**Plugin control**

| Tool | Does |
| --- | --- |
| `scripthook_status` | What the plugin resolved, how many ticks it has run |
| `scripthook_call_native` | Call a native on the game's script thread |
| `scripthook_manage_scripts` | List, hot-load and unload mod scripts |
| `scripthook_log` | Tail the plugin's ring log |

## Notes

Reads over 32 KiB are chunked and writes are two-phase, both transparently. The client serialises
every command behind a queue: ps4debug's server is strictly request/response and interleaving two
commands corrupts the stream. If a `ps4_raw_command` desynchronises the socket, call `ps4_connect`
again to reconnect.
