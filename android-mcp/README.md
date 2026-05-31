# Android MCP — full control of a rooted device

An [MCP](https://modelcontextprotocol.io) server that gives Claude (Opus 4.8)
hands-on control of a **rooted Android device** — built and tested against a
**OnePlus 7 Pro** — over [ADB](https://developer.android.com/tools/adb).

The server runs on your computer, talks to the phone over USB or wireless ADB,
and exposes a set of tools the model can call: run shell/root commands, tap and
swipe the screen, take screenshots, manage apps, transfer and edit files, read
logs, and reboot. Because every privileged action routes through `su`
(Magisk/SuperSU), on a rooted device the model effectively has full control.

> ⚠️ **This is powerful.** Point it only at a device **you own**, and only
> connect it to an MCP client **you trust**. Root tools can brick a device,
> wipe data, or change system behavior. Read [Safety](#safety) before use.

## How it works

```
┌────────────┐      MCP (stdio)      ┌──────────────┐      ADB (USB/WiFi)   ┌───────────────┐
│  Claude /  │  ◄────────────────►   │  android-mcp  │  ◄────────────────►  │  OnePlus 7 Pro │
│  MCP client│        tools          │   (this repo) │   adb shell / su     │   (rooted)     │
└────────────┘                       └──────────────┘                       └───────────────┘
```

The server is a Python process. It shells out to your local `adb` binary, so
ADB is the only hard dependency on the device side.

## Prerequisites

1. **Android platform-tools** (`adb`) installed and on your `PATH`
   ([download](https://developer.android.com/tools/releases/platform-tools)).
2. **Python 3.10+**. [`uv`](https://docs.astral.sh/uv/) is recommended.
3. On the phone:
   - **Developer options → USB debugging** enabled.
   - **Root** (Magisk on a OnePlus 7 Pro). Grant the **shell** app root when
     the first `su` prompt appears, and set it to "Remember".

## Setup

```bash
cd android-mcp

# with uv (recommended)
uv sync

# or with pip
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

Verify ADB sees the phone and root works:

```bash
adb devices -l
adb shell su -c id        # should print uid=0(root)
```

## Connecting wirelessly (optional)

```bash
adb tcpip 5555                 # while connected over USB
adb connect 192.168.1.42:5555  # phone's IP
```

Then set `ANDROID_SERIAL` to `192.168.1.42:5555` (see below) or call the
`connect_wireless` tool.

## Wiring it into Claude Desktop

Edit your Claude Desktop config (macOS:
`~/Library/Application Support/Claude/claude_desktop_config.json`,
Windows: `%APPDATA%\Claude\claude_desktop_config.json`) — see
[`claude_desktop_config.example.json`](./claude_desktop_config.example.json):

```json
{
  "mcpServers": {
    "android-control": {
      "command": "uv",
      "args": ["--directory", "/absolute/path/to/android-mcp", "run", "android-mcp"],
      "env": { "ADB_PATH": "adb", "ANDROID_SERIAL": "", "ADB_TIMEOUT": "120" }
    }
  }
}
```

Restart Claude Desktop. You should see the `android-control` tools appear.

### Using it from Claude Code

```bash
claude mcp add android-control -- uv --directory /absolute/path/to/android-mcp run android-mcp
```

## Configuration (env vars)

| Variable         | Default | Purpose                                              |
|------------------|---------|------------------------------------------------------|
| `ADB_PATH`       | `adb`   | Path to the adb binary                               |
| `ANDROID_SERIAL` | (unset) | Target a specific device serial or `host:port`       |
| `ADB_TIMEOUT`    | `120`   | Per-command timeout in seconds                       |

## Tools

| Tool | What it does |
|------|--------------|
| `list_devices` | List devices visible to adb |
| `connect_wireless` | Connect over wireless ADB (`host:port`) |
| `device_status` | Model, Android version, **root status** |
| `device_info` | Dump/filter `getprop` system properties |
| `shell` | Run a command as the shell user |
| `root_shell` | Run a command as **root** via `su -c` |
| `screenshot` | Capture the screen as a PNG |
| `tap` / `swipe` | Touch input at pixel coordinates |
| `input_text` | Type into the focused field |
| `keyevent` | Send keys (HOME, BACK, POWER, …) |
| `list_packages` | List installed apps (filter / 3rd-party only) |
| `start_app` / `stop_app` | Launch / force-stop an app |
| `install_apk` / `uninstall` | Install from host / remove an app |
| `push_file` / `pull_file` | Transfer files host ↔ device |
| `read_file` / `write_file` | Read/write device files (root by default) |
| `logcat` | Recent log snapshot (filterable) |
| `reboot` | Reboot (normal/recovery/bootloader/fastboot) |

### Example prompts

- "Take a screenshot and tell me what app is open."
- "List my third-party apps, then force-stop com.spotify.music."
- "Set the CPU governor to performance on all cores." *(uses `root_shell`)*
- "Read /proc/cpuinfo and summarize it."
- "Enable 90Hz: write the right value into the display sysfs node."

## Testing

Pure-logic tests for the ADB wrapper (no device needed):

```bash
cd android-mcp
python -m unittest discover -s tests -v
```

Interactive exploration with the MCP Inspector:

```bash
uv run mcp dev src/android_mcp/server.py
```

## Safety

- **Ownership:** Only use on devices you own and have rooted yourself.
- **Trust the client:** Anything driving this server can run arbitrary root
  commands. Don't expose it to untrusted automation.
- **Destructive actions:** `root_shell`, `write_file`, `uninstall`, and
  `reboot` can damage the system or lose data. Consider reviewing tool calls
  before approving them in your MCP client.
- **Backups:** Keep a current backup / know your recovery path (TWRP, fastboot
  images) before letting the model make system changes.

## License

MIT
