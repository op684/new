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

### Using it from Claude Code (CLI / Android Studio terminal)

This is the setup if you run the `claude` CLI inside Android Studio. Register
the server once, then Claude can read and drive the phone over ADB.

```bash
# From anywhere; --scope user makes it available in every project.
claude mcp add android-control --scope user -- \
  uv --directory /absolute/path/to/android-mcp run android-mcp
```

Or commit a project-scoped [`.mcp.json`](./.mcp.json.example) at your Android
Studio project root (copy the example and fix the path):

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

Verify it's connected from inside the CLI:

```
/mcp
```

You should see `android-control` listed with its tools. Now you can say things
like *"read what's on my phone screen right now"* and Claude will call
`screen_text` / `screen_elements` — **no screenshot needed**.

> **Seeing without screenshots:** `screen_text`, `screen_elements`, and
> `ui_tree` read the device's accessibility/UI tree (via `uiautomator`) and
> return it as plain text — actual on-screen labels, fields, and structure,
> not an image. That's faster and more precise than a screenshot for the model,
> and it works even when you can't (or don't want to) capture pixels. Keep
> `screenshot` for cases where an app draws custom/canvas UI the tree can't see.

## Configuration (env vars)

| Variable         | Default | Purpose                                              |
|------------------|---------|------------------------------------------------------|
| `ADB_PATH`       | `adb`   | Path to the adb binary                               |
| `ANDROID_SERIAL` | (unset) | Target a specific device serial or `host:port`       |
| `ADB_TIMEOUT`    | `120`   | Per-command timeout in seconds                       |

## Tools

The toolset is built so the model can operate the phone **as if it were holding
it** — see the screen, read the UI, and tap things by name.

### See the screen (no screenshot needed)

| Tool | What it does |
|------|--------------|
| `screen_text` | **Read all on-screen text as plain text** (accessibility tree) |
| `screen_elements` | Read the UI as a numbered list of elements + tap coordinates |
| `ui_tree` | Read the UI as an indented hierarchy (structure + text + coords) |
| `find_on_screen` | Search on-screen elements by text/desc/id |
| `current_app` | Which app/activity is in the foreground |
| `screenshot` | Capture the screen as a PNG (only when you need pixels) |

### Touch & gestures

| Tool | What it does |
|------|--------------|
| `tap_text` | Tap an element by its visible text/description |
| `tap_id` | Tap an element by resource-id |
| `tap` | Tap exact pixel coordinates |
| `long_press` | Press and hold |
| `double_tap` | Double-tap |
| `swipe` | Swipe/drag between two points |
| `scroll` | Scroll up/down/left/right by a fraction of the screen |
| `pinch` | Two-finger pinch to zoom in/out |

### Type

| Tool | What it does |
|------|--------------|
| `input_text` | Type into the focused field |
| `type_and_enter` | Type then press Enter (e.g. submit a search) |
| `clear_text` | Clear the focused field |
| `paste` | Paste the clipboard |
| `keyevent` | Send any key (ENTER, TAB, DEL, …) |

### Navigate

| Tool | What it does |
|------|--------------|
| `home` / `back` / `recents` | The three nav buttons |
| `open_notifications` / `open_quick_settings` | Pull down the shades |
| `close_panels` | Collapse panels & dialogs |

### Screen, lock & display

| Tool | What it does |
|------|--------------|
| `wake` / `sleep_screen` / `is_screen_on` | Display power |
| `unlock` | Wake, swipe up, and enter a PIN if given |
| `rotate` | Force portrait/landscape orientation |
| `set_brightness` | Set brightness 0–255 |
| `volume` | Media volume up/down/mute |
| `get_screen_size` | Resolution & density |

### Apps

| Tool | What it does |
|------|--------------|
| `list_packages` | List installed apps (filter / 3rd-party only) |
| `start_app` / `stop_app` | Launch / force-stop an app |
| `open_app_settings` | Open an app's App-Info screen |
| `install_apk` / `uninstall` | Install from host / remove an app |

### Communication & intents

| Tool | What it does |
|------|--------------|
| `open_url` | Open a URL in the browser |
| `dial` / `call` | Load the dialer / place a call (`call` uses root) |
| `compose_sms` | Open the SMS app with a drafted message |
| `start_intent` | Fire an arbitrary `am start` intent |

### System & connectivity

| Tool | What it does |
|------|--------------|
| `toggle_wifi` / `toggle_bluetooth` | Radios on/off (root) |
| `toggle_mobile_data` / `toggle_airplane` | Data & airplane mode (root) |
| `get_battery` | Battery level / charging / temp |
| `notifications` | Summary of active notifications |
| `clipboard_get` / `clipboard_set` | Read/write the clipboard (Android 12+) |

### Files, capture, shell & power

| Tool | What it does |
|------|--------------|
| `push_file` / `pull_file` | Transfer files host ↔ device |
| `read_file` / `write_file` | Read/write device files (root by default) |
| `screen_record` | Record the screen and pull the video |
| `logcat` | Recent log snapshot (filterable) |
| `shell` / `root_shell` | Arbitrary commands (user / root) |
| `device_status` / `device_info` | Model, Android version, **root status**, props |
| `list_devices` / `connect_wireless` | adb device management |
| `wait` | Pause so the UI can settle between actions |
| `reboot` | Reboot (normal/recovery/bootloader/fastboot) |

### The "hands-on" loop

A typical interaction mirrors how a person uses a phone:

1. `wake` / `unlock` — turn the screen on.
2. `screen_text` / `screen_elements` — *read* what's on screen (no screenshot).
3. `tap_text "Messages"` — *act* on what you see, by name.
4. `wait` — let the screen settle.
5. repeat: look → act → look.

### Example prompts

- "Unlock my phone (PIN 1234), open Chrome, search for the weather, and tell me
  the forecast." *(unlock → start_app → screen_elements → tap_text → type_and_enter → screenshot)*
- "Open Settings, go to Display, and turn on Dark mode." *(navigate by tapping labels)*
- "Read my latest notifications and summarize them." *(`notifications`)*
- "Turn on airplane mode, then back off after 10 seconds." *(`toggle_airplane`, `wait`)*
- "Set the CPU governor to performance on all cores." *(`root_shell`)*
- "Record a 15-second screen video of me scrolling Twitter." *(`screen_record` + `scroll`)*

## Testing

Pure-logic tests for the ADB wrapper and the UI-hierarchy parser (no device needed):

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
