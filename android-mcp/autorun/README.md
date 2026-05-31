# Auto-run on the phone (templates)

Drop these into your **Android Studio app project** (not this repo) so the
`claude` CLI automatically installs, opens, and tests the app on your rooted
OnePlus 7 Pro after it finishes coding — using the **android-control** MCP
server — without asking you each time.

## What's here

| File | Goes to (in your app project) | Purpose |
|------|-------------------------------|---------|
| `CLAUDE.md` | `<app-project>/CLAUDE.md` | Tells Claude to build → install → launch → read → test after every successful build. |
| `settings.json` | `<app-project>/.claude/settings.json` | Pre-approves the MCP tools + gradle build so the tools run without a prompt. |
| `.mcp.json` (use the one in the parent dir's `.mcp.json.example`) | `<app-project>/.mcp.json` | Registers the server for this project. |

## Setup (once per app project)

```bash
cd /path/to/your/android/app/project

# 1. Workflow instructions
cp /path/to/android-mcp/autorun/CLAUDE.md ./CLAUDE.md

# 2. Pre-approve the tools (merge if you already have a settings.json)
mkdir -p .claude
cp /path/to/android-mcp/autorun/settings.json ./.claude/settings.json

# 3. Register the MCP server for this project (edit the path inside)
cp /path/to/android-mcp/.mcp.json.example ./.mcp.json
#   then open .mcp.json and set the absolute path to android-mcp
```

Alternatively, register the server once for ALL projects instead of step 3:

```bash
claude mcp add android-control --scope user -- \
  uv --directory /absolute/path/to/android-mcp run android-mcp
```

## How it behaves after this

When you ask Claude to build a feature, once it compiles it will, on its own:

1. `./gradlew assembleDebug`
2. `install_and_launch(apk_path=..., package="<applicationId>")`
3. read the app's first screen and confirm it launched and looks right
4. exercise the new feature with `tap_text_and_read` / `input_text` / `screen_text`
5. on a crash, read `logcat`, fix, and repeat

You'll see it drive your phone automatically. Destructive tools
(`uninstall`, `reboot`, `root_shell`, `call`) are deliberately left to prompt;
move them into `allow` in `settings.json` if you want those silent too.

## Important

- Edit the APK path / `applicationId` to match your app. The default debug APK
  path is usually `app/build/outputs/apk/debug/app-debug.apk`.
- Keep the phone **unlocked** (or give Claude the PIN so it can `unlock`).
- This makes Claude act autonomously on a real device you own — review the
  allowlist and only use it on a device and project you trust.
