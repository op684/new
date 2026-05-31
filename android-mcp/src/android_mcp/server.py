"""MCP server exposing full control of a rooted Android device over ADB.

Designed for a personal, rooted OnePlus 7 Pro (or any rooted Android device).
The server runs on a host machine with ``adb`` installed and the phone attached
over USB or wireless ADB. Tools fall into a few groups:

* Connection & info   – list devices, connect wirelessly, device properties
* Shell               – run arbitrary commands as the shell user or as root
* UI automation       – tap, swipe, type text, send key events, screenshots
* App management       – list / launch / stop / install / uninstall apps
* Files               – push, pull, read, write (root) files on the device
* Diagnostics & power  – logcat, reboot

Every privileged action ultimately routes through ``su`` so, on a rooted
device, the model has unrestricted access. Treat this server accordingly:
only expose it to clients you trust, and only point it at devices you own.
"""

from __future__ import annotations

import base64
import os
import shlex
from typing import Annotated

from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.utilities.types import Image
from pydantic import Field

from .adb import Adb, AdbError

mcp = FastMCP(
    "android-control",
    instructions=(
        "Full control of a rooted Android device (OnePlus 7 Pro) via ADB. "
        "Use `device_status` first to confirm a device is attached and rooted. "
        "Prefer `root_shell` for system-level changes; `shell` for ordinary "
        "commands. UI automation tools (tap/swipe/input_text/keyevent) operate "
        "in screen coordinates — capture a `screenshot` first to see the layout."
    ),
)

# A single shared adb instance; configuration is pulled from the environment.
adb = Adb()


# --------------------------------------------------------------------------- #
# Connection & info
# --------------------------------------------------------------------------- #
@mcp.tool()
def list_devices() -> str:
    """List all devices currently visible to adb (with model/product details)."""
    try:
        return adb.devices().text()
    except AdbError as exc:
        return f"Error: {exc}"


@mcp.tool()
def connect_wireless(
    host_port: Annotated[
        str, Field(description="Device address as host:port, e.g. 192.168.1.42:5555")
    ],
) -> str:
    """Connect to a device over wireless ADB (after `adb tcpip 5555` on USB)."""
    try:
        return adb.connect(host_port).text()
    except AdbError as exc:
        return f"Error: {exc}"


@mcp.tool()
def device_status() -> str:
    """Report whether a device is attached, its model, Android version, and root status."""
    try:
        devices = adb.devices()
        if "device" not in devices.stdout.replace("List of devices", ""):
            return "No device attached.\n\n" + devices.text()

        props = {
            "model": "ro.product.model",
            "device": "ro.product.device",
            "android": "ro.build.version.release",
            "sdk": "ro.build.version.sdk",
            "build": "ro.build.display.id",
        }
        lines = []
        for label, prop in props.items():
            val = adb.shell(f"getprop {prop}").stdout.strip()
            lines.append(f"{label:>8}: {val}")
        lines.append(f"{'root':>8}: {'yes (su grants uid 0)' if adb.has_root() else 'NOT available'}")
        return "\n".join(lines)
    except AdbError as exc:
        return f"Error: {exc}"


@mcp.tool()
def device_info(
    property_filter: Annotated[
        str, Field(description="Optional substring to filter getprop output, e.g. 'battery' or 'product'")
    ] = "",
) -> str:
    """Dump device system properties (`getprop`), optionally filtered by substring."""
    try:
        res = adb.shell("getprop")
        if not res.ok:
            return res.text()
        if property_filter:
            matched = [ln for ln in res.stdout.splitlines()
                       if property_filter.lower() in ln.lower()]
            return "\n".join(matched) or f"No properties matched '{property_filter}'."
        return res.stdout
    except AdbError as exc:
        return f"Error: {exc}"


# --------------------------------------------------------------------------- #
# Shell
# --------------------------------------------------------------------------- #
@mcp.tool()
def shell(
    command: Annotated[str, Field(description="Shell command to run on the device (non-root)")],
) -> str:
    """Run an arbitrary command in the device shell as the regular shell user."""
    try:
        return adb.shell(command).text()
    except AdbError as exc:
        return f"Error: {exc}"


@mcp.tool()
def root_shell(
    command: Annotated[str, Field(description="Shell command to run as root via su")],
) -> str:
    """Run an arbitrary command as root (uid 0) via `su -c`. Requires a rooted device."""
    try:
        return adb.root_shell(command).text()
    except AdbError as exc:
        return f"Error: {exc}"


# --------------------------------------------------------------------------- #
# UI automation
# --------------------------------------------------------------------------- #
@mcp.tool()
def screenshot() -> Image:
    """Capture the current screen and return it as a PNG image."""
    # screencap to stdout; -p emits PNG. Keep bytes intact.
    proc = adb.raw(["exec-out", "screencap", "-p"], binary=True)
    if proc.returncode != 0:
        raise AdbError((proc.stderr or b"").decode(errors="replace") or "screencap failed")
    return Image(data=proc.stdout, format="png")


@mcp.tool()
def tap(
    x: Annotated[int, Field(description="X coordinate in pixels")],
    y: Annotated[int, Field(description="Y coordinate in pixels")],
) -> str:
    """Tap the screen at the given pixel coordinates."""
    try:
        adb.shell(f"input tap {x} {y}")
        return f"Tapped ({x}, {y})."
    except AdbError as exc:
        return f"Error: {exc}"


@mcp.tool()
def swipe(
    x1: Annotated[int, Field(description="Start X")],
    y1: Annotated[int, Field(description="Start Y")],
    x2: Annotated[int, Field(description="End X")],
    y2: Annotated[int, Field(description="End Y")],
    duration_ms: Annotated[int, Field(description="Swipe duration in milliseconds")] = 300,
) -> str:
    """Swipe from one point to another over the given duration (use for scroll/drag)."""
    try:
        adb.shell(f"input swipe {x1} {y1} {x2} {y2} {duration_ms}")
        return f"Swiped ({x1},{y1}) -> ({x2},{y2}) in {duration_ms}ms."
    except AdbError as exc:
        return f"Error: {exc}"


@mcp.tool()
def input_text(
    text: Annotated[str, Field(description="Text to type into the focused field")],
) -> str:
    """Type text into the currently focused input field."""
    try:
        # `input text` treats spaces specially; escape them as %s.
        escaped = text.replace(" ", "%s")
        adb.shell(f"input text {shlex.quote(escaped)}")
        return f"Typed {len(text)} characters."
    except AdbError as exc:
        return f"Error: {exc}"


@mcp.tool()
def keyevent(
    key: Annotated[
        str,
        Field(description="Android keycode name or number, e.g. HOME, BACK, ENTER, 26 (power), 4"),
    ],
) -> str:
    """Send a key event. Common names: HOME, BACK, MENU, POWER, VOLUME_UP, ENTER, APP_SWITCH."""
    try:
        # Accept either bare names (auto-prefixed) or raw numbers/full names.
        token = key if key.isdigit() or key.startswith("KEYCODE_") else f"KEYCODE_{key.upper()}"
        adb.shell(f"input keyevent {token}")
        return f"Sent keyevent {token}."
    except AdbError as exc:
        return f"Error: {exc}"


# --------------------------------------------------------------------------- #
# App management
# --------------------------------------------------------------------------- #
@mcp.tool()
def list_packages(
    filter_text: Annotated[str, Field(description="Optional substring to filter package names")] = "",
    third_party_only: Annotated[bool, Field(description="Only list user-installed (non-system) apps")] = False,
) -> str:
    """List installed application package names."""
    try:
        cmd = "pm list packages"
        if third_party_only:
            cmd += " -3"
        res = adb.shell(cmd)
        if not res.ok:
            return res.text()
        names = sorted(ln.replace("package:", "").strip() for ln in res.stdout.splitlines() if ln.strip())
        if filter_text:
            names = [n for n in names if filter_text.lower() in n.lower()]
        return "\n".join(names) or "No matching packages."
    except AdbError as exc:
        return f"Error: {exc}"


@mcp.tool()
def start_app(
    package: Annotated[str, Field(description="Package name, e.g. com.android.settings")],
) -> str:
    """Launch an app by package name using its default launcher activity."""
    try:
        res = adb.shell(
            f"monkey -p {shlex.quote(package)} -c android.intent.category.LAUNCHER 1"
        )
        return res.text()
    except AdbError as exc:
        return f"Error: {exc}"


@mcp.tool()
def stop_app(
    package: Annotated[str, Field(description="Package name to force-stop")],
) -> str:
    """Force-stop a running app by package name."""
    try:
        adb.shell(f"am force-stop {shlex.quote(package)}")
        return f"Force-stopped {package}."
    except AdbError as exc:
        return f"Error: {exc}"


@mcp.tool()
def install_apk(
    apk_path: Annotated[str, Field(description="Path to an APK file on the host machine")],
    reinstall: Annotated[bool, Field(description="Keep data and reinstall (-r) if already installed")] = True,
) -> str:
    """Install an APK from the host machine onto the device."""
    if not os.path.isfile(apk_path):
        return f"Error: file not found on host: {apk_path}"
    try:
        args = ["install"]
        if reinstall:
            args.append("-r")
        args.append(apk_path)
        return adb.run(args, timeout=300).text()
    except AdbError as exc:
        return f"Error: {exc}"


@mcp.tool()
def uninstall(
    package: Annotated[str, Field(description="Package name to uninstall")],
    keep_data: Annotated[bool, Field(description="Keep the app's data and cache (-k)")] = False,
) -> str:
    """Uninstall an app by package name."""
    try:
        args = ["uninstall"]
        if keep_data:
            args.append("-k")
        args.append(package)
        return adb.run(args).text()
    except AdbError as exc:
        return f"Error: {exc}"


# --------------------------------------------------------------------------- #
# Files
# --------------------------------------------------------------------------- #
@mcp.tool()
def push_file(
    local_path: Annotated[str, Field(description="Path on the host machine")],
    remote_path: Annotated[str, Field(description="Destination path on the device")],
) -> str:
    """Copy a file from the host machine to the device."""
    if not os.path.exists(local_path):
        return f"Error: local path not found: {local_path}"
    try:
        return adb.run(["push", local_path, remote_path], timeout=300).text()
    except AdbError as exc:
        return f"Error: {exc}"


@mcp.tool()
def pull_file(
    remote_path: Annotated[str, Field(description="Path on the device")],
    local_path: Annotated[str, Field(description="Destination path on the host machine")],
) -> str:
    """Copy a file from the device to the host machine."""
    try:
        return adb.run(["pull", remote_path, local_path], timeout=300).text()
    except AdbError as exc:
        return f"Error: {exc}"


@mcp.tool()
def read_file(
    remote_path: Annotated[str, Field(description="Absolute path of a file on the device")],
    as_root: Annotated[bool, Field(description="Read with root privileges (for protected paths)")] = True,
) -> str:
    """Read a text file on the device. Uses root by default so protected paths work."""
    try:
        cmd = f"cat {shlex.quote(remote_path)}"
        res = adb.root_shell(cmd) if as_root else adb.shell(cmd)
        return res.text()
    except AdbError as exc:
        return f"Error: {exc}"


@mcp.tool()
def write_file(
    remote_path: Annotated[str, Field(description="Absolute path of the file to write on the device")],
    content: Annotated[str, Field(description="Text content to write (overwrites existing file)")],
    as_root: Annotated[bool, Field(description="Write with root privileges (for protected paths)")] = True,
) -> str:
    """Write text to a file on the device. Uses root by default for protected paths.

    Content is base64-encoded on the host and decoded on the device, so it
    survives arbitrary bytes, quotes, and newlines safely.
    """
    try:
        encoded = base64.b64encode(content.encode()).decode()
        # Decode in the device shell and redirect into the target path.
        inner = f"echo {encoded} | base64 -d > {shlex.quote(remote_path)}"
        res = adb.root_shell(inner) if as_root else adb.shell(inner)
        if res.ok and not res.stderr.strip():
            return f"Wrote {len(content)} bytes to {remote_path}."
        return res.text()
    except AdbError as exc:
        return f"Error: {exc}"


# --------------------------------------------------------------------------- #
# Diagnostics & power
# --------------------------------------------------------------------------- #
@mcp.tool()
def logcat(
    lines: Annotated[int, Field(description="Number of recent log lines to return")] = 200,
    filter_text: Annotated[str, Field(description="Optional substring/tag to grep for")] = "",
) -> str:
    """Return recent logcat output (a snapshot, not a live stream)."""
    try:
        # -d dumps and exits; -t N limits to the last N lines.
        res = adb.shell(f"logcat -d -t {int(lines)}")
        if not res.ok:
            return res.text()
        out = res.stdout
        if filter_text:
            out = "\n".join(ln for ln in out.splitlines() if filter_text.lower() in ln.lower())
        return out or "(no matching log lines)"
    except AdbError as exc:
        return f"Error: {exc}"


@mcp.tool()
def reboot(
    mode: Annotated[
        str,
        Field(description="Reboot target: '' (normal), 'recovery', 'bootloader', or 'fastboot'"),
    ] = "",
) -> str:
    """Reboot the device, optionally into recovery/bootloader/fastboot."""
    try:
        args = ["reboot"] + ([mode] if mode else [])
        adb.run(args, timeout=30)
        return f"Reboot requested ({mode or 'normal'})."
    except AdbError as exc:
        # A dropped connection on reboot is expected, not a real failure.
        return f"Reboot requested ({mode or 'normal'}). (adb link dropped: {exc})"


def main() -> None:
    """Console-script entry point: run the server over stdio."""
    mcp.run()


if __name__ == "__main__":
    main()
