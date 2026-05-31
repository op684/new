"""MCP server giving a model human-like control of a rooted Android device.

Runs on a host with ``adb`` installed; the phone (a rooted OnePlus 7 Pro) is
attached over USB or wireless ADB. The toolset is designed so the model can use
the phone *as if it were holding it*:

* See      – UI-tree readers (tap by name), screenshots, OCR fallback
* Watch    – act-and-read tools that wait for the screen to settle, then read it
* Touch    – tap, long-press, double-tap, swipe, drag, scroll, pinch/zoom
* Type     – text entry, clear, paste, type-and-enter
* Navigate – home/back/recents, notifications & quick-settings shades
* Screen   – wake/sleep, unlock (with PIN), rotate, brightness, screen size
* Apps     – list/launch/stop/install/uninstall, current foreground app
* Comms    – open URLs, dial/call, compose SMS, arbitrary intents
* System   – Wi-Fi/Bluetooth/airplane/mobile-data toggles, battery, clipboard
* Files    – push/pull, root read/write
* Capture  – screenshot, screen recording, logcat
* Shell    – arbitrary commands as the shell user or as root
* Power    – reboot

Everything privileged routes through ``su``. Only point this at a device you
own and only connect it to an MCP client you trust.
"""

from __future__ import annotations

import base64
import os
import re
import shlex
import time
from typing import Annotated

from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.utilities.types import Image
from pydantic import Field

from . import ocr, ui
from .adb import Adb, AdbError

mcp = FastMCP(
    "android-control",
    instructions=(
        "Human-like control of a rooted Android device (OnePlus 7 Pro) via ADB. "
        "Workflow: call `device_status` once to confirm the phone is attached, "
        "rooted, and awake (use `wake`/`unlock` if not). To interact with the "
        "UI, prefer `screen_elements`/`screen_text` to SEE what's on screen, "
        "then act with `tap_text`/`tap_id` (tap by name, not pixels). Use "
        "`tap_text_and_read`/`tap_and_read` to act and automatically read the "
        "resulting screen in one step, and `wait_for_change` after a delayed "
        "action. If the readers come back empty (canvas/secure screens), fall "
        "back to `ocr_screen`/`ocr_tap`. Use `shell`/`root_shell` for anything "
        "not covered by a dedicated tool."
    ),
)

# A single shared adb instance; configuration is pulled from the environment.
adb = Adb()


# --------------------------------------------------------------------------- #
# Internal helpers
# --------------------------------------------------------------------------- #
def _err(exc: Exception) -> str:
    return f"Error: {exc}"


def _screen_size() -> tuple[int, int]:
    """Return (width, height) in pixels, honoring any override size."""
    out = adb.shell("wm size").stdout
    override = re.search(r"Override size:\s*(\d+)x(\d+)", out)
    physical = re.search(r"Physical size:\s*(\d+)x(\d+)", out)
    m = override or physical
    if m:
        return int(m.group(1)), int(m.group(2))
    return 1080, 2340  # sane OnePlus-ish fallback


def _dump_ui_xml() -> tuple[str, str]:
    """Dump the current UI hierarchy as raw XML. Returns (xml, error)."""
    adb.shell("uiautomator dump /sdcard/window_dump.xml", timeout=30)
    xml = adb.shell("cat /sdcard/window_dump.xml")
    if "<hierarchy" not in xml.stdout:
        return "", xml.text() or "Could not dump UI hierarchy."
    return xml.stdout, ""


def _get_elements() -> tuple[list[ui.Element], str]:
    """Dump and parse the current UI hierarchy. Returns (elements, error)."""
    xml, err = _dump_ui_xml()
    if err:
        return [], err
    return ui.parse_hierarchy(xml), ""


def _tap(x: int, y: int) -> None:
    adb.shell(f"input tap {x} {y}")


# --------------------------------------------------------------------------- #
# Connection & device info
# --------------------------------------------------------------------------- #
@mcp.tool()
def list_devices() -> str:
    """List all devices currently visible to adb (with model/product details)."""
    try:
        return adb.devices().text()
    except AdbError as exc:
        return _err(exc)


@mcp.tool()
def connect_wireless(
    host_port: Annotated[str, Field(description="Device address host:port, e.g. 192.168.1.42:5555")],
) -> str:
    """Connect to a device over wireless ADB (after `adb tcpip 5555` on USB)."""
    try:
        return adb.connect(host_port).text()
    except AdbError as exc:
        return _err(exc)


@mcp.tool()
def device_status() -> str:
    """Report device presence, model, Android version, root status, and screen state."""
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
        lines = [f"{k:>9}: {adb.shell(f'getprop {v}').stdout.strip()}" for k, v in props.items()]
        w, h = _screen_size()
        lines.append(f"{'screen':>9}: {w}x{h}")
        awake = "Awake" in adb.shell("dumpsys power").stdout or "state=ON" in adb.shell("dumpsys power").stdout
        lines.append(f"{'screen on':>9}: {'yes' if awake else 'no'}")
        lines.append(f"{'root':>9}: {'yes (su grants uid 0)' if adb.has_root() else 'NOT available'}")
        return "\n".join(lines)
    except AdbError as exc:
        return _err(exc)


@mcp.tool()
def device_info(
    property_filter: Annotated[str, Field(description="Optional substring filter for getprop, e.g. 'battery'")] = "",
) -> str:
    """Dump device system properties (`getprop`), optionally filtered by substring."""
    try:
        res = adb.shell("getprop")
        if not res.ok:
            return res.text()
        if property_filter:
            matched = [ln for ln in res.stdout.splitlines() if property_filter.lower() in ln.lower()]
            return "\n".join(matched) or f"No properties matched '{property_filter}'."
        return res.stdout
    except AdbError as exc:
        return _err(exc)


@mcp.tool()
def get_screen_size() -> str:
    """Return the screen resolution and density (pixels)."""
    try:
        w, h = _screen_size()
        density = adb.shell("wm density").stdout.strip()
        return f"{w}x{h}\n{density}"
    except AdbError as exc:
        return _err(exc)


# --------------------------------------------------------------------------- #
# Seeing the screen
# --------------------------------------------------------------------------- #
def _screencap_png() -> bytes:
    """Grab the current screen as raw PNG bytes."""
    proc = adb.raw(["exec-out", "screencap", "-p"], binary=True)
    if proc.returncode != 0:
        raise AdbError((proc.stderr or b"").decode(errors="replace") or "screencap failed")
    return proc.stdout


@mcp.tool()
def screenshot() -> Image:
    """Capture the current screen as a PNG image (look at the phone with your eyes)."""
    return Image(data=_screencap_png(), format="png")


@mcp.tool()
def ocr_status() -> str:
    """Check whether OCR is available (Python deps + the tesseract engine)."""
    ok, detail = ocr.available()
    return f"OCR available: {detail}" if ok else f"OCR NOT available — {detail}"


@mcp.tool()
def ocr_screen(
    min_confidence: Annotated[float, Field(description="Drop words below this OCR confidence (0–100)")] = 40.0,
    with_coords: Annotated[bool, Field(description="Also list each word with its tap coordinates")] = False,
) -> str:
    """Read on-screen text by OCR'ing a screenshot — the last-resort reader.

    Use this when `screen_text`/`screen_elements` come back empty or sparse,
    which happens on canvas/game-engine UIs, some Flutter views, DRM video, and
    FLAG_SECURE screens that hide themselves from the accessibility tree. OCR
    works on raw pixels, so it sees what the eye sees. With `with_coords`, each
    word is listed with a centre point you can pass to `tap`.
    """
    ok, detail = ocr.available()
    if not ok:
        return f"OCR not available — {detail}"
    try:
        png = _screencap_png()
    except AdbError as exc:
        return _err(exc)
    try:
        words = ocr.recognize_words(png, min_confidence=min_confidence)
    except RuntimeError as exc:
        return f"OCR error: {exc}"
    if not words:
        return "OCR found no text on screen."
    lines = ocr.group_lines(words)
    out = "\n".join(lines)
    if with_coords:
        coord_lines = [f"  {w.text!r} @ ({w.center[0]},{w.center[1]}) conf={w.confidence:.0f}" for w in words]
        out += "\n\n[words with coordinates]\n" + "\n".join(coord_lines)
    return out


@mcp.tool()
def ocr_tap(
    text: Annotated[str, Field(description="Visible word/phrase to find via OCR and tap")],
) -> str:
    """OCR the screen, find a word/phrase by its pixels, and tap it.

    The fallback to `tap_text` for screens the accessibility tree can't read.
    Matches the first OCR'd word containing `text` (case-insensitive); for a
    multi-word phrase, matches the first word of the phrase.
    """
    ok, detail = ocr.available()
    if not ok:
        return f"OCR not available — {detail}"
    try:
        png = _screencap_png()
    except AdbError as exc:
        return _err(exc)
    try:
        words = ocr.recognize_words(png)
    except RuntimeError as exc:
        return f"OCR error: {exc}"
    needle = text.strip().lower()
    first = needle.split()[0] if needle.split() else needle
    match = next((w for w in words if needle in w.text.lower() or first in w.text.lower()), None)
    if not match:
        return f"OCR could not find {text!r} on screen."
    cx, cy = match.center
    try:
        _tap(cx, cy)
    except AdbError as exc:
        return _err(exc)
    return f"OCR-tapped {match.text!r} @ ({cx},{cy})."


@mcp.tool()
def screen_elements(
    interactive_only: Annotated[bool, Field(description="Only show tappable/text-bearing elements")] = True,
    limit: Annotated[int, Field(description="Max elements to return")] = 80,
) -> str:
    """Read the on-screen UI as a numbered list of elements with tap coordinates.

    This is how you "see" buttons, fields, and labels. Each line shows the
    element's text/description/id, its centre (x,y), and flags. Tap by name
    with `tap_text`/`tap_id`, or use the coordinates with `tap`.
    """
    try:
        elements, err = _get_elements()
        if err:
            return err
        return _format_screen(elements, interactive_only=interactive_only, limit=limit)
    except AdbError as exc:
        return _err(exc)


@mcp.tool()
def find_on_screen(
    query: Annotated[str, Field(description="Text, content-description, or resource-id substring to search for")],
) -> str:
    """Find on-screen elements matching a query and report their tap coordinates."""
    try:
        elements, err = _get_elements()
        if err:
            return err
        matches = ui.find(elements, query)
        if not matches:
            return f"Nothing on screen matches '{query}'."
        return "\n".join(e.describe(i) for i, e in enumerate(matches))
    except AdbError as exc:
        return _err(exc)


@mcp.tool()
def screen_text() -> str:
    """Read ALL readable text currently on screen, in order — no screenshot needed.

    Pulls the visible text and content-descriptions straight from the
    accessibility/UI tree, so you "read" the phone as plain text instead of
    looking at pixels. Use this to understand what an app is showing.
    """
    try:
        elements, err = _get_elements()
        if err:
            return err
        lines = ui.extract_text(elements)
        return "\n".join(lines) or "No readable text on screen."
    except AdbError as exc:
        return _err(exc)


@mcp.tool()
def ui_tree(
    compact: Annotated[bool, Field(description="Collapse structural-only containers for readability")] = True,
    limit: Annotated[int, Field(description="Max lines to return")] = 400,
) -> str:
    """Read the screen as an indented hierarchy: structure + text + tap coords.

    This is the richest text-only view of the screen — it shows how elements
    nest (lists, rows, cards) along with each element's text/id and centre
    coordinates. Use it when flat `screen_elements` doesn't make the layout
    clear. No screenshot is taken.
    """
    try:
        xml, err = _dump_ui_xml()
        if err:
            return err
        tops = ui.parse_tree(xml)
        lines = ui.render_outline(tops, compact=compact)
        if not lines:
            return "No elements found on screen."
        shown = lines[:limit]
        more = f"\n… and {len(lines) - len(shown)} more lines (raise `limit`)." if len(lines) > limit else ""
        return "\n".join(shown) + more
    except AdbError as exc:
        return _err(exc)


@mcp.tool()
def current_app() -> str:
    """Report the package/activity of the app currently in the foreground."""
    try:
        out = adb.shell(
            "dumpsys activity activities | grep -E 'mResumedActivity|topResumedActivity'"
        ).stdout.strip()
        if not out:
            out = adb.shell("dumpsys window | grep -E 'mCurrentFocus|mFocusedApp'").stdout.strip()
        return out or "Could not determine the foreground app."
    except AdbError as exc:
        return _err(exc)


# --------------------------------------------------------------------------- #
# Touch — taps & gestures
# --------------------------------------------------------------------------- #
@mcp.tool()
def tap(x: Annotated[int, Field(description="X pixel")], y: Annotated[int, Field(description="Y pixel")]) -> str:
    """Tap the screen at exact pixel coordinates."""
    try:
        _tap(x, y)
        return f"Tapped ({x}, {y})."
    except AdbError as exc:
        return _err(exc)


@mcp.tool()
def tap_text(
    text: Annotated[str, Field(description="Visible text or content-description of the element to tap")],
    exact: Annotated[bool, Field(description="Require an exact match instead of substring")] = False,
) -> str:
    """Find an element by its visible text/description and tap its centre."""
    try:
        elements, err = _get_elements()
        if err:
            return err
        matches = ui.find(elements, text, exact=exact, clickable_only=True)
        if not matches:
            return f"No element matching '{text}'. Call `screen_elements` to see what's available."
        target = matches[0]
        cx, cy = target.center
        _tap(cx, cy)
        extra = f" ({len(matches)} matched; tapped first)" if len(matches) > 1 else ""
        return f"Tapped {target.label!r} @ ({cx},{cy}).{extra}"
    except AdbError as exc:
        return _err(exc)


@mcp.tool()
def tap_id(
    resource_id: Annotated[str, Field(description="Resource-id (or substring), e.g. com.app:id/login_button")],
) -> str:
    """Find an element by resource-id and tap its centre."""
    try:
        elements, err = _get_elements()
        if err:
            return err
        matches = ui.find_by_id(elements, resource_id)
        if not matches:
            return f"No element with id matching '{resource_id}'."
        cx, cy = matches[0].center
        _tap(cx, cy)
        return f"Tapped id={matches[0].resource_id} @ ({cx},{cy})."
    except AdbError as exc:
        return _err(exc)


@mcp.tool()
def long_press(
    x: Annotated[int, Field(description="X pixel")],
    y: Annotated[int, Field(description="Y pixel")],
    duration_ms: Annotated[int, Field(description="Hold duration in milliseconds")] = 800,
) -> str:
    """Press and hold at a point (e.g. to open a context menu)."""
    try:
        adb.shell(f"input swipe {x} {y} {x} {y} {duration_ms}")
        return f"Long-pressed ({x},{y}) for {duration_ms}ms."
    except AdbError as exc:
        return _err(exc)


@mcp.tool()
def double_tap(
    x: Annotated[int, Field(description="X pixel")],
    y: Annotated[int, Field(description="Y pixel")],
) -> str:
    """Double-tap at a point (e.g. to zoom)."""
    try:
        adb.shell(f"input tap {x} {y}; input tap {x} {y}")
        return f"Double-tapped ({x},{y})."
    except AdbError as exc:
        return _err(exc)


@mcp.tool()
def swipe(
    x1: Annotated[int, Field(description="Start X")],
    y1: Annotated[int, Field(description="Start Y")],
    x2: Annotated[int, Field(description="End X")],
    y2: Annotated[int, Field(description="End Y")],
    duration_ms: Annotated[int, Field(description="Swipe duration in milliseconds")] = 300,
) -> str:
    """Swipe/drag from one point to another over the given duration."""
    try:
        adb.shell(f"input swipe {x1} {y1} {x2} {y2} {duration_ms}")
        return f"Swiped ({x1},{y1}) -> ({x2},{y2}) in {duration_ms}ms."
    except AdbError as exc:
        return _err(exc)


@mcp.tool()
def scroll(
    direction: Annotated[str, Field(description="up, down, left, or right")],
    amount: Annotated[float, Field(description="Fraction of the screen to scroll, 0.1–0.9")] = 0.6,
) -> str:
    """Scroll the screen in a direction (content moves opposite to a finger swipe)."""
    try:
        w, h = _screen_size()
        cx, cy = w // 2, h // 2
        frac = max(0.1, min(0.9, amount))
        dx, dy = int(w * frac / 2), int(h * frac / 2)
        d = direction.lower()
        # To scroll "down" (reveal lower content), the finger swipes up.
        moves = {
            "down": (cx, cy + dy, cx, cy - dy),
            "up": (cx, cy - dy, cx, cy + dy),
            "left": (cx + dx, cy, cx - dx, cy),
            "right": (cx - dx, cy, cx + dx, cy),
        }
        if d not in moves:
            return "direction must be one of: up, down, left, right"
        x1, y1, x2, y2 = moves[d]
        adb.shell(f"input swipe {x1} {y1} {x2} {y2} 300")
        return f"Scrolled {d}."
    except AdbError as exc:
        return _err(exc)


@mcp.tool()
def pinch(
    direction: Annotated[str, Field(description="'in' to zoom out, 'out' to zoom in")],
    x: Annotated[int, Field(description="Centre X (default: screen centre)")] = -1,
    y: Annotated[int, Field(description="Centre Y (default: screen centre)")] = -1,
) -> str:
    """Two-finger pinch to zoom. 'out' zooms in, 'in' zooms out.

    Approximated with two simultaneous vertical swipes around the centre point.
    """
    try:
        w, h = _screen_size()
        cx = x if x >= 0 else w // 2
        cy = y if y >= 0 else h // 2
        near, far = 80, 360
        if direction.lower() == "out":  # zoom in: fingers move apart
            top = (cx, cy - near, cx, cy - far)
            bot = (cx, cy + near, cx, cy + far)
        elif direction.lower() == "in":  # zoom out: fingers move together
            top = (cx, cy - far, cx, cy - near)
            bot = (cx, cy + far, cx, cy + near)
        else:
            return "direction must be 'in' or 'out'"
        cmd = (
            f"input swipe {top[0]} {top[1]} {top[2]} {top[3]} 300 & "
            f"input swipe {bot[0]} {bot[1]} {bot[2]} {bot[3]} 300 & wait"
        )
        adb.shell(cmd)
        return f"Pinched {direction} around ({cx},{cy})."
    except AdbError as exc:
        return _err(exc)


# --------------------------------------------------------------------------- #
# Typing
# --------------------------------------------------------------------------- #
@mcp.tool()
def input_text(
    text: Annotated[str, Field(description="Text to type into the focused field")],
) -> str:
    """Type text into the currently focused input field."""
    try:
        escaped = text.replace(" ", "%s")
        adb.shell(f"input text {shlex.quote(escaped)}")
        return f"Typed {len(text)} characters."
    except AdbError as exc:
        return _err(exc)


@mcp.tool()
def type_and_enter(
    text: Annotated[str, Field(description="Text to type, followed by the Enter key")],
) -> str:
    """Type text into the focused field and press Enter (e.g. submit a search)."""
    try:
        escaped = text.replace(" ", "%s")
        adb.shell(f"input text {shlex.quote(escaped)}; input keyevent KEYCODE_ENTER")
        return f"Typed {len(text)} characters and pressed Enter."
    except AdbError as exc:
        return _err(exc)


@mcp.tool()
def clear_text() -> str:
    """Clear the currently focused text field (select-all then delete)."""
    try:
        # Move to end, select all, delete.
        adb.shell("input keyevent KEYCODE_MOVE_END")
        adb.shell("input keyevent --longpress $(seq -s ' ' 0 80 | sed 's/[0-9]*/KEYCODE_DEL/g')")
        return "Cleared focused field."
    except AdbError as exc:
        return _err(exc)


@mcp.tool()
def paste() -> str:
    """Paste clipboard contents into the focused field."""
    try:
        adb.shell("input keyevent KEYCODE_PASTE")
        return "Pasted."
    except AdbError as exc:
        return _err(exc)


@mcp.tool()
def keyevent(
    key: Annotated[str, Field(description="Keycode name or number, e.g. ENTER, TAB, DEL, 26, SEARCH")],
) -> str:
    """Send an arbitrary key event by name or number."""
    try:
        token = key if key.isdigit() or key.startswith("KEYCODE_") else f"KEYCODE_{key.upper()}"
        adb.shell(f"input keyevent {token}")
        return f"Sent keyevent {token}."
    except AdbError as exc:
        return _err(exc)


# --------------------------------------------------------------------------- #
# Navigation shortcuts
# --------------------------------------------------------------------------- #
def _key(name: str) -> str:
    adb.shell(f"input keyevent KEYCODE_{name}")
    return f"Pressed {name}."


@mcp.tool()
def home() -> str:
    """Press the Home button."""
    try:
        return _key("HOME")
    except AdbError as exc:
        return _err(exc)


@mcp.tool()
def back() -> str:
    """Press the Back button."""
    try:
        return _key("BACK")
    except AdbError as exc:
        return _err(exc)


@mcp.tool()
def recents() -> str:
    """Open the recent-apps / app-switcher view."""
    try:
        return _key("APP_SWITCH")
    except AdbError as exc:
        return _err(exc)


@mcp.tool()
def open_notifications() -> str:
    """Pull down the notification shade."""
    try:
        adb.shell("cmd statusbar expand-notifications")
        return "Opened notification shade."
    except AdbError as exc:
        return _err(exc)


@mcp.tool()
def open_quick_settings() -> str:
    """Pull down the quick-settings panel."""
    try:
        adb.shell("cmd statusbar expand-settings")
        return "Opened quick settings."
    except AdbError as exc:
        return _err(exc)


@mcp.tool()
def close_panels() -> str:
    """Collapse any open notification/quick-settings panels and dialogs."""
    try:
        adb.shell("cmd statusbar collapse")
        adb.shell("am broadcast -a android.intent.action.CLOSE_SYSTEM_DIALOGS")
        return "Collapsed panels."
    except AdbError as exc:
        return _err(exc)


# --------------------------------------------------------------------------- #
# Screen power, lock, rotation, brightness
# --------------------------------------------------------------------------- #
@mcp.tool()
def wake() -> str:
    """Wake the screen (turn the display on)."""
    try:
        adb.shell("input keyevent KEYCODE_WAKEUP")
        return "Woke the screen."
    except AdbError as exc:
        return _err(exc)


@mcp.tool()
def sleep_screen() -> str:
    """Turn the display off (sleep)."""
    try:
        adb.shell("input keyevent KEYCODE_SLEEP")
        return "Put the screen to sleep."
    except AdbError as exc:
        return _err(exc)


@mcp.tool()
def is_screen_on() -> str:
    """Report whether the display is currently on."""
    try:
        out = adb.shell("dumpsys power").stdout
        on = "Awake" in out or "mWakefulness=Awake" in out or "state=ON" in out
        return "Screen is ON." if on else "Screen is OFF."
    except AdbError as exc:
        return _err(exc)


@mcp.tool()
def unlock(
    pin: Annotated[str, Field(description="PIN/password to enter, if the device is secured (optional)")] = "",
) -> str:
    """Wake the device, swipe up to dismiss the lockscreen, and enter a PIN if given."""
    try:
        w, h = _screen_size()
        adb.shell("input keyevent KEYCODE_WAKEUP")
        time.sleep(0.4)
        adb.shell(f"input swipe {w // 2} {int(h * 0.8)} {w // 2} {int(h * 0.2)} 200")
        time.sleep(0.4)
        if pin:
            escaped = pin.replace(" ", "%s")
            adb.shell(f"input text {shlex.quote(escaped)}")
            adb.shell("input keyevent KEYCODE_ENTER")
            return "Woke, swiped up, and entered PIN."
        return "Woke and swiped up to unlock."
    except AdbError as exc:
        return _err(exc)


@mcp.tool()
def rotate(
    orientation: Annotated[str, Field(description="portrait, landscape, reverse-portrait, reverse-landscape, or 0/90/180/270")],
) -> str:
    """Force screen rotation (disables auto-rotate and sets a fixed orientation)."""
    try:
        mapping = {
            "portrait": 0, "0": 0,
            "landscape": 1, "90": 1,
            "reverse-portrait": 2, "180": 2,
            "reverse-landscape": 3, "270": 3,
        }
        val = mapping.get(orientation.lower())
        if val is None:
            return "orientation must be portrait/landscape/reverse-portrait/reverse-landscape or 0/90/180/270"
        adb.shell("settings put system accelerometer_rotation 0")
        adb.shell(f"settings put system user_rotation {val}")
        return f"Set orientation to {orientation}."
    except AdbError as exc:
        return _err(exc)


@mcp.tool()
def set_brightness(
    level: Annotated[int, Field(description="Brightness 0–255")],
) -> str:
    """Set screen brightness (switches to manual brightness mode)."""
    try:
        lvl = max(0, min(255, level))
        adb.shell("settings put system screen_brightness_mode 0")
        adb.shell(f"settings put system screen_brightness {lvl}")
        return f"Set brightness to {lvl}/255."
    except AdbError as exc:
        return _err(exc)


# --------------------------------------------------------------------------- #
# Volume
# --------------------------------------------------------------------------- #
@mcp.tool()
def volume(
    action: Annotated[str, Field(description="up, down, or mute")],
) -> str:
    """Adjust media volume (up/down) or toggle mute."""
    try:
        keys = {"up": "VOLUME_UP", "down": "VOLUME_DOWN", "mute": "VOLUME_MUTE"}
        key = keys.get(action.lower())
        if not key:
            return "action must be up, down, or mute"
        adb.shell(f"input keyevent KEYCODE_{key}")
        return f"Volume {action}."
    except AdbError as exc:
        return _err(exc)


# --------------------------------------------------------------------------- #
# Apps
# --------------------------------------------------------------------------- #
@mcp.tool()
def list_packages(
    filter_text: Annotated[str, Field(description="Optional substring filter for package names")] = "",
    third_party_only: Annotated[bool, Field(description="Only user-installed (non-system) apps")] = False,
) -> str:
    """List installed application package names."""
    try:
        cmd = "pm list packages" + (" -3" if third_party_only else "")
        res = adb.shell(cmd)
        if not res.ok:
            return res.text()
        names = sorted(ln.replace("package:", "").strip() for ln in res.stdout.splitlines() if ln.strip())
        if filter_text:
            names = [n for n in names if filter_text.lower() in n.lower()]
        return "\n".join(names) or "No matching packages."
    except AdbError as exc:
        return _err(exc)


@mcp.tool()
def start_app(
    package: Annotated[str, Field(description="Package name, e.g. com.android.settings")],
) -> str:
    """Launch an app by package name via its default launcher activity."""
    try:
        return adb.shell(
            f"monkey -p {shlex.quote(package)} -c android.intent.category.LAUNCHER 1"
        ).text()
    except AdbError as exc:
        return _err(exc)


@mcp.tool()
def stop_app(
    package: Annotated[str, Field(description="Package name to force-stop")],
) -> str:
    """Force-stop a running app by package name."""
    try:
        adb.shell(f"am force-stop {shlex.quote(package)}")
        return f"Force-stopped {package}."
    except AdbError as exc:
        return _err(exc)


@mcp.tool()
def open_app_settings(
    package: Annotated[str, Field(description="Package whose App Info screen to open")],
) -> str:
    """Open the system App-Info screen for a package."""
    try:
        adb.shell(
            f"am start -a android.settings.APPLICATION_DETAILS_SETTINGS -d package:{shlex.quote(package)}"
        )
        return f"Opened App Info for {package}."
    except AdbError as exc:
        return _err(exc)


@mcp.tool()
def install_apk(
    apk_path: Annotated[str, Field(description="Path to an APK file on the host machine")],
    reinstall: Annotated[bool, Field(description="Keep data and reinstall (-r) if already installed")] = True,
) -> str:
    """Install an APK from the host machine onto the device."""
    if not os.path.isfile(apk_path):
        return f"Error: file not found on host: {apk_path}"
    try:
        args = ["install"] + (["-r"] if reinstall else []) + [apk_path]
        return adb.run(args, timeout=300).text()
    except AdbError as exc:
        return _err(exc)


@mcp.tool()
def uninstall(
    package: Annotated[str, Field(description="Package name to uninstall")],
    keep_data: Annotated[bool, Field(description="Keep the app's data and cache (-k)")] = False,
) -> str:
    """Uninstall an app by package name."""
    try:
        args = ["uninstall"] + (["-k"] if keep_data else []) + [package]
        return adb.run(args).text()
    except AdbError as exc:
        return _err(exc)


# --------------------------------------------------------------------------- #
# Communication & intents
# --------------------------------------------------------------------------- #
@mcp.tool()
def open_url(
    url: Annotated[str, Field(description="URL to open in the default browser, e.g. https://example.com")],
) -> str:
    """Open a URL in the default browser."""
    try:
        return adb.shell(
            f"am start -a android.intent.action.VIEW -d {shlex.quote(url)}"
        ).text()
    except AdbError as exc:
        return _err(exc)


@mcp.tool()
def dial(
    number: Annotated[str, Field(description="Phone number to load into the dialer")],
) -> str:
    """Open the dialer pre-filled with a number (does not place the call)."""
    try:
        return adb.shell(f"am start -a android.intent.action.DIAL -d tel:{shlex.quote(number)}").text()
    except AdbError as exc:
        return _err(exc)


@mcp.tool()
def call(
    number: Annotated[str, Field(description="Phone number to call immediately")],
) -> str:
    """Place a phone call to a number (requires CALL permission; uses root)."""
    try:
        return adb.root_shell(f"am start -a android.intent.action.CALL -d tel:{shlex.quote(number)}").text()
    except AdbError as exc:
        return _err(exc)


@mcp.tool()
def compose_sms(
    number: Annotated[str, Field(description="Recipient phone number")],
    message: Annotated[str, Field(description="Message body to pre-fill")],
) -> str:
    """Open the SMS app composing a message (you still tap Send)."""
    try:
        return adb.shell(
            f"am start -a android.intent.action.SENDTO -d sms:{shlex.quote(number)} "
            f"--es sms_body {shlex.quote(message)} --ez exit_on_sent true"
        ).text()
    except AdbError as exc:
        return _err(exc)


@mcp.tool()
def start_intent(
    action: Annotated[str, Field(description="Intent action, e.g. android.intent.action.VIEW")] = "",
    data: Annotated[str, Field(description="Data URI, e.g. geo:0,0?q=coffee")] = "",
    component: Annotated[str, Field(description="Explicit component pkg/.Activity (optional)")] = "",
    extras: Annotated[str, Field(description="Extra am args, e.g. \"--es key value\"")] = "",
) -> str:
    """Fire an arbitrary intent with `am start` (advanced)."""
    try:
        cmd = "am start"
        if action:
            cmd += f" -a {shlex.quote(action)}"
        if data:
            cmd += f" -d {shlex.quote(data)}"
        if component:
            cmd += f" -n {shlex.quote(component)}"
        if extras:
            cmd += f" {extras}"
        return adb.shell(cmd).text()
    except AdbError as exc:
        return _err(exc)


# --------------------------------------------------------------------------- #
# Connectivity toggles (root)
# --------------------------------------------------------------------------- #
def _svc(domain: str, on: bool) -> str:
    state = "enable" if on else "disable"
    res = adb.root_shell(f"svc {domain} {state}")
    return f"{domain} {state}d." if res.ok else res.text()


@mcp.tool()
def toggle_wifi(on: Annotated[bool, Field(description="True to enable Wi-Fi, False to disable")]) -> str:
    """Turn Wi-Fi on or off (root)."""
    try:
        return _svc("wifi", on)
    except AdbError as exc:
        return _err(exc)


@mcp.tool()
def toggle_bluetooth(on: Annotated[bool, Field(description="True to enable Bluetooth, False to disable")]) -> str:
    """Turn Bluetooth on or off (root)."""
    try:
        return _svc("bluetooth", on)
    except AdbError as exc:
        return _err(exc)


@mcp.tool()
def toggle_mobile_data(on: Annotated[bool, Field(description="True to enable mobile data, False to disable")]) -> str:
    """Turn mobile data on or off (root)."""
    try:
        return _svc("data", on)
    except AdbError as exc:
        return _err(exc)


@mcp.tool()
def toggle_airplane(on: Annotated[bool, Field(description="True to enable airplane mode, False to disable")]) -> str:
    """Turn airplane mode on or off (root)."""
    try:
        val = 1 if on else 0
        adb.root_shell(f"settings put global airplane_mode_on {val}")
        adb.root_shell(
            f"am broadcast -a android.intent.action.AIRPLANE_MODE --ez state {'true' if on else 'false'}"
        )
        return f"Airplane mode {'on' if on else 'off'}."
    except AdbError as exc:
        return _err(exc)


# --------------------------------------------------------------------------- #
# System status: battery, notifications, clipboard
# --------------------------------------------------------------------------- #
@mcp.tool()
def get_battery() -> str:
    """Report battery level, charging state, temperature, and health."""
    try:
        out = adb.shell("dumpsys battery").stdout
        keep = ("level", "scale", "status", "health", "plugged", "temperature", "voltage")
        lines = [ln.strip() for ln in out.splitlines() if any(k in ln for k in keep)]
        return "\n".join(lines) or out
    except AdbError as exc:
        return _err(exc)


@mcp.tool()
def notifications() -> str:
    """List a summary of the currently active notifications."""
    try:
        out = adb.shell("dumpsys notification --noredact").stdout
        if not out.strip():
            out = adb.shell("dumpsys notification").stdout
        lines = []
        for ln in out.splitlines():
            s = ln.strip()
            if s.startswith("pkg=") or "android.title=" in s or "android.text=" in s or "tickerText=" in s:
                lines.append(s)
        return "\n".join(lines[:200]) or "No active notifications found."
    except AdbError as exc:
        return _err(exc)


@mcp.tool()
def clipboard_get() -> str:
    """Read the device clipboard text (best-effort; needs Android 12+)."""
    try:
        return adb.shell("cmd clipboard get-text").text()
    except AdbError as exc:
        return _err(exc)


@mcp.tool()
def clipboard_set(
    text: Annotated[str, Field(description="Text to place on the device clipboard")],
) -> str:
    """Set the device clipboard text (best-effort; needs Android 12+)."""
    try:
        res = adb.shell(f"cmd clipboard set-text {shlex.quote(text)}")
        return "Clipboard set." if res.ok else res.text()
    except AdbError as exc:
        return _err(exc)


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
        return _err(exc)


@mcp.tool()
def pull_file(
    remote_path: Annotated[str, Field(description="Path on the device")],
    local_path: Annotated[str, Field(description="Destination path on the host machine")],
) -> str:
    """Copy a file from the device to the host machine."""
    try:
        return adb.run(["pull", remote_path, local_path], timeout=300).text()
    except AdbError as exc:
        return _err(exc)


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
        return _err(exc)


@mcp.tool()
def write_file(
    remote_path: Annotated[str, Field(description="Absolute path of the file to write on the device")],
    content: Annotated[str, Field(description="Text content to write (overwrites existing file)")],
    as_root: Annotated[bool, Field(description="Write with root privileges (for protected paths)")] = True,
) -> str:
    """Write text to a file on the device (base64-safe). Uses root by default."""
    try:
        encoded = base64.b64encode(content.encode()).decode()
        inner = f"echo {encoded} | base64 -d > {shlex.quote(remote_path)}"
        res = adb.root_shell(inner) if as_root else adb.shell(inner)
        if res.ok and not res.stderr.strip():
            return f"Wrote {len(content)} bytes to {remote_path}."
        return res.text()
    except AdbError as exc:
        return _err(exc)


# --------------------------------------------------------------------------- #
# Capture: screen recording, logs
# --------------------------------------------------------------------------- #
@mcp.tool()
def screen_record(
    seconds: Annotated[int, Field(description="Recording length in seconds (max 180)")] = 10,
    local_path: Annotated[str, Field(description="Where to save the .mp4 on the host machine")] = "screenrecord.mp4",
) -> str:
    """Record the screen for N seconds and pull the video to the host machine."""
    try:
        secs = max(1, min(180, seconds))
        remote = "/sdcard/_mcp_screenrecord.mp4"
        adb.shell(f"screenrecord --time-limit {secs} {remote}", timeout=secs + 30)
        pull = adb.run(["pull", remote, local_path], timeout=120)
        adb.shell(f"rm -f {remote}")
        return f"Recorded {secs}s.\n{pull.text()}"
    except AdbError as exc:
        return _err(exc)


@mcp.tool()
def logcat(
    lines: Annotated[int, Field(description="Number of recent log lines to return")] = 200,
    filter_text: Annotated[str, Field(description="Optional substring/tag to grep for")] = "",
) -> str:
    """Return recent logcat output (a snapshot, not a live stream)."""
    try:
        res = adb.shell(f"logcat -d -t {int(lines)}")
        if not res.ok:
            return res.text()
        out = res.stdout
        if filter_text:
            out = "\n".join(ln for ln in out.splitlines() if filter_text.lower() in ln.lower())
        return out or "(no matching log lines)"
    except AdbError as exc:
        return _err(exc)


# --------------------------------------------------------------------------- #
# Shell & power
# --------------------------------------------------------------------------- #
@mcp.tool()
def shell(
    command: Annotated[str, Field(description="Shell command to run on the device (non-root)")],
) -> str:
    """Run an arbitrary command in the device shell as the regular shell user."""
    try:
        return adb.shell(command).text()
    except AdbError as exc:
        return _err(exc)


@mcp.tool()
def root_shell(
    command: Annotated[str, Field(description="Shell command to run as root via su")],
) -> str:
    """Run an arbitrary command as root (uid 0) via `su -c`. Requires a rooted device."""
    try:
        return adb.root_shell(command).text()
    except AdbError as exc:
        return _err(exc)


def _format_screen(elements: list[ui.Element], *, interactive_only: bool = True, limit: int = 80) -> str:
    """Render a list of elements the way `screen_elements` does."""
    els = ui.interactive(elements) if interactive_only else elements
    if not els:
        return "No elements found on screen."
    shown = els[:limit]
    body = "\n".join(e.describe(i) for i, e in enumerate(shown))
    more = f"\n… and {len(els) - len(shown)} more (raise `limit`)." if len(els) > limit else ""
    return body + more


def _settle(
    *, baseline: str | None, timeout: float, poll: float = 0.4, stable_for: float = 0.6
) -> tuple[list[ui.Element], str, bool]:
    """Poll the UI tree until it changes from ``baseline`` and then holds steady.

    Returns (elements, signature, changed). ``changed`` is False if we timed out
    without ever differing from the baseline (the screen never moved).
    """
    deadline = time.monotonic() + max(0.5, timeout)
    last_sig: str | None = None
    stable_since: float | None = None
    changed = baseline is None
    elements: list[ui.Element] = []
    sig = baseline or ""
    while time.monotonic() < deadline:
        elements, err = _get_elements()
        if err:
            time.sleep(poll)
            continue
        sig = ui.signature(elements)
        if baseline is not None and sig != baseline:
            changed = True
        # Once we've changed (or had no baseline), wait for two equal reads.
        if changed:
            if sig == last_sig:
                if stable_since is None:
                    stable_since = time.monotonic()
                elif time.monotonic() - stable_since >= stable_for:
                    break
            else:
                stable_since = None
        last_sig = sig
        time.sleep(poll)
    return elements, sig, changed


@mcp.tool()
def wait_for_change(
    timeout: Annotated[float, Field(description="Max seconds to wait for the screen to change & settle")] = 6.0,
    interactive_only: Annotated[bool, Field(description="Only show tappable/text-bearing elements")] = True,
    limit: Annotated[int, Field(description="Max elements to return")] = 80,
) -> str:
    """Wait until the screen changes from right now and settles, then read it.

    Snapshots the current UI signature, then polls until the screen differs and
    stops moving (animations/loads finished), and returns the new
    `screen_elements` view. Use after an action whose effect is delayed.
    """
    try:
        before, err = _get_elements()
        if err:
            return err
        baseline = ui.signature(before)
        elements, _sig, changed = _settle(baseline=baseline, timeout=timeout)
        header = "Screen changed and settled:\n" if changed else "(no change detected within timeout)\n"
        return header + _format_screen(elements, interactive_only=interactive_only, limit=limit)
    except AdbError as exc:
        return _err(exc)


@mcp.tool()
def tap_text_and_read(
    text: Annotated[str, Field(description="Visible text/description of the element to tap")],
    exact: Annotated[bool, Field(description="Require an exact match instead of substring")] = False,
    timeout: Annotated[float, Field(description="Max seconds to wait for the resulting screen to settle")] = 6.0,
) -> str:
    """Tap an element by name, then automatically wait for and read the new screen.

    This is the "act and see" tool — it taps, waits for the UI to react and
    settle, and returns the resulting `screen_elements` so you immediately know
    what happened without a separate read.
    """
    try:
        before, err = _get_elements()
        if err:
            return err
        baseline = ui.signature(before)
        matches = ui.find(before, text, exact=exact, clickable_only=True)
        if not matches:
            return f"No element matching '{text}'. Call `screen_elements` to see what's available."
        cx, cy = matches[0].center
        _tap(cx, cy)
        elements, _sig, changed = _settle(baseline=baseline, timeout=timeout)
        note = "" if changed else " (screen did not visibly change)"
        header = f"Tapped {matches[0].label!r} @ ({cx},{cy}).{note}\nNow showing:\n"
        return header + _format_screen(elements)
    except AdbError as exc:
        return _err(exc)


@mcp.tool()
def tap_and_read(
    x: Annotated[int, Field(description="X pixel")],
    y: Annotated[int, Field(description="Y pixel")],
    timeout: Annotated[float, Field(description="Max seconds to wait for the resulting screen to settle")] = 6.0,
) -> str:
    """Tap at coordinates, then automatically wait for and read the new screen."""
    try:
        before, err = _get_elements()
        baseline = ui.signature(before) if not err else None
        _tap(x, y)
        elements, _sig, changed = _settle(baseline=baseline, timeout=timeout)
        note = "" if changed else " (screen did not visibly change)"
        return f"Tapped ({x},{y}).{note}\nNow showing:\n" + _format_screen(elements)
    except AdbError as exc:
        return _err(exc)


@mcp.tool()
def wait(
    seconds: Annotated[float, Field(description="Seconds to pause (lets the UI settle)")] = 1.0,
) -> str:
    """Pause for a moment so the UI can react/animate before the next action."""
    secs = max(0.0, min(30.0, seconds))
    time.sleep(secs)
    return f"Waited {secs}s."


@mcp.tool()
def reboot(
    mode: Annotated[str, Field(description="'' (normal), 'recovery', 'bootloader', or 'fastboot'")] = "",
) -> str:
    """Reboot the device, optionally into recovery/bootloader/fastboot."""
    try:
        args = ["reboot"] + ([mode] if mode else [])
        adb.run(args, timeout=30)
        return f"Reboot requested ({mode or 'normal'})."
    except AdbError as exc:
        return f"Reboot requested ({mode or 'normal'}). (adb link dropped: {exc})"


def main() -> None:
    """Console-script entry point: run the server over stdio."""
    mcp.run()


if __name__ == "__main__":
    main()
