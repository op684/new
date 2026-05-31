"""Parse Android's UI hierarchy into structured, tappable elements.

`uiautomator dump` produces an XML tree describing everything on screen — each
node carries its text, resource-id, content-description, class, on-screen
``bounds`` and interaction flags (clickable, scrollable, …). Turning that into
a tidy list of elements with pre-computed centre coordinates is what lets the
model "see" the screen and tap things by name instead of guessing pixels.

This module is pure (no adb / no I/O) so it can be unit-tested on a fixture.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass

_BOUNDS_RE = re.compile(r"\[(-?\d+),(-?\d+)\]\[(-?\d+),(-?\d+)\]")


def _parse_bounds(raw: str) -> tuple[int, int, int, int]:
    m = _BOUNDS_RE.search(raw or "")
    if not m:
        return (0, 0, 0, 0)
    return tuple(int(v) for v in m.groups())  # type: ignore[return-value]


@dataclass
class Element:
    text: str
    resource_id: str
    content_desc: str
    clazz: str
    package: str
    bounds: tuple[int, int, int, int]
    clickable: bool
    enabled: bool
    focused: bool
    scrollable: bool
    checkable: bool
    checked: bool
    long_clickable: bool

    @property
    def center(self) -> tuple[int, int]:
        x1, y1, x2, y2 = self.bounds
        return ((x1 + x2) // 2, (y1 + y2) // 2)

    @property
    def label(self) -> str:
        """Best human-readable handle for the element."""
        return self.text or self.content_desc or self.resource_id or self.clazz

    def matches(self, query: str, *, exact: bool = False) -> bool:
        q = query.lower()
        fields = (self.text, self.content_desc, self.resource_id)
        if exact:
            return any(f.lower() == q for f in fields if f)
        return any(q in f.lower() for f in fields if f)

    def describe(self, index: int | None = None) -> str:
        cx, cy = self.center
        flags = []
        if self.clickable:
            flags.append("clickable")
        if self.scrollable:
            flags.append("scrollable")
        if self.checkable:
            flags.append("checked" if self.checked else "checkable")
        if not self.enabled:
            flags.append("disabled")
        if self.focused:
            flags.append("focused")
        parts = []
        if self.text:
            parts.append(f'"{self.text}"')
        if self.content_desc and self.content_desc != self.text:
            parts.append(f"desc={self.content_desc!r}")
        if self.resource_id:
            parts.append(f"id={self.resource_id}")
        head = f"[{index}] " if index is not None else ""
        flagstr = f"  <{', '.join(flags)}>" if flags else ""
        return f"{head}{' '.join(parts) or self.clazz} @ ({cx},{cy}){flagstr}"


def _b(node: ET.Element, attr: str) -> bool:
    return node.get(attr, "false") == "true"


def _make_element(node: ET.Element) -> Element:
    return Element(
        text=node.get("text", ""),
        resource_id=node.get("resource-id", ""),
        content_desc=node.get("content-desc", ""),
        clazz=node.get("class", ""),
        package=node.get("package", ""),
        bounds=_parse_bounds(node.get("bounds", "")),
        clickable=_b(node, "clickable"),
        enabled=_b(node, "enabled"),
        focused=_b(node, "focused"),
        scrollable=_b(node, "scrollable"),
        checkable=_b(node, "checkable"),
        checked=_b(node, "checked"),
        long_clickable=_b(node, "long-clickable"),
    )


def parse_hierarchy(xml: str) -> list[Element]:
    """Parse a uiautomator XML dump into a flat list of Elements (document order)."""
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return []
    return [_make_element(node) for node in root.iter("node")]


@dataclass
class TreeNode:
    """A UI element together with its children, preserving on-screen structure."""

    element: Element
    children: list["TreeNode"]


def parse_tree(xml: str) -> list[TreeNode]:
    """Parse a uiautomator XML dump into a nested tree of TreeNodes."""
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return []

    def build(node: ET.Element) -> TreeNode:
        return TreeNode(_make_element(node), [build(c) for c in node.findall("node")])

    return [build(c) for c in root.findall("node")]


def _informative(e: Element) -> bool:
    """True if an element carries something worth showing (text or interaction)."""
    return bool(
        e.text or e.content_desc or e.resource_id
        or e.clickable or e.scrollable or e.checkable or e.long_clickable
    )


def render_outline(nodes: list[TreeNode], *, compact: bool = True,
                   _depth: int = 0, _lines: list[str] | None = None) -> list[str]:
    """Render a tree as an indented outline.

    With ``compact`` (default), structural-only containers are skipped but their
    children are still shown (collapsed), so the outline stays readable while
    preserving the parent/child layout of meaningful elements.
    """
    if _lines is None:
        _lines = []
    for n in nodes:
        if _informative(n.element) or not compact:
            _lines.append("  " * _depth + n.element.describe())
            render_outline(n.children, compact=compact, _depth=_depth + 1, _lines=_lines)
        else:
            render_outline(n.children, compact=compact, _depth=_depth, _lines=_lines)
    return _lines


def extract_text(elements: list[Element]) -> list[str]:
    """Pull the human-readable text off the screen, in document order.

    Returns each element's visible text and its content-description (when that
    adds something new), so the model can "read" the screen as plain text.
    """
    out: list[str] = []
    for e in elements:
        t = e.text.strip()
        d = e.content_desc.strip()
        if t:
            out.append(t)
        if d and d != t:
            out.append(d)
    return out


def interactive(elements: list[Element]) -> list[Element]:
    """Elements worth showing the model: anything tappable or carrying text."""
    out = []
    for e in elements:
        if e.bounds == (0, 0, 0, 0):
            continue
        if e.clickable or e.scrollable or e.checkable or e.long_clickable or e.text or e.content_desc:
            out.append(e)
    return out


def find(elements: list[Element], query: str, *, exact: bool = False,
         clickable_only: bool = False) -> list[Element]:
    res = [e for e in elements if e.matches(query, exact=exact)]
    if clickable_only:
        clickable = [e for e in res if e.clickable]
        if clickable:
            return clickable
    return res


def find_by_id(elements: list[Element], resource_id: str) -> list[Element]:
    rid = resource_id.lower()
    return [e for e in elements if e.resource_id and rid in e.resource_id.lower()]


def signature(elements: list[Element]) -> str:
    """A short, stable fingerprint of what's on screen.

    Two dumps of the *same* screen produce the same signature; a navigation,
    dialog, or content change produces a different one. Used to detect when the
    UI has settled after an action. Based on each element's id/text/desc and
    bounds, which together capture both layout and content.
    """
    import hashlib

    parts = [
        f"{e.resource_id}|{e.text}|{e.content_desc}|{e.bounds}"
        for e in elements
    ]
    digest = hashlib.sha1("\n".join(parts).encode("utf-8", "replace")).hexdigest()
    return f"{len(elements)}:{digest[:16]}"
