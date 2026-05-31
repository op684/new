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


def parse_hierarchy(xml: str) -> list[Element]:
    """Parse a uiautomator XML dump into a flat list of Elements."""
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return []
    elements: list[Element] = []
    for node in root.iter("node"):
        elements.append(
            Element(
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
        )
    return elements


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
