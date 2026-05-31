"""Tests for the UI hierarchy parser (pure logic, no device needed)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from android_mcp import ui  # noqa: E402

SAMPLE = """<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>
<hierarchy rotation="0">
  <node index="0" text="" resource-id="" class="android.widget.FrameLayout"
        package="com.android.launcher" content-desc="" clickable="false"
        enabled="true" focused="false" scrollable="false" checkable="false"
        checked="false" long-clickable="false" bounds="[0,0][1440,3120]">
    <node index="0" text="Settings" resource-id="com.android.launcher:id/title"
          class="android.widget.TextView" package="com.android.launcher"
          content-desc="Open settings" clickable="true" enabled="true"
          focused="false" scrollable="false" checkable="false" checked="false"
          long-clickable="true" bounds="[100,200][300,260]" />
    <node index="1" text="" resource-id="com.android.launcher:id/toggle"
          class="android.widget.Switch" package="com.android.launcher"
          content-desc="Wi-Fi" clickable="true" enabled="true" focused="false"
          scrollable="false" checkable="true" checked="true"
          long-clickable="false" bounds="[1200,200][1380,260]" />
    <node index="2" text="Username" resource-id="com.app:id/field"
          class="android.widget.EditText" package="com.app" content-desc=""
          clickable="true" enabled="false" focused="true" scrollable="false"
          checkable="false" checked="false" long-clickable="false"
          bounds="[0,400][1440,500]" />
  </node>
</hierarchy>"""


class UITestCase(unittest.TestCase):
    def setUp(self):
        self.elements = ui.parse_hierarchy(SAMPLE)

    def test_parses_all_nodes(self):
        self.assertEqual(len(self.elements), 4)  # root + 3 children

    def test_text_and_desc(self):
        settings = next(e for e in self.elements if e.text == "Settings")
        self.assertEqual(settings.content_desc, "Open settings")
        self.assertEqual(settings.resource_id, "com.android.launcher:id/title")

    def test_center_computation(self):
        settings = next(e for e in self.elements if e.text == "Settings")
        self.assertEqual(settings.center, (200, 230))

    def test_flags(self):
        toggle = next(e for e in self.elements if e.content_desc == "Wi-Fi")
        self.assertTrue(toggle.checkable)
        self.assertTrue(toggle.checked)
        self.assertTrue(toggle.clickable)

    def test_disabled_and_focused(self):
        field = next(e for e in self.elements if e.resource_id == "com.app:id/field")
        self.assertFalse(field.enabled)
        self.assertTrue(field.focused)

    def test_label_prefers_text(self):
        toggle = next(e for e in self.elements if e.content_desc == "Wi-Fi")
        self.assertEqual(toggle.label, "Wi-Fi")  # no text -> falls back to desc

    def test_find_by_text_substring(self):
        res = ui.find(self.elements, "settings")
        # matches "Settings" text and "Open settings" desc -> same node, plus
        # the resource-ids contain neither, so expect exactly one element.
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0].text, "Settings")

    def test_find_clickable_only_filter(self):
        res = ui.find(self.elements, "Settings", clickable_only=True)
        self.assertTrue(all(e.clickable for e in res))

    def test_find_by_id(self):
        res = ui.find_by_id(self.elements, "id/toggle")
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0].content_desc, "Wi-Fi")

    def test_interactive_excludes_root_framelayout(self):
        inter = ui.interactive(self.elements)
        # The bare root FrameLayout has no text/desc and isn't interactive.
        self.assertNotIn("FrameLayout", [e.clazz for e in inter])
        self.assertEqual(len(inter), 3)

    def test_describe_includes_coords_and_index(self):
        settings = next(e for e in self.elements if e.text == "Settings")
        desc = settings.describe(5)
        self.assertIn("[5]", desc)
        self.assertIn("(200,230)", desc)
        self.assertIn("clickable", desc)

    def test_malformed_xml_returns_empty(self):
        self.assertEqual(ui.parse_hierarchy("not xml <<<"), [])

    # -- text extraction --------------------------------------------------

    def test_extract_text_reads_screen_content(self):
        text = ui.extract_text(self.elements)
        self.assertIn("Settings", text)        # visible text
        self.assertIn("Open settings", text)   # content-desc adds info
        self.assertIn("Wi-Fi", text)           # desc on the toggle
        self.assertIn("Username", text)

    def test_extract_text_skips_desc_equal_to_text(self):
        els = ui.parse_hierarchy(
            '<hierarchy><node text="OK" content-desc="OK" bounds="[0,0][1,1]"/></hierarchy>'
        )
        self.assertEqual(ui.extract_text(els), ["OK"])

    def test_extract_text_empty_when_no_text(self):
        els = ui.parse_hierarchy(
            '<hierarchy><node class="android.widget.View" bounds="[0,0][1,1]"/></hierarchy>'
        )
        self.assertEqual(ui.extract_text(els), [])

    # -- tree parsing -----------------------------------------------------

    def test_parse_tree_structure(self):
        tops = ui.parse_tree(SAMPLE)
        self.assertEqual(len(tops), 1)             # one root FrameLayout
        self.assertEqual(len(tops[0].children), 3)  # three children

    def test_render_outline_compact_collapses_container(self):
        tops = ui.parse_tree(SAMPLE)
        lines = ui.render_outline(tops, compact=True)
        # The bare root FrameLayout is collapsed; children render at depth 0.
        self.assertEqual(len(lines), 3)
        self.assertTrue(any('"Settings"' in ln for ln in lines))
        self.assertFalse(lines[0].startswith(" "))  # children rendered at depth 0

    def test_render_outline_full_includes_container(self):
        tops = ui.parse_tree(SAMPLE)
        lines = ui.render_outline(tops, compact=False)
        self.assertEqual(len(lines), 4)            # root + 3 children
        # children are indented under the root
        self.assertTrue(any(ln.startswith("  ") for ln in lines))

    def test_parse_tree_malformed_returns_empty(self):
        self.assertEqual(ui.parse_tree("nope <<"), [])

    # -- screen signature (change detection) ------------------------------

    def test_signature_stable_for_same_screen(self):
        a = ui.signature(self.elements)
        b = ui.signature(ui.parse_hierarchy(SAMPLE))
        self.assertEqual(a, b)

    def test_signature_differs_when_text_changes(self):
        changed = SAMPLE.replace("Settings", "Settings Changed")
        self.assertNotEqual(ui.signature(self.elements), ui.signature(ui.parse_hierarchy(changed)))

    def test_signature_differs_when_element_count_changes(self):
        fewer = ui.parse_hierarchy(
            '<hierarchy><node text="Only" bounds="[0,0][1,1]"/></hierarchy>'
        )
        self.assertNotEqual(ui.signature(self.elements), ui.signature(fewer))

    def test_signature_format(self):
        sig = ui.signature(self.elements)
        count, _, digest = sig.partition(":")
        self.assertEqual(int(count), len(self.elements))
        self.assertTrue(digest)


if __name__ == "__main__":
    unittest.main(verbosity=2)
