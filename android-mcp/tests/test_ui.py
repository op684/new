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


if __name__ == "__main__":
    unittest.main(verbosity=2)
