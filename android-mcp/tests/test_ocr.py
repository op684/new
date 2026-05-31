"""Tests for the OCR helpers that don't need tesseract installed.

The line-grouping and Word geometry are pure logic; we test those directly.
`available()` is exercised for its graceful-degradation behaviour.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from android_mcp import ocr  # noqa: E402


class OcrTestCase(unittest.TestCase):
    def test_word_center(self):
        w = ocr.Word("Hi", left=100, top=200, width=40, height=20, confidence=90.0)
        self.assertEqual(w.center, (120, 210))

    def test_group_lines_orders_left_to_right(self):
        words = [
            ocr.Word("world", 200, 100, 50, 20, 95),
            ocr.Word("Hello", 100, 102, 50, 20, 95),  # slightly different y, same line
            ocr.Word("again", 100, 200, 50, 20, 95),  # next line
        ]
        lines = ocr.group_lines(words, y_tolerance=12)
        self.assertEqual(lines, ["Hello world", "again"])

    def test_group_lines_separates_distant_rows(self):
        words = [
            ocr.Word("top", 0, 0, 30, 20, 90),
            ocr.Word("bottom", 0, 500, 60, 20, 90),
        ]
        self.assertEqual(ocr.group_lines(words), ["top", "bottom"])

    def test_group_lines_empty(self):
        self.assertEqual(ocr.group_lines([]), [])

    def test_available_returns_tuple(self):
        ok, detail = ocr.available()
        self.assertIsInstance(ok, bool)
        self.assertIsInstance(detail, str)
        self.assertTrue(detail)  # always explains the state

    def test_recognize_raises_helpfully_without_deps(self):
        # If pytesseract/PIL are absent, _imports must raise a clear RuntimeError.
        try:
            import pytesseract  # noqa: F401
            from PIL import Image  # noqa: F401
            have_deps = True
        except ImportError:
            have_deps = False
        if have_deps:
            self.skipTest("OCR deps installed; skipping the missing-deps path")
        with self.assertRaises(RuntimeError) as ctx:
            ocr.recognize_words(b"not really a png")
        self.assertIn("install", str(ctx.exception).lower())


if __name__ == "__main__":
    unittest.main(verbosity=2)
