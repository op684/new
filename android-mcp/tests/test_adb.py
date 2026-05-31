"""Tests for the ADB wrapper.

These cover the pure logic (command construction, result formatting, root
checks) by faking ``subprocess.run`` — no real device or adb binary needed.

Run with: ``python -m unittest discover tests`` or ``python tests/test_adb.py``.
"""

import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from android_mcp.adb import Adb, AdbError, CommandResult  # noqa: E402


class FakeCompleted:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class AdbTestCase(unittest.TestCase):
    def setUp(self):
        # Preserve the real subprocess.run and restore it after each test.
        self._real_run = subprocess.run
        self.calls = []

    def tearDown(self):
        subprocess.run = self._real_run

    def fake_run(self, result):
        def _run(cmd, **kwargs):
            self.calls.append((cmd, kwargs))
            return result
        subprocess.run = _run

    # -- argv construction ------------------------------------------------

    def test_base_command_includes_serial(self):
        self.assertEqual(Adb(adb_path="adb", serial="ABC123")._base(), ["adb", "-s", "ABC123"])

    def test_base_command_without_serial(self):
        self.assertEqual(Adb(adb_path="/opt/adb", serial=None)._base(), ["/opt/adb"])

    def test_shell_builds_expected_argv(self):
        self.fake_run(FakeCompleted(0, "hello", ""))
        res = Adb(serial="dev1").shell("echo hello")
        self.assertEqual(self.calls[0][0], ["adb", "-s", "dev1", "shell", "echo hello"])
        self.assertTrue(res.ok)
        self.assertEqual(res.stdout, "hello")

    def test_root_shell_quotes_command(self):
        self.fake_run(FakeCompleted(0, "uid=0(root)", ""))
        Adb().root_shell("cat /data/secret && echo done")
        cmd = self.calls[0][0]
        self.assertEqual(cmd[-2], "shell")
        self.assertTrue(cmd[-1].startswith("su -c "))
        self.assertIn("'cat /data/secret && echo done'", cmd[-1])

    # -- root detection ---------------------------------------------------

    def test_has_root_true_when_uid_zero(self):
        self.fake_run(FakeCompleted(0, "0\n", ""))
        self.assertTrue(Adb().has_root())

    def test_has_root_false_when_denied(self):
        self.fake_run(FakeCompleted(1, "", "su: permission denied"))
        self.assertFalse(Adb().has_root())

    # -- result formatting ------------------------------------------------

    def test_command_result_text_combines_streams(self):
        text = CommandResult(0, "out", "warn").text()
        self.assertIn("out", text)
        self.assertIn("[stderr]", text)

    def test_command_result_text_empty(self):
        self.assertIn("exit code 3", CommandResult(3, "", "").text())

    # -- error handling ---------------------------------------------------

    def test_missing_adb_binary_raises_adberror(self):
        def boom(cmd, **kwargs):
            raise FileNotFoundError()
        subprocess.run = boom
        with self.assertRaises(AdbError) as ctx:
            Adb(adb_path="definitely-not-a-real-binary-xyz").run(["devices"])
        self.assertIn("not found", str(ctx.exception))

    def test_timeout_raises_adberror(self):
        def slow(cmd, **kwargs):
            raise subprocess.TimeoutExpired(cmd, 1)
        subprocess.run = slow
        with self.assertRaises(AdbError) as ctx:
            Adb().run(["shell", "sleep 999"])
        self.assertIn("timed out", str(ctx.exception))


if __name__ == "__main__":
    unittest.main(verbosity=2)
