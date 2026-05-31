"""Thin wrapper around the ADB command-line tool.

All device interaction goes through here so the MCP server layer stays small.
The wrapper supports targeting a specific device (handy when several are
attached) and running commands either as the shell user or as root via ``su``.
"""

from __future__ import annotations

import os
import shlex
import subprocess
from dataclasses import dataclass


class AdbError(RuntimeError):
    """Raised when an adb invocation fails."""


@dataclass
class CommandResult:
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0

    def text(self) -> str:
        """Human-readable summary suitable for returning to the model."""
        parts: list[str] = []
        if self.stdout.strip():
            parts.append(self.stdout.rstrip())
        if self.stderr.strip():
            parts.append(f"[stderr]\n{self.stderr.rstrip()}")
        if not parts:
            parts.append(f"(no output, exit code {self.returncode})")
        elif self.returncode != 0:
            parts.append(f"[exit code {self.returncode}]")
        return "\n".join(parts)


class Adb:
    """Configurable adb runner.

    Configuration is read from the environment so the server can be wired up
    through an MCP client config without code changes:

    * ``ADB_PATH``       – path to the adb binary (default: ``adb`` on PATH)
    * ``ANDROID_SERIAL`` – device serial / ``host:port`` to target (optional)
    * ``ADB_TIMEOUT``    – per-command timeout in seconds (default: 120)
    """

    def __init__(
        self,
        adb_path: str | None = None,
        serial: str | None = None,
        timeout: float | None = None,
    ) -> None:
        self.adb_path = adb_path or os.environ.get("ADB_PATH", "adb")
        self.serial = serial or os.environ.get("ANDROID_SERIAL") or None
        self.timeout = timeout or float(os.environ.get("ADB_TIMEOUT", "120"))

    # -- low level ---------------------------------------------------------

    def _base(self) -> list[str]:
        cmd = [self.adb_path]
        if self.serial:
            cmd += ["-s", self.serial]
        return cmd

    def raw(self, args: list[str], *, binary: bool = False,
            timeout: float | None = None) -> subprocess.CompletedProcess:
        """Run ``adb <args>`` and return the completed process.

        Set ``binary=True`` to keep stdout as bytes (used for screenshots).
        """
        cmd = self._base() + args
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=not binary,
                timeout=timeout or self.timeout,
            )
        except FileNotFoundError as exc:
            raise AdbError(
                f"adb binary not found at '{self.adb_path}'. Install platform-tools "
                f"or set ADB_PATH."
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise AdbError(f"adb command timed out after {exc.timeout}s: {' '.join(cmd)}") from exc
        return proc

    def run(self, args: list[str], *, timeout: float | None = None) -> CommandResult:
        proc = self.raw(args, timeout=timeout)
        return CommandResult(proc.returncode, proc.stdout or "", proc.stderr or "")

    # -- shell -------------------------------------------------------------

    def shell(self, command: str, *, timeout: float | None = None) -> CommandResult:
        """Run a command in the device shell (non-root)."""
        return self.run(["shell", command], timeout=timeout)

    def root_shell(self, command: str, *, timeout: float | None = None) -> CommandResult:
        """Run a command as root via ``su -c`` (Magisk/SuperSU).

        The whole command is passed as a single quoted argument to ``su`` so
        pipes and redirects execute in the privileged shell.
        """
        quoted = shlex.quote(command)
        return self.run(["shell", f"su -c {quoted}"], timeout=timeout)

    # -- convenience -------------------------------------------------------

    def devices(self) -> CommandResult:
        return self.run(["devices", "-l"])

    def connect(self, host_port: str) -> CommandResult:
        return self.run(["connect", host_port])

    def has_root(self) -> bool:
        """Best-effort check that ``su`` is available and grants uid 0."""
        res = self.root_shell("id -u")
        return res.ok and res.stdout.strip().endswith("0")
