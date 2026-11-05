"""Run py_compile, then an optional project command, after a fix."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import os
import signal
import subprocess
import sys
from typing import Any


_TAIL = 4000


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    step: str
    output: str


def run_verification(root: Path, paths: list[str], command: str, timeout: int) -> VerifyResult:
    """Compile the edited files, then run `command` when one is configured."""
    compiled = py_compile_files(root, paths, timeout)
    if not compiled.ok:
        return compiled
    if not command.strip():
        return VerifyResult(True, "", "")
    return run_command(root, command, timeout)


def py_compile_files(root: Path, paths: list[str], timeout: int) -> VerifyResult:
    if not paths:
        return VerifyResult(True, "py_compile", "")
    return _run(
        [sys.executable, "-m", "py_compile", *paths],
        root,
        timeout,
        step="py_compile",
        shell=False,
    )


def run_command(root: Path, command: str, timeout: int) -> VerifyResult:
    return _run(command, root, timeout, step="command", shell=True)


def _run(
    args: list[str] | str,
    root: Path,
    timeout: int,
    *,
    step: str,
    shell: bool,
) -> VerifyResult:
    command: Any = args
    flags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) if sys.platform == "win32" else 0
    try:
        process = subprocess.Popen(
            command,
            cwd=root,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            shell=shell,
            creationflags=flags,
            start_new_session=sys.platform != "win32",
        )
    except OSError as exc:
        return VerifyResult(False, step, _tail(str(exc)))
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill(process)
        try:
            stdout, stderr = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            stdout, stderr = None, None
        output = _text(stdout) + _text(stderr)
        return VerifyResult(False, "timeout", _tail(output or "timed out"))
    output = _text(stdout) + _text(stderr)
    if process.returncode == 0:
        return VerifyResult(True, step, "")
    return VerifyResult(False, step, _tail(output))


def _kill(process: subprocess.Popen[str]) -> None:
    if sys.platform == "win32":
        subprocess.run(
            ["taskkill", "/F", "/T", "/PID", str(process.pid)],
            capture_output=True,
            check=False,
        )
        return
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        process.kill()


def _text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _tail(value: str) -> str:
    if len(value) <= _TAIL:
        return value
    return value[-_TAIL:]
