"""Live scan status for the command line.

Findings stay on standard output. Status goes to standard error so a long
analysis cannot sit on a blank terminal.
"""

from __future__ import annotations

import sys
import threading
import time
from typing import TextIO


class ScanProgress:
    """Print the current step and elapsed time about once a second."""

    def __init__(self, stream: TextIO | None = None, interval: float = 1.0) -> None:
        self.stream = stream
        self.interval = interval
        self.started = 0.0
        self.label = "scanning"
        self.detail = ""
        self._files: int | None = None
        self._tty = False
        self._width = 0
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def __enter__(self) -> ScanProgress:
        self.open()
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()

    def open(self) -> None:
        if self.stream is None:
            self.stream = sys.stderr
        self._tty = self.stream.isatty()
        self.started = time.monotonic()
        self._stop.clear()
        self._thread = threading.Thread(target=self._beat, name="vyarth-progress", daemon=True)
        self._thread.start()
        with self._lock:
            self._emit()

    def close(self) -> None:
        failed = sys.exc_info()[0] is not None
        self._stop.set()
        if self._thread is not None:
            self._thread.join()
        with self._lock:
            files = None if failed else self._files
            if files is None:
                self._clear()
            else:
                noun = "file" if files == 1 else "files"
                elapsed = format_duration(time.monotonic() - self.started)
                self._write(f"vyarth: scanned {files} {noun} in {elapsed}", newline=True)
            assert self.stream is not None
            self.stream.flush()

    def update(self, label: str, detail: str = "") -> None:
        with self._lock:
            changed = label != self.label
            self.label = label
            self.detail = detail
            if changed:
                self._emit()

    def succeed(self, files: int) -> None:
        self._files = files

    def _beat(self) -> None:
        while not self._stop.wait(self.interval):
            with self._lock:
                if self._stop.is_set():
                    return
                self._emit()

    def _emit(self) -> None:
        clock = format_duration(time.monotonic() - self.started)
        if self.detail:
            text = f"vyarth: {self.label} {self.detail}  {clock}"
        else:
            text = f"vyarth: {self.label}  {clock}"
        self._write(text, newline=False)

    def _write(self, text: str, *, newline: bool) -> None:
        assert self.stream is not None
        if self._tty:
            pad = max(0, self._width - len(text))
            self.stream.write("\r" + text + (" " * pad))
            self._width = 0 if newline else len(text)
            if newline:
                self.stream.write("\n")
        else:
            self.stream.write(text + "\n")
        self.stream.flush()

    def _clear(self) -> None:
        assert self.stream is not None
        if self._tty and self._width:
            self.stream.write("\r" + (" " * self._width) + "\r")
            self._width = 0


def format_duration(seconds: float) -> str:
    """Format a short elapsed time, such as ``1.2s`` or ``3m 08s``."""
    if seconds < 10:
        return f"{seconds:.1f}s"
    total = int(seconds)
    if total < 60:
        return f"{total}s"
    minutes, secs = divmod(total, 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours}h {minutes:02d}m {secs:02d}s"
    return f"{minutes}m {secs:02d}s"
