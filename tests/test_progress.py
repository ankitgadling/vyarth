import io
import time

from vyarth.progress import ScanProgress, format_duration


class _Tty(io.StringIO):
    def isatty(self) -> bool:
        return True


def test_duration_uses_seconds_then_minutes():
    assert format_duration(1.26) == "1.3s"
    assert format_duration(12.8) == "12s"
    assert format_duration(75) == "1m 15s"
    assert format_duration(3661) == "1h 01m 01s"


def test_progress_keeps_reporting_elapsed_time_during_a_slow_step():
    stream = io.StringIO()
    progress = ScanProgress(stream, interval=0.05)
    with progress:
        progress.update("checking methods", "1/4 django/forms/fields.py")
        time.sleep(0.4)
        progress.succeed(4)
    text = stream.getvalue()
    assert "vyarth: scanning" in text
    assert text.count("checking methods 1/4 django/forms/fields.py") >= 2
    assert "vyarth: scanned 4 files in " in text


def test_progress_rewrites_one_line_on_a_terminal():
    stream = _Tty()
    progress = ScanProgress(stream, interval=0.05)
    with progress:
        progress.update("indexing files", "1/2")
        time.sleep(0.12)
        progress.succeed(2)
    text = stream.getvalue()
    assert "\r" in text
    assert text.count("\n") == 1
    assert "scanned 2 files in " in text


def test_a_failed_scan_does_not_claim_it_finished(tmp_path):
    stream = io.StringIO()
    progress = ScanProgress(stream, interval=10)
    try:
        with progress:
            raise RuntimeError("stopped")
    except RuntimeError:
        pass
    assert "scanned" not in stream.getvalue()
