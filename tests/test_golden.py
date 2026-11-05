"""Golden snapshots of each report format. Roots and the tool version are normalized."""

from pathlib import Path

from vyarth import __version__
from vyarth.report import render_concise, render_github, render_json, render_jsonl, render_sarif, render_text
from vyarth import scan


_ROOT = Path(__file__).resolve().parents[1]
_SNAPSHOTS = _ROOT / "tests" / "snapshots"
_SOURCE = "import os\n\ndef helper():\n    return 1\n\nif __name__ == '__main__':\n    print(helper())\n"


def test_formats_match_the_snapshots(tmp_path):
    (tmp_path / "app.py").write_text(_SOURCE, encoding="utf-8")
    result = scan(tmp_path)
    rendered = {
        "text": render_text(result),
        "concise": render_concise(result, confidence=True),
        "github": render_github(result, tmp_path),
        "json": render_json(result, tmp_path),
        "jsonl": render_jsonl(result, tmp_path),
        "sarif": render_sarif(result, tmp_path),
    }
    for name, text in rendered.items():
        expected = (_SNAPSHOTS / f"app.{name}").read_text(encoding="utf-8")
        assert _normalize(text, tmp_path) == expected


def _normalize(text: str, root: Path) -> str:
    raw = str(root)
    escaped = raw.replace("\\", "\\\\")
    return (
        text.replace(escaped, "<root>")
        .replace(raw, "<root>")
        .replace(__version__, "<version>")
        .replace("\r\n", "\n")
    )
