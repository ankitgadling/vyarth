"""Ignore reasons, unused ignores, allow rules, and baseline version 2."""

import json

from tests.conftest import write_tree
from vyarth.cli import main
from vyarth.ignore import collect_ignores
from vyarth import scan


def test_ignore_reasons_parse_both_forms():
    dashed = collect_ignores("def live():\n    return 1  # vyarth: ignore[unused-function] -- called via Celery beat\n")
    quoted = collect_ignores('def live():\n    return 1  # vyarth: ignore[unused-function] reason="called via Celery beat"\n')
    assert dashed[0].reason == "called via Celery beat"
    assert quoted[0].reason == "called via Celery beat"
    assert dashed[0].reportable is True


def test_a_reason_keeps_the_suppression_and_an_unused_ignore_is_reported(tmp_path):
    write_tree(
        tmp_path,
        {
            "app.py": (
                "def live():  # vyarth: ignore[unused-function] -- called via Celery beat\n"
                "    return 1\n"
                "\n"
                "def spare():\n"
                "    return 1\n"
                "\n"
                "x = 1  # vyarth: ignore[unused-function]\n"
                "\n"
                "if __name__ == '__main__':\n"
                "    print('ok')\n"
            ),
        },
    )
    quiet = scan(tmp_path)
    assert not any(item.symbol == "live" and item.rule == "UNUSED_FUNCTION" for item in quiet.findings)
    assert not any(item.rule == "UNUSED_IGNORE" for item in quiet.findings)
    reported = scan(tmp_path, config=_config(tmp_path, report_unused_ignores=True))
    unused = [item for item in reported.findings if item.rule == "UNUSED_IGNORE"]
    assert len(unused) == 1
    assert "x = 1" in (tmp_path / "app.py").read_text(encoding="utf-8").splitlines()[unused[0].line - 1]


def test_require_ignore_reason_does_not_suppress(tmp_path):
    write_tree(
        tmp_path,
        {
            "pyproject.toml": "[tool.vyarth]\nrequire_ignore_reason = true\n",
            "app.py": (
                "def spare():  # vyarth: ignore[unused-function]\n"
                "    return 1\n"
                "\n"
                "def kept():  # vyarth: ignore[unused-function] -- called via Celery beat\n"
                "    return 1\n"
                "\n"
                "if __name__ == '__main__':\n"
                "    print('ok')\n"
            ),
        },
    )
    result = scan(tmp_path)
    rules = {(item.rule, item.symbol) for item in result.findings}
    assert ("UNUSED_FUNCTION", "spare") in rules
    assert ("IGNORE_WITHOUT_REASON", "unused_function") in rules
    assert ("UNUSED_FUNCTION", "kept") not in rules


def test_allow_glob_suppresses_a_symbol(tmp_path):
    write_tree(
        tmp_path,
        {
            "pyproject.toml": (
                "[[tool.vyarth.allow]]\n"
                'symbol = "spare"\n'
                'rule = "unused-function"\n'
                'reason = "loaded by a queue"\n'
            ),
            "app.py": (
                "def spare():\n"
                "    return 1\n"
                "\n"
                "def other():\n"
                "    return 1\n"
                "\n"
                "if __name__ == '__main__':\n"
                "    print('ok')\n"
            ),
        },
    )
    result = scan(tmp_path)
    symbols = {item.symbol for item in result.findings if item.rule == "UNUSED_FUNCTION"}
    assert "spare" not in symbols
    assert "other" in symbols


def test_a_version_1_baseline_still_hides_the_finding(tmp_path, capsys):
    write_tree(
        tmp_path,
        {"app.py": "def helper():\n    return 1\n\nif __name__ == '__main__':\n    print('ok')\n"},
    )
    found = scan(tmp_path)
    fingerprint = next(item.fingerprint for item in found.findings if item.symbol == "helper")
    baseline = tmp_path / "old.json"
    baseline.write_text(json.dumps({"findings": [fingerprint]}), encoding="utf-8")
    assert main(["scan", str(tmp_path), "--baseline", str(baseline), "--quiet"]) == 0
    assert "helper" not in capsys.readouterr().out


def test_add_is_idempotent_and_prune_counts(tmp_path, capsys):
    write_tree(tmp_path, {"app.py": "def helper():\n    return 1\n"})
    found = scan(tmp_path)
    helper = next(item for item in found.findings if item.symbol == "helper")
    assert main(["baseline", str(tmp_path), "--add", helper.id, "--reason", "kept for now", "--quiet"]) == 0
    assert "added 1" in capsys.readouterr().out
    assert main(["baseline", str(tmp_path), "--add", helper.id, "--reason", "kept for now", "--quiet"]) == 0
    assert "added 0" in capsys.readouterr().out
    payload = json.loads((tmp_path / "vyarth-baseline.json").read_text(encoding="utf-8"))
    assert payload["version"] == 2
    assert payload["findings"][0]["reason"] == "kept for now"
    payload["findings"].append(
        {
            "fingerprint": "UNUSED_FUNCTION:missing.py:gone",
            "id": "",
            "rule": "UNUSED_FUNCTION",
            "path": "missing.py",
            "symbol": "gone",
            "reason": "old",
            "added": "2026-11-04",
        }
    )
    (tmp_path / "vyarth-baseline.json").write_text(json.dumps(payload), encoding="utf-8")
    assert main(["baseline", str(tmp_path), "--prune", "--quiet"]) == 0
    assert "pruned 1" in capsys.readouterr().out
    kept = json.loads((tmp_path / "vyarth-baseline.json").read_text(encoding="utf-8"))
    assert [item["symbol"] for item in kept["findings"]] == ["helper"]


def test_baseline_mode_all_marks_the_finding(tmp_path, capsys):
    write_tree(tmp_path, {"app.py": "def helper():\n    return 1\n"})
    assert main(["baseline", str(tmp_path), "--quiet"]) == 0
    capsys.readouterr()
    assert main(["scan", str(tmp_path), "--baseline", "vyarth-baseline.json", "--baseline-mode", "all", "--format", "json", "--quiet"]) == 1
    report = json.loads(capsys.readouterr().out)
    helper = next(item for item in report["findings"] if item["symbol"] == "helper")
    assert helper["baselined"] is True


def _config(root, **changes):
    from dataclasses import replace

    from vyarth.config import load_config

    return replace(load_config(root), **changes)
