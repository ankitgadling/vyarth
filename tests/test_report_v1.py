"""Report schema v1: ids, reasons, formats, and fix notes on stderr."""

import json
from dataclasses import replace
from importlib.resources import files

import jsonschema
import pytest

from tests.conftest import write_tree
from vyarth.cli import main
from vyarth.model import Finding, assign_ids, resolve_ids, short_id
from vyarth import scan


def _schema():
    text = files("vyarth").joinpath("schema/report.v1.json").read_text(encoding="utf-8")
    return json.loads(text)


def _validate(payload):
    jsonschema.Draft202012Validator(_schema()).validate(payload)


def test_json_and_jsonl_match_the_schema(tmp_path, capsys):
    path = tmp_path / "app.py"
    path.write_text("def helper():\n    return 1\n", encoding="utf-8")
    assert main(["scan", str(path), "--format", "json"]) == 1
    payload = json.loads(capsys.readouterr().out)
    _validate(payload)
    assert payload["schema_version"] == 1
    assert payload["findings"][0]["fingerprint"].startswith("UNUSED_FUNCTION:")
    assert payload["findings"][0]["id"] == short_id(payload["findings"][0]["fingerprint"])
    assert "no_references" in payload["findings"][0]["reasons"]
    assert payload["summary"]["total"] == payload["summary"]["shown"]
    assert payload["summary"]["truncated"] is False

    assert main(["scan", str(path), "--output-format", "jsonl"]) == 1
    lines = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert lines[-1]["type"] == "summary"
    assert "fingerprint" in lines[0]
    finding = dict(lines[0])
    report = {
        "schema_version": 1,
        "files_scanned": 1,
        "findings": [finding],
        "errors": [],
    }
    _validate(report)


def test_duplicate_status_is_in_the_schema():
    payload = {
        "schema_version": 1,
        "files_scanned": 1,
        "findings": [
            {
                "id": "VYDUPLICATE",
                "fingerprint": "DUPLICATE_CODE:app.py:copy",
                "rule": "DUPLICATE_CODE",
                "path": "app.py",
                "line": 1,
                "column": 1,
                "symbol": "copy",
                "status": "POSSIBLY_DUPLICATE",
                "confidence": 80,
                "message": "duplicate",
                "evidence": [],
            }
        ],
        "errors": [],
    }
    _validate(payload)


def test_id_is_stable_when_lines_shift_and_changes_on_rename(tmp_path):
    path = tmp_path / "app.py"
    path.write_text("def helper():\n    return 1\n", encoding="utf-8")
    first = scan(path).findings[0]
    path.write_text("\n\ndef helper():\n    return 1\n", encoding="utf-8")
    shifted = scan(path).findings[0]
    assert shifted.line != first.line
    assert shifted.id == first.id
    assert shifted.fingerprint == first.fingerprint
    path.write_text("def renamed():\n    return 1\n", encoding="utf-8")
    renamed = scan(path).findings[0]
    assert renamed.id != first.id


def test_colliding_ids_grow_and_a_short_id_is_ambiguous(monkeypatch):
    calls: list[int] = []

    def fake(fingerprint: str, length: int = 8) -> str:
        calls.append(length)
        if length == 8:
            return "VYCOLLIDE"
        return "VYCOLLIDE" + fingerprint[-4:]

    monkeypatch.setattr("vyarth.model.short_id", fake)
    left = Finding(
        rule="UNUSED_FUNCTION",
        path="a.py",
        line=1,
        column=1,
        symbol="left",
        status="DEAD",
        confidence=100,
        message="",
        evidence=(),
        fingerprint="UNUSED_FUNCTION:a.py:left",
    )
    right = replace(left, symbol="right", fingerprint="UNUSED_FUNCTION:a.py:right")
    assigned = assign_ids([left, right])
    assert assigned[0].id != assigned[1].id
    assert 12 in calls
    assert all(item.id.startswith("VYCOLLIDE") and len(item.id) > len("VYCOLLIDE") for item in assigned)
    with pytest.raises(ValueError, match="ambiguous id"):
        resolve_ids(assigned, ["VYCOLLIDE"])
    assert resolve_ids(assigned, [assigned[0].id])[0].symbol == "left"


def test_fix_json_is_valid_and_notes_go_to_stderr(tmp_path, capsys):
    path = tmp_path / "app.py"
    path.write_text(
        "import os\n"
        "def outer():\n"
        "    def helper():\n"
        "        return 1\n"
        "    return 2\n",
        encoding="utf-8",
    )
    assert main(["fix", str(path), "--format", "json"]) == 1
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    _validate(payload)
    assert "applied" in payload
    assert payload["applied"]
    assert "fixed " in captured.err
    assert "fixed " not in captured.out


def test_select_id_refuses_an_ambiguous_prefix(tmp_path, capsys, monkeypatch):
    def fake(fingerprint: str, length: int = 8) -> str:
        if length == 8:
            return "VYCOLLIDE"
        return "VYCOLLIDE" + ("LEFT" if fingerprint.endswith("left") else "RIGHT")

    monkeypatch.setattr("vyarth.model.short_id", fake)
    write_tree(
        tmp_path,
        {
            "app.py": "def outer():\n    def left():\n        return 1\n    def right():\n        return 2\n    return 3\n",
        },
    )
    assert main(["fix", str(tmp_path), "--select-id", "VYCOLLIDE", "--dry-run"]) == 2
    assert "ambiguous id" in capsys.readouterr().err


def test_concise_confidence_is_opt_in(tmp_path, capsys):
    path = tmp_path / "app.py"
    path.write_text("def helper():\n    return 1\n", encoding="utf-8")
    assert main(["scan", str(path), "--format", "concise"]) == 1
    plain = capsys.readouterr().out
    assert "[" not in plain
    assert main(["scan", str(path), "--format", "concise", "--concise-confidence"]) == 1
    scored = capsys.readouterr().out
    assert " [" in scored
    assert scored.startswith(plain.rstrip())


def test_exit_zero_keeps_error_exits(tmp_path, capsys):
    path = tmp_path / "app.py"
    path.write_text("def helper():\n    return 1\n", encoding="utf-8")
    assert main(["scan", str(path), "--exit-zero"]) == 0
    assert "UNUSED_FUNCTION" in capsys.readouterr().out
    assert main(["scan", str(tmp_path / "missing.py"), "--exit-zero"]) == 2


def test_sarif_carries_confidence_and_a_rule_anchor(tmp_path, capsys):
    path = tmp_path / "app.py"
    path.write_text("def helper():\n    return 1\n", encoding="utf-8")
    assert main(["scan", str(path), "--format", "sarif"]) == 1
    payload = json.loads(capsys.readouterr().out)
    result = payload["runs"][0]["results"][0]
    rule = payload["runs"][0]["tool"]["driver"]["rules"][0]
    assert result["rank"] == result["properties"]["confidence"]
    assert result["properties"]["reasons"]
    assert result["locations"][0]["physicalLocation"]["region"]["endLine"] >= 1
    assert rule["helpUri"].endswith("#unused_function")


def test_schema_command_prints_the_shipped_file(capsys):
    assert main(["schema"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["$schema"] == "https://json-schema.org/draft/2020-12/schema"
