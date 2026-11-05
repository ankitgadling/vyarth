"""Agent-sized output: a window, a summary, and explain."""

import json

from tests.conftest import write_tree
from vyarth.cli import main
from vyarth import scan


_DUP = (
    "    item = value\n"
    "    item = item + 1\n"
    "    item = item + 1\n"
    "    item = item + 1\n"
    "    return item\n"
)

_RULES = {
    "UNUSED_IMPORT",
    "UNUSED_FUNCTION",
    "UNUSED_CLASS",
    "UNUSED_VARIABLE",
    "UNREACHABLE_CODE",
    "ORPHAN_FUNCTION",
    "POSSIBLY_UNUSED_MODULE",
    "WILDCARD_IMPORT",
    "UNUSED_DEPENDENCY",
    "DUPLICATE_CODE",
}


def _window(root) -> None:
    write_tree(
        root,
        {
            "app.py": (
                "import pkg.zzz\n"
                "\n"
                "def main():\n"
                "    return pkg.zzz\n"
                "\n"
                "if __name__ == '__main__':\n"
                "    main()\n"
            ),
            "pkg/__init__.py": "",
            "pkg/aaa.py": "def visible():\n    return 1\n",
            "pkg/zzz.py": "def _hidden():\n    return 1\n",
        },
    )


def _tree(root) -> None:
    write_tree(
        root,
        {
            "pyproject.toml": (
                "[project]\nname = 'demo'\nversion = '0.1.0'\n"
                "dependencies = ['not-a-real-dist-xyz']\n"
            ),
            "app.py": (
                "import os\n"
                "from data import *\n"
                "\n"
                "def main():\n"
                "    return 1\n"
                "\n"
                "def spare():\n"
                "    return 1\n"
                "\n"
                "def outer():\n"
                "    def inner():\n"
                "        return 1\n"
                "    return 2\n"
                "    leftover = 3\n"
                "\n"
                "def unused():\n"
                "    handlers = []\n"
                "    handlers.append(helper)\n"
                "    return handlers\n"
                "\n"
                "def helper():\n"
                "    return 1\n"
                "\n"
                "holder = 1\n"
                "\n"
                "class Box:\n"
                "    pass\n"
                "\n"
                "if __name__ == '__main__':\n"
                "    main()\n"
            ),
            "data.py": "VALUE = 1\n",
            "lonely.py": "SENTINEL = 1\n",
            "dup_a.py": f"def save_a(value):\n{_DUP}",
            "dup_b.py": (
                "def save_b(other):\n"
                "    item = other\n"
                "    item = item + 1\n"
                "    item = item + 1\n"
                "    item = item + 1\n"
                "    return item\n"
            ),
            "pkg/__init__.py": "",
            "pkg/aaa.py": "def visible():\n    return 1\n",
            "pkg/zzz.py": "def _hidden():\n    return 1\n",
        },
    )


def test_max_findings_defaults_to_confidence_and_counts_the_rest(tmp_path, capsys):
    _window(tmp_path)
    assert main(["scan", str(tmp_path), "--max-findings", "1", "--format", "json", "--quiet"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["summary"]["shown"] == 1
    assert payload["summary"]["truncated"] is True
    assert payload["summary"]["total"] > 1
    assert payload["findings"][0]["path"] == "pkg/zzz.py"
    assert payload["findings"][0]["symbol"] == "_hidden"

    assert main(["scan", str(tmp_path), "--sort", "path", "--max-findings", "1", "--format", "concise", "--quiet"]) == 1
    assert capsys.readouterr().out.startswith("pkg/aaa.py:")
    text = main(["scan", str(tmp_path), "--max-findings", "1", "--quiet"])
    assert text == 1
    rendered = capsys.readouterr().out
    omitted = payload["summary"]["total"] - 1
    assert f"... {omitted} more (use --max-findings or --min-confidence)" in rendered


def test_max_findings_zero_still_exits_1(tmp_path, capsys):
    _window(tmp_path)
    assert main(["scan", str(tmp_path), "--max-findings", "0", "--summary", "--quiet"]) == 1
    assert "findings" in capsys.readouterr().out


def test_rule_aliases_filter_and_an_unknown_rule_exits_2(tmp_path, capsys):
    _window(tmp_path)
    assert main(["scan", str(tmp_path), "--select", "unused-function", "--format", "json", "--quiet"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert {item["rule"] for item in payload["findings"]} == {"UNUSED_FUNCTION"}

    assert main(["scan", str(tmp_path), "--select", "unused_function", "--format", "json", "--quiet"]) == 1
    again = json.loads(capsys.readouterr().out)
    assert {item["symbol"] for item in again["findings"]} == {item["symbol"] for item in payload["findings"]}

    assert main(["scan", str(tmp_path), "--ignore-rule", "UNUSED_FUNCTION", "--format", "json", "--quiet"]) == 1
    ignored = json.loads(capsys.readouterr().out)
    assert "UNUSED_FUNCTION" not in {item["rule"] for item in ignored["findings"]}

    assert main(["scan", str(tmp_path), "--sort", "rule", "--format", "json", "--quiet"]) == 1
    ordered = [item["rule"] for item in json.loads(capsys.readouterr().out)["findings"]]
    assert ordered == sorted(ordered)

    assert main(["scan", str(tmp_path), "--select", "not-a-rule", "--quiet"]) == 2
    assert "unknown rule" in capsys.readouterr().err


def test_summary_paths_brief_and_fixable(tmp_path, capsys):
    _tree(tmp_path)
    assert main(["scan", str(tmp_path), "--summary", "--quiet"]) == 1
    line = capsys.readouterr().out
    assert line.startswith("vyarth: ")
    assert "safe-fixable" in line
    assert "top rules" in line

    assert main(["scan", str(tmp_path), "--summary", "--format", "json", "--quiet"]) == 1
    summary = json.loads(capsys.readouterr().out)
    assert "findings" not in summary
    assert summary["total"] == summary["shown"]
    assert summary["truncated"] is False

    assert main(["scan", str(tmp_path), "--paths-only", "--quiet"]) == 1
    paths = capsys.readouterr().out.splitlines()
    assert "lonely.py" in paths
    assert all(" " not in path for path in paths)

    assert main(["scan", str(tmp_path), "--format", "json", "--quiet"]) == 1
    full = json.loads(capsys.readouterr().out)
    assert "No references found." in full["findings"][0]["evidence"] or any(
        "No references found." in item["evidence"] for item in full["findings"]
    )

    assert main(["scan", str(tmp_path), "--format", "json", "--brief-evidence", "--quiet"]) == 1
    brief = json.loads(capsys.readouterr().out)
    assert all("No references found." not in item["evidence"] for item in brief["findings"])
    assert any("no_references" in item["reasons"] for item in brief["findings"])

    assert main(["scan", str(tmp_path), "--format", "jsonl", "--quiet"]) == 1
    first = json.loads(capsys.readouterr().out.splitlines()[0])
    assert "No references found." not in first["evidence"]
    assert "no_references" in first["reasons"]
    assert "rule_url" not in first
    assert "message" in first

    assert main(["scan", str(tmp_path), "--fixable-only", "--format", "json", "--quiet"]) == 1
    fixable = json.loads(capsys.readouterr().out)
    assert fixable["findings"]
    assert {item["fix"]["applicability"] for item in fixable["findings"]} == {"safe"}


def test_explain_covers_each_rule(tmp_path, capsys):
    _tree(tmp_path)
    result = scan(tmp_path)
    found = {item.rule for item in result.findings}
    assert found == _RULES
    orphan = next(item for item in result.findings if item.rule == "ORPHAN_FUNCTION")
    spare = next(item for item in result.findings if item.symbol == "spare")
    for rule in sorted(_RULES):
        finding = next(item for item in result.findings if item.rule == rule)
        assert main(["explain", finding.id, str(tmp_path), "--quiet"]) == 0
        text = capsys.readouterr().out
        assert text.startswith(rule + " ")
        assert "references: " in text
        assert "# vyarth: ignore[" in text
        assert "vyarth baseline . --output vyarth-baseline.json" in text
        assert "guidance: " in text
    assert main(["explain", f"{spare.path}:{spare.line}", str(tmp_path), "--quiet"]) == 0
    assert "references: 0" in capsys.readouterr().out
    assert main(["explain", f"{orphan.path}:{orphan.line}", str(tmp_path), "--format", "json", "--quiet"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["references"]["count"] >= 1
    assert payload["fix"]["applicability"] in {"safe", "unsafe", "none"}
    assert main(["explain", "dup_b.py:1", str(tmp_path), "--quiet"]) == 2
    assert "ambiguous id" in capsys.readouterr().err
    assert main(["explain", "VYNOSUCH", str(tmp_path), "--quiet"]) == 2
    assert "unknown id" in capsys.readouterr().err
