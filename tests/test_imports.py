from vyarth import scan


def _rules(tmp_path, source: str) -> set[tuple[str, str]]:
    path = tmp_path / "mod.py"
    path.write_text(source, encoding="utf-8")
    result = scan(path)
    return {(finding.rule, finding.symbol) for finding in result.findings}


def test_unused_alias_and_used_alias(tmp_path):
    found = _rules(
        tmp_path,
        "import json as js\n"
        "import csv as unused_csv\n"
        "\n"
        "def run(data):\n"
        "    return js.dumps(data)\n"
        "\n"
        "run({})\n",
    )
    assert ("UNUSED_IMPORT", "unused_csv") in found
    assert ("UNUSED_IMPORT", "js") not in found


def test_from_import_reports_only_the_unused_name(tmp_path):
    found = _rules(
        tmp_path,
        "from json import dumps, loads\n"
        "\n"
        "def run(data):\n"
        "    return dumps(data)\n"
        "\n"
        "run({})\n",
    )
    assert found == {("UNUSED_IMPORT", "loads")}


def test_annotation_keeps_a_typing_import(tmp_path):
    found = _rules(
        tmp_path,
        "from __future__ import annotations\n"
        "from typing import Optional\n"
        "\n"
        "def greet(name: Optional[str]) -> str:\n"
        "    return name or ''\n"
        "\n"
        "greet('a')\n",
    )
    assert found == set()


def test_wildcard_import_is_an_analysis_limit(tmp_path):
    path = tmp_path / "mod.py"
    path.write_text("from os import *\nimport json\n", encoding="utf-8")
    result = scan(path)
    wildcard = next(finding for finding in result.findings if finding.rule == "WILDCARD_IMPORT")
    assert wildcard.symbol == "os.*"
    assert wildcard.status == "ANALYSIS_LIMIT"
    assert wildcard.message == "Wildcard import prevents reliable analysis."
    assert wildcard.confidence == 100
    assert any(finding.rule == "UNUSED_IMPORT" and finding.symbol == "json" for finding in result.findings)


def test_future_import_is_used_on_its_own(tmp_path):
    found = _rules(tmp_path, "from __future__ import annotations\n")
    assert found == set()
