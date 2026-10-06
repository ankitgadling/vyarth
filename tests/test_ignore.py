from dataclasses import replace

from tests.conftest import write_tree
from vyarth import scan
from vyarth.config import load_config


def test_same_line_and_preceding_comment(tmp_path):
    path = tmp_path / "mod.py"
    path.write_text(
        "# vyarth: ignore\n"
        "def legacy():\n"
        "    return 1\n"
        "\n"
        "def kept():  # vyarth: ignore[unused-function]\n"
        "    value = 1\n"
        "    return value\n"
        "\n"
        "# vyarth: ignore\n"
        "\n"
        "def still_reported():\n"
        "    return 1\n",
        encoding="utf-8",
    )
    symbols = {finding.symbol for finding in scan(path).findings}
    assert "legacy" not in symbols
    assert "kept" not in symbols
    assert "still_reported" in symbols


def test_rule_specific_comment_leaves_other_findings(tmp_path):
    path = tmp_path / "mod.py"
    path.write_text(
        "# vyarth: ignore[unused-function]\n"
        "def legacy():\n"
        "    value = 1\n"
        "    return 1\n",
        encoding="utf-8",
    )
    found = {(finding.rule, finding.symbol) for finding in scan(path).findings}
    assert ("UNUSED_FUNCTION", "legacy") not in found
    assert ("UNUSED_VARIABLE", "value") in found


def test_path_ignore_suppresses_findings_but_still_counts_imports(tmp_path):
    write_tree(
        tmp_path,
        {
            "pyproject.toml": "[tool.vyarth]\nignore = ['legacy.py']\n",
            "legacy.py": "import kept\nkept\ndef dead():\n    return 1\n",
            "kept.py": "VALUE = 1\n",
            "app.py": "def live_unused():\n    return 1\n",
        },
    )
    result = scan(tmp_path)
    symbols = {finding.symbol for finding in result.findings}
    assert "dead" not in symbols
    assert "live_unused" in symbols
    assert not any(finding.path == "kept.py" and finding.rule == "POSSIBLY_UNUSED_MODULE" for finding in result.findings)
    assert any(finding.path == "legacy.py" and finding.rule == "POSSIBLY_UNUSED_MODULE" for finding in result.findings) is False


def test_exclude_drops_the_file_before_import_resolution(tmp_path):
    write_tree(
        tmp_path,
        {
            "pyproject.toml": "[tool.vyarth]\nexclude = ['skip.py']\n",
            "skip.py": "import kept\ndef skip_fn():\n    return 1\n",
            "kept.py": "VALUE = 1\n",
        },
    )
    result = scan(tmp_path)
    assert not any(finding.symbol == "skip_fn" for finding in result.findings)
    assert any(
        finding.rule == "POSSIBLY_UNUSED_MODULE" and finding.path == "kept.py"
        for finding in result.findings
    )


def test_min_confidence_filters_possible_modules(tmp_path):
    write_tree(
        tmp_path,
        {
            "pkg/__init__.py": "from . import live\nlive\n",
            "pkg/live.py": "def unused():\n    return 1\n",
            "pkg/orphan.py": "x = 1\n",
            "main.py": "import pkg\nif __name__ == '__main__':\n    print(pkg)\n",
        },
    )
    config = load_config(tmp_path)
    high = scan(tmp_path, config=replace(config, min_confidence=90))
    rules = {finding.rule for finding in high.findings}
    assert "UNUSED_FUNCTION" in rules
    assert "POSSIBLY_UNUSED_MODULE" not in rules


def test_vyarth_toml_config(tmp_path):
    write_tree(
        tmp_path,
        {
            "vyarth.toml": "ignore = ['legacy.py']\n",
            "legacy.py": "def dead():\n    return 1\n",
            "app.py": "def live_unused():\n    return 1\n",
        },
    )
    symbols = {finding.symbol for finding in scan(tmp_path).findings}
    assert "dead" not in symbols
    assert "live_unused" in symbols
