import json

from tests.conftest import write_tree
from vyarth.cli import main


def test_text_and_json_reports(tmp_path, capsys):
    path = tmp_path / "service.py"
    path.write_text(
        "def calculate_total(data):\n"
        "    result = sum(data)\n"
        "    debug_value = 123\n"
        "\n"
        "    return result\n"
        "\n"
        "calculate_total([])\n",
        encoding="utf-8",
    )
    assert main(["scan", str(path)]) == 1
    text = capsys.readouterr().out
    assert "UNUSED_VARIABLE" in text
    assert "File: service.py" in text
    assert "Line: 3" in text
    assert "Variable: debug_value" in text
    assert "Confidence: 100%" in text

    assert main(["scan", str(path), "--format", "json"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["files_scanned"] == 1
    assert payload["errors"] == []
    assert payload["findings"][0]["rule"] == "UNUSED_VARIABLE"
    assert payload["findings"][0]["symbol"] == "debug_value"
    assert payload["findings"][0]["evidence"] == ["No references found."]


def test_clean_file_exits_zero(tmp_path, capsys):
    path = tmp_path / "clean.py"
    path.write_text("x = 1\nprint(x)\n", encoding="utf-8")
    assert main(["scan", str(path)]) == 0
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "vyarth: scanned 1 file in " in captured.err


def test_missing_path_exits_two(tmp_path, capsys):
    assert main(["scan", str(tmp_path / "missing.py")]) == 2
    assert "path not found" in capsys.readouterr().err


def test_min_confidence_flag(tmp_path, capsys):
    write_tree(
        tmp_path,
        {
            "pkg/__init__.py": "from . import live\nlive\n",
            "pkg/live.py": "def unused():\n    return 1\n",
            "pkg/orphan.py": "x = 1\n",
            "main.py": "import pkg\nif __name__ == '__main__':\n    print(pkg)\n",
        },
    )
    assert main(["scan", str(tmp_path), "--format", "json", "--min-confidence", "90"]) == 1
    payload = json.loads(capsys.readouterr().out)
    rules = {finding["rule"] for finding in payload["findings"]}
    assert "UNUSED_FUNCTION" in rules
    assert "POSSIBLY_UNUSED_MODULE" not in rules
