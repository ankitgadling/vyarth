import io
import os
from pathlib import Path
import subprocess

from tests.conftest import write_tree
from vyarth import scan
from vyarth.cli import main
from vyarth.lsp import _dispatch, _read_message, _write_message, code_actions_for, diagnostics_for


def test_attribute_call_on_an_imported_module_reaches_the_function(tmp_path):
    write_tree(
        tmp_path,
        {
            "pkg/__init__.py": "",
            "pkg/api.py": "def func():\n    return helper()\n\ndef helper():\n    return 1\n",
            "main.py": "import pkg.api\n\ndef main():\n    return pkg.api.func()\n\nif __name__ == '__main__':\n    main()\n",
        },
    )
    symbols = {finding.symbol for finding in scan(tmp_path).findings}
    assert "func" not in symbols
    assert "helper" not in symbols


def test_from_import_attribute_call_reaches_the_submodule(tmp_path):
    write_tree(
        tmp_path,
        {
            "pkg/__init__.py": "",
            "pkg/api.py": "def func():\n    return 1\n",
            "main.py": "from pkg import api\n\ndef main():\n    return api.func()\n\nif __name__ == '__main__':\n    main()\n",
        },
    )
    assert not any(finding.symbol == "func" for finding in scan(tmp_path).findings)


def test_alias_call_reaches_the_function(tmp_path):
    write_tree(
        tmp_path,
        {
            "app.py": (
                "def helper():\n"
                "    return 1\n"
                "\n"
                "def func():\n"
                "    return helper()\n"
                "\n"
                "alias = func\n"
                "\n"
                "def main():\n"
                "    return alias()\n"
                "\n"
                "if __name__ == '__main__':\n"
                "    main()\n"
            ),
        },
    )
    symbols = {finding.symbol for finding in scan(tmp_path).findings}
    assert "func" not in symbols
    assert "helper" not in symbols


def test_annotated_return_reaches_the_method(tmp_path):
    write_tree(
        tmp_path,
        {
            "app.py": (
                "class Widget:\n"
                "    def run(self):\n"
                "        return 1\n"
                "\n"
                "def make() -> Widget:\n"
                "    return Widget()\n"
                "\n"
                "def main():\n"
                "    made = make()\n"
                "    return made.run()\n"
                "\n"
                "if __name__ == '__main__':\n"
                "    main()\n"
            ),
        },
    )
    assert not any(finding.symbol == "run" for finding in scan(tmp_path).findings)


def test_self_attribute_store_reaches_the_function(tmp_path):
    write_tree(
        tmp_path,
        {
            "app.py": (
                "def helper():\n"
                "    return 1\n"
                "\n"
                "def func():\n"
                "    return helper()\n"
                "\n"
                "class Box:\n"
                "    def run(self):\n"
                "        self.handler = func\n"
                "        return self.handler()\n"
                "\n"
                "if __name__ == '__main__':\n"
                "    Box().run()\n"
            ),
        },
    )
    symbols = {finding.symbol for finding in scan(tmp_path).findings}
    assert "func" not in symbols
    assert "helper" not in symbols


def test_fold_marks_the_other_branch_unreachable(tmp_path):
    write_tree(
        tmp_path,
        {
            "app.py": (
                "import os\n"
                "\n"
                "def helper():\n"
                "    return 1\n"
                "\n"
                "def live():\n"
                "    return 2\n"
                "\n"
                "def main():\n"
                "    if os.getenv('ENVIRONMENT') == 'production':\n"
                "        return live()\n"
                "    return helper()\n"
                "\n"
                "if __name__ == '__main__':\n"
                "    main()\n"
            ),
        },
    )
    result = scan(tmp_path, defines={"ENVIRONMENT": "production"})
    rules = {finding.rule for finding in result.findings}
    symbols = {finding.symbol for finding in result.findings}
    assert "UNREACHABLE_CODE" in rules
    assert "live" not in symbols
    assert "helper" in symbols


def test_duplicate_bodies_are_reported(tmp_path):
    body = (
        "    item = value\n"
        "    item = item + 1\n"
        "    item = item + 1\n"
        "    item = item + 1\n"
        "    return item\n"
    )
    write_tree(
        tmp_path,
        {
            "pkg/a.py": f"def save_a(value):\n{body}",
            "pkg/b.py": "def save_b(other):\n    item = other\n    item = item + 1\n    item = item + 1\n    item = item + 1\n    return item\n",
        },
    )
    finding = next(item for item in scan(tmp_path).findings if item.rule == "DUPLICATE_CODE")
    assert finding.symbol == "save_b"
    assert finding.confidence == 82
    assert finding.status == "POSSIBLY_DUPLICATE"
    assert finding.evidence[0] == "pkg/a.py:save_a"
    assert "no incoming imports" in finding.evidence[-1]


def test_changed_limits_the_report(tmp_path, capsys):
    write_tree(
        tmp_path,
        {
            "a.py": "def old():\n    return 1\n",
            "b.py": "value = 1\nprint(value)\n",
        },
    )
    _git(tmp_path, "init")
    _git(tmp_path, "add", "a.py", "b.py")
    _git(tmp_path, "commit", "-m", "base")
    (tmp_path / "b.py").write_text("value = 1\nprint(value)\n\ndef fresh():\n    return 1\n", encoding="utf-8")
    assert main(["scan", str(tmp_path), "--changed", "--no-cache"]) == 1
    text = capsys.readouterr().out
    assert "fresh" in text
    assert "old" not in text


def test_fix_removes_an_unused_import(tmp_path, capsys):
    path = tmp_path / "app.py"
    path.write_text("import os\nimport sys\nprint(sys.version)\n", encoding="utf-8")
    assert main(["fix", str(path)]) == 0
    assert "fixed app.py:1 os" in capsys.readouterr().out
    assert path.read_text(encoding="utf-8") == "import sys\nprint(sys.version)\n"


def test_fix_leaves_a_mixed_statement(tmp_path):
    path = tmp_path / "app.py"
    path.write_text("import os; value = 1\nprint(value)\n", encoding="utf-8")
    scan_result = scan(tmp_path)
    assert any(finding.rule == "UNUSED_IMPORT" and finding.symbol == "os" for finding in scan_result.findings)
    from vyarth.fix import apply_import_fixes

    assert apply_import_fixes(tmp_path, scan_result.findings) == []
    assert "import os" in path.read_text(encoding="utf-8")


def test_workers_scan_a_directory(tmp_path):
    write_tree(
        tmp_path,
        {
            "a.py": "def dead_a():\n    return 1\n",
            "b.py": "def dead_b():\n    return 1\n",
        },
    )
    symbols = {finding.symbol for finding in scan(tmp_path, workers=2, use_cache=False).findings}
    assert {"dead_a", "dead_b"} <= symbols


def test_lsp_diagnostic_for_an_unused_function(tmp_path):
    path = tmp_path / "app.py"
    path.write_text("def helper():\n    return 1\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text("[project]\nname='demo'\nversion='0'\n", encoding="utf-8")
    payload = diagnostics_for(path.resolve().as_uri())
    codes = {item["code"] for item in payload["items"]}
    assert "UNUSED_FUNCTION" in codes
    assert payload["items"][0]["source"] == "vyarth"


def test_lsp_code_action_removes_an_unused_local(tmp_path):
    path = tmp_path / "app.py"
    path.write_text(
        "def outer():\n    value = 1\n    return 2\n\nif __name__ == '__main__':\n    outer()\n",
        encoding="utf-8",
    )
    (tmp_path / "pyproject.toml").write_text("[project]\nname='demo'\nversion='0'\n", encoding="utf-8")
    uri = path.resolve().as_uri()
    actions = code_actions_for(uri, {"start": {"line": 1, "character": 4}, "end": {"line": 1, "character": 4}})
    assert actions
    assert actions[0]["kind"] == "quickfix"
    assert actions[0]["title"] == "Remove unused variable 'value'"
    edit = actions[0]["edit"]["changes"][uri][0]
    assert edit["newText"] == ""
    response = _dispatch(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "textDocument/codeAction",
            "params": {"textDocument": {"uri": uri}, "range": {"start": {"line": 1, "character": 0}, "end": {"line": 1, "character": 0}}},
        }
    )
    assert response["result"][0]["kind"] == "quickfix"


def test_lsp_reads_a_content_length_message():
    raw = io.BytesIO()
    _write_message(raw, {"jsonrpc": "2.0", "id": 1, "method": "shutdown"})
    raw.seek(0)
    message = _read_message(raw)
    assert message["method"] == "shutdown"


def _git(root: Path, *args: str) -> None:
    env = os.environ.copy()
    env.update(
        {
            "GIT_AUTHOR_NAME": "Vyarth",
            "GIT_AUTHOR_EMAIL": "vyarth@example.com",
            "GIT_COMMITTER_NAME": "Vyarth",
            "GIT_COMMITTER_EMAIL": "vyarth@example.com",
        }
    )
    subprocess.run(["git", *args], cwd=root, check=True, capture_output=True, env=env)
