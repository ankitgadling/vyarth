import io
import json
import os
from pathlib import Path
import subprocess

import pytest

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


def test_sarif_paths_include_the_git_prefix(tmp_path, capsys):
    write_tree(
        tmp_path,
        {
            "svc/pyproject.toml": "[project]\nname = 'svc'\nversion = '0'\n",
            "svc/app.py": "def dead():\n    return 1\n",
        },
    )
    _git(tmp_path, "init")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-m", "base")
    assert main(["scan", str(tmp_path / "svc"), "--format", "sarif", "--quiet"]) == 1
    sarif = json.loads(capsys.readouterr().out)
    result = next(item for item in sarif["runs"][0]["results"] if item["ruleId"] == "UNUSED_FUNCTION")
    location = result["locations"][0]["physicalLocation"]["artifactLocation"]
    assert location["uri"] == "svc/app.py"
    assert location["uriBaseId"] == "%SRCROOT%"


def test_changed_from_uses_the_merge_base(tmp_path):
    from vyarth.incremental import changed_python_files

    write_tree(tmp_path, {"a.py": "x = 1\n", "b.py": "y = 1\n"})
    _git(tmp_path, "init", "-b", "main")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-m", "base")
    _git(tmp_path, "checkout", "-b", "feature")
    _git(tmp_path, "checkout", "main")
    (tmp_path / "a.py").write_text("x = 2\n", encoding="utf-8")
    _git(tmp_path, "add", "a.py")
    _git(tmp_path, "commit", "-m", "main moves")
    _git(tmp_path, "checkout", "feature")
    assert changed_python_files(tmp_path, "main") == set()
    (tmp_path / "café.py").write_text("z = 1\n", encoding="utf-8")
    assert "café.py" in changed_python_files(tmp_path, "main")


def test_changed_includes_files_below_the_git_root(tmp_path, capsys):
    write_tree(
        tmp_path,
        {
            "svc/pyproject.toml": "[project]\nname = 'svc'\nversion = '0'\n",
            "svc/kept.py": "def old():\n    return 1\n",
            "svc/edited.py": "def stale():\n    return 1\n",
            "other.py": "def outside():\n    return 1\n",
        },
    )
    _git(tmp_path, "init")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-m", "base")
    (tmp_path / "svc" / "edited.py").write_text("def fresh():\n    return 1\n", encoding="utf-8")
    (tmp_path / "svc" / "new.py").write_text("def added():\n    return 1\n", encoding="utf-8")
    assert main(["scan", str(tmp_path / "svc"), "--changed", "--no-cache"]) == 1
    text = capsys.readouterr().out
    assert "fresh" in text
    assert "added" in text
    assert "old" not in text
    assert "outside" not in text


def test_changed_warns_when_python_edits_are_outside_the_project(tmp_path, capsys):
    write_tree(
        tmp_path,
        {
            "svc/pyproject.toml": "[project]\nname = 'svc'\nversion = '0'\n",
            "svc/kept.py": "def old():\n    return 1\n",
            "other.py": "def outside():\n    return 1\n",
        },
    )
    _git(tmp_path, "init")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-m", "base")
    (tmp_path / "other.py").write_text("def outside():\n    return 2\n", encoding="utf-8")
    assert main(["scan", str(tmp_path / "svc"), "--changed", "--no-cache"]) == 0
    assert "none are inside this project" in capsys.readouterr().err


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


def test_lsp_did_close_forgets_the_buffer(tmp_path):
    from vyarth.lsp import _buffers

    path = tmp_path / "app.py"
    path.write_text("x = 1\n", encoding="utf-8")
    uri = path.resolve().as_uri()
    _dispatch({"method": "textDocument/didOpen", "params": {"textDocument": {"uri": uri, "text": "y = 2\n"}}})
    assert path.resolve() in _buffers
    _dispatch({"method": "textDocument/didClose", "params": {"textDocument": {"uri": uri}}})
    assert path.resolve() not in _buffers


def test_lsp_missing_content_length_is_an_error():
    with pytest.raises(ValueError, match="Content-Length"):
        _read_message(io.BytesIO(b"\r\n"))


def test_lsp_unknown_method_is_not_found():
    response = _dispatch({"jsonrpc": "2.0", "id": 9, "method": "nope"})
    assert response["error"]["code"] == -32601


def test_lsp_column_is_a_utf16_code_unit(tmp_path):
    path = tmp_path / "app.py"
    path.write_text("def f():\n    x = 'é'; unused = 1\n    return x\n\nf()\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text("[project]\nname='demo'\nversion='0'\n", encoding="utf-8")
    payload = diagnostics_for(path.resolve().as_uri())
    unused = next(item for item in payload["items"] if "unused" in item["message"])
    assert unused["range"]["start"]["character"] == 13


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
