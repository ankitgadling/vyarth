import io
import json
import warnings

import pytest

from tests.conftest import write_tree
from tests.test_phase3 import _git
from vyarth import scan
from vyarth.cli import main
from vyarth.config import Config, load_config
from vyarth.confidence import REEXPORT_NOTE, SIDE_EFFECT_NOTE
from vyarth.fix import apply_fixes
from vyarth.lsp import _dispatch, _write_message, diagnostics_for, serve


def test_package_reexport_is_not_removed(tmp_path, capsys):
    write_tree(
        tmp_path,
        {
            "pkg/__init__.py": "from .core import helper\n",
            "pkg/core.py": "def helper():\n    return 1\n",
            "main.py": "import pkg\nif __name__ == '__main__':\n    print(pkg)\n",
        },
    )
    finding = next(item for item in scan(tmp_path).findings if item.rule == "UNUSED_IMPORT" and item.symbol == "helper")
    assert finding.confidence == 70
    assert finding.status == "POSSIBLY_DEAD"
    assert REEXPORT_NOTE in finding.evidence
    init = tmp_path / "pkg" / "__init__.py"
    assert apply_fixes(tmp_path, scan(tmp_path).findings) == []
    assert "helper" in init.read_text(encoding="utf-8")
    assert main(["fix", str(tmp_path), "--dry-run", "--quiet"]) == 1
    assert "would fix" not in capsys.readouterr().out
    assert "helper" in init.read_text(encoding="utf-8")
    assert main(["fix", str(tmp_path), "--unsafe", "--quiet"]) == 1
    assert "from .core import helper" not in init.read_text(encoding="utf-8")


def test_side_effect_import_is_not_removed(tmp_path):
    write_tree(
        tmp_path,
        {
            "pkg/__init__.py": "",
            "pkg/signals.py": "VALUE = 1\n",
            "app.py": "import pkg.signals\n",
            "main.py": "import app\nif __name__ == '__main__':\n    print(app)\n",
        },
    )
    finding = next(item for item in scan(tmp_path).findings if item.rule == "UNUSED_IMPORT" and item.symbol == "pkg")
    assert finding.confidence == 70
    assert SIDE_EFFECT_NOTE in finding.evidence
    assert apply_fixes(tmp_path, scan(tmp_path).findings) == []
    assert "import pkg.signals" in (tmp_path / "app.py").read_text(encoding="utf-8")


def test_fix_diff_does_not_write(tmp_path, capsys):
    path = tmp_path / "app.py"
    path.write_text("import os\nimport sys\nprint(sys.version)\n", encoding="utf-8")
    assert main(["fix", str(path), "--diff", "--quiet"]) == 1
    diff = capsys.readouterr().out
    assert "-import os" in diff
    assert "import os" in path.read_text(encoding="utf-8")


def test_capped_nested_function_is_not_dead(tmp_path):
    write_tree(
        tmp_path,
        {
            "lone.py": "def outer():\n    def buried():\n        return 1\n    return 1\n",
            "main.py": "if __name__ == '__main__':\n    print(1)\n",
        },
    )
    finding = next(item for item in scan(tmp_path).findings if item.symbol == "buried")
    assert finding.confidence == 82
    assert finding.status == "POSSIBLY_DEAD"


def test_conftest_and_pytest_hooks_are_entries(tmp_path):
    write_tree(
        tmp_path,
        {
            "conftest.py": "def pytest_configure(config):\n    return config\n",
            "plugin.py": "def pytest_addoption(parser):\n    return parser\n",
            "main.py": "import plugin\nif __name__ == '__main__':\n    print(plugin)\n",
        },
    )
    symbols = {finding.symbol for finding in scan(tmp_path).findings}
    assert "pytest_configure" not in symbols
    assert "pytest_addoption" not in symbols


def test_framework_presets_and_ignore_lists(tmp_path):
    write_tree(
        tmp_path,
        {
            "app/settings.py": "SECRET = 1\n",
            "app/urls.py": "urlpatterns = []\n",
            "app/tasks.py": "beat_schedule = {'daily': {}}\n\ndef hidden():\n    return 1\n",
            "app/models.py": (
                "def validator(fn):\n"
                "    return fn\n"
                "\n"
                "class User(BaseModel):\n"
                "    @validator\n"
                "    def clean(self):\n"
                "        return helper()\n"
                "\n"
                "def helper():\n"
                "    return 1\n"
            ),
            "app/plugin.py": (
                "class BasePlugin:\n"
                "    pass\n"
                "\n"
                "class Plugin(BasePlugin):\n"
                "    def run(self):\n"
                "        return kept()\n"
                "\n"
                "def kept():\n"
                "    return 1\n"
                "\n"
                "def skipped():\n"
                "    return 1\n"
            ),
            "main.py": "import app.plugin\nif __name__ == '__main__':\n    print(app.plugin)\n",
        },
    )
    config = Config(
        frameworks=("django", "pydantic", "celery"),
        ignore_names=("skipped",),
        ignore_bases=("BasePlugin",),
    )
    symbols = {finding.symbol for finding in scan(tmp_path, config=config).findings}
    assert "urlpatterns" not in symbols
    assert "beat_schedule" not in symbols
    assert "clean" not in symbols
    assert "helper" not in symbols
    assert "run" not in symbols
    assert "kept" not in symbols
    assert "skipped" not in symbols
    modules = {finding.path for finding in scan(tmp_path, config=config).findings if finding.rule == "POSSIBLY_UNUSED_MODULE"}
    assert "app/settings.py" not in modules


def test_namespace_and_runtime_dependencies(tmp_path, monkeypatch):
    monkeypatch.setattr("vyarth.dependencies._distribution_map", lambda: {})
    write_tree(
        tmp_path,
        {
            "requirements.txt": "zope.interface\ngoogle-cloud-storage\ngunicorn\n",
            "app.py": "import zope.interface\nimport google\nzope.interface\ngoogle\n",
            "main.py": "import app\nif __name__ == '__main__':\n    print(app)\n",
        },
    )
    findings = {item.symbol: item for item in scan(tmp_path).findings if item.rule == "UNUSED_DEPENDENCY"}
    assert "zope-interface" not in findings
    assert findings["google-cloud-storage"].confidence == 70
    assert findings["gunicorn"].confidence == 70


def test_nested_gitignore_and_info_exclude(tmp_path):
    write_tree(
        tmp_path,
        {
            "pkg/.gitignore": "hidden.py\n",
            "pkg/hidden.py": "def hidden():\n    return 1\n",
            "pkg/keep.py": "def kept():\n    return 1\n",
            "secret.py": "def secret():\n    return 1\n",
            "shown.py": "def shown():\n    return 1\n",
        },
    )
    exclude = tmp_path / ".git" / "info"
    exclude.mkdir(parents=True)
    (exclude / "exclude").write_text("secret.py\n", encoding="utf-8")
    symbols = {finding.symbol for finding in scan(tmp_path).findings}
    assert "hidden" not in symbols
    assert "secret" not in symbols
    assert "kept" in symbols
    assert "shown" in symbols


def test_nested_gitignore_can_unignore(tmp_path):
    write_tree(
        tmp_path,
        {
            ".gitignore": "*.log\n",
            "pkg/.gitignore": "!keep.log\n",
            "pkg/keep.log": "not python\n",
            "pkg/keep.py": "def kept():\n    return 1\n",
            "pkg/skip.py": "def skipped():\n    return 1\n",
        },
    )
    (tmp_path / "pkg" / ".gitignore").write_text("skip.py\n!keep.py\n", encoding="utf-8")
    symbols = {finding.symbol for finding in scan(tmp_path).findings}
    assert "skipped" not in symbols
    assert "kept" in symbols


def test_cache_markers_and_prune(tmp_path):
    write_tree(
        tmp_path,
        {
            "a.py": "def dead_a():\n    return 1\n",
            "b.py": "def dead_b():\n    return 1\n",
        },
    )
    scan(tmp_path)
    assert (tmp_path / ".vyarth" / ".gitignore").read_text(encoding="utf-8") == "*\n"
    assert "Signature:" in (tmp_path / ".vyarth" / "CACHEDIR.TAG").read_text(encoding="utf-8")
    (tmp_path / "b.py").unlink()
    scan(tmp_path)
    stored = _cached_index_paths(tmp_path)
    assert all(not item.endswith("b.py") for item in stored)
    assert any(item.endswith("a.py") for item in stored)
    manifest = json.loads((tmp_path / ".vyarth" / "cache" / "manifest.json").read_text(encoding="utf-8"))
    assert "b.py" not in manifest["files"]
    assert "a.py" in manifest["files"]


def test_cache_keeps_findings_after_the_project_moves(tmp_path):
    origin = tmp_path / "proj"
    write_tree(
        origin,
        {
            "app/__init__.py": "",
            "app/service.py": "def run():\n    return 1\n\ndef spare():\n    return 2\n",
            "main.py": (
                "import app.service\n"
                "\n"
                "def main():\n"
                "    return app.service.run()\n"
                "\n"
                "if __name__ == '__main__':\n"
                "    main()\n"
            ),
        },
    )
    scan(origin)
    moved = tmp_path / "proj2"
    origin.rename(moved)
    result = scan(moved)
    spare = [item for item in result.findings if item.symbol == "spare"]
    assert len(spare) == 1
    assert spare[0].path == "app/service.py"
    assert not any(item.symbol == "run" for item in result.findings)
    stored = _cached_index_paths(moved)
    assert stored
    assert all(str(moved) in item for item in stored)


def test_unwritable_cache_does_not_fail_the_scan(tmp_path, monkeypatch):
    write_tree(tmp_path, {"a.py": "def dead():\n    return 1\n"})

    def deny(*_args, **_kwargs):
        raise PermissionError("read-only")

    monkeypatch.setattr("vyarth.incremental.ensure_cache_markers", deny)
    result = scan(tmp_path)
    assert any(item.symbol == "dead" for item in result.findings)


def test_config_validation(tmp_path):
    (tmp_path / "vyarth.toml").write_text("typo = 1\nmin_confidence = 0\n", encoding="utf-8")
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        load_config(tmp_path)
    assert any("typo" in str(item.message) for item in caught)
    (tmp_path / "vyarth.toml").write_text("min_confidence = 101\n", encoding="utf-8")
    try:
        load_config(tmp_path)
    except ValueError as exc:
        assert "between 0 and 100" in str(exc)
    else:
        raise AssertionError("expected min_confidence to be rejected")
    (tmp_path / "vyarth.toml").write_text("duplicate_min_statements = 0\n", encoding="utf-8")
    try:
        load_config(tmp_path)
    except ValueError as exc:
        assert "positive" in str(exc)
    else:
        raise AssertionError("expected duplicate_min_statements to be rejected")


def test_cli_version_concise_exclude_and_missing_file(tmp_path, capsys, monkeypatch):
    with pytest.raises(SystemExit) as raised:
        main(["--version"])
    assert raised.value.code == 0
    assert "vyarth 0.1.0" in capsys.readouterr().out
    write_tree(
        tmp_path,
        {
            "app.py": "def helper():\n    return 1\n",
            "skip.py": "def skipped():\n    return 1\n",
        },
    )
    assert main(["scan", str(tmp_path), "--format", "concise", "--exclude", "skip.py", "--quiet"]) == 1
    text = capsys.readouterr().out
    assert "app.py:1:1: UNUSED_FUNCTION" in text
    assert "skipped" not in text
    assert "vyarth:" not in capsys.readouterr().err

    def boom(*_args, **_kwargs):
        raise FileNotFoundError("app.py")

    monkeypatch.setattr("vyarth.cli.scan", boom)
    assert main(["scan", str(tmp_path / "app.py"), "--quiet"]) == 2
    err = capsys.readouterr().err
    assert "file not found" in err
    assert "baseline not found" not in err


def test_github_paths_include_the_git_prefix(tmp_path, capsys):
    write_tree(
        tmp_path,
        {
            "svc/pyproject.toml": "[project]\nname = 'svc'\nversion = '0'\n",
            "svc/app.py": "def helper():\n    return 1\n",
        },
    )
    _git(tmp_path, "init")
    assert main(["scan", str(tmp_path / "svc"), "--format", "github", "--quiet"]) == 1
    assert "file=svc/app.py,line=" in capsys.readouterr().out


def test_lsp_did_open_uses_document_text(tmp_path):
    path = tmp_path / "app.py"
    path.write_text("def helper():\n    return 1\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text("[project]\nname = 'demo'\nversion = '0'\n", encoding="utf-8")
    uri = path.resolve().as_uri()
    _dispatch(
        {
            "jsonrpc": "2.0",
            "method": "textDocument/didOpen",
            "params": {"textDocument": {"uri": uri, "text": "value = 1\n"}},
        }
    )
    codes = {item["code"] for item in diagnostics_for(uri)["items"]}
    assert "UNUSED_FUNCTION" not in codes
    assert "UNUSED_VARIABLE" in codes


def test_lsp_bad_json_keeps_the_server_alive():
    bad = b"not-json"
    shutdown = io.BytesIO()
    _write_message(shutdown, {"jsonrpc": "2.0", "id": 2, "method": "shutdown"})
    raw = io.BytesIO(f"Content-Length: {len(bad)}\r\n\r\n".encode("ascii") + bad + shutdown.getvalue())
    raw.seek(0)
    out = io.BytesIO()
    serve(raw, out)
    text = out.getvalue().decode("utf-8")
    assert "-32700" in text
    assert '"id": 2' in text or '"id":2' in text


def test_lsp_publishes_diagnostics(tmp_path):
    path = tmp_path / "app.py"
    path.write_text("def helper():\n    return 1\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text("[project]\nname = 'demo'\nversion = '0'\n", encoding="utf-8")
    uri = path.resolve().as_uri()
    opened = io.BytesIO()
    _write_message(
        opened,
        {
            "jsonrpc": "2.0",
            "method": "textDocument/didOpen",
            "params": {"textDocument": {"uri": uri, "languageId": "python", "version": 1, "text": path.read_text(encoding="utf-8")}},
        },
    )
    opened.seek(0)
    out = io.BytesIO()
    serve(opened, out)
    body = out.getvalue().decode("utf-8")
    assert "textDocument/publishDiagnostics" in body
    assert "UNUSED_FUNCTION" in body


def _cached_index_paths(root) -> list[str]:
    stored = []
    for path in (root / ".vyarth" / "cache").rglob("*.json"):
        payload = json.loads(path.read_text(encoding="utf-8"))
        index = payload.get("index") if isinstance(payload, dict) else None
        if isinstance(index, dict) and isinstance(index.get("path"), str):
            stored.append(index["path"])
    return stored


def _forbid_reparse(monkeypatch) -> None:
    def deny(*_args, **_kwargs):
        raise AssertionError("cached scan parsed a file")

    monkeypatch.setattr("vyarth.engine.PythonAstBackend.index_source", deny)
    monkeypatch.setattr("vyarth.engine.load_cached", deny)


def test_unchanged_scan_reuses_findings_without_parsing(tmp_path, monkeypatch):
    write_tree(
        tmp_path,
        {
            "app.py": (
                "def public():\n"
                "    return 1\n"
                "\n"
                "def _private():\n"
                "    return 2\n"
                "\n"
                "if __name__ == '__main__':\n"
                "    pass\n"
            ),
        },
    )
    first = scan(tmp_path)
    _forbid_reparse(monkeypatch)
    second = scan(tmp_path)
    assert second.findings == first.findings
    assert second.errors == first.errors
    assert second.files_scanned == first.files_scanned
    assert {item.symbol: item.confidence for item in second.findings} == {"public": 60, "_private": 96}
    assert all(item.evidence for item in second.findings)


def test_editing_a_reached_function_invalidates_the_result(tmp_path):
    write_tree(
        tmp_path,
        {
            "app.py": (
                "def helper():\n"
                "    return 1\n"
                "\n"
                "def main():\n"
                "    return helper()\n"
                "\n"
                "if __name__ == '__main__':\n"
                "    main()\n"
            ),
        },
    )
    assert not any(item.symbol == "helper" for item in scan(tmp_path).findings)
    (tmp_path / "app.py").write_text(
        "def helper():\n    return 1\n\ndef main():\n    return 1\n\nif __name__ == '__main__':\n    main()\n",
        encoding="utf-8",
    )
    assert any(item.symbol == "helper" for item in scan(tmp_path).findings)


def test_editing_pyproject_dependencies_invalidates_the_result(tmp_path):
    write_tree(
        tmp_path,
        {
            "pyproject.toml": "[project]\nname = 'demo'\nversion = '0'\ndependencies = []\n",
            "app.py": "def used():\n    return 1\n\nif __name__ == '__main__':\n    used()\n",
        },
    )
    assert not any(item.rule == "UNUSED_DEPENDENCY" for item in scan(tmp_path).findings)
    (tmp_path / "pyproject.toml").write_text(
        "[project]\nname = 'demo'\nversion = '0'\ndependencies = ['requests']\n",
        encoding="utf-8",
    )
    dependencies = {item.symbol for item in scan(tmp_path).findings if item.rule == "UNUSED_DEPENDENCY"}
    assert "requests" in dependencies


def test_example_requirements_edit_does_not_reparse(tmp_path, monkeypatch):
    write_tree(
        tmp_path,
        {
            "pyproject.toml": "[project]\nname = 'demo'\nversion = '0'\n",
            "app.py": "def used():\n    return 1\n\nif __name__ == '__main__':\n    used()\n",
            "examples/celery/requirements.txt": "amqp\n",
            "node_modules/left-pad/requirements.txt": "leftpad\n",
        },
    )
    first = scan(tmp_path)
    assert not any(item.symbol in {"amqp", "leftpad"} for item in first.findings)
    (tmp_path / "examples" / "celery" / "requirements.txt").write_text("kombu\n", encoding="utf-8")
    _forbid_reparse(monkeypatch)
    second = scan(tmp_path)
    assert second.findings == first.findings
    assert not any(item.symbol in {"amqp", "kombu", "leftpad"} for item in second.findings)


def test_cached_scan_replays_confidence_baseline_and_changed(tmp_path, monkeypatch):
    write_tree(
        tmp_path,
        {
            "a.py": "def public():\n    return 1\n\ndef _private():\n    return 2\n\nif __name__ == '__main__':\n    pass\n",
            "b.py": "def other():\n    return 3\n\nif __name__ == '__main__':\n    pass\n",
        },
    )
    first = scan(tmp_path)
    from vyarth.baseline import write_baseline

    baseline = tmp_path / "baseline.json"
    write_baseline(baseline, [item for item in first.findings if item.path == "b.py"])
    _forbid_reparse(monkeypatch)
    narrowed = scan(tmp_path, min_confidence=90)
    assert {item.symbol for item in narrowed.findings} == {"_private"}
    assert narrowed.files_scanned == first.files_scanned
    baselined = scan(tmp_path, baseline=baseline)
    assert not any(item.path == "b.py" for item in baselined.findings)
    assert any(item.symbol == "public" for item in baselined.findings)
    monkeypatch.setattr("vyarth.engine.changed_python_files", lambda *_args, **_kwargs: {"a.py"})
    changed = scan(tmp_path, changed=True)
    assert {item.path for item in changed.findings} == {"a.py"}
    assert changed.files_scanned == first.files_scanned


def test_defines_change_invalidates_the_result(tmp_path):
    write_tree(
        tmp_path,
        {
            "app.py": (
                "def dead():\n"
                "    return 1\n"
                "\n"
                "def main():\n"
                "    if COUNT == 1:\n"
                "        dead()\n"
                "\n"
                "if __name__ == '__main__':\n"
                "    main()\n"
            ),
        },
    )
    reached = scan(tmp_path, defines={"COUNT": "1"})
    assert not any(item.symbol == "dead" for item in reached.findings)
    folded = scan(tmp_path, defines={"COUNT": "0"})
    assert any(item.symbol == "dead" for item in folded.findings)
