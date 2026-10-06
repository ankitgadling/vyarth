import json

from tests.conftest import write_tree
from vyarth import scan
from vyarth.cli import main


def test_framework_decorator_and_lambda_handler_are_entries(tmp_path):
    write_tree(
        tmp_path,
        {
            "vyarth.toml": '[tool.vyarth]\nframework_decorators = ["route"]\n',
            "app.py": (
                "def route(fn):\n"
                "    return fn\n"
                "\n"
                "@route\n"
                "def index():\n"
                "    return 1\n"
                "\n"
                "def lambda_handler(event, context):\n"
                "    return index()\n"
            ),
        },
    )
    result = scan(tmp_path)
    symbols = {finding.symbol for finding in result.findings}
    assert "index" not in symbols
    assert "lambda_handler" not in symbols
    assert "route" not in symbols


def test_function_called_only_from_dead_code_is_an_orphan(tmp_path):
    write_tree(
        tmp_path,
        {
            "app.py": "def live():\n    return 1\n\ndef dead():\n    return live()\n",
            "main.py": "import app\nif __name__ == '__main__':\n    print(app)\n",
        },
    )
    result = scan(tmp_path)
    found = {(finding.rule, finding.symbol, finding.status) for finding in result.findings}
    assert ("ORPHAN_FUNCTION", "live", "POSSIBLY_DEAD") in found
    assert ("UNUSED_FUNCTION", "dead", "POSSIBLY_DEAD") in found


def test_passing_a_function_as_a_value_is_not_an_orphan(tmp_path):
    write_tree(
        tmp_path,
        {
            "app.py": "def foo():\n    return 1\n\nhandlers = []\nhandlers.append(foo)\n",
            "main.py": "import app\nif __name__ == '__main__':\n    print(app)\n",
        },
    )
    result = scan(tmp_path)
    assert not any(finding.symbol == "foo" for finding in result.findings)


def test_modules_that_only_import_each_other_are_unused(tmp_path):
    write_tree(
        tmp_path,
        {
            "a.py": "import b\n",
            "b.py": "import a\n",
        },
    )
    modules = {finding.path for finding in scan(tmp_path).findings if finding.rule == "POSSIBLY_UNUSED_MODULE"}
    assert modules == {"a.py", "b.py"}


def test_getattr_lowers_unused_function_confidence(tmp_path):
    write_tree(
        tmp_path,
        {
            "app.py": (
                "def helper():\n"
                "    return 1\n"
                "\n"
                "def main():\n"
                "    return 1\n"
                "\n"
                "getattr(object(), 'missing', None)\n"
                "\n"
                "if __name__ == '__main__':\n"
                "    main()\n"
            ),
        },
    )
    finding = next(item for item in scan(tmp_path).findings if item.symbol == "helper")
    assert finding.rule == "UNUSED_FUNCTION"
    assert finding.status == "POSSIBLY_DEAD"
    assert finding.confidence == 96
    assert "No references found." in finding.evidence


def test_unused_requirement_is_reported(tmp_path):
    write_tree(
        tmp_path,
        {
            "requirements.txt": "old-package==1\npathspec>=0.12\n",
            "app.py": "import pathspec\npathspec\n",
            "main.py": "import app\nif __name__ == '__main__':\n    print(app)\n",
        },
    )
    finding = next(item for item in scan(tmp_path).findings if item.rule == "UNUSED_DEPENDENCY")
    assert finding.symbol == "old-package"
    assert finding.confidence == 95
    assert finding.status == "POSSIBLY_DEAD"
    assert "requirements.txt" in finding.evidence[0]


def test_pyproject_script_keeps_the_call_graph_alive(tmp_path):
    write_tree(
        tmp_path,
        {
            "pyproject.toml": '[project]\nname = "demo"\nversion = "0.1"\n\n[project.scripts]\ndemo = "pkg.cli:main"\n',
            "pkg/__init__.py": "",
            "pkg/cli.py": "def main():\n    return helper()\n\ndef helper():\n    return 1\n",
        },
    )
    assert scan(tmp_path).findings == ()


def test_src_scan_reads_parent_console_scripts(tmp_path):
    write_tree(
        tmp_path,
        {
            "pyproject.toml": (
                '[project]\nname = "demo"\nversion = "0.1"\n\n'
                '[project.entry-points.console_scripts]\n'
                'demo = "pkg.cli:main"\n'
            ),
            "other.py": "def outside():\n    return 1\n",
            "src/pkg/__init__.py": "",
            "src/pkg/cli.py": "def main():\n    return helper()\n\ndef helper():\n    return 1\n",
        },
    )
    result = scan(tmp_path / "src")
    assert result.files_scanned == 2
    assert result.findings == ()


def test_a_test_import_keeps_the_module_alive(tmp_path):
    write_tree(
        tmp_path,
        {
            "app.py": "def live():\n    return 1\n",
            "tests/test_app.py": "from app import live\n\ndef test_live():\n    assert live() == 1\n",
        },
    )
    result = scan(tmp_path)
    assert result.findings == ()


def test_baseline_filter_and_formats(tmp_path, capsys):
    write_tree(
        tmp_path,
        {"app.py": "def helper():\n    return 1\n"},
    )
    assert main(["baseline", str(tmp_path), "--output", "vyarth-baseline.json"]) == 0
    assert (tmp_path / "vyarth-baseline.json").is_file()
    assert main(["scan", str(tmp_path), "--baseline", str(tmp_path / "vyarth-baseline.json")]) == 0
    assert "UNUSED_FUNCTION" not in capsys.readouterr().out

    assert main(["scan", str(tmp_path), "--format", "github"]) == 1
    github = capsys.readouterr().out
    assert github.startswith("::error file=app.py,line=")
    assert "title=UNUSED_FUNCTION::" in github

    assert main(["scan", str(tmp_path), "--format", "sarif"]) == 1
    sarif = json.loads(capsys.readouterr().out)
    assert sarif["version"] == "2.1.0"
    result = next(item for item in sarif["runs"][0]["results"] if item["ruleId"] == "UNUSED_FUNCTION")
    assert result["level"] == "warning"
    assert result["partialFingerprints"]["vyarth/fingerprint"].startswith("UNUSED_FUNCTION:app.py:")


def test_fail_on_high_keeps_medium_findings_and_exits_zero(tmp_path, capsys):
    write_tree(
        tmp_path,
        {
            "pkg/__init__.py": "",
            "pkg/orphan.py": "",
            "main.py": "import pkg\nif __name__ == '__main__':\n    print(pkg)\n",
        },
    )
    assert main(["scan", str(tmp_path), "--fail-on", "high"]) == 0
    text = capsys.readouterr().out
    assert "POSSIBLY_UNUSED_MODULE" in text


def test_fixture_and_ready_are_entries(tmp_path):
    write_tree(
        tmp_path,
        {
            "app.py": (
                "def fixture(fn):\n"
                "    return fn\n"
                "\n"
                "@fixture\n"
                "def widget():\n"
                "    return 1\n"
                "\n"
                "class AppConfig:\n"
                "    def ready(self):\n"
                "        return widget()\n"
                "\n"
                "AppConfig()\n"
            ),
        },
    )
    assert {finding.symbol for finding in scan(tmp_path).findings}.isdisjoint({"widget", "ready", "fixture"})


def test_setup_pipfile_poetry_and_uv_dependencies(tmp_path):
    write_tree(
        tmp_path,
        {
            "setup.py": "setup(install_requires=['left-package'])\n",
            "Pipfile": '[packages]\nright-package = "*"\n',
            "pyproject.toml": (
                "[tool.poetry.dependencies]\n"
                "python = '^3.11'\n"
                "missing-poetry = '*'\n"
                "\n"
                "[tool.uv]\n"
                "dev-dependencies = ['missing-uv']\n"
            ),
            "main.py": "value = 1\nif __name__ == '__main__':\n    print(value)\n",
        },
    )
    symbols = {finding.symbol for finding in scan(tmp_path).findings if finding.rule == "UNUSED_DEPENDENCY"}
    assert symbols == {"left-package", "right-package", "missing-poetry", "missing-uv"}


def test_importlib_lowers_unused_module_confidence(tmp_path):
    write_tree(
        tmp_path,
        {
            "dyn.py": "import importlib\nimportlib.import_module('missing')\n",
            "lone.py": "VALUE = 1\n",
            "main.py": "import dyn\nif __name__ == '__main__':\n    print(dyn)\n",
        },
    )
    finding = next(item for item in scan(tmp_path).findings if item.path == "lone.py")
    assert finding.rule == "POSSIBLY_UNUSED_MODULE"
    assert finding.confidence == 60
    assert finding.message == "No incoming imports detected."
