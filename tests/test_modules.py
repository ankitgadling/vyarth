from pathlib import Path

from tests.conftest import write_tree
from vyarth import scan
from vyarth.discover import module_names, package_roots


def _modules(root) -> set[str]:
    result = scan(root)
    return {finding.path for finding in result.findings if finding.rule == "POSSIBLY_UNUSED_MODULE"}


def test_imported_modules_and_entry_files_are_kept(tmp_path):
    write_tree(
        tmp_path,
        {
            "pkg/__init__.py": "from . import a\na\n",
            "pkg/a.py": "from . import b\nb\n",
            "pkg/b.py": "VALUE = 1\n",
            "pkg/c.py": "VALUE = 1\n",
            "main.py": "import pkg\nif __name__ == '__main__':\n    print(pkg)\n",
            "wsgi.py": "app = None\n",
            "asgi.py": "",
            "manage.py": "",
            "__main__.py": "",
        },
    )
    result = scan(tmp_path)
    modules = {finding.path for finding in result.findings if finding.rule == "POSSIBLY_UNUSED_MODULE"}
    assert modules == {"pkg/c.py"}
    module = next(finding for finding in result.findings if finding.path == "pkg/c.py" and finding.rule == "POSSIBLY_UNUSED_MODULE")
    assert module.confidence == 82
    assert module.status == "POSSIBLY_UNUSED_MODULE"
    assert module.message == "No incoming imports detected."


def test_src_file_has_both_import_names(tmp_path):
    path = tmp_path / "src" / "account" / "cache.py"
    path.parent.mkdir(parents=True)
    path.write_text("value = 1\n", encoding="utf-8")
    assert module_names(path, package_roots(tmp_path)) == ["account.cache", "src.account.cache"]


def test_src_layout_resolves_package_imports(tmp_path):
    write_tree(
        tmp_path,
        {
            "src/app/__init__.py": "from . import kept\nkept\n",
            "src/app/kept.py": "VALUE = 1\n",
            "src/app/old.py": "VALUE = 1\n",
            "main.py": "import app\nif __name__ == '__main__':\n    print(app)\n",
        },
    )
    assert _modules(tmp_path) == {"src/app/old.py"}


def test_src_prefix_import_leaves_an_uncalled_function(tmp_path):
    write_tree(
        tmp_path,
        {
            "src/account/__init__.py": "",
            "src/account/cache.py": (
                "def invalidate_account_cache(tenant_id):\n"
                "    return tenant_id\n"
                "\n"
                "def set_cached_account(tenant_id):\n"
                "    return tenant_id\n"
            ),
            "src/main.py": (
                "from src.account.cache import invalidate_account_cache\n"
                "\n"
                "if __name__ == '__main__':\n"
                "    invalidate_account_cache('tenant')\n"
            ),
        },
    )
    result = scan(tmp_path)
    found = {(finding.rule, finding.symbol, finding.confidence) for finding in result.findings}
    assert ("UNUSED_FUNCTION", "invalidate_account_cache", 96) not in found
    assert ("UNUSED_FUNCTION", "set_cached_account", 96) in found
    assert "src/account/cache.py" not in _modules(tmp_path)


def test_src_prefix_import_reaches_the_defined_function(tmp_path):
    write_tree(
        tmp_path,
        {
            "src/account/__init__.py": "",
            "src/account/cache.py": "def invalidate_account_cache(tenant_id):\n    return tenant_id\n",
            "src/account/dao/__init__.py": "",
            "src/account/dao/acc_dao_v2.py": (
                "from src.account.cache import invalidate_account_cache\n"
                "\n"
                "def save(tenant):\n"
                "    return invalidate_account_cache(tenant)\n"
            ),
            "src/main.py": (
                "from src.account.dao.acc_dao_v2 import save\n"
                "\n"
                "if __name__ == '__main__':\n"
                "    save('tenant')\n"
            ),
        },
    )
    result = scan(tmp_path)
    assert "invalidate_account_cache" not in {finding.symbol for finding in result.findings}
    assert "src/account/cache.py" not in _modules(tmp_path)
    assert "src/account/dao/acc_dao_v2.py" not in _modules(tmp_path)


def test_test_files_and_gitignored_files_are_not_scanned(tmp_path):
    write_tree(
        tmp_path,
        {
            ".gitignore": "secret/\n",
            "secret/hidden.py": "def hidden():\n    return 1\n",
            "shown.py": "def shown():\n    return 1\n",
            "test_something.py": "def orphan_test():\n    return 1\n",
            "pkg/widget_test.py": "def hidden_widget():\n    return 1\n",
            "tests/test_more.py": "def also():\n    return 1\n",
        },
    )
    result = scan(tmp_path)
    symbols = {finding.symbol for finding in result.findings}
    assert "shown" in symbols
    assert "hidden" not in symbols
    assert "orphan_test" not in symbols
    assert "hidden_widget" not in symbols
    assert "also" not in symbols


def test_a_used_import_marks_the_definition_used(tmp_path):
    write_tree(
        tmp_path,
        {
            "pkg/__init__.py": "from .api import run\n",
            "pkg/api.py": "def run():\n    return 1\n",
            "main.py": "from pkg.api import run\nif __name__ == '__main__':\n    print(run())\n",
        },
    )
    result = scan(tmp_path)
    assert not any(finding.rule == "UNUSED_FUNCTION" and finding.symbol == "run" for finding in result.findings)
    assert not any(finding.rule == "POSSIBLY_UNUSED_MODULE" for finding in result.findings)


def test_an_unused_import_does_not_keep_the_definition_alive(tmp_path):
    write_tree(
        tmp_path,
        {
            "pkg/__init__.py": "",
            "pkg/api.py": "def dead():\n    return 1\n",
            "pkg/other.py": "from .api import dead\n",
            "main.py": "import pkg.other\nif __name__ == '__main__':\n    print(pkg.other)\n",
        },
    )
    result = scan(tmp_path)
    found = {(finding.rule, finding.path, finding.symbol) for finding in result.findings}
    assert ("UNUSED_FUNCTION", "pkg/api.py", "dead") in found
    assert ("UNUSED_IMPORT", "pkg/other.py", "dead") in found


def test_all_reexport_counts_as_a_use(tmp_path):
    write_tree(
        tmp_path,
        {
            "pkg/__init__.py": "from .api import run\n__all__ = ['run']\n",
            "pkg/api.py": "def run():\n    return 1\n",
            "main.py": "import pkg\nif __name__ == '__main__':\n    print(pkg)\n",
        },
    )
    result = scan(tmp_path)
    assert not any(finding.symbol == "run" for finding in result.findings)


def test_dev_extra_tools_are_importable():
    import mypy
    import ruff

    assert mypy.__name__ == "mypy"
    assert ruff.__name__ == "ruff"


def test_scanning_this_package_does_not_flag_its_public_api():
    root = Path(__file__).resolve().parents[1]
    result = scan(root)
    own = [finding for finding in result.findings if not finding.path.startswith("examples/")]
    assert result.errors == ()
    assert own == []


def test_syntax_error_does_not_abort_the_scan(tmp_path):
    write_tree(
        tmp_path,
        {
            "good.py": "def used():\n    return 1\nused()\n",
            "bad.py": "def (\n",
        },
    )
    result = scan(tmp_path)
    assert result.files_scanned == 1
    assert len(result.errors) == 1
    assert result.errors[0].path == "bad.py"
    assert result.errors[0].line >= 1
