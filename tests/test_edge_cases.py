"""Regressions for the residual reachability, scoring, fix, and manifest edges."""

import ast

from vyarth import scan
from vyarth.fix import apply_fixes
from vyarth.python_index import PythonAstBackend

from tests.conftest import write_tree


def _named(result, symbol):
    return [finding for finding in result.findings if finding.symbol == symbol]


def _rules(result, symbol):
    return {finding.rule for finding in _named(result, symbol)}


def test_dead_branch_call_is_unused_not_orphan(tmp_path):
    write_tree(
        tmp_path,
        {
            "app.py": (
                "def dead():\n"
                "    return 1\n"
                "\n"
                "def folded():\n"
                "    return 2\n"
                "\n"
                "def live():\n"
                "    return 3\n"
                "\n"
                "def main():\n"
                "    if False:\n"
                "        dead()\n"
                "    if COUNT == 1:\n"
                "        live()\n"
                "    else:\n"
                "        folded()\n"
                "\n"
                "if __name__ == '__main__':\n"
                "    main()\n"
            ),
        },
    )
    result = scan(tmp_path, defines={"COUNT": "1"})
    for symbol in ("dead", "folded"):
        found = _named(result, symbol)
        assert len(found) == 1
        assert found[0].rule == "UNUSED_FUNCTION"
        assert found[0].confidence >= 96
    assert _named(result, "live") == []


def test_nested_function_only_called_from_dead_branch(tmp_path):
    write_tree(
        tmp_path,
        {
            "app.py": (
                "def outer():\n"
                "    def helper():\n"
                "        return 1\n"
                "    return 1\n"
                "    helper()\n"
                "\n"
                "if __name__ == '__main__':\n"
                "    outer()\n"
            ),
        },
    )
    found = _named(scan(tmp_path), "helper")
    assert len(found) == 1
    assert found[0].rule == "UNUSED_FUNCTION"
    assert found[0].confidence == 100


def test_deleted_name_is_unused(tmp_path):
    write_tree(
        tmp_path,
        {
            "app.py": (
                "def collect():\n"
                "    value = 1\n"
                "    del value\n"
                "    return 1\n"
                "\n"
                "if __name__ == '__main__':\n"
                "    collect()\n"
            ),
        },
    )
    found = _named(scan(tmp_path), "value")
    assert len(found) == 1
    assert found[0].rule == "UNUSED_VARIABLE"
    assert found[0].confidence == 100


def test_reassignment_replaces_function_binding(tmp_path):
    source = (
        "def helper():\n"
        "    return 1\n"
        "\n"
        "helper = 1\n"
        "print(helper)\n"
    )
    path = tmp_path / "app.py"
    path.write_text(source, encoding="utf-8")
    index = PythonAstBackend().index_source(str(path), source)
    binding = next(item for item in index.bindings if item.name == "helper")
    assert binding.kind == "variable"
    assert binding.line == 4
    assert "UNUSED_FUNCTION" not in _rules(scan(path), "helper")


def test_uncalled_lambda_does_not_reach_callee(tmp_path):
    write_tree(
        tmp_path,
        {
            "app.py": (
                "def unused():\n"
                "    return 1\n"
                "\n"
                "def used():\n"
                "    return 2\n"
                "\n"
                "def main():\n"
                "    handler = lambda: unused()\n"
                "    return 1\n"
                "\n"
                "def entry():\n"
                "    return [used() for _ in range(1)]\n"
                "\n"
                "if __name__ == '__main__':\n"
                "    main()\n"
                "    entry()\n"
            ),
        },
    )
    result = scan(tmp_path)
    unused = _named(result, "unused")
    assert len(unused) == 1
    assert unused[0].rule == "UNUSED_FUNCTION"
    assert unused[0].confidence >= 96
    assert _named(result, "used") == []


def test_lambda_load_keeps_an_import_and_a_variable(tmp_path):
    path = tmp_path / "app.py"
    path.write_text(
        "import sqlite3\n"
        "from datetime import datetime\n"
        "\n"
        "def unused():\n"
        "    return 1\n"
        "\n"
        "offset = 1\n"
        "sqlite3.register_converter(\n"
        "    'timestamp',\n"
        "    lambda value: datetime.fromisoformat(value.decode()) + offset,\n"
        ")\n"
        "handler = lambda: unused()\n",
        encoding="utf-8",
    )
    result = scan(tmp_path)
    symbols = {(finding.rule, finding.symbol) for finding in result.findings}
    assert ("UNUSED_IMPORT", "datetime") not in symbols
    assert ("UNUSED_VARIABLE", "offset") not in symbols
    assert ("UNUSED_FUNCTION", "unused") in symbols
    apply_fixes(tmp_path, result.findings)
    text = path.read_text(encoding="utf-8")
    assert "datetime" in text
    assert "offset" in text


def test_file_getattr_keeps_unrelated_dead_functions(tmp_path):
    write_tree(
        tmp_path,
        {
            "app.py": (
                "def dead():\n"
                "    return 1\n"
                "\n"
                "def also_dead():\n"
                "    return 2\n"
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
    result = scan(tmp_path)
    for symbol in ("dead", "also_dead"):
        found = _named(result, symbol)
        assert len(found) == 1
        assert found[0].rule == "UNUSED_FUNCTION"
        assert found[0].confidence == 96


def test_literal_getattr_lowers_only_the_named_symbol(tmp_path):
    write_tree(
        tmp_path / "run_only",
        {
            "app.py": (
                "class Widget:\n"
                "    LIMIT = 1\n"
                "\n"
                "    def run(self):\n"
                "        return 1\n"
                "\n"
                "def main():\n"
                "    Widget()\n"
                "    getattr(Widget, 'run')\n"
                "\n"
                "if __name__ == '__main__':\n"
                "    main()\n"
            ),
        },
    )
    write_tree(
        tmp_path / "limit_only",
        {
            "app.py": (
                "class Widget:\n"
                "    LIMIT = 1\n"
                "\n"
                "    def run(self):\n"
                "        return 1\n"
                "\n"
                "def main():\n"
                "    Widget()\n"
                "    getattr(Widget, 'LIMIT')\n"
                "\n"
                "if __name__ == '__main__':\n"
                "    main()\n"
            ),
        },
    )
    run_only = scan(tmp_path / "run_only")
    run = _named(run_only, "run")
    limit = _named(run_only, "LIMIT")
    assert len(run) == 1
    assert run[0].rule == "UNUSED_FUNCTION"
    assert run[0].confidence <= 70
    assert len(limit) == 1
    assert limit[0].rule == "UNUSED_VARIABLE"
    assert limit[0].confidence == 96

    limit_only = scan(tmp_path / "limit_only")
    lowered = _named(limit_only, "LIMIT")
    kept = _named(limit_only, "run")
    assert len(lowered) == 1
    assert lowered[0].confidence <= 70
    assert len(kept) == 1
    assert kept[0].confidence == 96


def test_nested_eval_and_decorator_are_not_deleted(tmp_path):
    write_tree(
        tmp_path,
        {
            "app.py": (
                "class registry:\n"
                "    @staticmethod\n"
                "    def register(fn):\n"
                "        return fn\n"
                "\n"
                "def outer():\n"
                "    def helper():\n"
                "        return 1\n"
                "\n"
                "    eval('helper()')\n"
                "\n"
                "    @registry.register\n"
                "    def hooked():\n"
                "        return 2\n"
                "\n"
                "    return 3\n"
                "\n"
                "if __name__ == '__main__':\n"
                "    outer()\n"
            ),
        },
    )
    result = scan(tmp_path)
    for symbol in ("helper", "hooked"):
        found = _named(result, symbol)
        assert len(found) == 1
        assert found[0].confidence <= 75
    notes = apply_fixes(tmp_path, result.findings)
    text = (tmp_path / "app.py").read_text(encoding="utf-8")
    assert "def helper" in text
    assert "def hooked" in text
    assert notes == [] or all("helper" not in note and "hooked" not in note for note in notes)


def test_all_append_and_extend_are_exports(tmp_path):
    write_tree(
        tmp_path,
        {
            "app.py": (
                "def exported():\n"
                "    return 1\n"
                "\n"
                "def also():\n"
                "    return 2\n"
                "\n"
                "__all__ = []\n"
                "__all__.append('exported')\n"
                "__all__.extend(['also'])\n"
            ),
        },
    )
    symbols = {finding.symbol for finding in scan(tmp_path).findings}
    assert "exported" not in symbols
    assert "also" not in symbols


def test_basemodel_fields_stay_quiet(tmp_path):
    write_tree(
        tmp_path,
        {
            "app.py": (
                "class BaseModel:\n"
                "    pass\n"
                "\n"
                "class User(BaseModel):\n"
                "    name: str = 'x'\n"
                "\n"
                "class Box:\n"
                "    limit = 1\n"
                "\n"
                "def main():\n"
                "    User()\n"
                "    Box()\n"
                "\n"
                "if __name__ == '__main__':\n"
                "    main()\n"
            ),
        },
    )
    result = scan(tmp_path)
    assert _named(result, "name") == []
    limit = _named(result, "limit")
    assert len(limit) == 1
    assert limit[0].rule == "UNUSED_VARIABLE"
    assert limit[0].confidence == 96


def test_alias_call_uses_the_assignment_in_force(tmp_path):
    write_tree(
        tmp_path / "order",
        {
            "app.py": (
                "class A:\n"
                "    def run(self):\n"
                "        return 1\n"
                "\n"
                "class B:\n"
                "    def run(self):\n"
                "        return 2\n"
                "\n"
                "def make_a() -> A:\n"
                "    return A()\n"
                "\n"
                "def make_b() -> B:\n"
                "    return B()\n"
                "\n"
                "def main():\n"
                "    alias = make_a()\n"
                "    alias.run()\n"
                "    alias = make_b()\n"
                "    return 1\n"
                "\n"
                "if __name__ == '__main__':\n"
                "    main()\n"
            ),
        },
    )
    write_tree(
        tmp_path / "branch",
        {
            "app.py": (
                "class A:\n"
                "    def run(self):\n"
                "        return 1\n"
                "\n"
                "class B:\n"
                "    def run(self):\n"
                "        return 2\n"
                "\n"
                "def make_a() -> A:\n"
                "    return A()\n"
                "\n"
                "def make_b() -> B:\n"
                "    return B()\n"
                "\n"
                "def main(flag):\n"
                "    if flag:\n"
                "        alias = make_a()\n"
                "    else:\n"
                "        alias = make_b()\n"
                "    return alias.run()\n"
                "\n"
                "if __name__ == '__main__':\n"
                "    main(True)\n"
            ),
        },
    )
    order = {finding.fingerprint for finding in scan(tmp_path / "order").findings if finding.symbol == "run"}
    assert any(item.endswith(":B.run") for item in order)
    assert not any(item.endswith(":A.run") for item in order)
    branch = {finding.fingerprint for finding in scan(tmp_path / "branch").findings if finding.symbol == "run"}
    assert not any(item.endswith(":A.run") or item.endswith(":B.run") for item in branch)


def test_while_else_after_break_is_unreachable(tmp_path):
    write_tree(
        tmp_path,
        {
            "app.py": (
                "def after_while():\n"
                "    while True:\n"
                "        break\n"
                "    else:\n"
                "        print('no-while')\n"
                "\n"
                "def after_for():\n"
                "    for item in range(3):\n"
                "        break\n"
                "    else:\n"
                "        print('no-for')\n"
                "    return item\n"
                "\n"
                "after_while()\n"
                "after_for()\n"
            ),
        },
    )
    unreachable = [finding.symbol for finding in scan(tmp_path).findings if finding.rule == "UNREACHABLE_CODE"]
    assert "print('no-while')" in unreachable
    assert "print('no-for')" in unreachable


def test_try_else_after_return_is_unreachable(tmp_path):
    write_tree(
        tmp_path,
        {
            "app.py": (
                "def after_return():\n"
                "    try:\n"
                "        return 1\n"
                "    except Exception:\n"
                "        return 2\n"
                "    else:\n"
                "        print('no-else')\n"
                "\n"
                "def after_both():\n"
                "    try:\n"
                "        value = 1\n"
                "    except Exception:\n"
                "        return value\n"
                "    else:\n"
                "        return value\n"
                "    print('no-after')\n"
                "\n"
                "after_return()\n"
                "after_both(1)\n"
            ),
        },
    )
    unreachable = [finding.symbol for finding in scan(tmp_path).findings if finding.rule == "UNREACHABLE_CODE"]
    assert "print('no-else')" in unreachable
    assert "print('no-after')" in unreachable


def test_numeric_truthiness_and_bool_and(tmp_path):
    write_tree(
        tmp_path,
        {
            "app.py": (
                "def live():\n"
                "    return 1\n"
                "\n"
                "def main():\n"
                "    if 0:\n"
                "        print('no-if')\n"
                "    while 1:\n"
                "        return 1\n"
                "    print('no-while')\n"
                "    if False and live():\n"
                "        pass\n"
                "    return 0\n"
                "\n"
                "if __name__ == '__main__':\n"
                "    main()\n"
            ),
        },
    )
    result = scan(tmp_path)
    unreachable = [finding.symbol for finding in result.findings if finding.rule == "UNREACHABLE_CODE"]
    assert "print('no-if')" in unreachable
    assert "print('no-while')" in unreachable
    live = _named(result, "live")
    assert len(live) == 1
    assert live[0].rule == "UNUSED_FUNCTION"


def test_empty_for_body_is_unreachable(tmp_path):
    write_tree(
        tmp_path,
        {
            "app.py": (
                "def main():\n"
                "    for item in []:\n"
                "        print('no-list')\n"
                "    else:\n"
                "        print('yes-list')\n"
                "    for item in range(0):\n"
                "        print('no-range')\n"
                "    return item\n"
                "\n"
                "main()\n"
            ),
        },
    )
    unreachable = [finding.symbol for finding in scan(tmp_path).findings if finding.rule == "UNREACHABLE_CODE"]
    assert "print('no-list')" in unreachable
    assert "print('no-range')" in unreachable
    assert "print('yes-list')" not in unreachable


def test_process_exit_ends_the_block(tmp_path):
    write_tree(
        tmp_path,
        {
            "app.py": (
                "import os\n"
                "import sys\n"
                "\n"
                "def by_sys():\n"
                "    sys.exit(1)\n"
                "    print('no-sys')\n"
                "\n"
                "def by_os():\n"
                "    os._exit(0)\n"
                "    print('no-os')\n"
                "\n"
                "by_sys()\n"
                "by_os()\n"
            ),
        },
    )
    unreachable = [finding.symbol for finding in scan(tmp_path).findings if finding.rule == "UNREACHABLE_CODE"]
    assert "print('no-sys')" in unreachable
    assert "print('no-os')" in unreachable


def test_assert_false_does_not_end_the_block(tmp_path):
    write_tree(
        tmp_path,
        {
            "app.py": (
                "def foo():\n"
                "    assert False\n"
                "    return 1\n"
                "\n"
                "foo()\n"
            ),
        },
    )
    assert [finding for finding in scan(tmp_path).findings if finding.rule == "UNREACHABLE_CODE"] == []


def test_inner_call_on_a_later_dead_line_is_unreached(tmp_path):
    write_tree(
        tmp_path,
        {
            "app.py": (
                "def other():\n"
                "    return 1\n"
                "\n"
                "def helper(value):\n"
                "    return value\n"
                "\n"
                "def main():\n"
                "    return 1\n"
                "    helper(\n"
                "        other()\n"
                "    )\n"
                "\n"
                "if __name__ == '__main__':\n"
                "    main()\n"
            ),
        },
    )
    result = scan(tmp_path)
    for symbol in ("other", "helper"):
        found = _named(result, symbol)
        assert len(found) == 1
        assert found[0].rule == "UNUSED_FUNCTION"
        assert found[0].confidence >= 96


def test_semicolon_keeps_the_live_call(tmp_path):
    write_tree(
        tmp_path,
        {
            "app.py": (
                "def live():\n"
                "    return 1\n"
                "\n"
                "def dead():\n"
                "    return 2\n"
                "\n"
                "def main():\n"
                "    live(); return; dead()\n"
                "\n"
                "if __name__ == '__main__':\n"
                "    main()\n"
            ),
        },
    )
    result = scan(tmp_path)
    assert _named(result, "live") == []
    dead = _named(result, "dead")
    assert len(dead) == 1
    assert dead[0].rule == "UNUSED_FUNCTION"


def test_fix_does_not_empty_a_suite(tmp_path):
    write_tree(
        tmp_path,
        {
            "app.py": (
                "def outer():\n"
                "    if False:\n"
                "        print('no-if')\n"
                "    if True:\n"
                "        kept = 1\n"
                "    else:\n"
                "        print('no-else')\n"
                "    while False:\n"
                "        print('no-while')\n"
                "    return kept\n"
                "\n"
                "if __name__ == '__main__':\n"
                "    outer()\n"
            ),
        },
    )
    apply_fixes(tmp_path, scan(tmp_path).findings)
    text = (tmp_path / "app.py").read_text(encoding="utf-8")
    ast.parse(text)
    assert "no-if" not in text
    assert "no-else" not in text
    assert "no-while" not in text
    assert "pass" in text


def test_invalid_manifest_does_not_crash(tmp_path):
    write_tree(
        tmp_path,
        {
            "pyproject.toml": '[project]\nname = "demo"\nversion = "0.1"\n',
            "app.py": (
                "def dead():\n"
                "    return 1\n"
                "\n"
                "if __name__ == '__main__':\n"
                "    pass\n"
            ),
        },
    )
    (tmp_path / "Pipfile").write_text("this is not [valid\n", encoding="utf-8")
    (tmp_path / "requirements.txt").write_bytes(b"\xff\xfe unused-pkg\n")
    result = scan(tmp_path)
    assert result.errors
    assert any(finding.symbol == "dead" for finding in result.findings)


def test_nested_monorepo_manifests(tmp_path):
    write_tree(
        tmp_path,
        {
            "packages/foo/pyproject.toml": (
                '[project]\nname = "foo"\nversion = "0.1"\ndependencies = ["requests"]\n'
            ),
            "packages/foo/foo_app.py": "def build():\n    return 1\n",
            "packages/bar/pyproject.toml": (
                '[project]\nname = "bar"\nversion = "0.1"\ndependencies = ["rich"]\n'
            ),
            "packages/bar/bar_app.py": "import rich\nrich\n",
            "main.py": "if __name__ == '__main__':\n    pass\n",
        },
    )
    symbols = {finding.symbol for finding in scan(tmp_path).findings if finding.rule == "UNUSED_DEPENDENCY"}
    assert "requests" in symbols
    assert "rich" not in symbols


def test_editable_and_vcs_lines_do_not_crash(tmp_path):
    write_tree(
        tmp_path,
        {
            "requirements.txt": "-e ./packages/foo\ngit+https://example.com/foo.git\nstill-unused==1\n",
            "app.py": "if __name__ == '__main__':\n    pass\n",
        },
    )
    symbols = {finding.symbol for finding in scan(tmp_path).findings if finding.rule == "UNUSED_DEPENDENCY"}
    assert "still-unused" in symbols


def test_import_aliases_match_distribution_names(tmp_path):
    write_tree(
        tmp_path,
        {
            "requirements.txt": "beautifulsoup4==4\nopencv-python-headless==4\n",
            "app.py": "import bs4\nimport cv2\nbs4\ncv2\n",
            "main.py": "import app\nif __name__ == '__main__':\n    print(app)\n",
        },
    )
    bad = [
        finding
        for finding in scan(tmp_path).findings
        if finding.rule == "UNUSED_DEPENDENCY" and finding.confidence == 95
    ]
    assert {finding.symbol for finding in bad}.isdisjoint({"beautifulsoup4", "opencv-python-headless"})


def test_dependency_line_is_the_declaration(tmp_path):
    write_tree(
        tmp_path,
        {
            "requirements.txt": "# requests is mentioned here\nrequests==2\n",
            "app.py": "if __name__ == '__main__':\n    pass\n",
        },
    )
    finding = next(item for item in scan(tmp_path).findings if item.symbol == "requests")
    assert finding.rule == "UNUSED_DEPENDENCY"
    assert finding.line == 2


def test_src_layout_wins_a_module_name_collision(tmp_path):
    write_tree(
        tmp_path,
        {
            "src/pkg/__init__.py": "",
            "src/pkg/mod.py": "def live():\n    return 1\n",
            "pkg/__init__.py": "",
            "pkg/mod.py": "def dead():\n    return 1\n",
            "main.py": (
                "from pkg.mod import live\n"
                "\n"
                "def main():\n"
                "    return live()\n"
                "\n"
                "if __name__ == '__main__':\n"
                "    main()\n"
            ),
        },
    )
    result = scan(tmp_path)
    assert _named(result, "live") == []
    dead = _named(result, "dead")
    assert len(dead) == 1
    assert dead[0].rule == "UNUSED_FUNCTION"
