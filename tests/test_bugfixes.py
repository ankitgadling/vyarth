"""Regressions for analysis bugs found in review."""

from vyarth import scan
from vyarth.fix import apply_fixes, apply_import_fixes
from vyarth.incremental import cache_stamp
from vyarth.model import INDEX_VERSION

from tests.conftest import write_tree


def _rows(result):
    return {(finding.rule, finding.symbol, finding.path) for finding in result.findings}


def test_numeric_and_string_folds_keep_the_matching_branch(tmp_path):
    write_tree(
        tmp_path,
        {
            "app.py": (
                "import os\n"
                "\n"
                "def live_count():\n"
                "    return 1\n"
                "\n"
                "def dead_count():\n"
                "    return 2\n"
                "\n"
                "def live_flag():\n"
                "    return 3\n"
                "\n"
                "def dead_flag():\n"
                "    return 4\n"
                "\n"
                "def main():\n"
                "    if COUNT == 1:\n"
                "        live_count()\n"
                "    else:\n"
                "        dead_count()\n"
                "    if os.getenv('FLAG') == 'true':\n"
                "        live_flag()\n"
                "    else:\n"
                "        dead_flag()\n"
                "\n"
                "if __name__ == '__main__':\n"
                "    main()\n"
            ),
        },
    )
    result = scan(tmp_path, defines={"COUNT": "1", "FLAG": "true"})
    symbols = {finding.symbol for finding in result.findings}
    assert "live_count" not in symbols
    assert "live_flag" not in symbols
    assert "dead_count" in symbols
    assert "dead_flag" in symbols


def test_import_module_attribute_call_reaches_the_function(tmp_path):
    write_tree(
        tmp_path,
        {
            "api.py": "def func():\n    return 1\n",
            "pkg/__init__.py": "",
            "pkg/api.py": "def helper():\n    return 1\n",
            "main.py": (
                "import api\n"
                "import pkg.api as names\n"
                "\n"
                "def main():\n"
                "    return api.func() + names.helper()\n"
                "\n"
                "if __name__ == '__main__':\n"
                "    main()\n"
            ),
        },
    )
    symbols = {finding.symbol for finding in scan(tmp_path).findings}
    assert "func" not in symbols
    assert "helper" not in symbols


def test_inherited_method_and_super_are_reached(tmp_path):
    write_tree(
        tmp_path,
        {
            "app.py": (
                "class Base:\n"
                "    def close(self):\n"
                "        return 1\n"
                "\n"
                "class Child(Base):\n"
                "    def run(self):\n"
                "        return self.close()\n"
                "\n"
                "class Other(Base):\n"
                "    def close(self):\n"
                "        return super().close()\n"
                "\n"
                "if __name__ == '__main__':\n"
                "    Child().run()\n"
                "    Other().close()\n"
            ),
        },
    )
    assert "close" not in {finding.symbol for finding in scan(tmp_path).findings}


def test_dotted_return_annotation_selects_the_method(tmp_path):
    write_tree(
        tmp_path,
        {
            "pkg/__init__.py": "",
            "pkg/models.py": (
                "class Widget:\n"
                "    def run(self):\n"
                "        return 1\n"
                "\n"
                "class Other:\n"
                "    def run(self):\n"
                "        return 2\n"
            ),
            "app.py": (
                "import pkg.models\n"
                "\n"
                "def make() -> pkg.models.Widget:\n"
                "    return pkg.models.Widget()\n"
                "\n"
                "def main():\n"
                "    pkg.models.Other()\n"
                "    return make().run()\n"
                "\n"
                "if __name__ == '__main__':\n"
                "    main()\n"
            ),
        },
    )
    fingerprints = {finding.fingerprint for finding in scan(tmp_path).findings}
    assert not any(item.endswith("Widget.run") for item in fingerprints)
    assert any(item.endswith("Other.run") for item in fingerprints)


def test_exits_cover_try_loop_with_match_and_for_else(tmp_path):
    source = (
        "def after_try():\n"
        "    try:\n"
        "        return 1\n"
        "    finally:\n"
        "        pass\n"
        "    print('try')\n"
        "\n"
        "def after_loop():\n"
        "    while True:\n"
        "        return 1\n"
        "    print('loop')\n"
        "\n"
        "def after_with():\n"
        "    with open(__file__) as handle:\n"
        "        return handle\n"
        "    print('with')\n"
        "\n"
        "def after_with_in_loop():\n"
        "    while True:\n"
        "        with open(__file__) as handle:\n"
        "            return handle\n"
        "    print('with-loop')\n"
        "\n"
        "def break_in_with():\n"
        "    while True:\n"
        "        with open(__file__) as handle:\n"
        "            break\n"
        "    return handle\n"
        "\n"
        "def after_match(value):\n"
        "    match value:\n"
        "        case 1:\n"
        "            return 1\n"
        "        case _:\n"
        "            return 2\n"
        "    print('match')\n"
        "\n"
        "def after_break():\n"
        "    for item in range(3):\n"
        "        break\n"
        "    else:\n"
        "        print('else')\n"
        "    return item\n"
        "\n"
        "after_try()\n"
        "after_loop()\n"
        "after_with()\n"
        "after_with_in_loop()\n"
        "break_in_with()\n"
        "after_match(1)\n"
        "after_break()\n"
    )
    path = tmp_path / "app.py"
    path.write_text(source, encoding="utf-8")
    unreachable = [finding.symbol for finding in scan(path).findings if finding.rule == "UNREACHABLE_CODE"]
    assert unreachable == [
        "print('try')",
        "print('loop')",
        "print('with')",
        "print('with-loop')",
        "print('match')",
        "print('else')",
    ]


def test_wildcard_import_uses_the_imported_name(tmp_path):
    write_tree(
        tmp_path,
        {
            "pkg/__init__.py": "",
            "pkg/api.py": "def func():\n    return 1\n",
            "main.py": (
                "from pkg.api import *\n"
                "\n"
                "def main():\n"
                "    return func()\n"
                "\n"
                "if __name__ == '__main__':\n"
                "    main()\n"
            ),
        },
    )
    result = scan(tmp_path)
    assert any(finding.rule == "WILDCARD_IMPORT" for finding in result.findings)
    assert "func" not in {finding.symbol for finding in result.findings}


def test_abstract_and_pass_methods_are_not_orphans(tmp_path):
    write_tree(
        tmp_path,
        {
            "app.py": (
                "import abc\n"
                "\n"
                "class Base(abc.ABC):\n"
                "    @abc.abstractmethod\n"
                "    def close(self):\n"
                "        raise NotImplementedError\n"
                "\n"
                "    def unused_hook(self):\n"
                "        pass\n"
                "\n"
                "class Child(Base):\n"
                "    def close(self):\n"
                "        return 1\n"
                "\n"
                "if __name__ == '__main__':\n"
                "    Child().close()\n"
            ),
        },
    )
    symbols = {finding.symbol for finding in scan(tmp_path).findings}
    assert "close" not in symbols
    assert "unused_hook" not in symbols


def test_value_use_inside_an_unused_function_does_not_keep_the_target(tmp_path):
    write_tree(
        tmp_path,
        {
            "app.py": (
                "def unused():\n"
                "    handlers = []\n"
                "    handlers.append(helper)\n"
                "\n"
                "def helper():\n"
                "    return 1\n"
                "\n"
                "def main():\n"
                "    return 1\n"
                "\n"
                "if __name__ == '__main__':\n"
                "    main()\n"
            ),
        },
    )
    found = {(finding.rule, finding.symbol) for finding in scan(tmp_path).findings}
    assert ("UNUSED_FUNCTION", "unused") in found
    assert ("ORPHAN_FUNCTION", "helper") in found


def test_ignore_above_a_decorator_suppresses_the_function(tmp_path):
    path = tmp_path / "app.py"
    path.write_text(
        "def deco(fn):\n"
        "    return fn\n"
        "\n"
        "# vyarth: ignore\n"
        "@deco\n"
        "def legacy():\n"
        "    return 1\n"
        "\n"
        "if __name__ == '__main__':\n"
        "    deco(1)\n",
        encoding="utf-8",
    )
    assert "legacy" not in {finding.symbol for finding in scan(path).findings}


def test_fix_removes_every_name_in_a_parenthesized_import(tmp_path):
    path = tmp_path / "app.py"
    path.write_text("from json import (\n    dumps,\n    loads,\n)\n", encoding="utf-8")
    result = scan(tmp_path)
    notes = apply_import_fixes(tmp_path, result.findings)
    assert path.read_text(encoding="utf-8").strip() == ""
    assert len(notes) == 2


def test_fix_leaves_an_import_that_might_be_dynamic(tmp_path):
    path = tmp_path / "app.py"
    path.write_text(
        "import os\nimport importlib\nimportlib.import_module('json')\n",
        encoding="utf-8",
    )
    result = scan(tmp_path)
    assert any(finding.rule == "UNUSED_IMPORT" and finding.symbol == "os" and finding.confidence < 90 for finding in result.findings)
    assert apply_import_fixes(tmp_path, result.findings) == []
    assert "import os" in path.read_text(encoding="utf-8")


def test_import_module_string_counts_as_a_used_dependency(tmp_path):
    write_tree(
        tmp_path,
        {
            "app.py": "import importlib\nimportlib.import_module('pandas')\n",
            "requirements.txt": "pandas\n",
        },
    )
    assert not any(
        finding.rule == "UNUSED_DEPENDENCY" and finding.symbol == "pandas"
        for finding in scan(tmp_path).findings
    )


def test_cache_stamp_includes_the_analyzer_version():
    stamp = cache_stamp(4, 8, {"A": "b"})
    assert stamp.startswith(f"{INDEX_VERSION}:")


def test_later_assignment_is_the_call_target(tmp_path):
    write_tree(
        tmp_path,
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
                "    alias = make_b()\n"
                "    return alias.run()\n"
                "\n"
                "if __name__ == '__main__':\n"
                "    main()\n"
            ),
        },
    )
    fingerprints = {finding.fingerprint for finding in scan(tmp_path).findings if finding.symbol == "run"}
    assert any(item.endswith(":A.run") for item in fingerprints)
    assert not any(item.endswith(":B.run") for item in fingerprints)


def test_unreferenced_method_and_class_attribute_score_96(tmp_path):
    write_tree(
        tmp_path,
        {
            "app.py": (
                "class Box:\n"
                "    LIMIT = 1\n"
                "\n"
                "    @property\n"
                "    def label(self):\n"
                "        return 'box'\n"
                "\n"
                "    @staticmethod\n"
                "    def quiet():\n"
                "        return 1\n"
                "\n"
                "    def close(self):\n"
                "        return 1\n"
                "\n"
                "def main():\n"
                "    Box()\n"
                "\n"
                "if __name__ == '__main__':\n"
                "    main()\n"
            ),
        },
    )
    findings = {finding.symbol: finding for finding in scan(tmp_path).findings}
    assert findings["close"].rule == "UNUSED_FUNCTION"
    assert findings["close"].confidence == 96
    assert findings["quiet"].rule == "UNUSED_FUNCTION"
    assert findings["quiet"].confidence == 96
    assert findings["LIMIT"].rule == "UNUSED_VARIABLE"
    assert findings["LIMIT"].confidence == 96
    assert "label" not in findings


def test_unresolved_method_name_stays_at_60(tmp_path):
    write_tree(
        tmp_path,
        {
            "app.py": (
                "class Box:\n"
                "    def close(self):\n"
                "        return 1\n"
                "\n"
                "class Other:\n"
                "    def close(self):\n"
                "        return 2\n"
                "\n"
                "def main():\n"
                "    obj = unknown()\n"
                "    obj.close()\n"
                "    Box()\n"
                "    Other()\n"
                "\n"
                "if __name__ == '__main__':\n"
                "    main()\n"
            ),
        },
    )
    closes = [item for item in scan(tmp_path).findings if item.symbol == "close"]
    assert len(closes) == 2
    assert {item.rule for item in closes} == {"ORPHAN_FUNCTION"}
    assert {item.confidence for item in closes} == {60}


def test_referenced_method_outside_the_entry_stays_an_orphan(tmp_path):
    write_tree(
        tmp_path,
        {
            "app.py": (
                "class Box:\n"
                "    def close(self):\n"
                "        return 1\n"
                "\n"
                "    def unused(self):\n"
                "        return self.close()\n"
                "\n"
                "def main():\n"
                "    Box()\n"
                "\n"
                "if __name__ == '__main__':\n"
                "    main()\n"
            ),
        },
    )
    findings = {finding.symbol: finding for finding in scan(tmp_path).findings}
    assert findings["unused"].rule == "UNUSED_FUNCTION"
    assert findings["unused"].confidence == 96
    assert findings["close"].rule == "ORPHAN_FUNCTION"
    assert findings["close"].confidence == 80


def test_dataclass_fields_are_not_unused_attributes(tmp_path):
    write_tree(
        tmp_path,
        {
            "app.py": (
                "from dataclasses import dataclass\n"
                "\n"
                "@dataclass\n"
                "class Box:\n"
                "    limit: int = 1\n"
                "\n"
                "def main():\n"
                "    Box(1)\n"
                "\n"
                "if __name__ == '__main__':\n"
                "    main()\n"
            ),
        },
    )
    assert "limit" not in {finding.symbol for finding in scan(tmp_path).findings}


def test_subscript_call_walks_only_that_element(tmp_path):
    write_tree(
        tmp_path,
        {
            "app.py": (
                "def foo():\n"
                "    return used()\n"
                "\n"
                "def bar():\n"
                "    return secret()\n"
                "\n"
                "def used():\n"
                "    return 1\n"
                "\n"
                "def secret():\n"
                "    return 1\n"
                "\n"
                "def main():\n"
                "    handlers = [foo, bar]\n"
                "    handlers[0]()\n"
                "\n"
                "if __name__ == '__main__':\n"
                "    main()\n"
            ),
        },
    )
    symbols = {finding.symbol for finding in scan(tmp_path).findings}
    assert "foo" not in symbols
    assert "bar" not in symbols
    assert "used" not in symbols
    assert "secret" in symbols


def test_bare_append_still_walks_the_stored_function(tmp_path):
    write_tree(
        tmp_path,
        {
            "app.py": (
                "def foo():\n"
                "    return helper()\n"
                "\n"
                "def helper():\n"
                "    return 1\n"
                "\n"
                "handlers = []\n"
                "handlers.append(foo)\n"
            ),
            "main.py": "import app\nif __name__ == '__main__':\n    print(app)\n",
        },
    )
    assert not any(finding.symbol in {"foo", "helper"} for finding in scan(tmp_path).findings)


def test_loop_calls_every_stored_function(tmp_path):
    write_tree(
        tmp_path,
        {
            "app.py": (
                "def foo():\n"
                "    return used()\n"
                "\n"
                "def bar():\n"
                "    return secret()\n"
                "\n"
                "def used():\n"
                "    return 1\n"
                "\n"
                "def secret():\n"
                "    return 1\n"
                "\n"
                "def main():\n"
                "    handlers = []\n"
                "    handlers.append(foo)\n"
                "    handlers.append(bar)\n"
                "    for handler in handlers:\n"
                "        handler()\n"
                "\n"
                "if __name__ == '__main__':\n"
                "    main()\n"
            ),
        },
    )
    assert not any(finding.symbol in {"used", "secret", "foo", "bar"} for finding in scan(tmp_path).findings)


def test_fix_removes_unreachable_code_nested_functions_and_plain_locals(tmp_path):
    path = tmp_path / "app.py"
    path.write_text(
        "def outer():\n"
        "    def helper():\n"
        "        return 1\n"
        "    value = 1\n"
        "    kept = len('x')\n"
        "    return 1\n"
        "    left = 2\n"
        "\n"
        "if __name__ == '__main__':\n"
        "    outer()\n",
        encoding="utf-8",
    )
    notes = apply_fixes(tmp_path, scan(tmp_path).findings)
    text = path.read_text(encoding="utf-8")
    assert "def helper" not in text
    assert "value = 1" not in text
    assert "left = 2" not in text
    assert "kept = len('x')" in text
    assert notes
