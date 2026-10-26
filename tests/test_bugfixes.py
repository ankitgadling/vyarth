"""Regressions for analysis bugs found in review."""

import pytest

from vyarth import scan
from vyarth.fix import apply_fixes, apply_import_fixes, rewrite_source
from vyarth.incremental import cache_stamp
from vyarth.model import INDEX_VERSION, Finding

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
    result = scan(path)
    notes = apply_import_fixes(tmp_path, result.findings)
    assert path.read_text(encoding="utf-8").strip() == ""
    assert len(notes) == 2


def test_quoted_name_inside_callable_keeps_a_type_checking_import(tmp_path):
    path = tmp_path / "app.py"
    path.write_text(
        "from typing import TYPE_CHECKING, Any, Callable, TypeAlias\n"
        "if TYPE_CHECKING:\n"
        "    from decimal import Decimal\n"
        "    from fractions import Fraction\n"
        "\n"
        'HookType: TypeAlias = Callable[["Decimal"], Any]\n',
        encoding="utf-8",
    )
    unused = {finding.symbol for finding in scan(path).findings if finding.rule == "UNUSED_IMPORT"}
    assert "Decimal" not in unused
    assert "Fraction" in unused


def test_quoted_annotation_keeps_a_type_checking_import(tmp_path):
    path = tmp_path / "app.py"
    path.write_text(
        "from typing import TYPE_CHECKING\n"
        "if TYPE_CHECKING:\n"
        "    from decimal import Decimal\n"
        "    from fractions import Fraction\n"
        "\n"
        'rate: "Decimal"\n'
        "\n"
        "def price(value: \"list['Decimal']\") -> \"Decimal\":\n"
        "    return value\n",
        encoding="utf-8",
    )
    result = scan(path)
    unused = {finding.symbol for finding in result.findings if finding.rule == "UNUSED_IMPORT"}
    assert "Decimal" not in unused
    assert "Fraction" in unused
    apply_fixes(tmp_path, result.findings)
    text = path.read_text(encoding="utf-8")
    assert "from decimal import Decimal" in text
    assert "Fraction" not in text


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
    from vyarth import __version__

    stamp = cache_stamp(4, 8, {"A": "b"})
    assert stamp.startswith(f"{__version__}:{INDEX_VERSION}:")


def test_cached_index_tolerates_missing_confidence_fields():
    from dataclasses import asdict

    from vyarth.incremental import _index_from_dict
    from vyarth.python_index import PythonAstBackend

    index = PythonAstBackend().index_source("app.py", "def helper():\n    return 1\n")
    data = asdict(index)
    for item in data["bindings"]:
        del item["typing_only"]
    del data["lambda_mentions"]
    loaded = _index_from_dict(data)
    assert loaded.lambda_mentions == ()
    binding = next(item for item in loaded.bindings if item.name == "helper")
    assert binding.typing_only is False


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
                "    def _close(self):\n"
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
    assert findings["close"].confidence == 60
    assert findings["_close"].confidence == 96
    assert findings["quiet"].rule == "UNUSED_FUNCTION"
    assert findings["quiet"].confidence == 60
    assert findings["LIMIT"].rule == "UNUSED_VARIABLE"
    assert findings["LIMIT"].confidence == 60
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
    assert findings["unused"].confidence == 60
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


def _finding(**overrides) -> Finding:
    data = {
        "rule": "UNUSED_IMPORT",
        "path": "app.py",
        "line": 1,
        "column": 1,
        "symbol": "os",
        "status": "DEAD",
        "confidence": 100,
        "message": "",
        "evidence": (),
        "fingerprint": "UNUSED_IMPORT:app.py:os",
    }
    data.update(overrides)
    return Finding(**data)


def test_fix_leaves_star_and_semicolon_imports():
    star = "from os import *\n"
    updated, notes = rewrite_source(star, [_finding(symbol="*")], "app.py")
    assert updated == star
    assert notes == []
    mixed = "import os; import sys\n"
    updated, notes = rewrite_source(mixed, [_finding(symbol="os")], "app.py")
    assert updated == mixed
    assert notes == []


def test_fix_keeps_a_trailing_import_comment():
    source = "from os import path, getcwd  # keep me\nprint(getcwd())\n"
    updated, notes = rewrite_source(source, [_finding(symbol="path", line=1)], "app.py")
    assert updated == "from os import getcwd  # keep me\nprint(getcwd())\n"
    assert notes == ["fixed app.py:1 path"]


def test_fix_removes_an_annotated_assignment(tmp_path):
    path = tmp_path / "app.py"
    path.write_text(
        "def outer():\n"
        "    value: int = 1\n"
        "    return 0\n"
        "\n"
        "if __name__ == '__main__':\n"
        "    outer()\n",
        encoding="utf-8",
    )
    apply_fixes(tmp_path, scan(tmp_path).findings)
    text = path.read_text(encoding="utf-8")
    assert "value: int = 1" not in text
    assert "return 0" in text


def test_fix_replaces_a_fully_dead_suite_with_pass(tmp_path):
    path = tmp_path / "app.py"
    path.write_text(
        "def outer():\n"
        "    if False:\n"
        "        left = 1\n"
        "        right = 2\n"
        "    return 0\n"
        "\n"
        "if __name__ == '__main__':\n"
        "    outer()\n",
        encoding="utf-8",
    )
    apply_fixes(tmp_path, scan(tmp_path).findings)
    text = path.read_text(encoding="utf-8")
    assert "left" not in text
    assert "right" not in text
    assert "pass" in text
    assert text.count("pass") == 1


def test_fix_ignores_a_syntax_error_and_a_missing_file(tmp_path):
    source = "def (\n"
    assert rewrite_source(source, [_finding()], "app.py") == (source, [])
    notes = apply_fixes(tmp_path, [_finding(path="missing.py")])
    assert notes == []
    assert not (tmp_path / "missing.py").exists()


def test_overlapping_fix_edits_apply_once(tmp_path):
    path = tmp_path / "app.py"
    path.write_text(
        "def outer():\n"
        "    def helper():\n"
        "        return 1\n"
        "        left = 2\n"
        "    return 0\n"
        "\n"
        "if __name__ == '__main__':\n"
        "    outer()\n",
        encoding="utf-8",
    )
    apply_fixes(tmp_path, scan(tmp_path).findings)
    text = path.read_text(encoding="utf-8")
    assert "left" not in text
    assert "def helper" in text
    assert "return 0" in text
    compile(text, "app.py", "exec")


def test_quoted_union_alias_keeps_the_type_checking_import(tmp_path):
    path = tmp_path / "app.py"
    path.write_text(
        "from typing import TYPE_CHECKING, Union\n"
        "if TYPE_CHECKING:\n"
        "    from decimal import Decimal\n"
        "    from fractions import Fraction\n"
        "\n"
        "URLTypes = Union['Decimal', str]\n",
        encoding="utf-8",
    )
    unused = {finding.symbol for finding in scan(tmp_path).findings if finding.rule == "UNUSED_IMPORT"}
    assert "Decimal" not in unused
    assert "Fraction" in unused


def test_property_body_keeps_the_called_classmethod(tmp_path):
    write_tree(
        tmp_path,
        {
            "codes.py": (
                "class codes:\n"
                "    @classmethod\n"
                "    def is_informational(cls, value: int) -> bool:\n"
                "        return value < 200\n"
            ),
            "models.py": (
                "from codes import codes\n"
                "\n"
                "class Response:\n"
                "    @property\n"
                "    def is_informational(self) -> bool:\n"
                "        return codes.is_informational(1)\n"
            ),
            "main.py": "from models import Response\nif __name__ == '__main__':\n    Response()\n",
        },
    )
    assert "is_informational" not in {finding.symbol for finding in scan(tmp_path).findings}


def test_override_of_a_reached_method_is_used(tmp_path):
    write_tree(
        tmp_path,
        {
            "auth.py": (
                "class Auth:\n"
                "    def auth_flow(self):\n"
                "        yield 1\n"
                "\n"
                "    def sync(self):\n"
                "        return list(self.auth_flow())\n"
                "\n"
                "class BasicAuth(Auth):\n"
                "    def auth_flow(self):\n"
                "        yield 2\n"
            ),
            "main.py": "from auth import Auth\nif __name__ == '__main__':\n    Auth().sync()\n",
        },
    )
    assert "auth_flow" not in {finding.symbol for finding in scan(tmp_path).findings}


def test_unreached_typed_call_is_an_orphan(tmp_path):
    write_tree(
        tmp_path,
        {
            "auth.py": (
                "class Auth:\n"
                "    def async_auth_flow(self, request):\n"
                "        return request\n"
            ),
            "client.py": (
                "from auth import Auth\n"
                "\n"
                "def send(auth: Auth):\n"
                "    return auth.async_auth_flow(1)\n"
            ),
            "main.py": "import client\nif __name__ == '__main__':\n    print(client)\n",
        },
    )
    found = {(finding.rule, finding.symbol) for finding in scan(tmp_path).findings}
    assert ("UNUSED_FUNCTION", "async_auth_flow") not in found
    assert ("ORPHAN_FUNCTION", "async_auth_flow") in found


def test_enum_members_are_not_unused_attributes(tmp_path):
    write_tree(
        tmp_path,
        {
            "codes.py": (
                "from enum import IntEnum\n"
                "\n"
                "class codes(IntEnum):\n"
                "    OK = 200\n"
                "\n"
                "    def label(self) -> str:\n"
                "        return 'ok'\n"
            ),
            "main.py": "from codes import codes\nif __name__ == '__main__':\n    print(codes)\n",
        },
    )
    found = {(finding.rule, finding.symbol) for finding in scan(tmp_path).findings}
    assert ("UNUSED_VARIABLE", "OK") not in found
    assert ("UNUSED_FUNCTION", "label") in found


def test_noqa_f401_suppresses_the_unused_import(tmp_path):
    path = tmp_path / "app.py"
    path.write_text(
        "import encodings.idna  # noqa: F401\n"
        "import socket  # noqa: F841\n"
        "\n"
        "def main():\n"
        "    return 1\n"
        "\n"
        "if __name__ == '__main__':\n"
        "    main()\n",
        encoding="utf-8",
    )
    unused = {finding.symbol for finding in scan(tmp_path).findings if finding.rule == "UNUSED_IMPORT"}
    assert "encodings" not in unused
    assert "socket" in unused


def test_noqa_f401_with_a_trailing_note_suppresses_the_import(tmp_path):
    path = tmp_path / "app.py"
    path.write_text(
        "import encodings.idna  # noqa: F401 kept for plugins\n"
        "import socket\n"
        "\n"
        "def main():\n"
        "    return 1\n"
        "\n"
        "if __name__ == '__main__':\n"
        "    main()\n",
        encoding="utf-8",
    )
    unused = {finding.symbol for finding in scan(tmp_path).findings if finding.rule == "UNUSED_IMPORT"}
    assert "encodings" not in unused
    assert "socket" in unused


def test_standalone_noqa_does_not_hide_the_next_import(tmp_path):
    path = tmp_path / "app.py"
    path.write_text(
        "# noqa\n"
        "import socket\n"
        "\n"
        "def main():\n"
        "    return 1\n"
        "\n"
        "if __name__ == '__main__':\n"
        "    main()\n",
        encoding="utf-8",
    )
    unused = {finding.symbol for finding in scan(tmp_path).findings if finding.rule == "UNUSED_IMPORT"}
    assert "socket" in unused


def test_parenthesized_noqa_covers_every_imported_name(tmp_path):
    path = tmp_path / "app.py"
    path.write_text(
        "from json import (  # noqa: F401\n"
        "    dumps,\n"
        "    loads,\n"
        ")\n"
        "\n"
        "def main():\n"
        "    return 1\n"
        "\n"
        "if __name__ == '__main__':\n"
        "    main()\n",
        encoding="utf-8",
    )
    unused = {finding.symbol for finding in scan(tmp_path).findings if finding.rule == "UNUSED_IMPORT"}
    assert unused.isdisjoint({"dumps", "loads"})


def test_import_error_probe_scores_70(tmp_path):
    path = tmp_path / "app.py"
    path.write_text(
        "def enable():\n"
        "    try:\n"
        "        import h2\n"
        "    except ImportError:\n"
        "        raise ImportError('missing')\n"
        "\n"
        "if __name__ == '__main__':\n"
        "    enable()\n",
        encoding="utf-8",
    )
    finding = next(item for item in scan(tmp_path).findings if item.rule == "UNUSED_IMPORT" and item.symbol == "h2")
    assert finding.confidence == 70
    assert finding.status == "POSSIBLY_DEAD"
    assert "ImportError" in finding.evidence[-1]


def test_pyopenssl_import_satisfies_the_dependency(tmp_path):
    write_tree(
        tmp_path,
        {
            "pyproject.toml": "[project]\nname = 'app'\nversion = '0.1'\ndependencies = ['pyopenssl']\n",
            "help.py": "import OpenSSL\nOpenSSL\n",
            "main.py": "import help\nif __name__ == '__main__':\n    print(help)\n",
        },
    )
    assert not any(
        finding.rule == "UNUSED_DEPENDENCY" and finding.symbol == "pyopenssl"
        for finding in scan(tmp_path).findings
    )


def test_dev_only_dependency_scores_70(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "vyarth.dependencies._distribution_map",
        lambda: {"runtime-missing": ["runtime-missing"]},
    )
    write_tree(
        tmp_path,
        {
            "requirements.txt": "runtime-missing\n",
            "requirements-dev.txt": "ruff\n",
            "docs/requirements.txt": "sphinx\n",
            "pyproject.toml": (
                "[dependency-groups]\n"
                "dev = ['pytest']\n"
            ),
            "main.py": "if __name__ == '__main__':\n    print(1)\n",
        },
    )
    findings = {item.symbol: item for item in scan(tmp_path).findings if item.rule == "UNUSED_DEPENDENCY"}
    assert findings["runtime-missing"].confidence == 95
    assert "ruff" not in findings
    assert "sphinx" not in findings
    assert "pytest" not in findings
    from vyarth.config import Config

    reported = {
        item.symbol: item
        for item in scan(tmp_path, config=Config(report_dev_dependencies=True)).findings
        if item.rule == "UNUSED_DEPENDENCY"
    }
    assert reported["ruff"].confidence == 70
    assert "development or docs" in reported["ruff"].evidence[0]
    assert reported["sphinx"].confidence == 70
    assert reported["pytest"].confidence == 70


def test_cast_string_keeps_the_import(tmp_path):
    path = tmp_path / "app.py"
    path.write_text(
        "from typing import TYPE_CHECKING, cast\n"
        "if TYPE_CHECKING:\n"
        "    from fractions import Fraction\n"
        "\n"
        "def main(value):\n"
        "    return cast('Fraction', value)\n"
        "\n"
        "if __name__ == '__main__':\n"
        "    main(1)\n",
        encoding="utf-8",
    )
    assert "Fraction" not in {finding.symbol for finding in scan(tmp_path).findings if finding.rule == "UNUSED_IMPORT"}
    apply_fixes(tmp_path, scan(tmp_path).findings)
    assert "Fraction" in path.read_text(encoding="utf-8")


def test_constructor_call_reaches_the_method(tmp_path):
    path = tmp_path / "app.py"
    path.write_text(
        "class Widget:\n"
        "    def run(self):\n"
        "        return 1\n"
        "\n"
        "def main():\n"
        "    return Widget().run()\n"
        "\n"
        "if __name__ == '__main__':\n"
        "    main()\n",
        encoding="utf-8",
    )
    assert "run" not in {finding.symbol for finding in scan(tmp_path).findings}


def test_node_visitor_methods_are_reached(tmp_path):
    write_tree(
        tmp_path,
        {
            "walk.py": (
                "import ast\n"
                "\n"
                "class Walker(ast.NodeVisitor):\n"
                "    def visit_Name(self, node):\n"
                "        return helper(node)\n"
                "\n"
                "def helper(node):\n"
                "    return node.id\n"
                "\n"
                "def main():\n"
                "    Walker().visit(ast.parse('x'))\n"
                "\n"
                "if __name__ == '__main__':\n"
                "    main()\n"
            ),
            "pages.py": (
                "class Page:\n"
                "    def visit_page(self):\n"
                "        return 1\n"
                "\n"
                "def main():\n"
                "    return Page()\n"
                "\n"
                "if __name__ == '__main__':\n"
                "    main()\n"
            ),
        },
    )
    found = {(finding.rule, finding.symbol) for finding in scan(tmp_path).findings}
    assert ("UNUSED_FUNCTION", "visit_Name") not in found
    assert ("ORPHAN_FUNCTION", "helper") not in found
    assert ("UNUSED_FUNCTION", "visit_page") in found


def test_root_scan_skips_nested_example_requirements(tmp_path):
    write_tree(
        tmp_path,
        {
            "pyproject.toml": "[project]\nname = 'app'\nversion = '0.1'\n",
            "requirements.txt": "root-only-pkg\n",
            "examples/celery/requirements.txt": "amqp\nkombu\n",
            "docs/requirements.txt": "sphinx\n",
            "main.py": "if __name__ == '__main__':\n    print(1)\n",
        },
    )
    root_symbols = {item.symbol for item in scan(tmp_path).findings if item.rule == "UNUSED_DEPENDENCY"}
    assert "root-only-pkg" in root_symbols
    assert "amqp" not in root_symbols
    assert "kombu" not in root_symbols
    assert "sphinx" not in root_symbols

    from vyarth.config import Config

    reported = {
        item.symbol
        for item in scan(tmp_path, config=Config(report_dev_dependencies=True)).findings
        if item.rule == "UNUSED_DEPENDENCY"
    }
    assert "sphinx" in reported
    assert "amqp" not in reported

    example = {
        item.symbol
        for item in scan(tmp_path / "examples" / "celery").findings
        if item.rule == "UNUSED_DEPENDENCY"
    }
    assert {"amqp", "kombu", "root-only-pkg"} <= example
    assert "sphinx" not in example


def test_subdirectory_scan_ignores_manifests_outside_it(tmp_path):
    write_tree(
        tmp_path,
        {
            "pyproject.toml": "[project]\nname = 'app'\nversion = '0.1'\ndependencies = ['pathspec']\n",
            "src/app.py": "def main():\n    return 1\n",
            "examples/requirements.txt": "requests\n",
        },
    )
    findings = [item for item in scan(tmp_path / "src").findings if item.rule == "UNUSED_DEPENDENCY"]
    assert {item.symbol for item in findings} == {"pathspec"}
    assert all(not item.path.startswith("examples/") for item in findings)


def test_literal_string_does_not_hide_an_unused_variable(tmp_path):
    path = tmp_path / "app.py"
    path.write_text(
        "from typing import Annotated, Literal\n"
        "\n"
        "fast = 1\n"
        "mode = Literal['fast']\n"
        "kind = Annotated[int, 'fast']\n"
        "\n"
        "def main():\n"
        "    return mode, kind\n"
        "\n"
        "if __name__ == '__main__':\n"
        "    main()\n",
        encoding="utf-8",
    )
    unused = {finding.symbol for finding in scan(tmp_path).findings if finding.rule == "UNUSED_VARIABLE"}
    assert "fast" in unused


def test_annotated_keeps_only_its_first_argument(tmp_path):
    path = tmp_path / "app.py"
    path.write_text(
        "from typing import TYPE_CHECKING, Annotated\n"
        "if TYPE_CHECKING:\n"
        "    from decimal import Decimal\n"
        "    from fractions import Fraction\n"
        "\n"
        "Alias = Annotated['Decimal', 'Fraction']\n",
        encoding="utf-8",
    )
    unused = {finding.symbol for finding in scan(tmp_path).findings if finding.rule == "UNUSED_IMPORT"}
    assert "Decimal" not in unused
    assert "Fraction" in unused


def test_dev_optional_extra_scores_70(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "vyarth.dependencies._distribution_map",
        lambda: {"click": ["click"]},
    )
    write_tree(
        tmp_path,
        {
            "pyproject.toml": (
                "[project]\n"
                "name = 'app'\n"
                "version = '0.1'\n"
                "\n"
                "[project.optional-dependencies]\n"
                "dev = ['ruff']\n"
                "cli = ['click']\n"
            ),
            "main.py": "if __name__ == '__main__':\n    print(1)\n",
        },
    )
    findings = {item.symbol: item for item in scan(tmp_path).findings if item.rule == "UNUSED_DEPENDENCY"}
    assert "ruff" not in findings
    assert findings["click"].confidence == 95
    from vyarth.config import Config

    reported = {
        item.symbol: item
        for item in scan(tmp_path, config=Config(report_dev_dependencies=True)).findings
        if item.rule == "UNUSED_DEPENDENCY"
    }
    assert reported["ruff"].confidence == 70
    assert "development or docs" in reported["ruff"].evidence[0]


def test_fix_keeps_a_suite_when_its_only_statement_is_removed(tmp_path):
    path = tmp_path / "a.py"
    path.write_text(
        "from typing import TYPE_CHECKING\n"
        "if TYPE_CHECKING:\n"
        "    from collections.abc import Iterator\n"
        "\n"
        "def handler(data):\n"
        "    try:\n"
        "        return data['k']\n"
        "    except KeyError:\n"
        "        missing = True\n"
        "\n"
        "def outer():\n"
        "    def inner():\n"
        "        return 1\n"
        "\n"
        "if __name__ == '__main__':\n"
        "    handler({})\n"
        "    outer()\n",
        encoding="utf-8",
    )
    apply_fixes(tmp_path, scan(path).findings)
    text = path.read_text(encoding="utf-8")
    ast = __import__("ast")
    ast.parse(text)
    assert "Iterator" not in text
    assert "missing = True" not in text
    assert "def inner" not in text
    assert text.count("pass") >= 3


def test_fix_leaves_assignments_with_side_effects(tmp_path):
    path = tmp_path / "a.py"
    path.write_text(
        "def ticker():\n"
        "    while True:\n"
        "        tick = yield\n"
        "        print('tick')\n"
        "\n"
        "def require(d):\n"
        "    value = d['token']\n"
        "    return True\n"
        "\n"
        "def bound(xs):\n"
        "    _x = (n := 10)\n"
        "    return n\n"
        "\n"
        "def plain():\n"
        "    unused = 1\n"
        "    return 0\n"
        "\n"
        "if __name__ == '__main__':\n"
        "    ticker()\n"
        "    require({})\n"
        "    bound([])\n"
        "    plain()\n",
        encoding="utf-8",
    )
    apply_fixes(tmp_path, scan(path).findings)
    text = path.read_text(encoding="utf-8")
    assert "tick = yield" in text
    assert "d['token']" in text
    assert "n :=" in text
    assert "unused = 1" not in text


def test_fix_preserves_crlf(tmp_path):
    path = tmp_path / "a.py"
    path.write_bytes(
        b"import os\r\n"
        b"def main():\r\n"
        b"    return 1\r\n"
        b"\r\n"
        b"if __name__ == '__main__':\r\n"
        b"    main()\r\n"
    )
    apply_fixes(tmp_path, scan(path).findings)
    raw = path.read_bytes()
    assert b"\r\n" in raw
    assert b"import os" not in raw
    assert b"\n" not in raw.replace(b"\r\n", b"")


def test_external_base_methods_score_60(tmp_path):
    write_tree(
        tmp_path,
        {
            "main.py": (
                "import json\n"
                "import threading\n"
                "\n"
                "class Enc(json.JSONEncoder):\n"
                "    def default(self, o):\n"
                "        return str(o)\n"
                "\n"
                "class Worker(threading.Thread):\n"
                "    def run(self):\n"
                "        return 1\n"
                "\n"
                "class Box:\n"
                "    def close(self):\n"
                "        return 1\n"
                "\n"
                "    def _shut(self):\n"
                "        return 1\n"
                "\n"
                "def main():\n"
                "    Enc()\n"
                "    Worker()\n"
                "    Box()\n"
                "\n"
                "if __name__ == '__main__':\n"
                "    main()\n"
            ),
        },
    )
    findings = {item.symbol: item for item in scan(tmp_path).findings if item.rule == "UNUSED_FUNCTION"}
    assert findings["default"].confidence == 60
    assert "external base" in findings["default"].evidence[-1]
    assert findings["run"].confidence == 60
    assert findings["close"].confidence == 60
    assert "Public name" in findings["close"].evidence[-1]
    assert findings["_shut"].confidence == 96


def test_builtin_alias_and_call_bases_score_60(tmp_path):
    write_tree(
        tmp_path,
        {
            "main.py": (
                "from typing import Generic, TypeVar\n"
                "\n"
                "T = TypeVar('T')\n"
                "Base = dict\n"
                "\n"
                "def with_metaclass(meta):\n"
                "    return meta\n"
                "\n"
                "class Bag(dict):\n"
                "    def missing(self):\n"
                "        return 1\n"
                "\n"
                "class Problem(Exception):\n"
                "    def explain(self):\n"
                "        return 1\n"
                "\n"
                "class Model(Base):\n"
                "    def save(self):\n"
                "        return 1\n"
                "\n"
                "class Box(Generic[T]):\n"
                "    def pack(self):\n"
                "        return 1\n"
                "\n"
                "class Built(with_metaclass(type)):\n"
                "    def seal(self):\n"
                "        return 1\n"
                "\n"
                "def main():\n"
                "    Bag()\n"
                "    Problem()\n"
                "    Model()\n"
                "    Box()\n"
                "    Built()\n"
                "\n"
                "if __name__ == '__main__':\n"
                "    main()\n"
            ),
        },
    )
    findings = {item.symbol: item for item in scan(tmp_path).findings if item.rule == "UNUSED_FUNCTION"}
    for name in ("missing", "explain", "save", "pack", "seal"):
        assert findings[name].confidence == 60
        assert "external base" in findings[name].evidence[-1]


def test_project_class_bases_stay_96(tmp_path):
    write_tree(
        tmp_path,
        {
            "pkg/__init__.py": "",
            "pkg/base.py": (
                "class Parent:\n"
                "    def hook(self):\n"
                "        return 1\n"
            ),
            "pkg/child.py": (
                "from typing import Generic, TypeVar\n"
                "from pkg.base import Parent\n"
                "\n"
                "T = TypeVar('T')\n"
                "\n"
                "class Local:\n"
                "    def keep(self):\n"
                "        return 1\n"
                "\n"
                "    def _keep(self):\n"
                "        return 1\n"
                "\n"
                "class Direct(Local):\n"
                "    def extra(self):\n"
                "        return 2\n"
                "\n"
                "class Imported(Parent):\n"
                "    def other(self):\n"
                "        return 3\n"
                "\n"
                "class Box(Generic[T]):\n"
                "    def pack(self):\n"
                "        return 4\n"
                "\n"
                "class Sub(Box[int]):\n"
                "    def seal(self):\n"
                "        return 5\n"
            ),
            "main.py": (
                "import pkg.child\n"
                "\n"
                "def main():\n"
                "    pkg.child.Local()\n"
                "    pkg.child.Direct()\n"
                "    pkg.child.Parent()\n"
                "    pkg.child.Imported()\n"
                "    pkg.child.Box()\n"
                "    pkg.child.Sub()\n"
                "\n"
                "if __name__ == '__main__':\n"
                "    main()\n"
            ),
        },
    )
    findings = {item.symbol: item for item in scan(tmp_path).findings if item.rule == "UNUSED_FUNCTION"}
    assert findings["extra"].confidence == 60
    assert findings["other"].confidence == 60
    assert findings["seal"].confidence == 60
    assert findings["keep"].confidence == 60
    assert findings["_keep"].confidence == 96
    assert findings["pack"].confidence == 60


def test_duplicate_hash_keeps_free_names(tmp_path):
    write_tree(
        tmp_path,
        {
            "a.py": (
                "def clamp_low(a, b, c, d):\n"
                "    x = min(a, b)\n"
                "    y = min(c, d)\n"
                "    z = min(x, y)\n"
                "    print(z)\n"
                "    return z\n"
                "\n"
                "def clamp_high(a, b, c, d):\n"
                "    x = max(a, b)\n"
                "    y = max(c, d)\n"
                "    z = max(x, y)\n"
                "    print(z)\n"
                "    return z\n"
                "\n"
                "def main():\n"
                "    return clamp_low(1, 2, 3, 4) + clamp_high(1, 2, 3, 4)\n"
                "\n"
                "if __name__ == '__main__':\n"
                "    main()\n"
            ),
        },
    )
    assert not any(item.rule == "DUPLICATE_CODE" for item in scan(tmp_path).findings)


def test_unknown_distribution_scores_70(tmp_path, monkeypatch):
    monkeypatch.setattr("vyarth.dependencies._distribution_map", lambda: {})
    write_tree(
        tmp_path,
        {
            "pyproject.toml": "[project]\nname = 'app'\nversion = '0.1'\ndependencies = ['attrs']\n",
            "main.py": "import attr\nattr\n",
        },
    )
    finding = next(item for item in scan(tmp_path).findings if item.rule == "UNUSED_DEPENDENCY")
    assert finding.symbol == "attrs"
    assert finding.confidence == 70
    assert "metadata" in finding.evidence[0]


def test_namespace_distributions_are_not_all_marked_used(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "vyarth.dependencies._distribution_map",
        lambda: {"google": ["google-cloud-storage", "protobuf"]},
    )
    write_tree(
        tmp_path,
        {
            "pyproject.toml": (
                "[project]\n"
                "name = 'app'\n"
                "version = '0.1'\n"
                "dependencies = ['google-cloud-storage', 'protobuf']\n"
            ),
            "main.py": "import google\ngoogle\n",
        },
    )
    findings = {item.symbol: item for item in scan(tmp_path).findings if item.rule == "UNUSED_DEPENDENCY"}
    assert findings["google-cloud-storage"].confidence == 70
    assert findings["protobuf"].confidence == 70


def test_dotted_import_uses_the_distribution_that_provides_it(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "vyarth.dependencies._distribution_map",
        lambda: {"google": ["google-cloud-storage", "protobuf"]},
    )
    monkeypatch.setattr(
        "vyarth.dependencies._distribution_provides",
        lambda name, module: name == "protobuf" and module == "google.protobuf",
    )
    write_tree(
        tmp_path,
        {
            "pyproject.toml": (
                "[project]\n"
                "name = 'app'\n"
                "version = '0.1'\n"
                "dependencies = ['google-cloud-storage', 'protobuf']\n"
            ),
            "main.py": "import google.protobuf\ngoogle.protobuf\n",
        },
    )
    findings = {item.symbol: item for item in scan(tmp_path).findings if item.rule == "UNUSED_DEPENDENCY"}
    assert "protobuf" not in findings
    assert findings["google-cloud-storage"].confidence == 70


def test_requirements_bom_does_not_hide_the_first_package(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "vyarth.dependencies._distribution_map",
        lambda: {"requests": ["requests"]},
    )
    (tmp_path / "requirements.txt").write_bytes(b"\xef\xbb\xbfrequests\nclick\n")
    (tmp_path / "main.py").write_text("if __name__ == '__main__':\n    print(1)\n", encoding="utf-8")
    findings = {item.symbol: item for item in scan(tmp_path).findings if item.rule == "UNUSED_DEPENDENCY"}
    assert findings["requests"].confidence == 95
    assert findings["click"].confidence == 70


def test_bom_and_coding_cookie_files_are_indexed(tmp_path):
    bom = tmp_path / "bom.py"
    bom.write_bytes(b"\xef\xbb\xbfdef dead():\n    return 1\n")
    latin = tmp_path / "latin.py"
    latin.write_bytes("# -*- coding: latin-1 -*-\nvalue = 'caf\xe9'\n".encode("latin-1"))
    bom_result = scan(bom)
    latin_result = scan(latin)
    assert bom_result.errors == ()
    assert any(item.symbol == "dead" for item in bom_result.findings)
    assert latin_result.errors == ()
    fixed = tmp_path / "fixed.py"
    fixed.write_bytes(
        b"\xef\xbb\xbfimport os\n"
        b"def main():\n"
        b"    return 1\n"
        b"\n"
        b"if __name__ == '__main__':\n"
        b"    main()\n"
    )
    apply_fixes(tmp_path, scan(fixed).findings)
    raw = fixed.read_bytes()
    assert raw.startswith(b"\xef\xbb\xbf")
    assert b"import os" not in raw


def test_symlinked_requirements_outside_the_root_do_not_abort(tmp_path):
    root = tmp_path / "api"
    shared = tmp_path / "shared"
    write_tree(
        root,
        {
            "pyproject.toml": "[project]\nname = 'api'\nversion = '0.1'\n",
            "app.py": "def dead():\n    return 1\n",
        },
    )
    shared.mkdir()
    (shared / "requirements.txt").write_text("not-a-real-package\n", encoding="utf-8")
    link = root / "requirements.txt"
    try:
        link.symlink_to(shared / "requirements.txt")
    except OSError:
        pytest.skip("symlinks are not available")
    result = scan(root)
    assert result.errors == ()
    assert any(item.symbol == "dead" for item in result.findings)


def test_nested_directory_is_its_own_package_root(tmp_path):
    write_tree(
        tmp_path,
        {
            "pyproject.toml": "[project]\nname = 'repo'\nversion = '0.1'\n",
            "examples/app/main.py": (
                "import app.service\n"
                "\n"
                "def main():\n"
                "    return app.service.run()\n"
                "\n"
                "if __name__ == '__main__':\n"
                "    main()\n"
            ),
            "examples/app/app/__init__.py": "",
            "examples/app/app/service.py": "def run():\n    return 1\n\ndef spare():\n    return 2\n",
        },
    )
    result = scan(tmp_path / "examples" / "app")
    spare = [item for item in result.findings if item.symbol == "spare"]
    assert len(spare) == 1
    assert spare[0].path.endswith("app/service.py")
    assert not any(item.symbol == "run" for item in result.findings)


def test_scanning_a_package_directory_keeps_its_name(tmp_path):
    write_tree(
        tmp_path,
        {
            "pyproject.toml": "[project]\nname = 'repo'\nversion = '0.1'\n",
            "mypkg/__init__.py": (
                "from .service import run\n"
                "from .sub import child\n"
                "\n"
                "def main():\n"
                "    return run() + child()\n"
                "\n"
                "if __name__ == '__main__':\n"
                "    main()\n"
            ),
            "mypkg/service.py": "def run():\n    return 1\n\ndef spare():\n    return 2\n",
            "mypkg/sub/__init__.py": "from ..service import run\n\ndef child():\n    return run()\n",
            "mypkg/logging.py": "def note():\n    return 1\n",
            "src/mypkg/__init__.py": (
                "from .service import run\n"
                "from .sub import child\n"
                "\n"
                "def main():\n"
                "    return run() + child()\n"
                "\n"
                "if __name__ == '__main__':\n"
                "    main()\n"
            ),
            "src/mypkg/service.py": "def run():\n    return 1\n\ndef spare():\n    return 2\n",
            "src/mypkg/sub/__init__.py": "from ..service import run\n\ndef child():\n    return run()\n",
            "src/mypkg/logging.py": "def note():\n    return 1\n",
        },
    )
    for folder in (tmp_path / "mypkg", tmp_path / "src" / "mypkg"):
        symbols = {item.symbol for item in scan(folder).findings}
        assert "spare" in symbols
        assert "note" in symbols
        assert "run" not in symbols


def test_unused_comprehension_target_is_not_reported(tmp_path):
    path = tmp_path / "a.py"
    path.write_text("def f():\n    return [1 for i in range(3)]\n\nf()\n", encoding="utf-8")
    assert not [item for item in scan(path).findings if item.symbol == "i"]


def test_ignore_bases_covers_a_class_nested_in_a_function(tmp_path):
    write_tree(
        tmp_path,
        {
            "vyarth.toml": 'ignore_bases = ["Plugin"]\n',
            "app.py": (
                "class Plugin:\n"
                "    pass\n"
                "\n"
                "def factory():\n"
                "    class Impl(Plugin):\n"
                "        def handle(self):\n"
                "            return 1\n"
                "    return Impl\n"
                "\n"
                "if __name__ == '__main__':\n"
                "    factory()\n"
            ),
        },
    )
    assert not any(item.symbol == "handle" for item in scan(tmp_path).findings)
