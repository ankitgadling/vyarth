from vyarth import scan


def _findings(tmp_path, source: str):
    path = tmp_path / "mod.py"
    path.write_text(source, encoding="utf-8")
    return scan(path).findings


def test_spec_example_reports_the_unread_local(tmp_path):
    findings = _findings(
        tmp_path,
        "def calculate_total(data):\n"
        "    result = sum(data)\n"
        "    debug_value = 123\n"
        "\n"
        "    return result\n"
        "\n"
        "calculate_total([])\n",
    )
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule == "UNUSED_VARIABLE"
    assert finding.path == "mod.py"
    assert finding.line == 3
    assert finding.symbol == "debug_value"
    assert finding.confidence == 100
    assert finding.status == "DEAD"
    assert finding.fingerprint == "UNUSED_VARIABLE:mod.py:calculate_total.debug_value"


def test_unused_function_class_constant_and_base_class(tmp_path):
    findings = _findings(
        tmp_path,
        "LIMIT = 5\n"
        "\n"
        "def helper():\n"
        "    return 1\n"
        "\n"
        "class A:\n"
        "    pass\n"
        "\n"
        "class B(A):\n"
        "    pass\n",
    )
    found = {(finding.rule, finding.symbol) for finding in findings}
    assert ("UNUSED_VARIABLE", "LIMIT") in found
    assert ("UNUSED_FUNCTION", "helper") in found
    assert ("UNUSED_CLASS", "B") in found
    assert ("UNUSED_CLASS", "A") not in found


def test_class_body_symbols_are_not_reported(tmp_path):
    findings = _findings(
        tmp_path,
        "class A:\n"
        "    value = 1\n"
        "    def method(self):\n"
        "        return 1\n",
    )
    assert {(finding.rule, finding.symbol) for finding in findings} == {("UNUSED_CLASS", "A")}


def test_unused_nested_function_is_reported_when_the_outer_function_is_used(tmp_path):
    findings = _findings(
        tmp_path,
        "def outer():\n"
        "    def helper():\n"
        "        return 1\n"
        "    return 2\n"
        "\n"
        "outer()\n",
    )
    assert {(finding.rule, finding.symbol) for finding in findings} == {("UNUSED_FUNCTION", "helper")}


def test_nested_function_that_is_called_is_used(tmp_path):
    findings = _findings(
        tmp_path,
        "def outer():\n"
        "    def helper():\n"
        "        return 1\n"
        "    return helper()\n"
        "\n"
        "outer()\n",
    )
    assert findings == ()


def test_decorator_uses_the_decorator_and_not_the_decorated_function(tmp_path):
    findings = _findings(
        tmp_path,
        "def deco(fn):\n"
        "    return fn\n"
        "\n"
        "@deco\n"
        "def target():\n"
        "    return 1\n",
    )
    assert {(finding.rule, finding.symbol) for finding in findings} == {("UNUSED_FUNCTION", "target")}


def test_all_marks_the_exported_name_used(tmp_path):
    findings = _findings(
        tmp_path,
        "def external_api():\n"
        "    return 1\n"
        "\n"
        "__all__ = ['external_api']\n",
    )
    assert findings == ()


def test_parameters_underscore_and_dunder_names_are_not_reported(tmp_path):
    findings = _findings(
        tmp_path,
        "__all__ = ['kept']\n"
        "__version__ = '1'\n"
        "\n"
        "def kept(value):\n"
        "    for _ in range(value):\n"
        "        pass\n"
        "    return 1\n"
        "\n"
        "kept(1)\n",
    )
    assert findings == ()


def test_method_local_helper_is_reported(tmp_path):
    findings = _findings(
        tmp_path,
        "class A:\n"
        "    def method(self):\n"
        "        def helper():\n"
        "            return 1\n"
        "        return 1\n"
        "\n"
        "A()\n",
    )
    found = {(finding.rule, finding.symbol) for finding in findings}
    assert ("UNUSED_FUNCTION", "helper") in found
    method = next(finding for finding in findings if finding.symbol == "method")
    assert method.rule == "UNUSED_FUNCTION"
    assert method.confidence == 96
    assert "A" not in {symbol for _, symbol in found}
