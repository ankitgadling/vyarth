from vyarth.python_index import PythonAstBackend
from vyarth import scan


def _index(source: str):
    return PythonAstBackend().index_source("mod.py", source)


def _reads(source: str) -> dict[str, int]:
    index = _index(source)
    return {binding.qualname: binding.read_count for binding in index.bindings}


def test_module_and_local_names_are_separate():
    reads = _reads(
        "x = 10\n"
        "\n"
        "def foo():\n"
        "    x = 20\n"
        "    print(x)\n"
    )
    assert reads["x"] == 0
    assert reads["foo.x"] == 1


def test_shadowed_module_variable_is_reported(tmp_path):
    path = tmp_path / "mod.py"
    path.write_text("x = 10\n\ndef foo():\n    x = 20\n    print(x)\n", encoding="utf-8")
    result = scan(path)
    symbols = {(finding.rule, finding.symbol) for finding in result.findings}
    assert ("UNUSED_VARIABLE", "x") in symbols
    assert ("UNUSED_FUNCTION", "foo") in symbols
    assert not any(finding.symbol == "x" and finding.line != 1 for finding in result.findings)


def test_global_reads_the_module_binding():
    reads = _reads(
        "x = 10\n"
        "\n"
        "def foo():\n"
        "    global x\n"
        "    print(x)\n"
    )
    assert reads["x"] == 1
    assert "foo.x" not in reads


def test_nonlocal_reads_the_enclosing_binding():
    reads = _reads(
        "def outer():\n"
        "    x = 1\n"
        "    def inner():\n"
        "        nonlocal x\n"
        "        print(x)\n"
        "    return inner\n"
    )
    assert reads["outer.x"] == 1
    assert reads["outer.inner"] == 1


def test_method_does_not_read_class_variable():
    reads = _reads(
        "x = 10\n"
        "\n"
        "class A:\n"
        "    x = 20\n"
        "    def m(self):\n"
        "        return x\n"
    )
    assert reads["x"] == 1
    assert reads["A.x"] == 0


def test_class_body_can_read_its_own_name():
    reads = _reads(
        "class A:\n"
        "    x = 1\n"
        "    y = x\n"
    )
    assert reads["A.x"] == 1


def test_class_body_same_name_reads_the_enclosing_binding():
    reads = _reads(
        "version = '/v1'\n"
        "\n"
        "class API:\n"
        "    version = version\n"
        "    label = version\n"
    )
    assert reads["version"] == 1
    assert reads["API.version"] == 1
    assert reads["API.label"] == 0


def test_class_body_load_before_assignment_reads_the_enclosing_binding():
    reads = _reads(
        "version = '/v1'\n"
        "\n"
        "class API:\n"
        "    label = version\n"
        "    version = 1\n"
    )
    assert reads["version"] == 1
    assert reads["API.version"] == 0


def test_class_body_reassignment_reads_the_class_attribute():
    reads = _reads(
        "version = '/v1'\n"
        "\n"
        "class API:\n"
        "    version = 1\n"
        "    version = version\n"
    )
    assert reads["version"] == 0
    assert reads["API.version"] == 1


def test_class_loop_iter_reads_the_enclosing_binding():
    reads = _reads(
        "version = (1,)\n"
        "\n"
        "class API:\n"
        "    for version in version:\n"
        "        pass\n"
    )
    assert reads["version"] == 1
    assert reads["API.version"] == 0


def test_copied_module_name_is_used(tmp_path):
    path = tmp_path / "mod.py"
    path.write_text(
        "version = '/v1'\n"
        "\n"
        "class API:\n"
        "    version = version\n"
        "\n"
        "def main():\n"
        "    return API.version\n"
        "\n"
        "if __name__ == '__main__':\n"
        "    main()\n",
        encoding="utf-8",
    )
    assert not any(finding.symbol == "version" for finding in scan(path).findings)


def test_comprehension_keeps_its_targets_and_reads_outer_names():
    source = (
        "def flatten(groups):\n"
        "    return [item for group in groups for item in group]\n"
    )
    reads = _reads(source)
    assert reads["flatten.groups"] == 1
    group = next(binding for binding in _index(source).bindings if binding.name == "group")
    assert group.scope_kind == "comprehension"
    assert group.read_count == 1


def test_walrus_binds_in_the_enclosing_function():
    source = (
        "def collect(items):\n"
        "    rows = [(z := item) for item in items]\n"
        "    return rows\n"
    )
    index = _index(source)
    walrus = next(binding for binding in index.bindings if binding.name == "z")
    assert walrus.qualname == "collect.z"
    assert walrus.scope_kind == "function"
    assert walrus.read_count == 0
    item = next(binding for binding in index.bindings if binding.name == "item")
    assert item.scope_kind == "comprehension"
    assert item.read_count == 1
