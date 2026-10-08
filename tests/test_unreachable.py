from vyarth import scan
from vyarth.fix import apply_fixes, is_fixable


def _unreachable(tmp_path, source: str) -> list[str]:
    path = tmp_path / "mod.py"
    path.write_text(source, encoding="utf-8")
    return [finding.symbol for finding in scan(path).findings if finding.rule == "UNREACHABLE_CODE"]


def test_code_after_return_and_raise(tmp_path):
    assert _unreachable(
        tmp_path,
        "def foo():\n"
        "    return 1\n"
        "    print('never')\n"
        "\n"
        "foo()\n",
    ) == ["print('never')"]
    assert _unreachable(
        tmp_path,
        "def foo():\n"
        "    raise ValueError()\n"
        "    do_something()\n"
        "\n"
        "foo()\n",
    ) == ["do_something()"]


def test_constant_false_and_true_branches(tmp_path):
    assert _unreachable(
        tmp_path,
        "def foo():\n"
        "    if False:\n"
        "        print('no')\n"
        "    return 1\n"
        "\n"
        "foo()\n",
    ) == ["print('no')"]
    assert _unreachable(
        tmp_path,
        "def foo():\n"
        "    if True:\n"
        "        return 1\n"
        "    else:\n"
        "        print('no')\n"
        "\n"
        "foo()\n",
    ) == ["print('no')"]


def test_while_false_body_is_unreachable_and_the_following_code_is_not(tmp_path):
    path = tmp_path / "mod.py"
    path.write_text(
        "def foo():\n"
        "    while False:\n"
        "        print('no')\n"
        "    print('yes')\n"
        "\n"
        "foo()\n",
        encoding="utf-8",
    )
    result = scan(path)
    unreachable = [finding.symbol for finding in result.findings if finding.rule == "UNREACHABLE_CODE"]
    assert unreachable == ["print('no')"]
    assert all(finding.symbol != "print('yes')" for finding in result.findings)


def test_both_branches_exiting_makes_the_next_statement_unreachable(tmp_path):
    findings_source = (
        "def foo(flag):\n"
        "    if flag:\n"
        "        return 1\n"
        "    else:\n"
        "        raise ValueError('no')\n"
        "    cleanup()\n"
        "\n"
        "foo(True)\n"
    )
    path = tmp_path / "mod.py"
    path.write_text(findings_source, encoding="utf-8")
    result = scan(path)
    unreachable = [finding for finding in result.findings if finding.rule == "UNREACHABLE_CODE"]
    assert len(unreachable) == 1
    assert unreachable[0].symbol == "cleanup()"
    assert unreachable[0].message == "Control flow terminates before this statement."
    assert unreachable[0].confidence == 100


def test_break_makes_the_rest_of_the_loop_body_unreachable(tmp_path):
    assert _unreachable(
        tmp_path,
        "def foo():\n"
        "    for i in range(3):\n"
        "        break\n"
        "        print('no')\n"
        "    return i\n"
        "\n"
        "foo()\n",
    ) == ["print('no')"]


def test_named_conditions_are_not_folded(tmp_path):
    path = tmp_path / "mod.py"
    path.write_text(
        "DEBUG = False\n"
        "\n"
        "def foo():\n"
        "    if DEBUG:\n"
        "        print('maybe')\n"
        "    return 1\n"
        "\n"
        "foo()\n",
        encoding="utf-8",
    )
    result = scan(path)
    assert result.findings == ()


def test_fix_keeps_the_yield_that_makes_a_generator(tmp_path):
    path = tmp_path / "mod.py"
    source = (
        "def gen():\n"
        "    raise RuntimeError('closed')\n"
        "    yield b''\n"
        "\n"
        "gen()\n"
    )
    path.write_text(source, encoding="utf-8")
    result = scan(tmp_path)
    yields = [finding for finding in result.findings if finding.rule == "UNREACHABLE_CODE" and "yield" in finding.symbol]
    assert len(yields) == 1
    assert is_fixable(yields[0], source) is False
    apply_fixes(tmp_path, result.findings)
    assert "yield b''" in path.read_text(encoding="utf-8")


def test_fix_deletes_an_extra_unreachable_yield(tmp_path):
    path = tmp_path / "mod.py"
    path.write_text(
        "def gen():\n"
        "    yield 1\n"
        "    return\n"
        "    yield 2\n"
        "\n"
        "gen()\n",
        encoding="utf-8",
    )
    apply_fixes(tmp_path, scan(tmp_path).findings)
    text = path.read_text(encoding="utf-8")
    assert "yield 1" in text
    assert "yield 2" not in text


def test_assert_does_not_end_the_block(tmp_path):
    assert _unreachable(
        tmp_path,
        "def foo():\n"
        "    assert False\n"
        "    return 1\n"
        "\n"
        "foo()\n",
    ) == []
