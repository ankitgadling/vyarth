from vyarth import scan
from vyarth.fix import apply_fixes, is_fixable
from vyarth.model import Finding


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
    assert yields == []
    apply_fixes(tmp_path, result.findings)
    assert path.read_text(encoding="utf-8") == source
    stale = Finding(
        rule="UNREACHABLE_CODE",
        path="mod.py",
        line=3,
        column=5,
        symbol="yield b''",
        status="DEAD",
        confidence=100,
        message="Control flow terminates before this statement.",
        evidence=("Control flow terminates before this statement.",),
        fingerprint="UNREACHABLE_CODE:mod.py:gen",
    )
    assert is_fixable(stale, source) is False
    apply_fixes(tmp_path, [stale])
    assert path.read_text(encoding="utf-8") == source


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
    result = scan(tmp_path)
    yields = [finding for finding in result.findings if finding.rule == "UNREACHABLE_CODE" and "yield" in finding.symbol]
    assert [finding.symbol.strip() for finding in yields] == ["yield 2"]
    apply_fixes(tmp_path, result.findings)
    text = path.read_text(encoding="utf-8")
    assert "yield 1" in text
    assert "yield 2" not in text


def test_only_yield_in_an_empty_loop_is_not_unreachable(tmp_path):
    assert _unreachable(
        tmp_path,
        "def gen():\n"
        "    for _ in ():\n"
        "        yield\n"
        "\n"
        "gen()\n",
    ) == []


def test_assert_does_not_end_the_block(tmp_path):
    assert _unreachable(
        tmp_path,
        "def foo():\n"
        "    assert False\n"
        "    return 1\n"
        "\n"
        "foo()\n",
    ) == []


def test_suppressing_with_does_not_kill_the_next_statement(tmp_path):
    source = (
        "from contextlib import suppress\n"
        "\n"
        "def lookup(cache, key):\n"
        "    with suppress(KeyError):\n"
        "        return cache[key]\n"
        "        print('inside')\n"
        "    return compute(key)\n"
        "\n"
        "def compute(key):\n"
        "    return key * 2\n"
        "\n"
        "if __name__ == '__main__':\n"
        "    print(lookup({}, 3))\n"
    )
    assert _unreachable(tmp_path, source) == ["print('inside')"]
    path = tmp_path / "mod.py"
    apply_fixes(tmp_path, scan(path).findings)
    text = path.read_text(encoding="utf-8")
    assert "return compute(key)" in text
    assert "def compute" in text
