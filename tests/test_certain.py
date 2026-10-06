from tests.conftest import write_tree
from vyarth import scan


def test_reached_package_reports_only_certain_dead_code_at_100(tmp_path):
    write_tree(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/forgotten.py": "def buried():\n    return 1\n",
            "app/service.py": (
                "import json\n"
                "import math\n"
                "\n"
                'TITLE = "spare"\n'
                "\n"
                "class Box:\n"
                "    limit = 1\n"
                "\n"
                "    def close(self):\n"
                "        return 1\n"
                "\n"
                "def unused_module_function():\n"
                "    return 1\n"
                "\n"
                "def outer():\n"
                "    debug_value = 123\n"
                "\n"
                "    def helper():\n"
                "        return 1\n"
                "\n"
                "    def used_inner():\n"
                "        return 2\n"
                "\n"
                "    return used_inner()\n"
                '    print("never")\n'
                "\n"
                "def run():\n"
                "    Box()\n"
                "    return outer() + math.floor(1)\n"
            ),
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
    result = scan(tmp_path)
    certain = {
        (finding.rule, finding.symbol, finding.path)
        for finding in result.findings
        if finding.confidence == 100
    }
    assert certain == {
        ("UNUSED_IMPORT", "json", "app/service.py"),
        ("UNUSED_VARIABLE", "TITLE", "app/service.py"),
        ("UNUSED_VARIABLE", "debug_value", "app/service.py"),
        ("UNUSED_FUNCTION", "helper", "app/service.py"),
        ("UNREACHABLE_CODE", 'print("never")', "app/service.py"),
    }
    assert all(finding.status == "DEAD" for finding in result.findings if finding.confidence == 100)

    by_symbol = {finding.symbol: finding for finding in result.findings}
    for symbol in ("unused_module_function", "close", "limit"):
        assert by_symbol[symbol].confidence == 96
    assert by_symbol["buried"].confidence == 82
    for name in ("run", "outer", "used_inner", "Box", "math"):
        assert name not in by_symbol
