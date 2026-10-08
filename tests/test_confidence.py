from tests.conftest import write_tree
from vyarth import scan


def test_unused_module_caps_a_function(tmp_path):
    write_tree(
        tmp_path,
        {
            "main.py": "if __name__ == '__main__':\n    print(1)\n",
            "lone.py": "def helper():\n    return 1\n",
        },
    )
    finding = next(item for item in scan(tmp_path).findings if item.symbol == "helper")
    assert finding.confidence == 82
    assert "no incoming imports" in finding.evidence[-1]


def test_dynamic_import_caps_a_function_with_the_module(tmp_path):
    write_tree(
        tmp_path,
        {
            "dyn.py": "import importlib\nimportlib.import_module('missing')\n",
            "lone.py": "def helper():\n    return 1\n",
            "main.py": "import dyn\nif __name__ == '__main__':\n    print(dyn)\n",
        },
    )
    finding = next(item for item in scan(tmp_path).findings if item.symbol == "helper")
    assert finding.confidence == 60


def test_reached_module_keeps_a_high_function_score(tmp_path):
    write_tree(
        tmp_path,
        {
            "live.py": "def helper():\n    return 1\n",
            "main.py": "import live\nif __name__ == '__main__':\n    print(live)\n",
        },
    )
    finding = next(item for item in scan(tmp_path).findings if item.symbol == "helper")
    assert finding.confidence == 96
    assert "no incoming imports" not in " ".join(finding.evidence)


def test_duplicate_in_a_reached_module_stays_at_90(tmp_path):
    body = (
        "    item = value\n"
        "    item = item + 1\n"
        "    item = item + 1\n"
        "    item = item + 1\n"
        "    return item\n"
    )
    write_tree(
        tmp_path,
        {
            "pkg/__init__.py": "",
            "pkg/a.py": f"def save_a(value):\n{body}",
            "pkg/b.py": (
                "def save_b(other):\n"
                "    item = other\n"
                "    item = item + 1\n"
                "    item = item + 1\n"
                "    item = item + 1\n"
                "    return item\n"
            ),
            "main.py": "import pkg.a\nimport pkg.b\nif __name__ == '__main__':\n    print(pkg.a, pkg.b)\n",
        },
    )
    finding = next(item for item in scan(tmp_path).findings if item.rule == "DUPLICATE_CODE")
    assert finding.confidence == 90
    assert finding.evidence == ("pkg/a.py:save_a",)


def test_unrecognized_decorator_scores_75(tmp_path):
    write_tree(
        tmp_path,
        {
            "app.py": "def deco(fn):\n    return fn\n\n@deco\ndef startup():\n    return 1\n",
            "main.py": "import app\nif __name__ == '__main__':\n    print(app)\n",
        },
    )
    finding = next(item for item in scan(tmp_path).findings if item.symbol == "startup")
    assert finding.confidence == 75
    assert "not a recognized framework entry" in " ".join(finding.evidence)


def test_alembic_names_score_70_and_stay_reported(tmp_path):
    write_tree(
        tmp_path,
        {
            "alembic/versions/001_init.py": "revision = '001'\n\ndef upgrade():\n    pass\n\ndef downgrade():\n    pass\n",
            "main.py": "if __name__ == '__main__':\n    print(1)\n",
        },
    )
    findings = [item for item in scan(tmp_path).findings if item.symbol == "upgrade"]
    assert len(findings) == 1
    assert findings[0].confidence == 70
    assert "Alembic loads this name" in findings[0].evidence[-1]


def test_requirement_aliases_score_70_when_the_import_name_is_used(tmp_path, monkeypatch):
    monkeypatch.setattr("vyarth.dependencies._distribution_map", lambda: {})
    write_tree(
        tmp_path,
        {
            "requirements.txt": "psycopg2-binary==2\npython-dotenv==1\npython-jose==3\n",
            "app.py": "import psycopg2\nimport dotenv\nimport jose\npsycopg2\ndotenv\njose\n",
            "main.py": "import app\nif __name__ == '__main__':\n    print(app)\n",
        },
    )
    findings = {item.symbol: item for item in scan(tmp_path).findings if item.rule == "UNUSED_DEPENDENCY"}
    assert findings["psycopg2-binary"].confidence == 70
    assert "psycopg2" in findings["psycopg2-binary"].evidence[0]
    assert findings["python-dotenv"].confidence == 70
    assert findings["python-jose"].confidence == 70


def test_requirement_alias_scores_70_when_the_import_is_used(tmp_path, monkeypatch):
    monkeypatch.setattr("vyarth.dependencies._distribution_map", lambda: {})
    write_tree(
        tmp_path,
        {
            "requirements.txt": "pyjwt==2\nurllib3==2\n",
            "app.py": "import jwt\njwt\n",
            "main.py": "import app\nif __name__ == '__main__':\n    print(app)\n",
        },
    )
    findings = {item.symbol: item for item in scan(tmp_path).findings if item.rule == "UNUSED_DEPENDENCY"}
    assert findings["pyjwt"].confidence == 70
    assert "jwt" in findings["pyjwt"].evidence[0]
    assert findings["urllib3"].confidence == 95


def test_requirement_alias_stays_95_when_neither_name_is_imported(tmp_path):
    write_tree(
        tmp_path,
        {
            "requirements.txt": "pyjwt==2\n",
            "main.py": "if __name__ == '__main__':\n    print(1)\n",
        },
    )
    finding = next(item for item in scan(tmp_path).findings if item.symbol == "pyjwt")
    assert finding.confidence == 95


def test_unreachable_code_is_not_capped(tmp_path):
    write_tree(
        tmp_path,
        {
            "lone.py": "def helper():\n    return 1\n    value = 2\n",
            "main.py": "if __name__ == '__main__':\n    print(1)\n",
        },
    )
    finding = next(item for item in scan(tmp_path).findings if item.rule == "UNREACHABLE_CODE")
    assert finding.confidence == 100
