"""Verified fixes, rollback, and the 90-99 review queue."""

import hashlib
import subprocess
import sys

from tests.conftest import write_tree
from vyarth.cli import main
from vyarth.fix import apply_fixes_verified
from vyarth.verify import VerifyResult
from vyarth import scan


def _git(root, *args):
    subprocess.run(["git", *args], cwd=root, check=True, capture_output=True, text=True)


def _commit(root):
    _git(root, "init")
    _git(root, "add", ".")
    _git(root, "-c", "user.email=vyarth@example.com", "-c", "user.name=vyarth", "commit", "-m", "init")


def test_verify_rolls_back_a_side_effect_and_keeps_the_bytes(tmp_path, capsys):
    write_tree(
        tmp_path,
        {
            "app.py": "import register\n\ndef main():\n    return 1\n\nif __name__ == '__main__':\n    main()\n",
            "register.py": "from pathlib import Path\nPath('ran.txt').write_text('yes')\n",
            "check.py": (
                "import pathlib\n"
                "import runpy\n"
                "path = pathlib.Path('ran.txt')\n"
                "path.unlink(missing_ok=True)\n"
                "runpy.run_path('app.py', run_name='app')\n"
                "if not path.is_file():\n"
                "    raise SystemExit(1)\n"
            ),
        },
    )
    target = tmp_path / "app.py"
    before = target.read_bytes()
    command = subprocess.list2cmdline([sys.executable, "check.py"])
    assert main(["fix", str(tmp_path), "--verify", command, "--quiet"]) == 3
    assert target.read_bytes() == before
    assert hashlib.sha256(target.read_bytes()).hexdigest() == hashlib.sha256(before).hexdigest()
    payload = __import__("json").loads(capsys.readouterr().out)
    assert payload["verified"] is False
    assert payload["rolled_back"] is True
    assert payload["failed_step"] == "command"
    assert list((tmp_path / ".vyarth" / "backup").iterdir())


def test_verify_timeout_rolls_back(tmp_path):
    write_tree(
        tmp_path,
        {
            "app.py": "import os\n\ndef main():\n    return 1\n\nif __name__ == '__main__':\n    main()\n",
            "sleep.py": "import time\ntime.sleep(15)\n",
        },
    )
    before = (tmp_path / "app.py").read_bytes()
    findings = [item for item in scan(tmp_path).findings if item.symbol == "os"]
    command = subprocess.list2cmdline([sys.executable, "sleep.py"])
    report = apply_fixes_verified(tmp_path, findings, verify_cmd=command, timeout=1)
    assert report.rolled_back is True
    assert report.failed_step == "timeout"
    assert (tmp_path / "app.py").read_bytes() == before


def test_select_id_fixes_only_the_named_import(tmp_path, capsys):
    path = tmp_path / "app.py"
    path.write_text("import os\nimport sys\n", encoding="utf-8")
    findings = {item.symbol: item for item in scan(tmp_path).findings if item.rule == "UNUSED_IMPORT"}
    assert main(["fix", str(tmp_path), "--select-id", findings["os"].id, "--dry-run", "--quiet"]) == 1
    notes = capsys.readouterr().out
    assert "os" in notes
    assert "sys" not in notes
    assert "import sys" in path.read_text(encoding="utf-8")


def test_an_edit_outside_dirty_lines_still_applies(tmp_path):
    write_tree(
        tmp_path,
        {"app.py": "import json\n\ndef main():\n    return 1\n\nif __name__ == '__main__':\n    main()\n\nmarker = 1\n"},
    )
    _commit(tmp_path)
    path = tmp_path / "app.py"
    path.write_text(path.read_text(encoding="utf-8").replace("marker = 1", "marker = 2"), encoding="utf-8")
    assert main(["fix", str(tmp_path), "--verify", "--quiet"]) == 1
    text = path.read_text(encoding="utf-8")
    assert "import json" not in text
    assert "marker = 2" in text


def test_an_edit_on_a_dirty_line_is_refused(tmp_path, capsys):
    write_tree(
        tmp_path,
        {"app.py": "import json\n\ndef main():\n    return 1\n\nif __name__ == '__main__':\n    main()\n"},
    )
    _commit(tmp_path)
    path = tmp_path / "app.py"
    path.write_text(path.read_text(encoding="utf-8").replace("import json", "import json  # local"), encoding="utf-8")
    dirty = path.read_bytes()
    assert main(["fix", str(tmp_path), "--verify", "--quiet"]) == 1
    assert path.read_bytes() == dirty
    assert "dirty_lines" in capsys.readouterr().err


def test_require_clean_refuses_a_dirty_worktree(tmp_path, capsys):
    write_tree(tmp_path, {"app.py": "import os\n"})
    _commit(tmp_path)
    path = tmp_path / "app.py"
    path.write_text("import os\nvalue = 1\n", encoding="utf-8")
    before = path.read_bytes()
    assert main(["fix", str(tmp_path), "--require-clean", "--quiet"]) == 2
    assert "dirty worktree" in capsys.readouterr().err
    assert path.read_bytes() == before


def test_unsafe_fixes_need_a_selected_id_and_leave_module_level_names(tmp_path, capsys):
    write_tree(
        tmp_path,
        {
            "app.py": (
                "class Box:\n"
                "    def keep(self):\n"
                "        return 1\n"
                "    def drop(self):\n"
                "        return 2\n"
                "\n"
                "def spare():\n"
                "    return 3\n"
                "\n"
                "def main():\n"
                "    return Box().keep()\n"
                "\n"
                "if __name__ == '__main__':\n"
                "    main()\n"
            ),
        },
    )
    findings = {item.symbol: item for item in scan(tmp_path).findings}
    assert findings["drop"].confidence < 100
    assert main(["fix", str(tmp_path), "--unsafe-fixes", "--quiet"]) == 2
    assert "requires --select-id" in capsys.readouterr().err
    assert "def drop" in (tmp_path / "app.py").read_text(encoding="utf-8")

    assert main(["fix", str(tmp_path), "--unsafe", "--select-id", findings["drop"].id, "--quiet"]) == 1
    assert "def drop" in (tmp_path / "app.py").read_text(encoding="utf-8")

    assert main(["fix", str(tmp_path), "--unsafe-fixes", "--select-id", findings["drop"].id, "--quiet"]) == 1
    text = (tmp_path / "app.py").read_text(encoding="utf-8")
    assert "def drop" not in text
    assert "def spare" in text
    assert "def keep" in text


def test_diff_json_lists_one_edit(tmp_path, capsys):
    (tmp_path / "app.py").write_text(
        "import os\n\ndef main():\n    return 1\n\nif __name__ == '__main__':\n    main()\n",
        encoding="utf-8",
    )
    assert main(["fix", str(tmp_path), "--diff", "--format", "json", "--quiet"]) == 1
    payload = __import__("json").loads(capsys.readouterr().out)
    assert payload["edits"]
    assert payload["edits"][0]["applicability"] == "safe"
    assert "import os" in payload["edits"][0]["diff"]
    assert "import os" in (tmp_path / "app.py").read_text(encoding="utf-8")


def test_windows_line_endings_survive_a_fix(tmp_path):
    path = tmp_path / "app.py"
    path.write_bytes(
        b"import os\r\n\r\ndef main():\r\n    return 1\r\n\r\nif __name__ == '__main__':\r\n    main()\r\n"
    )
    findings = [item for item in scan(tmp_path).findings if item.symbol == "os"]
    apply_fixes_verified(tmp_path, findings, verify_cmd="")
    data = path.read_bytes()
    assert b"\r\n" in data
    assert b"import os" not in data


def test_exit_zero_does_not_hide_a_failed_verify(tmp_path):
    write_tree(
        tmp_path,
        {
            "app.py": "import os\n\ndef main():\n    return 1\n\nif __name__ == '__main__':\n    main()\n",
            "check.py": "raise SystemExit(1)\n",
        },
    )
    command = subprocess.list2cmdline([sys.executable, "check.py"])
    assert main(["fix", str(tmp_path), "--verify", command, "--exit-zero", "--quiet"]) == 3


def test_verify_each_keeps_the_file_that_passes(tmp_path, monkeypatch):
    write_tree(
        tmp_path,
        {
            "good.py": "import os\n\ndef main():\n    return 1\n\nif __name__ == '__main__':\n    main()\n",
            "bad.py": "import sys\n\ndef main():\n    return 1\n\nif __name__ == '__main__':\n    main()\n",
        },
    )

    def verify(root, paths, command, timeout):
        if "bad.py" in paths:
            return VerifyResult(False, "py_compile", "bad")
        return VerifyResult(True, "py_compile", "")

    monkeypatch.setattr("vyarth.fix.run_verification", verify)
    findings = [item for item in scan(tmp_path).findings if item.rule == "UNUSED_IMPORT"]
    report = apply_fixes_verified(tmp_path, findings, verify_each=True)
    assert report.rolled_back is True
    assert report.verified is False
    assert b"import os" not in (tmp_path / "good.py").read_bytes()
    assert b"import sys" in (tmp_path / "bad.py").read_bytes()
    assert any(item.path == "good.py" for item in report.applied)
