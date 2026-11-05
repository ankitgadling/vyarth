"""Agent init files, the pre-commit hook, and the GitHub Action."""

from vyarth.cli import main


def test_init_writes_new_files_and_refuses_to_overwrite(tmp_path, capsys):
    assert main(["init", "--agent", "cursor", "--root", str(tmp_path)]) == 0
    rule = tmp_path / ".cursor" / "rules" / "vyarth.mdc"
    config = tmp_path / ".cursor" / "mcp.json"
    assert "vyarth explain" in rule.read_text(encoding="utf-8")
    assert "mcpServers" in config.read_text(encoding="utf-8")
    assert main(["init", "--agent", "cursor", "--root", str(tmp_path)]) == 2
    assert "refusing to overwrite" in capsys.readouterr().err
    assert main(["init", "--agent", "cursor", "--root", str(tmp_path), "--force"]) == 0


def test_hook_and_action_exist():
    root = __import__("pathlib").Path(__file__).resolve().parents[1]
    hook = (root / ".pre-commit-hooks.yaml").read_text(encoding="utf-8")
    action = (root / "action.yml").read_text(encoding="utf-8")
    assert "vyarth scan --changed --fail-on high --format concise" in hook
    assert "pass_filenames: false" in hook
    assert "min-confidence" in action
    assert "upload-sarif" in action
