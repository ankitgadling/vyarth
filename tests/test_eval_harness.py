"""The scripted eval deletes only proved-dead names."""

from vyarth.eval_harness import run_builtin


def test_builtin_eval_does_not_delete_a_live_name():
    report = run_builtin()
    assert report["wrong_deletions"] == 0
    assert report["precision"] == "not measured"
    surfaces = {item["surface"] for item in report["tasks"]}
    assert surfaces == {"json", "window", "mcp"}
    for item in report["tasks"]:
        assert item["wrong_deletions"] == 0
        assert item["correct_deletions"] >= 1
