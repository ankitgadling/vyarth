"""MCP stdio server."""

import json
import os
from pathlib import Path
import subprocess
import sys

from tests.conftest import write_tree


def test_mcp_serves_each_tool_and_rejects_a_path_outside_the_root(tmp_path):
    write_tree(
        tmp_path,
        {
            "app.py": (
                "import os\n"
                "\n"
                "def keep():\n"
                "    return 1\n"
                "\n"
                "if __name__ == '__main__':\n"
                "    print(keep())\n"
            ),
        },
    )
    process = _server(tmp_path)
    try:
        replies = []
        replies.append(_rpc(process, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}}))
        process.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
        process.stdin.flush()
        replies.append(_rpc(process, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}))
        replies.append(_rpc(process, {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "list_rules", "arguments": {}}}))
        replies.append(
            _rpc(
                process,
                {
                    "jsonrpc": "2.0",
                    "id": 4,
                    "method": "tools/call",
                    "params": {"name": "scan", "arguments": {"min_confidence": 0, "max_findings": 50}},
                },
            )
        )
        findings = replies[-1]["result"]["structuredContent"]["findings"]
        chosen = next(item for item in findings if item["symbol"] == "os")
        replies.append(
            _rpc(
                process,
                {
                    "jsonrpc": "2.0",
                    "id": 5,
                    "method": "tools/call",
                    "params": {"name": "explain", "arguments": {"id": chosen["id"]}},
                },
            )
        )
        replies.append(
            _rpc(
                process,
                {
                    "jsonrpc": "2.0",
                    "id": 6,
                    "method": "tools/call",
                    "params": {"name": "fix_preview", "arguments": {"ids": [chosen["id"]]}},
                },
            )
        )
        replies.append(
            _rpc(
                process,
                {
                    "jsonrpc": "2.0",
                    "id": 7,
                    "method": "tools/call",
                    "params": {
                        "name": "add_to_baseline",
                        "arguments": {"ids": [chosen["id"]], "reason": "kept until the next release"},
                    },
                },
            )
        )
        replies.append(
            _rpc(
                process,
                {
                    "jsonrpc": "2.0",
                    "id": 8,
                    "method": "tools/call",
                    "params": {"name": "apply_fix", "arguments": {"ids": [chosen["id"]], "verify": True}},
                },
            )
        )
        replies.append(
            _rpc(
                process,
                {
                    "jsonrpc": "2.0",
                    "id": 9,
                    "method": "tools/call",
                    "params": {"name": "scan", "arguments": {"path": str(tmp_path.parent)}},
                },
            )
        )
    finally:
        assert process.stdin is not None
        process.stdin.close()
        assert process.wait(timeout=20) == 0
    assert replies[0]["result"]["protocolVersion"] == "2025-06-18"
    names = {item["name"] for item in replies[1]["result"]["tools"]}
    assert {"scan", "explain", "fix_preview", "apply_fix", "add_to_baseline", "list_rules"} <= names
    assert replies[4]["result"]["structuredContent"]["finding"]["symbol"] == "os"
    assert replies[5]["result"]["structuredContent"]["edits"]
    assert replies[6]["result"]["structuredContent"]["added"] == 1
    assert replies[7]["result"]["isError"] is False
    assert "import os" not in (tmp_path / "app.py").read_text(encoding="utf-8")
    outside = replies[8]["result"]
    assert outside["isError"] is True
    assert outside["structuredContent"]["code"] == "path_outside_root"
    for reply in replies:
        json.dumps(reply)


def test_read_only_hides_write_tools(tmp_path):
    process = _server(tmp_path, "--read-only")
    try:
        _rpc(process, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        listed = _rpc(process, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    finally:
        assert process.stdin is not None
        process.stdin.close()
        process.wait(timeout=20)
    names = {item["name"] for item in listed["result"]["tools"]}
    assert "apply_fix" not in names
    assert "scan" in names


def test_the_server_stdout_is_only_json(tmp_path):
    process = _server(tmp_path)
    assert process.stdin is not None
    assert process.stdout is not None
    process.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping"}) + "\n")
    process.stdin.close()
    raw = process.stdout.read()
    process.wait(timeout=20)
    lines = [line for line in raw.splitlines() if line.strip()]
    assert lines
    for line in lines:
        json.loads(line)


def _server(root: Path, *extra: str) -> subprocess.Popen[str]:
    env = os.environ.copy()
    src = str(Path(__file__).resolve().parents[1] / "src")
    env["PYTHONPATH"] = src + os.pathsep + env.get("PYTHONPATH", "")
    process = subprocess.Popen(
        [sys.executable, "-m", "vyarth", "mcp", "--root", str(root), *extra],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        env=env,
    )
    assert process.stdin is not None
    assert process.stdout is not None
    return process


def _rpc(process: subprocess.Popen[str], message: dict) -> dict:
    assert process.stdin is not None
    assert process.stdout is not None
    process.stdin.write(json.dumps(message) + "\n")
    process.stdin.flush()
    line = process.stdout.readline()
    assert line, process.stderr.read() if process.stderr is not None else "no stdout"
    return json.loads(line)
