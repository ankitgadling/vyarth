"""Conformance against the official MCP Python client."""

import asyncio
import os
from pathlib import Path
import sys

import pytest

from tests.conftest import write_tree


pytest.importorskip("mcp")


def test_sdk_client_initializes_and_lists_rules(tmp_path):
    write_tree(
        tmp_path,
        {
            "app.py": "import os\n\nif __name__ == '__main__':\n    print('ok')\n",
        },
    )
    names, rules = asyncio.run(_session(tmp_path))
    assert "scan" in names
    assert "list_rules" in names
    assert "apply_fix" in names
    assert any(item["id"] == "UNUSED_IMPORT" for item in rules)


async def _session(root: Path) -> tuple[set[str], list[dict]]:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    src = str(Path(__file__).resolve().parents[1] / "src")
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "vyarth", "mcp", "--root", str(root)],
        env={"PYTHONPATH": src + os.pathsep + os.environ.get("PYTHONPATH", "")},
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            listed = await session.list_tools()
            called = await session.call_tool("list_rules", {})
    names = {tool.name for tool in listed.tools}
    body = called.structured_content or {}
    rules = body.get("rules", []) if isinstance(body, dict) else []
    assert called.is_error is False
    return names, rules
