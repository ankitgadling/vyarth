# MCP

`vyarth mcp` speaks newline-delimited JSON-RPC on stdin and stdout. Logs go to stderr. The default protocol version is `2025-11-25`. A client that asks for `2025-06-18` or `2026-07-28` gets that version back.

```bash
vyarth mcp --root .
vyarth mcp --read-only
```

Every tool path is resolved inside `--root`. A path that escapes it is rejected. `--read-only` hides `apply_fix` and `add_to_baseline`.

`apply_fix` runs `py_compile` on the edited files and then `fix_verify_command` when one is configured. It does not run a command supplied by the model. A failed check restores the original bytes. An edit that covers uncommitted lines is skipped.

## Tools

| Tool | Role |
| --- | --- |
| `scan` | Report v1, brief evidence, at most 50 findings, sorted by confidence. |
| `explain` | One finding by id, fingerprint, or `path:line`. |
| `fix_preview` | Diffs for the named ids. |
| `apply_fix` | Writes those edits and verifies them. |
| `add_to_baseline` | Appends ids. The reason must be at least 10 characters. |
| `list_rules` | Rule ids, aliases, and help links. |

## Cursor

`.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "vyarth": {
      "command": "vyarth",
      "args": ["mcp"]
    }
  }
}
```

## Claude Code

```bash
claude mcp add vyarth -- vyarth mcp
```

`.mcp.json` uses the same `mcpServers` object as Cursor.

## VS Code and Copilot

`.vscode/mcp.json`:

```json
{
  "servers": {
    "vyarth": {
      "command": "vyarth",
      "args": ["mcp"]
    }
  }
}
```

## Codex

```toml
[mcp_servers.vyarth]
command = "vyarth"
args = ["mcp"]
```

`vyarth init --agent cursor|claude|copilot` writes the snippet and the matching config. It does not overwrite a file unless `--force` is set.
