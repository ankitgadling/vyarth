# Fix and editor

## `vyarth fix`

```bash
vyarth fix .
vyarth fix src/ --min-confidence 100
```

`fix` scans, rewrites the edits that are safe to delete, and scans again. Each edit prints a note such as `fixed pkg/app.py:4 helper`. The report after the rescan is the command output. The same flags as `scan` apply to both passes.

These findings are rewritten when confidence is 100:

| Finding | Edit |
| --- | --- |
| `UNUSED_IMPORT` with status `DEAD` | Drop that imported name. An import statement with no names left is deleted. |
| `UNREACHABLE_CODE` | Delete the statement. If that empties a `if`, `for`, `while`, `try`, `with`, or `match` body, the body becomes `pass`. A `yield` or `yield from` that is the only yield in its function is left in place. |
| `UNUSED_FUNCTION` whose qualname is nested | Delete the nested function, including its decorators. |
| `UNUSED_VARIABLE` whose qualname is nested | Delete the assignment when every name on that line is an unused local and the value is not a call. |

Module-level functions, classes, methods, and module-level assignments stay reported. A line that mixes an import with another statement is left alone, and so is a wildcard import. A trailing comment on an import line is kept when the statement remains.

`vyarth.fix.rewrite_source(source, findings, relpath)` applies the same edits to a string and returns `(new_source, notes)`. `apply_fixes(root, findings)` writes the files. `is_fixable(finding, source=None)` reports whether a finding is a candidate before the syntax checks that can still skip it. Pass the file text so the sole-yield guard can refuse an unreachable generator yield.

## Language server

```bash
vyarth lsp
```

The server speaks [Language Server Protocol](https://microsoft.github.io/language-server-protocol/) messages with `Content-Length` headers on stdin and stdout. Point an editor client at that command.

`initialize` advertises:

- full text-document sync
- pull diagnostics (`diagnosticProvider`, with `interFileDependencies`)
- code actions of kind `quickfix`

It answers:

| Method | Behavior |
| --- | --- |
| `initialize` | Returns the capabilities above. `serverInfo.name` is `vyarth`. |
| `shutdown` | Returns a null result. |
| `exit` | Stops the process. |
| `textDocument/didOpen` | Remembers the buffer and uses it on the next diagnostic request. |
| `textDocument/didChange` | Replaces the remembered buffer with the latest full text. |
| `textDocument/didSave` | Drops the buffer so the next request reads the file from disk. |
| `textDocument/diagnostic` | Returns diagnostics for that file from a project scan. |
| `textDocument/codeAction` | Returns a quick fix for each fixable finding in the requested range. |

Diagnostics use severity 1 (error) at confidence 90 or above and severity 2 (warning) below that. `source` is `vyarth` and `code` is the rule id.

The project root is the nearest parent of the file that contains `pyproject.toml`, `vyarth.toml`, or `.git`. A scan of that root is reused until a file’s size or modification time changes, or an open buffer supplies overlay text. Code actions call the same rewrites as `vyarth fix` and return a workspace edit for the changed span.

There is no published editor extension yet. Any client that can launch a stdio language server can use `vyarth lsp` directly.
