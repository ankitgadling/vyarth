# Command line

```text
vyarth --version
vyarth scan [PATH] [options]
vyarth explain SELECTOR [PATH] [options]
vyarth baseline [PATH] [options]
vyarth fix [PATH] [options]
vyarth schema
vyarth lsp
vyarth mcp [--root PATH] [--read-only]
vyarth init --agent cursor|claude|copilot
vyarth eval
```

`PATH` defaults to the current directory. When the path is a file, Vyarth scans that file only. The project root is the nearest directory at or above the path that contains `pyproject.toml`, `vyarth.toml`, or `.git`. A subdirectory scan still reads that project's configuration and console scripts, and it only indexes files under the path you named. Dependency manifests outside that directory are skipped, except files that sit in the project root. A scan of the project root also skips manifests under `examples/`, `tutorial/`, `samples/`, `demo/`, and `benchmarks/`. Nested package manifests still count. Scanning one of those directories reports its own manifest. Module and dependency checks run only for a directory scan.

## `scan`

```bash
vyarth scan .
vyarth scan src/ --format json
vyarth scan . --format sarif
vyarth scan . --format github
vyarth scan . --format concise
vyarth scan . --min-confidence 90
vyarth scan . --fail-on high
vyarth scan . --baseline vyarth-baseline.json
vyarth scan . --config vyarth.toml
vyarth scan . --define ENVIRONMENT=production
vyarth scan . --changed --changed-from origin/main
vyarth scan . --workers 0
vyarth scan . --no-cache
vyarth scan . --quiet --exclude experiments/**
vyarth scan . --summary
vyarth scan . --sort confidence --max-findings 50 --format jsonl
vyarth scan . --select unused-function --ignore-rule unused-import
vyarth scan . --fixable-only --paths-only
```

| Option | Meaning |
| --- | --- |
| `--format text\|json\|jsonl\|sarif\|github\|concise` | Output format. Default: `text`. `--output-format` is the same option. |
| `--concise-confidence` | Append ` [96]` to each concise line. The default concise line is unchanged. |
| `--show-fixes` | Include `fix.edits` for safe and unsafe findings. |
| `--exit-zero` | Exit 0 when findings remain. A missing path, a bad config, or a bad baseline still exits 2. |
| `--config PATH` | Read this TOML file instead of discovering `pyproject.toml` or `vyarth.toml`. |
| `--min-confidence N` | Drop findings below this score. Overrides the config value. |
| `--baseline PATH` | Report only fingerprints that are not already in this file. |
| `--baseline-mode new\|all` | `new` hides baselined findings. `all` keeps them and sets `baselined` to true. |
| `--report-unused-ignores` | Report an ignore comment that suppressed nothing. |
| `--fail-on high\|medium\|low` | Exit 1 only when a printed finding is at or above 90, 70, or 0. |
| `--workers N` | Process pool size. `1` stays in-process. `0` uses the CPU count. Overrides the config value. |
| `--define NAME=VALUE` | Fold this name as a constant. Repeat the flag for more names. |
| `--changed` | Index the project, then keep findings only in Python files changed against git. |
| `--changed-from REF` | Git ref for `--changed`. The diff uses the merge-base of `REF` and `HEAD`. Default: `HEAD`. |
| `--no-cache` | Reparse every file. The cache lives in `.vyarth/cache`. |
| `--quiet` | Do not print scan progress. |
| `--exclude PATTERN` | Do not index paths matching this pattern. Repeat the flag to add more. |
| `--summary` | Print one line: the finding count, how many are at or above 90, how many are safe to fix, and the top rules. json, jsonl, and sarif print the `summary` object. |
| `--max-findings N` | Keep the first N findings. With no `--sort`, the order is confidence, then safe fixes, then path. `summary.total` is the count before the cut, `summary.shown` is N, and `summary.truncated` is true. Text and concise add `... 9944 more (use --max-findings or --min-confidence)`. |
| `--sort confidence\|path\|rule` | Order findings. Default: `path`. |
| `--select RULE[,RULE]` | Keep these rules. `UNUSED_FUNCTION`, `unused-function`, and `unused_function` match. |
| `--ignore-rule RULE[,RULE]` | Drop these rules. Same names as `--select`. |
| `--fixable-only` | Keep findings a safe fix can delete. |
| `--paths-only` | Print the unique file paths. json, jsonl, and sarif print `{"paths", "summary"}`. |
| `--brief-evidence` | Omit `No references found`, `No decorators`, `Not exported`, `Not an entry point`, and `No dynamic references detected`. The `reasons` codes stay. jsonl omits those lines by default. |

`--fail-on` still prints every finding that passes the other filters. The exit code is the only thing it changes. With no `--fail-on` and no `fail_on` in config, any remaining finding exits 1.

`--changed` reads `git diff --name-only` against the merge-base of the ref and `HEAD`, plus `git ls-files --others --exclude-standard`. Non-ASCII paths are kept. Paths are mapped into the project even when that project sits below the git root, and untracked Python files are included. The scan still indexes the whole project so imports and calls from unchanged files keep symbols alive. The report then keeps findings whose path is in that set. An empty set prints nothing and exits 0. If git reports Python paths and none of them fall inside the project, vyarth prints a warning on standard error. A directory that is not a git repository exits 2.

## `baseline`

```bash
vyarth baseline .
vyarth baseline . --output path/to/baseline.json
vyarth baseline . --config vyarth.toml
```

Writes baseline version 2: a sorted list of fingerprint, id, rule, path, symbol, reason, and date. Version 1 files and plain fingerprint strings still load. The default file is `vyarth-baseline.json` in the project root. A relative `--output` is resolved from that root. `baseline` accepts the same scan flags as `scan`, including `--quiet`, `--exclude`, and `--min-confidence`, and it does not apply an existing baseline.

`vyarth baseline . --add ID --reason "called from a queue"` appends that finding. Adding it again does not create a second row. `--prune` drops entries the current scan does not report and prints the removed count. See [Continuous integration](continuous-integration.md).

## `fix`

```bash
vyarth fix .
vyarth fix . --dry-run
vyarth fix . --diff
vyarth fix . --unsafe
```

`fix` accepts the same options as `scan`, including the summary and the finding window. The window is applied before the edit, so `--max-findings` and `--select` limit what gets deleted. It deletes the rewrites that are safe at status `DEAD`, prints a note for each edit, and scans again. The second scan is what gets printed. `--dry-run` prints `would fix` notes and does not write. `--diff` prints a unified diff and does not write. `--diff --format json` prints `{"edits":[{"id","path","diff","applicability"}]}`. `--unsafe` also removes unused imports in `__init__.py` and dotted `import pkg.sub` side-effect imports. It does not remove imports that were lowered because of `importlib` or an `ImportError` probe, and it does not delete a 90–99 finding. `--unsafe-fixes` deletes a selected 90–99 nested name and requires `--select-id`. `--select-id ID[,ID]` fixes only those findings. An id is `VY` plus base32, or a fingerprint. An id that matches two findings is refused. An edit that touches lines already changed in git is skipped (`dirty_lines`). `--require-clean` refuses the whole fix when the worktree is dirty. `--verify [CMD]` copies each file under `.vyarth/backup/`, writes the edits, runs `py_compile` on the touched files, then runs `CMD` or `fix_verify_command`. A failure restores the original bytes and exits 3. `--verify-each` does that one file at a time and keeps the files that pass. With `--format json`, `jsonl`, or `sarif`, the notes go to standard error and the JSON object includes `applied`. See [Fix and editor](fix-and-editor.md).

## `explain`

```bash
vyarth explain VY7K2QF9XA
vyarth explain UNUSED_FUNCTION:pkg/app.py:helper
vyarth explain pkg/app.py:4
vyarth explain pkg/app.py:4 --format json
```

`explain` scans, then prints one finding: the evidence, the reason codes, other lines in the project that spell the name, the `# vyarth: ignore[rule]` comment, `vyarth baseline . --output vyarth-baseline.json`, an `ignore` pattern for the file, whether a fix is safe, and the diff when it is. `--format json` prints that record as JSON. `--select`, `--ignore-rule`, `--min-confidence`, and `--fixable-only` still apply. `--max-findings` does not, so an id outside the window can still be explained. An unknown or ambiguous selector exits 2.

## `mcp`

```bash
vyarth mcp
vyarth mcp --root . --read-only
```

Serves newline-delimited JSON-RPC on stdin and stdout. Logs go to stderr. Tool paths stay inside `--root`. `--read-only` hides `apply_fix` and `add_to_baseline`. The tools are `scan`, `explain`, `fix_preview`, `apply_fix`, `add_to_baseline`, and `list_rules`. `apply_fix` runs the configured verify command and restores the files when the check fails. See [MCP](mcp.md).

## `init`

```bash
vyarth init --agent cursor
vyarth init --agent claude --force
```

Writes a short agent snippet and an MCP config for Cursor, Claude Code, or Copilot. Existing files are left in place unless `--force` is set.

## `eval`

```bash
vyarth eval
```

Runs a scripted policy on a built-in fixture and prints deletion, token, rollback, and timing counts. Precision is `not measured` unless a later hand label is supplied. `VYARTH_EVAL_ROOTS` adds repositories that contain `vyarth-eval.json`. The process exits 1 when a live symbol was deleted.

## `schema`

```bash
vyarth schema
```

Prints the version 1 report JSON Schema.

## `lsp`

```bash
vyarth lsp
```

Speaks Content-Length JSON-RPC on stdin and stdout. It has no path argument. See [Fix and editor](fix-and-editor.md).

## Exit codes

| Code | When |
| --- | --- |
| 0 | No findings remain after filters, or `--fail-on` is set and nothing meets that floor. |
| 1 | Findings remain, or one of them meets the `--fail-on` floor. |
| 2 | The path does not exist, a file disappears during the scan, the config or a `--define` value is invalid, the baseline file is missing or malformed, git cannot answer `--changed`, or `--require-clean` finds a dirty worktree. |
| 3 | `fix --verify` wrote edits, a check failed, and the files were restored. `--exit-zero` does not change this code. |

A missing baseline prints `baseline not found`. Any other missing path prints `file not found`. Syntax errors are not a failing exit by themselves. Each one is printed on standard error as `SYNTAX_ERROR` with the file, line, and message, and the scan continues.

## Output formats

### Text

One block per finding. The symbol line is labeled `Import`, `Function`, `Class`, `Variable`, `Statement`, `Module`, or `Package` according to the rule. Rules that need a reason also print `Reason:`. Evidence lines, when present, are `Evidence:`.

### JSON

`vyarth scan . --format json` prints report schema v1, the same object as `ScanResult.to_report()`. `vyarth schema` prints the JSON Schema. Every key from earlier versions is still present. The report adds `schema_version`, `tool`, `root`, `summary`, and on each finding `id`, `rule_url`, `kind`, `qualname`, `end_line`, `end_column`, `reasons`, `fix`, and `baselined`. `id` is `VY` plus the first 8 characters of the unpadded base32 SHA-1 of the fingerprint. Two findings that share those 8 characters both use 12. A dependency finding whose metadata is missing also sets `env_sensitive` to true.

```bash
vyarth scan . --format jsonl
```

JSONL prints one finding per line, then a final line `{"type":"summary",...}`. It omits the five checklist evidence lines. It also omits `rule_url`, `kind`, `qualname`, `end_line`, `end_column`, and `baselined`, and it omits `fix` when the applicability is `none`. A truncated jsonl stream can drop the summary line. `--summary` prints that object by itself.

`vyarth scan . --format json` prints:

```json
{
  "schema_version": 1,
  "files_scanned": 12,
  "findings": [
    {
      "id": "VY7K2QF9XA",
      "rule": "UNUSED_FUNCTION",
      "path": "pkg/app.py",
      "line": 4,
      "column": 1,
      "symbol": "helper",
      "qualname": "helper",
      "status": "POSSIBLY_DEAD",
      "confidence": 96,
      "message": "Function 'helper' is never used.",
      "reasons": ["no_references"],
      "fix": {"applicability": "none"},
      "evidence": [
        "No references found.",
        "No decorators.",
        "Not exported.",
        "Not an entry point.",
        "No dynamic references detected."
      ],
      "fingerprint": "UNUSED_FUNCTION:pkg/app.py:helper"
    }
  ],
  "errors": []
}
```

`errors` holds parse failures: `path`, `line`, `column`, and `message`.

### Concise

One finding per line: `path:line:column: RULE message`. `--concise-confidence` appends ` [96]`.

### GitHub

```text
::error file=pkg/app.py,line=4,title=UNUSED_FUNCTION::Function 'helper' is never used.
```

Confidence at or above 90 uses `::error`. Anything lower uses `::warning`. `%`, carriage returns, newlines, `:`, and `,` in the command properties are escaped, and `%`, carriage returns, and newlines in the message are escaped. When the project sits below the git root, the file path includes that prefix so an annotation attaches in a monorepo.

### SARIF

`--format sarif` prints [SARIF 2.1.0](https://sarifweb.azurewebsites.net/). Each result carries `partialFingerprints.vyarth/fingerprint`, `rank` equal to the confidence, and `properties.confidence`, `properties.reasons`, and `properties.evidence`. The region includes `endLine`. Confidence at or above 90 is `error`. Anything lower is `warning`. Each rule’s `fullDescription` is the rule’s meaning, not one finding’s message, and `helpUri` points at the rule’s anchor in the rules document. `--show-fixes` adds `fixes` for a safe deletion. The driver sets `informationUri` to the repository.
