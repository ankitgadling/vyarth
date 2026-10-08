# Command line

```text
vyarth --version
vyarth scan [PATH] [options]
vyarth baseline [PATH] [options]
vyarth fix [PATH] [options]
vyarth lsp
```

`PATH` defaults to the current directory. When the path is a file, Vyarth scans that file only. The project root is the nearest directory at or above the path that contains `pyproject.toml`, `vyarth.toml`, or `.git`. A subdirectory scan still reads that project's configuration and console scripts, and it only indexes files under the path you named. Dependency manifests outside that directory are skipped, except files that sit in the project root. Module and dependency checks run only for a directory scan.

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
```

| Option | Meaning |
| --- | --- |
| `--format text\|json\|sarif\|github\|concise` | Output format. Default: `text`. |
| `--config PATH` | Read this TOML file instead of discovering `pyproject.toml` or `vyarth.toml`. |
| `--min-confidence N` | Drop findings below this score. Overrides the config value. |
| `--baseline PATH` | Report only fingerprints that are not already in this file. |
| `--fail-on high\|medium\|low` | Exit 1 only when a printed finding is at or above 90, 70, or 0. |
| `--workers N` | Process pool size. `1` stays in-process. `0` uses the CPU count. Overrides the config value. |
| `--define NAME=VALUE` | Fold this name as a constant. Repeat the flag for more names. |
| `--changed` | Index the project, then keep findings only in Python files changed against git. |
| `--changed-from REF` | Git ref for `--changed`. Default: `HEAD`. |
| `--no-cache` | Reparse every file. The cache lives in `.vyarth/cache`. |
| `--quiet` | Do not print scan progress. |
| `--exclude PATTERN` | Do not index paths matching this pattern. Repeat the flag to add more. |

`--fail-on` still prints every finding that passes the other filters. The exit code is the only thing it changes. With no `--fail-on` and no `fail_on` in config, any remaining finding exits 1.

`--changed` reads `git diff --name-only` and `git ls-files --others --exclude-standard` against the ref. Paths are mapped into the project even when that project sits below the git root, and untracked Python files are included. The scan still indexes the whole project so imports and calls from unchanged files keep symbols alive. The report then keeps findings whose path is in that set. An empty set prints nothing and exits 0. If git reports Python paths and none of them fall inside the project, vyarth prints a warning on standard error. A directory that is not a git repository exits 2.

## `baseline`

```bash
vyarth baseline .
vyarth baseline . --output path/to/baseline.json
vyarth baseline . --config vyarth.toml
```

Writes a sorted fingerprint list. The default file is `vyarth-baseline.json` in the project root. A relative `--output` is resolved from that root. See [Continuous integration](continuous-integration.md).

## `fix`

```bash
vyarth fix .
vyarth fix . --dry-run
vyarth fix . --diff
vyarth fix . --unsafe
```

`fix` accepts the same options as `scan`. It deletes the rewrites that are safe at status `DEAD`, prints a note for each edit, and scans again. The second scan is what gets printed. `--dry-run` prints `would fix` notes and does not write. `--diff` prints a unified diff and does not write. `--unsafe` also removes unused imports in `__init__.py` and dotted `import pkg.sub` side-effect imports. It does not remove imports that were lowered because of `importlib` or an `ImportError` probe. See [Fix and editor](fix-and-editor.md).

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
| 2 | The path does not exist, a file disappears during the scan, the config or a `--define` value is invalid, the baseline file is missing or malformed, or git cannot answer `--changed`. |

A missing baseline prints `baseline not found`. Any other missing path prints `file not found`. Syntax errors are not a failing exit by themselves. Each one is printed on standard error as `SYNTAX_ERROR` with the file, line, and message, and the scan continues.

## Output formats

### Text

One block per finding. The symbol line is labeled `Import`, `Function`, `Class`, `Variable`, `Statement`, `Module`, or `Package` according to the rule. Rules that need a reason also print `Reason:`. Evidence lines, when present, are `Evidence:`.

### JSON

`vyarth scan . --format json` prints the same object as `ScanResult.to_json()`:

```json
{
  "files_scanned": 12,
  "findings": [
    {
      "rule": "UNUSED_FUNCTION",
      "path": "pkg/app.py",
      "line": 4,
      "column": 1,
      "symbol": "helper",
      "status": "POSSIBLY_DEAD",
      "confidence": 96,
      "message": "Function 'helper' is never used.",
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

One finding per line: `path:line:column: RULE message`.

### GitHub

```text
::error file=pkg/app.py,line=4,title=UNUSED_FUNCTION::Function 'helper' is never used.
```

Confidence at or above 90 uses `::error`. Anything lower uses `::warning`. `%`, carriage returns, newlines, `:`, and `,` in the command properties are escaped, and `%`, carriage returns, and newlines in the message are escaped. When the project sits below the git root, the file path includes that prefix so an annotation attaches in a monorepo.

### SARIF

`--format sarif` prints [SARIF 2.1.0](https://sarifweb.azurewebsites.net/). Each result carries `partialFingerprints.vyarth/fingerprint`. Confidence at or above 90 is `error`. Anything lower is `warning`. Each rule’s `fullDescription` is the rule’s meaning, not one finding’s message, and `helpUri` points at the rules document. The driver sets `informationUri` to the repository.
