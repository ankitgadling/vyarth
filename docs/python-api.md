# Python API

```python
from vyarth import Config, Finding, ParseError, ScanResult, load_config, scan
```

`vyarth.__version__` is the installed version.

## `scan`

```python
def scan(
    path: str | Path = ".",
    config: Config | None = None,
    *,
    config_path: str | Path | None = None,
    min_confidence: int | None = None,
    baseline: str | Path | None = None,
    apply_baseline: bool = True,
    workers: int | None = None,
    defines: dict[str, str] | None = None,
    changed: bool = False,
    changed_from: str = "HEAD",
    use_cache: bool = True,
    overlays: dict[str, str] | None = None,
    progress: ScanProgress | None = None,
) -> ScanResult:
```

`path` is a file or a directory. A missing path raises `FileNotFoundError`.

`config` is a `Config` instance. When it is omitted, `scan` loads configuration from `config_path`, or from the project root. `min_confidence`, when set, replaces `config.min_confidence` for this call.

`baseline` is a fingerprint file. When it is omitted and `apply_baseline` is true, the path in `config.baseline` is used. Pass `apply_baseline=False` to ignore both. A missing or malformed baseline raises `FileNotFoundError` or `ValueError`.

`defines` merges into the fold map from config. Keys in `defines` win.

`changed=True` on a directory scan keeps findings in Python files that `git diff --name-only <changed_from>` lists. Git failures raise `RuntimeError`. An empty diff returns a result with no findings and `files_scanned == 0`.

`use_cache=False` reparses every file. Single-file scans do not read or write the cache.

`overlays` maps an absolute file path to source text. The language server uses this for an unsaved buffer. Overlay text is not cached.

`progress` is a `vyarth.progress.ScanProgress`. The CLI constructs one and writes the status line to standard error. Leave it as `None` in library code.

```python
from vyarth import scan

result = scan("src", min_confidence=90, defines={"ENVIRONMENT": "production"})
if result.findings:
    raise SystemExit(result.to_json())
```

## `ScanResult`

| Field | Type | Meaning |
| --- | --- | --- |
| `findings` | `tuple[Finding, ...]` | Sorted by path, line, column, rule, and symbol. |
| `errors` | `tuple[ParseError, ...]` | Files that failed to parse. The rest of the project was still scanned. |
| `files_scanned` | `int` | Files that produced an index. |

`to_dict()` returns `files_scanned`, `findings`, and `errors`. `to_json()` returns that object as indented JSON with a trailing newline.

## `Finding`

Frozen dataclass. Every field is a plain value, so `dataclasses.asdict` round-trips a finding.

| Field | Meaning |
| --- | --- |
| `rule` | Rule id, such as `UNUSED_FUNCTION`. |
| `path` | Path relative to the scan root, with forward slashes. |
| `line`, `column` | 1-based position. |
| `symbol` | The unused name, statement text, module path, or package name. |
| `status` | `DEAD`, `POSSIBLY_DEAD`, `POSSIBLY_UNUSED_MODULE`, `ANALYSIS_LIMIT`, or `POSSIBLY_DUPLICATE`. |
| `confidence` | Integer from 0 to 100. |
| `message` | One sentence suitable for a diagnostic. |
| `evidence` | Short checks that produced the score. |
| `fingerprint` | `rule:path:qualname`. Stable across line shifts. |

## `ParseError`

`path`, `line`, `column`, and `message` for one syntax error.

## `Config` and `load_config`

```python
from pathlib import Path
from vyarth import load_config

config = load_config(Path("."))
```

`load_config(root, config_path=None)` reads `[tool.vyarth]` from `root / "pyproject.toml"`, then `root / "vyarth.toml"`. An explicit `config_path` loads that file only. The fields match the [configuration keys](configuration.md): `ignore`, `exclude`, `entry_patterns`, `min_confidence`, `framework_decorators`, `entry_points`, `baseline`, `fail_on`, `fold`, `workers`, and `duplicate_min_statements`.

`config.fold_map()` returns the fold table as a `dict`. `config.excludes` is the built-in excludes plus `config.exclude`.

You can construct `Config` yourself and pass it to `scan`. That skips file discovery.

## Rendering

The CLI formatters are public on `vyarth.report`:

```python
from vyarth.report import render_github, render_json, render_sarif, render_text

text = render_text(result)
```

## Fixes and baselines

```python
from vyarth.baseline import load_baseline, write_baseline
from vyarth.fix import apply_fixes, is_fixable, rewrite_source

write_baseline("vyarth-baseline.json", result.findings)
known = load_baseline("vyarth-baseline.json")

notes = apply_fixes(root, result.findings)
updated, notes = rewrite_source(source, result.findings, "pkg/app.py")
```

`apply_fixes` writes files and returns one note per edit. `rewrite_source` returns the new text and does not touch the disk. `is_fixable` is true for an unused import, and for unreachable code, nested functions, and function-local assignments at confidence 100. Details are in [Fix and editor](fix-and-editor.md).
