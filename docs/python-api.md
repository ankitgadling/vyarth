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
    sort: str | None = None,
    max_findings: int | None = None,
    select: tuple[str, ...] = (),
    ignore_rules: tuple[str, ...] = (),
    fixable_only: bool = False,
    baseline_mode: str = "new",
) -> ScanResult:
```

`path` is a file or a directory. A missing path raises `FileNotFoundError`.

`config` is a `Config` instance. When it is omitted, `scan` loads configuration from `config_path`, or from the project root. `min_confidence`, when set, replaces `config.min_confidence` for this call.

`baseline` is a fingerprint file. When it is omitted and `apply_baseline` is true, the path in `config.baseline` is used. Pass `apply_baseline=False` to ignore both. A missing or malformed baseline raises `FileNotFoundError` or `ValueError`. `baseline_mode="all"` keeps baselined findings and sets `Finding.baselined`. `"new"` hides them.

`defines` merges into the fold map from config. Keys in `defines` win.

`changed=True` on a directory scan keeps findings in Python files from `git diff` against the merge-base of `changed_from` and `HEAD`, and from untracked files. Paths are mapped into the project when it sits below the git root. Git failures raise `RuntimeError`. An empty mapped set returns a result with no findings and `files_scanned == 0`.

`use_cache=False` reparses every file. Single-file scans do not read or write the cache.

`overlays` maps an absolute file path to source text. The language server uses this for an unsaved buffer. Overlay text is not cached.

`progress` is a `vyarth.progress.ScanProgress`. The CLI constructs one and writes the status line to standard error. Leave it as `None` in library code.

`sort` is `confidence`, `path`, or `rule`. When it is omitted and `max_findings` is set, the order is `confidence`. Otherwise the order is `path`. `max_findings` keeps that many findings. `ScanResult.census` counts the set before the cut, and `to_report` copies those counts into `summary`. `select` and `ignore_rules` are canonical rule names such as `UNUSED_FUNCTION`. `fixable_only` keeps findings a safe fix can delete. An unknown sort or rule raises `ValueError`.

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

`to_dict()` and `to_json()` return report schema v1. `to_report(root=..., show_fixes=False, applied=None)` is the same object. It keeps `files_scanned`, `findings`, and `errors`, and adds `schema_version`, `summary`, and the per-finding fields `id`, `reasons`, `fix`, `qualname`, `kind`, and end positions. `to_json()` is indented JSON with a trailing newline.

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
| `id` | `VY` plus base32 of the fingerprint. Filled in when the scan result is built. An 8-character collision uses 12. |
| `qualname`, `kind` | Qualname from the fingerprint, and `import`, `function`, `class`, `variable`, `statement`, `module`, or `package`. |
| `reasons` | Machine codes for the evidence lines, from `vyarth.reasons.REASONS`. |
| `end_line`, `end_column` | Filled in the report when a root is available. The dataclass leaves them at 0. |

## `ParseError`

`path`, `line`, `column`, and `message` for one syntax error.

## `Config` and `load_config`

```python
from pathlib import Path
from vyarth import load_config

config = load_config(Path("."))
```

`load_config(root, config_path=None)` reads `[tool.vyarth]` from `root / "pyproject.toml"`, then `root / "vyarth.toml"`. An explicit `config_path` loads that file only. The fields match the [configuration keys](configuration.md), including `require_ignore_reason`, `report_unused_ignores`, and `allow`.

`config.fold_map()` returns the fold table as a `dict`. `config.excludes` is the built-in excludes plus `config.exclude`.

You can construct `Config` yourself and pass it to `scan`. That skips file discovery and leaves `frameworks` empty. `load_config` is what applies `frameworks = "auto"`.

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

`apply_fixes` writes files and returns one note per edit. `apply_fixes_verified` writes them, runs `py_compile` and an optional command, and restores the original bytes when a check fails. `rewrite_source` returns the new text and does not touch the disk. Both accept `unsafe=True` to include unused imports in `__init__.py` and dotted side-effect imports. `unsafe_fixes=True` also deletes a nested 90–99 name. `is_fixable` is true for an unused import whose status is `DEAD`, except one in `__init__.py`, and for unreachable code, nested functions, and function-local assignments at confidence 100. Details are in [Fix and editor](fix-and-editor.md).
