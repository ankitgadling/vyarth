# Configuration

Vyarth reads `[tool.vyarth]` from `pyproject.toml` in the scan root. When that table is absent, it reads `vyarth.toml`. A `vyarth.toml` file uses the same keys at the top level or under `[tool.vyarth]`. `--config` loads that file and skips discovery.

```toml
[tool.vyarth]
ignore = ["src/legacy/*"]
exclude = ["experiments/*"]
entry_patterns = ["**/wsgi.py", "**/asgi.py", "**/__main__.py", "**/manage.py"]
framework_decorators = ["myapp.route"]
entry_points = ["pkg.wsgi:app"]
baseline = "vyarth-baseline.json"
fail_on = "high"
workers = 1
duplicate_min_statements = 5
min_confidence = 0

[tool.vyarth.fold]
ENVIRONMENT = "production"
```

| Key | Default | Meaning |
| --- | --- | --- |
| `ignore` | none | Index these paths, then drop findings inside them. Their imports and calls still count. Gitignore-style patterns. |
| `exclude` | none | Do not index these paths. Added on top of the built-in excludes. |
| `entry_patterns` | see below | Files that count as entry modules. Setting this key replaces the default list. |
| `framework_decorators` | none | Extra decorator names that mark a function or class as an entry. |
| `entry_points` | none | Extra `module:symbol` targets, in the same form as `[project.scripts]`. |
| `baseline` | none | Fingerprint file applied on every scan unless the command passes `--baseline` or the library sets `apply_baseline=False`. |
| `fail_on` | none | `high`, `medium`, or `low`. Same floors as the CLI flag: 90, 70, and 0. |
| `workers` | `1` | Process pool size. `1` stays in-process. `0` uses the CPU count. A pool starts only when there are at least eight files to parse. |
| `duplicate_min_statements` | `5` | Minimum statement count before two function bodies can be reported as duplicates. |
| `min_confidence` | `0` | Drop findings below this score. |
| `fold` | none | Names folded to constants. Values are strings, numbers, or booleans. |

A command-line flag overrides the matching config key for that run: `--min-confidence`, `--baseline`, `--fail-on`, `--workers`, and `--define`.

Invalid values fail the scan with exit code 2. `min_confidence`, `workers`, and `duplicate_min_statements` must be integers. `workers` must be zero or positive. `fail_on` must be `high`, `medium`, or `low`. List options must be strings or arrays of strings. `fold` must be a table.

## Paths that are never scanned

These are always excluded, in addition to anything in `.gitignore`:

`.git`, `.vyarth`, `.venv`, `venv`, `__pycache__`, `build`, `dist`

`tests/`, `test_*.py`, and `*_test.py` are indexed so their imports and calls keep application code alive. Findings inside those paths are hidden.

## `ignore` and `exclude`

`exclude` removes a path from the index. A module listed there cannot keep another module alive, and its own symbols are not reported.

`ignore` still indexes the file. Use it for generated or legacy code whose imports should count and whose findings should not.

## Entry patterns and entry points

The default entry patterns are:

```text
**/__main__.py
**/wsgi.py
**/asgi.py
**/manage.py
setup.py
**/docs/conf.py
```

`[project.scripts]`, `[project.gui-scripts]`, and the `[project.entry-points]` groups `console_scripts` and `gui_scripts` in `pyproject.toml` are read automatically. `entry_points` adds more targets in the form `pkg.wsgi:app`. A value with no colon names a module.

`framework_decorators` matches the decorator’s full name or its final attribute. `myapp.route` matches `@myapp.route` and `@route` does not, unless you also list `route`. The built-in hook names are always recognized. See [How analysis works](how-analysis-works.md).

## Constant folding

`[tool.vyarth.fold]` and `--define NAME=VALUE` fold:

- `os.environ["NAME"]` and `os.environ.get("NAME")`
- `os.getenv("NAME")`
- a bare name that appears in the map

Equality, inequality, and `not` against that value become constant, so the dead branch is unreachable and calls inside it are ignored. A name that is not in the map stays unfolded. Booleans are stored as `true` and `false`.

```bash
vyarth scan . --define ENVIRONMENT=production --define DEBUG=false
```

## Cache

Directory scans store one JSON record per file under `.vyarth/cache`, keyed by path, size, modification time, the fold map, and the duplicate-statement minimum. `--no-cache` reparses every file. A single-file scan does not use the cache. Overlay text from the language server is not cached.
