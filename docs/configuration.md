# Configuration

Vyarth reads `[tool.vyarth]` from `pyproject.toml` in the scan root. When that table is absent, it reads `vyarth.toml`. A `vyarth.toml` file uses the same keys at the top level or under `[tool.vyarth]`. `--config` loads that file and skips discovery.

```toml
[tool.vyarth]
ignore = ["src/legacy/*"]
exclude = ["experiments/*"]
entry_patterns = ["**/wsgi.py", "**/asgi.py", "**/__main__.py", "**/manage.py"]
framework_decorators = ["myapp.route"]
frameworks = ["django"]
ignore_names = ["legacy_*"]
ignore_decorators = ["myapp.hook"]
ignore_bases = ["Protocol"]
entry_points = ["pkg.wsgi:app"]
baseline = "vyarth-baseline.json"
fail_on = "high"
workers = 1
duplicate_min_statements = 5
min_confidence = 0
report_dev_dependencies = false

[tool.vyarth.fold]
ENVIRONMENT = "production"
```

| Key | Default | Meaning |
| --- | --- | --- |
| `ignore` | none | Index these paths, then drop findings inside them. Their imports and calls still count. Gitignore-style patterns. |
| `exclude` | none | Do not index these paths. Added on top of the built-in excludes. |
| `entry_patterns` | see below | Files that count as entry modules. Setting this key replaces the default list. |
| `framework_decorators` | none | Extra decorator names that mark a function or class as an entry. |
| `frameworks` | none | Opt-in presets: `django`, `pydantic`, `celery`. An unknown name fails the scan. |
| `ignore_names` | none | `fnmatch` patterns. A finding whose symbol matches is dropped. |
| `ignore_decorators` | none | Decorator names that mark a symbol as an entry, same matching as `framework_decorators`. |
| `ignore_bases` | none | A class with one of these bases is used, and its methods and attributes are not reported. |
| `entry_points` | none | Extra `module:symbol` targets, in the same form as `[project.scripts]`. |
| `baseline` | none | Fingerprint file applied on every scan unless the command passes `--baseline` or the library sets `apply_baseline=False`. |
| `fail_on` | none | `high`, `medium`, or `low`. Same floors as the CLI flag: 90, 70, and 0. |
| `workers` | `1` | Process pool size. `1` stays in-process. `0` uses the CPU count. A pool starts only when there are at least eight files to parse. |
| `duplicate_min_statements` | `5` | Minimum statement count before two function bodies can be reported as duplicates. |
| `min_confidence` | `0` | Drop findings below this score. Must be from 0 to 100. |
| `report_dev_dependencies` | `false` | Report development and docs dependencies. They score 70. |
| `fold` | none | Names folded to constants. Values are strings, numbers, or booleans. |

A command-line flag overrides the matching config key for that run: `--min-confidence`, `--baseline`, `--fail-on`, `--workers`, and `--define`.

Invalid values fail the scan with exit code 2. `min_confidence`, `workers`, and `duplicate_min_statements` must be integers. `min_confidence` must be from 0 to 100. `duplicate_min_statements` must be at least 1. `workers` must be zero or positive. `fail_on` must be `high`, `medium`, or `low`. `report_dev_dependencies` must be a boolean. `frameworks` must be names from `django`, `pydantic`, and `celery`. List options must be strings or arrays of strings. `fold` must be a table. A key Vyarth does not recognize prints a warning and does not fail the scan.

## Paths that are never scanned

These are always excluded, in addition to `.gitignore`, `.git/info/exclude`, and nested `.gitignore` files:

`.git`, `.vyarth`, `.venv`, `venv`, `__pycache__`, `build`, `dist`

`tests/`, `test_*.py`, `*_test.py`, and `conftest.py` are indexed so their imports and calls keep application code alive. Findings inside those paths are hidden. A nested `.gitignore` applies under its directory. A later rule wins, so a nested `!` pattern can un-ignore a file. A `.gitignore` inside an already ignored directory is not read.

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

`framework_decorators` matches the decorator’s full name or its final attribute. `myapp.route` matches `@myapp.route` and `@route` does not, unless you also list `route`. The built-in hook names are always recognized. `ignore_decorators` uses the same match and makes the decorated symbol an entry, so its body stays reachable. See [How analysis works](how-analysis-works.md).

`frameworks` is empty unless you set it. The presets add to the entry list. They do not replace `entry_patterns`.

- `django` treats `**/settings.py`, `**/admin.py`, `**/apps.py`, `**/urls.py`, and `**/migrations/*.py` as entry files. A nested class named `Meta` is an entry. A module-level `urlpatterns` is used.
- `pydantic` treats `validator`, `field_validator`, `model_validator`, `computed_field`, `field_serializer`, and `model_serializer` as entry decorators.
- `celery` already counts `task` and `shared_task`. It also treats a module-level `beat_schedule` as used.

`ignore_names` drops a finding when the symbol matches a pattern. `ignore_bases` treats a class with that base as used. Its methods and attributes are not reported as unused. `vyarth baseline` is still the fingerprint list. There is no separate whitelist command.

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

Directory scans store one JSON record per file under `.vyarth/cache`. The key includes the Vyarth version, the index version, path, size, modification time, the fold map, and the duplicate-statement minimum. The first write creates `.vyarth/.gitignore` containing `*` and a `CACHEDIR.TAG`. After a scan of the project root, cache files whose stored path was not indexed are deleted. A subdirectory scan and a language-server overlay do not prune the cache. `--no-cache` reparses every file. A single-file scan does not use the cache. Overlay text from the language server is not cached.
