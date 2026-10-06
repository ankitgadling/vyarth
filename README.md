# Vyarth

Vyarth (व्यर्थ, “in vain”) finds Python code that nothing uses: unused imports, functions, classes, and variables, unreachable statements, modules no entry point can import, and declared dependencies the code never imports.

It is a library and a command-line tool. The indexer is behind a small backend interface so a faster implementation can replace it later without rewriting the rules.

The user guide is in [docs/index.md](docs/index.md): the command line, configuration, rules, the Python API, CI, fixes, and how the analysis decides a name is unused.

## Install

Vyarth is not published on PyPI yet. From a checkout of this repository:

```bash
pip install .
```

Requires Python 3.11 or newer. Release notes are in `CHANGELOG.md`.

To work on Vyarth itself:

```bash
pip install -e ".[dev]"
pytest
```

## Command

```bash
vyarth scan .
vyarth scan src/ --format json
vyarth scan . --format sarif
vyarth scan . --format github
vyarth scan . --min-confidence 90
vyarth scan . --fail-on high
vyarth scan . --baseline vyarth-baseline.json
vyarth scan . --config vyarth.toml
vyarth scan . --define ENVIRONMENT=production
vyarth scan . --changed --changed-from origin/main
vyarth scan . --workers 0
vyarth baseline .
vyarth fix .
vyarth lsp
```

The process exits with code 1 when findings remain. `--fail-on high|medium|low` still prints every finding that passes the other filters, and exits 1 only when one of them is at or above 90, 70, or 0. A missing path or baseline exits 2. A syntax error in one file is reported and the rest of the scan continues.

While the scan runs, the current step and elapsed time are written to standard error and refreshed about once a second. In a terminal that status stays on one line, for example `vyarth: checking methods 412/2841 django/db/models/base.py  3m 08s`. Findings stay on standard output. When the scan finishes, the status line becomes `vyarth: scanned 2841 files in 4m 12s`.

Text output looks like this:

```text
UNUSED_VARIABLE
File: service.py
Line: 3
Variable: debug_value
Confidence: 100%
```

`vyarth scan . --format json` prints `files_scanned`, `findings`, and `errors`.

## Library

```python
from vyarth import scan

result = scan("src")
for finding in result.findings:
    print(finding.rule, finding.path, finding.line, finding.symbol)
print(result.to_json())
```

## What it reports

| Rule | Meaning | Confidence |
| --- | --- | --- |
| `UNUSED_IMPORT` | Import name never loaded | 100, or 70 when that file imports dynamically |
| `UNUSED_FUNCTION` | Function never loaded | 96 for a module-level function in a reached file, 96 for an unreferenced method on a used class, 75 when decorated but not an entry, 100 for a nested one |
| `UNUSED_CLASS` | Class never loaded, including as a base class | 96 at module level in a reached file, 75 when decorated but not an entry, 100 when nested |
| `UNUSED_VARIABLE` | Module or function variable never read | 100 in a reached file, or 70 for a module-level name in a dynamic file |
| `UNREACHABLE_CODE` | Statement after an exit, or a literal `False` branch | 100, status `DEAD` |
| `ORPHAN_FUNCTION` | Referenced, but no entry point reaches it | 80, or 60 when an unresolved attribute call uses the name |
| `POSSIBLY_UNUSED_MODULE` | No entry module can import this file | 82, or 60 when the project imports dynamically |
| `WILDCARD_IMPORT` | `from module import *` limits analysis | 100, status `ANALYSIS_LIMIT` |
| `UNUSED_DEPENDENCY` | Declared package with no import | 95, or 70 when the import name differs from the package name |
| `DUPLICATE_CODE` | Function body matches another function | 90, status `POSSIBLY_DUPLICATE` |

A load is a read: a call, a decorator, passing the name as a value, or using it in an annotation. Names are resolved per scope, so a local `x` does not count as a use of a module-level `x`. `global` and `nonlocal` are honored. The name `_` and dunder names such as `__all__` are not reported. Parameters are indexed and not reported yet.

`import pandas as pd` and `from pandas import DataFrame` follow the alias. `from __future__ import ...` is treated as used.

A module-level function or class with no references is `POSSIBLY_DEAD` at 96% when an entry module can import that file. The text report lists the checks under `Evidence:`: no references, no decorators, not exported, not an entry point, and no dynamic references. A literal name passed to `getattr`, `setattr`, `eval`, or `exec` lowers that name to 70%, including a method or nested function. Other names in the file stay at their own score. A decorator that is not a recognized entry lowers the score to 75%, including a nested function. Nested functions and function-local variables with no dynamic name and no decorator stay at 100%.

Unused modules are not called dead. They stay at 82% unless the project calls `importlib` or `__import__`, which lowers them to 60%. Functions, classes, variables, imports, orphans, and duplicates in that file do not score above the module. They disappear with the module under `--min-confidence 90`. `UNREACHABLE_CODE` stays at 100%. A module is unused only when no entry module can import it. Two modules that import only each other are both unused.

A project that contains a `src/` directory accepts both import styles. `src/account/cache.py` is `account.cache` for a src-layout install (`import account.cache`) and `src.account.cache` when the project root is on the path (`from src.account.cache import invalidate_account_cache`). Either import reaches that file. A function in the file is unused only when no reached module calls it.

`upgrade`, `downgrade`, `revision`, `down_revision`, `branch_labels`, and `depends_on` under `alembic/versions/` score 70%. The finding stays. `psycopg2-binary`, `pyjwt`, `python-dotenv`, and `python-jose` score 70% when the import name (`psycopg2`, `jwt`, `dotenv`, `jose`) is used. A package that is neither declared under that import name nor imported stays at 95%.

Entry modules are files matching the entry patterns, files with `if __name__ == "__main__":`, `[project.scripts]` and `[project.gui-scripts]` targets, `entry_points` from config, and test modules. The default entry patterns are `**/__main__.py`, `**/wsgi.py`, `**/asgi.py`, and `**/manage.py`. A symbol is also an entry when it is decorated with a framework hook (`route`, `get`, `post`, `put`, `delete`, `patch`, `head`, `options`, `task`, `shared_task`, `command`, `group`, `fixture`), named `lambda_handler` or `test_*`, or a method named `ready`. `@property`, `@staticmethod`, and `@classmethod` are recorded and are not entries by themselves. Extra decorator names go in `framework_decorators`.

These paths are not scanned: `.git`, `.venv`, `venv`, `__pycache__`, `build`, `dist`, plus anything in `.gitignore`. `tests/`, `test_*.py`, and `*_test.py` are indexed so their imports and calls keep application code alive, and findings inside those paths are hidden.

## Configuration

`pyproject.toml`:

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

`exclude` adds paths that are not indexed. `ignore` indexes the files (so their imports still count) and drops findings in those paths. Setting `entry_patterns` replaces the default list. A `vyarth.toml` file uses the same keys at the top level, or under `[tool.vyarth]`.

`workers` is the process pool size. `1` stays in-process. `0` uses the CPU count. `--workers` overrides the config value.

`[tool.vyarth.fold]` and `--define NAME=VALUE` fold `os.environ["NAME"]`, `os.getenv("NAME")`, and a bare name in the map. Equality, inequality, and `not` against that value become constant, so the dead branch is unreachable and calls inside it are ignored. A name that is not in the map stays unfolded.

`--changed` reads `git diff --name-only` against `HEAD`, or against `--changed-from REF`. The scan still indexes the project, using a cache in `.vyarth/cache` keyed by path, size, and mtime, and the report keeps findings in the changed Python files. `--no-cache` reparses every file. A missing git repository exits 2.

`vyarth fix` deletes unused imports and rescans. It also deletes unreachable statements, nested functions, and function-local assignments whose confidence is 100, when the assignment's value is not a call. A line that mixes an import with another statement is left alone, and so is a wildcard import. Module-level functions stay reported.

`vyarth lsp` speaks Content-Length JSON-RPC on stdin and stdout. It answers `initialize`, `shutdown`, `textDocument/didOpen`, `textDocument/didChange`, `textDocument/didSave`, pull `textDocument/diagnostic`, and `textDocument/codeAction` for those same rewrites.

## Baseline and CI

`vyarth baseline .` writes `vyarth-baseline.json`, a sorted list of fingerprints. `vyarth scan . --baseline vyarth-baseline.json` reports only fingerprints that are not in that file. The exit code follows the filtered set.

`--format github` prints GitHub annotations:

```text
::error file=pkg/app.py,line=4,title=UNUSED_FUNCTION::Function 'helper' is never used.
```

`--format sarif` prints SARIF 2.1.0. Each result carries `partialFingerprints` from the finding fingerprint. Confidence at or above 90 is `error`; anything lower is `warning`.

```yaml
- name: Vyarth
  run: vyarth scan . --format github --fail-on high
```

## Suppress a finding

On the same line, or on the line immediately above:

```python
# vyarth: ignore
def legacy_function():
    ...

value = 1  # vyarth: ignore[unused-variable]
```

Rule names are case-insensitive. Hyphens and underscores match, so `unused-function` is `UNUSED_FUNCTION`.

## Limits

An unreferenced method on a used class is `UNUSED_FUNCTION` at 96. `@property`, `@cached_property`, abstract methods, `pass`, `...`, and `raise NotImplementedError` stay silent. A method that is referenced, but no entry reaches the call, stays `ORPHAN_FUNCTION` at 80. An unresolved `obj.method()` lowers that to 60. A plain class attribute that nothing loads is `UNUSED_VARIABLE` at 96. `@dataclass` and attrs classes are left alone.

A name listed in `__all__` is used. So is a name that another project module imports and then loads: a call, an annotation, or another `__all__` entry. An import that nothing in the importing file loads does not keep the original definition alive. Passing a function as a value (`handlers.append(foo)`) is a use, so that function is not an orphan.

Dependency names are read from `requirements.txt`, `requirements-dev.txt`, `pyproject.toml` (project dependencies, optional dependencies, Poetry, and uv), `Pipfile`, and a literal `install_requires` list in `setup.py`. Install-name matches are not reported: `pillow` / `PIL`, `pyyaml` / `yaml`, `scikit-learn` / `sklearn`, and `opencv-python` / `cv2`. `psycopg2-binary`, `pyjwt`, `python-dotenv`, and `python-jose` stay reported at 70% when the code imports `psycopg2`, `jwt`, `dotenv`, or `jose`. A declared package with no matching import stays at 95%.

`assert` is not treated as an exit. Aliases (`alias = func` then `alias()`), `pkg.api.func()`, stores such as `self.handler = func`, and `make().run()` when `make` is annotated `-> Widget` are followed. An unresolved `obj.method()` still does not connect every method of that name.

Duplicate detection hashes statement shape and constants. Local names are ignored. Two bodies match only when they are structurally the same and at least `duplicate_min_statements` long. A list or tuple in one function records the functions stored in it. A later constant subscript calls that element, and a loop or an unknown index calls every element. A store with no later call still counts as a use, and the stored function's body is still walked. Fuzzy clone detection and a published editor extension are later work.
