# Changelog

## 0.1.0

First release of Vyarth, a scope-aware detector for unused Python code.

- Reports unused imports, functions, classes, and variables, unreachable statements, modules no entry can import, orphan functions, unused declared dependencies, and duplicate function bodies.
- Scores each finding so `--min-confidence 100` keeps names and statements static analysis can show are unused.
- Provides `scan`, `fix`, `baseline`, and `lsp`. Text, JSON, SARIF, and GitHub annotation output.
- Fixes unused imports, unreachable statements, nested functions, and function-local assignments at confidence 100 when the assigned value is not a call.
- Reads configuration from `pyproject.toml` or `vyarth.toml`, including excludes, entry points, framework decorators, baselines, and constant folding.
- Treats a quoted annotation such as `"Decimal"` as a use of that name, including an import that exists only under `if TYPE_CHECKING:`.
- Treats an import or variable loaded inside a lambda as used. A function or class that the lambda would call stays unused until the lambda is called.
- When the scan path is a subdirectory, still reads console scripts from the parent `pyproject.toml` and only indexes files under that path.
- Shows the current scan step and elapsed time on standard error.
