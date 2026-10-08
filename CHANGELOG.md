# Changelog

## Unreleased

- Counts `from module import Name as Name` as a public re-export, follows an attribute on an imported submodule, and reads a quoted name inside `Union`, `Optional`, the first argument of `Annotated`, and a `|` expression.
- Skips members of `Enum`, `IntEnum`, `StrEnum`, `Flag`, and `IntFlag`. Methods on those classes are still reported.
- Walks `@property` and `@cached_property` bodies on a used class, follows a typed cross-module call, and reaches an override of a reached method.
- Treats `setup.py` and `docs/conf.py` as entry modules.
- Leaves the only `yield` or `yield from` in a function in place when fixing unreachable code.
- Honors `# noqa` and `# noqa: F401` on an import statement, including a note after the code. A `# noqa` on the previous line does not apply.
- Reports an import inside `try`/`except ImportError` or `ModuleNotFoundError` at 70% instead of hiding it.
- Maps `OpenSSL` to `pyopenssl`. A package declared only as a development or docs dependency scores 70%, including a `[project.optional-dependencies]` group named `dev`, `test`, `tests`, `docs`, or `lint`.

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
