# Rules

Each finding has a rule, a status, a confidence from 0 to 100, a message, evidence lines, and a fingerprint. The fingerprint is `RULE:path:qualname`. Line numbers are left out so a baseline survives edits that shift lines.

`--min-confidence 100` keeps names and statements that static analysis can show are unused. Scores below 100 mean something in the project could still load the name at runtime.

| Rule | Meaning | Confidence | Status |
| --- | --- | --- | --- |
| `UNUSED_IMPORT` | Import name never loaded | 100, or 70 when that file imports dynamically or the import is an `ImportError` probe | `DEAD`, or `POSSIBLY_DEAD` at 70 |
| `UNUSED_FUNCTION` | Function or method never loaded | 100 nested, 96 at module level or on a used class, 75 when decorated but not an entry, 70 when a dynamic call names it | `DEAD` at 100, otherwise `POSSIBLY_DEAD` |
| `UNUSED_CLASS` | Class never loaded, including as a base class | 100 nested, 96 at module level, 75 when decorated but not an entry, 70 when a dynamic call names it | `DEAD` at 100, otherwise `POSSIBLY_DEAD` |
| `UNUSED_VARIABLE` | Module, class, or function variable never read | 100 in a function or at module level, 96 for an unreferenced attribute on a used class, 70 or 60 when a dynamic or unresolved call uses the name | `DEAD` at 100, otherwise `POSSIBLY_DEAD` |
| `UNREACHABLE_CODE` | Statement after an exit, or a literal `False` branch | 100 | `DEAD` |
| `ORPHAN_FUNCTION` | Referenced, but no entry point reaches it | 80, or 60 when an unresolved attribute call uses the name | `POSSIBLY_DEAD` |
| `POSSIBLY_UNUSED_MODULE` | No entry module can import this file | 82, or 60 when the project imports dynamically | `POSSIBLY_UNUSED_MODULE` |
| `WILDCARD_IMPORT` | `from module import *` limits analysis | 100 | `ANALYSIS_LIMIT` |
| `UNUSED_DEPENDENCY` | Declared package with no import | 95, or 70 when the import name differs from the package name, or when the package is only a development or docs dependency | `POSSIBLY_DEAD` |
| `DUPLICATE_CODE` | Function body matches another function | 90 | `POSSIBLY_DUPLICATE` |

Findings inside a possibly unused module do not score above that module, except `UNREACHABLE_CODE`, which stays at 100. Those findings disappear with the module under `--min-confidence 90`.

## What counts as a load

A load is a read: a call, a decorator, passing the name as a value, or using it in an annotation. Names are resolved per scope, so a local `x` does not count as a use of a module-level `x`. `global` and `nonlocal` are honored.

The name `_` and dunder names such as `__all__` are not reported. Parameters are indexed and not reported.

`import pandas as pd` and `from pandas import DataFrame` follow the alias. `from __future__ import ...` is treated as used. `from module import Name as Name` is a public re-export: the import is used, and the original definition stays alive. An attribute on an imported submodule, such as `types.OptionHelpExtra`, loads that name. A quoted name inside `Union`, `Optional`, the first argument of `Annotated`, or a `|` expression does too. A string inside `Literal`, or later `Annotated` metadata, does not.

A name listed in `__all__` is used. So is a name that another project module imports and then loads: a call, an annotation, or another `__all__` entry. An import that nothing in the importing file loads does not keep the original definition alive. Passing a function as a value (`handlers.append(foo)`) is a use.

## `UNUSED_FUNCTION` and `UNUSED_CLASS`

A module-level function or class with no references is `POSSIBLY_DEAD` at 96% when an entry module can import that file. The text report lists the checks under `Evidence:`:

- No references found.
- No decorators.
- Not exported.
- Not an entry point.
- No dynamic references detected.

A nested function with no dynamic name and no decorator stays at 100%.

An unreferenced method on a used class is `UNUSED_FUNCTION` at 96, with the message `Method 'name' is never used.` `@property`, `@cached_property`, abstract methods, `pass`, `...`, and `raise NotImplementedError` stay silent. The body of a `@property` or `@cached_property` on a used class is still walked, so a call inside it counts. A reached call to a method also reaches an override of that method on a known subclass. A method that is referenced, but no entry reaches the call, is `ORPHAN_FUNCTION` instead. A typed call such as `auth.async_auth_flow()` counts as a reference even when the caller itself is not reached.

A decorator that is not a recognized entry lowers the score to 75%, including a nested function. `@property`, `@staticmethod`, and `@classmethod` are recorded and are not entries by themselves. See [How analysis works](how-analysis-works.md) for the decorator list.

A literal name passed to `getattr`, `setattr`, `eval`, or `exec` lowers that name to 70%, including a method or nested function. The message becomes `Dynamic usage detected. Static analysis cannot prove this symbol is unused.` Other names in the file stay at their own score.

`upgrade`, `downgrade`, `revision`, `down_revision`, `branch_labels`, and `depends_on` under `alembic/versions/` score 70%. The finding stays, with evidence that Alembic loads the name when the migration runs.

## `UNUSED_VARIABLE`

A function-local assignment that nothing reads is 100%. A module-level name that nothing reads is 100% unless a dynamic call names it, which lowers it to 70%.

A plain class attribute that nothing loads, on a class that is used, is `UNUSED_VARIABLE` at 96. An unresolved `obj.name()` anywhere lowers an attribute of that name to 60. `@dataclass` and attrs classes are left alone, so their fields are not reported. Members of `Enum`, `IntEnum`, `StrEnum`, `Flag`, and `IntFlag` are left alone too. Methods on those classes are still reported.

## `UNUSED_IMPORT`

The imported name is unused when nothing in that file loads it and it is not re-exported through `__all__` or `from module import Name as Name`. Confidence stays at 100 unless the same file calls `importlib`, `importlib.import_module`, or `__import__`, which lowers every unused import in that file to 70%. An import that is the body of a `try` whose handler catches `ImportError` or `ModuleNotFoundError` stays reported at 70%, because the import may be an availability check and may also be unused. `# noqa` and `# noqa: F401` on the import statement, including a parenthesized import and a note after the code such as `# noqa: F401 kept for plugins`, suppress `UNUSED_IMPORT` for the names in that statement. A `# noqa` on the previous line does not.

## `UNREACHABLE_CODE`

Reported after `return`, `raise`, `break`, or `continue`, and after `sys.exit()` or `os._exit()`. A branch whose test is the constant `False` is unreachable. `assert` is not an exit. A `for` over an empty literal or an empty `range` makes the body unreachable. A loop `else` is unreachable when the body cannot finish normally, because it always `break`s, `return`s, or `raise`s. `vyarth fix` leaves a `yield` or `yield from` in place when it is the only yield in its function, because deleting it would turn a generator into a normal function. The finding stays.

Folded environment checks use the same rule. With `ENVIRONMENT` folded to `production`, the body of `if os.getenv("ENVIRONMENT") == "development":` is unreachable, and calls inside it do not count.

## `ORPHAN_FUNCTION`

The function is referenced — something loads the name — and no entry point reaches that reference. Confidence is 80. An unresolved `obj.method()` lowers every orphan of that method name to 60, with the evidence `An unresolved attribute call uses this name.`

## `POSSIBLY_UNUSED_MODULE`

A module is unused only when no entry module can import it. Two modules that import only each other are both unused. The finding is not called dead. It stays at 82% unless any file in the project calls `importlib` or `__import__`, which lowers every such module to 60%.

A project that contains a `src/` directory accepts both import styles. `src/account/cache.py` is `account.cache` for a src-layout install (`import account.cache`) and `src.account.cache` when the project root is on the path (`from src.account.cache import invalidate_account_cache`). Either import reaches that file. A function in the file is unused only when no reached module calls it.

Scanning a single file skips this rule.

## `WILDCARD_IMPORT`

`from module import *` is reported so you can see where analysis is incomplete. The imported names are still treated as possible references when the target module is in the project.

## `UNUSED_DEPENDENCY`

Dependency names are read from:

- `requirements.txt` and `requirements-dev.txt`
- `pyproject.toml`: `[project.dependencies]`, `[project.optional-dependencies]`, `[dependency-groups]`, Poetry dependencies and groups, and `[tool.uv] dev-dependencies`
- `Pipfile` packages and dev-packages
- a literal `install_requires` list or keyword in `setup.py`

The package `python` is skipped. Requirement lines that are comments, `-r`, `-c`, `-e`, `--`, `git+`, or URLs are skipped.

These install names match their import names and are not reported: `pillow` / `PIL`, `pyyaml` / `yaml`, `scikit-learn` / `sklearn`, `opencv-python` / `cv2`, `beautifulsoup4` / `bs4`, `pyopenssl` / `OpenSSL`. `psycopg2-binary`, `pyjwt`, `python-dotenv`, and `python-jose` stay reported at 70% when the code imports `psycopg2`, `jwt`, `dotenv`, or `jose`. A package declared only in a development or docs manifest (`requirements-dev.txt`, `docs/requirements.txt`, `[dependency-groups]`, a Poetry group, uv `dev-dependencies`, Pipfile `dev-packages`, or a `[project.optional-dependencies]` group named `dev`, `test`, `tests`, `docs`, `doc`, `lint`, or ending in `-dev`) stays reported at 70%. Other optional extras stay at 95% when nothing imports them. A runtime package with no matching import stays at 95%, with the message `No Python imports found.`

Scanning a single file skips this rule. A dynamic `importlib.import_module("pkg")` with a string literal counts as an import of `pkg`.

## `DUPLICATE_CODE`

Duplicate detection hashes statement shape and constants. Local names are ignored. Two bodies match only when they are structurally the same and at least `duplicate_min_statements` long (default 5). The first copy, in path and line order, is the origin. Later copies are reported at 90% with status `POSSIBLY_DUPLICATE` and a message such as `Function 'format_row' duplicates pkg/a.py:format_row`. Test modules are not compared.

## Suppress a finding

On the same line, or on the line immediately above:

```python
# vyarth: ignore
def legacy_function():
    ...

value = 1  # vyarth: ignore[unused-variable]
```

A comment with no bracket suppresses every rule on that statement. A bracket lists one or more rules, separated by commas. Rule names are case-insensitive. Hyphens and underscores match, so `unused-function` is `UNUSED_FUNCTION`.

A comment on the line above a decorator, or on a decorator line, also covers the `def` or `class` it belongs to.

`# noqa` and `# noqa: F401` on an import statement suppress `UNUSED_IMPORT` for every name in that statement. Words after the code, as in `# noqa: F401 kept for plugins`, are ignored. A `# noqa` that lists other codes, and not `F401`, does not. A `# noqa` on the line above the import does not either.

Path suppression is separate: `ignore` in config drops findings without a comment. See [Configuration](configuration.md).
