# Changelog

## Unreleased

- Fewer false positives, found by probing the analyzer with repro cases:
  - Quoted types in `TypeVar(bound=...)`, `List["X"]`, `NewType`, `TypedDict`, `NamedTuple`, `cast`, `isinstance`, and `Generic`, and `# type:` comments, count as uses. An import behind `if False:` that only holds typing names is treated as a typing import.
  - `locals()` and `vars()` read every local. Loop, unpacking, `with ... as`, and comprehension targets, and `_name` locals, are not reported as unused variables.
  - A lambda that is passed, stored, or returned is assumed to run, so its callees are reached. This replaces the earlier rule that waited for a call to the lambda.
  - A method called on a receiver of unknown type reaches the method when one class owns that name or when its owners share a base. A call on a base class that does not define the method reaches subclass overrides. `type(self).x`, `self.__class__.x`, and `self.x += 1` read the attribute.
  - Names built with `getattr(obj, "prefix_" + x)`, `globals()`, and `getattr(self, name)` lower the matching findings to 70.
  - Subclasses of a class with `__init_subclass__` count as used. A name re-exported through `from .core import *` is found, and `pkg.thing()` marks the import in `pkg/__init__.py` as used.
  - Fields on classes that inherit from a declarative base through project classes are not reported. A project class that merely shares a name such as `Model` is not a declarative base. A class attribute under an external base scores at most 60.
  - Reads every entry-point group, `[tool.poetry.scripts]`, `setup.cfg`, and `setup.py`. Treats `noxfile.py`, `fabfile.py`, `tasks.py`, `alembic/env.py`, `scripts/`, and `bin/` as entries, and `test/`, `testing/`, and `tests.py` as tests. A top-level folder that holds packages, such as `backend/app/`, is an import root.
  - Orphan functions score 60 when the scan finds no entry point. A file that fails to parse lowers to 70 only the cross-file findings whose name it mentions. Local variables and findings it never names keep their score. Parse errors in test files are ignored.
  - Build tools, linters, type stubs, and packages named in a source string score 70 as unused dependencies instead of 95. celery, lembic, and supervisor are runtime libraries and keep 95.
- A manifest change to `setup.cfg` now invalidates the cached result. The per-file cache manifest is written once per scan instead of once per file.
- A base-class method called through `self` from a subclass `__init__` or dunder in another module is no longer reported.
- The index format changed. Cached indexes from an earlier version are rebuilt on the next scan.
- A quoted name inside `Callable[["Name"], Any]`, including the value of a `TypeAlias`, counts as a use of that name.
- Confidence 100 is only a name or statement that is unused and safe to delete.
- An unchanged directory scan reuses the previous finding list. Dependency manifests are collected during file discovery, and cache pruning reads a sidecar instead of every index.
- Scores an unused public name at 60% only when it can be API: the scan is a library, or `__init__.py` or `__all__` exposes it. In an application with an entry point, a dead public function, class, method, or attribute stays at 96%, so `--fail-on high` still fails on it. A dead public module-level variable is 96% there, not 100%. Private names keep 96%, or 100% for a private module-level variable. A scan is an application only if it has a real program: a console script (plugin entry-point groups do not count), `__main__.py`, `wsgi.py`, `asgi.py`, `manage.py`, a framework callback such as a route or task, or a top-level script with a main guard. `docs/conf.py`, `setup.py`, examples, and a main guard inside a package module do not make a project an application.
- Module-level names in `docs/conf.py` are read by Sphinx and are not reported.
- Scores duplicate function bodies at 80%, so they stay out of `--fail-on high`.
- A scan of the project root no longer treats manifests under `examples/`, `tutorial/`, `samples/`, `demo/`, or `benchmarks/` as project dependencies. Nested package manifests still count. Scanning that directory reports its own manifest.
- Counts `from module import Name as Name` as a public re-export, follows an attribute on an imported submodule, and reads a quoted name inside `Union`, `Optional`, the first argument of `Annotated`, and a `|` expression.
- Skips members of `Enum`, `IntEnum`, `StrEnum`, `Flag`, and `IntFlag`. Methods on those classes are still reported.
- Walks `@property` and `@cached_property` bodies on a used class, follows a typed cross-module call, and reaches an override of a reached method.
- Treats `setup.py` and `docs/conf.py` as entry modules.
- Leaves the only `yield` or `yield from` in a function in place when fixing unreachable code.
- Honors `# noqa` and `# noqa: F401` on an import statement, including a note after the code. A `# noqa` on the previous line does not apply.
- Reports an import inside `try`/`except ImportError` or `ModuleNotFoundError` at 70% instead of hiding it.
- Maps `OpenSSL` to `pyopenssl`. A package declared only as a development or docs dependency scores 70%, including a `[project.optional-dependencies]` group named `dev`, `test`, `tests`, `docs`, or `lint`.
- Treats the first argument of `cast("Fraction", value)` as a use of that name.
- Reaches `visit_*` methods on a used `NodeVisitor` or `NodeTransformer`. `Widget().run()` reaches `Widget.run`.
- A subdirectory scan no longer reports dependency manifests that live outside that directory, such as `examples/requirements.txt`. Manifests in the project root still count.

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
