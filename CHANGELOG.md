# Changelog

## Unreleased

- A class attribute or method stays at 60 when an ancestor, not only a direct base, is defined outside the project. `object` and `type` do not count. Enum members stay quiet when the enum base is a project class. A class attribute that a base reads is treated as used on subclasses that override it. An `UPPER_CASE` name in a module whose filename contains `settings` stays at 60.
- An ignore comment can carry a reason, and `require_ignore_reason` rejects one that does not. `--report-unused-ignores` reports a directive that suppressed nothing. `[[tool.vyarth.allow]]` suppresses a qualname glob. Baseline files gain a version 2 record with a reason and a date. Version 1 files still load. `--add` appends one id, `--prune` drops entries the scan no longer reports, and `--baseline-mode all` keeps baselined findings visible.
- `vyarth mcp` answers scan, explain, fix preview, apply, baseline, and list-rules over stdio. `vyarth init` writes the agent snippet and MCP config. `AGENTS.md`, `docs/agents.md`, and `llms.txt` describe the loop. A pre-commit hook and a GitHub Action run the scan. `vyarth eval` scores a scripted policy that deletes only confidence-100 safe fixes.
- `fix --verify` compiles the edited files and can run `fix_verify_command`. A failed check restores the original bytes and exits 3. `--exit-zero` does not hide that exit. `--verify-each` keeps the files that pass. `--unsafe-fixes` with `--select-id` deletes a nested 90–99 name. `--unsafe` still only removes confidence-70 imports. An edit that covers uncommitted lines is skipped. `--require-clean` refuses a dirty worktree. `--diff --format json` prints the diffs.
- `--summary` prints one line, or the summary object for json, jsonl, and sarif. `--max-findings` keeps the first N after sorting and records the rest on `summary`. With no `--sort`, that window sorts by confidence. `--sort` is `confidence`, `path`, or `rule`. `--select` and `--ignore-rule` filter rules. `--fixable-only` keeps safe fixes. `--paths-only` prints the files. `--brief-evidence` drops the five checklist evidence lines, and jsonl does that by default. `vyarth explain` prints the evidence, reason codes, other lines that spell the name, the ignore comment, the baseline command, and the fix diff.
- `--format json` is report schema v1. It adds `schema_version`, `id`, `reasons`, `fix`, `summary`, and end positions, and keeps every existing key. `--format jsonl` prints one finding per line and a summary line. `vyarth schema` prints the schema. `fix` notes for json, jsonl, and sarif go to stderr, and the JSON report includes `applied`. `--exit-zero` exits 0 when findings remain. `--concise-confidence` appends the score to concise lines.
- A dotted string in `MIDDLEWARE`, `INSTALLED_APPS`, `AUTHENTICATION_BACKENDS`, or a `*_BACKEND` / `*_BACKENDS` list marks the project class or function it names as used. `from module import NAME` followed by `NAME = ...` still counts as a use of the source. An override through an empty intermediate class stays reached. `dir(module)` or `getattr(module, name)` lowers upper-case names in that module to 70%.
- `frameworks` defaults to `auto`. A required `django` dependency, or `DJANGO_SETTINGS_MODULE` assigned in `manage.py`, `wsgi.py`, or `asgi.py`, turns on the Django entry files. `frameworks = []` opts out. An optional extra, a Poetry group, `dependency-groups`, or `requirements-dev.txt` does not. `settings.py`, `urls.py`, `apps.py`, `admin.py`, and migration modules do not mark the project as an application.
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
