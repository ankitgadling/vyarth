# How analysis works

A scan indexes every Python file, decides which modules an entry point can import, and then asks which names those modules actually load. The rules never see AST nodes. They read a `FileIndex`: bindings, imports, calls, decorators, and unreachable spans. Another indexer can emit the same records later.

## What gets indexed

File discovery starts at the directory you named, so `vyarth scan src` does not index the rest of the repository. The project root is the nearest ancestor that contains `pyproject.toml`, `vyarth.toml`, or `.git`. Configuration, console scripts, and finding paths come from that root. The walk skips the built-in excludes, the root `.gitignore`, `.git/info/exclude`, and each nested `.gitignore`, and it skips `exclude` patterns from config. A nested ignore file applies under its directory, and a later rule wins. Test modules, including `conftest.py`, stay in the index. Their findings are removed after scoring, so a test that calls `app.service.run` keeps `run` alive.

Each file is parsed with the standard library `ast` module. The index records:

- every binding and how many times its name is loaded in that scope
- imports, including relative imports and wildcards
- calls, and whether the callee resolved inside the file
- decorators
- class bases
- assignments of functions into lists, tuples, and attributes
- return annotations, including a quoted forward reference such as `"Decimal"`
- a structural hash of each function body
- string literals passed to `getattr`, `setattr`, `eval`, `exec`, and `importlib`

A syntax error becomes a `ParseError`. That file is skipped and the scan continues.

## Entry points

A module is an entry when any of these is true:

- its path matches an entry pattern (`**/__main__.py`, `**/wsgi.py`, `**/asgi.py`, `**/manage.py`, `setup.py`, `**/docs/conf.py`, unless you replace the list)
- it contains `if __name__ == "__main__":`
- it is a test module, including `conftest.py`
- `[project.scripts]`, `[project.gui-scripts]`, or an entry-points group named `console_scripts` or `gui_scripts` names it
- `entry_points` in config names it
- `frameworks` includes `django` and the path is `settings.py`, `admin.py`, `apps.py`, `urls.py`, or a file under `migrations/`

A symbol is an entry when:

- it is decorated with a framework hook, a name in `ignore_decorators`, or a Pydantic hook when `frameworks` includes `pydantic`
- it is a module-level function named `lambda_handler`, or whose name starts with `pytest_`
- its name starts with `test_`
- it is a method named `ready`
- `frameworks` includes `django` and it is a class named `Meta`, or a module-level name `urlpatterns`
- `frameworks` includes `celery` and it is a module-level name `beat_schedule`
- its class has a base listed in `ignore_bases`, which also covers that class’s methods and attributes

The built-in decorator hooks, matched on the final attribute, are `route`, `get`, `post`, `put`, `delete`, `patch`, `head`, `options`, `task`, `shared_task`, `command`, `group`, and `fixture`. `framework_decorators` adds more names. `@property`, `@staticmethod`, `@classmethod`, and the abstract-method decorators are recorded and are not entries by themselves.

## Reachability

From each entry module, Vyarth follows imports. A relative import is resolved against the importing file. In a project that contains `src/`, a file is reachable under both the src-layout name (`account.cache`) and the path from the project root (`src.account.cache`).

A module that no entry can import is `POSSIBLY_UNUSED_MODULE`. Modules that import only each other are both unused, because nothing outside the cycle starts the walk.

Inside a reached module, a symbol is alive when any of these is true:

- something in its scope loads the name
- the module lists it in `__all__`, or re-exports it with `from module import Name as Name`
- a reached caller calls it, decorates with it, or passes it as a value
- an entry decorator or an entry name marks it
- another module imports it and then loads that import

Aliases are followed. `alias = func` and then `alias()` reaches `func`. `pkg.api.func()` reaches `func` when `pkg.api` resolves to a project module. `types.Name` reaches `Name` when `types` is a project submodule. `self.handler = func` and a later `self.handler()` reach `func`. `make().run()` reaches `Widget.run` when `make` is annotated `-> Widget`. `Widget().run()` reaches `Widget.run` as well. A call on a parameter annotated as a class reaches that method. The body of a `@property` or `@cached_property` on a used class is walked. A reached method call also reaches an override of that method on a known subclass.

A list or tuple of functions records those functions in order. A later constant subscript calls that element. A loop, or an unknown index, calls every element. A store with no later call still counts as a use, and the stored function’s body is still walked.

An unresolved `obj.method()` does not connect every method named `method`. It lowers the confidence of an orphan or unused class attribute with that name to 60.

Calls inside unreachable statements are ignored.

## Confidence

Rules first mark a name unused at 100. A second pass lowers the score when static analysis cannot prove the name is dead:

| Situation | Score |
| --- | --- |
| Module-level function or class with no references | 96 |
| Unreferenced method on a used class | 96 |
| Unreferenced attribute on a used class | 96 |
| Decorated, and the decorator is not an entry | 75 |
| The name appears as a string in `getattr`, `setattr`, `eval`, or `exec` | 70 |
| The file calls `importlib` or `__import__` | unused imports in that file drop to 70 |
| Unused import in `__init__.py` | 70, as a possible public re-export |
| Unused dotted `import pkg.sub` | 70, because the import may run the submodule for its side effects |
| Any file in the project imports dynamically | unused modules drop to 60 |
| Referenced, but no entry reaches the reference | 80, or 60 if an unresolved attribute call uses the name |
| Duplicate body | 90 |

Findings in an unused module, other than unreachable code, are capped at the module’s score. A `DEAD` finding that this cap, or the Alembic adjustment, lowers below 100 becomes `POSSIBLY_DEAD`.

## Dependencies and duplicates

After the symbol rules, a directory scan reads dependency manifests and reports packages that no indexed import mentions. It then groups function-body hashes and reports later copies. Both steps are described in [Rules](rules.md).

## Limits

These are outside what the current indexer proves:

- A string built at runtime and passed to `getattr` or `importlib` is invisible. Only literal names lower confidence.
- A name loaded inside a lambda counts as a use, so an import or variable used only there is kept. A function or class that the lambda would call does not count until something calls the lambda.
- `assert` is not an exit, so code after a failing assert is still treated as live.
- An unresolved attribute call does not match a specific class. It only lowers the score of that method name.
- Fuzzy clone detection is not implemented. Duplicates are exact structural matches.
- Parameters are not reported.
- There is no published editor extension. `vyarth lsp` is the server a client can launch.
