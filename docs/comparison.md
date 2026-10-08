# Comparison

These counts are from one local run on 8 October 2026, on Python 3.12.6, Windows. Nothing was labeled by hand as a complete true or false set. The tables are raw finding counts, plus a few disagreements that were checked in the source.

An earlier revision of this page used Flask 3.1.2 and requests 2.32.5. The trees below are current checkouts.

## Tools

| Tool | Release | Command |
| --- | --- | --- |
| Vyarth | 0.1.0, this repository | `vyarth scan <checkout> --min-confidence 0 --no-cache` |
| Vulture | 2.16 | `vulture <checkout> --min-confidence 80` and `--min-confidence 60` |
| deadcode | 2.4.1 | `deadcode <checkout> --no-color` |
| dead | 2.1.0 | `dead`, run from the checkout |
| Skylos | 4.47.0 | not run |

Skylos 4.47.0 is absent from the tables. `pip install skylos` failed while building `tree-sitter-dart-orchard`: that package had no Windows wheel, and this machine has no Microsoft C++ build tools. Its README describes a default `skylos PATH` scan for dead code and unused files, and `skylos clean --dry-run` or `--apply` for Python import and function rewrites. `skylos PATH -a` adds security, secrets, quality, and dependency checks. It also ships a VS Code extension.

## Checkouts

Each tool that ran saw the whole checkout, including tests, examples, and docs.

| Project | Commit | Python files |
| --- | --- | --- |
| Flask 3.2.0.dev, `main` | `d086db856be187255b8ec61ef409357393020f32` | 83 |
| requests 2.34.2 | `611c6162cbc4ac2020a2f91c7cfa4f3abf9bbb60` | 37 |

Vyarth scanned all 83 and 37 Python files. A scan of only `src/flask` or `src/requests` makes public re-exports look unused, because the tests that call them sit outside that directory.

## How the counts were taken

Vyarth indexes tests, then hides findings inside test modules. The ≥90 column keeps findings whose confidence is at least 90, which is the same set as `vyarth scan <checkout> --min-confidence 90`.

Vulture’s lines are whatever it printed at that threshold, grouped by the words in the message. It separates `unused function` from `unused method`. Vyarth’s `UNUSED_FUNCTION` includes methods. deadcode has no confidence score. Its codes in this run are DC01 variable, DC02 function, DC03 class, DC04 method, DC05 attribute, DC07 import, and DC08 property. It printed no DC09 unreachable-code lines. `dead` prints one line per name and splits “never read” from “only referenced in tests”.

| | Vyarth | Vulture | deadcode | dead | Skylos |
| --- | --- | --- | --- | --- | --- |
| Unused names | imports, functions, classes, variables | those, plus attributes, methods, and properties | DC01–DC08 in this run | one line per unread name | README: dead code. Not run |
| Unreachable code | yes | yes | no lines in this run | no lines in this run | not run |
| Entry reachability | orphans and unused modules | name-based | name-based | name-based, with a test split | not run |
| Unused dependencies | yes | no | no | no | README: with `-a` |
| Duplicate function bodies | yes | no | no | no | README: quality checks with `-a` |
| Rewrite | `vyarth fix`, including `--dry-run` and `--diff` | no | `--fix` and `--dry` | no | README: `skylos clean --dry-run` / `--apply` |
| Ignore lists | `ignore_names`, `ignore_decorators`, `ignore_bases`, `# vyarth: ignore` | `--ignore-names`, `--ignore-decorators`, `--make-whitelist` | several `--ignore-*` flags | `--symbol-allowlist`, `# dead: disable` | not run |

## Counts

| Project | Vyarth | Vyarth ≥90 | Vulture ≥60 | Vulture ≥80 | deadcode | dead |
| --- | --- | --- | --- | --- | --- | --- |
| Flask 3.2.0.dev | 176 | 95 | 342 | 35 | 307 | 66 |
| requests 2.34.2 | 103 | 70 | 89 | 11 | 84 | 70 |

`dead` on Flask printed 36 names that are never read and 30 that are only referenced in tests. On requests those splits are 63 and 7.

Imports and functions, at the stricter threshold for the two tools that have one:

| Project | Vyarth imports ≥90 | Vyarth functions ≥90 | Vulture imports ≥80 | Vulture functions ≥80 | deadcode imports (DC07) | deadcode functions (DC02) |
| --- | --- | --- | --- | --- | --- | --- |
| Flask 3.2.0.dev | 0 | 31 | 0 | 0 | 0 | 252 |
| requests 2.34.2 | 1 | 25 | 3 | 0 | 4 | 8 |

Flask has no `UNUSED_IMPORT` findings at any confidence. At confidence 60, Vulture reported 252 unused functions and 10 unused methods in Flask, and deadcode reported the same 252 functions (DC02) and 10 methods (DC04). On requests those pairs are 8 and 16 for Vulture, and 8 and 17 for deadcode.

Vulture at confidence 80 printed 34 unused variables and 1 unreachable statement in Flask, and 8 unused variables in requests. It printed no unused functions in either checkout.

Vyarth’s findings by rule:

| Rule | Flask | Flask ≥90 | requests | requests ≥90 |
| --- | --- | --- | --- | --- |
| `UNUSED_IMPORT` | 0 | 0 | 7 | 1 |
| `UNUSED_FUNCTION` | 35 | 31 | 26 | 25 |
| `UNUSED_CLASS` | 1 | 1 | 2 | 1 |
| `UNUSED_VARIABLE` | 61 | 54 | 42 | 42 |
| `ORPHAN_FUNCTION` | 62 | 0 | 20 | 0 |
| `POSSIBLY_UNUSED_MODULE` | 1 | 0 | 1 | 0 |
| `UNUSED_DEPENDENCY` | 16 | 9 | 5 | 1 |

Nine of Flask’s unused-dependency findings score 95. Several of those names, including `amqp` and `kombu`, are pinned in `examples/celery/requirements.txt`.

## Disagreements that were checked

`from datetime import datetime` in Flask’s tutorial `examples/tutorial/flaskr/db.py` is used only inside `sqlite3.register_converter("timestamp", lambda v: datetime.fromisoformat(...))`. That load counts, so the import is kept. A function or class named only as the callee of an uncalled lambda still does not count as reached.

`import socket` in `requests/adapters.py` is marked `# noqa: F401` and is not otherwise loaded. Vyarth honors that comment and does not report the import. Vulture’s output does not list it either.

`Response` in `requests/_types.py` is imported under `if TYPE_CHECKING` and nothing in that file loads the name. It is Vyarth’s only unused import at or above 90, with confidence 100. Vulture’s confidence-80 imports are the three names below, and its output does not list `Response`.

`quote_plus`, `unquote_plus`, and `urldefrag` in `requests/compat.py` are legacy names. Vulture reports them as unused imports at 90, and deadcode reports them as DC07. Vyarth reports them at 70, so they fall out of the ≥90 column. `compat.py` calls `importlib.import_module`, which lowers every unused import in that file. The same file’s `OrderedDict`, `Callable`, and `StringIO` are at 70 for the same reason. deadcode’s fourth DC07 is `HEADER_VALIDATORS` in `requests/utils.py`.

`MockRequest.get_full_url` in `requests/cookies.py` is part of the `urllib2.Request` surface that `http.cookiejar` calls. Nothing in the checkout loads that name. Vyarth reports it as an unused function at 96. Vulture reports it as an unused method at 60, so `--min-confidence 80` hides it.

`Flask.send_static_file` in `src/flask/app.py` is an unused function at 96. The checkout never loads that name. Vulture’s output, including the confidence-60 run, does not list `send_static_file`. That gap, and the function-count gap in the table above, is why this page stops at raw counts and the lines checked here.
