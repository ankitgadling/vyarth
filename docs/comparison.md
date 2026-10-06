# Comparison with Vulture

These counts are from one local run. They are not a precision score. Nothing here was labeled by hand as a complete true or false set, so the tables are raw finding counts plus a few disagreements that were checked in the source.

## Method

Both tools saw the same checkout, including tests, examples, and docs:

- Flask 3.1.2, commit `2c1b30d0503cfb064f1cb252e6614a06915a362a` (83 Python files)
- requests 2.32.5, commit `b25c87d7cb8d6a18a37fa12442b5f883f9e41741` (36 Python files)

Vyarth was `vyarth scan <checkout> --min-confidence 90`. The counts below keep only `UNUSED_IMPORT` and `UNUSED_FUNCTION`. Vulture was `vulture <checkout> --min-confidence 80`. Vulture's lines are whatever it printed at that threshold, grouped by the words in the message. Vulture also reports unused variables and unreachable code. Those are omitted from Vyarth's columns so the two import and function numbers can be read side by side.

A subdirectory scan of only `src/flask` or `src/requests` makes public re-exports look unused, because the tests that call them are outside the scan. The numbers below are for the whole checkout.

## Counts

| Project | Vyarth unused imports | Vyarth unused functions | Vulture unused imports | Vulture unused functions |
| --- | --- | --- | --- | --- |
| Flask 3.1.2 | 27 | 45 | 0 | 0 |
| requests 2.32.5 | 28 | 27 | 3 | 0 |

At confidence 80, Vulture's other output was 31 unused variables in Flask and 8 unused variables in requests. It reported no unused functions in either checkout.

## Disagreements that were checked

`from datetime import datetime` in Flask's tutorial `examples/tutorial/flaskr/db.py` is used only inside `sqlite3.register_converter("timestamp", lambda v: datetime.fromisoformat(...))`. That load now counts, so the import is kept. A function or class named only as the callee of an uncalled lambda still does not count as reached.

`import socket` in `requests/adapters.py` is marked `# noqa: F401` and is not otherwise loaded. Vyarth reports it at confidence 100. Vulture does not. The comment says the import is intentionally unused.

`MockRequest.get_full_url` and the other methods next to it in `requests/cookies.py` copy the `urllib.request.Request` surface that `http.cookiejar` calls. Nothing in the requests checkout loads those names. Vyarth reports them as unused functions at 96. Vulture does not.

Vulture reports `quote_plus`, `unquote_plus`, and `urldefrag` in `requests/compat.py` as unused imports at 90. They are legacy names re-exported for old callers and are not loaded inside the checkout. Vyarth reports the same kind of unused import elsewhere in requests, including `socket` above. The two tools do not list the same import lines.

Public methods such as `Flask.send_static_file` are in Vyarth's unused-function count when the checkout never loads them. Vulture's run did not list those methods. That gap, not a labeled sample of every finding, is why this page does not state a false-positive rate.
