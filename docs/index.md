# Vyarth

Vyarth (व्यर्थ, “in vain”) finds Python code that nothing uses. It reports unused imports, functions, classes, and variables, unreachable statements, modules no entry point can import, functions that are referenced but never reached from an entry, declared dependencies the code never imports, and duplicate function bodies.

It is a library and a command-line tool. The indexer sits behind a small backend interface, so a faster implementation can replace it later without rewriting the rules.

Vyarth requires Python 3.11 or newer. The license is MIT. Release notes are in [CHANGELOG.md](../CHANGELOG.md).

## Install

Vyarth is not published on PyPI yet. From a checkout of this repository:

```bash
pip install .
```

To work on Vyarth itself:

```bash
pip install -e ".[dev]"
pytest
```

## Scan a project

```bash
vyarth scan .
```

Findings go to standard output. While the scan runs, the current step and elapsed time are written to standard error and refreshed about once a second. In a terminal that status stays on one line:

```text
vyarth: checking methods 412/2841 django/db/models/base.py  3m 08s
```

When the scan finishes, the status line becomes `vyarth: scanned 2841 files in 4m 12s`.

A text finding looks like this:

```text
UNUSED_VARIABLE
File: service.py
Line: 3
Variable: debug_value
Confidence: 100%
```

The process exits with code 1 when findings remain. A missing path, a bad config file, a missing baseline, or a git error exits 2. A syntax error in one file is reported on standard error and the rest of the scan continues.

## Use it from Python

```python
from vyarth import scan

result = scan("src")
for finding in result.findings:
    print(finding.rule, finding.path, finding.line, finding.symbol)
print(result.to_json())
```

## Where to read next

| Topic | Page |
| --- | --- |
| Commands, flags, and exit codes | [Command line](command-line.md) |
| `pyproject.toml` and `vyarth.toml` | [Configuration](configuration.md) |
| Each rule, its score, and what a load means | [Rules](rules.md) |
| `scan`, `Finding`, and `ScanResult` | [Python API](python-api.md) |
| Baselines, SARIF, and GitHub Actions | [Continuous integration](continuous-integration.md) |
| Automatic rewrites and the language server | [Fix and editor](fix-and-editor.md) |
| Entries, reachability, and known limits | [How analysis works](how-analysis-works.md) |
| Counts against Vulture, deadcode, and dead | [Comparison](comparison.md) |
