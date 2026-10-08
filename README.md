# Vyarth

Vyarth (व्यर्थ, “in vain”) finds Python code that nothing uses: unused imports, functions, classes, and variables, unreachable statements, modules no entry point can import, functions that are referenced but never reached, declared dependencies the code never imports, and duplicate function bodies.

It is a library and a command-line tool. The indexer sits behind a small backend interface, so a faster implementation can replace it later without rewriting the rules.

Requires Python 3.11 or newer. The license is MIT. The user guide is in [docs/index.md](docs/index.md). Release notes are in [CHANGELOG.md](CHANGELOG.md).

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

Findings go to standard output. Progress is written to standard error. The process exits 1 when findings remain, and 2 when the path, config, baseline, or git state is unusable. A syntax error in one file is reported and the rest of the scan continues.

```text
UNUSED_VARIABLE
File: service.py
Line: 3
Variable: debug_value
Confidence: 100%
```

```python
from vyarth import scan

result = scan("src")
for finding in result.findings:
    print(finding.rule, finding.path, finding.line, finding.symbol)
```

## Where to read next

| Topic | Page |
| --- | --- |
| Commands, flags, and exit codes | [Command line](docs/command-line.md) |
| `pyproject.toml` and `vyarth.toml` | [Configuration](docs/configuration.md) |
| Each rule, its score, and what a load means | [Rules](docs/rules.md) |
| `scan`, `Finding`, and `ScanResult` | [Python API](docs/python-api.md) |
| Baselines, SARIF, and GitHub Actions | [Continuous integration](docs/continuous-integration.md) |
| Automatic rewrites and the language server | [Fix and editor](docs/fix-and-editor.md) |
| Entries, reachability, and known limits | [How analysis works](docs/how-analysis-works.md) |
| Counts against other scanners | [Comparison](docs/comparison.md) |
