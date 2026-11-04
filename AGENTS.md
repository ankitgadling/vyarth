# Agents working on vyarth

Vyarth is a scope-aware unused-Python detector. This file is for agents changing the tool. Agents using vyarth on another project should read [docs/agents.md](docs/agents.md).

## Setup

```bash
pip install -e ".[dev]"
```

Python 3.11 or newer. The only runtime dependency is `pathspec`.

## Checks

```bash
ruff check src tests
mypy
pytest
```

Those are the commands in `.github/workflows/ci.yml`.

## Module map

`cli` parses arguments and calls `engine.scan`. `engine` indexes files, then `rules`, `confidence`, and `entries` decide what is unused. `report` and `fix` render and rewrite findings. `lsp` and `mcp` serve the same scan through `session`. `verify` checks a fix and restores the original bytes when the check fails.

## False positives

Every false-positive fix ships with a repro in `tests/test_false_positives.py`. Do not hide a name by lowering a score in one project without that fixture.
