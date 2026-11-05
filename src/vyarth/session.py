"""Scan cache shared by the language server and the MCP server."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from vyarth.config import load_config
from vyarth.discover import discover_files, relative_posix
from vyarth.engine import scan
from vyarth.model import ScanResult


_cache: dict[tuple[object, ...], ScanResult] = {}
_file_lists: dict[Path, list[Path]] = {}


def cached_scan(root: Path, overlays: tuple[tuple[str, str], ...] = (), **kwargs: Any) -> ScanResult:
    """Return a scan for this root, reusing it while the file stamps and overlays match."""
    stamp = file_stamp(root)
    key = (str(root.resolve()), overlays, stamp, json.dumps(_jsonable(kwargs), sort_keys=True))
    result = _cache.get(key)
    if result is None:
        result = scan(root, overlays=dict(overlays) or None, **kwargs)
        _cache[key] = result
        if len(_cache) > 8:
            _cache.pop(next(iter(_cache)))
    return result


def file_stamp(root: Path, *, refresh: bool = False) -> tuple[tuple[str, int, int], ...]:
    """Size and mtime of every indexed file, the config files, and the baseline.

    The file list is discovered on every call so new files, config edits and
    baseline changes invalidate the cache. `refresh` is kept for callers that
    want to force discovery; discovery now always runs.
    """
    config = load_config(root)
    files = discover_files(root, config)
    _file_lists[root] = files
    extra = [root / "pyproject.toml", root / "vyarth.toml"]
    if config.baseline:
        extra.append(root / config.baseline)
    else:
        extra.append(root / "vyarth-baseline.json")
    stamps: list[tuple[str, int, int]] = []
    for file in [*files, *extra]:
        try:
            stat = file.stat()
        except OSError:
            continue
        stamps.append((relative_posix(file, root), stat.st_size, stat.st_mtime_ns))
    return tuple(stamps)


def drop_root(root: Path) -> None:
    """Forget a root after a buffer closes, so the next scan reads the files again."""
    _file_lists.pop(root, None)
    stale = [key for key in _cache if key and key[0] == str(root.resolve())]
    for key in stale:
        _cache.pop(key, None)


def _jsonable(value: object) -> object:
    if isinstance(value, tuple):
        return [_jsonable(item) for item in value]
    if isinstance(value, list):
        return [_jsonable(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    return value
