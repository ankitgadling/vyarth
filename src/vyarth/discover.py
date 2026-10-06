"""File discovery, gitignore handling, and import-name resolution."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Protocol, TypeVar

import pathspec

from vyarth.config import TEST_PATTERNS, Config


def project_root(start: Path) -> Path:
    """Nearest directory at or above `start` that holds the project file or a git checkout."""
    current = start.resolve()
    for parent in (current, *current.parents):
        if (parent / "pyproject.toml").is_file() or (parent / "vyarth.toml").is_file() or (parent / ".git").exists():
            return parent
    return current


def discover_files(root: Path, config: Config, *, within: Path | None = None) -> list[Path]:
    """Return Python files under `within` or `root`, skipping excludes and `.gitignore`.

    Excludes and `.gitignore` are matched on paths relative to `root`. `within` limits
    the walk when the caller asked to scan a subdirectory of the project.
    """
    root = root.resolve()
    start = root if within is None else within.resolve()
    exclude_spec = pathspec.GitIgnoreSpec.from_lines(config.excludes)
    gitignore = _load_gitignore(root)
    found: list[Path] = []
    for dirpath, dirnames, filenames in os_walk(start):
        directory = Path(dirpath)
        kept: list[str] = []
        for name in dirnames:
            rel = _relative(root, directory / name)
            if _excluded(exclude_spec, gitignore, rel):
                continue
            kept.append(name)
        dirnames[:] = kept
        for name in filenames:
            if not name.endswith(".py"):
                continue
            path = directory / name
            rel = _relative(root, path)
            if _excluded(exclude_spec, gitignore, rel):
                continue
            found.append(path)
    found.sort(key=lambda path: _relative(root, path))
    return found


def package_roots(root: Path) -> list[Path]:
    """Scan root, plus `src/` when that directory exists. Longest path wins."""
    root = root.resolve()
    roots = [root]
    src = root / "src"
    if src.is_dir():
        roots.append(src)
    roots.sort(key=lambda path: len(path.as_posix()), reverse=True)
    return roots


def module_name(path: Path, roots: list[Path]) -> str | None:
    """Dotted module name for a project file, or None when the path is not importable.

    The longest package root wins. A file under ``src/`` is ``app.mod`` when that
    directory is a root, which is the name a src-layout install imports.
    """
    names = module_names(path, roots)
    return names[0] if names else None


def module_names(path: Path, roots: list[Path]) -> list[str]:
    """Every dotted name for this file. The longest package root stays first.

    ``src/account/cache.py`` is both ``account.cache`` and ``src.account.cache``
    when the project root and ``src/`` are both roots. Call sites that import
    through the ``src.`` prefix resolve to the same file.
    """
    resolved = path.resolve()
    names: list[str] = []
    for root in roots:
        name = _module_name_under(resolved, root)
        if name and name not in names:
            names.append(name)
    return names


class _HasPath(Protocol):
    @property
    def path(self) -> str: ...


_Index = TypeVar("_Index", bound=_HasPath)


def indexes_by_module(indexes: list[_Index], roots: list[Path]) -> dict[str, _Index]:
    """Map every module name, including ``src.`` aliases, to the file that defines it.

    When two files claim the same dotted name, the longer package root wins.
    ``src/pkg/mod.py`` keeps ``pkg.mod`` over a root-level ``pkg/mod.py``.
    """
    found: dict[str, _Index] = {}
    rank: dict[str, int] = {}
    for index in indexes:
        path = Path(index.path)
        for name in module_names(path, roots):
            score = _name_root_length(path, roots, name)
            if name not in found or score > rank[name]:
                found[name] = index
                rank[name] = score
    return found


def _name_root_length(path: Path, roots: list[Path], name: str) -> int:
    best = -1
    resolved = path.resolve()
    for root in roots:
        produced = _module_name_under(resolved, root)
        if produced == name:
            best = max(best, len(root.resolve().as_posix()))
    return best


def _module_name_under(resolved: Path, root: Path) -> str | None:
    try:
        relative = resolved.relative_to(root.resolve())
    except ValueError:
        return None
    parts = list(relative.parts)
    if not parts:
        return None
    if parts[-1] == "__init__.py":
        parts = parts[:-1]
    elif parts[-1].endswith(".py"):
        parts[-1] = parts[-1][:-3]
    else:
        return None
    if not parts or any(not part.isidentifier() for part in parts):
        return None
    return ".".join(parts)


def package_parts(path: Path, roots: list[Path]) -> list[str] | None:
    """Package that contains `path`. `__init__.py` is the package itself."""
    name = module_name(path, roots)
    if name is None:
        return None
    parts = name.split(".")
    if path.name != "__init__.py":
        parts = parts[:-1]
    return parts


def modules_used_by(edge_module: str | None, edge_level: int, edge_imported: str | None, importer: Path, roots: list[Path]) -> set[str]:
    """Project module names an import edge can load, including parent packages."""
    target = _target_module(edge_module, edge_level, importer, roots)
    if target is None:
        return set()
    names: set[str] = set()
    if target:
        segments = target.split(".")
        for index in range(1, len(segments) + 1):
            names.add(".".join(segments[:index]))
    if edge_imported and edge_imported != "*":
        child = f"{target}.{edge_imported}" if target else edge_imported
        names.add(child)
    return names


_TEST_SPEC = pathspec.GitIgnoreSpec.from_lines(TEST_PATTERNS)


def is_test_path(relative: str) -> bool:
    """Test modules are indexed, but findings inside them are suppressed."""
    return _TEST_SPEC.match_file(relative)


def import_target(module: str | None, level: int, importer: Path, roots: list[Path]) -> str | None:
    """Module a `from` import loads names from. `import pkg` has no symbol target."""
    return _target_module(module, level, importer, roots)


def relative_posix(path: Path, root: Path) -> str:
    return _relative(root.resolve(), path.resolve())


def os_walk(root: Path):
    return os.walk(root)


def _target_module(module: str | None, level: int, importer: Path, roots: list[Path]) -> str | None:
    if level <= 0:
        return module or ""
    base = package_parts(importer, roots)
    if base is None:
        return None
    drop = level - 1
    if drop > len(base):
        return None
    parts = list(base[: len(base) - drop] if drop else base)
    if module:
        parts.extend(part for part in module.split(".") if part)
    return ".".join(parts)


def _relative(root: Path, path: Path) -> str:
    try:
        relative = path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.name
    return "" if relative == "." else relative


def _excluded(exclude_spec: pathspec.PathSpec, gitignore: pathspec.PathSpec | None, relative: str) -> bool:
    if not relative:
        return False
    if _matches(exclude_spec, relative):
        return True
    if gitignore is not None and _matches(gitignore, relative):
        return True
    return False


def _matches(spec: pathspec.PathSpec, relative: str) -> bool:
    if spec.match_file(relative):
        return True
    return spec.match_file(relative.rstrip("/") + "/")


def _load_gitignore(root: Path) -> pathspec.PathSpec | None:
    path = root / ".gitignore"
    if not path.is_file():
        return None
    lines = path.read_text(encoding="utf-8").splitlines()
    return pathspec.GitIgnoreSpec.from_lines(lines)
