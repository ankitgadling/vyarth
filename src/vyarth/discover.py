"""File discovery, gitignore handling, and import-name resolution."""

from __future__ import annotations

from functools import lru_cache
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
    exclude_spec, gitignore = exclusion_specs(root, config)
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
    return list(_cached_module_names(str(path), tuple(str(root) for root in roots)))


@lru_cache(maxsize=8192)
def _cached_module_names(path_text: str, roots: tuple[str, ...]) -> tuple[str, ...]:
    resolved = Path(path_text).resolve()
    names: list[str] = []
    for root in roots:
        name = _module_name_under(resolved, Path(root))
        if name and name not in names:
            names.append(name)
    return tuple(names)


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


def path_excluded(
    relative: str,
    exclude_spec: pathspec.PathSpec,
    gitignore: pathspec.PathSpec | None,
) -> bool:
    return _excluded(exclude_spec, gitignore, relative)


def exclusion_specs(root: Path, config: Config) -> tuple[pathspec.PathSpec, pathspec.PathSpec | None]:
    """Exclude patterns and the gitignore stack for `root`."""
    root = root.resolve()
    return pathspec.GitIgnoreSpec.from_lines(config.excludes), load_gitignore(root)


def load_gitignore(root: Path) -> pathspec.PathSpec | None:
    """Root `.gitignore`, `.git/info/exclude`, and nested `.gitignore` files.

    A nested file applies only under its directory. A later rule wins, so a
    nested `!` pattern can un-ignore a file. A gitignore inside an already
    ignored directory is not read.
    """
    root = root.resolve()
    lines: list[str] = []
    exclude = root / ".git" / "info" / "exclude"
    if exclude.is_file():
        lines.extend(_read_ignore_lines(exclude))
    top = root / ".gitignore"
    if top.is_file():
        lines.extend(_read_ignore_lines(top))
    spec = pathspec.GitIgnoreSpec.from_lines(lines) if lines else None
    for dirpath, dirnames, _ in os.walk(root):
        directory = Path(dirpath)
        if directory.name == ".git":
            dirnames[:] = []
            continue
        relative = "" if directory == root else _relative(root, directory)
        if directory != root:
            gitignore = directory / ".gitignore"
            if gitignore.is_file() and relative and not _ignored(spec, relative):
                prefixed = _prefix_gitignore(relative, _read_ignore_lines(gitignore))
                if prefixed:
                    lines.extend(prefixed)
                    spec = pathspec.GitIgnoreSpec.from_lines(lines)
        kept: list[str] = []
        for name in dirnames:
            if name == ".git":
                continue
            child = f"{relative}/{name}" if relative else name
            if _ignored(spec, child):
                continue
            kept.append(name)
        dirnames[:] = kept
    return spec


def _ignored(spec: pathspec.PathSpec | None, relative: str) -> bool:
    if spec is None or not relative:
        return False
    return _matches(spec, relative)


def _read_ignore_lines(path: Path) -> list[str]:
    try:
        return path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        return []


def _prefix_gitignore(directory: str, lines: list[str]) -> list[str]:
    prefixed: list[str] = []
    for raw in lines:
        text = raw.strip()
        if not text or text.startswith("#"):
            continue
        negation = text.startswith("!")
        body = text[1:].lstrip() if negation else text
        anchored = body.startswith("/")
        pattern = body[1:] if anchored else body
        if not pattern:
            continue
        slashless = pattern.rstrip("/")
        if anchored or "/" in slashless:
            rewritten = f"{directory}/{pattern.lstrip('/')}"
        else:
            rewritten = f"{directory}/**/{pattern}"
        prefixed.append(f"!{rewritten}" if negation else rewritten)
    return prefixed
