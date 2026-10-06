"""Declared packages that the indexed source never imports."""

from __future__ import annotations

import ast
import os
from pathlib import Path
import re
import tomllib

from vyarth.model import FileIndex, Finding, ParseError, make_fingerprint


_NAME = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)")
_MESSAGE = "No Python imports found."
_CANONICAL = {
    "pil": "pillow",
    "pillow": "pillow",
    "yaml": "pyyaml",
    "pyyaml": "pyyaml",
    "sklearn": "scikit-learn",
    "scikit-learn": "scikit-learn",
    "cv2": "opencv-python",
    "opencv-python": "opencv-python",
    "opencv-python-headless": "opencv-python",
    "bs4": "beautifulsoup4",
    "beautifulsoup4": "beautifulsoup4",
}
_MANIFESTS = {"requirements.txt", "requirements-dev.txt", "pyproject.toml", "Pipfile", "setup.py"}
_SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".vyarth",
    ".venv",
    "venv",
    "__pycache__",
    "build",
    "dist",
    "site-packages",
    "node_modules",
}
_IMPORT_ALIAS = {
    "psycopg2-binary": "psycopg2",
    "pyjwt": "jwt",
    "python-dotenv": "dotenv",
    "python-jose": "jose",
}


def dependency_findings(indexes: list[FileIndex], root: Path) -> tuple[list[Finding], list[ParseError]]:
    imported = {_canonical(_top_level(name)) for name in _import_roots(indexes)}
    declared: dict[str, tuple[str, int]] = {}
    errors: list[ParseError] = []
    for manifest, packages, error in _declared(root):
        if error is not None:
            errors.append(error)
        relpath = manifest.relative_to(root).as_posix()
        for name, line in packages:
            key = _canonical(name)
            if not key or key == "python":
                continue
            declared.setdefault(key, (relpath, line))
    findings: list[Finding] = []
    for name in sorted(declared):
        if name in imported:
            continue
        relpath, line = declared[name]
        alias = _IMPORT_ALIAS.get(name)
        if alias is not None and alias in imported:
            confidence = 70
            evidence = (f"Imported as {alias}, so the package name cannot be proved unused.",)
        else:
            confidence = 95
            evidence = (f"Declared in {relpath} and never imported.",)
        findings.append(
            Finding(
                rule="UNUSED_DEPENDENCY",
                path=relpath,
                line=line,
                column=1,
                symbol=name,
                status="POSSIBLY_DEAD",
                confidence=confidence,
                message=_MESSAGE,
                evidence=evidence,
                fingerprint=make_fingerprint("UNUSED_DEPENDENCY", relpath, name),
            )
        )
    return findings, errors


def _import_roots(indexes: list[FileIndex]) -> set[str]:
    roots: set[str] = set()
    for index in indexes:
        for edge in index.imports:
            if edge.level:
                continue
            module = edge.module or ""
            top = module.split(".", 1)[0]
            if top:
                roots.add(top)
        roots.update(name for name in index.dynamic_imports if name)
    return roots


def _top_level(name: str) -> str:
    return name.split(".", 1)[0]


def _canonical(name: str) -> str:
    normalized = name.strip().lower().replace("_", "-")
    return _CANONICAL.get(normalized, normalized)


def _declared(root: Path) -> list[tuple[Path, list[tuple[str, int]], ParseError | None]]:
    found: list[tuple[Path, list[tuple[str, int]], ParseError | None]] = []
    root = root.resolve()
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [name for name in dirnames if name not in _SKIP_DIRS and not name.endswith(".egg-info")]
        for name in sorted(filenames):
            if name not in _MANIFESTS:
                continue
            path = Path(dirpath) / name
            packages, error = _read_manifest(path, root)
            found.append((path, packages, error))
    return found


def _read_manifest(path: Path, root: Path) -> tuple[list[tuple[str, int]], ParseError | None]:
    try:
        if path.name in {"requirements.txt", "requirements-dev.txt"}:
            return _requirements(path), None
        if path.name == "pyproject.toml":
            return _pyproject(path), None
        if path.name == "Pipfile":
            return _pipfile(path), None
        if path.name == "setup.py":
            return _setup(path), None
    except (tomllib.TOMLDecodeError, UnicodeDecodeError, OSError, ValueError) as exc:
        relative = path.resolve().relative_to(root).as_posix()
        return [], ParseError(path=relative, line=1, column=1, message=str(exc))
    return [], None


def _requirements(path: Path) -> list[tuple[str, int]]:
    packages: list[tuple[str, int]] = []
    for line_number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        text = raw.split("#", 1)[0].strip()
        if not text or text.startswith(("-r", "-c", "-e", "--", "git+", "http://", "https://")):
            continue
        match = _NAME.match(text)
        if match:
            packages.append((match.group(1), line_number))
    return packages


def _pyproject(path: Path) -> list[tuple[str, int]]:
    with path.open("rb") as handle:
        data = tomllib.load(handle)
    lines = path.read_text(encoding="utf-8").splitlines()
    packages: list[tuple[str, int]] = []
    project = data.get("project", {})
    if isinstance(project, dict):
        packages.extend(_requirement_list(project.get("dependencies"), lines))
        optional = project.get("optional-dependencies", {})
        if isinstance(optional, dict):
            for group in optional.values():
                packages.extend(_requirement_list(group, lines))
    poetry = data.get("tool", {})
    if isinstance(poetry, dict):
        poetry_table = poetry.get("poetry", {})
        if isinstance(poetry_table, dict):
            packages.extend(_toml_keys(poetry_table.get("dependencies"), lines))
            groups = poetry_table.get("group", {})
            if isinstance(groups, dict):
                for group in groups.values():
                    if isinstance(group, dict):
                        packages.extend(_toml_keys(group.get("dependencies"), lines))
        uv_table = poetry.get("uv", {})
        if isinstance(uv_table, dict):
            packages.extend(_requirement_list(uv_table.get("dev-dependencies"), lines))
    groups = data.get("dependency-groups", {})
    if isinstance(groups, dict):
        for group in groups.values():
            packages.extend(_requirement_list(group, lines))
    return packages


def _pipfile(path: Path) -> list[tuple[str, int]]:
    with path.open("rb") as handle:
        data = tomllib.load(handle)
    lines = path.read_text(encoding="utf-8").splitlines()
    packages: list[tuple[str, int]] = []
    for key in ("packages", "dev-packages"):
        packages.extend(_toml_keys(data.get(key), lines))
    return packages


def _setup(path: Path) -> list[tuple[str, int]]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except SyntaxError:
        return []
    packages: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "install_requires":
                    packages.extend(_string_list(node.value))
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            if node.target.id == "install_requires" and node.value is not None:
                packages.extend(_string_list(node.value))
        elif isinstance(node, ast.Call):
            for keyword in node.keywords:
                if keyword.arg == "install_requires":
                    packages.extend(_string_list(keyword.value))
    return packages


def _requirement_list(value: object, lines: list[str]) -> list[tuple[str, int]]:
    if not isinstance(value, list):
        return []
    packages: list[tuple[str, int]] = []
    for item in value:
        if not isinstance(item, str):
            continue
        match = _NAME.match(item.strip())
        if match:
            packages.append((match.group(1), _line_of(lines, match.group(1))))
    return packages


def _toml_keys(value: object, lines: list[str]) -> list[tuple[str, int]]:
    if not isinstance(value, dict):
        return []
    return [(str(key), _line_of(lines, str(key))) for key in value]


def _string_list(node: ast.expr) -> list[tuple[str, int]]:
    if not isinstance(node, ast.List | ast.Tuple):
        return []
    packages: list[tuple[str, int]] = []
    for element in node.elts:
        if isinstance(element, ast.Constant) and isinstance(element.value, str):
            match = _NAME.match(element.value.strip())
            if match:
                packages.append((match.group(1), element.lineno or 1))
    return packages


def _line_of(lines: list[str], name: str) -> int:
    pattern = re.compile(rf"(?<![A-Za-z0-9._-]){re.escape(name)}(?![A-Za-z0-9._-])", re.IGNORECASE)
    for number, line in enumerate(lines, start=1):
        code = line.split("#", 1)[0]
        if pattern.search(code):
            return number
    return 1
