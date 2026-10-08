"""Declared packages that the indexed source never imports."""

from __future__ import annotations

import ast
import os
from pathlib import Path
import re
import tomllib

from vyarth.config import Config
from vyarth.discover import exclusion_specs, path_excluded, relative_posix
from vyarth.model import FileIndex, Finding, ParseError, make_fingerprint


_NAME = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)")
_PEP503 = re.compile(r"[-_.]+")
_MESSAGE = "No Python imports found."
_DEV_EVIDENCE = "Declared in {path} as a development or docs dependency and never imported."
_NAMESPACE_NOTE = "A top-level import uses this package's namespace, so the dependency cannot be proved unused."
_RUNTIME_NOTE = "This package is often started without an import."
_RUNTIME_ONLY = frozenset(
    {
        "gunicorn",
        "uvicorn",
        "hypercorn",
        "daphne",
        "waitress",
        "gevent",
        "eventlet",
        "psycopg",
        "psycopg2",
        "psycopg2-binary",
        "mysqlclient",
        "pymysql",
        "asyncpg",
        "redis",
        "hiredis",
        "whitenoise",
    }
)
_DEV_EXTRAS = {"dev", "test", "tests", "docs", "doc", "lint"}
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
    "openssl": "pyopenssl",
    "pyopenssl": "pyopenssl",
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


def dependency_findings(
    indexes: list[FileIndex],
    root: Path,
    within: Path | None = None,
    config: Config | None = None,
) -> tuple[list[Finding], list[ParseError]]:
    if config is None:
        config = Config()
    modules = _import_modules(indexes)
    imported = {_canonical(_top_level(name)) for name in modules}
    distributions = _used_distributions(modules)
    declared: dict[str, tuple[str, int, bool]] = {}
    errors: list[ParseError] = []
    for manifest, packages, error in _declared(root, config):
        if not _manifest_in_scan(manifest, root, within):
            continue
        if error is not None:
            errors.append(error)
        relpath = manifest.relative_to(root).as_posix()
        for name, line, dev in packages:
            key = _canonical(name)
            if not key or key == "python":
                continue
            current = declared.get(key)
            if current is None or (current[2] and not dev):
                declared[key] = (relpath, line, dev)
    findings: list[Finding] = []
    for name in sorted(declared):
        if name in imported or name in distributions or _import_match(name, modules) == "used":
            continue
        relpath, line, dev = declared[name]
        alias = _IMPORT_ALIAS.get(name)
        if alias is not None and _canonical(alias) in imported:
            confidence = 70
            evidence = (f"Imported as {alias}, so the package name cannot be proved unused.",)
        elif _import_match(name, modules) == "namespace":
            confidence = 70
            evidence = (_NAMESPACE_NOTE,)
        elif dev:
            if not config.report_dev_dependencies:
                continue
            confidence = 70
            evidence = (_DEV_EVIDENCE.format(path=relpath),)
        elif name in _RUNTIME_ONLY:
            confidence = 70
            evidence = (_RUNTIME_NOTE,)
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


def _manifest_in_scan(path: Path, root: Path, within: Path | None) -> bool:
    """Keep manifests inside the scanned directory, plus files that sit in the project root.

    A `vyarth scan src` still sees the root `pyproject.toml`. It does not see
    `examples/requirements.txt`.
    """
    resolved = path.resolve()
    if within is None or resolved.is_relative_to(within.resolve()):
        return True
    return resolved.parent == root.resolve()


def _import_modules(indexes: list[FileIndex]) -> set[str]:
    modules: set[str] = set()
    for index in indexes:
        for edge in index.imports:
            if edge.level:
                continue
            module = edge.module or ""
            if module:
                modules.add(module)
        modules.update(name for name in index.dynamic_imports if name)
    return modules


_DISTRIBUTIONS: dict[str, list[str]] | None = None


def _used_distributions(modules: set[str]) -> set[str]:
    mapping = _distribution_map()
    found: set[str] = set()
    for module in modules:
        for dist in mapping.get(_top_level(module), ()):
            found.add(_canonical(str(dist)))
    return found


def _distribution_map() -> dict[str, list[str]]:
    global _DISTRIBUTIONS
    if _DISTRIBUTIONS is not None:
        return _DISTRIBUTIONS
    try:
        from importlib.metadata import packages_distributions

        loaded = packages_distributions()
    except Exception:
        loaded = {}
    _DISTRIBUTIONS = {str(key): [str(item) for item in value] for key, value in loaded.items()}
    return _DISTRIBUTIONS


def _import_match(name: str, modules: set[str]) -> str:
    """`used` when an import names the package, `namespace` for a top-level overlap."""
    dotted = name.replace("-", ".")
    namespace = False
    for module in modules:
        if not module:
            continue
        if module == dotted or module.startswith(f"{dotted}."):
            return "used"
        if dotted.startswith(f"{module}."):
            if "." in module:
                return "used"
            namespace = True
    return "namespace" if namespace else ""


def _top_level(name: str) -> str:
    return name.split(".", 1)[0]


def _canonical(name: str) -> str:
    normalized = _PEP503.sub("-", name.strip().lower())
    return _CANONICAL.get(normalized, normalized)


def _declared(
    root: Path,
    config: Config,
) -> list[tuple[Path, list[tuple[str, int, bool]], ParseError | None]]:
    found: list[tuple[Path, list[tuple[str, int, bool]], ParseError | None]] = []
    root = root.resolve()
    exclude_spec, gitignore = exclusion_specs(root, config)
    for dirpath, dirnames, filenames in os.walk(root):
        directory = Path(dirpath)
        kept: list[str] = []
        for name in dirnames:
            if name in _SKIP_DIRS or name.endswith(".egg-info"):
                continue
            relative = relative_posix(directory / name, root)
            if path_excluded(relative, exclude_spec, gitignore):
                continue
            kept.append(name)
        dirnames[:] = kept
        for name in sorted(filenames):
            if name not in _MANIFESTS:
                continue
            path = directory / name
            relative = relative_posix(path, root)
            if path_excluded(relative, exclude_spec, gitignore):
                continue
            packages, error = _read_manifest(path, root)
            found.append((path, packages, error))
    return found


def _read_manifest(path: Path, root: Path) -> tuple[list[tuple[str, int, bool]], ParseError | None]:
    try:
        if path.name == "requirements.txt":
            return _tag(_requirements(path), _docs_requirements(path, root)), None
        if path.name == "requirements-dev.txt":
            return _tag(_requirements(path), True), None
        if path.name == "pyproject.toml":
            return _pyproject(path), None
        if path.name == "Pipfile":
            return _pipfile(path), None
        if path.name == "setup.py":
            return _tag(_setup(path), False), None
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


def _docs_requirements(path: Path, root: Path) -> bool:
    relative = path.resolve().relative_to(root.resolve())
    return relative.name == "requirements.txt" and "docs" in relative.parts


def _dev_extra(name: str) -> bool:
    """True for optional-dependency groups that install tools, not runtime packages."""
    normalized = str(name).strip().lower().replace("_", "-")
    return normalized in _DEV_EXTRAS or normalized.endswith("-dev")


def _tag(packages: list[tuple[str, int]], dev: bool) -> list[tuple[str, int, bool]]:
    return [(name, line, dev) for name, line in packages]


def _pyproject(path: Path) -> list[tuple[str, int, bool]]:
    with path.open("rb") as handle:
        data = tomllib.load(handle)
    lines = path.read_text(encoding="utf-8").splitlines()
    packages: list[tuple[str, int, bool]] = []
    project = data.get("project", {})
    if isinstance(project, dict):
        packages.extend(_tag(_requirement_list(project.get("dependencies"), lines), False))
        optional = project.get("optional-dependencies", {})
        if isinstance(optional, dict):
            for group_name, group in optional.items():
                packages.extend(_tag(_requirement_list(group, lines), _dev_extra(group_name)))
    poetry = data.get("tool", {})
    if isinstance(poetry, dict):
        poetry_table = poetry.get("poetry", {})
        if isinstance(poetry_table, dict):
            packages.extend(_tag(_toml_keys(poetry_table.get("dependencies"), lines), False))
            groups = poetry_table.get("group", {})
            if isinstance(groups, dict):
                for group in groups.values():
                    if isinstance(group, dict):
                        packages.extend(_tag(_toml_keys(group.get("dependencies"), lines), True))
        uv_table = poetry.get("uv", {})
        if isinstance(uv_table, dict):
            packages.extend(_tag(_requirement_list(uv_table.get("dev-dependencies"), lines), True))
    groups = data.get("dependency-groups", {})
    if isinstance(groups, dict):
        for group in groups.values():
            packages.extend(_tag(_requirement_list(group, lines), True))
    return packages


def _pipfile(path: Path) -> list[tuple[str, int, bool]]:
    with path.open("rb") as handle:
        data = tomllib.load(handle)
    lines = path.read_text(encoding="utf-8").splitlines()
    packages: list[tuple[str, int, bool]] = []
    packages.extend(_tag(_toml_keys(data.get("packages"), lines), False))
    packages.extend(_tag(_toml_keys(data.get("dev-packages"), lines), True))
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
