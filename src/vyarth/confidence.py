"""Evidence checklist and dynamic-call downgrades. Applied after rules, before ignores."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import re

from vyarth.discover import import_target, indexes_by_module, package_roots, relative_posix
from vyarth.model import PUBLIC_NAME_NOTE, FileIndex, Finding, ImportEdge


_NEUTRAL_DECORATORS = {
    "property",
    "cached_property",
    "staticmethod",
    "classmethod",
    "setter",
    "deleter",
    "abstractmethod",
    "abstractproperty",
    "abstractclassmethod",
    "abstractstaticmethod",
}
_CHECKLIST = (
    "No references found.",
    "No decorators.",
    "Not exported.",
    "Not an entry point.",
    "No dynamic references detected.",
)
_DYNAMIC_MESSAGE = "Dynamic usage detected. Static analysis cannot prove this symbol is unused."
_DECORATED_NOTE = "Decorated, but not a recognized framework entry."
_LAMBDA_NOTE = "Only referenced from a lambda this scan did not prove is called."
_MODULE_CAP_NOTE = "This file has no incoming imports, so this score follows the module."
_ALEMBIC_NOTE = "Alembic loads this name when the migration runs."
_PROBE_NOTE = "This import sits in a try that catches ImportError, so it may be an availability check."
_REEXPORT_NOTE = "Possible public re-export."
_SIDE_EFFECT_NOTE = "Import may run the submodule for its side effects."
REEXPORT_NOTE = _REEXPORT_NOTE
SIDE_EFFECT_NOTE = _SIDE_EFFECT_NOTE
PROBE_NOTE = _PROBE_NOTE
_CAPPED_RULES = {
    "UNUSED_FUNCTION",
    "UNUSED_CLASS",
    "UNUSED_VARIABLE",
    "UNUSED_IMPORT",
    "ORPHAN_FUNCTION",
    "DUPLICATE_CODE",
}
_ALEMBIC_NAMES = {"upgrade", "downgrade", "revision", "down_revision", "branch_labels", "depends_on"}
_FRAMEWORK_CONVENTION_NOTE = "Framework convention. This name is loaded by the framework without a local reference."
_URL_SYMBOLS = frozenset({"urlpatterns", "handler400", "handler403", "handler404", "handler500"})
BOOT_FILE_NAMES = frozenset({"manage.py", "wsgi.py", "asgi.py"})
DJANGO_SETTINGS_ASSIGNMENT = re.compile(
    r"""DJANGO_SETTINGS_MODULE["'](?:\s*\]\s*=\s*["']|\s*,\s*["'])([A-Za-z_][\w.]*)"""
)
_META_FILE_NAMES = frozenset({"models.py", "admin.py", "forms.py", "serializers.py"})
_META_DIR_NAMES = frozenset({"models", "admin", "forms", "serializers"})


def apply_confidence(findings: list[Finding], indexes: list[FileIndex], root: Path) -> list[Finding]:
    by_path = {relative_posix(Path(index.path), root): index for index in indexes}
    project_imports_dynamically = any(_import_dynamic(index) for index in indexes)
    adjusted: list[Finding] = []
    for finding in findings:
        index = by_path.get(finding.path)
        adjusted.append(_adjust(finding, index, project_imports_dynamically))
    module_caps = {
        finding.path: finding.confidence
        for finding in adjusted
        if finding.rule == "POSSIBLY_UNUSED_MODULE"
    }
    settings_paths = _django_settings_modules(indexes)
    roots = package_roots(root)
    by_module = indexes_by_module(indexes, roots)
    capped: list[Finding] = []
    for finding in adjusted:
        finding = _alembic(finding)
        cap = module_caps.get(finding.path)
        if cap is not None and finding.rule in _CAPPED_RULES and finding.confidence > cap:
            finding = replace(
                finding,
                confidence=cap,
                status=_lowered_status(finding.status),
                evidence=_with_note(finding.evidence, _MODULE_CAP_NOTE),
            )
        finding = _framework_convention(
            finding,
            by_path.get(finding.path),
            settings_paths,
            by_module,
            roots,
        )
        capped.append(finding)
    return capped


def _adjust(finding: Finding, index: FileIndex | None, project_imports_dynamically: bool) -> Finding:
    if finding.rule in {"UNREACHABLE_CODE", "WILDCARD_IMPORT", "ORPHAN_FUNCTION", "UNUSED_DEPENDENCY", "DUPLICATE_CODE"}:
        return finding
    qualname = _qualname(finding)
    if finding.rule == "POSSIBLY_UNUSED_MODULE":
        if project_imports_dynamically:
            return replace(finding, confidence=60, status="POSSIBLY_UNUSED_MODULE")
        return finding
    if finding.rule == "UNUSED_IMPORT":
        if index is not None and finding.symbol in index.import_probes:
            return replace(
                finding,
                confidence=70,
                status="POSSIBLY_DEAD",
                evidence=_with_note(finding.evidence, _PROBE_NOTE),
            )
        if index is not None and _import_dynamic(index):
            return replace(finding, confidence=70, status="POSSIBLY_DEAD")
        if index is not None and _side_effect_import(index, finding):
            return replace(
                finding,
                confidence=70,
                status="POSSIBLY_DEAD",
                evidence=_with_note(finding.evidence, _SIDE_EFFECT_NOTE),
            )
        if _package_init(finding.path):
            return replace(
                finding,
                confidence=70,
                status="POSSIBLY_DEAD",
                evidence=_with_note(finding.evidence, _REEXPORT_NOTE),
            )
        return finding
    if _symbol_dynamic(finding, index):
        return replace(
            finding,
            status="POSSIBLY_DEAD",
            confidence=min(finding.confidence, 70),
            message=_DYNAMIC_MESSAGE,
            evidence=(_DYNAMIC_MESSAGE,),
        )
    if finding.rule == "UNUSED_VARIABLE":
        return finding
    if finding.rule not in {"UNUSED_FUNCTION", "UNUSED_CLASS"}:
        return finding
    if index is not None and qualname in index.lambda_mentions:
        return replace(
            finding,
            status="POSSIBLY_DEAD",
            confidence=60,
            evidence=_with_note(finding.evidence, _LAMBDA_NOTE),
        )
    decorated = index is not None and _unrecognized_decorator(index, qualname)
    if decorated:
        evidence = (
            "No references found.",
            _DECORATED_NOTE,
            "Not exported.",
            "Not an entry point.",
            "No dynamic references detected.",
        )
        return replace(finding, status="POSSIBLY_DEAD", confidence=min(finding.confidence, 75), evidence=evidence)
    if "." in qualname:
        return finding
    # Rules already scored a public name that outside code may load at 60.
    checklist = _with_note(_CHECKLIST, PUBLIC_NAME_NOTE) if PUBLIC_NAME_NOTE in finding.evidence else _CHECKLIST
    return replace(
        finding,
        status="POSSIBLY_DEAD",
        confidence=min(finding.confidence, 96),
        evidence=checklist,
    )


def _unrecognized_decorator(index: FileIndex, qualname: str) -> bool:
    names = [item.name for item in index.decorators if item.qualname == qualname]
    if not names:
        return False
    return any(name.rsplit(".", 1)[-1] not in _NEUTRAL_DECORATORS for name in names)


def _symbol_dynamic(finding: Finding, index: FileIndex | None) -> bool:
    if index is None:
        return False
    names: set[str] = set()
    for marker in index.dynamic_markers:
        names.update(marker.symbols)
    if not names:
        return False
    if "*" in names:
        return True
    prefixes = tuple(name[:-1] for name in names if name.endswith("*"))
    leaf = _qualname(finding).rsplit(".", 1)[-1]
    if prefixes and (finding.symbol.startswith(prefixes) or leaf.startswith(prefixes)):
        return True
    return finding.symbol in names or leaf in names


def _import_dynamic(index: FileIndex) -> bool:
    for marker in index.dynamic_markers:
        if marker.name in {"__import__", "import_module"} or marker.name.startswith("importlib."):
            return True
    return False


def _framework_convention(
    finding: Finding,
    index: FileIndex | None,
    settings_paths: frozenset[str],
    by_module: dict[str, FileIndex],
    roots: list[Path],
) -> Finding:
    """Cap names a framework loads by file shape. This does not consult `frameworks`."""
    if not _matches_convention(finding, index, settings_paths, by_module, roots):
        return finding
    evidence = _with_note(finding.evidence, _FRAMEWORK_CONVENTION_NOTE)
    if finding.confidence <= 60 and evidence == finding.evidence:
        return finding
    return replace(
        finding,
        confidence=min(finding.confidence, 60),
        status=_lowered_status(finding.status) if finding.confidence > 60 else finding.status,
        evidence=evidence,
    )


def _matches_convention(
    finding: Finding,
    index: FileIndex | None,
    settings_paths: frozenset[str],
    by_module: dict[str, FileIndex],
    roots: list[Path],
) -> bool:
    if _meta_attribute(finding):
        return True
    if "." in _qualname(finding):
        return False
    path = finding.path.replace("\\", "/")
    if finding.rule == "UNUSED_CLASS" and finding.symbol == "Migration" and _in_migrations_package(path):
        return True
    if _is_settings_path(path, settings_paths) and _is_upper_name(finding.symbol):
        return True
    if (
        path.rsplit("/", 1)[-1] == "apps.py"
        and finding.rule == "UNUSED_CLASS"
        and index is not None
        and _is_appconfig_subclass(index, _qualname(finding), by_module, roots)
    ):
        return True
    if path.rsplit("/", 1)[-1] == "urls.py" and finding.symbol in _URL_SYMBOLS:
        return True
    return finding.rule == "UNUSED_FUNCTION" and finding.symbol == "setup" and _sphinx_conf(path)


def _meta_attribute(finding: Finding) -> bool:
    """A nested `Meta` in a models, admin, forms, or serializers module."""
    parts = _qualname(finding).split(".")
    if len(parts) < 3 or parts[-2] != "Meta":
        return False
    path = finding.path.replace("\\", "/")
    name = path.rsplit("/", 1)[-1]
    if name in _META_FILE_NAMES:
        return True
    parent = path.rsplit("/", 1)[0] if "/" in path else ""
    return parent.rsplit("/", 1)[-1] in _META_DIR_NAMES and name.endswith(".py")


def _in_migrations_package(path: str) -> bool:
    name = path.rsplit("/", 1)[-1]
    if name == "__init__.py":
        return False
    parent = path.rsplit("/", 1)[0] if "/" in path else ""
    return parent.rsplit("/", 1)[-1] == "migrations"


def _is_settings_path(path: str, extra: frozenset[str]) -> bool:
    if any(_settings_module_path(path, item) for item in extra):
        return True
    name = path.rsplit("/", 1)[-1]
    if name == "settings.py" or name.endswith("_settings.py"):
        return True
    parent = path.rsplit("/", 1)[0] if "/" in path else ""
    return parent.rsplit("/", 1)[-1] == "settings" and name.endswith(".py")


def _settings_module_path(path: str, item: str) -> bool:
    """True when `path` is the file recorded for one `DJANGO_SETTINGS_MODULE`.

    A dotted module may sit under `src/` or another import root, so
    `myproject/settings.py` matches `src/myproject/settings.py`. A one-segment
    module records `config.py` or `config/__init__.py` and matches only that
    path, or the same path under `src/`. `pkg/config.py` is a different module.
    """
    if path == item or path == f"src/{item}":
        return True
    if not _dotted_settings_record(item):
        return False
    return path.endswith("/" + item)


def _dotted_settings_record(item: str) -> bool:
    if "/" not in item:
        return False
    parent, _, name = item.rpartition("/")
    return not (name == "__init__.py" and "/" not in parent)


def _is_upper_name(name: str) -> bool:
    letters = [char for char in name if char.isalpha()]
    return bool(letters) and all(char.isupper() for char in letters)


def _sphinx_conf(path: str) -> bool:
    parts = path.split("/")
    return parts[-1] == "conf.py" and bool({"docs", "doc"}.intersection(parts[:-1]))


def _django_settings_modules(indexes: list[FileIndex]) -> frozenset[str]:
    """Modules named by `DJANGO_SETTINGS_MODULE` in manage.py, wsgi.py, or asgi.py."""
    found: set[str] = set()
    for index in indexes:
        path = Path(index.path)
        if path.name not in BOOT_FILE_NAMES:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for match in DJANGO_SETTINGS_ASSIGNMENT.finditer(text):
            slash = "/".join(match.group(1).split("."))
            found.add(f"{slash}.py")
            found.add(f"{slash}/__init__.py")
    return frozenset(found)


def _is_appconfig_subclass(
    index: FileIndex,
    qualname: str,
    by_module: dict[str, FileIndex],
    roots: list[Path],
    seen: set[tuple[str, str]] | None = None,
) -> bool:
    if seen is None:
        seen = set()
    key = (index.path, qualname)
    if key in seen:
        return False
    seen.add(key)
    bases = dict(index.class_bases).get(qualname)
    if not bases:
        return False
    for base in bases:
        if _base_is_appconfig(index, base):
            return True
        followed = _followed_base(index, base, by_module, roots)
        if followed is not None and _is_appconfig_subclass(followed[0], followed[1], by_module, roots, seen):
            return True
        if not base.startswith("@") and _is_appconfig_subclass(index, base, by_module, roots, seen):
            return True
    return False


def _followed_base(
    index: FileIndex,
    base: str,
    by_module: dict[str, FileIndex],
    roots: list[Path],
) -> tuple[FileIndex, str] | None:
    """The project class a base refers to in another file."""
    if base.startswith("@import:"):
        edge = _import_edge(index, base[len("@import:") :])
        if edge is None or not edge.imported_name:
            return None
        module = import_target(edge.module, edge.level, Path(index.path), roots)
        name = edge.imported_name
    elif base.startswith("@expr:"):
        dotted = base[len("@expr:") :]
        module, separator, name = dotted.rpartition(".")
        if not separator or not module:
            return None
    else:
        return None
    if not module:
        return None
    target = by_module.get(module)
    if target is None:
        return None
    if not any(item.kind == "class" and item.qualname == name for item in target.bindings):
        return None
    return target, name


def _import_edge(index: FileIndex, local: str) -> ImportEdge | None:
    for edge in index.imports:
        if (edge.alias or edge.imported_name or "") == local:
            return edge
    return None


def _base_is_appconfig(index: FileIndex, base: str) -> bool:
    if base.startswith("@expr:"):
        leaf = base[len("@expr:") :]
    elif base.startswith("@import:"):
        leaf = _imported_leaf(index, base[len("@import:") :])
    else:
        leaf = base
    return leaf.rsplit(".", 1)[-1] == "AppConfig"


def _imported_leaf(index: FileIndex, local: str) -> str:
    """Original imported name for a local alias. `AppConfig as AC` yields `AppConfig`."""
    for edge in index.imports:
        bound = edge.alias or edge.imported_name or ""
        if bound == local and edge.imported_name:
            return edge.imported_name
    return local


def _alembic(finding: Finding) -> Finding:
    path = finding.path.replace("\\", "/")
    if "alembic/versions/" not in path or finding.symbol not in _ALEMBIC_NAMES:
        return finding
    if finding.rule not in _CAPPED_RULES:
        return finding
    return replace(
        finding,
        confidence=min(finding.confidence, 70),
        status=_lowered_status(finding.status),
        evidence=_with_note(finding.evidence, _ALEMBIC_NOTE),
    )


def _lowered_status(status: str) -> str:
    if status == "DEAD":
        return "POSSIBLY_DEAD"
    return status


def _package_init(path: str) -> bool:
    name = path.replace("\\", "/")
    return name == "__init__.py" or name.endswith("/__init__.py")


def _side_effect_import(index: FileIndex, finding: Finding) -> bool:
    for edge in index.imports:
        if edge.line != finding.line or edge.imported_name:
            continue
        module = edge.module or ""
        if "." not in module:
            continue
        if edge.alias == finding.symbol:
            return True
    return False


def _with_note(evidence: tuple[str, ...], note: str) -> tuple[str, ...]:
    if note in evidence:
        return evidence
    return evidence + (note,)


def _qualname(finding: Finding) -> str:
    prefix = f"{finding.rule}:{finding.path}:"
    if finding.fingerprint.startswith(prefix):
        return finding.fingerprint[len(prefix) :]
    return finding.symbol
