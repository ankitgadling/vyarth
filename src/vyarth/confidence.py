"""Evidence checklist and dynamic-call downgrades. Applied after rules, before ignores."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from vyarth.discover import relative_posix
from vyarth.model import FileIndex, Finding


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
_MODULE_CAP_NOTE = "This file has no incoming imports, so this score follows the module."
_ALEMBIC_NOTE = "Alembic loads this name when the migration runs."
_PROBE_NOTE = "This import sits in a try that catches ImportError, so it may be an availability check."
_CAPPED_RULES = {
    "UNUSED_FUNCTION",
    "UNUSED_CLASS",
    "UNUSED_VARIABLE",
    "UNUSED_IMPORT",
    "ORPHAN_FUNCTION",
    "DUPLICATE_CODE",
}
_ALEMBIC_NAMES = {"upgrade", "downgrade", "revision", "down_revision", "branch_labels", "depends_on"}


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
    capped: list[Finding] = []
    for finding in adjusted:
        finding = _alembic(finding)
        cap = module_caps.get(finding.path)
        if cap is not None and finding.rule in _CAPPED_RULES and finding.confidence > cap:
            finding = replace(
                finding,
                confidence=cap,
                evidence=_with_note(finding.evidence, _MODULE_CAP_NOTE),
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
    return replace(finding, status="POSSIBLY_DEAD", confidence=96, evidence=_CHECKLIST)


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
    if finding.symbol in names:
        return True
    return _qualname(finding).rsplit(".", 1)[-1] in names


def _import_dynamic(index: FileIndex) -> bool:
    for marker in index.dynamic_markers:
        if marker.name in {"__import__", "import_module"} or marker.name.startswith("importlib."):
            return True
    return False


def _alembic(finding: Finding) -> Finding:
    path = finding.path.replace("\\", "/")
    if "alembic/versions/" not in path or finding.symbol not in _ALEMBIC_NAMES:
        return finding
    if finding.rule not in _CAPPED_RULES or finding.confidence <= 70:
        return finding
    return replace(finding, confidence=70, evidence=_with_note(finding.evidence, _ALEMBIC_NOTE))


def _with_note(evidence: tuple[str, ...], note: str) -> tuple[str, ...]:
    if note in evidence:
        return evidence
    return evidence + (note,)


def _qualname(finding: Finding) -> str:
    prefix = f"{finding.rule}:{finding.path}:"
    if finding.fingerprint.startswith(prefix):
        return finding.fingerprint[len(prefix) :]
    return finding.symbol
