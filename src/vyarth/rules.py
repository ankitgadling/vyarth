"""Dead-code rules over a FileIndex. These functions never see AST nodes."""

from __future__ import annotations

from pathlib import Path

from vyarth.config import Config
from vyarth.discover import import_target, module_name, relative_posix
from vyarth.entries import EntrySet, collect_entries
from vyarth.flow import apply_flow
from vyarth.graph import (
    _reachable_symbols,
    class_attribute_findings,
    orphan_findings,
    reachable_modules,
    wildcard_references,
)
from vyarth.model import Binding, FileIndex, Finding, ImportEdge, make_fingerprint
from vyarth.progress import ScanProgress
from vyarth.project import Project, build_project, rebind


_KIND_RULES = {
    "import": "UNUSED_IMPORT",
    "function": "UNUSED_FUNCTION",
    "class": "UNUSED_CLASS",
    "variable": "UNUSED_VARIABLE",
}

_MESSAGES = {
    "UNUSED_IMPORT": "Import '{name}' is never used.",
    "UNUSED_FUNCTION": "Function '{name}' is never used.",
    "UNUSED_CLASS": "Class '{name}' is never used.",
    "UNUSED_VARIABLE": "Variable '{name}' is never used.",
}

_UNREACHABLE_MESSAGE = "Control flow terminates before this statement."
_MODULE_MESSAGE = "No incoming imports detected."
_WILDCARD_MESSAGE = "Wildcard import prevents reliable analysis."


def collect_findings(
    indexes: list[FileIndex],
    root: Path,
    config: Config,
    *,
    check_modules: bool,
    progress: ScanProgress | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    _status(progress, "tracing which code runs")
    project = build_project(indexes, root)
    project = rebind(project, apply_flow(project))
    entries = collect_entries(project, config)
    reached, unresolved = _reachable_symbols(project, entries)
    referenced, exported = _cross_module_uses(project)
    referenced |= wildcard_references(project)
    for index in project.indexes:
        relpath = relative_posix(Path(index.path), project.root)
        findings.extend(_symbol_findings(index, relpath, referenced, entries, reached))
        findings.extend(_wildcard_findings(index, relpath))
        findings.extend(_unreachable_findings(index, relpath))
    findings.extend(orphan_findings(project, entries, referenced, exported, reached, unresolved, progress))
    findings.extend(class_attribute_findings(project, referenced, reached, unresolved, progress))
    if check_modules:
        _status(progress, "checking modules")
        findings.extend(_module_findings(project, entries, config))
    return findings


def _status(progress: ScanProgress | None, label: str, detail: str = "") -> None:
    if progress is not None:
        progress.update(label, detail)


def _symbol_findings(
    index: FileIndex,
    relpath: str,
    referenced: set[tuple[str, str]],
    entries: EntrySet,
    reached: set[tuple[str, str]],
) -> list[Finding]:
    findings: list[Finding] = []
    for binding in index.bindings:
        if _binding_is_used(index, binding, referenced, entries, reached) or binding.kind == "parameter":
            continue
        if binding.scope_kind == "class" and binding.kind != "import":
            # Methods and class attributes are reached through attribute access.
            continue
        if _silent_name(binding.name):
            continue
        rule = _KIND_RULES.get(binding.kind)
        if rule is None:
            continue
        findings.append(
            _finding(
                rule=rule,
                path=relpath,
                line=binding.line,
                column=binding.column,
                symbol=binding.name,
                message=_MESSAGES[rule].format(name=binding.name),
                evidence=("No references found.",),
                qualname=binding.qualname,
            )
        )
    return findings


def _binding_is_used(
    index: FileIndex,
    binding: Binding,
    referenced: set[tuple[str, str]],
    entries: EntrySet,
    reached: set[tuple[str, str]],
) -> bool:
    if binding.read_count > 0:
        return True
    if binding.scope_kind == "module" and binding.name in index.exports:
        return True
    if (index.path, binding.qualname) in entries.symbols:
        return True
    if (index.path, binding.qualname) in reached:
        return True
    return (index.path, binding.qualname) in referenced


def _cross_module_uses(project: Project) -> tuple[set[tuple[str, str]], set[tuple[str, str]]]:
    """Definitions reached by an import that the importing module actually uses.

    A used import keeps the target alive. An unused import does not. Re-exports
    listed in ``__all__`` count as uses, and the walk follows them. Targets
    reached from an export are recorded in the second set during the same walk.
    """
    queue: list[tuple[FileIndex, Binding, bool]] = []
    for index in project.indexes:
        for binding in index.bindings:
            if binding.kind != "import" or not _locally_used(index, binding):
                continue
            exported = binding.scope_kind == "module" and binding.name in index.exports
            queue.append((index, binding, exported))

    referenced: set[tuple[str, str]] = set()
    exported_targets: set[tuple[str, str]] = set()
    seen_all: set[tuple[str, str]] = set()
    seen_export: set[tuple[str, str]] = set()
    while queue:
        index, binding, from_export = queue.pop()
        marker = (index.path, binding.qualname)
        if from_export:
            if marker in seen_export:
                continue
            seen_export.add(marker)
        elif marker in seen_all:
            continue
        seen_all.add(marker)
        origin = _import_origin(project, index, binding)
        if origin is None:
            continue
        module, symbol = origin
        target = project.by_module.get(module)
        if target is None:
            continue
        target_binding = project.module_binding(target.path, symbol)
        if target_binding is None:
            continue
        reached = (target.path, target_binding.qualname)
        referenced.add(reached)
        if from_export:
            exported_targets.add(reached)
        if target_binding.kind == "import":
            queue.append((target, target_binding, from_export))
    return referenced, exported_targets


def _locally_used(index: FileIndex, binding: Binding) -> bool:
    if binding.read_count > 0:
        return True
    return binding.scope_kind == "module" and binding.name in index.exports


def _import_origin(project: Project, index: FileIndex, binding: Binding) -> tuple[str, str] | None:
    edge = project.edge_for(index.path, binding.name, binding.line)
    if edge is None or edge.is_wildcard or not edge.imported_name or edge.imported_name == "*":
        return None
    module = import_target(edge.module, edge.level, Path(index.path), project.roots)
    if not module:
        return None
    return module, edge.imported_name


def _wildcard_findings(index: FileIndex, relpath: str) -> list[Finding]:
    findings: list[Finding] = []
    for edge in index.imports:
        if not edge.is_wildcard:
            continue
        symbol = _wildcard_symbol(edge)
        findings.append(
            _finding(
                rule="WILDCARD_IMPORT",
                path=relpath,
                line=edge.line,
                column=edge.column,
                symbol=symbol,
                message=_WILDCARD_MESSAGE,
                evidence=(_WILDCARD_MESSAGE,),
                qualname=symbol,
            )
        )
    return findings


def _unreachable_findings(index: FileIndex, relpath: str) -> list[Finding]:
    findings: list[Finding] = []
    seen: dict[str, int] = {}
    for span in index.unreachable:
        base = f"{span.scope_qualname}:{span.symbol}"
        seen[base] = seen.get(base, 0) + 1
        qualname = base if seen[base] == 1 else f"{base}#{seen[base]}"
        findings.append(
            _finding(
                rule="UNREACHABLE_CODE",
                path=relpath,
                line=span.line,
                column=span.column,
                symbol=span.symbol,
                message=span.message or _UNREACHABLE_MESSAGE,
                evidence=(span.message or _UNREACHABLE_MESSAGE,),
                qualname=qualname,
            )
        )
    return findings


def _module_findings(project: Project, entries: EntrySet, config: Config) -> list[Finding]:
    scanned: dict[str, tuple[str, FileIndex]] = {}
    for index in project.indexes:
        path = Path(index.path)
        relpath = relative_posix(path, project.root)
        name = module_name(path, project.roots)
        if name is not None:
            scanned.setdefault(name, (relpath, index))
    reachable = reachable_modules(project, entries, config)
    findings: list[Finding] = []
    for name, (relpath, index) in scanned.items():
        if name in reachable:
            continue
        findings.append(
            Finding(
                rule="POSSIBLY_UNUSED_MODULE",
                path=relpath,
                line=1,
                column=1,
                symbol=relpath,
                status="POSSIBLY_UNUSED_MODULE",
                confidence=82,
                message=_MODULE_MESSAGE,
                evidence=(_MODULE_MESSAGE,),
                fingerprint=make_fingerprint("POSSIBLY_UNUSED_MODULE", relpath, name),
            )
        )
    return findings


def _finding(
    *,
    rule: str,
    path: str,
    line: int,
    column: int,
    symbol: str,
    message: str,
    evidence: tuple[str, ...],
    qualname: str,
) -> Finding:
    status, confidence = _classify(rule)
    return Finding(
        rule=rule,
        path=path,
        line=line,
        column=column,
        symbol=symbol,
        status=status,
        confidence=confidence,
        message=message,
        evidence=evidence,
        fingerprint=make_fingerprint(rule, path, qualname),
    )


def _classify(rule: str) -> tuple[str, int]:
    if rule == "WILDCARD_IMPORT":
        return "ANALYSIS_LIMIT", 100
    return "DEAD", 100


def _silent_name(name: str) -> bool:
    if name == "_":
        return True
    return len(name) >= 5 and name.startswith("__") and name.endswith("__")


def _wildcard_symbol(edge: ImportEdge) -> str:
    prefix = "." * edge.level
    if edge.module:
        prefix += edge.module
    if not prefix:
        prefix = "."
    return f"{prefix}.*"
