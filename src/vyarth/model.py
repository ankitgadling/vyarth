"""Serializable analysis records and user-facing findings."""

from __future__ import annotations

import ast
import base64
from dataclasses import asdict, dataclass, replace
import hashlib
import json
from pathlib import Path
from typing import Any

from vyarth.reasons import BRIEF_EVIDENCE, codes_for

# Bump when FileIndex gains fields or the indexer changes meaning.
# The scan cache mixes this into its stamp so old records are not reused.
INDEX_VERSION = 18

PUBLIC_NAME_NOTE = "Public name. Callers outside this project may still load it."


def is_private_name(name: str) -> bool:
    """True when the name is not part of the importable public surface."""
    return name.startswith("_")


def make_fingerprint(rule: str, path: str, qualname: str) -> str:
    """Stable id for a finding. Line numbers are omitted so later baselines survive edits."""
    return f"{rule}:{path}:{qualname}"


def short_id(fingerprint: str, length: int = 8) -> str:
    """`VY` plus the first `length` characters of the unpadded base32 SHA-1."""
    digest = hashlib.sha1(fingerprint.encode("utf-8")).digest()
    encoded = base64.b32encode(digest).decode("ascii").rstrip("=")
    return "VY" + encoded[:length]


def assign_ids(findings: list[Finding] | tuple[Finding, ...]) -> tuple[Finding, ...]:
    """Give every finding an id. An 8-character collision extends both ids to 12."""
    grouped: dict[str, list[Finding]] = {}
    for finding in findings:
        grouped.setdefault(short_id(finding.fingerprint), []).append(finding)
    assigned: list[Finding] = []
    for finding in findings:
        length = 12 if len(grouped[short_id(finding.fingerprint)]) > 1 else 8
        assigned.append(replace(finding, id=short_id(finding.fingerprint, length)))
    return tuple(assigned)


class IdError(ValueError):
    """An id selector that names no finding, or more than one."""


def resolve_ids(findings: tuple[Finding, ...] | list[Finding], tokens: list[str]) -> tuple[Finding, ...]:
    """Findings named by an id or a fingerprint. An id that matches two findings is an error."""
    chosen: list[Finding] = []
    seen: set[str] = set()
    for token in tokens:
        exact = [item for item in findings if item.id == token or item.fingerprint == token]
        matches = exact or [item for item in findings if token and item.id.startswith(token)]
        if len(matches) > 1:
            raise IdError(f"ambiguous id: {token}")
        if not matches:
            raise IdError(f"unknown id: {token}")
        if matches[0].fingerprint not in seen:
            seen.add(matches[0].fingerprint)
            chosen.append(matches[0])
    return tuple(chosen)


_KINDS = {
    "UNUSED_IMPORT": "import",
    "WILDCARD_IMPORT": "import",
    "UNUSED_FUNCTION": "function",
    "ORPHAN_FUNCTION": "function",
    "DUPLICATE_CODE": "function",
    "UNUSED_CLASS": "class",
    "UNUSED_VARIABLE": "variable",
    "UNREACHABLE_CODE": "statement",
    "POSSIBLY_UNUSED_MODULE": "module",
    "UNUSED_DEPENDENCY": "package",
    "UNUSED_IGNORE": "ignore",
    "IGNORE_WITHOUT_REASON": "ignore",
}
_HELP_URI = "https://github.com/ankitgadling/vyarth/blob/main/docs/rules.md"


def qualname_of(finding: Finding) -> str:
    prefix = f"{finding.rule}:{finding.path}:"
    if finding.fingerprint.startswith(prefix):
        return finding.fingerprint[len(prefix) :]
    return finding.symbol


def kind_of(finding: Finding) -> str:
    return _KINDS.get(finding.rule, "symbol")


def attach_reasons(finding: Finding) -> Finding:
    codes = codes_for(finding.evidence)
    qualname = qualname_of(finding)
    kind = kind_of(finding)
    if finding.reasons == codes and finding.qualname == qualname and finding.kind == kind:
        return finding
    return replace(finding, reasons=codes, qualname=qualname, kind=kind)


@dataclass(frozen=True)
class Binding:
    name: str
    qualname: str
    kind: str
    line: int
    column: int
    scope_id: str
    scope_kind: str
    read_count: int
    typing_only: bool = False
    # Set when every store of this name is a loop target, an unpacking target,
    # a `with ... as` name, a comprehension target, or a `match` capture.
    # Those names are unused by design, so they are not reported.
    origin: str = ""


@dataclass(frozen=True)
class ScopeInfo:
    id: str
    kind: str
    name: str
    parent_id: str | None


@dataclass(frozen=True)
class ImportEdge:
    line: int
    column: int
    module: str | None
    level: int
    imported_name: str | None
    alias: str | None
    is_wildcard: bool


@dataclass(frozen=True)
class UnreachableSpan:
    line: int
    column: int
    symbol: str
    message: str
    scope_qualname: str
    end_line: int = 0
    end_offset: int = 0


@dataclass(frozen=True)
class CallEdge:
    """One call. `callee` is a qualname in the same file when `resolved` is true."""

    caller: str
    callee: str
    callee_name: str
    kind: str
    resolved: bool
    line: int
    col_offset: int = 0


@dataclass(frozen=True)
class Decorator:
    qualname: str
    name: str
    arguments: tuple[str, ...]


@dataclass(frozen=True)
class DynamicMarker:
    name: str
    line: int
    symbols: tuple[str, ...] = ()


@dataclass(frozen=True)
class FlowBind:
    """A name or `self.attr` bound to another name in `caller`."""

    caller: str
    target: str
    source: str
    line: int
    branch: str = ""


def span_contains(span: UnreachableSpan, line: int, col_offset: int) -> bool:
    """True when a 0-based source point lies inside this dead statement."""
    end_line = span.end_line or span.line
    end_offset = span.end_offset if span.end_line else 10**9
    start_col = max(span.column - 1, 0)
    if line < span.line or line > end_line:
        return False
    if span.line == end_line:
        return start_col <= col_offset < end_offset
    if line == span.line:
        return col_offset >= start_col
    if line == end_line:
        return col_offset < end_offset
    return True


def point_in_spans(spans: tuple[UnreachableSpan, ...] | list[UnreachableSpan], line: int, col_offset: int) -> bool:
    return any(span_contains(span, line, col_offset) for span in spans)


@dataclass(frozen=True)
class ReturnNote:
    """Return annotation used when a call's result is used as a receiver."""

    qualname: str
    annotation: str
    line: int


@dataclass(frozen=True)
class ContainerStore:
    """Functions placed in one container name, in source order.

    `mode` is `replace` for a list or tuple assignment, `append` for append,
    extend, and `+=`, and `insert` for insert. `elements` aligns with that
    order. An empty string is a slot that is not a function.
    """

    caller: str
    name: str
    elements: tuple[str, ...]
    line: int
    mode: str
    index: int


@dataclass(frozen=True)
class BodyHash:
    """Structural hash of a function body. Local names and positions are ignored."""

    qualname: str
    name: str
    digest: str
    statements: int
    line: int


@dataclass(frozen=True)
class IgnoreDirective:
    """A `# vyarth: ignore` comment. `rules` is None when every rule is suppressed.

    `exact` is set for `# noqa` directives, which cover only the import line they
    name. A directive on the previous line must not hide the next import.
    """

    line: int
    rules: tuple[str, ...] | None
    exact: bool = False
    reason: str | None = None
    # Comment line that this directive came from. Expansions keep that line.
    origin: int = 0
    # Set for a vyarth ignore comment. noqa copies are not reported.
    reportable: bool = False


@dataclass(frozen=True)
class FileIndex:
    """Semantic index for one file. No AST nodes, so another backend can emit the same shape."""

    path: str
    bindings: tuple[Binding, ...]
    scopes: tuple[ScopeInfo, ...]
    imports: tuple[ImportEdge, ...]
    unreachable: tuple[UnreachableSpan, ...]
    has_main_guard: bool
    ignores: tuple[IgnoreDirective, ...]
    exports: tuple[str, ...]
    calls: tuple[CallEdge, ...] = ()
    decorators: tuple[Decorator, ...] = ()
    dynamic_markers: tuple[DynamicMarker, ...] = ()
    value_references: tuple[str, ...] = ()
    abstract: tuple[str, ...] = ()
    flow_binds: tuple[FlowBind, ...] = ()
    returns: tuple[ReturnNote, ...] = ()
    body_hashes: tuple[BodyHash, ...] = ()
    value_uses: tuple[tuple[str, str], ...] = ()
    class_bases: tuple[tuple[str, tuple[str, ...]], ...] = ()
    unbound_names: tuple[str, ...] = ()
    dynamic_imports: tuple[str, ...] = ()
    container_stores: tuple[ContainerStore, ...] = ()
    import_probes: tuple[str, ...] = ()
    lambda_mentions: tuple[str, ...] = ()
    module_strings: tuple[str, ...] = ()
    # (assignment qualname, dotted string) for MIDDLEWARE, INSTALLED_APPS, and *_BACKEND(S).
    setting_strings: tuple[tuple[str, str], ...] = ()
    # Local names passed to dir() or to getattr with a non-literal attribute.
    module_sweeps: tuple[str, ...] = ()


@dataclass(frozen=True)
class Finding:
    rule: str
    path: str
    line: int
    column: int
    symbol: str
    status: str
    confidence: int
    message: str
    evidence: tuple[str, ...]
    fingerprint: str
    id: str = ""
    end_line: int = 0
    end_column: int = 0
    qualname: str = ""
    kind: str = ""
    reasons: tuple[str, ...] = ()
    baselined: bool = False


@dataclass(frozen=True)
class ParseError:
    path: str
    line: int
    column: int
    message: str


@dataclass(frozen=True)
class FindingCensus:
    """Counts for the findings that passed the filters, before `--max-findings`."""

    total: int
    by_rule: tuple[tuple[str, int], ...]
    by_band: tuple[tuple[str, int], ...]
    fixable_safe: int
    fixable_unsafe: int


@dataclass(frozen=True)
class ScanResult:
    findings: tuple[Finding, ...]
    errors: tuple[ParseError, ...]
    files_scanned: int
    census: FindingCensus | None = None

    def to_dict(self, **kwargs: Any) -> dict[str, Any]:
        return self.to_report(**kwargs)

    def to_json(self, **kwargs: Any) -> str:
        return json.dumps(self.to_dict(**kwargs), indent=2) + "\n"

    def to_report(
        self,
        *,
        root: Path | None = None,
        show_fixes: bool = False,
        applied: list[dict[str, Any]] | None = None,
        version: int = 1,
        brief_evidence: bool = False,
    ) -> dict[str, Any]:
        """Version 1 report. Existing keys stay. New keys are only added."""
        from vyarth import __version__
        from vyarth.fix import applicability, fix_edits

        sources = _sources(root, self.findings) if root is not None else {}
        spans = _spans(root, self.findings, sources) if root is not None else {}
        rows = []
        safe = 0
        unsafe = 0
        for finding in self.findings:
            end_line, end_column = spans.get(finding.fingerprint, (finding.line, finding.column))
            level = applicability(finding, sources.get(finding.path))
            if level == "safe":
                safe += 1
            elif level == "unsafe":
                unsafe += 1
            fix: dict[str, Any] = {"applicability": level}
            if show_fixes and level in {"safe", "unsafe"} and root is not None:
                fix["edits"] = fix_edits(root, finding)
            evidence = list(finding.evidence)
            if brief_evidence:
                evidence = [item for item in evidence if item not in BRIEF_EVIDENCE]
            row: dict[str, Any] = {
                "id": finding.id or short_id(finding.fingerprint),
                "fingerprint": finding.fingerprint,
                "rule": finding.rule,
                "rule_url": f"{_HELP_URI}#{finding.rule.lower()}",
                "kind": finding.kind or kind_of(finding),
                "path": finding.path,
                "line": finding.line,
                "column": finding.column,
                "end_line": end_line,
                "end_column": end_column,
                "symbol": finding.symbol,
                "qualname": finding.qualname or qualname_of(finding),
                "status": finding.status,
                "confidence": finding.confidence,
                "message": finding.message,
                "reasons": list(finding.reasons or codes_for(finding.evidence)),
                "evidence": evidence,
                "fix": fix,
                "baselined": finding.baselined,
            }
            if "no_dist_metadata" in row["reasons"]:
                row["env_sensitive"] = True
            rows.append(row)
        report: dict[str, Any] = {
            "schema_version": version,
            "tool": {"name": "vyarth", "version": __version__},
            "root": str(root) if root is not None else "",
            "files_scanned": self.files_scanned,
            "summary": _summary(rows),
            "findings": rows,
            "errors": [asdict(error) for error in self.errors],
        }
        if self.census is None:
            report["summary"]["fixable"] = {"safe": safe, "unsafe": unsafe}
        else:
            report["summary"]["total"] = self.census.total
            report["summary"]["shown"] = len(rows)
            report["summary"]["truncated"] = len(rows) < self.census.total
            report["summary"]["by_rule"] = dict(self.census.by_rule)
            report["summary"]["by_band"] = dict(self.census.by_band)
            report["summary"]["fixable"] = {"safe": self.census.fixable_safe, "unsafe": self.census.fixable_unsafe}
        if applied is not None:
            report["applied"] = applied
        return report


def _summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    by_rule: dict[str, int] = {}
    bands = {"100": 0, "90-99": 0, "70-89": 0, "0-69": 0}
    for row in rows:
        by_rule[row["rule"]] = by_rule.get(row["rule"], 0) + 1
        score = row["confidence"]
        if score == 100:
            bands["100"] += 1
        elif score >= 90:
            bands["90-99"] += 1
        elif score >= 70:
            bands["70-89"] += 1
        else:
            bands["0-69"] += 1
    return {
        "total": len(rows),
        "shown": len(rows),
        "truncated": False,
        "by_rule": by_rule,
        "by_band": bands,
        "fixable": {"safe": 0, "unsafe": 0},
    }


def _sources(root: Path, findings: tuple[Finding, ...]) -> dict[str, str]:
    found: dict[str, str] = {}
    for finding in findings:
        if finding.path in found:
            continue
        try:
            found[finding.path] = (root / finding.path).read_text(encoding="utf-8")
        except OSError:
            found[finding.path] = ""
    return found


def _spans(
    root: Path,
    findings: tuple[Finding, ...],
    sources: dict[str, str] | None = None,
) -> dict[str, tuple[int, int]]:
    sources = sources if sources is not None else _sources(root, findings)
    trees: dict[str, ast.AST | None] = {}
    spans: dict[str, tuple[int, int]] = {}
    for finding in findings:
        if finding.path not in trees:
            trees[finding.path] = _parse(sources.get(finding.path, ""))
        spans[finding.fingerprint] = _statement_end(trees[finding.path], finding.line, finding.symbol)
    return spans


def _parse(source: str) -> ast.AST | None:
    if not source:
        return None
    try:
        return ast.parse(source)
    except SyntaxError:
        return None


def _statement_end(tree: ast.AST | None, line: int, symbol: str) -> tuple[int, int]:
    if tree is None:
        return line, 1
    found: ast.AST | None = None
    for node in ast.walk(tree):
        if getattr(node, "lineno", None) != line:
            continue
        name = getattr(node, "name", None) or getattr(node, "id", None)
        if found is None or name == symbol:
            found = node
            if name == symbol:
                break
    if found is None:
        return line, 1
    end_line = getattr(found, "end_lineno", None) or line
    end_col = getattr(found, "end_col_offset", None)
    if not isinstance(end_line, int):
        end_line = line
    if not isinstance(end_col, int):
        return end_line, 1
    return end_line, end_col + 1
