"""Serializable analysis records and user-facing findings."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from typing import Any

# Bump when FileIndex gains fields or the indexer changes meaning.
# The scan cache mixes this into its stamp so old records are not reused.
INDEX_VERSION = 10


def make_fingerprint(rule: str, path: str, qualname: str) -> str:
    """Stable id for a finding. Line numbers are omitted so later baselines survive edits."""
    return f"{rule}:{path}:{qualname}"


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


@dataclass(frozen=True)
class ParseError:
    path: str
    line: int
    column: int
    message: str


@dataclass(frozen=True)
class ScanResult:
    findings: tuple[Finding, ...]
    errors: tuple[ParseError, ...]
    files_scanned: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "files_scanned": self.files_scanned,
            "findings": [asdict(finding) for finding in self.findings],
            "errors": [asdict(error) for error in self.errors],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2) + "\n"
