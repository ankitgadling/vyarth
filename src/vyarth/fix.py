"""Rewrite findings that are safe to delete, then let the caller rescan."""

from __future__ import annotations

import ast
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import difflib
from io import StringIO
import json
from pathlib import Path
import subprocess
import tokenize
from typing import Any

from vyarth.confidence import PROBE_NOTE, REEXPORT_NOTE, SIDE_EFFECT_NOTE
from vyarth.discover import read_python_source
from vyarth.model import Finding, qualname_of
from vyarth.verify import run_verification


@dataclass(frozen=True)
class AppliedFix:
    """One rewrite. The CLI renders the sentence. Machine reports keep this object."""

    id: str
    fingerprint: str
    path: str
    line: int
    symbol: str
    applicability: str


@dataclass(frozen=True)
class SkippedFix:
    id: str
    path: str
    line: int
    symbol: str
    reason: str


@dataclass(frozen=True)
class FixReport:
    """Result of a verified fix. A failed check restores the snapshot."""

    applied: tuple[AppliedFix, ...]
    skipped: tuple[SkippedFix, ...]
    verified: bool
    rolled_back: bool
    failed_step: str
    output_tail: str

    def failure(self) -> dict[str, object]:
        return {
            "verified": self.verified,
            "rolled_back": self.rolled_back,
            "failed_step": self.failed_step,
            "output_tail": self.output_tail,
        }


def apply_fixes(
    root: Path,
    findings: list[Finding] | tuple[Finding, ...],
    *,
    unsafe: bool = False,
    unsafe_fixes: bool = False,
    write: bool = True,
) -> list[AppliedFix]:
    """Apply every safe rewrite. Returns one record for each edit."""
    return _write(root, list(findings), unsafe=unsafe, unsafe_fixes=unsafe_fixes, write=write)


def apply_import_fixes(
    root: Path,
    findings: list[Finding] | tuple[Finding, ...],
    *,
    unsafe: bool = False,
    write: bool = True,
) -> list[AppliedFix]:
    """Remove unused import names. Returns one record for each edit."""
    chosen = [finding for finding in findings if finding.rule == "UNUSED_IMPORT"]
    return _write(root, chosen, unsafe=unsafe, write=write)


def apply_fixes_verified(
    root: Path,
    findings: list[Finding] | tuple[Finding, ...],
    *,
    unsafe: bool = False,
    unsafe_fixes: bool = False,
    verify_cmd: str = "",
    timeout: int = 60,
    verify_each: bool = False,
) -> FixReport:
    """Write edits, compile them, and restore the snapshot when a check fails."""
    kept, skipped = split_dirty(root, list(findings), unsafe=unsafe, unsafe_fixes=unsafe_fixes)
    if verify_each:
        return _verify_each(root, kept, skipped, unsafe=unsafe, unsafe_fixes=unsafe_fixes, verify_cmd=verify_cmd, timeout=timeout)
    return _verify_all(root, kept, skipped, unsafe=unsafe, unsafe_fixes=unsafe_fixes, verify_cmd=verify_cmd, timeout=timeout)


def ensure_clean(root: Path) -> None:
    """Refuse a fix when the worktree has uncommitted changes."""
    status = _git(root, ["git", "status", "--porcelain"])
    if status is None:
        raise ValueError("not a git repository")
    if status.strip():
        raise ValueError("dirty worktree")


def render_applied(item: AppliedFix, *, wrote: bool) -> str:
    """The sentence previously printed for one edit."""
    if item.line <= 0:
        return item.symbol
    verb = "fixed" if wrote else "would fix"
    return f"{verb} {item.path}:{item.line} {item.symbol}"


def applicability(finding: Finding, source: str | None = None) -> str:
    """`safe` when the rewrite may run. `unsafe` is a nested 90–99 name. Otherwise `none`."""
    if is_fixable(finding, source):
        return "safe"
    qualname = finding.qualname or qualname_of(finding)
    nested = "." in qualname
    if nested and 90 <= finding.confidence <= 99 and finding.rule in {"UNUSED_FUNCTION", "UNUSED_VARIABLE", "UNREACHABLE_CODE"}:
        return "unsafe"
    return "none"


def fix_edits(root: Path, finding: Finding) -> list[dict[str, Any]]:
    """Edits for one safe finding. An unsafe or missing file contributes nothing."""
    path = root / finding.path
    if not path.is_file():
        return []
    try:
        source, _encoding = read_python_source(path)
    except OSError:
        return []
    level = applicability(finding, source)
    if level == "none":
        return []
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    removed: dict[int, tuple[int, int]] = {}
    edits = _import_edits(tree, source, [finding], finding.path, unsafe=False, verb="fixed", removed=removed)
    edits.extend(
        _statement_edits(
            tree,
            source,
            [finding],
            finding.path,
            verb="fixed",
            removed=removed,
            unsafe_fixes=level == "unsafe",
        )
    )
    edits = _keep_suites(tree, source, edits, removed)
    rendered: list[dict[str, Any]] = []
    for start, end, replacement, _notes in edits:
        rendered.append(
            {
                "content": replacement,
                "location": {"row": start, "column": 1},
                "end_location": {"row": end, "column": 1},
            }
        )
    return rendered


def applied_dicts(items: list[AppliedFix]) -> list[dict[str, Any]]:
    return [asdict(item) for item in items]


def render_fix_diff(
    root: Path,
    findings: list[Finding] | tuple[Finding, ...],
    *,
    unsafe: bool = False,
    unsafe_fixes: bool = False,
) -> str:
    """Unified diff of the rewrites. Nothing is written."""
    chunks: list[str] = []
    for relpath, before, after, _, _ in _previews(
        root,
        list(findings),
        unsafe=unsafe,
        unsafe_fixes=unsafe_fixes,
    ):
        chunks.extend(
            difflib.unified_diff(
                before.splitlines(keepends=True),
                after.splitlines(keepends=True),
                fromfile=relpath,
                tofile=relpath,
            )
        )
    return "".join(chunks)


def render_fix_diff_json(
    root: Path,
    findings: list[Finding] | tuple[Finding, ...],
    *,
    unsafe: bool = False,
    unsafe_fixes: bool = False,
) -> str:
    """One diff per finding that would be rewritten."""
    edits: list[dict[str, str]] = []
    for finding in findings:
        preview = _previews(root, [finding], unsafe=unsafe, unsafe_fixes=unsafe_fixes)
        if not preview:
            continue
        relpath, before, after, _, _ = preview[0]
        if before == after:
            continue
        diff = "".join(
            difflib.unified_diff(
                before.splitlines(keepends=True),
                after.splitlines(keepends=True),
                fromfile=relpath,
                tofile=relpath,
            )
        )
        source = before
        edits.append(
            {
                "id": finding.id,
                "path": finding.path,
                "diff": diff,
                "applicability": applicability(finding, source),
            }
        )
    return json.dumps({"edits": edits}, indent=2) + "\n"


def is_fixable(finding: Finding, source: str | None = None) -> bool:
    """True when a rewrite may delete this finding.

    Pass `source` so an unreachable `yield` that is the only yield in its
    function is left in place. Deleting it would turn a generator into a
    normal function.
    """
    if finding.rule == "UNUSED_IMPORT" and finding.status == "DEAD":
        if _package_init(finding.path):
            return False
        return True
    if finding.confidence < 100:
        return False
    if finding.rule == "UNREACHABLE_CODE":
        return source is None or not _sole_yield(source, finding.line)
    return finding.rule in {"UNUSED_FUNCTION", "UNUSED_VARIABLE"} and _nested_name(finding)


def rewrite_source(
    source: str,
    findings: list[Finding] | tuple[Finding, ...],
    relpath: str,
    *,
    unsafe: bool = False,
    unsafe_fixes: bool = False,
    verb: str = "fixed",
) -> tuple[str, list[str]]:
    """Return edited source and a note for each change. The file is not written."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return source, []
    chosen = list(findings)
    removed: dict[int, tuple[int, int]] = {}
    edits = _import_edits(tree, source, chosen, relpath, unsafe=unsafe, verb=verb, removed=removed)
    edits.extend(
        _statement_edits(
            tree,
            source,
            chosen,
            relpath,
            verb=verb,
            removed=removed,
            unsafe_fixes=unsafe_fixes,
        )
    )
    edits = _keep_suites(tree, source, edits, removed)
    updated, notes = _apply_edits(source, edits)
    try:
        ast.parse(updated)
    except SyntaxError:
        return source, [f"skipped {relpath}: rewrite would not parse"]
    return updated, notes


def _write(
    root: Path,
    findings: list[Finding],
    *,
    unsafe: bool,
    write: bool,
    unsafe_fixes: bool = False,
) -> list[AppliedFix]:
    verb = "fixed" if write else "would fix"
    kept, skipped = split_dirty(root, findings, unsafe=unsafe, unsafe_fixes=unsafe_fixes)
    notes: list[str] = []
    for relpath, source, updated, edits, encoding in _previews(
        root,
        kept,
        unsafe=unsafe,
        unsafe_fixes=unsafe_fixes,
        verb=verb,
    ):
        if source == updated:
            notes.extend(edits)
            continue
        if not write:
            notes.extend(edits)
            continue
        path = root / relpath
        _write_python(path, updated, encoding)
        notes.extend(edits)
    applied = [_applied(findings, note, verb) for note in notes]
    for finding in skipped:
        applied.append(
            AppliedFix(
                finding.id,
                finding.fingerprint,
                finding.path,
                0,
                f"skipped {finding.path}:{finding.line} {finding.symbol}: dirty_lines",
                "none",
            )
        )
    return applied


def _applied(findings: list[Finding], note: str, verb: str) -> AppliedFix:
    parsed = _parse_note(note, verb)
    if parsed is None:
        return AppliedFix("", "", "", 0, note, "none")
    path, line, symbol = parsed
    finding = next((item for item in findings if item.path == path and item.line == line and item.symbol == symbol), None)
    if finding is None:
        return AppliedFix("", "", path, line, symbol, "safe")
    level = applicability(finding) if finding is not None else "safe"
    if level == "none":
        level = "safe"
    return AppliedFix(finding.id, finding.fingerprint, path, line, symbol, level)


def _parse_note(note: str, verb: str) -> tuple[str, int, str] | None:
    prefix = f"{verb} "
    if not note.startswith(prefix):
        return None
    path_line, separator, symbol = note[len(prefix) :].rpartition(" ")
    if not separator:
        return None
    path, separator, line = path_line.rpartition(":")
    if not separator or not line.isdigit():
        return None
    return path, int(line), symbol


def _previews(
    root: Path,
    findings: list[Finding],
    *,
    unsafe: bool,
    verb: str = "fixed",
    unsafe_fixes: bool = False,
) -> list[tuple[str, str, str, list[str], str]]:
    grouped: dict[str, list[Finding]] = {}
    for finding in findings:
        grouped.setdefault(finding.path, []).append(finding)
    previews: list[tuple[str, str, str, list[str], str]] = []
    for relpath, items in grouped.items():
        path = root / relpath
        if not path.is_file():
            continue
        source, encoding = read_python_source(path)
        updated, edits = rewrite_source(
            source,
            items,
            relpath,
            unsafe=unsafe,
            unsafe_fixes=unsafe_fixes,
            verb=verb,
        )
        if updated == source and not edits:
            continue
        previews.append((relpath, source, updated, edits, encoding))
    return previews


def _import_edits(
    tree: ast.AST,
    source: str,
    findings: list[Finding],
    relpath: str,
    *,
    unsafe: bool,
    verb: str,
    removed: dict[int, tuple[int, int]],
) -> list[tuple[int, int, str, tuple[str, ...]]]:
    groups: dict[tuple[int, int], tuple[ast.Import | ast.ImportFrom, dict[str, int]]] = {}
    imports = [finding for finding in findings if _import_is_editable(finding, relpath, tree, unsafe)]
    for finding in imports:
        node = _import_at(tree, finding.line, finding.symbol)
        if node is None or not _pure_import(source, node):
            continue
        key = (node.lineno, node.end_lineno or node.lineno)
        slot = groups.get(key)
        if slot is None:
            groups[key] = (node, {finding.symbol: finding.line})
        else:
            slot[1][finding.symbol] = finding.line
    edits: list[tuple[int, int, str, tuple[str, ...]]] = []
    lines = source.splitlines(keepends=True)
    for key in sorted(groups):
        node, symbols = groups[key]
        rendered = _render(node, set(symbols))
        if rendered == "skip":
            continue
        start = node.lineno
        end = node.end_lineno or node.lineno
        dropped_lines = _removed_alias_lines(node, set(symbols))
        if rendered is None:
            replacement = ""
            removed[node.lineno] = (start, end)
        else:
            indent = lines[start - 1][: len(lines[start - 1]) - len(lines[start - 1].lstrip(" \t"))]
            comment = _preserved_comments(source, node, dropped_lines)
            line = f"{indent}{rendered}"
            if comment:
                line = f"{line}  {comment}"
            if not line.endswith(("\n", "\r")):
                line += _line_ending(source)
            replacement = line
        notes = tuple(
            f"{verb} {relpath}:{line_number} {symbol}"
            for symbol, line_number in sorted(symbols.items(), key=lambda item: item[1])
        )
        edits.append((start, end, replacement, notes))
    return edits


def _import_at(tree: ast.AST, line: int, symbol: str) -> ast.Import | ast.ImportFrom | None:
    for node in ast.walk(tree):
        if not isinstance(node, ast.Import | ast.ImportFrom):
            continue
        for alias in node.names:
            if alias.name == "*":
                continue
            alias_line = alias.lineno or node.lineno
            if alias_line != line and node.lineno != line:
                continue
            if _alias_symbol(node, alias) == symbol:
                return node
    return None


def _alias_symbol(node: ast.Import | ast.ImportFrom, alias: ast.alias) -> str:
    if isinstance(node, ast.ImportFrom):
        return alias.asname or alias.name
    return alias.asname or alias.name.split(".", 1)[0]


def _render(node: ast.Import | ast.ImportFrom, symbols: set[str]) -> str | None:
    if any(alias.name == "*" for alias in node.names):
        return "skip"
    kept = [alias for alias in node.names if _alias_symbol(node, alias) not in symbols]
    if len(kept) == len(node.names):
        return "skip"
    if not kept:
        return None
    parts = [alias.name if not alias.asname else f"{alias.name} as {alias.asname}" for alias in kept]
    if isinstance(node, ast.Import):
        return "import " + ", ".join(parts)
    dots = "." * (node.level or 0)
    module = node.module or ""
    return f"from {dots}{module} import " + ", ".join(parts)


def _pure_import(source: str, node: ast.Import | ast.ImportFrom) -> bool:
    end = node.end_lineno or node.lineno
    segment = set(range(node.lineno, end + 1))
    chunk = source.splitlines()[node.lineno - 1 : end]
    if any(";" in line for line in chunk):
        return False
    allowed = {",", ".", "(", ")"}
    try:
        tokens = tokenize.generate_tokens(StringIO(source).readline)
        for token in tokens:
            if token.start[0] not in segment:
                continue
            if token.type in {
                tokenize.NEWLINE,
                tokenize.NL,
                tokenize.COMMENT,
                tokenize.INDENT,
                tokenize.DEDENT,
                tokenize.ENDMARKER,
                tokenize.ENCODING,
                tokenize.NAME,
            }:
                continue
            if token.type == tokenize.OP and token.string in allowed:
                continue
            return False
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return False
    return True


def _removed_alias_lines(node: ast.Import | ast.ImportFrom, symbols: set[str]) -> set[int]:
    """Lines whose only imported name is being removed. Comments there go with it."""
    removed: set[int] = set()
    kept: set[int] = set()
    for alias in node.names:
        if alias.name == "*":
            continue
        line = alias.lineno or node.lineno
        if _alias_symbol(node, alias) in symbols:
            removed.add(line)
        else:
            kept.add(line)
    return removed - kept


def _preserved_comments(source: str, node: ast.Import | ast.ImportFrom, dropped_lines: set[int]) -> str:
    """Comments on lines that still belong to the import, in source order."""
    start = node.lineno
    end = node.end_lineno or node.lineno
    found: list[str] = []
    try:
        tokens = tokenize.generate_tokens(StringIO(source).readline)
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return ""
    for token in tokens:
        if token.type != tokenize.COMMENT:
            continue
        line = token.start[0]
        if start <= line <= end and line not in dropped_lines and token.string not in found:
            found.append(token.string)
    return "  ".join(found)


def _statement_edits(
    tree: ast.AST,
    source: str,
    findings: list[Finding],
    relpath: str,
    *,
    verb: str,
    removed: dict[int, tuple[int, int]],
    unsafe_fixes: bool = False,
) -> list[tuple[int, int, str, tuple[str, ...]]]:
    parents = _parents(tree)
    locals_at = {
        (finding.line, finding.symbol)
        for finding in findings
        if finding.rule == "UNUSED_VARIABLE"
        and _nested_name(finding)
        and _rewrite_level(finding, source, unsafe_fixes) != "skip"
    }
    edits: list[tuple[int, int, str, tuple[str, ...]]] = []
    variable_edits: list[tuple[tuple[int, int, str, tuple[str, ...]], int, str]] = []
    for finding in findings:
        if _rewrite_level(finding, source, unsafe_fixes) == "skip":
            continue
        edit: tuple[int, int, str, tuple[str, ...]] | None = None
        if finding.rule == "UNREACHABLE_CODE" and not _sole_yield(source, finding.line):
            edit = _unreachable_edit(tree, parents, source, finding, relpath, verb)
        elif finding.rule == "UNUSED_FUNCTION" and _nested_name(finding):
            edit = _function_edit(tree, parents, source, finding, relpath, verb)
        elif finding.rule == "UNUSED_VARIABLE" and _nested_name(finding):
            edit = _variable_edit(tree, parents, source, finding, locals_at, relpath, verb)
        if edit is None:
            continue
        if finding.rule == "UNUSED_VARIABLE":
            statement = _statement_at(tree, finding.line)
            owner = id(_owner(statement, parents)) if statement is not None else id(tree)
            variable_edits.append((edit, owner, finding.symbol))
            continue
        removed[finding.line] = (edit[0], edit[1])
        edits.append(edit)
    edited_names: dict[int, set[str]] = {}
    for _edit, owner, symbol in variable_edits:
        edited_names.setdefault(owner, set()).add(symbol)
    pinned: dict[int, set[str]] = {}
    del_edits: list[tuple[tuple[int, int, str, tuple[str, ...]], set[str], int]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Delete):
            continue
        names = _plain_delete_names(node)
        if not names:
            continue
        owner = id(_owner(node, parents))
        edited = edited_names.get(owner, set())
        if names <= edited and _private_span(node, parents, source):
            end = node.end_lineno or node.lineno
            label = " ".join(sorted(names))
            edit = (node.lineno, end, "", (f"{verb} {relpath}:{node.lineno} {label}",))
            del_edits.append((edit, names, owner))
        else:
            pinned.setdefault(owner, set()).update(names & edited)
    for edit, owner, symbol in variable_edits:
        if symbol in pinned.get(owner, ()):
            continue
        removed[edit[0]] = (edit[0], edit[1])
        edits.append(edit)
    for edit, names, owner in del_edits:
        if names & pinned.get(owner, set()):
            continue
        removed[edit[0]] = (edit[0], edit[1])
        edits.append(edit)
    return edits


def _sole_yield(source: str, line: int) -> bool:
    """True when `line` holds the only yield in its function."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return False
    parents = _parents(tree)
    match = _statement_at(tree, line)
    if match is None or not _contains_yield(match):
        return False
    function: ast.AST | None = match
    while function is not None and not isinstance(function, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda):
        function = parents.get(function)
    if not isinstance(function, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda):
        return False
    yields = [node for node in ast.walk(function) if isinstance(node, ast.Yield | ast.YieldFrom)]
    return len(yields) == 1


def _contains_yield(node: ast.AST) -> bool:
    return any(isinstance(child, ast.Yield | ast.YieldFrom) for child in ast.walk(node))


def _unreachable_edit(
    tree: ast.AST,
    parents: dict[ast.AST, ast.AST],
    source: str,
    finding: Finding,
    relpath: str,
    verb: str,
) -> tuple[int, int, str, tuple[str, ...]] | None:
    match = _statement_at(tree, finding.line)
    if match is None or not _private_span(match, parents, source):
        return None
    end = match.end_lineno or match.lineno
    return match.lineno, end, "", (f"{verb} {relpath}:{finding.line} {finding.symbol}",)


def _function_edit(
    tree: ast.AST,
    parents: dict[ast.AST, ast.AST],
    source: str,
    finding: Finding,
    relpath: str,
    verb: str,
) -> tuple[int, int, str, tuple[str, ...]] | None:
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        if node.lineno != finding.line or node.name != finding.symbol:
            continue
        if not _private_span(node, parents, source):
            return None
        start = node.lineno
        if node.decorator_list:
            start = min(item.lineno for item in node.decorator_list)
        end = node.end_lineno or node.lineno
        return start, end, "", (f"{verb} {relpath}:{finding.line} {finding.symbol}",)
    return None


def _variable_edit(
    tree: ast.AST,
    parents: dict[ast.AST, ast.AST],
    source: str,
    finding: Finding,
    locals_at: set[tuple[int, str]],
    relpath: str,
    verb: str,
) -> tuple[int, int, str, tuple[str, ...]] | None:
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and node.lineno == finding.line:
            names: list[str] = []
            for target in node.targets:
                found = _target_names(target)
                if found is None:
                    return None
                names.extend(found)
            if finding.symbol not in names:
                continue
            if any((node.lineno, name) not in locals_at for name in names):
                return None
            if _has_effect(node.value) or not _private_span(node, parents, source):
                return None
            end = node.end_lineno or node.lineno
            return node.lineno, end, "", (f"{verb} {relpath}:{finding.line} {finding.symbol}",)
        if isinstance(node, ast.AnnAssign) and node.lineno == finding.line and node.value is not None:
            if not isinstance(node.target, ast.Name) or node.target.id != finding.symbol:
                continue
            if _has_effect(node.value) or not _private_span(node, parents, source):
                return None
            end = node.end_lineno or node.lineno
            return node.lineno, end, "", (f"{verb} {relpath}:{finding.line} {finding.symbol}",)
    return None


def _import_is_editable(finding: Finding, relpath: str, tree: ast.AST, unsafe: bool) -> bool:
    if finding.rule != "UNUSED_IMPORT":
        return False
    protected = _protected_import(finding, relpath, tree)
    if finding.status == "DEAD":
        return unsafe or not protected
    if not unsafe or PROBE_NOTE in finding.evidence:
        return False
    if REEXPORT_NOTE not in finding.evidence and SIDE_EFFECT_NOTE not in finding.evidence:
        return False
    return protected


def _protected_import(finding: Finding, relpath: str, tree: ast.AST) -> bool:
    if _package_init(relpath):
        return True
    node = _import_at(tree, finding.line, finding.symbol)
    if not isinstance(node, ast.Import):
        return False
    for alias in node.names:
        if _alias_symbol(node, alias) == finding.symbol and "." in alias.name:
            return True
    return False


def _package_init(path: str) -> bool:
    name = path.replace("\\", "/")
    return name == "__init__.py" or name.endswith("/__init__.py")


def _apply_edits(
    source: str,
    edits: list[tuple[int, int, str, tuple[str, ...]]],
) -> tuple[str, list[str]]:
    # The wider span wins. An unreachable block is removed whole, instead of a
    # dead assignment inside it leaving the rest of the block behind.
    chosen: list[tuple[int, int, str, tuple[str, ...]]] = []
    occupied: list[tuple[int, int]] = []
    for start, end, replacement, note in sorted(edits, key=lambda item: (item[0], -(item[1]))):
        if any(not (end < used_start or start > used_end) for used_start, used_end in occupied):
            continue
        occupied.append((start, end))
        chosen.append((start, end, replacement, note))
    lines = source.splitlines(keepends=True)
    notes: list[str] = []
    applied: list[tuple[str, ...]] = []
    for start, end, replacement, note in sorted(chosen, key=lambda item: item[0], reverse=True):
        lines = lines[: start - 1] + ([replacement] if replacement else []) + lines[end:]
        applied.append(note)
    for note in reversed(applied):
        notes.extend(note)
    return "".join(lines), notes


def _plain_delete_names(node: ast.Delete) -> set[str] | None:
    """Names in `del a, b`. None when a target is an attribute or subscript."""
    names: list[str] = []
    for target in node.targets:
        found = _target_names(target)
        if found is None:
            return None
        names.extend(found)
    return set(names)


def _owner(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> ast.AST:
    """Function, class, or module that binds names for this statement."""
    current: ast.AST | None = node
    while current is not None and not isinstance(
        current, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda | ast.ClassDef | ast.Module
    ):
        current = parents.get(current)
    return current if current is not None else node


def _parents(tree: ast.AST) -> dict[ast.AST, ast.AST]:
    found: dict[ast.AST, ast.AST] = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            found[child] = node
    return found


def _statement_at(tree: ast.AST, line: int) -> ast.stmt | None:
    found: ast.stmt | None = None
    for node in ast.walk(tree):
        if isinstance(node, ast.stmt) and node.lineno == line:
            if found is None or (node.end_lineno or node.lineno) <= (found.end_lineno or found.lineno):
                found = node
    return found


def _private_span(node: ast.stmt, parents: dict[ast.AST, ast.AST], source: str) -> bool:
    parent = parents.get(node)
    if parent is not None and getattr(parent, "lineno", None) == node.lineno:
        return False
    end = node.end_lineno or node.lineno
    chunk = source.splitlines()[node.lineno - 1 : end]
    return all(";" not in line for line in chunk)


def _target_names(target: ast.expr) -> list[str] | None:
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, ast.Tuple | ast.List):
        names: list[str] = []
        for element in target.elts:
            found = _target_names(element)
            if found is None:
                return None
            names.extend(found)
        return names
    return None


_PURE_VALUE = (ast.Constant, ast.Name, ast.Tuple, ast.List, ast.Dict, ast.Set, ast.Load, ast.Store)


def _has_effect(node: ast.AST) -> bool:
    """True when deleting the value could change behavior or drop a binding."""
    for item in ast.walk(node):
        if isinstance(item, ast.Dict) and any(key is None for key in item.keys):
            return True
        if not isinstance(item, _PURE_VALUE):
            return True
    return False


def _write_python(path: Path, text: str, encoding: str) -> None:
    """Write source in the encoding it was read with, including a BOM when present."""
    path.write_bytes(text.encode(encoding))


def _line_ending(source: str) -> str:
    if "\r\n" in source:
        return "\r\n"
    if "\r" in source:
        return "\r"
    return "\n"


def _keep_suites(
    tree: ast.AST,
    source: str,
    edits: list[tuple[int, int, str, tuple[str, ...]]],
    removed: dict[int, tuple[int, int]],
) -> list[tuple[int, int, str, tuple[str, ...]]]:
    """Insert `pass` when every statement in a non-module suite is being removed."""
    emptied: set[tuple[int, int]] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Module):
            continue
        for suite in _owned_suites(node):
            if suite and all(statement.lineno in removed for statement in suite):
                span = removed.get(suite[0].lineno)
                if span is not None:
                    emptied.add(span)
    if not emptied:
        return edits
    lines = source.splitlines(keepends=True)
    ending = _line_ending(source)
    adjusted: list[tuple[int, int, str, tuple[str, ...]]] = []
    for start, end, replacement, notes in edits:
        if replacement == "" and (start, end) in emptied:
            original = lines[start - 1] if start - 1 < len(lines) else ""
            indent = original[: len(original) - len(original.lstrip(" \t"))]
            replacement = f"{indent}pass{ending}"
        adjusted.append((start, end, replacement, notes))
    return adjusted


def _owned_suites(node: ast.AST) -> list[list[ast.stmt]]:
    suites: list[list[ast.stmt]] = []
    for field in ("body", "orelse", "finalbody"):
        suite = getattr(node, field, None)
        if isinstance(suite, list) and suite and isinstance(suite[0], ast.stmt):
            suites.append(suite)
    for handler in getattr(node, "handlers", ()) or ():
        if handler.body:
            suites.append(handler.body)
    for case in getattr(node, "cases", ()) or ():
        if case.body:
            suites.append(case.body)
    return suites


def _nested_name(finding: Finding) -> bool:
    prefix = f"{finding.rule}:{finding.path}:"
    qualname = finding.fingerprint[len(prefix) :] if finding.fingerprint.startswith(prefix) else finding.symbol
    return "." in qualname


def _rewrite_level(finding: Finding, source: str, unsafe_fixes: bool) -> str:
    level = applicability(finding, source)
    if level == "safe":
        return "safe"
    if level == "unsafe" and unsafe_fixes:
        return "unsafe"
    return "skip"


def split_dirty(
    root: Path,
    findings: list[Finding],
    *,
    unsafe: bool,
    unsafe_fixes: bool,
) -> tuple[list[Finding], list[Finding]]:
    """Drop an edit whose lines are already changed in the worktree."""
    dirty = _worktree_dirty_lines(root)
    if not dirty:
        return list(findings), []
    kept: list[Finding] = []
    skipped: list[Finding] = []
    for finding in findings:
        lines = dirty.get(finding.path.replace("\\", "/"), set())
        if lines and _overlaps_dirty(root, finding, lines, unsafe=unsafe, unsafe_fixes=unsafe_fixes):
            skipped.append(finding)
        else:
            kept.append(finding)
    return kept, skipped


def _overlaps_dirty(
    root: Path,
    finding: Finding,
    dirty_lines: set[int],
    *,
    unsafe: bool,
    unsafe_fixes: bool,
) -> bool:
    if finding.line in dirty_lines:
        return True
    path = root / finding.path
    if not path.is_file():
        return False
    try:
        source, _encoding = read_python_source(path)
    except OSError:
        return False
    updated, _notes = rewrite_source(
        source,
        [finding],
        finding.path,
        unsafe=unsafe,
        unsafe_fixes=unsafe_fixes,
    )
    if updated == source:
        return False
    return bool(_changed_lines(source, updated) & dirty_lines)


def _changed_lines(before: str, after: str) -> set[int]:
    matcher = difflib.SequenceMatcher(a=before.splitlines(), b=after.splitlines())
    lines: set[int] = set()
    for tag, start, end, _j1, _j2 in matcher.get_opcodes():
        if tag == "equal":
            continue
        if start == end:
            lines.add(start + 1)
            continue
        lines.update(range(start + 1, end + 1))
    return lines


def _verify_all(
    root: Path,
    findings: list[Finding],
    skipped: list[Finding],
    *,
    unsafe: bool,
    unsafe_fixes: bool,
    verify_cmd: str,
    timeout: int,
) -> FixReport:
    blocked, snapshots = _snapshot(root, findings, unsafe=unsafe, unsafe_fixes=unsafe_fixes)
    held = [_skip(item, "dirty_lines") for item in skipped] + blocked
    blocked_paths = {item.path for item in blocked}
    writable = [finding for finding in findings if finding.path not in blocked_paths]
    if not snapshots:
        return _report((), held, verified=True, rolled_back=False, failed_step="", output_tail="")
    applied = _write(root, writable, unsafe=unsafe, unsafe_fixes=unsafe_fixes, write=True)
    checked = run_verification(root, list(snapshots), verify_cmd, timeout)
    if checked.ok:
        return _report(_written(applied), held, verified=True, rolled_back=False, failed_step="", output_tail="")
    if not _restore(root, snapshots):
        return _report((), held, verified=False, rolled_back=False, failed_step="restore", output_tail=checked.output)
    return _report((), held, verified=False, rolled_back=True, failed_step=checked.step, output_tail=checked.output)


def _verify_each(
    root: Path,
    findings: list[Finding],
    skipped: list[Finding],
    *,
    unsafe: bool,
    unsafe_fixes: bool,
    verify_cmd: str,
    timeout: int,
) -> FixReport:
    groups: dict[str, list[Finding]] = {}
    for finding in findings:
        groups.setdefault(finding.path, []).append(finding)
    applied: list[AppliedFix] = []
    held = [_skip(item, "dirty_lines") for item in skipped]
    failed_step = ""
    output = ""
    rolled = False
    for items in groups.values():
        blocked, snapshots = _snapshot(root, items, unsafe=unsafe, unsafe_fixes=unsafe_fixes)
        held.extend(blocked)
        if not snapshots:
            continue
        wrote = _write(root, items, unsafe=unsafe, unsafe_fixes=unsafe_fixes, write=True)
        checked = run_verification(root, list(snapshots), verify_cmd, timeout)
        if checked.ok:
            applied.extend(_written(wrote))
            continue
        if not _restore(root, snapshots):
            return _report(applied, held, verified=False, rolled_back=False, failed_step="restore", output_tail=checked.output)
        rolled = True
        failed_step = failed_step or checked.step
        output = output or checked.output
    return _report(applied, held, verified=not rolled, rolled_back=rolled, failed_step=failed_step, output_tail=output)


def _snapshot(
    root: Path,
    findings: list[Finding],
    *,
    unsafe: bool,
    unsafe_fixes: bool,
) -> tuple[list[SkippedFix], dict[str, bytes]]:
    """Original bytes of files a rewrite would change. A failed copy is skipped."""
    blocked: list[SkippedFix] = []
    snapshots: dict[str, bytes] = {}
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    seen: set[str] = set()
    for relpath, source, updated, _edits, _encoding in _previews(
        root,
        findings,
        unsafe=unsafe,
        unsafe_fixes=unsafe_fixes,
    ):
        if source == updated or relpath in snapshots or relpath in seen:
            continue
        path = root / relpath
        try:
            data = path.read_bytes()
        except OSError:
            blocked.extend(_skip(item, "snapshot") for item in findings if item.path == relpath)
            seen.add(relpath)
            continue
        if not _save_backup(root, stamp, relpath, data):
            blocked.extend(_skip(item, "snapshot") for item in findings if item.path == relpath)
            seen.add(relpath)
            continue
        snapshots[relpath] = data
    return blocked, snapshots


def _save_backup(root: Path, stamp: str, relpath: str, data: bytes) -> bool:
    dest = root / ".vyarth" / "backup" / stamp / relpath
    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
    except OSError:
        return False
    return True


def _restore(root: Path, snapshots: dict[str, bytes]) -> bool:
    try:
        for relpath, data in snapshots.items():
            (root / relpath).write_bytes(data)
    except OSError:
        return False
    return True


def _written(applied: list[AppliedFix]) -> list[AppliedFix]:
    return [item for item in applied if item.line > 0]


def _skip(finding: Finding, reason: str) -> SkippedFix:
    return SkippedFix(finding.id, finding.path, finding.line, finding.symbol, reason)


def _report(
    applied: list[AppliedFix] | tuple[AppliedFix, ...],
    skipped: list[SkippedFix],
    *,
    verified: bool,
    rolled_back: bool,
    failed_step: str,
    output_tail: str,
) -> FixReport:
    return FixReport(
        applied=tuple(applied),
        skipped=tuple(skipped),
        verified=verified,
        rolled_back=rolled_back,
        failed_step=failed_step,
        output_tail=output_tail,
    )


def _worktree_dirty_lines(root: Path) -> dict[str, set[int]] | None:
    inside = _git(root, ["git", "rev-parse", "--is-inside-work-tree"])
    if inside is None or inside.strip() != "true":
        return None
    diff = _git(root, ["git", "diff", "-U0", "HEAD"])
    if diff is None:
        return {}
    prefix = (_git(root, ["git", "rev-parse", "--show-prefix"]) or "").strip()
    return _parse_dirty(diff, prefix)


def _parse_dirty(diff: str, prefix: str) -> dict[str, set[int]]:
    found: dict[str, set[int]] = {}
    current = ""
    for line in diff.splitlines():
        if line.startswith("+++ b/"):
            current = line[6:]
            if prefix and current.startswith(prefix):
                current = current[len(prefix) :]
            found.setdefault(current, set())
            continue
        if not line.startswith("@@") or not current:
            continue
        parts = line.split(" ")
        if len(parts) < 3 or not parts[2].startswith("+"):
            continue
        plus = parts[2][1:]
        if "," in plus:
            start_text, count_text = plus.split(",", 1)
            start, count = int(start_text), int(count_text)
        else:
            start, count = int(plus), 1
        bucket = found.setdefault(current, set())
        if count <= 0:
            bucket.add(max(start, 1))
            continue
        bucket.update(range(start, start + count))
    return found


def _git(root: Path, args: list[str]) -> str | None:
    try:
        result = subprocess.run(
            args,
            cwd=root,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
    except OSError:
        return None
    if result.returncode != 0:
        return None
    return result.stdout
