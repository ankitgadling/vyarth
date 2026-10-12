"""Rewrite findings that are safe to delete, then let the caller rescan."""

from __future__ import annotations

import ast
import difflib
from io import StringIO
from pathlib import Path
import tokenize

from vyarth.confidence import PROBE_NOTE, REEXPORT_NOTE, SIDE_EFFECT_NOTE
from vyarth.discover import read_python_source
from vyarth.model import Finding


def apply_fixes(
    root: Path,
    findings: list[Finding] | tuple[Finding, ...],
    *,
    unsafe: bool = False,
    write: bool = True,
) -> list[str]:
    """Apply every safe rewrite. Returns a note for each edit."""
    return _write(root, list(findings), unsafe=unsafe, write=write)


def apply_import_fixes(
    root: Path,
    findings: list[Finding] | tuple[Finding, ...],
    *,
    unsafe: bool = False,
    write: bool = True,
) -> list[str]:
    """Remove unused import names. Returns a note for each edit."""
    chosen = [finding for finding in findings if finding.rule == "UNUSED_IMPORT"]
    return _write(root, chosen, unsafe=unsafe, write=write)


def render_fix_diff(
    root: Path,
    findings: list[Finding] | tuple[Finding, ...],
    *,
    unsafe: bool = False,
) -> str:
    """Unified diff of the rewrites. Nothing is written."""
    chunks: list[str] = []
    for relpath, before, after, _, _ in _previews(root, list(findings), unsafe=unsafe):
        chunks.extend(
            difflib.unified_diff(
                before.splitlines(keepends=True),
                after.splitlines(keepends=True),
                fromfile=relpath,
                tofile=relpath,
            )
        )
    return "".join(chunks)


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
    edits.extend(_statement_edits(tree, source, chosen, relpath, verb=verb, removed=removed))
    edits = _keep_suites(tree, source, edits, removed)
    updated, notes = _apply_edits(source, edits)
    try:
        ast.parse(updated)
    except SyntaxError:
        return source, [f"skipped {relpath}: rewrite would not parse"]
    return updated, notes


def _write(root: Path, findings: list[Finding], *, unsafe: bool, write: bool) -> list[str]:
    verb = "fixed" if write else "would fix"
    notes: list[str] = []
    for relpath, source, updated, edits, encoding in _previews(root, findings, unsafe=unsafe, verb=verb):
        if source == updated:
            notes.extend(edits)
            continue
        if not write:
            notes.extend(edits)
            continue
        path = root / relpath
        _write_python(path, updated, encoding)
        notes.extend(edits)
    return notes


def _previews(
    root: Path,
    findings: list[Finding],
    *,
    unsafe: bool,
    verb: str = "fixed",
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
        updated, edits = rewrite_source(source, items, relpath, unsafe=unsafe, verb=verb)
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
        if rendered is None:
            replacement = ""
            removed[node.lineno] = (start, end)
        else:
            indent = lines[start - 1][: len(lines[start - 1]) - len(lines[start - 1].lstrip(" \t"))]
            comment = _trailing_comment(source, node)
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


def _trailing_comment(source: str, node: ast.Import | ast.ImportFrom) -> str:
    end = node.end_lineno or node.lineno
    try:
        tokens = tokenize.generate_tokens(StringIO(source).readline)
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return ""
    for token in tokens:
        if token.type == tokenize.COMMENT and token.start[0] == end:
            return token.string
    return ""


def _statement_edits(
    tree: ast.AST,
    source: str,
    findings: list[Finding],
    relpath: str,
    *,
    verb: str,
    removed: dict[int, tuple[int, int]],
) -> list[tuple[int, int, str, tuple[str, ...]]]:
    parents = _parents(tree)
    locals_at = {
        (finding.line, finding.symbol)
        for finding in findings
        if finding.rule == "UNUSED_VARIABLE" and finding.confidence >= 100 and _nested_name(finding)
    }
    edits: list[tuple[int, int, str, tuple[str, ...]]] = []
    for finding in findings:
        if finding.confidence < 100:
            continue
        edit: tuple[int, int, str, tuple[str, ...]] | None = None
        if finding.rule == "UNREACHABLE_CODE" and not _sole_yield(source, finding.line):
            edit = _unreachable_edit(tree, parents, source, finding, relpath, verb)
        elif finding.rule == "UNUSED_FUNCTION" and _nested_name(finding):
            edit = _function_edit(tree, parents, source, finding, relpath, verb)
        elif finding.rule == "UNUSED_VARIABLE" and _nested_name(finding):
            edit = _variable_edit(tree, parents, source, finding, locals_at, relpath, verb)
        if edit is not None:
            removed[finding.line] = (edit[0], edit[1])
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
    chosen: list[tuple[int, int, str, tuple[str, ...]]] = []
    occupied: list[tuple[int, int]] = []
    for start, end, replacement, note in sorted(edits, key=lambda item: (item[0], -item[1]), reverse=True):
        if any(not (end < used_start or start > used_end) for used_start, used_end in occupied):
            continue
        occupied.append((start, end))
        chosen.append((start, end, replacement, note))
    lines = source.splitlines(keepends=True)
    notes: list[str] = []
    for start, end, replacement, note in chosen:
        lines = lines[: start - 1] + ([replacement] if replacement else []) + lines[end:]
        notes.extend(note)
    notes.reverse()
    return "".join(lines), notes


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
