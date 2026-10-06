"""Rewrite findings that are safe to delete, then let the caller rescan."""

from __future__ import annotations

import ast
from io import StringIO
from pathlib import Path
import tokenize

from vyarth.model import Finding


def apply_fixes(root: Path, findings: list[Finding] | tuple[Finding, ...]) -> list[str]:
    """Apply every safe rewrite. Returns a note for each edit."""
    return _write(root, list(findings))


def apply_import_fixes(root: Path, findings: list[Finding] | tuple[Finding, ...]) -> list[str]:
    """Remove unused import names. Returns a note for each edit."""
    chosen = [
        finding
        for finding in findings
        if finding.rule == "UNUSED_IMPORT" and finding.status == "DEAD"
    ]
    return _write(root, chosen)


def is_fixable(finding: Finding) -> bool:
    """True when a rewrite may delete this finding."""
    if finding.rule == "UNUSED_IMPORT" and finding.status == "DEAD":
        return True
    if finding.confidence < 100:
        return False
    if finding.rule == "UNREACHABLE_CODE":
        return True
    return finding.rule in {"UNUSED_FUNCTION", "UNUSED_VARIABLE"} and _nested_name(finding)


def rewrite_source(source: str, findings: list[Finding] | tuple[Finding, ...], relpath: str) -> tuple[str, list[str]]:
    """Return edited source and a note for each change. The file is not written."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return source, []
    edits = _import_edits(tree, source, list(findings), relpath)
    edits.extend(_statement_edits(tree, source, list(findings), relpath))
    return _apply_edits(source, edits)


def _write(root: Path, findings: list[Finding]) -> list[str]:
    grouped: dict[str, list[Finding]] = {}
    for finding in findings:
        grouped.setdefault(finding.path, []).append(finding)
    notes: list[str] = []
    for relpath, items in grouped.items():
        path = root / relpath
        if not path.is_file():
            continue
        source = path.read_text(encoding="utf-8")
        updated, edits = rewrite_source(source, items, relpath)
        if updated == source:
            continue
        path.write_text(updated, encoding="utf-8")
        notes.extend(edits)
    return notes


def _import_edits(
    tree: ast.AST,
    source: str,
    findings: list[Finding],
    relpath: str,
) -> list[tuple[int, int, str, tuple[str, ...]]]:
    groups: dict[tuple[int, int], tuple[ast.Import | ast.ImportFrom, dict[str, int]]] = {}
    imports = [
        finding
        for finding in findings
        if finding.rule == "UNUSED_IMPORT" and finding.status == "DEAD"
    ]
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
        else:
            indent = lines[start - 1][: len(lines[start - 1]) - len(lines[start - 1].lstrip(" \t"))]
            comment = _trailing_comment(source, node)
            line = f"{indent}{rendered}"
            if comment:
                line = f"{line}  {comment}"
            if not line.endswith("\n"):
                line += "\n"
            replacement = line
        notes = tuple(
            f"fixed {relpath}:{line_number} {symbol}"
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
) -> list[tuple[int, int, str, tuple[str, ...]]]:
    parents = _parents(tree)
    locals_at = {
        (finding.line, finding.symbol)
        for finding in findings
        if finding.rule == "UNUSED_VARIABLE" and finding.confidence >= 100 and _nested_name(finding)
    }
    edits: list[tuple[int, int, str, tuple[str, ...]]] = []
    dead_lines = {
        finding.line
        for finding in findings
        if finding.rule == "UNREACHABLE_CODE" and finding.confidence >= 100
    }
    for finding in findings:
        if finding.confidence < 100:
            continue
        edit: tuple[int, int, str, tuple[str, ...]] | None = None
        if finding.rule == "UNREACHABLE_CODE":
            edit = _unreachable_edit(tree, parents, source, finding, relpath, dead_lines)
        elif finding.rule == "UNUSED_FUNCTION" and _nested_name(finding):
            edit = _function_edit(tree, parents, source, finding, relpath)
        elif finding.rule == "UNUSED_VARIABLE" and _nested_name(finding):
            edit = _variable_edit(tree, parents, source, finding, locals_at, relpath)
        if edit is not None:
            edits.append(edit)
    return edits


def _unreachable_edit(
    tree: ast.AST,
    parents: dict[ast.AST, ast.AST],
    source: str,
    finding: Finding,
    relpath: str,
    dead_lines: set[int],
) -> tuple[int, int, str, tuple[str, ...]] | None:
    match = _statement_at(tree, finding.line)
    if match is None or not _private_span(match, parents, source):
        return None
    end = match.end_lineno or match.lineno
    replacement = ""
    suite = _suite_containing(parents.get(match), match)
    if suite is not None and suite[0] is match and _suite_is_dead(parents.get(match), suite, dead_lines):
        lines = source.splitlines(keepends=True)
        original = lines[match.lineno - 1]
        indent = original[: len(original) - len(original.lstrip(" \t"))]
        replacement = f"{indent}pass\n"
    return match.lineno, end, replacement, (f"fixed {relpath}:{finding.line} {finding.symbol}",)


def _suite_containing(parent: ast.AST | None, node: ast.AST) -> list[ast.stmt] | None:
    if parent is None:
        return None
    for field in ("body", "orelse", "finalbody"):
        suite = getattr(parent, field, None)
        if isinstance(suite, list) and node in suite:
            return suite
    for handler in getattr(parent, "handlers", ()) or ():
        if node in handler.body:
            return handler.body
    for case in getattr(parent, "cases", ()) or ():
        if node in case.body:
            return case.body
    return None


def _suite_is_dead(parent: ast.AST | None, suite: list[ast.stmt], dead_lines: set[int]) -> bool:
    if parent is None or isinstance(parent, ast.Module):
        return False
    return all(getattr(statement, "lineno", None) in dead_lines for statement in suite)


def _function_edit(
    tree: ast.AST,
    parents: dict[ast.AST, ast.AST],
    source: str,
    finding: Finding,
    relpath: str,
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
        return start, end, "", (f"fixed {relpath}:{finding.line} {finding.symbol}",)
    return None


def _variable_edit(
    tree: ast.AST,
    parents: dict[ast.AST, ast.AST],
    source: str,
    finding: Finding,
    locals_at: set[tuple[int, str]],
    relpath: str,
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
            if _has_call(node.value) or not _private_span(node, parents, source):
                return None
            end = node.end_lineno or node.lineno
            return node.lineno, end, "", (f"fixed {relpath}:{finding.line} {finding.symbol}",)
        if isinstance(node, ast.AnnAssign) and node.lineno == finding.line and node.value is not None:
            if not isinstance(node.target, ast.Name) or node.target.id != finding.symbol:
                continue
            if _has_call(node.value) or not _private_span(node, parents, source):
                return None
            end = node.end_lineno or node.lineno
            return node.lineno, end, "", (f"fixed {relpath}:{finding.line} {finding.symbol}",)
    return None


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


def _has_call(node: ast.AST) -> bool:
    return any(isinstance(item, ast.Call | ast.Await) for item in ast.walk(node))


def _nested_name(finding: Finding) -> bool:
    prefix = f"{finding.rule}:{finding.path}:"
    qualname = finding.fingerprint[len(prefix) :] if finding.fingerprint.startswith(prefix) else finding.symbol
    return "." in qualname
