"""Comment and path suppression."""

from __future__ import annotations

import ast
from io import StringIO
import re
import tokenize

import pathspec

from vyarth.config import Config
from vyarth.model import FileIndex, Finding, IgnoreDirective


_IGNORE_RE = re.compile(
    r"vyarth\s*:\s*ignore(?:\s*\[\s*([^\]]*?)\s*\])?",
    re.IGNORECASE,
)
_NOQA_RE = re.compile(
    r"noqa\b(?:\s*:\s*([A-Za-z0-9_,\s]+))?",
    re.IGNORECASE,
)


def normalize_rule(rule: str) -> str:
    return rule.strip().lower().replace("-", "_")


def collect_ignores(source: str) -> tuple[IgnoreDirective, ...]:
    """Map `# vyarth: ignore` comments to the line they occupy."""
    directives: list[IgnoreDirective] = []
    try:
        tokens = tokenize.generate_tokens(StringIO(source).readline)
        for token in tokens:
            if token.type != tokenize.COMMENT:
                continue
            match = _IGNORE_RE.search(token.string)
            if match is None:
                continue
            raw_rules = match.group(1)
            if raw_rules is None:
                rules = None
            else:
                rules = tuple(
                    normalize_rule(part)
                    for part in raw_rules.split(",")
                    if part.strip()
                )
            directives.append(IgnoreDirective(line=token.start[0], rules=rules))
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return ()
    return tuple(directives)


def import_noqa_ignores(tree: ast.AST, source: str) -> tuple[IgnoreDirective, ...]:
    """`# noqa` and `# noqa: F401` suppress unused imports on that statement.

    The comment may sit on the import line, on any line of a parenthesized
    import, or on the line immediately above the statement.
    """
    lines = _noqa_import_lines(source)
    if not lines:
        return ()
    spans = [
        (node.lineno, node.end_lineno or node.lineno)
        for node in ast.walk(tree)
        if isinstance(node, ast.Import | ast.ImportFrom)
    ]
    extra: list[IgnoreDirective] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Import | ast.ImportFrom):
            continue
        start = node.lineno
        end = node.end_lineno or start
        if not _noqa_covers_import(start, end, lines, spans):
            continue
        for alias in node.names:
            if alias.name == "*":
                continue
            line = alias.lineno if isinstance(alias.lineno, int) else start
            extra.append(IgnoreDirective(line=line, rules=("unused_import",), exact=True))
    return tuple(extra)


def _noqa_covers_import(start: int, end: int, lines: set[int], spans: list[tuple[int, int]]) -> bool:
    for line in lines:
        if start <= line <= end:
            return True
        # A noqa on the previous line belongs to this import only when that
        # line is not already inside another import statement.
        if line == start - 1 and not any(span_start <= line <= span_end for span_start, span_end in spans):
            return True
    return False


def _noqa_import_lines(source: str) -> set[int]:
    found: set[int] = set()
    try:
        tokens = tokenize.generate_tokens(StringIO(source).readline)
        for token in tokens:
            if token.type != tokenize.COMMENT:
                continue
            match = _NOQA_RE.search(token.string)
            if match is None:
                continue
            codes = match.group(1)
            if codes is None or "F401" in {part.strip().upper() for part in codes.split(",") if part.strip()}:
                found.add(token.start[0])
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return set()
    return found


def expand_decorator_ignores(tree: ast.AST, directives: tuple[IgnoreDirective, ...]) -> tuple[IgnoreDirective, ...]:
    """Copy a comment above a decorator onto the def or class line it belongs to."""
    if not directives:
        return directives
    anchors: list[tuple[int, int]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            continue
        if not node.decorator_list:
            continue
        first = min(decorator.lineno for decorator in node.decorator_list)
        anchors.append((first, node.lineno))
    extra: list[IgnoreDirective] = []
    for directive in directives:
        for first, statement_line in anchors:
            on_decorator = first <= directive.line < statement_line
            directly_above = directive.line + 1 == first
            if on_decorator or directly_above:
                extra.append(IgnoreDirective(line=statement_line, rules=directive.rules))
    if not extra:
        return directives
    return directives + tuple(extra)


def apply_ignores(
    findings: list[Finding],
    indexes: dict[str, FileIndex],
    config: Config,
) -> list[Finding]:
    path_spec = pathspec.GitIgnoreSpec.from_lines(config.ignore)
    kept: list[Finding] = []
    for finding in findings:
        if path_spec.match_file(finding.path):
            continue
        index = indexes.get(finding.path)
        if index is not None and _comment_suppresses(index, finding):
            continue
        kept.append(finding)
    return kept


def _comment_suppresses(index: FileIndex, finding: Finding) -> bool:
    rule = normalize_rule(finding.rule)
    for directive in index.ignores:
        if directive.exact:
            if directive.line != finding.line:
                continue
        elif directive.line != finding.line and directive.line != finding.line - 1:
            continue
        if directive.rules is None or rule in directive.rules:
            return True
    return False
