"""Comment and path suppression."""

from __future__ import annotations

import ast
import fnmatch
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
_NOQA_CODE = r"[A-Za-z]+[0-9]+"
_NOQA_RE = re.compile(
    rf"noqa\b(?:\s*:\s*({_NOQA_CODE}(?:\s*,\s*{_NOQA_CODE})*))?",
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

    The comment may sit on any line of the import, including a parenthesized
    import. A `# noqa` on the previous line does not apply. Words after the
    code, as in `# noqa: F401 kept for plugins`, are not part of the code.
    """
    lines = _noqa_import_lines(source)
    if not lines:
        return ()
    extra: list[IgnoreDirective] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Import | ast.ImportFrom):
            continue
        start = node.lineno
        end = node.end_lineno or start
        if not any(start <= line <= end for line in lines):
            continue
        for alias in node.names:
            if alias.name == "*":
                continue
            line = alias.lineno if isinstance(alias.lineno, int) else start
            extra.append(IgnoreDirective(line=line, rules=("unused_import",), exact=True))
    return tuple(extra)


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
        if _name_ignored(finding, config.ignore_names):
            continue
        index = indexes.get(finding.path)
        if index is not None and _comment_suppresses(index, finding):
            continue
        kept.append(finding)
    return kept


def _name_ignored(finding: Finding, patterns: tuple[str, ...]) -> bool:
    if not patterns:
        return False
    return any(fnmatch.fnmatchcase(finding.symbol, pattern) for pattern in patterns)


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
