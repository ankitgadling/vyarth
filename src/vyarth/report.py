"""Terminal and JSON rendering."""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import quote

from vyarth.model import Finding, ScanResult
from vyarth.reasons import BRIEF_EVIDENCE


_HELP_URI = "https://github.com/ankitgadling/vyarth/blob/main/docs/rules.md"
_INFORMATION_URI = "https://github.com/ankitgadling/vyarth"
_RULE_TEXT = {
    "UNUSED_IMPORT": "An imported name is never used.",
    "UNUSED_FUNCTION": "A function or method is never used.",
    "UNUSED_CLASS": "A class is never used.",
    "UNUSED_VARIABLE": "A variable is never used.",
    "UNREACHABLE_CODE": "A statement never runs.",
    "POSSIBLY_UNUSED_MODULE": "No entry point imports this module.",
    "WILDCARD_IMPORT": "A wildcard import limits analysis.",
    "ORPHAN_FUNCTION": "A function is referenced, but no entry point reaches it.",
    "UNUSED_DEPENDENCY": "A declared package is never imported.",
    "DUPLICATE_CODE": "A function body duplicates an earlier function.",
}


_LABELS = {
    "UNUSED_IMPORT": "Import",
    "UNUSED_FUNCTION": "Function",
    "UNUSED_CLASS": "Class",
    "UNUSED_VARIABLE": "Variable",
    "UNREACHABLE_CODE": "Statement",
    "POSSIBLY_UNUSED_MODULE": "Module",
    "WILDCARD_IMPORT": "Import",
    "ORPHAN_FUNCTION": "Function",
    "UNUSED_DEPENDENCY": "Package",
    "DUPLICATE_CODE": "Function",
}

_BRIEF_JSONL_OMIT = ("rule_url", "kind", "end_line", "end_column", "qualname", "baselined")

_WITH_REASON = {
    "UNREACHABLE_CODE",
    "POSSIBLY_UNUSED_MODULE",
    "WILDCARD_IMPORT",
    "ORPHAN_FUNCTION",
    "UNUSED_DEPENDENCY",
    "DUPLICATE_CODE",
}


def render_text(result: ScanResult, *, brief_evidence: bool = False) -> str:
    blocks = [_render_finding(finding, brief_evidence=brief_evidence) for finding in result.findings]
    if not blocks:
        return ""
    return "\n\n".join(blocks) + "\n"


def render_json(
    result: ScanResult,
    root: Path | None = None,
    *,
    show_fixes: bool = False,
    applied: list[dict] | None = None,
    brief_evidence: bool = False,
) -> str:
    return result.to_json(root=root, show_fixes=show_fixes, applied=applied, brief_evidence=brief_evidence)


def render_jsonl(
    result: ScanResult,
    root: Path | None = None,
    *,
    show_fixes: bool = False,
    applied: list[dict] | None = None,
    brief_evidence: bool = True,
) -> str:
    report = result.to_report(
        root=root,
        show_fixes=show_fixes,
        applied=applied,
        brief_evidence=brief_evidence,
    )
    lines = [
        json.dumps(_jsonl_row(finding, brief_evidence), separators=(",", ":"))
        for finding in report["findings"]
    ]
    summary = {"type": "summary", **report["summary"]}
    if applied is not None:
        summary["applied"] = report["applied"]
    lines.append(json.dumps(summary, separators=(",", ":")))
    return "\n".join(lines) + "\n"


def render_concise(result: ScanResult, *, confidence: bool = False) -> str:
    lines = []
    for finding in result.findings:
        line = f"{finding.path}:{finding.line}:{finding.column}: {finding.rule} {finding.message}"
        if confidence:
            line = f"{line} [{finding.confidence}]"
        lines.append(line)
    if not lines:
        return ""
    return "\n".join(lines) + "\n"


def render_github(result: ScanResult, root: Path | None = None) -> str:
    prefix = _github_prefix(root)
    lines = []
    for finding in result.findings:
        level = "error" if finding.confidence >= 90 else "warning"
        path = _escape_property(f"{prefix}{finding.path}")
        title = _escape_property(finding.rule)
        message = _escape_message(finding.message)
        lines.append(f"::{level} file={path},line={finding.line},title={title}::{message}")
    if not lines:
        return ""
    return "\n".join(lines) + "\n"


def render_sarif(
    result: ScanResult,
    root: Path | None = None,
    *,
    show_fixes: bool = False,
    brief_evidence: bool = False,
) -> str:
    from vyarth import __version__

    prefix = _github_prefix(root)
    sources: dict[str, str] = {}
    ends = {}
    if root is not None:
        ends = {row["fingerprint"]: row["end_line"] for row in result.to_report(root=root)["findings"]}
    rules = []
    seen: set[str] = set()
    results = []
    for finding in result.findings:
        if finding.rule not in seen:
            seen.add(finding.rule)
            rules.append(
                {
                    "id": finding.rule,
                    "shortDescription": {"text": finding.rule},
                    "fullDescription": {"text": _RULE_TEXT.get(finding.rule, finding.rule)},
                    "helpUri": f"{_HELP_URI}#{finding.rule.lower()}",
                }
            )
        end_line = ends.get(finding.fingerprint) or finding.line
        result_row: dict = {
            "ruleId": finding.rule,
            "level": "error" if finding.confidence >= 90 else "warning",
            "rank": finding.confidence,
            "message": {"text": finding.message},
            "partialFingerprints": {"vyarth/fingerprint": finding.fingerprint},
            "properties": {
                "confidence": finding.confidence,
                "reasons": list(finding.reasons),
                "evidence": _visible_evidence(finding, brief_evidence),
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": quote(f"{prefix}{finding.path}", safe="/"),
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": finding.line,
                            "startColumn": _sarif_column(root, finding, sources),
                            "endLine": end_line,
                        },
                    }
                }
            ],
        }
        if show_fixes and root is not None:
            from vyarth.fix import applicability, fix_edits

            if applicability(finding) == "safe":
                edits = fix_edits(root, finding)
                if edits:
                    result_row["fixes"] = [
                        {
                            "description": {"text": "Remove unused code"},
                            "artifactChanges": [
                                {
                                    "artifactLocation": {"uri": quote(f"{prefix}{finding.path}", safe="/")},
                                    "replacements": [
                                        {
                                            "deletedRegion": {
                                                "startLine": edit["location"]["row"],
                                                "endLine": edit["end_location"]["row"],
                                            },
                                            "insertedContent": {"text": edit["content"]},
                                        }
                                        for edit in edits
                                    ],
                                }
                            ],
                        }
                    ]
        results.append(result_row)
    document = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "vyarth",
                        "version": __version__,
                        "informationUri": _INFORMATION_URI,
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(document, indent=2) + "\n"


def utf16_column(source: str, line: int, column: int) -> int:
    """Convert an ast UTF-8 byte column to a 1-based UTF-16 code unit."""
    if column <= 1 or line < 1:
        return max(column, 1)
    lines = source.splitlines()
    if line > len(lines):
        return column
    raw = lines[line - 1].encode("utf-8")
    prefix = raw[: column - 1]
    try:
        decoded = prefix.decode("utf-8")
    except UnicodeDecodeError:
        decoded = prefix.decode("utf-8", errors="ignore")
    return len(decoded.encode("utf-16-le")) // 2 + 1


def _sarif_column(root: Path | None, finding: Finding, sources: dict[str, str]) -> int:
    if root is None:
        return finding.column
    source = sources.get(finding.path)
    if source is None:
        file = root / finding.path
        try:
            from vyarth.discover import read_python_source

            source, _ = read_python_source(file)
        except OSError:
            source = ""
        sources[finding.path] = source
    if not source:
        return finding.column
    return utf16_column(source, finding.line, finding.column)


def _github_prefix(root: Path | None) -> str:
    if root is None:
        return ""
    from vyarth.incremental import _git_prefix

    try:
        return _git_prefix(root)
    except (OSError, RuntimeError):
        return ""


def _escape_property(value: str) -> str:
    return (
        value.replace("%", "%25")
        .replace("\r", "%0D")
        .replace("\n", "%0A")
        .replace(":", "%3A")
        .replace(",", "%2C")
    )


def _escape_message(value: str) -> str:
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _render_finding(finding: Finding, *, brief_evidence: bool = False) -> str:
    label = _LABELS.get(finding.rule, "Symbol")
    lines = [
        finding.rule,
        f"File: {finding.path}",
        f"Line: {finding.line}",
        f"{label}: {finding.symbol}",
        f"Confidence: {finding.confidence}%",
    ]
    if finding.rule in _WITH_REASON and finding.message:
        lines.append(f"Reason: {finding.message}")
    for item in _visible_evidence(finding, brief_evidence):
        lines.append(f"Evidence: {item}")
    return "\n".join(lines)


def _jsonl_row(finding: dict, brief: bool) -> dict:
    """jsonl drops fields a caller can derive, so a 50-line window stays small."""
    if not brief:
        return finding
    row = {key: value for key, value in finding.items() if key not in _BRIEF_JSONL_OMIT}
    fix = row.get("fix")
    if isinstance(fix, dict) and fix.get("applicability") == "none" and "edits" not in fix:
        row.pop("fix")
    return row


def _visible_evidence(finding: Finding, brief: bool) -> list[str]:
    if not brief:
        return list(finding.evidence)
    return [item for item in finding.evidence if item not in BRIEF_EVIDENCE]
