"""Terminal and JSON rendering."""

from __future__ import annotations

import json
from pathlib import Path

from vyarth.model import Finding, ScanResult


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

_WITH_REASON = {
    "UNREACHABLE_CODE",
    "POSSIBLY_UNUSED_MODULE",
    "WILDCARD_IMPORT",
    "ORPHAN_FUNCTION",
    "UNUSED_DEPENDENCY",
    "DUPLICATE_CODE",
}


def render_text(result: ScanResult) -> str:
    blocks = [_render_finding(finding) for finding in result.findings]
    if not blocks:
        return ""
    return "\n\n".join(blocks) + "\n"


def render_json(result: ScanResult) -> str:
    return result.to_json()


def render_concise(result: ScanResult) -> str:
    lines = [
        f"{finding.path}:{finding.line}:{finding.column}: {finding.rule} {finding.message}"
        for finding in result.findings
    ]
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


def render_sarif(result: ScanResult) -> str:
    from vyarth import __version__

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
                    "helpUri": _HELP_URI,
                }
            )
        results.append(
            {
                "ruleId": finding.rule,
                "level": "error" if finding.confidence >= 90 else "warning",
                "message": {"text": finding.message},
                "partialFingerprints": {"vyarth/fingerprint": finding.fingerprint},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.path},
                            "region": {"startLine": finding.line, "startColumn": finding.column},
                        }
                    }
                ],
            }
        )
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


def _render_finding(finding: Finding) -> str:
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
    for item in finding.evidence:
        lines.append(f"Evidence: {item}")
    return "\n".join(lines)
