"""Terminal and JSON rendering."""

from __future__ import annotations

import json

from vyarth.model import Finding, ScanResult


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


def render_github(result: ScanResult) -> str:
    lines = [
        f"::error file={finding.path},line={finding.line},title={finding.rule}::{finding.message}"
        for finding in result.findings
    ]
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
                    "fullDescription": {"text": finding.message},
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
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(document, indent=2) + "\n"


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
