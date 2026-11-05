"""One finding, with the evidence a review needs."""

from __future__ import annotations

import json
from pathlib import Path, PurePosixPath
import re

from vyarth.config import Config
from vyarth.discover import discover_scan, read_python_source, relative_posix
from vyarth.fix import applicability, render_fix_diff
from vyarth.model import Finding, IdError


_SAMPLE_LIMIT = 5


def locate(findings: tuple[Finding, ...] | list[Finding], selector: str) -> Finding:
    """One finding named by an id, a fingerprint, or `path:line`."""
    exact = [item for item in findings if item.id == selector or item.fingerprint == selector]
    if len(exact) > 1:
        raise IdError(f"ambiguous id: {selector}")
    if len(exact) == 1:
        return exact[0]
    path_line = _path_line(selector)
    if path_line is not None:
        path, line = path_line
        matches = [item for item in findings if item.path == path and item.line == line]
        if len(matches) > 1:
            raise IdError(f"ambiguous id: {selector}")
        if len(matches) == 1:
            return matches[0]
    prefix = [item for item in findings if selector and item.id.startswith(selector)]
    if len(prefix) > 1:
        raise IdError(f"ambiguous id: {selector}")
    if len(prefix) == 1:
        return prefix[0]
    raise IdError(f"unknown id: {selector}")


def explain_payload(root: Path, config: Config, finding: Finding) -> dict[str, object]:
    source = _source(root, finding.path)
    level = applicability(finding, source)
    diff = render_fix_diff(root, [finding]) if level == "safe" else ""
    count, sample = incoming_references(root, config, finding)
    slug = finding.rule.lower().replace("_", "-")
    return {
        "finding": {
            "id": finding.id,
            "fingerprint": finding.fingerprint,
            "rule": finding.rule,
            "path": finding.path,
            "line": finding.line,
            "column": finding.column,
            "symbol": finding.symbol,
            "status": finding.status,
            "confidence": finding.confidence,
            "message": finding.message,
        },
        "reasons": list(finding.reasons),
        "evidence": list(finding.evidence),
        "references": {"count": count, "sample": sample},
        "suppress": {
            "inline": f"# vyarth: ignore[{slug}]",
            "baseline_cmd": "vyarth baseline . --output vyarth-baseline.json",
            "allow_toml": f'ignore = ["{finding.path}"]',
        },
        "fix": {"applicability": level, "diff": diff},
        "guidance": guidance_for(finding),
    }


def render_explain(payload: dict[str, object], fmt: str) -> str:
    if fmt == "json":
        return json.dumps(payload, indent=2) + "\n"
    finding = payload["finding"]
    assert isinstance(finding, dict)
    reasons = payload["reasons"]
    evidence = payload["evidence"]
    references = payload["references"]
    suppress = payload["suppress"]
    fix = payload["fix"]
    assert isinstance(reasons, list)
    assert isinstance(evidence, list)
    assert isinstance(references, dict)
    assert isinstance(suppress, dict)
    assert isinstance(fix, dict)
    lines = [
        f"{finding['rule']} {finding['path']}:{finding['line']}:{finding['column']} {finding['symbol']}",
        f"id: {finding['id']}",
        f"fingerprint: {finding['fingerprint']}",
        f"confidence: {finding['confidence']}",
        f"status: {finding['status']}",
        "reasons: " + ", ".join(str(item) for item in reasons),
        "evidence:",
    ]
    lines.extend(f"  {item}" for item in evidence)
    lines.append(f"references: {references['count']}")
    sample = references["sample"]
    if isinstance(sample, list):
        lines.extend(f"  {item}" for item in sample)
    lines.append(f"suppress: {suppress['inline']}")
    lines.append(f"baseline: {suppress['baseline_cmd']}")
    lines.append(f"allow: {suppress['allow_toml']}")
    lines.append(f"fix: {fix['applicability']}")
    diff = fix.get("diff") or ""
    if diff:
        lines.append("diff:")
        lines.append(str(diff).rstrip("\n"))
    lines.append(f"guidance: {payload['guidance']}")
    return "\n".join(lines) + "\n"


def incoming_references(root: Path, config: Config, finding: Finding) -> tuple[int, list[str]]:
    """Other lines that spell this name. A dead name should have none."""
    needle = _needle(finding)
    if not needle.isidentifier():
        return 0, []
    pattern = re.compile(rf"\b{re.escape(needle)}\b")
    files, _manifests = discover_scan(root, config)
    count = 0
    sample: list[str] = []
    for file in files:
        relpath = relative_posix(file, root)
        try:
            text, _encoding = read_python_source(file)
        except (OSError, UnicodeDecodeError):
            continue
        for number, line in enumerate(text.splitlines(), start=1):
            if relpath == finding.path and number == finding.line:
                continue
            if pattern.search(line) is None:
                continue
            count += 1
            if len(sample) < _SAMPLE_LIMIT:
                sample.append(f"{relpath}:{number}: {line.strip()}")
    return count, sample


def guidance_for(finding: Finding) -> str:
    path = finding.path.replace("\\", "/")
    parts = path.split("/")
    score = finding.confidence
    if "migrations" in parts and score >= 90:
        return f"confidence {score} on a migration file: verify before deleting"
    if score >= 90 and (path.endswith(("settings.py", "_settings.py", "conf.py")) or "settings" in parts):
        return f"confidence {score} on a settings file: verify before deleting"
    if 90 <= score <= 99:
        return f"confidence {score}: review before deleting"
    if score == 100:
        return "confidence 100: static analysis shows this is unused"
    return f"confidence {score}: static analysis cannot prove this is unused"


def _needle(finding: Finding) -> str:
    if finding.rule != "POSSIBLY_UNUSED_MODULE":
        return finding.symbol
    path = PurePosixPath(finding.path)
    if path.stem == "__init__":
        return path.parent.name
    return path.stem


def _path_line(selector: str) -> tuple[str, int] | None:
    path, separator, line = selector.rpartition(":")
    if not separator or not path or not line.isdigit():
        return None
    return path, int(line)


def _source(root: Path, relpath: str) -> str | None:
    path = root / relpath
    if not path.is_file():
        return None
    try:
        text, _encoding = read_python_source(path)
    except OSError:
        return None
    return text
