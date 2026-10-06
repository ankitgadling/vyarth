"""Fingerprint baselines. A scan keeps only findings the file does not already list."""

from __future__ import annotations

import json
from pathlib import Path

from vyarth.model import Finding


def write_baseline(path: str | Path, findings: list[Finding] | tuple[Finding, ...]) -> None:
    target = Path(path)
    records = [
        {
            "fingerprint": finding.fingerprint,
            "rule": finding.rule,
            "path": finding.path,
            "symbol": finding.symbol,
        }
        for finding in sorted(findings, key=lambda finding: finding.fingerprint)
    ]
    payload = {"findings": records}
    target.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def load_baseline(path: str | Path) -> set[str]:
    target = Path(path)
    data = json.loads(target.read_text(encoding="utf-8"))
    rows = data.get("findings", []) if isinstance(data, dict) else None
    if not isinstance(rows, list):
        raise ValueError(f"baseline must contain a findings list: {target}")
    fingerprints: set[str] = set()
    for row in rows:
        if isinstance(row, dict) and isinstance(row.get("fingerprint"), str):
            fingerprints.add(row["fingerprint"])
        elif isinstance(row, str):
            fingerprints.add(row)
        else:
            raise ValueError(f"baseline finding is missing a fingerprint: {target}")
    return fingerprints


def filter_baselined(findings: list[Finding], known: set[str]) -> list[Finding]:
    return [finding for finding in findings if finding.fingerprint not in known]
