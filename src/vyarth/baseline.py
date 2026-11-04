"""Fingerprint baselines. A scan keeps only findings the file does not already list."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
import json
from pathlib import Path

from vyarth.model import Finding


@dataclass(frozen=True)
class BaselineEntry:
    fingerprint: str
    rule: str = ""
    path: str = ""
    symbol: str = ""
    id: str = ""
    reason: str = ""
    added: str = ""


def write_baseline(
    path: str | Path,
    findings: list[Finding] | tuple[Finding, ...],
    *,
    reason: str = "",
) -> None:
    today = date.today().isoformat()
    entries = [
        BaselineEntry(
            fingerprint=finding.fingerprint,
            rule=finding.rule,
            path=finding.path,
            symbol=finding.symbol,
            id=finding.id,
            reason=reason,
            added=today,
        )
        for finding in sorted(findings, key=lambda finding: finding.fingerprint)
    ]
    _write(path, entries)


def load_baseline(path: str | Path) -> set[str]:
    return {entry.fingerprint for entry in load_entries(path)}


def filter_baselined(findings: list[Finding], known: set[str]) -> list[Finding]:
    return [finding for finding in findings if finding.fingerprint not in known]


def load_entries(path: str | Path) -> list[BaselineEntry]:
    target = Path(path)
    data = json.loads(target.read_text(encoding="utf-8"))
    rows = data.get("findings", []) if isinstance(data, dict) else None
    if not isinstance(rows, list):
        raise ValueError(f"baseline must contain a findings list: {target}")
    entries: list[BaselineEntry] = []
    for row in rows:
        if isinstance(row, str):
            entries.append(BaselineEntry(fingerprint=row))
            continue
        if isinstance(row, dict) and isinstance(row.get("fingerprint"), str):
            entries.append(
                BaselineEntry(
                    fingerprint=row["fingerprint"],
                    rule=_text(row.get("rule")),
                    path=_text(row.get("path")),
                    symbol=_text(row.get("symbol")),
                    id=_text(row.get("id")),
                    reason=_text(row.get("reason")),
                    added=_text(row.get("added")),
                )
            )
            continue
        raise ValueError(f"baseline finding is missing a fingerprint: {target}")
    return entries


def append_baseline(
    path: str | Path,
    findings: list[Finding] | tuple[Finding, ...],
    reason: str,
) -> tuple[int, int]:
    """Add findings that are not already listed. Adding the same id twice changes nothing."""
    target = Path(path)
    existing = load_entries(target) if target.is_file() else []
    known = {item.fingerprint for item in existing}
    today = date.today().isoformat()
    added = 0
    rows = list(existing)
    for finding in findings:
        if finding.fingerprint in known:
            continue
        known.add(finding.fingerprint)
        rows.append(
            BaselineEntry(
                fingerprint=finding.fingerprint,
                rule=finding.rule,
                path=finding.path,
                symbol=finding.symbol,
                id=finding.id,
                reason=reason,
                added=today,
            )
        )
        added += 1
    rows.sort(key=lambda item: item.fingerprint)
    _write(target, rows)
    return added, len(rows)


def prune_baseline(path: str | Path, findings: list[Finding] | tuple[Finding, ...]) -> tuple[int, int]:
    """Drop entries the current scan does not report. Returns the removed count and the new total."""
    existing = load_entries(path)
    live = {item.fingerprint for item in findings}
    kept = [item for item in existing if item.fingerprint in live]
    _write(path, kept)
    return len(existing) - len(kept), len(kept)


def _write(path: str | Path, entries: list[BaselineEntry]) -> None:
    records = [
        {
            "fingerprint": item.fingerprint,
            "id": item.id,
            "rule": item.rule,
            "path": item.path,
            "symbol": item.symbol,
            "reason": item.reason,
            "added": item.added,
        }
        for item in entries
    ]
    Path(path).write_text(json.dumps({"version": 2, "findings": records}, indent=2) + "\n", encoding="utf-8")


def _text(value: object) -> str:
    return value if isinstance(value, str) else ""
