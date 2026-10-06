"""Structurally identical function bodies."""

from __future__ import annotations

from pathlib import Path

from vyarth.discover import is_test_path, relative_posix
from vyarth.model import BodyHash, FileIndex, Finding, make_fingerprint


_MESSAGE = "Function '{name}' duplicates {origin}."


def duplicate_findings(indexes: list[FileIndex], root: Path, minimum: int) -> list[Finding]:
    groups: dict[str, list[tuple[str, BodyHash]]] = {}
    for index in indexes:
        relpath = relative_posix(Path(index.path), root)
        if is_test_path(relpath):
            continue
        for body in index.body_hashes:
            if not body.digest or body.statements == 0 or body.statements < minimum:
                continue
            groups.setdefault(body.digest, []).append((relpath, body))
    findings: list[Finding] = []
    for copies in groups.values():
        if len(copies) < 2:
            continue
        copies.sort(key=lambda item: (item[0], item[1].line, item[1].qualname))
        origin_path, origin = copies[0]
        evidence = f"{origin_path}:{origin.name}"
        for relpath, body in copies[1:]:
            findings.append(
                Finding(
                    rule="DUPLICATE_CODE",
                    path=relpath,
                    line=body.line,
                    column=1,
                    symbol=body.name,
                    status="POSSIBLY_DUPLICATE",
                    confidence=90,
                    message=_MESSAGE.format(name=body.name, origin=evidence),
                    evidence=(evidence,),
                    fingerprint=make_fingerprint("DUPLICATE_CODE", relpath, body.qualname),
                )
            )
    return findings
