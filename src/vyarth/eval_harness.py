"""Scripted agent eval. It deletes only confidence-100 safe fixes and scores the result."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

from vyarth.fix import applicability, apply_fixes_verified
from vyarth.model import Finding
from vyarth.engine import scan


_APP = """import json
import os

def keep():
    return json.dumps({"ok": True})

def spare():
    return 1

if __name__ == "__main__":
    print(keep())
"""
_LIVE = ("def keep", "def spare", "import json")
_DEAD = ("import os",)


def run_builtin() -> dict[str, object]:
    """Score the built-in fixture, plus any labeled roots in VYARTH_EVAL_ROOTS."""
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / "app.py").write_text(_APP, encoding="utf-8")
        tasks: list[tuple[str, Path, tuple[str, ...] | list[str], tuple[str, ...] | list[str]]] = [
            ("fixture", root, _LIVE, _DEAD)
        ]
        tasks.extend(_labeled_roots())
        reports = [
            _measure(surface, name, source, live, dead)
            for name, source, live, dead in tasks
            for surface in ("json", "window", "mcp")
        ]
    wrong = 0
    for item in reports:
        count = item["wrong_deletions"]
        if isinstance(count, int):
            wrong += count
    return {"wrong_deletions": wrong, "precision": "not measured", "tasks": reports}


def _measure(
    surface: str,
    name: str,
    source: Path,
    live: tuple[str, ...] | list[str],
    dead: tuple[str, ...] | list[str],
) -> dict[str, object]:
    with tempfile.TemporaryDirectory() as directory:
        work = Path(directory)
        _copy(source, work)
        started = time.perf_counter()
        if surface == "mcp":
            tokens, rollbacks = _mcp(work)
        else:
            tokens, rollbacks = _library(work, surface)
        seconds = round(time.perf_counter() - started, 3)
        corpus = _corpus(work)
    wrong = [item for item in live if item not in corpus]
    correct = [item for item in dead if item not in corpus]
    return {
        "repo": name,
        "surface": surface,
        "wrong_deletions": len(wrong),
        "correct_deletions": len(correct),
        "tokens": tokens,
        "rollbacks": rollbacks,
        "seconds": seconds,
    }


def _library(root: Path, surface: str) -> tuple[int, int]:
    if surface == "window":
        result = scan(root, min_confidence=0, max_findings=50, sort="confidence")
    else:
        result = scan(root, min_confidence=0)
    tokens = len(result.to_json(root=root)) // 4
    report = apply_fixes_verified(root, _safe(root, result.findings), verify_cmd="")
    return tokens, 1 if report.rolled_back else 0


def _safe(root: Path, findings: tuple[Finding, ...] | list[Finding]) -> list[Finding]:
    chosen: list[Finding] = []
    for finding in findings:
        if finding.confidence != 100 or finding.status != "DEAD":
            continue
        if applicability(finding, _read(root, finding.path)) == "safe":
            chosen.append(finding)
    return chosen


def _mcp(root: Path) -> tuple[int, int]:
    env = os.environ.copy()
    src = str(Path(__file__).resolve().parents[1])
    env["PYTHONPATH"] = src + os.pathsep + env.get("PYTHONPATH", "")
    process = subprocess.Popen(
        [sys.executable, "-m", "vyarth", "mcp", "--root", str(root)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        encoding="utf-8",
        env=env,
    )
    assert process.stdin is not None
    assert process.stdout is not None
    try:
        blobs: list[str] = []
        blobs.append(_rpc(process, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-11-25"}}))
        process.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
        process.stdin.flush()
        scanned = json.loads(
            _rpc(
                process,
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {
                        "name": "scan",
                        "arguments": {"min_confidence": 0, "max_findings": 50, "sort": "confidence"},
                    },
                },
            )
        )
        blobs.append(json.dumps(scanned))
        findings = scanned["result"]["structuredContent"]["findings"]
        ids = [
            item["id"]
            for item in findings
            if item["confidence"] == 100 and item["status"] == "DEAD" and item["fix"]["applicability"] == "safe"
        ]
        rollbacks = 0
        if ids:
            applied = json.loads(
                _rpc(
                    process,
                    {
                        "jsonrpc": "2.0",
                        "id": 3,
                        "method": "tools/call",
                        "params": {"name": "apply_fix", "arguments": {"ids": ids, "verify": True}},
                    },
                )
            )
            blobs.append(json.dumps(applied))
            if applied["result"]["structuredContent"].get("rolled_back"):
                rollbacks = 1
        return len("".join(blobs)) // 4, rollbacks
    finally:
        process.stdin.close()
        process.wait(timeout=30)


def _rpc(process: subprocess.Popen[str], message: dict[str, object]) -> str:
    assert process.stdin is not None
    assert process.stdout is not None
    process.stdin.write(json.dumps(message) + "\n")
    process.stdin.flush()
    line = process.stdout.readline()
    if not line:
        raise RuntimeError("mcp server closed stdout")
    return line


def _labeled_roots() -> list[tuple[str, Path, list[str], list[str]]]:
    raw = os.environ.get("VYARTH_EVAL_ROOTS", "")
    found: list[tuple[str, Path, list[str], list[str]]] = []
    for item in raw.split(os.pathsep):
        if not item.strip():
            continue
        root = Path(item)
        labels = root / "vyarth-eval.json"
        if not root.is_dir() or not labels.is_file():
            continue
        data = json.loads(labels.read_text(encoding="utf-8"))
        found.append((root.name, root, list(data.get("live", [])), list(data.get("dead", []))))
    return found


def _copy(source: Path, dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    for path in source.rglob("*"):
        if ".vyarth" in path.parts or not path.is_file():
            continue
        target = dest / path.relative_to(source)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)


def _corpus(root: Path) -> str:
    parts: list[str] = []
    for path in sorted(root.rglob("*.py")):
        if ".vyarth" in path.parts:
            continue
        parts.append(path.read_text(encoding="utf-8", errors="replace"))
    return "\n".join(parts)


def _read(root: Path, relpath: str) -> str | None:
    path = root / relpath
    if not path.is_file():
        return None
    return path.read_text(encoding="utf-8", errors="replace")
