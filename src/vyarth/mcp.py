"""Newline-delimited MCP server. JSON-RPC goes to stdout. Logs go to stderr."""

from __future__ import annotations

import json
from pathlib import Path
import sys
from typing import Any, TextIO

from vyarth import __version__
from vyarth.baseline import append_baseline
from vyarth.config import load_config
from vyarth.discover import read_python_source, relative_posix
from vyarth.explain import explain_payload, locate
from vyarth.fix import applicability, apply_fixes, apply_fixes_verified, render_fix_diff, split_dirty
from vyarth.model import Finding, ScanResult, resolve_ids
from vyarth.present import RULES, canonical_rules
from vyarth.session import cached_scan


_VERSIONS = {"2025-06-18", "2025-11-25", "2026-07-28"}
_DEFAULT_VERSION = "2025-11-25"
_WRITE_TOOLS = {"apply_fix", "add_to_baseline"}
_HELP = "https://github.com/ankitgadling/vyarth/blob/main/docs/rules.md"
_FIXABLE = {"UNUSED_IMPORT", "UNUSED_FUNCTION", "UNUSED_VARIABLE", "UNREACHABLE_CODE"}
_BLURB = {
    "UNUSED_IMPORT": "Import name never loaded.",
    "UNUSED_FUNCTION": "Function or method never loaded.",
    "UNUSED_CLASS": "Class never loaded.",
    "UNUSED_VARIABLE": "Variable never read.",
    "UNREACHABLE_CODE": "Statement after an exit.",
    "ORPHAN_FUNCTION": "Referenced, but no entry point reaches it.",
    "POSSIBLY_UNUSED_MODULE": "No entry module can import this file.",
    "WILDCARD_IMPORT": "A wildcard import limits analysis.",
    "UNUSED_DEPENDENCY": "Declared package with no import.",
    "DUPLICATE_CODE": "Function body matches another function.",
    "UNUSED_IGNORE": "Ignore directive suppressed nothing.",
    "IGNORE_WITHOUT_REASON": "Ignore directive has no reason.",
}


class _ToolError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def serve(
    stdin: TextIO | None = None,
    stdout: TextIO | None = None,
    *,
    root: Path | None = None,
    read_only: bool = False,
) -> None:
    """Read one JSON-RPC message per line until stdin closes."""
    reader = stdin if stdin is not None else sys.stdin
    writer = stdout if stdout is not None else sys.stdout
    project = (root or Path.cwd()).resolve()
    while True:
        line = reader.readline()
        if line == "":
            return
        if not line.strip():
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            _send(writer, _rpc_error(None, -32700, "parse error"))
            continue
        if not isinstance(message, dict):
            _send(writer, _rpc_error(None, -32600, "invalid request"))
            continue
        try:
            response = _dispatch(message, project, read_only)
        except Exception as exc:
            print(f"vyarth mcp: {exc}", file=sys.stderr)
            if "id" in message:
                _send(writer, _rpc_error(message.get("id"), -32603, str(exc)))
            continue
        if response is not None:
            _send(writer, response)


def _dispatch(message: dict[str, Any], root: Path, read_only: bool) -> dict[str, Any] | None:
    if "id" not in message:
        return None
    request_id = message.get("id")
    method = message.get("method", "")
    params = message.get("params") or {}
    if not isinstance(params, dict):
        return _rpc_error(request_id, -32602, "params must be an object")
    if method == "initialize":
        return _initialize(request_id, params)
    if method == "ping":
        return {"jsonrpc": "2.0", "id": request_id, "result": {}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": request_id, "result": {"tools": _tools(read_only)}}
    if method == "tools/call":
        return _call(request_id, params, root, read_only)
    return _rpc_error(request_id, -32601, f"method not found: {method}")


def _initialize(request_id: object, params: dict[str, Any]) -> dict[str, Any]:
    requested = params.get("protocolVersion")
    version = requested if isinstance(requested, str) and requested in _VERSIONS else _DEFAULT_VERSION
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": {
            "protocolVersion": version,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "vyarth", "version": __version__},
        },
    }


def _call(request_id: object, params: dict[str, Any], root: Path, read_only: bool) -> dict[str, Any]:
    name = params.get("name")
    arguments = params.get("arguments") or {}
    if not isinstance(name, str) or not isinstance(arguments, dict):
        return _rpc_error(request_id, -32602, "tools/call needs a name and arguments")
    if read_only and name in _WRITE_TOOLS:
        return _fail(request_id, "not_found", "tool is not available in read-only mode")
    try:
        payload = _invoke(name, arguments, root)
    except _ApplyFailed as exc:
        return _fail(request_id, exc.code, str(exc), exc.body)
    except _ToolError as exc:
        return _fail(request_id, exc.code, str(exc))
    except ValueError as exc:
        code = "unknown_id" if "id" in str(exc) else "not_found"
        return _fail(request_id, code, str(exc))
    except FileNotFoundError as exc:
        return _fail(request_id, "not_found", str(exc))
    return _ok(request_id, payload)


def _invoke(name: str, arguments: dict[str, Any], root: Path) -> dict[str, Any]:
    if name == "scan":
        return _tool_scan(root, arguments)
    if name == "explain":
        return _tool_explain(root, arguments)
    if name == "fix_preview":
        return _tool_preview(root, arguments)
    if name == "apply_fix":
        return _tool_apply(root, arguments)
    if name == "add_to_baseline":
        return _tool_baseline(root, arguments)
    if name == "list_rules":
        return _tool_rules()
    raise _ToolError("not_found", f"unknown tool: {name}")


def _tool_scan(root: Path, arguments: dict[str, Any]) -> dict[str, Any]:
    target = _inside(root, str(arguments.get("path") or "."))
    rules = arguments.get("rules") or []
    if not isinstance(rules, list):
        raise _ToolError("not_found", "rules must be a list")
    selected = canonical_rules([str(item) for item in rules]) if rules else ()
    changed_from = arguments.get("changed_from")
    result = cached_scan(
        root,
        min_confidence=int(arguments.get("min_confidence", 90)),
        max_findings=int(arguments.get("max_findings", 50)),
        sort=str(arguments.get("sort") or "confidence"),
        select=selected,
        fixable_only=bool(arguments.get("fixable_only", False)),
        changed=bool(changed_from),
        changed_from=str(changed_from or "HEAD"),
    )
    if target != root:
        narrowed = scan_within(result, root, target)
    else:
        narrowed = result
    report = narrowed.to_report(root=root, brief_evidence=True)
    paths = arguments.get("paths") or []
    if paths:
        report["findings"] = [row for row in report["findings"] if _path_selected(root, paths, row["path"])]
        report["summary"]["shown"] = len(report["findings"])
        report["summary"]["total"] = len(report["findings"])
        report["summary"]["truncated"] = False
    return report


def scan_within(result: ScanResult, root: Path, target: Path) -> ScanResult:
    """Keep findings under a file or directory inside the project."""
    from dataclasses import replace

    relative = "." if target == root else relative_posix(target, root)
    if target.is_file():
        findings = tuple(item for item in result.findings if item.path == relative)
    else:
        prefix = relative.rstrip("/") + "/"
        findings = tuple(item for item in result.findings if item.path == relative or item.path.startswith(prefix))
    return replace(result, findings=findings, census=None)


def _tool_explain(root: Path, arguments: dict[str, Any]) -> dict[str, Any]:
    selector = arguments.get("id")
    if not isinstance(selector, str) or not selector:
        raise _ToolError("unknown_id", "id is required")
    result = cached_scan(root, min_confidence=0)
    config = load_config(root)
    return explain_payload(root, config, locate(result.findings, selector))


def _tool_preview(root: Path, arguments: dict[str, Any]) -> dict[str, Any]:
    chosen = _selected(root, arguments)
    unsafe_fixes = bool(arguments.get("unsafe_fixes", False))
    kept, dirty = split_dirty(root, list(chosen), unsafe=False, unsafe_fixes=unsafe_fixes)
    skipped = [{"id": item.id, "reason": "dirty_lines"} for item in dirty]
    edits = []
    for finding in kept:
        level = applicability(finding, _source(root, finding.path))
        if level == "none" or (level == "unsafe" and not unsafe_fixes):
            skipped.append({"id": finding.id, "reason": "unsafe" if level == "unsafe" else "not_fixable"})
            continue
        diff = render_fix_diff(root, [finding], unsafe_fixes=level == "unsafe")
        if not diff.strip():
            skipped.append({"id": finding.id, "reason": "not_fixable"})
            continue
        edits.append({"id": finding.id, "path": finding.path, "applicability": level, "diff": diff})
    return {"edits": edits, "skipped": skipped}


def _tool_apply(root: Path, arguments: dict[str, Any]) -> dict[str, Any]:
    chosen = _selected(root, arguments)
    unsafe_fixes = bool(arguments.get("unsafe_fixes", False))
    verify = bool(arguments.get("verify", True))
    kept, dirty = split_dirty(root, list(chosen), unsafe=False, unsafe_fixes=unsafe_fixes)
    applicable = []
    skipped = [{"id": item.id, "reason": "dirty_lines"} for item in dirty]
    for finding in kept:
        level = applicability(finding, _source(root, finding.path))
        if level == "safe" or (level == "unsafe" and unsafe_fixes):
            applicable.append(finding)
        else:
            skipped.append({"id": finding.id, "reason": "unsafe" if level == "unsafe" else "not_fixable"})
    config = load_config(root)
    rolled_back = False
    verified = False
    tail = ""
    applied_ids: list[str] = []
    if applicable and verify:
        report = apply_fixes_verified(
            root,
            applicable,
            unsafe=False,
            unsafe_fixes=unsafe_fixes,
            verify_cmd=config.fix_verify_command,
            timeout=config.fix_verify_timeout,
        )
        applied_ids = [item.id for item in report.applied if item.line > 0]
        skipped.extend({"id": item.id, "reason": item.reason} for item in report.skipped)
        rolled_back = report.rolled_back
        verified = report.verified
        tail = report.output_tail
    elif applicable:
        applied = apply_fixes(root, applicable, unsafe=False, unsafe_fixes=unsafe_fixes, write=True)
        applied_ids = [item.id for item in applied if item.line > 0]
    body = {
        "applied": applied_ids,
        "skipped": skipped,
        "verified": verified,
        "rolled_back": rolled_back,
        "verify_output_tail": tail,
        "remaining": {"summary": _summary(root)},
    }
    if rolled_back and not applied_ids:
        raise _ApplyFailed("verify_failed", tail or "verification failed", body)
    if not applied_ids and skipped and all(item["reason"] == "dirty_lines" for item in skipped):
        raise _ApplyFailed("dirty_lines", "edit covers uncommitted lines", body)
    return body


def _tool_baseline(root: Path, arguments: dict[str, Any]) -> dict[str, Any]:
    reason = arguments.get("reason")
    if not isinstance(reason, str) or len(reason.strip()) < 10:
        raise _ToolError("not_found", "reason must be at least 10 characters")
    chosen = _selected(root, arguments)
    config = load_config(root)
    target = _inside(root, config.baseline or "vyarth-baseline.json")
    added, total = append_baseline(target, chosen, reason.strip())
    return {"added": added, "baseline_path": relative_posix(target, root), "total": total}


def _tool_rules() -> dict[str, Any]:
    rules: list[dict[str, Any]] = []
    for alias, rule_id in sorted(RULES.items(), key=lambda item: item[1]):
        if any(item["id"] == rule_id for item in rules):
            continue
        hyphen = rule_id.lower().replace("_", "-")
        rules.append(
            {
                "id": rule_id,
                "aliases": [alias, hyphen],
                "description": _BLURB.get(rule_id, rule_id),
                "fixable": rule_id in _FIXABLE,
                "rule_url": f"{_HELP}#{rule_id.lower()}",
            }
        )
    return {"rules": rules}


def _selected(root: Path, arguments: dict[str, Any]) -> tuple[Finding, ...]:
    raw = arguments.get("ids")
    if not isinstance(raw, list) or not raw or not all(isinstance(item, str) and item for item in raw):
        raise _ToolError("unknown_id", "ids must be a list of strings")
    result = cached_scan(root, min_confidence=0)
    return resolve_ids(result.findings, raw)


def _summary(root: Path) -> dict[str, Any]:
    result = cached_scan(root, min_confidence=0, max_findings=50, sort="confidence")
    summary = result.to_report(root=root, brief_evidence=True)["summary"]
    return summary if isinstance(summary, dict) else {}


def _path_selected(root: Path, paths: object, finding_path: str) -> bool:
    if not isinstance(paths, list):
        raise _ToolError("path_outside_root", "paths must be a list")
    for raw in paths:
        target = _inside(root, str(raw))
        relative = relative_posix(target, root)
        if finding_path == relative or finding_path.startswith(relative.rstrip("/") + "/"):
            return True
    return False


def _inside(root: Path, raw: str) -> Path:
    candidate = Path(raw)
    if not candidate.is_absolute():
        candidate = root / candidate
    try:
        resolved = candidate.resolve()
        resolved.relative_to(root.resolve())
    except (OSError, ValueError) as exc:
        raise _ToolError("path_outside_root", f"path is outside the root: {raw}") from exc
    return resolved


def _source(root: Path, relpath: str) -> str | None:
    path = root / relpath
    if not path.is_file():
        return None
    try:
        text, _encoding = read_python_source(path)
    except OSError:
        return None
    return text


def _tools(read_only: bool) -> list[dict[str, Any]]:
    tools = [
        _spec("scan", "Scan a project and return report v1.", _SCAN_SCHEMA, read_only=True),
        _spec("explain", "Explain one finding.", {"type": "object", "required": ["id"], "properties": {"id": {"type": "string"}}}, read_only=True),
        _spec("fix_preview", "Show diffs for the named findings.", _IDS_SCHEMA, read_only=True),
        _spec("apply_fix", "Apply the named edits and verify them.", _APPLY_SCHEMA, destructive=True),
        _spec("add_to_baseline", "Append findings to the baseline.", _BASELINE_SCHEMA, destructive=False),
        _spec("list_rules", "List the rules vyarth can report.", {"type": "object", "properties": {}}, read_only=True),
    ]
    if read_only:
        return [item for item in tools if item["name"] not in _WRITE_TOOLS]
    return tools


def _spec(
    name: str,
    description: str,
    schema: dict[str, Any],
    *,
    read_only: bool = False,
    destructive: bool = False,
) -> dict[str, Any]:
    return {
        "name": name,
        "description": description,
        "inputSchema": schema,
        "annotations": {
            "readOnlyHint": read_only,
            "destructiveHint": destructive,
            "idempotentHint": read_only,
        },
    }


def _ok(request_id: object, payload: dict[str, Any]) -> dict[str, Any]:
    return _result(request_id, payload, False)


def _fail(request_id: object, code: str, message: str, extra: dict[str, Any] | None = None) -> dict[str, Any]:
    body: dict[str, Any] = {"code": code, "message": message}
    if extra:
        body.update(extra)
    return _result(request_id, body, True)


def _result(request_id: object, payload: dict[str, Any], is_error: bool) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": {
            "content": [{"type": "text", "text": json.dumps(payload)}],
            "structuredContent": payload,
            "isError": is_error,
        },
    }


def _rpc_error(request_id: object, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def _send(writer: TextIO, payload: dict[str, Any]) -> None:
    writer.write(json.dumps(payload) + "\n")
    writer.flush()


class _ApplyFailed(_ToolError):
    def __init__(self, code: str, message: str, body: dict[str, Any]) -> None:
        super().__init__(code, message)
        self.body = body


_SCAN_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "path": {"type": "string"},
        "min_confidence": {"type": "integer"},
        "max_findings": {"type": "integer"},
        "sort": {"type": "string", "enum": ["confidence", "path"]},
        "rules": {"type": "array", "items": {"type": "string"}},
        "changed_from": {"type": "string"},
        "fixable_only": {"type": "boolean"},
        "paths": {"type": "array", "items": {"type": "string"}},
    },
}
_IDS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["ids"],
    "properties": {
        "ids": {"type": "array", "items": {"type": "string"}},
        "unsafe_fixes": {"type": "boolean"},
    },
}
_APPLY_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["ids"],
    "properties": {
        "ids": {"type": "array", "items": {"type": "string"}},
        "verify": {"type": "boolean"},
        "unsafe_fixes": {"type": "boolean"},
    },
}
_BASELINE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["ids", "reason"],
    "properties": {
        "ids": {"type": "array", "items": {"type": "string"}},
        "reason": {"type": "string", "minLength": 10},
    },
}
