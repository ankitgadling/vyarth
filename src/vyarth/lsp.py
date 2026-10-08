"""A small language server. Diagnostics come from one project scan."""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys
from urllib.parse import unquote, urlparse

from vyarth.config import load_config
from vyarth.discover import discover_files, project_root, relative_posix
from vyarth.engine import scan
from vyarth.fix import is_fixable, rewrite_source
from vyarth.model import Finding, ScanResult


_results: dict[Path, tuple[tuple[tuple[str, int, int], ...], ScanResult]] = {}
_buffers: dict[Path, str] = {}


def serve(stdin=None, stdout=None) -> None:
    reader = stdin if stdin is not None else sys.stdin
    writer = stdout if stdout is not None else sys.stdout
    while True:
        message = _read_message(reader)
        if message is None:
            return
        method = message.get("method", "")
        if method == "exit":
            return
        response = _dispatch(message)
        if response is not None:
            _write_message(writer, response)


def diagnostics_for(uri: str) -> dict:
    """Pull-model diagnostics for one file."""
    scanned = _scanned(uri)
    if scanned is None:
        return {"kind": "full", "items": []}
    _, relpath, _, result = scanned
    items = []
    for finding in result.findings:
        if finding.path != relpath:
            continue
        line = max(finding.line - 1, 0)
        character = max(finding.column - 1, 0)
        items.append(
            {
                "range": {
                    "start": {"line": line, "character": character},
                    "end": {"line": line, "character": character + 1},
                },
                "severity": 1 if finding.confidence >= 90 else 2,
                "source": "vyarth",
                "message": finding.message,
                "code": finding.rule,
            }
        )
    return {"kind": "full", "items": items}


def code_actions_for(uri: str, lsp_range: dict | None = None) -> list[dict]:
    """Quick fixes for findings a rewrite can delete."""
    scanned = _scanned(uri)
    if scanned is None:
        return []
    _, relpath, source, result = scanned
    actions: list[dict] = []
    for finding in result.findings:
        if finding.path != relpath or not is_fixable(finding, source):
            continue
        if lsp_range is not None and not _covers(finding.line, lsp_range):
            continue
        updated, notes = rewrite_source(source, [finding], relpath)
        if updated == source or not notes:
            continue
        actions.append(
            {
                "title": _action_title(finding),
                "kind": "quickfix",
                "edit": {"changes": {uri: [_span_edit(source, updated)]}},
            }
        )
    return actions


def uri_to_path(uri: str) -> Path:
    parsed = urlparse(uri)
    raw = unquote(parsed.path)
    if os.name == "nt" and raw.startswith("/") and len(raw) > 2 and raw[2] == ":":
        raw = raw[1:]
    return Path(raw)


def _dispatch(message: dict) -> dict | None:
    method = message.get("method", "")
    request_id = message.get("id")
    if method == "initialize":
        return _result(
            request_id,
            {
                "capabilities": {
                    "textDocumentSync": 1,
                    "diagnosticProvider": {"interFileDependencies": True, "workspaceDiagnostics": False},
                    "codeActionProvider": {"codeActionKinds": ["quickfix"]},
                },
                "serverInfo": {"name": "vyarth"},
            },
        )
    if method == "shutdown":
        return _result(request_id, None)
    if method == "textDocument/diagnostic":
        uri = message.get("params", {}).get("textDocument", {}).get("uri", "")
        return _result(request_id, diagnostics_for(uri))
    if method == "textDocument/codeAction":
        params = message.get("params", {})
        uri = params.get("textDocument", {}).get("uri", "")
        return _result(request_id, code_actions_for(uri, params.get("range")))
    if method in {"textDocument/didOpen", "textDocument/didChange"}:
        _remember_buffer(message)
        return None
    if method == "textDocument/didSave":
        _forget_buffer(message)
        return None
    if request_id is not None:
        return _result(request_id, None)
    return None


def _scanned(uri: str) -> tuple[Path, str, str, ScanResult] | None:
    path = uri_to_path(uri)
    root = project_root(path if path.is_dir() else path.parent)
    if not path.is_file():
        return None
    resolved = path.resolve()
    text = _buffers.get(resolved)
    stamp = _file_stamp(root)
    cached = _results.get(root)
    if text is None and cached is not None and cached[0] == stamp:
        result = cached[1]
    else:
        overlays = {str(resolved): text} if text is not None else None
        result = scan(root, overlays=overlays)
        if text is None:
            _results[root] = (stamp, result)
    try:
        relpath = relative_posix(path, root)
    except ValueError:
        relpath = path.name
    source = text if text is not None else path.read_text(encoding="utf-8")
    return path, relpath, source, result


def _covers(line: int, lsp_range: dict) -> bool:
    start = int(lsp_range.get("start", {}).get("line", 0))
    end = int(lsp_range.get("end", {}).get("line", start))
    zero = max(line - 1, 0)
    if start == end:
        return zero == start
    return start <= zero <= end


def _action_title(finding: Finding) -> str:
    if finding.rule == "UNUSED_IMPORT":
        return f"Remove unused import '{finding.symbol}'"
    if finding.rule == "UNREACHABLE_CODE":
        return "Remove unreachable code"
    if finding.rule == "UNUSED_FUNCTION":
        return f"Remove unused function '{finding.symbol}'"
    return f"Remove unused variable '{finding.symbol}'"


def _span_edit(source: str, updated: str) -> dict:
    old = source.splitlines(keepends=True)
    new = updated.splitlines(keepends=True)
    start = 0
    while start < len(old) and start < len(new) and old[start] == new[start]:
        start += 1
    old_end = len(old)
    new_end = len(new)
    while old_end > start and new_end > start and old[old_end - 1] == new[new_end - 1]:
        old_end -= 1
        new_end -= 1
    return {
        "range": {
            "start": {"line": start, "character": 0},
            "end": {"line": old_end, "character": 0},
        },
        "newText": "".join(new[start:new_end]),
    }


def _file_stamp(root: Path) -> tuple[tuple[str, int, int], ...]:
    config = load_config(root)
    stamps: list[tuple[str, int, int]] = []
    for file in discover_files(root, config):
        stat = file.stat()
        stamps.append((relative_posix(file, root), stat.st_size, stat.st_mtime_ns))
    return tuple(stamps)


def _remember_buffer(message: dict) -> None:
    params = message.get("params") or {}
    document = params.get("textDocument") or {}
    uri = document.get("uri") or ""
    if not uri:
        return
    text = params.get("text")
    if text is None:
        changes = params.get("contentChanges") or []
        if changes and isinstance(changes[-1], dict):
            text = changes[-1].get("text")
    if not isinstance(text, str):
        return
    _buffers[uri_to_path(uri).resolve()] = text


def _forget_buffer(message: dict) -> None:
    params = message.get("params") or {}
    document = params.get("textDocument") or {}
    uri = document.get("uri") or ""
    if uri:
        _buffers.pop(uri_to_path(uri).resolve(), None)


def _result(request_id: object, result: object) -> dict:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _read_message(stream) -> dict | None:
    reader = _binary(stream)
    headers: dict[str, str] = {}
    while True:
        line = reader.readline()
        if not line:
            return None
        if line in {b"\r\n", b"\n"}:
            break
        key, _, value = line.decode("ascii", errors="replace").partition(":")
        headers[key.strip().lower()] = value.strip()
    length = int(headers.get("content-length", "0"))
    if length <= 0:
        return None
    body = reader.read(length)
    payload = json.loads(body.decode("utf-8"))
    if not isinstance(payload, dict):
        return None
    return payload


def _write_message(stream, payload: dict) -> None:
    body = json.dumps(payload).encode("utf-8")
    writer = _binary(stream)
    writer.write(f"Content-Length: {len(body)}\r\n\r\n".encode("ascii") + body)
    writer.flush()


def _binary(stream):
    buffer = getattr(stream, "buffer", None)
    return buffer if buffer is not None else stream
