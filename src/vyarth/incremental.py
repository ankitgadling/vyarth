"""Git changed-file selection and a FileIndex cache."""

from __future__ import annotations

from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import subprocess
import sys

from vyarth.model import (
    INDEX_VERSION,
    Binding,
    BodyHash,
    CallEdge,
    ContainerStore,
    Decorator,
    DynamicMarker,
    FileIndex,
    Finding,
    FlowBind,
    IgnoreDirective,
    ImportEdge,
    ParseError,
    ReturnNote,
    ScopeInfo,
    UnreachableSpan,
)


def changed_python_files(root: Path, ref: str = "HEAD") -> set[str]:
    """Python paths changed relative to `ref`, including untracked files.

    Paths are relative to `root`. `root` may sit below the git repository.
    Raises RuntimeError when git cannot answer.
    """
    prefix = _git_prefix(root)
    base = _merge_base(root, ref)
    diff_paths = _git_lines(
        root,
        ["git", "-c", "core.quotePath=false", "diff", "--name-only", base],
    )
    untracked = _git_lines(
        root,
        ["git", "-c", "core.quotePath=false", "ls-files", "--others", "--exclude-standard", "--full-name"],
    )
    mapped: set[str] = set()
    saw_python = False
    for path in (*diff_paths, *untracked):
        if not path.endswith(".py"):
            continue
        saw_python = True
        relative = _strip_git_prefix(path, prefix)
        if relative is not None:
            mapped.add(relative)
    if saw_python and not mapped:
        print(
            "warning: git reported Python changes, but none are inside this project",
            file=sys.stderr,
        )
    return mapped


def load_cached(root: Path, relpath: str, stamp: str) -> FileIndex | None:
    path = _cache_path(root, relpath)
    if not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return None
    if not isinstance(payload, dict) or payload.get("stamp") != stamp:
        return None
    index = payload.get("index")
    if not isinstance(index, dict):
        return None
    try:
        return _index_from_dict(index)
    except (KeyError, TypeError, ValueError):
        return None


def store_cached(root: Path, relpath: str, stamp: str, index: FileIndex) -> None:
    """Write one cache record. A read-only project skips the cache instead of failing the scan."""
    try:
        ensure_cache_markers(root)
        path = _cache_path(root, relpath)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"stamp": stamp, "index": asdict(index)}
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(payload), encoding="utf-8")
        temporary.replace(path)
        _remember_cached(root, relpath, stamp, index.path, path)
    except OSError:
        return


def load_result(
    root: Path,
    key: str,
) -> tuple[list[Finding], list[ParseError], int] | None:
    """Findings stored after ignores and before the baseline filter."""
    path = _result_path(root)
    if not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return None
    if not isinstance(payload, dict) or payload.get("key") != key:
        return None
    try:
        findings = [_finding_from_dict(item) for item in payload["findings"]]
        errors = [ParseError(**item) for item in payload["errors"]]
        scanned = int(payload["files_scanned"])
    except (KeyError, TypeError, ValueError):
        return None
    return findings, errors, scanned


def store_result(
    root: Path,
    key: str,
    findings: list[Finding],
    errors: list[ParseError],
    files_scanned: int,
) -> None:
    """Remember a finished analysis. A later scan replays baseline and confidence filters."""
    try:
        ensure_cache_markers(root)
        path = _result_path(root)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "key": key,
            "files_scanned": files_scanned,
            "findings": [asdict(finding) for finding in findings],
            "errors": [asdict(error) for error in errors],
        }
        _write_json(path, payload)
    except OSError:
        return


def result_cache_key(
    root: Path,
    scan_path: str,
    files: list[list[object]],
    manifests: list[list[object]],
    config_payload: str,
) -> str:
    """Identity of every input the analysis reads. Filters applied later are not included."""
    from vyarth import __version__

    blob = json.dumps(
        {
            "version": __version__,
            "index": INDEX_VERSION,
            "root": str(root.resolve()),
            "scan": scan_path,
            "files": files,
            "manifests": manifests,
            "config": config_payload,
        },
        separators=(",", ":"),
    )
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def cache_stamp(size: int, mtime_ns: int, fold: dict[str, str], duplicate_min_statements: int = 5) -> str:
    from vyarth import __version__

    folded = json.dumps(sorted(fold.items()), separators=(",", ":"))
    return f"{__version__}:{INDEX_VERSION}:{duplicate_min_statements}:{size}:{mtime_ns}:{folded}"


def ensure_cache_markers(root: Path) -> None:
    """Write the files that keep `.vyarth` out of git status."""
    directory = root / ".vyarth"
    directory.mkdir(parents=True, exist_ok=True)
    gitignore = directory / ".gitignore"
    if not gitignore.is_file():
        gitignore.write_text("*\n", encoding="utf-8")
    tag = directory / "CACHEDIR.TAG"
    if not tag.is_file():
        tag.write_text(
            "Signature: 8a477f597d28d172789f06886806bc55\n"
            "# This file is a cache directory tag created by vyarth.\n"
            "# For information about cache directory tags, see:\n"
            "#\thttps://bford.info/cachedir/\n",
            encoding="utf-8",
        )


def prune_cache(root: Path, live_paths: set[str]) -> None:
    """Delete cache records for files that this directory scan did not index.

    The sidecar lists each record's absolute path, so a normal prune does not
    decode the index. A missing sidecar, or a path that disagrees with the
    JSON, falls back to reading that record.
    """
    cache = root / ".vyarth" / "cache"
    if not cache.is_dir():
        return
    live = {str(Path(path)) for path in live_paths}
    manifest = _load_manifest(root)
    if manifest is None:
        _prune_by_reading(cache, live)
        return
    kept: dict[str, dict[str, str]] = {}
    accounted: set[Path] = set()
    files = manifest.get("files")
    if not isinstance(files, dict):
        _prune_by_reading(cache, live)
        return
    for relpath, entry in files.items():
        if not isinstance(relpath, str) or not isinstance(entry, dict):
            continue
        cache_name = entry.get("cache")
        if not isinstance(cache_name, str):
            continue
        file = cache / cache_name
        try:
            accounted.add(file.resolve())
        except OSError:
            continue
        if not file.is_file():
            continue
        stamp = entry.get("stamp")
        sidecar_path = entry.get("path") if isinstance(entry.get("path"), str) else None
        normalized = str(Path(sidecar_path)) if sidecar_path is not None else None
        if normalized is not None and normalized in live:
            kept[relpath] = {"stamp": stamp if isinstance(stamp, str) else "", "path": normalized, "cache": cache_name}
            continue
        chosen = _path_to_keep(file, live)
        if chosen is None:
            _unlink(file)
            continue
        kept[relpath] = {"stamp": stamp if isinstance(stamp, str) else "", "path": chosen, "cache": cache_name}
    for file in cache.rglob("*.json"):
        if file.name in {"manifest.json", "result.json"}:
            continue
        try:
            resolved = file.resolve()
        except OSError:
            continue
        if resolved in accounted:
            continue
        if _path_to_keep(file, live) is None:
            _unlink(file)
    _write_manifest(root, kept)


def _git_prefix(root: Path) -> str:
    text = _git_output(root, ["git", "rev-parse", "--show-prefix"]).strip().replace("\\", "/")
    if text and not text.endswith("/"):
        text += "/"
    return text


def _strip_git_prefix(path: str, prefix: str) -> str | None:
    if prefix:
        if not path.startswith(prefix):
            return None
        relative = path[len(prefix) :]
    else:
        relative = path
    if not relative or relative.startswith("../") or ".." in Path(relative).parts:
        return None
    return relative


def _git_lines(root: Path, args: list[str]) -> list[str]:
    return [
        line.strip().replace("\\", "/")
        for line in _git_output(root, args).splitlines()
        if line.strip()
    ]


def _merge_base(root: Path, ref: str) -> str:
    """Commit to diff against. A failed merge-base falls back to `ref`.

    Shallow clones and unrelated histories make `git merge-base` exit non-zero.
    Diffing against `ref` itself still lists the files that changed.
    """
    try:
        found = _git_output(root, ["git", "merge-base", ref, "HEAD"]).strip()
    except RuntimeError:
        return ref
    return found or ref


def _git_output(root: Path, args: list[str]) -> str:
    try:
        result = subprocess.run(
            args,
            cwd=root,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="surrogateescape",
            check=False,
        )
    except OSError as exc:
        raise RuntimeError(f"git diff failed: {exc}") from exc
    if result.returncode != 0:
        message = result.stderr.strip() or "git diff failed"
        raise RuntimeError(message)
    return result.stdout


def _cache_path(root: Path, relpath: str) -> Path:
    digest = hashlib.sha256(relpath.encode("utf-8")).hexdigest()
    return root / ".vyarth" / "cache" / digest[:2] / f"{digest}.json"


def _result_path(root: Path) -> Path:
    return root / ".vyarth" / "cache" / "result.json"


def _manifest_path(root: Path) -> Path:
    return root / ".vyarth" / "cache" / "manifest.json"


def _remember_cached(root: Path, relpath: str, stamp: str, absolute: str, cache_file: Path) -> None:
    cache = root / ".vyarth" / "cache"
    current = _load_manifest(root) or {}
    files = current.get("files")
    if not isinstance(files, dict):
        files = {}
    try:
        cache_name = cache_file.resolve().relative_to(cache.resolve()).as_posix()
    except ValueError:
        return
    files[relpath] = {"stamp": stamp, "path": absolute, "cache": cache_name}
    _write_manifest(root, files)


def _load_manifest(root: Path) -> dict | None:
    path = _manifest_path(root)
    if not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return None
    if not isinstance(payload, dict):
        return None
    return payload


def _write_manifest(root: Path, files: dict[str, dict[str, str]]) -> None:
    _write_json(_manifest_path(root), {"files": files})


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload), encoding="utf-8")
    temporary.replace(path)


def _prune_by_reading(cache: Path, live: set[str]) -> None:
    for file in cache.rglob("*.json"):
        if file.name in {"manifest.json", "result.json"}:
            continue
        if _path_to_keep(file, live) is None:
            _unlink(file)


def _path_to_keep(file: Path, live: set[str]) -> str | None:
    """Absolute path from the JSON record, or None when the record should be deleted.

    An unreadable record is deleted. The next scan parses that file again and
    writes the same index.
    """
    stored = _stored_index_path(file)
    if stored is not None and str(Path(stored)) in live:
        return str(Path(stored))
    return None


def _stored_index_path(file: Path) -> str | None:
    try:
        payload = json.loads(file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeError, TypeError, ValueError):
        return None
    index = payload.get("index") if isinstance(payload, dict) else None
    stored = index.get("path") if isinstance(index, dict) else None
    if isinstance(stored, str):
        return stored
    return None


def _unlink(file: Path) -> None:
    try:
        file.unlink(missing_ok=True)
    except OSError:
        return


def _finding_from_dict(item: dict) -> Finding:
    evidence = item.get("evidence") or ()
    return Finding(
        rule=item["rule"],
        path=item["path"],
        line=int(item["line"]),
        column=int(item["column"]),
        symbol=item["symbol"],
        status=item["status"],
        confidence=int(item["confidence"]),
        message=item["message"],
        evidence=tuple(evidence),
        fingerprint=item["fingerprint"],
    )


def _index_from_dict(data: dict) -> FileIndex:
    return FileIndex(
        path=data["path"],
        bindings=tuple(Binding(**item) for item in data["bindings"]),
        scopes=tuple(ScopeInfo(**item) for item in data["scopes"]),
        imports=tuple(ImportEdge(**item) for item in data["imports"]),
        unreachable=tuple(UnreachableSpan(**item) for item in data["unreachable"]),
        has_main_guard=bool(data["has_main_guard"]),
        ignores=tuple(_ignore(item) for item in data["ignores"]),
        exports=tuple(data["exports"]),
        calls=tuple(CallEdge(**item) for item in data.get("calls", ())),
        decorators=tuple(_decorator(item) for item in data.get("decorators", ())),
        dynamic_markers=tuple(DynamicMarker(**item) for item in data.get("dynamic_markers", ())),
        value_references=tuple(data.get("value_references", ())),
        abstract=tuple(data.get("abstract", ())),
        flow_binds=tuple(FlowBind(**item) for item in data.get("flow_binds", ())),
        returns=tuple(ReturnNote(**item) for item in data.get("returns", ())),
        body_hashes=tuple(BodyHash(**item) for item in data.get("body_hashes", ())),
        value_uses=tuple((item[0], item[1]) for item in data.get("value_uses", ())),
        class_bases=tuple((item[0], tuple(item[1])) for item in data.get("class_bases", ())),
        unbound_names=tuple(data.get("unbound_names", ())),
        dynamic_imports=tuple(data.get("dynamic_imports", ())),
        container_stores=tuple(_container(item) for item in data.get("container_stores", ())),
        import_probes=tuple(data.get("import_probes", ())),
    )


def _ignore(item: dict) -> IgnoreDirective:
    rules = item.get("rules")
    return IgnoreDirective(
        line=item["line"],
        rules=None if rules is None else tuple(rules),
        exact=bool(item.get("exact", False)),
    )


def _container(item: dict) -> ContainerStore:
    return ContainerStore(
        caller=item["caller"],
        name=item["name"],
        elements=tuple(item.get("elements", ())),
        line=item["line"],
        mode=item["mode"],
        index=item["index"],
    )


def _decorator(item: dict) -> Decorator:
    return Decorator(qualname=item["qualname"], name=item["name"], arguments=tuple(item.get("arguments", ())))
