"""Git changed-file selection and a FileIndex cache."""

from __future__ import annotations

from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import subprocess

from vyarth.model import (
    INDEX_VERSION,
    Binding,
    BodyHash,
    CallEdge,
    ContainerStore,
    Decorator,
    DynamicMarker,
    FileIndex,
    FlowBind,
    IgnoreDirective,
    ImportEdge,
    ReturnNote,
    ScopeInfo,
    UnreachableSpan,
)


def changed_python_files(root: Path, ref: str = "HEAD") -> set[str]:
    """Python paths changed relative to `ref`. Raises RuntimeError when git cannot answer."""
    try:
        result = subprocess.run(
            ["git", "diff", "--name-only", ref],
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as exc:
        raise RuntimeError(f"git diff failed: {exc}") from exc
    if result.returncode != 0:
        message = result.stderr.strip() or "git diff failed"
        raise RuntimeError(message)
    return {
        line.strip().replace("\\", "/")
        for line in result.stdout.splitlines()
        if line.strip().endswith(".py")
    }


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
    path = _cache_path(root, relpath)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"stamp": stamp, "index": asdict(index)}
    path.write_text(json.dumps(payload), encoding="utf-8")


def cache_stamp(size: int, mtime_ns: int, fold: dict[str, str], duplicate_min_statements: int = 5) -> str:
    folded = json.dumps(sorted(fold.items()), separators=(",", ":"))
    return f"{INDEX_VERSION}:{duplicate_min_statements}:{size}:{mtime_ns}:{folded}"


def _cache_path(root: Path, relpath: str) -> Path:
    digest = hashlib.sha256(relpath.encode("utf-8")).hexdigest()
    return root / ".vyarth" / "cache" / digest[:2] / f"{digest}.json"


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
    )


def _ignore(item: dict) -> IgnoreDirective:
    rules = item.get("rules")
    return IgnoreDirective(line=item["line"], rules=None if rules is None else tuple(rules))


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
