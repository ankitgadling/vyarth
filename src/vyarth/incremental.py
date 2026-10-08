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
    FlowBind,
    IgnoreDirective,
    ImportEdge,
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
    diff_paths = _git_lines(root, ["git", "diff", "--name-only", ref])
    untracked = _git_lines(root, ["git", "ls-files", "--others", "--exclude-standard", "--full-name"])
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
    ensure_cache_markers(root)
    path = _cache_path(root, relpath)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"stamp": stamp, "index": asdict(index)}
    path.write_text(json.dumps(payload), encoding="utf-8")


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
    """Delete cache records for files that this directory scan did not index."""
    cache = root / ".vyarth" / "cache"
    if not cache.is_dir():
        return
    live = {str(Path(path)) for path in live_paths}
    for file in cache.rglob("*.json"):
        try:
            payload = json.loads(file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, UnicodeError):
            file.unlink(missing_ok=True)
            continue
        index = payload.get("index") if isinstance(payload, dict) else None
        stored = index.get("path") if isinstance(index, dict) else None
        if not isinstance(stored, str) or stored not in live:
            file.unlink(missing_ok=True)


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


def _git_output(root: Path, args: list[str]) -> str:
    try:
        result = subprocess.run(
            args,
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
    return result.stdout


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
