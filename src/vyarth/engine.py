"""Scan orchestration."""

from __future__ import annotations

from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import replace
import json
import os
from pathlib import Path
import re

from vyarth.baseline import filter_baselined, load_baseline
from vyarth.confidence import apply_confidence
from vyarth.config import Config, load_config
from vyarth.dependencies import dependency_findings, selected_manifests
from vyarth.discover import discover_scan, is_test_path, project_root, read_python_source, relative_posix
from vyarth.duplicates import duplicate_findings
from vyarth.ignore import apply_ignores
from vyarth.incremental import (
    CacheEntry,
    cache_stamp,
    changed_python_files,
    load_cached,
    load_result,
    prune_cache,
    remember_cached,
    result_cache_key,
    store_cached,
    store_result,
)
from vyarth.model import FileIndex, Finding, ParseError, ScanResult
from vyarth.progress import ScanProgress
from vyarth.python_index import PythonAstBackend
from vyarth.rules import collect_findings


# Spawning a process pool costs more than parsing a few modules, especially on Windows.
_POOL_MIN_FILES = 8


class BaselineNotFoundError(FileNotFoundError):
    """The baseline file named by config or `--baseline` does not exist."""


def scan(
    path: str | Path = ".",
    config: Config | None = None,
    *,
    config_path: str | Path | None = None,
    min_confidence: int | None = None,
    baseline: str | Path | None = None,
    apply_baseline: bool = True,
    workers: int | None = None,
    defines: dict[str, str] | None = None,
    changed: bool = False,
    changed_from: str = "HEAD",
    use_cache: bool = True,
    overlays: dict[str, str] | None = None,
    progress: ScanProgress | None = None,
) -> ScanResult:
    """Scan a file or directory and return findings at or above the confidence threshold."""
    target = Path(path).expanduser().resolve()
    if not target.exists():
        raise FileNotFoundError(path)
    single_file = target.is_file()
    requested = target.parent if single_file else target
    root = project_root(requested)
    if config is None:
        explicit = Path(config_path) if config_path is not None else None
        config = load_config(root, explicit)
    if min_confidence is not None:
        config = replace(config, min_confidence=min_confidence)
    report_only: set[str] | None = None
    if changed and not single_file:
        _status(progress, "finding changed files")
        report_only = changed_python_files(root, changed_from)
        if not report_only:
            return ScanResult(findings=(), errors=(), files_scanned=0)

    _status(progress, "finding python files")
    if single_file:
        files = [target]
        manifests: list[Path] = []
    else:
        files, found_manifests = discover_scan(root, config, within=requested)
        manifests = selected_manifests(found_manifests, root, requested)
    fold = config.fold_map()
    if defines:
        fold.update(defines)
    cache_result = use_cache and not single_file and not overlays
    result_key = ""
    if cache_result:
        result_key = result_cache_key(
            root,
            relative_posix(requested, root),
            _input_stamps(root, files),
            _input_stamps(root, manifests),
            _analysis_payload(config, fold),
        )
        cached = load_result(root, result_key)
        if cached is not None:
            _status(progress, "using cached result")
            findings, errors, files_scanned = cached
            return _finish(
                findings,
                errors,
                files_scanned,
                root,
                config,
                baseline,
                apply_baseline,
                report_only,
            )

    _status(progress, "indexing files", _index_detail(0, len(files), 0))
    indexes, errors = _index_files(
        files,
        root,
        fold,
        workers if workers is not None else config.workers,
        use_cache and not single_file,
        config.duplicate_min_statements,
        overlays,
        progress,
    )
    broken_names = _broken_names(root, errors)

    # A nested folder that is not a package becomes a root, so `scan examples/app`
    # resolves `import app`. A directory with `__init__.py` keeps its own name.
    extra_roots: tuple[Path, ...] = ()
    if not single_file and requested != root and not (requested / "__init__.py").is_file():
        extra_roots = (requested,)
    findings = collect_findings(
        indexes,
        root,
        config,
        check_modules=not single_file,
        progress=progress,
        extra_roots=extra_roots,
    )
    _status(progress, "checking dependencies")
    if not single_file:
        dep_findings, dep_errors = dependency_findings(
            indexes,
            root,
            within=requested,
            config=config,
            manifests=manifests,
        )
        findings.extend(dep_findings)
        errors.extend(dep_errors)
    _status(progress, "checking duplicate code")
    findings.extend(duplicate_findings(indexes, root, config.duplicate_min_statements))
    findings = apply_confidence(findings, indexes, root)
    by_path = {relative_posix(Path(index.path), root): index for index in indexes}
    if broken_names is None or broken_names:
        findings = [_soften_for_parse_errors(item, broken_names, by_path) for item in findings]
    findings = [finding for finding in findings if not is_test_path(finding.path)]
    findings = apply_ignores(findings, by_path, config)
    if cache_result:
        store_result(root, result_key, findings, errors, len(indexes))
    if use_cache and not single_file and requested == root and not overlays:
        prune_cache(root, {index.path for index in indexes})
    return _finish(
        findings,
        errors,
        len(indexes),
        root,
        config,
        baseline,
        apply_baseline,
        report_only,
    )


_PARSE_ERROR_NOTE = "A file failed to parse, so it may use this symbol."
_PARSE_SENSITIVE = {
    "UNUSED_FUNCTION",
    "UNUSED_CLASS",
    "ORPHAN_FUNCTION",
    "POSSIBLY_UNUSED_MODULE",
    "UNUSED_DEPENDENCY",
    "UNUSED_VARIABLE",
}


_WORD = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def _broken_names(root: Path, errors: list[ParseError]) -> set[str] | None:
    """Lowercased words in the source files that failed to parse.

    A broken test file, which is often broken on purpose, is ignored. None means
    a broken file could not be read, so its contents are unknown.
    """
    words: set[str] = set()
    for error in errors:
        if is_test_path(error.path):
            continue
        try:
            text, _ = read_python_source(root / error.path)
        except (OSError, UnicodeDecodeError):
            return None
        words.update(word.lower() for word in _WORD.findall(text))
    return words


def _soften_for_parse_errors(
    finding: Finding,
    broken: set[str] | None,
    by_path: dict[str, FileIndex],
) -> Finding:
    """Drop a claim to 70 only when a file that failed to parse mentions the name it rests on."""
    if finding.rule not in _PARSE_SENSITIVE or finding.confidence <= 70:
        return finding
    if _is_local(finding, by_path):
        return finding
    if broken is not None and not _mentioned(finding, broken, by_path):
        return finding
    status = "POSSIBLY_DEAD" if finding.status == "DEAD" else finding.status
    return replace(
        finding,
        confidence=70,
        status=status,
        evidence=finding.evidence + (_PARSE_ERROR_NOTE,),
    )


def _mentioned(finding: Finding, broken: set[str], by_path: dict[str, FileIndex]) -> bool:
    if finding.rule == "UNUSED_DEPENDENCY":
        name = finding.symbol.lower()
        return bool({name, name.replace("-", "_"), name.replace("-", "")} & broken) or any(
            part in broken for part in name.split("-") if len(part) > 2
        )
    if finding.rule == "POSSIBLY_UNUSED_MODULE":
        parts = Path(finding.path).with_suffix("").parts
        return any(part.lower() in broken for part in parts if part != "__init__")
    prefix = f"{finding.rule}:{finding.path}:"
    if not finding.fingerprint.startswith(prefix):
        return True
    return finding.symbol.lower() in broken


def _is_local(finding: Finding, by_path: dict[str, FileIndex]) -> bool:
    """A name bound inside a function cannot be imported by another file."""
    prefix = f"{finding.rule}:{finding.path}:"
    index = by_path.get(finding.path)
    if index is None or not finding.fingerprint.startswith(prefix):
        return False
    qualname = finding.fingerprint[len(prefix) :]
    return any(item.qualname == qualname and item.scope_kind == "function" for item in index.bindings)


def _finish(
    findings: list[Finding],
    errors: list[ParseError],
    files_scanned: int,
    root: Path,
    config: Config,
    baseline: str | Path | None,
    apply_baseline: bool,
    report_only: set[str] | None,
) -> ScanResult:
    """Apply filters that do not change the analysis itself."""
    findings = _apply_baseline(findings, root, config, baseline, apply_baseline)
    findings = [finding for finding in findings if finding.confidence >= config.min_confidence]
    if report_only is not None:
        findings = [finding for finding in findings if finding.path in report_only]
    findings.sort(key=lambda finding: (finding.path, finding.line, finding.column, finding.rule, finding.symbol))
    return ScanResult(findings=tuple(findings), errors=tuple(errors), files_scanned=files_scanned)


def _analysis_payload(config: Config, fold: dict[str, str]) -> str:
    """Config fields that change which names the analysis reports."""
    payload = {
        "ignore": list(config.ignore),
        "exclude": list(config.exclude),
        "entry_patterns": list(config.entry_patterns),
        "framework_decorators": list(config.framework_decorators),
        "entry_points": list(config.entry_points),
        "fold": sorted(fold.items()),
        "duplicate_min_statements": config.duplicate_min_statements,
        "frameworks": list(config.frameworks),
        "ignore_names": list(config.ignore_names),
        "ignore_decorators": list(config.ignore_decorators),
        "ignore_bases": list(config.ignore_bases),
        "report_dev_dependencies": config.report_dev_dependencies,
    }
    return json.dumps(payload, separators=(",", ":"))


def _input_stamps(root: Path, paths: list[Path]) -> list[list[object]]:
    rows: list[list[object]] = []
    for path in paths:
        relative = relative_posix(path, root)
        try:
            stat = path.stat()
        except OSError:
            rows.append([relative, -1, -1])
            continue
        rows.append([relative, stat.st_size, stat.st_mtime_ns])
    rows.sort()
    return rows


def _index_files(
    files: list[Path],
    root: Path,
    fold: dict[str, str],
    workers: int,
    use_cache: bool,
    duplicate_min_statements: int,
    overlays: dict[str, str] | None,
    progress: ScanProgress | None = None,
) -> tuple[list[FileIndex], list[ParseError]]:
    indexes: list[FileIndex] = []
    errors: list[ParseError] = []
    queued: list[CacheEntry] = []
    pending: list[tuple[str, str, str | None, str, bool]] = []
    fold_pairs = tuple(sorted(fold.items()))
    total = len(files)
    cached_count = 0
    for file in files:
        relpath = relative_posix(file, root)
        source = overlays.get(str(file.resolve())) if overlays else None
        stamp = ""
        if use_cache and source is None:
            stat = file.stat()
            stamp = cache_stamp(stat.st_size, stat.st_mtime_ns, fold, duplicate_min_statements)
            cached = load_cached(root, relpath, stamp)
            if cached is not None:
                current = str(file)
                if cached.path != current:
                    cached = replace(cached, path=current)
                    store_cached(root, relpath, stamp, cached, queued)
                indexes.append(cached)
                cached_count += 1
                _status(progress, "indexing files", _index_detail(cached_count, total, cached_count))
                continue
        pending.append((str(file), relpath, source, stamp, source is not None))

    worker_count = (os.cpu_count() or 1) if workers == 0 else workers
    jobs = [
        (path, relpath, source, fold_pairs, duplicate_min_statements) for path, relpath, source, _, _ in pending
    ]
    produced: list[tuple[str, FileIndex | ParseError] | None] = []
    if worker_count <= 1 or len(jobs) < _POOL_MIN_FILES:
        for index, job in enumerate(jobs, start=1):
            produced.append(_index_job(job))
            done = cached_count + index
            _status(progress, "indexing files", _index_detail(done, total, cached_count))
    else:
        produced = [None] * len(jobs)
        with ProcessPoolExecutor(max_workers=worker_count) as pool:
            futures = {pool.submit(_index_job, job): index for index, job in enumerate(jobs)}
            finished = 0
            for future in as_completed(futures):
                produced[futures[future]] = future.result()
                finished += 1
                done = cached_count + finished
                _status(progress, "indexing files", _index_detail(done, total, cached_count))
    for (_, relpath, _, stamp, overlaid), item in zip(pending, produced, strict=True):
        if item is None:
            continue
        kind, payload = item
        if kind == "error" and isinstance(payload, ParseError):
            errors.append(payload)
            continue
        if isinstance(payload, FileIndex):
            indexes.append(payload)
            if use_cache and stamp and not overlaid:
                store_cached(root, relpath, stamp, payload, queued)
    remember_cached(root, queued)
    return indexes, errors


def _backend() -> PythonAstBackend:
    return PythonAstBackend()


def _index_job(
    job: tuple[str, str, str | None, tuple[tuple[str, str], ...], int],
) -> tuple[str, FileIndex | ParseError]:
    """Index one file in this process or a worker process."""
    path, relpath, source, fold_pairs, duplicate_min_statements = job
    try:
        if source is None:
            source, _ = read_python_source(path)
        index = _backend().index_source(
            path,
            source,
            fold=dict(fold_pairs),
            duplicate_min_statements=duplicate_min_statements,
        )
    except (UnicodeDecodeError, OSError) as exc:
        return "error", ParseError(path=relpath, line=1, column=1, message=str(exc))
    except SyntaxError as exc:
        return (
            "error",
            ParseError(
                path=relpath,
                line=exc.lineno or 1,
                column=exc.offset or 1,
                message=exc.msg or "syntax error",
            ),
        )
    return "ok", index


def _apply_baseline(
    findings: list[Finding],
    root: Path,
    config: Config,
    baseline: str | Path | None,
    apply_baseline: bool,
) -> list[Finding]:
    if not apply_baseline:
        return findings
    chosen = baseline if baseline is not None else config.baseline
    if not chosen:
        return findings
    path = Path(chosen)
    if not path.is_absolute():
        path = root / path
    if not path.is_file():
        raise BaselineNotFoundError(path)
    return filter_baselined(findings, load_baseline(path))


def _status(progress: ScanProgress | None, label: str, detail: str = "") -> None:
    if progress is not None:
        progress.update(label, detail)


def _index_detail(done: int, total: int, cached: int) -> str:
    detail = f"{done}/{total}"
    if cached:
        detail += f", {cached} cached"
    return detail
