"""Scan orchestration."""

from __future__ import annotations

from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import replace
import os
from pathlib import Path

from vyarth.baseline import filter_baselined, load_baseline
from vyarth.confidence import apply_confidence
from vyarth.config import Config, load_config
from vyarth.dependencies import dependency_findings
from vyarth.discover import discover_files, is_test_path, project_root, relative_posix
from vyarth.duplicates import duplicate_findings
from vyarth.ignore import apply_ignores
from vyarth.incremental import cache_stamp, changed_python_files, load_cached, prune_cache, store_cached
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
    files = [target] if single_file else discover_files(root, config, within=requested)
    fold = config.fold_map()
    if defines:
        fold.update(defines)
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

    findings = collect_findings(indexes, root, config, check_modules=not single_file, progress=progress)
    _status(progress, "checking dependencies")
    if not single_file:
        dep_findings, dep_errors = dependency_findings(indexes, root, within=requested, config=config)
        findings.extend(dep_findings)
        errors.extend(dep_errors)
    _status(progress, "checking duplicate code")
    findings.extend(duplicate_findings(indexes, root, config.duplicate_min_statements))
    findings = apply_confidence(findings, indexes, root)
    findings = [finding for finding in findings if not is_test_path(finding.path)]
    by_path = {relative_posix(Path(index.path), root): index for index in indexes}
    findings = apply_ignores(findings, by_path, config)
    findings = _apply_baseline(findings, root, config, baseline, apply_baseline)
    findings = [finding for finding in findings if finding.confidence >= config.min_confidence]
    if report_only is not None:
        findings = [finding for finding in findings if finding.path in report_only]
    findings.sort(key=lambda finding: (finding.path, finding.line, finding.column, finding.rule, finding.symbol))
    if use_cache and not single_file and requested == root and not overlays:
        prune_cache(root, {index.path for index in indexes})
    return ScanResult(findings=tuple(findings), errors=tuple(errors), files_scanned=len(indexes))


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
                store_cached(root, relpath, stamp, payload)
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
            source = Path(path).read_text(encoding="utf-8")
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
