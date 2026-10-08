"""Command line interface."""

from __future__ import annotations

import argparse
from dataclasses import replace
import json
from pathlib import Path
import sys
import tomllib

from vyarth import __version__
from vyarth.baseline import write_baseline
from vyarth.config import FAIL_ON_LEVELS, Config, load_config
from vyarth.discover import project_root
from vyarth.engine import BaselineNotFoundError, scan
from vyarth.fix import apply_fixes, render_fix_diff
from vyarth.lsp import serve
from vyarth.model import ScanResult
from vyarth.progress import ScanProgress
from vyarth.report import render_concise, render_github, render_json, render_sarif, render_text


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="vyarth", description="Find Python code that is never used.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subcommands = parser.add_subparsers(dest="command", required=True)
    scan_parser = subcommands.add_parser("scan", help="Scan a file or directory")
    _add_scan_arguments(scan_parser)
    baseline_parser = subcommands.add_parser("baseline", help="Write a fingerprint baseline for the current findings")
    baseline_parser.add_argument("path", nargs="?", default=".", help="File or directory to scan. Default: the current directory.")
    baseline_parser.add_argument(
        "--output",
        "-o",
        default="vyarth-baseline.json",
        help="Baseline file to write. A relative path is resolved from the project root. Default: vyarth-baseline.json.",
    )
    baseline_parser.add_argument(
        "--config",
        default=None,
        help="Read this TOML file instead of discovering pyproject.toml or vyarth.toml.",
    )
    fix_parser = subcommands.add_parser("fix", help="Remove safe dead code and rescan")
    _add_scan_arguments(fix_parser)
    fix_parser.add_argument("--dry-run", action="store_true", help="Print the edits and do not write them.")
    fix_parser.add_argument("--diff", action="store_true", help="Print a unified diff and do not write it.")
    fix_parser.add_argument(
        "--unsafe",
        action="store_true",
        help="Also remove package re-exports and side-effect submodule imports.",
    )
    subcommands.add_parser("lsp", help="Serve diagnostics over stdin and stdout")
    args = parser.parse_args(argv)

    if args.command == "lsp":
        serve()
        return 0

    target = Path(args.path)
    if not target.exists():
        print(f"path not found: {args.path}", file=sys.stderr)
        return 2
    requested = target.resolve().parent if target.is_file() else target.resolve()
    root = project_root(requested)
    try:
        config_path = Path(args.config) if args.config else None
        config = load_config(root, config_path)
        excludes = getattr(args, "exclude", None)
        if excludes:
            config = replace(config, exclude=config.exclude + tuple(excludes))
        defines = _defines(getattr(args, "define", None))
    except (OSError, tomllib.TOMLDecodeError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2

    try:
        if args.command == "baseline":
            result = _scan_with_progress(target, config=config, apply_baseline=False, quiet=False)
            output = Path(args.output)
            if not output.is_absolute():
                output = root / output
            write_baseline(output, result.findings)
            print(f"wrote {output}")
            return 0
        if args.command == "fix":
            result = _run_scan(target, config, args, defines)
            if args.diff:
                sys.stdout.write(render_fix_diff(root, result.findings, unsafe=args.unsafe))
            else:
                notes = apply_fixes(root, result.findings, unsafe=args.unsafe, write=not args.dry_run)
                for note in notes:
                    print(note)
                if notes and not args.dry_run:
                    result = _run_scan(target, config, args, defines)
        else:
            result = _run_scan(target, config, args, defines)
    except BaselineNotFoundError as exc:
        print(f"baseline not found: {exc.filename or exc}", file=sys.stderr)
        return 2
    except FileNotFoundError as exc:
        print(f"file not found: {exc.filename or exc}", file=sys.stderr)
        return 2
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except (json.JSONDecodeError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    for error in result.errors:
        print(
            f"SYNTAX_ERROR\nFile: {error.path}\nLine: {error.line}\nMessage: {error.message}\n",
            file=sys.stderr,
        )
    if not getattr(args, "diff", False) and (args.command != "fix" or result.findings):
        sys.stdout.write(_render(result, getattr(args, "format", "text"), root))
    fail_on = args.fail_on if getattr(args, "fail_on", None) is not None else config.fail_on
    if not fail_on:
        return 1 if result.findings else 0
    floor = FAIL_ON_LEVELS[fail_on]
    return 1 if any(finding.confidence >= floor for finding in result.findings) else 0


def _add_scan_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("path", nargs="?", default=".", help="File or directory to scan. Default: the current directory.")
    parser.add_argument(
        "--format",
        choices=("text", "json", "sarif", "github", "concise"),
        default="text",
        help="Output format. Default: text.",
    )
    parser.add_argument("--quiet", action="store_true", help="Do not print scan progress.")
    parser.add_argument(
        "--exclude",
        action="append",
        default=None,
        metavar="PATTERN",
        help="Do not index paths matching this pattern. Repeat the flag to add more.",
    )
    parser.add_argument(
        "--config",
        default=None,
        help="Read this TOML file instead of discovering pyproject.toml or vyarth.toml.",
    )
    parser.add_argument(
        "--min-confidence",
        type=int,
        default=None,
        help="Drop findings below this score. Overrides the config value.",
    )
    parser.add_argument(
        "--baseline",
        default=None,
        help="Report only fingerprints that are not already in this file.",
    )
    parser.add_argument(
        "--fail-on",
        choices=tuple(FAIL_ON_LEVELS),
        default=None,
        help="Exit 1 only when a printed finding is at or above 90, 70, or 0.",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=None,
        help="Process pool size. 1 stays in-process. 0 uses the CPU count. Overrides the config value.",
    )
    parser.add_argument(
        "--define",
        action="append",
        default=None,
        metavar="NAME=VALUE",
        help="Fold this name as a constant. Repeat the flag for more names.",
    )
    parser.add_argument(
        "--changed",
        action="store_true",
        help="Index the project, then keep findings only in Python files changed against git.",
    )
    parser.add_argument("--changed-from", default="HEAD", help="Git ref for --changed. Default: HEAD.")
    parser.add_argument("--no-cache", action="store_true", help="Reparse every file. The cache lives in .vyarth/cache.")


def _run_scan(target: Path, config: Config, args: argparse.Namespace, defines: dict[str, str]) -> ScanResult:
    return _scan_with_progress(
        target,
        config=config,
        min_confidence=args.min_confidence,
        baseline=args.baseline,
        workers=args.workers,
        defines=defines or None,
        changed=args.changed,
        changed_from=args.changed_from,
        use_cache=not args.no_cache,
        quiet=args.quiet,
    )


def _scan_with_progress(target: Path, *, quiet: bool = False, **kwargs) -> ScanResult:
    progress = None if quiet else ScanProgress()
    if progress is not None:
        progress.open()
    try:
        result = scan(target, progress=progress, **kwargs)
        if progress is not None:
            progress.succeed(result.files_scanned)
        return result
    finally:
        if progress is not None:
            progress.close()


def _render(result: ScanResult, fmt: str, root: Path) -> str:
    if fmt == "json":
        return render_json(result)
    if fmt == "sarif":
        return render_sarif(result)
    if fmt == "github":
        return render_github(result, root=root)
    if fmt == "concise":
        return render_concise(result)
    return render_text(result)


def _defines(values: list[str] | None) -> dict[str, str]:
    found: dict[str, str] = {}
    for item in values or []:
        if "=" not in item:
            raise ValueError(f"define must be NAME=VALUE: {item}")
        key, _, value = item.partition("=")
        if not key:
            raise ValueError(f"define must be NAME=VALUE: {item}")
        found[key] = value
    return found


if __name__ == "__main__":
    raise SystemExit(main())
