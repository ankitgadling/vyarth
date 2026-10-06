"""Command line interface."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import tomllib

from vyarth.baseline import write_baseline
from vyarth.config import FAIL_ON_LEVELS, load_config
from vyarth.engine import scan
from vyarth.fix import apply_fixes
from vyarth.lsp import serve
from vyarth.progress import ScanProgress
from vyarth.report import render_github, render_json, render_sarif, render_text


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="vyarth", description="Find Python code that is never used.")
    subcommands = parser.add_subparsers(dest="command", required=True)
    scan_parser = subcommands.add_parser("scan", help="Scan a file or directory")
    _add_scan_arguments(scan_parser)
    baseline_parser = subcommands.add_parser("baseline", help="Write a fingerprint baseline for the current findings")
    baseline_parser.add_argument("path", nargs="?", default=".")
    baseline_parser.add_argument("--output", "-o", default="vyarth-baseline.json")
    baseline_parser.add_argument("--config", default=None)
    fix_parser = subcommands.add_parser("fix", help="Remove safe dead code and rescan")
    _add_scan_arguments(fix_parser)
    subcommands.add_parser("lsp", help="Serve diagnostics over stdin and stdout")
    args = parser.parse_args(argv)

    if args.command == "lsp":
        serve()
        return 0

    target = Path(args.path)
    if not target.exists():
        print(f"path not found: {args.path}", file=sys.stderr)
        return 2
    root = target.resolve().parent if target.is_file() else target.resolve()
    try:
        config_path = Path(args.config) if args.config else None
        config = load_config(root, config_path)
        defines = _defines(getattr(args, "define", None))
    except (OSError, tomllib.TOMLDecodeError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2

    try:
        if args.command == "baseline":
            result = _scan_with_progress(target, config=config, apply_baseline=False)
            output = Path(args.output)
            if not output.is_absolute():
                output = root / output
            write_baseline(output, result.findings)
            print(f"wrote {output}")
            return 0
        if args.command == "fix":
            result = _run_scan(target, root, config, args, defines)
            notes = apply_fixes(root, result.findings)
            for note in notes:
                print(note)
            if notes:
                result = _run_scan(target, root, config, args, defines)
        else:
            result = _run_scan(target, root, config, args, defines)
    except FileNotFoundError as exc:
        print(f"baseline not found: {exc.filename or exc}", file=sys.stderr)
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
    if args.command != "fix" or result.findings:
        rendered = {
            "json": render_json,
            "sarif": render_sarif,
            "github": render_github,
        }.get(getattr(args, "format", "text"), render_text)
        sys.stdout.write(rendered(result))
    fail_on = args.fail_on if getattr(args, "fail_on", None) is not None else config.fail_on
    if not fail_on:
        return 1 if result.findings else 0
    floor = FAIL_ON_LEVELS[fail_on]
    return 1 if any(finding.confidence >= floor for finding in result.findings) else 0


def _add_scan_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("path", nargs="?", default=".")
    parser.add_argument("--format", choices=("text", "json", "sarif", "github"), default="text")
    parser.add_argument("--config", default=None)
    parser.add_argument("--min-confidence", type=int, default=None)
    parser.add_argument("--baseline", default=None)
    parser.add_argument("--fail-on", choices=tuple(FAIL_ON_LEVELS), default=None)
    parser.add_argument("--workers", type=int, default=None)
    parser.add_argument("--define", action="append", default=None, metavar="NAME=VALUE")
    parser.add_argument("--changed", action="store_true")
    parser.add_argument("--changed-from", default="HEAD")
    parser.add_argument("--no-cache", action="store_true")


def _run_scan(target: Path, root: Path, config, args, defines: dict[str, str]):
    del root
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
    )


def _scan_with_progress(target: Path, **kwargs):
    progress = ScanProgress()
    progress.open()
    try:
        result = scan(target, progress=progress, **kwargs)
        progress.succeed(result.files_scanned)
        return result
    finally:
        progress.close()


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
