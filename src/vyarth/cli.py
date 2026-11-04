"""Command line interface."""

from __future__ import annotations

import argparse
from dataclasses import replace
import json
from pathlib import Path
import sys
import tomllib

from vyarth import __version__
from vyarth.baseline import append_baseline, prune_baseline, write_baseline
from vyarth.config import FAIL_ON_LEVELS, Config, load_config
from vyarth.discover import project_root
from vyarth.engine import BaselineNotFoundError, scan
from vyarth.eval_harness import run_builtin
from vyarth.explain import explain_payload, locate, render_explain
from vyarth.fix import (
    applied_dicts,
    apply_fixes,
    apply_fixes_verified,
    ensure_clean,
    render_applied,
    render_fix_diff,
    render_fix_diff_json,
)
from vyarth.lsp import serve
from vyarth.mcp import serve as serve_mcp
from vyarth.model import ScanResult, resolve_ids
from vyarth.present import canonical_rules, summary_line, truncation_line
from vyarth.progress import ScanProgress
from vyarth.report import render_concise, render_github, render_json, render_jsonl, render_sarif, render_text

_MACHINE_FORMATS = {"json", "jsonl", "sarif"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="vyarth", description="Find Python code that is never used.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subcommands = parser.add_subparsers(dest="command", required=True)
    scan_parser = subcommands.add_parser("scan", help="Scan a file or directory")
    _add_scan_arguments(scan_parser)
    _add_window_arguments(scan_parser)
    baseline_parser = subcommands.add_parser("baseline", help="Write a fingerprint baseline for the current findings")
    _add_scan_arguments(baseline_parser)
    baseline_parser.add_argument(
        "--output",
        "-o",
        default="vyarth-baseline.json",
        help="Baseline file to write. A relative path is resolved from the project root. Default: vyarth-baseline.json.",
    )
    baseline_parser.add_argument("--add", default=None, metavar="ID[,ID]", help="Append these findings. Requires --reason.")
    baseline_parser.add_argument("--reason", default=None, help="Why the added findings are baselined.")
    baseline_parser.add_argument("--prune", action="store_true", help="Drop baseline entries the scan no longer reports.")
    fix_parser = subcommands.add_parser("fix", help="Remove safe dead code and rescan")
    _add_scan_arguments(fix_parser)
    _add_window_arguments(fix_parser)
    fix_parser.add_argument("--dry-run", action="store_true", help="Print the edits and do not write them.")
    fix_parser.add_argument("--diff", action="store_true", help="Print a unified diff and do not write it.")
    fix_parser.add_argument(
        "--unsafe",
        action="store_true",
        help="Also remove package re-exports and side-effect submodule imports.",
    )
    fix_parser.add_argument(
        "--select-id",
        default=None,
        metavar="ID[,ID]",
        help="Fix only these ids or fingerprints. An id that matches two findings is refused.",
    )
    fix_parser.add_argument(
        "--unsafe-fixes",
        action="store_true",
        help="Also delete the selected 90-99 findings. Requires --select-id.",
    )
    fix_parser.add_argument(
        "--verify",
        nargs="?",
        const="",
        default=None,
        metavar="CMD",
        help="Compile the edited files, then run CMD. With no CMD, only py_compile runs. A failure restores the files and exits 3.",
    )
    fix_parser.add_argument(
        "--verify-each",
        action="store_true",
        help="Verify one file at a time and keep the files that pass.",
    )
    fix_parser.add_argument(
        "--require-clean",
        action="store_true",
        help="Refuse the fix when the git worktree has uncommitted changes.",
    )
    subcommands.add_parser("lsp", help="Serve diagnostics over stdin and stdout")
    mcp_parser = subcommands.add_parser("mcp", help="Serve MCP tools on stdin and stdout")
    mcp_parser.add_argument("--root", default=".", help="Reject tool paths that resolve outside this directory.")
    mcp_writes = mcp_parser.add_mutually_exclusive_group()
    mcp_writes.add_argument("--allow-write", action="store_true", help="Expose the tools that write. This is the default.")
    mcp_writes.add_argument("--read-only", action="store_true", help="Hide apply_fix and add_to_baseline.")
    init_parser = subcommands.add_parser("init", help="Write an agent snippet and an MCP config")
    init_parser.add_argument("--agent", required=True, choices=("cursor", "claude", "copilot"))
    init_parser.add_argument("--force", action="store_true", help="Overwrite files that already exist.")
    init_parser.add_argument("--root", default=".", help="Directory that receives the files.")
    subcommands.add_parser("eval", help="Run the scripted agent eval and print metrics")
    subcommands.add_parser("schema", help="Print the version 1 report JSON Schema")
    explain_parser = subcommands.add_parser("explain", help="Explain one finding")
    explain_parser.add_argument("selector", help="An id, a fingerprint, or path:line.")
    _add_scan_arguments(explain_parser)
    _add_window_arguments(explain_parser)
    args = parser.parse_args(argv)
    if getattr(args, "output_format", None):
        args.format = args.output_format

    if args.command == "lsp":
        serve()
        return 0
    if args.command == "mcp":
        serve_mcp(root=Path(args.root).resolve(), read_only=bool(args.read_only))
        return 0
    if args.command == "init":
        return _init_agent(Path(args.root).resolve(), args.agent, bool(args.force))
    if args.command == "eval":
        metrics = run_builtin()
        sys.stdout.write(json.dumps(metrics, indent=2) + "\n")
        return 1 if metrics["wrong_deletions"] else 0
    if args.command == "schema":
        sys.stdout.write(_schema_text())
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
        if getattr(args, "report_unused_ignores", False):
            config = replace(config, report_unused_ignores=True)
        excludes = getattr(args, "exclude", None)
        if excludes:
            config = replace(config, exclude=config.exclude + tuple(excludes))
        defines = _defines(getattr(args, "define", None))
    except (OSError, tomllib.TOMLDecodeError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2

    try:
        if args.command == "baseline":
            result = _scan_with_progress(
                target,
                config=config,
                min_confidence=args.min_confidence,
                apply_baseline=False,
                workers=args.workers,
                defines=defines or None,
                changed=args.changed,
                changed_from=args.changed_from,
                use_cache=not args.no_cache,
                quiet=args.quiet,
            )
            output = Path(args.output)
            if not output.is_absolute():
                output = root / output
            if args.add and args.prune:
                print("--add and --prune are separate", file=sys.stderr)
                return 2
            if args.add:
                if not (args.reason and str(args.reason).strip()):
                    print("--add requires --reason", file=sys.stderr)
                    return 2
                chosen = resolve_ids(result.findings, _id_tokens(args.add))
                added, _total = append_baseline(output, chosen, str(args.reason).strip())
                print(f"added {added}")
                return 0
            if args.prune:
                if not output.is_file():
                    print(f"baseline not found: {output}", file=sys.stderr)
                    return 2
                pruned, _total = prune_baseline(output, result.findings)
                print(f"pruned {pruned}")
                return 0
            write_baseline(output, result.findings)
            print(f"wrote {output}")
            return 0
        if args.command == "fix":
            result = _run_scan(target, config, args, defines)
            if getattr(args, "select_id", None):
                result = replace(
                    result,
                    findings=resolve_ids(result.findings, _id_tokens(args.select_id)),
                    census=None,
                )
            if args.unsafe_fixes and not args.select_id:
                print("--unsafe-fixes requires --select-id", file=sys.stderr)
                return 2
            if args.require_clean:
                ensure_clean(root)
            if args.diff:
                if args.format == "json":
                    sys.stdout.write(
                        render_fix_diff_json(
                            root,
                            result.findings,
                            unsafe=args.unsafe,
                            unsafe_fixes=args.unsafe_fixes,
                        )
                    )
                else:
                    sys.stdout.write(
                        render_fix_diff(root, result.findings, unsafe=args.unsafe, unsafe_fixes=args.unsafe_fixes)
                    )
            elif not args.dry_run and (args.verify is not None or args.verify_each):
                command = args.verify or config.fix_verify_command
                report = apply_fixes_verified(
                    root,
                    result.findings,
                    unsafe=args.unsafe,
                    unsafe_fixes=args.unsafe_fixes,
                    verify_cmd=command,
                    timeout=config.fix_verify_timeout,
                    verify_each=args.verify_each,
                )
                note_stream = sys.stderr if args.format in _MACHINE_FORMATS else sys.stdout
                for item in report.applied:
                    print(render_applied(item, wrote=True), file=note_stream)
                for skipped in report.skipped:
                    print(f"skipped {skipped.path}:{skipped.line} {skipped.symbol}: {skipped.reason}", file=sys.stderr)
                args._applied = applied_dicts(list(report.applied))
                if report.rolled_back and not report.applied:
                    sys.stdout.write(json.dumps(report.failure(), indent=2) + "\n")
                    return 3
                if report.applied:
                    result = _run_scan(target, config, args, defines)
                if report.rolled_back:
                    args._verify_exit = 3
            else:
                applied = apply_fixes(
                    root,
                    result.findings,
                    unsafe=args.unsafe,
                    unsafe_fixes=args.unsafe_fixes,
                    write=not args.dry_run,
                )
                note_stream = sys.stderr if args.format in _MACHINE_FORMATS else sys.stdout
                for item in applied:
                    print(render_applied(item, wrote=not args.dry_run), file=note_stream)
                if applied and not args.dry_run and any(item.line > 0 for item in applied):
                    result = _run_scan(target, config, args, defines)
                args._applied = applied_dicts(applied)
        elif args.command == "explain":
            result = _run_scan(target, config, args, defines)
            payload = explain_payload(root, config, locate(result.findings, args.selector))
            sys.stdout.write(render_explain(payload, args.format))
            return 0
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
    if not getattr(args, "diff", False) and (args.command != "fix" or result.findings or args.format in _MACHINE_FORMATS):
        sys.stdout.write(_render(result, getattr(args, "format", "text"), root, args))
    fail_on = args.fail_on if getattr(args, "fail_on", None) is not None else config.fail_on
    code = _exit_code(result, fail_on, summary=bool(getattr(args, "summary", False)))
    if getattr(args, "_verify_exit", None) == 3:
        return 3
    if getattr(args, "exit_zero", False) and code == 1:
        return 0
    return code


def _add_scan_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("path", nargs="?", default=".", help="File or directory to scan. Default: the current directory.")
    parser.add_argument(
        "--format",
        dest="format",
        choices=("text", "json", "jsonl", "sarif", "github", "concise"),
        default="text",
        help="Output format. Default: text.",
    )
    parser.add_argument(
        "--output-format",
        default=None,
        choices=("text", "json", "jsonl", "sarif", "github", "concise"),
        help="Alias of --format.",
    )
    parser.add_argument(
        "--concise-confidence",
        action="store_true",
        help="Append the confidence score to concise output.",
    )
    parser.add_argument(
        "--show-fixes",
        action="store_true",
        help="Include edit objects on findings whose fix is safe.",
    )
    parser.add_argument(
        "--exit-zero",
        action="store_true",
        help="Exit 0 when findings remain. A path, config, or baseline error still exits 2.",
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
        type=_bounded_int(0, 100),
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
        type=_non_negative_int,
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
    parser.add_argument(
        "--report-unused-ignores",
        action="store_true",
        help="Report ignore directives that suppressed nothing.",
    )
    parser.add_argument(
        "--baseline-mode",
        choices=("new", "all"),
        default=None,
        help="new hides baselined findings. all keeps them and sets baselined to true.",
    )


def _add_window_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--summary",
        action="store_true",
        help="Print one summary line, or the summary object for json, jsonl, and sarif.",
    )
    parser.add_argument(
        "--max-findings",
        type=_at_least_zero,
        default=None,
        metavar="N",
        help="Keep the first N findings. With no --sort, this sorts by confidence.",
    )
    parser.add_argument(
        "--sort",
        choices=("confidence", "path", "rule"),
        default=None,
        help="Order findings. Default: path. confidence is highest first, then safe fixes.",
    )
    parser.add_argument(
        "--select",
        default=None,
        metavar="RULE[,RULE]",
        help="Keep these rules. Accepts UNUSED_FUNCTION, unused-function, or unused_function.",
    )
    parser.add_argument(
        "--ignore-rule",
        default=None,
        metavar="RULE[,RULE]",
        help="Drop these rules. Same names as --select.",
    )
    parser.add_argument("--fixable-only", action="store_true", help="Keep findings a safe fix can delete.")
    parser.add_argument("--paths-only", action="store_true", help="Print the unique file paths and no findings.")
    parser.add_argument(
        "--brief-evidence",
        action="store_true",
        help="Omit the five checklist evidence lines. jsonl omits them by default.",
    )


def _run_scan(target: Path, config: Config, args: argparse.Namespace, defines: dict[str, str]) -> ScanResult:
    select = canonical_rules(_id_tokens(args.select)) if getattr(args, "select", None) else ()
    ignore_rules = canonical_rules(_id_tokens(args.ignore_rule)) if getattr(args, "ignore_rule", None) else ()
    sort = getattr(args, "sort", None)
    max_findings = getattr(args, "max_findings", None)
    if args.command == "explain":
        sort = None
        max_findings = None
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
        sort=sort,
        max_findings=max_findings,
        select=select,
        ignore_rules=ignore_rules,
        fixable_only=bool(getattr(args, "fixable_only", False)),
        baseline_mode=getattr(args, "baseline_mode", None) or "new",
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


def _render(result: ScanResult, fmt: str, root: Path, args: argparse.Namespace) -> str:
    show_fixes = bool(getattr(args, "show_fixes", False))
    applied = getattr(args, "_applied", None)
    brief = fmt == "jsonl" or bool(getattr(args, "brief_evidence", False))
    if getattr(args, "summary", False):
        if fmt in {"json", "jsonl", "sarif"}:
            report = result.to_report(root=root, show_fixes=show_fixes, applied=applied, brief_evidence=brief)
            return json.dumps(report["summary"], indent=2) + "\n"
        return summary_line(result)
    if getattr(args, "paths_only", False):
        paths = sorted({finding.path for finding in result.findings})
        if fmt in {"json", "jsonl", "sarif"}:
            report = result.to_report(root=root, show_fixes=show_fixes, applied=applied, brief_evidence=brief)
            return json.dumps({"paths": paths, "summary": report["summary"]}, indent=2) + "\n"
        body = "".join(f"{path}\n" for path in paths)
        if fmt in {"text", "concise"}:
            return body + truncation_line(result)
        return body
    if fmt == "json":
        rendered = render_json(result, root, show_fixes=show_fixes, applied=applied, brief_evidence=brief)
    elif fmt == "jsonl":
        rendered = render_jsonl(result, root, show_fixes=show_fixes, applied=applied, brief_evidence=brief)
    elif fmt == "sarif":
        rendered = render_sarif(result, root=root, show_fixes=show_fixes, brief_evidence=brief)
    elif fmt == "github":
        rendered = render_github(result, root=root)
    elif fmt == "concise":
        rendered = render_concise(result, confidence=bool(getattr(args, "concise_confidence", False)))
    else:
        rendered = render_text(result, brief_evidence=brief)
    if fmt in {"text", "concise"}:
        return rendered + truncation_line(result)
    return rendered


def _exit_code(result: ScanResult, fail_on: str | None, *, summary: bool) -> int:
    census = result.census
    if not fail_on:
        total = census.total if census is not None else len(result.findings)
        return 1 if total else 0
    floor = FAIL_ON_LEVELS[fail_on]
    if summary and census is not None:
        bands = dict(census.by_band)
        if floor <= 0:
            return 1 if census.total else 0
        high = bands.get("100", 0) + bands.get("90-99", 0)
        if floor <= 70:
            return 1 if high + bands.get("70-89", 0) else 0
        return 1 if high else 0
    return 1 if any(finding.confidence >= floor for finding in result.findings) else 0


def _init_agent(root: Path, agent: str, force: bool) -> int:
    files = _agent_files(root, agent)
    existing = [path for path, _text in files if path.exists()]
    if existing and not force:
        names = ", ".join(str(path) for path in existing)
        print(f"refusing to overwrite {names}", file=sys.stderr)
        return 2
    for path, text in files:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        print(f"wrote {path}")
    return 0


def _agent_files(root: Path, agent: str) -> list[tuple[Path, str]]:
    snippet = _AGENT_SNIPPET
    if agent == "cursor":
        return [
            (root / ".cursor" / "rules" / "vyarth.mdc", _CURSOR_RULE),
            (root / ".cursor" / "mcp.json", _MCP_SERVERS),
        ]
    if agent == "claude":
        return [
            (root / "CLAUDE.md", snippet),
            (root / ".mcp.json", _MCP_SERVERS),
        ]
    return [
        (root / ".github" / "copilot-instructions.md", snippet),
        (root / ".vscode" / "mcp.json", _VSCODE_MCP),
    ]


_AGENT_SNIPPET = """# Vyarth

Run `vyarth scan . --sort confidence --max-findings 50 --format jsonl` before deleting code.
Explain a finding with `vyarth explain ID` before deleting a score from 90 to 99.
Never delete a 9x finding in migrations/, settings, conf.py, or a string-referenced class without explain.
Apply a fix with `vyarth fix --select-id ID --verify`.
Suppress with `# vyarth: ignore[unused-function] -- reason` or `vyarth baseline --add ID --reason "..."`.
"""

_CURSOR_RULE = """---
description: How to use vyarth on this project
globs: "**/*.py"
alwaysApply: false
---
""" + _AGENT_SNIPPET

_MCP_SERVERS = """{
  "mcpServers": {
    "vyarth": {
      "command": "vyarth",
      "args": ["mcp"]
    }
  }
}
"""

_VSCODE_MCP = """{
  "servers": {
    "vyarth": {
      "command": "vyarth",
      "args": ["mcp"]
    }
  }
}
"""


def _id_tokens(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def _schema_text() -> str:
    from importlib.resources import files

    return files("vyarth").joinpath("schema/report.v1.json").read_text(encoding="utf-8")


def _bounded_int(low: int, high: int):
    def parse(value: str) -> int:
        try:
            number = int(value)
        except ValueError as exc:
            raise argparse.ArgumentTypeError("expected an integer") from exc
        if not low <= number <= high:
            raise argparse.ArgumentTypeError(f"must be between {low} and {high}")
        return number

    return parse


def _at_least_zero(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("expected an integer") from exc
    if number < 0:
        raise argparse.ArgumentTypeError("must be zero or a positive integer")
    return number


def _non_negative_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("workers must be an integer") from exc
    if number < 0:
        raise argparse.ArgumentTypeError("workers must be zero or a positive integer")
    return number


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
