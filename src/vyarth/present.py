"""Sort, rule filters, and the summary line. These do not change the analysis."""

from __future__ import annotations

from pathlib import Path

from vyarth.fix import applicability
from vyarth.ignore import normalize_rule
from vyarth.model import Finding, FindingCensus, ScanResult


RULES = {
    "unused_import": "UNUSED_IMPORT",
    "unused_function": "UNUSED_FUNCTION",
    "unused_class": "UNUSED_CLASS",
    "unused_variable": "UNUSED_VARIABLE",
    "unreachable_code": "UNREACHABLE_CODE",
    "orphan_function": "ORPHAN_FUNCTION",
    "possibly_unused_module": "POSSIBLY_UNUSED_MODULE",
    "wildcard_import": "WILDCARD_IMPORT",
    "unused_dependency": "UNUSED_DEPENDENCY",
    "duplicate_code": "DUPLICATE_CODE",
    "unused_ignore": "UNUSED_IGNORE",
    "ignore_without_reason": "IGNORE_WITHOUT_REASON",
}

_SORTS = {"confidence", "path", "rule"}


def canonical_rules(names: list[str]) -> tuple[str, ...]:
    """`UNUSED_FUNCTION`, `unused-function`, and `unused_function` are one rule."""
    found: list[str] = []
    for name in names:
        key = normalize_rule(name)
        if key not in RULES:
            raise ValueError(f"unknown rule: {name}")
        found.append(RULES[key])
    return tuple(found)


def present_findings(
    findings: tuple[Finding, ...] | list[Finding],
    *,
    root: Path,
    sort: str | None,
    max_findings: int | None,
    select: tuple[str, ...],
    ignore_rules: tuple[str, ...],
    fixable_only: bool,
) -> tuple[tuple[Finding, ...], FindingCensus]:
    """Filter, sort, then keep the first N. The census counts the set before the cut."""
    chosen = list(findings)
    if select:
        allowed = set(select)
        chosen = [finding for finding in chosen if finding.rule in allowed]
    if ignore_rules:
        denied = set(ignore_rules)
        chosen = [finding for finding in chosen if finding.rule not in denied]
    if fixable_only:
        sources: dict[str, str | None] = {}
        chosen = [finding for finding in chosen if _level(root, finding, sources) == "safe"]
    mode = sort or ("confidence" if max_findings is not None else "path")
    if mode not in _SORTS:
        raise ValueError(f"unknown sort: {mode}")
    chosen.sort(key=lambda finding: _sort_key(finding, mode))
    census = census_of(chosen, root)
    if max_findings is not None:
        chosen = chosen[:max_findings]
    return tuple(chosen), census


def census_of(findings: list[Finding] | tuple[Finding, ...], root: Path) -> FindingCensus:
    by_rule: dict[str, int] = {}
    bands = {"100": 0, "90-99": 0, "70-89": 0, "0-69": 0}
    safe = 0
    unsafe = 0
    sources: dict[str, str | None] = {}
    for finding in findings:
        by_rule[finding.rule] = by_rule.get(finding.rule, 0) + 1
        score = finding.confidence
        if score == 100:
            bands["100"] += 1
        elif score >= 90:
            bands["90-99"] += 1
        elif score >= 70:
            bands["70-89"] += 1
        else:
            bands["0-69"] += 1
        level = _level(root, finding, sources)
        if level == "safe":
            safe += 1
        elif level == "unsafe":
            unsafe += 1
    return FindingCensus(
        total=len(findings),
        by_rule=tuple(sorted(by_rule.items())),
        by_band=tuple(bands.items()),
        fixable_safe=safe,
        fixable_unsafe=unsafe,
    )


def summary_line(result: ScanResult) -> str:
    """One line for `--summary`. Counts are the set before `--max-findings`."""
    census = result.census
    if census is None:
        census = census_of(result.findings, Path("."))
    bands = dict(census.by_band)
    high = bands.get("100", 0) + bands.get("90-99", 0)
    line = (
        f"vyarth: {census.total} findings ({high} ≥90, {census.fixable_safe} safe-fixable) "
        f"in {result.files_scanned} files"
    )
    ranked = sorted(census.by_rule, key=lambda item: (-item[1], item[0]))[:3]
    if not ranked:
        return line + "\n"
    rules = ", ".join(f"{name} {count}" for name, count in ranked)
    return f"{line}; top rules {rules}\n"


def truncation_line(result: ScanResult) -> str:
    total = result.census.total if result.census is not None else len(result.findings)
    omitted = total - len(result.findings)
    if omitted <= 0:
        return ""
    return f"... {omitted} more (use --max-findings or --min-confidence)\n"


def _level(root: Path, finding: Finding, sources: dict[str, str | None]) -> str:
    source = None
    if finding.rule == "UNREACHABLE_CODE":
        source = sources.get(finding.path)
        if source is None and finding.path not in sources:
            try:
                source = (root / finding.path).read_text(encoding="utf-8")
            except OSError:
                source = ""
            sources[finding.path] = source
    return applicability(finding, source)


def _sort_key(finding: Finding, mode: str) -> tuple[object, ...]:
    if mode == "confidence":
        fixable = 0 if applicability(finding) == "safe" else 1
        return (
            -finding.confidence,
            fixable,
            finding.path,
            finding.line,
            finding.column,
            finding.rule,
            finding.symbol,
        )
    if mode == "rule":
        return (finding.rule, finding.path, finding.line, finding.column, finding.symbol)
    return (finding.path, finding.line, finding.column, finding.rule, finding.symbol)
