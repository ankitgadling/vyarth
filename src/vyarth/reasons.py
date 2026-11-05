"""Machine reason codes. Each code is the stable form of one evidence sentence."""

from __future__ import annotations


# Text is the evidence sentence. Code is what a report puts in `reasons`.
REASONS: dict[str, str] = {
    "no_references": "No references found.",
    "no_decorators": "No decorators.",
    "not_exported": "Not exported.",
    "not_entry": "Not an entry point.",
    "no_dynamic_refs": "No dynamic references detected.",
    "unresolved_attr_call": "An unresolved attribute call uses this name.",
    "no_entry_reaches": "No entry point reaches this function.",
    "no_scan_entry": "This scan found no entry point, so this may be a library whose callers are outside the scan.",
    "module_cap": "This file has no incoming imports, so this score follows the module.",
    "framework_convention": "Framework convention. This name is loaded by the framework without a local reference.",
    "public_name": "Public name. Callers outside this project may still load it.",
    "may_override_external": "May override a method of an external base.",
    "no_incoming_imports": "No incoming imports detected.",
    "unrecognized_decorator": "Decorated, but not a recognized framework entry.",
    "dynamic_usage": "Dynamic usage detected. Static analysis cannot prove this symbol is unused.",
    "settings_sweep": "This module is read with getattr or dir(), so this name may be loaded by that loop.",
    "namespace_import": "A top-level import uses this package's namespace, so the dependency cannot be proved unused.",
    "wildcard_import": "Wildcard import prevents reliable analysis.",
    "no_dist_metadata": "Distribution metadata is unavailable, so the package cannot be proved unused.",
    "lambda_only": "Only referenced from a lambda this scan did not prove is called.",
    "string_reference": "Named by a dotted string. The final attribute was not found on that module.",
    "string_names_package": "A string in the source names this package, as settings and plugin lists do.",
    "import_probe": "This import sits in a try that catches ImportError, so it may be an availability check.",
    "side_effect_import": "Import may run the submodule for its side effects.",
    "package_init": "Possible public re-export.",
    "parse_error_nearby": "A file failed to parse, so it may use this symbol.",
    "alembic_name": "Alembic loads this name when the migration runs.",
    "unreachable": "Control flow terminates before this statement.",
    "runtime_package": "This package is often started without an import.",
    "tooling_package": "This package is a tool or plugin that runs without being imported.",
    "unused_ignore": "This ignore directive suppressed nothing.",
    "ignore_without_reason": "This ignore directive has no reason.",
}

_BY_TEXT = {text: code for code, text in REASONS.items()}

# The checklist repeated on most dead names. Brief output keeps the reason codes only.
BRIEF_EVIDENCE = frozenset(
    {
        REASONS["no_references"],
        REASONS["no_decorators"],
        REASONS["not_exported"],
        REASONS["not_entry"],
        REASONS["no_dynamic_refs"],
    }
)

# `no_entry_reaches` is the orphan message. The scan-with-no-entry note is a separate code
# so a consumer can tell the two sentences apart. The plan's initial name for the orphan
# sentence is `no_entry_reaches`.


def codes_for(evidence: tuple[str, ...]) -> tuple[str, ...]:
    """Codes for evidence lines, in the same order, skipping a sentence with no code."""
    found: list[str] = []
    for text in evidence:
        code = _BY_TEXT.get(text)
        if code is None:
            code = _prefix_code(text)
        if code is not None and code not in found:
            found.append(code)
    return tuple(found)


def _prefix_code(text: str) -> str | None:
    if text.startswith("Imported as "):
        return "import_alias"
    if text.startswith("Function ") and " duplicates " in text:
        return "duplicate_body"
    if text.startswith("Declared in ") and "development or docs" in text:
        return "dev_dependency"
    if text.startswith("Declared in ") and text.endswith("never imported."):
        return "declared_unused"
    return None
