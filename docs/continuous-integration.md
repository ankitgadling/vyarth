# Continuous integration

Fail the job when a high-confidence finding is new, and keep older findings in a baseline until someone removes them.

## GitHub Actions

```yaml
- name: Vyarth
  run: vyarth scan . --format github --fail-on high
```

`--format github` prints annotations that GitHub attaches to the changed lines:

```text
::error file=pkg/app.py,line=4,title=UNUSED_FUNCTION::Function 'helper' is never used.
```

`--fail-on high` still prints medium and low findings. The step fails only when one finding has confidence 90 or higher. Use `medium` (70) or `low` (0) for a stricter gate. Omit `--fail-on` to fail on any finding.

SARIF upload uses the same scan:

```yaml
- name: Vyarth SARIF
  run: vyarth scan . --format sarif --fail-on high > vyarth.sarif
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: vyarth.sarif
```

Each SARIF result includes `partialFingerprints.vyarth/fingerprint`, so a code-scanning backend can track the same finding across runs.

## Baseline

Generate the file once, commit it, and pass it on later scans:

```bash
vyarth baseline .
vyarth scan . --baseline vyarth-baseline.json --fail-on high
```

`vyarth-baseline.json` is a sorted list:

```json
{
  "findings": [
    {
      "fingerprint": "UNUSED_FUNCTION:pkg/app.py:helper",
      "rule": "UNUSED_FUNCTION",
      "path": "pkg/app.py",
      "symbol": "helper"
    }
  ]
}
```

A fingerprint is `RULE:relative/path.py:qualname`. The line number is not part of it, so an edit above the symbol does not look like a new finding. Renaming the symbol or moving the file does.

The scan reports only fingerprints that are absent from the file. The exit code follows that filtered set. A finding that disappears from the code can stay in the baseline; it has no effect until the symbol comes back.

You can also set the path in config so every scan uses it:

```toml
[tool.vyarth]
baseline = "vyarth-baseline.json"
fail_on = "high"
```

`vyarth baseline` writes the file and does not apply an existing baseline, so the snapshot includes the current findings.

A baseline file may also be a list of fingerprint strings. Each object form must contain a string `fingerprint`. Anything else exits 2.

## Changed files only

```bash
vyarth scan . --changed --changed-from origin/main --fail-on high
```

The project is still indexed, so a call from an unchanged file keeps a symbol alive. The report keeps findings in the Python files that differ from `origin/main`. Pair this with a committed baseline when the pull request should ignore known findings in those files too.

## Confidence as a gate

| Floor | Flag | What still fails the job |
| --- | --- | --- |
| 90 | `--fail-on high` | Unused nested code, unreachable statements, wildcard imports, unused dependencies at 95, duplicates, and module-level unused functions and classes at 96. |
| 70 | `--fail-on medium` | The high set, plus dynamic-name findings, Alembic migration names, import-name mismatches, and orphan functions at 80. |
| 0 | `--fail-on low` | Every printed finding, including unused modules at 82 or 60 and unresolved orphans at 60. |

`--min-confidence` removes findings from the report before the exit check. `--min-confidence 90` hides unused modules and dynamic-name findings entirely. `--fail-on` does not hide them.
