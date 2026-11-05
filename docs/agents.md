# Using vyarth from an agent

Scan a window, explain the finding you would delete, then fix it with a check or record why it stays.

```bash
vyarth scan . --sort confidence --max-findings 50 --format jsonl
vyarth explain ID
vyarth fix --select-id ID --verify
vyarth baseline . --add ID --reason "called from a queue"
```

`# vyarth: ignore[unused-function] -- called via Celery beat` suppresses one line and keeps the reason. `reason="..."` is the same note. An ignore with no reason still works unless `require_ignore_reason` is set.

Never delete a finding scored from 90 to 99 in `migrations/`, a settings module, `conf.py`, or a class that is only named by a string, until `explain` has been read. `--unsafe-fixes` is how a selected 90–99 nested name is deleted. `--unsafe` only removes confidence-70 imports.

## What confidence means

| Score | Meaning |
| --- | --- |
| 100, status `DEAD` | Proved unused: an import that was not lowered, unreachable code, or a nested function or variable. |
| 96 | No reference, and the name is not on the external surface. A top-level name in an application, or a private attribute. |
| 82 | A possibly unused module. The score drops to 60 when the project imports dynamically. |
| 80 | An orphan that is referenced but that no entry reaches. Duplicate code is also 80. |
| 75 | An unrecognized decorator. |
| 70 | Dynamic usage, an import probe, a side-effect import, a re-export, an Alembic name, or a nearby parse error. |
| 60 | Public API, or an analysis limit: a wildcard, an external base, an unresolved attribute, a lambda-only reference, or a framework convention. |

`verified: true` means the edited files compiled and the configured command passed. It does not prove the name is unused at runtime.

## Patterns that are usually not dead

- A `Migration` class, an `AppConfig` subclass, Django settings constants, `urlpatterns`, and a Sphinx `setup` function are capped at 60 or below.
- Attributes of a class named `Meta` are hidden unless `report_framework_conventions` is set.
- A public name in a library stays at 60 because callers outside the scan may load it.
- A dotted string in `INSTALLED_APPS`, `MIDDLEWARE`, or a `*_BACKEND` list marks that class or function as used.
