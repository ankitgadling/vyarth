"""Project configuration from pyproject.toml or vyarth.toml."""

from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path
import os
import tomllib
import warnings


DEFAULT_ENTRY_PATTERNS: tuple[str, ...] = (
    "**/__main__.py",
    "**/wsgi.py",
    "**/asgi.py",
    "**/manage.py",
    "setup.py",
    "**/docs/conf.py",
    "noxfile.py",
    "fabfile.py",
    "tasks.py",
    "**/gunicorn.conf.py",
    "**/alembic/env.py",
    "scripts/**/*.py",
    "bin/**/*.py",
)

DEFAULT_EXCLUDES: tuple[str, ...] = (
    ".git",
    ".git/**",
    ".vyarth",
    ".vyarth/**",
    ".venv",
    ".venv/**",
    "venv",
    "venv/**",
    "**/__pycache__",
    "**/__pycache__/**",
    "build",
    "build/**",
    "dist",
    "dist/**",
)

TEST_PATTERNS: tuple[str, ...] = (
    "tests",
    "tests/**",
    "**/tests/**",
    "/test",
    "/test/**",
    "tests.py",
    "**/tests.py",
    "test_*.py",
    "**/test_*.py",
    "*_test.py",
    "**/*_test.py",
    "conftest.py",
    "**/conftest.py",
)

FRAMEWORKS = frozenset({"django", "pydantic", "celery"})
_KNOWN_KEYS = frozenset(
    {
        "ignore",
        "exclude",
        "entry_patterns",
        "min_confidence",
        "framework_decorators",
        "entry_points",
        "baseline",
        "fail_on",
        "fold",
        "workers",
        "duplicate_min_statements",
        "frameworks",
        "ignore_names",
        "ignore_decorators",
        "ignore_bases",
        "report_dev_dependencies",
        "report_framework_conventions",
    }
)

FAIL_ON_LEVELS = {"high": 90, "medium": 70, "low": 0}


@dataclass(frozen=True)
class Config:
    ignore: tuple[str, ...] = ()
    exclude: tuple[str, ...] = ()
    entry_patterns: tuple[str, ...] = DEFAULT_ENTRY_PATTERNS
    min_confidence: int = 0
    framework_decorators: tuple[str, ...] = ()
    entry_points: tuple[str, ...] = ()
    baseline: str = ""
    fail_on: str = ""
    fold: tuple[tuple[str, str], ...] = ()
    workers: int = 1
    duplicate_min_statements: int = 5
    frameworks: tuple[str, ...] = ()
    ignore_names: tuple[str, ...] = ()
    ignore_decorators: tuple[str, ...] = ()
    ignore_bases: tuple[str, ...] = ()
    report_dev_dependencies: bool = False
    report_framework_conventions: bool = False

    def fold_map(self) -> dict[str, str]:
        return dict(self.fold)

    @property
    def excludes(self) -> tuple[str, ...]:
        return DEFAULT_EXCLUDES + self.exclude


def load_config(root: Path, config_path: Path | None = None) -> Config:
    """Load `[tool.vyarth]` from the scan root, or an explicit toml file."""
    if config_path is not None:
        config, auto = _read_config_file(config_path)
        return _apply_framework_auto(root, config, auto)
    pyproject = root / "pyproject.toml"
    if pyproject.is_file():
        data = _load_toml(pyproject)
        tool = data.get("tool", {})
        if isinstance(tool, dict) and isinstance(tool.get("vyarth"), dict):
            config, auto = _config_from_table(tool["vyarth"])
            return _apply_framework_auto(root, config, auto)
    vyarth_toml = root / "vyarth.toml"
    if vyarth_toml.is_file():
        config, auto = _read_config_file(vyarth_toml)
        return _apply_framework_auto(root, config, auto)
    return _apply_framework_auto(root, Config(), True)


def _read_config_file(path: Path) -> tuple[Config, bool]:
    data = _load_toml(path)
    tool = data.get("tool", {})
    if isinstance(tool, dict) and isinstance(tool.get("vyarth"), dict):
        return _config_from_table(tool["vyarth"])
    return _config_from_table(data)


def _load_toml(path: Path) -> dict:
    with path.open("rb") as handle:
        loaded = tomllib.load(handle)
    if not isinstance(loaded, dict):
        return {}
    return loaded


def _config_from_table(table: dict) -> tuple[Config, bool]:
    unknown = sorted(key for key in table if key not in _KNOWN_KEYS)
    if unknown:
        warnings.warn(f"unknown configuration keys: {', '.join(unknown)}", stacklevel=2)
    ignore = _as_strings(table.get("ignore"))
    exclude = _as_strings(table.get("exclude"))
    if "entry_patterns" in table and table["entry_patterns"] is not None:
        entry_patterns = _as_strings(table["entry_patterns"])
    else:
        entry_patterns = DEFAULT_ENTRY_PATTERNS
    minimum = table.get("min_confidence", 0)
    try:
        min_confidence = int(minimum)
    except (TypeError, ValueError) as exc:
        raise ValueError("min_confidence must be an integer") from exc
    if not 0 <= min_confidence <= 100:
        raise ValueError("min_confidence must be between 0 and 100")
    fail_on = str(table.get("fail_on") or "")
    if fail_on and fail_on not in FAIL_ON_LEVELS:
        raise ValueError("fail_on must be high, medium, or low")
    baseline = table.get("baseline") or ""
    workers = table.get("workers", 1)
    try:
        worker_count = int(workers)
    except (TypeError, ValueError) as exc:
        raise ValueError("workers must be an integer") from exc
    if worker_count < 0:
        raise ValueError("workers must be zero or a positive integer")
    minimum_statements = table.get("duplicate_min_statements", 5)
    try:
        duplicate_min_statements = int(minimum_statements)
    except (TypeError, ValueError) as exc:
        raise ValueError("duplicate_min_statements must be an integer") from exc
    if duplicate_min_statements < 1:
        raise ValueError("duplicate_min_statements must be a positive integer")
    frameworks, auto = _parse_frameworks(table)
    return Config(
        ignore=ignore,
        exclude=exclude,
        entry_patterns=entry_patterns,
        min_confidence=min_confidence,
        framework_decorators=_as_strings(table.get("framework_decorators")),
        entry_points=_as_strings(table.get("entry_points")),
        baseline=str(baseline),
        fail_on=fail_on,
        fold=_as_fold(table.get("fold")),
        workers=worker_count,
        duplicate_min_statements=duplicate_min_statements,
        frameworks=frameworks,
        ignore_names=_as_strings(table.get("ignore_names")),
        ignore_decorators=_as_strings(table.get("ignore_decorators")),
        ignore_bases=_as_strings(table.get("ignore_bases")),
        report_dev_dependencies=_as_bool(table.get("report_dev_dependencies"), False, "report_dev_dependencies"),
        report_framework_conventions=_as_bool(
            table.get("report_framework_conventions"),
            False,
            "report_framework_conventions",
        ),
    ), auto


def _parse_frameworks(table: dict) -> tuple[tuple[str, ...], bool]:
    """Return the preset names and whether Django may be detected.

    A missing key and the string ``auto`` detect. ``[]`` leaves presets off.
    A bare string stays one preset, except ``auto``.
    """
    if "frameworks" not in table or table["frameworks"] is None:
        return (), True
    value = table["frameworks"]
    if isinstance(value, str) and value.strip().lower() == "auto":
        return (), True
    names = _as_strings(value)
    unknown = sorted(set(names) - FRAMEWORKS)
    if unknown:
        raise ValueError(f"unknown frameworks: {', '.join(unknown)}")
    return names, False


def _apply_framework_auto(root: Path, config: Config, auto: bool) -> Config:
    if not auto or "django" in config.frameworks:
        return config
    if _django_project(root, config):
        return replace(config, frameworks=config.frameworks + ("django",))
    return config


def _django_project(root: Path, config: Config) -> bool:
    """Required ``django`` dependency, or a boot file setting ``DJANGO_SETTINGS_MODULE``."""
    if _boot_assigns_settings(root, config):
        return True
    from vyarth.dependencies import has_runtime_requirement

    return has_runtime_requirement(root, "django", config)


def _boot_assigns_settings(root: Path, config: Config) -> bool:
    """``manage.py``, ``wsgi.py``, or ``asgi.py`` assigns ``DJANGO_SETTINGS_MODULE``.

    Example, tutorial, and vendored trees do not count. The same file names are
    what the settings-module cap reads.
    """
    from vyarth.confidence import BOOT_FILE_NAMES, DJANGO_SETTINGS_ASSIGNMENT
    from vyarth.dependencies import _under_example_tree
    from vyarth.discover import MANIFEST_SKIP_DIRS, exclusion_specs, path_excluded, relative_posix

    root = root.resolve()
    exclude_spec, gitignore = exclusion_specs(root, config)
    for dirpath, dirnames, filenames in os.walk(root):
        directory = Path(dirpath)
        kept: list[str] = []
        for name in dirnames:
            if name in MANIFEST_SKIP_DIRS or name.endswith(".egg-info"):
                continue
            relative = relative_posix(directory / name, root)
            if path_excluded(relative, exclude_spec, gitignore):
                continue
            kept.append(name)
        dirnames[:] = kept
        if directory != root and _under_example_tree(directory, root):
            continue
        for name in filenames:
            if name not in BOOT_FILE_NAMES:
                continue
            path = directory / name
            if _under_example_tree(path, root):
                continue
            relative = relative_posix(path, root)
            if path_excluded(relative, exclude_spec, gitignore):
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if DJANGO_SETTINGS_ASSIGNMENT.search(text):
                return True
    return False


def _as_bool(value: object, default: bool, key: str) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    raise ValueError(f"{key} must be true or false")


def _as_fold(value: object) -> tuple[tuple[str, str], ...]:
    if value is None:
        return ()
    if not isinstance(value, dict):
        raise ValueError("fold must be a table of names to values")
    pairs: list[tuple[str, str]] = []
    for key, item in value.items():
        if isinstance(item, bool):
            text = "true" if item else "false"
        elif isinstance(item, str | int | float):
            text = str(item)
        else:
            raise ValueError("fold values must be strings, numbers, or booleans")
        pairs.append((str(key), text))
    return tuple(pairs)


def _as_strings(value: object) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, list | tuple):
        return tuple(str(item) for item in value)
    raise ValueError("configuration lists must be arrays of strings")
