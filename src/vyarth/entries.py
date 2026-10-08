"""Framework callbacks, scripts, and other symbols that are alive without a local call."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pathspec

from vyarth.config import Config
from vyarth.discover import is_test_path, module_name, relative_posix
from vyarth.model import Binding
from vyarth.project import Project


_DJANGO_PATTERNS = (
    "**/settings.py",
    "**/admin.py",
    "**/apps.py",
    "**/urls.py",
    "**/migrations/*.py",
)
_PYDANTIC_DECORATORS = (
    "validator",
    "field_validator",
    "model_validator",
    "computed_field",
    "field_serializer",
    "model_serializer",
)
_ENTRY_SUFFIXES = frozenset(
    {
        "route",
        "get",
        "post",
        "put",
        "delete",
        "patch",
        "head",
        "options",
        "task",
        "shared_task",
        "command",
        "group",
        "fixture",
    }
)


@dataclass(frozen=True)
class EntrySet:
    symbols: frozenset[tuple[str, str]]
    modules: frozenset[str]


def collect_entries(project: Project, config: Config) -> EntrySet:
    symbols: set[tuple[str, str]] = set()
    modules: set[str] = set()
    patterns = list(config.entry_patterns)
    if "django" in config.frameworks:
        patterns.extend(_DJANGO_PATTERNS)
    entry_files = pathspec.GitIgnoreSpec.from_lines(patterns)
    decorator_names = config.framework_decorators + config.ignore_decorators
    if "pydantic" in config.frameworks:
        decorator_names = decorator_names + _PYDANTIC_DECORATORS
    for module_name_text, qualname in _configured_symbols(project.root, config):
        modules.add(module_name_text)
        index = project.by_module.get(module_name_text)
        if index is None or not qualname:
            continue
        binding = project.bindings.get(index.path, {}).get(qualname)
        if binding is not None:
            symbols.add((index.path, binding.qualname))

    for index in project.indexes:
        path = Path(index.path)
        dotted = module_name(path, project.roots)
        relpath = relative_posix(path, project.root)
        file_is_entry = index.has_main_guard or entry_files.match_file(relpath) or is_test_path(relpath)
        if file_is_entry and dotted:
            modules.add(dotted)
        decorated: dict[str, list[str]] = {}
        for item in index.decorators:
            decorated.setdefault(item.qualname, []).append(item.name)
        for binding in index.bindings:
            names = decorated.get(binding.qualname, [])
            if _symbol_is_entry(binding, names, config, relpath, decorator_names):
                symbols.add((index.path, binding.qualname))
                if dotted and binding.scope_kind == "module":
                    modules.add(dotted)
            elif _framework_value(binding, config):
                symbols.add((index.path, binding.qualname))
    symbols.update(_base_symbols(project, config))
    return EntrySet(symbols=frozenset(symbols), modules=frozenset(modules))


def _symbol_is_entry(
    binding: Binding,
    decorator_names: list[str],
    config: Config,
    relpath: str,
    extra_decorators: tuple[str, ...],
) -> bool:
    if binding.kind not in {"function", "class"}:
        return False
    if any(is_entry_decorator(name, extra_decorators) for name in decorator_names):
        return True
    if binding.scope_kind == "module" and binding.kind == "function" and binding.name.startswith("pytest_"):
        return True
    if "django" in config.frameworks and binding.kind == "class" and binding.name == "Meta":
        return True
    if binding.scope_kind == "module" and binding.kind == "function" and binding.name in {"lambda_handler"}:
        return True
    if binding.scope_kind == "module" and binding.name.startswith("test_"):
        return True
    if binding.scope_kind == "class" and binding.name == "ready":
        return True
    if is_test_path(relpath) and binding.kind == "function" and binding.name.startswith("test_"):
        return True
    return False


def _framework_value(binding: Binding, config: Config) -> bool:
    if binding.scope_kind != "module" or binding.kind != "variable":
        return False
    if "django" in config.frameworks and binding.name == "urlpatterns":
        return True
    return "celery" in config.frameworks and binding.name == "beat_schedule"


def _base_symbols(project: Project, config: Config) -> set[tuple[str, str]]:
    if not config.ignore_bases:
        return set()
    found: set[tuple[str, str]] = set()
    for index in project.indexes:
        matched: set[str] = set()
        for class_name, bases in index.class_bases:
            if any(_base_matches(base, config.ignore_bases) for base in bases):
                matched.add(class_name)
        if not matched:
            continue
        for binding in index.bindings:
            owner = binding.qualname.split(".", 1)[0]
            if binding.qualname in matched or owner in matched:
                found.add((index.path, binding.qualname))
    return found


def _base_matches(base: str, names: tuple[str, ...]) -> bool:
    leaf = base
    if leaf.startswith("@expr:"):
        leaf = leaf[len("@expr:") :]
    elif leaf.startswith("@import:"):
        leaf = leaf[len("@import:") :]
    leaf = leaf.rsplit(".", 1)[-1]
    return leaf in names or base in names


def is_entry_decorator(name: str, extras: tuple[str, ...]) -> bool:
    if not name:
        return False
    for extra in extras:
        if name == extra or name.endswith(f".{extra}"):
            return True
    last = name.rsplit(".", 1)[-1]
    if name in {"fixture", "pytest.fixture"} or last == "fixture":
        return True
    return last in _ENTRY_SUFFIXES


def _configured_symbols(root: Path, config: Config) -> list[tuple[str, str]]:
    found = list(_pyproject_scripts(root))
    for item in config.entry_points:
        parsed = _parse_entrypoint(item)
        if parsed is not None:
            found.append(parsed)
    return found


def _pyproject_scripts(root: Path) -> list[tuple[str, str]]:
    path = root / "pyproject.toml"
    if not path.is_file():
        return []
    import tomllib

    with path.open("rb") as handle:
        data = tomllib.load(handle)
    project = data.get("project", {})
    if not isinstance(project, dict):
        return []
    found: list[tuple[str, str]] = []
    for key in ("scripts", "gui-scripts"):
        _collect_scripts(project.get(key, {}), found)
    entry_points = project.get("entry-points", {})
    if isinstance(entry_points, dict):
        for key in ("console_scripts", "gui_scripts"):
            _collect_scripts(entry_points.get(key, {}), found)
    return found


def _collect_scripts(table: object, found: list[tuple[str, str]]) -> None:
    if not isinstance(table, dict):
        return
    for value in table.values():
        if not isinstance(value, str):
            continue
        parsed = _parse_entrypoint(value)
        if parsed is not None:
            found.append(parsed)


def _parse_entrypoint(value: str) -> tuple[str, str] | None:
    text = value.strip()
    if ":" not in text:
        return (text, "") if text else None
    module, _, qualname = text.partition(":")
    module = module.strip()
    qualname = qualname.strip()
    if not module:
        return None
    return module, qualname

