"""Framework callbacks, scripts, and other symbols that are alive without a local call."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re

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
        "websocket",
        "on_event",
        "middleware",
        "exception_handler",
        "errorhandler",
        "before_request",
        "after_request",
        "teardown_request",
        "context_processor",
        "template_filter",
        "template_global",
        "listens_for",
        "receiver",
        "hookimpl",
        "hookspec",
        "periodic_task",
        "subscriber",
        "listener",
    }
)


@dataclass(frozen=True)
class EntrySet:
    symbols: frozenset[tuple[str, str]]
    modules: frozenset[str]
    # True when the scan holds a real program: a console script, `__main__.py`, a
    # framework app, or a top-level script. `docs/conf.py`, `setup.py`, examples and
    # a main guard inside a package module run code but do not make a project an app.
    app: bool = False


# Files that only a program has.
_APP_FILE_NAMES = frozenset({"__main__.py", "wsgi.py", "asgi.py", "manage.py", "gunicorn.conf.py"})
# Scripts that tooling or documentation runs. A main guard there says nothing about the project.
_TOOLING_FILE_NAMES = frozenset({"setup.py", "conf.py", "noxfile.py", "fabfile.py", "tasks.py"})
_SIDE_DIRS = frozenset(
    {
        "docs",
        "doc",
        "examples",
        "example",
        "tutorial",
        "tutorials",
        "samples",
        "sample",
        "demo",
        "demos",
        "benchmarks",
        "scripts",
        "bin",
        "tools",
    }
)
# Decorators that mark a callback, not a program. Plugin libraries use them too.
_NOT_APP_DECORATORS = frozenset({"fixture", "hookimpl", "hookspec"})


def collect_entries(project: Project, config: Config) -> EntrySet:
    symbols: set[tuple[str, str]] = set()
    modules: set[str] = set()
    app = bool(config.entry_points) or bool(_console_scripts(project.root))
    package_dirs = {Path(index.path).parent for index in project.indexes if Path(index.path).name == "__init__.py"}
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
        in_tests = is_test_path(relpath)
        if not app and not in_tests:
            app = _is_program_file(path, relpath, index.has_main_guard, entry_files, package_dirs, config)
        decorated: dict[str, list[str]] = {}
        for item in index.decorators:
            decorated.setdefault(item.qualname, []).append(item.name)
        for binding in index.bindings:
            names = decorated.get(binding.qualname, [])
            if _symbol_is_entry(binding, names, config, relpath, decorator_names):
                symbols.add((index.path, binding.qualname))
                if dotted and binding.scope_kind == "module":
                    modules.add(dotted)
                if not in_tests and any(
                    is_entry_decorator(name, decorator_names) and name.rsplit(".", 1)[-1] not in _NOT_APP_DECORATORS
                    for name in names
                ):
                    app = True
            elif _framework_value(binding, config) or _sphinx_setting(binding, path, relpath):
                symbols.add((index.path, binding.qualname))
    symbols.update(_base_symbols(project, config))
    return EntrySet(symbols=frozenset(symbols), modules=frozenset(modules), app=app)


def _is_program_file(
    path: Path,
    relpath: str,
    has_main_guard: bool,
    entry_files: pathspec.GitIgnoreSpec,
    package_dirs: set[Path],
    config: Config,
) -> bool:
    if path.name in _APP_FILE_NAMES:
        return True
    if "django" in config.frameworks and entry_files.match_file(relpath) and path.name != "conf.py":
        return True
    if not has_main_guard or path.name in _TOOLING_FILE_NAMES:
        return False
    if _SIDE_DIRS.intersection(relpath.split("/")[:-1]):
        return False
    # A main guard inside a package is a convenience for `python -m`, as in `requests/help.py`.
    return path.parent not in package_dirs


def _console_scripts(root: Path) -> list[tuple[str, str]]:
    """Programs the project installs. Plugin entry-point groups are not programs."""
    found: list[tuple[str, str]] = []
    path = root / "pyproject.toml"
    if path.is_file():
        import tomllib

        try:
            with path.open("rb") as handle:
                data = tomllib.load(handle)
        except (OSError, tomllib.TOMLDecodeError):
            data = {}
        project = data.get("project", {})
        if isinstance(project, dict):
            for key in ("scripts", "gui-scripts"):
                _collect_scripts(project.get(key, {}), found)
        tool = data.get("tool", {})
        poetry = tool.get("poetry", {}) if isinstance(tool, dict) else {}
        if isinstance(poetry, dict):
            _collect_scripts(poetry.get("scripts", {}), found)
    found.extend(_setup_cfg_scripts(root / "setup.cfg", groups=("console_scripts", "gui_scripts")))
    setup_py = root / "setup.py"
    if setup_py.is_file():
        try:
            text = setup_py.read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = ""
        if "console_scripts" in text or "gui_scripts" in text:
            found.extend(_setup_py_scripts(setup_py))
    return found


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


def _sphinx_setting(binding: Binding, path: Path, relpath: str) -> bool:
    """Sphinx reads the module-level names of `docs/conf.py` by name."""
    if path.name != "conf.py" or binding.scope_kind != "module" or binding.kind != "variable":
        return False
    return bool({"docs", "doc"}.intersection(relpath.split("/")[:-1]))


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
            if any(
                binding.qualname == name or binding.qualname.startswith(name + ".")
                for name in matched
            ):
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
    found: list[tuple[str, str]] = []
    path = root / "pyproject.toml"
    if path.is_file():
        import tomllib

        try:
            with path.open("rb") as handle:
                data = tomllib.load(handle)
        except (OSError, tomllib.TOMLDecodeError):
            data = {}
        project = data.get("project", {})
        if isinstance(project, dict):
            for key in ("scripts", "gui-scripts"):
                _collect_scripts(project.get(key, {}), found)
            _collect_groups(project.get("entry-points", {}), found)
        tool = data.get("tool", {})
        poetry = tool.get("poetry", {}) if isinstance(tool, dict) else {}
        if isinstance(poetry, dict):
            _collect_scripts(poetry.get("scripts", {}), found)
            _collect_groups(poetry.get("plugins", {}), found)
    found.extend(_setup_cfg_scripts(root / "setup.cfg"))
    found.extend(_setup_py_scripts(root / "setup.py"))
    return found


def _collect_groups(groups: object, found: list[tuple[str, str]]) -> None:
    """Every entry-point group, not only console scripts: plugins load by name."""
    if not isinstance(groups, dict):
        return
    for table in groups.values():
        _collect_scripts(table, found)


def _setup_cfg_scripts(path: Path, groups: tuple[str, ...] | None = None) -> list[tuple[str, str]]:
    if not path.is_file():
        return []
    import configparser

    parser = configparser.ConfigParser(interpolation=None)
    try:
        parser.read(path, encoding="utf-8")
    except (OSError, configparser.Error, UnicodeDecodeError):
        return []
    found: list[tuple[str, str]] = []
    if not parser.has_section("options.entry_points"):
        return found
    for group, block in parser.items("options.entry_points"):
        if groups is not None and group not in groups:
            continue
        for line in block.splitlines():
            _, _, target = line.partition("=")
            parsed = _parse_entrypoint(target) if target.strip() else None
            if parsed is not None:
                found.append(parsed)
    return found


_SETUP_ENTRY = re.compile(r"""['"]\s*[\w.\-]+\s*=\s*([\w.]+):([\w.]+)\s*(?:\[[^\]]*\])?\s*['"]""")


def _setup_py_scripts(path: Path) -> list[tuple[str, str]]:
    if not path.is_file():
        return []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    return [(match.group(1), match.group(2)) for match in _SETUP_ENTRY.finditer(text)]


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
    if "[" in text:
        text = text.split("[", 1)[0].strip()
    if ":" not in text:
        return (text, "") if text else None
    module, _, qualname = text.partition(":")
    module = module.strip()
    qualname = qualname.strip()
    if not module:
        return None
    return module, qualname

