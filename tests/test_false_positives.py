"""Regression tests for code that looks unused to a static scan but is used."""

from pathlib import Path
from textwrap import dedent

from tests.conftest import write_tree
from vyarth import scan
from vyarth.config import Config, load_config

MAIN = "\nif __name__ == '__main__':\n    main()\n"


def _clean(text):
    """Dedent an indented triple-quoted body, keeping an unindented MAIN tail intact."""
    if text.endswith(MAIN):
        return dedent(text[: -len(MAIN)]) + MAIN
    return dedent(text)


def findings_for(tmp_path, files, pyproject=None):
    tree = {name: _clean(text) for name, text in files.items()}
    if pyproject is not None:
        tree["pyproject.toml"] = pyproject
    write_tree(tmp_path, tree)
    return scan(tmp_path).findings


def symbols(tmp_path, files, pyproject=None, rule=None):
    return {
        item.symbol
        for item in findings_for(tmp_path, files, pyproject)
        if rule is None or item.rule == rule
    }


def confident(tmp_path, files, pyproject=None):
    """Symbols reported at 90 or above, which is what `--fail-on high` breaks on."""
    return {item.symbol for item in findings_for(tmp_path, files, pyproject) if item.confidence >= 90}


# --- locals, loop targets, and other names that are unused on purpose ---


def test_locals_reads_every_local(tmp_path):
    source = (
        "def main():\n"
        "    name = 'x'\n"
        "    age = 3\n"
        "    return '{name} {age}'.format(**locals())\n"
    )
    assert not symbols(tmp_path, {"app.py": source + MAIN})


def test_vars_with_no_argument_reads_every_local(tmp_path):
    source = "def main():\n    name = 'x'\n    return vars()\n"
    assert "name" not in symbols(tmp_path, {"app.py": source + MAIN})


def test_unused_by_design_names_are_not_reported(tmp_path):
    source = """
    def main():
        for i in range(3):
            pass
        a, b = 1, 2
        print(a)
        with open("f") as handle:
            pass
        squares = [0 for k in range(3)]
        print(squares)
        _scratch = 5
    """
    assert not symbols(tmp_path, {"app.py": source + MAIN})


def test_plain_unused_local_is_still_reported(tmp_path):
    source = "def main():\n    leftover = 1\n"
    assert "leftover" in symbols(tmp_path, {"app.py": source + MAIN})


# --- annotations spelled as strings or comments ---


def test_quoted_types_in_typing_helpers_use_the_import(tmp_path):
    source = """
    from __future__ import annotations
    from typing import TYPE_CHECKING, TypeVar, List, Dict, NewType
    if TYPE_CHECKING:
        from decimal import Decimal
        from fractions import Fraction
        from pathlib import Path
        from collections import OrderedDict

    T = TypeVar("T", bound="Decimal")
    Alias = List["Fraction"]
    Alias2 = Dict[str, "Path"]
    N = NewType("N", "OrderedDict")

    def main():
        return T, Alias, Alias2, N
    """
    found = symbols(tmp_path, {"app.py": source + MAIN}, rule="UNUSED_IMPORT")
    assert not found


def test_type_comments_use_the_import(tmp_path):
    source = """
    from typing import TYPE_CHECKING, List
    if TYPE_CHECKING:
        from uuid import UUID
        from datetime import date

    def main():
        x = []  # type: List[UUID]
        return x

    def other(a):
        # type: (date) -> None
        return a
    """
    found = symbols(tmp_path, {"app.py": source + MAIN}, rule="UNUSED_IMPORT")
    assert not found


def test_import_behind_a_constant_false_guard_is_a_typing_idiom(tmp_path):
    source = """
    if False:
        from typing import List

    def main():
        x = []  # type: List[int]
        return x
    """
    assert not symbols(tmp_path, {"app.py": source + MAIN}, rule="UNUSED_IMPORT")


# --- lambdas and callbacks ---


def test_lambda_passed_as_a_callback_reaches_its_callee(tmp_path):
    source = """
    def helper(x):
        return x + 1

    def helper2(x):
        return x

    def helper3(x):
        return x

    def register(callback):
        return callback

    def main():
        register(lambda: helper(1))
        items = sorted([1, 2], key=lambda v: helper2(v))
        return list(map(lambda v: helper3(v), items))
    """
    found = symbols(tmp_path, {"app.py": source + MAIN})
    assert not {"helper", "helper2", "helper3"} & found


# --- calls on receivers the scan cannot type ---


def test_method_passed_from_an_unknown_receiver_is_used(tmp_path):
    source = """
    import threading

    class Worker:
        def _run(self):
            return 1

        def _score(self):
            return 2

        CONST = 1
        _PRIVATE = 2

    def start(worker):
        thread = threading.Thread(target=worker._run)
        ranked = sorted([worker], key=lambda item: item._score)
        return thread, ranked, worker.CONST, worker._PRIVATE

    def main():
        start(Worker())
    """
    assert not symbols(tmp_path, {"app.py": source + MAIN})


def test_template_method_call_reaches_the_subclass_hook(tmp_path):
    source = """
    class Base:
        def run(self):
            return self.step() + self._hook()

    class Child(Base):
        def step(self):
            return 1

        def _hook(self):
            return 2

    def main():
        Child().run()
    """
    assert not symbols(tmp_path, {"app.py": source + MAIN})


def test_strategy_methods_are_reached_through_the_shared_base(tmp_path):
    source = """
    class Strategy:
        def execute(self):
            raise NotImplementedError

    class A(Strategy):
        def execute(self):
            return 1

    class B(Strategy):
        def execute(self):
            return 2

    class Context:
        def __init__(self, strategy):
            self.strategy = strategy

        def run(self):
            return self.strategy.execute()

    def main():
        Context(A()).run()
        B()
    """
    assert not symbols(tmp_path, {"app.py": source + MAIN})


def test_type_self_and_dunder_class_attributes_are_used(tmp_path):
    source = """
    class Registry:
        _registry = {}
        _count = 0

        def add(self, key):
            type(self)._registry[key] = 1
            self.__class__._count += 1

    def main():
        Registry().add(1)
    """
    assert not symbols(tmp_path, {"app.py": source + MAIN})


# --- dynamic dispatch ---


def test_getattr_with_a_built_name_downgrades_matching_methods(tmp_path):
    source = """
    class Handler:
        def _handle_a(self):
            return 1

        def dispatch(self, kind):
            return getattr(self, "_handle_" + kind)()

    def main():
        Handler().dispatch("a")
    """
    found = findings_for(tmp_path, {"app.py": source + MAIN})
    assert not [item for item in found if item.symbol == "_handle_a" and item.confidence >= 90]


def test_globals_lookup_downgrades_module_functions(tmp_path):
    source = """
    def _cmd_a():
        return 1

    def main(name):
        return globals()["_cmd_" + name]()
    """
    found = findings_for(tmp_path, {"app.py": source + MAIN})
    assert not [item for item in found if item.symbol == "_cmd_a" and item.confidence >= 90]


def test_init_subclass_registry_keeps_subclasses(tmp_path):
    source = """
    class Plugin:
        registry = []

        def __init_subclass__(cls, **kwargs):
            super().__init_subclass__(**kwargs)
            Plugin.registry.append(cls)

    class AutoPlugin(Plugin):
        def run(self):
            return 1

    def main():
        return [item for item in Plugin.registry]
    """
    assert not symbols(tmp_path, {"app.py": source + MAIN})


def test_singledispatch_implementation_is_only_possible(tmp_path):
    source = """
    from functools import singledispatch

    @singledispatch
    def show(arg):
        pass

    @show.register(str)
    def _show_str(arg):
        return 2

    def main():
        show(1)
    """
    assert "_show_str" not in confident(tmp_path, {"app.py": source + MAIN})


# --- re-exports ---


def test_wildcard_reexport_keeps_the_definition(tmp_path):
    files = {
        "pkg/__init__.py": "from .core import *\n",
        "pkg/core.py": "def thing():\n    return 1\n\ndef other():\n    return 2\n",
        "app.py": "import pkg\nfrom pkg import other\n\ndef main():\n    return pkg.thing(), other()\n" + MAIN,
    }
    found = symbols(tmp_path, files)
    assert "thing" not in found
    assert "other" not in found


def test_package_attribute_call_uses_the_init_import(tmp_path):
    files = {
        "pkg/__init__.py": "from .core import thing\n",
        "pkg/core.py": "def thing():\n    return 1\n",
        "main.py": "import pkg\n\ndef main():\n    return pkg.thing()\n" + MAIN,
    }
    found = findings_for(tmp_path, files)
    assert not [item for item in found if item.rule == "UNUSED_IMPORT"]


# --- class attributes owned by frameworks ---


def test_declarative_subclasses_keep_their_fields(tmp_path):
    source = """
    from typing import NamedTuple
    from pydantic import BaseModel

    class Point(NamedTuple):
        x: int = 0
        y: int = 0

    class Item(BaseModel):
        name: str = "a"

    class Sub(Item):
        price: float = 1.0

    def main():
        return Point(), Sub()
    """
    found = symbols(tmp_path, {"app.py": source + MAIN}, rule="UNUSED_VARIABLE")
    assert not found


def test_public_class_attribute_on_a_framework_base_is_only_possible(tmp_path):
    source = """
    import threading

    class Worker(threading.Thread):
        visible = 1

    def main():
        Worker()
    """
    found = findings_for(tmp_path, {"app.py": source + MAIN})
    hidden = [item for item in found if item.symbol == "visible"]
    assert hidden and all(item.confidence < 90 for item in hidden)


# --- entry points and layout ---


def test_poetry_scripts_and_every_entry_point_group_are_entries(tmp_path):
    files = {
        "pkg/__init__.py": "",
        "pkg/cli.py": "def main():\n    return 1\n\ndef plugin_entry():\n    return 2\n",
        "pkg/other.py": "def run():\n    return 1\n",
        "setup.py": (
            "from setuptools import setup\n"
            "setup(name='x', entry_points={'console_scripts': ['x = pkg.other:run']})\n"
        ),
    }
    pyproject = (
        "[tool.poetry]\nname='x'\n"
        "[tool.poetry.scripts]\nx = 'pkg.cli:main'\n"
        "[project.entry-points.'myplug']\np = 'pkg.cli:plugin_entry'\n"
    )
    found = symbols(tmp_path, files, pyproject=pyproject)
    assert not {"main", "plugin_entry", "run"} & found


def test_setup_cfg_entry_points_are_entries(tmp_path):
    files = {
        "pkg/__init__.py": "",
        "pkg/cli.py": "def main():\n    return 1\n",
        "setup.cfg": "[options.entry_points]\nconsole_scripts =\n    x = pkg.cli:main\n",
    }
    assert "main" not in symbols(tmp_path, files)


def test_task_runner_and_script_files_are_entry_modules(tmp_path):
    files = {
        "noxfile.py": "import nox\n\n@nox.session\ndef tests(session):\n    session.run('pytest')\n",
        "fabfile.py": "def deploy():\n    pass\n",
        "scripts/migrate.py": "print('migrating')\n",
        "alembic/env.py": "from alembic import context\ncontext.run_migrations()\n",
    }
    found = [item for item in findings_for(tmp_path, files) if item.rule == "POSSIBLY_UNUSED_MODULE"]
    assert not found


def test_test_directories_with_other_names_are_tests(tmp_path):
    files = {
        "pkg/__init__.py": "",
        "pkg/util.py": "def helper():\n    return 1\n",
        "test/test_util.py": "from pkg.util import helper\n\ndef test_helper():\n    assert helper()\n",
        "app/__init__.py": "",
        "app/models.py": "def build():\n    return 1\n",
        "app/tests.py": "from app.models import build\n\ndef test_build():\n    assert build()\n",
    }
    found = symbols(tmp_path, files)
    assert "helper" not in found
    assert "build" not in found


def test_monorepo_subfolder_is_an_import_root(tmp_path):
    files = {
        "backend/app/__init__.py": "",
        "backend/app/models.py": "def _helper():\n    return 1\n\ndef public():\n    return _helper()\n",
        "backend/main.py": "from app.models import public\n\ndef main():\n    return public()\n" + MAIN,
    }
    assert not symbols(tmp_path, files)


def test_library_without_entry_points_is_not_a_confident_orphan(tmp_path):
    files = {
        "lib.py": (
            "def _helper():\n    return 1\n\n"
            "def public_api():\n    return _helper()\n"
        ),
    }
    found = findings_for(tmp_path, files)
    orphans = [item for item in found if item.rule == "ORPHAN_FUNCTION"]
    assert all(item.confidence <= 60 for item in orphans)


def test_parse_error_softens_a_name_the_broken_file_mentions(tmp_path):
    files = {
        "broken.py": "from util import _private\ndef x(:\n",
        "util.py": "def _private():\n    return 1\n",
        "main.py": "import util\n\ndef main():\n    return util\n" + MAIN,
    }
    found = findings_for(tmp_path, files)
    private = [item for item in found if item.symbol == "_private"]
    assert private and all(item.confidence < 90 for item in private)


def test_parse_error_leaves_unrelated_and_local_findings_alone(tmp_path):
    files = {
        "broken.py": "def x(:\n",
        "util.py": "def _private():\n    return 1\n",
        "main.py": (
            "import util\n\ndef main():\n    unused_local = 1\n    return util\n" + MAIN
        ),
    }
    found = {item.symbol: item for item in findings_for(tmp_path, files)}
    assert found["_private"].confidence == 96
    assert found["unused_local"].confidence == 100


def test_parse_error_in_a_test_file_changes_nothing(tmp_path):
    files = {
        "tests/data/broken.py": "from util import _private\ndef x(:\n",
        "util.py": "def _private():\n    return 1\n",
        "main.py": "import util\n\ndef main():\n    return util\n" + MAIN,
    }
    found = {item.symbol: item for item in findings_for(tmp_path, files)}
    assert found["_private"].confidence == 96


# --- scoring of public names ---


def test_dead_public_helper_in_an_application_stays_high(tmp_path):
    files = {
        "app.py": "def dead_helper():\n    return 1\n\ndef main():\n    return 2\n" + MAIN,
    }
    found = {item.symbol: item for item in findings_for(tmp_path, files)}
    assert found["dead_helper"].confidence == 96


def test_public_name_in_a_library_is_only_possible(tmp_path):
    files = {"lib.py": "def public_api():\n    return 1\n"}
    found = {item.symbol: item for item in findings_for(tmp_path, files)}
    assert found["public_api"].confidence == 60


def test_name_exposed_by_init_is_only_possible_in_an_application(tmp_path):
    files = {
        "pkg/__init__.py": "from .core import exposed\n",
        "pkg/core.py": "def exposed():\n    return 1\n\ndef internal():\n    return 2\n",
        "main.py": "import pkg\n\ndef main():\n    return pkg\n" + MAIN,
    }
    found = {item.symbol: item for item in findings_for(tmp_path, files)}
    assert found["exposed"].confidence == 60
    assert found["internal"].confidence == 96


def test_dead_public_module_variable_in_an_application_is_not_certain(tmp_path):
    files = {"app.py": "SPARE = 1\n\ndef main():\n    return 2\n" + MAIN}
    found = {item.symbol: item for item in findings_for(tmp_path, files)}
    assert found["SPARE"].confidence == 96


# --- cache inputs ---


def test_setup_cfg_entry_point_invalidates_the_cached_result(tmp_path):
    files = {
        "pkg/__init__.py": "",
        "pkg/cli.py": "def main():\n    return 1\n",
        "main.py": "import pkg.cli\n\ndef run():\n    return pkg.cli\n" + MAIN.replace("main()", "run()"),
    }
    write_tree(tmp_path, {name: _clean(text) for name, text in files.items()})
    first = scan(tmp_path)
    assert "main" in {item.symbol for item in first.findings}
    (tmp_path / "setup.cfg").write_text(
        "[options.entry_points]\nconsole_scripts =\n    x = pkg.cli:main\n", encoding="utf-8"
    )
    second = scan(tmp_path)
    assert "main" not in {item.symbol for item in second.findings}


# --- class names that only look like framework bases ---


def test_project_class_named_model_is_not_a_declarative_base(tmp_path):
    source = """
    class Model:
        pass

    class User(Model):
        _secret = 1
        label = 2

    def main():
        return User()
    """
    found = {item.symbol: item for item in findings_for(tmp_path, {"app.py": source + MAIN})}
    assert found["_secret"].confidence == 96
    assert found["label"].confidence == 96


def test_external_base_through_a_project_class_caps_the_subclass(tmp_path):
    source = """
    import threading

    class Worker(threading.Thread):
        pass

    class Child(Worker):
        label = 1

        def work(self):
            return 1

    def main():
        return Child()
    """
    found = {item.symbol: item for item in findings_for(tmp_path, {"app.py": source + MAIN})}
    assert found["label"].confidence < 90
    assert found["work"].confidence < 90


def test_enum_through_a_project_class_keeps_its_members(tmp_path):
    source = """
    from enum import Enum

    class BaseEnum(Enum):
        pass

    class Color(BaseEnum):
        RED = "red"

    def main():
        return Color.RED
    """
    assert "RED" not in symbols(tmp_path, {"app.py": source + MAIN})


def test_subclass_attribute_read_by_the_base_is_used(tmp_path):
    files = {
        "pkg/__init__.py": "",
        "pkg/base.py": (
            "class Editor:\n"
            "    sql = 'UPDATE'\n"
            "\n"
            "    def run(self):\n"
            "        return self.sql\n"
        ),
        "pkg/pg.py": (
            "from pkg.base import Editor\n"
            "\n"
            "class Pg(Editor):\n"
            "    sql = 'UPDATE PG'\n"
            "    extra = 1\n"
        ),
        "main.py": "from pkg.pg import Pg\n\ndef main():\n    print(Pg().run())\n" + MAIN,
    }
    found = symbols(tmp_path, files)
    assert "sql" not in found
    assert "extra" in found


def test_framework_model_base_from_a_package_keeps_fields_quiet(tmp_path):
    source = """
    from django.db import models

    class Article(models.Model):
        title = 1

    def main():
        return Article()
    """
    assert "title" not in symbols(tmp_path, {"app.py": source + MAIN})


# --- test directories ---


def test_shipped_testing_package_is_not_treated_as_tests(tmp_path):
    files = {
        "myapp/__init__.py": "",
        "myapp/testing/__init__.py": "",
        "myapp/testing/helpers.py": "def _dead_helper():\n    return 1\n",
        "main.py": "import myapp.testing.helpers\n\ndef main():\n    return myapp\n" + MAIN,
    }
    assert "_dead_helper" in symbols(tmp_path, files)


# --- base-class methods reached through self ---


def test_base_method_called_through_self_in_another_module(tmp_path):
    files = {
        "pkg/__init__.py": "from ._client import Client\n",
        "pkg/_client.py": (
            "class Base:\n"
            "    def _get_proxy_map(self, proxy):\n"
            "        return {}\n"
            "\n"
            "class Client(Base):\n"
            "    def __init__(self, proxy=None):\n"
            "        self.mounts = self._get_proxy_map(proxy)\n"
        ),
        "tests/test_client.py": "from pkg import Client\n\ndef test_client():\n    Client()\n",
    }
    assert "_get_proxy_map" not in symbols(tmp_path, files)


def test_base_method_called_from_a_dunder_on_a_used_class(tmp_path):
    source = """
    class Base:
        def _open(self):
            return 1

    class Client(Base):
        def __enter__(self):
            self._open()
            return self

        def __exit__(self, *args):
            return False

    def main():
        with Client():
            pass
    """
    assert "_open" not in symbols(tmp_path, {"app.py": source + MAIN})


# --- dependencies ---


def test_tooling_and_runtime_packages_are_only_possible(tmp_path):
    files = {"app.py": "def main():\n    return 1\n" + MAIN}
    write_tree(tmp_path, {"app.py": files["app.py"], "requirements.txt": "black\nmypy\nsetuptools\npython-multipart\n"})
    found = [item for item in scan(tmp_path).findings if item.rule == "UNUSED_DEPENDENCY"]
    assert found
    assert all(item.confidence < 90 for item in found)


def test_dependency_named_in_a_string_is_only_possible(tmp_path):
    write_tree(
        tmp_path,
        {
            "settings.py": "INSTALLED_APPS = ['rest_framework']\n",
            "requirements.txt": "rest-framework\n",
            "app.py": "import settings\n\ndef main():\n    return settings\n" + MAIN,
        },
    )
    found = [item for item in scan(tmp_path).findings if item.rule == "UNUSED_DEPENDENCY"]
    assert all(item.confidence < 90 for item in found)


# --- library or application ---

_GUARD = "\nif __name__ == '__main__':\n    pass\n"


def test_docs_setup_and_package_main_guards_do_not_make_an_application(tmp_path):
    files = {
        "pkg/__init__.py": "",
        "pkg/api.py": "def helper():\n    return 1\n",
        "pkg/help.py": "def info():\n    return 1\n" + _GUARD,
        "docs/conf.py": "project = 'x'\n" + _GUARD,
        "setup.py": "from setuptools import setup\nsetup()\n" + _GUARD,
        "examples/demo.py": "def demo():\n    return 1\n" + _GUARD,
    }
    found = {item.symbol: item for item in findings_for(tmp_path, files)}
    assert found["helper"].confidence == 60


def test_console_script_makes_an_application(tmp_path):
    files = {
        "pkg/__init__.py": "",
        "pkg/cli.py": "from pkg import api\n\ndef main():\n    return api\n",
        "pkg/api.py": "def helper():\n    return 1\n",
        "pyproject.toml": "[project]\nname = 'x'\n[project.scripts]\nx = 'pkg.cli:main'\n",
    }
    found = {item.symbol: item for item in findings_for(tmp_path, files)}
    assert found["helper"].confidence == 96


def test_plugin_entry_point_group_does_not_make_an_application(tmp_path):
    files = {
        "pkg/__init__.py": "",
        "pkg/plugin.py": "def load():\n    return 1\n",
        "pkg/api.py": "def helper():\n    return 1\n",
        "pyproject.toml": "[project]\nname = 'x'\n[project.entry-points.pytest11]\nx = 'pkg.plugin:load'\n",
    }
    found = {item.symbol: item for item in findings_for(tmp_path, files)}
    assert found["helper"].confidence == 60


def test_dunder_main_module_makes_an_application(tmp_path):
    files = {
        "pkg/__init__.py": "",
        "pkg/__main__.py": "from pkg import api\nprint(api)\n",
        "pkg/api.py": "def helper():\n    return 1\n",
    }
    found = {item.symbol: item for item in findings_for(tmp_path, files)}
    assert found["helper"].confidence == 96


def test_sphinx_settings_are_not_reported(tmp_path):
    files = {"docs/conf.py": "project = 'x'\nextensions = []\n", "lib.py": "X = 1\n"}
    assert not {"project", "extensions"} & symbols(tmp_path, files)


def _named(findings, symbol, path):
    return [item for item in findings if item.symbol == symbol and item.path == path]


def test_migration_and_settings_caps_apply_without_django_mode(tmp_path):
    write_tree(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/migrations/__init__.py": "class Migration:\n    pass\n",
            "app/migrations/extra.py": "class Migration:\n    pass\n\nclass Helper:\n    pass\n",
            "app/settings.py": "SITE_ID = 1\nname = 'x'\n",
            "app/global_settings.py": "SECURE_HOST = 'x'\n",
            "cfg/__init__.py": "",
            "cfg/settings/__init__.py": "",
            "cfg/settings/base.py": "DATABASES = {}\n",
            "pkg/__init__.py": "",
            "pkg/runtime.py": "SECRET_KEY = 'x'\nplain = 1\n",
            "manage.py": "import os\nos.environ.setdefault('DJANGO_SETTINGS_MODULE', 'pkg.runtime')\n",
            "main.py": (
                "import app.migrations\n"
                "import app.migrations.extra\n"
                "import app.settings\n"
                "import app.global_settings\n"
                "import cfg.settings.base\n"
                "import pkg.runtime\n"
                "\n"
                "def main():\n"
                "    return 1\n"
                "\n"
                "if __name__ == '__main__':\n"
                "    main()\n"
            ),
        },
    )
    findings = scan(tmp_path).findings
    migration = _named(findings, "Migration", "app/migrations/extra.py")
    package_migration = _named(findings, "Migration", "app/migrations/__init__.py")
    helper = _named(findings, "Helper", "app/migrations/extra.py")
    assert migration and all(item.confidence <= 60 for item in migration)
    assert "Framework convention" in migration[0].evidence[-1]
    assert package_migration and all("Framework convention" not in item.evidence[-1] for item in package_migration)
    assert helper and all(item.confidence >= 90 for item in helper)
    for symbol, path in (
        ("SITE_ID", "app/settings.py"),
        ("SECURE_HOST", "app/global_settings.py"),
        ("DATABASES", "cfg/settings/base.py"),
        ("SECRET_KEY", "pkg/runtime.py"),
    ):
        found = _named(findings, symbol, path)
        assert found and all(item.confidence <= 60 for item in found)
    assert _named(findings, "name", "app/settings.py")[0].confidence >= 90
    assert _named(findings, "plain", "pkg/runtime.py")[0].confidence >= 90


def test_upper_names_in_a_settings_template_are_capped(tmp_path):
    write_tree(
        tmp_path,
        {
            "zproject/__init__.py": "",
            "zproject/prod_settings_template.py": "EMAIL_GATEWAY_PATTERN = 'x'\nplain = 1\n",
            "main.py": (
                "import zproject.prod_settings_template\n"
                "\n"
                "def main():\n"
                "    return 1\n"
                "\n"
                "if __name__ == '__main__':\n"
                "    main()\n"
            ),
        },
    )
    findings = scan(tmp_path).findings
    pattern = _named(findings, "EMAIL_GATEWAY_PATTERN", "zproject/prod_settings_template.py")
    plain = _named(findings, "plain", "zproject/prod_settings_template.py")
    assert pattern and pattern[0].confidence <= 60
    assert plain and plain[0].confidence >= 90


def test_appconfig_alias_url_hooks_and_sphinx_setup_are_capped(tmp_path):
    write_tree(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/base.py": (
                "from django.apps import AppConfig\n"
                "\n"
                "class BaseAppConfig(AppConfig):\n"
                "    name = 'base'\n"
            ),
            "app/apps.py": (
                "from app.base import BaseAppConfig\n"
                "from django.apps import AppConfig as AC\n"
                "\n"
                "class AccountAppConfig(AC):\n"
                "    name = 'app'\n"
                "\n"
                "class ProductAppConfig(django.apps.AppConfig):\n"
                "    name = 'product'\n"
                "\n"
                "class Inherited(BaseAppConfig):\n"
                "    name = 'inherited'\n"
                "\n"
                "class Dotted(app.base.BaseAppConfig):\n"
                "    name = 'dotted'\n"
                "\n"
                "class Plain:\n"
                "    pass\n"
            ),
            "app/urls.py": "urlpatterns = []\nhandler404 = 'app.views.missing'\nOTHER = 1\n",
            "docs/__init__.py": "",
            "docs/conf.py": "def setup(app):\n    return app\n\ndef theme():\n    return 1\n",
            "main.py": (
                "import app.apps\n"
                "import app.urls\n"
                "import docs.conf\n"
                "\n"
                "def main():\n"
                "    return 1\n"
                "\n"
                "if __name__ == '__main__':\n"
                "    main()\n"
            ),
        },
    )
    findings = scan(tmp_path).findings
    for symbol in (
        "AccountAppConfig",
        "ProductAppConfig",
        "Inherited",
        "Dotted",
        "urlpatterns",
        "handler404",
        "setup",
    ):
        found = [item for item in findings if item.symbol == symbol]
        assert found and all(item.confidence <= 60 for item in found), symbol
    assert _named(findings, "Plain", "app/apps.py")[0].confidence >= 90
    assert _named(findings, "OTHER", "app/urls.py")[0].confidence >= 90
    assert _named(findings, "theme", "docs/conf.py")[0].confidence >= 90


def test_meta_attributes_stay_hidden_until_requested(tmp_path):
    write_tree(
        tmp_path,
        {
            "shop/__init__.py": "",
            "shop/models.py": (
                "class Other:\n"
                "    model = 1\n"
                "\n"
                "class Order:\n"
                "    class Meta:\n"
                "        model = 'orders.Order'\n"
                "        fields = ['id']\n"
                "\n"
                "def main():\n"
                "    obj = unknown()\n"
                "    Other()\n"
                "    return obj.model\n"
                "\n"
                "if __name__ == '__main__':\n"
                "    main()\n"
            ),
        },
    )
    hidden = scan(tmp_path, config=Config(frameworks=("django",))).findings
    assert not [item for item in hidden if "Meta." in item.fingerprint]
    assert not [item for item in hidden if item.fingerprint.endswith("Other.model")]
    shown = scan(tmp_path, config=Config(report_framework_conventions=True)).findings
    meta_model = [item for item in shown if item.fingerprint.endswith("Order.Meta.model")]
    meta_fields = [item for item in shown if item.fingerprint.endswith("Order.Meta.fields")]
    assert meta_model and meta_model[0].confidence <= 60
    assert "Framework convention" in meta_model[0].evidence[-1]
    assert meta_fields and meta_fields[0].confidence <= 60
    assert not [item for item in shown if item.fingerprint.endswith("Other.model")]


_LIBRARY = {
    "app/__init__.py": "",
    "app/settings.py": "INSTALLED_APPS = []\nSECRET = 1\n",
    "app/urls.py": "urlpatterns = []\n",
    "app/api.py": "def helper():\n    return 1\n",
}


def _unused_modules(findings):
    return {item.path for item in findings if item.rule == "POSSIBLY_UNUSED_MODULE"}


def test_runtime_django_enables_the_preset_without_app_mode(tmp_path):
    findings = findings_for(
        tmp_path,
        _LIBRARY,
        pyproject='[project]\nname = "demo"\nversion = "0.1.0"\ndependencies = ["Django>=4.2"]\n',
    )
    assert load_config(tmp_path).frameworks == ("django",)
    unused = _unused_modules(findings)
    assert "app/settings.py" not in unused
    assert "app/urls.py" not in unused
    assert _named(findings, "helper", "app/api.py")[0].confidence == 60


def test_explicit_django_string_does_not_need_a_dependency(tmp_path):
    findings = findings_for(tmp_path, _LIBRARY, pyproject='[tool.vyarth]\nframeworks = "django"\n')
    assert "app/settings.py" not in _unused_modules(findings)
    assert _named(findings, "helper", "app/api.py")[0].confidence == 60


def test_empty_frameworks_opts_out_of_django_entries(tmp_path):
    findings = findings_for(
        tmp_path,
        _LIBRARY,
        pyproject=(
            '[project]\nname = "demo"\nversion = "0.1.0"\ndependencies = ["Django>=4.2"]\n\n'
            "[tool.vyarth]\nframeworks = []\n"
        ),
    )
    assert load_config(tmp_path).frameworks == ()
    assert "app/settings.py" in _unused_modules(findings)


def test_installed_apps_alone_does_not_enable_django(tmp_path):
    findings = findings_for(tmp_path, _LIBRARY)
    assert load_config(tmp_path).frameworks == ()
    assert "app/settings.py" in _unused_modules(findings)
    assert _named(findings, "helper", "app/api.py")[0].confidence == 60


def test_dev_only_django_does_not_enable_the_preset(tmp_path):
    trees = [
        {
            "pyproject.toml": (
                '[project]\nname = "demo"\nversion = "0.1.0"\ndependencies = ["requests"]\n\n'
                '[project.optional-dependencies]\ntest = ["Django>=4.2"]\n'
            ),
        },
        {"requirements-dev.txt": "Django>=4.2\n"},
        {"docs/requirements.txt": "Django>=4.2\n"},
        {"pyproject.toml": '[tool.poetry.group.dev.dependencies]\ndjango = "*"\n'},
        {"pyproject.toml": '[dependency-groups]\ndev = ["Django>=4.2"]\n'},
        {
            "pyproject.toml": (
                '[project]\nname = "demo"\nversion = "0.1.0"\ndependencies = ["requests"]\n\n'
                '[project.optional-dependencies]\ndjango = ["Django>=4.2"]\n'
            ),
        },
        {
            "pyproject.toml": (
                '[tool.poetry.dependencies]\npython = "^3.11"\n'
                'django = { version = ">=4.2", optional = true }\n'
            ),
        },
    ]
    for index, extra in enumerate(trees):
        root = tmp_path / str(index)
        write_tree(root, {**_LIBRARY, **extra})
        assert load_config(root).frameworks == ()
        assert "app/settings.py" in _unused_modules(scan(root).findings)


def test_poetry_runtime_django_enables_the_preset(tmp_path):
    findings = findings_for(
        tmp_path,
        _LIBRARY,
        pyproject='[tool.poetry.dependencies]\npython = "^3.11"\ndjango = "*"\n',
    )
    assert load_config(tmp_path).frameworks == ("django",)
    assert "app/settings.py" not in _unused_modules(findings)
    assert _named(findings, "helper", "app/api.py")[0].confidence == 60


def test_manage_py_settings_module_enables_django(tmp_path):
    findings = findings_for(
        tmp_path,
        {
            **_LIBRARY,
            "manage.py": (
                "import os\n"
                "import app.api\n"
                "os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'app.settings')\n"
            ),
        },
    )
    assert load_config(tmp_path).frameworks == ("django",)
    assert "app/settings.py" not in _unused_modules(findings)
    assert _named(findings, "helper", "app/api.py")[0].confidence == 96


def test_setup_cfg_install_requires_enables_django(tmp_path):
    findings = findings_for(
        tmp_path,
        {**_LIBRARY, "setup.cfg": "[options]\ninstall_requires =\n    Django>=4.2\n"},
    )
    assert load_config(tmp_path).frameworks == ("django",)
    assert "app/settings.py" not in _unused_modules(findings)
    assert _named(findings, "helper", "app/api.py")[0].confidence == 60


def test_package_wsgi_enables_django(tmp_path):
    findings = findings_for(
        tmp_path,
        {
            **_LIBRARY,
            "app/wsgi.py": "import os\nos.environ.setdefault('DJANGO_SETTINGS_MODULE', 'app.settings')\n",
        },
    )
    assert load_config(tmp_path).frameworks == ("django",)
    assert "app/settings.py" not in _unused_modules(findings)


def test_example_manage_py_does_not_enable_django(tmp_path):
    findings = findings_for(
        tmp_path,
        {
            **_LIBRARY,
            "examples/manage.py": "import os\nos.environ.setdefault('DJANGO_SETTINGS_MODULE', 'app.settings')\n",
        },
    )
    assert load_config(tmp_path).frameworks == ()
    assert "app/settings.py" in _unused_modules(findings)


def test_one_segment_settings_module_does_not_cap_another_file(tmp_path):
    write_tree(
        tmp_path,
        {
            "manage.py": (
                "import os\n"
                "import config\n"
                "import pkg.config\n"
                "os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config')\n"
            ),
            "config.py": "SECRET = 1\n",
            "pkg/__init__.py": "",
            "pkg/config.py": "TOKEN = 1\n",
        },
    )
    findings = scan(tmp_path).findings
    assert _named(findings, "SECRET", "config.py")[0].confidence <= 60
    assert _named(findings, "TOKEN", "pkg/config.py")[0].confidence >= 90


def test_used_meta_outside_a_model_module_keeps_its_score(tmp_path):
    findings = findings_for(
        tmp_path,
        {
            "app.py": (
                "class Widget:\n"
                "    class Meta:\n"
                "        label = 1\n"
                "\n"
                "def main():\n"
                "    return Widget.Meta()\n"
                "\n"
                "if __name__ == '__main__':\n"
                "    main()\n"
            ),
        },
    )
    found = [item for item in findings if item.fingerprint.endswith("Widget.Meta.label")]
    assert found and found[0].confidence >= 90
    assert "Framework convention" not in found[0].evidence[-1]


def test_dotted_settings_string_marks_the_class_used(tmp_path):
    findings = findings_for(
        tmp_path,
        {
            "zerver/__init__.py": "",
            "zerver/middleware.py": (
                "class DetectProxyMisconfiguration:\n"
                "    def process_request(self, request):\n"
                "        return request\n"
                "\n"
                "class Other:\n"
                "    pass\n"
                "\n"
                "def helper():\n"
                "    return 1\n"
            ),
            "zproject/__init__.py": "",
            "zproject/computed_settings.py": (
                "MIDDLEWARE = [\n"
                "    'zerver.middleware.DetectProxyMisconfiguration',\n"
                "    'django.middleware.common.CommonMiddleware',\n"
                "    'zerver.middleware.Ghost.missing',\n"
                "]\n"
            ),
            "main.py": (
                "import zerver.middleware\n"
                "import zproject.computed_settings\n"
                "\n"
                "def main():\n"
                "    return zproject.computed_settings.MIDDLEWARE\n"
                "\n"
                "if __name__ == '__main__':\n"
                "    main()\n"
            ),
        },
    )
    symbols_found = {item.symbol for item in findings}
    assert "DetectProxyMisconfiguration" not in symbols_found
    assert "process_request" not in symbols_found
    assert "Other" in symbols_found
    missing = [item for item in findings if item.symbol == "helper"]
    assert missing and missing[0].confidence >= 90
    ghost = [item for item in findings if item.symbol == "Ghost"]
    assert not ghost


def test_unresolved_dotted_string_caps_only_the_matching_name(tmp_path):
    findings = findings_for(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/hooks.py": (
                "class Ghost:\n"
                "    pass\n"
                "\n"
                "def missing():\n"
                "    return 1\n"
                "\n"
                "def helper():\n"
                "    return 1\n"
            ),
            "app/settings.py": "EMAIL_BACKEND = 'app.hooks.Ghost.missing'\n",
            "main.py": (
                "import app.hooks\n"
                "import app.settings\n"
                "\n"
                "def main():\n"
                "    return app.settings.EMAIL_BACKEND\n"
                "\n"
                "if __name__ == '__main__':\n"
                "    main()\n"
            ),
        },
    )
    assert "Ghost" not in {item.symbol for item in findings}
    missing = [item for item in findings if item.symbol == "missing"]
    assert missing and all(item.confidence <= 60 for item in missing)
    assert "dotted string" in missing[0].evidence[-1]
    helper = [item for item in findings if item.symbol == "helper"]
    assert helper and helper[0].confidence >= 90


def test_rebound_from_import_marks_the_source_used(tmp_path):
    findings = findings_for(
        tmp_path,
        {
            "pkg/__init__.py": "",
            "pkg/global_settings.py": "DSN = 'default'\nOTHER = 1\n",
            "pkg/settings.py": (
                "from pkg.global_settings import DSN\n"
                "DSN = 'override'\n"
                "\n"
                "def value():\n"
                "    return DSN\n"
            ),
            "main.py": (
                "import pkg.settings\n"
                "\n"
                "def main():\n"
                "    return pkg.settings.value()\n"
                "\n"
                "if __name__ == '__main__':\n"
                "    main()\n"
            ),
        },
    )
    assert not _named(findings, "DSN", "pkg/global_settings.py")
    assert "OTHER" in {item.symbol for item in findings}


def test_override_through_an_empty_intermediate_class_is_reached(tmp_path):
    findings = findings_for(
        tmp_path,
        {
            "auth.py": (
                "class Base:\n"
                "    def run(self):\n"
                "        return 1\n"
                "\n"
                "class Mid(Base):\n"
                "    pass\n"
                "\n"
                "class Child(Mid):\n"
                "    def run(self):\n"
                "        return 2\n"
                "\n"
                "class Side(Base):\n"
                "    def other(self):\n"
                "        return 3\n"
            ),
            "main.py": (
                "from auth import Base, Side\n"
                "\n"
                "def main():\n"
                "    Side()\n"
                "    return Base().run()\n"
                "\n"
                "if __name__ == '__main__':\n"
                "    main()\n"
            ),
        },
    )
    names = {item.symbol for item in findings}
    assert "run" not in names
    assert "other" in names


def test_dir_and_getattr_lower_upper_names_in_the_target_module(tmp_path):
    findings = findings_for(
        tmp_path,
        {
            "pkg/__init__.py": "",
            "pkg/defaults.py": "SECURE_HOST = 'x'\nplain = 1\n",
            "pkg/settings.py": (
                "import pkg.defaults as defaults\n"
                "\n"
                "def load():\n"
                "    for name in dir(defaults):\n"
                "        if name.isupper():\n"
                "            globals()[name] = getattr(defaults, name)\n"
            ),
            "main.py": (
                "import pkg.settings\n"
                "\n"
                "def main():\n"
                "    return pkg.settings.load()\n"
                "\n"
                "if __name__ == '__main__':\n"
                "    main()\n"
            ),
        },
    )
    host = [item for item in findings if item.symbol == "SECURE_HOST"]
    assert host and all(item.confidence <= 70 for item in host)
    assert "getattr or dir()" in host[0].evidence[-1]
    plain = [item for item in findings if item.symbol == "plain"]
    assert plain and plain[0].confidence >= 90


def test_mini_django_app_fixture(tmp_path):
    source = Path(__file__).parent / "fixtures" / "django_app"
    for path in source.rglob("*"):
        if not path.is_file():
            continue
        dest = tmp_path / path.relative_to(source)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(path.read_bytes())
    findings = scan(tmp_path).findings
    names = {item.symbol for item in findings}

    def score(symbol, path):
        found = _named(findings, symbol, path)
        assert found, symbol
        return found[0].confidence

    assert "ProxyGuard" not in names
    assert "process_request" not in names
    assert "DSN" not in names
    assert score("Migration", "app/migrations/0001_initial.py") <= 60
    assert score("AccountConfig", "app/apps.py") <= 60
    assert score("urlpatterns", "app/urls.py") <= 60
    assert score("SECRET_KEY", "app/settings.py") <= 60
    assert score("SECURE_HOST", "app/defaults.py") <= 70
    assert score("plain", "app/defaults.py") >= 90
    assert score("forgotten", "app/middleware.py") >= 90


def test_manage_py_without_settings_module_stays_off(tmp_path):
    findings = findings_for(
        tmp_path,
        {**_LIBRARY, "manage.py": "import app.api\n\ndef main():\n    return 1\n"},
    )
    assert load_config(tmp_path).frameworks == ()
    assert "app/settings.py" in _unused_modules(findings)
    assert _named(findings, "helper", "app/api.py")[0].confidence == 96
