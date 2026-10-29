"""Regression tests for code that looks unused to a static scan but is used."""

from textwrap import dedent

from tests.conftest import write_tree
from vyarth import scan

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
