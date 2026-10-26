"""Call-graph orphans and import reachability from entry modules."""

from __future__ import annotations

from pathlib import Path

import pathspec

from vyarth.config import Config
from vyarth.discover import relative_posix
from vyarth.entries import EntrySet
from vyarth.flow import container_targets, held_elements, _module_function, _module_named
from vyarth.model import PUBLIC_NAME_NOTE, Binding, CallEdge, FileIndex, Finding, is_private_name, make_fingerprint
from vyarth.progress import ScanProgress
from vyarth.project import Project, call_is_dead


_ORPHAN_MESSAGE = "No entry point reaches this function."
_EXTERNAL_BASE_NOTE = "May override a method of an external base."
_METHOD_MESSAGE = "Method '{name}' is never used."
_VARIABLE_MESSAGE = "Variable '{name}' is never used."
_UNRESOLVED_NOTE = "An unresolved attribute call uses this name."
_VISITOR_CALLS = {"visit", "generic_visit"}
_PROPERTY_DECORATORS = {"property", "cached_property", "setter", "deleter"}
_WALKED_PROPERTIES = {"property", "cached_property"}
_ENUM_BASES = {"Enum", "IntEnum", "StrEnum", "Flag", "IntFlag"}
_VISITOR_BASES = {"NodeVisitor", "NodeTransformer"}
_FIELD_DECORATORS = {"dataclass", "define"}
_FIELD_NAMES = {
    "attr.s",
    "attr.define",
    "attr.frozen",
    "attr.mutable",
    "attrs.define",
    "attrs.frozen",
    "attrs.mutable",
}


def reachable_modules(project: Project, entries: EntrySet, config: Config) -> set[str]:
    """Modules an entry file can import, including packages along the way."""
    aliases: dict[str, set[str]] = {}
    for index in project.indexes:
        names = set(project.module_names_by_path.get(index.path, ()))
        for name in names:
            if project.by_module.get(name) is index:
                aliases[name] = names
    seeds = set(entries.modules)
    if config.ignore:
        ignored = pathspec.GitIgnoreSpec.from_lines(config.ignore)
        for index in project.indexes:
            relpath = relative_posix(Path(index.path), project.root)
            if ignored.match_file(relpath):
                dotted = project.module_names_by_path.get(index.path, ())
                if dotted:
                    seeds.add(dotted[0])
    seen = _with_parents(seeds)
    queue = list(seen)
    while queue:
        name = queue.pop()
        module_index = project.by_module.get(name)
        if module_index is None:
            continue
        for edge in module_index.imports:
            for used in project.modules_used_by(edge.module, edge.level, edge.imported_name, module_index.path):
                _reach(used, seen, queue, aliases)
    return seen


def _reach(name: str, seen: set[str], queue: list[str], aliases: dict[str, set[str]]) -> None:
    pending = [name]
    while pending:
        current = pending.pop()
        if current in seen:
            continue
        seen.add(current)
        queue.append(current)
        pending.extend(aliases.get(current, ()))


def orphan_findings(
    project: Project,
    entries: EntrySet,
    referenced: set[tuple[str, str]],
    exported: set[tuple[str, str]],
    reachable: set[tuple[str, str]],
    unresolved: set[str],
    progress: ScanProgress | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    total = len(project.indexes)
    for number, index in enumerate(project.indexes, start=1):
        relpath = relative_posix(Path(index.path), project.root)
        if progress is not None:
            progress.update("checking methods", f"{number}/{total} {relpath}")
        classes = {binding.qualname: binding for binding in index.bindings if binding.kind == "class"}
        for binding in index.bindings:
            if binding.kind != "function":
                continue
            if _silent_name(binding.name) or binding.qualname in index.abstract:
                continue
            if (index.path, binding.qualname) in entries.symbols:
                continue
            if (index.path, binding.qualname) in reachable:
                continue
            if (index.path, binding.qualname) in exported:
                continue
            if binding.scope_kind == "module":
                if binding.name in index.exports:
                    continue
                if not _referenced(index, binding, referenced):
                    continue
            elif binding.scope_kind == "class":
                if _decorated(index, binding.qualname, _PROPERTY_DECORATORS):
                    continue
                class_name = binding.qualname.rsplit(".", 1)[0]
                class_binding = classes.get(class_name)
                if class_binding is None or not _class_used(index, class_binding, referenced, reachable):
                    continue
                if binding.name in unresolved:
                    findings.append(_orphan(relpath, binding, 60))
                    continue
                if _symbol_referenced(project, index, binding, referenced):
                    findings.append(_orphan(relpath, binding, 80))
                    continue
                if _has_external_base(project, index, class_name):
                    findings.append(
                        Finding(
                            rule="UNUSED_FUNCTION",
                            path=relpath,
                            line=binding.line,
                            column=binding.column,
                            symbol=binding.name,
                            status="POSSIBLY_DEAD",
                            confidence=60,
                            message=_METHOD_MESSAGE.format(name=binding.name),
                            evidence=("No references found.", _EXTERNAL_BASE_NOTE),
                            fingerprint=make_fingerprint("UNUSED_FUNCTION", relpath, binding.qualname),
                        )
                    )
                    continue
                private = is_private_name(binding.name)
                findings.append(
                    Finding(
                        rule="UNUSED_FUNCTION",
                        path=relpath,
                        line=binding.line,
                        column=binding.column,
                        symbol=binding.name,
                        status="POSSIBLY_DEAD",
                        confidence=96 if private else 60,
                        message=_METHOD_MESSAGE.format(name=binding.name),
                        evidence=("No references found.",) if private else ("No references found.", PUBLIC_NAME_NOTE),
                        fingerprint=make_fingerprint("UNUSED_FUNCTION", relpath, binding.qualname),
                    )
                )
                continue
            else:
                continue
            confidence = 60 if binding.name in unresolved else 80
            findings.append(_orphan(relpath, binding, confidence))
    return findings


def class_attribute_findings(
    project: Project,
    referenced: set[tuple[str, str]],
    reachable: set[tuple[str, str]],
    unresolved: set[str],
    progress: ScanProgress | None = None,
) -> list[Finding]:
    """Class attributes nobody loads. Dataclass and attrs fields stay quiet."""
    findings: list[Finding] = []
    total = len(project.indexes)
    owners = _attribute_owners(project, referenced, reachable)
    for number, index in enumerate(project.indexes, start=1):
        relpath = relative_posix(Path(index.path), project.root)
        if progress is not None:
            progress.update("checking class attributes", f"{number}/{total} {relpath}")
        classes = {binding.qualname: binding for binding in index.bindings if binding.kind == "class"}
        for binding in index.bindings:
            if binding.kind != "variable" or binding.scope_kind != "class" or "." not in binding.qualname:
                continue
            if _silent_name(binding.name):
                continue
            class_name = binding.qualname.rsplit(".", 1)[0]
            if _declarative_class(project, index, class_name) or _enum_class(index, class_name):
                continue
            class_binding = classes.get(class_name)
            if class_binding is None or not _class_used(index, class_binding, referenced, reachable):
                continue
            if (index.path, binding.qualname) in reachable:
                continue
            if _symbol_referenced(project, index, binding, referenced):
                continue
            if binding.name in unresolved and owners.get(binding.name, 0) == 1:
                # One class defines this name and an attribute with that name is loaded
                # on a receiver of unknown type.
                continue
            if binding.name in unresolved:
                confidence = 60
                evidence = (_UNRESOLVED_NOTE,)
            elif _has_external_base(project, index, class_name):
                # A framework base may read this name by reflection.
                confidence = 60
                evidence = ("No references found.", _EXTERNAL_BASE_NOTE)
            elif is_private_name(binding.name):
                confidence = 96
                evidence = ("No references found.",)
            else:
                confidence = 60
                evidence = ("No references found.", PUBLIC_NAME_NOTE)
            findings.append(
                Finding(
                    rule="UNUSED_VARIABLE",
                    path=relpath,
                    line=binding.line,
                    column=binding.column,
                    symbol=binding.name,
                    status="POSSIBLY_DEAD",
                    confidence=confidence,
                    message=_VARIABLE_MESSAGE.format(name=binding.name),
                    evidence=evidence,
                    fingerprint=make_fingerprint("UNUSED_VARIABLE", relpath, binding.qualname),
                )
            )
    return findings


def _attribute_owners(
    project: Project,
    referenced: set[tuple[str, str]],
    reachable: set[tuple[str, str]],
) -> dict[str, int]:
    """How many used classes define a class attribute of each name."""
    counts: dict[str, int] = {}
    for index in project.indexes:
        classes = {binding.qualname: binding for binding in index.bindings if binding.kind == "class"}
        for binding in index.bindings:
            if binding.kind != "variable" or binding.scope_kind != "class" or "." not in binding.qualname:
                continue
            class_binding = classes.get(binding.qualname.rsplit(".", 1)[0])
            if class_binding is None or not _class_used(index, class_binding, referenced, reachable):
                continue
            counts[binding.name] = counts.get(binding.name, 0) + 1
    return counts


def subclass_registry_symbols(project: Project) -> set[tuple[str, str]]:
    """Subclasses of a class that defines `__init_subclass__`.

    Defining the subclass runs the parent hook, so nothing needs to name it.
    """
    hooks: set[tuple[str, str]] = set()
    for path, bindings in project.bindings.items():
        for qualname, binding in bindings.items():
            if binding.kind == "function" and binding.name == "__init_subclass__" and "." in qualname:
                hooks.add((path, qualname.rsplit(".", 1)[0]))
    if not hooks:
        return set()
    found: set[tuple[str, str]] = set()
    for index in project.indexes:
        for class_name, _bases in index.class_bases:
            ancestors = _class_ancestors(project, index.path, class_name)
            ancestors.discard((index.path, class_name))
            if ancestors & hooks:
                found.add((index.path, class_name))
    return found


def import_hops(project: Project) -> set[tuple[str, str]]:
    """Import bindings that a resolved call or value chain passes through.

    `pkg.thing()` uses the `thing` that `pkg/__init__.py` imports, even when
    `__init__.py` never loads the name itself.
    """
    _resolved_mentions(project)
    found: set[tuple[str, str]] = set()
    for hops in project.follow_hops.values():
        for path, qualname in hops:
            binding = project.bindings.get(path, {}).get(qualname)
            if binding is not None and binding.kind == "import":
                found.add((path, qualname))
    return found


def _orphan(relpath: str, binding: Binding, confidence: int) -> Finding:
    evidence = [_ORPHAN_MESSAGE]
    if confidence == 60:
        evidence.append(_UNRESOLVED_NOTE)
    return Finding(
        rule="ORPHAN_FUNCTION",
        path=relpath,
        line=binding.line,
        column=binding.column,
        symbol=binding.name,
        status="POSSIBLY_DEAD",
        confidence=confidence,
        message=_ORPHAN_MESSAGE,
        evidence=tuple(evidence),
        fingerprint=make_fingerprint("ORPHAN_FUNCTION", relpath, binding.qualname),
    )


def reachable_symbols(project: Project, entries: EntrySet) -> tuple[set[tuple[str, str]], set[str]]:
    reachable: set[tuple[str, str]] = set()
    unresolved: set[str] = set()
    queue: list[tuple[str, str]] = []
    queued: set[tuple[str, str]] = set()
    owners: dict[str, list[tuple[str, str]]] = {}
    seen_classes: set[tuple[str, str]] = set()

    def add(path: str, qualname: str) -> bool:
        """Mark a symbol reached. False when the name matches no definition."""
        if qualname.startswith("@lambda:"):
            queued_marker = (path, qualname)
            if queued_marker in queued:
                return True
            queued.add(queued_marker)
            queue.append(queued_marker)
            return True
        if qualname.startswith("@attr:"):
            unresolved.add(qualname[len("@attr:") :])
            return True
        resolved = _marker(path, qualname)
        if resolved is None:
            return False
        reachable.add(resolved)
        if resolved in queued:
            return True
        queued.add(resolved)
        queue.append(resolved)
        _mark_overrides(resolved)
        return True

    def add_dangling(path: str, call: CallEdge) -> None:
        """A method call that named no definition may hit a subclass or an unseen receiver."""
        callee = call.callee
        if "." in callee and not callee.startswith("@"):
            class_name, method = callee.rsplit(".", 1)
            found = False
            for sub_path, sub_class in _all_subclasses(path, class_name):
                override = f"{sub_class}.{method}"
                if override in project.bindings.get(sub_path, {}):
                    add(sub_path, override)
                    found = True
            if found:
                return
        if call.callee_name and (
            not callee.startswith("@") or _import_targets_project(project, path, callee)
        ):
            unresolved.add(call.callee_name)

    def _all_subclasses(path: str, class_name: str) -> list[tuple[str, str]]:
        found: list[tuple[str, str]] = []
        pending = [(path, class_name)]
        seen_here: set[tuple[str, str]] = set()
        while pending:
            key = pending.pop()
            for item in subclasses.get(key, ()):
                if item in seen_here:
                    continue
                seen_here.add(item)
                found.append(item)
                pending.append(item)
        return found

    def _mark_overrides(resolved: tuple[str, str]) -> None:
        path, qualname = resolved
        binding = project.bindings.get(path, {}).get(qualname)
        if binding is None or binding.kind != "function" or "." not in qualname:
            return
        class_name, method = qualname.rsplit(".", 1)
        for sub_path, sub_class in subclasses.get((path, class_name), ()):
            override = f"{sub_class}.{method}"
            if override in project.bindings.get(sub_path, {}):
                add(sub_path, override)

    def touch(path: str, qualname: str) -> None:
        """Mark a stored function used without walking its body."""
        marker = _marker(path, qualname)
        if marker is None:
            return
        reachable.add(marker)

    def _marker(path: str, qualname: str) -> tuple[str, str] | None:
        current_path, current_name = _locate(path, qualname)
        if current_name not in project.bindings.get(current_path, {}):
            return None
        return current_path, current_name

    def _locate(path: str, qualname: str) -> tuple[str, str]:
        current_path, current_name = _follow_imports(project, path, qualname)
        if current_name.startswith("@super:"):
            found = _inherited_method(current_path, current_name[len("@super:") :])
            return found if found is not None else (current_path, current_name)
        if current_name not in project.bindings.get(current_path, {}):
            found = _inherited_method(current_path, current_name)
            if found is not None:
                return found
        return current_path, current_name

    def _inherited_method(path: str, qualname: str) -> tuple[str, str] | None:
        if "." not in qualname or qualname.startswith("@"):
            return None
        class_name, method = qualname.rsplit(".", 1)
        return _find_in_bases(path, class_name, method, set())

    def _find_in_bases(path: str, class_name: str, method: str, seen: set[tuple[str, str]]) -> tuple[str, str] | None:
        index = project.by_path.get(path)
        if index is None:
            return None
        for base in project.bases.get(path, {}).get(class_name, ()):
            resolved = _resolve_base(index, base)
            if resolved is None:
                continue
            base_path, base_name = resolved
            key = (base_path, base_name)
            if key in seen:
                continue
            seen.add(key)
            candidate = f"{base_name}.{method}"
            if candidate in project.bindings.get(base_path, {}):
                return base_path, candidate
            found = _find_in_bases(base_path, base_name, method, seen)
            if found is not None:
                return found
        return None

    def _resolve_base(index: FileIndex, spec: str) -> tuple[str, str] | None:
        return _project_base(project, index, spec)

    def consider_values(path: str, caller: str) -> None:
        for qualname in project.value_uses.get((path, caller), ()):
            add(path, qualname)
        index = project.by_path.get(path)
        if index is None:
            return
        held = held_elements(index, caller)
        if not held:
            return
        selected = container_targets(index, caller, project.dead_spans.get(path, ()))
        if selected is None:
            for qualname in held:
                add(path, qualname)
            return
        for qualname, names in held.items():
            if any(qualname in selected.get(name, ()) for name in names):
                add(path, qualname)
            elif any(name in selected for name in names):
                touch(path, qualname)
            else:
                add(path, qualname)

    def deferred(path: str, caller: str) -> bool:
        return "<lambda:" in caller or "<lambda#" in caller or (path, caller) in project.function_callers

    def consider(index: FileIndex, call: CallEdge) -> None:
        if call_is_dead(project, index.path, call.line, call.col_offset):
            return
        if call.callee.startswith("@box:"):
            return
        if call.callee.startswith("@super:"):
            add(index.path, call.callee)
            return
        if call.resolved and call.callee:
            if not _add_call_target(project, index.path, call, add) and call.kind == "method":
                add_dangling(index.path, call)
            return
        if call.kind == "name" and call.callee_name:
            target = _wildcard_symbol(project, index, call.callee_name)
            if target is not None:
                add(*target)
                return
        if call.callee_name:
            unresolved.add(call.callee_name)

    def add_unique_methods() -> None:
        for key in referenced_classes(project, reachable) - seen_classes:
            seen_classes.add(key)
            for name, qualname in project.methods_by_class.get(key, ()):
                owners.setdefault(name, []).append((key[0], qualname))
        for name in unresolved:
            matches = owners.get(name, [])
            # One owner is unambiguous. Several owners that share a base are one
            # polymorphic method, so a call on any receiver can reach all of them.
            if len(matches) == 1 or (len(matches) > 1 and _share_a_base(project, matches)):
                for match in matches:
                    add(*match)

    def add_properties() -> None:
        """Walk `@property` bodies on a used class so calls inside them count."""
        for path, class_name in referenced_classes(project, reachable):
            index = project.by_path.get(path)
            if index is None:
                continue
            for item in index.decorators:
                if item.name.rsplit(".", 1)[-1] not in _WALKED_PROPERTIES or "." not in item.qualname:
                    continue
                owner = item.qualname.rsplit(".", 1)[0]
                if owner == class_name:
                    add(path, item.qualname)

    def add_visitors() -> None:
        """`ast.NodeVisitor.visit` dispatches to `visit_*` by node name."""
        for path, class_name in referenced_classes(project, reachable):
            methods = project.visitors.get((path, class_name))
            if not methods or not _visitor_class(project, path, class_name):
                continue
            for qualname in methods:
                add(path, qualname)

    subclasses: dict[tuple[str, str], list[tuple[str, str]]] = {}
    for index in project.indexes:
        for class_name, bases in index.class_bases:
            for base in bases:
                resolved = _resolve_base(index, base)
                if resolved is None:
                    continue
                subclasses.setdefault(resolved, []).append((index.path, class_name))

    for path, qualname in entries.symbols:
        add(path, qualname)
    for path, class_name in subclass_registry_symbols(project):
        add(path, class_name)
        add(path, f"{class_name}.__init__")
        for _name, method in project.methods_by_class.get((path, class_name), ()):
            add(path, method)
    opened: set[tuple[str, str]] = set()
    for path, caller in project.value_uses:
        if not deferred(path, caller):
            consider_values(path, caller)
            opened.add((path, caller))
    for index in project.indexes:
        for store in index.container_stores:
            key = (index.path, store.caller)
            if key in opened or (store.caller != "<module>" and deferred(index.path, store.caller)):
                continue
            consider_values(index.path, store.caller)
            opened.add(key)
    for (path, caller), calls in project.calls_by_caller.items():
        if caller != "<module>" and deferred(path, caller):
            continue
        index = project.by_path[path]
        for call in calls:
            consider(index, call)

    progress = True
    while progress:
        progress = False
        while queue:
            path, qualname = queue.pop()
            if qualname.startswith("@lambda:"):
                caller = qualname[len("@lambda:") :]
                consider_values(path, caller)
                index = project.by_path[path]
                for call in project.calls_by_caller.get((path, caller), ()):
                    consider(index, call)
                continue
            index = project.by_path[path]
            consider_values(path, qualname)
            for call in project.calls_by_caller.get((path, qualname), ()):
                consider(index, call)
        before = len(reachable)
        add_unique_methods()
        add_properties()
        add_visitors()
        if len(reachable) != before:
            progress = True
    return reachable, unresolved


def referenced_classes(project: Project, reachable: set[tuple[str, str]]) -> set[tuple[str, str]]:
    found: set[tuple[str, str]] = set()
    for path, binding in project.classes:
        if binding.read_count > 0 or (path, binding.qualname) in reachable:
            found.add((path, binding.qualname))
        elif binding.scope_kind == "module" and binding.name in project.by_path[path].exports:
            found.add((path, binding.qualname))
    return found


def _add_call_target(project: Project, path: str, call: CallEdge, add) -> bool:
    found = add(path, call.callee)
    binding = project.bindings.get(path, {}).get(call.callee)
    if binding is not None and binding.kind == "class":
        add(path, f"{binding.qualname}.__init__")
    if call.kind == "method" and call.callee_name in _VISITOR_CALLS and "." in call.callee:
        class_name = call.callee.rsplit(".", 1)[0]
        for qualname in project.visitors.get((path, class_name), ()):
            add(path, qualname)
    return found


def _class_ancestors(project: Project, path: str, class_name: str) -> set[tuple[str, str]]:
    """The class and every project class it inherits from."""
    found: set[tuple[str, str]] = set()
    pending = [(path, class_name)]
    while pending:
        current = pending.pop()
        if current in found:
            continue
        found.add(current)
        index = project.by_path.get(current[0])
        if index is None:
            continue
        for base in project.bases.get(current[0], {}).get(current[1], ()):
            resolved = _project_base(project, index, base)
            if resolved is not None:
                pending.append(resolved)
    return found


def _share_a_base(project: Project, matches: list[tuple[str, str]]) -> bool:
    common: set[tuple[str, str]] | None = None
    for path, qualname in matches:
        ancestors = _class_ancestors(project, path, qualname.rsplit(".", 1)[0])
        common = ancestors if common is None else common & ancestors
        if not common:
            return False
    return bool(common)


def _import_targets_project(project: Project, path: str, callee: str) -> bool:
    """True when an `@import:` callee names a module or symbol this scan indexed."""
    if not callee.startswith("@import:"):
        return False
    import_qual, _method = _split_import_qualname(callee)
    if import_qual is None:
        return False
    binding = project.bindings.get(path, {}).get(import_qual)
    if binding is None or binding.kind != "import":
        return False
    edge = project.edge_for(path, binding.name, binding.line)
    if edge is None or edge.is_wildcard:
        return False
    module = project.resolve_import(edge.module, edge.level, path)
    if module is None:
        return False
    if edge.imported_name:
        child = f"{module}.{edge.imported_name}" if module else edge.imported_name
        return module in project.by_module or child in project.by_module
    return module in project.by_module


def _follow_imports(project: Project, path: str, qualname: str) -> tuple[str, str]:
    key = (path, qualname)
    cached = project.follow_cache.get(key)
    if cached is not None:
        return cached
    seen: set[tuple[str, str]] = set()
    current = (path, qualname)
    while current not in seen:
        seen.add(current)
        jumped = _jump_import(project, current[0], current[1])
        if jumped is None:
            break
        current = jumped
    project.follow_cache[key] = current
    project.follow_hops[key] = tuple(seen)
    return current


def _jump_import(project: Project, path: str, qualname: str) -> tuple[str, str] | None:
    xref = _parse_xref(qualname)
    if xref is not None:
        return xref
    import_qual, method = _split_import_qualname(qualname)
    if import_qual is None:
        binding = project.bindings.get(path, {}).get(qualname)
        if binding is None or binding.kind != "import":
            return None
        import_qual = qualname
        method = ""
    index = project.by_path.get(path)
    if index is None:
        return None
    binding = project.bindings.get(path, {}).get(import_qual)
    if binding is None or binding.kind != "import":
        return None
    edge = project.edge_for(index.path, binding.name, binding.line)
    if edge is None or edge.is_wildcard or edge.imported_name == "*":
        return None
    module = project.resolve_import(edge.module, edge.level, index.path)
    if not edge.imported_name:
        if not method or not module:
            return None
        target = project.by_module.get(module)
        if target is None:
            return None
        target_binding = project.module_binding(target.path, method)
        if target_binding is None:
            return _wildcard_symbol(project, target, method)
        return target.path, target_binding.qualname
    if module is None:
        return None
    submodule = _submodule_symbol(project, module, edge.imported_name, method)
    if submodule is not None:
        return submodule
    if not module:
        return None
    target = project.by_module.get(module)
    if target is None:
        return None
    target_binding = project.module_binding(target.path, edge.imported_name)
    if target_binding is None:
        reexported = _wildcard_symbol(project, target, edge.imported_name)
        if reexported is None:
            return None
        if method:
            return reexported[0], f"{reexported[1]}.{method}"
        return reexported
    if method:
        return target.path, f"{target_binding.qualname}.{method}"
    return target.path, target_binding.qualname


def _submodule_symbol(
    project: Project,
    module: str,
    imported_name: str,
    method: str,
) -> tuple[str, str] | None:
    """`types.OptionHelpExtra` when `types` is a project submodule, not a class."""
    if not method:
        return None
    child = f"{module}.{imported_name}" if module else imported_name
    submodule = project.by_module.get(child)
    if submodule is None:
        return None
    symbol = project.module_binding(submodule.path, method)
    if symbol is None or symbol.scope_kind != "module":
        return None
    return submodule.path, symbol.qualname


def _parse_xref(qualname: str) -> tuple[str, str] | None:
    marker = "@xref:"
    if not qualname.startswith(marker):
        return None
    path, separator, name = qualname[len(marker) :].partition("\x1f")
    if not separator or not path or not name:
        return None
    return path, name


def _split_import_qualname(qualname: str) -> tuple[str | None, str]:
    marker = "@import:"
    if not qualname.startswith(marker):
        return None, ""
    rest = qualname[len(marker) :]
    import_qual, separator, method = rest.rpartition(".")
    if not separator:
        return rest, ""
    return import_qual, method


def wildcard_references(project: Project) -> set[tuple[str, str]]:
    """Definitions named by a wildcard import in a file that actually loads them."""
    found: set[tuple[str, str]] = set()
    for index in project.indexes:
        if not index.unbound_names:
            continue
        for name in index.unbound_names:
            target = _wildcard_symbol(project, index, name)
            if target is not None:
                found.add(target)
    return found


def _wildcard_symbol(project: Project, index: FileIndex, name: str) -> tuple[str, str] | None:
    found: tuple[str, str] | None = None
    for edge in index.imports:
        if not edge.is_wildcard:
            continue
        module = project.resolve_import(edge.module, edge.level, index.path)
        if not module:
            continue
        target = project.by_module.get(module)
        if target is None:
            continue
        binding = project.module_binding(target.path, name)
        if binding is None or binding.scope_kind != "module":
            continue
        if target.exports:
            if name not in target.exports:
                continue
        elif name.startswith("_"):
            continue
        found = (target.path, binding.qualname)
    return found


def reexported_symbol(project: Project, target: FileIndex, name: str) -> tuple[str, str] | None:
    """Definition `target` re-exports under `name` through a wildcard import."""
    return _wildcard_symbol(project, target, name)


def _decorated(index: FileIndex, qualname: str, names: set[str]) -> bool:
    for item in index.decorators:
        if item.qualname == qualname and item.name.rsplit(".", 1)[-1] in names:
            return True
    return False


def _visitor_class(project: Project, path: str, class_name: str) -> bool:
    index = project.by_path.get(path)
    if index is None:
        return False
    for name, bases in index.class_bases:
        if name != class_name:
            continue
        if any(_base_leaf(base) in _VISITOR_BASES for base in bases):
            return True
    bindings = project.bindings.get(path, {})
    return any(f"{class_name}.{method}" in bindings for method in _VISITOR_CALLS)


def _enum_class(index: FileIndex, qualname: str) -> bool:
    for class_name, bases in index.class_bases:
        if class_name != qualname:
            continue
        for base in bases:
            if _base_leaf(base) in _ENUM_BASES:
                return True
    return False


def _field_class(index: FileIndex, qualname: str) -> bool:
    for item in index.decorators:
        if item.qualname != qualname:
            continue
        if item.name in _FIELD_NAMES or item.name.rsplit(".", 1)[-1] in _FIELD_DECORATORS:
            return True
    for class_name, bases in index.class_bases:
        if class_name != qualname:
            continue
        for base in bases:
            if _base_leaf(base) in {"BaseModel", "DeclarativeBase"}:
                return True
    return False


_DECLARATIVE_BASES = {
    "BaseModel",
    "BaseSettings",
    "DeclarativeBase",
    "DeclarativeBaseNoMeta",
    "Model",
    "SQLModel",
    "Schema",
    "Serializer",
    "ModelSerializer",
    "Form",
    "ModelForm",
    "TypedDict",
    "NamedTuple",
    "Protocol",
    "Struct",
    "Document",
}


def _declarative_class(project: Project, index: FileIndex, qualname: str, _seen: frozenset = frozenset()) -> bool:
    """A class whose class-level names are framework fields, directly or by inheritance."""
    if _field_class(index, qualname):
        return True
    key = (index.path, qualname)
    if key in _seen:
        return False
    for class_name, bases in index.class_bases:
        if class_name != qualname:
            continue
        for base in bases:
            if _base_leaf(base) in _DECLARATIVE_BASES:
                return True
            resolved = _project_base(project, index, base)
            if resolved is None:
                continue
            owner = project.by_path.get(resolved[0])
            if owner is not None and _declarative_class(project, owner, resolved[1], _seen | {key}):
                return True
    return False


def _base_leaf(base: str) -> str:
    if base.startswith("@expr:"):
        base = base[len("@expr:") :]
    elif base.startswith("@import:"):
        base = base[len("@import:") :]
    return base.rsplit(".", 1)[-1]


def _resolved_mentions(project: Project) -> set[tuple[str, str]]:
    if project.mentions is not None:
        return project.mentions
    found: set[tuple[str, str]] = set()
    for (path, _), calls in project.calls_by_caller.items():
        for call in calls:
            if not call.resolved or not call.callee:
                continue
            found.add(_follow_imports(project, path, call.callee))
    for (path, _), uses in project.value_uses.items():
        for used in uses:
            found.add(_follow_imports(project, path, used))
    project.mentions = found
    return found


def _project_base(project: Project, index: FileIndex, spec: str) -> tuple[str, str] | None:
    """Project class a base expression names, or None when the base is external."""
    if spec.startswith("@expr:"):
        dotted = spec[len("@expr:") :]
        dotted_module, separator, attr = dotted.rpartition(".")
        if not separator:
            return None
        module = _module_named(project, index, dotted_module)
        binding = _module_function(project, module, attr)
        if module is None or binding is None or binding.kind != "class":
            return None
        return module.path, binding.qualname
    if spec.startswith("@import:"):
        resolved_path, name = _follow_imports(project, index.path, spec)
        binding = project.bindings.get(resolved_path, {}).get(name)
        if binding is not None and binding.kind == "class":
            return resolved_path, name
        return None
    binding = project.bindings.get(index.path, {}).get(spec)
    if binding is not None and binding.kind == "class":
        return index.path, spec
    return None


def _has_external_base(project: Project, index: FileIndex, class_name: str) -> bool:
    bases = dict(index.class_bases).get(class_name)
    if not bases:
        return False
    return any(_project_base(project, index, base) is None for base in bases)


def _symbol_referenced(
    project: Project,
    index: FileIndex,
    binding: Binding,
    referenced: set[tuple[str, str]],
) -> bool:
    if _referenced(index, binding, referenced):
        return True
    return (index.path, binding.qualname) in _resolved_mentions(project)


def _referenced(index: FileIndex, binding: Binding, referenced: set[tuple[str, str]]) -> bool:
    if binding.read_count > 0:
        return True
    return (index.path, binding.qualname) in referenced


def _class_used(
    index: FileIndex,
    binding: Binding,
    referenced: set[tuple[str, str]],
    reachable: set[tuple[str, str]],
) -> bool:
    if binding.read_count > 0 or (index.path, binding.qualname) in reachable:
        return True
    if binding.scope_kind == "module" and binding.name in index.exports:
        return True
    return (index.path, binding.qualname) in referenced


def _with_parents(names: set[str]) -> set[str]:
    found = set(names)
    for name in names:
        parts = name.split(".")
        for index in range(1, len(parts)):
            found.add(".".join(parts[:index]))
    return found


def _silent_name(name: str) -> bool:
    if name == "_":
        return True
    return len(name) >= 5 and name.startswith("__") and name.endswith("__")
