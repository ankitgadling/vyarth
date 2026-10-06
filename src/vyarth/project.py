"""Indexes shared by one scan. Built once so later passes do not rebuild them."""

from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path

from vyarth.discover import indexes_by_module, package_roots
from vyarth.model import Binding, CallEdge, FileIndex, ImportEdge, UnreachableSpan, point_in_spans


@dataclass
class Project:
    root: Path
    roots: list[Path]
    indexes: list[FileIndex]
    by_path: dict[str, FileIndex]
    by_module: dict[str, FileIndex]
    bindings: dict[str, dict[str, Binding]]
    module_bindings: dict[str, dict[str, Binding]]
    import_edges: dict[str, dict[str, tuple[ImportEdge, ...]]]
    calls_by_caller: dict[tuple[str, str], tuple[CallEdge, ...]]
    methods_by_class: dict[tuple[str, str], tuple[tuple[str, str], ...]]
    visitors: dict[tuple[str, str], tuple[str, ...]]
    classes: tuple[tuple[str, Binding], ...]
    bases: dict[str, dict[str, tuple[str, ...]]]
    function_callers: set[tuple[str, str]]
    value_uses: dict[tuple[str, str], tuple[str, ...]]
    dead_spans: dict[str, tuple[UnreachableSpan, ...]]

    def edge_for(self, path: str, alias: str, line: int) -> ImportEdge | None:
        edges = self.import_edges.get(path, {}).get(alias, ())
        for edge in edges:
            if edge.line == line:
                return edge
        if edges:
            return edges[-1]
        return None

    def module_binding(self, path: str, name: str) -> Binding | None:
        return self.module_bindings.get(path, {}).get(name)


def rebind(project: Project, indexes: list[FileIndex]) -> Project:
    """Point module maps at indexes whose call edges were extended."""
    by_path = {index.path: index for index in indexes}
    by_module = {name: by_path[index.path] for name, index in project.by_module.items()}
    return replace(
        project,
        indexes=indexes,
        by_path=by_path,
        by_module=by_module,
        calls_by_caller=_calls_by_caller(indexes),
    )


def build_project(indexes: list[FileIndex], root: Path) -> Project:
    root = root.resolve()
    roots = package_roots(root)
    by_path = {index.path: index for index in indexes}
    bindings: dict[str, dict[str, Binding]] = {}
    module_bindings: dict[str, dict[str, Binding]] = {}
    import_edges: dict[str, dict[str, tuple[ImportEdge, ...]]] = {}
    methods: dict[tuple[str, str], list[tuple[str, str]]] = {}
    visitors: dict[tuple[str, str], list[str]] = {}
    classes: list[tuple[str, Binding]] = []
    bases: dict[str, dict[str, tuple[str, ...]]] = {}
    function_callers: set[tuple[str, str]] = set()
    value_uses: dict[tuple[str, str], list[str]] = {}
    for index in indexes:
        qualnames: dict[str, Binding] = {}
        modules: dict[str, Binding] = {}
        for binding in index.bindings:
            qualnames[binding.qualname] = binding
            if binding.scope_kind == "module" and binding.name not in modules:
                modules[binding.name] = binding
            if binding.kind == "class":
                classes.append((index.path, binding))
            if binding.kind == "function" and ".visit_" in binding.qualname:
                class_name = binding.qualname.split(".visit_", 1)[0]
                visitors.setdefault((index.path, class_name), []).append(binding.qualname)
            if binding.kind != "function":
                continue
            function_callers.add((index.path, binding.qualname))
            if binding.scope_kind != "class" or "." not in binding.qualname:
                continue
            class_name, method_name = binding.qualname.rsplit(".", 1)
            methods.setdefault((index.path, class_name), []).append((method_name, binding.qualname))
        bindings[index.path] = qualnames
        module_bindings[index.path] = modules
        grouped: dict[str, list[ImportEdge]] = {}
        for edge in index.imports:
            if edge.is_wildcard or not edge.alias:
                continue
            grouped.setdefault(edge.alias, []).append(edge)
        import_edges[index.path] = {name: tuple(found) for name, found in grouped.items()}
        bases[index.path] = {name: names for name, names in index.class_bases}
        for caller, qualname in index.value_uses:
            value_uses.setdefault((index.path, caller), []).append(qualname)
    return Project(
        root=root,
        roots=roots,
        indexes=indexes,
        by_path=by_path,
        by_module=indexes_by_module(indexes, roots),
        bindings=bindings,
        module_bindings=module_bindings,
        import_edges=import_edges,
        calls_by_caller=_calls_by_caller(indexes),
        methods_by_class={key: tuple(found) for key, found in methods.items()},
        visitors={key: tuple(found) for key, found in visitors.items()},
        classes=tuple(classes),
        bases=bases,
        function_callers=function_callers,
        value_uses={key: tuple(found) for key, found in value_uses.items()},
        dead_spans={index.path: index.unreachable for index in indexes},
    )


def call_is_dead(project: Project, path: str, line: int, col_offset: int) -> bool:
    return point_in_spans(project.dead_spans.get(path, ()), line, col_offset)


def _calls_by_caller(indexes: list[FileIndex]) -> dict[tuple[str, str], tuple[CallEdge, ...]]:
    grouped: dict[tuple[str, str], list[CallEdge]] = {}
    for index in indexes:
        for call in index.calls:
            grouped.setdefault((index.path, call.caller), []).append(call)
    return {key: tuple(found) for key, found in grouped.items()}
