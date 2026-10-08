"""Indexes shared by one scan. Built once so later passes do not rebuild them."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from pathlib import Path

from vyarth.discover import import_target, indexes_by_module, module_names, package_roots
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
    module_names_by_path: dict[str, tuple[str, ...]]
    package_parts_by_path: dict[str, tuple[str, ...] | None]
    follow_cache: dict[tuple[str, str], tuple[str, str]] = field(default_factory=dict)
    mentions: set[tuple[str, str]] | None = None

    def resolve_import(self, module: str | None, level: int, importer: str) -> str | None:
        """Module an import loads. Relative imports use the importer's package parts."""
        if level <= 0:
            return module or ""
        if importer not in self.package_parts_by_path:
            return import_target(module, level, Path(importer), self.roots)
        package = self.package_parts_by_path[importer]
        if package is None:
            return None
        drop = level - 1
        if drop > len(package):
            return None
        parts = list(package[: len(package) - drop] if drop else package)
        if module:
            parts.extend(part for part in module.split(".") if part)
        return ".".join(parts)

    def modules_used_by(self, module: str | None, level: int, imported: str | None, importer: str) -> set[str]:
        target = self.resolve_import(module, level, importer)
        if target is None:
            return set()
        names: set[str] = set()
        if target:
            segments = target.split(".")
            for index in range(1, len(segments) + 1):
                names.add(".".join(segments[:index]))
        if imported and imported != "*":
            child = f"{target}.{imported}" if target else imported
            names.add(child)
        return names

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
    module_names_by_path, package_parts_by_path = _module_maps(indexes, roots)
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
        module_names_by_path=module_names_by_path,
        package_parts_by_path=package_parts_by_path,
    )


def call_is_dead(project: Project, path: str, line: int, col_offset: int) -> bool:
    return point_in_spans(project.dead_spans.get(path, ()), line, col_offset)


def _module_maps(
    indexes: list[FileIndex],
    roots: list[Path],
) -> tuple[dict[str, tuple[str, ...]], dict[str, tuple[str, ...] | None]]:
    names_by_path: dict[str, tuple[str, ...]] = {}
    packages: dict[str, tuple[str, ...] | None] = {}
    for index in indexes:
        path = Path(index.path)
        names = tuple(module_names(path, roots))
        names_by_path[index.path] = names
        if not names:
            packages[index.path] = None
            continue
        parts = names[0].split(".")
        if path.name != "__init__.py":
            parts = parts[:-1]
        packages[index.path] = tuple(parts)
    return names_by_path, packages


def _calls_by_caller(indexes: list[FileIndex]) -> dict[tuple[str, str], tuple[CallEdge, ...]]:
    grouped: dict[tuple[str, str], list[CallEdge]] = {}
    for index in indexes:
        for call in index.calls:
            grouped.setdefault((index.path, call.caller), []).append(call)
    return {key: tuple(found) for key, found in grouped.items()}
