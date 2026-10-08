"""Turn aliases, attribute chains, self stores, and return annotations into call edges."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from vyarth.discover import import_target
from vyarth.model import Binding, CallEdge, ContainerStore, FileIndex, FlowBind, point_in_spans
from vyarth.project import Project, call_is_dead


def apply_flow(project: Project) -> list[FileIndex]:
    """Copy indexes, appending call edges that name and direct-call resolution missed."""
    updated: list[FileIndex] = []
    for index in project.indexes:
        extra = [
            edge
            for call in index.calls
            if not call_is_dead(project, index.path, call.line, call.col_offset)
            for edge in _edges_for_call(project, index, call)
        ]
        if not extra:
            updated.append(index)
            continue
        updated.append(replace(index, calls=index.calls + tuple(extra)))
    return updated


def _edges_for_call(project: Project, index: FileIndex, call: CallEdge) -> list[CallEdge]:
    binding_map = project.bindings.get(index.path, {})
    edges: list[CallEdge] = []
    if call.kind == "name" and call.resolved and call.callee:
        binding = binding_map.get(call.callee)
        if binding is not None and binding.kind == "variable":
            for target in _alias_targets(index, call.caller, binding.name, binding_map, call.line):
                if target:
                    edges.append(_edge(call, target))
    if call.callee_name and (call.kind == "method" or call.callee.startswith("@recv:")):
        source = _self_store(index, call.caller, call.callee_name)
        if source and not source.startswith("@return:"):
            target = _alias_target(index, call.caller, source, binding_map)
            if target:
                edges.append(_edge(call, target))
    if call.callee.startswith("@chain:"):
        target = _chain_target(project, index, call.callee[len("@chain:") :], call.callee_name)
        if target:
            edges.append(_edge(call, target))
    if call.callee.startswith("@call:"):
        owner = call.callee[len("@call:") :]
        target = _annotated_method(
            project,
            index,
            owner,
            call.callee_name,
            call.caller,
            binding_map,
        )
        if not target:
            target = _constructor_method(binding_map, owner, call.callee_name)
        if target:
            edges.append(_edge(call, target))
    if call.callee.startswith("@recv:"):
        for bind in _binds_reaching(index, call.caller, call.callee[len("@recv:") :], call.line):
            if bind.source.startswith("@lambda:"):
                edges.append(_edge(call, bind.source))
                continue
            if not bind.source.startswith("@return:"):
                continue
            target = _annotated_method(
                project,
                index,
                bind.source[len("@return:") :],
                call.callee_name,
                call.caller,
                binding_map,
            )
            if target:
                edges.append(_edge(call, target))
    if call.callee.startswith("@box:"):
        name = call.callee[len("@box:") :]
        elements = container_elements(index, call.caller, name, call.line)
        for qualname in pick_elements(elements, call.callee_name):
            edges.append(_edge(call, qualname))
    if call.resolved and call.callee.startswith("@import:"):
        target = _submodule_attribute(project, index, call.callee, binding_map)
        if target:
            edges.append(_edge(call, target))
    return edges


def container_elements(index: FileIndex, caller: str, name: str, line: int) -> list[str]:
    """Ordered function qualnames in `name` after stores at or before `line`."""
    items: list[str] | None = None
    for store in index.container_stores:
        if store.caller != caller or store.name != name or store.line > line:
            continue
        items = _apply_store(items, store)
    return items or []


def container_targets(index: FileIndex, caller: str, dead: tuple | list) -> dict[str, set[str]] | None:
    """Functions a reached container call can hit. None when this caller never calls one."""
    selected: dict[str, set[str]] = {}
    saw = False
    for call in index.calls:
        if call.caller != caller or not call.callee.startswith("@box:"):
            continue
        if point_in_spans(dead, call.line, call.col_offset):
            continue
        saw = True
        name = call.callee[len("@box:") :]
        chosen = pick_elements(container_elements(index, caller, name, call.line), call.callee_name)
        selected.setdefault(name, set()).update(chosen)
    if not saw:
        return None
    return selected


def held_elements(index: FileIndex, caller: str) -> dict[str, set[str]]:
    """Qualname to the container names in `caller` that store it."""
    held: dict[str, set[str]] = {}
    for store in index.container_stores:
        if store.caller != caller:
            continue
        for element in store.elements:
            if element:
                held.setdefault(element, set()).add(store.name)
    return held


def pick_elements(elements: list[str], selector: str) -> list[str]:
    if selector == "*":
        return [item for item in elements if item]
    try:
        index = int(selector)
    except ValueError:
        return [item for item in elements if item]
    if index < 0:
        index += len(elements)
    if index < 0 or index >= len(elements):
        return []
    element = elements[index]
    return [element] if element else []


def _apply_store(items: list[str] | None, store: ContainerStore) -> list[str]:
    if store.mode == "replace":
        return list(store.elements)
    if items is None:
        items = []
    if store.mode == "insert":
        position = store.index
        if position < 0:
            position = max(len(items) + position, 0)
        else:
            position = min(position, len(items))
        for offset, element in enumerate(store.elements):
            items.insert(position + offset, element)
        return items
    items.extend(store.elements)
    return items


def _edge(call: CallEdge, callee: str) -> CallEdge:
    return CallEdge(
        caller=call.caller,
        callee=callee,
        callee_name=call.callee_name or callee.rsplit(".", 1)[-1],
        kind="name",
        resolved=True,
        line=call.line,
        col_offset=call.col_offset,
    )


def _alias_targets(
    index: FileIndex,
    caller: str,
    name: str,
    binding_map: dict[str, Binding],
    line: int,
) -> list[str]:
    binds = _binds_reaching(index, caller, name, line)
    if not binds:
        target = _binding_target(binding_map, caller, name)
        return [target] if target else []
    found: list[str] = []
    for bind in binds:
        if bind.source.startswith("@lambda:"):
            target = bind.source
        elif bind.source.startswith("@return:") or bind.source.startswith("@box:"):
            target = ""
        else:
            target = _alias_target(index, caller, bind.source, binding_map, line)
        if target and target not in found:
            found.append(target)
    return found


def _alias_target(index: FileIndex, caller: str, name: str, binding_map: dict[str, Binding], line: int = 10**9) -> str:
    seen: set[str] = set()
    current = name
    while current not in seen:
        seen.add(current)
        bind = _bind_for(index, caller, current, line)
        if bind is None or bind.source.startswith(("@return:", "@box:", "@lambda:")):
            if bind is not None and bind.source.startswith("@lambda:"):
                return bind.source
            break
        current = bind.source
    return _binding_target(binding_map, caller, current)


def _binding_target(binding_map: dict[str, Binding], caller: str, name: str) -> str:
    qualnames = [name]
    if caller and caller != "<module>":
        qualnames.append(f"{caller}.{name}")
    for qualname in qualnames:
        binding = binding_map.get(qualname)
        if binding is None:
            continue
        if binding.kind == "import":
            return f"@import:{binding.qualname}"
        if binding.kind in {"function", "class"}:
            return binding.qualname
    return ""


def _bind_for(index: FileIndex, caller: str, target: str, line: int = 10**9) -> FlowBind | None:
    """Last store at or before `line`. A later store in the same caller does not apply."""
    found = _binds_reaching(index, caller, target, line)
    if found:
        return found[-1]
    return None


def _binds_reaching(index: FileIndex, caller: str, target: str, line: int) -> list[FlowBind]:
    """Stores that can still hold `target` when execution reaches `line`."""
    prior = [bind for bind in index.flow_binds if bind.target == target and bind.caller == caller and bind.line <= line]
    if not prior:
        prior = [
            bind
            for bind in index.flow_binds
            if bind.target == target and bind.caller == "<module>" and bind.line <= line
        ]
    if not prior:
        return []
    last = max(prior, key=lambda bind: bind.line)
    if not last.branch:
        return [last]
    parent, if_id, side = _split_branch(last.branch)
    if not if_id or not side:
        return [last]
    by_side: dict[str, FlowBind] = {}
    for bind in prior:
        bind_parent, bind_if, bind_side = _split_branch(bind.branch)
        if bind_parent == parent and bind_if == if_id and bind_side:
            current = by_side.get(bind_side)
            if current is None or bind.line >= current.line:
                by_side[bind_side] = bind
    if "body" in by_side and "else" in by_side:
        return [by_side["body"], by_side["else"]]
    return [last]


def _split_branch(branch: str) -> tuple[str, str, str]:
    parent, _, leaf = branch.rpartition("/")
    if_id, separator, side = leaf.rpartition(":")
    if not separator:
        return parent, "", ""
    return parent, if_id, side


def _self_store(index: FileIndex, caller: str, attr: str) -> str:
    class_name = caller.rsplit(".", 1)[0] if "." in caller else ""
    found = ""
    for bind in index.flow_binds:
        if bind.target not in {f"self.{attr}", f"cls.{attr}"}:
            continue
        same_method = bind.caller == caller
        same_class = bool(class_name) and (bind.caller == class_name or bind.caller.startswith(f"{class_name}."))
        if same_method or same_class:
            found = bind.source
    return found


def _constructor_method(binding_map: dict[str, Binding], function_name: str, method: str) -> str:
    """`Widget().run()` reaches `Widget.run` without a return annotation."""
    if not method:
        return ""
    binding = binding_map.get(function_name)
    if binding is None:
        return ""
    if binding.kind == "class":
        qualname = f"{binding.qualname}.{method}"
        if qualname in binding_map:
            return qualname
        return ""
    if binding.kind == "import":
        return f"@import:{binding.qualname}.{method}"
    return ""


def _annotated_method(
    project: Project,
    index: FileIndex,
    function_name: str,
    method: str,
    caller: str,
    binding_map: dict[str, Binding],
) -> str:
    qualnames = [function_name]
    if caller and caller != "<module>":
        qualnames.append(f"{caller}.{function_name}")
    note = next((item for item in index.returns if item.qualname in qualnames), None)
    if note is None:
        note = next((item for item in index.returns if item.qualname == function_name), None)
    if note is None:
        return ""
    class_name = _resolve_annotation(project, index, note.annotation, caller, binding_map)
    if not class_name:
        return ""
    return f"{class_name}.{method}"


def _resolve_annotation(
    project: Project,
    index: FileIndex,
    annotation: str,
    caller: str,
    binding_map: dict[str, Binding],
) -> str:
    if "." not in annotation:
        class_name = _binding_target(binding_map, caller, annotation)
        if not class_name:
            class_name = _binding_target(binding_map, "<module>", annotation)
        return class_name
    module_name, _, attr = annotation.rpartition(".")
    module = _module_named(project, index, module_name)
    binding = _module_function(project, module, attr)
    if module is not None and binding is not None and binding.kind == "class":
        return _xref(module.path, binding.qualname)
    return ""


def _chain_target(project: Project, index: FileIndex, owner: str, attr: str) -> str:
    module = _module_named(project, index, owner)
    if module is None:
        return ""
    binding = _module_function(project, module, attr)
    if binding is None:
        return ""
    return _xref(module.path, binding.qualname)


def _submodule_attribute(
    project: Project,
    index: FileIndex,
    callee: str,
    binding_map: dict[str, Binding],
) -> str:
    rest = callee[len("@import:") :]
    import_qual, separator, method = rest.rpartition(".")
    if not separator or not method:
        return ""
    binding = binding_map.get(import_qual)
    if binding is None or binding.kind != "import":
        return ""
    edge = project.edge_for(index.path, binding.name, binding.line)
    if edge is None or edge.is_wildcard or edge.imported_name == "*":
        return ""
    if not edge.imported_name:
        if not edge.module:
            return ""
        module = import_target(edge.module, edge.level, Path(index.path), project.roots)
        if not module:
            return ""
        parent = project.by_module.get(module)
        target = _module_function(project, parent, method)
        if parent is None or target is None:
            return ""
        return _xref(parent.path, target.qualname)
    module = import_target(edge.module, edge.level, Path(index.path), project.roots)
    if not module:
        return ""
    parent = project.by_module.get(module)
    symbol = _module_function(project, parent, edge.imported_name) if parent is not None else None
    if symbol is not None and symbol.kind in {"class", "function"}:
        return ""
    child = project.by_module.get(f"{module}.{edge.imported_name}")
    target = _module_function(project, child, method)
    if child is None or target is None:
        return ""
    return _xref(child.path, target.qualname)


def _module_named(project: Project, index: FileIndex, owner: str) -> FileIndex | None:
    root_name = owner.split(".", 1)[0]
    for edge in index.imports:
        if edge.is_wildcard or edge.alias != root_name:
            continue
        if edge.imported_name:
            module = import_target(edge.module, edge.level, Path(index.path), project.roots)
            if module is None:
                continue
            if owner == edge.alias:
                return project.by_module.get(f"{module}.{edge.imported_name}")
            continue
        if edge.module and (owner == edge.module or owner.startswith(f"{edge.module}.")):
            return project.by_module.get(owner if owner.startswith(edge.module) else edge.module)
        if edge.module == root_name and owner.startswith(f"{root_name}."):
            return project.by_module.get(owner)
    return project.by_module.get(owner)


def _module_function(project: Project, index: FileIndex | None, name: str) -> Binding | None:
    if index is None:
        return None
    return project.module_binding(index.path, name)


def _xref(path: str, qualname: str) -> str:
    return f"@xref:{path}\x1f{qualname}"
