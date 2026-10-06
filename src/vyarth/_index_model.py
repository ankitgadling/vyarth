"""Private scope records for one file's indexer."""

from __future__ import annotations

from vyarth.model import Binding, ScopeInfo


class _Scope:
    def __init__(self, scope_id: str, kind: str, name: str, parent: _Scope | None) -> None:
        self.id = scope_id
        self.kind = kind
        self.name = name
        self.parent = parent
        self.bindings: dict[str, _Binding] = {}
        self.global_names: set[str] = set()
        self.nonlocal_names: set[str] = set()
        self.children: list[_Scope] = []

class _Binding:
    def __init__(
        self,
        name: str,
        qualname: str,
        kind: str,
        line: int,
        column: int,
        scope: _Scope,
    ) -> None:
        self.name = name
        self.qualname = qualname
        self.kind = kind
        self.line = line
        self.column = column
        self.scope = scope
        self.read_count = 0

    def freeze(self) -> Binding:
        return Binding(
            name=self.name,
            qualname=self.qualname,
            kind=self.kind,
            line=self.line,
            column=self.column,
            scope_id=self.scope.id,
            scope_kind=self.scope.kind,
            read_count=self.read_count,
        )

class _Load:
    def __init__(
        self,
        scope: _Scope,
        name: str,
        class_bound: bool = True,
        line: int = 0,
        col: int = 0,
        suppressed: bool = False,
    ) -> None:
        self.scope = scope
        self.name = name
        # False when a class-body load ran before this name was stored on the class.
        self.class_bound = class_bound
        self.line = line
        self.col = col
        self.suppressed = suppressed

class _RawCall:
    def __init__(
        self,
        caller: str,
        scope: _Scope,
        line: int,
        mode: str,
        name: str,
        owner: str,
        class_bound: bool = True,
        col: int = 0,
    ) -> None:
        self.caller = caller
        self.scope = scope
        self.line = line
        self.mode = mode
        self.name = name
        self.owner = owner
        self.class_bound = class_bound
        self.col = col

class _ContainerOp:
    def __init__(
        self,
        caller: str,
        scope: _Scope,
        name: str,
        elements: tuple[str, ...],
        mode: str,
        line: int,
        index: int,
    ) -> None:
        self.caller = caller
        self.scope = scope
        self.name = name
        self.elements = elements
        self.mode = mode
        self.line = line
        self.index = index

class _InstanceBind:
    def __init__(self, scope: _Scope, name: str, class_name: str) -> None:
        self.scope = scope
        self.name = name
        self.class_name = class_name

def _resolve(scope: _Scope, name: str, module: _Scope, *, class_bound: bool = True) -> _Binding | None:
    current: _Scope | None = scope
    while current is not None:
        if name in current.global_names and current.kind != "module":
            return module.bindings.get(name)
        if name in current.nonlocal_names:
            owner = _nonlocal_owner(current)
            return owner.bindings.get(name)
        # The class namespace is not a closure. A load in the class body itself
        # sees a class attribute only after an earlier statement stored that name.
        if current.kind == "class" and (current is not scope or not class_bound):
            current = current.parent
            continue
        found = current.bindings.get(name)
        if found is not None:
            return found
        current = current.parent
    return None

def _nonlocal_owner(scope: _Scope) -> _Scope:
    current = scope.parent
    while current is not None:
        if current.kind == "class" or current.kind == "comprehension":
            current = current.parent
            continue
        return current
    return scope

def _assignment_scope(scope: _Scope) -> _Scope:
    current = scope
    while current.kind == "comprehension" and current.parent is not None:
        current = current.parent
    return current

def _scope_qualname(scope: _Scope | None) -> str:
    if scope is None or scope.kind == "module":
        return "<module>"
    parts: list[str] = []
    current: _Scope | None = scope
    while current is not None and current.kind != "module":
        if current.name:
            parts.append(current.name)
        current = current.parent
    parts.reverse()
    return ".".join(parts) if parts else "<module>"

def _runtime_caller(scope: _Scope) -> str:
    """Scope that actually runs a decorator. Class bodies run in their enclosing scope."""
    current: _Scope | None = scope
    while current is not None and current.kind in {"comprehension", "class"}:
        current = current.parent
    return _scope_qualname(current)

def _caller_name(scope: _Scope) -> str:
    current: _Scope | None = scope
    while current is not None and current.kind == "comprehension":
        current = current.parent
    return _scope_qualname(current)

def _inside_lambda(scope: _Scope) -> bool:
    current: _Scope | None = scope
    while current is not None:
        if current.kind == "lambda":
            return True
        current = current.parent
    return False

def _enclosing_class(scope: _Scope) -> _Scope | None:
    current: _Scope | None = scope
    while current is not None:
        if current.kind == "class":
            return current
        current = current.parent
    return None

def _qualname(scope: _Scope, name: str) -> str:
    parts: list[str] = []
    current: _Scope | None = scope
    while current is not None and current.kind != "module":
        if current.name:
            parts.append(current.name)
        current = current.parent
    parts.reverse()
    parts.append(name)
    return ".".join(parts)

def _freeze_bindings(scope: _Scope) -> list[Binding]:
    found: list[Binding] = []

    def walk(current: _Scope) -> None:
        for binding in current.bindings.values():
            found.append(binding.freeze())
        for child in current.children:
            walk(child)

    walk(scope)
    return found

def _freeze_scopes(scope: _Scope) -> list[ScopeInfo]:
    found: list[ScopeInfo] = []

    def walk(current: _Scope) -> None:
        parent_id = None if current.parent is None else current.parent.id
        found.append(ScopeInfo(id=current.id, kind=current.kind, name=current.name, parent_id=parent_id))
        for child in current.children:
            walk(child)

    walk(scope)
    return found
