"""Scope-aware Python indexer and unreachable-statement walk."""

from __future__ import annotations

import ast
import contextvars
import hashlib
import re

from vyarth.ignore import collect_ignores, expand_decorator_ignores
from vyarth.model import (
    Binding,
    BodyHash,
    CallEdge,
    ContainerStore,
    Decorator,
    DynamicMarker,
    FileIndex,
    FlowBind,
    ImportEdge,
    ReturnNote,
    ScopeInfo,
    UnreachableSpan,
    point_in_spans,
)


_UNREACHABLE_MESSAGE = "Control flow terminates before this statement."
_FOLD: contextvars.ContextVar[dict[str, str]] = contextvars.ContextVar("vyarth_fold", default={})
_DYNAMIC_NAMES = {"getattr", "setattr", "globals", "locals", "eval", "exec", "__import__"}
_DYNAMIC_IMPORT_ATTRS = {"import_module", "__import__"}
_DYNAMIC_NAME = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")


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


class _Indexer(ast.NodeVisitor):
    def __init__(
        self,
        path: str,
        source: str,
        fold: dict[str, str] | None = None,
        duplicate_min_statements: int = 5,
    ) -> None:
        self.path = path
        self.source = source
        self.module = _Scope("module", "module", "", None)
        self.scope = self.module
        self.loads: list[_Load] = []
        self.imports: list[ImportEdge] = []
        self.has_main_guard = False
        self.exports: set[str] = set()
        self.value_loads: list[_Load] = []
        self.raw_calls: list[_RawCall] = []
        self.raw_attrs: list[_RawCall] = []
        self.instances: list[_InstanceBind] = []
        self.decorators: list[Decorator] = []
        self.dynamic_markers: list[DynamicMarker] = []
        self.abstract: set[str] = set()
        self.flow_binds: list[FlowBind] = []
        self.returns: list[ReturnNote] = []
        self.body_hashes: list[BodyHash] = []
        self.dynamic_imports: list[str] = []
        self.pending_bases: list[tuple[str, _Scope, tuple[str, ...]]] = []
        self.unbound: set[str] = set()
        self.container_ops: list[_ContainerOp] = []
        self._container_depth = 0
        self._suppress = 0
        self._branches: list[str] = []
        self._pending_lambdas: dict[int, str] = {}
        self._lambda_qualnames: dict[int, str] = {}
        self._dead_spans: tuple[UnreachableSpan, ...] = ()
        self.fold = fold or {}
        self.duplicate_min = duplicate_min_statements
        self._counter = 0

    def index(self) -> FileIndex:
        tree = ast.parse(self.source, filename=self.path)
        token = _FOLD.set(self.fold)
        try:
            self.visit(tree)
            unreachable = tuple(_unreachable_spans(tree, self.source))
            self._dead_spans = unreachable
            self._resolve_loads()
            value_uses = tuple(self._value_uses())
        finally:
            _FOLD.reset(token)
        ignores = expand_decorator_ignores(tree, collect_ignores(self.source))
        return FileIndex(
            path=self.path,
            bindings=tuple(_freeze_bindings(self.module)),
            scopes=tuple(_freeze_scopes(self.module)),
            imports=tuple(self.imports),
            unreachable=unreachable,
            has_main_guard=self.has_main_guard,
            ignores=ignores,
            exports=tuple(sorted(self.exports)),
            calls=tuple(self._resolve_calls()),
            decorators=tuple(self.decorators),
            dynamic_markers=tuple(self.dynamic_markers),
            value_references=tuple(sorted({qualname for _, qualname in value_uses})),
            abstract=tuple(sorted(self.abstract)),
            flow_binds=tuple(self.flow_binds),
            returns=tuple(self.returns),
            body_hashes=tuple(self.body_hashes),
            value_uses=value_uses,
            class_bases=self._class_bases(),
            unbound_names=tuple(sorted(self.unbound)),
            dynamic_imports=tuple(dict.fromkeys(self.dynamic_imports)),
            container_stores=tuple(self._container_stores()),
        )

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        qualname = _qualname(self.scope, node.name)
        self._record_decorators(qualname, node.decorator_list)
        base_names = tuple(name for base in node.bases if (name := _dotted_name(base)))
        if base_names:
            self.pending_bases.append((qualname, self.scope, base_names))
        for decorator in node.decorator_list:
            self.visit(decorator)
        for base in node.bases:
            self.visit(base)
        for keyword in node.keywords:
            self.visit(keyword.value)
        self._visit_type_params(node)
        self._bind(node.name, "class", node.lineno, node.col_offset)
        self._push("class", node.name)
        for statement in node.body:
            self.visit(statement)
        self._pop()

    def visit_Lambda(self, node: ast.Lambda) -> None:
        self._visit_signature(node.args, None)
        name = self._pending_lambdas.pop(id(node), None)
        if name is None:
            name = self._fresh("lambda")
        self._lambda_qualnames[id(node)] = _qualname(self.scope, name)
        self._push("lambda", name)
        self._bind_arguments(node.args)
        self.visit(node.body)
        self._pop()

    def visit_ListComp(self, node: ast.ListComp) -> None:
        self._visit_comprehension(node.generators, lambda: self.visit(node.elt))

    def visit_SetComp(self, node: ast.SetComp) -> None:
        self._visit_comprehension(node.generators, lambda: self.visit(node.elt))

    def visit_GeneratorExp(self, node: ast.GeneratorExp) -> None:
        self._visit_comprehension(node.generators, lambda: self.visit(node.elt))

    def visit_DictComp(self, node: ast.DictComp) -> None:
        self._visit_comprehension(
            node.generators,
            lambda: (self.visit(node.key), self.visit(node.value)),
        )

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        self.visit(node.value)
        target = _assignment_scope(self.scope)
        previous = self.scope
        self.scope = target
        self.visit(node.target)
        self.scope = previous

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            local = alias.asname or alias.name.split(".")[0]
            line, column = _alias_position(alias, node)
            self._bind(local, "import", line, column)
            self.imports.append(
                ImportEdge(
                    line=line,
                    column=column,
                    module=alias.name,
                    level=0,
                    imported_name=None,
                    alias=local,
                    is_wildcard=False,
                )
            )

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for alias in node.names:
            line, column = _alias_position(alias, node)
            if alias.name == "*":
                self.imports.append(
                    ImportEdge(
                        line=line,
                        column=column,
                        module=node.module,
                        level=node.level or 0,
                        imported_name="*",
                        alias=None,
                        is_wildcard=True,
                    )
                )
                continue
            local = alias.asname or alias.name
            binding = self._bind(local, "import", line, column)
            if node.module == "__future__":
                binding.read_count += 1
            self.imports.append(
                ImportEdge(
                    line=line,
                    column=column,
                    module=node.module,
                    level=node.level or 0,
                    imported_name=alias.name,
                    alias=local,
                    is_wildcard=False,
                )
            )

    def visit_Global(self, node: ast.Global) -> None:
        self.scope.global_names.update(node.names)

    def visit_Nonlocal(self, node: ast.Nonlocal) -> None:
        self.scope.nonlocal_names.update(node.names)

    def visit_If(self, node: ast.If) -> None:
        if self.scope.kind == "module" and _is_main_guard(node.test):
            self.has_main_guard = True
        self.visit(node.test)
        self._branches.append(f"if:{node.lineno}:body")
        for statement in node.body:
            self.visit(statement)
        self._branches.pop()
        self._branches.append(f"if:{node.lineno}:else")
        for statement in node.orelse:
            self.visit(statement)
        self._branches.pop()

    def visit_BoolOp(self, node: ast.BoolOp) -> None:
        seen_stop = False
        for value in node.values:
            if seen_stop:
                self._suppress += 1
                try:
                    self.visit(value)
                finally:
                    self._suppress -= 1
                continue
            self.visit(value)
            truth = _const_bool(value)
            if isinstance(node.op, ast.And) and truth is False:
                seen_stop = True
            elif isinstance(node.op, ast.Or) and truth is True:
                seen_stop = True

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            self._note_exports(target, node.value)
            self._note_instance(target, node.value)
            self._note_flow(target, node.value)
        slots = _sequence_slots(node.value)
        if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) and slots is not None:
            self._visit_container(node.value)
            self.visit(node.targets[0])
            self._remember_container(node.targets[0].id, slots, "replace", node.lineno, -1)
            return
        # The value runs before the name is stored, including `version = version`.
        self.visit(node.value)
        for target in node.targets:
            self.visit(target)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        if isinstance(node.op, ast.Add):
            self._note_exports(node.target, node.value)
        slots = _sequence_slots(node.value) if isinstance(node.op, ast.Add) else None
        if isinstance(node.target, ast.Name) and slots is not None:
            self._add_load(node.target.id, node.target.lineno, node.target.col_offset)
            self._visit_container(node.value)
            self.visit(node.target)
            self._remember_container(node.target.id, slots, "append", node.lineno, -1)
            return
        if isinstance(node.target, ast.Name):
            self._add_load(node.target.id, node.target.lineno, node.target.col_offset)
        self.visit(node.value)
        self.visit(node.target)

    def visit_For(self, node: ast.For) -> None:
        self._note_loop(node)
        self._visit_loop(node)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        self._note_loop(node)
        self._visit_loop(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.annotation is not None:
            self.visit(node.annotation)
        if node.value is not None:
            self._note_exports(node.target, node.value)
            self._note_instance(node.target, node.value)
            self._note_flow(node.target, node.value)
            self.visit(node.value)
            self.visit(node.target)

    def _note_exports(self, target: ast.expr, value: ast.expr) -> None:
        if self.scope.kind != "module":
            return
        if isinstance(target, ast.Name) and target.id == "__all__":
            self.exports.update(_export_names(value))

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.type is not None:
            self.visit(node.type)
        if node.name:
            self._bind(node.name, "variable", node.lineno, node.col_offset)
        for statement in node.body:
            self.visit(statement)

    def visit_Match(self, node: ast.Match) -> None:
        self.visit(node.subject)
        for case in node.cases:
            self._bind_pattern(case.pattern)
            if case.guard is not None:
                self.visit(case.guard)
            for statement in case.body:
                self.visit(statement)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if self._suppress:
            self.visit(node.value)
            return
        if isinstance(node.ctx, ast.Load):
            if isinstance(node.value, ast.Name):
                mode = "self" if node.value.id in {"self", "cls"} else "nameattr"
                self.raw_attrs.append(_RawCall("", self.scope, node.lineno, mode, node.attr, node.value.id))
            elif isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name):
                self.raw_attrs.append(
                    _RawCall("", self.scope, node.lineno, "constructed", node.attr, node.value.func.id)
                )
        self.visit(node.value)

    def visit_Call(self, node: ast.Call) -> None:
        if self._suppress == 0:
            self._note_dynamic(node)
            self._note_all_mutation(node)
        mutation = _container_mutation(node)
        self._note_call(node)
        if mutation is not None:
            name, slots, mode, index, parts = mutation
            self._visit_container_parts(parts)
            for argument in node.args:
                if argument not in parts:
                    self.visit(argument)
            for keyword in node.keywords:
                if keyword.value is not None:
                    self.visit(keyword.value)
            self._remember_container(name, slots, mode, node.lineno, index)
            return
        for argument in node.args:
            self.visit(argument)
        for keyword in node.keywords:
            if keyword.value is not None:
                self.visit(keyword.value)

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, ast.Load):
            self._add_load(node.id, node.lineno, node.col_offset, value=True)
        elif isinstance(node.ctx, ast.Store):
            self._bind(node.id, "variable", node.lineno, node.col_offset)

    def _class_bound(self, name: str) -> bool:
        """True when this class-body load can already see `name` on the class."""
        return self.scope.kind != "class" or name in self.scope.bindings

    def _make_load(self, name: str, line: int = 0, col: int = 0) -> _Load:
        return _Load(self.scope, name, self._class_bound(name), line, col, self._suppress > 0)

    def _add_load(self, name: str, line: int, col: int, value: bool = False) -> None:
        site = self._make_load(name, line, col)
        if site.suppressed:
            return
        self.loads.append(site)
        if value and self._container_depth == 0:
            self.value_loads.append(site)

    def _push_raw(self, raw: _RawCall) -> None:
        if self._suppress:
            return
        self.raw_calls.append(raw)

    def _branch_label(self) -> str:
        return "/".join(self._branches)

    def _in_dead(self, line: int, col: int) -> bool:
        if line <= 0:
            return False
        return point_in_spans(self._dead_spans, line, col)

    def _visit_loop(self, node: ast.For | ast.AsyncFor) -> None:
        self.visit(node.iter)
        self.visit(node.target)
        for statement in node.body:
            self.visit(statement)
        for statement in node.orelse:
            self.visit(statement)

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        qualname = _qualname(self.scope, node.name)
        if _is_abstract_function(node):
            self.abstract.add(qualname)
        annotation = _return_annotation(node.returns) if node.returns is not None else ""
        if annotation:
            self.returns.append(ReturnNote(qualname=qualname, annotation=annotation, line=node.lineno))
        digest, count = _body_signature(node, self.duplicate_min)
        self.body_hashes.append(
            BodyHash(qualname=qualname, name=node.name, digest=digest, statements=count, line=node.lineno)
        )
        self._record_decorators(qualname, node.decorator_list)
        for decorator in node.decorator_list:
            self.visit(decorator)
        self._visit_type_params(node)
        self._visit_signature(node.args, node.returns)
        self._bind(node.name, "function", node.lineno, node.col_offset)
        self._push("function", node.name)
        self._bind_arguments(node.args)
        for statement in node.body:
            self.visit(statement)
        self._pop()

    def _visit_signature(self, args: ast.arguments, returns: ast.expr | None) -> None:
        for arg in (*args.posonlyargs, *args.args, *args.kwonlyargs):
            if arg.annotation is not None:
                self.visit(arg.annotation)
        if args.vararg and args.vararg.annotation is not None:
            self.visit(args.vararg.annotation)
        if args.kwarg and args.kwarg.annotation is not None:
            self.visit(args.kwarg.annotation)
        for default in args.defaults:
            self.visit(default)
        for default in args.kw_defaults:
            if default is not None:
                self.visit(default)
        if returns is not None:
            self.visit(returns)

    def _visit_type_params(self, node: ast.AST) -> None:
        for param in getattr(node, "type_params", ()):
            self.visit(param)

    def _bind_arguments(self, args: ast.arguments) -> None:
        for arg in (*args.posonlyargs, *args.args, *args.kwonlyargs):
            self._bind(arg.arg, "parameter", arg.lineno, arg.col_offset)
            if arg.annotation is not None:
                for class_name in _annotation_names(arg.annotation):
                    self.instances.append(_InstanceBind(self.scope, arg.arg, class_name))
        if args.vararg is not None:
            self._bind(args.vararg.arg, "parameter", args.vararg.lineno, args.vararg.col_offset)
        if args.kwarg is not None:
            self._bind(args.kwarg.arg, "parameter", args.kwarg.lineno, args.kwarg.col_offset)

    def _visit_comprehension(self, generators: list[ast.comprehension], visit_elements) -> None:
        if not generators:
            visit_elements()
            return
        # The first iterable is evaluated in the enclosing scope.
        self.visit(generators[0].iter)
        self._push("comprehension", self._fresh("comprehension"))
        self.visit(generators[0].target)
        for test in generators[0].ifs:
            self.visit(test)
        for generator in generators[1:]:
            self.visit(generator.iter)
            self.visit(generator.target)
            for test in generator.ifs:
                self.visit(test)
        visit_elements()
        self._pop()

    def _bind_pattern(self, pattern: ast.pattern) -> None:
        if isinstance(pattern, ast.MatchAs):
            if pattern.pattern is not None:
                self._bind_pattern(pattern.pattern)
            if pattern.name:
                self._bind(pattern.name, "variable", pattern.lineno, pattern.col_offset)
        elif isinstance(pattern, ast.MatchOr):
            for child in pattern.patterns:
                self._bind_pattern(child)
        elif isinstance(pattern, ast.MatchValue):
            self.visit(pattern.value)
        elif isinstance(pattern, ast.MatchSequence):
            for child in pattern.patterns:
                self._bind_pattern(child)
        elif isinstance(pattern, ast.MatchStar):
            if pattern.name:
                self._bind(pattern.name, "variable", pattern.lineno, pattern.col_offset)
        elif isinstance(pattern, ast.MatchMapping):
            for key in pattern.keys:
                self.visit(key)
            for child in pattern.patterns:
                self._bind_pattern(child)
            if pattern.rest:
                self._bind(pattern.rest, "variable", pattern.lineno, pattern.col_offset)
        elif isinstance(pattern, ast.MatchClass):
            self.visit(pattern.cls)
            for child in pattern.patterns:
                self._bind_pattern(child)
            for child in pattern.kwd_patterns:
                self._bind_pattern(child)

    def _bind(self, name: str, kind: str, line: int, column: int) -> _Binding:
        scope = self._store_scope(name)
        existing = scope.bindings.get(name)
        if existing is not None:
            if existing.kind == "variable" and kind in {"function", "class", "import"}:
                existing.kind = kind
                existing.line = line
                existing.column = _column(column)
                existing.qualname = _qualname(scope, name)
            elif kind == "variable" and existing.kind in {"function", "class", "import"}:
                existing.kind = kind
                existing.line = line
                existing.column = _column(column)
                existing.qualname = _qualname(scope, name)
            return existing
        binding = _Binding(
            name=name,
            qualname=_qualname(scope, name),
            kind=kind,
            line=line,
            column=_column(column),
            scope=scope,
        )
        scope.bindings[name] = binding
        return binding

    def _store_scope(self, name: str) -> _Scope:
        if name in self.scope.global_names and self.scope.kind != "module":
            return self.module
        if name in self.scope.nonlocal_names:
            return _nonlocal_owner(self.scope)
        return self.scope

    def _push(self, kind: str, name: str) -> _Scope:
        self._counter += 1
        child = _Scope(f"{kind}:{self._counter}", kind, name, self.scope)
        self.scope.children.append(child)
        self.scope = child
        return child

    def _pop(self) -> None:
        if self.scope.parent is None:
            return
        self.scope = self.scope.parent

    def _fresh(self, prefix: str) -> str:
        self._counter += 1
        return f"<{prefix}:{self._counter}>"

    def _resolve_loads(self) -> None:
        wildcard = any(edge.is_wildcard for edge in self.imports)
        for site in self.loads:
            if site.suppressed or self._in_dead(site.line, site.col) or _inside_lambda(site.scope):
                continue
            binding = _resolve(site.scope, site.name, self.module, class_bound=site.class_bound)
            if binding is not None:
                binding.read_count += 1
            elif wildcard:
                self.unbound.add(site.name)

    def _value_uses(self) -> list[tuple[str, str]]:
        found: list[tuple[str, str]] = []
        seen: set[tuple[str, str]] = set()

        def add(scope: _Scope, qualname: str) -> None:
            item = (_caller_name(scope), qualname)
            if item in seen:
                return
            seen.add(item)
            found.append(item)

        for site in self.value_loads:
            if site.suppressed or self._in_dead(site.line, site.col):
                continue
            binding = _resolve(site.scope, site.name, self.module, class_bound=site.class_bound)
            if binding is not None:
                add(site.scope, binding.qualname)
        instances = self._resolved_instances()
        for raw in self.raw_attrs:
            class_qualname = self._class_for_owner(raw.scope, raw.owner, raw.mode, instances)
            if class_qualname:
                add(raw.scope, f"{class_qualname}.{raw.name}")
        return found

    def _class_bases(self) -> tuple[tuple[str, tuple[str, ...]], ...]:
        found: list[tuple[str, tuple[str, ...]]] = []
        for qualname, scope, names in self.pending_bases:
            resolved = tuple(item for name in names if (item := self._resolve_base_name(scope, name)))
            if resolved:
                found.append((qualname, resolved))
        return tuple(found)

    def _resolve_base_name(self, scope: _Scope, dotted: str) -> str:
        if "." not in dotted:
            binding = _resolve(scope, dotted, self.module)
            if binding is None:
                return ""
            if binding.kind == "class":
                return binding.qualname
            if binding.kind == "import":
                return f"@import:{binding.qualname}"
            return ""
        return f"@expr:{dotted}"

    def _resolve_calls(self) -> list[CallEdge]:
        instances = self._resolved_instances()
        edges: list[CallEdge] = []
        for raw in self.raw_calls:
            if raw.mode == "container":
                edges.append(
                    CallEdge(
                        caller=raw.caller,
                        callee=f"@box:{raw.owner}",
                        callee_name=raw.name,
                        kind="container",
                        resolved=False,
                        line=raw.line,
                        col_offset=raw.col,
                    )
                )
                continue
            if raw.mode == "lambda":
                edges.append(
                    CallEdge(
                        caller=raw.caller,
                        callee=f"@lambda:{raw.name}",
                        callee_name=raw.name.rsplit(".", 1)[-1],
                        kind="name",
                        resolved=True,
                        line=raw.line,
                        col_offset=raw.col,
                    )
                )
                continue
            if raw.mode == "super":
                callee = f"@super:{raw.owner}.{raw.name}" if raw.owner else ""
                edges.append(
                    CallEdge(
                        caller=raw.caller,
                        callee=callee,
                        callee_name=raw.name,
                        kind="method",
                        resolved=bool(callee),
                        line=raw.line,
                        col_offset=raw.col,
                    )
                )
                continue
            if raw.mode == "name":
                binding = _resolve(raw.scope, raw.name, self.module, class_bound=raw.class_bound)
                edges.append(
                    CallEdge(
                        caller=raw.caller,
                        callee=binding.qualname if binding is not None else "",
                        callee_name=raw.name,
                        kind="name",
                        resolved=binding is not None,
                        line=raw.line,
                        col_offset=raw.col,
                    )
                )
                continue
            class_qualname = self._class_for_owner(raw.scope, raw.owner, raw.mode, instances)
            if class_qualname:
                edges.append(
                    CallEdge(
                        caller=raw.caller,
                        callee=f"{class_qualname}.{raw.name}",
                        callee_name=raw.name,
                        kind="method",
                        resolved=True,
                        line=raw.line,
                        col_offset=raw.col,
                    )
                )
            else:
                if raw.mode == "chain" and raw.owner:
                    callee = f"@chain:{raw.owner}"
                elif raw.mode == "constructed" and raw.owner:
                    callee = f"@call:{raw.owner}"
                elif raw.owner:
                    callee = f"@recv:{raw.owner}"
                else:
                    callee = ""
                edges.append(
                    CallEdge(
                        caller=raw.caller,
                        callee=callee,
                        callee_name=raw.name,
                        kind="attribute",
                        resolved=False,
                        line=raw.line,
                        col_offset=raw.col,
                    )
                )
        return edges

    def _class_for_owner(
        self,
        scope: _Scope,
        owner: str,
        mode: str,
        instances: dict[tuple[int, str], str],
    ) -> str:
        if mode == "self":
            enclosing = _enclosing_class(scope)
            return _scope_qualname(enclosing) if enclosing is not None else ""
        if mode not in {"instance", "classattr", "constructed", "nameattr"}:
            return ""
        current: _Scope | None = scope
        while current is not None:
            found = instances.get((id(current), owner))
            if found:
                return found
            current = current.parent
        if mode in {"classattr", "constructed", "nameattr"}:
            binding = _resolve(scope, owner, self.module)
            if binding is not None and binding.kind == "class":
                return binding.qualname
            if binding is not None and binding.kind == "import":
                return f"@import:{binding.qualname}"
        return ""

    def _resolved_instances(self) -> dict[tuple[int, str], str]:
        resolved: dict[tuple[int, str], str] = {}
        for bind in self.instances:
            binding = _resolve(bind.scope, bind.class_name, self.module)
            if binding is None:
                continue
            key = (id(bind.scope), bind.name)
            if binding.kind == "class":
                resolved[key] = binding.qualname
            elif binding.kind == "import" and key not in resolved:
                resolved[key] = f"@import:{binding.qualname}"
        return resolved

    def _note_call(self, node: ast.Call) -> None:
        func = node.func
        caller = _caller_name(self.scope)
        if self._suppress:
            self.visit(func)
            return
        if isinstance(func, ast.Name):
            self._add_load(func.id, func.lineno, func.col_offset)
            self._push_raw(
                _RawCall(
                    caller,
                    self.scope,
                    node.lineno,
                    "name",
                    func.id,
                    "",
                    self._class_bound(func.id),
                    func.col_offset,
                )
            )
            return
        if isinstance(func, ast.Attribute):
            self._note_attribute_call(func, caller, node.lineno)
            return
        if isinstance(func, ast.Subscript):
            self._note_subscript_call(func, caller, node.lineno)
            return
        if isinstance(func, ast.Lambda):
            self.visit(func)
            qualname = self._lambda_qualnames.get(id(func), "")
            if qualname:
                self._push_raw(_RawCall(caller, self.scope, node.lineno, "lambda", qualname, "", True, node.col_offset))
            return
        self.visit(func)

    def _note_subscript_call(self, func: ast.Subscript, caller: str, line: int) -> None:
        self.visit(func)
        if not isinstance(func.value, ast.Name):
            return
        selector = "*"
        if isinstance(func.slice, ast.Constant) and isinstance(func.slice.value, int):
            selector = str(func.slice.value)
        self._push_raw(_RawCall(caller, self.scope, line, "container", selector, func.value.id, True, func.col_offset))

    def _note_loop(self, node: ast.For | ast.AsyncFor) -> None:
        if not isinstance(node.target, ast.Name) or not isinstance(node.iter, ast.Name):
            return
        caller = _caller_name(self.scope)
        self.flow_binds.append(
            FlowBind(
                caller=caller,
                target=node.target.id,
                source=f"@box:{node.iter.id}",
                line=node.lineno,
                branch=self._branch_label(),
            )
        )
        self._push_raw(_RawCall(caller, self.scope, node.lineno, "container", "*", node.iter.id, True, node.col_offset))

    def _visit_container(self, node: ast.AST) -> None:
        self._container_depth += 1
        try:
            self.visit(node)
        finally:
            self._container_depth -= 1

    def _visit_container_parts(self, parts: list[ast.expr]) -> None:
        self._container_depth += 1
        try:
            for part in parts:
                self.visit(part)
        finally:
            self._container_depth -= 1

    def _remember_container(self, name: str, elements: tuple[str, ...], mode: str, line: int, index: int) -> None:
        self.container_ops.append(
            _ContainerOp(_caller_name(self.scope), self.scope, name, elements, mode, line, index)
        )

    def _container_stores(self) -> list[ContainerStore]:
        found: list[ContainerStore] = []
        for op in self.container_ops:
            elements: list[str] = []
            for name in op.elements:
                if not name:
                    elements.append("")
                    continue
                binding = _resolve(op.scope, name, self.module)
                if binding is not None and binding.kind in {"function", "class", "import"}:
                    elements.append(binding.qualname)
                else:
                    elements.append("")
            found.append(
                ContainerStore(
                    caller=op.caller,
                    name=op.name,
                    elements=tuple(elements),
                    line=op.line,
                    mode=op.mode,
                    index=op.index,
                )
            )
        return found

    def _note_attribute_call(self, func: ast.Attribute, caller: str, line: int) -> None:
        value = func.value
        if isinstance(value, ast.Name) and value.id in {"self", "cls"}:
            self._add_load(value.id, value.lineno, value.col_offset)
            self._push_raw(_RawCall(caller, self.scope, line, "self", func.attr, value.id, True, func.col_offset))
            return
        if isinstance(value, ast.Name):
            self._add_load(value.id, value.lineno, value.col_offset, value=True)
            mode = "instance" if any(item.name == value.id and item.scope is self.scope for item in self.instances) else "classattr"
            self._push_raw(_RawCall(caller, self.scope, line, mode, func.attr, value.id, True, func.col_offset))
            return
        if isinstance(value, ast.Call) and isinstance(value.func, ast.Name) and value.func.id == "super":
            self.visit(value)
            enclosing = _enclosing_class(self.scope)
            class_name = _scope_qualname(enclosing) if enclosing is not None else ""
            self._push_raw(_RawCall(caller, self.scope, line, "super", func.attr, class_name, True, func.col_offset))
            return
        if isinstance(value, ast.Call) and isinstance(value.func, ast.Name):
            self.visit(value)
            self._push_raw(_RawCall(caller, self.scope, line, "constructed", func.attr, value.func.id, True, func.col_offset))
            return
        if isinstance(value, ast.Attribute):
            dotted = _dotted_name(value)
            if dotted:
                self.visit(value)
                self._push_raw(_RawCall(caller, self.scope, line, "chain", func.attr, dotted, True, func.col_offset))
                return
        self.visit(value)
        self._push_raw(_RawCall(caller, self.scope, line, "unknown", func.attr, "", True, func.col_offset))

    def _note_all_mutation(self, node: ast.Call) -> None:
        if self.scope.kind != "module" or self._suppress:
            return
        func = node.func
        if not isinstance(func, ast.Attribute) or not isinstance(func.value, ast.Name):
            return
        if func.value.id != "__all__":
            return
        if func.attr == "append" and len(node.args) == 1:
            self.exports.update(_string_constants(node.args[0]))
        elif func.attr == "extend" and len(node.args) == 1:
            self.exports.update(_export_names(node.args[0]))

    def _note_dynamic(self, node: ast.Call) -> None:
        name = _dynamic_call_name(node.func)
        if name:
            self.dynamic_markers.append(
                DynamicMarker(name=name, line=node.lineno, symbols=_dynamic_symbols(node, name))
            )
        imported = _literal_dynamic_import(node)
        if imported:
            self.dynamic_imports.append(imported)

    def _note_flow(self, target: ast.expr, value: ast.expr) -> None:
        caller = _caller_name(self.scope)
        line = getattr(value, "lineno", getattr(target, "lineno", 1))
        branch = self._branch_label()
        if isinstance(target, ast.Name) and isinstance(value, ast.Lambda):
            qualname = self._reserve_lambda(value)
            self.flow_binds.append(FlowBind(caller=caller, target=target.id, source=f"@lambda:{qualname}", line=line, branch=branch))
            return
        if isinstance(target, ast.Name) and isinstance(value, ast.Name):
            self.flow_binds.append(FlowBind(caller=caller, target=target.id, source=value.id, line=line, branch=branch))
            return
        if isinstance(target, ast.Name) and isinstance(value, ast.Call) and isinstance(value.func, ast.Name):
            self.flow_binds.append(
                FlowBind(caller=caller, target=target.id, source=f"@return:{value.func.id}", line=line, branch=branch)
            )
            return
        if (
            isinstance(target, ast.Attribute)
            and isinstance(target.value, ast.Name)
            and target.value.id in {"self", "cls"}
            and isinstance(value, ast.Name)
        ):
            self.flow_binds.append(
                FlowBind(
                    caller=caller,
                    target=f"{target.value.id}.{target.attr}",
                    source=value.id,
                    line=line,
                    branch=branch,
                )
            )

    def _reserve_lambda(self, node: ast.Lambda) -> str:
        name = self._pending_lambdas.get(id(node))
        if name is None:
            name = self._fresh("lambda")
            self._pending_lambdas[id(node)] = name
        return _qualname(self.scope, name)

    def _note_instance(self, target: ast.expr, value: ast.expr) -> None:
        if not isinstance(target, ast.Name):
            return
        class_name = _constructed_name(value)
        if class_name:
            self.instances.append(_InstanceBind(self.scope, target.id, class_name))

    def _record_decorators(self, qualname: str, decorators: list[ast.expr]) -> None:
        caller = _runtime_caller(self.scope)
        for decorator in decorators:
            name, arguments = _decorator_parts(decorator)
            if name:
                self.decorators.append(Decorator(qualname=qualname, name=name, arguments=arguments))
            expr = decorator.func if isinstance(decorator, ast.Call) else decorator
            line = getattr(decorator, "lineno", 1)
            if isinstance(expr, ast.Name):
                self._push_raw(_RawCall(caller, self.scope, line, "name", expr.id, "", True, getattr(expr, "col_offset", 0)))
            elif isinstance(expr, ast.Attribute):
                self._note_attribute_call(expr, caller, line)


class PythonAstBackend:
    """Stdlib `ast` backend. A future backend only has to return the same FileIndex."""

    def index_source(
        self,
        path: str,
        source: str,
        *,
        fold: dict[str, str] | None = None,
        duplicate_min_statements: int = 5,
    ) -> FileIndex:
        return _Indexer(path, source, fold, duplicate_min_statements).index()


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


def _annotation_names(node: ast.expr) -> list[str]:
    names: list[str] = []
    if isinstance(node, ast.Name):
        names.append(node.id)
    elif isinstance(node, ast.Attribute):
        names.append(node.attr)
    elif isinstance(node, ast.BinOp):
        names.extend(_annotation_names(node.left))
        names.extend(_annotation_names(node.right))
    elif isinstance(node, ast.Subscript):
        names.extend(_annotation_names(node.value))
        slice_node = node.slice
        if isinstance(slice_node, ast.expr):
            names.extend(_annotation_names(slice_node))
    elif isinstance(node, ast.Tuple):
        for element in node.elts:
            names.extend(_annotation_names(element))
    return names


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


def _is_abstract_function(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    if _has_abstract_decorator(node):
        return True
    body = list(node.body)
    if body and _is_docstring(body[0]):
        body = body[1:]
    if not body:
        return True
    if len(body) != 1:
        return False
    statement = body[0]
    return _is_ellipsis(statement) or isinstance(statement, ast.Pass) or _is_not_implemented(statement)


def _has_abstract_decorator(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for decorator in node.decorator_list:
        current = decorator.func if isinstance(decorator, ast.Call) else decorator
        name = _dotted_name(current)
        if name.rsplit(".", 1)[-1] in {"abstractmethod", "abstractproperty", "abstractclassmethod", "abstractstaticmethod"}:
            return True
    return False


def _is_not_implemented(statement: ast.stmt) -> bool:
    if not isinstance(statement, ast.Raise) or statement.exc is None:
        return False
    exc = statement.exc
    if isinstance(exc, ast.Call):
        exc = exc.func
    if isinstance(exc, ast.Name):
        return exc.id == "NotImplementedError"
    if isinstance(exc, ast.Attribute):
        return exc.attr == "NotImplementedError"
    return False


def _is_docstring(statement: ast.stmt) -> bool:
    return (
        isinstance(statement, ast.Expr)
        and isinstance(statement.value, ast.Constant)
        and isinstance(statement.value.value, str)
    )


def _is_ellipsis(statement: ast.stmt) -> bool:
    return (
        isinstance(statement, ast.Expr)
        and isinstance(statement.value, ast.Constant)
        and statement.value.value is Ellipsis
    )


def _sequence_slots(node: ast.expr) -> tuple[str, ...] | None:
    """Names stored in a list or tuple. A star or other shape returns None."""
    if not isinstance(node, ast.List | ast.Tuple):
        return None
    slots: list[str] = []
    for element in node.elts:
        if isinstance(element, ast.Starred):
            return None
        slots.append(element.id if isinstance(element, ast.Name) else "")
    return tuple(slots)


def _container_mutation(
    node: ast.Call,
) -> tuple[str, tuple[str, ...], str, int, list[ast.expr]] | None:
    """append, insert, or extend on a name. The last list is the nodes to visit as elements."""
    func = node.func
    if not isinstance(func, ast.Attribute) or not isinstance(func.value, ast.Name):
        return None
    name = func.value.id
    if func.attr == "append" and len(node.args) == 1:
        arg = node.args[0]
        slots = (arg.id if isinstance(arg, ast.Name) else "",)
        return name, slots, "append", -1, [arg]
    if func.attr == "insert" and len(node.args) == 2 and isinstance(node.args[0], ast.Constant):
        if not isinstance(node.args[0].value, int):
            return None
        arg = node.args[1]
        slots = (arg.id if isinstance(arg, ast.Name) else "",)
        return name, slots, "insert", node.args[0].value, [arg]
    if func.attr == "extend" and len(node.args) == 1:
        slots = _sequence_slots(node.args[0])
        if slots is None:
            return None
        return name, slots, "append", -1, [node.args[0]]
    return None


def _constructed_name(value: ast.expr) -> str:
    if isinstance(value, ast.Call) and isinstance(value.func, ast.Name):
        return value.func.id
    if isinstance(value, ast.Name):
        return value.id
    return ""


def _decorator_parts(node: ast.expr) -> tuple[str, tuple[str, ...]]:
    arguments: tuple[str, ...] = ()
    current = node
    if isinstance(node, ast.Call):
        arguments = tuple(
            element.value
            for element in node.args
            if isinstance(element, ast.Constant) and isinstance(element.value, str)
        )
        current = node.func
    return _dotted_name(current), arguments


def _dotted_name(node: ast.expr) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


def _dynamic_symbols(node: ast.Call, name: str) -> tuple[str, ...]:
    if name in {"getattr", "setattr", "hasattr"} and len(node.args) >= 2:
        text = _const_str(node.args[1])
        if text and text.isidentifier():
            return (text,)
        return ()
    if name in {"eval", "exec"} and node.args:
        text = _const_str(node.args[0])
        if not text:
            return ()
        return tuple(dict.fromkeys(_DYNAMIC_NAME.findall(text)))
    return ()


def _string_constants(node: ast.expr) -> set[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return {node.value}
    return set()


def _dynamic_call_name(func: ast.expr) -> str:
    if isinstance(func, ast.Name) and (func.id in _DYNAMIC_NAMES or func.id == "import_module"):
        return func.id
    if isinstance(func, ast.Attribute) and func.attr in _DYNAMIC_IMPORT_ATTRS:
        if isinstance(func.value, ast.Name) and func.value.id == "importlib":
            return f"importlib.{func.attr}"
    return ""


def _return_annotation(node: ast.expr) -> str:
    name = _annotation_text(node)
    return "" if name == "None" else name


def _annotation_text(node: ast.expr) -> str:
    """Dotted type name, unwrapping `X | None` and Optional/Union."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return _dotted_name(node)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        for side in (node.left, node.right):
            name = _annotation_text(side)
            if name and name != "None":
                return name
        return ""
    if isinstance(node, ast.Subscript):
        head = _dotted_name(node.value)
        if head.rsplit(".", 1)[-1] in {"Optional", "Union", "Annotated"}:
            return _first_annotation(node.slice)
        return ""
    if isinstance(node, ast.Constant) and node.value is None:
        return "None"
    return ""


def _first_annotation(node: ast.expr) -> str:
    if isinstance(node, ast.Tuple):
        for element in node.elts:
            name = _annotation_text(element)
            if name and name != "None":
                return name
        return ""
    return _annotation_text(node)


def _literal_dynamic_import(node: ast.Call) -> str:
    func = node.func
    is_import = isinstance(func, ast.Name) and func.id in {"__import__", "import_module"}
    if not is_import and isinstance(func, ast.Attribute):
        is_import = func.attr in {"import_module", "__import__"}
    if not is_import or not node.args:
        return ""
    text = _const_str(node.args[0])
    if not text:
        return ""
    return text.split(".", 1)[0]


def _body_signature(node: ast.FunctionDef | ast.AsyncFunctionDef, minimum: int) -> tuple[str, int]:
    body = list(node.body)
    if body and _is_docstring(body[0]):
        body = body[1:]
    count = len(body)
    if count < minimum:
        return "", count
    tokens = [_shape(statement) for statement in body]
    digest = hashlib.sha256("\n".join(tokens).encode("utf-8")).hexdigest()
    return digest, count


def _shape(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return "Name"
    if isinstance(node, ast.Constant):
        return f"Const:{node.value!r}"
    if isinstance(node, ast.arg):
        return "arg"
    parts: list[str] = []
    for field, value in ast.iter_fields(node):
        if field in {"lineno", "col_offset", "end_lineno", "end_col_offset", "ctx", "type_comment", "decorator_list"}:
            continue
        if isinstance(value, ast.AST):
            parts.append(_shape(value))
        elif isinstance(value, list):
            bits = [_shape(item) if isinstance(item, ast.AST) else repr(item) for item in value]
            parts.append("[" + ",".join(bits) + "]")
        else:
            parts.append(repr(value))
    return type(node).__name__ + "(" + ",".join(parts) + ")"


def _folded_name(node: ast.expr) -> object:
    if not isinstance(node, ast.Name):
        return None
    fold = _FOLD.get()
    if node.id not in fold:
        return None
    return _coerce_fold(fold[node.id])


def _folded_compare(node: ast.expr) -> bool | None:
    fold = _FOLD.get()
    if not fold or not isinstance(node, ast.Compare) or len(node.ops) != 1 or len(node.comparators) != 1:
        return None
    left = _compare_value(node.left, node.comparators[0], fold)
    right = _compare_value(node.comparators[0], node.left, fold)
    if left is None or right is None:
        return None
    if isinstance(node.ops[0], ast.Eq):
        return left == right
    if isinstance(node.ops[0], ast.NotEq):
        return left != right
    return None


def _compare_value(node: ast.expr, other: ast.expr, fold: dict[str, str]) -> object:
    if isinstance(node, ast.Constant) and isinstance(node.value, str | bool | int | float):
        return node.value
    raw = _raw_fold(node, fold)
    if raw is None:
        return None
    if isinstance(other, ast.Constant) and isinstance(other.value, str | bool | int | float):
        return _coerce_like(raw, other.value)
    if _raw_fold(other, fold) is not None:
        return _coerce_fold(raw)
    return None


def _raw_fold(node: ast.expr, fold: dict[str, str]) -> str | None:
    if isinstance(node, ast.Name) and node.id in fold:
        return fold[node.id]
    key = _environ_key(node)
    if key is not None and key in fold:
        return fold[key]
    return None


def _coerce_like(raw: str, other: object) -> object:
    """Match a folded string to the literal it is compared with."""
    if isinstance(other, bool):
        folded = _coerce_fold(raw)
        return folded if isinstance(folded, bool) else raw
    if isinstance(other, int):
        try:
            return int(raw)
        except ValueError:
            return raw
    if isinstance(other, float):
        try:
            return float(raw)
        except ValueError:
            return raw
    if isinstance(other, str):
        return raw
    return _coerce_fold(raw)


def _coerce_fold(value: str) -> object:
    if value.lower() == "true":
        return True
    if value.lower() == "false":
        return False
    return value


def _environ_key(node: ast.expr) -> str | None:
    if isinstance(node, ast.Subscript) and _is_os_environ(node.value):
        return _const_str(node.slice)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.args:
        if node.func.attr == "get" and _is_os_environ(node.func.value):
            return _const_str(node.args[0])
        if node.func.attr == "getenv" and isinstance(node.func.value, ast.Name) and node.func.value.id == "os":
            return _const_str(node.args[0])
    return None


def _is_os_environ(node: ast.expr) -> bool:
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "environ"
        and isinstance(node.value, ast.Name)
        and node.value.id == "os"
    )


def _const_str(node: ast.expr) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _export_names(node: ast.expr) -> set[str]:
    """String literals in `__all__`. Dynamic values are skipped."""
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        names: set[str] = set()
        for element in node.elts:
            if isinstance(element, ast.Constant) and isinstance(element.value, str):
                names.add(element.value)
            elif isinstance(element, ast.Starred):
                names.update(_export_names(element.value))
        return names
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _export_names(node.left) | _export_names(node.right)
    return set()


def _alias_position(alias: ast.alias, node: ast.AST) -> tuple[int, int]:
    line = getattr(alias, "lineno", None) or getattr(node, "lineno", 1)
    column = getattr(alias, "col_offset", None)
    if column is None:
        column = getattr(node, "col_offset", 0)
    return line, column


def _column(column: int) -> int:
    return column + 1 if column >= 0 else 1


def _is_main_guard(test: ast.expr) -> bool:
    if not isinstance(test, ast.Compare) or len(test.ops) != 1 or len(test.comparators) != 1:
        return False
    if not isinstance(test.ops[0], ast.Eq):
        return False
    left = test.left
    right = test.comparators[0]
    return (_is_name_dunder(left) and _is_main_string(right)) or (
        _is_main_string(left) and _is_name_dunder(right)
    )


def _is_name_dunder(node: ast.expr) -> bool:
    return isinstance(node, ast.Name) and node.id == "__name__"


def _is_main_string(node: ast.expr) -> bool:
    return isinstance(node, ast.Constant) and node.value == "__main__"


def _const_bool(node: ast.expr) -> bool | None:
    if isinstance(node, ast.Constant):
        if isinstance(node.value, bool):
            return node.value
        if isinstance(node.value, int) and node.value == 0:
            return False
        if isinstance(node.value, int) and node.value == 1:
            return True
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        inner = _const_bool(node.operand)
        if inner is None:
            return None
        return not inner
    if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.And):
        values = [_const_bool(value) for value in node.values]
        if any(value is False for value in values):
            return False
        if all(value is True for value in values):
            return True
        return None
    if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.Or):
        values = [_const_bool(value) for value in node.values]
        if any(value is True for value in values):
            return True
        if all(value is False for value in values):
            return False
        return None
    folded = _folded_name(node)
    if isinstance(folded, bool):
        return folded
    return _folded_compare(node)


def _block_always_exits(statements: list[ast.stmt]) -> bool:
    for statement in statements:
        if _stmt_always_exits(statement):
            return True
    return False


def _stmt_always_exits(statement: ast.stmt) -> bool:
    if isinstance(statement, ast.Return | ast.Raise | ast.Break | ast.Continue):
        return True
    if isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Call) and _is_process_exit(statement.value):
        return True
    if isinstance(statement, ast.If):
        truth = _const_bool(statement.test)
        if truth is True:
            return _block_always_exits(statement.body)
        if truth is False:
            return _block_always_exits(statement.orelse)
        if not statement.orelse:
            return False
        return _block_always_exits(statement.body) and _block_always_exits(statement.orelse)
    if isinstance(statement, ast.While):
        truth = _const_bool(statement.test)
        if truth is False:
            return _block_always_exits(statement.orelse)
        if truth is True and not _can_break(statement.body):
            return True
        return False
    if isinstance(statement, ast.With | ast.AsyncWith):
        return _block_always_exits(statement.body)
    if isinstance(statement, ast.Try | ast.TryStar):
        if statement.finalbody and _block_always_exits(statement.finalbody):
            return True
        handlers_exit = all(_block_always_exits(handler.body) for handler in statement.handlers)
        if _block_always_exits(statement.body) and handlers_exit:
            return True
        if statement.orelse and _block_always_exits(statement.orelse) and handlers_exit:
            return True
        return False
    if isinstance(statement, ast.Match):
        if not statement.cases or not all(_block_always_exits(case.body) for case in statement.cases):
            return False
        last = statement.cases[-1]
        if last.guard is not None:
            return False
        pattern = last.pattern
        return isinstance(pattern, ast.MatchAs) and pattern.pattern is None
    return False


def _can_break(statements: list[ast.stmt]) -> bool:
    """True when a reachable `break` can leave the enclosing loop."""
    for statement in statements:
        if isinstance(statement, ast.Break):
            return True
        if isinstance(statement, ast.Continue | ast.Return | ast.Raise):
            return False
        if isinstance(statement, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            continue
        if isinstance(statement, ast.For | ast.AsyncFor | ast.While):
            if _can_break(statement.orelse):
                return True
            if _stmt_always_exits(statement):
                return False
            continue
        if _break_in_nested(statement):
            return True
        if _stmt_always_exits(statement):
            return False
    return False


def _break_in_nested(statement: ast.stmt) -> bool:
    if isinstance(statement, ast.If):
        return _can_break(statement.body) or _can_break(statement.orelse)
    if isinstance(statement, ast.With | ast.AsyncWith):
        return _can_break(statement.body)
    if isinstance(statement, ast.Try | ast.TryStar):
        if _can_break(statement.body) or _can_break(statement.orelse) or _can_break(statement.finalbody):
            return True
        return any(_can_break(handler.body) for handler in statement.handlers)
    if isinstance(statement, ast.Match):
        return any(_can_break(case.body) for case in statement.cases)
    return False


def _body_skips_for_else(statements: list[ast.stmt]) -> bool:
    """True when an entered loop cannot finish normally, so its else does not run."""
    for statement in statements:
        if isinstance(statement, ast.Break | ast.Return | ast.Raise):
            return True
        if isinstance(statement, ast.Continue):
            return False
        if isinstance(statement, ast.If):
            truth = _const_bool(statement.test)
            if truth is True:
                return _body_skips_for_else(statement.body)
            if truth is False:
                return _body_skips_for_else(statement.orelse)
            if statement.orelse and _body_skips_for_else(statement.body) and _body_skips_for_else(statement.orelse):
                return True
            return False
        if isinstance(statement, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            continue
        if _stmt_always_exits(statement):
            return True
    return False


def _is_process_exit(call: ast.Call) -> bool:
    func = call.func
    if not isinstance(func, ast.Attribute) or not isinstance(func.value, ast.Name):
        return False
    if func.value.id == "sys" and func.attr == "exit":
        return True
    return func.value.id == "os" and func.attr == "_exit"


def _iter_is_empty(node: ast.expr) -> bool:
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        return len(node.elts) == 0
    if isinstance(node, ast.Dict):
        return len(node.keys) == 0
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return len(node.value) == 0
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "range":
        return _range_is_empty(node)
    return False


def _range_is_empty(node: ast.Call) -> bool:
    if not node.args or len(node.args) > 3:
        return False
    numbers: list[int] = []
    for arg in node.args:
        if isinstance(arg, ast.Constant) and isinstance(arg.value, int) and not isinstance(arg.value, bool):
            numbers.append(arg.value)
        else:
            return False
    if len(numbers) == 1:
        return numbers[0] <= 0
    start, stop = numbers[0], numbers[1]
    step = numbers[2] if len(numbers) == 3 else 1
    if step == 0:
        return False
    return (stop - start) * step <= 0


def _iter_is_nonempty(node: ast.expr) -> bool:
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        return len(node.elts) > 0
    if isinstance(node, ast.Dict):
        return len(node.keys) > 0
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return len(node.value) > 0
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "range":
        return _range_is_nonempty(node)
    return False


def _range_is_nonempty(node: ast.Call) -> bool:
    if not node.args or len(node.args) > 3:
        return False
    numbers: list[int] = []
    for arg in node.args:
        if isinstance(arg, ast.Constant) and isinstance(arg.value, int) and not isinstance(arg.value, bool):
            numbers.append(arg.value)
        else:
            return False
    if len(numbers) == 1:
        return numbers[0] > 0
    start, stop = numbers[0], numbers[1]
    step = numbers[2] if len(numbers) == 3 else 1
    if step == 0:
        return False
    return (stop - start) * step > 0


def _unreachable_spans(tree: ast.AST, source: str) -> list[UnreachableSpan]:
    spans: list[UnreachableSpan] = []
    if isinstance(tree, ast.Module):
        _walk_block(tree.body, [], spans, source)
    return spans


def _walk_block(
    statements: list[ast.stmt],
    stack: list[str],
    spans: list[UnreachableSpan],
    source: str,
) -> None:
    exited = False
    for statement in statements:
        if exited:
            _record(statement, stack, spans, source)
            continue
        _walk_inside(statement, stack, spans, source)
        if _stmt_always_exits(statement):
            exited = True


def _walk_inside(
    statement: ast.stmt,
    stack: list[str],
    spans: list[UnreachableSpan],
    source: str,
) -> None:
    if isinstance(statement, ast.FunctionDef | ast.AsyncFunctionDef):
        stack.append(statement.name)
        _walk_block(statement.body, stack, spans, source)
        stack.pop()
        return
    if isinstance(statement, ast.ClassDef):
        stack.append(statement.name)
        _walk_block(statement.body, stack, spans, source)
        stack.pop()
        return
    if isinstance(statement, ast.If):
        truth = _const_bool(statement.test)
        if truth is False:
            for inner in statement.body:
                _record(inner, stack, spans, source)
            _walk_block(statement.orelse, stack, spans, source)
        elif truth is True:
            _walk_block(statement.body, stack, spans, source)
            for inner in statement.orelse:
                _record(inner, stack, spans, source)
        else:
            _walk_block(statement.body, stack, spans, source)
            _walk_block(statement.orelse, stack, spans, source)
        return
    if isinstance(statement, ast.While):
        truth = _const_bool(statement.test)
        if truth is False:
            for inner in statement.body:
                _record(inner, stack, spans, source)
            _walk_block(statement.orelse, stack, spans, source)
        elif truth is True:
            _walk_block(statement.body, stack, spans, source)
            for inner in statement.orelse:
                _record(inner, stack, spans, source)
        else:
            _walk_block(statement.body, stack, spans, source)
            _walk_block(statement.orelse, stack, spans, source)
        return
    if isinstance(statement, ast.For | ast.AsyncFor):
        if _iter_is_empty(statement.iter):
            for inner in statement.body:
                _record(inner, stack, spans, source)
            _walk_block(statement.orelse, stack, spans, source)
            return
        _walk_block(statement.body, stack, spans, source)
        if statement.orelse and _iter_is_nonempty(statement.iter) and _body_skips_for_else(statement.body):
            for inner in statement.orelse:
                _record(inner, stack, spans, source)
        else:
            _walk_block(statement.orelse, stack, spans, source)
        return
    if isinstance(statement, ast.With | ast.AsyncWith):
        _walk_block(statement.body, stack, spans, source)
        return
    if isinstance(statement, ast.Try | ast.TryStar):
        _walk_block(statement.body, stack, spans, source)
        for handler in statement.handlers:
            _walk_block(handler.body, stack, spans, source)
        if _block_always_exits(statement.body):
            for inner in statement.orelse:
                _record(inner, stack, spans, source)
        else:
            _walk_block(statement.orelse, stack, spans, source)
        _walk_block(statement.finalbody, stack, spans, source)
        return
    if isinstance(statement, ast.Match):
        for case in statement.cases:
            _walk_block(case.body, stack, spans, source)


def _record(
    statement: ast.stmt,
    stack: list[str],
    spans: list[UnreachableSpan],
    source: str,
) -> None:
    end_line = getattr(statement, "end_lineno", None) or statement.lineno
    end_offset = getattr(statement, "end_col_offset", None)
    if end_offset is None:
        end_offset = statement.col_offset + 1
    if isinstance(statement, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef) and statement.body:
        first = statement.body[0]
        if first.lineno > statement.lineno or first.col_offset > statement.col_offset:
            end_line = first.lineno
            end_offset = first.col_offset
    spans.append(
        UnreachableSpan(
            line=statement.lineno,
            column=_column(statement.col_offset),
            symbol=_snippet(source, statement.lineno),
            message=_UNREACHABLE_MESSAGE,
            scope_qualname=".".join(stack) if stack else "<module>",
            end_line=end_line,
            end_offset=end_offset,
        )
    )


def _snippet(source: str, line: int) -> str:
    rows = source.splitlines()
    if line < 1 or line > len(rows):
        return ""
    text = rows[line - 1].strip()
    if len(text) > 120:
        return text[:117] + "..."
    return text
