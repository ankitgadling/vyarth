"""Scope-aware Python indexer."""

from __future__ import annotations

import ast

from vyarth.ignore import collect_ignores, expand_decorator_ignores, import_noqa_ignores
from vyarth.model import (
    BodyHash,
    CallEdge,
    ContainerStore,
    Decorator,
    DynamicMarker,
    FileIndex,
    FlowBind,
    ImportEdge,
    ReturnNote,
    UnreachableSpan,
    point_in_spans,
)
from vyarth._index_model import (
    _Binding,
    _ContainerOp,
    _InstanceBind,
    _Load,
    _RawCall,
    _Scope,
    _assignment_scope,
    _caller_name,
    _enclosing_class,
    _freeze_bindings,
    _freeze_scopes,
    _inside_lambda,
    _nonlocal_owner,
    _qualname,
    _resolve,
    _runtime_caller,
    _scope_qualname,
)
from vyarth._index_walk import (
    _FOLD,
    _alias_position,
    _annotation_names,
    _body_signature,
    _column,
    _const_bool,
    _constructed_name,
    _container_mutation,
    _decorator_parts,
    _dotted_name,
    _dynamic_call_name,
    _dynamic_symbols,
    _export_names,
    _is_abstract_function,
    _is_main_guard,
    _literal_dynamic_import,
    _parse_annotation_expr,
    _return_annotation,
    _sequence_slots,
    _string_constants,
    _unreachable_spans,
)


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
        self._annotation_depth = 0
        self._import_probe = 0

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
        ignores = ignores + import_noqa_ignores(tree, self.source)
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
            binding = self._bind(local, "import", line, column)
            self._probe_import(binding)
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
            elif self._explicit_reexport(alias):
                binding.read_count += 1
                self.exports.add(local)
            self._probe_import(binding)
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

    def _explicit_reexport(self, alias: ast.alias) -> bool:
        """PEP 484 marks `from module import Name as Name` as a public re-export."""
        return (
            self.scope.kind == "module"
            and alias.asname is not None
            and alias.asname == alias.name
        )

    def _probe_import(self, binding: _Binding) -> None:
        """An import inside `try/except ImportError` is used for its side effect."""
        if self._import_probe:
            binding.read_count += 1

    def visit_Try(self, node: ast.Try) -> None:
        self._visit_try(node)

    def visit_TryStar(self, node: ast.TryStar) -> None:
        self._visit_try(node)

    def _visit_try(self, node: ast.Try | ast.TryStar) -> None:
        probe = _catches_import_error(node.handlers)
        if probe:
            self._import_probe += 1
        for statement in node.body:
            self.visit(statement)
        if probe:
            self._import_probe -= 1
        for handler in node.handlers:
            self.visit(handler)
        for statement in node.orelse:
            self.visit(statement)
        for statement in node.finalbody:
            self.visit(statement)

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
            self._visit_annotation(node.annotation)
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

    def visit_Subscript(self, node: ast.Subscript) -> None:
        if self._annotation_depth == 0 and _is_typing_form(node.value):
            self.visit(node.value)
            self._visit_annotation(node.slice)
            return
        self.visit(node.value)
        self.visit(node.slice)

    def visit_BinOp(self, node: ast.BinOp) -> None:
        if isinstance(node.op, ast.BitOr):
            self._visit_union_operand(node.left)
            self._visit_union_operand(node.right)
            return
        self.visit(node.left)
        self.visit(node.right)

    def _visit_union_operand(self, node: ast.expr) -> None:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            self._visit_annotation(node)
            return
        self.visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        if self._annotation_depth <= 0 or not isinstance(node.value, str):
            return
        parsed = _parse_annotation_expr(node)
        if parsed is not None:
            self.visit(parsed)

    def visit_TypeAlias(self, node: ast.AST) -> None:
        value = getattr(node, "value", None)
        if isinstance(value, ast.expr):
            self._visit_annotation(value)

    def _visit_annotation(self, node: ast.expr) -> None:
        """Visit an annotation, parsing quoted forward references into real names."""
        self._annotation_depth += 1
        try:
            self.visit(node)
        finally:
            self._annotation_depth -= 1

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
                self._visit_annotation(arg.annotation)
        if args.vararg and args.vararg.annotation is not None:
            self._visit_annotation(args.vararg.annotation)
        if args.kwarg and args.kwarg.annotation is not None:
            self._visit_annotation(args.kwarg.annotation)
        for positional in args.defaults:
            self.visit(positional)
        for kw_default in args.kw_defaults:
            if kw_default is not None:
                self.visit(kw_default)
        if returns is not None:
            self._visit_annotation(returns)

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
            if site.suppressed or self._in_dead(site.line, site.col):
                continue
            binding = _resolve(site.scope, site.name, self.module, class_bound=site.class_bound)
            # An uncalled lambda must not keep a function or class alive just by naming it.
            # Imports and variables loaded in the lambda are real uses.
            if _inside_lambda(site.scope) and (binding is None or binding.kind in {"function", "class"}):
                continue
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


_TYPING_FORMS = {"Union", "Optional", "Annotated", "Literal"}
_IMPORT_ERRORS = {"ImportError", "ModuleNotFoundError"}


def _is_typing_form(node: ast.expr) -> bool:
    if isinstance(node, ast.Name):
        return node.id in _TYPING_FORMS
    if isinstance(node, ast.Attribute):
        return node.attr in _TYPING_FORMS
    return False


def _catches_import_error(handlers: list[ast.ExceptHandler]) -> bool:
    return any(_exception_names(handler.type) & _IMPORT_ERRORS for handler in handlers if handler.type is not None)


def _exception_names(node: ast.expr) -> set[str]:
    if isinstance(node, ast.Name):
        return {node.id}
    if isinstance(node, ast.Attribute):
        return {node.attr}
    if isinstance(node, ast.Tuple):
        found: set[str] = set()
        for element in node.elts:
            found.update(_exception_names(element))
        return found
    return set()


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
