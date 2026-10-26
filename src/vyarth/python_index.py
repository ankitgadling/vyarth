"""Scope-aware Python indexer."""

from __future__ import annotations

import ast
import re

from vyarth.backend import AnalysisBackend
from vyarth.ignore import collect_ignores, expand_decorator_ignores, expand_import_ignores, import_noqa_ignores
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


def _is_type_checking(test: ast.expr) -> bool:
    """True for `TYPE_CHECKING` and `typing.TYPE_CHECKING`."""
    if isinstance(test, ast.Name):
        return test.id == "TYPE_CHECKING"
    return (
        isinstance(test, ast.Attribute)
        and test.attr == "TYPE_CHECKING"
        and isinstance(test.value, ast.Name)
        and test.value.id == "typing"
    )


def _base_expression(node: ast.expr) -> str:
    """Name of a class base, unwrapping subscripts and calls.

    `Generic[T]` and `with_metaclass(Meta)` still name a base. An expression
    with no name is `@external`, so the class is not treated as having no base.
    """
    current = node
    while isinstance(current, ast.Subscript):
        current = current.value
    if isinstance(current, ast.Call):
        current = current.func
    return _dotted_name(current) or "@external"


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
        self.import_probes: list[str] = []
        self._type_checking = 0
        self._origin = ""
        self.lambda_mentions: set[str] = set()
        self.module_strings: set[str] = set()

    def index(self) -> FileIndex:
        tree = ast.parse(self.source, filename=self.path, type_comments=True)
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
        ignores = expand_import_ignores(tree, ignores)
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
            import_probes=tuple(dict.fromkeys(self.import_probes)),
            lambda_mentions=tuple(sorted(self.lambda_mentions)),
            module_strings=tuple(sorted(self.module_strings)),
        )

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        qualname = _qualname(self.scope, node.name)
        self._record_decorators(qualname, node.decorator_list)
        if node.bases:
            base_names = tuple(_base_expression(base) for base in node.bases)
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
        tracked = name is not None
        if name is None:
            name = self._fresh("lambda")
        qualname = _qualname(self.scope, name)
        self._lambda_qualnames[id(node)] = qualname
        caller = _caller_name(self.scope)
        self._push("lambda", name)
        self._bind_arguments(node.args)
        self.visit(node.body)
        self._pop()
        if not tracked:
            # A lambda that is passed along, stored in a container, or returned is
            # assumed to run. Only `name = lambda: ...` waits for a call to `name`.
            self._push_raw(_RawCall(caller, self.scope, node.lineno, "lambda", qualname, "", True, node.col_offset))

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
            if (
                alias.asname is not None
                and alias.asname == alias.name
                and self.scope.kind == "module"
            ):
                # `import os as os` is the PEP 484 spelling of a public re-export.
                binding.read_count += 1
                self.exports.add(local)
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
        """Remember an import inside `try/except ImportError` for a lower score."""
        if self._import_probe:
            self.import_probes.append(binding.name)

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
        self._visit_branch(node.body, f"if:{node.lineno}:body", _is_type_checking(node.test))
        self._visit_branch(node.orelse, f"if:{node.lineno}:else", False)

    def _visit_branch(self, statements: list[ast.stmt], label: str, typing_only: bool) -> None:
        self._branches.append(label)
        if typing_only:
            self._type_checking += 1
        try:
            for statement in statements:
                self.visit(statement)
        finally:
            if typing_only:
                self._type_checking -= 1
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
        self._visit_type_comment(node)
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
            if isinstance(target, ast.Tuple | ast.List):
                self._visit_with_origin("unpack", target)
            else:
                self.visit(target)

    def _visit_with_origin(self, origin: str, node: ast.AST) -> None:
        previous = self._origin
        self._origin = origin
        try:
            self.visit(node)
        finally:
            self._origin = previous

    def visit_With(self, node: ast.With) -> None:
        self._visit_type_comment(node)
        self.generic_visit(node)

    def visit_AsyncWith(self, node: ast.AsyncWith) -> None:
        self._visit_type_comment(node)
        self.generic_visit(node)

    def visit_withitem(self, node: ast.withitem) -> None:
        self.visit(node.context_expr)
        if node.optional_vars is not None:
            self._visit_with_origin("with", node.optional_vars)

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
        elif isinstance(node.target, ast.Attribute) and not self._suppress:
            # `self.count += 1` reads the attribute before it writes it.
            self._record_attribute_load(node.target)
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
            if _is_type_alias(node.annotation):
                self._visit_annotation(node.value)
            else:
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
            previous = self._origin
            self._origin = "match"
            try:
                self._bind_pattern(case.pattern)
            finally:
                self._origin = previous
            if case.guard is not None:
                self.visit(case.guard)
            for statement in case.body:
                self.visit(statement)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if self._suppress:
            self.visit(node.value)
            return
        if isinstance(node.ctx, ast.Load):
            self._record_attribute_load(node)
        self.visit(node.value)

    def _record_attribute_load(self, node: ast.Attribute) -> None:
        value = node.value
        own = _own_class_receiver(value)
        if own:
            self.raw_attrs.append(_RawCall("", self.scope, node.lineno, "self", node.attr, own))
        elif isinstance(value, ast.Name):
            mode = "self" if value.id in {"self", "cls"} else "nameattr"
            self.raw_attrs.append(_RawCall("", self.scope, node.lineno, mode, node.attr, value.id))
        elif isinstance(value, ast.Call) and isinstance(value.func, ast.Name):
            self.raw_attrs.append(
                _RawCall("", self.scope, node.lineno, "constructed", node.attr, value.func.id)
            )
        else:
            # The receiver has no known class. The name still counts as a mention.
            self.raw_attrs.append(_RawCall("", self.scope, node.lineno, "unknown", node.attr, ""))

    def visit_Call(self, node: ast.Call) -> None:
        if self._suppress == 0:
            self._note_dynamic(node)
            self._note_all_mutation(node)
        mutation = _container_mutation(node)
        self._note_call(node)
        self._note_locals(node)
        cast_type = self._visit_cast_type(node)
        self._visit_typing_constructor(node)
        if mutation is not None:
            name, slots, mode, index, parts = mutation
            self._visit_container_parts(parts)
            for argument in node.args:
                if argument is not cast_type and argument not in parts:
                    self.visit(argument)
            for keyword in node.keywords:
                if keyword.value is not None:
                    self.visit(keyword.value)
            self._remember_container(name, slots, mode, node.lineno, index)
            return
        for argument in node.args:
            if argument is not cast_type:
                self.visit(argument)
        for keyword in node.keywords:
            if keyword.value is not None:
                self.visit(keyword.value)

    def _visit_cast_type(self, node: ast.Call) -> ast.expr | None:
        """`cast("Fraction", value)` uses `Fraction`, including a quoted forward reference."""
        if not _is_cast_call(node.func) or not node.args:
            return None
        self._visit_annotation(node.args[0])
        return node.args[0]

    def _note_locals(self, node: ast.Call) -> None:
        """`locals()` and a bare `vars()` hand every local name to code this scan cannot see."""
        func = node.func
        if not isinstance(func, ast.Name) or func.id not in {"locals", "vars"}:
            return
        if node.args or node.keywords or self._suppress:
            return
        _assignment_scope(self.scope).reads_locals = True

    def _visit_typing_constructor(self, node: ast.Call) -> None:
        """Quoted types in `TypeVar`, `NewType`, and functional `TypedDict` / `NamedTuple` are uses."""
        leaf = _form_name(node.func)
        if leaf in {"TypeVar", "ParamSpec", "TypeVarTuple"}:
            for argument in node.args[1:]:
                self._visit_annotation(argument)
            for keyword in node.keywords:
                if keyword.arg in {"bound", "default"}:
                    self._visit_annotation(keyword.value)
        elif leaf == "NewType" and len(node.args) >= 2:
            self._visit_annotation(node.args[1])
        elif leaf in {"TypedDict", "NamedTuple"} and len(node.args) >= 2:
            fields = node.args[1]
            if isinstance(fields, ast.Dict):
                for value in fields.values:
                    self._visit_annotation(value)
            elif isinstance(fields, ast.List | ast.Tuple):
                for element in fields.elts:
                    if isinstance(element, ast.Tuple) and len(element.elts) == 2:
                        self._visit_annotation(element.elts[1])
            for keyword in node.keywords:
                if keyword.arg not in {"total", "module", "defaults", "rename"}:
                    self._visit_annotation(keyword.value)

    def _visit_type_comment(self, node: ast.AST) -> None:
        """A `# type:` comment names types the same way an annotation does."""
        text = getattr(node, "type_comment", None)
        if not text:
            return
        function = isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
        for expression in _type_comment_exprs(text, node, function):
            self._visit_annotation(expression)

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, ast.Load):
            self._add_load(node.id, node.lineno, node.col_offset, value=True)
        elif isinstance(node.ctx, ast.Store):
            self._bind(node.id, "variable", node.lineno, node.col_offset)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        if _form_name(node.value) == "Literal":
            # Strings in `Literal[...]` are values, not names.
            self.visit(node.value)
            depth = self._annotation_depth
            self._annotation_depth = 0
            try:
                self.visit(node.slice)
            finally:
                self._annotation_depth = depth
            return
        if _is_annotated(node.value):
            self.visit(node.value)
            self._visit_annotated_slice(node.slice)
            return
        if self._annotation_depth == 0 and _is_typing_form(node.value):
            self.visit(node.value)
            self._visit_annotation(node.slice)
            return
        self.visit(node.value)
        self.visit(node.slice)

    def _visit_annotated_slice(self, node: ast.expr) -> None:
        """Only the first argument of `Annotated` is a type. The rest is metadata."""
        elements = node.elts if isinstance(node, ast.Tuple) else (node,)
        if not elements:
            return
        self._visit_annotation(elements[0])
        depth = self._annotation_depth
        self._annotation_depth = 0
        try:
            for extra in elements[1:]:
                self.visit(extra)
        finally:
            self._annotation_depth = depth

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
        if isinstance(node.value, str) and _MODULE_STRING.match(node.value):
            self.module_strings.add(node.value)
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
        self._visit_type_comment(node)
        self.visit(node.iter)
        self._visit_with_origin("loop", node.target)
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
        self._visit_type_comment(node)
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
            self._visit_type_comment(arg)
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
        self._visit_with_origin("comp", generators[0].target)
        for test in generators[0].ifs:
            self.visit(test)
        for generator in generators[1:]:
            self.visit(generator.iter)
            self._visit_with_origin("comp", generator.target)
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
            if self._origin == "" or kind != "variable":
                existing.origin = ""
            if self._type_checking == 0:
                existing.typing_only = False
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
        binding.typing_only = self._type_checking > 0
        if kind == "variable":
            binding.origin = self._origin
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
        """Number anonymous scopes inside their parent, so earlier defs do not shift them."""
        number = sum(1 for child in self.scope.children if child.kind == prefix) + 1
        return f"<{prefix}#{number}>"

    def _resolve_loads(self) -> None:
        wildcard = any(edge.is_wildcard for edge in self.imports)
        for site in self.loads:
            if site.suppressed or self._in_dead(site.line, site.col):
                continue
            binding = _resolve(site.scope, site.name, self.module, class_bound=site.class_bound)
            # An uncalled lambda must not keep a function or class alive just by naming it.
            # Imports and variables loaded in the lambda are real uses.
            if _inside_lambda(site.scope) and (binding is None or binding.kind in {"function", "class"}):
                if binding is not None:
                    self.lambda_mentions.add(binding.qualname)
                continue
            if binding is not None:
                binding.read_count += 1
            elif wildcard:
                self.unbound.add(site.name)
        self._apply_locals_reads(self.module)

    def _apply_locals_reads(self, scope: _Scope) -> None:
        if scope.reads_locals:
            for binding in scope.bindings.values():
                if binding.kind == "variable":
                    binding.read_count += 1
        for child in scope.children:
            self._apply_locals_reads(child)

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
            else:
                add(raw.scope, f"@attr:{raw.name}")
        return found

    def _class_bases(self) -> tuple[tuple[str, tuple[str, ...]], ...]:
        found: list[tuple[str, tuple[str, ...]]] = []
        for qualname, scope, names in self.pending_bases:
            resolved = tuple(item for name in names if (item := self._resolve_base_name(scope, name)))
            if resolved:
                found.append((qualname, resolved))
        return tuple(found)

    def _resolve_base_name(self, scope: _Scope, dotted: str) -> str:
        if dotted == "@external":
            return "@external"
        if "." not in dotted:
            binding = _resolve(scope, dotted, self.module)
            if binding is not None and binding.kind == "class":
                return binding.qualname
            if binding is not None and binding.kind == "import":
                return f"@import:{binding.qualname}"
            # A builtin, an alias, or any other non-class name is not a project base.
            return dotted
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
                if binding is not None and binding.kind in {"function", "class"} and _inside_lambda(raw.scope):
                    self.lambda_mentions.add(binding.qualname)
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
                if _inside_lambda(raw.scope):
                    self.lambda_mentions.add(f"{class_qualname}.{raw.name}")
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
        own = _own_class_receiver(value)
        if own:
            self.visit(value)
            self._push_raw(_RawCall(caller, self.scope, line, "self", func.attr, own, True, func.col_offset))
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


_TYPING_FORMS = {
    "Union",
    "Optional",
    "Annotated",
    "Callable",
    "List",
    "Dict",
    "Set",
    "FrozenSet",
    "Tuple",
    "Type",
    "DefaultDict",
    "OrderedDict",
    "Counter",
    "Deque",
    "ChainMap",
    "Sequence",
    "MutableSequence",
    "Mapping",
    "MutableMapping",
    "MutableSet",
    "AbstractSet",
    "Iterable",
    "Iterator",
    "Collection",
    "Container",
    "Generator",
    "AsyncIterable",
    "AsyncIterator",
    "AsyncGenerator",
    "Awaitable",
    "Coroutine",
    "ClassVar",
    "Final",
    "Generic",
    "Protocol",
    "TypeGuard",
    "Required",
    "NotRequired",
    "ReadOnly",
    "Concatenate",
    "Unpack",
    "ContextManager",
    "AsyncContextManager",
    "Pattern",
    "Match",
    "IO",
    "list",
    "dict",
    "set",
    "frozenset",
    "tuple",
    "type",
}
_IMPORT_ERRORS = {"ImportError", "ModuleNotFoundError"}
_MODULE_STRING = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$")


def _form_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _is_typing_form(node: ast.expr) -> bool:
    return _form_name(node) in _TYPING_FORMS


def _own_class_receiver(node: ast.expr) -> str:
    """`self` or `cls` for `type(self)` and `self.__class__`. Empty for any other receiver."""
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "type"
        and len(node.args) == 1
        and isinstance(node.args[0], ast.Name)
        and node.args[0].id in {"self", "cls"}
    ):
        return node.args[0].id
    if (
        isinstance(node, ast.Attribute)
        and node.attr == "__class__"
        and isinstance(node.value, ast.Name)
        and node.value.id in {"self", "cls"}
    ):
        return node.value.id
    return ""


def _type_comment_exprs(text: str, node: ast.AST, function: bool) -> list[ast.expr]:
    """Types named in a `# type:` comment, located at the statement that carries it."""
    try:
        if function:
            parsed = ast.parse(text, mode="func_type")
            expressions = [*parsed.argtypes, parsed.returns]  # type: ignore[attr-defined]
        else:
            expressions = [ast.parse(text, mode="eval").body]
    except SyntaxError:
        return []
    line = getattr(node, "lineno", 1)
    column = getattr(node, "col_offset", 0)
    for expression in expressions:
        for child in ast.walk(expression):
            if isinstance(child, ast.expr):
                child.lineno = line
                child.col_offset = column
                child.end_lineno = line
                child.end_col_offset = column
    return expressions


def _is_type_alias(node: ast.expr | None) -> bool:
    return _form_name(node) == "TypeAlias" if node is not None else False


def _is_annotated(node: ast.expr) -> bool:
    return _form_name(node) == "Annotated"


def _is_cast_call(node: ast.expr) -> bool:
    if isinstance(node, ast.Name):
        return node.id == "cast"
    if isinstance(node, ast.Attribute):
        return node.attr == "cast"
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


class PythonAstBackend(AnalysisBackend):
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
