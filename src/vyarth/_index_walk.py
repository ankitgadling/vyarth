"""Annotation parsing, constant folding, and unreachable-statement spans."""

from __future__ import annotations

import ast
import contextvars
import hashlib
import re

from vyarth.model import UnreachableSpan


_UNREACHABLE_MESSAGE = "Control flow terminates before this statement."
_FOLD: contextvars.ContextVar[dict[str, str]] = contextvars.ContextVar("vyarth_fold", default={})
_DYNAMIC_NAMES = {"getattr", "setattr", "globals", "locals", "eval", "exec", "__import__"}
_DYNAMIC_IMPORT_ATTRS = {"import_module", "__import__"}
_DYNAMIC_NAME = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")


def _parse_annotation_expr(node: ast.Constant) -> ast.expr | None:
    """Parse a quoted annotation. Locations stay on the original string."""
    text = node.value
    if not isinstance(text, str):
        return None
    try:
        parsed = ast.parse(text, mode="eval")
    except SyntaxError:
        return None
    body = parsed.body
    for child in ast.walk(body):
        if not isinstance(child, ast.expr):
            continue
        child.lineno = node.lineno
        child.col_offset = node.col_offset
        child.end_lineno = node.end_lineno if node.end_lineno is not None else node.lineno
        child.end_col_offset = node.end_col_offset if node.end_col_offset is not None else node.col_offset
    return body

def _annotation_names(node: ast.expr) -> list[str]:
    names: list[str] = []
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        parsed = _parse_annotation_expr(node)
        if parsed is not None:
            names.extend(_annotation_names(parsed))
        return names
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
        extended = _sequence_slots(node.args[0])
        if extended is None:
            return None
        return name, extended, "append", -1, [node.args[0]]
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
    """Dotted type name, unwrapping `X | None`, Optional/Union, and quoted refs."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        parsed = _parse_annotation_expr(node)
        return _annotation_text(parsed) if parsed is not None else ""
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
    line = alias.lineno if isinstance(alias.lineno, int) else _ast_int(node, "lineno", 1)
    column = alias.col_offset if isinstance(alias.col_offset, int) else _ast_int(node, "col_offset", 0)
    return line, column

def _ast_int(node: ast.AST, name: str, default: int) -> int:
    value = getattr(node, name, default)
    return value if isinstance(value, int) else default

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
