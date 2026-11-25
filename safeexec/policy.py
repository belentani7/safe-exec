"""Static, execution-free policy analysis for Python source.

The analyser never imports, executes or evaluates the source it inspects. It
builds an AST, resolves names through a *scope-aware* symbolic environment and
folds only literal string/bytes constants. Whenever an expression could resolve
to a restricted symbol at runtime but cannot be proven harmless, the analyser
reports a finding (fail-closed) rather than staying silent.

Known limits are documented in ``docs/THREAT-MODEL.md``. This module narrows
whole classes of evasion; it is not a substitute for the sandbox and the
signed consensus protocol.
"""

from __future__ import annotations

import ast
import io
import tokenize
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

RULES_FILENAME = "rules.yaml"

#: Hard ceiling on AST nodes per file. Ordinary code is ~40k nodes per MiB;
#: 400k leaves room for generated code while bounding analysis time and memory.
MAX_AST_NODES = 400_000

#: Hard ceiling on analysed source size.
MAX_SOURCE_BYTES = 1_048_576

#: Marker for "this expression could be anything at runtime".
UNKNOWN = "?"

_BUILTIN_MARKERS = frozenset({"builtins", "__builtins__"})
_DYNAMIC_CALLABLES = (
    "__import__",
    "builtins.__import__",
    "importlib.import_module",
    "importlib.__import__",
)
_WILDCARD_EXPAND_THRESHOLD = 64
_TRANSPARENT_NODES = (ast.Expr, ast.Return, ast.Pass, ast.TypeIgnore)

#: Sentinel returned by ``_subscript_context`` for ``sys.modules``.
_MODULES = "\x00modules"


@dataclass(frozen=True, order=True)
class Finding:
    """One policy violation, ordered deterministically for reproducible output."""

    rule: str
    line: int
    detail: str


@dataclass(frozen=True)
class PolicyRules:
    """Immutable rule set, safe to share between threads."""

    version: str
    blocked_imports: frozenset[str]
    blocked_calls: frozenset[str]
    blocked_literals: tuple[str, ...]
    max_source_bytes: int
    max_ast_nodes: int

    @classmethod
    def load(cls, path: Path) -> PolicyRules:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if not isinstance(raw, Mapping):
            raise ValueError(f"{path}: policy document must be a mapping")
        return cls(
            version=str(raw.get("version", "safeexec-1")),
            blocked_imports=frozenset(_string_sequence(raw.get("blocked_imports", []))),
            blocked_calls=frozenset(_string_sequence(raw.get("blocked_calls", []))),
            blocked_literals=tuple(_string_sequence(raw.get("blocked_literals", []))),
            max_source_bytes=_positive_int(raw.get("max_source_bytes"), MAX_SOURCE_BYTES),
            max_ast_nodes=_positive_int(raw.get("max_ast_nodes"), MAX_AST_NODES),
        )


def _string_sequence(value: Any) -> list[str]:
    if not isinstance(value, (list, tuple)):
        raise ValueError("policy entries must be a list of strings")
    result = []
    for item in value:
        if not isinstance(item, str):
            raise ValueError(f"policy entry must be a string, got {type(item).__name__}")
        if item:
            result.append(item)
    return result


def _positive_int(value: Any, default: int) -> int:
    if value is None:
        return default
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ValueError("policy limits must be positive integers")
    return value


class StaticPolicyEvaluator(ast.NodeVisitor):
    """Evaluate Python source against a policy without executing it.

    The evaluator is re-entrant: :meth:`evaluate` resets all per-file state, so
    one instance may be reused across requests (or threads, one call each).
    """

    def __init__(
        self,
        rules_path: Path | str,
        rules: PolicyRules | None = None,
    ) -> None:
        self.rules = rules if rules is not None else PolicyRules.load(Path(rules_path))
        self.rules_path = Path(rules_path)
        self.findings: list[Finding] = []
        self._aliases: dict[str, str] = {}
        self._nodes = 0
        self._node_budget = self.rules.max_ast_nodes
        self._wildcard_modules: set[str] = set()

    # ------------------------------------------------------------------ API

    def evaluate(self, source: str | bytes) -> list[Finding]:
        """Return deterministic findings for ``source``; never executes it."""
        self._reset()
        if isinstance(source, bytes):
            source = source.decode("utf-8-sig", errors="replace")
        else:
            source = source.lstrip("\ufeff")

        if len(source.encode("utf-8", errors="replace")) > self.rules.max_source_bytes:
            return [Finding("oversized-source", 0, "source exceeds configured limit")]

        try:
            tree = ast.parse(source)
        except SyntaxError as exc:
            return [Finding("invalid-python", exc.lineno or 0, str(exc))]
        except (ValueError, RecursionError, MemoryError) as exc:
            return [Finding("unparsable-source", 0, type(exc).__name__)]

        try:
            self._index_tree(tree)
            self.visit(tree)
        except _BudgetExceeded:
            self.findings.append(
                Finding("complexity-budget", 0, f"AST exceeds {self._node_budget} nodes")
            )
        except RecursionError:
            self.findings.append(Finding("complexity-budget", 0, "nesting too deep"))
        return self._finalise()

    # ------------------------------------------------------------ internals

    def _reset(self) -> None:
        self.findings = []
        self._aliases = {}
        self._nodes = 0
        self._node_budget = self.rules.max_ast_nodes
        self._wildcard_modules = set()

    def _finalise(self) -> list[Finding]:
        unique = {(f.rule, f.line, f.detail) for f in self.findings}
        return [Finding(*item) for item in sorted(unique)]

    def _add(self, rule: str, line: int, detail: str) -> None:
        self.findings.append(Finding(rule, line, detail))

    def _count(self, node: ast.AST) -> None:
        self._nodes += 1
        if self._nodes > self._node_budget:
            raise _BudgetExceeded

    # ------------------------------------------------------- rules helpers

    def _is_blocked_call(self, canonical: str) -> bool:
        if canonical in self.rules.blocked_calls:
            return True
        # A restricted attribute reached through an unknown receiver is still a
        # restriction: `?system` must not be treated as harmless.
        if "." in canonical:
            suffix = canonical.split(".", 1)[1]
            if suffix in self.rules.blocked_calls:
                return True
        return False

    def _is_blocked_module(self, name: str) -> bool:
        parts = name.split(".")
        return any(
            ".".join(parts[:i]) in self.rules.blocked_imports
            for i in range(1, len(parts) + 1)
        )

    # ------------------------------------------------------------- visiting

    def visit(self, node: ast.AST) -> None:  # type: ignore[override]
        self._count(node)
        super().visit(node)

    def _annotate_parents(self, tree: ast.AST) -> None:
        """Record each node's parent once per file (cost: one AST walk)."""
        for parent in ast.walk(tree):
            for child in ast.iter_child_nodes(parent):
                child._safeexec_parent = parent  # type: ignore[attr-defined]

    def generic_visit(self, node: ast.AST) -> None:
        super().generic_visit(node)

    # --- statements that open scopes -------------------------------------

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node)

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        for decorator in node.decorator_list:
            self.visit(decorator)
        self._visit_defaults(node.args)
        # Mutate the environment in place so the enclosing flow keeps every
        # binding made here (the analyser is intentionally flow-insensitive
        # about ordering, but must not lose restrictions).
        for argument in _iter_arguments(node.args):
            self._bind(argument, UNKNOWN)
        self._visit_block(node.body)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        for decorator in node.decorator_list:
            self.visit(decorator)
        for base in node.bases:
            self.visit(base)
        for keyword in node.keywords:
            self.visit(keyword.value)
        self._visit_block(node.body)

    def visit_Lambda(self, node: ast.Lambda) -> None:
        self._visit_defaults(node.args)
        # ``lambda: os.system`` hands the callable to the caller, who can invoke
        # it without any name the alias layer could follow.
        canonical = self._canonical(node.body)
        if self._is_blocked_call(canonical):
            self._add("blocked-call", node.lineno, canonical.lstrip("?"))
        self.visit(node.body)

    def _visit_defaults(self, args: ast.arguments) -> None:
        for default in list(args.defaults) + [d for d in args.kw_defaults if d is not None]:
            self.visit(default)

    # --- branching: conservative merge -----------------------------------

    def visit_If(self, node: ast.If) -> None:
        self.visit(node.test)
        before = dict(self._aliases)
        self._visit_block(node.body)
        body_state = self._aliases
        self._aliases = dict(before)
        self._visit_block(node.orelse)
        else_state = self._aliases
        self._aliases = self._merge(before, body_state, else_state)

    def visit_IfExp(self, node: ast.IfExp) -> None:
        self.visit(node.test)
        before = dict(self._aliases)
        self._visit_expression(node.body)
        body_state = self._aliases
        self._aliases = dict(before)
        self._visit_expression(node.orelse)
        else_state = self._aliases
        self._aliases = self._merge(before, body_state, else_state)

    def visit_Try(self, node: ast.Try) -> None:
        before = dict(self._aliases)
        self._visit_block(node.body)
        branch_states = [self._aliases]
        for handler in node.handlers:
            self._aliases = dict(branch_states[0])
            if handler.type is not None:
                self.visit(handler.type)
            if handler.name:
                # ``except E as name`` binds only *inside* the handler.
                self._bind(handler.name, UNKNOWN)
            self._visit_block(handler.body)
            branch_states.append(self._aliases)
        # The ``else`` block only runs when no handler did.
        self._aliases = dict(branch_states[0])
        self._visit_block(node.orelse)
        branch_states.append(self._aliases)

        # Entry state for ``finally`` is the merge of every way of reaching it;
        # ``finally`` may itself rebind names (e.g. clean up a callback).
        self._aliases = self._merge(before, *branch_states)
        self._visit_block(node.finalbody)
        self._aliases = self._merge(before, *branch_states, self._aliases)

    def visit_Match(self, node: ast.Match) -> None:
        self.visit(node.subject)
        before = dict(self._aliases)
        states: list[dict[str, str]] = [dict(before)]
        for case in node.cases:
            self._aliases = dict(before)
            self.visit(case.pattern)
            if case.guard is not None:
                self.visit(case.guard)
            self._visit_block(case.body)
            states.append(self._aliases)
        self._aliases = self._merge(*states)

    # --- loops: body may run zero times, may run many ---------------------

    def visit_For(self, node: ast.For) -> None:
        self.visit(node.iter)
        before = dict(self._aliases)
        self._bind_targets(node.target, UNKNOWN)
        self._visit_block(node.body)
        body_state = self._aliases
        self._aliases = dict(before)
        self._visit_block(node.orelse)
        self._aliases = self._merge(before, body_state, self._aliases)

    visit_AsyncFor = visit_For  # type: ignore[assignment]

    def visit_While(self, node: ast.While) -> None:
        self.visit(node.test)
        before = dict(self._aliases)
        self._visit_block(node.body)
        body_state = self._aliases
        self._aliases = dict(before)
        self._visit_block(node.orelse)
        self._aliases = self._merge(before, body_state, self._aliases)

    def visit_With(self, node: ast.With) -> None:
        for item in node.items:
            self.visit(item.context_expr)
            if item.optional_vars is not None:
                self._bind_targets(item.optional_vars, UNKNOWN)
        self._visit_block(node.body)

    visit_AsyncWith = visit_With  # type: ignore[assignment]

    # --- imports ----------------------------------------------------------

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            if self._is_blocked_module(alias.name):
                self._add("blocked-import", node.lineno, alias.name)
            self._bind(alias.asname or alias.name.split(".")[0], alias.name)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        if node.level and not module:
            module = "." * node.level
        if node.module and self._is_blocked_module(node.module):
            self._add("blocked-import", node.lineno, node.module)
        for alias in node.names:
            if alias.name == "*":
                self._add(
                    "wildcard-import",
                    node.lineno,
                    f"from {module or '.'} import * hides every restricted name",
                )
                if module:
                    self._wildcard_modules.add(module)
                continue
            target = f"{module}.{alias.name}".lstrip(".") or alias.name
            self._bind(alias.asname or alias.name, target)

    # --- assignments ------------------------------------------------------

    def visit_Assign(self, node: ast.Assign) -> None:
        self.visit(node.value)
        resolved = self._resolve(node.value)
        for target in node.targets:
            if isinstance(target, ast.Name):
                # An unconditional rebinding replaces the previous value. When
                # the new value cannot be attributed to a callable, the name
                # becomes unknown rather than keeping a stale restriction.
                self._bind(target.id, resolved)
            else:
                self._bind_targets(target, UNKNOWN)
                self.visit(target)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self.visit(node.value)
            canonical = self._resolve(node.value)
        else:
            canonical = UNKNOWN
        if isinstance(node.target, ast.Name):
            self._bind(node.target.id, canonical)
        else:
            self._bind_targets(node.target, UNKNOWN)
            self.visit(node.target)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        self.visit(node.value)
        if isinstance(node.target, ast.Name):
            self._bind(node.target.id, UNKNOWN)
        else:
            self.visit(node.target)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        self.visit(node.value)
        if isinstance(node.target, ast.Name):
            self._bind(node.target.id, self._resolve(node.value))

    # --- calls ------------------------------------------------------------

    def visit_Call(self, node: ast.Call) -> None:
        canonical = self._canonical(node.func)
        if self._is_blocked_call(canonical):
            self._add("blocked-call", node.lineno, canonical.lstrip("?"))
        if canonical in _DYNAMIC_CALLABLES or canonical.endswith("." + "__import__"):
            target = self._fold_literal(node.args[0]) if node.args else None
            if isinstance(target, str) and self._is_blocked_module(target):
                self._add("blocked-call", node.lineno, f"__import__({target!r})")
        if canonical.split(".")[-1] in {"getattr", "setattr"} and len(node.args) >= 2:
            self._check_reflective(node)
        if canonical in {"builtins.getattr", "getattr"} and len(node.args) >= 2:
            self._check_reflective(node)
        self.generic_visit(node)

    def _check_reflective(self, node: ast.Call) -> None:
        receiver = self._canonical(node.args[0])
        attribute = self._fold_literal(node.args[1])
        if not isinstance(attribute, str):
            return
        candidate = f"{receiver}.{attribute}"
        if self._is_blocked_call(candidate):
            self._add("blocked-call", node.lineno, candidate.lstrip("?"))

    # --- subscripts that reveal restricted attributes ---------------------

    def visit_Subscript(self, node: ast.Subscript) -> None:
        key = self._fold_literal(node.slice)
        if isinstance(key, str):
            context = self._subscript_context(node)
            if context is _MODULES and self._is_blocked_module(key):
                self._add("blocked-import", node.lineno, f"dynamic import {key!r}")
            elif context is not None:
                # A restricted attribute reached through a computed name is
                # reported even when the receiver is unknown (`?system`).
                candidate = f"{context}.{key}" if context else key
                if self._is_blocked_call(candidate) or self._is_blocked_call(f"?{key}"):
                    self._add("blocked-call", node.lineno, f"dynamic attribute {key!r}")
        self.generic_visit(node)

    def _subscript_context(self, node: ast.Subscript) -> str | None:
        """Module/namespace a computed subscript reads from, if statically known.

        Returns ``""`` for the builtins namespace, a dotted module name for
        ``x.__dict__``/``vars(x)``, or ``None`` when the receiver is opaque.
        """
        container = node.value
        if isinstance(container, ast.Attribute) and container.attr == "__dict__":
            return self._canonical(container.value).lstrip("?")
        if isinstance(container, ast.Attribute) and container.attr == "modules":
            return _MODULES  # sentinel handled by the caller
        if isinstance(container, ast.Call):
            name = _plain_name(container.func)
            if name in {"globals", "locals"}:
                # globals()['__builtins__'] is the builtins namespace itself.
                inner = self._fold_literal(node.slice)
                return "" if inner == "__builtins__" else name
            if name == "vars" and container.args:
                return self._canonical(container.args[0]).lstrip("?")
            if name == "__builtins__":
                return ""
        if isinstance(container, ast.Subscript) and container.value is not None:
            inner_context = self._subscript_context(container)
            if inner_context == "":
                return ""
            return None
        return None

    def visit_Attribute(self, node: ast.Attribute) -> None:
        # Merely *reading* ``os.system`` is not executable harm; the call site
        # reports it. Reading it *inside a container* is different: a list,
        # tuple or dict holding a restricted callable can be indexed later
        # without any name the alias layer can follow, so it is reported here.
        imported = _imported_alias_name(node)
        canonical = imported or self._canonical(node)
        if self._is_blocked_call(canonical) and self._in_container(node):
            self._add("blocked-call", node.lineno, canonical.lstrip("?"))
        self.generic_visit(node)

    @staticmethod
    def _in_container(node: ast.AST) -> bool:
        """True when a restricted callable is *stored* rather than just read.

        Storing it in a collection, a class/attribute target, a comprehension
        or a call argument lets it be retrieved later without a name the alias
        layer can follow. A plain local rebinding is different: the alias layer
        tracks it and can clear it, so it is not reported here.
        """
        parent = getattr(node, "_safeexec_parent", None)
        if parent is None:
            return False
        if isinstance(parent, (ast.List, ast.Tuple, ast.Set, ast.Dict, ast.keyword)):
            return True
        if isinstance(parent, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            return True
        if isinstance(parent, (ast.Yield, ast.YieldFrom)):
            return True
        if isinstance(parent, ast.Call) and node in parent.args:
            return True
        grandparent = getattr(parent, "_safeexec_parent", None)
        for candidate in (parent, grandparent):
            if isinstance(candidate, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                if any(not isinstance(t, ast.Name) for t in _assign_targets(candidate)):
                    return True
                # ``class C: x = os.system`` binds a *class attribute*: reachable
                # as ``C.x`` from anywhere, and never a trackable local name.
                if isinstance(getattr(candidate, "_safeexec_parent", None), ast.ClassDef):
                    return True
        return False

    # --- literals ---------------------------------------------------------

    def visit_Constant(self, node: ast.Constant) -> None:
        # Literal findings are already emitted by ``_index_tree``; constants
        # have no children, so visiting stops here.
        return

    # --- name binding -----------------------------------------------------

    def _bind(self, name: str, canonical: str) -> None:
        # Record the new value even when it is unknown: an unconditional
        # rebinding must clear a stale restriction instead of preserving it.
        if canonical and canonical != UNKNOWN:
            self._aliases[name] = canonical
        else:
            self._aliases.pop(name, None)

    def _bind_targets(self, target: ast.AST, canonical: str) -> None:
        if isinstance(target, ast.Name):
            self._bind(target.id, canonical)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                self._bind_targets(element, UNKNOWN)
        elif isinstance(target, ast.Starred):
            self._bind_targets(target.value, UNKNOWN)

    def _merge(self, *states: Mapping[str, str]) -> dict[str, str]:
        """Merge branch states, keeping any restriction reachable on a path."""
        if not states:
            return {}
        merged: dict[str, str] = {}
        keys: set[str] = set()
        for state in states:
            keys.update(state)
        for name in keys:
            values = [state[name] for state in states if name in state]
            restricted = next((v for v in values if self._is_restricted(v)), None)
            merged[name] = restricted or (values[0] if values else UNKNOWN)
        return merged

    def _is_restricted(self, canonical: str) -> bool:
        if not canonical or canonical == UNKNOWN:
            return False
        if self._is_blocked_call(canonical.lstrip("?")):
            return True
        return self._is_blocked_module(canonical.lstrip("?"))

    # --- expression resolution -------------------------------------------

    def _lookup(self, name: str) -> str:
        """Resolve a bound name; unbound names keep their source identity."""
        if name in self._aliases:
            return self._aliases[name]
        return name

    def _canonical(self, node: ast.AST) -> str:
        """Best-effort canonical name for an expression; ``?`` marks uncertainty."""
        if isinstance(node, ast.Name):
            return self._lookup(node.id)
        if isinstance(node, ast.Attribute):
            base = self._canonical(node.value)
            return f"{base}.{node.attr}"
        if isinstance(node, ast.Call):
            callee = self._canonical(node.func)
            if callee in {"getattr", "builtins.getattr"} and len(node.args) >= 2:
                receiver = self._canonical(node.args[0])
                attribute = self._fold_literal(node.args[1])
                if isinstance(attribute, str):
                    return f"{receiver}.{attribute}"
            if callee in _DYNAMIC_CALLABLES:
                target = self._fold_literal(node.args[0]) if node.args else None
                return target if isinstance(target, str) else UNKNOWN
            return UNKNOWN
        if isinstance(node, ast.Subscript):
            return self._canonical_subscript(node)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            folded = self._fold_literal(node)
            return folded if isinstance(folded, str) else UNKNOWN
        if isinstance(node, ast.JoinedStr):
            folded = self._fold_string(node)
            return folded if folded is not None else UNKNOWN
        return UNKNOWN

    def _canonical_subscript(self, node: ast.Subscript) -> str:
        key = self._fold_literal(node.slice)
        if not isinstance(key, str):
            return UNKNOWN
        receiver = self._canonical(node.value)
        container = receiver.split(".")[0]
        if container in {"vars", "globals", "locals"} and receiver == container:
            return key
        if container in _BUILTIN_MARKERS or receiver.endswith("__dict__"):
            return key
        if container == "sys" and receiver.endswith("modules"):
            return key
        return UNKNOWN

    _resolve = _canonical

    def _index_tree(self, tree: ast.AST) -> None:
        """Single pre-pass: record parents and report blocked literal fragments.

        Walking once is enough for both jobs. The literal sweep catches pieces
        the visitor never reaches (docstrings, decorator arguments) and folded
        fragments such as ``'/etc/sh' + 'adow'`` without executing anything.
        """
        for parent in ast.walk(tree):
            for child in ast.iter_child_nodes(parent):
                child._safeexec_parent = parent  # type: ignore[attr-defined]
            if isinstance(parent, ast.Constant):
                self._check_literal(parent.value, getattr(parent, "lineno", 0))
            elif isinstance(parent, ast.BinOp) and isinstance(parent.op, ast.Add):
                folded = self._fold_literal(parent)
                if isinstance(folded, (str, bytes)):
                    self._check_literal(folded, getattr(parent, "lineno", 0))
            elif isinstance(parent, ast.JoinedStr):
                folded = self._fold_string(parent)
                if folded is not None:
                    self._check_literal(folded, getattr(parent, "lineno", 0))

    def _check_literal(self, value: Any, line: int) -> None:
        if isinstance(value, bytes):
            value = value.decode("utf-8", errors="replace")
        if not isinstance(value, str):
            return
        for literal in self.rules.blocked_literals:
            if literal in value:
                self._add("blocked-literal", line, literal)

    # --- literal folding (never executes the input) ----------------------

    def _fold_literal(self, node: ast.AST | None) -> Any:
        """Fold constant expressions using only constant-safe nodes."""
        if node is None:
            return None
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = self._fold_literal(node.left)
            right = self._fold_literal(node.right)
            if isinstance(left, (str, bytes)) and isinstance(right, type(left)):
                return left + right
            return None
        if isinstance(node, ast.JoinedStr):
            return self._fold_string(node)
        return None

    def _fold_string(self, node: ast.JoinedStr) -> str | None:
        parts = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
            elif isinstance(value, ast.FormattedValue) and value.conversion in {-1, None}:
                inner = self._fold_literal(value.value)
                parts.append(str(inner) if inner is not None else "?")
            else:
                return None
        return "".join(parts)

    # --- misc AST nodes ---------------------------------------------------

    def visit_Expr(self, node: ast.Expr) -> None:
        self.visit(node.value)

    def _visit_block(self, statements: Iterable[ast.stmt]) -> None:
        for statement in statements:
            self.visit(statement)

    def _visit_expression(self, node: ast.AST) -> None:
        self.visit(node)


class _BudgetExceeded(RuntimeError):
    """Raised internally when the AST node budget is exhausted."""


def _imported_alias_name(node: ast.Attribute) -> str:
    """Resolve ``module.attr`` using the module's real name, not a local alias.

    Imports are collected while walking, but a function or class body may be
    visited before the enclosing ``import`` binds its alias. Falling back to the
    canonical module path makes the check independent of visit order.
    """
    base = node.value
    if isinstance(base, ast.Name):
        return f"{base.id}.{node.attr}"
    if isinstance(base, ast.Attribute):
        return f"{_imported_alias_name(base)}.{node.attr}"
    return ""


def _assign_targets(node: ast.Assign | ast.AnnAssign | ast.AugAssign) -> list[ast.AST]:
    if isinstance(node, ast.Assign):
        return list(node.targets)
    return [node.target]


def _iter_arguments(args: ast.arguments) -> Iterable[str]:
    for argument in list(args.posonlyargs) + list(args.args) + list(args.kwonlyargs):
        yield argument.arg
    if args.vararg:
        yield args.vararg.arg
    if args.kwarg:
        yield args.kwarg.arg


def count_nodes(tree: ast.AST) -> int:
    """Return the number of AST nodes (useful for benchmarks and tests)."""
    return sum(1 for _ in ast.walk(tree))


def load_rules(path: Path | str | None = None) -> PolicyRules:
    """Load rules from ``path`` or the packaged default."""
    from .resources import packaged_rules_path

    return PolicyRules.load(Path(path) if path is not None else packaged_rules_path())


def evaluate_source(source: str | bytes, rules_path: Path | str | None = None) -> list[Finding]:
    """Convenience wrapper used by tools and tests."""
    evaluator = StaticPolicyEvaluator(load_rules_path(rules_path), rules=load_rules(rules_path))
    return evaluator.evaluate(source)


def load_rules_path(rules_path: Path | str | None) -> Path:
    from .resources import packaged_rules_path

    return Path(rules_path) if rules_path is not None else packaged_rules_path()


def decode_source(raw: bytes, strict: bool = False) -> str:
    """Decode Python source honouring PEP 263 cookies and a UTF-8 BOM.

    With ``strict=True`` an undecodable file raises :class:`UnicodeDecodeError`
    so callers can report a controlled denial instead of parsing mojibake.
    """
    try:
        encoding, _ = tokenize.detect_encoding(io.BytesIO(raw).readline)
        return raw.decode(encoding)
    except (SyntaxError, LookupError):
        if strict:
            return raw.decode("utf-8")
        return raw.decode("utf-8-sig", errors="replace")


def _plain_name(node: ast.AST) -> str:
    """Return the dotted source name of a pure Name/Attribute chain."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _plain_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


__all__ = [
    "MAX_AST_NODES",
    "MAX_SOURCE_BYTES",
    "RULES_FILENAME",
    "UNKNOWN",
    "Finding",
    "PolicyRules",
    "StaticPolicyEvaluator",
    "count_nodes",
    "decode_source",
    "evaluate_source",
    "load_rules",
    "load_rules_path",
]
