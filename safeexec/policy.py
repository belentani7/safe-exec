from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

import yaml


@dataclass(frozen=True)
class Finding:
    rule: str
    line: int
    detail: str


class StaticPolicyEvaluator(ast.NodeVisitor):
    def __init__(self, rules_path: Path):
        rules = yaml.safe_load(rules_path.read_text(encoding="utf-8")) or {}
        self.blocked_calls = set(rules.get("blocked_calls", []))
        self.blocked_imports = set(rules.get("blocked_imports", []))
        self.blocked_literals = tuple(rules.get("blocked_literals", []))
        self.findings: list[Finding] = []
        self.aliases: dict[str, str] = {}

    def evaluate(self, source: str) -> list[Finding]:
        self.findings.clear()
        self.aliases.clear()
        try:
            tree = ast.parse(source)
        except SyntaxError as exc:
            return [Finding("invalid-python", exc.lineno or 0, str(exc))]
        self.visit(tree)
        return list(self.findings)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            # Resolve imports such as `import os as operating_system`.
            # Importing a dotted module binds its root unless renamed.
            self.aliases[alias.asname or alias.name.split(".")[0]] = (
                alias.name if alias.asname else alias.name.split(".")[0]
            )
            root = alias.name.split(".")[0]
            if root in self.blocked_imports:
                self.findings.append(Finding("blocked-import", node.lineno, alias.name))
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        root = (node.module or "").split(".")[0]
        if root in self.blocked_imports:
            self.findings.append(Finding("blocked-import", node.lineno, node.module or ""))
        for alias in node.names:
            if alias.name != "*":
                self.aliases[alias.asname or alias.name] = (
                    f"{node.module}.{alias.name}" if node.module else alias.name
                )
        self.generic_visit(node)

    def _canonical_call(self, name: str) -> str:
        """Resolve imports and simple function assignments; not arbitrary data flow."""
        root, dot, rest = name.partition(".")
        canonical = self.aliases.get(root, root) + (dot + rest if dot else "")
        if canonical.startswith("builtins."):
            short = canonical.removeprefix("builtins.")
            if short in self.blocked_calls:
                return short
        return canonical

    def visit_Assign(self, node: ast.Assign) -> None:
        # Simple named aliases are a common way to disguise dangerous calls.
        # Never evaluate the assignment: inspect syntax only.
        self.visit(node.value)
        name = self._call_name(node.value)
        canonical = self._canonical_call(name) if name else ""
        for target in node.targets:
            if isinstance(target, ast.Name):
                if canonical:
                    self.aliases[target.id] = canonical
                else:
                    self.aliases.pop(target.id, None)
            else:
                self.visit(target)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self.visit(node.value)
        if isinstance(node.target, ast.Name):
            name = self._call_name(node.value) if node.value is not None else ""
            canonical = self._canonical_call(name) if name else ""
            if canonical:
                self.aliases[node.target.id] = canonical
            else:
                self.aliases.pop(node.target.id, None)
        else:
            self.visit(node.target)

    def visit_Call(self, node: ast.Call) -> None:
        canonical = self._canonical_call(self._call_name(node.func))
        if canonical in self.blocked_calls:
            self.findings.append(Finding("blocked-call", node.lineno, canonical))
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        if isinstance(node.value, str):
            for literal in self.blocked_literals:
                if literal in node.value:
                    self.findings.append(Finding("blocked-literal", node.lineno, literal))

    @staticmethod
    def _call_name(node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            base = StaticPolicyEvaluator._call_name(node.value)
            return f"{base}.{node.attr}" if base else node.attr
        return ""
