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

    def evaluate(self, source: str) -> list[Finding]:
        self.findings.clear()
        try:
            tree = ast.parse(source)
        except SyntaxError as exc:
            return [Finding("invalid-python", exc.lineno or 0, str(exc))]
        self.visit(tree)
        return list(self.findings)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            root = alias.name.split(".")[0]
            if root in self.blocked_imports:
                self.findings.append(Finding("blocked-import", node.lineno, alias.name))
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        root = (node.module or "").split(".")[0]
        if root in self.blocked_imports:
            self.findings.append(Finding("blocked-import", node.lineno, node.module or ""))
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        name = self._call_name(node.func)
        if name in self.blocked_calls:
            self.findings.append(Finding("blocked-call", node.lineno, name))
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
