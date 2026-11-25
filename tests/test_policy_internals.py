"""Unit tests for policy internals: rule loading, limits and AST corners.

These cover the fail-closed edges that the corpora cannot reach: malformed
policy documents, exhausted budgets, unparsable bytes and unusual syntax.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from safeexec.policy import (
    MAX_AST_NODES,
    MAX_SOURCE_BYTES,
    Finding,
    PolicyRules,
    StaticPolicyEvaluator,
    count_nodes,
    decode_source,
    evaluate_source,
    load_rules,
    load_rules_path,
)
from safeexec.resources import packaged_rules_path


@pytest.fixture
def rules_file(tmp_path) -> Path:
    path = tmp_path / "rules.yaml"
    path.write_text(
        "version: test-1\n"
        "blocked_imports: [ctypes]\n"
        "blocked_calls: [os.system, eval]\n"
        "blocked_literals: [/etc/shadow]\n"
        "max_source_bytes: 200\n"
        "max_ast_nodes: 50\n",
        encoding="utf-8",
    )
    return path


# ---------------------------------------------------------------- rule loading


def test_rules_load_metadata(rules_file: Path) -> None:
    rules = PolicyRules.load(rules_file)
    assert rules.version == "test-1"
    assert rules.blocked_imports == frozenset({"ctypes"})
    assert rules.max_source_bytes == 200
    assert rules.max_ast_nodes == 50


def test_rules_default_limits_when_absent(tmp_path: Path) -> None:
    path = tmp_path / "r.yaml"
    path.write_text("blocked_calls: [eval]\n", encoding="utf-8")
    rules = PolicyRules.load(path)
    assert rules.max_source_bytes == MAX_SOURCE_BYTES
    assert rules.max_ast_nodes == MAX_AST_NODES


def test_empty_entries_are_ignored(tmp_path: Path) -> None:
    path = tmp_path / "r.yaml"
    path.write_text("blocked_calls: ['', eval]\n", encoding="utf-8")
    assert PolicyRules.load(path).blocked_calls == frozenset({"eval"})


@pytest.mark.parametrize(
    "document",
    [
        "just a string",
        "blocked_calls: {a: 1}",
        "blocked_calls: [1, 2]",
        "max_source_bytes: -1",
        "max_source_bytes: true",
        "max_ast_nodes: 0",
    ],
)
def test_invalid_rules_are_rejected(tmp_path: Path, document: str) -> None:
    path = tmp_path / "r.yaml"
    path.write_text(document + "\n", encoding="utf-8")
    with pytest.raises(ValueError):
        PolicyRules.load(path)


def test_empty_rules_document_is_allowed(tmp_path: Path) -> None:
    path = tmp_path / "r.yaml"
    path.write_text("", encoding="utf-8")
    rules = PolicyRules.load(path)
    assert rules.blocked_calls == frozenset()


def test_packaged_rules_version() -> None:
    assert load_rules().version == "safeexec-1"
    assert load_rules_path(None) == packaged_rules_path()


# ---------------------------------------------------------------------- limits


def test_oversized_source_is_denied(rules_file: Path) -> None:
    evaluator = StaticPolicyEvaluator(rules_file)
    findings = evaluator.evaluate("x = 1\n" * 100)
    assert findings[0].rule == "oversized-source"


def test_ast_budget_is_enforced(rules_file: Path) -> None:
    evaluator = StaticPolicyEvaluator(rules_file)
    # The budget counts visited nodes, so a long chain exceeds it quickly.
    findings = evaluator.evaluate(" + ".join(["1"] * 40))
    assert any(f.rule == "complexity-budget" for f in findings)


def test_bytes_input_is_decoded(rules_file: Path) -> None:
    evaluator = StaticPolicyEvaluator(rules_file)
    assert evaluator.evaluate(b"x = 1\n") == []


def test_bom_is_tolerated(rules_file: Path) -> None:
    evaluator = StaticPolicyEvaluator(rules_file)
    assert evaluator.evaluate("\ufeffx = 1\n") == []


def test_invalid_syntax_is_reported(rules_file: Path) -> None:
    evaluator = StaticPolicyEvaluator(rules_file)
    assert evaluator.evaluate("def broken(")[0].rule == "invalid-python"


def test_null_bytes_do_not_crash(rules_file: Path) -> None:
    evaluator = StaticPolicyEvaluator(rules_file)
    findings = evaluator.evaluate("x = 1\x00\n")
    assert findings and findings[0].rule in {"invalid-python", "unparsable-source"}


# ------------------------------------------------------------------ AST corners


@pytest.mark.parametrize(
    "code",
    [
        "import ctypes",
        "from ctypes import CDLL",
        "import ctypes.util",
        "from . import relative",
        "def f(*args, **kwargs):\n    return args, kwargs",
        "async def f():\n    async with open('x') as h:\n        pass",
        "async def f():\n    async for i in g():\n        pass",
        "class C(Base, metaclass=Meta):\n    pass",
        "@decorator\ndef f():\n    pass",
        "x: int",
        "x: int = 5",
        "x += 1",
        "if (y := 2) > 1:\n    pass",
        "match value:\n    case {'k': v}:\n        pass",
        "for a, *rest in items:\n    pass",
        "with a as (b, c):\n    pass",
        "d = {**other}",
        "f(*args, **kwargs)",
        "x = a if b else c",
        "x = [i for i in range(3) if i]",
        "x = {k: v for k, v in items}",
        "x = (i for i in range(3))",
        "x = {1, 2, 3}",
        "x = b'bytes'",
        "x = f'{a}'",
        "x = f'{a!r:{w}}'",
        "x = 1e309",
        "x = ...",
        "del x",
        "global x",
        "nonlocal_ = 1",
        "assert True",
        "raise ValueError from None",
        "yield_only = (yield)" if False else "def g():\n    yield from range(3)",
    ],
)
def test_unusual_but_valid_syntax_is_handled(rules_file: Path, code: str) -> None:
    evaluator = StaticPolicyEvaluator(rules_file)
    findings = evaluator.evaluate(code)
    assert all(isinstance(f, Finding) for f in findings)


def test_count_nodes_matches_ast_walk(rules_file: Path) -> None:
    import ast

    tree = ast.parse("x = 1 + 2\n")
    assert count_nodes(tree) == sum(1 for _ in ast.walk(tree))


def test_evaluate_source_helper_uses_packaged_rules() -> None:
    assert evaluate_source("print(1)") == []
    assert evaluate_source("import os\nos.system('id')")


def test_decode_source_handles_coding_cookie() -> None:
    raw = "# -*- coding: latin-1 -*-\n# café\n".encode("latin-1")
    assert "café" in decode_source(raw)


def test_decode_source_strict_raises_on_bad_bytes() -> None:
    with pytest.raises(UnicodeDecodeError):
        decode_source(b"\xff\xfe\x00", strict=True)


def test_decode_source_lenient_replaces() -> None:
    assert "\ufffd" in decode_source(b"\xff\xfe\x00")
