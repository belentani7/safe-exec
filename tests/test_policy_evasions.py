"""Adversarial corpus for the static policy.

Every snippet here is a real bypass pattern against the v1.0 analyser. The
expected outcome is a finding; silently passing any of these is a regression.
"""

from __future__ import annotations

import pytest
from safeexec.policy import StaticPolicyEvaluator
from safeexec.resources import packaged_rules_path


@pytest.fixture
def evaluator() -> StaticPolicyEvaluator:
    return StaticPolicyEvaluator(packaged_rules_path())


WILDCARD = [
    "from os import *\nsystem('id')",
    "from subprocess import *\ncall(['id'])",
    "from shutil import *\nrmtree('/')",
]

DYNAMIC_IMPORT = [
    "__import__('os').system('id')",
    "getattr(__import__('os'), 'system')('id')",
    "import importlib\nimportlib.import_module('os').system('id')",
    "from builtins import __import__ as imp\nimp('os').system('id')",
    "import builtins\nbuiltins.__import__('subprocess')",
    "importlib = __import__('importlib')\nimportlib.import_module('os')",
]

REFLECTIVE = [
    "import os\nos.__dict__['system']('id')",
    "import os\nvars(os)['system']('id')",
    "globals()['__builtins__']['eval']('1')",
    "import sys\nsys.modules['os'].system('id')",
    "import os\nsetattr(os, 'system_', os.system)",
]

INDIRECTION = [
    "import os\nfor f in [os.system]:\n    f('id')",
    "import os\nwith open('x') as f:\n    g = os.system\ng('id')",
    "import os\ntry:\n    f = print\nexcept Exception:\n    f = os.system\nf('id')",
    "import os\nxs = [os.system for _ in range(1)]\nxs[0]('id')",
    "import os\nclass C:\n    x = os.system\nC.x('id')",
    "import functools, os\nfunctools.partial(os.system, 'id')()",
    "import os\nf = lambda: os.system\nf()('id')",
    "import os\nd = {'run': os.system}\nd['run']('id')",
]

LITERAL_FRAGMENTS = [
    "open('/etc/sh' + 'adow')",
    "p = '/' + 'etc' + '/shadow'\nopen(p)",
    "open(f'/etc/{\"shadow\"}')",
    "open(b'/etc/shadow')",
]

OBFUSCATED_CALLS = [
    "import os\nos.popen('id')",
    "import os\nos.spawnv(os.P_WAIT, '/bin/id', [])",
    "import os\nos.execv('/bin/sh', ['sh'])",
    "import os\nos.fork()",
    "import importlib\nimportlib.import_module('pickle').loads(b'x')",
    "import marshal\nmarshal.loads(b'x')",
]


@pytest.mark.parametrize(
    "code", WILDCARD + DYNAMIC_IMPORT + REFLECTIVE + INDIRECTION + LITERAL_FRAGMENTS + OBFUSCATED_CALLS
)
def test_known_evasion_is_reported(evaluator: StaticPolicyEvaluator, code: str) -> None:
    findings = evaluator.evaluate(code)
    assert findings, f"evasion slipped through: {code!r}"


def test_wildcard_import_has_its_own_rule(evaluator: StaticPolicyEvaluator) -> None:
    findings = evaluator.evaluate("from os import *\nsystem('id')")
    assert any(f.rule == "wildcard-import" for f in findings)


def test_literal_fragment_reports_the_full_needle(evaluator: StaticPolicyEvaluator) -> None:
    findings = evaluator.evaluate("open('/etc/sh' + 'adow')")
    assert any(f.rule == "blocked-literal" and f.detail == "/etc/shadow" for f in findings)


@pytest.mark.parametrize(
    "code",
    [
        "import math\nprint(math.sqrt(9))",
        "class A:\n    def __init__(self):\n        self.v = 1\n    def get(self):\n        return self.v",
        "with open('data.txt') as handle:\n    print(handle.read())",
        "def g():\n    yield 1\nprint(list(g()))",
        "import os\nprint(os.path.join('a', 'b'))",
        "import json\nprint(json.dumps({'a': [1, 2]}))",
        "def f():\n    'docstring only'\n    return 1",
        "import asyncio\nasync def m():\n    await asyncio.sleep(0)",
        "xs = [i * i for i in range(10)]\nprint(sum(xs))",
        "def outer():\n    def inner():\n        return 2\n    return inner()",
        "import os\nrun = os.system\nrun = print\nrun('hello')",
        "import math\nx = getattr(math, 'sqrt')(9)",
    ],
)
def test_legitimate_code_is_not_flagged(evaluator: StaticPolicyEvaluator, code: str) -> None:
    assert evaluator.evaluate(code) == []


def test_decorated_function_defaults_are_still_inspected(evaluator: StaticPolicyEvaluator) -> None:
    code = "import os\ndef f(x=os.system('id')):\n    return x"
    assert evaluator.evaluate(code)


def test_rebinding_inside_class_body_does_not_clear_alias(evaluator: StaticPolicyEvaluator) -> None:
    code = "import os\nclass C:\n    run = os.system\nprint('ok')\nC.run('id')"
    assert evaluator.evaluate(code)


def test_safe_rebinding_after_branch_clears_restriction(evaluator: StaticPolicyEvaluator) -> None:
    code = "import os\nfn = os.system\nif unknown:\n    fn = os.system\nfn = print\nfn('safe')"
    assert not any(f.rule == "blocked-call" for f in evaluator.evaluate(code))


def test_findings_are_deterministic_and_deduplicated(evaluator: StaticPolicyEvaluator) -> None:
    code = "import os\nos.system('a')\nos.system('b')\nprint(os.system)"
    first = evaluator.evaluate(code)
    second = evaluator.evaluate(code)
    assert first == second
    assert len({(f.rule, f.line, f.detail) for f in first}) == len(first)


def test_state_does_not_leak_between_scans(evaluator: StaticPolicyEvaluator) -> None:
    evaluator.evaluate("import os as o\no.system('id')")
    assert evaluator.evaluate("o.system('id')") == []
