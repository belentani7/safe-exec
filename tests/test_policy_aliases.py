"""Policy regressions for aliasing of imports and repeated source evaluations."""

from pathlib import Path

import pytest

from safeexec.policy import StaticPolicyEvaluator


@pytest.fixture
def evaluator(tmp_path: Path):
    rules = tmp_path / "rules.yaml"
    rules.write_text(
        "blocked_imports: [ctypes]\n"
        "blocked_calls: [os.system, subprocess.run, eval]\n"
        "blocked_literals: [/etc/shadow]\n",
        encoding="utf-8",
    )
    return StaticPolicyEvaluator(rules)


@pytest.mark.parametrize("code", [
    "import os as operating_system\noperating_system.system('echo hello')",
    "from os import system as invoke\ninvoke('echo hello')",
    "import subprocess as process\nprocess.run(['echo', 'hello'])",
    "from subprocess import run as execute\nexecute(['echo', 'hello'])",
])
def test_aliases_cannot_hide_blocked_calls(evaluator, code):
    findings = evaluator.evaluate(code)
    assert any(f.rule == "blocked-call" for f in findings)


def test_aliases_do_not_leak_between_scans(evaluator):
    evaluator.evaluate("import os as o\no.system('echo hello')")
    assert evaluator.evaluate("o.system('echo hello')") == []


def test_safe_code_is_still_allowed(evaluator):
    assert evaluator.evaluate("import math\nprint(math.sqrt(9))") == []


def test_blocked_import_still_works(evaluator):
    assert any(f.rule == "blocked-import" for f in evaluator.evaluate("import ctypes as c"))


def test_invalid_python_still_rejected(evaluator):
    assert evaluator.evaluate("def broken(")[0].rule == "invalid-python"

@pytest.mark.parametrize("code", [
    "from builtins import eval as e\ne('2+2')",
    "import builtins as b\nb.eval('2+2')",
    "import os as o\nrun = o.system\nrun('echo')",
    "from os import system as invoke\nexecute = invoke\nexecute('echo')",
    "import os\ncall: object = os.system\ncall('echo')",
])
def test_builtin_and_assignment_aliases_are_inspected(evaluator, code):
    assert any(f.rule == "blocked-call" for f in evaluator.evaluate(code))


def test_alias_rebinding_to_safe_symbol_clears_stale_binding(evaluator):
    code = "import os\nrun = os.system\nrun = print\nrun('hello')"
    assert not any(f.rule == "blocked-call" for f in evaluator.evaluate(code))


def test_scanner_reports_new_simple_alias_without_running_it(evaluator):
    findings = evaluator.evaluate("import os\nfn = os.system\nfn('never execute')")
    assert [f.detail for f in findings if f.rule == "blocked-call"] == ["os.system"]

@pytest.mark.parametrize("code", [
    "import os as operating\ngetattr(operating, 'system')('echo')",
    "import os\ncall = getattr(os, 'system')\ncall('echo')",
    "from builtins import getattr as attr\nimport subprocess as sp\nattr(sp, 'run')(['whoami'])",
    "import builtins\ne = getattr(builtins, 'eval')\ne('1 + 1')",
])
def test_literal_getattr_does_not_disguise_blocked_calls(evaluator, code):
    assert any(result.rule == "blocked-call" for result in evaluator.evaluate(code))


def test_computed_getattr_is_not_executed_by_static_policy(evaluator):
    # Arbitrary expressions must remain inert at analysis time.
    code = "import math\nx = getattr(math, 's' + 'qrt')(9)"
    assert evaluator.evaluate(code) == []

