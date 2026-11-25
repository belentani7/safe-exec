#!/usr/bin/env python3
"""Reproducible self-audit for SAFE-EXEC.

Runs the adversarial corpus, the false-positive corpus and a quick property
check, then prints a table. Exits non-zero if any evasion slips through or any
legitimate snippet is flagged, so CI can gate on it.

Usage:
    python scripts/audit.py
    python scripts/audit.py --json
    python scripts/audit.py --rules path/to/rules.yaml
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from safeexec.policy import StaticPolicyEvaluator  # noqa: E402
from safeexec.resources import packaged_rules_path  # noqa: E402

EVASIONS: dict[str, str] = {
    "wildcard-import": "from os import *\nsystem('id')",
    "dunder-import": "__import__('os').system('id')",
    "getattr-import": "getattr(__import__('os'), 'system')('id')",
    "dict-subscript": "import os\nos.__dict__['system']('id')",
    "vars-subscript": "import os\nvars(os)['system']('id')",
    "builtins-globals": "globals()['__builtins__']['eval']('1')",
    "sys-modules": "import sys\nsys.modules['os'].system('id')",
    "for-loop-rebind": "import os\nfor f in [os.system]:\n    f('id')",
    "lambda-capture": "import os\nf = lambda: os.system\nf()('id')",
    "partial-capture": "import functools, os\nfunctools.partial(os.system, 'id')()",
    "class-attribute": "import os\nclass C:\n    x = os.system\nC.x('id')",
    "except-rebind": (
        "import os\ntry:\n    f = print\nexcept Exception:\n    f = os.system\nf('id')"
    ),
    "literal-concat": "open('/etc/sh' + 'adow')",
    "fstring-literal": "open(f'/etc/{\"shadow\"}')",
    "importlib": "import importlib\nimportlib.import_module('os').system('id')",
}

LEGITIMATE: dict[str, str] = {
    "math": "import math\nprint(math.sqrt(9))",
    "class": (
        "class A:\n    def __init__(self):\n        self.v = 1\n"
        "    def get(self):\n        return self.v"
    ),
    "generator": "def g():\n    yield 1\nprint(list(g()))",
    "json": "import json\nprint(json.dumps({'a': [1, 2]}))",
    "os-path": "import os\nprint(os.path.join('a', 'b'))",
    "safe-rebind": "import os\nfn = os.system\nfn = print\nfn('hello')",
    "safe-getattr": "import math\nx = getattr(math, 'sqrt')(9)",
    "comprehension": "xs = [i * i for i in range(10)]",
}


def run(rules: Path, as_json: bool) -> int:
    evaluator = StaticPolicyEvaluator(rules)
    missed = []
    flagged = []

    for name, code in EVASIONS.items():
        if not evaluator.evaluate(code):
            missed.append(name)
    for name, code in LEGITIMATE.items():
        if evaluator.evaluate(code):
            flagged.append(name)

    if as_json:
        print(json.dumps(
            {
                "evasions_total": len(EVASIONS),
                "evasions_missed": missed,
                "legitimate_total": len(LEGITIMATE),
                "legitimate_flagged": flagged,
                "ok": not missed and not flagged,
            },
            indent=2,
        ))
    else:
        width = max(len(name) for name in EVASIONS) + 2
        print(f"rules: {rules}")
        print(f"\nEvasion corpus ({len(EVASIONS)} patterns)")
        for name in EVASIONS:
            status = "MISSED" if name in missed else "blocked"
            print(f"  {name:<{width}} {status}")
        print(f"\nFalse-positive corpus ({len(LEGITIMATE)} snippets)")
        for name in LEGITIMATE:
            status = "FLAGGED" if name in flagged else "clean"
            print(f"  {name:<{width}} {status}")
        print()
        if missed:
            print(f"FAIL: {len(missed)} evasion(s) not detected: {', '.join(missed)}")
        if flagged:
            print(f"FAIL: {len(flagged)} legitimate snippet(s) flagged: {', '.join(flagged)}")
        if not missed and not flagged:
            print("OK: every evasion is reported and no legitimate snippet is flagged.")
    return 0 if not missed and not flagged else 1


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="audit.py",
        description="Run the SAFE-EXEC adversarial and false-positive corpora.",
    )
    parser.add_argument("--rules", type=Path, default=None, help="policy file to audit")
    parser.add_argument("--json", action="store_true", help="emit machine-readable results")
    args = parser.parse_args()
    return run(args.rules or packaged_rules_path(), args.json)


if __name__ == "__main__":
    raise SystemExit(main())
