from __future__ import annotations

import argparse
import hashlib
from pathlib import Path

from .orchestrator import run
from .policy import StaticPolicyEvaluator


def main() -> None:
    parser = argparse.ArgumentParser(prog="safe-exec")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("run", "scan", "hash"):
        command = sub.add_parser(name)
        command.add_argument("file", type=Path)
    args = parser.parse_args()
    if not args.file.is_file():
        parser.error(f"file not found: {args.file}")
    if args.command == "hash":
        print(hashlib.sha256(args.file.read_bytes()).hexdigest())
        return
    if args.command == "scan":
        findings = StaticPolicyEvaluator(Path(__file__).parents[1] / "rules.yaml").evaluate(args.file.read_text(encoding="utf-8"))
        for finding in findings:
            print(f"{finding.rule}:{finding.line}:{finding.detail}")
        raise SystemExit(1 if findings else 0)
    approved, output = run(args.file)
    print(output)
    raise SystemExit(0 if approved else 1)
