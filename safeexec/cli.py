from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from .orchestrator import run
from .policy import Finding, StaticPolicyEvaluator


def main() -> None:
    parser = argparse.ArgumentParser(prog="safe-exec")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("run", "scan", "hash"):
        command = sub.add_parser(name)
        command.add_argument("file", type=Path)
        if name == "scan":
            command.add_argument(
                "--json", action="store_true", dest="json_output",
                help="emit machine-readable scan findings and SHA-256",
            )
    args = parser.parse_args()
    if not args.file.is_file():
        parser.error(f"file not found: {args.file}")
    if args.command == "hash":
        print(hashlib.sha256(args.file.read_bytes()).hexdigest())
        return
    if args.command == "scan":
        # Hash and parse exactly the same bytes: a scan never executes the input.
        content = args.file.read_bytes()
        try:
            source = content.decode("utf-8")
        except UnicodeDecodeError:
            findings = [Finding("invalid-encoding", 0, "Expected UTF-8 Python source")]
        else:
            findings = StaticPolicyEvaluator(
                Path(__file__).parents[1] / "rules.yaml"
            ).evaluate(source)
        if args.json_output:
            print(json.dumps({
                "schema_version": 1,
                "file_sha256": hashlib.sha256(content).hexdigest(),
                "allowed": not findings,
                "findings": [
                    {"rule": f.rule, "line": f.line, "detail": f.detail}
                    for f in findings
                ],
            }, ensure_ascii=False))
        else:
            for finding in findings:
                print(f"{finding.rule}:{finding.line}:{finding.detail}")
        raise SystemExit(1 if findings else 0)
    approved, output = run(args.file)
    print(output)
    raise SystemExit(0 if approved else 1)
