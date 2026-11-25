"""Command-line interface for SAFE-EXEC.

Commands never execute the inspected file. ``run`` submits it to the signed
consensus protocol; ``scan`` and ``hash`` are purely local.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from . import __version__
from .policy import Finding, PolicyRules, StaticPolicyEvaluator, decode_source
from .resources import packaged_rules_path


def hash_file(path: Path) -> str:
    """Hash file bytes incrementally without loading the whole file."""
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="safe-exec",
        description="Inspect or run a Python file through signed pre-execution consensus.",
    )
    parser.add_argument("--version", action="version", version=f"safe-exec {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    for name, help_text in (
        ("scan", "statically analyse a file without executing it"),
        ("hash", "print the SHA-256 of a file"),
        ("run", "submit a file to the evaluator consensus and sandbox"),
    ):
        command = sub.add_parser(name, help=help_text, description=help_text)
        command.add_argument("file", type=Path, help="Python file to inspect")
        if name == "scan":
            command.add_argument(
                "--json",
                action="store_true",
                dest="json_output",
                help="emit a machine-readable report (schema_version 1)",
            )
            command.add_argument(
                "--rules",
                type=Path,
                default=None,
                help="policy file (defaults to the packaged rules.yaml)",
            )
            command.add_argument(
                "--quiet",
                action="store_true",
                help="print nothing when the file is allowed",
            )
    return parser


def _report_text(findings: list[Finding], path: Path, digest: str, quiet: bool) -> None:
    if not findings:
        if not quiet:
            print(f"allowed  {path}  sha256={digest}")
        return
    blocked = any(f.rule != "blocked-literal" for f in findings)
    header = "denied" if blocked else "review"
    print(f"{header}   {path}  sha256={digest}")
    for finding in findings:
        print(f"  {finding.line:>5}  {finding.rule:<18} {finding.detail}")
    print(
        "\nThis is a static opinion about the source text, not a guarantee of safety.\n"
        "The sandbox and the signed consensus still decide whether it may run.",
        file=sys.stderr,
    )


def _report_json(findings: list[Finding], digest: str) -> str:
    return json.dumps(
        {
            "schema_version": 1,
            "file_sha256": digest,
            "allowed": not findings,
            "findings": [
                {"rule": f.rule, "line": f.line, "detail": f.detail} for f in findings
            ],
        },
        ensure_ascii=False,
        sort_keys=True,
    )


def _scan(path: Path, rules_path: Path | None, as_json: bool, quiet: bool) -> int:
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    rules = PolicyRules.load(rules_path or packaged_rules_path())
    if len(raw) > rules.max_source_bytes:
        findings = [Finding("oversized-source", 0, f"{len(raw)} bytes exceeds policy limit")]
    else:
        try:
            # PEP 263 aware so a BOM or coding cookie is not a syntax error.
            source = decode_source(raw, strict=True)
        except UnicodeDecodeError:
            findings = [Finding("invalid-encoding", 0, "Expected decodable Python source")]
        else:
            findings = StaticPolicyEvaluator(
                rules_path or packaged_rules_path(), rules=rules
            ).evaluate(source)
    if as_json:
        print(_report_json(findings, digest))
    else:
        _report_text(findings, path, digest, quiet)
    return 1 if findings else 0


def main(argv: list[str] | None = None) -> None:
    """Run one command and raise :class:`SystemExit` with its status."""
    raise SystemExit(run_command(argv))


def entrypoint() -> None:
    """Console script: expose the status as the process exit code."""
    raise SystemExit(run_command())


def run_command(argv: list[str] | None = None) -> int:
    """Run one command and return its exit status (0 ok, 1 denied/failed)."""
    parser = _build_parser()
    args = parser.parse_args(argv)
    if not args.file.is_file():
        parser.error(f"file not found: {args.file}")

    if args.command == "hash":
        print(hash_file(args.file))
        return 0
    if args.command == "scan":
        return _scan(args.file, args.rules, args.json_output, args.quiet)

    # ``run`` is imported lazily: it pulls in httpx and the sandbox extras.
    from .orchestrator import run

    approved, output = run(args.file)
    print(output)
    return 0 if approved else 1


if __name__ == "__main__":  # pragma: no cover - module entry point
    raise SystemExit(run_command())
