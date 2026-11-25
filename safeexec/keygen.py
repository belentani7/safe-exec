"""Generate the Ed25519 identities used by every SAFE-EXEC role.

Keys never leave the host they were created on. The brute-force of a private
key is infeasible, but a leaked one forges every vote that identity is trusted
for: in production these belong in a KMS/HSM, not on disk.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from .crypto import generate_keypair

NODES = ("local", "global", "semantic", "broker")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="safe-exec-keygen",
        description="Create one Ed25519 identity per SAFE-EXEC role.",
    )
    parser.add_argument(
        "directory",
        type=Path,
        nargs="?",
        default=Path("secrets"),
        help="output directory (default: ./secrets)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="overwrite existing keys (destroys the ability to verify old votes)",
    )
    parser.add_argument(
        "--nodes",
        nargs="+",
        default=list(NODES),
        choices=list(NODES),
        help="roles to generate (default: all four)",
    )
    args = parser.parse_args(argv)

    generated: list[str] = []
    for node in args.nodes:
        private = args.directory / f"{node}_private.pem"
        public = args.directory / f"{node}_public.pem"
        if args.force:
            private.unlink(missing_ok=True)
            public.unlink(missing_ok=True)
        try:
            generate_keypair(private, public)
        except FileExistsError as exc:
            raise SystemExit(f"refusing to overwrite: {exc} (pass --force to replace)") from exc
        generated.append(node)

    print(f"Generated {len(generated)} Ed25519 identities in {args.directory.resolve()}")
    print("Private keys are mode 0600 and must never be committed.")


if __name__ == "__main__":  # pragma: no cover - module entry point
    main()
