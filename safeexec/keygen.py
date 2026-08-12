from __future__ import annotations

import argparse
from pathlib import Path

from .crypto import generate_keypair


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path, nargs="?", default=Path("secrets"))
    args = parser.parse_args()
    for node in ("local", "global", "semantic", "broker"):
        generate_keypair(args.directory / f"{node}_private.pem", args.directory / f"{node}_public.pem")
    print(f"Generated four Ed25519 identities in {args.directory.resolve()}")
