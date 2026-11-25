from __future__ import annotations

import base64
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .models import canonical_json


def generate_keypair(private_path: Path, public_path: Path) -> None:
    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)
    if private_path.exists() or public_path.exists():
        raise FileExistsError(f"Key already exists: {private_path} or {public_path}")
    private = Ed25519PrivateKey.generate()
    private_path.write_bytes(private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    public_path.write_bytes(private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    try:
        private_path.chmod(0o600)
        public_path.chmod(0o644)
    except OSError:
        pass


def sign(private_path: Path, payload: dict[str, Any]) -> str:
    key = serialization.load_pem_private_key(private_path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError("Expected Ed25519 private key")
    return base64.b64encode(key.sign(canonical_json(payload))).decode("ascii")


def verify(public_path: Path, payload: dict[str, Any], signature: str) -> bool:
    try:
        key = serialization.load_pem_public_key(public_path.read_bytes())
        if not isinstance(key, Ed25519PublicKey):
            return False
        key.verify(base64.b64decode(signature, validate=True), canonical_json(payload))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False
