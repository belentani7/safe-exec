"""CLI hashing retains SHA-256 compatibility without eager reads."""

import hashlib

from safeexec.cli import hash_file


def test_streamed_hash_matches_in_memory_sha256(tmp_path):
    content = (bytes(range(256)) * 10000) + b"ending"
    path = tmp_path / "example.py"
    path.write_bytes(content)
    assert hash_file(path) == hashlib.sha256(content).hexdigest()


def test_empty_file_has_sha256_digest(tmp_path):
    path = tmp_path / "empty.py"
    path.write_bytes(b"")
    assert hash_file(path) == hashlib.sha256(b"").hexdigest()
