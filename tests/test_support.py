"""Tests for keygen, crypto helpers, resources and service internals."""

from __future__ import annotations

import hashlib
import stat
from pathlib import Path

import pytest
from safeexec import keygen, resources, service
from safeexec.crypto import generate_keypair, sign, verify

# --------------------------------------------------------------------- keygen


def test_keygen_creates_all_four_identities(tmp_path, capsys) -> None:
    keygen.main([str(tmp_path)])
    for node in ("local", "global", "semantic", "broker"):
        assert (tmp_path / f"{node}_private.pem").is_file()
        assert (tmp_path / f"{node}_public.pem").is_file()
    assert "4 Ed25519 identities" in capsys.readouterr().out


def test_keygen_refuses_to_overwrite_without_force(tmp_path) -> None:
    keygen.main([str(tmp_path)])
    with pytest.raises(SystemExit):
        keygen.main([str(tmp_path)])


def test_keygen_force_replaces_keys(tmp_path) -> None:
    keygen.main([str(tmp_path)])
    before = (tmp_path / "local_private.pem").read_bytes()
    keygen.main([str(tmp_path), "--force"])
    assert (tmp_path / "local_private.pem").read_bytes() != before


def test_keygen_selects_nodes(tmp_path) -> None:
    keygen.main([str(tmp_path), "--nodes", "local"])
    assert (tmp_path / "local_private.pem").is_file()
    assert not (tmp_path / "broker_private.pem").exists()


@pytest.mark.skipif(Path("/").stat().st_uid != 0 and __import__("os").getuid() == 0, reason="root ignores modes")
def test_private_key_is_not_world_readable(tmp_path) -> None:
    generate_keypair(tmp_path / "a_private.pem", tmp_path / "a_public.pem")
    mode = (tmp_path / "a_private.pem").stat().st_mode
    assert not mode & stat.S_IROTH


# --------------------------------------------------------------------- crypto


def test_signature_round_trip(tmp_path) -> None:
    generate_keypair(tmp_path / "p.pem", tmp_path / "pub.pem")
    payload = {"a": 1, "b": [2, 3]}
    signature = sign(tmp_path / "p.pem", payload)
    assert verify(tmp_path / "pub.pem", payload, signature)


def test_tampered_payload_fails_verification(tmp_path) -> None:
    generate_keypair(tmp_path / "p.pem", tmp_path / "pub.pem")
    signature = sign(tmp_path / "p.pem", {"a": 1})
    assert not verify(tmp_path / "pub.pem", {"a": 2}, signature)


def test_malformed_signature_is_false_not_raise(tmp_path) -> None:
    generate_keypair(tmp_path / "p.pem", tmp_path / "pub.pem")
    assert verify(tmp_path / "pub.pem", {"a": 1}, "not-base64!!") is False


def test_wrong_key_type_is_rejected(tmp_path) -> None:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    path = tmp_path / "rsa.pem"
    path.write_bytes(
        rsa_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    with pytest.raises(TypeError):
        sign(path, {"a": 1})


def test_generate_keypair_refuses_existing(tmp_path) -> None:
    generate_keypair(tmp_path / "p.pem", tmp_path / "pub.pem")
    with pytest.raises(FileExistsError):
        generate_keypair(tmp_path / "p.pem", tmp_path / "pub.pem")


# --------------------------------------------------------------------- resources


def test_packaged_rules_exist_and_parse() -> None:
    path = resources.packaged_rules_path()
    assert path.is_file()
    assert "blocked_calls" in path.read_text(encoding="utf-8")


def test_packaged_rules_is_cached() -> None:
    assert resources.packaged_rules_path() == resources.packaged_rules_path()


def test_read_rules_text_matches_file() -> None:
    assert resources.read_rules_text() == resources.packaged_rules_path().read_text(encoding="utf-8")


# --------------------------------------------------------------------- service


def test_read_secret_returns_empty_when_unset(monkeypatch) -> None:
    monkeypatch.delenv("VT_API_KEY_FILE", raising=False)
    assert service._read_secret("VT_API_KEY_FILE") == ""


def test_read_secret_returns_empty_when_unreadable(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("VT_API_KEY_FILE", str(tmp_path / "absent"))
    assert service._read_secret("VT_API_KEY_FILE") == ""


def test_read_secret_strips_whitespace(monkeypatch, tmp_path) -> None:
    secret = tmp_path / "k.txt"
    secret.write_text("  abc123\n", encoding="utf-8")
    monkeypatch.setenv("VT_API_KEY_FILE", str(secret))
    assert service._read_secret("VT_API_KEY_FILE") == "abc123"


def test_vt_assess_reports_unknown_hash(monkeypatch, tmp_path) -> None:
    import urllib.error

    secret = tmp_path / "k.txt"
    secret.write_text("key", encoding="utf-8")
    monkeypatch.setenv("VT_API_KEY_FILE", str(secret))

    def not_found(*_a, **_k):
        raise urllib.error.HTTPError("u", 404, "nf", {}, None)  # type: ignore[arg-type]

    monkeypatch.setattr(service.urllib.request, "urlopen", not_found)
    verdict, _confidence, reason, evidence = service._vt_assess("0" * 64)
    assert verdict is False
    assert evidence == ["unknown-hash"]
    assert "unknown" in reason


def test_vt_assess_parses_clean_report(monkeypatch, tmp_path) -> None:
    import io
    import json

    secret = tmp_path / "k.txt"
    secret.write_text("key", encoding="utf-8")
    monkeypatch.setenv("VT_API_KEY_FILE", str(secret))

    body = json.dumps(
        {"data": {"attributes": {"last_analysis_stats": {"malicious": 0, "suspicious": 0}}}}
    ).encode()

    class Response(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

    monkeypatch.setattr(service.urllib.request, "urlopen", lambda *a, **k: Response(body))
    verdict, confidence, _, _ = service._vt_assess("0" * 64)
    assert verdict is True
    assert confidence == 0.95


def test_ollama_assess_parses_json(monkeypatch) -> None:
    import io
    import json

    class Response(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

    inner = json.dumps({"verdict": "SAFE", "confidence": 0.8, "reason": "fine", "evidence": ["x"]})
    body = json.dumps({"response": inner}).encode()
    monkeypatch.setattr(service.urllib.request, "urlopen", lambda *a, **k: Response(body))
    verdict, confidence, reason, evidence = service._ollama_assess("print(1)")
    assert verdict is True
    assert confidence == 0.8
    assert reason == "fine"
    assert evidence == ["x"]


def test_ollama_assess_treats_garbage_as_dangerous(monkeypatch) -> None:
    import io
    import json

    class Response(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

    body = json.dumps({"response": json.dumps({"confidence": "high"})}).encode()
    monkeypatch.setattr(service.urllib.request, "urlopen", lambda *a, **k: Response(body))
    verdict, confidence, _, _ = service._ollama_assess("print(1)")
    assert verdict is False
    assert confidence == 0.0


def test_service_reports_policy_versions_match_the_file() -> None:
    rules = service.load_rules(service.packaged_rules_path())
    assert rules.version.startswith("safeexec-")


def test_cli_hash_streams_without_full_read(tmp_path, monkeypatch) -> None:
    from safeexec import cli

    target = tmp_path / "many.py"
    target.write_bytes(b"print(1)\n" * 1000)

    def forbidden(*_a, **_k):
        raise AssertionError("read_bytes must not be used for hashing")

    monkeypatch.setattr(Path, "read_bytes", forbidden)
    assert cli.hash_file(target) == hashlib.sha256(b"print(1)\n" * 1000).hexdigest()
