"""Endpoint tests for evaluator and broker roles using FastAPI's TestClient.

No network, no Docker, no external APIs: every remote dependency is either
absent (which must fail closed) or replaced by a fake.
"""

from __future__ import annotations

import base64
import hashlib
import time
from typing import Any

import pytest
from fastapi.testclient import TestClient
from safeexec import service
from safeexec.crypto import generate_keypair, verify
from safeexec.models import canonical_json


@pytest.fixture
def keys(tmp_path, monkeypatch):
    paths = {}
    for node in ("local", "global", "semantic", "broker"):
        private = tmp_path / f"{node}_private"
        public = tmp_path / f"{node}_public"
        generate_keypair(private, public)
        paths[node] = (private, public)
    monkeypatch.setattr(service, "KEY_PATH", paths["local"][0])
    monkeypatch.setenv("SAFEEXEC_TRUSTED_KEYS", str(tmp_path))
    return paths


def make_request(content: bytes = b"print('hi')\n", ttl: int = 120) -> dict[str, Any]:
    now = int(time.time())
    return {
        "request_id": "req-1",
        "nonce": "nonce-1",
        "file_hash": hashlib.sha256(content).hexdigest(),
        "filename": "sample.py",
        "content_b64": base64.b64encode(content).decode(),
        "policy_version": "safeexec-1",
        "issued_at": now,
        "expires_at": now + ttl,
    }


@pytest.fixture
def local_client(monkeypatch):
    monkeypatch.setattr(service, "ROLE", "local")
    monkeypatch.setattr(service, "RULES_PATH", service.packaged_rules_path())
    return TestClient(service.app)


def test_health_reports_role_and_version(local_client: TestClient) -> None:
    body = local_client.get("/health").json()
    assert body["status"] == "ok"
    assert body["role"] == "local"
    assert body["version"]


def test_local_evaluator_signs_vote_for_clean_source(local_client, keys) -> None:
    response = local_client.post("/evaluate", json=make_request())
    assert response.status_code == 200
    vote = response.json()
    assert vote["payload"]["node"] == "LOCAL"
    assert vote["payload"]["verdict"] is True
    assert verify(
        keys["local"][1],
        vote["payload"],
        vote["signature"],
    )


def test_local_evaluator_denies_dangerous_source(local_client, keys) -> None:
    response = local_client.post("/evaluate", json=make_request(b"import os\nos.system('id')\n"))
    vote = response.json()
    assert vote["payload"]["verdict"] is False
    assert any("blocked-call" in item for item in vote["payload"]["evidence"])


def test_hash_mismatch_is_rejected(local_client) -> None:
    payload = make_request()
    payload["file_hash"] = "0" * 64
    assert local_client.post("/evaluate", json=payload).status_code == 400


def test_expired_request_is_rejected(local_client) -> None:
    payload = make_request(ttl=-10)
    assert local_client.post("/evaluate", json=payload).status_code == 400


def test_invalid_base64_is_rejected(local_client) -> None:
    payload = make_request()
    payload["content_b64"] = "not base64!!"
    assert local_client.post("/evaluate", json=payload).status_code == 400


def test_non_utf8_source_is_rejected(local_client) -> None:
    content = b"\xff\xfe\x00"
    payload = make_request(content)
    assert local_client.post("/evaluate", json=payload).status_code == 400


def test_oversized_payload_is_rejected(local_client) -> None:
    payload = make_request()
    payload["content_b64"] = "A" * (service.MAX_B64_CHARS + 1)
    assert local_client.post("/evaluate", json=payload).status_code == 413


def test_malformed_request_body_is_rejected(local_client) -> None:
    assert local_client.post("/evaluate", json={"request_id": "only"}).status_code == 400


def test_analyser_crash_fails_closed(local_client, keys, monkeypatch) -> None:
    def boom(*_args, **_kwargs):
        raise RuntimeError("simulated analyser fault")

    monkeypatch.setattr(service.StaticPolicyEvaluator, "evaluate", boom)
    vote = local_client.post("/evaluate", json=make_request()).json()
    assert vote["payload"]["verdict"] is False
    assert "denying" in vote["payload"]["reason"]


def test_global_role_without_key_denies(monkeypatch, keys) -> None:
    monkeypatch.setattr(service, "ROLE", "global")
    monkeypatch.setattr(service, "KEY_PATH", keys["global"][0])
    monkeypatch.delenv("VT_API_KEY_FILE", raising=False)
    client = TestClient(service.app)
    vote = client.post("/evaluate", json=make_request()).json()
    assert vote["payload"]["verdict"] is False
    assert vote["payload"]["confidence"] == 1.0


def test_semantic_role_unavailable_denies(monkeypatch, keys) -> None:
    monkeypatch.setattr(service, "ROLE", "semantic")
    monkeypatch.setattr(service, "KEY_PATH", keys["semantic"][0])
    monkeypatch.setenv("OLLAMA_ENDPOINT", "http://127.0.0.1:1")
    client = TestClient(service.app)
    vote = client.post("/evaluate", json=make_request()).json()
    assert vote["payload"]["verdict"] is False


def test_evaluator_role_cannot_decide(local_client) -> None:
    assert local_client.post("/decide", json={}).status_code == 404


def test_missing_policy_fails_closed(monkeypatch, keys) -> None:
    monkeypatch.setattr(service, "ROLE", "local")
    monkeypatch.setattr(service, "KEY_PATH", keys["local"][0])
    monkeypatch.setattr(service, "RULES_PATH", keys["local"][0].parent / "absent.yaml")
    service._rules_cache.clear()
    client = TestClient(service.app)
    assert client.post("/evaluate", json=make_request()).status_code == 503


def test_rule_cache_reuses_parsed_policy(tmp_path, monkeypatch) -> None:
    import shutil

    rules = tmp_path / "rules.yaml"
    shutil.copy(service.packaged_rules_path(), rules)
    service._rules_cache.clear()
    first = service.load_rules(rules)
    second = service.load_rules(rules)
    assert first is second


def test_vote_signature_binds_the_request(keys) -> None:
    """A vote's payload must be the exact canonical JSON that was signed."""
    from safeexec.models import VotePayload

    payload = VotePayload("r", "n", "h", "p", "LOCAL", True, 1.0, "ok", (), 1, 2)
    signature = service.sign(keys["local"][0], payload.signing_data())
    assert verify(keys["local"][1], payload.signing_data(), signature)
    tampered = dict(payload.signing_data())
    tampered["verdict"] = False
    assert not verify(keys["local"][1], tampered, signature)
    assert canonical_json(payload.signing_data())
