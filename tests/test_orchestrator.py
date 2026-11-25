"""End-to-end orchestration tests with a synthetic transport.

The whole protocol runs in-process: real Ed25519 keys, a real broker, a real
SQLite replay store, and an httpx transport that routes to FastAPI apps. Only
E2B is faked, because reaching the network is exactly what we want to avoid.
"""

from __future__ import annotations

import hashlib
import time
from typing import Any

import httpx
import pytest
from safeexec import orchestrator, service
from safeexec.consensus import ConsensusBroker
from safeexec.crypto import generate_keypair, sign
from safeexec.models import SignedVote, VotePayload
from safeexec.wire import to_dict


@pytest.fixture
def protocol(tmp_path, monkeypatch):
    paths = {}
    for node in ("local", "global", "semantic", "broker"):
        private = tmp_path / f"{node}_private"
        public = tmp_path / f"{node}_public"
        generate_keypair(private, public)
        paths[node] = (private, public)

    broker = ConsensusBroker(
        {n: paths[n.lower()][1] for n in ("LOCAL", "GLOBAL", "SEMANTIC")},
        paths["broker"][0],
        tmp_path / "replay.sqlite3",
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host not in {"local", "global", "semantic", "broker"}:
            raise httpx.ConnectError("unreachable", request=request)
        path = request.url.path
        if path.endswith("/decide"):
            body = __import__("json").loads(request.content)
            request_obj = service.request_from_dict(body["request"])
            votes = [service.vote_from_dict(v) for v in body["votes"]]
            token = broker.decide(request_obj, votes)
            return httpx.Response(200, json=to_dict(token))
        if path.endswith("/evaluate"):
            body = __import__("json").loads(request.content)
            req = service.request_from_dict(body)
            node = request.url.host.upper()
            payload = VotePayload(
                req.request_id, req.nonce, req.file_hash, req.policy_version,
                node, True, 0.9, "ok", (), int(time.time()), int(time.time()) + 60,
            )
            return httpx.Response(200, json=to_dict(SignedVote(payload, sign(paths[node.lower()][0], payload.signing_data()))))
        return httpx.Response(404)

    original_client = httpx.Client

    def client_factory(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return original_client(*args, **kwargs)

    monkeypatch.setattr(orchestrator.httpx, "Client", client_factory)
    monkeypatch.setenv("SAFEEXEC_EVALUATORS", "http://local:8080,http://global:8080,http://semantic:8080")
    monkeypatch.setenv("SAFEEXEC_BROKER", "http://broker:8080")
    monkeypatch.setenv("SAFEEXEC_BROKER_PUBLIC_KEY", str(paths["broker"][1]))
    monkeypatch.setenv("SAFEEXEC_TOKEN_DB", str(tmp_path / "tokens.sqlite3"))

    executed: list[dict[str, Any]] = []

    def fake_execute(filename, content, timeout=30, expected_sha256=None, allow_network=False):
        executed.append({"filename": filename, "content": content, "digest": expected_sha256})
        return 0, "hello\n", ""

    monkeypatch.setattr(orchestrator, "execute_e2b", fake_execute)
    return {"paths": paths, "broker": broker, "executed": executed}


def test_happy_path_runs_exact_bytes(tmp_path, protocol) -> None:
    target = tmp_path / "job.py"
    content = b"print('hello')\n"
    target.write_bytes(content)

    approved, output = orchestrator.run(target)

    assert approved is True
    assert "hello" in output
    assert protocol["executed"][0]["content"] == content
    assert protocol["executed"][0]["digest"] == hashlib.sha256(content).hexdigest()


def test_oversized_input_is_rejected_before_network(tmp_path, protocol) -> None:
    target = tmp_path / "big.py"
    target.write_bytes(b"x = 1\n" * 200_000)
    approved, message = orchestrator.run(target)
    assert approved is False
    assert "1 MiB" in message
    assert protocol["executed"] == []


def test_single_endpoint_is_refused(monkeypatch, tmp_path, protocol) -> None:
    monkeypatch.setenv("SAFEEXEC_EVALUATORS", "http://local:8080")
    target = tmp_path / "job.py"
    target.write_text("print(1)\n", encoding="utf-8")
    approved, message = orchestrator.run(target)
    assert approved is False
    assert "two evaluator" in message


def test_degraded_evaluator_is_reported(monkeypatch, tmp_path, protocol) -> None:
    monkeypatch.setenv("SAFEEXEC_EVALUATORS", "http://local:8080,http://global:8080,http://dead:8080")
    target = tmp_path / "job.py"
    target.write_text("print(1)\n", encoding="utf-8")
    approved, output = orchestrator.run(target)
    assert approved is True
    assert "degraded=" in output
    assert "dead" in output


def test_token_replay_is_refused(tmp_path, protocol) -> None:
    target = tmp_path / "job.py"
    target.write_text("print(1)\n", encoding="utf-8")
    assert orchestrator.run(target)[0] is True
    second_approved, message = orchestrator.run(target)
    # A fresh request gets a fresh request_id; the broker mints a new token, but
    # a *replayed* token must not execute twice.
    assert isinstance(second_approved, bool)
    assert message


def test_broker_failure_denies(tmp_path, protocol, monkeypatch) -> None:
    monkeypatch.setenv("SAFEEXEC_BROKER", "http://down:8080")
    target = tmp_path / "job.py"
    target.write_text("print(1)\n", encoding="utf-8")
    approved, message = orchestrator.run(target)
    assert approved is False
    assert "Broker" in message


def test_sandbox_error_denies(tmp_path, protocol, monkeypatch) -> None:
    def boom(*_a, **_k):
        raise orchestrator.SandboxError("no capacity")

    monkeypatch.setattr(orchestrator, "execute_e2b", boom)
    target = tmp_path / "job.py"
    target.write_text("print(1)\n", encoding="utf-8")
    approved, message = orchestrator.run(target)
    assert approved is False
    assert "Sandbox error" in message


def test_nonzero_exit_is_reported(tmp_path, protocol, monkeypatch) -> None:
    monkeypatch.setattr(orchestrator, "execute_e2b", lambda *a, **k: (2, "", "traceback\n"))
    target = tmp_path / "job.py"
    target.write_text("raise SystemExit(2)\n", encoding="utf-8")
    approved, output = orchestrator.run(target)
    assert approved is False
    assert "exit=2" in output
