"""Consensus rules that go beyond the original happy-path protocol tests."""

from __future__ import annotations

import base64

import pytest
from safeexec.consensus import (
    MAX_VOTES,
    RELEASE_TTL_SECONDS,
    ConsensusBroker,
    ConsensusError,
    verify_release,
)
from safeexec.crypto import generate_keypair, sign
from safeexec.models import EvaluationRequest, SignedVote, VotePayload

NOW = 1_900_000_000
NODES = ("LOCAL", "GLOBAL", "SEMANTIC", "BROKER")


@pytest.fixture
def keys(tmp_path):
    result = {}
    for node in NODES:
        private = tmp_path / f"{node.lower()}-private.pem"
        public = tmp_path / f"{node.lower()}-public.pem"
        generate_keypair(private, public)
        result[node] = (private, public)
    return result


@pytest.fixture
def broker(tmp_path, keys):
    return ConsensusBroker(
        {n: keys[n][1] for n in ("LOCAL", "GLOBAL", "SEMANTIC")},
        keys["BROKER"][0],
        tmp_path / "replay.sqlite3",
    )


def make_request(content: bytes = b"print('safe')", now: int = NOW) -> EvaluationRequest:
    raw = EvaluationRequest.create("s.py", content, base64.b64encode(content).decode(), ttl=120)
    return EvaluationRequest(
        raw.request_id, raw.nonce, raw.file_hash, raw.filename,
        raw.content_b64, raw.policy_version, now, now + 120,
    )


def vote(req, node, private, verdict=True, confidence=0.9, now=NOW):
    payload = VotePayload(
        req.request_id, req.nonce, req.file_hash, req.policy_version,
        node, verdict, confidence, "test", (), now, now + 60,
    )
    return SignedVote(payload, sign(private, payload.signing_data()))


def test_low_confidence_approval_does_not_count(broker, keys) -> None:
    req = make_request()
    token = broker.decide(
        req,
        [vote(req, "LOCAL", keys["LOCAL"][0], confidence=0.1),
         vote(req, "GLOBAL", keys["GLOBAL"][0])],
        now=NOW + 1,
    )
    assert token.payload.approved is False


def test_low_confidence_local_vetoes_even_with_two_others(broker, keys) -> None:
    req = make_request()
    token = broker.decide(
        req,
        [vote(req, "LOCAL", keys["LOCAL"][0], confidence=0.2),
         vote(req, "GLOBAL", keys["GLOBAL"][0]),
         vote(req, "SEMANTIC", keys["SEMANTIC"][0])],
        now=NOW + 1,
    )
    assert token.payload.approved is False


def test_too_many_votes_rejected(broker, keys) -> None:
    req = make_request()
    votes = [vote(req, "LOCAL", keys["LOCAL"][0]) for _ in range(MAX_VOTES + 1)]
    with pytest.raises(ConsensusError, match="too many votes"):
        broker.decide(req, votes, now=NOW + 1)


def test_denial_still_consumes_the_request(broker, keys) -> None:
    req = make_request()
    first = broker.decide(req, [vote(req, "LOCAL", keys["LOCAL"][0], verdict=False)], now=NOW + 1)
    assert first.payload.approved is False
    with pytest.raises(ConsensusError, match="consumed"):
        broker.decide(req, [vote(req, "LOCAL", keys["LOCAL"][0])], now=NOW + 2)


def test_token_lifetime_is_short(broker, keys) -> None:
    req = make_request()
    token = broker.decide(
        req,
        [vote(req, "LOCAL", keys["LOCAL"][0]), vote(req, "GLOBAL", keys["GLOBAL"][0])],
        now=NOW + 1,
    )
    assert token.payload.expires_at - token.payload.issued_at == RELEASE_TTL_SECONDS
    assert not verify_release(token, keys["BROKER"][1], req, now=NOW + RELEASE_TTL_SECONDS + 5)


def test_prune_removes_only_old_entries(broker, keys) -> None:
    req = make_request()
    broker.decide(
        req,
        [vote(req, "LOCAL", keys["LOCAL"][0]), vote(req, "GLOBAL", keys["GLOBAL"][0])],
        now=NOW,
    )
    assert broker.prune(now=NOW + 10, retention=100) == 0
    assert broker.prune(now=NOW + 10_000, retention=100) == 1


def test_unknown_voter_is_rejected(broker, keys) -> None:
    req = make_request()
    rogue = vote(req, "ROGUE", keys["GLOBAL"][0])
    with pytest.raises(ConsensusError, match="invalid signature"):
        broker.decide(req, [rogue], now=NOW + 1)


def test_expired_vote_is_rejected(broker, keys) -> None:
    req = make_request()
    stale = vote(req, "LOCAL", keys["LOCAL"][0], now=NOW - 100)
    with pytest.raises(ConsensusError, match="expired vote"):
        broker.decide(req, [stale], now=NOW + 1)


def test_missing_local_approval_cannot_approve(broker, keys) -> None:
    req = make_request()
    token = broker.decide(
        req,
        [vote(req, "GLOBAL", keys["GLOBAL"][0]), vote(req, "SEMANTIC", keys["SEMANTIC"][0])],
        now=NOW + 1,
    )
    assert token.payload.approved is False
    assert not verify_release(token, keys["BROKER"][1], req, now=NOW + 2)


def test_verify_release_rejects_tampered_payload(broker, keys) -> None:
    req = make_request()
    token = broker.decide(
        req,
        [vote(req, "LOCAL", keys["LOCAL"][0]), vote(req, "GLOBAL", keys["GLOBAL"][0])],
        now=NOW + 1,
    )
    forged = type(token)(
        type(token.payload)(
            **{**token.payload.__dict__, "voters": ("LOCAL", "GLOBAL", "SEMANTIC")}
        ),
        token.signature,
    )
    assert not verify_release(forged, keys["BROKER"][1], req, now=NOW + 2)


def test_broker_requires_trusted_keys(tmp_path, keys) -> None:
    with pytest.raises(ConsensusError):
        ConsensusBroker({}, keys["BROKER"][0], tmp_path / "replay.sqlite3")
