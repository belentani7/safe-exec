import base64
import time
from pathlib import Path

import pytest

from safeexec.consensus import ConsensusBroker, ConsensusError, verify_release
from safeexec.crypto import generate_keypair, sign
from safeexec.models import EvaluationRequest, SignedVote, VotePayload
from safeexec.policy import StaticPolicyEvaluator


def identities(root: Path):
    result = {}
    for node in ("LOCAL", "GLOBAL", "SEMANTIC", "BROKER"):
        private = root / f"{node.lower()}-private.pem"
        public = root / f"{node.lower()}-public.pem"
        generate_keypair(private, public)
        result[node] = (private, public)
    return result


def request(now: int = 1_900_000_000):
    content = b"print('safe')"
    raw = EvaluationRequest.create("sample.py", content, base64.b64encode(content).decode(), ttl=120)
    return EvaluationRequest(raw.request_id, raw.nonce, raw.file_hash, raw.filename, raw.content_b64, raw.policy_version, now, now + 120)


def vote(req, node, private, verdict=True, now=1_900_000_000):
    payload = VotePayload(req.request_id, req.nonce, req.file_hash, req.policy_version, node, verdict, 0.9, "test", (), now, now + 60)
    return SignedVote(payload, sign(private, payload.signing_data()))


def test_two_valid_signatures_release_once(tmp_path):
    keys = identities(tmp_path)
    req = request()
    broker = ConsensusBroker({n: keys[n][1] for n in ("LOCAL", "GLOBAL", "SEMANTIC")}, keys["BROKER"][0], tmp_path / "replay.sqlite3")
    token = broker.decide(req, [vote(req, "LOCAL", keys["LOCAL"][0]), vote(req, "SEMANTIC", keys["SEMANTIC"][0])], now=req.issued_at + 1)
    assert verify_release(token, keys["BROKER"][1], req, now=req.issued_at + 2)
    with pytest.raises(ConsensusError, match="consumed"):
        broker.decide(req, [vote(req, "LOCAL", keys["LOCAL"][0]), vote(req, "GLOBAL", keys["GLOBAL"][0])], now=req.issued_at + 2)


def test_forged_vote_is_rejected(tmp_path):
    keys = identities(tmp_path)
    req = request()
    forged = vote(req, "LOCAL", keys["GLOBAL"][0])
    broker = ConsensusBroker({n: keys[n][1] for n in ("LOCAL", "GLOBAL", "SEMANTIC")}, keys["BROKER"][0], tmp_path / "replay.sqlite3")
    with pytest.raises(ConsensusError, match="invalid signature"):
        broker.decide(req, [forged], now=req.issued_at + 1)


def test_vote_for_other_file_is_rejected(tmp_path):
    keys = identities(tmp_path)
    req = request()
    other = request()
    broker = ConsensusBroker({n: keys[n][1] for n in ("LOCAL", "GLOBAL", "SEMANTIC")}, keys["BROKER"][0], tmp_path / "replay.sqlite3")
    with pytest.raises(ConsensusError, match="binding mismatch"):
        broker.decide(req, [vote(other, "LOCAL", keys["LOCAL"][0])], now=req.issued_at + 1)


def test_static_policy_uses_ast(tmp_path):
    rules = tmp_path / "rules.yaml"
    rules.write_text("blocked_imports: [ctypes]\nblocked_calls: [os.system, eval]\nblocked_literals: [/etc/shadow]\n", encoding="utf-8")
    findings = StaticPolicyEvaluator(rules).evaluate("import os\nos.system('id')\n")
    assert [(f.rule, f.detail) for f in findings] == [("blocked-call", "os.system")]


def test_invalid_python_is_blocked(tmp_path):
    rules = tmp_path / "rules.yaml"
    rules.write_text("{}", encoding="utf-8")
    assert StaticPolicyEvaluator(rules).evaluate("def broken(")[0].rule == "invalid-python"


def test_local_denial_cannot_be_overridden(tmp_path):
    keys = identities(tmp_path)
    req = request()
    broker = ConsensusBroker({n: keys[n][1] for n in ("LOCAL", "GLOBAL", "SEMANTIC")}, keys["BROKER"][0], tmp_path / "replay.sqlite3")
    token = broker.decide(req, [
        vote(req, "LOCAL", keys["LOCAL"][0], verdict=False),
        vote(req, "GLOBAL", keys["GLOBAL"][0]),
        vote(req, "SEMANTIC", keys["SEMANTIC"][0]),
    ], now=req.issued_at + 1)
    assert token.payload.approved is False
