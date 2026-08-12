from __future__ import annotations

import sqlite3
import time
from pathlib import Path

from .crypto import sign, verify
from .models import EvaluationRequest, ReleasePayload, ReleaseToken, SignedVote


class ConsensusError(ValueError):
    pass


class ConsensusBroker:
    def __init__(self, trusted_keys: dict[str, Path], broker_private_key: Path, replay_db: Path):
        self.trusted_keys = trusted_keys
        self.broker_private_key = broker_private_key
        self.replay_db = replay_db
        replay_db.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(replay_db) as db:
            db.execute("CREATE TABLE IF NOT EXISTS consumed (request_id TEXT PRIMARY KEY, consumed_at INTEGER NOT NULL)")

    def decide(self, request: EvaluationRequest, votes: list[SignedVote], now: int | None = None) -> ReleaseToken:
        now = int(time.time()) if now is None else now
        if not request.issued_at <= now <= request.expires_at:
            raise ConsensusError("request expired or not yet valid")
        if self._is_consumed(request.request_id):
            raise ConsensusError("request already consumed")

        unique: dict[str, SignedVote] = {}
        for vote in votes:
            payload = vote.payload
            if payload.node in unique:
                raise ConsensusError(f"duplicate voter: {payload.node}")
            key = self.trusted_keys.get(payload.node)
            if key is None or not verify(key, payload.signing_data(), vote.signature):
                raise ConsensusError(f"invalid signature: {payload.node}")
            if (payload.request_id, payload.nonce, payload.file_hash, payload.policy_version) != (
                request.request_id, request.nonce, request.file_hash, request.policy_version
            ):
                raise ConsensusError(f"vote binding mismatch: {payload.node}")
            if not payload.issued_at <= now <= payload.expires_at:
                raise ConsensusError(f"expired vote: {payload.node}")
            unique[payload.node] = vote

        approvals = sum(v.payload.verdict for v in unique.values())
        denials = len(unique) - approvals
        approved = approvals >= 2 and unique.get("LOCAL") is not None and unique["LOCAL"].payload.verdict
        release = ReleasePayload(
            request_id=request.request_id,
            nonce=request.nonce,
            file_hash=request.file_hash,
            policy_version=request.policy_version,
            approved=approved,
            approvals=approvals,
            denials=denials,
            voters=tuple(sorted(unique)),
            issued_at=now,
            expires_at=min(request.expires_at, now + 30),
        )
        self._consume(request.request_id, now)
        return ReleaseToken(release, sign(self.broker_private_key, release.signing_data()))

    def _is_consumed(self, request_id: str) -> bool:
        with sqlite3.connect(self.replay_db) as db:
            return db.execute("SELECT 1 FROM consumed WHERE request_id=?", (request_id,)).fetchone() is not None

    def _consume(self, request_id: str, now: int) -> None:
        try:
            with sqlite3.connect(self.replay_db) as db:
                db.execute("INSERT INTO consumed(request_id, consumed_at) VALUES (?, ?)", (request_id, now))
        except sqlite3.IntegrityError as exc:
            raise ConsensusError("request already consumed") from exc


def verify_release(token: ReleaseToken, broker_public_key: Path, request: EvaluationRequest, now: int | None = None) -> bool:
    now = int(time.time()) if now is None else now
    payload = token.payload
    binding = (payload.request_id, payload.nonce, payload.file_hash, payload.policy_version)
    expected = (request.request_id, request.nonce, request.file_hash, request.policy_version)
    return (
        payload.approved
        and binding == expected
        and payload.issued_at <= now <= payload.expires_at
        and verify(broker_public_key, payload.signing_data(), token.signature)
    )
