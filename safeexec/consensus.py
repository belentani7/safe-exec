"""Consensus broker and release-token verification.

The broker is the only component allowed to mint a release token. Its decision
is deliberately narrow and fail-closed:

* a request must be inside its validity window and unused;
* every vote must come from a distinct trusted identity with a valid Ed25519
  signature bound to this exact request, nonce, file hash and policy version;
* ``LOCAL`` must approve, and its approval cannot be outvoted;
* at least two approvals are required, and each approval must reach the
  configured confidence floor;
* a request is consumed whether the outcome is approval or denial, so a denial
  cannot be retried with different votes.
"""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path

from .crypto import sign, verify
from .models import EvaluationRequest, ReleasePayload, ReleaseToken, SignedVote

#: The broker refuses more votes than this, bounding parser work per request.
MAX_VOTES = 16

#: Approvals below this confidence do not count towards the quorum.
MIN_APPROVAL_CONFIDENCE = 0.5

#: Nodes whose approval is mandatory regardless of arithmetic.
REQUIRED_NODE = "LOCAL"

#: How long a minted release token stays usable.
RELEASE_TTL_SECONDS = 30

#: Lifetime after which a consumed request id may be pruned from the replay DB.
REPLAY_RETENTION_SECONDS = 86_400


class ConsensusError(ValueError):
    """Raised when a decision cannot be minted safely."""


class ConsensusBroker:
    def __init__(
        self,
        trusted_keys: dict[str, Path],
        broker_private_key: Path,
        replay_db: Path,
        *,
        min_confidence: float = MIN_APPROVAL_CONFIDENCE,
        required_node: str = REQUIRED_NODE,
    ) -> None:
        if not trusted_keys:
            raise ConsensusError("no trusted keys configured")
        self.trusted_keys = trusted_keys
        self.broker_private_key = broker_private_key
        self.replay_db = replay_db
        self.min_confidence = min_confidence
        self.required_node = required_node
        replay_db.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(replay_db) as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS consumed ("
                "request_id TEXT PRIMARY KEY, consumed_at INTEGER NOT NULL)"
            )
            db.execute(
                "CREATE INDEX IF NOT EXISTS consumed_at_idx ON consumed (consumed_at)"
            )

    # ------------------------------------------------------------- decision

    def decide(
        self,
        request: EvaluationRequest,
        votes: list[SignedVote],
        now: int | None = None,
    ) -> ReleaseToken:
        now = int(time.time()) if now is None else now
        if not request.issued_at <= now <= request.expires_at:
            raise ConsensusError("request expired or not yet valid")
        if len(votes) > MAX_VOTES:
            raise ConsensusError(f"too many votes: {len(votes)} > {MAX_VOTES}")
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
                request.request_id,
                request.nonce,
                request.file_hash,
                request.policy_version,
            ):
                raise ConsensusError(f"vote binding mismatch: {payload.node}")
            if not payload.issued_at <= now <= payload.expires_at:
                raise ConsensusError(f"expired vote: {payload.node}")
            unique[payload.node] = vote

        approving = [
            vote
            for vote in unique.values()
            if vote.payload.verdict and vote.payload.confidence >= self.min_confidence
        ]
        approvals = len(approving)
        denials = len(unique) - approvals
        required = unique.get(self.required_node)
        approved = (
            approvals >= 2
            and required is not None
            and required.payload.verdict
            and required.payload.confidence >= self.min_confidence
        )

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
            expires_at=min(request.expires_at, now + RELEASE_TTL_SECONDS),
        )
        # Consume on every outcome: a denial must not be retried with new votes.
        self._consume(request.request_id, now)
        return ReleaseToken(release, sign(self.broker_private_key, release.signing_data()))

    def prune(self, now: int | None = None, retention: int = REPLAY_RETENTION_SECONDS) -> int:
        """Delete consumed request ids older than ``retention``; return count."""
        cutoff = (int(time.time()) if now is None else now) - retention
        with sqlite3.connect(self.replay_db) as db:
            cursor = db.execute("DELETE FROM consumed WHERE consumed_at < ?", (cutoff,))
            return cursor.rowcount or 0

    # ---------------------------------------------------------- replay store

    def _is_consumed(self, request_id: str) -> bool:
        with sqlite3.connect(self.replay_db) as db:
            row = db.execute(
                "SELECT 1 FROM consumed WHERE request_id=?", (request_id,)
            ).fetchone()
            return row is not None

    def _consume(self, request_id: str, now: int) -> None:
        try:
            with sqlite3.connect(self.replay_db) as db:
                db.execute(
                    "INSERT INTO consumed(request_id, consumed_at) VALUES (?, ?)",
                    (request_id, now),
                )
        except sqlite3.IntegrityError as exc:
            raise ConsensusError("request already consumed") from exc


def verify_release(
    token: ReleaseToken,
    broker_public_key: Path,
    request: EvaluationRequest,
    now: int | None = None,
    *,
    required_node: str | None = REQUIRED_NODE,
    min_confidence: float = MIN_APPROVAL_CONFIDENCE,
) -> bool:
    """Verify a release token against the request it claims to authorise.

    This is defence in depth: the orchestrator checks it before executing even
    though the broker already decided, because the token travels over a network
    that the orchestrator does not fully trust.
    """
    now = int(time.time()) if now is None else now
    payload = token.payload
    binding = (payload.request_id, payload.nonce, payload.file_hash, payload.policy_version)
    expected = (request.request_id, request.nonce, request.file_hash, request.policy_version)
    if not payload.approved or binding != expected:
        return False
    if not payload.issued_at <= now <= payload.expires_at:
        return False
    if payload.approvals < 2 or payload.denials < 0:
        return False
    if required_node is not None and required_node not in payload.voters:
        return False
    del min_confidence  # confidence is enforced at the broker; token states the outcome
    return verify(broker_public_key, payload.signing_data(), token.signature)


__all__ = [
    "MAX_VOTES",
    "MIN_APPROVAL_CONFIDENCE",
    "RELEASE_TTL_SECONDS",
    "REPLAY_RETENTION_SECONDS",
    "REQUIRED_NODE",
    "ConsensusBroker",
    "ConsensusError",
    "verify_release",
]
