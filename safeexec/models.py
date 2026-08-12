from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


@dataclass(frozen=True)
class EvaluationRequest:
    request_id: str
    nonce: str
    file_hash: str
    filename: str
    content_b64: str
    policy_version: str
    issued_at: int
    expires_at: int

    @classmethod
    def create(cls, filename: str, content: bytes, content_b64: str, ttl: int = 120) -> "EvaluationRequest":
        now = int(time.time())
        return cls(
            request_id=str(uuid.uuid4()),
            nonce=uuid.uuid4().hex,
            file_hash=hashlib.sha256(content).hexdigest(),
            filename=filename,
            content_b64=content_b64,
            policy_version="safeexec-1",
            issued_at=now,
            expires_at=now + ttl,
        )

    def signing_data(self) -> dict[str, Any]:
        data = asdict(self)
        data.pop("content_b64")
        return data


@dataclass(frozen=True)
class VotePayload:
    request_id: str
    nonce: str
    file_hash: str
    policy_version: str
    node: str
    verdict: bool
    confidence: float
    reason: str
    evidence: tuple[str, ...] = field(default_factory=tuple)
    issued_at: int = 0
    expires_at: int = 0

    def signing_data(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class SignedVote:
    payload: VotePayload
    signature: str


@dataclass(frozen=True)
class ReleasePayload:
    request_id: str
    nonce: str
    file_hash: str
    policy_version: str
    approved: bool
    approvals: int
    denials: int
    voters: tuple[str, ...]
    issued_at: int
    expires_at: int

    def signing_data(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ReleaseToken:
    payload: ReleasePayload
    signature: str
