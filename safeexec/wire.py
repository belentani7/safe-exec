from __future__ import annotations

from dataclasses import asdict

from .models import EvaluationRequest, ReleasePayload, ReleaseToken, SignedVote, VotePayload


def request_from_dict(data: dict) -> EvaluationRequest:
    return EvaluationRequest(**data)


def vote_from_dict(data: dict) -> SignedVote:
    payload = dict(data["payload"])
    payload["evidence"] = tuple(payload.get("evidence", []))
    return SignedVote(VotePayload(**payload), data["signature"])


def token_from_dict(data: dict) -> ReleaseToken:
    payload = dict(data["payload"])
    payload["voters"] = tuple(payload.get("voters", []))
    return ReleaseToken(ReleasePayload(**payload), data["signature"])


def to_dict(value) -> dict:
    return asdict(value)
