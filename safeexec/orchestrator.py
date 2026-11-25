"""Orchestrator: evaluate → decide → verify → execute exactly those bytes.

The flow is intentionally boring and fail-closed:

1. read the file once and hash those bytes;
2. fan out the identical request to every evaluator, tolerating one outage;
3. let the broker mint a release token;
4. verify that token locally against the same request;
5. execute in a disposable sandbox, refusing if the remote digest drifts.
"""

from __future__ import annotations

import base64
import os
import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

import httpx

from .consensus import verify_release
from .models import EvaluationRequest
from .sandbox import SandboxError, execute_e2b
from .wire import to_dict, token_from_dict

#: Files above this size are rejected before base64 encoding.
MAX_INPUT_BYTES = 1_048_576
#: Evaluators may take up to this long (LLM inference dominates).
EVALUATOR_TIMEOUT_SECONDS = 70
#: The broker must answer quickly; it only verifies signatures.
BROKER_TIMEOUT_SECONDS = 15
DEFAULT_EVALUATORS = "http://local:8080,http://global:8080,http://semantic:8080"
DEFAULT_BROKER = "http://broker:8080"


def _evaluator_endpoints() -> list[str]:
    raw = os.environ.get("SAFEEXEC_EVALUATORS", DEFAULT_EVALUATORS)
    return [item.strip() for item in raw.split(",") if item.strip()]


def _fetch_vote(endpoint: str, payload: dict[str, Any]) -> dict[str, Any]:
    with httpx.Client(timeout=EVALUATOR_TIMEOUT_SECONDS) as client:
        response = client.post(f"{endpoint}/evaluate", json=payload)
        response.raise_for_status()
        return response.json()


def run(filepath: Path, timeout: int = 30) -> tuple[bool, str]:
    """Return ``(approved_and_succeeded, human_readable_output)``."""
    content = filepath.read_bytes()
    if len(content) > MAX_INPUT_BYTES:
        return False, "File exceeds 1 MiB limit"

    request = EvaluationRequest.create(
        filepath.name, content, base64.b64encode(content).decode("ascii")
    )
    endpoints = _evaluator_endpoints()
    if len(endpoints) < 2:
        return False, "At least two evaluator endpoints are required"

    votes: list[dict[str, Any]] = []
    failures: list[str] = []
    with ThreadPoolExecutor(max_workers=min(8, len(endpoints))) as pool:
        futures = {
            pool.submit(_fetch_vote, endpoint, to_dict(request)): endpoint
            for endpoint in endpoints
        }
        for future in as_completed(futures):
            try:
                votes.append(future.result())
            except Exception as exc:
                failures.append(f"{futures[future]} ({type(exc).__name__})")

    if len(votes) < 2:
        reason = "; ".join(failures) or "no responses"
        return False, f"Insufficient evaluator responses: {reason}"

    broker_url = os.environ.get("SAFEEXEC_BROKER", DEFAULT_BROKER)
    try:
        with httpx.Client(timeout=BROKER_TIMEOUT_SECONDS) as client:
            response = client.post(
                f"{broker_url}/decide", json={"request": to_dict(request), "votes": votes}
            )
            response.raise_for_status()
            token = token_from_dict(response.json())
    except Exception as exc:
        return False, f"Broker unavailable or rejected the decision ({type(exc).__name__})"

    broker_public = Path(
        os.environ.get("SAFEEXEC_BROKER_PUBLIC_KEY", "/run/secrets/broker_public")
    )
    if not verify_release(token, broker_public, request, int(time.time())):
        return False, "Release token rejected"

    token_db = Path(os.environ.get("SAFEEXEC_TOKEN_DB", ".safeexec-tokens.sqlite3"))
    token_db.parent.mkdir(parents=True, exist_ok=True)
    try:
        with sqlite3.connect(token_db) as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS used ("
                "request_id TEXT PRIMARY KEY, used_at INTEGER NOT NULL)"
            )
            db.execute(
                "INSERT INTO used(request_id, used_at) VALUES (?, ?)",
                (request.request_id, int(time.time())),
            )
    except sqlite3.IntegrityError:
        return False, "Release token already used"

    try:
        # The same bytes that were hashed and evaluated, verified remotely.
        exit_code, stdout, stderr = execute_e2b(
            filepath.name, content, timeout, expected_sha256=request.file_hash
        )
    except SandboxError as exc:
        return False, f"Sandbox error: {exc}"

    summary = f"voters={','.join(token.payload.voters)} exit={exit_code}"
    if failures:
        summary += f" degraded={'; '.join(failures)}"
    output = f"{summary}\n{stdout}{stderr}".rstrip()
    return exit_code == 0, output


__all__ = ["DEFAULT_BROKER", "DEFAULT_EVALUATORS", "MAX_INPUT_BYTES", "run"]
