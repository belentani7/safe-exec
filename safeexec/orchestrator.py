from __future__ import annotations

import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
import os
import sqlite3
import time
from pathlib import Path

import httpx

from .consensus import verify_release
from .models import EvaluationRequest
from .sandbox import execute_e2b
from .wire import to_dict, token_from_dict


def run(filepath: Path, timeout: int = 30) -> tuple[bool, str]:
    content = filepath.read_bytes()
    if len(content) > 1_048_576:
        return False, "File exceeds 1 MiB limit"
    request = EvaluationRequest.create(filepath.name, content, base64.b64encode(content).decode("ascii"))
    endpoints = [item.strip() for item in os.environ.get(
        "SAFEEXEC_EVALUATORS",
        "http://local:8080,http://global:8080,http://semantic:8080",
    ).split(",") if item.strip()]
    votes: list[dict] = []
    failures: list[str] = []

    def fetch_vote(endpoint: str) -> dict:
        with httpx.Client(timeout=70) as client:
            response = client.post(f"{endpoint}/evaluate", json=to_dict(request))
            response.raise_for_status()
            return response.json()

    with ThreadPoolExecutor(max_workers=3) as pool:
        futures = {pool.submit(fetch_vote, endpoint): endpoint for endpoint in endpoints}
        for future in as_completed(futures):
            try:
                votes.append(future.result())
            except Exception as exc:
                failures.append(f"{futures[future]}:{type(exc).__name__}")
    if len(votes) < 2:
        return False, "Insufficient evaluator responses: " + ", ".join(failures)

    with httpx.Client(timeout=15) as client:
        broker_url = os.environ.get("SAFEEXEC_BROKER", "http://broker:8080")
        response = client.post(f"{broker_url}/decide", json={"request": to_dict(request), "votes": votes})
        response.raise_for_status()
    token = token_from_dict(response.json())
    broker_public = Path(os.environ.get("SAFEEXEC_BROKER_PUBLIC_KEY", "/run/secrets/broker_public"))
    if not verify_release(token, broker_public, request, int(time.time())):
        return False, "Release token rejected"
    token_db = Path(os.environ.get("SAFEEXEC_TOKEN_DB", ".safeexec-tokens.sqlite3"))
    token_db.parent.mkdir(parents=True, exist_ok=True)
    try:
        with sqlite3.connect(token_db) as db:
            db.execute("CREATE TABLE IF NOT EXISTS used (request_id TEXT PRIMARY KEY, used_at INTEGER NOT NULL)")
            db.execute("INSERT INTO used(request_id, used_at) VALUES (?, ?)", (request.request_id, int(time.time())))
    except sqlite3.IntegrityError:
        return False, "Release token already used"
    exit_code, stdout, stderr = execute_e2b(filepath.name, content, timeout)
    return exit_code == 0, stdout + stderr
