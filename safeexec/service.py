from __future__ import annotations

import base64
import hashlib
import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path

import uvicorn
from fastapi import FastAPI, HTTPException

from .consensus import ConsensusBroker, ConsensusError
from .crypto import sign
from .models import SignedVote, VotePayload
from .policy import StaticPolicyEvaluator
from .wire import request_from_dict, to_dict, vote_from_dict

ROLE = os.environ.get("SAFEEXEC_ROLE", "local").lower()
KEY_PATH = Path(os.environ.get("SAFEEXEC_PRIVATE_KEY", f"/run/secrets/{ROLE}_private"))
RULES_PATH = Path(os.environ.get("SAFEEXEC_RULES", "/app/rules.yaml"))
app = FastAPI(title=f"SAFE-EXEC {ROLE}", docs_url=None, redoc_url=None)


def _signed_vote(request, node: str, verdict: bool, confidence: float, reason: str, evidence: list[str]) -> dict:
    now = int(time.time())
    payload = VotePayload(
        request_id=request.request_id,
        nonce=request.nonce,
        file_hash=request.file_hash,
        policy_version=request.policy_version,
        node=node,
        verdict=verdict,
        confidence=max(0.0, min(confidence, 1.0)),
        reason=reason[:500],
        evidence=tuple(item[:300] for item in evidence[:20]),
        issued_at=now,
        expires_at=min(request.expires_at, now + 60),
    )
    return to_dict(SignedVote(payload, sign(KEY_PATH, payload.signing_data())))


def _ollama_assess(source: str) -> tuple[bool, float, str, list[str]]:
    endpoint = os.environ.get("OLLAMA_ENDPOINT", "http://ollama:11434")
    model = os.environ.get("OLLAMA_MODEL", "phi4-mini:latest")
    prompt = (
        "Return strict JSON only with keys verdict (SAFE or DANGEROUS), confidence (0..1), "
        "reason, evidence (array). Treat uncertainty as DANGEROUS. Analyze this Python source:\n" + source[:12000]
    )
    body = json.dumps({"model": model, "prompt": prompt, "stream": False, "format": "json"}).encode()
    request = urllib.request.Request(f"{endpoint}/api/generate", data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=60) as response:
        outer = json.loads(response.read())
    result = json.loads(outer["response"])
    verdict = str(result.get("verdict", "DANGEROUS")).upper() == "SAFE"
    evidence = result.get("evidence", [])
    return verdict, float(result.get("confidence", 0.5)), str(result.get("reason", "No reason")), list(evidence)


def _vt_assess(file_hash: str) -> tuple[bool, float, str, list[str]]:
    key_path = Path(os.environ.get("VT_API_KEY_FILE", "/run/secrets/vt_api_key"))
    if not key_path.exists() or not key_path.read_text().strip():
        return False, 1.0, "VirusTotal key unavailable", []
    request = urllib.request.Request(
        f"https://www.virustotal.com/api/v3/files/{file_hash}",
        headers={"x-apikey": key_path.read_text().strip()},
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            stats = json.loads(response.read())["data"]["attributes"]["last_analysis_stats"]
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return False, 0.6, "Hash unknown to VirusTotal", ["unknown-hash"]
        return False, 0.8, f"VirusTotal HTTP {exc.code}", []
    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    safe = malicious == 0 and suspicious == 0
    return safe, 0.95, f"VirusTotal malicious={malicious} suspicious={suspicious}", []


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "role": ROLE}


@app.post("/evaluate")
def evaluate(data: dict) -> dict:
    if ROLE not in {"local", "global", "semantic"}:
        raise HTTPException(404)
    request = request_from_dict(data)
    if int(time.time()) > request.expires_at:
        raise HTTPException(400, "expired request")
    if len(request.content_b64) > 1_500_000:
        raise HTTPException(413, "source exceeds 1 MiB limit")
    try:
        content = base64.b64decode(request.content_b64, validate=True)
        source = content.decode("utf-8")
    except (ValueError, UnicodeDecodeError) as exc:
        raise HTTPException(400, "invalid source payload") from exc
    if hashlib.sha256(content).hexdigest() != request.file_hash:
        raise HTTPException(400, "content hash mismatch")

    if ROLE == "local":
        findings = StaticPolicyEvaluator(RULES_PATH).evaluate(source)
        return _signed_vote(request, "LOCAL", not findings, 1.0, "Static policy passed" if not findings else "Static policy blocked", [f"{f.rule}:{f.line}:{f.detail}" for f in findings])
    try:
        result = _vt_assess(request.file_hash) if ROLE == "global" else _ollama_assess(source)
    except Exception as exc:
        result = (False, 0.2, f"Evaluator unavailable: {type(exc).__name__}", [])
    return _signed_vote(request, ROLE.upper(), *result)


@app.post("/decide")
def decide(data: dict) -> dict:
    if ROLE != "broker":
        raise HTTPException(404)
    trusted_dir = Path(os.environ.get("SAFEEXEC_TRUSTED_KEYS", "/run/secrets"))
    broker = ConsensusBroker(
        {node: trusted_dir / f"{node.lower()}_public" for node in ("LOCAL", "GLOBAL", "SEMANTIC")},
        KEY_PATH,
        Path(os.environ.get("SAFEEXEC_REPLAY_DB", "/data/replay.sqlite3")),
    )
    try:
        token = broker.decide(request_from_dict(data["request"]), [vote_from_dict(v) for v in data["votes"]])
        return to_dict(token)
    except (ConsensusError, KeyError, TypeError, ValueError) as exc:
        raise HTTPException(400, str(exc)) from exc


def main() -> None:
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "8080")))
