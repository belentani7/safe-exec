# Originality and positioning

## Accurate claim

SAFE-EXEC is an admission-control system for agent-generated code. It combines heterogeneous pre-execution assessments with signed, request-bound evidence and a one-use release token.

## Established foundations

- Zero Trust authorization
- Ed25519 signatures
- Threshold/quorum decisions
- Software attestations and policy admission
- Static analysis, threat reputation and LLM review
- Disposable execution sandboxes

None of those components is new by itself. “Byzantine consensus” is not an accurate claim for a single-host Docker deployment because the host and runtime remain a shared failure domain.

## Potential differentiation

- Designed specifically for autonomous agents about to execute generated code
- Three heterogeneous evaluators with evidence users can inspect
- Exact-byte binding from evaluation through sandbox upload
- Fail-closed local policy plus degraded operation when one optional evaluator is unavailable
- Small deployable reference implementation instead of an enterprise policy stack

## Evidence needed for a strong project

- Benchmark corpus of benign, malicious and obfuscated programs
- False-positive and false-negative rates per evaluator and ensemble
- Latency and cost measurements
- Red-team results against replay, forgery, prompt injection and TOCTOU
- Comparison with Sigstore policy-controller, in-toto attestations and existing sandbox products

Patent novelty is not established by this repository. It requires a professional prior-art search and narrowly defined claims.
