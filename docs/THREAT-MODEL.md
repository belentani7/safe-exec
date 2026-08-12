# Threat model

## Protected decision

SAFE-EXEC protects one decision: whether exact Python bytes identified by SHA-256 may be executed once in an external disposable sandbox.

## Trusted computing base

- Host kernel and container runtime
- Orchestrator binary and broker public key
- Broker private key and replay database
- At least LOCAL plus one other uncompromised evaluator
- E2B control plane and sandbox isolation
- Cryptography and HTTP/TLS implementations

## Defended threats

- Forged evaluator vote without its Ed25519 private key
- Vote copied to another request, nonce, file hash or policy version
- Expired vote or release token
- Duplicate evaluator identity
- Replay at broker and single orchestrator deployment
- File replacement between evaluation and upload to E2B
- Loss of one optional evaluator
- Common dangerous Python calls identified through AST policy

## Not defended in version 1

- Compromise of host kernel or Docker daemon
- Two compromised approving evaluators including LOCAL
- Theft of keys from container memory
- Side channels, denial of service or traffic analysis
- Unknown malicious behavior that passes static and semantic review
- E2B escape or provider compromise
- Native binaries or languages other than Python
- Replay across multiple orchestrators without a shared token database

## Production gates

1. Run nodes in distinct administrative domains.
2. Store private keys in KMS/HSM and use short-lived workload identities.
3. Add mTLS with service identity and certificate rotation.
4. Record requests, votes and releases in an append-only transparency log.
5. Pin container images by digest; publish SBOM and signed provenance.
6. Fuzz parsers and protocol bindings; commission an external security review.
7. Configure a sandbox template with explicit network, CPU, memory, process and filesystem policy.
