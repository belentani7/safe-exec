# Security policy

SAFE-EXEC makes a narrow, explicit promise: a decision about **exact bytes**,
supported by signed evidence, with the sandbox as the last line. Treat every
claim below as a boundary you can verify, not as a guarantee you can assume.

## Reporting a vulnerability

Please use GitHub's private channel:

**<https://github.com/belentani7/safe-exec/security/advisories/new>**

Do not open a public issue for anything that could let code escape evaluation,
forge a vote, replay a token, or silently bypass the static policy. If you are
unsure whether something qualifies, report it privately; we would rather triage
a false alarm than miss a real one.

Include:

- the version or commit you tested;
- a minimal reproducer (source snippet, request body, or command);
- what you expected versus what happened;
- any assumption you had to make about the deployment.

## What is in scope

| Area | Examples |
| --- | --- |
| Static policy | Evading `blocked_calls` / `blocked_imports` / `blocked_literals`, crashing the analyser, exhausting its budget |
| Protocol | Forging a vote, replaying a token, bypassing the LOCAL requirement, confusing the confidence floor |
| Bytes binding | Making the sandbox execute different bytes than were evaluated |
| Services | Malformed request bodies that cause 5xx instead of a controlled denial, unbounded memory use |
| Packaging | Installing the wheel and getting a broken or unverified policy |

## What is out of scope

- Compromise of the host kernel, the Docker daemon, or the E2B control plane.
- Theft of private keys from container memory.
- Two compromised evaluators that include LOCAL — the threat model assumes at
  most one optional evaluator is dishonest or unavailable.
- Side channels, denial of service, traffic analysis.
- Malicious behaviour that passes static, reputation and semantic review.
- Native binaries or languages other than Python.

These are documented in [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md). A report
that one of them exists is welcome as research; it is not a vulnerability claim.

## Supported versions

| Version | Supported |
| --- | --- |
| 1.1.x | Yes |
| 1.0.x | No (the wheel did not ship its policy; upgrade) |

## Our commitment

- Acknowledge a private report within 7 days.
- Publish a fix and an advisory for confirmed issues affecting supported versions.
- Credit reporters unless they prefer to remain anonymous.
- Say plainly when something is a known limitation rather than a bug.

## Hardening checklist for operators

1. Run each evaluator in a separate administrative domain.
2. Keep private keys in a KMS/HSM; never commit `secrets/`.
3. Put mTLS in front of the broker; the reference compose file does not.
4. Pin images by digest and publish an SBOM.
5. Configure the E2B template with explicit network, CPU, memory and filesystem
   limits; SAFE-EXEC denies network access by default but cannot widen that
   guarantee beyond what the provider enforces.
6. Rotate keys on a schedule and prune the replay database
   (`ConsensusBroker.prune`).
