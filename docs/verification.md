# Verification status

## Local qualification

The generic repository was qualified locally on macOS with host Python 3.14.7,
Python 3.12 pinned inside its execution containers, Hermes Agent v0.19.1 at
upstream revision `26e0b1c12c2bbc2d1ef4640df18abff2d737445a`, Docker 29, and an
ARM64 Docker engine. This is the tested revision, not a claim that every build
reporting the same semantic version is equivalent.

The current local release checks cover 42 controller/adapter tests and:

- controller and adapter unit tests;
- deterministic retry, exhaustion, timeout, injection rejection, and cleanup;
- path, symlink, binary, mode, size, digest, and artifact-tampering denial;
- provider-environment scrubbing and scoped container cleanup;
- execution-plan binding to incident, required test, and path policy;
- repository and controller-owned verification;
- candidate-test timeout cleanup with exact container ownership checks;
- a successful disposable PostgreSQL 14.24, Kafka 4.3.1, and OpenSearch 3.8.0 scenario;
- clean-workspace patch reapplication and exact candidate digest;
- a successful real Hermes CLI and isolated-terminal scripted-provider smoke test;
- a hash-bound, expiring Trivy image-vulnerability baseline;
- zero remaining Compose resources after the qualified service run.

The service example processed four synthetic events, retained three unique event identities, produced two tenant-scoped search documents, and rejected a write through the read-only evidence role.

## Not yet proven

- A provider-neutral real-model qualification from a clean public clone
- Linux AMD64 and Windows host qualification
- Durable crash recovery and concurrent-run coordination
- Signed or immutable attestations
- Live evidence or delivery connectors
- Real repository and CI parity for any external project
- Production security, privacy, cost, retention, and operational readiness

Run `./scripts/run-local.sh test`, the relevant scenario, `verify`,
`python3 scripts/check-public-surface.py`, and the image-vulnerability check on
the release candidate rather than relying on this document alone.
