# Verification status

## Local qualification

The generic repository was qualified locally on macOS with host Python 3.14.7,
Python 3.12 pinned inside its execution containers, Hermes Agent v0.20.6 at
source revision `5fc308a70719a83cccdbba4c0e39c23f5a8239d5`, Docker 29, and an
ARM64 Docker engine. This is the tested revision, not a claim that every build
reporting the same semantic version is equivalent.

The current local release checks cover 98 controller/adapter tests and:

- controller and adapter unit tests;
- effective-policy dump output and CLI JSON parsing;
- deterministic retry, exhaustion, timeout, injection rejection, and cleanup;
- path, symlink, binary, mode, size, digest, and artifact-tampering denial;
- provider-environment scrubbing and scoped container cleanup;
- exact Hermes checkout, clean-tree, `pyproject.toml`, and `uv.lock` identity;
- per-attempt disposable Hermes profile state hygiene, allowlisted credential
  bridging, exact upstream cache mounts, fail-closed profile cleanup, and a
  separate Docker boundary for terminal isolation;
- execution-plan binding to incident, required test, and path policy;
- optional independent diagnosis with no prior diagnosis or edit plan in the
  worker request;
- fail-closed equality between the incident exact-path allowlist and the trusted
  scenario list before worker execution;
- strict `candidate_ready`, zero test exit, and exact proposal-to-host-diff path
  binding;
- repository and controller-owned verification;
- rejection of candidate clean exits, forged success output, crashes, timeouts,
  and attempts to write the supervisor completion channel;
- required trusted verifier completion for runtime delivery eligibility and
  post-run verification across fixture and Hermes providers;
- exact per-scenario changed-file policy for every verified candidate surface;
- a held-out-check retry in which visible tests pass first, bounded feedback is
  digest-linked, the second attempt uses the original baseline, candidates are
  distinct, and publication occurs only after independent acceptance;
- post-run scenario and candidate-source inference from trusted request,
  candidate, event, and Hermes artifact evidence rather than mutable control
  labels, plus an independent replay of the rejected attempt that reconstructs
  its exact bounded feedback;
- exact provider-reported usage buckets and aggregate accounting, with
  reasoning retained as an output subset and unknown cost kept `null`;
- package/home path redaction plus an allowlisted SHA-256 manifest over every
  retained terminal-state artifact;
- fail-closed availability checks for the pinned candidate image and explicit
  service-stack contracts for `--with-docker`;
- candidate-test timeout cleanup with exact container ownership checks;
- a successful disposable PostgreSQL 14.24, Kafka 4.3.1, and OpenSearch 3.8.0 scenario;
- clean-workspace patch reapplication and exact candidate digest;
- a successful real Hermes CLI and isolated-terminal scripted-provider smoke test;
- a hash-bound, expiring Trivy image-vulnerability baseline;
- zero remaining Compose resources after the qualified service run.

The service example processed four synthetic events, retained three unique event identities, produced two tenant-scoped search documents, and rejected a write through the read-only evidence role.

## 2026-09-10 maintenance check

The control changes in the current working tree passed all 98 local tests, the
two-attempt `retry-success` scenario, post-run verification, idempotent cleanup,
and the public-surface scan. The service-stack preflight correctly failed before
evidence collection because three pinned service images were not installed; the
service scenario was therefore not re-qualified in this maintenance check.

The no-request Hermes sandbox smoke also failed closed before execution because
the installed Hermes build was v0.19.1 at a different source revision, while
this repository requires the qualified v0.20.6 revision. No model provider was
called. The image-vulnerability comparison failed because the current scanner
results differed from the recorded baseline for all five pinned images. The
baseline was deliberately not changed without security review. These three
results remain release blockers rather than successful qualification evidence.

## Not yet proven

- A provider-neutral real-model qualification from a clean public clone
- Linux AMD64 and Windows host qualification
- Durable crash recovery and concurrent-run coordination
- Signed or immutable attestations
- Live evidence or delivery connectors
- Real repository and CI parity for any external project
- Production security, privacy, cost, retention, and operational readiness

The new controls above were exercised with local synthetic fixtures and mocked
Hermes state only. This maintenance qualification made no paid provider call,
used no customer evidence, and does not establish customer or live readiness.
The real-model, provider-retention, billing, live-connector, and target-repository
claims remain unproven until separately authorized and evidenced.

Run `./scripts/run-local.sh test`, the relevant scenario, `verify`,
`python3 scripts/check-public-surface.py`, and the image-vulnerability check on
the release candidate rather than relying on this document alone.
