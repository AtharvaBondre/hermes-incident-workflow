# Verification status

## Local qualification

The generic repository's unit and fixture controls were qualified locally on
macOS with host Python 3.14.7, Python 3.12 pinned inside its execution
containers, Hermes Agent v0.23.1 at
source revision `3b421578588243f920886e6fe79a6faa87ea026e`, Docker 29, and an
ARM64 Docker engine. This is the tested revision, not a claim that every build
reporting the same semantic version is equivalent.

The current local release checks cover 102 controller/adapter tests and:

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
- a disposable PostgreSQL 14.25, Kafka 4.3.2, and OpenSearch 3.9.0 service
  contract with fail-closed pinned-image preflight;
- clean-workspace patch reapplication and exact candidate digest;
- a required real Hermes CLI and isolated-terminal scripted-provider smoke
  gate;
- a hash-bound, expiring Trivy image-vulnerability baseline;
- fail-closed cleanup checks that require zero remaining Compose resources
  after any service run.

The service verifier requires four synthetic events, three unique event
identities, two tenant-scoped search documents, and a rejected write through
the read-only evidence role.

## Superseded 2026-09-10 maintenance check

The earlier maintenance check demonstrated fail-closed behavior for unavailable
service images, a mismatched Hermes checkout, and an out-of-date vulnerability
baseline. It made no provider call. Those historical failures are not evidence
for the current pins; the 2026-11-16 qualification below replaces their runtime
and image conclusions.

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

## 2026-11-16 upstream review

- `./scripts/run-local.sh test` passed all 102 controller and adapter tests on
  the current release candidate.
- All ten reusable controls remain present in the generic controller and local
  synthetic qualification: optional independent diagnosis, strict readiness
  and path binding, exact incident paths, genuine held-out retry, exact
  nullable usage, retained linkage, path redaction, a closed sanitized SHA-256
  manifest, Docker/service preflight, and explicit synthetic-only claims.
- Hermes Agent v0.23.1 at commit
  `3b421578588243f920886e6fe79a6faa87ea026e` is the current qualified external
  runtime. Disposable installation, exact checkout identity, packaging hashes,
  and profile installation passed without a provider or inference call. The
  unsigned upstream tag is not accepted without those additional bindings.
- The current upstream security policy recognizes OS-level isolation as the
  containment boundary and recommends whole-process wrapping for untrusted
  surfaces. This repository's host Hermes process has not passed such a
  whole-process qualification, so real-model and untrusted-input readiness
  remain blocked.
- The Python, PostgreSQL, Kafka, and OpenSearch image pins were refreshed and
  reviewed with a hash-bound synthetic-only exception through 2026-12-16.
  Their residual HIGH and CRITICAL findings remain production blockers.
- The two-attempt `retry-success` run at
  `artifacts/20261116T062959Z-8b10e579` succeeded and its independent
  verification reported no issues.
- The pinned PostgreSQL, Kafka, and OpenSearch service run at
  `artifacts/20261116T065109Z-be1240c0` succeeded, its independent verification
  reported no issues, and its Compose resources were cleaned up.
- The exact-v0.23.1 no-external-provider scripted sandbox smoke at
  `artifacts/20261116T072229Z-hermes-sandbox` passed every recorded runtime,
  containment, tool-surface, gateway, container, profile, and cleanup check.
- Trivy 0.70.0 reproduced the hash-bound image-vulnerability baseline with no
  comparison issues. The public-surface scan and `git diff --check` also
  passed on the release candidate.

These results are local, synthetic qualification only. They used no paid model
provider, customer evidence, live connector, or production system, and do not
establish customer, real-model, live, or production readiness.

Run `./scripts/run-local.sh test`, the relevant scenario, `verify`,
`python3 scripts/check-public-surface.py`, and the image-vulnerability check on
the release candidate rather than relying on this document alone.
