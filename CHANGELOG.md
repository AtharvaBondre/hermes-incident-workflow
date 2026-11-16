# Changelog

## Unreleased

- Qualified Hermes Agent v0.23.1 at an exact source revision and packaging
  identity, including its expanded disposable cache-mount contract.
- Refreshed the digest-pinned Python, PostgreSQL, Kafka, and OpenSearch images
  and their hash-bound, synthetic-only vulnerability exceptions through
  2026-12-16; no image is thereby cleared for production.
- Extended only the OpenSearch startup allowance for the current 3.9.0 image;
  the health probe, resource limits, run deadline, and fail-closed dependency
  gate remain unchanged.
- Limited the Hermes terminal container to 256 processes and stop its
  disposable gateway before exact output-mount cleanup, while retaining
  fail-closed gateway and container cleanup evidence.
- Retained the upstream whole-process isolation limitation: the Docker terminal
  confines candidate commands but does not sandbox the host Hermes process.
- Added optional independent diagnosis, strict proposal/path binding, exact
  incident-to-scenario path policy, and retained held-out retry verification.
- Added provider-reported per-attempt and aggregate usage evidence, package/home
  path redaction, and sanitized SHA-256 artifact manifests.
- Made the pinned candidate image a fail-closed preflight dependency and limited
  `--with-docker` to scenarios with an explicit service-stack contract.
- Added public, profile-scoped Hermes model and credential setup guidance plus
  a no-request preflight check for the selected workflow profile.
- Removed dated continuation and internal roadmap documents from the public
  tree and added a public-surface regression guard for them.

## 0.1.0 - 2026-08-18

- Added a policy-controlled local remediation controller.
- Added deterministic success, retry, exhaustion, timeout, and injection-rejection scenarios.
- Added a reusable isolated Hermes profile and remediation skill.
- Added optional PostgreSQL, Kafka, and OpenSearch verification for a synthetic event-indexing incident.
- Added exact-patch, clean-reapply, artifact-linkage, environment-scrubbing, and cleanup checks.
- Added public documentation, CI, schemas, and disclosure checks.
- Added customer-pack guidance, connector contracts, and a reusable private-pack
  template for organization-specific adoption.
- Isolated every candidate test and verifier from the host in a locked-down Docker sandbox.
- Hash-locked verifier dependencies and upgraded kafka-python to 2.3.2.
- Refreshed disposable service pins and added an expiring, hash-bound image vulnerability baseline.
