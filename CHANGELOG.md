# Changelog

## 0.1.0 - Unreleased

- Added a policy-controlled local remediation controller.
- Added deterministic success, retry, exhaustion, timeout, and injection-rejection scenarios.
- Added a reusable isolated Hermes profile and remediation skill.
- Added optional PostgreSQL, Kafka, and OpenSearch verification for a synthetic event-indexing incident.
- Added exact-patch, clean-reapply, artifact-linkage, environment-scrubbing, and cleanup checks.
- Added public documentation, CI, schemas, and disclosure checks.
- Isolated every candidate test and verifier from the host in a locked-down Docker sandbox.
- Hash-locked verifier dependencies and upgraded kafka-python to 2.3.2.
- Refreshed disposable service pins and added an expiring, hash-bound image vulnerability baseline.
