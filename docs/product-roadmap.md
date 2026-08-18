# Product Roadmap

This project is a local-first reference implementation today. The product
direction is a configurable incident-remediation workflow that customers can run
against their own repositories, evidence sources, and delivery process while
preserving the core rule: Hermes proposes, the controller decides.

## Current product boundary

The current release supports:

- synthetic incidents and fixture repositories;
- deterministic retry, exhaustion, timeout, and injection-rejection paths;
- a real Hermes adapter for explicit manual qualification;
- isolated candidate editing and testing;
- optional disposable PostgreSQL, Kafka, and OpenSearch verification;
- draft-only file delivery;
- auditable artifacts and cleanup records.

It intentionally does not include live production connectors.

## Near-term work

- Add a packaged customer-pack loader that can point at a private pack path.
- Add connector interfaces for log evidence, database evidence, source-control
  delivery, and notification delivery.
- Add more synthetic scenarios for API regressions, background jobs, migrations,
  and test-failure repair.
- Add a repeated real-model qualification script that records pass rate, retry
  behavior, runtime, cleanup, and proposal-schema quality.
- Add signed or externally stored attestations for retained run evidence.
- Add Linux AMD64 qualification from a clean public clone.

## Connector roadmap

Connectors should be brokered services, not raw credentials exposed to the
model. Each connector should accept a versioned request, enforce policy, return
bounded redacted output, and write an audit record.

Candidate connector families:

- log evidence broker;
- relational database evidence broker;
- source-control draft publisher;
- notification publisher;
- incident-trigger receiver;
- artifact retention sink.

## Product packaging roadmap

- Keep the public repository as the reusable core.
- Keep private customer packs outside the public repository.
- Publish versioned releases with compatibility notes for Hermes Agent, Docker,
  Python, and container image pins.
- Provide an operator checklist for each release.
- Maintain a threat model for every connector family before adding live effects.

## Readiness levels

| Level | Meaning |
|---|---|
| Local fixture | Synthetic incident passes without model credentials. |
| Local real-model | Synthetic incident passes with a real Hermes model. |
| Customer-pack dry run | Private pack passes with sanitized customer-shaped data. |
| Non-production pilot | Brokered connectors run against approved non-production systems. |
| Production evidence pilot | Read-only production evidence is used with customer approval. |
| Production workflow | Repeatability, recovery, audit, cost, and ownership are proven. |

Do not skip readiness levels by adding a live connector directly to the public
fixture path.
