# Customer Packs

A customer pack is the private layer that adapts this generic workflow to one
company, repository, incident source, evidence plane, and delivery process.

The public repository should stay generic. Customer packs should stay private
when they contain real repository names, internal endpoints, table names, log
labels, delivery channels, provider choices, or operational runbooks.

## What belongs in the public repository

- The deterministic controller and its tests.
- Generic schemas, policy validation, patch validation, artifact linkage, and
  cleanup behavior.
- Synthetic incidents and fixture repositories.
- Draft-only delivery mocks.
- Connector contracts and examples that contain no real customer data.
- Documentation that explains how to adapt the workflow safely.

## What belongs in a private customer pack

- The selected repository, base branch, allowed path prefixes, and required test
  command.
- The incident trigger contract and authentication policy.
- Log and database broker configuration.
- Approved evidence views, labels, row limits, field allowlists, redaction rules,
  and timeouts.
- The Hermes profile, provider, model, and retention policy approved by the
  customer.
- GitHub, GitLab, Slack, Teams, PagerDuty, Jira, or other delivery adapters.
- Pilot runbooks, owner mappings, rollback contacts, and escalation rules.
- Customer-specific fixture incidents that have been sanitized for local testing.

## Pack layout

Use `customer-pack-template/` as the starting point:

```text
customer-pack-template/
  README.md
  workflow.json
  incidents/example-incident.json
  evidence/example-evidence.json
  connectors/
    database-evidence-broker.md
    log-evidence-broker.md
  delivery/
    notification-delivery.md
    source-control-delivery.md
  runbooks/
    pilot-readiness.md
```

The template is intentionally documentation-first. It defines the contract before
any live credential or connector exists.

## Adoption sequence

1. Copy the template into a private repository or private directory.
2. Fill in `workflow.json` with the target repository, service, environment,
   path prefixes, test command, evidence caps, Hermes profile, and hard limits.
3. Inspect the resolved policy with `./scripts/run-local.sh dump-policy` and
   confirm the repository, paths, evidence caps, test command, Hermes profile,
   attempt limits, and delivery authority match the intended mode.
4. Add a synthetic incident that resembles one real class of issue without using
   production data. Give it an exact path allowlist that matches the trusted
   scenario list and remains beneath the package policy.
5. Add visible repository tests and at least one controller-owned verifier.
6. Run the deterministic fixture flow until success, failure, retry, timeout,
   and cleanup behavior are predictable.
7. Add brokered evidence connectors behind fixed allowlists.
8. Add draft-only delivery adapters.
9. Run a real-model qualification on synthetic data.
10. Complete the pilot readiness checklist before any live evidence is used.

## Mode mapping

A customer pack should state which operating mode it implements before any live
connector is added:

- `synthetic`: fixture-only development and demos.
- `dry-run`: customer-specific fixtures with no live systems.
- `shadow-readonly`: bounded live evidence reads, no delivery.
- `live-evidence-readonly`: live evidence reads plus local artifact output.
- `draft-pr-only`: live evidence reads plus digest-bound draft delivery.

Do not infer the mode from incident text. The mode is operator-owned policy and
should be visible in the policy review output.

## Non-negotiable boundaries

- Incident text must not choose the repository, test command, delivery target,
  credential, model, attempt limit, or allowed paths. An incident path list must
  exactly match the trusted scenario list before any worker request is built.
- The model must not receive raw production credentials.
- Evidence brokers must return bounded, redacted data and reject free-form
  queries.
- Delivery adapters must expose only the approved draft operation.
- Merge, approval, deployment, incident mutation, production writes, and
  protected-branch bypass remain outside the workflow.
- A customer pack is not production-ready until its live connectors, provider
  retention, audit storage, cost controls, cleanup, and owner escalation have
  been reviewed separately.
