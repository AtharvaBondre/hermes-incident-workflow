# Customer Pack Template

This template shows how to adapt Hermes Incident Workflow for one organization
without placing private details in the public core repository.

Copy this directory into a private location, then replace the placeholder values
with reviewed customer-specific policy.

## Files

- `workflow.json`: trusted operator policy for repository scope, evidence caps,
  validation, Hermes profile, and limits.
- `incidents/example-incident.json`: a sanitized incident packet used for dry
  runs.
- `evidence/example-evidence.json`: bounded synthetic evidence shaped like the
  target evidence broker output.
- `connectors/`: contracts for brokered read-only evidence.
- `delivery/`: contracts for draft-only source-control and notification output.
- `runbooks/pilot-readiness.md`: checklist before using live evidence.

## Fill-in order

1. Define the trusted workflow policy.
2. Create a synthetic incident that exercises one real failure class.
3. Add visible repository tests and controller-owned verifier logic.
4. Run deterministic fixture attempts.
5. Qualify a real Hermes model on synthetic data.
6. Add brokered live connectors only after the private threat model is accepted.

## Safety boundary

The private pack may contain real names and internal contracts. Do not commit it
back into the public repository unless it has been fully sanitized.
