# Pilot Readiness Checklist

Use this checklist before any customer pack reads live evidence or creates a
real draft change request.

## Policy

- [ ] Repository, base branch, and allowed path prefixes are reviewed.
- [ ] Required test commands are fixed in trusted policy.
- [ ] Attempt ceiling and remediation deadline are agreed.
- [ ] Provider, model, prompt-data retention, and model-memory behavior are
      accepted.
- [ ] Human review, merge, deployment, and incident-state boundaries are written
      down.

## Evidence

- [ ] Log broker accepts only reviewed query IDs or labels.
- [ ] Database broker accepts only reviewed views or stored read paths.
- [ ] Broker credentials are unavailable to Hermes tools.
- [ ] Row, byte, record, time, and redaction limits are tested.
- [ ] Write attempts, unsafe queries, and cross-scope requests are denied.

## Verification

- [ ] Synthetic fixture run succeeds.
- [ ] First-attempt failure and repair behavior is proven.
- [ ] Exhaustion, timeout, cancellation, malformed proposal, and cleanup cases
      are proven.
- [ ] Candidate tests and controller verifiers run outside the editable
      workspace.
- [ ] Cleanup leaves no owned containers, volumes, networks, or workspaces.

## Delivery

- [ ] Source-control adapter can create only draft changes.
- [ ] Merge, approval, deployment, and protected-branch bypass are absent.
- [ ] Notification adapter redacts evidence and links to retained artifacts.
- [ ] Delivery failure and retry behavior is tested.

## Operations

- [ ] Run owner, reviewer owner, evidence owner, and shutdown owner are named.
- [ ] Cost and rate limits are defined.
- [ ] Audit retention and deletion policy are defined.
- [ ] Incident escalation path is defined for failed or uncertain runs.
