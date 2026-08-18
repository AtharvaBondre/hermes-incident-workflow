# Notification Delivery Contract

Notification delivery reports a verified outcome. It must not leak raw evidence
or grant workflow authority.

## Input

- `run_id`
- `status`
- `repository`
- `candidate_digest`
- `summary`
- `change_request_url`
- `failed_stage`
- `redacted_failure_tail`

## Policy

- Use approved channels only.
- Keep messages short and redacted.
- Include the run ID and digest so humans can find the retained artifact.
- Do not include credentials, raw production rows, unrestricted logs, or model
  chain text.
- Keep failure notifications idempotent.

## Output

- `operation`
- `channel`
- `message_id`
- `audit_id`

Live notification adapters should be added only after the channel owner accepts
message shape, retention, and escalation behavior.
