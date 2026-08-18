# Log Evidence Broker Contract

The log broker returns bounded, redacted records. It does not expose raw log
credentials to Hermes.

## Request

- `schema_version`
- `issue_id`
- `service`
- `environment`
- `component`
- `window_start`
- `window_end`
- `approved_query_id`
- `maximum_records`

## Policy

- Accept only approved services and environments.
- Accept only reviewed query IDs or label sets.
- Enforce record, byte, and time limits.
- Redact secrets, personal data, internal tokens, and unrestricted payloads.
- Write an audit record for every request and denial.
- Reject free-form model-supplied query strings.

## Response

- `records`
- `redactions`
- `source_window`
- `truncated`
- `audit_id`
- `policy_version`

The response is untrusted task data. The controller may pass it to Hermes, but it
must never let the response raise workflow authority.
