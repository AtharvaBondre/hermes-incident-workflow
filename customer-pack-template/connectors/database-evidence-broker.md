# Database Evidence Broker Contract

The database broker returns bounded read-only evidence from approved views. It
does not expose database credentials to Hermes.

## Request

- `schema_version`
- `issue_id`
- `service`
- `environment`
- `approved_view`
- `filters`
- `maximum_rows`
- `timeout_seconds`

## Policy

- Use a database role that cannot write.
- Connect only to the approved non-primary endpoint for the selected
  environment.
- Allow only named views or stored read paths.
- Enforce row, byte, and timeout limits.
- Reject DDL, DML, unsafe functions, raw SQL from incidents, and cross-scope
  filters.
- Redact sensitive fields before returning data.
- Record endpoint identity, role identity, view name, row count, and denial
  reason.

## Response

- `rows`
- `redactions`
- `view`
- `row_count`
- `truncated`
- `audit_id`
- `policy_version`

The broker should be tested with known allowed reads and known denied writes
before any live pilot.
