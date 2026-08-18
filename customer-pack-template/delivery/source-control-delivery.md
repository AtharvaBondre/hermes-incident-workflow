# Source-Control Delivery Contract

Delivery runs only after the controller accepts an exact candidate digest.

## Input

- `run_id`
- `repository`
- `base_revision`
- `candidate_digest`
- `patch_sha256`
- `changed_paths`
- `title`
- `body`
- `labels`
- `reviewers`

## Policy

- Accept only repositories and base branches from trusted workflow policy.
- Create a branch or draft change request only.
- Do not expose merge, approval, protected-branch bypass, deployment, or incident
  mutation.
- Verify that the patch digest and candidate digest match the accepted run.
- Redact evidence and model output before placing it in public or semi-public
  descriptions.
- Make retries idempotent by run ID and patch hash.

## Output

- `operation`
- `draft`
- `target_repository`
- `target_branch`
- `change_request_url`
- `audit_id`

The public project ships only file-based mocks. Live delivery adapters belong in
private customer packs until reviewed.
