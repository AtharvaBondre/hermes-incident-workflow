# Adapting the workflow

For a real organization, start by copying `customer-pack-template/` into a
private location and filling in the policy and broker contracts there. Keep this
public repository limited to reusable controller code, synthetic fixtures, and
generic documentation.

## Start with a new synthetic scenario

1. Add a minimal buggy repository under `fixtures/repositories/<scenario>/`.
2. Add visible tests inside that repository.
3. Add a normalized incident and evidence packet under `fixtures/`.
4. Add a required controller-owned verifier under `verifiers/`. Use
   `candidate_probe.py` so candidate imports and calls remain in a subordinate
   executor behind its trusted supervisor; keep assertions and the completion
   marker in the trusted verifier parent.
5. Add reviewed fixture patches for deterministic success and failure paths.
6. Register the scenario in `fixtures/scenarios.json`.
7. Run it without a model before enabling the Hermes provider.

Give the incident an exact `allowed_paths` list and give the trusted scenario
the same sorted `allowed_changed_paths` list. The controller rejects a mismatch
before constructing a worker request, even when both lists remain beneath the
broader package path prefixes. Set `independent_diagnosis` to `true` when the
worker must receive no prewritten diagnosis or edit plan.

Keep customer names, real identifiers, internal endpoints, credentials, and retained model sessions out of examples.

## Change trusted policy

Edit `config/workflow.json` to select the fixture repository contract, allowed service and environment, path prefixes, evidence caps, required test, Hermes profile, and hard limits.

Policy is trusted operator input. Do not derive these values from incident text or model output.

After editing policy, inspect the effective operator surface:

```bash
./scripts/run-local.sh dump-policy
```

Review the output before running a model. It is the compact product-facing view
of what the controller will allow: repository, service, environment, paths,
evidence caps, required test, Hermes profile, limits, delivery authority, and
safety-mode pattern.

For a customer pack, keep the public `config/workflow.json` as an example and
store the real policy in the private pack. Do not publish repository names,
internal evidence sources, channels, reviewers, or provider decisions unless the
owner has explicitly approved publication.

## Add another language

Replace the fixture repository and test command, then update the Docker profile image only if the editing toolchain needs another runtime. Keep the same read-only inputs, single writable output, no network, no credential forwarding, and host-derived patch policy.

Add policy tests for language-specific links, generated files, lockfiles, binary output, and test-command handling.

## Add an evidence broker

A broker should accept a normalized query contract and return only bounded, redacted data. It should enforce:

- fixed data source and operation;
- label, table, view, or query allowlists;
- row, byte, and time limits;
- read-only credentials that the model never receives;
- tenant and incident scoping;
- deterministic redaction and audit metadata.

Do not let free-form model text become a database query, log query, shell command, or cloud API request.

Implement each broker as a deterministic pipeline:

```text
request -> validate -> authorize -> execute -> redact -> record -> verify
```

The model should receive the redacted broker result, not the credential, raw
query surface, or live client.

## Add a delivery adapter

Accept only a verified run ID, exact patch digest, candidate digest, target repository, and approved metadata. Expose only the minimum draft operation required.

Keep merge, approval, deployment, protected-branch bypass, incident mutation, and production writes out of the model-facing interface.

The public workflow should keep file-based draft mocks. Live delivery adapters
belong in customer packs until their permissions, branch protection, retry
behavior, and message redaction have been reviewed.

## Real-model qualification

Use a dedicated Hermes profile and an approved provider. Run repeated synthetic
scenarios, including a visible-test pass followed by a held-out-check failure,
distinct retry candidate, malformed proposal output, provider timeout, cleanup
failure, path-policy denial, usage capture, manifest tampering, and retained-path
redaction.

Do not make a credentialed model run a required public CI job. Keep it an
explicit manual qualification step. Local synthetic proof is not customer or
live readiness; document missing provider, repository, connector, and operating
environment evidence as limitations.
