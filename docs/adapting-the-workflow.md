# Adapting the workflow

## Start with a new synthetic scenario

1. Add a minimal buggy repository under `fixtures/repositories/<scenario>/`.
2. Add visible tests inside that repository.
3. Add a normalized incident and evidence packet under `fixtures/`.
4. Add a controller-owned verifier under `verifiers/` when visible tests are insufficient.
5. Add reviewed fixture patches for deterministic success and failure paths.
6. Register the scenario in `fixtures/scenarios.json`.
7. Run it without a model before enabling the Hermes provider.

Keep customer names, real identifiers, internal endpoints, credentials, and retained model sessions out of examples.

## Change trusted policy

Edit `config/workflow.json` to select the fixture repository contract, allowed service and environment, path prefixes, evidence caps, required test, Hermes profile, and hard limits.

Policy is trusted operator input. Do not derive these values from incident text or model output.

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

## Add a delivery adapter

Accept only a verified run ID, exact patch digest, candidate digest, target repository, and approved metadata. Expose only the minimum draft operation required.

Keep merge, approval, deployment, protected-branch bypass, incident mutation, and production writes out of the model-facing interface.

## Real-model qualification

Use a dedicated Hermes profile and an approved provider. Run repeated synthetic scenarios, including failed first attempts, malformed proposal output, provider timeout, cleanup failure, and patch-policy denial.

Do not make a credentialed model run a required public CI job. Keep it an explicit manual qualification step.
