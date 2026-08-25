# Continuation handoff: 2026-08-25

Use this document as the first read for a new maintainer or AI-assisted coding
session on this repository.

## Repository

- Remote: `https://github.com/AtharvaBondre/hermes-incident-workflow.git`
- Default branch: `main`
- Current baseline before this handoff: `6a4915cb4bbe18d8be557db83a23c83747d29b86`
- License: Apache-2.0
- Status: open-source reference implementation, local-first, experimental POC.

Keep this repository customer-neutral. Do not add private customer names,
customer endpoints, internal account identifiers, credentials, retained provider
sessions, billing exports, or local absolute machine paths.

## Product objective

Hermes Incident Workflow demonstrates a bounded remediation loop:

1. A controller receives an incident with constrained evidence.
2. Hermes may inspect the task and propose a candidate code change.
3. The controller treats that candidate as untrusted.
4. The controller computes the patch from Git, enforces path/content policy,
   runs deterministic tests, optionally exercises disposable services, reapplies
   the accepted patch to a clean baseline, verifies the exact digest, writes
   draft delivery artifacts, and cleans up run resources.

The rule to preserve is:

```text
Hermes proposes; the controller decides.
```

The repository is not intended to grant an AI agent direct authority over merge,
approval, deployment, production writes, incident-status mutation, cloud
configuration, or unrestricted credentials.

## Current implementation surface

The main implementation and docs are:

- `scripts/runner.py` - controller, state machine, policy gates, attempts,
  verification, delivery mock generation, cleanup, and provider adapters.
- `scripts/run-local.sh` - operator entrypoint for preflight, test, run,
  verification, and policy inspection.
- `scripts/hermes_sandbox_smoke.py` - no-cost Hermes CLI smoke test using a
  local scripted model endpoint.
- `scripts/install-hermes-profile.sh` - installs the isolated Hermes profile.
- `scripts/check-public-surface.py` - checks that publish-sensitive terms do not
  appear in tracked repo content.
- `compose.event-indexing.yaml` - optional disposable PostgreSQL, Kafka, and
  OpenSearch verification scenario.
- `hermes-profile/` - locked-down Hermes profile and skill distribution.
- `customer-pack-template/` - placeholder-only private-pack structure for
  customer adaptation.
- `docs/architecture.md` - trust boundaries, execution stages, connector
  pipeline, and safety modes.
- `docs/verification.md` - verification flow and expected run evidence.
- `docs/customer-packs.md` - how private customer adapters should be packaged
  without polluting the public repo.
- `docs/security-baseline.md` and `docs/threat-model.md` - safety and threat
  model.
- `docs/model-costing.md` - current token-cost formula and public model-rate
  comparison structure.
- `docs/release-checklist.md` - publish/readiness checks.

## Proven behavior so far

The repository currently covers these flows:

- Deterministic success, retry-success, exhaustion, timeout, and prompt-injection
  rejection scenarios.
- A real Hermes candidate-provider adapter with a fresh session per attempt.
- A Hermes sandbox smoke test that uses a local scripted model endpoint and does
  not make a paid provider call.
- Network-disabled candidate-code test execution.
- Host-derived patch generation and policy enforcement.
- Clean-workspace reapplication with exact candidate digest verification.
- Draft-only delivery payloads for pull request and notification simulation.
- Disposable service verification with PostgreSQL, Kafka, and OpenSearch.
- Public-surface scanning to reduce accidental leakage of private/customer
  material.

Recent local validation before this handoff:

```bash
python3 scripts/check-public-surface.py
./scripts/run-local.sh test
./scripts/run-local.sh preflight
git diff --check
```

Expected current results:

- Public-surface check: passes.
- Unit/integration test suite: `44 passed`.
- Preflight: passes with Hermes `v0.19.1`, qualified upstream revision
  `26e0b1c1`.
- Git whitespace check: passes.

The last full deterministic retry proof used:

```bash
./scripts/run-local.sh run --scenario retry-success --budget-seconds 120 --max-attempts 2
./scripts/run-local.sh verify --latest
```

That flow intentionally failed the first candidate, accepted the second
candidate, generated draft delivery payloads, and verified the latest artifact.

## Recent design decisions

### Keep the system as a controller, not a free-running agent

The controller owns:

- intake validation
- evidence limits
- policy selection
- maximum attempts
- wall-clock deadline
- patch derivation
- test execution
- service verification
- digest acceptance
- draft delivery artifact creation
- cleanup

Hermes owns only candidate investigation and proposal.

### Keep public repository and private customer packs separate

The public repository should remain reusable. Customer-specific work belongs in
private packs or private downstream repositories.

Allowed in the public repo:

- synthetic fixtures
- placeholder connector contracts
- generic documentation
- reusable guardrails
- local disposable services
- draft-only delivery mocks

Not allowed in the public repo:

- customer names or private incident details
- internal network paths
- production account identifiers
- provider tokens or billing exports
- retained model sessions
- real database/logging endpoints
- customer repository code

### Keep cost reporting evidence-backed

`docs/model-costing.md` defines the cost formulas and comparison structure. The
current boundary is:

- deterministic fixture runs have no billable model tokens;
- a historical real-model run cannot be priced exactly unless provider usage
  counters or billing export were retained;
- the next real-model qualification should capture a cost packet containing
  input, output, cache-read, cache-write, reasoning tokens, provider, model,
  pricing source, and calculated or invoice-backed cost.

Do not quote a precise daily cost without measured token usage or invoice-backed
cost.

## DeepSeek Harness comparison outcome

A separate evaluation compared this project with DeepSeek Harness. The useful
takeaway is not to clone DeepSeek Harness. DeepSeek Harness is a broader agent
orchestration platform; this repository is intentionally narrower: a bounded
incident-remediation workflow with deterministic acceptance.

Ideas already reflected or worth preserving:

- explicit policy inspection before runs;
- safety modes for synthetic, dry-run, shadow-readonly, live-evidence-readonly,
  and draft-pr-only operation;
- connector pipeline structure;
- session/event artifacts;
- provider failure handling tests.

Avoid adding a large general-purpose UI or broad agent platform scope until the
core workflow is stable and measurable.

## Safe next improvements

The next useful work items are:

1. Add first-class provider usage capture to the Hermes adapter, writing a
   `cost-packet.json` into each artifact when the provider exposes usage data.
2. Add a deterministic fake-usage provider test so cost calculation can be
   verified without paid inference.
3. Add a `./scripts/run-local.sh cost --artifact <path>` command that reads the
   cost packet and applies `docs/model-costing.md`.
4. Expand connector contracts for generic read-only log evidence and read-only
   SQL evidence using fixtures first.
5. Add a customer-pack example that remains fully synthetic but demonstrates how
   private users can map their own repository, tests, evidence broker, and draft
   delivery sink.
6. Add a maintainer-friendly architecture diagram export if the README diagram
   is not enough for external users.

Do not start with live customer infrastructure. Prove each new capability with a
synthetic fixture and deterministic test first.

## Commands for a fresh session

From a clean clone:

```bash
git clone https://github.com/AtharvaBondre/hermes-incident-workflow.git
cd hermes-incident-workflow

./scripts/bootstrap-pinned-images.sh sandbox
./scripts/run-local.sh preflight
./scripts/run-local.sh dump-policy
./scripts/run-local.sh test

./scripts/run-local.sh run \
  --scenario retry-success \
  --budget-seconds 120 \
  --max-attempts 2

./scripts/run-local.sh verify --latest
```

For the disposable service example:

```bash
./scripts/bootstrap-pinned-images.sh all
./scripts/run-local.sh preflight --with-docker

./scripts/run-local.sh run \
  --scenario event-indexing-collision \
  --budget-seconds 900 \
  --max-attempts 2 \
  --with-docker

./scripts/run-local.sh verify --latest
```

For Hermes profile validation:

```bash
./scripts/install-hermes-profile.sh
python3 scripts/hermes_sandbox_smoke.py
```

For real-model experiments, configure provider authentication through Hermes
outside this repository. Do not put provider credentials in repository files or
shell-exported project scripts.

## Suggested opening prompt for a new Codex task

```text
This task is dedicated only to the open-source repository:
https://github.com/AtharvaBondre/hermes-incident-workflow.git

Clone or open the repository, start from origin/main, and read
docs/continuation-handoff-2026-08-25.md and AGENTS.md first.

Keep the repository customer-neutral and safe to publish. Do not use private
customer docs, credentials, internal endpoints, retained model sessions, or local
absolute machine paths. Hermes stays external; do not vendor it.

First summarize the current product state, validation commands, safety
boundaries, and the next safe improvements. Do not make changes until I ask.
```
