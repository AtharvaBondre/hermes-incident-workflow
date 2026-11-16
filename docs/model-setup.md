# Hermes model setup

The default fixture workflow and Hermes sandbox smoke do not require a paid
model account. Configure a real model only for an explicit manual qualification
run.

Hermes Agent is an external dependency. This repository does not vendor its
source, Python environment, model credentials, sessions, or user configuration.

## 1. Install and verify Hermes

Review the [official Hermes Agent installation
instructions](https://github.com/NousResearch/hermes-agent#quick-install), then
use its installer with this repository's exact qualified source revision:

```bash
curl -fsSL https://hermes-agent.nousresearch.com/install.sh \
  | bash -s -- --commit 3b421578588243f920886e6fe79a6faa87ea026e
```

Verify the installed build:

```bash
hermes --version
```

This repository currently requires Hermes Agent `v0.23.1` at source revision
`3b421578588243f920886e6fe79a6faa87ea026e`. The installer does not roll an
existing newer checkout backward unless `--force-commit` is also supplied; use
that option only when intentionally dedicating that Hermes installation to
this qualified workflow version. Do not edit its `pyproject.toml` or `uv.lock`.
The workflow verifies the direct checkout revision, a clean tracked and
untracked tree, and the qualified hashes of both packaging files immediately
before every real-model invocation. It does not trust the banner's moving
`upstream` field.

The exact packaging identity is also bound to SHA-256
`ee825ad304ad685625c8878cd34b7923ec64579cdc08e646b84b76ba3d4c1cfc`
for `pyproject.toml` and
`d0ae8bfd20db7a8ca0e75418df718315c58088b120366227cc62ee8fe25d4274`
for `uv.lock`. The upstream v0.23.1 tag is not publisher-signed, so the semantic
version or tag name alone is not accepted as runtime identity.

## 2. Install the disposable workflow profile

From this repository's root:

```bash
./scripts/bootstrap-pinned-images.sh sandbox
./scripts/install-hermes-profile.sh
hermes profile info hermes-incident-workflow
```

The installed profile keeps its configuration and authentication outside this
repository. For every real-model attempt, the controller creates a disposable
Hermes home from the public profile and bridges only `.env`, `auth.json`, and
`.anthropic_oauth.json` when those files exist in the selected installed
profile. Only secret-shaped provider assignments are retained from `.env`;
behavioral variables such as `HOME`, `HERMES_HOME`, `PATH`, and terminal
settings are discarded. It never copies sessions, memories, logs, caches,
attachments, or user configuration. The disposable home is deleted after the
attempt, and a cleanup failure makes the candidate ineligible for delivery.

This profile is a state-hygiene boundary, not an operating-system sandbox.
Controller-owned policy and the Docker terminal restrictions below provide the
candidate tool-execution boundary.

The current upstream
[security policy](https://github.com/NousResearch/hermes-agent/blob/v0.23.1/SECURITY.md)
states that only operating-system isolation contains an adversarial model and
that terminal-backend isolation does not confine in-process code execution,
MCP, plugins, hooks, or skills. This profile disables those ambient surfaces,
but the host Hermes process is not a qualified whole-process sandbox. Do not
treat this integration as safe for untrusted input or production use without a
separately approved and tested whole-process design.

The terminal backend remains Docker-based and network-disabled. Besides the
read-only input, task, and skill mounts and the writable output mount, Hermes
v0.23.1 adds read-only cache, image, attachment, generated-output, and
composer-paste mounts. Every one is sourced from the controller-created
disposable profile, starts empty, and is checked by the sandbox smoke. No
credential file is mounted into the candidate container.

Hermes v0.23.1 routes `chat` through its gateway. For every attempt, the
controller waits for readiness from the exact qualified revision, discards the
attach ticket, materializes the three host-owned mount sources in the copied
profile because launcher environment placeholders do not cross the gateway
boundary, and verifies that the disposable gateway has stopped before deleting
its state. The exact model-visible tool surface is `terminal`, `tool_search`,
`tool_describe`, and `tool_call`; `process_manage` is deferred behind that
bridge. Bridge discovery and dispatch use the same disabled-toolset scope, so
they do not re-enable the `memory`, `web`, `browser`, `delegation`,
`code_execution`, `cronjob`, `bfl`, or `kanban` toolsets disabled by this
profile.

## 3. Configure a provider and model

Use Hermes' own credential store for the installed profile:

```bash
hermes -p hermes-incident-workflow setup model
```

Alternatively, add a credential through a secure prompt and then select a
model:

```bash
hermes -p hermes-incident-workflow auth add "provider-id"
hermes -p hermes-incident-workflow model
hermes -p hermes-incident-workflow auth status "provider-id"
```

Do not use `--api-key "secret-value"` in a command because shell history may
retain the secret. Do not create a repository `.env` file. The workflow
launcher starts Hermes with a credential-free process environment;
authentication must already exist in the selected Hermes profile.

Prefer provider API keys stored by the profile-scoped setup flow. Credentials
that exist only in another CLI's home directory are intentionally unavailable
inside the isolated launcher home. Refreshable OAuth state is disposable for
each attempt; configure a non-expiring provider key for repeatable unattended
workflow runs.

The qualified runtime includes the upstream Anthropic OAuth hardening first
published in Hermes v0.21.0. That does not qualify any provider, OAuth flow, or
unattended real-model run for this repository; prefer a scoped provider API key
and complete a separately approved no-customer-data qualification before use.

Provider and model identifiers passed to the workflow must match the values
selected in Hermes. The available providers and models are owned by the
installed Hermes version and the user's account, so this repository does not
hard-code or provision them.

## 4. Validate and run

Replace `provider-id` and `replace-with-model-id` with the values configured
above:

```bash
./scripts/run-local.sh preflight \
  --require-hermes \
  --hermes-profile hermes-incident-workflow

./scripts/run-local.sh run \
  --scenario retry-success \
  --candidate-provider hermes \
  --hermes-profile hermes-incident-workflow \
  --hermes-provider "provider-id" \
  --hermes-model "replace-with-model-id" \
  --budget-seconds 600 \
  --max-attempts 2

./scripts/run-local.sh verify --latest
```

The host Hermes process is expected to contact the selected inference provider,
but this project does not enforce or allowlist host egress. Terminal commands
and candidate verification remain in separate network-disabled Docker
boundaries. No credential is copied into those containers.

Preflight always checks the pinned candidate-test image because repository and
controller verification require that Docker boundary. Add `--with-docker` only
for a scenario that declares a reviewed service-stack contract, for example
`--scenario event-indexing-collision --with-docker`; it is not a generic switch
for the candidate-test sandbox. Service-stack preflight resolves the declared
Compose verification service and fails before evidence or model work if any
runtime or Dockerfile base image is unpinned or unavailable locally.

## Troubleshooting

- **`hermes` not found:** complete the upstream installation and reload the
  shell indicated by its installer.
- **Version or checkout rejected:** install the exact qualified Hermes source
  revision with its unmodified lockfile before using the real-model path; do
  not weaken the identity checks.
- **Profile missing:** rerun `./scripts/install-hermes-profile.sh`.
- **Authentication failed:** rerun the profile-scoped `setup model` flow and
  check `hermes -p hermes-incident-workflow auth status "provider-id"`.
- **Docker unavailable:** start Docker, bootstrap the sandbox image, and rerun
  preflight.
- **Model unavailable:** select another model through the profile-scoped
  `hermes model` command and use the same provider/model identifiers in the
  workflow command.

Review the model provider's processing, retention, regional, and billing terms
before using non-synthetic input. Model output never has acceptance or delivery
authority.
