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
  | bash -s -- --commit 5fc308a70719a83cccdbba4c0e39c23f5a8239d5
```

Verify the installed build:

```bash
hermes --version
```

This repository currently requires Hermes Agent `v0.20.6` at source revision
`5fc308a70719a83cccdbba4c0e39c23f5a8239d5`. The installer does not roll an
existing newer checkout backward unless `--force-commit` is also supplied; use
that option only when intentionally dedicating that Hermes installation to
this qualified workflow version. Do not edit its `pyproject.toml` or `uv.lock`.
The workflow verifies the direct checkout revision, a clean tracked and
untracked tree, and the qualified hashes of both packaging files immediately
before every real-model invocation. It does not trust the banner's moving
`upstream` field.

## 2. Install the isolated workflow profile

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

The terminal backend remains Docker-based and network-disabled. Besides the
read-only input, task, and skill mounts and the writable output mount, Hermes
v0.20.6 adds read-only cache, image, and attachment mounts. Every one is
sourced from the controller-created disposable profile, starts empty, and is
checked by the sandbox smoke. No credential file is mounted into the candidate
container.

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

Provider and model identifiers passed to the workflow must match the values
selected in Hermes. The available providers and models are owned by the
installed Hermes version and the user's account, so this repository does not
hard-code or provision them.

## 4. Validate and run

Replace `provider-id` and `replace-with-model-id` with the values configured
above:

```bash
./scripts/run-local.sh preflight \
  --with-docker \
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
