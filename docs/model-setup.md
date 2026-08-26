# Hermes model setup

The default fixture workflow and Hermes sandbox smoke do not require a paid
model account. Configure a real model only for an explicit manual qualification
run.

Hermes Agent is an external dependency. This repository does not vendor its
source, Python environment, model credentials, sessions, or user configuration.

## 1. Install and verify Hermes

Follow the [official Hermes Agent installation
instructions](https://github.com/NousResearch/hermes-agent#quick-install), then
verify the installed build:

```bash
hermes --version
```

This repository currently requires Hermes Agent `v0.19.1` and was qualified
against upstream revision `26e0b1c1`. The workflow preflight rejects a failed
version lookup, a different semantic version, or a build that does not report
that qualified revision.

## 2. Install the isolated workflow profile

From this repository's root:

```bash
./scripts/bootstrap-pinned-images.sh sandbox
./scripts/install-hermes-profile.sh
hermes profile info hermes-incident-workflow
```

The installed profile keeps its configuration and authentication outside this
repository. Its terminal backend is Docker-based, network-disabled, and limited
to the workflow's read-only input and writable output mounts.

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
- **Version rejected:** install the qualified Hermes version before using the
  real-model path; do not weaken the version check.
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
