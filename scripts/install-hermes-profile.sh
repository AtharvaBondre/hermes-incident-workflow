#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repository_root="$(cd "${script_dir}/.." && pwd)"
profile_source="${repository_root}/hermes-profile"
required_hermes_version="0.19.1"
qualified_hermes_revision="26e0b1c1"

if ! command -v hermes >/dev/null 2>&1; then
  printf '%s\n' 'Hermes is not installed or is not on PATH.' >&2
  exit 1
fi

if ! hermes_version_output="$(hermes --version 2>&1)"; then
  printf '%s\n' 'Unable to determine the installed Hermes version.' >&2
  exit 1
fi

hermes_version_line="${hermes_version_output%%$'\n'*}"
if [[ ! "${hermes_version_line}" =~ ^Hermes[[:space:]]Agent[[:space:]]v([0-9]+\.[0-9]+\.[0-9]+)([[:space:]]|$) ]]; then
  printf 'Unrecognized Hermes version output: %s\n' "${hermes_version_line}" >&2
  exit 1
fi

installed_hermes_version="${BASH_REMATCH[1]}"
if [[ "${installed_hermes_version}" != "${required_hermes_version}" ]]; then
  printf 'Hermes v%s is required; found v%s.\n' \
    "${required_hermes_version}" "${installed_hermes_version}" >&2
  exit 1
fi

if [[ "${hermes_version_line}" != *"upstream ${qualified_hermes_revision}"* ]]; then
  printf 'Warning: this v%s build is not the locally qualified upstream revision %s.\n' \
    "${required_hermes_version}" "${qualified_hermes_revision}" >&2
fi

exec hermes profile install "${profile_source}" \
  --name hermes-incident-workflow \
  --force \
  --yes
