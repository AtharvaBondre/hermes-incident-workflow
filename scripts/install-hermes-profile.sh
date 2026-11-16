#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repository_root="$(cd "${script_dir}/.." && pwd)"
profile_source="${repository_root}/hermes-profile"
required_hermes_version="0.23.1"
qualified_hermes_revision="3b421578588243f920886e6fe79a6faa87ea026e"
qualified_pyproject_sha256="ee825ad304ad685625c8878cd34b7923ec64579cdc08e646b84b76ba3d4c1cfc"
qualified_lock_sha256="d0ae8bfd20db7a8ca0e75418df718315c58088b120366227cc62ee8fe25d4274"

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

install_directory="$(printf '%s\n' "${hermes_version_output}" | sed -n 's/^Install directory:[[:space:]]*//p')"
if [[ -z "${install_directory}" || "${install_directory}" == *$'\n'* || ! -d "${install_directory}" ]]; then
  printf '%s\n' 'Hermes must report one valid source install directory.' >&2
  exit 1
fi

if ! installed_revision="$(git -C "${install_directory}" rev-parse HEAD 2>/dev/null)" || \
   [[ "${installed_revision}" != "${qualified_hermes_revision}" ]]; then
  printf 'Hermes source checkout must be qualified revision %s.\n' \
    "${qualified_hermes_revision}" >&2
  exit 1
fi

if ! checkout_status="$(git -C "${install_directory}" status --porcelain --untracked-files=all)"; then
  printf '%s\n' 'Hermes source checkout status could not be verified.' >&2
  exit 1
fi
if [[ -n "${checkout_status}" ]]; then
  printf '%s\n' 'Hermes source checkout has tracked or untracked changes.' >&2
  exit 1
fi

file_sha256() {
  python3 - "$1" <<'PY'
import hashlib
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
print(hashlib.sha256(path.read_bytes()).hexdigest())
PY
}

if [[ "$(file_sha256 "${install_directory}/pyproject.toml")" != "${qualified_pyproject_sha256}" ]]; then
  printf '%s\n' 'Hermes pyproject.toml digest is not qualified.' >&2
  exit 1
fi
if [[ "$(file_sha256 "${install_directory}/uv.lock")" != "${qualified_lock_sha256}" ]]; then
  printf '%s\n' 'Hermes uv.lock digest is not qualified.' >&2
  exit 1
fi

exec hermes profile install "${profile_source}" \
  --name hermes-incident-workflow \
  --force \
  --yes
