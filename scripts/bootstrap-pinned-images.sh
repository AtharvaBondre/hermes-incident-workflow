#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repository_root="$(cd "${script_dir}/.." && pwd)"
scope="${1:-sandbox}"

case "${scope}" in
  sandbox)
    sources=(
      "${repository_root}/hermes-profile/config.yaml"
      "${repository_root}/docker/incident-poc/Dockerfile"
    )
    ;;
  all)
    sources=(
      "${repository_root}/compose.yaml"
      "${repository_root}/compose.event-indexing.yaml"
      "${repository_root}/hermes-profile/config.yaml"
      "${repository_root}/docker/incident-poc/Dockerfile"
    )
    ;;
  *)
    printf 'Usage: %s [sandbox|all]\n' "$0" >&2
    exit 2
    ;;
esac

if ! command -v docker >/dev/null 2>&1; then
  printf '%s\n' 'Docker is not installed or is not on PATH.' >&2
  exit 1
fi

unpinned="$({
  grep -hE '^[[:space:]]*(image|docker_image):' "${sources[@]}" || true
  grep -hE '^FROM[[:space:]]+' "${sources[@]}" || true
} | grep -Ev '@sha256:[0-9a-f]{64}"?[[:space:]]*$' || true)"
if [[ -n "${unpinned}" ]]; then
  printf '%s\n' 'Refusing to bootstrap an unpinned image declaration:' >&2
  printf '%s\n' "${unpinned}" >&2
  exit 1
fi

image_count=0
while IFS= read -r image; do
  [[ -n "${image}" ]] || continue
  image_count=$((image_count + 1))
  printf 'Pulling %s\n' "${image}"
  docker pull "${image}"
  docker image inspect "${image}" \
    --format 'Ready: {{.Os}}/{{.Architecture}} {{index .RepoDigests 0}}'
done < <(
  {
    sed -En 's/^[[:space:]]*(image|docker_image):[[:space:]]*"?([^"[:space:]]+@sha256:[0-9a-f]{64})"?[[:space:]]*$/\2/p' "${sources[@]}"
    sed -En 's/^FROM[[:space:]]+([^[:space:]]+@sha256:[0-9a-f]{64})([[:space:]].*)?$/\1/p' "${sources[@]}"
  } | LC_ALL=C sort -u
)

if [[ "${image_count}" -eq 0 ]]; then
  printf '%s\n' 'No digest-pinned images were found.' >&2
  exit 1
fi
