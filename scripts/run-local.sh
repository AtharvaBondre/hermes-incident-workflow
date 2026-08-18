#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
package_root="$(cd "${script_dir}/.." && pwd)"
cd "${package_root}"

exec env -i \
  PATH="${PATH}" \
  HOME="${HOME}" \
  USER="${USER:-user}" \
  SHELL="${SHELL:-/bin/sh}" \
  TMPDIR="${TMPDIR:-/tmp}" \
  LANG="${LANG:-C.UTF-8}" \
  python3 "${script_dir}/runner.py" "$@"
