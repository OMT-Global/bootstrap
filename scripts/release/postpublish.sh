#!/usr/bin/env bash
set -euo pipefail

tag="${1:-${GITHUB_REF_NAME:-}}"
if [[ -n "${tag}" && -n "${GITHUB_REPOSITORY:-}" && -n "${GH_TOKEN:-}" ]]; then
  gh release view "${tag}" --repo "${GITHUB_REPOSITORY}" >/dev/null
  echo "GitHub Release ${tag} exists."
else
  echo "No GitHub release lookup context available. Skipping postpublish remote check."
fi