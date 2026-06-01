#!/usr/bin/env bash
set -euo pipefail

if [[ -x scripts/ci/run-fast-checks.sh ]]; then
  bash scripts/ci/run-fast-checks.sh
else
  echo "No fast-check script found. Skipping release preflight checks."
fi
