#!/usr/bin/env bash
set -euo pipefail

if [[ -x scripts/ci/run-extended-validation.sh ]]; then
  bash scripts/ci/run-extended-validation.sh
elif [[ -x scripts/ci/run-fast-checks.sh ]]; then
  bash scripts/ci/run-fast-checks.sh
else
  echo "No validation script found. Skipping release validation checks."
fi
