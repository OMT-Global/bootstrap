#!/usr/bin/env bash
set -euo pipefail
bash scripts/ci/run-fast-checks.sh
if [[ "${RELEASE_PROFILE:-}" == "full" ]]; then
  image='mcr.microsoft.com/devcontainers/javascript-node@sha256:7f53703699da429555e7eebed7047e12823dac65508831413b5485e4566c00a8'
  docker pull --platform linux/amd64 "$image"
  BOOTSTRAP_REQUIRE_ISOLATION_TESTS=1 npm test -- tests/isolated-validation-docker.test.ts --maxWorkers=1
  python3 scripts/ci/reviewer-artifacts.py
else
  echo "Actual Docker isolation tests require the full release-validation profile or the dedicated manual workflow."
fi
