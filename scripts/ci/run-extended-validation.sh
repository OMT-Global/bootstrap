#!/usr/bin/env bash
set -euo pipefail
bash scripts/ci/run-fast-checks.sh
if [[ "${RELEASE_PROFILE:-}" == "full" ]]; then
  image='mcr.microsoft.com/devcontainers/javascript-node@sha256:447fa75fbc7123952284b50229148e933ea756c40718601fa0ec46edd29fd0c6'
  docker pull --platform linux/amd64 "$image"
  BOOTSTRAP_REQUIRE_ISOLATION_TESTS=1 npm test -- tests/isolated-validation-docker.test.ts --maxWorkers=1 --minWorkers=1
  BOOTSTRAP_REQUIRE_HOST_BROKER_TESTS=1 npm test -- tests/upgrade-host-linux.test.ts tests/upgrade-transport-linux.test.ts tests/upgrade-brokers-integration-linux.test.ts tests/upgrade-publication.test.ts --maxWorkers=1 --minWorkers=1
else
  echo "Actual Docker isolation tests require the full release-validation profile or the dedicated manual workflow."
fi
