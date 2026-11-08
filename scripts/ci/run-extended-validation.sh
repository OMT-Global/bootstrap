#!/usr/bin/env bash
set -euo pipefail
bash scripts/ci/run-fast-checks.sh
if [[ "${RELEASE_PROFILE:-}" == "full" ]]; then
  image='docker.io/library/node@sha256:6b9d4ea31e614e29f364bf75758458731eb1e105b80c99667438dd6b3fe262e0'
  docker pull --platform linux/amd64 "$image"
  BOOTSTRAP_REQUIRE_ISOLATION_TESTS=1 npm test -- tests/isolated-validation-docker.test.ts --maxWorkers=1 --minWorkers=1
else
  echo "Actual Docker isolation tests require the full release-validation profile or the dedicated manual workflow."
fi
