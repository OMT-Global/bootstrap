#!/usr/bin/env bash
set -euo pipefail

echo "--- typecheck"
npm run typecheck

echo "--- build"
npm run build

echo "--- test"
npm test
