#!/usr/bin/env bash
set -euo pipefail
node -e 'if (Number(process.versions.node.split(".")[0]) < 20) { console.error("Bootstrap checks require Node.js 20 or newer."); process.exit(1); }'
npm ci --ignore-scripts
npm run typecheck
npm test -- --maxWorkers=2 --minWorkers=1
npm run build
