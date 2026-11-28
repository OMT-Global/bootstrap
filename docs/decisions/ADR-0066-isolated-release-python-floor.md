# ADR-0066: Require CPython 3.12 in isolated release validation

Status: Proposed

Date: 2026-11-23

Governing issues: [#27](https://github.com/OMT-Global/bootstrap/issues/27) and [#62](https://github.com/OMT-Global/bootstrap/issues/62).

## Context

[ADR-0013](ADR-0013-isolated-node-validation-backend.md) pins the Linux/amd64 isolation backend to the Microsoft Dev Containers Node 24 Debian 12 image. [ADR-0030](ADR-0030-immutable-release-primitives.md) requires POSIX CPython 3.12 or later for the exact release artifact verifier. The [hosted isolation run](https://github.com/OMT-Global/bootstrap/actions/runs/45209771916) after the writable-fixture change observed Python 3.11.2 and still failed the nested release verifier tests. Those same suites on the #283 source passed all 181 tests with local CPython 3.12 and 3.13. They failed 83 tests on local CPython 3.11.

## Proposed decision

Amend ADR-0013's image and Python probe for the `node-npm-linux-v1` backend. Pin the Linux/amd64 manifest `mcr.microsoft.com/devcontainers/javascript-node@sha256:7f53703699da429555e7eebed7047e12823dac65508831413b5485e4566c00a8` in the backend and both hosted validation pull sites. The candidate is the Debian 13 sibling from the same Microsoft Node 24 image release. Its [image provenance record](../security/node-npm-linux-v1-image.md) links the exact OCI identities and observed package evidence.

Before repository-controlled phases, run the existing six-tool probes and require `python3 -I -S` to report POSIX CPython 3.12 or later. An incompatible or missing interpreter fails preparation. Keep ADR-0013's Linux/amd64 host, offline dependency installation, non-root worker, immutable source, resource, network, privilege, and cleanup requirements. The separately pinned controlled-reviewer probe is outside this backend decision.

## Qualification

Obtain independent design review and maintainer acceptance before adopting this record. Verify the actual interpreter and all six tools and execute the complete Docker confinement and nested Bootstrap release test suites at the exact candidate revision. Inspect the actual no-new-privileges, storage continuity and cleanup results. Verify the regenerated workflow and its managed-file inventory against the project manifest. After the final source autoreview and merge, run Full Release Validation on the exact proposed release SHA.

The digest and package data establish the selected image identity and its reported contents. Hosted execution is required to establish runtime compatibility and confinement. This decision grants authority for the image and probe change only.
