# Tier A CI Contract

This document is the control-plane contract for Tier A `OMT-Global` repos.

## Workflow Family

- `pr-fast-ci`
  - Cheap required gate
  - Repo-compatible only
  - No deploy or release steps
- `security-pr`
  - Reusable workflow
  - Hosted by default or isolated on a dedicated security runner group
  - Consumes repo hooks for Semgrep, OSV, and custom CodeQL build steps
- `extended-validation`
  - Runs on `main`, nightly, and manual dispatch
  - Carries slower repo-specific validation
- `release`
  - Reusable workflow
  - Separates verification, version validation, build, and publish
  - Validates repo version surfaces (`package.json`, `pyproject.toml`, container metadata) against the pushed tag before build
  - Builds `dist/release/` artifacts, generates SHA256 checksums, and uploads them as release assets
  - Generates categorized release notes from `.github/release.yml` and writes them to `dist/release/RELEASE_NOTES.md`
  - Promotes floating `vX.Y` and `vX` tags from immutable exact `vX.Y.Z` tags
  - Uses OIDC-capable permissions by default
- `ai-attestation`
  - Reusable workflow
  - Signs a commit-scoped AI attestation with cosign keyless signing
  - Uploads and verifies the JSON, signature, and certificate artifact set

## Runner Classes

- Hosted is mandatory for:
  - public untrusted PR execution unless the runner class is explicitly public-safe and ephemeral
  - browser stacks, `container:` jobs, service containers, and Docker-daemon jobs without a dedicated isolated plane
- Shell-safe self-hosted is allowed for:
  - JS actions, Python `3.12`, Terraform, docs, lint, unit tests, and deterministic repo validation
- Private macOS/Xcode self-hosted is allowed for:
  - native Apple build and test lanes that need a real macOS host
- Custom routing is allowed only when:
  - the repo has a real trust or runtime need that the default contract cannot express cleanly
  - the exception is written down in repo-local docs or manifest metadata

## Consumer Pattern

Tier A repos should keep local `pr-fast-ci.yml` and `extended-validation.yml` when those are template-generated, but consume reusable workflows for shared security, release, and AI attestation behavior.

Example security caller:

```yaml
jobs:
  security:
    uses: OMT-Global/bootstrap/.github/workflows/security-pr.yml@d9c5bc7e50f4bcc97e4b4d3d2efc64e4ab3dca50
    with:
      dependency-review: true
      run-osv: true
      run-semgrep: false
      codeql-languages: python
```

Example release caller:

```yaml
on:
  push:
    tags:
      - 'v*.*.*'

jobs:
  release:
    uses: OMT-Global/bootstrap/.github/workflows/release.yml@d9c5bc7e50f4bcc97e4b4d3d2efc64e4ab3dca50
    secrets: inherit
    with:
      runs-on: '["ubuntu-latest"]'
      verify-script: scripts/ci/run-release-verification.sh
      version-script: scripts/ci/run-release-version.sh
      build-script: scripts/ci/run-release-build.sh
      publish-script: scripts/ci/run-release-publish.sh
      release-notes-file: dist/release/RELEASE_NOTES.md
      artifact-dir: dist/release
      create-github-release: true
      tag-prefix: v
      update-major-tag: true
      update-minor-tag: true
```

Release hooks that need signing, notarization, or external publish credentials
must read them from environment variables. The reusable release workflow passes
declared caller secrets through to hook scripts, and the caller must include
`secrets: inherit` or explicitly map those values. For macOS app releases this
includes Dockyard-compatible variables such as
`DOCKYARD_DEVELOPER_ID_APPLICATION`, `DOCKYARD_KEYCHAIN_ACCESS_GROUP`,
`DOCKYARD_NOTARY_KEYCHAIN_PROFILE`, and optional Sparkle paths.

Release policy:

- create immutable exact tags such as `v1.2.3`
- let automation advance `v1.2` and `v1` to that same commit
- cut patch releases from `release/X.Y`, and cut new minor or major releases from `main`
- land version bumps in a pull request before tagging; the release workflow validates, it does not create post-tag commits
- configure version surfaces, artifact directory, checksums, and changelog categories under `release` in `project.bootstrap.yaml`

Example AI attestation caller:

```yaml
env:
  AI_ATTESTATION_PROVIDER_DEFAULT: OpenAI
  AI_ATTESTATION_MODEL_DEFAULT: unknown
  AI_ATTESTATION_PROMPT_HASH_DEFAULT: unknown

jobs:
  attest:
    uses: OMT-Global/bootstrap/.github/workflows/ai-attestation-reusable.yml@d9c5bc7e50f4bcc97e4b4d3d2efc64e4ab3dca50
    with:
      artifact_name: ai-attestation
      retention_days: 90
      ai_provider: ${{ vars.AI_ATTESTATION_PROVIDER || env.AI_ATTESTATION_PROVIDER_DEFAULT }}
      ai_model: ${{ vars.AI_ATTESTATION_MODEL || env.AI_ATTESTATION_MODEL_DEFAULT }}
      prompt_hash: ${{ vars.AI_ATTESTATION_PROMPT_HASH || env.AI_ATTESTATION_PROMPT_HASH_DEFAULT }}
```

Pin to an exact tag or SHA for every production rollout, and override the attestation metadata defaults with repo variables before treating the signed payload as authoritative.

## Publish Readiness

Before Tier A repos adopt these workflows broadly:

- validate the reusable workflow YAML and repository tests on the control-plane branch
- merge the control-plane branch to `main`
- create control-plane SemVer tags such as `v1.2.3`, then let automation advance `v1.2` and `v1`
- move consumer repos from branch refs to that tag or an immutable SHA
- only after that treat the workflows as production policy rather than iteration contracts

## Consumer Rollout Checklist

- keep local `pr-fast-ci.yml` and `extended-validation.yml` only when the repo still needs local path filters or repo-specific execution hooks
- replace repo-local bespoke security logic with a caller to `security-pr.yml` where possible
- replace repo-local bespoke release orchestration with a caller to `release.yml` where possible
- replace repo-local bespoke attestation wiring with the generated or shared attestation caller where possible
- record exceptions when the repo must keep a custom lane, such as trust-aware routing or platform-specific runtime constraints
