# Bootstrap

Manifest-first control plane for repo scaffolding, GitHub governance, and portable agent profiles.

Use `project.bootstrap.yaml` as the control plane for repo-local scaffolding, GitHub governance, CI policy, and portable Codex/Claude profile sync. Plan first, then apply repo, GitHub, and home targets deliberately.

## What The Bootstrap Owns

- GitHub governance, environments, and optional org defaults

- Repo-local `AGENTS.md`, `CLAUDE.md`, `CONTRIBUTING.md`, and pull request template guidance
- Fast PR checks plus heavier extended validation lanes
- SemVer release automation with floating major/minor compatibility tags
- Optional signed AI attestation workflow backed by the control-plane reusable contract
- Portable Codex and Claude home profile sync
- Operator docs for onboarding, hosted agents, and follow-up setup

## Quickstart

```sh
bootstrap plan --manifest ./project.bootstrap.yaml
bootstrap apply repo --manifest ./project.bootstrap.yaml
bootstrap apply github --manifest ./project.bootstrap.yaml
bootstrap apply home --manifest ./project.bootstrap.yaml
bootstrap doctor --manifest ./project.bootstrap.yaml
```

If `github.organization` is set and `OMT-Global` is an organization, `bootstrap apply github` also reconciles org defaults for new repos.

Confirm branch protection points at the `CI Gate` status. and require approval from someone other than the most recent pusher.

## Contributor And PR Guidance

- `CONTRIBUTING.md` is the canonical contributor onboarding and local validation surface.
- `.github/PULL_REQUEST_TEMPLATE.md` is the canonical pull request format for summaries, governing issue links, validation notes, and merge-readiness checks.
- Existing bootstrapped repos can retrofit these surfaces with `bootstrap apply repo --manifest ./project.bootstrap.yaml`; repos with restricted `repo.managedPaths` should include both paths before applying.

## Project Identity

- Product name: `Bootstrap`
- Repository: `OMT-Global/bootstrap`
- Manifest: `project.bootstrap.yaml`
- Visibility: `public`
- Default branch: `main`
- Archetype: `generic-empty`


## Release Standard

This bootstrap uses immutable exact SemVer tags such as `v1.2.3`, then automatically advances the floating compatibility tags `v1.2` and `v1` to the same commit.

Cut patch releases from `release/X.Y` branches when you maintain an older minor line. Cut new minor and major releases from `main`.

## AI Attestation

This bootstrap also renders `.github/workflows/ai-attestation.yml` as a caller for the shared attestation workflow at `OMT-Global/bootstrap/.github/workflows/ai-attestation-reusable.yml@refs/heads/main`.

Override the default provider, model, and prompt hash with repo variables (`AI_ATTESTATION_PROVIDER`, `AI_ATTESTATION_MODEL`, `AI_ATTESTATION_PROMPT_HASH`) or update `project.bootstrap.yaml` before production rollout.

## Tier A Control Plane

This repo now carries the shared Tier A workflow contracts:

- `.github/workflows/security-pr.yml`
- `.github/workflows/release.yml`
- `.github/workflows/ai-attestation-reusable.yml`

Use `docs/bootstrap/tier-a-ci-contract.md` for the consumer interface and rollout pattern. Use `docs/bootstrap/next-steps.md` as the publish checklist before downstream repos pin to a tag or immutable SHA.

## Claude Code

This bootstrap can prepare these Claude workflows:

- First-party Claude Code on the web via `claude.ai/code` and `bash scripts/claude-cloud/setup.sh`
- Interactive containerized work via `.devcontainer/devcontainer.json` and `bash scripts/claude/setup-devcontainer.sh`
- Remote GitHub-hosted automation via `.github/workflows/claude.yml`

The full checklist is in `docs/bootstrap/claude-environment.md`.

## Repository URL

- https://github.com/OMT-Global/bootstrap
