# Bootstrap Onboarding

Use this checklist after the first bootstrap render or whenever `project.bootstrap.yaml` changes in a way that affects GitHub policy, environments, or home-profile sync.

## Project

- Product name: `Bootstrap`
- Repository: `OMT-Global/bootstrap`
- Manifest: `project.bootstrap.yaml`

## Repo Governance

- Confirm branch protection or rulesets on `main` require one approval, code owner review, and approval from someone other than the most recent pusher.
- Confirm branch protection points at the `CI Gate` status.
- Confirm `CONTRIBUTING.md` and `.github/PULL_REQUEST_TEMPLATE.md` are present as the required contributor and PR guidance surfaces.
- Confirm the pull request template is present and PR Fast CI validates the required PR description sections before CI Gate can pass.
- Confirm `delete branch on merge` and `allow auto-merge` are enabled when the GitHub plan supports them; otherwise record the plan-limit evidence and use the fallback merge-readiness policy.
- Fallback merge readiness requires passing or intentionally skipped required checks, satisfied approvals, resolved conversations, no blocking review state, and a manual maintainer merge.

## Org Governance

- Confirm the org default repository permission is `read`.
- Confirm member repository creation is disabled.
- Confirm new-repo security defaults keep dependency graph, Dependabot alerts, Dependabot security updates, secret scanning, push protection enabled.
- Treat upstream-aligned forks as explicit exceptions; keep them aligned with the source fork unless you intentionally manage their GitHub policy here.


## Environments

- `dev`: open by default for rapid iteration.
- `stage`: one reviewer required and self-review blocked.
- `prod`: one reviewer required, self-review blocked, deployments limited to `main`.

## Runner Policy

- Shell-safe jobs may use `[self-hosted, synology, shell-only, public]`.
- Docker, service-container, browser, and `container:` workloads stay on GitHub-hosted runners.
- Keep PR checks cheap. Add heavy validation to `scripts/ci/run-extended-validation.sh` instead of the PR lane.

- Consume shared security, release, and AI attestation workflows from the control-plane repo once those contracts are pinned for production use.

## Contributor And PR Guidance

- `CONTRIBUTING.md` defines the contributor workflow, branch expectations, validation expectations, and secret-handling baseline.
- `.github/PULL_REQUEST_TEMPLATE.md` defines the standard PR shape: summary, governing issue link, validation notes, and bootstrap governance checklist.
- To retrofit an existing bootstrapped repo, add `CONTRIBUTING.md` and `.github/PULL_REQUEST_TEMPLATE.md` to `repo.managedPaths` when that repo restricts managed paths, then run `bootstrap apply repo --manifest ./project.bootstrap.yaml`.
- Keep these files repo-generic unless project metadata or the manifest requires a stricter local rule.

## Release Standard

- Use immutable exact SemVer tags such as `v1.2.3` as the source of truth.
- Automatically advance `v1.2` and `v1` to the newest compatible exact tag; never retag an exact release.
- Cut patch releases from `release/X.Y` when you maintain older minors; cut new minors and majors from `main`.

## AI Attestation

- `.github/workflows/ai-attestation.yml` calls `OMT-Global/bootstrap/.github/workflows/ai-attestation-reusable.yml@refs/heads/main`.
- Override default metadata with repo variables (`AI_ATTESTATION_PROVIDER`, `AI_ATTESTATION_MODEL`, `AI_ATTESTATION_PROMPT_HASH`) before treating the artifact metadata as authoritative.
- Pin the reusable workflow to a tag or SHA once the control-plane contract is stable.

## Home Profiles

- Run `bootstrap apply home --manifest ./project.bootstrap.yaml` after reviewing the bundled profile content.
- The bootstrap manages portable Codex and Claude assets only. Auth, sessions, caches, and machine-local state stay unmanaged.

## Claude Setup

- First-party Claude web sessions should use `bash scripts/claude-cloud/setup.sh` in `claude.ai/code`.
- Interactive Claude work is prepared through `.devcontainer/devcontainer.json`.
- GitHub-hosted Claude automation lives in `.github/workflows/claude.yml` and is intentionally separate from the required PR checks.
- Finish GitHub-side auth by running `/install-github-app` in Claude Code or adding `ANTHROPIC_API_KEY` as a repo secret.
