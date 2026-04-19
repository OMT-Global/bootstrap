# Bootstrap Onboarding

Use this checklist after the first bootstrap render or whenever `project.bootstrap.yaml` changes in a way that affects GitHub policy, environments, or home-profile sync.

## Project

- Product name: `Bootstrap`
- Repository: `OMT-Global/bootstrap`
- Manifest: `project.bootstrap.yaml`

## Repo Governance

- Confirm branch protection or rulesets on `main` require one approval and code owner review.
- Confirm branch protection points at the `CI Gate` status.
- Confirm `delete branch on merge` and `allow auto-merge` are enabled.
- Confirm `CONTRIBUTING.md` and `.github/PULL_REQUEST_TEMPLATE.md` are present as the required contributor and PR guidance surfaces.

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

## Contributor And PR Guidance

- `CONTRIBUTING.md` defines the contributor workflow, branch expectations, validation expectations, and secret-handling baseline.
- `.github/PULL_REQUEST_TEMPLATE.md` defines the standard PR shape: summary, governing issue link, validation notes, and bootstrap governance checklist.
- To retrofit an existing bootstrapped repo, add `CONTRIBUTING.md` and `.github/PULL_REQUEST_TEMPLATE.md` to `repo.managedPaths` when that repo restricts managed paths, then run `bootstrap apply repo --manifest ./project.bootstrap.yaml`.
- Keep these files repo-generic unless project metadata or the manifest requires a stricter local rule.

## Home Profiles

- Run `bootstrap apply home --manifest ./project.bootstrap.yaml` after reviewing the bundled profile content.
- The bootstrap manages portable Codex and Claude assets only. Auth, sessions, caches, and machine-local state stay unmanaged.

## Claude Setup

- First-party Claude web sessions should use `bash scripts/claude-cloud/setup.sh` in `claude.ai/code`.
- Interactive Claude work is prepared through `.devcontainer/devcontainer.json`.
- GitHub-hosted Claude automation lives in `.github/workflows/claude.yml` and is intentionally separate from the required PR checks.
- Finish GitHub-side auth by running `/install-github-app` in Claude Code or adding `ANTHROPIC_API_KEY` as a repo secret.
