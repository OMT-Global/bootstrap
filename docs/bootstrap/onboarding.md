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
- Confirm `AGENTS.md` requires the `autoreview` skill against the intended PR diff before an agent opens or updates a PR, and that the PR template records the final command and result.
- Confirm the pull request template is present and PR Fast CI validates the required PR description sections before CI Gate can pass.
- Confirm `Issue Hygiene Report` runs weekly with read-only issue permission and retains its JSON evidence artifact.
- Confirm PR Fast CI uses the fork-safe `pull_request` event with only read permissions. It must validate Conventional titles, contributed-commit DCO trailers, changed-line accounting, and material-change ADR/reviewer evidence without accessing repository secrets.
- Confirm every third-party `uses:` entry is a 40-character commit SHA followed by readable tag metadata. The `Validate Action Pins` check fails closed on mutable references and silently ignores local or Bootstrap-owned reusable workflows.
- Confirm `delete branch on merge` and `allow auto-merge` are enabled when the GitHub plan supports them; otherwise record the plan-limit evidence and use the fallback merge-readiness policy.
- Fallback merge readiness requires passing or intentionally skipped required checks, satisfied approvals, resolved conversations, no blocking review state, and a manual maintainer merge.

## Org Governance

- Confirm the org default repository permission is `read`.
- Confirm member repository creation is disabled.
- Confirm new-repo security defaults keep dependency graph, Dependabot alerts, Dependabot security updates, secret scanning, push protection enabled.
- Treat upstream-aligned forks as explicit exceptions; keep them aligned with the source fork unless you intentionally manage their GitHub policy here.

## Public Security Baseline

- Review `docs/bootstrap/security.md` before changing security workflow events, permissions, or runner labels.
- Confirm dependency review is the only security job reachable from fork pull requests and runs on GitHub-hosted isolation; CodeQL and SBOM jobs must remain trusted-event only and GitHub-hosted.
- Capture the seven required GitHub capability observations before treating remote security controls as verified.
- Confirm `SECURITY.md` private reporting and response targets match the maintained operational policy.


## Environments

- `dev`: open by default for rapid iteration.
- `stage`: one reviewer required and self-review blocked.
- `prod`: one reviewer required, self-review blocked, deployments limited to `main`.

## Runner Policy

- Private-repository trusted shell-safe jobs use `[self-hosted, linux, shell-only, private]`.
- Public repository security workflows use GitHub-hosted isolation. Fork pull-request jobs always remain read-only and GitHub-hosted.
- Native repos must use self-hosted runners for trusted required automation; Docker, service-container, browser, and `container:` workloads require a dedicated self-hosted runner pool with matching capability labels.
- Keep PR checks cheap. Add heavy validation to `scripts/ci/run-extended-validation.sh` instead of the PR lane.

- Consume shared security, release, and AI attestation workflows from the control-plane repo once those contracts are pinned for production use.

## Contributor And PR Guidance

- `CONTRIBUTING.md` defines the contributor workflow, branch expectations, validation expectations, and secret-handling baseline.
- `.github/PULL_REQUEST_TEMPLATE.md` defines the standard PR shape: summary, governing issue link, validation notes, and bootstrap governance checklist.
- To retrofit an existing bootstrapped repo, add `CONTRIBUTING.md` and `.github/PULL_REQUEST_TEMPLATE.md` to `repo.managedPaths` when that repo restricts managed paths, then run `bootstrap apply repo --manifest ./project.bootstrap.yaml`.
- Keep these files repo-generic unless project metadata or the manifest requires a stricter local rule.

## Issue Hygiene

- Review `docs/bootstrap/issue-hygiene.md` before acting on a 30-day review or 90-day close-or-rescope proposal.
- The scheduled workflow is report-only: it never comments, labels, closes, or reschedules issues.
- A 90-day proposal always requires a maintainer decision. Record a structured, evidenced future action when the issue should remain open.

## Licensing

- Repository visibility never selects or grants a license. Declare `license.mode` explicitly before Bootstrap manages `LICENSE`.
- Current manifest mode: not declared; Bootstrap will not create, replace, or remove a license.
- Keep `THIRD_PARTY_NOTICES.md` separate from the first-party notice and inventory dependencies, assets, fonts, media, and incorporated source.
- Any existing-license replacement requires legal ownership, contributor, distribution-history, issue, and approver evidence in the manifest. Previously granted rights are not revoked.
- Verify GitHub license detection after publishing an SPDX license. Never describe a proprietary notice as SPDX, OSI approved, or GitHub-recognized.

## Fleet Reconciliation

- Run `bootstrap reconcile --workspace-root ~/src --report bootstrap-reconcile.json` first; this is plan-only and does not write files.
- Add `--org OMT-Global` when OpenClaw should enumerate GitHub repos first; missing local checkouts or repos without `project.bootstrap.yaml` are skipped and reported.
- Use `--repo <name...>` as the initial allowlist when onboarding daily OpenClaw reconciliation.
- Use `--apply-repo --create-pr` for unattended repo drift so generated changes go through draft PRs instead of default-branch pushes.
- Use `--apply-github` only after the report shape is trusted because it mutates repository settings, environments, branch protection, and labels directly through the GitHub API.
- Dirty target worktrees are blocked and reported instead of being overwritten.

## Release Standard

- Use immutable exact SemVer tags such as `v1.2.3` as the source of truth.
- Automatically advance `v1.2` and `v1` to the newest compatible exact tag; never retag an exact release.
- Cut patch releases from `release/X.Y` when you maintain older minors; cut new minors and majors from `main`.

## AI Attestation

- `.github/workflows/ai-attestation.yml` calls `OMT-Global/bootstrap/.github/workflows/ai-attestation-reusable.yml@d9c5bc7e50f4bcc97e4b4d3d2efc64e4ab3dca50`.
- Override default metadata with repo variables (`AI_ATTESTATION_PROVIDER`, `AI_ATTESTATION_MODEL`, `AI_ATTESTATION_PROMPT_HASH`) before treating the artifact metadata as authoritative.
- Pin the reusable workflow to a tag or SHA once the control-plane contract is stable.

## Home Profiles

- Run `bootstrap apply home --manifest ./project.bootstrap.yaml` after reviewing the bundled profile content.
- The bootstrap manages portable Codex assets only. Auth, sessions, caches, and machine-local state stay unmanaged.
