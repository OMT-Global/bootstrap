# Bootstrap Vision

Version: 0.2

Bootstrap is the manifest-first control plane for OMT-Global repository setup, GitHub governance, CI policy, release scaffolding, and portable Codex home-profile assets. Its job is to make the repo contract explicit in `project.bootstrap.yaml`, preview changes with `plan`, and only then apply repo, GitHub, or home-profile mutations.

Bootstrap is not only a project generator. It is the reconciliation layer that keeps active repos aligned without copying local secrets, hand-editing policy drift, or relying on one machine's memory of how a repo should be governed.

## Who It Serves

- Maintainers creating, repairing, or reconciling OMT-Global repositories.
- Agents that need a reliable source of truth before touching generated files, GitHub settings, or portable home profiles.
- Downstream repos that want consistent PR templates, issue labels, runner policy, CI gates, release lanes, and onboarding docs.

## Current Product Boundary

- Control plane: `project.bootstrap.yaml`.
- Repo target: generated guidance, templates, managed CI files, scripts, and docs under the manifest's managed paths.
- GitHub target: repository features, issue labels, reviewers, branch protection where plan capabilities allow it, environments, and org defaults for new repos.
- Home target: portable Codex profile sync, excluding auth state, sessions, caches, and machine-local secrets.
- Fleet target: reconciliation reports and draft PRs for repo file drift.

## Product Principles

- Plan before apply. GitHub policy and home-profile changes should be previewed before mutation.
- Generated assets must be reviewable, reproducible, and scoped to managed paths.
- GitHub plan limits, billing gates, and unavailable ruleset features must be reported as blockers, not hidden.
- PR description validation, issue linkage, validation evidence, and merge-readiness checks are part of the governance product.
- Portable agent profiles must carry instructions and skills, never credentials or runtime state.

## Near-Term Direction

- Keep Tier A workflow contracts, PR templates, and release automation consumable by downstream repos through tags or immutable SHAs.
- Improve reconciliation so repo drift becomes narrow draft PRs instead of broad manual cleanup.
- Keep branch-protection and last-push approval behavior aligned with what GitHub actually permits per repo visibility and plan.
- Make home-profile sync safer and more transparent for repeatable Codex setup.

## Non-Goals

- Do not silently mutate GitHub settings without a manifest-backed plan.
- Do not turn bootstrap into an unbounded platform orchestrator.
- Do not manage auth material, sessions, caches, or machine-local overrides.
- Do not pretend a generated template is aligned if the target repo has intentionally narrowed `managedPaths`.
