# ADR-0005: Project a fork-safe public repository security baseline

Status: Accepted

Date: 2026-07-18

Decision owners: Bootstrap maintainers

Decision record: [Bootstrap issue #60](https://github.com/OMT-Global/bootstrap/issues/60)

## Context

Bootstrap already projects basic dependency updates, a vulnerability-reporting document, and organization-level security defaults. Those pieces do not guarantee that every public repository receives dependency review, code scanning, an SBOM, actionable response targets, or a fork-safe permission boundary. Remote GitHub controls also vary by plan and repository configuration, so local files alone cannot prove that scanning and private reporting are active.

Security automation for pull requests must treat fork content as untrusted. Workflows that use `pull_request_target`, expose a secret expression, or grant write permissions to a pull-request-reachable job can turn a routine contribution into a repository or external-service credential boundary.

## Decision

Every public repository receives these Bootstrap-managed surfaces:

1. `SECURITY.md` with a private-advisory route, acknowledgement and update targets, severity-based remediation targets, and coordinated disclosure guidance.
2. `.github/dependabot.yml` with security updates plus the `github-actions` ecosystem so immutable action pins remain updateable.
3. `.github/workflows/security.yml` with dependency review on an unfiltered `pull_request` trigger after the dependency graph prerequisite is provisioned and activated through `DEPENDENCY_REVIEW_ENABLED`, plus CodeQL and SPDX JSON SBOM generation only on trusted default-branch push or scheduled events. Trusted jobs default to GitHub-hosted isolation; a configured self-hosted group must restrict workflow access to this file pinned to the protected default branch.
4. `docs/bootstrap/security.md` describing trust boundaries, required controls, fork safety, and capability evidence.

All third-party actions remain pinned to immutable commits with readable release metadata. The public security workflow uses read-only top-level permissions and contains no secret references. Every job uses GitHub-hosted isolation. Jobs that require `security-events: write` or `contents: write` are explicitly unreachable from pull requests.

Conformance adds stable local baseline and fork-safety rules. It also expects authorized observations for dependency graph, Dependabot alerts and security updates, secret scanning, push protection, code scanning, and private vulnerability reporting. A supported dependency-graph observation must separately record `dependencyReviewEnabled: true` after verifying the activation variable; absence remains `unverified` and `false` is `misconfigured`. A missing observation is `unverified`, an unsupported plan capability is `unsupported`, and an available but disabled capability is `misconfigured`. Only a current typed exception matching `security-baseline` / `repo.security` or `github-capability` / `github.<control>` can waive the corresponding deviation.

## Consequences

- Public repositories gain an additional scheduled and trusted-push workflow.
- Fork pull requests run dependency review on GitHub-hosted isolation without repository secrets or write permissions; CodeQL and SBOM jobs do not run in that event lane.
- Public security jobs use GitHub-hosted runners. Any future self-hosted activation requires a separate design that verifies the remote authorization boundary before workflow projection.
- Capability capture remains an authorized external step; conformance does not infer plan support from ambiguous API failures.
- An explicit public-repository opt-out is visible as a blocking conformance result unless a current security waiver governs it.

## Alternatives considered

### Run every security job on fork pull requests

Rejected because code scanning and artifact publication require permissions that are unnecessary for untrusted pull-request validation and behave inconsistently across fork boundaries.

### Use `pull_request_target` to gain permissions

Rejected because it moves untrusted contribution data into a privileged workflow context and is unnecessary for dependency review.

### Use mutable action tags for automatic updates

Rejected because mutable tags weaken reproducibility. Dependabot can update immutable SHAs while retaining readable version metadata.

### Treat missing remote capability evidence as success

Rejected because absence of evidence does not prove a control is enabled. Missing observations remain explicitly `unverified`.

## Rollout

1. Land the projection and conformance rules in Bootstrap.
2. Apply the new managed files to Bootstrap and verify the first trusted security run.
3. Dogfood the same projection in Flow through issue #63.
4. Capture authorized capability snapshots and resolve or waive each unsupported or misconfigured control.

## Security and privacy

The generated reporting route uses GitHub private vulnerability reporting. When that form is unavailable, reporters request a confidential channel through a detail-free public issue, so no maintainer email address or vulnerability detail is published. Capability snapshots are schema-bounded and should stay outside the repository when they contain operational detail. The fork lane never references GitHub Actions secrets, and privileged jobs are gated away from pull-request events.

## Revisit conditions

Revisit if GitHub offers a stable plan-capability API, if a projected scanner requires a dedicated runner capability pool, or if CodeQL can safely provide equivalent fork coverage without widening permissions.
