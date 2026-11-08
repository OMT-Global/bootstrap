# ADR-0010: Generate bounded Flow policy upgrade draft PRs

Status: Accepted

Date: 2026-11-08

Decision owners: Bootstrap maintainers

Governing issue: [#62](https://github.com/OMT-Global/bootstrap/issues/62)

## Context

The version classifier and first-of-class planner do not execute upgrades. Generic reconciliation does not bind changes to a target Flow policy, verified public inventory, pilot evidence, or upgrade-specific validation. Issue #62 authorizes a governed executor while excluding unbounded migrations and mass merges.

## Decision

Provide a separate `upgrade-pr` command with a read-only default and an explicit repository allowlist. Its input binds a clean generator commit, compatible immutable Flow policy source and digest, and repository-specific issue, diff, tests, exception, provenance, and review evidence. It discovers inventory from local manifests and verifies repository identity and public visibility against GitHub before reporting public metadata.

An explicit `--apply` creates bounded draft PRs. It never applies GitHub settings, syncs home profiles, approves reviews, enables auto-merge, or merges. A representative may receive a draft while its pilot is pending; later repositories in that class require a passing outcome bound to the representative's live default-branch commit, class, source/target versions, target pin, and successful checks. Failed pilots stop that class with remediation.

Patch upgrades report merge eligibility after a verified pilot. Minor upgrades require independent review before merge. Major upgrades require notification and an accepted compatibility decision; the current resolver only implements Public Repository Standard v1, so unsupported major upgrades fail closed. This ADR does not invent a future v2 compatibility contract or approve any major policy deviation. Exception-bearing upgrades remain blocked for a separately reviewed migration.

Execution requires clean, current default-branch checkouts and matching origins. It creates new branches without resetting existing recovery state, validates generated changes, runs the target's checks and autoreview before pushing, and uses a body file containing the required PR sections and upgrade evidence. Failures retain recovery commits or dirty output and report restoration errors. There is no automatic transactional rollback or resume.

## Consequences

- Flow policy version, Flow release reference, and Bootstrap generator commit remain distinct inputs.
- Operator-supplied pilot success flags alone cannot unlock a class batch.
- Draft creation is preparation for independent review and required CI, not proof of merge readiness.
- This implementation decision does not authorize a live fleet run or replace the private-provenance design review and human sign-off required by #161.
- The current public-visibility, compatible-v1, no-exception, and installed-reviewer restrictions deliberately stop unsupported migrations instead of silently weakening governance.

## Validation

Synthetic Git repositories and injected remote commands cover default immutability, public visibility, exact pins, evidence, pilot gating, bounded batches, and partial failure/recovery. Real fleet mutations require a separately inspected dry-run against the intended repositories.
