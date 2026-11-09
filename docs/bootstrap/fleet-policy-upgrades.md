# Fleet Policy Upgrades

Use `bootstrap upgrade-plan --input inventory.json --json` to produce a non-mutating inventory before preparing upgrade PRs. Omit `--json` for human-readable output.

Each manually prepared inventory entry records repository, class, current and target exact SemVer policy versions, optional exception, and pilot outcome. Patch upgrades become eligible only after a passing first representative per class. Pending or missing pilot outcomes block later class members; failed pilots stop their class batch with remediation. Minor upgrades require independent review; major upgrades require notification and an accepted ADR. Exception-bearing upgrades require human review.

Policy versions use numeric `X.Y.Z` triplets, optionally prefixed by `v`. Components cannot contain leading zeros, and the target must be strictly newer. Components are compared exactly even beyond JavaScript's safe-integer range. Prerelease/build labels, ranges, and surrounding whitespace are not accepted.

The planner does not create PRs, execute target-repository code, or verify remote pilot outcomes. Operators must attach policy diff, validation, exceptions, and provenance evidence to any governed upgrade PR.

## Guarded execution follow-up

[#62](https://github.com/OMT-Global/bootstrap/issues/62) remains open for version-aware PR generation. Its mutating executor is deferred until an isolated validation backend and the credential boundary receive independent review. Repository-controlled checks, Git hooks, and review tools must execute without the orchestrator's GitHub publication credentials or machine-local authentication state. Only reviewed outputs should cross into narrowly scoped credentialed publication. Planner eligibility does not establish that this isolation or pilot verification exists.

This change retains the planner's pending-pilot repair and the separate reconciliation recovery behavior below. It provides no new upgrade execution command or unsafe opt-in around the isolation gate.

## Reconciliation recovery

The separate `bootstrap reconcile --apply-repo --create-pr` command handles generic file drift, not version-aware upgrade execution. It has no transactional fleet rollback or automatic resume journal. Review each repository result after interruption or failure; successful repositories are not rolled back when another repository fails.

Reconciliation creates a new branch and refuses to reset an existing branch with the same name. A same-day retry may therefore fail with an existing-branch error. Inspect and finish the existing recovery branch and any remote PR before starting another attempt; use a distinct `--branch-prefix` only for an intentionally new run.

If apply, staging, or commit fails with dirty output, reconciliation leaves those files and the index on the recovery branch. A subsequent apply is blocked while that worktree is dirty, even if its generated files already match the templates. Inspect the status, diff, staged diff, and reported branch before manually completing or reverting the attempt. Do not interpret matching files as proof that a commit, push, or PR succeeded.

After a clean commit, reconciliation attempts to restore the starting branch even if push or PR creation failed. Recovery commits remain on the reconciliation branch. If restoration also fails, the report records both errors; if the PR was already created, its URL remains in the failed result. Inspect local and remote state before resuming an interrupted run, since a process killed before report completion cannot record its final outcome.
