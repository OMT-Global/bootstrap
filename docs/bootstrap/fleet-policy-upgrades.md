# Fleet Policy Upgrades

Use `bootstrap upgrade-plan --input inventory.json --json` to produce a non-mutating inventory before opening any upgrade PRs.

Each inventory entry records repository, class, current and target exact SemVer policy versions, optional exception, and pilot outcome. Patch upgrades become eligible only after a passing first representative per class; failed pilots block the remaining class batch. Minor upgrades require independent review; major upgrades require notification and an accepted ADR.

This planner deliberately does not create PRs or merge upgrades. Operators must attach policy diff, validation, exceptions, and provenance evidence to the governed PR after the dry run is approved.

## Reconciliation recovery

The separate `bootstrap reconcile --apply-repo --create-pr` command handles generic file drift, not version-aware upgrade execution. It has no transactional fleet rollback or automatic resume journal. Review each repository result after interruption or failure; successful repositories are not rolled back when another repository fails.

Reconciliation creates a new branch and refuses to reset an existing branch with the same name. A same-day retry may therefore fail with an existing-branch error. Inspect and finish the existing recovery branch and any remote PR before starting another attempt; use a distinct `--branch-prefix` only for an intentionally new run.

If apply, staging, or commit fails with dirty output, reconciliation leaves those files and the index on the recovery branch. A subsequent apply is blocked while that worktree is dirty, even if its generated files already match the templates. Inspect the status, diff, staged diff, and reported branch before manually completing or reverting the attempt. Do not interpret matching files as proof that a commit, push, or PR succeeded.

After a clean commit, reconciliation attempts to restore the starting branch even if push or PR creation failed. Recovery commits remain on the reconciliation branch. If restoration also fails, the report records both errors; if the PR was already created, its URL remains in the failed result. Inspect local and remote state before resuming an interrupted run, since a process killed before report completion cannot record its final outcome.
