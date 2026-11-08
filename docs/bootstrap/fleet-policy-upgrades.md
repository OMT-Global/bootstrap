# Fleet Policy Upgrades

`bootstrap upgrade-plan --input inventory.json --json` remains a non-mutating SemVer risk planner for manually prepared candidates. Its `pilotOutcome` strings cannot authorize execution.

## Governed draft generation

`bootstrap upgrade-pr --workspace-root ~/src/omt-global --repo owner/first owner/second --input approved-upgrade.json --json` inventories only explicitly allowlisted existing checkouts. Omit `--apply` for the default dry run. Add `--apply --max-batch-size 1` after inspecting the plan to create a bounded draft PR. The limit counts attempted mutations, including failures; values from 1 through 10 are accepted. No command merges or enables auto-merge.

This executor upgrades the manifest's verified `policy.flow` bundle and regenerates files with the exact approved Bootstrap generator commit. It supports the resolver's compatible Public Repository Standard v1 contract; it does not infer new configuration semantics from arbitrary bundle fields. Major policies require notification, an accepted ADR, and resolver compatibility work before execution; v2 policies fail closed. Same-version content repins are rejected. Generator-only drift belongs to `reconcile`.

Every checkout must be on its live public default-branch commit, clean, and connected to the same allowlisted GitHub origin for both fetch and push. Local manifest identity and visibility must match live GitHub metadata. Missing, private, archived, or unverified targets produce a redacted result. Unknown manifest settings, unsafe filesystem paths, existing recovery branches, and exception-bearing migrations require manual remediation. GitHub settings and portable home assets are not applied.

The approved JSON input has this shape (replace placeholder values with reviewed evidence):

```json
{
  "generatorCommit": "0000000000000000000000000000000000000000",
  "target": {
    "ref": "refs/tags/v1.0.1",
    "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
    "bundlePath": "/local/reviewed/flow-policy-v1.0.1.yaml"
  },
  "evidence": [{
    "repo": "owner/first",
    "issue": "https://github.com/owner/first/issues/1",
    "policyDiff": "https://github.com/owner/first/issues/1",
    "tests": "https://github.com/owner/first/actions/runs/1",
    "exceptions": "https://github.com/owner/first/issues/1",
    "provenance": "https://github.com/owner/first/issues/1",
    "autoreview": "https://github.com/owner/first/issues/1"
  }],
  "pilots": []
}
```

The generator checkout must be clean at `generatorCommit` for apply. `target.sha256` is the canonical `flowPolicyDigest` of the parsed YAML, not the file-byte hash. Both existing and target bundles pass the immutable-ref/digest resolver before writing. The target file is staged locally by the operator; the executor does not fetch policy releases. Every evidence link must stay within its verified public target repository, use HTTPS without query strings, and contain no credential-like literals. The governing issue must be an issue in that repository. Evidence links record the operator's reviewed context; they do not assert that an unavailable check or approval happened.

Repositories are sorted by full name; the first verified public repository of each explicit class is its representative. A pending representative may receive a draft, while later members stay blocked. After its reviewed upgrade is merged and validation passes on the current default-branch commit, supply a class record such as:

```json
{
  "repo": "owner/first",
  "repoClass": "cli",
  "currentPolicy": "1.0.0",
  "targetPolicy": "1.0.1",
  "commit": "0000000000000000000000000000000000000000",
  "sourceCommit": "0000000000000000000000000000000000000000",
  "outcome": "passed",
  "validationWorkflow": ".github/workflows/extended-validation.yml",
  "evidence": "https://github.com/owner/first/actions/runs/1"
}
```

`sourceCommit` must identify an immutable pre-upgrade representative commit that is an ancestor of the validated target commit. Its public identity, class, policy version, immutable pin, and bundle digest are fetched and verified; the declared source version alone is never trusted. Later class members must have that same proven source version and pin. Heterogeneous source paths stay blocked until a matching representative migration is supplied.

A passing declaration alone does not unlock rollout. The executor verifies the representative identity/class, source and target versions, current default-branch commit, committed target pin and bundle digest, and the named Actions run's repository, exact commit, successful completion, trusted `push` or `workflow_dispatch` event, and approved checked-in workflow path. Every returned check and status must also pass; incomplete pagination fails closed. PR-only `CI Gate` is not required on the squash commit. Refresh evidence when the representative default branch advances. Failed pilots and failed class execution stop later class members with remediation. Patch eligibility is reported only after this proof; minor PRs explicitly require independent review before merge. Exception-bearing and major migrations remain human-governed manual work.

Apply creates a new `codex/flow-policy-<version>-<base>` branch, writes the bundle and manifest, regenerates managed files, runs `bash scripts/ci/run-fast-checks.sh`, and requires an idempotent second plan. Configure meaningful repository checks: a generic empty-archetype script is not substantive behavior proof. Validation may not introduce unrelated staged or untracked output or change prepared allowed files: raw bytes, executable modes, and deletions are snapshotted after apply and checked after validation and commit, with path safety checked before reads. Dry-run drift includes manual manifest and bundle writes even when managed paths exclude them. NUL-delimited Git paths are compared byte-for-byte without trimming. Only literal allowlisted paths are staged and passed explicitly to `git commit --only`, including generated additions and deletions. Commits carry DCO sign-off; configured signing remains in force. The `autoreview` helper must be on PATH and successfully review the prepared branch against its captured base before any push. The draft body links the policy diff, validation, exceptions, provenance, prior review, and current review command/result.

An apply report containing an execution `failed` result exits with status 1 after writing stdout and any requested report file. Dry runs and preflight `blocked` results retain status 0; automation must inspect those reports for eligibility. Apply never resets an existing local or remote branch. Dirty output stays on its recovery branch; clean commits remain recoverable after push, review, or PR failure. Restoration errors retain the primary failure and any known PR URL. There is no automatic rollback or resume journal; inspect local status, generated Git state, branch commits, remote state, and reports before retrying. Temporary PR-body cleanup failure does not mask the primary result.

## Reconciliation recovery

The separate `bootstrap reconcile --apply-repo --create-pr` command handles generic file drift, not version-aware upgrade execution. It has no transactional fleet rollback or automatic resume journal. Review each repository result after interruption or failure; successful repositories are not rolled back when another repository fails.

Reconciliation creates a new branch and refuses to reset an existing branch with the same name. A same-day retry may therefore fail with an existing-branch error. Inspect and finish the existing recovery branch and any remote PR before starting another attempt; use a distinct `--branch-prefix` only for an intentionally new run.

If apply, staging, or commit fails with dirty output, reconciliation leaves those files and the index on the recovery branch. A subsequent apply is blocked while that worktree is dirty, even if its generated files already match the templates. Inspect the status, diff, staged diff, and reported branch before manually completing or reverting the attempt. Do not interpret matching files as proof that a commit, push, or PR succeeded.

After a clean commit, reconciliation attempts to restore the starting branch even if push or PR creation failed. Recovery commits remain on the reconciliation branch. If restoration also fails, the report records both errors; if the PR was already created, its URL remains in the failed result. Inspect local and remote state before resuming an interrupted run, since a process killed before report completion cannot record its final outcome.
