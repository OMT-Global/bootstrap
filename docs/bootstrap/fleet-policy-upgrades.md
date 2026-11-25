# Fleet Policy Upgrades

Use `bootstrap upgrade-plan --input inventory.json --json` to produce a non-mutating inventory before preparing upgrade PRs. Omit `--json` for human-readable output.

For inventory derived from public repository observations, use
[`bootstrap inventory-public-fleet`](fleet-public-inventory.md). It collects policy
bindings, managed drift and declared exceptions while retaining pending pilot gates.

Each manually prepared inventory entry records repository, class, current and target exact SemVer policy versions, optional exception, and pilot outcome. Patch upgrades become eligible only after a passing first representative per class for the same target version. An invalid pilot cannot confer a pass; pending or missing pilot outcomes block later class members, and failed pilots and their class batch are blocked until remediation. The plan blocks every class containing a duplicate repository string, comparing without case or surrounding whitespace; this does not detect remote aliases. If the inventory mixes target versions within a class, run a separate plan with a representative pilot for each target; an optional leading `v` does not distinguish otherwise identical versions. Minor upgrades require independent review; major upgrades require notification and an accepted ADR. Exception-bearing upgrades require human review.

The first representative is selected by locale-independent UTF-16 code-unit ordering of class and repository names. Identical class and repository strings retain input order; this does not authenticate or normalize repository identities.

The input must be a JSON array of objects with nonblank string `repo` and `repoClass`, and string `currentPolicy` and `targetPolicy` fields. If present, `exceptionId` must be a nonblank string and `pilotOutcome` must be `pending`, `passed`, or `failed`. A missing pilot outcome remains pending. The command rejects malformed inventory before producing a plan; invalid version strings are still represented as blocked entries.

Policy versions use numeric `X.Y.Z` triplets, optionally prefixed by `v`. Components cannot contain leading zeros, and the target must be strictly newer. Components are compared exactly even beyond JavaScript's safe-integer range. Prerelease/build labels, ranges, and surrounding whitespace are not accepted.

The planner does not create PRs, execute target-repository code, or verify remote pilot outcomes. Operators must attach policy diff, validation, exceptions, and provenance evidence to any governed upgrade PR.

## Governed upgrade dry run

[#62](https://github.com/OMT-Global/bootstrap/issues/62) remains open for governed PR generation. [#268](https://github.com/OMT-Global/bootstrap/pull/268) prepares exact candidates. [#272](https://github.com/OMT-Global/bootstrap/pull/272) and [#273](https://github.com/OMT-Global/bootstrap/pull/273) provide runtime policy and pilot verification. [#274](https://github.com/OMT-Global/bootstrap/pull/274) and [#275](https://github.com/OMT-Global/bootstrap/pull/275) provide native review and signing.

The governed command plans a single selected repository. Its read-only plan needs a clean trusted Linux Bootstrap generator checkout at the current public controller commit, the controller's enrolled `fleetRuntime` policy, and current public governance evidence. The request selects one public repository by name and numeric ID, an exact Flow target and digest, and the existing local paths. Keep request files local. The paths below are fabricated.

```sh
bootstrap upgrade-public-repository --request ./upgrade-request.json
bootstrap upgrade-public-repository --request ./upgrade-request.json --json
```

```json
{
  "repository": "example/widget",
  "repositoryId": 501,
  "originalRoot": "/home/example/checkouts/widget",
  "generatorRoot": "/home/example/checkouts/bootstrap",
  "generatorCommit": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "target": {
    "ref": "refs/tags/v1.2.3",
    "sha256": "1111111111111111111111111111111111111111111111111111111111111111"
  },
  "cohortComment": 720
}
```

A verified plan exits zero and reports the selected base, rollout role, pilot status, and pending publication gates. Missing, blocked, or stale evidence exits nonzero with a redacted reason. Publication remains unavailable in this source stage, and `--publish` exits nonzero. A passing pilot requires the merged PR and CI evidence below.

### Pilot outcomes and remediation

The enrolled human pilot actor records outcomes in the configured governance issue. Each comment body consists of the marker line and a single compact JSON line in `JSON.stringify` form. Paste just those two lines as the comment body, ending immediately after the JSON object. Select the current cohort and its exact target digest. The examples below are fabricated alternatives.

A passing record binds an actual merged PR, its exact candidate and merge commits, and successful CI evidence for the recorded target.

```text
PRS-FLEET-GOVERNANCE-001
{"schemaVersion":1,"kind":"pilot-outcome","outcome":"passed","cohort":720,"repositoryId":501,"targetDigest":"1111111111111111111111111111111111111111111111111111111111111111","candidateCommit":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","mergedCommit":"cccccccccccccccccccccccccccccccccccccccc","pullNumber":42,"ci":{"runId":900,"attempt":1,"evidenceSha256":"2222222222222222222222222222222222222222222222222222222222222222","workflowSha256":"3333333333333333333333333333333333333333333333333333333333333333"}}
```

A failed outcome can refer to a candidate whose PR has yet to merge. Supply a merge commit only when the PR actually merged.

```text
PRS-FLEET-GOVERNANCE-001
{"schemaVersion":1,"kind":"pilot-outcome","outcome":"failed","cohort":720,"repositoryId":501,"targetDigest":"1111111111111111111111111111111111111111111111111111111111111111","candidateCommit":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","pullNumber":42,"failure":"The representative failed validation."}
```

A remediation record references the failed outcome's comment ID. This permits the representative to retry. Later members of the same class stay blocked until an authenticated pass for that target.

```text
PRS-FLEET-GOVERNANCE-001
{"schemaVersion":1,"kind":"remediation","cohort":720,"repositoryId":501,"targetDigest":"1111111111111111111111111111111111111111111111111111111111111111","failedComment":723,"resolution":"The failed validation was corrected and reviewed."}
```

### Publication recovery

The forthcoming executor depends on the exact signed candidate, verified native capture and provenance, and the narrowly scoped App. After an uncertain branch write, PR creation, or credential cleanup, retain the attempt and reconcile the exact ref and PR with a maintainer. The unresolved repository record blocks a fresh attempt for that numeric repository, including a regenerated candidate or different branch.

## Reconciliation recovery

The separate `bootstrap reconcile --apply-repo --create-pr` command handles generic file drift, not version-aware upgrade execution. It has no transactional fleet rollback or automatic resume journal. Review each repository result after interruption or failure; successful repositories are not rolled back when another repository fails.

Reconciliation creates a new branch and refuses to reset an existing branch with the same name. A same-day retry may therefore fail with an existing-branch error. Inspect and finish the existing recovery branch and any remote PR before starting another attempt; use a distinct `--branch-prefix` only for an intentionally new run.

If apply, staging, or commit fails with dirty output, reconciliation leaves those files and the index on the recovery branch. A subsequent apply is blocked while that worktree is dirty, even if its generated files already match the templates. Inspect the status, diff, staged diff, and reported branch before manually completing or reverting the attempt. Do not interpret matching files as proof that a commit, push, or PR succeeded.

After a clean commit, reconciliation attempts to restore the starting branch even if push or PR creation failed. Recovery commits remain on the reconciliation branch. If restoration also fails, the report records both errors; if the PR was already created, its URL remains in the failed result. Inspect local and remote state before resuming an interrupted run, since a process killed before report completion cannot record its final outcome.
