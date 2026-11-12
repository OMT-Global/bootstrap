# ADR-0049: Validate fleet upgrade inventory before planning

Status: Accepted

Date: 2026-11-11

Decision owner: OMT Global repository owner

Decision record: The repository owner accepted the proposed inventory-validation decision in the Bootstrap project chat on 2026-11-11. Implementation review, GitHub approval, and merge remain separate.

Related issue: [Bootstrap #62](https://github.com/OMT-Global/bootstrap/issues/62)

## Context

`bootstrap upgrade-plan` reads operator-supplied JSON to prepare a non-mutating policy upgrade plan. The documented inventory records repository, class, current and target policy versions, optional exception ID, and pilot outcome. The CLI previously cast parsed JSON to the expected type without validating its contents. Fabricated entries with blank identifiers or empty or non-string exception IDs could be reported as eligible. The planner does not verify pilot or exception evidence, execute upgrades, or create pull requests.

## Decision

Validate the complete parsed inventory before invoking the planner or emitting plan output:

1. Require an array of objects with nonblank string `repo` and `repoClass`, and string `currentPolicy` and `targetPolicy` fields.
2. If present, `exceptionId` must be a nonblank string and `pilotOutcome` must be exactly `pending`, `passed`, or `failed`. An absent pilot outcome retains the existing pending behavior.
3. Reject the whole malformed inventory with an error identifying the entry index and field without echoing the rejected value. Preserve unknown operator metadata in valid entries; an empty inventory is valid.
4. Leave version-string interpretation to the planner. Invalid or unsupported versions remain blocked plan rows instead of aborting the whole inventory. This retains useful per-entry version diagnostics.
5. Treat structural validity as distinct from authenticating a pilot, exception, repository identity, or policy version. Duplicate identity handling, normalization, remote validation, and guarded execution remain separate decisions.

## Consequences and alternatives

Inventories with blank identifiers, null optional fields, unrecognized pilot values, or false or empty exception IDs now fail before any plan is emitted. Operators must correct those inputs. Missing pilot outcomes remain pending rather than becoming assumed passes or invalid entries.

Continuing to trust the type cast would allow malformed inputs to be reported eligible. Aborting for invalid version strings would replace the planner's existing blocked-row diagnostics. Requiring every pilot outcome would reject inventories that intentionally defer that evidence.

This decision covers local input validation only. It does not authenticate evidence, enable PR generation or remote actions, change provider settings, or close #62. Independent implementation review, required autoreview, GitHub approval, and hosted validation remain separate.
