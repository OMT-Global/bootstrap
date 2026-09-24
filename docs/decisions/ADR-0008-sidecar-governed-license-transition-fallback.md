# ADR-0008: Classify byte-matching sidecar licenses as governed without local state

Status: Accepted

Date: 2026-09-24

Decision owners: Bootstrap maintainers

Acceptance attribution: accepted by the coordinator under JT's 2026-09-24 keep-flowing authority, implementing the sealed reviewer recommendation (finding F-1, `reports/flow36-review-qwen-20260924/` for OMT-Global/flow#36); design authored by the lane worker (`qwen-token-plan/qwen3.8-max`). The deliverable is non-independent (same-family worker remediating a same-family sealed review) and remains advisory until distinct-family review.

Decision record: sealed review finding F-1 (remediation option 1) and the implementing pull request

## Context

The license transition guard (`PRS-LICENSE-TRANSITION-001`, see ADR-0002) fails closed on ungoverned legal transitions: adopting an existing unclassified LICENSE, or changing a managed license, requires exact recorded evidence binding approver, issue, ownership, contributor, and distribution history to the before/after modes and content hashes. The prior legal classification is read from RepoState, which bootstrap stores at `.git/info/bootstrap-state.json`. That state is git-local: it never propagates through push or clone, so every fresh environment is stateless.

The committed ownership sidecar is the only license-governance record that survives push/clone. Bootstrap parsed and fully validated its `license` entry (mode, 64-hex `contentSha256`, internal consistency with `managedFiles.LICENSE.sha256`, identifier presence per mode) but then dropped it as classification evidence.

Consequence: a fresh clone of an already-governed repository — concretely, OMT-Global/flow at merged main after PR #36 — hard-stopped stateless `plan`/`apply` with `PRS-LICENSE-TRANSITION-001` even though the on-disk LICENSE byte-matched the sidecar's declared content hash and the manifest rendered identical bytes. With no state and no line-start `SPDX-License-Identifier:` marker in flow's LICENSE, classification fell back to `existing-unclassified` and `transitionRequired` became unconditionally true. This false positive blocked both documented governed regeneration paths — the sidecar's own `regenerationCommand` and plan-before-apply onboarding — in every fresh environment. A causality control (seeding the git-local state) confirmed the repository is already at its governed fixed point: `spdx:MIT → spdx:MIT`, `transitionRequired=false`.

## Decision

1. When the git-local state carries no license record, bootstrap falls back to the validated ownership-sidecar license entry as the prior legal classification, and only when `sha256(on-disk LICENSE bytes)` equals the sidecar's declared `contentSha256` under a strict comparison; any deviation fails closed.
2. A byte-matching sidecar-governed license is a governed fixed point, not a transition: such plans report `transitionRequired=false` and carry an explicit `classificationSource: "ownership-sidecar"` audit field, plus a matching audit line in human-readable plan output.
3. The hard stop is preserved for every ungoverned case: a missing sidecar license entry, a hash mismatch, changed rendered bytes, or a mode change still requires exact adoption/transition evidence (for a sidecar-governed license, `from` = the governed mode at the on-disk hash), and sidecar file-ownership claims still never authorize updates or removals on their own.
4. When git-local state is present, semantics are unchanged: state always wins, and `PRS-OWNERSHIP-001` tamper/deletion detection is untouched.
5. `bootstrap conform` receives the same fallback consistently with `plan`, so no path reports a stale blocking `PRS-LICENSE-TRANSITION-001` from a clean clone.
6. Trust is content-verified, not git-tracked: bootstrap does not spawn git to verify the sidecar is tracked. This is no weaker than the status quo, because the previously trusted classifier (the git-local state file) is itself uncommitted, locally writable, and trivially seedable, and because the fallback only turns a hard stop into a pass when the on-disk LICENSE byte-matches the claim and the manifest renders identical bytes.

## Consequences

- Fresh-clone governed regeneration works statelessly: both documented flow regeneration paths pass against merged flow main, with zero tracked-file drift (verified by an A/B/A′ differential: unfixed control hard-stops, fixed build passes, base behavior unregressed).
- Consumers can distinguish fallback classification through the `classificationSource` audit field; the plan JSON shape is otherwise unchanged (conditional spread), so strict equality consumers are unaffected.
- Ungoverned adoptions — including byte-identical unmanaged licenses — still require exact evidence; no fail-closed property of ADR-0002 is weakened.
- One existing test encoded the old policy (stateless hard stop despite a tracked byte-matching sidecar) and was rewritten to the new governed semantics, keeping its stale-state `PRS-OWNERSHIP-001`, notices-reconciliation, and license-policy-removal assertions; negative tests cover hash mismatch, missing sidecar license entry, and stateless mode change.
- `docs/bootstrap/licensing.md` documents the fallback and its fail-closed boundary.

## Alternatives considered

### Weaken the transition check globally (treat any byte-identical existing LICENSE as a non-transition)

Rejected because it would remove the ADR-0002 fail-closed guarantee for ungoverned adoptions: a byte-identical unmanaged LICENSE would pass silently without evidence, erasing the governed/ungoverned distinction the guard exists to enforce.

### Seed git-local state from the flow side only (fix in flow, not bootstrap)

Rejected because it breaks the fresh-clone acceptance criterion: every new clone of flow — or of any other sidecar-governed repository — would still hard-stop until someone manually seeds uncommitted local state, and seeding scripts would not survive re-clones. The misclassification lives in bootstrap's classification logic, so the fix belongs there.

### Verify sidecar trackedness with a git subprocess before trusting it

Rejected as out of scope for a minimal fix: it would add a subprocess git dependency to the licensing path while providing trust that is provably no stronger than the existing git-local-state trust (Decision 6). Recorded here for distinct-family reviewer judgment.

## Security and privacy

The fallback introduces no new trust in unvalidated content: sidecar license entries must pass the full pre-existing validation, and any invalid claim still fails as an invalid ownership sidecar. Planting a passing fake sidecar requires planting a LICENSE byte-identical to the manifest's own approved-template render, which grants no capability the locally writable git-local state file does not already grant. Coordinated sidecar-plus-LICENSE tampering while live state exists still triggers `PRS-OWNERSHIP-001`.

## Revisit conditions

Revisit when RepoState propagates through clone (making the fallback redundant), when a trusted-channel or git-trackedness verification requirement is adopted for sidecars, or if distinct-family review rejects the content-verified trust boundary in Decision 6.
