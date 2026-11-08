# ADR-0015: Bind managed security projection to verified Flow policy

Status: Accepted

Date: 2026-11-08

Decision owners: Bootstrap maintainers

Decision record: the task coordinator selects this bounded implementation contract for [Bootstrap #63](https://github.com/OMT-Global/bootstrap/issues/63) after independent design review. Acceptance does not supply independent PR approval or authorize repository application, ownership migration, settings changes, or new legal commitments.

## Context

The manifest can declare an immutable, canonically digest-pinned Flow policy whose four response targets differ from Bootstrap's legacy generic text. The managed SECURITY renderer did not consume the resolved policy, and legacy conformance could report a passing security baseline for acknowledgement within three business days and no explicit seven-calendar-day triage despite a verified two/seven/seven/thirty pin. Product-owned policy checking in ADR-0014 deliberately left this separate managed path unchanged.

## Decision

1. Keep `renderManagedFiles` synchronous and pure. Its optional `ResolvedPolicyContract` argument supplies the context required when rendering declared-Flow managed SECURITY. At runtime match the context source ref/digest to the actual manifest pin, rerun the existing pure resolver over the supplied policy body, and parse the strict four positive-safe-integer targets. Missing, stale, mutated, incompatible, or mismatched context fails with fixed `PRS-POLICY-SOURCE-001` evidence. Never trust a caller's type or a verified label alone.
2. Share one internal canonical five-statement helper between projection and conformance. Render the pinned acknowledgement, triage, critical remediation/containment, high remediation, and coordinated-disclosure commitments. Preserve Bootstrap's separate ten-business-day status-update and ninety-day moderate remediation targets. No-policy output and checks remain byte-identical; do not hardcode current Flow numeric values or derive them from prose.
3. Resolve repository projection through one asynchronous boundary used by planning and conformance. The existing `targetDir` is the source root for the declared relative `bundlePath`, including when `--manifest` names an external file. Never infer a different source directory, fetch a policy, or copy one automatically. A caller may supply the already-resolved context to `planRepo`; it is revalidated against the manifest and body. Conformance loads once and passes that same verified context into final planning. `applyRepo` continues executing a completed plan and fails on invalid policy before output or state writes.
4. Since planning now loads policy inputs automatically, bound the owning shared loader: lexical and resolved-parent repository containment, no-follow/nonblocking opened regular singly linked file, at most 1 MiB of fatal UTF-8 input, guaranteed closure, and fixed sanitized input errors. Preserve existing digest/reference/version checks after parsing. No external fallback; repository root remains trusted and concurrent filesystem replacement races are outside this guarantee.
5. Public declared-Flow response conformance uses ADR-0014's same bounded reader and whole-paragraph AST grammar for managed and product-owned documents. Read the protected SECURITY leaf before generic conformance reads, reuse supported bytes for required-file presence and managed ownership hashes, and withhold final generic planning after unsupported or missing input. Preserve historical product-ownership migration blockers and every ownership claim. Managed-path exclusions and product docs settings continue to determine actual selection.
6. Invalid policy produces an unsuppressible source blocker and explicit unavailable results for dependent required-artifact and declared-license projections. Do not fabricate dependent passes or fall back to generic clocks. Keep independent action/workflow/fork/capability/classification/profile/exception/sidecar-shape checks and historical managed-file drift evidence. Existing legal transition and notice requirements remain in force.
7. Direct `planRepo`/`applyRepo` retain their preexisting generic managed-file comparison I/O. This change establishes the conformance protected-input boundary, not general filesystem race safety or special-file hardening for all planning/application calls. The target repository remains a trusted containing boundary. No dependency, manifest field, CLI flag, settings operation, or automatic ownership migration is added.

## Consequences and validation

Managed policy generation now reflects the actual declared bundle and fails closed without valid context. Consumers of the pure renderer that render managed SECURITY for a declared pin must pass a resolved contract. Unconfigured callers preserve the full legacy document. Flow's product-owned bytes stay unselected and unchanged.

Required evidence includes the four before-failing integration witnesses, alternate compatible target values and singular units, stale/bad/missing contexts and bundles, no-output/state writes on resolution failure, exact no-policy output digest captured from the base, applied-byte sidecar hashes and clean-clone repeat planning, product/excluded ownership preservation, independent control/drift failures on invalid policy, and managed licensed/unlicensed symlink/hardlink/FIFO/oversize cases with zero generic SECURITY reads. The existing project-owned Node 20 compatibility job also runs the new managed-policy tests. Full repository checks, independent implementation review, committed actual-base autoreview, and exact-head PR gates remain necessary.
