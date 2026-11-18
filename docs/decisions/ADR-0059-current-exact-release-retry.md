# ADR-0059: Current exact-release retry

Status: Accepted

Date: 2026-11-15

Governing issue: [#27](https://github.com/OMT-Global/bootstrap/issues/27).

The owner accepted the proposed current exact-match retry contract on 2026-11-15. The coordinator adopts this bounded source integration under that decision. This does not authorize an App installation, real key/token access, settings changes, publication or rollout. Review and current-head PR approval remain separate.

## Decision

A retry may return `verified-existing` when repeated authenticated observations match the independently approved package. It does not claim an atomic snapshot, permanent immutability, original publisher identity, original-run approval, or exclusive writer authority. An exact release from another original run may qualify. No creation receipt is required for this current-state result; a future stronger creation-provenance mode remains separate.

Preserve the existing exact-manifest approval and artifact acquisition contracts: JMCTE approves the current manifest head and is distinct from the preflight requester/attempt actor and publication requester/attempt actor. Requester and publisher need not differ from one another. Independently acquired ZIP and source-package bytes remain the expected asset facts. A dedicated App token must select only Bootstrap and retain the narrowly reviewed grants and expiry checks from ADR-0057.

Select the numeric release ID from a complete authenticated draft-visible listing, bind it to the approved repository and signed exact tag/commit, and re-read it by ID. Compare exact notes, prerelease/latest state and the complete asset inventory, including stable asset IDs, names, lengths and authenticated provider SHA-256 digests. Missing digests, missing latest evidence, draft/duplicate releases, pagination ambiguity, expiry or changed observations fail closed. Repeat current approval, actor, target, validation-run and token-scope checks before returning.

Successful reuse performs no publish hook, release creation, upload, replacement, publication-state mutation or floating-tag update. Token issuance is a separately configured credential operation, not publication. The result cannot be used as proof that this attempt performed `publish_new_release` and cannot authorize alias movement.

## Workflow integration and compatibility

The actual reusable publish workflow has an opt-in Bootstrap retry branch. It reads target-tag code as data from `release-target`, checks out the trusted Bootstrap runtime separately at an explicitly configured full commit, and builds that runtime before exposing the App key. It does not infer reusable-source identity from caller `github.workflow_sha`. Runtime policy must bind the publication, preflight and validation workflow identities and tool digests. The release issue is checked before runtime invocation; full validation is acquired and checked inside the trusted runtime before any release comparison. The branch never runs legacy unbounded downloads or target Git/hook operations. Its verification evidence uses a fixed runner-owned temporary path.

Full-validation evidence uses the same bounded ZIP verifier with a fixed validation profile. Select one artifact by authenticated run inventory, bind its numeric ID/provider digest and successful workflow/run/attempt, and require only `validation-evidence.json` with exact independent target/repository/run/attempt and completed checks. Recheck authenticated run/artifact identities after acquisition and at later boundaries. The producer adds its attempt stamp; unsupported old evidence fails closed. This is source wiring of the retained full-validation requirement, not an alternate approval or authority grant.

Existing callers remain byte-compatible by default. `release.approvedRetry: true` makes generated callers expose the new optional inputs only after an operator selects a compatible reusable-workflow pin. Current pins and environment settings are unchanged by this source stage.

The generic create path checks a complete release inventory before running its existing hooks. Existing or ambiguous releases stop; creation is attempted once without overwrite or error-to-create fallback. This preserves generic hook compatibility, not an at-most-once external-hook guarantee. An uncertain creation fails before verification/aliases and requires reconciliation. New Bootstrap publication is not authorized by the approved retry branch; absence there fails closed. A separately reviewed first-publication consumer and separately authorized floating-alias promotion are still required for the real #27 pilot.

## Validation and limits

Use fabricated credentials/providers and actual fabricated Git/archive/package bytes. Test historical-publisher-independent exact reuse, identity recreation, content changes, draft visibility, pagination ambiguity, revoked approval/token, actor mismatch and expiry. Assert that the retry consumer issues only observation requests after its single scoped token issuance and that the rendered shell exits before every hook or publication mutation.

A workflow-consumer test substitutes the already-tested branded package producer; separate composition tests exercise real package acquisition and fresh retry approval together. Local macOS results do not prove the Linux runtime host requirements, installed App identity, operational tool pins or protected environment configuration. An authorized hosted rehearsal and real release pilot remain acceptance work for #27.
