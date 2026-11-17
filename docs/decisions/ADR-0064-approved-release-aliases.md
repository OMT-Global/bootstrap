# ADR-0064: Approved compatibility-alias promotion

Status: Accepted

Date: 2026-11-15

Governing issue: [#27](https://github.com/OMT-Global/bootstrap/issues/27).

The coordinator adopts the independently reviewed r3 source design under the owner's selected dedicated Bootstrap release App, current exact-package approval, and aliases only after successful publication. The design packet SHA-256 is `f397a1269cf9f9def6e30d94ffeec73b85562b9ace63b36767e06b6429f1d0d7`. Separate-agent review is established; model-family independence remains unproved. This accepts source behavior only, not a real alias operation, credential access, App installation, settings change, deployment or pilot.

## Decision

`promoteApprovedBootstrapReleaseAliases` is a concrete trusted workflow consumer. It reacquires the approved package and full validation, authenticates current JMCTE manifest approval and actor separation, verifies the exact signed tag and published release bytes/ID, and rechecks the scoped installation token. It never consumes diagnostic success JSON as authority. Only a stable or maintenance canonical `vMAJOR.MINOR.PATCH` package is eligible; rc/beta packages are rejected. Numeric SemVer comparison avoids floating-point loss.

Complete bounded authenticated tag and release inventories derive the enabled newest compatible aliases. A newer stable exact tag blocks its family even before publication. A relevant published stable release with a missing exact tag is ambiguous and blocks. `vX.Y` can advance only to the newest X.Y target; `vX` only to the newest X target. A maintenance release may advance its minor alias while leaving a newer major alias untouched. No other unapproved package can become the target.

For every existing alias in the eligible update list, preserve its raw object ID for the atomic condition and resolve its commit. Its baseline is the greatest authenticated exact stable version in the same family sharing that commit. Missing, wrong-family, unsupported or greater baselines block; removing historical exact tags cannot justify a downgrade. An untouched newer major alias does not block eligible minor-only promotion. An already-correct authorized alias is verified unchanged, not a claimed new promotion or recovery.

## Exact operation authority and transaction

A separate non-secret record comes from reviewed protected deployment configuration. It binds the configured alias-authorizer identity, repository numeric/canonical identity, App/installation, exact package approval SHA, signed tag object/commit, published release ID, workflow commit/run/attempt, and one or two fully qualified derived aliases with explicit before/after IDs. Validity is at most ten minutes. The record/hash does not authenticate arbitrary environment input; trusted configuration origin and real authorizer qualification are operational requirements, with no source-selected default identity.

After fresh repeated package/release/tag/inventory observations, one GraphQL `updateRefs` uses the authenticated repository node ID, explicit expected-before IDs (zero only for observed absence), the approved nonzero commit and `force:true`. No exact tag, branch, arbitrary ref, deletion or release write is possible. All selected aliases participate in one atomic provider transaction. Synchronous package/record validity checks run immediately before mutation after request preparation. Fresh observations must then verify all resulting aliases and the same exact release.

Any error, conflict, uncertain result or later mismatch stops for manual reconciliation. No second mutation, REST fallback, rollback, automatic adoption or implicit retry exists. A later attempt requires a new exact authorized operation. Atomicity covers the refs, not surrounding approval/release/tag inventory; a newer tag arriving after the last observation remains an explicit race. Expected-before conditions protect concurrent alias changes, not global writer exclusion.

## Compatibility and remaining qualification

`release.approvedAliases: true` exposes an optional default-false `promote_release_aliases` input only with a compatible reusable pin. Alias, publication and read-only retry selections are mutually exclusive. Approved dispatch precedes legacy downloads/Git/hooks and uses fixed runner-owned evidence. Default callers, generic hooks and both existing approved consumers retain their contracts; no manifest selector or runtime/workflow pin is activated here.

Preserve the narrow App profile: contents write, actions read, pull requests read. GitHub documents installation-token GraphQL access and Contents-write ref operations, but exact `updateRefs` permission/protected-ref behavior needs authorized provider qualification. Source mocks do not prove it, and permission failure permits no fallback or grant expansion. Real protected configuration, alias authority, approved target/package, provider qualification and separately authorized alias pilot remain required to close #27.

References: [atomic updateRefs](https://docs.github.com/en/graphql/reference/git#updaterefs), [installation-token GraphQL access](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/authenticating-as-a-github-app-installation), [Git reference permissions](https://docs.github.com/en/rest/git/refs#update-a-reference), [GraphQL App permission qualification](https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/choosing-permissions-for-a-github-app#choosing-permissions-for-graphql-api-access).
