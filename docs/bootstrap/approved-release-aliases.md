# Approved compatibility-alias promotion

This source consumer implements [ADR-0064](../decisions/ADR-0064-approved-release-aliases.md). It verifies a current exact approved published package and promotes only its eligible `vX.Y` / `vX` aliases in one expected-before GraphQL transaction. It never publishes a release or changes an exact tag. Operational activation and a real pilot remain outstanding.

Select a compatible immutable reusable/runtime revision before setting `release.approvedAliases: true` and running doctor/plan/apply for the caller. The optional `promote_release_aliases` dispatch input defaults to false and conflicts with `verify_existing_release` and `publish_new_source_release`. The existing major/minor switches select candidate families; the runtime derives eligibility. Source changes do not activate current caller pins, settings or operations.

The consumer uses the existing [trusted acquisition configuration](approved-release-retry.md), current JMCTE manifest review, scoped App token and bounded full-validation evidence. A prior `verified-existing` or `verified-created` JSON result is diagnostic, never an authority input. It rechecks the package and authenticated release itself. Prereleases cannot promote aliases. A maintenance release can advance its minor alias while a newer major alias stays unchanged. An alias without a surviving authenticated same-family version baseline blocks rather than risking a downgrade.

## Protected exact operation configuration

Add `aliasAuthorization` to reviewed protected `RELEASE_RETRY_CONFIG` with exact `json`, its lowercase SHA-256 `sha256`, and a configured numeric `authorizerId`. No default authorizer is selected. The origin of these values must be the reviewed protected deployment configuration, not workflow caller inputs, target code, artifacts or arbitrary environment values. Hash equality only detects mismatch and does not authenticate the named authorizer.

The strict JSON contains:

- `schema_version: 1`, `action: "promote_release_aliases"`, `authorized_by`, ISO `authorized_at` and `expires_at` (at most ten minutes).
- `repository: "OMT-Global/bootstrap"`, numeric-string `repository_id`, integer `app_id` and `installation_id`.
- Exact approved `tag`, `commit`, signed `tag_object`, `approval_sha256` and numeric-string `release_id`.
- Numeric-string `operation_run_id`, `operation_attempt`, and exact 40-character `operation_workflow_commit`.
- `updates`: exactly one or two strict objects `{ "name": "refs/tags/vX.Y", "beforeOid": "<40 lowercase hex>", "afterOid": "<approved commit>" }`, matching the derived eligible list. A proven absent ref uses forty zeros only for `beforeOid`. No zero after-ID or other ref class is allowed.

The record must be prepared for the actual run/attempt, captured aliases and current approval. Inventory, identity, expiration or expected-before drift stops the operation. Protected configuration handling, real authority identity and exact provider/grant behavior must be qualified before activation; fabricated tests supply no production authorization.

## Result and recovery

Success is `promoted-aliases` with verified names/commit/release ID, or `verified-unchanged-aliases` when all authorized refs already match. Both require the same fresh checks. Evidence is written to fixed runner-owned `approved-retry-evidence.json` for compatibility with the shared trusted dispatcher, then uploaded under the configured evidence artifact name with a `-publish` suffix; it is not a signed authorization receipt.

A conflict, timeout, GraphQL error, wrong mutation echo or failed final observation stops for human reconciliation. The runtime makes no automatic second mutation, rollback, fallback or uncertain-operation adoption. Inspect current release and refs independently, then prepare a new exact operation if appropriate. Concurrent newer tags after observation remain a documented race; the atomic transaction protects only the expected-before alias set.

The App grant stays contents write/actions read/pull requests read. Qualification of the exact GraphQL mutation and protected refs is still required. Do not add administration permission to bypass a failed operation. Generic callers retain their previous release-hook behavior; this optional consumer does not activate or rewrite that path.
