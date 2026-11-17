# Approved Bootstrap source publication

The optional source-distribution consumer creates a new approved GitHub release through one draft, exact asset uploads, draft verification, publication and verification of the captured release/asset IDs. It checks the known no-op publish hook in approved Git data without executing it. It does not invoke custom hooks or move floating aliases. See [ADR-0063](../decisions/ADR-0063-first-approved-source-publication.md).

Select a compatible immutable reusable/runtime revision before setting `release.approvedPublication: true` and running doctor/plan/apply for the caller. The new dispatch input `publish_new_source_release` defaults to false and conflicts with `verify_existing_release`. Both operations use the separately built trusted runtime and the existing [approval/acquisition configuration](approved-release-retry.md). This source change does not activate those pins, settings or operations.

## Protection qualification

`RELEASE_RETRY_CONFIG.publicationQualification` adds three fields: `json` (exact non-secret qualification text, at most 8192 UTF-8 bytes), `sha256` (its lowercase SHA-256), and `qualifierId` (the configured administrator's numeric GitHub ID string). These are trusted, reviewed protected deployment configuration, captured once for the attempt. They must not be copied from dispatch inputs or target artifacts. A hash alongside arbitrary caller-controlled JSON would supply no authority. The runtime independently binds App/install/workflow configuration and the actual publication run/attempt.

The strict qualification JSON contains:

| Field | Binding |
| --- | --- |
| `schema_version`, `action` | `1`, `publish_new_source_release` |
| `qualified_by`, `qualified_at`, `expires_at` | Configured administrator ID and UTC timestamps; no future start, expired record or window longer than ten minutes |
| `repository`, `repository_id` | `OMT-Global/bootstrap` and approved numeric ID string |
| `app_id`, `installation_id` | Configured dedicated App and installation numbers |
| `tag`, `commit`, `tag_object` | Approved exact tag/commit and authenticated signed annotated tag object |
| `approval_sha256` | Current exact approved package manifest hash |
| `publication_run_id`, `publication_attempt`, `publication_workflow_commit` | Actual current run/attempt and trusted configured workflow commit |
| `bypass_actors` | Empty array explicitly observed by the qualifying administrator |
| `projection` | Exact `id`, `source_type: Repository`, `source`, `target: tag`, `enforcement: active`, `updated_at`, `conditions.ref_name` and `rules` security projection |

The supported projection includes exactly the approved `refs/tags/<tag>`, no exclusions, and exactly one each of the `creation`, `deletion` and `update` rules. Additional or different rule shapes require a reviewed source extension. Current visible projection and timestamp must match; visible bypass must be empty. A missing current bypass list is expected with the narrow token and remains unknown, supported only by the qualified no-change deployment assumption.

The administrator must obtain the actual full ruleset view, verify no bypass, approve/store this exact record through the protected deployment process and keep the policy unchanged during the validity window. No administrator credential enters the publisher. After any administrative change, requalify; matching update timestamps alone is not proof against every hidden bypass-only edit. The repository's real protected environment, qualification origin and administrator identity still require an authorized deployment review. No values are supplied here.

GitHub's [ruleset API](https://docs.github.com/en/rest/repos/rules#get-a-repository-ruleset) exposes basic reads with metadata access but withholds bypass actors without ruleset-write access. The publisher preserves its existing grants and checks the visible projection repeatedly. The rule protections, not observation alone, must prevent tag recreation if another actor deletes the tag between a read and the release request.

## Failure and recovery

Release name is the approved tag. A package requesting `latest:false` requires existing authenticated full latest-release evidence before draft creation. First-ever rc/beta publication is deliberately unsupported by this slice; stable `latest:true` can establish the first latest release.

Every create/upload/publish call is attempted once. A timeout, unexpected status, digest/ID mismatch, revoked approval, changed validation or expired qualification stops. Do not rerun publication blindly: inspect any draft, uploaded assets and published state, then reconcile manually. There is no automatic delete, replacement, rollback or adoption. A later separate exact-state retry can verify a matching published release without claiming who originally created it.

GitHub supports [draft creation and publication by release update](https://docs.github.com/en/rest/releases/releases). [Asset uploads](https://docs.github.com/en/rest/releases/assets#upload-a-release-asset) send raw approved bytes; duplicate names and uncertain provider outcomes stop instead of invoking deletion/re-upload recovery. Targets requiring additional workflow permissions fail without broadening the dedicated App grant.

Local fabricated provider and actual Git/archive/package tests do not qualify a real App, protected environment, Linux host, runtime/tool pin or publication. The hosted pilot and separately authorized [alias operation](approved-release-aliases.md) remain outstanding issue acceptance work.
