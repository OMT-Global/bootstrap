import { createHash } from "node:crypto";
import type { approvedReleasePackageMetadata } from "../../src/release-approved-package.js";
export function publicationQualificationFixture(m: ReturnType<typeof approvedReleasePackageMetadata>) {
  const now = Math.floor(Date.now()/1000)*1000;
  const projection = { id: 42, source_type: "Repository", source: m.repository, target: "tag", enforcement: "active", updated_at: new Date(now - 60000).toISOString(),
    conditions: { ref_name: { include: [`refs/tags/${m.tag}`], exclude: [] } }, rules: [{ type: "creation" }, { type: "deletion" }, { type: "update" }] };
  const record = { schema_version: 1, action: "publish_new_source_release", qualified_by: "111", qualified_at: new Date(now - 1000).toISOString(), expires_at: new Date(now + 300000).toISOString(),
    repository: m.repository, repository_id: m.repositoryId, app_id: 10, installation_id: 20, tag: m.tag, commit: m.commit, tag_object: "9".repeat(40),
    approval_sha256: m.approvalSha256, publication_run_id: "130", publication_attempt: "3", publication_workflow_commit: "c".repeat(40), bypass_actors: [], projection };
  const json = JSON.stringify(record);
  return { record, qualification: { json, sha256: createHash("sha256").update(json).digest("hex"), qualifierId: "111", appId: 10, installationId: 20,
    publicationRunId: "130", publicationAttempt: "3", publicationWorkflowCommit: "c".repeat(40) } };
}
