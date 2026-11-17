import { createHash } from "node:crypto";
import { z } from "zod";
import { readGitHubExactTag } from "./github-approval-reader.js";
import { releaseJson, releaseObject } from "./github-release-transport.js";
import { type ApprovedReleasePackage, approvedReleasePackageMetadata } from "./release-approved-package.js";

const id = z.string().regex(/^[1-9][0-9]{0,15}$/);
const sha = z.string().regex(/^[0-9a-f]{40}$/);
const digest = z.string().regex(/^[0-9a-f]{64}$/);
const timestamp = z.string().datetime();
const projection = z.object({ id: z.number().int().positive().safe(), source_type: z.literal("Repository"), source: z.literal("OMT-Global/bootstrap"),
  target: z.literal("tag"), enforcement: z.literal("active"), updated_at: timestamp,
  conditions: z.object({ ref_name: z.object({ include: z.array(z.string()).length(1), exclude: z.array(z.never()).length(0) }).strict() }).strict(),
  rules: z.array(z.object({ type: z.enum(["creation", "deletion", "update"]) }).strict()).length(3) }).strict();
const schema = z.object({ schema_version: z.literal(1), action: z.literal("publish_new_source_release"), qualified_by: id,
  qualified_at: timestamp, expires_at: timestamp, repository: z.literal("OMT-Global/bootstrap"), repository_id: id,
  app_id: z.number().int().positive().safe(), installation_id: z.number().int().positive().safe(),
  tag: z.string(), commit: sha, tag_object: sha, approval_sha256: digest, publication_run_id: id, publication_attempt: id, publication_workflow_commit: sha,
  bypass_actors: z.array(z.never()).length(0), projection }).strict();
const canonical = (value: unknown): unknown => Array.isArray(value) ? value.map(canonical) : value && typeof value === "object"
  ? Object.fromEntries(Object.entries(value).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([key, item]) => [key, canonical(item)])) : value;

export type PublicationQualification = { json: string; sha256: string; qualifierId: string; appId: number; installationId: number;
  publicationRunId: string; publicationAttempt: string; publicationWorkflowCommit: string };

/** Trusted deployment configuration supplies these exact qualification bytes/hash,
 * never a target artifact or workflow input. This is administrator qualification,
 * not a signature or proof that hidden bypass state remained unchanged. */
export function publicationProtection(input: { qualification: PublicationQualification; package: ApprovedReleasePackage; token: string; fetchImpl?: typeof fetch }) {
  const q = { ...input.qualification }; const packageFact = input.package; const token = input.token; const fetcher = input.fetchImpl ?? fetch;
  const expected = approvedReleasePackageMetadata(packageFact);
  if (typeof q.json !== "string" || Buffer.byteLength(q.json) > 8192 || !digest.safeParse(q.sha256).success ||
      createHash("sha256").update(q.json).digest("hex") !== q.sha256) throw new Error();
  const record = schema.parse(JSON.parse(q.json));
  const validFrom = Date.parse(record.qualified_at), expires = Date.parse(record.expires_at);
  if (expires <= validFrom || expires - validFrom > 600_000 || record.qualified_by !== q.qualifierId ||
      record.app_id !== q.appId || record.installation_id !== q.installationId || record.repository !== expected.repository ||
      record.repository_id !== expected.repositoryId || record.tag !== expected.tag || record.commit !== expected.commit ||
      record.approval_sha256 !== expected.approvalSha256 || record.publication_run_id !== q.publicationRunId ||
      record.publication_attempt !== q.publicationAttempt || record.publication_workflow_commit !== q.publicationWorkflowCommit ||
      record.projection.conditions.ref_name.include[0] !== `refs/tags/${expected.tag}` ||
      new Set(record.projection.rules.map((rule) => rule.type)).size !== 3) throw new Error();
  const url = `https://api.github.com/repos/${expected.repository}/rulesets/${record.projection.id}?includes_parents=false`;
  const assertValid = () => {
    if (Date.now() < validFrom || Date.now() >= expires) throw new Error();
    approvedReleasePackageMetadata(packageFact);
  };
  const assertCurrent = async () => {
    assertValid();
    const response = await fetcher(url, { method: "GET", headers: { Accept: "application/vnd.github+json", Authorization: `Bearer ${token}`,
      "X-GitHub-Api-Version": "2022-11-28" }, redirect: "manual", signal: AbortSignal.timeout(30_000) });
    const current = releaseObject(await releaseJson(response, url, 200));
    if (current.bypass_actors !== undefined && (!Array.isArray(current.bypass_actors) || current.bypass_actors.length)) throw new Error();
    const visible = projection.parse(Object.fromEntries(Object.keys(record.projection).map((key) => [key, current[key]])));
    if (JSON.stringify(canonical(visible)) !== JSON.stringify(canonical(record.projection))) throw new Error();
    const target = await readGitHubExactTag({ repository: expected.repository, repositoryId: expected.repositoryId,
      tag: expected.tag, expectedCommit: expected.commit, requireSigned: true, token, fetchImpl: fetcher });
    if (target.objectId !== record.tag_object) throw new Error();
    assertValid();
  };
  return Object.freeze({ assertCurrent, assertValid });
}
