import { z } from "zod";
import { boundedValue, PublicObservationRead, publicRepository, record, repositoryPath } from "./upgrade-public-read.js";
import { readPages } from "./upgrade-pilot-ci.js";
import { freezeRuntimeValue, readRuntimePolicy, runtimeDemand, runtimeDigest, type RuntimePolicy } from "./upgrade-runtime-policy.js";

export const GOVERNANCE_MARKER = "PRS-FLEET-GOVERNANCE-001\n";
const id = z.number().int().positive().max(Number.MAX_SAFE_INTEGER);
const oid = z.string().regex(/^[0-9a-f]{40}$/);
const sha = z.string().regex(/^[0-9a-f]{64}$/);
const version = z.string().regex(/^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/);
const slug = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9-]{0,38}\/[A-Za-z0-9._-]{1,100}$/);
const member = z.object({ repositoryId: id, repository: slug, repoClass: z.string().min(1).max(100),
  sourceVersion: version, sourceDigest: sha, sourceHead: oid }).strict();
const target = z.object({ version, ref: z.string().regex(/^(?:[0-9a-f]{40}|refs\/tags\/v[0-9]+\.[0-9]+\.[0-9]+)$/), digest: sha, commit: oid }).strict();
const common = { schemaVersion: z.literal(1), cohort: id, repositoryId: id, targetDigest: sha };
const ci = z.object({ runId: id, attempt: id, evidenceSha256: sha, workflowSha256: sha }).strict();
const decision = z.union([
  z.object({ schemaVersion: z.literal(1), kind: z.literal("cohort"), organization: z.string().min(1).max(39),
    inventory: z.array(z.object({ repositoryId: id, repository: slug, managed: z.boolean() }).strict()).min(1).max(500),
    members: z.array(member).min(1).max(500), target, supersedes: id.optional(), reconciliation: z.string().min(1).max(2000).optional() }).strict(),
  z.object({ ...common, kind: z.literal("pilot-outcome"), outcome: z.literal("passed"), candidateCommit: oid,
    mergedCommit: oid, pullNumber: id, ci }).strict(),
  z.object({ ...common, kind: z.literal("pilot-outcome"), outcome: z.literal("failed"), candidateCommit: oid,
    pullNumber: id, mergedCommit: oid.optional(), failure: z.string().min(1).max(2000) }).strict(),
  z.object({ ...common, kind: z.literal("remediation"), failedComment: id, resolution: z.string().min(1).max(2000) }).strict(),
  z.object({ ...common, kind: z.literal("exception"), exceptionDigest: sha, expiresAt: z.string().regex(/^\d{4}-\d\d-\d\d$/).optional() }).strict(),
  z.object({ ...common, kind: z.literal("major-notice"), baseCommit: oid, explanation: z.string().min(1).max(2000) }).strict(),
  z.object({ ...common, kind: z.literal("accepted-adr"), baseCommit: oid,
    adr: z.object({ repository: slug, repositoryId: id, defaultBranch: z.string().min(1).max(255), commit: oid,
      path: z.string().regex(/^docs\/decisions\/ADR-[0-9]+-[A-Za-z0-9-]+\.md$/), sha256: sha }).strict() }).strict(),
  z.object({ schemaVersion: z.literal(1), kind: z.literal("revoke"), comment: id }).strict()
]);
export type GovernanceDecision = z.infer<typeof decision>;
export type DecisionRecord = Readonly<{ commentId: number; actorId: number; actorLogin: string; url: string;
  bodyDigest: string; value: GovernanceDecision }>;
export type DecisionObservation = Readonly<{ digest: string; count: number; requests: number; receivedBytes: number }>;
type OwnedDecisions = Readonly<{ policy: RuntimePolicy; records: readonly DecisionRecord[]; signal?: AbortSignal }>;
const observations = new WeakMap<DecisionObservation, OwnedDecisions>();
const role = (value: GovernanceDecision): "cohort" | "pilot" | "exception" | "major" | undefined =>
  value.kind === "cohort" ? "cohort" : ["pilot-outcome", "remediation"].includes(value.kind) ? "pilot"
    : value.kind === "exception" ? "exception" : value.kind === "revoke" ? undefined : "major";

/** Locators and comment bodies are claims; native actor identity and policy roles authenticate records. */
export async function observeUpgradeDecisions(policy: RuntimePolicy, options: { signal?: AbortSignal } = {}): Promise<DecisionObservation> {
  const signal = options.signal; signal?.throwIfAborted(); const { projection } = readRuntimePolicy(policy);
  const selected = projection.governance; const prefix = repositoryPath(selected.repository);
  const issueUrl = `https://github.com/${selected.repository}/issues/${selected.issue}`;
  const read = new PublicObservationRead(signal, selected.repository);
  let records: DecisionRecord[] = [];
  const scan = async (): Promise<DecisionRecord[]> => {
    await publicRepository(read, selected);
    const issue = record((await read.json(`${prefix}/issues/${selected.issue}`)).value);
    runtimeDemand(issue.number === selected.issue && issue.html_url === issueUrl && !issue.pull_request && Number.isSafeInteger(issue.id), "governance-target");
    const comments = await readPages(read, `${prefix}/issues/${selected.issue}/comments`, undefined, Number(issue.comments));
    const result: DecisionRecord[] = []; const ids = new Set<number>();
    for (const raw of comments) {
      const comment = record(raw); const actor = record(comment.user);
      runtimeDemand(Number.isSafeInteger(comment.id) && Number(comment.id) > 0 && !ids.has(Number(comment.id)), "governance-comment-identity"); ids.add(Number(comment.id));
      const approved = projection.actors.find((entry) => entry.id === actor.id && entry.login.toLowerCase() === String(actor.login).toLowerCase());
      if (!approved || actor.type !== "User" || typeof comment.body !== "string" || !comment.body.startsWith(GOVERNANCE_MARKER)) continue;
      runtimeDemand(comment.html_url === `${issueUrl}#issuecomment-${comment.id}` &&
        comment.url === `https://api.github.com${prefix}/issues/comments/${comment.id}` &&
        comment.issue_url === `https://api.github.com${prefix}/issues/${selected.issue}`, "governance-comment-binding");
      runtimeDemand(Buffer.byteLength(comment.body) <= 128 * 1024, "governance-record-limit");
      const text = comment.body.slice(GOVERNANCE_MARKER.length); const rawValue: unknown = JSON.parse(text); boundedValue(rawValue);
      // Canonical JSON makes duplicate object keys, hidden trailing text and ambiguous encodings inadmissible.
      runtimeDemand(JSON.stringify(rawValue) === text, "governance-record-noncanonical");
      const value = decision.parse(rawValue); const required = role(value);
      runtimeDemand(!required || approved.roles.includes(required), "governance-actor-role");
      if (value.kind === "revoke") {
        const prior = result.find((entry) => entry.commentId === value.comment);
        runtimeDemand(prior && prior.value.kind !== "revoke" && approved.roles.includes(role(prior.value)!), "governance-revocation");
      }
      result.push(freezeRuntimeValue({ commentId: Number(comment.id), actorId: approved.id, actorLogin: approved.login,
        url: comment.html_url as string, bodyDigest: runtimeDigest([comment.body, comment.created_at, comment.updated_at]), value }));
    }
    runtimeDemand(result.every((entry, index) => index === 0 || entry.commentId > result[index - 1]!.commentId), "governance-order");
    await publicRepository(read, selected); return result;
  };
  try {
    records = await scan(); runtimeDemand(runtimeDigest(await scan()) === runtimeDigest(records), "governance-changed");
    readRuntimePolicy(policy); read.check();
  } finally { await read.close(); }
  signal?.throwIfAborted();
  const handle = Object.freeze({ digest: runtimeDigest(records), count: records.length, ...read.stats });
  observations.set(handle, Object.freeze({ policy, records: Object.freeze(records), ...(signal ? { signal } : {}) })); return handle;
}
export function readOwnedDecisionObservation(handle: DecisionObservation): OwnedDecisions {
  const owned = observations.get(handle); runtimeDemand(owned, "unowned-decision-observation");
  readRuntimePolicy(owned!.policy); owned!.signal?.throwIfAborted(); return owned!;
}
export function activeUpgradeDecisions(handle: DecisionObservation): readonly DecisionRecord[] {
  const { records } = readOwnedDecisionObservation(handle);
  const revoked = new Set(records.flatMap((entry) => entry.value.kind === "revoke" ? [entry.value.comment] : []));
  return Object.freeze(records.filter((entry) => entry.value.kind !== "revoke" && !revoked.has(entry.commentId)));
}
