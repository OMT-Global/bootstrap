import { createHash } from "node:crypto";
import { z } from "zod";

const id = z.string().regex(/^[1-9][0-9]{0,19}$/);
const sha = z.string().regex(/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/);
const digest = z.string().regex(/^[0-9a-f]{64}$/);
const asset = z.object({ name: z.string().min(1).max(255).regex(/^[^/\\\x00-\x1f\x7f]+$/), size: z.number().int().nonnegative().safe(), sha256: digest }).strict();
const manifestSchema = z.object({
  schema_version: z.literal(2),
  approval_id: z.string().uuid(),
  expires_at: z.string().datetime(),
  action: z.literal("publish_new_release"),
  repository: z.object({ id, full_name: z.string().regex(/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/).max(201) }).strict(),
  tag: z.string().max(255).regex(/^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-(?:rc|beta)\.[0-9]+)?$/),
  version: z.string().max(255),
  channel: z.enum(["rc", "beta", "stable", "maintenance"]),
  publication: z.object({ notes_asset: z.string().min(1).max(255), latest: z.boolean() }).strict(),
  target: z.object({ commit: sha, tree: sha }).strict(),
  preflight: z.object({ workflow_path: z.string().regex(/^\.github\/workflows\/[A-Za-z0-9_.-]+\.ya?ml$/), workflow_id: id, workflow_commit: sha, run_id: id, attempt: id, artifact_id: id, archive_sha256: digest, requester_id: id, attempt_actor_id: id }).strict(),
  assets: z.array(asset).min(1).max(100)
}).strict();

export type ReleaseApprovalManifest = z.infer<typeof manifestSchema>;
type Review = { id: string; reviewer_id: string; state: "APPROVED" | "CHANGES_REQUESTED" | "COMMENTED" | "DISMISSED"; commit: string; submitted_at: string; body: string };

/**
 * The adapter providing these facts must authenticate GitHub, bind every response
 * to its request, collect all review pages, and establish the artifact, source,
 * requester and publisher facts independently. This function cannot verify a
 * caller's authority, complete pagination, or eliminate a subsequent race.
 */
export type ApprovalObservation = {
  manifestBytes: Uint8Array;
  actual: Omit<ReleaseApprovalManifest, "approval_id" | "expires_at">;
  pull: { repository_id: string; state: "open" | "closed"; head: string; author_id: string; changed_paths: string[] };
  reviews: Review[];
  publisher_id: string;
  publisher_attempt_actor_id: string;
};

export type ApprovalReviewObservation = Omit<ApprovalObservation, "actual">;

export type ApprovalPolicy = { reviewer_id: string; manifest_path: string; max_validity_seconds: number };
export class ReleaseApprovalError extends Error {
  constructor() { super("Release approval unavailable or invalid."); }
}

function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value !== null && typeof value === "object") {
    const object = value as Record<string, unknown>;
    return `{${Object.keys(object).sort().map((key) => `${JSON.stringify(key)}:${canonical(object[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function timestamp(value: string): number {
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) throw new ReleaseApprovalError();
  return parsed;
}

type ReviewResult = { manifest_sha256: string; review_id: string; head: string };
type ReviewedRecord = { manifest: ReleaseApprovalManifest; result: ReviewResult; expires: number };
declare const reviewedBrand: unique symbol;
export type ReviewedReleaseManifest = { readonly [reviewedBrand]: true };
const reviewed = new WeakMap<object, ReviewedRecord>();

/** Verify the review decision only. Caller-authenticated GitHub facts and actors are required. */
function reviewManifest(observation: ApprovalReviewObservation, policy: ApprovalPolicy, now: Date): ReviewedRecord {
  try {
    if (!id.safeParse(policy.reviewer_id).success || !id.safeParse(observation.publisher_id).success || !id.safeParse(observation.publisher_attempt_actor_id).success ||
      !Number.isSafeInteger(policy.max_validity_seconds) || policy.max_validity_seconds < 1 || policy.max_validity_seconds > 86400 ||
      !/^\.github\/release-approvals\/[A-Za-z0-9_-]+\.json$/.test(policy.manifest_path) ||
      !(observation.manifestBytes instanceof Uint8Array) || observation.manifestBytes.byteLength > 65536) throw new Error();
    const text = new TextDecoder("utf-8", { fatal: true }).decode(observation.manifestBytes);
    const parsed = JSON.parse(text) as unknown;
    const manifest = manifestSchema.parse(parsed);
    if (`${canonical(parsed)}\n` !== text) throw new Error();
    const prerelease = /-(?:rc|beta)\.[0-9]+$/.test(manifest.tag);
    if (manifest.version !== manifest.tag || prerelease !== (manifest.channel === "rc" || manifest.channel === "beta")) throw new Error();
    const names = manifest.assets.map((entry) => entry.name);
    if (!names.includes(manifest.publication.notes_asset) || (prerelease && manifest.publication.latest) ||
        new Set(names).size !== names.length || names.some((name, index) => index > 0 && (names[index - 1] ?? "") >= name)) throw new Error();
    const pull = observation.pull;
    if (pull.repository_id !== manifest.repository.id || pull.state !== "open" || !sha.safeParse(pull.head).success ||
      !id.safeParse(pull.author_id).success || pull.author_id === policy.reviewer_id ||
      manifest.preflight.requester_id === policy.reviewer_id || manifest.preflight.attempt_actor_id === policy.reviewer_id || observation.publisher_id === policy.reviewer_id || observation.publisher_attempt_actor_id === policy.reviewer_id ||
      pull.changed_paths.length !== 1 || pull.changed_paths[0] !== policy.manifest_path) throw new Error();
    if (observation.reviews.length === 0 || observation.reviews.length > 1000) throw new Error();
    const latest = new Map<string, { review: Review; time: number }>();
    const reviewIds = new Set<string>();
    const current = now.getTime();
    if (!Number.isFinite(current)) throw new Error();
    for (const review of observation.reviews) {
      if (!id.safeParse(review.id).success || !id.safeParse(review.reviewer_id).success || !sha.safeParse(review.commit).success ||
        !["APPROVED", "CHANGES_REQUESTED", "COMMENTED", "DISMISSED"].includes(review.state) || typeof review.body !== "string" || review.body.length > 65536 || reviewIds.has(review.id)) throw new Error();
      reviewIds.add(review.id);
      const time = timestamp(review.submitted_at);
      if (time > current) throw new Error();
      if (review.state === "COMMENTED") continue;
      const previous = latest.get(review.reviewer_id);
      if (previous && previous.time === time) throw new Error();
      if (!previous || time > previous.time) latest.set(review.reviewer_id, { review, time });
    }
    if ([...latest.values()].some(({ review }) => review.state === "CHANGES_REQUESTED")) throw new Error();
    const approved = latest.get(policy.reviewer_id);
    const checksum = createHash("sha256").update(observation.manifestBytes).digest("hex");
    const expires = timestamp(manifest.expires_at);
    if (!approved || approved.review.state !== "APPROVED" || approved.review.commit !== pull.head ||
      approved.review.body !== `APPROVE-RELEASE-SHA256 ${checksum}` || !Number.isFinite(current) ||
      approved.time > current || current >= expires || expires - approved.time > policy.max_validity_seconds * 1000) throw new Error();
    return { manifest, result: { manifest_sha256: checksum, review_id: approved.review.id, head: pull.head }, expires };
  } catch {
    throw new ReleaseApprovalError();
  }
}

/**
 * Authenticates a reviewed manifest before artifact acquisition. This fact is not
 * an approved package or publication authority. All observations and actors must
 * come from a trusted authenticated provider and be refreshed at use boundaries.
 */
export function reviewReleaseManifest(observation: ApprovalReviewObservation, policy: ApprovalPolicy, now: Date): ReviewedReleaseManifest {
  const record = reviewManifest(observation, policy, now);
  const fact = Object.freeze({}) as ReviewedReleaseManifest;
  reviewed.set(fact, record);
  return fact;
}

/** Return immutable acquisition selectors before expiry; this does not recheck a live review. */
export function reviewedReleaseSelectors(value: ReviewedReleaseManifest): Readonly<{
  repositoryId: string; repository: string; tag: string; version: string; channel: string; targetCommit: string; targetTree: string;
  runId: string; attempt: string; artifactId: string; archiveSha256: string;
  workflowId: string; workflowPath: string; workflowCommit: string; requesterId: string; attemptActorId: string;
  notesAssetName: string; assets: readonly Readonly<{ name: string; size: number; sha256: string }>[]; manifestSha256: string;
}> {
  const record = reviewed.get(value);
  if (!record || Date.now() >= record.expires) throw new ReleaseApprovalError();
  const m = record.manifest;
  return Object.freeze({ repositoryId: m.repository.id, repository: m.repository.full_name, tag: m.tag, version: m.version, channel: m.channel, targetCommit: m.target.commit,
    targetTree: m.target.tree, runId: m.preflight.run_id, attempt: m.preflight.attempt, artifactId: m.preflight.artifact_id,
    archiveSha256: m.preflight.archive_sha256, workflowId: m.preflight.workflow_id, workflowPath: m.preflight.workflow_path,
    workflowCommit: m.preflight.workflow_commit, requesterId: m.preflight.requester_id, attemptActorId: m.preflight.attempt_actor_id,
    notesAssetName: m.publication.notes_asset, assets: Object.freeze(m.assets.map((asset) => Object.freeze({ ...asset }))), manifestSha256: record.result.manifest_sha256 });
}

/** Compare a reviewed manifest with independently derived package facts; never publish. */
export function verifyReleaseApproval(observation: ApprovalObservation, policy: ApprovalPolicy, now: Date): ReviewResult {
  try {
    const record = reviewManifest(observation, policy, now);
    const { approval_id: _approval, expires_at: _expiry, ...bound } = record.manifest;
    if (canonical(bound) !== canonical(observation.actual)) throw new Error();
    return record.result;
  } catch {
    throw new ReleaseApprovalError();
  }
}
