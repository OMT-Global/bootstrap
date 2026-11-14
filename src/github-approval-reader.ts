import { createHash } from "node:crypto";
import type { ApprovalObservation } from "./release-approval.js";
import { ReleaseApprovalError } from "./release-approval.js";

const MAX_RESPONSE_BYTES = 1024 * 1024;
const MAX_MANIFEST_BYTES = 65536;
const MAX_REVIEW_PAGES = 10;
type ObjectValue = Record<string, unknown>;
type ApprovalPull = ApprovalObservation["pull"];
type ApprovalReviews = ApprovalObservation["reviews"];

function object(value: unknown): ObjectValue {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error();
  return value as ObjectValue;
}
function integerId(value: unknown): string {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value <= 0) throw new Error();
  return String(value);
}
function gitSha(value: unknown): string {
  if (typeof value !== "string" || !/^[0-9a-f]{40}$/.test(value)) throw new Error();
  return value;
}
function validTarget(repository: string, repositoryId: string, token: string): boolean {
  return /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository) && repository.length <= 201 &&
    !repository.split("/").some((part) => part === "." || part === "..") &&
    /^[1-9][0-9]{0,19}$/.test(repositoryId) && /^[\x21-\x7e]{1,4096}$/.test(token);
}
function githubReader(repository: string, token: string, fetchImpl: typeof fetch) {
  const base = `https://api.github.com/repos/${repository}`;
  return async (path: string): Promise<{ value: unknown; hasNext: boolean }> => {
    const response = await fetchImpl(`${base}${path}`, {
      method: "GET", redirect: "manual", signal: AbortSignal.timeout(10000),
      headers: { Accept: "application/vnd.github+json", Authorization: `Bearer ${token}`, "X-GitHub-Api-Version": "2022-11-28" }
    });
    if (!response.ok || response.redirected || !response.body) throw new Error();
    const links = response.headers.get("link");
    let hasNext = false;
    if (links) {
      for (const part of links.split(",")) {
        const match = /^\s*<([^>]+)>;\s*rel="(next|prev|first|last)"\s*$/.exec(part);
        if (!match) throw new Error();
        const linked = new URL(match[1] ?? "");
        const current = new URL(`${base}${path}`);
        if (linked.origin !== current.origin || linked.pathname !== current.pathname) throw new Error();
        if (match[2] === "next") {
          if (hasNext || linked.searchParams.get("per_page") !== "100" ||
            Number(linked.searchParams.get("page")) !== Number(current.searchParams.get("page")) + 1) throw new Error();
          hasNext = true;
        }
      }
    }
    const chunks: Uint8Array[] = [];
    let total = 0;
    for await (const chunk of response.body) {
      total += chunk.byteLength;
      if (total > MAX_RESPONSE_BYTES) throw new Error();
      chunks.push(chunk);
    }
    return { value: JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks))), hasNext };
  };
}
function pullFacts(value: unknown, repositoryId: string, pullNumber: number): { pull: ApprovalPull; base: string } {
  const data = object(value);
  const head = object(data.head);
  const base = object(data.base);
  if (data.number !== pullNumber || data.state !== "open" || data.changed_files !== 1 ||
      integerId(object(head.repo).id) !== repositoryId || integerId(object(base.repo).id) !== repositoryId) throw new Error();
  return { pull: { repository_id: repositoryId, state: "open", head: gitSha(head.sha), author_id: integerId(object(data.user).id), changed_paths: [] }, base: gitSha(base.sha) };
}

/**
 * Read only the PR facts for an approval. The token and optional fetch function
 * are trusted runtime inputs. No release, artifact, actor, or token authority is
 * established here. Production callers must supply a least-privilege token and
 * separately authenticate all remaining facts required by verifyReleaseApproval.
 */
export async function readGitHubApproval(input: {
  repository: string; repositoryId: string; pullNumber: number; manifestPath: string; token: string; fetchImpl?: typeof fetch;
}): Promise<Pick<ApprovalObservation, "manifestBytes" | "pull" | "reviews">> {
  try {
    if (!validTarget(input.repository, input.repositoryId, input.token) || !Number.isSafeInteger(input.pullNumber) || input.pullNumber < 1 ||
      !/^\.github\/release-approvals\/[A-Za-z0-9_-]+\.json$/.test(input.manifestPath)) throw new Error();
    const get = githubReader(input.repository, input.token, input.fetchImpl ?? fetch);
    const pullPath = `/pulls/${input.pullNumber}`;
    const first = pullFacts((await get(pullPath)).value, input.repositoryId, input.pullNumber);
    const files = await get(`${pullPath}/files?per_page=100&page=1`);
    if (!Array.isArray(files.value) || files.value.length !== 1 || files.hasNext) throw new Error();
    const file = object(files.value[0]);
    if (file.filename !== input.manifestPath || !["added", "modified"].includes(String(file.status)) || file.previous_filename !== undefined) throw new Error();
    const blobSha = gitSha(file.sha);
    const blob = object((await get(`/git/blobs/${blobSha}`)).value);
    if (blob.sha !== blobSha || blob.encoding !== "base64" || typeof blob.content !== "string" ||
      typeof blob.size !== "number" || !Number.isSafeInteger(blob.size) || blob.size < 1 || blob.size > MAX_MANIFEST_BYTES) throw new Error();
    const encoded = blob.content.replace(/\n/g, "");
    if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(encoded)) throw new Error();
    const manifestBytes = Buffer.from(encoded, "base64");
    if (manifestBytes.length !== blob.size || manifestBytes.toString("base64") !== encoded ||
      createHash("sha1").update(`blob ${manifestBytes.length}\0`).update(manifestBytes).digest("hex") !== blobSha) throw new Error();
    async function readReviews(): Promise<ApprovalReviews> {
      const reviews: ApprovalReviews = [];
      const ids = new Set<string>();
      for (let page = 1; page <= MAX_REVIEW_PAGES; page++) {
        const data = await get(`${pullPath}/reviews?per_page=100&page=${page}`);
        if (!Array.isArray(data.value) || data.value.length > 100 || (data.hasNext && data.value.length === 0)) throw new Error();
        for (const raw of data.value) {
          const review = object(raw);
          if (!["APPROVED", "CHANGES_REQUESTED", "COMMENTED", "DISMISSED"].includes(String(review.state)) ||
            typeof review.submitted_at !== "string" || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{3})?Z$/.test(review.submitted_at) ||
            (review.body !== null && typeof review.body !== "string")) throw new Error();
          const reviewId = integerId(review.id);
          if (ids.has(reviewId)) throw new Error();
          ids.add(reviewId);
          const submitted = new Date(review.submitted_at);
          if (!Number.isFinite(submitted.getTime()) || submitted.toISOString().replace(".000Z", "Z") !== review.submitted_at.replace(".000Z", "Z")) throw new Error();
          reviews.push({ id: reviewId, reviewer_id: integerId(object(review.user).id), state: review.state as ApprovalReviews[number]["state"],
            commit: gitSha(review.commit_id), submitted_at: submitted.toISOString(), body: review.body ?? "" });
        }
        if (data.value.length < 100 && !data.hasNext) return reviews;
      }
      throw new Error();
    }
    const reviews = await readReviews();
    if (JSON.stringify(reviews) !== JSON.stringify(await readReviews())) throw new Error();
    const last = pullFacts((await get(pullPath)).value, input.repositoryId, input.pullNumber);
    if (first.base !== last.base || first.pull.head !== last.pull.head || first.pull.author_id !== last.pull.author_id) throw new Error();
    return { manifestBytes, pull: { ...last.pull, changed_paths: [input.manifestPath] }, reviews };
  } catch {
    throw new ReleaseApprovalError();
  }
}

/**
 * Authenticate selected workflow/run/artifact metadata from GitHub. The workflow
 * path and revision are trusted policy inputs, not values obtained from the
 * approval manifest. This does not download the archive, verify its contents,
 * establish target source bytes, prove token permissions, or authorize release.
 */
export async function readGitHubPreflightMetadata(input: {
  repository: string; repositoryId: string; runId: string; attempt: string; artifactId: string;
  expectedWorkflowPath: string; expectedWorkflowCommit: string; targetCommit: string;
  token: string; fetchImpl?: typeof fetch;
}): Promise<{
  repository_id: string; workflow_path: string; workflow_id: string; workflow_commit: string; run_id: string; attempt: string;
  artifact_id: string; archive_sha256: string; requester_id: string; attempt_actor_id: string; target_commit: string; target_tree: string;
  limitations: { reusable_workflow: "unverified"; artifact_attempt_binding: "unverified"; archive_bytes: "unverified"; target_source_bytes: "unverified" };
}> {
  try {
    if (!validTarget(input.repository, input.repositoryId, input.token) ||
      ![input.runId, input.attempt, input.artifactId].every((value) => /^[1-9][0-9]{0,19}$/.test(value)) ||
      !/^\.github\/workflows\/[A-Za-z0-9_.-]+\.ya?ml$/.test(input.expectedWorkflowPath)) throw new Error();
    const workflowCommit = gitSha(input.expectedWorkflowCommit);
    const targetCommit = gitSha(input.targetCommit);
    const get = githubReader(input.repository, input.token, input.fetchImpl ?? fetch);
    async function one(path: string): Promise<ObjectValue> {
      const result = await get(path);
      if (result.hasNext) throw new Error();
      return object(result.value);
    }
    async function facts() {
      const run = await one(`/actions/runs/${input.runId}/attempts/${input.attempt}`);
      if (integerId(run.id) !== input.runId || integerId(run.run_attempt) !== input.attempt ||
        run.path !== input.expectedWorkflowPath || run.event !== "workflow_dispatch" || run.status !== "completed" || run.conclusion !== "success" ||
        gitSha(run.head_sha) !== workflowCommit || integerId(object(run.repository).id) !== input.repositoryId ||
        integerId(object(run.head_repository).id) !== input.repositoryId) throw new Error();
      const workflowId = integerId(run.workflow_id);
      const workflow = await one(`/actions/workflows/${workflowId}`);
      if (integerId(workflow.id) !== workflowId || workflow.path !== input.expectedWorkflowPath) throw new Error();
      const actor = object(run.actor);
      const trigger = object(run.triggering_actor);
      if (!["User", "Bot"].includes(String(actor.type)) || !["User", "Bot"].includes(String(trigger.type))) throw new Error();
      const artifact = await one(`/actions/artifacts/${input.artifactId}`);
      const artifactRun = object(artifact.workflow_run);
      if (integerId(artifact.id) !== input.artifactId || artifact.name !== "release-package" || artifact.expired !== false ||
        typeof artifact.digest !== "string" || !/^sha256:[0-9a-f]{64}$/.test(artifact.digest) ||
        integerId(artifactRun.id) !== input.runId || integerId(artifactRun.repository_id) !== input.repositoryId ||
        integerId(artifactRun.head_repository_id) !== input.repositoryId || gitSha(artifactRun.head_sha) !== workflowCommit) throw new Error();
      const commit = await one(`/git/commits/${targetCommit}`);
      if (gitSha(commit.sha) !== targetCommit) throw new Error();
      return { repository_id: input.repositoryId, workflow_path: input.expectedWorkflowPath, workflow_id: workflowId, workflow_commit: workflowCommit,
        run_id: input.runId, attempt: input.attempt, artifact_id: input.artifactId, archive_sha256: artifact.digest.slice(7),
        requester_id: integerId(actor.id), attempt_actor_id: integerId(trigger.id), target_commit: targetCommit, target_tree: gitSha(object(commit.tree).sha),
        limitations: { reusable_workflow: "unverified" as const, artifact_attempt_binding: "unverified" as const, archive_bytes: "unverified" as const, target_source_bytes: "unverified" as const } };
    }
    const first = await facts();
    if (JSON.stringify(first) !== JSON.stringify(await facts())) throw new Error();
    return first;
  } catch {
    throw new ReleaseApprovalError();
  }
}
