import { spawn } from "node:child_process";
import { performance } from "node:perf_hooks";
import { z } from "zod";

import { canonicalizeProvenanceJson, containsCredential, publicProvenanceInputSchema, type PublicProvenance } from "./provenance.js";

const repositoryName = z.string().max(140).regex(/^[A-Za-z0-9][A-Za-z0-9-]{0,38}\/[A-Za-z0-9_.-]{1,100}$/)
  .refine((value) => !containsCredential(value) && ![".", ".."].includes(value.split("/")[1] ?? ""));
export const publicPullRequestContextSchema = z.object({
  repository: repositoryName,
  commitSha: z.string().regex(/^[0-9a-f]{40}$/),
  pullRequest: z.number().int().min(1).max(2_147_483_647)
}).strict();
export type PublicPullRequestContext = z.infer<typeof publicPullRequestContextSchema>;

const nodeId = z.string().min(1).max(256);
const actor = z.object({ id: nodeId, login: publicProvenanceInputSchema.shape.reviewers.element.shape.login }).strict();
const repository = z.object({ id: nodeId, nameWithOwner: repositoryName, isPrivate: z.literal(false) }).strict();
const review = z.object({
  id: nodeId,
  author: actor,
  commit: z.object({ oid: z.string().regex(/^[0-9a-f]{40}$/) }).strict().nullable(),
  state: z.enum(["APPROVED", "CHANGES_REQUESTED", "COMMENTED", "DISMISSED", "PENDING"]),
  submittedAt: z.string().datetime({ offset: true }).nullable()
}).strict();
const cursorSchema = z.string().min(1).max(1_024);
const responseSchema = z.object({
  errors: z.array(z.unknown()).max(0).optional(),
  data: z.object({ repository: repository.extend({ pullRequest: z.object({
    id: nodeId,
    number: z.number().int(),
    headRefOid: z.string().regex(/^[0-9a-f]{40}$/),
    headRepository: repository,
    author: actor,
    reviewDecision: z.literal("APPROVED"),
    latestOpinionatedReviews: z.object({
      totalCount: z.number().int().min(0).max(1_600),
      nodes: z.array(review).max(100),
      pageInfo: z.object({ hasNextPage: z.boolean(), endCursor: cursorSchema.nullable() }).strict()
    }).strict()
  }).strict() }).strict() }).strict()
}).strict();

// This fixed query is read-only; caller strings are variables, never query text or endpoints.
const query = `query PublicProvenanceReviews($owner:String!,$name:String!,$number:Int!,$cursor:String) {
  repository(owner:$owner,name:$name) {
    id nameWithOwner isPrivate
    pullRequest(number:$number) {
      id number headRefOid headRepository { id nameWithOwner isPrivate }
      author { login ... on User { id } ... on Bot { id } }
      reviewDecision
      latestOpinionatedReviews(first:100,after:$cursor) {
        totalCount nodes {
          id state submittedAt commit { oid }
          author { login ... on User { id } ... on Bot { id } }
        }
        pageInfo { hasNextPage endCursor }
      }
    }
  }
}`;

async function readPage(context: PublicPullRequestContext, cursor: string | undefined, deadline: number): Promise<unknown> {
  const [owner, name] = context.repository.split("/");
  const args = ["api", "--hostname", "github.com", "graphql", "--method", "POST",
    "--raw-field", `query=${query}`, "--raw-field", `owner=${owner}`, "--raw-field", `name=${name}`,
    "--field", `number=${context.pullRequest}`];
  if (cursor !== undefined) args.push("--raw-field", `cursor=${cursor}`);
  const timeout = Math.min(30_000, deadline - performance.now());
  if (timeout <= 0) throw new Error("GitHub review lookup exceeded its deadline.");
  return new Promise((resolve, reject) => {
    const child = spawn("gh", args, {
      shell: false,
      detached: process.platform !== "win32",
      stdio: ["ignore", "pipe", "pipe"],
      env: { ...process.env, GH_HOST: "github.com", GH_PROMPT_DISABLED: "1", GH_PAGER: "cat", GH_DEBUG: "" }
    });
    let failed = false;
    let settled = false;
    let bytes = 0;
    const chunks: Buffer[] = [];
    const stop = () => {
      failed = true;
      try {
        if (process.platform !== "win32" && child.pid) process.kill(-child.pid, "SIGKILL");
        else child.kill("SIGKILL");
      } catch { /* A concurrently exited owned process needs no further signal. */ }
    };
    const timer = setTimeout(stop, timeout);
    timer.unref();
    process.once("SIGINT", stop);
    process.once("SIGTERM", stop);
    const finish = (ok: boolean) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      process.removeListener("SIGINT", stop);
      process.removeListener("SIGTERM", stop);
      if (!ok || failed) return reject(new Error("GitHub review lookup failed."));
      try { resolve(JSON.parse(Buffer.concat(chunks).toString("utf8"))); }
      catch { reject(new Error("GitHub review lookup returned invalid data.")); }
    };
    const consume = (chunk: Buffer, retain: boolean) => {
      bytes += chunk.length;
      if (bytes > 1_048_576) return stop();
      if (retain && !failed) chunks.push(chunk);
    };
    child.stdout.on("data", (chunk: Buffer) => consume(chunk, true));
    child.stderr.on("data", (chunk: Buffer) => consume(chunk, false));
    child.once("error", () => { stop(); finish(false); });
    child.once("close", (code) => finish(code === 0));
  });
}

type ReadReviewPage = (cursor: string | undefined, deadline: number) => Promise<unknown>;
interface ReviewIdentity {
  repositoryNodeId: string;
  headRepositoryNodeId: string;
  pullRequestNodeId: string;
}
async function collect(context: PublicPullRequestContext, deadline: number, read: ReadReviewPage,
  expected?: ReviewIdentity) {
  const rows: Array<z.infer<typeof review>> = [];
  const cursors = new Set<string>();
  let cursor: string | undefined;
  let identity: string | undefined;
  let authorId = "";
  let authorLogin = "";
  let total = 0;
  for (let page = 0; page < 16; page += 1) {
    const result = responseSchema.parse(await read(cursor, deadline)).data.repository;
    const pr = result.pullRequest;
    if (result.nameWithOwner !== context.repository || pr.number !== context.pullRequest || pr.headRefOid !== context.commitSha) {
      throw new Error("GitHub review subject does not match the expected context.");
    }
    if (expected && (result.id !== expected.repositoryNodeId || pr.id !== expected.pullRequestNodeId
      || pr.headRepository.id !== expected.headRepositoryNodeId)) {
      throw new Error("GitHub review identity does not match the expected context.");
    }
    const { latestOpinionatedReviews: connection, ...prIdentity } = pr;
    const currentIdentity = canonicalizeProvenanceJson({ repositoryId: result.id, name: result.nameWithOwner, ...prIdentity, total: connection.totalCount });
    if (identity !== undefined && identity !== currentIdentity) throw new Error("GitHub review subject changed during lookup.");
    identity = currentIdentity;
    authorId = pr.author.id;
    authorLogin = pr.author.login.toLowerCase();
    total = connection.totalCount;
    rows.push(...connection.nodes);
    if (!connection.pageInfo.hasNextPage) break;
    const next = connection.pageInfo.endCursor;
    if (page === 15 || connection.nodes.length === 0 || next === null || cursors.has(next)) {
      throw new Error("GitHub review pagination is incomplete.");
    }
    cursors.add(next);
    cursor = next;
  }
  if (rows.length !== total) throw new Error("GitHub review pagination is incomplete.");
  const ids = new Set<string>();
  const authors = new Set<string>();
  const logins = new Set<string>();
  const reviewers: PublicProvenance["reviewers"] = [];
  for (const row of rows) {
    const login = row.author.login.toLowerCase();
    if (ids.has(row.id) || authors.has(row.author.id) || logins.has(login)) throw new Error("GitHub review identities are ambiguous.");
    ids.add(row.id); authors.add(row.author.id); logins.add(login);
    if (row.state === "PENDING" || row.state === "DISMISSED") continue;
    if (row.submittedAt === null || row.commit === null) throw new Error("GitHub review is missing submitted provenance.");
    if (row.commit.oid !== context.commitSha) continue;
    if (row.author.id === authorId || login === authorLogin) {
      if (row.state !== "COMMENTED") throw new Error("GitHub review is not independent of the PR author.");
      continue;
    }
    reviewers.push({ login, state: row.state.toLowerCase() as "approved" | "changes_requested" | "commented" });
  }
  reviewers.sort((a, b) => a.login < b.login ? -1 : a.login > b.login ? 1 : 0);
  if (!reviewers.some((row) => row.state === "approved")) throw new Error("GitHub has no independent approval at the expected head.");
  rows.sort((a, b) => a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
  return { reviewers, snapshot: canonicalizeProvenanceJson({ identity, rows }) };
}

/** A bounded observation of native GitHub reviews, not a permanent merge authorization. */
export async function resolvePublicGitHubReviewers(context: PublicPullRequestContext): Promise<PublicProvenance["reviewers"]> {
  try {
    const expected = publicPullRequestContextSchema.parse(context);
    const deadline = performance.now() + 120_000;
    const read: ReadReviewPage = (cursor, end) => readPage(expected, cursor, end);
    const before = await collect(expected, deadline, read);
    const after = await collect(expected, deadline, read);
    if (before.snapshot !== after.snapshot) throw new Error("GitHub reviews changed during lookup.");
    return after.reviewers;
  } catch {
    // Remote errors and payloads can contain authentication diagnostics or untrusted text.
    throw new Error("Public GitHub reviewer verification failed.");
  }
}

/** Review observation for the enrolled workload, using its explicit token and the fixed GitHub API. */
export async function observeWorkloadPublicGitHubReviews(context: PublicPullRequestContext,
  identity: ReviewIdentity, token: string, signal: AbortSignal) {
  const expected = publicPullRequestContextSchema.parse(context);
  const [owner, name] = expected.repository.split("/");
  const read: ReadReviewPage = async (cursor, deadline) => {
    const timeout = Math.min(30_000, Math.floor(deadline - performance.now()));
    if (timeout <= 0 || signal.aborted) throw new Error("GitHub review lookup exceeded its deadline.");
    const abortSignal = AbortSignal.any([signal, AbortSignal.timeout(timeout)]);
    const response = await fetch("https://api.github.com/graphql", {
      method: "POST", redirect: "error", signal: abortSignal, cache: "no-store",
      headers: { authorization: `Bearer ${token}`, accept: "application/json", "content-type": "application/json" },
      body: JSON.stringify({ query, variables: { owner, name, number: expected.pullRequest, cursor } })
    });
    if (response.status !== 200 || response.redirected || !response.body) {
      void response.body?.cancel().catch(() => {});
      throw new Error("GitHub review response is unavailable.");
    }
    const reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    let size = 0;
    const cancel = () => { void reader.cancel().catch(() => {}); };
    abortSignal.addEventListener("abort", cancel, { once: true });
    try {
      for (;;) {
        const row = await reader.read();
        if (abortSignal.aborted) throw new Error("GitHub review lookup was interrupted.");
        if (row.done) break;
        size += row.value.byteLength;
        if (size > 1_048_576 || chunks.length >= 16_384) throw new Error("GitHub review response exceeds its bound.");
        chunks.push(row.value);
      }
      return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks))) as unknown;
    } finally {
      abortSignal.removeEventListener("abort", cancel);
      cancel();
    }
  };
  const deadline = performance.now() + 120_000;
  const before = await collect(expected, deadline, read, identity);
  const after = await collect(expected, deadline, read, identity);
  if (before.snapshot !== after.snapshot) throw new Error("GitHub reviews changed during lookup.");
  if (after.reviewers.some((reviewer) => reviewer.state === "changes_requested")) {
    throw new Error("GitHub has a blocking opinion at the expected head.");
  }
  return after;
}
