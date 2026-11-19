import { EventEmitter } from "node:events";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const harness = vi.hoisted(() => ({ spawn: vi.fn(), now: vi.fn() }));
vi.mock("node:child_process", () => ({ spawn: harness.spawn }));
vi.mock("node:perf_hooks", () => ({ performance: { now: harness.now } }));

import { resolvePublicGitHubReviewers } from "../src/provenance-github.js";

const expected = { repository: "acme/widget", commitSha: "a".repeat(40), pullRequest: 7 };
function review(id = "R1", login = "reviewer", state = "APPROVED", commit = expected.commitSha) {
  return { id, author: { id: `U_${login}`, login }, state, commit: { oid: commit }, submittedAt: "2026-11-09T00:00:00Z" };
}
function fixture(nodes = [review()]) {
  return { data: { repository: {
    id: "REPO1", nameWithOwner: expected.repository, isPrivate: false,
    pullRequest: {
      id: "PR1", number: 7, headRefOid: expected.commitSha,
      headRepository: { id: "HEAD1", nameWithOwner: "contributor/widget", isPrivate: false },
      author: { id: "U_author", login: "author" }, reviewDecision: "APPROVED",
      latestOpinionatedReviews: { totalCount: nodes.length, nodes, pageInfo: { hasNextPage: false, endCursor: null as string | null } }
    }
  } } };
}
type Reply = { payload?: unknown; raw?: string; stderr?: string; exit?: number; stall?: boolean; overflow?: boolean; error?: boolean };
let replies: Reply[];
let children: Array<EventEmitter & { kill: ReturnType<typeof vi.fn> }>;

beforeEach(() => {
  replies = [];
  children = [];
  harness.now.mockReset().mockReturnValue(0);
  harness.spawn.mockReset().mockImplementation(() => {
    const child = Object.assign(new EventEmitter(), {
      stdout: new EventEmitter(), stderr: new EventEmitter(),
      kill: vi.fn(() => { queueMicrotask(() => child.emit("close", null)); return true; })
    });
    children.push(child);
    const reply = replies.shift() ?? { payload: fixture() };
    queueMicrotask(() => {
      if (reply.stall) return;
      if (reply.error) { child.emit("error", new Error("UNTRUSTED_DIAGNOSTIC")); return; }
      if (reply.stderr) child.stderr.emit("data", Buffer.from(reply.stderr));
      if (reply.overflow) child.stdout.emit("data", Buffer.alloc(1_048_577));
      else child.stdout.emit("data", Buffer.from(reply.raw ?? JSON.stringify(reply.payload ?? fixture())));
      child.emit("close", reply.exit ?? 0);
    });
    return child;
  });
});
afterEach(() => { vi.useRealTimers(); });

describe("concrete public GitHub reviewer lookup", () => {
  it("uses fixed-host read-only GraphQL and returns native independent current-head reviewers", async () => {
    await expect(resolvePublicGitHubReviewers(expected)).resolves.toEqual([{ login: "reviewer", state: "approved" }]);
    expect(harness.spawn).toHaveBeenCalledTimes(2);
    const [binary, args, options] = harness.spawn.mock.calls[0]!;
    expect(binary).toBe("gh");
    expect(args.slice(0, 6)).toEqual(["api", "--hostname", "github.com", "graphql", "--method", "POST"]);
    expect(args).toContain("owner=acme");
    expect(args).toContain("name=widget");
    expect(args).toContain("number=7");
    const query = args.find((arg: string) => arg.startsWith("query="));
    expect(query).toContain("query PublicProvenanceReviews");
    expect(query).toContain("latestOpinionatedReviews");
    expect(query).not.toContain("mutation");
    expect(query).not.toContain("latestReviews(");
    expect(options.shell).toBe(false);
    expect(options.env.GH_HOST).toBe("github.com");
    expect(options.env.GH_PROMPT_DISABLED).toBe("1");
    expect(options.env.GH_DEBUG).toBe("");
  });

  it("paginates the complete native set twice and sorts canonical public reviewer identities", async () => {
    const first = fixture([review("R1", "Zebra")]);
    const second = fixture([review("R2", "Alpha", "COMMENTED")]);
    first.data.repository.pullRequest.latestOpinionatedReviews.totalCount = 2;
    first.data.repository.pullRequest.latestOpinionatedReviews.pageInfo = { hasNextPage: true, endCursor: "cursor-one" };
    second.data.repository.pullRequest.latestOpinionatedReviews.totalCount = 2;
    replies = [first, second, first, second].map((payload) => ({ payload }));
    await expect(resolvePublicGitHubReviewers(expected)).resolves.toEqual([
      { login: "alpha", state: "commented" }, { login: "zebra", state: "approved" }
    ]);
    expect(harness.spawn).toHaveBeenCalledTimes(4);
    expect(harness.spawn.mock.calls[1]![1]).toContain("cursor=cursor-one");
    expect(harness.spawn.mock.calls[2]![1]).not.toContain("cursor=cursor-one");
  });

  it("supports a verified public fork head while preserving the independently expected base identity", async () => {
    const response = fixture();
    expect(response.data.repository.pullRequest.headRepository.nameWithOwner).not.toBe(expected.repository);
    replies = [{ payload: response }, { payload: response }];
    await expect(resolvePublicGitHubReviewers(expected)).resolves.toEqual([{ login: "reviewer", state: "approved" }]);
  });

  it("uses the native opinion instead of inventing a latest-comment or review-ID heuristic", async () => {
    const response = fixture([review("R_old_id", "reviewer"), review("R_new_id", "commenter", "COMMENTED")]);
    replies = [{ payload: response }, { payload: response }];
    await expect(resolvePublicGitHubReviewers(expected)).resolves.toEqual([
      { login: "commenter", state: "commented" }, { login: "reviewer", state: "approved" }
    ]);
  });

  it("does not convert old, pending, dismissed or author-comment rows into approval", async () => {
    const response = fixture([
      review("R1", "reviewer"), review("R2", "old", "APPROVED", "b".repeat(40)),
      review("R3", "pending", "PENDING"), review("R4", "dismissed", "DISMISSED"), review("R5", "author", "COMMENTED")
    ]);
    replies = [{ payload: response }, { payload: response }];
    await expect(resolvePublicGitHubReviewers(expected)).resolves.toEqual([{ login: "reviewer", state: "approved" }]);
  });

  const invalid: Array<[string, (value: ReturnType<typeof fixture>) => void]> = [
    ["wrong base repository", (x) => { x.data.repository.nameWithOwner = "other/repo"; }],
    ["nonpublic base", (x) => { x.data.repository.isPrivate = true; }],
    ["nonpublic head repository", (x) => { x.data.repository.pullRequest.headRepository.isPrivate = true; }],
    ["absent head repository", (x) => { Object.assign(x.data.repository.pullRequest, { headRepository: null }); }],
    ["wrong PR", (x) => { x.data.repository.pullRequest.number = 8; }],
    ["moved head", (x) => { x.data.repository.pullRequest.headRefOid = "b".repeat(40); }],
    ["missing PR author", (x) => { Object.assign(x.data.repository.pullRequest, { author: null }); }],
    ["missing review author", (x) => { Object.assign(x.data.repository.pullRequest.latestOpinionatedReviews.nodes[0]!, { author: null }); }],
    ["native review required", (x) => { x.data.repository.pullRequest.reviewDecision = "REVIEW_REQUIRED"; }],
    ["native changes requested", (x) => { x.data.repository.pullRequest.reviewDecision = "CHANGES_REQUESTED"; }],
    ["self approval", (x) => { x.data.repository.pullRequest.latestOpinionatedReviews.nodes[0]!.author = { id: "U_author", login: "author" }; }],
    ["old-head-only approval", (x) => { x.data.repository.pullRequest.latestOpinionatedReviews.nodes[0]!.commit.oid = "b".repeat(40); }],
    ["dismissed-only approval", (x) => { x.data.repository.pullRequest.latestOpinionatedReviews.nodes[0]!.state = "DISMISSED"; }],
    ["pending-only approval", (x) => { x.data.repository.pullRequest.latestOpinionatedReviews.nodes[0]!.state = "PENDING"; }],
    ["comment-only lineage", (x) => { x.data.repository.pullRequest.latestOpinionatedReviews.nodes[0]!.state = "COMMENTED"; }],
    ["missing submitted commit", (x) => { Object.assign(x.data.repository.pullRequest.latestOpinionatedReviews.nodes[0]!, { commit: null }); }],
    ["missing submission time", (x) => { Object.assign(x.data.repository.pullRequest.latestOpinionatedReviews.nodes[0]!, { submittedAt: null }); }],
    ["unknown review state", (x) => { x.data.repository.pullRequest.latestOpinionatedReviews.nodes[0]!.state = "UNKNOWN"; }],
    ["duplicate review", (x) => { x.data.repository.pullRequest.latestOpinionatedReviews.nodes.push(review()); x.data.repository.pullRequest.latestOpinionatedReviews.totalCount = 2; }],
    ["ambiguous author ID", (x) => { const extra = review("R2", "other"); extra.author.id = "U_reviewer"; x.data.repository.pullRequest.latestOpinionatedReviews.nodes.push(extra); x.data.repository.pullRequest.latestOpinionatedReviews.totalCount = 2; }],
    ["ambiguous login case", (x) => { x.data.repository.pullRequest.latestOpinionatedReviews.nodes.push(review("R2", "Reviewer")); x.data.repository.pullRequest.latestOpinionatedReviews.totalCount = 2; }],
    ["wrong complete count", (x) => { x.data.repository.pullRequest.latestOpinionatedReviews.totalCount = 2; }],
    ["too many reviews", (x) => { x.data.repository.pullRequest.latestOpinionatedReviews.totalCount = 1_601; }],
    ["missing next cursor", (x) => { x.data.repository.pullRequest.latestOpinionatedReviews.pageInfo.hasNextPage = true; }]
  ];
  it.each(invalid)("fails closed for %s", async (_label, mutate) => {
    const response = fixture(); mutate(response); replies = [{ payload: response }];
    await expect(resolvePublicGitHubReviewers(expected)).rejects.toThrow("Public GitHub reviewer verification failed.");
  });

  it("rejects changed reviews, author identity and head repository between complete reads", async () => {
    for (const mutate of [
      (x: ReturnType<typeof fixture>) => { x.data.repository.pullRequest.latestOpinionatedReviews.nodes[0]!.id = "R_replaced"; },
      (x: ReturnType<typeof fixture>) => { x.data.repository.pullRequest.author.id = "OTHER_AUTHOR"; },
      (x: ReturnType<typeof fixture>) => { x.data.repository.pullRequest.headRepository.id = "OTHER_HEAD"; }
    ]) {
      const after = fixture(); mutate(after); replies = [{ payload: fixture() }, { payload: after }];
      await expect(resolvePublicGitHubReviewers(expected)).rejects.toThrow("verification failed");
    }
  });

  it("rejects a changed head in the middle of pagination", async () => {
    const first = fixture(); first.data.repository.pullRequest.latestOpinionatedReviews.totalCount = 2;
    first.data.repository.pullRequest.latestOpinionatedReviews.pageInfo = { hasNextPage: true, endCursor: "next" };
    const next = fixture([review("R2", "other")]); next.data.repository.pullRequest.headRefOid = "b".repeat(40);
    replies = [{ payload: first }, { payload: next }];
    await expect(resolvePublicGitHubReviewers(expected)).rejects.toThrow("verification failed");
  });

  it("stops repeated cursors and bounded incomplete page sequences", async () => {
    const response = fixture(); response.data.repository.pullRequest.latestOpinionatedReviews.totalCount = 16;
    response.data.repository.pullRequest.latestOpinionatedReviews.pageInfo = { hasNextPage: true, endCursor: "same" };
    replies = [{ payload: response }, { payload: response }];
    await expect(resolvePublicGitHubReviewers(expected)).rejects.toThrow("verification failed");
    expect(harness.spawn).toHaveBeenCalledTimes(2);
    harness.spawn.mockClear();
    replies = Array.from({ length: 16 }, (_, i) => {
      const page = fixture([review(`R${i}`, `person${i}`)]);
      page.data.repository.pullRequest.latestOpinionatedReviews.totalCount = 16;
      page.data.repository.pullRequest.latestOpinionatedReviews.pageInfo = { hasNextPage: true, endCursor: `cursor${i}` };
      return { payload: page };
    });
    await expect(resolvePublicGitHubReviewers(expected)).rejects.toThrow("verification failed");
    expect(harness.spawn).toHaveBeenCalledTimes(16);
  });

  it.each([
    { payload: { data: fixture().data, errors: [{ message: "UNTRUSTED_DIAGNOSTIC" }] } },
    { raw: "UNTRUSTED_DIAGNOSTIC" },
    { stderr: "UNTRUSTED_DIAGNOSTIC", exit: 1 },
    { error: true }
  ])("sanitizes malformed and failed transport responses", async (reply) => {
    replies = [reply];
    await expect(resolvePublicGitHubReviewers(expected)).rejects.toThrow(/^Public GitHub reviewer verification failed\.$/);
  });

  it("bounds combined stdout and stderr and terminates its owned subprocess", async () => {
    replies = [{ stderr: "x".repeat(1_048_576), raw: "{}" }];
    await expect(resolvePublicGitHubReviewers(expected)).rejects.toThrow("verification failed");
    expect(children[0]!.kill).toHaveBeenCalledWith("SIGKILL");
  });

  it("terminates a stalled owned request at the per-command deadline and removes its listeners", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "Date"] });
    replies = [{ stall: true }];
    const before = [process.listenerCount("SIGINT"), process.listenerCount("SIGTERM")];
    const failure = expect(resolvePublicGitHubReviewers(expected)).rejects.toThrow("verification failed");
    await vi.advanceTimersByTimeAsync(30_001);
    await failure;
    expect(children[0]!.kill).toHaveBeenCalledWith("SIGKILL");
    expect([process.listenerCount("SIGINT"), process.listenerCount("SIGTERM")]).toEqual(before);
  });

  it("enforces one monotonic aggregate budget across complete collections", async () => {
    harness.now.mockReturnValueOnce(0).mockReturnValueOnce(0).mockReturnValueOnce(120_001);
    await expect(resolvePublicGitHubReviewers(expected)).rejects.toThrow("verification failed");
    expect(harness.spawn).toHaveBeenCalledTimes(1);
  });

  it.each([
    { ...expected, repository: "https://elsewhere.invalid/acme/widget" },
    { ...expected, repository: "acme/.." },
    { ...expected, commitSha: "main" },
    { ...expected, pullRequest: 0 },
    { ...expected, pullRequest: 2_147_483_648 },
    { ...expected, extra: "not-context" }
  ])("validates independently expected context before starting a subprocess", async (context) => {
    await expect(resolvePublicGitHubReviewers(context)).rejects.toThrow("verification failed");
    expect(harness.spawn).not.toHaveBeenCalled();
  });
});
