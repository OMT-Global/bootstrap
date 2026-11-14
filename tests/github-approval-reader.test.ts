import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { readGitHubApproval } from "../src/github-approval-reader.js";
import { type ReleaseApprovalManifest, verifyReleaseApproval } from "../src/release-approval.js";

const head = "a".repeat(40);
const base = "b".repeat(40);
const path = ".github/release-approvals/pilot.json";
const content = Buffer.from('{"fixture":true}\n');
const blobSha = createHash("sha1").update(`blob ${content.length}\0`).update(content).digest("hex");
const pull = { number: 4, state: "open", changed_files: 1, head: { sha: head, repo: { id: 100 } }, base: { sha: base, repo: { id: 100 } }, user: { id: 112 } };
const files = [{ filename: path, status: "added", sha: blobSha }];
const blob = { sha: blobSha, encoding: "base64", content: content.toString("base64"), size: content.length };
const review = { id: 200, user: { id: 111 }, state: "APPROVED", commit_id: head, submitted_at: "2026-11-12T11:45:00Z", body: "fake approval" };

type RequestFn = typeof fetch;
function harness(overrides?: (kind: string, count: number, url: URL) => unknown) {
  const calls: { url: string; method: string; authorization: string; redirect: string }[] = [];
  const counts = new Map<string, number>();
  const fake: RequestFn = async (input, init) => {
    const url = new URL(String(input));
    const headers = new Headers(init?.headers);
    calls.push({ url: url.href, method: String(init?.method), authorization: headers.get("authorization") ?? "", redirect: String(init?.redirect) });
    const kind = url.pathname.endsWith("/files") ? "files" : url.pathname.includes("/git/blobs/") ? "blob" : url.pathname.endsWith("/reviews") ? "reviews" : "pull";
    const count = (counts.get(kind) ?? 0) + 1;
    counts.set(kind, count);
    const selected = overrides?.(kind, count, url) ?? ({ pull, files, blob, reviews: [review] } as Record<string, unknown>)[kind];
    if (selected instanceof Response) return selected;
    return new Response(JSON.stringify(selected), { status: 200, headers: { "content-type": "application/json" } });
  };
  return { calls, input: { repository: "example/project", repositoryId: "100", pullNumber: 4, manifestPath: path, token: "fabricated-token", fetchImpl: fake } };
}

describe("read-only GitHub approval observations", () => {
  it("feeds an exact digest-bound GitHub approval into the comparator", async () => {
    const manifest: ReleaseApprovalManifest = {
      schema_version: 1, approval_id: "e665169c-1234-4a62-a1f1-67bd80af3617", expires_at: "2026-11-12T12:30:00.000Z", action: "publish_new_release",
      repository: { id: "100", full_name: "example/project" }, tag: "v1.2.3", version: "v1.2.3", channel: "stable",
      target: { commit: "c".repeat(40), tree: "d".repeat(40) },
      preflight: { workflow_path: ".github/workflows/preflight.yml", workflow_id: "122", workflow_commit: "e".repeat(40), run_id: "120", attempt: "1", artifact_id: "121", archive_sha256: "f".repeat(64), requester_id: "112", attempt_actor_id: "114" },
      assets: [{ name: "archive.tar.gz", size: 19, sha256: "1".repeat(64) }]
    };
    function sorted(value: unknown): unknown {
      if (Array.isArray(value)) return value.map(sorted);
      if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([key, item]) => [key, sorted(item)]));
      return value;
    }
    const bytes = Buffer.from(`${JSON.stringify(sorted(manifest))}\n`);
    const sha = createHash("sha1").update(`blob ${bytes.length}\0`).update(bytes).digest("hex");
    const body = `APPROVE-RELEASE-SHA256 ${createHash("sha256").update(bytes).digest("hex")}`;
    const h = harness((kind) => kind === "files" ? [{ ...files[0], sha }] : kind === "blob" ? { sha, encoding: "base64", content: bytes.toString("base64"), size: bytes.length } : kind === "reviews" ? [{ ...review, body }] : undefined);
    const observed = await readGitHubApproval(h.input);
    const { approval_id: _approval, expires_at: _expiry, ...actual } = manifest;
    expect(verifyReleaseApproval({ ...observed, actual, publisher_id: "113", publisher_attempt_actor_id: "115" }, { reviewer_id: "111", manifest_path: path, max_validity_seconds: 3600 }, new Date("2026-11-12T12:00:00.000Z")).review_id).toBe("200");
  });
  it("binds the blob and reads the same complete review history twice", async () => {
    const h = harness();
    const result = await readGitHubApproval(h.input);
    expect(result.pull).toEqual({ repository_id: "100", state: "open", head, author_id: "112", changed_paths: [path] });
    expect(Buffer.from(result.manifestBytes)).toEqual(content);
    expect(result.reviews).toEqual([{ id: "200", reviewer_id: "111", state: "APPROVED", commit: head, submitted_at: "2026-11-12T11:45:00.000Z", body: "fake approval" }]);
    expect(h.calls).toHaveLength(6);
    expect(h.calls.every((c) => c.url.startsWith("https://api.github.com/repos/example/project/") && c.method === "GET" && c.redirect === "manual" && c.authorization === "Bearer fabricated-token")).toBe(true);
  });
  it("paginates full review pages and checks the whole history twice", async () => {
    const first = Array.from({ length: 100 }, (_, index) => ({ ...review, id: 200 + index }));
    const h = harness((kind, _count, url) => kind === "reviews" ? (url.searchParams.get("page") === "1" ? first : []) : undefined);
    expect((await readGitHubApproval(h.input)).reviews).toHaveLength(100);
    expect(h.calls.filter((call) => call.url.includes("/reviews?")).length).toBe(4);
  });
  it("follows a declared next page even when the current page is short", async () => {
    const h = harness((kind, _count, url) => {
      if (kind !== "reviews") return undefined;
      if (url.searchParams.get("page") === "1") return new Response(JSON.stringify([review]), { headers: { link: '<https://api.github.com/repos/example/project/pulls/4/reviews?per_page=100&page=2>; rel="next"' } });
      return [{ ...review, id: 201 }];
    });
    expect((await readGitHubApproval(h.input)).reviews).toHaveLength(2);
  });
  it.each([
    ["repository identity changes", (kind: string) => kind === "pull" ? { ...pull, base: { ...pull.base, repo: { id: 999 } } } : undefined],
    ["foreign head repository", (kind: string) => kind === "pull" ? { ...pull, head: { ...pull.head, repo: { id: 999 } } } : undefined],
    ["extra changed files", (kind: string) => kind === "pull" ? { ...pull, changed_files: 2 } : undefined],
    ["wrong file", (kind: string) => kind === "files" ? [{ ...files[0], filename: "another.json" }] : undefined],
    ["renamed file", (kind: string) => kind === "files" ? [{ ...files[0], previous_filename: "old.json" }] : undefined],
    ["mismatched blob bytes", (kind: string) => kind === "blob" ? { ...blob, content: Buffer.alloc(content.length).toString("base64") } : undefined],
    ["unavailable response", (kind: string) => kind === "reviews" ? new Response("not authorized", { status: 403 }) : undefined],
    ["redirect", (kind: string) => kind === "files" ? new Response(null, { status: 302, headers: { location: "https://elsewhere.invalid" } }) : undefined],
    ["foreign pagination target", (kind: string) => kind === "reviews" ? new Response(JSON.stringify([review]), { headers: { link: '<https://elsewhere.invalid/x?per_page=100&page=2>; rel="next"' } }) : undefined],
    ["duplicate review IDs", (kind: string) => kind === "reviews" ? [review, review] : undefined],
    ["unknown review state", (kind: string) => kind === "reviews" ? [{ ...review, state: "PENDING" }] : undefined],
    ["invalid timestamp", (kind: string) => kind === "reviews" ? [{ ...review, submitted_at: "2026-02-30T11:45:00Z" }] : undefined],
    ["unsafe numeric IDs", (kind: string) => kind === "reviews" ? [{ ...review, id: Number.MAX_SAFE_INTEGER + 1 }] : undefined],
    ["oversize response", (kind: string) => kind === "files" ? new Response("x".repeat(1024 * 1024 + 1)) : undefined]
  ])("rejects %s without leaking the token", async (_name, override) => {
    const h = harness(override);
    await expect(readGitHubApproval(h.input)).rejects.toThrow("Release approval unavailable or invalid.");
  });
  it("rejects a moved head, changed base, or changing reviews", async () => {
    for (const kind of ["head", "base", "review"]) {
      const h = harness((which, count) => {
        if (which === "pull" && count === 2 && kind === "head") return { ...pull, head: { ...pull.head, sha: "c".repeat(40) } };
        if (which === "pull" && count === 2 && kind === "base") return { ...pull, base: { ...pull.base, sha: "c".repeat(40) } };
        if (which === "reviews" && count === 2 && kind === "review") return [{ ...review, state: "DISMISSED" }];
        return undefined;
      });
      await expect(readGitHubApproval(h.input)).rejects.toThrow();
    }
  });
  it("refuses a full tenth page because completeness is unproven", async () => {
    const h = harness((kind, _count, url) => kind === "reviews" ? Array.from({ length: 100 }, (_, index) => ({ ...review, id: Number(url.searchParams.get("page")) * 1000 + index })) : undefined);
    await expect(readGitHubApproval(h.input)).rejects.toThrow();
  });
  it("rejects unsafe input before making a request", async () => {
    for (const change of [{ repository: "../project" }, { manifestPath: "../secret" }, { token: "bad\ntoken" }, { pullNumber: 0 }]) {
      const h = harness();
      await expect(readGitHubApproval({ ...h.input, ...change })).rejects.toThrow();
      expect(h.calls).toHaveLength(0);
    }
  });
});
