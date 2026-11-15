import { describe, expect, it } from "vitest";
import { readGitHubExactTag } from "../src/github-approval-reader.js";

const commit = "a".repeat(40);
const objectId = "b".repeat(40);
const ref = { ref: "refs/tags/v1.2.3", object: { type: "tag", sha: objectId } };
const tagObject = { sha: objectId, tag: "v1.2.3", object: { type: "commit", sha: commit },
  verification: { verified: true, reason: "valid", signature: "fabricated-signature", payload: "fabricated-payload" } };
function harness(edit?: (kind: string, count: number) => unknown) {
  const calls: string[] = [];
  const counts = new Map<string, number>();
  const fetchImpl: typeof fetch = async (request, init) => {
    const url = new URL(String(request));
    calls.push(url.pathname);
    expect(init?.method).toBe("GET");
    expect(init?.redirect).toBe("manual");
    const kind = url.pathname.includes("/git/ref/") ? "ref" : url.pathname.includes("/git/tags/") ? "tag" : "repo";
    const count = (counts.get(kind) ?? 0) + 1; counts.set(kind, count);
    const value = edit?.(kind, count) ?? ({ repo: { id: 100, full_name: "Example/repo", private: false }, ref, tag: tagObject } as Record<string, unknown>)[kind];
    if (value instanceof Response) return value;
    return new Response(JSON.stringify(value), { status: 200 });
  };
  return { calls, input: { repository: "Example/repo", repositoryId: "100", tag: "v1.2.3", expectedCommit: commit,
    requireSigned: true, token: "fabricated-token", fetchImpl } };
}

describe("exact GitHub tag observation", () => {
  it("checks a GitHub-verified annotated tag, ref and repository twice", async () => {
    const h = harness();
    const result = await readGitHubExactTag(h.input);
    expect(result).toEqual({ repositoryId: "100", tag: "v1.2.3", objectId, objectType: "tag", commit, githubSignature: "valid" });
    expect(Object.isFrozen(result)).toBe(true);
    expect(h.calls).toHaveLength(6);
    expect(JSON.stringify(result)).not.toContain("fabricated-signature");
  });
  it("supports a lightweight tag when signature verification is not required", async () => {
    const h = harness((kind) => kind === "ref" ? { ...ref, object: { type: "commit", sha: commit } } : undefined);
    expect(await readGitHubExactTag({ ...h.input, requireSigned: false })).toMatchObject({ objectType: "commit", githubSignature: "not-required" });
    expect(h.calls).toHaveLength(4);
    await expect(readGitHubExactTag(h.input)).rejects.toThrow();
  });
  it.each([
    ["private repository", (kind: string) => kind === "repo" ? { id: 100, full_name: "Example/repo", private: true } : undefined],
    ["repository ID", (kind: string) => kind === "repo" ? { id: 101, full_name: "Example/repo", private: false } : undefined],
    ["wrong ref", (kind: string) => kind === "ref" ? { ...ref, ref: "refs/tags/v1.2.4" } : undefined],
    ["wrong tag object", (kind: string) => kind === "tag" ? { ...tagObject, sha: "c".repeat(40) } : undefined],
    ["wrong tag name", (kind: string) => kind === "tag" ? { ...tagObject, tag: "v1.2.4" } : undefined],
    ["wrong commit", (kind: string) => kind === "tag" ? { ...tagObject, object: { type: "commit", sha: "c".repeat(40) } } : undefined],
    ["nested tag", (kind: string) => kind === "tag" ? { ...tagObject, object: { type: "tag", sha: commit } } : undefined],
    ["unsigned", (kind: string) => kind === "tag" ? { ...tagObject, verification: { verified: false, reason: "unsigned", signature: null, payload: null } } : undefined],
    ["unavailable signature service", (kind: string) => kind === "tag" ? { ...tagObject, verification: { verified: false, reason: "gpgverify_error" } } : undefined],
    ["unavailable tag", (kind: string) => kind === "tag" ? new Response("denied", { status: 403 }) : undefined]
  ])("rejects %s", async (_name, edit) => {
    const h = harness(edit);
    await expect(readGitHubExactTag(h.input)).rejects.toThrow("Exact GitHub tag unavailable.");
  });
  it("rejects a ref changed between observations", async () => {
    const h = harness((kind, count) => kind === "ref" && count === 2 ? { ...ref, object: { type: "tag", sha: "d".repeat(40) } } : undefined);
    await expect(readGitHubExactTag(h.input)).rejects.toThrow();
  });
  it("rejects invalid inputs before network access", async () => {
    const h = harness();
    await expect(readGitHubExactTag({ ...h.input, tag: "../malicious" })).rejects.toThrow();
    expect(h.calls).toEqual([]);
  });
});
