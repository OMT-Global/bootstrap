import { describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import { readGitHubPreflightMetadata } from "../src/github-approval-reader.js";
import { verifyReleaseApproval } from "../src/release-approval.js";

const workflowCommit = "a".repeat(40);
const targetCommit = "b".repeat(40);
const tree = "c".repeat(40);
const digest = "d".repeat(64);
const workflowPath = ".github/workflows/release-preflight.yml";
const run = { id: 120, run_attempt: 2, workflow_id: 122, path: workflowPath, event: "workflow_dispatch", status: "completed", conclusion: "success", head_sha: workflowCommit, repository: { id: 100 }, head_repository: { id: 100 }, actor: { id: 112, type: "User" }, triggering_actor: { id: 114, type: "User" } };
const workflow = { id: 122, path: workflowPath };
const artifact = { id: 121, name: "release-package", expired: false, digest: `sha256:${digest}`, workflow_run: { id: 120, repository_id: 100, head_repository_id: 100, head_sha: workflowCommit } };
const commit = { sha: targetCommit, tree: { sha: tree } };

function harness(override?: (kind: string, count: number) => unknown) {
  const calls: Array<{ url: string; method: string; redirect: string }> = [];
  const counts = new Map<string, number>();
  const fake: typeof fetch = async (input, init) => {
    const url = new URL(String(input));
    calls.push({ url: url.href, method: String(init?.method), redirect: String(init?.redirect) });
    const kind = url.pathname.includes("/attempts/") ? "run" : url.pathname.includes("/actions/workflows/") ? "workflow" : url.pathname.includes("/actions/artifacts/") ? "artifact" : "commit";
    const count = (counts.get(kind) ?? 0) + 1;
    counts.set(kind, count);
    const selected = override?.(kind, count) ?? ({ run, workflow, artifact, commit } as Record<string, unknown>)[kind];
    if (selected instanceof Response) return selected;
    return new Response(JSON.stringify(selected), { status: 200 });
  };
  return { calls, input: { repository: "example/project", repositoryId: "100", runId: "120", attempt: "2", artifactId: "121", expectedWorkflowPath: workflowPath, expectedWorkflowCommit: workflowCommit, targetCommit, token: "fabricated-token", fetchImpl: fake } };
}

describe("GitHub preflight metadata", () => {
  it("binds the observed run identities and target tree to a digest-approved manifest", async () => {
    const metadata = await readGitHubPreflightMetadata(harness().input);
    const actual = { schema_version: 1 as const, action: "publish_new_release" as const,
      repository: { id: metadata.repository_id, full_name: "example/project" }, tag: "v1.2.3", version: "v1.2.3", channel: "stable" as const,
      target: { commit: metadata.target_commit, tree: metadata.target_tree },
      preflight: { workflow_path: metadata.workflow_path, workflow_id: metadata.workflow_id, workflow_commit: metadata.workflow_commit, run_id: metadata.run_id, attempt: metadata.attempt,
        artifact_id: metadata.artifact_id, archive_sha256: metadata.archive_sha256, requester_id: metadata.requester_id, attempt_actor_id: metadata.attempt_actor_id },
      assets: [{ name: "source.tar.gz", size: 10, sha256: "e".repeat(64) }] };
    const manifest = { ...actual, approval_id: "e665169c-1234-4a62-a1f1-67bd80af3617", expires_at: "2026-11-12T12:30:00.000Z" };
    function sorted(value: unknown): unknown {
      if (Array.isArray(value)) return value.map(sorted);
      if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([key, item]) => [key, sorted(item)]));
      return value;
    }
    const bytes = Buffer.from(`${JSON.stringify(sorted(manifest))}\n`);
    const body = `APPROVE-RELEASE-SHA256 ${createHash("sha256").update(bytes).digest("hex")}`;
    const observation = { manifestBytes: bytes, actual, pull: { repository_id: "100", state: "open" as const, head: workflowCommit, author_id: "112", changed_paths: [".github/release-approvals/pilot.json"] },
      reviews: [{ id: "200", reviewer_id: "111", state: "APPROVED" as const, commit: workflowCommit, submitted_at: "2026-11-12T11:45:00.000Z", body }], publisher_id: "113", publisher_attempt_actor_id: "115" };
    const policy = { reviewer_id: "111", manifest_path: ".github/release-approvals/pilot.json", max_validity_seconds: 3600 };
    const now = new Date("2026-11-12T12:00:00.000Z");
    expect(verifyReleaseApproval(observation, policy, now).review_id).toBe("200");
    expect(() => verifyReleaseApproval({ ...observation, actual: { ...actual, preflight: { ...actual.preflight, attempt_actor_id: "115" } } }, policy, now)).toThrow();
  });
  it("binds exact historical run, separate actors, artifact and target tree twice", async () => {
    const h = harness();
    expect(await readGitHubPreflightMetadata(h.input)).toEqual({ repository_id: "100", workflow_path: workflowPath, workflow_id: "122", workflow_commit: workflowCommit, run_id: "120", attempt: "2", artifact_id: "121", archive_sha256: digest, requester_id: "112", attempt_actor_id: "114", target_commit: targetCommit, target_tree: tree, limitations: { reusable_workflow: "unverified", artifact_attempt_binding: "unverified", archive_bytes: "unverified", target_source_bytes: "unverified" } });
    expect(h.calls).toHaveLength(8);
    expect(h.calls.every((call) => call.url.startsWith("https://api.github.com/repos/example/project/") && call.method === "GET" && call.redirect === "manual")).toBe(true);
  });
  it.each([
    ["wrong attempt", (kind: string) => kind === "run" ? { ...run, run_attempt: 3 } : undefined],
    ["failed run", (kind: string) => kind === "run" ? { ...run, conclusion: "failure" } : undefined],
    ["non-dispatch event", (kind: string) => kind === "run" ? { ...run, event: "pull_request" } : undefined],
    ["wrong workflow commit", (kind: string) => kind === "run" ? { ...run, head_sha: targetCommit } : undefined],
    ["wrong workflow path", (kind: string) => kind === "run" ? { ...run, path: ".github/workflows/other.yml" } : undefined],
    ["workflow ID reused for another path", (kind: string) => kind === "workflow" ? { ...workflow, path: ".github/workflows/other.yml" } : undefined],
    ["foreign run repository", (kind: string) => kind === "run" ? { ...run, repository: { id: 999 } } : undefined],
    ["foreign run head", (kind: string) => kind === "run" ? { ...run, head_repository: { id: 999 } } : undefined],
    ["unknown actor type", (kind: string) => kind === "run" ? { ...run, triggering_actor: { id: 114, type: "Unknown" } } : undefined],
    ["missing actor", (kind: string) => kind === "run" ? { ...run, triggering_actor: null } : undefined],
    ["expired artifact", (kind: string) => kind === "artifact" ? { ...artifact, expired: true } : undefined],
    ["wrong artifact name", (kind: string) => kind === "artifact" ? { ...artifact, name: "other" } : undefined],
    ["missing artifact digest", (kind: string) => kind === "artifact" ? { ...artifact, digest: null } : undefined],
    ["wrong artifact run", (kind: string) => kind === "artifact" ? { ...artifact, workflow_run: { ...artifact.workflow_run, id: 123 } } : undefined],
    ["foreign artifact head", (kind: string) => kind === "artifact" ? { ...artifact, workflow_run: { ...artifact.workflow_run, head_repository_id: 999 } } : undefined],
    ["wrong target commit", (kind: string) => kind === "commit" ? { ...commit, sha: workflowCommit } : undefined],
    ["unavailable run", (kind: string) => kind === "run" ? new Response("denied", { status: 403 }) : undefined],
    ["redirected artifact", (kind: string) => kind === "artifact" ? new Response(null, { status: 302, headers: { location: "https://elsewhere.invalid" } }) : undefined]
  ])("rejects %s", async (_name, override) => {
    const h = harness(override);
    await expect(readGitHubPreflightMetadata(h.input)).rejects.toThrow("Release approval unavailable or invalid.");
  });
  it("fails closed if any observed metadata changes between reads", async () => {
    const h = harness((kind, count) => kind === "run" && count === 2 ? { ...run, triggering_actor: { id: 115, type: "User" } } : undefined);
    await expect(readGitHubPreflightMetadata(h.input)).rejects.toThrow();
  });
  it("validates identifiers and target before making requests", async () => {
    for (const change of [{ runId: "01" }, { attempt: "0" }, { artifactId: "1/../../secret" }, { repository: "../project" }, { token: "x\ny" }, { expectedWorkflowCommit: "invalid" }]) {
      const h = harness();
      await expect(readGitHubPreflightMetadata({ ...h.input, ...change })).rejects.toThrow();
      expect(h.calls).toHaveLength(0);
    }
  });
});
