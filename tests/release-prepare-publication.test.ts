import { describe, expect, it } from "vitest";
import { approvedReleasePackageMetadata } from "../src/release-approved-package.js";
import { readReviewedGitHubPreflight } from "../src/release-reviewed-github-preflight.js";
import { prepareReleaseForPublication } from "../src/release-prepare-publication.js";
import { packageFixture } from "./helpers/release-approved-package-fixture.js";

function setup() {
  const source = packageFixture();
  const events: string[] = [];
  return { source, events, input: {
    policy: source.policy,
    async readApproval() { events.push("review"); const { actual: _actual, ...review } = structuredClone(source.observation); return review; },
    async acquire(env: { GITHUB_REPOSITORY_ID: string; PREFLIGHT_RUN_ID: string; PREFLIGHT_APPROVED_ATTEMPT: string; PREFLIGHT_ARTIFACT_ID: string; PREFLIGHT_ARTIFACT_SHA256: string; PREFLIGHT_TARGET_SHA: string; GITHUB_REPOSITORY: string }) {
      events.push("acquire");
      expect(Object.isFrozen(env)).toBe(true);
      expect(env).toMatchObject({ GITHUB_REPOSITORY: "Example/repo", GITHUB_REPOSITORY_ID: "100", PREFLIGHT_RUN_ID: "120",
        PREFLIGHT_APPROVED_ATTEMPT: "1", PREFLIGHT_ARTIFACT_ID: "121", PREFLIGHT_ARTIFACT_SHA256: "d".repeat(64), PREFLIGHT_TARGET_SHA: "a".repeat(40) });
      return { actual: source.observation.actual, assets: source.assets };
    }
  } };
}

describe("source-only publication preparation", () => {
  it("reviews, acquires exact selectors, and rechecks review and package", async () => {
    const h = setup();
    const pkg = await prepareReleaseForPublication(h.input);
    expect(h.events).toEqual(["review", "acquire", "review"]);
    expect(approvedReleasePackageMetadata(pkg)).toMatchObject({ notes: "Release notes\n", notesAssetName: "RELEASE_NOTES.md", latest: true });
  });
  it("keeps the selected callbacks and policy when retained options change during the first read", async () => {
    const h = setup();
    const read = h.input.readApproval;
    h.input.readApproval = async () => {
      h.input.acquire = async () => { throw new Error("replacement acquisition callback ran"); };
      h.input.readApproval = async () => { throw new Error("replacement review callback ran"); };
      h.input.policy.reviewer_id = "999";
      return await read();
    };
    const pkg = await prepareReleaseForPublication(h.input);
    expect(approvedReleasePackageMetadata(pkg).tag).toBe("v1.2.3");
    expect(h.events).toEqual(["review", "acquire", "review"]);
  });
  it("composes reviewed provider metadata into package preparation", async () => {
    const source = packageFixture();
    const calls: string[] = [];
    const fake: typeof fetch = async (request) => {
      const path = new URL(String(request)).pathname;
      calls.push(path);
      const run = { id: 120, run_attempt: 1, workflow_id: 122, path: ".github/workflows/preflight.yml", event: "workflow_dispatch",
        status: "completed", conclusion: "success", head_sha: "c".repeat(40), repository: { id: 100 }, head_repository: { id: 100 },
        actor: { id: 112, type: "User" }, triggering_actor: { id: 114, type: "User" } };
      const workflow = { id: 122, path: ".github/workflows/preflight.yml" };
      const artifact = { id: 121, name: "release-package", expired: false, digest: `sha256:${"d".repeat(64)}`,
        workflow_run: { id: 120, repository_id: 100, head_repository_id: 100, head_sha: "c".repeat(40) } };
      const commit = { sha: "a".repeat(40), tree: { sha: "b".repeat(40) } };
      const data = path.includes("/attempts/") ? run : path.includes("/actions/workflows/") ? workflow : path.includes("/actions/artifacts/") ? artifact : commit;
      return new Response(JSON.stringify(data), { status: 200 });
    };
    const pkg = await prepareReleaseForPublication({ policy: source.policy,
      async readApproval() { const { actual: _actual, ...review } = structuredClone(source.observation); return review; },
      async acquire(_env, reviewed) {
        const metadata = await readReviewedGitHubPreflight({ reviewed, repository: "Example/repo", repositoryId: "100",
          expectedWorkflowPath: ".github/workflows/preflight.yml", expectedWorkflowCommit: "c".repeat(40), token: "fabricated-token", fetchImpl: fake });
        const actual = structuredClone(source.observation.actual);
        actual.target = { commit: metadata.target_commit, tree: metadata.target_tree };
        actual.preflight = { workflow_path: metadata.workflow_path, workflow_id: metadata.workflow_id, workflow_commit: metadata.workflow_commit,
          run_id: metadata.run_id, attempt: metadata.attempt, artifact_id: metadata.artifact_id, archive_sha256: metadata.archive_sha256,
          requester_id: metadata.requester_id, attempt_actor_id: metadata.attempt_actor_id };
        return { actual, assets: source.assets };
      }
    });
    expect(approvedReleasePackageMetadata(pkg).tag).toBe("v1.2.3");
    expect(calls).toHaveLength(8);
  });
  it("does not acquire when the first approval is invalid", async () => {
    const h = setup();
    h.source.observation.reviews[0]!.state = "DISMISSED";
    await expect(prepareReleaseForPublication(h.input)).rejects.toThrow("Release preparation unavailable.");
    expect(h.events).toEqual(["review"]);
  });
  it("rejects a review dismissed while acquiring", async () => {
    const h = setup();
    const acquire = h.input.acquire;
    h.input.acquire = async (env) => { const data = await acquire(env); h.source.observation.reviews[0]!.state = "DISMISSED"; return data; };
    await expect(prepareReleaseForPublication(h.input)).rejects.toThrow();
    expect(h.events).toEqual(["review", "acquire", "review"]);
  });
  it("rejects altered extracted bytes and a different actual artifact", async () => {
    for (const kind of ["asset", "artifact"] as const) {
      const h = setup();
      const acquire = h.input.acquire;
      h.input.acquire = async (env) => {
        const data = structuredClone(await acquire(env));
        if (kind === "asset") data.assets[0]!.bytes[0] ^= 1;
        else data.actual.preflight.artifact_id = "999";
        return data;
      };
      await expect(prepareReleaseForPublication(h.input)).rejects.toThrow();
    }
  });
  it("does not expose an adapter exception", async () => {
    const h = setup();
    h.input.acquire = async () => { throw new Error("private fake provider detail"); };
    await expect(prepareReleaseForPublication(h.input)).rejects.toThrow("Release preparation unavailable.");
  });
});
