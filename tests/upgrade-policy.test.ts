import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { performance } from "node:perf_hooks";
import { mkdir, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

const operator = vi.hoisted(() => ({ home: "" }));
vi.mock("node:os", async (original) => {
  const actual = await original<typeof import("node:os")>();
  return { ...actual, default: { ...actual, userInfo: () => ({ ...actual.userInfo(), homedir: operator.home }) } };
});
// Only Linux eligibility and prlimit are simulated. Git/filesystem, generator
// capture, discovery registry, policy/rendering and CI verifier are real.
vi.mock("../src/upgrade-host.js", async (original) => {
  const actual = await original<typeof import("../src/upgrade-host.js")>();
  return { ...actual, PRLIMIT_ARGS: [], requireLinuxHost: async () => ({ git: "/usr/bin/git", prlimit: "/usr/bin/env" }) };
});


import { normalizeManifest, stringifyManifest } from "../src/manifest.js";
import { flowPolicyDigest, resolveFlowPolicy } from "../src/policy.js";
import { resolveRepositoryProjection } from "../src/render.js";
import { discoverPublicManifests } from "../src/upgrade-discovery.js";
import { capturePublicGenerator } from "../src/upgrade-generator.js";
import { neutralEnvironment } from "../src/upgrade-host.js";
import { PublicObservationRead } from "../src/upgrade-public-read.js";
import { observePublicPolicies, POLICY_PUBLISHER, readOwnedPolicyObservation, copyOwnedTargetPolicyBytes } from "../src/upgrade-policy.js";

type Json = Record<string, unknown>;
type Reply = { value: unknown; status?: number; headers?: Record<string, string>; url?: string };
const roots: string[] = [];
const repository = "OMT-Global/bootstrap-fixture";
const sourceRef = "refs/tags/v1.0.1";
const targetRef = "refs/tags/v1.2.3";
const workflowPath = ".github/workflows/extended-validation.yml";
const started = "2026-11-09T00:00:00Z";
const ended = "2026-11-09T00:01:00Z";
function git(root: string, env: NodeJS.ProcessEnv, args: string[], input?: string | Uint8Array): Buffer {
  return execFileSync("/usr/bin/git", ["-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-c", "commit.gpgsign=false", ...args],
    { cwd: root, env, input, maxBuffer: 4 * 1024 ** 2 });
}
class Objects {
  constructor(readonly root: string, readonly env: NodeJS.ProcessEnv) {}
  async commit(files: Record<string, string>, parent?: string): Promise<string> {
    for (const [file, text] of Object.entries(files)) { await mkdir(path.dirname(path.join(this.root, file)), { recursive: true }); await writeFile(path.join(this.root, file), text); }
    git(this.root, this.env, ["add", "--all"]);
    const tree = git(this.root, this.env, ["write-tree"]).toString().trim();
    const head = git(this.root, this.env, ["commit-tree", tree, ...(parent ? ["-p", parent] : [])], "fabricated public source\n").toString().trim();
    git(this.root, this.env, ["update-ref", "refs/heads/main", head]);
    return head;
  }
  tree(sha: string): string { return git(this.root, this.env, ["rev-parse", `${sha}^{tree}`]).toString().trim(); }
  response(kind: string, sha: string): unknown {
    if (kind === "commits") return { sha, tree: { sha: this.tree(sha) } };
    if (kind === "trees") {
      const entries = git(this.root, this.env, ["ls-tree", "-lz", sha]).toString().split("\0").filter(Boolean).map((row) => {
        const [header, file] = row.split("\t");
        const [mode, type, oid, size] = header!.trim().split(/\s+/);
        return { path: file, mode, type, sha: oid, ...(size !== "-" ? { size: Number(size) } : {}) };
      });
      return { sha, truncated: false, tree: entries };
    }
    const bytes = git(this.root, this.env, ["cat-file", "blob", sha]);
    return { sha, encoding: "base64", size: bytes.length, content: bytes.toString("base64").replace(/(.{60})/g, "$1\n") };
  }
}
class PublicFixture {
  calls: { url: string; init: RequestInit }[] = [];
  change?: (url: URL, reply: Reply, call: number) => Reply;
  constructor(readonly source: Objects, readonly publisher: Objects, readonly head: string, readonly oldPolicy: string, readonly newPolicy: string) {
    vi.stubGlobal("fetch", vi.fn(this.fetch.bind(this)));
  }
  metadata(publisher = false): Json {
    const name = publisher ? "flow" : "bootstrap-fixture";
    return { id: publisher ? POLICY_PUBLISHER.id : 42, name, full_name: publisher ? POLICY_PUBLISHER.repository : repository,
      owner: { login: "OMT-Global", id: 7, type: "Organization" }, private: false, visibility: "public", default_branch: "main", fork: false, archived: false, disabled: false };
  }
  run(): Json {
    return { id: 100, run_attempt: 1, check_suite_id: 200, workflow_id: 300, path: workflowPath, name: "Extended Validation",
      head_sha: this.head, head_branch: "main", event: "schedule", status: "completed", conclusion: "success", referenced_workflows: [],
      repository: this.metadata(), head_repository: this.metadata(), html_url: `https://github.com/${repository}/actions/runs/100`,
      created_at: started, run_started_at: started, updated_at: ended };
  }
  jobs(): Json[] {
    return [
      ["Detect Extended Validation Scope", "Run full suite for nightly or manual invocations"],
      ["Fast Checks", "Run fast checks"], ["Extended Checks", "Run extended validation"],
      ["Validate Secrets", "Scan repository for secret patterns"], ["Extended Validation Gate", "Check extended validation jobs"]
    ].map(([name, step], index) => ({ id: 400 + index, run_id: 100, run_attempt: 1, head_sha: this.head, head_branch: "main", workflow_name: "Extended Validation", name,
      html_url: `https://github.com/${repository}/actions/runs/100/job/${400 + index}`, check_run_url: `https://api.github.com/repos/${repository}/check-runs/${500 + index}`,
      status: "completed", conclusion: "success", started_at: started, completed_at: ended,
      steps: [
        ...(index > 0 && index < 4 ? [{ number: 1, name: "Run actions/checkout@11d5960a326750d5838078e36cf38b85af677262", status: "completed", conclusion: "success", started_at: started, completed_at: ended }] : []),
        { number: 2, name: step, status: "completed", conclusion: "success", started_at: started, completed_at: ended }
      ] }));
  }
  async fetch(input: string | URL | Request, init: RequestInit = {}): Promise<Response> {
    const url = new URL(String(input));
    this.calls.push({ url: url.href, init });
    const parts = url.pathname.split("/");
    const publisher = parts[3] === "flow";
    const objects = publisher ? this.publisher : this.source;
    let value: unknown;
    if (parts[1] === "orgs") value = [this.metadata(), this.metadata(true)];
    else if (parts.length === 4) value = this.metadata(publisher);
    else if (parts[4] === "git" && parts[5] === "ref") {
      const ref = `refs/${parts.slice(6).map(decodeURIComponent).join("/")}`;
      const sha = !publisher ? this.head : ref === sourceRef ? this.oldPolicy : this.newPolicy;
      value = { ref, object: { type: "commit", sha } };
    } else if (parts[4] === "git") value = objects.response(parts[5]!, parts[6]!);
    else if (parts[4] === "actions" && parts[5] === "workflows" && parts[7] === "runs") value = { total_count: 1, workflow_runs: [this.run()] };
    else if (parts[4] === "actions" && parts[5] === "workflows") value = { id: 300, path: workflowPath, name: "Extended Validation", state: "active" };
    else if (parts[4] === "actions" && parts[5] === "runs" && parts[9] === "jobs") value = { total_count: 5, jobs: this.jobs() };
    else if (parts[4] === "actions" && parts[5] === "runs") value = this.run();
    else if (parts[4] === "check-runs") {
      const index = Number(parts[5]) - 500;
      const job = this.jobs()[index]!;
      value = { id: 500 + index, head_sha: this.head, name: job.name, check_suite: { id: 200 }, app: { id: 15368 }, html_url: job.html_url,
        status: "completed", conclusion: "success", started_at: started, completed_at: ended };
    } else throw new Error("Unexpected fabricated public endpoint.");
    const reply = this.change?.(url, { value }, this.calls.length) ?? { value };
    const response = new Response(JSON.stringify(reply.value), { status: reply.status ?? 200, headers: { "Content-Type": "application/json", ...reply.headers } });
    Object.defineProperty(response, "url", { value: reply.url ?? url.href });
    return response;
  }
}
async function fixture(options: { policyVersion?: string; managed?: boolean; bundlePath?: string; explicitClass?: boolean; targetRawPrefix?: string; targetRawSuffix?: string; canonicalization?: "sorted-utf16-v1" } = {}) {
  const directory = await mkdtemp(path.join(await realpath(path.join(process.cwd(), "node_modules")), ".policy-observation-"));
  roots.push(directory);
  const home = path.join(directory, "home"); const sourceRoot = path.join(directory, "source"); const publisherRoot = path.join(directory, "publisher"); const empty = path.join(directory, "empty");
  await Promise.all([home, sourceRoot, publisherRoot, empty].map((root) => mkdir(root)));
  operator.home = home;
  for (const key of Object.keys(process.env)) if (key.startsWith("GIT_") || key === "EMAIL" || key === "XDG_CONFIG_HOME") vi.stubEnv(key, undefined);
  vi.stubEnv("HOME", home); vi.stubEnv("SSH_AUTH_SOCK", undefined);
  const env = { ...neutralEnvironment(home, directory), GIT_AUTHOR_NAME: "Fabricated Operator", GIT_AUTHOR_EMAIL: "fixture@example.invalid", GIT_AUTHOR_DATE: "@1767225600 +0000",
    GIT_COMMITTER_NAME: "Fabricated Operator", GIT_COMMITTER_EMAIL: "fixture@example.invalid", GIT_COMMITTER_DATE: "@1767225600 +0000" };
  for (const root of [sourceRoot, publisherRoot]) git(root, env, ["init", "--quiet", "--initial-branch=main", `--template=${empty}`]);
  const bundle = JSON.parse(await readFile(new URL("../policy/flow-public-standard.json", import.meta.url), "utf8")) as Json;
  if (options.canonicalization) bundle.sortProbe = { a: 1, Z: 2 };
  const targetBundle = { ...bundle, version: options.policyVersion ?? "1.1.0" };
  const bundlePath = options.bundlePath ?? "policy/flow-public-standard.json";
  const raw = { version: 1 as const, project: { owner: "OMT-Global", name: "bootstrap-fixture", visibility: "public" as const, defaultBranch: "main" }, archetype: { kind: "generic-empty" as const },
    repo: { ...(options.explicitClass === false ? {} : { class: "cli" as const }), ...(options.managed === false ? { managedPaths: ["LICENSE"] } : {}) },
    ci: { codeqlLanguages: ["javascript-typescript" as const] },
    policy: { flow: { ref: sourceRef, sha256: flowPolicyDigest(bundle, options.canonicalization), bundlePath,
      ...(options.canonicalization === undefined ? {} : { canonicalization: options.canonicalization }) } } };
  const manifest = normalizeManifest(raw);
  const resolved = resolveFlowPolicy(manifest, bundle, manifest.policy!.flow!);
  const projection = await resolveRepositoryProjection(manifest, "/", resolved);
  const source = new Objects(sourceRoot, env); const publisher = new Objects(publisherRoot, env);
  const oldPolicy = await publisher.commit({ [POLICY_PUBLISHER.bundlePath]: JSON.stringify(bundle, null, 2) + "\n" });
  const newPolicy = await publisher.commit({ [POLICY_PUBLISHER.bundlePath]: `${options.targetRawPrefix ?? ""}${JSON.stringify(targetBundle)}${options.targetRawSuffix ?? ""}` }, oldPolicy);
  const expected = projection.files.find((file) => file.path === workflowPath)?.contents ?? "name: excluded\n";
  const head = await source.commit({ "project.bootstrap.yaml": stringifyManifest(manifest), [bundlePath]: JSON.stringify(bundle), [workflowPath]: expected,
    "package-lock.json": '{"lockfileVersion":3}\n', ".gitignore": "node_modules/\ndist/\n" });
  const network = new PublicFixture(source, publisher, head, oldPolicy, newPolicy);
  const discovery = await discoverPublicManifests("OMT-Global", {});
  expect(discovery.status).toBe("complete");
  const found = discovery.repositories.find((repo) => repo.repository === repository)!;
  const generator = await capturePublicGenerator(sourceRoot, head);
  const target = { ref: targetRef, sha256: flowPolicyDigest(targetBundle, options.canonicalization) };
  return { directory, source, publisher, network, discovery, found, generator, target, bundle, targetBundle, head, expected };
}
afterEach(async () => {
  vi.unstubAllGlobals(); vi.unstubAllEnvs(); vi.restoreAllMocks();
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe("actual private public-policy observation producer", () => {
  it("rejects copied discovery and generator facts without making a request", async () => {
    const data = await fixture(); const before = data.network.calls.length;
    for (const kind of ["discovery", "record", "generator"]) {
      const result = await observePublicPolicies(kind === "discovery" ? { ...data.discovery } : data.discovery,
        kind === "record" ? { ...data.found } : data.found, kind === "generator" ? { ...data.generator } : data.generator, data.target);
      expect(result.status).not.toBe("observed");
      expect(() => readOwnedPolicyObservation(result)).toThrow();
    }
    expect(data.network.calls.length).toBe(before);
  });

  it("uses only the explicitly supplied read capability and does not expose it in results", async () => {
    const data = await fixture(); const before = data.network.calls.length;
    const options: { publicReadToken?: string } = { publicReadToken: "fixture-token-abcdefghijkl" };
    data.network.change = (_url, reply) => { options.publicReadToken = "other-token"; return reply; };
    const result = await observePublicPolicies(data.discovery, data.found, data.generator, data.target, options);
    expect(result.status).toBe("observed");
    const requests = data.network.calls.slice(before);
    expect(requests.length).toBeGreaterThan(0);
    expect(requests.every(({ url, init }) => {
      const parsed = new URL(url);
      const authorization = (init.headers as Record<string, string>).Authorization;
      return parsed.origin === "https://api.github.com" && (parsed.pathname.startsWith(`/repos/${repository}/`) || parsed.pathname === `/repos/${repository}`
        ? authorization === "Bearer fixture-token-abcdefghijkl" : authorization === undefined);
    })).toBe(true);
    expect(requests.some(({ url }) => new URL(url).pathname.startsWith(`/repos/${POLICY_PUBLISHER.repository}/`))).toBe(true);
    expect(JSON.stringify(result)).not.toContain("fixture-token-abcdefghijkl");
    expect(JSON.stringify(readOwnedPolicyObservation(result))).not.toContain("fixture-token-abcdefghijkl");
  });

  it("rejects malformed read capabilities before issuing a request", async () => {
    const data = await fixture(); const before = data.network.calls.length;
    for (const publicReadToken of ["", "short", "bad\nvalue", "x".repeat(4097)]) {
      const result = await observePublicPolicies(data.discovery, data.found, data.generator, data.target, { publicReadToken });
      expect(result).toMatchObject({ status: "incomplete", reason: "invalid-input" });
    }
    expect(data.network.calls.length).toBe(before);
  });

  it("rejects unexpected options and accessors without invoking them", async () => {
    const data = await fixture(); const before = data.network.calls.length;
    let invoked = false;
    const accessor = Object.defineProperty({}, "publicReadToken", { get() { invoked = true; return "fixture-token-abcdefghijkl"; } });
    for (const options of [accessor, { publicReadToken: "fixture-token-abcdefghijkl", extra: true }]) {
      const result = await observePublicPolicies(data.discovery, data.found, data.generator, data.target, options);
      expect(result).toMatchObject({ status: "incomplete", reason: "invalid-input" });
    }
    expect(invoked).toBe(false);
    expect(data.network.calls.length).toBe(before);
  });

  it("stops on a denied authenticated request without retrying anonymously", async () => {
    const data = await fixture(); const before = data.network.calls.length;
    data.network.change = (_url, reply) => ({ ...reply, status: 401 });
    const result = await observePublicPolicies(data.discovery, data.found, data.generator, data.target, { publicReadToken: "fixture-token-abcdefghijkl" });
    expect(result).toMatchObject({ status: "incomplete", reason: "http-error" });
    expect(data.network.calls.slice(before)).toHaveLength(1);
  });

  it("preserves and applies the source digest mode to both published policy pins", async () => {
    const data = await fixture({ canonicalization: "sorted-utf16-v1" });
    expect(flowPolicyDigest(data.targetBundle)).not.toBe(data.target.sha256);
    const result = await observePublicPolicies(data.discovery, data.found, data.generator, data.target);
    expect(result.status).toBe("observed");
    const owned = readOwnedPolicyObservation(result);
    expect(owned.sourceBinding.canonicalization).toBe("sorted-utf16-v1");
    expect(owned.targetBinding.canonicalization).toBe("sorted-utf16-v1");
    expect(owned.target.manifest.policy?.flow?.canonicalization).toBe("sorted-utf16-v1");
  });

  it("rejects a legacy target digest when the source pin selects UTF-16 mode", async () => {
    const data = await fixture({ canonicalization: "sorted-utf16-v1" });
    const result = await observePublicPolicies(data.discovery, data.found, data.generator,
      { ...data.target, sha256: flowPolicyDigest(data.targetBundle) });
    expect(result).toMatchObject({ status: "incomplete", reason: "policy-digest" });
    expect(() => readOwnedPolicyObservation(result)).toThrow();
  });

  it("derives versions from bundle content independently of immutable release tag numbers", async () => {
    const data = await fixture();
    const result = await observePublicPolicies(data.discovery, data.found, data.generator, data.target);
    expect(result).toMatchObject({ status: "observed", sourceVersion: "1.0.0", targetVersion: "1.1.0", transition: "minor" });
    const owned = readOwnedPolicyObservation(result);
    expect(owned.observationWindow.endedMonotonic).toBeGreaterThanOrEqual(owned.observationWindow.beganMonotonic);
    expect(owned.observationWindow.endedMonotonic - owned.observationWindow.beganMonotonic).toBeLessThanOrEqual(120000);
    expect(owned.sourceBinding).toMatchObject({ ref: "refs/tags/v1.0.1", commit: data.network.oldPolicy, canonicalSha256: flowPolicyDigest(data.bundle) });
    expect(owned.sourceBinding.oid).toBe(git(data.publisher.root, data.publisher.env, ["rev-parse", `${data.network.oldPolicy}:${POLICY_PUBLISHER.bundlePath}`]).toString().trim());
    expect(owned.targetBinding).toMatchObject({ ref: "refs/tags/v1.2.3", commit: data.network.newPolicy, canonicalSha256: flowPolicyDigest(data.targetBundle) });
    expect(owned.sourceBinding.rawSha256).not.toBe(owned.sourceBinding.canonicalSha256);
    expect(owned.localBinding).toMatchObject({ commit: data.head, canonicalSha256: owned.sourceBinding.canonicalSha256 });
    expect(owned.localBinding.oid).not.toBe(owned.sourceBinding.oid);
    expect(owned.workflow).toMatchObject({ text: data.expected });
    expect(Object.isFrozen(owned.manifest.policy!.flow)).toBe(true);
    expect(() => readOwnedPolicyObservation({ ...result })).toThrow("unowned-observation");
    expect(JSON.stringify(result)).not.toContain("policy:");
    expect(data.network.calls.every((call) => call.init.method === "GET" && call.init.credentials === "omit" && call.init.redirect === "error")).toBe(true);
  });

  it("retains exact target publisher bytes privately and returns fresh copies", async () => {
    const data = await fixture({ targetRawPrefix: "\ufeff", targetRawSuffix: "\r\n" });
    const result = await observePublicPolicies(data.discovery, data.found, data.generator, data.target);
    expect(result.status).toBe("observed");
    const expected = Buffer.from(`\ufeff${JSON.stringify(data.targetBundle)}\r\n`); const owned = readOwnedPolicyObservation(result);
    expect(owned.targetRawByteLength).toBe(expected.length); expect(owned.targetBinding.rawSha256).toBe(createHash("sha256").update(expected).digest("hex"));
    expect(copyOwnedTargetPolicyBytes(result)).toEqual(expected); const copy = copyOwnedTargetPolicyBytes(result); copy.fill(0);
    expect(copyOwnedTargetPolicyBytes(result)).toEqual(expected); expect(() => copyOwnedTargetPolicyBytes({ ...result })).toThrow();
    expect(owned).not.toHaveProperty("bytes"); expect(owned).not.toHaveProperty("targetBytes"); expect(JSON.stringify(result)).not.toContain(JSON.stringify(data.targetBundle));
  });

  it("can observe an unchanged target without claiming increasing-version or pilot permission", async () => {
    const data = await fixture({ policyVersion: "1.0.0" });
    const result = await observePublicPolicies(data.discovery, data.found, data.generator, data.target);
    expect(result).toMatchObject({ status: "observed", transition: "invalid", sourceVersion: "1.0.0", targetVersion: "1.0.0" });
    expect(Object.keys(result)).not.toEqual(expect.arrayContaining(["passed", "eligible", "approved"]));
  });

  it.each(["2.0.0", "not-a-version"])("reports unsupported actual target policy %s", async (version) => {
    const data = await fixture({ policyVersion: version });
    const result = await observePublicPolicies(data.discovery, data.found, data.generator, data.target);
    expect(result).toMatchObject({ status: "unsupported", reason: "invalid-source" });
    expect(() => readOwnedPolicyObservation(result)).toThrow();
  });

  it("does not turn a wrong target digest into an owned observation", async () => {
    const data = await fixture();
    const result = await observePublicPolicies(data.discovery, data.found, data.generator, { ...data.target, sha256: "0".repeat(64) });
    expect(result).toMatchObject({ status: "incomplete", reason: "policy-digest" });
    expect(() => readOwnedPolicyObservation(result)).toThrow();
  });

  it("reports unsupported project-owned/excluded CI instead of claiming the managed profile", async () => {
    const data = await fixture({ managed: false });
    const result = await observePublicPolicies(data.discovery, data.found, data.generator, data.target);
    expect(result).toMatchObject({ status: "unsupported", reason: "unsupported-ci-profile" });
  });

  it("does not infer a class absent from the actual public manifest", async () => {
    const data = await fixture({ explicitClass: false });
    const result = await observePublicPolicies(data.discovery, data.found, data.generator, data.target);
    expect(result.status).not.toBe("observed");
  });

  it.each(["private", "identity", "head", "truncated", "blob", "tree"])("stops on changed or malformed %s evidence", async (kind) => {
    const data = await fixture();
    data.network.change = (url, reply) => {
      const value = reply.value as Json;
      if (kind === "private" && url.pathname === `/repos/${repository}`) return { value: { ...value, private: true } };
      if (kind === "identity" && url.pathname === `/repos/${repository}`) return { value: { ...value, id: 99 } };
      if (kind === "head" && url.pathname.endsWith("/git/ref/heads/main")) return { value: { ...value, object: { type: "commit", sha: "a".repeat(40) } } };
      if (kind === "truncated" && url.pathname.includes("/git/trees/")) return { value: { ...value, truncated: true } };
      if (kind === "blob" && url.pathname.includes("/git/blobs/")) return { value: { ...value, content: Buffer.from("different").toString("base64") } };
      if (kind === "tree" && url.pathname.includes("/git/trees/")) return { value: { ...value, tree: [] } };
      return reply;
    };
    const result = await observePublicPolicies(data.discovery, data.found, data.generator, data.target);
    expect(result.status).toBe("incomplete");
    expect(() => readOwnedPolicyObservation(result)).toThrow();
  });

  it("rechecks the exact source and target tag resolutions before yielding ownership", async () => {
    const data = await fixture(); let calls = 0;
    data.network.change = (url, reply) => url.pathname.endsWith("/git/ref/tags/v1.2.3") && ++calls > 1
      ? { value: { ref: targetRef, object: { type: "commit", sha: data.network.oldPolicy } } } : reply;
    const result = await observePublicPolicies(data.discovery, data.found, data.generator, data.target);
    expect(result).toMatchObject({ status: "incomplete", reason: "changed-policy" });
  });

  it("freezes the selected target before asynchronous reads rather than following caller mutation", async () => {
    const data = await fixture(); const target = { ...data.target };
    data.network.change = (url, reply) => { if (url.pathname.endsWith("/git/ref/tags/v1.2.3")) target.ref = sourceRef; return reply; };
    const result = await observePublicPolicies(data.discovery, data.found, data.generator, target);
    expect(result.status).toBe("observed");
    expect(readOwnedPolicyObservation(result).targetBinding.ref).toBe(targetRef);
    expect(readOwnedPolicyObservation(result).target.source.ref).toBe(targetRef);
  });

  it("rejects unsupported floating policy locators without following a caller URL", async () => {
    const data = await fixture();
    const result = await observePublicPolicies(data.discovery, data.found, data.generator, { ...data.target, ref: "https://example.invalid/private" });
    expect(result.status).not.toBe("observed");
    expect(data.network.calls.every((call) => new URL(call.url).origin === "https://api.github.com")).toBe(true);
  });

  it("returns bounded public errors for rate limit, redirect and cancellation", async () => {
    const data = await fixture();
    data.network.change = (_url, reply) => ({ ...reply, status: 429 });
    expect(await observePublicPolicies(data.discovery, data.found, data.generator, data.target)).toMatchObject({ status: "incomplete", reason: "rate-limit" });
    data.network.change = (_url, reply) => ({ ...reply, url: "https://example.invalid/elsewhere" });
    expect(await observePublicPolicies(data.discovery, data.found, data.generator, data.target)).toMatchObject({ status: "incomplete", reason: "invalid-response" });
    const controller = new AbortController(); controller.abort();
    expect(await observePublicPolicies(data.discovery, data.found, data.generator, data.target, { signal: controller.signal })).toMatchObject({ status: "incomplete", reason: "aborted" });
  });
});

describe("cleanup liveness at actual private ownership registration", () => {
  function loseLivenessOnClose(controller: AbortController, mode: "abort" | "expiry"): () => void {
    const close = PublicObservationRead.prototype.close; let triggered = false; let restoreClock = () => {};
    vi.spyOn(PublicObservationRead.prototype, "close").mockImplementation(async function (this: PublicObservationRead) {
      await close.call(this);
      if (triggered) return; triggered = true;
      if (mode === "abort") controller.abort();
      else {
        const expired = performance.now() + 120001;
        const clock = vi.spyOn(performance, "now").mockReturnValue(expired); restoreClock = () => { clock.mockRestore(); };
      }
    });
    return () => restoreClock();
  }

  it.each(["abort", "expiry"] as const)("denies P ownership when %s arrives during awaited cleanup", async (mode) => {
    const data = await fixture(); const controller = new AbortController(); const restoreClock = loseLivenessOnClose(controller, mode);
    let result: Awaited<ReturnType<typeof observePublicPolicies>>;
    try { result = await observePublicPolicies(data.discovery, data.found, data.generator, data.target, { signal: controller.signal }); }
    finally { restoreClock(); }
    expect.soft(result!.status).toBe("incomplete");
    expect.soft(() => readOwnedPolicyObservation(result!)).toThrow();
    expect.soft(() => copyOwnedTargetPolicyBytes(result!)).toThrow();
  });

});
