import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { performance } from "node:perf_hooks";
import { chmod, mkdir, readFile, rm, symlink, unlink, writeFile } from "node:fs/promises";
import os from "node:os";
import { Readable } from "node:stream";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { trustedFixtureDirectory } from "./helpers/trusted-fixture-directory.js";

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
import { PublicObservationRead, readPublicDirectory, readPublicFile } from "../src/upgrade-public-read.js";
import { runPublicInventory, collectPublicFleetInventory } from "../src/upgrade-public-inventory.js";
import { createOwnershipSidecar } from "../src/state.js";
import { projectLicensePolicy } from "../src/licensing.js";
import { observePublicPolicies, POLICY_PUBLISHER, readOwnedPolicyObservation, copyOwnedTargetPolicyBytes } from "../src/upgrade-policy.js";
import { GOVERNANCE_MARKER } from "../src/upgrade-approval-read.js";
import { RUNTIME_CONTROLLER } from "../src/upgrade-runtime-policy.js";
import { runGovernedUpgradeCommand } from "../src/upgrade-runtime.js";

type Json = Record<string, unknown>;
type Reply = { value: unknown; status?: number; headers?: Record<string, string>; url?: string };
const roots: string[] = [];
const repository = "OMT-Global/bootstrap-fixture";
const sourceRef = "refs/tags/v1.0.1";
const targetRef = "refs/tags/v1.2.3";
const workflowPath = ".github/workflows/extended-validation.yml";
const started = "2026-11-09T00:00:00Z";
const ended = "2026-11-09T00:01:00Z";
const governanceActor = { id: 501, login: "fixture-operator", type: "User" };
const governanceIssue = 62;
const cohortComment = 601;
function git(root: string, env: NodeJS.ProcessEnv, args: string[], input?: string | Uint8Array): Buffer {
  return execFileSync("/usr/bin/git", ["-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-c", "commit.gpgsign=false", ...args],
    { cwd: root, env, input, maxBuffer: 4 * 1024 ** 2 });
}
class Objects {
  constructor(readonly root: string, readonly env: NodeJS.ProcessEnv, readonly executables = new Set<string>()) {}
  async commit(files: Record<string, string>, parent?: string): Promise<string> {
    for (const [file, text] of Object.entries(files)) { await mkdir(path.dirname(path.join(this.root, file)), { recursive: true }); await writeFile(path.join(this.root, file), text); await chmod(path.join(this.root, file), this.executables.has(file) ? 0o755 : 0o644); }
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
  cohort?: Json;
  constructor(readonly source: Objects, readonly publisher: Objects, readonly head: string, readonly oldPolicy: string,
    readonly newPolicy: string, readonly identity = { repository, id: 42 }) {
    vi.stubGlobal("fetch", vi.fn(this.fetch.bind(this)));
  }
  metadata(publisher = false): Json {
    const identity = publisher ? POLICY_PUBLISHER : this.identity;
    return { id: identity.id, name: identity.repository.split("/")[1], full_name: identity.repository,
      owner: { login: "OMT-Global", id: 7, type: "Organization" }, private: false, visibility: "public", default_branch: "main", fork: false, archived: false, disabled: false };
  }
  run(): Json {
    return { id: 100, run_attempt: 1, check_suite_id: 200, workflow_id: 300, path: workflowPath, name: "Extended Validation",
      head_sha: this.head, head_branch: "main", event: "schedule", status: "completed", conclusion: "success", referenced_workflows: [],
      repository: this.metadata(), head_repository: this.metadata(), html_url: `https://github.com/${this.identity.repository}/actions/runs/100`,
      created_at: started, run_started_at: started, updated_at: ended };
  }
  jobs(): Json[] {
    return [
      ["Detect Extended Validation Scope", "Run full suite for nightly or manual invocations"],
      ["Fast Checks", "Run fast checks"], ["Extended Checks", "Run extended validation"],
      ["Validate Secrets", "Scan repository for secret patterns"], ["Extended Validation Gate", "Check extended validation jobs"]
    ].map(([name, step], index) => ({ id: 400 + index, run_id: 100, run_attempt: 1, head_sha: this.head, head_branch: "main", workflow_name: "Extended Validation", name,
      html_url: `https://github.com/${this.identity.repository}/actions/runs/100/job/${400 + index}`, check_run_url: `https://api.github.com/repos/${this.identity.repository}/check-runs/${500 + index}`,
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
    else if (this.cohort && url.pathname === "/repos/OMT-Global/bootstrap/issues/62") {
      value = { id: 602, number: governanceIssue, html_url: "https://github.com/OMT-Global/bootstrap/issues/62", comments: 1 };
    } else if (this.cohort && url.pathname === "/repos/OMT-Global/bootstrap/issues/62/comments") {
      value = [this.cohort];
    } else if (parts[4] === "git" && parts[5] === "ref") {
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
async function fixture(options: { policyVersion?: string; managed?: boolean; bundlePath?: string; explicitClass?: boolean; targetRawPrefix?: string; targetRawSuffix?: string; canonicalization?: "sorted-utf16-v1"; legal?: boolean; altered?: string; missing?: string; extraClaim?: boolean; alternate?: boolean; exceptions?: number; projectLegal?: boolean; governed?: boolean; manifestTail?: string } = {}) {
  const directory = await trustedFixtureDirectory(".policy-observation-");
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
  const template = "SPDX-License-Identifier: {{spdx_identifier}}\nCopyright {{copyright_years}} {{copyright_holder}}\nFabricated MIT fixture terms.\n";
  const license = options.legal ? { mode: "spdx" as const, identifier: "MIT", holder: "Fabricated Holder", holderVerification: "fixture-entity", years: "2026", template: { path: "legal/MIT.txt", sha256: createHash("sha256").update(template).digest("hex"), approval: "fixture-approval", spdxIdentifier: "MIT" }, thirdPartyNotices: [] } : undefined;
  const identity = options.governed ? RUNTIME_CONTROLLER : { repository, id: 42 };
  const raw = { version: 1 as const, project: { owner: "OMT-Global", name: identity.repository.split("/")[1]!, visibility: "public" as const, defaultBranch: "main" }, archetype: { kind: "generic-empty" as const },
    ...(options.governed ? { fleetRuntime: {
      schemaVersion: 1 as const, organization: "OMT-Global", repositories: [identity],
      governance: { ...identity, issue: governanceIssue },
      actors: [{ id: governanceActor.id, login: governanceActor.login, roles: ["cohort" as const] }]
    } } : {}),
    repo: { ...(options.explicitClass === false ? {} : { class: "cli" as const }), managedPaths: options.managed === false ? ["LICENSE"] : ["project.bootstrap.yaml", workflowPath, "README.md"] },
    ci: { codeqlLanguages: ["javascript-typescript" as const] }, ...(license ? { license } : {}),
    exceptions: Array.from({ length: options.exceptions ?? 0 }, (_, index) => ({ id: `EX-${index + 1}`, policy: "PRS-CI-001", scope: "fixture", rationale: "Fabricated exception", approvedBy: "fixture-reviewer", issue: "https://github.com/OMT-Global/bootstrap/issues/62", permanent: false, expiresAt: "2099-01-01T00:00:00Z" })),
    policy: { flow: { ref: sourceRef, sha256: flowPolicyDigest(bundle, options.canonicalization), bundlePath,
      ...(options.canonicalization === undefined ? {} : { canonicalization: options.canonicalization }) } } };
  const manifest = normalizeManifest(raw);
  const resolved = resolveFlowPolicy(manifest, bundle, manifest.policy!.flow!);
  const projection = await resolveRepositoryProjection(manifest, "/", resolved);
  if (license) { await mkdir(path.join(sourceRoot, "legal")); await writeFile(path.join(sourceRoot, license.template.path), template); }
  const legal = await projectLicensePolicy(manifest, sourceRoot);
  const rendered = [...projection.files, ...(legal?.files ?? [])];
  if (options.manifestTail) {
    const manifestFile = rendered.find(({ path }) => path === "project.bootstrap.yaml")!;
    manifestFile.contents += options.manifestTail;
  }
  const sidecar = createOwnershipSidecar(manifest, rendered);
  if (options.extraClaim) { const value = JSON.parse(sidecar.contents); value.managedFiles["old-managed.txt"] = { sha256: "0".repeat(64), source: "bootstrap" }; sidecar.contents = JSON.stringify(value); }
  const source = new Objects(sourceRoot, env, new Set(rendered.filter((file) => file.executable).map((file) => file.path))); const publisher = new Objects(publisherRoot, env);
  const oldPolicy = await publisher.commit({ [POLICY_PUBLISHER.bundlePath]: JSON.stringify(bundle, null, 2) + "\n" });
  const newPolicy = await publisher.commit({ [POLICY_PUBLISHER.bundlePath]: `${options.targetRawPrefix ?? ""}${JSON.stringify(targetBundle)}${options.targetRawSuffix ?? ""}` }, oldPolicy);
  const expected = projection.files.find((file) => file.path === workflowPath)?.contents ?? "name: excluded\n";
  const files: Record<string, string> = { ...Object.fromEntries([...rendered, sidecar].map((file) => [file.path, file.contents])), [bundlePath]: JSON.stringify(bundle),
    "package-lock.json": '{"lockfileVersion":3}\n', ".gitignore": "node_modules/\ndist/\n", ...(options.alternate ? { "COPYING.txt": "alternate fixture" } : {}), ...(options.projectLegal ? { LICENSE: "Project-owned fixture terms", "THIRD_PARTY_NOTICES.md": "Project-owned fixture notices" } : {}) };
  if (options.altered) files[options.altered] = "unexpected fixture content\n";
  if (options.missing) delete files[options.missing];
  const head = await source.commit(files);
  const network = new PublicFixture(source, publisher, head, oldPolicy, newPolicy, identity);
  const discovery = await discoverPublicManifests("OMT-Global", {});
  expect(discovery.status).toBe("complete");
  const found = discovery.repositories.find((repo) => repo.repository === identity.repository)!;
  const generator = await capturePublicGenerator(sourceRoot, head);
  const target = { ref: targetRef, sha256: flowPolicyDigest(targetBundle, options.canonicalization) };
  return { oldPolicy, directory, sourceRoot, source, publisher, network, discovery, found, generator, target, bundle, targetBundle, head, expected };
}
afterEach(async () => {
  vi.unstubAllGlobals(); vi.unstubAllEnvs(); vi.restoreAllMocks();
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});


function options(data: Awaited<ReturnType<typeof fixture>>) {
  return { org: "OMT-Global", targetRef: data.target.ref, targetSha256: data.target.sha256, generatorRoot: data.sourceRoot, generatorCommit: data.head, json: true };
}
async function inventory(data: Awaited<ReturnType<typeof fixture>>) {
  const result = await runPublicInventory(options(data), Readable.from([]));
  return { ...result, report: JSON.parse(result.output), row: JSON.parse(result.output).repositories.find((row: { repository: string }) => row.repository === repository) };
}

async function governedRequest(manifestTail?: string) {
  const data = await fixture({ governed: true, policyVersion: "1.0.1", ...(manifestTail ? { manifestTail } : {}) });
  const { network, target, head } = data;
  const { id: repositoryId, repository } = RUNTIME_CONTROLLER;
  const cohort = {
    schemaVersion: 1, kind: "cohort", organization: "OMT-Global",
    inventory: [{ repositoryId, repository, managed: true },
      { repositoryId: POLICY_PUBLISHER.id, repository: POLICY_PUBLISHER.repository, managed: false }],
    members: [{ repositoryId, repository, repoClass: "cli", sourceVersion: data.bundle.version,
      sourceDigest: flowPolicyDigest(data.bundle), sourceHead: head }],
    target: { version: data.targetBundle.version, ref: target.ref, digest: target.sha256, commit: network.newPolicy }
  };
  network.cohort = {
    id: cohortComment, user: governanceActor, body: GOVERNANCE_MARKER + JSON.stringify(cohort),
    html_url: "https://github.com/OMT-Global/bootstrap/issues/62#issuecomment-601",
    url: "https://api.github.com/repos/OMT-Global/bootstrap/issues/comments/601",
    issue_url: "https://api.github.com/repos/OMT-Global/bootstrap/issues/62",
    created_at: started, updated_at: started
  };
  const requestFile = path.join(data.directory, "governed-request.json");
  await writeFile(requestFile, JSON.stringify({
    repositoryId, repository, originalRoot: data.sourceRoot, generatorRoot: data.sourceRoot,
    generatorCommit: head, cohortComment, target
  }));
  network.calls.length = 0;
  return { ...data, requestFile };
}

describe("governed dry run with real ownership and fabricated provider", () => {
  it("reports the selected representative in text and JSON without credentials or publication authority", async () => {
    const data = await governedRequest();
    const human = await runGovernedUpgradeCommand(data.requestFile, {});
    const json = await runGovernedUpgradeCommand(data.requestFile, { json: true });
    expect(human.exitCode, human.output).toBe(0);
    expect(human.output).toContain("Fleet upgrade dry run for OMT-Global/bootstrap");
    expect(human.output).toContain("Publication is unavailable.");
    expect(human.output).not.toContain(data.directory);
    expect(json.exitCode).toBe(0);
    expect(json.output).not.toContain(data.directory);
    expect(JSON.parse(json.output)).toMatchObject({
      schemaVersion: 1, status: "planned", authority: "none", publication: "unavailable",
      repositoryId: RUNTIME_CONTROLLER.id, baseCommit: data.head, cohortComment, targetDigest: data.target.sha256,
      plan: { repo: RUNTIME_CONTROLLER.repository, repoClass: "cli", role: "pilot", risk: "patch", pilotOutcome: "pending", status: "review-required" },
      independentReview: "pending",
      publicationBlockers: ["authorized-signer-unconfigured", "native-review-profile-unconfigured",
        "publication-app-unconfigured", "attempt-directory-unconfigured"]
    });
    expect(data.network.calls.some(({ url }) => new URL(url).pathname === "/repos/OMT-Global/bootstrap/issues/62/comments")).toBe(true);
    expect(data.network.calls.every(({ init }) => init.method === "GET" && !new Headers(init.headers).has("authorization"))).toBe(true);
  });

  it("rejects a moved controller before using cohort evidence or returning a plan", async () => {
    const data = await governedRequest();
    data.network.change = (url, reply) => url.pathname === "/repos/OMT-Global/bootstrap/git/ref/heads/main"
      ? { value: { ref: "refs/heads/main", object: { type: "commit", sha: "f".repeat(40) } } } : reply;
    const result = await runGovernedUpgradeCommand(data.requestFile, { json: true });
    expect(result.exitCode).toBe(1);
    expect(JSON.parse(result.output)).toEqual({
      schemaVersion: 1, status: "blocked", authority: "none", publication: "unavailable", reason: "controller-not-current"
    });
    expect(data.network.calls.some(({ url }) => new URL(url).pathname.includes("/issues/62"))).toBe(false);
  });

  it("still rejects unrecognized settings in the committed controller manifest", async () => {
    const data = await governedRequest("futureRuntimeSwitch: true\n");
    expect(data.found).toMatchObject({ outcome: "unsupported", reason: "invalid-manifest" });
    const result = await runGovernedUpgradeCommand(data.requestFile, { json: true });
    expect(result.exitCode).toBe(1);
    expect(JSON.parse(result.output)).toEqual({
      schemaVersion: 1, status: "blocked", authority: "none", publication: "unavailable", reason: "fleet-incomplete"
    });
  });
});

describe("public inventory command composition with fabricated provider and Linux eligibility", () => {
  it("collects actual discovered policies, complete rendered drift and pending planner gates without writes", async () => {
    const data = await fixture(); const result = await inventory(data);
    expect(result.exitCode).toBe(0);
    expect(result.report.status).toBe("complete");
    expect(result.row).toMatchObject({ status: "observed", class: "cli", versions: { current: "1.0.0", target: "1.1.0" }, drift: { status: "observed", unassessedPaths: [] }, plan: { pilotOutcome: "pending", status: "review-required" } });
    expect(result.row.drift.paths.every((file: { status: string }) => file.status === "unchanged")).toBe(true);
    expect(result.report.repositories.find((row: { repository: string }) => row.repository === POLICY_PUBLISHER.repository).status).toBe("unmanaged");
    expect(result.report.authority).toBe("none");
    expect(result.report.pilots).toBe("unverified");
    expect(data.network.calls.every((call) => call.init.method === "GET")).toBe(true);
    expect(data.network.calls.some((call) => new URL(call.url).pathname.includes("/actions/"))).toBe(false);
  });
  it.each(["altered", "missing"] as const)("reports %s managed files as drift using authenticated tree absence", async (kind) => {
    const data = await fixture({ [kind]: "README.md" }); const result = await inventory(data);
    expect(result.exitCode).toBe(0);
    expect(result.row.drift.paths).toContainEqual({ path: "README.md", status: kind === "altered" ? "changed" : "missing" });
    expect(result.row.plan.status).not.toBe("eligible");
  });
  it("includes every exception and retains a review gate", async () => {
    const data = await fixture({ exceptions: 2 }); const result = await inventory(data);
    expect(result.row.exceptions.map((item: { id: string }) => item.id)).toEqual(["EX-1", "EX-2"]);
    expect(result.row.plan).toMatchObject({ status: "review-required", exceptionId: "EX-1" });
    const human = await runPublicInventory({ ...options(data), json: false }, Readable.from([]));
    expect(human.output).toContain('declared-exceptions=["EX-1","EX-2"]');
    expect(human.output).toContain("policy=1.0.0 -> 1.1.0");
    expect(human.output).toContain("pin=refs/tags/v1.0.1@");
  });
  it("keeps unclaimed project-owned legal files outside managed drift", async () => {
    const data = await fixture({ projectLegal: true }); const result = await inventory(data);
    expect(result.exitCode).toBe(0);
    expect(result.row.drift.unassessedPaths).toEqual([]);
    expect(result.row.drift.paths.some((value: { path: string }) => ["LICENSE", "THIRD_PARTY_NOTICES.md"].includes(value.path))).toBe(false);
  });
  it("projects governed legal outputs and the exact ownership sidecar", async () => {
    const data = await fixture({ legal: true }); const result = await inventory(data);
    expect(result.exitCode).toBe(0);
    expect(result.row.drift).toMatchObject({ status: "observed", unassessedPaths: [] });
    for (const file of ["LICENSE", "THIRD_PARTY_NOTICES.md", ".bootstrap/managed-files.json"]) expect(result.row.drift.paths).toContainEqual({ path: file, status: "unchanged" });
  });
  it.each([{ legal: true, alternate: true }, { legal: true, altered: "LICENSE" }, { extraClaim: true }])("keeps unassessed legal/ownership requirements incomplete %#", async (change) => {
    const data = await fixture(change); const result = await inventory(data);
    expect(result.exitCode).toBe(1);
    expect(result.row.drift.status).not.toBe("observed");
    expect(result.row.drift.unassessedPaths.length).toBeGreaterThan(0);
    expect(result.row.plan?.status).not.toBe("eligible");
  });
  it("does not treat a legal symlink as an ordinary projected file", async () => {
    const data = await fixture({ legal: true });
    const generatorRoot = path.join(data.directory, "separate-generator");
    git(data.sourceRoot, data.source.env, ["clone", "--quiet", "--no-hardlinks", data.sourceRoot, generatorRoot]);
    await unlink(path.join(data.sourceRoot, "LICENSE"));
    await symlink("legal/MIT.txt", path.join(data.sourceRoot, "LICENSE"));
    const changed = await data.source.commit({}, data.head);
    (data.network as unknown as { head: string }).head = changed;
    const result = await runPublicInventory({ ...options(data), generatorRoot }, Readable.from([]));
    const row = JSON.parse(result.output).repositories.find((value: { repository: string }) => value.repository === repository);
    expect(result.exitCode).toBe(1);
    expect(row.drift).toMatchObject({ status: "unsupported", reason: "unsupported-root-entry" });
    expect(row.drift.unassessedPaths).toContain("LICENSE");
    expect(row.drift.paths.some((value: { path: string; status: string }) => value.path === "LICENSE" && value.status === "unchanged")).toBe(false);
  });
  it("does not confer patch eligibility without an independently recorded pilot", async () => {
    const data = await fixture({ policyVersion: "1.0.1" }); const result = await inventory(data);
    expect(result.row.plan).toMatchObject({ risk: "patch", role: "pilot", pilotOutcome: "pending", status: "review-required" });
  });
  it("retains unsupported policy rows instead of inventing versions", async () => {
    const data = await fixture({ explicitClass: false }); const result = await inventory(data);
    expect(result.exitCode).toBe(1);
    expect(result.row.status).toBe("unsupported");
    expect(result.row.versions).toBeUndefined();
    expect(result.row.plan).toBeUndefined();
  });
  it.each(["head", "visibility", "http"])("rejects %s changes during drift observation", async (change) => {
    const data = await fixture(); let drift = false;
    const readme = git(data.source.root, data.source.env, ["rev-parse", `${data.head}:README.md`]).toString().trim();
    data.network.change = (url, reply) => {
      if (url.pathname.endsWith(`/blobs/${readme}`)) drift = true;
      if (!drift || !url.pathname.startsWith(`/repos/${repository}`)) return reply;
      if (change === "head" && url.pathname.endsWith("/git/ref/heads/main")) return { value: { ref: "refs/heads/main", object: { type: "commit", sha: "0".repeat(40) } } };
      if (change === "visibility" && url.pathname === `/repos/${repository}`) return { value: { ...data.network.metadata(), private: true, visibility: "private" } };
      if (change === "http" && url.pathname.endsWith(`/blobs/${readme}`)) return { value: { secret: "must-not-print" }, status: 404 };
      return reply;
    };
    const result = await inventory(data);
    expect(result.exitCode).toBe(1);
    expect(result.row.status).toBe("incomplete");
    expect(result.row.plan?.status).not.toBe("eligible");
    expect(result.output).not.toContain("must-not-print");
  });
  it("returns incomplete when discovery changes and never runs policy reads on partial discovery", async () => {
    const data = await fixture(); data.network.change = (url, reply) => url.pathname.startsWith("/orgs/") ? { ...reply, status: 503 } : reply;
    const result = await inventory(data);
    expect(result.exitCode).toBe(1); expect(result.report.repositories).toEqual([]);
  });
  it.each([
    { kind: "visibility", source: {} }, { kind: "membership", source: {} }, { kind: "archive", source: {} },
    { kind: "visibility", source: { legal: true, alternate: true } }, { kind: "visibility", source: { extraClaim: true } }
  ])("clears early details after final $kind rejection %#", async ({ kind, source }) => {
    const data = await fixture({ ...source, exceptions: 1 }); let enumerations = 0;
    data.network.change = (url, reply) => {
      if (url.pathname.startsWith("/orgs/")) {
        enumerations++;
        if (enumerations >= 3 && kind === "membership") return { value: [data.network.metadata(true)] };
      }
      if (enumerations >= 3 && url.pathname === `/repos/${repository}`) {
        if (kind === "visibility") return { value: { ...data.network.metadata(), private: true, visibility: "private" } };
        if (kind === "archive") return { value: { ...data.network.metadata(), archived: true } };
      }
      return reply;
    };
    const result = await inventory(data);
    expect(result.exitCode).toBe(1);
    expect(result.row).toEqual({ repository, repositoryId: 42, status: "incomplete", reason: "changed-fleet" });
    expect(result.row.pins).toBeUndefined(); expect(result.row.exceptions).toBeUndefined(); expect(result.row.drift).toBeUndefined(); expect(result.row.plan).toBeUndefined();
  });
  it("rejects a policy tag that moves after the per-repository observation", async () => {
    const data = await fixture(); let enumerations = 0;
    data.network.change = (url, reply) => {
      if (url.pathname.startsWith("/orgs/")) enumerations++;
      if (enumerations >= 3 && url.pathname.endsWith(`/git/ref/tags/${targetRef.slice(10)}`)) return { value: { ref: targetRef, object: { type: "commit", sha: data.oldPolicy } } };
      return reply;
    };
    const result = await inventory(data);
    expect(result.exitCode).toBe(1); expect(result.report.failure).toBe("changed-policy");
    expect(result.row.plan).toBeUndefined(); expect(result.row.pins).toBeUndefined();
  });
  it("uses only an explicitly supplied capability and keeps organization enumeration anonymous", async () => {
    const data = await fixture(); const capability = "fabricated_public_read_capability";
    vi.stubEnv("GH_TOKEN", "ambient_token_must_not_be_used");
    const result = await runPublicInventory({ ...options(data), readTokenStdin: true }, Readable.from([capability + "\n"]));
    expect(result.exitCode).toBe(0); expect(result.output).not.toContain(capability);
    expect(data.network.calls.filter((call) => new URL(call.url).pathname.startsWith("/orgs/")).every((call) => !(call.init.headers as Record<string,string>).Authorization)).toBe(true);
    expect(data.network.calls.every((call) => !(call.init.headers as Record<string,string>).Authorization?.includes("ambient"))).toBe(true);
  });
  it("stops on aggregate observer accounting exhaustion without making a plan", async () => {
    const data = await fixture();
    const original = Object.getOwnPropertyDescriptor(PublicObservationRead.prototype, "stats")!.get!;
    // Model a completed bounded phase after earlier fleet budget consumption.
    vi.spyOn(PublicObservationRead.prototype, "stats", "get").mockImplementation(function(this: PublicObservationRead) {
      return { ...original.call(this), requests: 10000 };
    });
    const result = await inventory(data);
    expect(result.exitCode).toBe(1); expect(result.report.failure).toBe("inventory-budget");
    expect(result.row.plan).toBeUndefined(); expect(result.row.versions).toBeUndefined();
  });
  it("stops an aborted inventory without sending requests", async () => {
    const data = await fixture(); const before = data.network.calls.length;
    const signal = AbortSignal.abort(); const report = await collectPublicFleetInventory({ ...options(data), signal });
    expect(report.status).toBe("incomplete"); expect(data.network.calls.length).toBe(before);
  });
});

describe("verified public directory reads", () => {
  it("returns immutable complete root entries and treats missing files only from verified trees", async () => {
    const data = await fixture(); const read = new PublicObservationRead(undefined, repository);
    try {
      const root = await readPublicDirectory(read, repository, data.head, "", data.source.tree(data.head));
      expect(Object.isFrozen(root)).toBe(true); expect(Object.isFrozen(root.entries)).toBe(true); expect(Object.isFrozen(root.entries[0])).toBe(true);
      expect(root.entries.some((entry) => entry.path === "project.bootstrap.yaml")).toBe(true);
      await expect(readPublicFile(read, repository, data.head, "absent-file.txt")).rejects.toMatchObject({ code: "missing-source" });
    } finally { await read.close(); }
  });
  it.each(["truncated", "omitted-entry", "tree-mismatch", "http"])("rejects %s directory evidence", async (kind) => {
    const data = await fixture(); const tree = data.source.tree(data.head);
    data.network.change = (url, reply) => {
      if (!url.pathname.endsWith(`/git/trees/${tree}`)) return reply;
      const value = reply.value as Json;
      if (kind === "truncated") return { value: { ...value, truncated: true } };
      if (kind === "omitted-entry") return { value: { ...value, tree: (value.tree as unknown[]).slice(1) } };
      if (kind === "tree-mismatch") return { value: { ...value, sha: "0".repeat(40) } };
      return { value, status: 404 };
    };
    const read = new PublicObservationRead(undefined, repository);
    try { await expect(readPublicDirectory(read, repository, data.head, "", tree)).rejects.toThrow(); }
    finally { await read.close(); }
  });
});
