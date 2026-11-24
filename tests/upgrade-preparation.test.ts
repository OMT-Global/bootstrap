import { execFileSync } from "node:child_process";
import { chmod, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

const operator = vi.hoisted(() => ({ home: "", fixture: "" }));
vi.mock("node:os", async (original) => {
  const actual = await original<typeof import("node:os")>();
  return { ...actual, default: { ...actual, userInfo: () => ({ ...actual.userInfo(), homedir: operator.home }) } };
});
// Simulate Linux eligibility/prlimit and trusted ancestry only for this test's
// disposable fixture under the system temporary directory. Git, captures, policy observations and
// current/target generation are real; all HTTP is fabricated.
vi.mock("../src/upgrade-host.js", async (original) => {
  const actual = await original<typeof import("../src/upgrade-host.js")>();
  return { ...actual, PRLIMIT_ARGS: [], requireLinuxHost: async () => ({ git: "/usr/bin/git", prlimit: "/usr/bin/env" }),
    readRegular: (file: string, limit: number, trusted = false, proc = false) => actual.readRegular(file, limit,
      trusted && !file.startsWith(operator.fixture + "/"), proc) };
});

import { normalizeManifest, stringifyManifest } from "../src/manifest.js";
import { flowPolicyDigest, resolveFlowPolicy } from "../src/policy.js";
import * as renderer from "../src/render.js";
import { createOwnershipSidecar } from "../src/state.js";
import { discoverPublicManifests } from "../src/upgrade-discovery.js";
import { capturePublicGenerator, generatorSnapshot } from "../src/upgrade-generator.js";
import * as gitData from "../src/upgrade-git.js";
import { neutralEnvironment } from "../src/upgrade-host.js";
import { observePublicPolicies, POLICY_PUBLISHER } from "../src/upgrade-policy.js";
import { copyPreparedUpgradeSource, describePreparedUpgrade, discardPreparedUpgrade, prepareObservedUpgrade } from "../src/upgrade-preparation.js";

const roots: string[] = [];
const repository = "OMT-Global/bootstrap-fixture";
const sourceRef = "refs/tags/v1.0.1";
const targetRef = "refs/tags/v1.2.3";
const workflow = ".github/workflows/extended-validation.yml";
const bundlePath = "policy/flow-public-standard.json";
function git(root: string, env: NodeJS.ProcessEnv, args: string[], input?: string | Uint8Array): Buffer {
  return execFileSync("/usr/bin/git", ["-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-c", "commit.gpgsign=false", ...args],
    { cwd: root, env, input, maxBuffer: 4 * 1024 ** 2 });
}
class Objects {
  constructor(readonly root: string, readonly env: NodeJS.ProcessEnv) {}
  async commit(files: Record<string, string | Buffer>, executable: string[] = [], parent?: string): Promise<string> {
    for (const [file, bytes] of Object.entries(files)) {
      await mkdir(path.dirname(path.join(this.root, file)), { recursive: true }); await writeFile(path.join(this.root, file), bytes);
      await chmod(path.join(this.root, file), executable.includes(file) ? 0o755 : 0o644);
    }
    git(this.root, this.env, ["add", "--all"]);
    const tree = git(this.root, this.env, ["write-tree"]).toString().trim();
    const head = git(this.root, this.env, ["commit-tree", tree, ...(parent ? ["-p", parent] : [])], "fabricated public source\n").toString().trim();
    git(this.root, this.env, ["update-ref", "refs/heads/main", head]); return head;
  }
  tree(sha: string): string { return git(this.root, this.env, ["rev-parse", `${sha}^{tree}`]).toString().trim(); }
  response(kind: string, sha: string): unknown {
    if (kind === "commits") return { sha, tree: { sha: this.tree(sha) } };
    if (kind === "trees") return { sha, truncated: false, tree: git(this.root, this.env, ["ls-tree", "-lz", sha]).toString().split("\0").filter(Boolean).map((row) => {
      const split = row.indexOf("\t"); const [mode, type, oid, size] = row.slice(0, split).trim().split(/\s+/);
      return { path: row.slice(split + 1), mode, type, sha: oid, ...(size !== "-" ? { size: Number(size) } : {}) };
    }) };
    const bytes = git(this.root, this.env, ["cat-file", "blob", sha]);
    return { sha, encoding: "base64", size: bytes.length, content: bytes.toString("base64") };
  }
}
class PublicFixture {
  calls: Array<{ url: URL; init: RequestInit }> = [];
  change?: (url: URL, value: unknown) => unknown | Promise<unknown>;
  constructor(readonly source: Objects, readonly publisher: Objects, readonly head: string, readonly oldPolicy: string, readonly newPolicy: string) {
    vi.stubGlobal("fetch", vi.fn(this.fetch.bind(this)));
  }
  metadata(publisher = false) {
    return { id: publisher ? POLICY_PUBLISHER.id : 42, name: publisher ? "flow" : "bootstrap-fixture", full_name: publisher ? POLICY_PUBLISHER.repository : repository,
      owner: { login: "OMT-Global", id: 7, type: "Organization" }, private: false, visibility: "public", default_branch: "main", fork: false, archived: false, disabled: false };
  }
  async fetch(input: string | URL | Request, init: RequestInit = {}): Promise<Response> {
    const url = new URL(String(input)); this.calls.push({ url, init });
    const parts = url.pathname.split("/"); const publisher = parts[3] === "flow"; let value: unknown;
    if (parts[1] === "orgs") value = [this.metadata(), this.metadata(true)];
    else if (parts.length === 4) value = this.metadata(publisher);
    else if (parts[4] === "git" && parts[5] === "ref") {
      const ref = `refs/${parts.slice(6).map(decodeURIComponent).join("/")}`;
      value = { ref, object: { type: "commit", sha: !publisher ? this.head : ref === sourceRef ? this.oldPolicy : this.newPolicy } };
    } else if (parts[4] === "git") value = (publisher ? this.publisher : this.source).response(parts[5]!, parts[6]!);
    else throw new Error("Unexpected fabricated public endpoint.");
    const response = new Response(JSON.stringify(await this.change?.(url, value) ?? value), { headers: { "Content-Type": "application/json" } });
    Object.defineProperty(response, "url", { value: url.href }); return response;
  }
}
async function fixture(options: { projectManifest?: boolean; drift?: boolean; modeDrift?: boolean; version?: string; canonicalization?: "sorted-utf16-v1"; state?: boolean } = {}) {
  const directory = await mkdtemp(path.join(await realpath(os.tmpdir()), "bootstrap-preparation-test-")); roots.push(directory); operator.fixture = directory;
  const [home, sourceRoot, publisherRoot, empty] = ["home", "source", "publisher", "empty"].map((name) => path.join(directory, name));
  await Promise.all([home, sourceRoot, publisherRoot, empty].map((root) => mkdir(root!))); operator.home = home!;
  for (const key of Object.keys(process.env)) if (key.startsWith("GIT_") || key === "EMAIL" || key === "XDG_CONFIG_HOME") vi.stubEnv(key, undefined);
  vi.stubEnv("HOME", home); vi.stubEnv("TMPDIR", directory); vi.stubEnv("SSH_AUTH_SOCK", undefined);
  const env = { ...neutralEnvironment(home!, directory), GIT_AUTHOR_NAME: "Fabricated Operator", GIT_AUTHOR_EMAIL: "fixture@example.invalid", GIT_AUTHOR_DATE: "@1767225600 +0000",
    GIT_COMMITTER_NAME: "Fabricated Operator", GIT_COMMITTER_EMAIL: "fixture@example.invalid", GIT_COMMITTER_DATE: "@1767225600 +0000" };
  for (const root of [sourceRoot, publisherRoot]) git(root!, env, ["init", "--quiet", "--initial-branch=main", `--template=${empty}`]);
  git(sourceRoot!, env, ["remote", "add", "origin", `https://github.com/${repository}.git`]);
  git(sourceRoot!, env, ["config", "core.hooksPath", ".githooks"]);
  const bundle = JSON.parse(await readFile(new URL("../policy/flow-public-standard.json", import.meta.url), "utf8"));
  if (options.canonicalization) bundle.sortProbe = { a: 1, Z: 2 };
  const targetBundle = { ...bundle, version: options.version ?? "1.1.0" };
  const raw = { version: 1 as const, project: { owner: "OMT-Global", name: "bootstrap-fixture", visibility: "public" as const, defaultBranch: "main" }, archetype: { kind: "generic-empty" as const },
    repo: { class: "cli" as const, managedPaths: [...(options.projectManifest ? [] : ["project.bootstrap.yaml"]), workflow, "README.md"] },
    ci: { codeqlLanguages: ["javascript-typescript" as const] },
    policy: { flow: { ref: sourceRef, sha256: flowPolicyDigest(bundle, options.canonicalization), bundlePath,
      ...(options.canonicalization ? { canonicalization: options.canonicalization } : {}) } } };
  const manifest = normalizeManifest(raw);
  const projection = await renderer.resolveRepositoryProjection(manifest, "/", resolveFlowPolicy(manifest, bundle, manifest.policy!.flow!));
  const sidecar = createOwnershipSidecar(manifest, projection.files);
  const projectText = `# Unmanaged comments stay: café\r\n${stringifyManifest(manifest).replaceAll("\n", "\r\n")}`;
  const files: Record<string, string | Buffer> = { ...Object.fromEntries([...projection.files, sidecar].map((file) => [file.path, file.contents])),
    ...(options.projectManifest ? { "project.bootstrap.yaml": projectText } : {}), [bundlePath]: JSON.stringify(bundle), "package-lock.json": '{"lockfileVersion":3}\n',
    ".gitignore": "node_modules/\ndist/\n", "opaque/é\nartifact.bin": Buffer.from([0, 255, 1, 13, 10]), "opaque/tool": "unrelated executable\r\n",
    ".githooks/pre-commit": "#!/bin/sh\nexit 91\n", LICENSE: "Project-owned terms\n" };
  if (options.drift) files["README.md"] = "committed unmanaged drift\n";
  if (options.state) files[".bootstrap/bootstrap-state.json"] = "{}\n";
  const source = new Objects(sourceRoot!, env); const publisher = new Objects(publisherRoot!, env);
  const oldPolicy = await publisher.commit({ [POLICY_PUBLISHER.bundlePath]: JSON.stringify(bundle, null, 2) + "\n" });
  const targetRaw = Buffer.from("  \n" + JSON.stringify(targetBundle) + "\n");
  const newPolicy = await publisher.commit({ [POLICY_PUBLISHER.bundlePath]: targetRaw }, [], oldPolicy);
  const executables = [...projection.files.filter((file) => file.executable).map((file) => file.path), "opaque/tool", ".githooks/pre-commit", ...(options.modeDrift ? ["README.md"] : [])];
  const head = await source.commit(files, executables);
  const network = new PublicFixture(source, publisher, head, oldPolicy, newPolicy);
  const discovery = await discoverPublicManifests("OMT-Global", {}); expect(discovery.status).toBe("complete");
  const found = discovery.repositories.find((repo) => repo.repository === repository)!;
  const generator = await capturePublicGenerator(sourceRoot!, head);
  const observation = await observePublicPolicies(discovery, found, generator, { ref: targetRef, sha256: flowPolicyDigest(targetBundle, options.canonicalization) });
  expect(observation.status).toBe("observed");
  const sourceSnapshot = generatorSnapshot(generator);
  return { directory, root: sourceRoot!, source, head, generator, observation, sourceSnapshot, network, targetRaw, projectText, env, files };
}
const prepare = (data: Awaited<ReturnType<typeof fixture>>, extra: Partial<Parameters<typeof prepareObservedUpgrade>[0]> = {}) =>
  prepareObservedUpgrade({ observation: data.observation, generator: data.generator, source: data.sourceSnapshot, originalRoot: data.root, ...extra });
afterEach(async () => {
  vi.unstubAllGlobals(); vi.unstubAllEnvs(); vi.restoreAllMocks();
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe("single-target source preparation with real temporary Git", () => {
  it.each([false, true])("preserves raw unrelated bytes/modes and both fixedpoints; project-owned manifest=%s", async (projectManifest) => {
    const data = await fixture({ projectManifest, canonicalization: "sorted-utf16-v1" });
    const before = git(data.root, data.env, ["status", "--porcelain=v1", "-z"]);
    const metadata = await Promise.all(["HEAD", "index", "config"].map((name) => readFile(path.join(data.root, ".git", name))));
    const candidate = await prepare(data); const facts = describePreparedUpgrade(candidate); const result = copyPreparedUpgradeSource(candidate);
    expect(facts).toMatchObject({ repository, repositoryId: 42, baseCommit: data.head, baseTree: data.sourceSnapshot.tree,
      sourceVersion: "1.0.0", targetVersion: "1.1.0", risk: "minor", authority: "none", pilot: "unverified", hook: "pending", signing: "pending", finalCheck: "pending", independentReview: "pending", publication: "pending" });
    expect(facts.tree).not.toBe(facts.baseTree); expect(Object.isFrozen(facts)).toBe(true);
    for (const name of ["opaque/é\nartifact.bin", "opaque/tool", ".githooks/pre-commit", "LICENSE", ".gitignore", "package-lock.json"])
      expect(facts.changedPaths).not.toContain(name);
    for (const original of gitData.copySnapshotFiles(data.sourceSnapshot)) {
      if (facts.changedPaths.includes(original.path)) continue;
      expect(result.files.find((file) => file.path === original.path)).toEqual(original);
    }
    expect(result.files.find((file) => file.path === bundlePath)?.bytes).toEqual(data.targetRaw);
    expect(facts.changedPaths).toContain("project.bootstrap.yaml"); expect(facts.changedPaths).toContain(bundlePath);
    expect(facts.changedPaths).not.toContain("LICENSE"); expect(result.base).toBe(data.sourceSnapshot);
    if (projectManifest) expect(Buffer.from(result.files.find((file) => file.path === "project.bootstrap.yaml")!.bytes).toString()).toBe(
      data.projectText.replace(sourceRef, targetRef).replace(data.observation.sourceDigest!, data.observation.targetDigest!));
    expect(git(data.root, data.env, ["status", "--porcelain=v1", "-z"])).toEqual(before);
    expect(await Promise.all(["HEAD", "index", "config"].map((name) => readFile(path.join(data.root, ".git", name))))).toEqual(metadata);
    expect(data.network.calls.every(({ init }) => init.method === "GET" && !new Headers(init.headers).has("authorization"))).toBe(true);
    // Independently reconstruct the candidate's raw Git tree without running a hook.
    const independent = path.join(data.directory, "independent"); await mkdir(independent);
    git(independent, data.env, ["init", "--quiet", "--initial-branch=main", `--template=${path.join(data.directory, "empty")}`]);
    const index: Buffer[] = [];
    for (const file of result.files) {
      const oid = git(independent, data.env, ["hash-object", "--no-filters", "-w", "--stdin"], file.bytes).toString().trim();
      index.push(Buffer.from(`${file.mode} ${oid}\t${file.path}\0`));
    }
    git(independent, data.env, ["update-index", "-z", "--index-info"], Buffer.concat(index));
    expect(git(independent, data.env, ["write-tree"]).toString().trim()).toBe(facts.tree);
    result.files[0]!.bytes.fill(1); expect(copyPreparedUpgradeSource(candidate).files[0]!.bytes).not.toEqual(result.files[0]!.bytes);
    expect(() => describePreparedUpgrade({ ...candidate })).toThrow("unavailable");
    discardPreparedUpgrade(candidate); expect(() => copyPreparedUpgradeSource(candidate)).toThrow("unavailable");
  });
  it.each([{ drift: true }, { modeDrift: true }, { state: true }, { version: "1.0.0" }])("rejects committed drift, inherited state or non-upgrade input %#", async (options) => {
    const data = await fixture(options); await expect(prepare(data)).rejects.toThrow("unavailable");
  });
  it.each(["bytes", "mode", "staged", "untracked", "origin"])("rejects original checkout %s drift without repair", async (kind) => {
    const data = await fixture(); const file = path.join(data.root, "opaque/tool");
    if (kind === "mode") await chmod(file, 0o644);
    else if (kind === "origin") git(data.root, data.env, ["remote", "set-url", "origin", "https://github.com/Other/repository.git"]);
    else if (kind === "untracked") await writeFile(path.join(data.root, "untracked-private.txt"), "fabricated private sentinel");
    else { await writeFile(file, "changed bytes"); if (kind === "staged") git(data.root, data.env, ["add", "opaque/tool"]); }
    const before = git(data.root, data.env, ["status", "--porcelain=v1", "-z"]);
    await expect(prepare(data)).rejects.toThrow("unavailable"); expect(git(data.root, data.env, ["status", "--porcelain=v1", "-z"])).toEqual(before);
  });
  it.each(["observation", "generator", "source"] as const)("rejects copied %s statements", async (field) => {
    const data = await fixture(); const value = field === "source" ? data.sourceSnapshot : data[field];
    await expect(prepare(data, { [field]: { ...value } })).rejects.toThrow("unavailable");
  });
  it.each(["head", "policy", "visibility"])("rejects changed public %s before staging", async (kind) => {
    const data = await fixture();
    data.network.change = (url, value) => {
      if (kind === "head" && url.pathname.endsWith("/ref/heads/main")) return { ...(value as object), object: { type: "commit", sha: "a".repeat(40) } };
      if (kind === "policy" && url.pathname.endsWith("/ref/tags/v1.2.3")) return { ...(value as object), object: { type: "commit", sha: data.network.oldPolicy } };
      if (kind === "visibility" && url.pathname.endsWith("/bootstrap-fixture")) return { ...(value as object), private: true, visibility: "private" };
      return value;
    };
    await expect(prepare(data)).rejects.toThrow("unavailable");
  });
  it("rejects a moved public target on final refresh", async () => {
    const data = await fixture(); let targetReads = 0;
    data.network.change = (url, value) => url.pathname.endsWith("/ref/tags/v1.2.3") && ++targetReads > 1
      ? { ...(value as object), object: { type: "commit", sha: data.network.oldPolicy } } : value;
    await expect(prepare(data)).rejects.toThrow("unavailable"); expect(targetReads).toBe(2);
  });
  it.each(["opaque/tool", "README.md", "project.bootstrap.yaml", bundlePath])("rejects target %s tampering after apply even when the reported plan is unchanged", async (file) => {
    const data = await fixture(); const realApply = renderer.applyRepo; let applications = 0;
    vi.spyOn(renderer, "applyRepo").mockImplementation(async (...args) => {
      const result = await realApply(...args);
      if (++applications === 2) await writeFile(path.join(args[1], file), "unexpected target output");
      return result;
    });
    await expect(prepare(data)).rejects.toThrow("unavailable"); expect(applications).toBe(2);
  });
  it("rejects original checkout changes during staging", async () => {
    const data = await fixture(); const realApply = renderer.applyRepo;
    vi.spyOn(renderer, "applyRepo").mockImplementation(async (...args) => {
      const result = await realApply(...args); await writeFile(path.join(data.root, "opaque/tool"), "concurrent original edit"); return result;
    });
    await expect(prepare(data)).rejects.toThrow("unavailable");
    expect(await readFile(path.join(data.root, "opaque/tool"), "utf8")).toBe("concurrent original edit");
  });
  it("rejects a genuine raw snapshot for a different commit even when its file tree matches", async () => {
    const data = await fixture();
    const different = git(data.root, data.env, ["commit-tree", data.sourceSnapshot.tree, "-p", data.head], "different authentic commit\n").toString().trim();
    const source = gitData.verifyGitSnapshot({ baseCommit: different, commitBytes: git(data.root, data.env, ["cat-file", "commit", different]), files: gitData.copySnapshotFiles(data.sourceSnapshot) });
    await expect(prepare(data, { source })).rejects.toThrow("unavailable");
  });
  it("rejects cleanup failure even when a cleanup retry succeeds", async () => {
    const data = await fixture(); const realOpen = gitData.openDataRepository; let opens = 0; let disposals = 0;
    vi.spyOn(gitData, "openDataRepository").mockImplementation(async (...args) => {
      const result = await realOpen(...args); if (++opens !== 2) return result;
      return { ...result, dispose: async () => { await result.dispose(); if (++disposals === 1) throw new Error("fabricated cleanup failure"); } };
    });
    await expect(prepare(data)).rejects.toThrow("unavailable"); expect(opens).toBe(3); expect(disposals).toBe(2);
  });
  it("honors cancellation before work and invalidates later source access", async () => {
    const data = await fixture(); const cancelled = new AbortController(); cancelled.abort();
    await expect(prepare(data, { signal: cancelled.signal })).rejects.toThrow("unavailable");
    const controller = new AbortController(); const candidate = await prepare(data, { signal: controller.signal }); controller.abort();
    expect(() => describePreparedUpgrade(candidate)).toThrow("unavailable"); expect(() => copyPreparedUpgradeSource(candidate)).toThrow("unavailable");
    expect(() => discardPreparedUpgrade(candidate)).not.toThrow(); expect(() => discardPreparedUpgrade(candidate)).toThrow("unavailable");
  });
});
