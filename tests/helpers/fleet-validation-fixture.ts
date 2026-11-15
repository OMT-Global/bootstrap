import { execFileSync } from "node:child_process";
import { chmod, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { expect, vi } from "vitest";

import { normalizeManifest, stringifyManifest } from "../../src/manifest.js";
import { flowPolicyDigest, resolveFlowPolicy } from "../../src/policy.js";
import * as renderer from "../../src/render.js";
import { createOwnershipSidecar } from "../../src/state.js";
import { discoverPublicManifests } from "../../src/upgrade-discovery.js";
import { capturePublicGenerator, generatorSnapshot } from "../../src/upgrade-generator.js";
import { neutralEnvironment } from "../../src/upgrade-host.js";
import { observePublicPolicies, POLICY_PUBLISHER } from "../../src/upgrade-policy.js";

export const roots: string[] = [];
const repository = "OMT-Global/bootstrap-fixture";
const sourceRef = "refs/tags/v1.0.1";
const targetRef = "refs/tags/v1.2.3";
const workflow = ".github/workflows/extended-validation.yml";
const bundlePath = "policy/flow-public-standard.json";
export function git(root: string, env: NodeJS.ProcessEnv, args: string[], input?: string | Uint8Array): Buffer {
  return execFileSync("/usr/bin/git", ["-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-c", "commit.gpgsign=false", ...args],
    { cwd: root, env, input, maxBuffer: 4 * 1024 ** 2, stdio: ["pipe", "pipe", "pipe"] });
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
export async function fixture(operator: { home: string; fixture: string }, options: { projectManifest?: boolean; drift?: boolean; modeDrift?: boolean; version?: string; canonicalization?: "sorted-utf16-v1"; state?: boolean } = {}) {
  const directory = await mkdtemp(path.join(await realpath(process.cwd()), ".git/info/validation-test-")); roots.push(directory); operator.fixture = directory;
  const [home, sourceRoot, publisherRoot, empty] = ["home", "source", "publisher", "empty"].map((name) => path.join(directory, name));
  await Promise.all([home, sourceRoot, publisherRoot, empty].map((root) => mkdir(root!))); operator.home = home!;
  for (const key of Object.keys(process.env)) if (key.startsWith("GIT_") || key === "EMAIL" || key === "XDG_CONFIG_HOME") vi.stubEnv(key, undefined);
  vi.stubEnv("HOME", home); vi.stubEnv("TMPDIR", directory); vi.stubEnv("SSH_AUTH_SOCK", undefined);
  const env = { ...neutralEnvironment(home!, directory), GIT_AUTHOR_NAME: "Fabricated Operator", GIT_AUTHOR_EMAIL: "fixture@example.invalid", GIT_AUTHOR_DATE: "@1767225600 +0000",
    GIT_COMMITTER_NAME: "Fabricated Operator", GIT_COMMITTER_EMAIL: "fixture@example.invalid", GIT_COMMITTER_DATE: "@1767225600 +0000" };
  for (const root of [sourceRoot, publisherRoot]) git(root!, env, ["init", "--quiet", "--initial-branch=main", `--template=${empty}`]);
  git(sourceRoot!, env, ["remote", "add", "origin", `https://github.com/${repository}.git`]);
  git(sourceRoot!, env, ["config", "core.hooksPath", ".githooks"]);
  const bundle = JSON.parse(await readFile(new URL("../../policy/flow-public-standard.json", import.meta.url), "utf8"));
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
    ...(options.projectManifest ? { "project.bootstrap.yaml": projectText } : {}), [bundlePath]: JSON.stringify(bundle), "package-lock.json": '{"lockfileVersion":3,"packages":{"":{}}}\n', "package.json": '{"name":"fixture","version":"1.0.0"}\n', "scripts/ci/run-fast-checks.sh": "#!/bin/sh\nexit 0\n",
    ".gitignore": "node_modules/\ndist/\n", "opaque/é\nartifact.bin": Buffer.from([0, 255, 1, 13, 10]), "opaque/tool": "unrelated executable\r\n",
    ".githooks/pre-commit": "#!/bin/sh\nexit 0\n", LICENSE: "Project-owned terms\n" };
  if (options.drift) files["README.md"] = "committed unmanaged drift\n";
  if (options.state) files[".bootstrap/bootstrap-state.json"] = "{}\n";
  const source = new Objects(sourceRoot!, env); const publisher = new Objects(publisherRoot!, env);
  const oldPolicy = await publisher.commit({ [POLICY_PUBLISHER.bundlePath]: JSON.stringify(bundle, null, 2) + "\n" });
  const targetRaw = Buffer.from("  \n" + JSON.stringify(targetBundle) + "\n");
  const newPolicy = await publisher.commit({ [POLICY_PUBLISHER.bundlePath]: targetRaw }, [], oldPolicy);
  const executables = [...projection.files.filter((file) => file.executable).map((file) => file.path), "opaque/tool", ".githooks/pre-commit", ...(options.modeDrift ? ["README.md"] : [])];
  const rootCommit = await source.commit(files, executables); const tree = source.tree(rootCommit);
  const left = git(sourceRoot!, env, ["commit-tree", tree, "-p", rootCommit], "left public ancestor\n").toString().trim();
  const right = git(sourceRoot!, env, ["commit-tree", tree, "-p", rootCommit], "right public ancestor\n").toString().trim();
  const head = git(sourceRoot!, env, ["commit-tree", tree, "-p", left, "-p", right], "public merge base\n").toString().trim();
  git(sourceRoot!, env, ["update-ref", "refs/heads/main", head]);
  const network = new PublicFixture(source, publisher, head, oldPolicy, newPolicy);
  const discovery = await discoverPublicManifests("OMT-Global", {}); expect(discovery.status).toBe("complete");
  const found = discovery.repositories.find((repo) => repo.repository === repository)!;
  const generator = await capturePublicGenerator(sourceRoot!, head);
  const observation = await observePublicPolicies(discovery, found, generator, { ref: targetRef, sha256: flowPolicyDigest(targetBundle, options.canonicalization) });
  expect(observation.status).toBe("observed");
  const sourceSnapshot = generatorSnapshot(generator);
  return { directory, root: sourceRoot!, source, head, generator, observation, sourceSnapshot, network, targetRaw, projectText, env, files };
}
