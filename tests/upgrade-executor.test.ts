import { chmod, link, mkdir, mkdtemp, readFile, realpath, rm, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import YAML from "yaml";

import { execRunner, type CommandRunner } from "../src/lib/process.js";
import { loadManifest, normalizeManifest, stringifyManifest } from "../src/manifest.js";
import { applyRepo } from "../src/render.js";
import { flowPolicyDigest } from "../src/policy.js";
import { executeFleetPolicyUpgrades } from "../src/upgrade-executor.js";

const temporary: string[] = [];
const generatorCommit = "a".repeat(40);
const policy = (version: string) => ({ standard: "public-repository-standard", version });
const ok = (value = "") => ({ stdout: value, stderr: "", exitCode: 0 });
const fail = () => ({ stdout: "", stderr: "injected fault", exitCode: 1 });
const evidence = (repo: string) => Object.fromEntries(["repo", "issue", "policyDiff", "tests", "exceptions", "provenance", "autoreview"].map((key) => [key, key === "repo" ? repo : `https://github.com/${repo}/${key === "issue" ? "issues/62" : "actions/runs/123"}`])) as { repo: string; issue: string; policyDiff: string; tests: string; exceptions: string; provenance: string; autoreview: string };

async function git(cwd: string, args: string[]) {
  const result = await execRunner("git", args, { cwd });
  if (result.exitCode) throw new Error(result.stderr);
  return result.stdout.trim();
}

async function fixture(targetVersion = "1.0.1") {
  const workspaceRoot = await realpath(await mkdtemp(path.join(os.tmpdir(), "bootstrap-upgrade-test-")));
  temporary.push(workspaceRoot);
  const target = policy(targetVersion);
  const bundlePath = path.join(workspaceRoot, "approved-target.yaml");
  await writeFile(bundlePath, YAML.stringify(target));
  const input = {
    generatorCommit,
    target: { ref: `refs/tags/v${targetVersion}`, sha256: flowPolicyDigest(target), bundlePath },
    evidence: [] as ReturnType<typeof evidence>[],
    pilots: [] as { repo: string; repoClass: string; currentPolicy: string; targetPolicy: string; commit: string; sourceCommit: string; outcome: "passed" | "failed"; validationWorkflow: string; evidence: string }[]
  };
  const repos = new Map<string, { cwd: string; head: string; sourceHead: string; sourceVersion: string; visibility: string; repoClass: "cli" | "service" }>();
  const calls: { command: string; args: string[]; cwd?: string }[] = [];
  const bodies: string[] = [];
  const faults = { commit: false, push: false, restore: false, review: false, checks: false, status: false, validation: false, missingUrl: false, untrustedRun: false };
  let githubUnavailable = false;
  let validationMutation: ((cwd: string) => Promise<void>) | undefined;
  async function add(repo: string, options: { version?: string; sourceVersion?: string; managedPaths?: string[]; repoClass?: "cli" | "service"; visibility?: "public" | "private" } = {}) {
    const cwd = path.join(workspaceRoot, repo.split("/")[1]!);
    const currentVersion = options.version ?? "1.0.0";
    const repoClass = options.repoClass ?? "cli";
    const seedVersion = options.sourceVersion ?? (currentVersion === targetVersion ? "1.0.0" : currentVersion);
    await mkdir(path.join(cwd, "scripts/ci"), { recursive: true });
    const manifest = normalizeManifest({ version: 2, project: { name: repo.split("/")[1]!, owner: repo.split("/")[0]!, visibility: options.visibility ?? "public", defaultBranch: "main" }, repo: { class: repoClass, managedPaths: options.managedPaths ?? ["project.bootstrap.yaml"] }, archetype: { kind: "generic-empty" }, ci: { codeqlLanguages: ["javascript-typescript"] }, policy: { flow: { ref: `refs/tags/v${seedVersion}`, sha256: flowPolicyDigest(policy(seedVersion)), bundlePath: "flow-policy.yaml" } } });
    await git(cwd, ["init", "-b", "main"]);
    await git(cwd, ["config", "user.name", "Synthetic Test"]);
    await git(cwd, ["config", "user.email", "synthetic@example.invalid"]);
    await git(cwd, ["config", "commit.gpgsign", "false"]);
    await git(cwd, ["remote", "add", "origin", `https://github.com/${repo}.git`]);
    await writeFile(path.join(cwd, "flow-policy.yaml"), YAML.stringify(policy(seedVersion)));
    await writeFile(path.join(cwd, "scripts/ci/run-fast-checks.sh"), "#!/usr/bin/env bash\nset -euo pipefail\ntest -f flow-policy.yaml\n");
    await writeFile(path.join(cwd, "project.bootstrap.yaml"), stringifyManifest(manifest));
    await applyRepo(manifest, cwd);
    await git(cwd, ["add", "--all"]);
    await git(cwd, ["commit", "-m", "test fixture"]);
    const sourceHead = await git(cwd, ["rev-parse", "HEAD"]);
    if (currentVersion !== seedVersion) {
      const upgraded = { ...manifest, policy: { flow: { ...manifest.policy!.flow, ref: `refs/tags/v${currentVersion}`, sha256: flowPolicyDigest(policy(currentVersion)) } } };
      await writeFile(path.join(cwd, "flow-policy.yaml"), YAML.stringify(policy(currentVersion)));
      await writeFile(path.join(cwd, "project.bootstrap.yaml"), stringifyManifest(upgraded));
      await applyRepo(upgraded, cwd);
      await git(cwd, ["add", "--all"]);
      await git(cwd, ["commit", "-m", "fixture governed policy upgrade"]);
    }
    repos.set(repo, { cwd, head: await git(cwd, ["rev-parse", "HEAD"]), sourceHead, sourceVersion: seedVersion, visibility: options.visibility ?? "public", repoClass });
    input.evidence.push(evidence(repo));
    return cwd;
  }
  const runner: CommandRunner = async (command, args = [], options = {}) => {
    calls.push({ command, args, ...(options.cwd ? { cwd: options.cwd } : {}) });
    if (command === "git" && ![...repos.values()].some((repo) => repo.cwd === options.cwd)) {
      if (args.join(" ") === "rev-parse HEAD") return ok(generatorCommit);
      if (args.join(" ") === "status --porcelain") return ok();
      throw new Error(`Unexpected generator command: ${args.join(" ")}`);
    }
    if (command === "git" && args[0] === "push") return faults.push ? fail() : ok();
    if (command === "git" && args[0] === "ls-remote") return ok();
    if (command === "git" && args[0] === "commit" && faults.commit) return fail();
    if (command === "git" && args.join(" ") === "checkout main" && faults.restore) return fail();
    if (command === "autoreview") return faults.review ? fail() : ok("No actionable findings.");
    if (command === "bash" && faults.validation) return fail();
    if (command === "bash" && validationMutation) {
      const result = await execRunner(command, args, options);
      if (result.exitCode === 0) await validationMutation(options.cwd!);
      return result;
    }
    if (command === "gh") {
      if (githubUnavailable) return fail();
      if (args[0] === "api") {
        const endpoint = args[1]!;
        const name = endpoint.split("/").slice(1, 3).join("/");
        const repo = repos.get(name)!;
        if (endpoint === `repos/${name}`) return ok(JSON.stringify({ full_name: name, visibility: repo.visibility, private: repo.visibility === "private", archived: false, default_branch: "main" }));
        if (endpoint.includes("/compare/")) {
          const [source, targetCommit] = endpoint.split("/compare/")[1]!.split("...");
          const ancestor = await execRunner("git", ["merge-base", "--is-ancestor", source!, targetCommit!], { cwd: repo.cwd });
          const valid = ancestor.exitCode === 0 && source !== targetCommit;
          return ok(JSON.stringify({ status: valid ? "ahead" : "diverged", base_commit: { sha: source }, merge_base_commit: { sha: valid ? source : "0".repeat(40) } }));
        }
        if (endpoint.endsWith("/commits/main")) return ok(JSON.stringify({ sha: repo.head }));
        if (endpoint.includes("/actions/runs/")) return ok(JSON.stringify({ repository: { full_name: name }, head_sha: repo.head, status: "completed", conclusion: "success", event: faults.untrustedRun ? "pull_request" : "workflow_dispatch", path: ".github/workflows/extended-validation.yml" }));
        if (endpoint.includes("/contents/")) {
          if (endpoint.includes(".github/workflows/extended-validation.yml")) return ok(JSON.stringify({ type: "file", path: ".github/workflows/extended-validation.yml" }));
          const file = endpoint.split("/contents/")[1]!.split("?")[0]!;
          const ref = endpoint.split("?ref=")[1] ?? repo.head;
          return ok(JSON.stringify({ content: Buffer.from(await git(repo.cwd, ["show", `${ref}:${file}`])).toString("base64") }));
        }
        if (endpoint.endsWith("/status")) return ok(JSON.stringify({ total_count: 1, state: faults.status ? "failure" : "success" }));
        if (endpoint.includes("/check-runs?")) return ok(JSON.stringify({ total_count: 1, check_runs: [{ name: "Validation", status: faults.checks ? "in_progress" : "completed", conclusion: faults.checks ? null : "success" }] }));
        throw new Error(`Unexpected API endpoint: ${endpoint}`);
      }
      if (args.slice(0, 2).join(" ") === "pr create") {
        bodies.push(await readFile(args[args.indexOf("--body-file") + 1]!, "utf8"));
        return ok(faults.missingUrl ? "" : `https://github.com/${args[args.indexOf("--repo") + 1]}/pull/99\n`);
      }
      throw new Error(`Unexpected GitHub command: ${args.join(" ")}`);
    }
    return execRunner(command, args, options);
  };
  function pilot(repo: string) {
    const candidate = repos.get(repo)!;
    input.pilots.push({ repo, repoClass: candidate.repoClass, currentPolicy: candidate.sourceVersion, targetPolicy: targetVersion, commit: candidate.head, sourceCommit: candidate.sourceHead, outcome: "passed", validationWorkflow: ".github/workflows/extended-validation.yml", evidence: `https://github.com/${repo}/actions/runs/123` });
  }
  return { workspaceRoot, input, repos, add, runner, calls, faults, bodies, pilot, afterValidation: (mutation: (cwd: string) => Promise<void>) => { validationMutation = mutation; }, unavailable: () => { githubUnavailable = true; }, run: (apply = false, maxBatchSize = 1) => executeFleetPolicyUpgrades({ workspaceRoot, repos: [...repos.keys()], input, runner, apply, maxBatchSize }) };
}

afterEach(async () => { await Promise.all(temporary.splice(0).map((dir) => rm(dir, { recursive: true, force: true }))); });

describe("guarded Flow policy upgrade execution", () => {
  it("defaults to a non-mutating inventory and blocks later class entries without a verified pilot", async () => {
    const f = await fixture();
    const a = await f.add("acme/a");
    await f.add("acme/b");
    const before = await readFile(path.join(a, "project.bootstrap.yaml"), "utf8");
    const report = await f.run();
    expect(report.mode).toBe("plan");
    expect(report.results[0]).toMatchObject({ repo: "acme/a", status: "planned", role: "pilot", currentPolicy: "1.0.0", targetPolicy: "1.0.1", risk: "patch", autoMergeEligible: false });
    expect(report.results[1]).toMatchObject({ repo: "acme/b", status: "blocked", role: "batch" });
    expect(report.results[1]!.reason).toContain("has not passed");
    expect(await readFile(path.join(a, "project.bootstrap.yaml"), "utf8")).toBe(before);
    expect(f.calls.some(({ command, args }) => command === "autoreview" || ["push", "checkout", "commit"].includes(args[0] ?? ""))).toBe(false);
  });

  it("redacts private and unverified checkouts from reports", async () => {
    const f = await fixture();
    await f.add("secret/local-private", { visibility: "private" });
    await f.add("secret/remote-private");
    f.repos.get("secret/remote-private")!.visibility = "private";
    expect(JSON.stringify(await f.run())).not.toContain("secret/");
    const g = await fixture();
    await g.add("secret/unverified");
    g.unavailable();
    expect(JSON.stringify(await g.run())).not.toContain("secret/");
  });

  it("rejects stale generator, invalid target digest, mutable target refs, and duplicate allowlists", async () => {
    const f = await fixture();
    await f.add("acme/a");
    const run = (input: unknown = f.input, repos = ["acme/a"]) => executeFleetPolicyUpgrades({ workspaceRoot: f.workspaceRoot, repos, input, runner: f.runner });
    await expect(run({ ...f.input, generatorCommit: "b".repeat(40) })).rejects.toThrow("Generator commit");
    await expect(run({ ...f.input, target: { ...f.input.target, sha256: "b".repeat(64) } })).rejects.toThrow("digest");
    expect((await run({ ...f.input, target: { ...f.input.target, ref: "refs/heads/main" } })).results[0]!.status).toBe("blocked");
    await expect(run(f.input, ["acme/a", "other/a"])).rejects.toThrow("ambiguous");
    await expect(run({ ...f.input, pilotOutcome: "passed" })).rejects.toThrow("Invalid upgrade input");
  });

  it("does not replace a dirty representative with a later clean repository", async () => {
    const f = await fixture();
    const a = await f.add("acme/a");
    await f.add("acme/b");
    await writeFile(path.join(a, "operator-work"), "preserve");
    const report = await f.run(true);
    expect(report.results.map(({ status }) => status)).toEqual(["blocked", "blocked"]);
    expect(report.results[0]!.reason).toContain("Dirty");
    expect(report.results[1]!.reason).toContain("has not passed");
    expect(await readFile(path.join(a, "operator-work"), "utf8")).toBe("preserve");
  });

  it("fails closed for origin mismatch and stale default-branch checkouts", async () => {
    const f = await fixture();
    const a = await f.add("acme/a");
    await git(a, ["remote", "set-url", "origin", "https://github.com/other/repo.git"]);
    expect((await f.run(true)).results[0]!.reason).toContain("Origin differs");
    await git(a, ["remote", "set-url", "origin", "https://github.com/acme/a.git"]);
    await git(a, ["remote", "set-url", "--push", "origin", "https://github.com/other/repo.git"]);
    expect((await f.run(true)).results[0]!.reason).toContain("Origin differs");
    await git(a, ["config", "--unset", "remote.origin.pushurl"]);
    f.repos.get("acme/a")!.head = "f".repeat(40);
    expect((await f.run(true)).results[0]!.reason).toContain("live default branch");
  });

  it("verifies the passed pilot commit, policy bundle, and exact-head checks before patch eligibility", async () => {
    const f = await fixture();
    await f.add("acme/a", { version: "1.0.1" });
    await f.add("acme/b");
    f.pilot("acme/a");
    expect((await f.run()).results[1]).toMatchObject({ status: "planned", role: "batch", autoMergeEligible: true });
    f.faults.untrustedRun = true;
    expect((await f.run()).results[1]!.reason).toContain("exact trusted commit and workflow");
    f.faults.untrustedRun = false;
    f.faults.checks = true;
    expect((await f.run()).results[1]!.reason).toContain("incomplete or failing");
    f.faults.checks = false;
    f.faults.status = true;
    expect((await f.run()).results[1]!.reason).toContain("statuses");
    f.faults.status = false;
    f.input.pilots[0]!.commit = "b".repeat(40);
    expect((await f.run()).results[1]!.reason).toContain("Pilot commit differs");
  });

  it("requires matching source/target/class evidence and stops failed pilots", async () => {
    const f = await fixture();
    await f.add("acme/a", { version: "1.0.1" });
    await f.add("acme/b");
    f.pilot("acme/a");
    f.input.pilots[0]!.currentPolicy = "0.9.0";
    expect((await f.run()).results[1]!.reason).toContain("Declared pilot source version differs");
    f.input.pilots[0]!.currentPolicy = "1.0.0";
    f.input.pilots[0]!.outcome = "failed";
    expect((await f.run()).results[1]!.reason).toContain("pilot failed");
  });

  it.each([
    ["owner", "other-owner"], ["name", "other-name"], ["visibility", "private"], ["defaultBranch", "trunk"]
  ])("rejects a pilot target manifest with mismatched %s", async (field, value) => {
    const f = await fixture();
    const a = await f.add("acme/a", { version: "1.0.1" });
    await f.add("acme/b");
    const manifestPath = path.join(a, "project.bootstrap.yaml");
    const document = YAML.parseDocument(await readFile(manifestPath, "utf8"));
    document.setIn(["project", field], value);
    await writeFile(manifestPath, document.toString());
    await git(a, ["add", "project.bootstrap.yaml"]);
    await git(a, ["commit", "-m", "fixture mismatched pilot target identity"]);
    const representative = f.repos.get("acme/a")!;
    representative.head = await git(a, ["rev-parse", "HEAD"]);
    await git(a, ["reset", "--hard", representative.sourceHead]);
    f.pilot("acme/a");
    const report = await f.run();
    expect(report.results[0]!.reason).toContain("live default branch");
    expect(report.results[1]!.status).toBe("blocked");
    expect(report.results[1]!.reason).toContain("Pilot target manifest does not match the verified public repository");
  });

  it("rejects heterogeneous batch source paths", async () => {
    const f = await fixture("1.0.2");
    await f.add("acme/a", { version: "1.0.2", sourceVersion: "1.0.0" });
    await f.add("acme/b", { version: "1.0.1" });
    f.pilot("acme/a");
    expect((await f.run()).results[1]!.reason).toContain("Batch source policy does not match");
  });

  it("rejects forged pilot source versions and non-ancestor source commits", async () => {
    const f = await fixture("1.0.2");
    await f.add("acme/a", { version: "1.0.2", sourceVersion: "1.0.0" });
    await f.add("acme/b", { version: "1.0.1" });
    f.pilot("acme/a");
    f.input.pilots[0]!.currentPolicy = "1.0.1";
    expect((await f.run()).results[1]!.reason).toContain("Declared pilot source version differs");
    f.input.pilots[0]!.currentPolicy = "1.0.0";
    f.input.pilots[0]!.sourceCommit = f.repos.get("acme/b")!.head;
    expect((await f.run()).results[1]!.reason).toContain("not a verified ancestor");
  });

  it("creates a validated, reviewed draft on a new branch and restores main without enabling merge", async () => {
    const f = await fixture();
    const a = await f.add("acme/a");
    const result = (await f.run(true)).results[0]!;
    expect(result).toMatchObject({ status: "pr-opened", pullRequestUrl: "https://github.com/acme/a/pull/99" });
    expect(await git(a, ["branch", "--show-current"])).toBe("main");
    expect(await git(a, ["status", "--porcelain"])).toBe("");
    expect(await git(a, ["show", `${result.branch}:flow-policy.yaml`])).toContain("1.0.1");
    const committed = YAML.parse(await git(a, ["show", `${result.branch}:project.bootstrap.yaml`]));
    expect(committed.policy.flow).toMatchObject({ ref: f.input.target.ref, sha256: f.input.target.sha256 });
    expect(await git(a, ["show", "-s", "--format=%B", result.branch!])).toContain("Signed-off-by: Synthetic Test");
    expect(f.bodies[0]).toContain("Refs https://github.com/acme/a/issues/62");
    expect(f.bodies[0]).toContain("Provenance: https://github.com/acme/a/actions/runs/123");
    expect(f.calls.findIndex(({ command }) => command === "bash")).toBeLessThan(f.calls.findIndex(({ command }) => command === "autoreview"));
    expect(f.calls.findIndex(({ command }) => command === "autoreview")).toBeLessThan(f.calls.findIndex(({ args }) => args[0] === "push"));
    expect(f.calls.some(({ command, args }) => command === "gh" && (args.includes("merge") || args.includes("--auto")))).toBe(false);
  });

  it("preserves dirty generated output after commit failure and blocks retries", async () => {
    const f = await fixture();
    const a = await f.add("acme/a");
    f.faults.commit = true;
    const first = (await f.run(true)).results[0]!;
    expect(first.status).toBe("failed");
    expect(first.reason).toContain("commit failed");
    expect(await git(a, ["branch", "--show-current"])).toBe(first.branch);
    expect(await git(a, ["status", "--porcelain"])).not.toBe("");
    const before = await git(a, ["rev-parse", first.branch!]);
    f.faults.commit = false;
    expect((await f.run(true)).results[0]!.status).toBe("blocked");
    expect(await git(a, ["rev-parse", first.branch!])).toBe(before);
  });

  it("preserves pushed-recovery commits after push failure and refuses an existing branch on retry", async () => {
    const f = await fixture();
    const a = await f.add("acme/a");
    f.faults.push = true;
    const first = (await f.run(true)).results[0]!;
    expect(first.status).toBe("failed");
    expect(await git(a, ["branch", "--show-current"])).toBe("main");
    const recovery = await git(a, ["rev-parse", first.branch!]);
    f.faults.push = false;
    expect((await f.run(true)).results[0]!.reason).toContain("Recovery branch exists");
    expect(await git(a, ["rev-parse", first.branch!])).toBe(recovery);
  });

  it("retains a known PR URL and reports restoration failure", async () => {
    const f = await fixture();
    await f.add("acme/a");
    f.faults.restore = true;
    const result = (await f.run(true)).results[0]!;
    expect(result).toMatchObject({ status: "failed", pullRequestUrl: "https://github.com/acme/a/pull/99" });
    expect(result.reason).toContain("Could not restore");
  });

  it("bounds attempted mutations across independent classes even when the first attempt fails", async () => {
    const f = await fixture();
    await f.add("acme/a");
    await f.add("acme/b", { repoClass: "service" });
    f.faults.push = true;
    const report = await f.run(true);
    expect(report.results[0]!.status).toBe("failed");
    expect(report.results[1]!.reason).toContain("Batch limit reached");
    expect(f.calls.filter(({ args }) => args[0] === "push")).toHaveLength(1);
  });

  it("runs local validation and refuses to push when validation or autoreview fails", async () => {
    for (const fault of ["validation", "review"] as const) {
      const f = await fixture();
      await f.add("acme/a");
      f.faults[fault] = true;
      expect((await f.run(true)).results[0]!.status).toBe("failed");
      expect(f.calls.some(({ args }) => args[0] === "push")).toBe(false);
    }
  });

  it.each(["manifest", "bundle", "generated", "executable"])("rejects validation mutations within the allowed %s output before commit", async (kind) => {
    const f = await fixture();
    const a = await f.add("acme/a", kind === "manifest" ? { managedPaths: ["README.md"] } : {});
    f.afterValidation(async (cwd) => {
      if (kind === "manifest") {
        const file = path.join(cwd, "project.bootstrap.yaml");
        const document = YAML.parseDocument(await readFile(file, "utf8"));
        document.setIn(["github", "deleteBranchOnMerge"], false);
        await writeFile(file, document.toString());
      } else if (kind === "bundle") {
        const file = path.join(cwd, "flow-policy.yaml");
        await writeFile(file, Buffer.concat([await readFile(file), Buffer.from([0x23, 0xff, 0x0a])]));
      } else if (kind === "generated") {
        const file = path.join(cwd, ".bootstrap/managed-files.json");
        await writeFile(file, `${await readFile(file, "utf8")}\n`);
      } else await chmod(path.join(cwd, "flow-policy.yaml"), 0o755);
    });
    const result = (await f.run(true)).results[0]!;
    expect(result.status).toBe("failed");
    expect(result.reason).toContain("changed prepared output");
    expect(await git(a, ["branch", "--show-current"])).toBe(result.branch);
    expect(f.calls.some(({ args }) => args[0] === "commit" || args[0] === "push")).toBe(false);
  });

  it("rejects validation resurrecting an allowed generated deletion", async () => {
    const f = await fixture();
    const a = await f.add("acme/a");
    await writeFile(path.join(a, "stale-generated.txt"), "retired output\n");
    const { loadRepoState, writeRepoState } = await import("../src/state.js");
    const { sha256 } = await import("../src/lib/hash.js");
    const state = (await loadRepoState(a))!;
    state.managedFiles["stale-generated.txt"] = sha256("retired output\n");
    await writeRepoState(a, state);
    await git(a, ["add", "stale-generated.txt"]);
    await git(a, ["commit", "-m", "fixture generated deletion"]);
    f.repos.get("acme/a")!.head = await git(a, ["rev-parse", "HEAD"]);
    f.afterValidation((cwd) => writeFile(path.join(cwd, "stale-generated.txt"), "resurrected output\n"));
    const result = (await f.run(true)).results[0]!;
    expect(result.reason).toContain("changed prepared output");
    expect(f.calls.some(({ args }) => args[0] === "commit" || args[0] === "push")).toBe(false);
  });

  it.each(["symlink", "hardlink", "directory"])("rejects validation replacing an allowed output with a %s", async (kind) => {
    const f = await fixture();
    const a = await f.add("acme/a");
    const outside = path.join(f.workspaceRoot, "outside-policy.yaml");
    const bytes = await readFile(f.input.target.bundlePath);
    await writeFile(outside, bytes);
    f.afterValidation(async (cwd) => {
      const file = path.join(cwd, "flow-policy.yaml");
      await rm(file);
      if (kind === "symlink") await symlink(outside, file);
      else if (kind === "hardlink") await link(outside, file);
      else await mkdir(file);
    });
    const result = (await f.run(true)).results[0]!;
    expect(result.status).toBe("failed");
    expect(result.reason).toContain(kind === "directory" ? "regular file or a deletion" : "Non-regular, symlink, or hardlinked");
    expect(await readFile(outside)).toEqual(bytes);
    expect(await git(a, ["branch", "--show-current"])).toBe(result.branch);
    expect(f.calls.some(({ args }) => args[0] === "commit" || args[0] === "push")).toBe(false);
  });

  it("rejects formatter-hook mutations of prepared output after commit without pushing", async () => {
    const f = await fixture();
    const a = await f.add("acme/a");
    const hook = path.join(a, ".git/hooks/pre-commit");
    await writeFile(hook, "#!/usr/bin/env bash\nset -euo pipefail\nprintf '# hook mutation\\n' >> flow-policy.yaml\ngit add -- flow-policy.yaml\n");
    await chmod(hook, 0o755);
    const result = (await f.run(true)).results[0]!;
    expect(result.status).toBe("failed");
    expect(result.reason).toContain("changed prepared output");
    expect(f.calls.some(({ args }) => args[0] === "push")).toBe(false);
    expect(f.calls.some(({ command }) => command === "autoreview")).toBe(false);
    expect(await git(a, ["show", `${result.branch}:flow-policy.yaml`])).toContain("hook mutation");
  });

  it("preserves unrelated validation outputs without staging or committing them", async () => {
    for (const staged of [false, true]) {
      const f = await fixture();
      const a = await f.add("acme/a");
      await writeFile(path.join(a, "scripts/ci/run-fast-checks.sh"), `#!/usr/bin/env bash\nset -euo pipefail\necho preserve > unrelated-output\n${staged ? "git add unrelated-output" : ""}\n`);
      await git(a, ["add", "scripts/ci/run-fast-checks.sh"]);
      await git(a, ["commit", "-m", "fixture validation output"]);
      f.repos.get("acme/a")!.head = await git(a, ["rev-parse", "HEAD"]);
      const result = (await f.run(true)).results[0]!;
      expect(result.status).toBe("failed");
      expect(result.reason).toContain("unrelated files");
      expect(await readFile(path.join(a, "unrelated-output"), "utf8")).toContain("preserve");
      expect(f.calls.some(({ args }) => args[0] === "push" || args[0] === "commit")).toBe(false);
      if (!staged) expect(await git(a, ["diff", "--cached", "--name-only"])).not.toContain("unrelated-output");
    }
  });

  it("preserves exact whitespace-prefixed staged names and never commits unrelated validation output", async () => {
    const f = await fixture();
    const a = await f.add("acme/a");
    await writeFile(path.join(a, "scripts/ci/run-fast-checks.sh"), "#!/usr/bin/env bash\nset -euo pipefail\necho preserve > ' project.bootstrap.yaml'\ngit add -- ' project.bootstrap.yaml'\n");
    await git(a, ["add", "scripts/ci/run-fast-checks.sh"]);
    await git(a, ["commit", "-m", "fixture whitespace validation output"]);
    f.repos.get("acme/a")!.head = await git(a, ["rev-parse", "HEAD"]);
    const result = (await f.run(true)).results[0]!;
    expect(result.status).toBe("failed");
    expect(result.reason).toContain("unrelated files");
    const index = await execRunner("git", ["diff", "--cached", "--name-only", "-z"], { cwd: a });
    expect(index.stdout).toBe(" project.bootstrap.yaml\0");
    expect(f.calls.some(({ args }) => args[0] === "push" || args[0] === "commit")).toBe(false);
    expect(await git(a, ["rev-parse", "HEAD"])).toBe(f.repos.get("acme/a")!.head);
  });

  it("includes manual manifest and bundle writes in restricted dry-run plans and preserves no-op behavior", async () => {
    const f = await fixture();
    const a = await f.add("acme/a", { managedPaths: ["README.md"] });
    const planned = (await f.run()).results[0]!;
    expect(planned.drift).toEqual(["flow-policy.yaml", "project.bootstrap.yaml"]);
    const result = (await f.run(true)).results[0]!;
    expect(result.status).toBe("pr-opened");
    const written = (await git(a, ["diff", "--name-only", f.repos.get("acme/a")!.head, result.branch!])).split("\n");
    expect(written.sort()).toEqual(planned.drift);
    const g = await fixture();
    await g.add("acme/no-op", { version: "1.0.1", managedPaths: ["README.md"] });
    await writeFile(g.input.target.bundlePath, `# layout-only difference\n${await readFile(g.input.target.bundlePath, "utf8")}`);
    expect((await g.run()).results[0]).toMatchObject({ status: "unchanged", drift: [] });
  });

  it("commits only allowed new files and deletions with explicit literal paths", async () => {
    const f = await fixture();
    const a = await f.add("acme/a", { managedPaths: ["project.bootstrap.yaml", "README.md"] });
    await rm(path.join(a, "README.md"));
    await writeFile(path.join(a, "stale-generated.txt"), "old generator output\n");
    const { loadRepoState, writeRepoState } = await import("../src/state.js");
    const { sha256 } = await import("../src/lib/hash.js");
    const state = (await loadRepoState(a))!;
    state.managedFiles["stale-generated.txt"] = sha256("old generator output\n");
    await writeRepoState(a, state);
    await git(a, ["add", "--all"]);
    await git(a, ["commit", "-m", "fixture generated additions and deletions"]);
    f.repos.get("acme/a")!.head = await git(a, ["rev-parse", "HEAD"]);
    const result = (await f.run(true)).results[0]!;
    expect(result.status).toBe("pr-opened");
    const changes = await git(a, ["diff", "--name-status", f.repos.get("acme/a")!.head, result.branch!]);
    expect(changes).toContain("A\tREADME.md");
    expect(changes).toContain("D\tstale-generated.txt");
    const commit = f.calls.find(({ args }) => args[0] === "commit")!;
    expect(commit.args).toContain("--only");
    expect(commit.args).toContain(":(literal)stale-generated.txt");
    expect(commit.args).toContain(":(literal)README.md");
  });

  it("routes minor upgrades to independent review and blocks unsupported major policies", async () => {
    const minor = await fixture("1.1.0");
    await minor.add("acme/a");
    expect((await minor.run()).results[0]).toMatchObject({ status: "planned", risk: "minor", autoMergeEligible: false });
    expect((await minor.run()).results[0]!.reason).toContain("Independent review");
    const major = await fixture("2.0.0");
    await major.add("acme/a");
    expect((await major.run()).results[0]!.reason).toContain("notification and an accepted ADR");
  });

  it("blocks evidence links to unverified repositories and normalization tricks", async () => {
    const f = await fixture();
    await f.add("acme/a");
    f.input.evidence[0]!.provenance = "https://github.com/private/evidence/actions/runs/123";
    expect((await f.run()).results[0]!.reason).toContain("verified public repository");
    f.input.evidence[0]!.provenance = "https://github.com/acme/a/../../private/evidence";
    expect((await f.run()).results[0]!.reason).toContain("verified public repository");
    expect(JSON.stringify(await f.run())).not.toContain("private/evidence");
  });

  it("rejects symlink and hardlinked write targets without changing their external files", async () => {
    for (const kind of ["symlink", "hardlink"] as const) {
      const f = await fixture();
      const a = await f.add("acme/a");
      const original = path.join(a, "flow-policy.yaml");
      const outside = path.join(f.workspaceRoot, "external.yaml");
      const before = await readFile(original, "utf8");
      await writeFile(outside, before);
      await rm(original);
      if (kind === "symlink") await symlink(outside, original); else await link(outside, original);
      await git(a, ["add", "--all"]);
      await git(a, ["commit", "--allow-empty", "-m", "unsafe fixture path"]);
      f.repos.get("acme/a")!.head = await git(a, ["rev-parse", "HEAD"]);
      expect((await f.run(true)).results[0]!.status).toBe("blocked");
      expect(await readFile(outside, "utf8")).toBe(before);
      expect(f.calls.some(({ args }) => args[0] === "push")).toBe(false);
    }
  });
});
