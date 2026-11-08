import { execFile } from "node:child_process";
import { chmod, mkdir, mkdtemp, readFile, readdir, realpath, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";

import { afterEach, describe, expect, it } from "vitest";

import YAML from "yaml";

import { normalizeManifest, stringifyManifest } from "../src/manifest.js";
import { flowPolicyDigest } from "../src/policy.js";
import { applyRepo } from "../src/render.js";

const execFileAsync = promisify(execFile);
const tsx = new URL("../node_modules/.bin/tsx", import.meta.url).pathname;
const cli = new URL("../src/cli.ts", import.meta.url).pathname;

describe("CLI help", () => {
  it("describes configured webhook delivery", async () => {
    const [deliver, exceptions, conform] = await Promise.all([
      execFileAsync(tsx, [cli, "notifications", "deliver", "--help"]),
      execFileAsync(tsx, [cli, "notifications", "exceptions", "--help"]),
      execFileAsync(tsx, [cli, "conform", "--help"])
    ]);

    expect(deliver.stdout).toContain("configured webhook");
    expect(deliver.stdout).not.toContain("currently disabled");
    expect(exceptions.stdout).toContain("configured webhook");
    expect(exceptions.stdout).not.toContain("currently disabled");
    expect(conform.stdout).toContain("--github-capabilities");
  });
});

const tempDirs: string[] = [];
const runCli = (args: string[]) => execFileAsync(process.execPath, ["--import", "tsx", cli, ...args]);

afterEach(async () => {
  await Promise.all(tempDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

describe("governed upgrade CLI", () => {
  it("requires the workspace, repository allowlist, and input before execution", async () => {
    await expect(runCli(["upgrade-pr"])).rejects.toMatchObject({
      code: 1,
      stderr: expect.stringContaining("--workspace-root")
    });
    await expect(runCli(["upgrade-pr", "--workspace-root", "/tmp"])).rejects.toMatchObject({
      code: 1,
      stderr: expect.stringContaining("--repo")
    });
    await expect(runCli(["upgrade-pr", "--workspace-root", "/tmp", "--repo", "acme/example"])).rejects.toMatchObject({
      code: 1,
      stderr: expect.stringContaining("--input")
    });
  });

  it.each(["0", "-1", "1.5", "three", "9007199254740992"])("rejects invalid batch size %s before reading input", async (value) => {
    await expect(runCli([
      "upgrade-pr", "--workspace-root", "/tmp", "--repo", "acme/example", "--input", "/does-not-exist.json",
      "--max-batch-size", value
    ])).rejects.toMatchObject({
      code: 1,
      stderr: expect.stringContaining("Batch size must be a positive safe integer")
    });
  });

  it("returns nonzero after apply failure while preserving reports, and leaves dry-run blocks successful", async () => {
    const workspace = await realpath(await mkdtemp(path.join(os.tmpdir(), "bootstrap-upgrade-cli-failure-")));
    tempDirs.push(workspace);
    const repo = path.join(workspace, "example");
    const bin = path.join(workspace, "bin");
    await mkdir(path.join(repo, "scripts/ci"), { recursive: true });
    await mkdir(bin);
    const { stdout: gitPath } = await execFileAsync("bash", ["-c", "command -v git"]);
    const realGit = gitPath.trim();
    const git = async (args: string[]) => (await execFileAsync(realGit, args, { cwd: repo })).stdout.trim();
    await git(["init", "-b", "main"]);
    await git(["config", "user.name", "Synthetic Test"]);
    await git(["config", "user.email", "synthetic@example.invalid"]);
    await git(["config", "commit.gpgsign", "false"]);
    await git(["remote", "add", "origin", "https://github.com/acme/example.git"]);
    const current = { standard: "public-repository-standard", version: "1.0.0" };
    const target = { ...current, version: "1.0.1" };
    const manifest = normalizeManifest({
      version: 2,
      project: { name: "example", owner: "acme", visibility: "public", defaultBranch: "main" },
      repo: { class: "cli", managedPaths: ["project.bootstrap.yaml"] },
      archetype: { kind: "generic-empty" },
      ci: { codeqlLanguages: ["javascript-typescript"] },
      policy: { flow: { ref: "refs/tags/v1.0.0", sha256: flowPolicyDigest(current), bundlePath: "flow-policy.yaml" } }
    });
    await writeFile(path.join(repo, "project.bootstrap.yaml"), stringifyManifest(manifest));
    await writeFile(path.join(repo, "flow-policy.yaml"), YAML.stringify(current));
    await writeFile(path.join(repo, "scripts/ci/run-fast-checks.sh"), "#!/usr/bin/env bash\nexit 23\n");
    await applyRepo(manifest, repo);
    await git(["add", "--all"]);
    await git(["commit", "-m", "synthetic CLI fixture"]);
    const head = await git(["rev-parse", "HEAD"]);
    const generatorRoot = path.dirname(path.dirname(cli));
    const { stdout: generatorCommit } = await execFileAsync(realGit, ["rev-parse", "HEAD"], { cwd: generatorRoot });
    const targetPath = path.join(workspace, "target.yml");
    await writeFile(targetPath, YAML.stringify(target));
    const inputPath = path.join(workspace, "input.json");
    const evidence = Object.fromEntries(["issue", "policyDiff", "tests", "exceptions", "provenance", "autoreview"].map((field) => [field, `https://github.com/acme/example/${field === "issue" ? "issues/62" : "actions/runs/123"}`]));
    await writeFile(inputPath, JSON.stringify({
      generatorCommit: generatorCommit.trim(),
      target: { ref: "refs/tags/v1.0.1", sha256: flowPolicyDigest(target), bundlePath: targetPath },
      evidence: [{ repo: "acme/example", ...evidence }], pilots: []
    }));
    // Only generator cleanliness and remote reads are injected; target Git and the failing check are real.
    await writeFile(path.join(bin, "git"), `#!${process.execPath}\nconst { spawnSync } = require("node:child_process");
const args = process.argv.slice(2);
if (process.cwd() === ${JSON.stringify(generatorRoot)}) {
  if (args.join(" ") === "rev-parse HEAD") { process.stdout.write(${JSON.stringify(generatorCommit.trim())}); process.exit(0); }
  if (args.join(" ") === "status --porcelain") process.exit(0);
  process.exit(90);
}
if (process.cwd() !== ${JSON.stringify(repo)} || args[0] === "push") process.exit(91);
const result = args[0] === "ls-remote" ? { status: 0 } : spawnSync(${JSON.stringify(realGit)}, args, { stdio: "inherit" });
process.exit(result.status ?? 92);
`);
    await writeFile(path.join(bin, "gh"), `#!${process.execPath}\nconst args = process.argv.slice(2);
if (args[0] !== "api") process.exit(90);
if (args[1] === "repos/acme/example") process.stdout.write(JSON.stringify({ full_name: "acme/example", visibility: "public", private: false, archived: false, default_branch: "main" }));
else if (args[1] === "repos/acme/example/commits/main") process.stdout.write(JSON.stringify({ sha: ${JSON.stringify(head)} }));
else process.exit(91);
`);
    await Promise.all(["git", "gh"].map((name) => chmod(path.join(bin, name), 0o755)));
    const reportPath = path.join(workspace, "report.json");
    const args = ["upgrade-pr", "--workspace-root", workspace, "--repo", "acme/example", "--input", inputPath, "--json", "--report", reportPath];
    const env = { ...process.env, PATH: `${bin}${path.delimiter}${process.env.PATH}` };
    const result = await execFileAsync(process.execPath, ["--import", "tsx", cli, ...args, "--apply"], { env }).then(
      (output) => ({ ...output, code: 0 }),
      (error: { stdout: string; stderr: string; code: number }) => error
    );
    expect(result.code).toBe(1);
    const report = JSON.parse(result.stdout);
    expect(report).toMatchObject({ mode: "apply", results: [{ status: "failed", reason: expect.stringContaining("bash scripts/ci/run-fast-checks.sh failed") }] });
    expect(JSON.parse(await readFile(reportPath, "utf8"))).toEqual(report);
    expect(await git(["branch", "--show-current"])).toMatch(/^codex\/flow-policy-/);
    expect(await git(["status", "--porcelain"])).not.toBe("");
    const planned = await execFileAsync(process.execPath, ["--import", "tsx", cli, ...args], { env });
    expect(JSON.parse(planned.stdout)).toMatchObject({ mode: "plan", results: [{ status: "blocked" }] });
    expect(JSON.parse(await readFile(reportPath, "utf8"))).toEqual(JSON.parse(planned.stdout));
  }, 20_000);

  it("defaults to a non-mutating plan and writes the requested structured report", async () => {
    const workspace = await mkdtemp(path.join(os.tmpdir(), "bootstrap-upgrade-cli-"));
    tempDirs.push(workspace);
    const target = path.join(workspace, "target.yml");
    const targetContents = "standard: public-repository-standard\nversion: 1.0.1\n";
    await writeFile(target, targetContents);
    const { stdout: commit } = await execFileAsync("git", ["rev-parse", "HEAD"]);
    const inputPath = path.join(workspace, "input.json");
    await writeFile(inputPath, JSON.stringify({
      generatorCommit: commit.trim(),
      target: {
        ref: "refs/tags/v1.0.1",
        sha256: flowPolicyDigest({ standard: "public-repository-standard", version: "1.0.1" }),
        bundlePath: target
      },
      evidence: [],
      pilots: []
    }));
    const reportPath = path.join(workspace, "report.json");
    const { stdout, stderr } = await runCli([
      "upgrade-pr", "--workspace-root", workspace, "--repo", "acme/missing", "--input", inputPath,
      "--json", "--report", reportPath
    ]);
    const report = JSON.parse(stdout);
    expect(stderr).toBe("");
    expect(report.mode).toBe("plan");
    expect(report.results).toEqual([expect.objectContaining({ repo: "[unverified]", status: "skipped" })]);
    expect(JSON.parse(await readFile(reportPath, "utf8"))).toEqual(report);
    expect(await readFile(target, "utf8")).toBe(targetContents);
    expect((await readdir(workspace)).sort()).toEqual(["input.json", "report.json", "target.yml"]);
  });
});
