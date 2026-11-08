import { execFile } from "node:child_process";
import { mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";

import { afterEach, describe, expect, it } from "vitest";

import { flowPolicyDigest } from "../src/policy.js";

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
