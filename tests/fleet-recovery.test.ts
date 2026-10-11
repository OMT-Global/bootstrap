import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { reconcileFleet } from "../src/fleet.js";
import { execRunner, type CommandRunner } from "../src/lib/process.js";

const tempDirs: string[] = [];
// All Git operations target disposable synthetic repositories; no user hooks or signing.
const localGit: CommandRunner = (command, args, options) => {
  if (command !== "git") throw new Error(`Unexpected external command: ${command}`);
  return execRunner(command, [
    "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false",
    "-c", "user.name=Fleet test", "-c", "user.email=fleet-test@example.invalid",
    ...(args ?? [])
  ], options);
};

async function fixture() {
  const workspaceRoot = await mkdtemp(path.join(os.tmpdir(), "bootstrap-recovery-"));
  tempDirs.push(workspaceRoot);
  const repoPath = path.join(workspaceRoot, "example");
  await mkdir(repoPath);
  const git = async (...args: string[]) => {
    const result = await localGit("git", args, { cwd: repoPath });
    if (result.exitCode !== 0) throw new Error(result.stderr);
    return result.stdout.trim();
  };
  await git("init", "-b", "main");
  await writeFile(path.join(repoPath, "project.bootstrap.yaml"),
    "project:\n  name: example\n  owner: acme\narchetype:\n  kind: generic-empty\n");
  await git("add", ".");
  await git("commit", "-m", "Synthetic baseline");
  return { workspaceRoot, repoPath, git };
}

afterEach(async () => {
  await Promise.all(tempDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

describe("fleet recovery with synthetic Git repositories", () => {
  it.each(["push", "pr"])("preserves the existing recovery branch when retrying after %s failure", async (failure) => {
    const { workspaceRoot, git } = await fixture();
    let branch = "";
    const runner: CommandRunner = async (command, args, options) => {
      if (args?.[0] === "push") {
        branch = args.at(-1)!;
        return { stdout: "", stderr: "Synthetic push failure", exitCode: failure === "push" ? 1 : 0 };
      }
      if (command === "gh") return { stdout: "", stderr: "Synthetic PR failure", exitCode: 1 };
      return localGit(command, args, options);
    };
    const first = await reconcileFleet({ workspaceRoot, applyRepo: true, createPr: true, runner });
    expect(first.results[0].status).toBe("failed");
    expect(await git("branch", "--show-current")).toBe("main");
    await git("checkout", branch);
    await git("commit", "--allow-empty", "-m", "Operator recovery evidence");
    const recoveryHead = await git("rev-parse", "HEAD");
    await git("checkout", "main");

    const retry = await reconcileFleet({ workspaceRoot, applyRepo: true, createPr: true, runner });
    expect(await git("rev-parse", branch)).toBe(recoveryHead);
    expect(retry.results[0]).toMatchObject({ status: "failed", reason: expect.stringContaining("already exists") });
    expect(await git("branch", "--show-current")).toBe("main");
  });

  it.each(["commit", "add"])("keeps generated output on the recovery branch after %s failure and blocks a retry", async (failure) => {
    const { workspaceRoot, repoPath, git } = await fixture();
    const runner: CommandRunner = async (command, args, options) => {
      if (args?.[0] === failure) return { stdout: "", stderr: `Synthetic ${failure} failure`, exitCode: 1 };
      return localGit(command, args, options);
    };
    const first = await reconcileFleet({ workspaceRoot, applyRepo: true, createPr: true, runner });
    expect(first.results[0]).toMatchObject({ status: "failed", reason: expect.stringContaining(`Synthetic ${failure} failure`) });
    expect(await git("branch", "--show-current")).toMatch(/^codex\/bootstrap-reconcile\//);
    const staged = await git("diff", "--cached");
    if (failure === "commit") expect(staged).not.toBe("");
    const generated = await readFile(path.join(repoPath, "AGENTS.md"), "utf8");
    const retry = await reconcileFleet({ workspaceRoot, applyRepo: true, createPr: true, runner });
    expect(retry.results[0].status).toBe("blocked");
    expect(await git("diff", "--cached")).toBe(staged);
    expect(await readFile(path.join(repoPath, "AGENTS.md"), "utf8")).toBe(generated);
  });

  it("reports restoration failure instead of claiming a fully successful PR run", async () => {
    const { workspaceRoot, git } = await fixture();
    const runner: CommandRunner = async (command, args, options) => {
      if (command === "gh") return { stdout: "https://github.com/acme/example/pull/1", stderr: "", exitCode: 0 };
      if (args?.[0] === "push") return { stdout: "", stderr: "", exitCode: 0 };
      if (args?.join(" ") === "checkout main") return { stdout: "", stderr: "Synthetic checkout failure", exitCode: 1 };
      return localGit(command, args, options);
    };
    const report = await reconcileFleet({ workspaceRoot, applyRepo: true, createPr: true, runner });
    expect(report.results[0]).toMatchObject({ status: "failed", pullRequestUrl: "https://github.com/acme/example/pull/1", reason: expect.stringContaining("Synthetic checkout failure") });
    expect(await git("branch", "--show-current")).toMatch(/^codex\/bootstrap-reconcile\//);
  });

  it("retains both the primary failure and a restoration failure", async () => {
    const { workspaceRoot } = await fixture();
    const runner: CommandRunner = async (command, args, options) => {
      if (args?.[0] === "push") return { stdout: "", stderr: "Synthetic push failure", exitCode: 1 };
      if (args?.join(" ") === "checkout main") return { stdout: "", stderr: "Synthetic checkout failure", exitCode: 1 };
      return localGit(command, args, options);
    };
    const report = await reconcileFleet({ workspaceRoot, applyRepo: true, createPr: true, runner });
    expect(report.results[0]).toMatchObject({ status: "failed", branch: expect.stringMatching(/^codex\/bootstrap-reconcile\//) });
    expect(report.results[0].reason).toContain("Synthetic push failure");
    expect(report.results[0].reason).toContain("Synthetic checkout failure");
  });

});
