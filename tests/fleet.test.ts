import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it, vi } from "vitest";

const applyGitHubMock = vi.hoisted(() =>
  vi.fn(async () => [{ id: "issue-labels", description: "Synced issue labels." }])
);

vi.mock("../src/github/provision.js", () => ({
  applyGitHub: applyGitHubMock
}));

import { reconcileFleet } from "../src/fleet.js";
import { execRunner, type CommandRunner } from "../src/lib/process.js";
import { loadManifest } from "../src/manifest.js";
import { applyRepo, planRepo } from "../src/render.js";

const tempDirs: string[] = [];

async function makeTempDir(): Promise<string> {
  const dir = await mkdtemp(path.join(os.tmpdir(), "bootstrap-fleet-"));
  tempDirs.push(dir);
  return dir;
}

async function writeManifest(repoPath: string, name: string): Promise<void> {
  await writeFile(
    path.join(repoPath, "project.bootstrap.yaml"),
    [
      "project:",
      `  name: ${name}`,
      "  owner: acme",
      "archetype:",
      "  kind: generic-empty",
      ""
    ].join("\n"),
    "utf8"
  );
}

afterEach(async () => {
  applyGitHubMock.mockReset();
  applyGitHubMock.mockResolvedValue([{ id: "issue-labels", description: "Synced issue labels." }]);
  await Promise.all(tempDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

describe("reconcileFleet", () => {
  it("plans local bootstrapped repos without mutating files", async () => {
    const workspaceRoot = await makeTempDir();
    const repoPath = path.join(workspaceRoot, "example");
    await import("node:fs/promises").then(({ mkdir }) => mkdir(repoPath, { recursive: true }));
    await writeManifest(repoPath, "example");

    const report = await reconcileFleet({ workspaceRoot });

    expect(report.mode).toBe("plan");
    expect(report.results).toHaveLength(1);
    expect(report.results[0]).toMatchObject({
      repo: "acme/example",
      status: "planned"
    });
    await expect(readFile(path.join(repoPath, "AGENTS.md"), "utf8")).rejects.toThrow();
  });

  it("blocks repo apply when the target worktree is dirty", async () => {
    const workspaceRoot = await makeTempDir();
    const repoPath = path.join(workspaceRoot, "dirty");
    await import("node:fs/promises").then(({ mkdir }) => mkdir(repoPath, { recursive: true }));
    await writeManifest(repoPath, "dirty");

    const runner: CommandRunner = async (command, args) => {
      if (command === "git" && args?.join(" ") === "status --porcelain") {
        return { stdout: "M existing-file\n", stderr: "", exitCode: 0 };
      }
      return { stdout: "", stderr: `unexpected ${command} ${args?.join(" ")}`, exitCode: 1 };
    };

    const report = await reconcileFleet({ workspaceRoot, applyRepo: true, runner });

    expect(report.results[0]).toMatchObject({
      repo: "acme/dirty",
      status: "blocked",
      reason: "Target worktree is dirty; refusing to apply bootstrap changes."
    });
  });

  it("blocks GitHub-only apply from an uncommitted manifest even when generated files match", async () => {
    const workspaceRoot = await makeTempDir();
    const repoPath = path.join(workspaceRoot, "dirty-manifest");
    await import("node:fs/promises").then(({ mkdir }) => mkdir(repoPath));
    const runner: CommandRunner = (command, args, options) => {
      if (command !== "git") throw new Error(`Unexpected command: ${command}`);
      return execRunner(command, [
        "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false",
        "-c", "user.name=Fleet test", "-c", "user.email=fleet-test@example.invalid",
        ...(args ?? [])
      ], options);
    };
    const git = async (...args: string[]) => {
      const result = await runner("git", args, { cwd: repoPath });
      if (result.exitCode !== 0) throw new Error(result.stderr);
      return result.stdout.trim();
    };
    const manifestPath = path.join(repoPath, "project.bootstrap.yaml");
    const originalManifest = [
      "project:", "  name: dirty-manifest", "  owner: acme", "archetype:", "  kind: generic-empty",
      "repo:", "  managedPaths: [CODEOWNERS]", "github:", "  requiredApprovals: 1", "  codeowners:",
      '    - pattern: "*"', '      owners: ["@maintainer"]', ""
    ].join("\n");
    await writeFile(manifestPath, originalManifest);
    await git("init", "-b", "main");
    await applyRepo(await loadManifest(manifestPath), repoPath);
    await git("add", ".");
    await git("commit", "-m", "Synthetic governed baseline");
    await writeFile(manifestPath, originalManifest.replace("requiredApprovals: 1", "requiredApprovals: 2"));
    const plan = await planRepo(await loadManifest(manifestPath), repoPath);
    expect(plan.changes.every((change) => change.type === "unchanged")).toBe(true);
    expect(await git("status", "--porcelain")).toContain("project.bootstrap.yaml");

    const report = await reconcileFleet({ workspaceRoot, applyGitHub: true, runner });

    expect(report.results[0]).toMatchObject({
      repo: "acme/dirty-manifest",
      status: "blocked",
      reason: "Target worktree is dirty; refusing to apply bootstrap changes.",
      githubActions: []
    });
    expect(applyGitHubMock).not.toHaveBeenCalled();
    expect(await readFile(manifestPath, "utf8")).toContain("requiredApprovals: 2");
    expect(await git("status", "--porcelain")).toContain("project.bootstrap.yaml");
  });

  it("opens a draft PR for repo drift when requested", async () => {
    const workspaceRoot = await makeTempDir();
    const repoPath = path.join(workspaceRoot, "needs-sync");
    await import("node:fs/promises").then(({ mkdir }) => mkdir(repoPath, { recursive: true }));
    await writeManifest(repoPath, "needs-sync");
    const calls: string[] = [];
    const runner: CommandRunner = async (command, args) => {
      calls.push(`${command} ${args?.join(" ") ?? ""}`.trim());
      if (command === "git" && args?.join(" ") === "status --porcelain") {
        return { stdout: "", stderr: "", exitCode: 0 };
      }
      if (command === "git" && args?.join(" ") === "rev-parse --abbrev-ref HEAD") {
        return { stdout: "main\n", stderr: "", exitCode: 0 };
      }
      if (command === "gh" && args?.slice(0, 2).join(" ") === "pr create") {
        return { stdout: "https://github.com/acme/needs-sync/pull/42\n", stderr: "", exitCode: 0 };
      }
      return { stdout: "", stderr: "", exitCode: 0 };
    };

    const report = await reconcileFleet({
      workspaceRoot,
      applyRepo: true,
      createPr: true,
      runner
    });

    expect(report.results[0]).toMatchObject({
      repo: "acme/needs-sync",
      status: "pr-opened",
      pullRequestUrl: "https://github.com/acme/needs-sync/pull/42"
    });
    expect(calls.some((call) => call.startsWith("git checkout -b codex/bootstrap-reconcile/needs-sync-"))).toBe(
      true
    );
    expect(calls).toContain("git commit -m chore: reconcile bootstrap-managed files");
    expect(calls).toContain("git checkout main");
  });


  it("reports GitHub-only apply runs as applied instead of planned", async () => {
    const workspaceRoot = await makeTempDir();
    const repoPath = path.join(workspaceRoot, "github-only");
    await import("node:fs/promises").then(({ mkdir }) => mkdir(repoPath, { recursive: true }));
    await writeManifest(repoPath, "github-only");

    const runner: CommandRunner = async (command, args) => {
      if (command === "git" && args?.join(" ") === "status --porcelain") {
        return { stdout: "", stderr: "", exitCode: 0 };
      }
      throw new Error(`Unexpected command: ${command} ${args?.join(" ")}`);
    };
    const report = await reconcileFleet({ workspaceRoot, applyGitHub: true, runner });

    expect(applyGitHubMock).toHaveBeenCalledTimes(1);
    expect(report.mode).toBe("apply");
    expect(report.results[0]).toMatchObject({
      repo: "acme/github-only",
      status: "applied",
      reason: "Repo drift detected; run with --apply-repo to write file changes.",
      githubActions: [{ id: "issue-labels", description: "Synced issue labels." }]
    });
  });

  it("applies GitHub drift without opening an empty PR when repo files are already current", async () => {
    const workspaceRoot = await makeTempDir();
    const repoPath = path.join(workspaceRoot, "github-current");
    await import("node:fs/promises").then(({ mkdir }) => mkdir(repoPath, { recursive: true }));
    await writeManifest(repoPath, "github-current");
    const calls: string[] = [];
    const runner: CommandRunner = async (command, args) => {
      calls.push(`${command} ${args?.join(" ") ?? ""}`.trim());
      if (command === "git" && args?.join(" ") === "status --porcelain") {
        return { stdout: "", stderr: "", exitCode: 0 };
      }
      if (command === "git" && args?.join(" ") === "rev-parse --abbrev-ref HEAD") {
        return { stdout: "main\n", stderr: "", exitCode: 0 };
      }
      return { stdout: "", stderr: "", exitCode: 0 };
    };

    await reconcileFleet({ workspaceRoot, applyRepo: true, runner });
    calls.length = 0;
    applyGitHubMock.mockClear();

    const report = await reconcileFleet({
      workspaceRoot,
      applyRepo: true,
      applyGitHub: true,
      createPr: true,
      runner
    });

    expect(applyGitHubMock).toHaveBeenCalledTimes(1);
    expect(report.results[0]).toMatchObject({
      repo: "acme/github-current",
      status: "applied",
      reason: "No repo drift; applied GitHub reconciliation without opening a PR."
    });
    expect(calls).toContain("git status --porcelain");
    expect(calls.some((call) => call.startsWith("git checkout -b "))).toBe(false);
    expect(calls).not.toContain("git commit -m chore: reconcile bootstrap-managed files");
    expect(calls.some((call) => call.startsWith("gh pr create"))).toBe(false);
  });

  it("can discover org repos and skip local checkouts that are not bootstrapped", async () => {
    const workspaceRoot = await makeTempDir();
    const repoPath = path.join(workspaceRoot, "bootstrapped");
    await import("node:fs/promises").then(({ mkdir }) => mkdir(repoPath, { recursive: true }));
    await writeManifest(repoPath, "bootstrapped");
    const runner: CommandRunner = async (command, args) => {
      if (command === "gh" && args?.slice(0, 2).join(" ") === "repo list") {
        return {
          stdout: JSON.stringify([
            {
              name: "bootstrapped",
              nameWithOwner: "acme/bootstrapped",
              isArchived: false
            },
            {
              name: "missing-local",
              nameWithOwner: "acme/missing-local",
              isArchived: false
            },
            {
              name: "archived",
              nameWithOwner: "acme/archived",
              isArchived: true
            }
          ]),
          stderr: "",
          exitCode: 0
        };
      }
      return { stdout: "", stderr: `unexpected ${command} ${args?.join(" ")}`, exitCode: 1 };
    };

    const report = await reconcileFleet({ workspaceRoot, org: "acme", runner });

    expect(report.results.map((result) => [result.repo, result.status])).toEqual([
      ["acme/bootstrapped", "planned"],
      ["acme/missing-local", "skipped"]
    ]);
  });
});
