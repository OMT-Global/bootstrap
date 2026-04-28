import { readdir } from "node:fs/promises";
import path from "node:path";

import { applyGitHub } from "./github/provision.js";
import { exists, writeTextFile } from "./lib/fs.js";
import type { CommandRunner } from "./lib/process.js";
import { execRunner } from "./lib/process.js";
import { loadManifest } from "./manifest.js";
import { applyRepo, planRepo } from "./render.js";
import type { PlannedFileChange, PlannedGitHubAction } from "./types.js";

export type FleetRepoStatus =
  | "planned"
  | "unchanged"
  | "skipped"
  | "applied"
  | "pr-opened"
  | "blocked"
  | "failed";

export interface FleetRepoResult {
  repo: string;
  path: string;
  status: FleetRepoStatus;
  branch?: string;
  pullRequestUrl?: string;
  reason?: string;
  repoChanges: PlannedFileChange[];
  githubActions: PlannedGitHubAction[];
}

export interface FleetReport {
  mode: "plan" | "apply";
  generatedAt: string;
  workspaceRoot: string;
  results: FleetRepoResult[];
}

export interface ReconcileFleetOptions {
  workspaceRoot: string;
  org?: string;
  repos?: string[];
  applyRepo?: boolean;
  applyGitHub?: boolean;
  createPr?: boolean;
  branchPrefix?: string;
  reportPath?: string;
  runner?: CommandRunner;
}

interface LocalRepo {
  name: string;
  nameWithOwner?: string;
  path: string;
}

function hasRepoDrift(changes: PlannedFileChange[]): boolean {
  return changes.some((change) => change.type !== "unchanged");
}

function repoSlug(repoPath: string): string {
  return path.basename(repoPath).replace(/[^a-zA-Z0-9._-]+/g, "-");
}

function branchName(repoPath: string, branchPrefix: string): string {
  const date = new Date().toISOString().slice(0, 10).replace(/-/g, "");
  return `${branchPrefix}/${repoSlug(repoPath)}-${date}`;
}

function parsePullRequestUrl(output: string): string | undefined {
  return output
    .split(/\s+/)
    .find((token) => token.startsWith("https://github.com/") && token.includes("/pull/"));
}

interface GitHubRepoListItem {
  name: string;
  nameWithOwner: string;
  isArchived: boolean;
}

async function discoverOrgRepos(
  workspaceRoot: string,
  org: string,
  runner: CommandRunner
): Promise<LocalRepo[]> {
  const result = await runner("gh", [
    "repo",
    "list",
    org,
    "--limit",
    "1000",
    "--json",
    "name,nameWithOwner,isArchived"
  ]);
  if (result.exitCode !== 0) {
    throw new Error(result.stderr.trim() || result.stdout.trim() || `gh repo list ${org} failed`);
  }

  const repos = JSON.parse(result.stdout) as GitHubRepoListItem[];
  return repos
    .filter((repo) => !repo.isArchived)
    .map((repo) => ({
      name: repo.name,
      nameWithOwner: repo.nameWithOwner,
      path: path.join(workspaceRoot, repo.name)
    }))
    .sort((left, right) => left.name.localeCompare(right.name));
}

async function discoverWorkspaceRepos(
  workspaceRoot: string,
  runner: CommandRunner,
  repos?: string[],
  org?: string
): Promise<LocalRepo[]> {
  if (repos && repos.length > 0) {
    return repos.map((repo) => {
      const name = repo.includes("/") ? repo.split("/").at(-1)! : repo;
      return {
        name,
        ...(repo.includes("/") ? { nameWithOwner: repo } : {}),
        path: path.resolve(workspaceRoot, name)
      };
    });
  }

  if (org) {
    return discoverOrgRepos(workspaceRoot, org, runner);
  }

  const entries = await readdir(workspaceRoot, { withFileTypes: true });
  const candidates = entries
    .filter((entry) => entry.isDirectory())
    .map((entry) => ({
      name: entry.name,
      path: path.join(workspaceRoot, entry.name)
    }));
  const bootstrapped: LocalRepo[] = [];
  for (const candidate of candidates) {
    if (await exists(path.join(candidate.path, "project.bootstrap.yaml"))) {
      bootstrapped.push(candidate);
    }
  }
  return bootstrapped.sort((left, right) => left.name.localeCompare(right.name));
}

async function gitOutput(
  runner: CommandRunner,
  cwd: string,
  args: string[]
): Promise<string> {
  const result = await runner("git", args, { cwd });
  if (result.exitCode !== 0) {
    throw new Error(result.stderr.trim() || result.stdout.trim() || `git ${args.join(" ")} failed`);
  }
  return result.stdout.trim();
}

async function isCleanWorktree(runner: CommandRunner, cwd: string): Promise<boolean> {
  return (await gitOutput(runner, cwd, ["status", "--porcelain"])).length === 0;
}

async function currentBranch(runner: CommandRunner, cwd: string): Promise<string> {
  return gitOutput(runner, cwd, ["rev-parse", "--abbrev-ref", "HEAD"]);
}

async function applyRepoThroughPullRequest(
  repo: LocalRepo,
  manifestPath: string,
  branch: string,
  runner: CommandRunner
): Promise<{ branch: string; pullRequestUrl?: string }> {
  await gitOutput(runner, repo.path, ["checkout", "-B", branch]);
  await applyRepo(await loadManifest(manifestPath), repo.path);
  await gitOutput(runner, repo.path, ["add", "."]);
  await gitOutput(runner, repo.path, [
    "commit",
    "-m",
    "chore: reconcile bootstrap-managed files"
  ]);
  await gitOutput(runner, repo.path, ["push", "-u", "origin", branch]);

  const pr = await runner(
    "gh",
    [
      "pr",
      "create",
      "--fill",
      "--draft",
      "--title",
      "chore: reconcile bootstrap-managed files",
      "--body",
      [
        "## Summary",
        "- Reconcile bootstrap-managed files with the current control-plane templates.",
        "",
        "## Governing Issue",
        "No governing issue is linked; this is scheduled bootstrap fleet reconciliation.",
        "",
        "## Validation",
        "- [x] `bootstrap reconcile --apply-repo --create-pr` generated this PR after local repo apply.",
        "- [ ] Required PR checks are expected to pass after GitHub runs them.",
        "",
        "## Bootstrap Governance",
        "- [x] Changes are limited to bootstrap-managed file drift.",
        "- [x] No real secrets, runtime auth, or machine-local env files are committed.",
        "",
        "## Notes",
        "- Daily fleet reconciliation PR; review before merge."
      ].join("\n")
    ],
    { cwd: repo.path }
  );
  if (pr.exitCode !== 0) {
    throw new Error(pr.stderr.trim() || pr.stdout.trim() || "gh pr create failed");
  }

  const pullRequestUrl = parsePullRequestUrl(pr.stdout);
  return {
    branch,
    ...(pullRequestUrl ? { pullRequestUrl } : {})
  };
}

async function reconcileOneRepo(
  repo: LocalRepo,
  options: Required<Pick<ReconcileFleetOptions, "applyRepo" | "applyGitHub" | "createPr" | "branchPrefix">> & {
    runner: CommandRunner;
  }
): Promise<FleetRepoResult> {
  const manifestPath = path.join(repo.path, "project.bootstrap.yaml");
  if (!(await exists(manifestPath))) {
    return {
      repo: repo.nameWithOwner ?? repo.name,
      path: repo.path,
      status: "skipped",
      reason: "project.bootstrap.yaml not found.",
      repoChanges: [],
      githubActions: []
    };
  }

  const manifest = await loadManifest(manifestPath);
  const plannedRepo = await planRepo(manifest, repo.path);
  const repoDrift = hasRepoDrift(plannedRepo.changes);
  let githubActions: PlannedGitHubAction[] = [];

  if (!repoDrift && !options.applyGitHub) {
    return {
      repo: `${manifest.project.owner}/${manifest.project.name}`,
      path: repo.path,
      status: "unchanged",
      repoChanges: plannedRepo.changes,
      githubActions
    };
  }

  if (!options.applyRepo) {
    if (options.applyGitHub) {
      githubActions = await applyGitHub(manifest);
    }
    return {
      repo: `${manifest.project.owner}/${manifest.project.name}`,
      path: repo.path,
      status: "planned",
      ...(repoDrift ? { reason: "Repo drift detected; run with --apply-repo to write changes." } : {}),
      repoChanges: plannedRepo.changes,
      githubActions
    };
  }

  if (!(await isCleanWorktree(options.runner, repo.path))) {
    return {
      repo: `${manifest.project.owner}/${manifest.project.name}`,
      path: repo.path,
      status: "blocked",
      reason: "Target worktree is dirty; refusing to apply bootstrap changes.",
      repoChanges: plannedRepo.changes,
      githubActions
    };
  }

  const startingBranch = await currentBranch(options.runner, repo.path);
  const branch = branchName(repo.path, options.branchPrefix);
  try {
    if (options.createPr) {
      const pr = await applyRepoThroughPullRequest(repo, manifestPath, branch, options.runner);
      if (options.applyGitHub) {
        githubActions = await applyGitHub(manifest);
      }
      return {
        repo: `${manifest.project.owner}/${manifest.project.name}`,
        path: repo.path,
        status: "pr-opened",
        branch: pr.branch,
        ...(pr.pullRequestUrl ? { pullRequestUrl: pr.pullRequestUrl } : {}),
        repoChanges: plannedRepo.changes,
        githubActions
      };
    }

    await applyRepo(manifest, repo.path);
    if (options.applyGitHub) {
      githubActions = await applyGitHub(manifest);
    }
    return {
      repo: `${manifest.project.owner}/${manifest.project.name}`,
      path: repo.path,
      status: "applied",
      repoChanges: plannedRepo.changes,
      githubActions
    };
  } finally {
    if (options.createPr && startingBranch !== branch) {
      await options.runner("git", ["checkout", startingBranch], { cwd: repo.path });
    }
  }
}

export async function reconcileFleet(options: ReconcileFleetOptions): Promise<FleetReport> {
  const workspaceRoot = path.resolve(options.workspaceRoot);
  const runner = options.runner ?? execRunner;
  const repos = await discoverWorkspaceRepos(workspaceRoot, runner, options.repos, options.org);
  const results: FleetRepoResult[] = [];
  const applyRepoOption = options.applyRepo ?? false;
  const applyGitHubOption = options.applyGitHub ?? false;
  const createPrOption = options.createPr ?? false;
  const branchPrefix = options.branchPrefix ?? "codex/bootstrap-reconcile";

  for (const repo of repos) {
    try {
      results.push(
        await reconcileOneRepo(repo, {
          applyRepo: applyRepoOption,
          applyGitHub: applyGitHubOption,
          createPr: createPrOption,
          branchPrefix,
          runner
        })
      );
    } catch (error) {
      results.push({
        repo: repo.name,
        path: repo.path,
        status: "failed",
        reason: error instanceof Error ? error.message : String(error),
        repoChanges: [],
        githubActions: []
      });
    }
  }

  const report: FleetReport = {
    mode: applyRepoOption || applyGitHubOption ? "apply" : "plan",
    generatedAt: new Date().toISOString(),
    workspaceRoot,
    results
  };

  if (options.reportPath) {
    await writeTextFile(path.resolve(options.reportPath), `${JSON.stringify(report, null, 2)}\n`);
  }

  return report;
}
