#!/usr/bin/env node
import path from "node:path";

import { Command } from "commander";

import { runDoctor } from "./doctor.js";
import { reconcileFleet } from "./fleet.js";
import { planGitHub, applyGitHub } from "./github/provision.js";
import { planHome, applyHome } from "./home/sync.js";
import {
  createSampleManifest,
  loadManifest,
  resolveManifestPath
} from "./manifest.js";
import { planRepo, applyRepo } from "./render.js";

function defaultTargetDir(manifest: Awaited<ReturnType<typeof loadManifest>>, cwd = process.cwd()): string {
  const currentBasename = path.basename(cwd);
  return currentBasename === manifest.project.name ? cwd : path.resolve(cwd, manifest.project.name);
}

function formatRepoChanges(changes: Awaited<ReturnType<typeof planRepo>>["changes"]): string {
  if (changes.length === 0) {
    return "Repo: no managed file changes.";
  }

  return [
    "**Repo**",
    ...changes.map((change) => `- [${change.type}] ${change.path}: ${change.reason}`)
  ].join("\n");
}

function formatLanguageProfiles(profiles: Awaited<ReturnType<typeof planRepo>>["languageProfiles"]): string {
  const selected = profiles.selected.length === 0 ? "none" : profiles.selected.join(", ");
  const conflicts = profiles.conflicts.map((conflict) => `- [warn] ${conflict.reason}`);
  return ["**Language profiles**", `- Selected: ${selected}`, ...conflicts].join("\n");
}

function formatGitHubActions(actions: Awaited<ReturnType<typeof planGitHub>>): string {
  return [
    "**GitHub**",
    ...actions.map((action) => `- ${action.description}`)
  ].join("\n");
}

function formatHomeActions(actions: Awaited<ReturnType<typeof planHome>>["actions"]): string {
  return [
    "**Home**",
    ...actions.map((action) => `- [${action.type}] ${action.path}: ${action.reason}`)
  ].join("\n");
}

function formatFleetReport(report: Awaited<ReturnType<typeof reconcileFleet>>): string {
  if (report.results.length === 0) {
    return "Fleet: no bootstrapped repositories found.";
  }

  return [
    `**Fleet ${report.mode}**`,
    ...report.results.map((result) => {
      const changed = result.repoChanges.filter((change) => change.type !== "unchanged").length;
      const githubActions = result.githubActions.length;
      const details = [
        `${result.repo}: ${result.status}`,
        changed > 0 ? `${changed} repo change(s)` : "no repo drift",
        githubActions > 0 ? `${githubActions} GitHub action(s)` : undefined,
        result.pullRequestUrl ? `PR ${result.pullRequestUrl}` : undefined,
        result.reason
      ].filter(Boolean);
      return `- ${details.join(" - ")}`;
    })
  ].join("\n");
}

async function main(): Promise<void> {
  const program = new Command();
  program
    .name("bootstrap")
    .description("Manifest-first control plane for repo scaffolding, GitHub governance, and portable agent profiles.");

  program
    .command("init-manifest")
    .description("Create a starter project.bootstrap.yaml manifest.")
    .option("--output <path>", "Output path", "project.bootstrap.yaml")
    .option("--name <name>", "Project name", "example-project")
    .option("--owner <owner>", "GitHub owner", "your-org")
    .option(
      "--archetype <kind>",
      "Archetype kind",
      "node-ts-service"
    )
    .action(async (options) => {
      const manifestContents = createSampleManifest({
        project: {
          name: options.name,
          owner: options.owner,
          description:
            "Manifest-first control plane for repo scaffolding, GitHub governance, and portable agent profiles.",
          visibility: "private",
          defaultBranch: "main"
        },
        archetype: {
          kind: options.archetype,
          packageManager: "npm",
          moduleName: options.name.replace(/[^a-z0-9]+/gi, "_").toLowerCase()
        }
      } as never);
      const outputPath = path.resolve(options.output);
      await import("node:fs/promises").then(({ mkdir, writeFile }) =>
        mkdir(path.dirname(outputPath), { recursive: true }).then(() =>
          writeFile(outputPath, manifestContents, "utf8")
        )
      );
      process.stdout.write(`Wrote ${outputPath}\n`);
    });

  program
    .command("plan")
    .description("Print the non-mutating repo, GitHub, and home plan.")
    .option("--manifest <path>", "Path to manifest")
    .option("--target <path>", "Target repository directory")
    .option("--home-dir <path>", "Override home directory")
    .option("--json", "Emit JSON")
    .action(async (options) => {
      const manifest = await loadManifest(resolveManifestPath(options.manifest));
      const targetDir = options.target ? path.resolve(options.target) : defaultTargetDir(manifest);
      const repoPlan = await planRepo(manifest, targetDir);
      const githubPlan = await planGitHub(manifest);
      const homePlan = await planHome(manifest, options.homeDir ? path.resolve(options.homeDir) : undefined);

      if (options.json) {
        process.stdout.write(
          `${JSON.stringify(
            {
              targetDir,
              repo: repoPlan.changes,
              languageProfiles: repoPlan.languageProfiles,
              github: githubPlan,
              home: homePlan.actions
            },
            null,
            2
          )}\n`
        );
        return;
      }

      process.stdout.write(
        `${formatRepoChanges(repoPlan.changes)}\n\n${formatLanguageProfiles(repoPlan.languageProfiles)}\n\n${formatGitHubActions(githubPlan)}\n\n${formatHomeActions(
          homePlan.actions
        )}\n`
      );
    });

  program
    .command("reconcile")
    .description("Plan or apply bootstrap alignment across local bootstrapped repositories.")
    .requiredOption("--workspace-root <path>", "Directory containing local repository checkouts")
    .option("--org <owner>", "Discover repositories from a GitHub org or user, then map them to local checkouts")
    .option("--repo <name...>", "Restrict to one or more repo names or owner/name values")
    .option("--apply-repo", "Write repo-local bootstrap drift")
    .option("--apply-github", "Apply GitHub settings and label drift")
    .option("--create-pr", "Commit repo drift on a branch, push, and open a draft PR")
    .option("--branch-prefix <prefix>", "Branch prefix for PR mode", "codex/bootstrap-reconcile")
    .option("--report <path>", "Write JSON report")
    .option("--json", "Emit JSON")
    .action(async (options) => {
      const report = await reconcileFleet({
        workspaceRoot: path.resolve(options.workspaceRoot),
        org: options.org,
        repos: options.repo,
        applyRepo: options.applyRepo ?? false,
        applyGitHub: options.applyGithub ?? false,
        createPr: options.createPr ?? false,
        branchPrefix: options.branchPrefix,
        reportPath: options.report
      });

      if (options.json) {
        process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
        return;
      }

      process.stdout.write(`${formatFleetReport(report)}\n`);
    });

  const apply = program.command("apply").description("Apply one bootstrap target.");

  apply
    .command("repo")
    .description("Render repo-local files into the target directory.")
    .option("--manifest <path>", "Path to manifest")
    .option("--target <path>", "Target repository directory")
    .action(async (options) => {
      const manifest = await loadManifest(resolveManifestPath(options.manifest));
      const targetDir = options.target ? path.resolve(options.target) : defaultTargetDir(manifest);
      const repoPlan = await applyRepo(manifest, targetDir);
      process.stdout.write(`${formatRepoChanges(repoPlan.changes)}\n`);
    });

  apply
    .command("github")
    .description("Create or update GitHub org defaults, repo settings, branch protection, and environments.")
    .option("--manifest <path>", "Path to manifest")
    .action(async (options) => {
      const manifest = await loadManifest(resolveManifestPath(options.manifest));
      const actions = await applyGitHub(manifest);
      process.stdout.write(`${formatGitHubActions(actions)}\n`);
    });

  apply
    .command("home")
    .description("Sync portable Codex home assets.")
    .option("--manifest <path>", "Path to manifest")
    .option("--home-dir <path>", "Override home directory")
    .action(async (options) => {
      const manifest = await loadManifest(resolveManifestPath(options.manifest));
      const actions = await applyHome(manifest, options.homeDir ? path.resolve(options.homeDir) : undefined);
      process.stdout.write(`${formatHomeActions(actions)}\n`);
    });

  program
    .command("doctor")
    .description("Validate local prerequisites and policy compatibility.")
    .option("--manifest <path>", "Path to manifest")
    .option("--home-dir <path>", "Override home directory")
    .option("--json", "Emit JSON")
    .action(async (options) => {
      const manifest = await loadManifest(resolveManifestPath(options.manifest));
      const checks = await runDoctor(manifest, {
        ...(options.homeDir ? { homeDir: path.resolve(options.homeDir) } : {})
      });

      if (options.json) {
        process.stdout.write(`${JSON.stringify(checks, null, 2)}\n`);
        return;
      }

      process.stdout.write(
        `${checks.map((check) => `- [${check.status}] ${check.name}: ${check.detail}`).join("\n")}\n`
      );
    });

  await program.parseAsync(process.argv);
}

main().catch((error) => {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`${message}\n`);
  process.exit(1);
});
