import os from "node:os";

import { execRunner, type CommandRunner } from "./lib/process.js";
import { resolveRunsOn } from "./runners.js";
import type { BootstrapManifest } from "./types.js";
import { GitHubClient } from "./github/client.js";

export interface DoctorCheck {
  name: string;
  status: "ok" | "warn" | "fail";
  detail: string;
}

function requiredStatusChecksLabel(manifest: BootstrapManifest): string {
  return manifest.github.requiredStatusChecks.join(", ");
}

function additionalWorkflowsLabel(manifest: BootstrapManifest): string {
  return manifest.ci.additionalWorkflows.map((workflow) => workflow.path).join(", ");
}

async function commandExists(runner: CommandRunner, command: string): Promise<boolean> {
  const result = await runner(command, ["--version"]);
  return result.exitCode === 0;
}

export async function runDoctor(
  manifest: BootstrapManifest,
  options: {
    runner?: CommandRunner;
    homeDir?: string;
    githubClient?: GitHubClient;
  } = {}
): Promise<DoctorCheck[]> {
  const runner = options.runner ?? execRunner;
  const homeDir = options.homeDir ?? os.homedir();
  const githubClient = options.githubClient ?? new GitHubClient({ runner });

  const checks: DoctorCheck[] = [];

  const ghAvailable = await githubClient.isAvailable();
  checks.push({
    name: "gh CLI",
    status: ghAvailable ? "ok" : "fail",
    detail: ghAvailable ? "gh is available." : "gh is missing from PATH."
  });

  if (ghAvailable) {
    const ghAuthenticated = await githubClient.isAuthenticated();
    checks.push({
      name: "GitHub auth",
      status: ghAuthenticated ? "ok" : "warn",
      detail: ghAuthenticated
        ? "gh auth status succeeded."
        : "gh is installed but not authenticated. `apply github` will fail until `gh auth login` succeeds."
    });
  }

  if (manifest.github.organization) {
    checks.push({
      name: "GitHub org policy",
      status: "ok",
      detail: `apply github will also reconcile org defaults for ${manifest.project.owner}.`
    });
  }

  if (manifest.agents.manageCodexHome) {
    const codexAvailable = await commandExists(runner, "codex");
    checks.push({
      name: "Codex CLI",
      status: codexAvailable ? "ok" : "warn",
      detail: codexAvailable
        ? "codex is available."
        : "codex is not on PATH. Home sync can still write files, but the CLI is unavailable."
    });
  }

  const runnerLabels = resolveRunsOn(
    manifest.ci.runnerPolicy,
    manifest.project.visibility,
    ["shell"]
  );
  checks.push({
    name: "Runner policy",
    status: "ok",
    detail:
      typeof runnerLabels === "string"
        ? `Shell-safe jobs resolve to ${runnerLabels}.`
        : `Shell-safe jobs resolve to [${runnerLabels.join(", ")}].`
  });

  checks.push({
    name: "CI shape",
    status: "ok",
    detail:
      manifest.ci.additionalWorkflows.length === 0
        ? `Standard CI shape uses ${requiredStatusChecksLabel(manifest)} for PR gating plus extended validation on ${manifest.project.defaultBranch}, nightly, and manual dispatch.`
        : `Standard CI shape uses ${requiredStatusChecksLabel(manifest)} for PR gating plus adjunct repo-specific workflow lanes: ${additionalWorkflowsLabel(manifest)}.`
  });

  for (const environmentName of ["stage", "prod"] as const) {
    const environment = manifest.environments[environmentName];
    const hasReviewers = environment.reviewers.length > 0;
    checks.push({
      name: `${environmentName} reviewers`,
      status: hasReviewers ? "ok" : "warn",
      detail: hasReviewers
        ? `${environmentName} environment has ${environment.reviewers.length} reviewer target(s).`
        : `${environmentName} requires approval but no reviewers are configured.`
    });
  }

  const unsupportedBranchPolicies = (["dev", "stage", "prod"] as const).filter((environmentName) => {
    const branches = manifest.environments[environmentName].branches;
    return branches.length > 1 || (branches.length === 1 && branches[0] !== manifest.project.defaultBranch);
  });
  checks.push({
    name: "Environment branch policy",
    status: unsupportedBranchPolicies.length === 0 ? "ok" : "warn",
    detail:
      unsupportedBranchPolicies.length === 0
        ? "Environment branches are compatible with the default branch policy flow."
        : `Custom environment branch policies need follow-up for: ${unsupportedBranchPolicies.join(", ")}.`
  });

  checks.push({
    name: "Home root",
    status: "ok",
    detail: `Home sync will target ${homeDir}.`
  });

  return checks;
}
