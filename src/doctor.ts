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

  if (manifest.agents.manageClaudeHome) {
    const claudeAvailable = await commandExists(runner, "claude");
    checks.push({
      name: "Claude CLI",
      status: claudeAvailable ? "ok" : "warn",
      detail: claudeAvailable
        ? "claude is available."
        : "claude is not on PATH. Home sync can still write files, but the CLI is unavailable."
    });
  }

  if (manifest.agents.enableClaudeDevcontainer) {
    const dockerAvailable = await commandExists(runner, "docker");
    checks.push({
      name: "Claude devcontainer runtime",
      status: dockerAvailable ? "ok" : "warn",
      detail: dockerAvailable
        ? "docker is available for the generated Claude devcontainer."
        : "docker is not on PATH. The generated .devcontainer config will exist, but local container launches will fail until Docker is installed."
    });
  }

  if (manifest.agents.enableClaudeWebEnvironment) {
    checks.push({
      name: "Claude web environment",
      status: "ok",
      detail:
        "Use claude.ai/code with the generated scripts/claude-cloud/setup.sh file, limited network access, and the repo CLAUDE.md instructions."
    });
  }

  if (manifest.agents.enableClaudeGitHubAction) {
    checks.push({
      name: "Claude GitHub Action",
      status: "ok",
      detail:
        `The generated workflow is opt-in and separate from the required PR checks (${requiredStatusChecksLabel(manifest)}). Finish GitHub-side auth with the Claude GitHub app or a repository ANTHROPIC_API_KEY secret.`
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
