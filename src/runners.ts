import type { ProjectVisibility, RunnerPolicy } from "./types.js";

export type RunnerCapability = "shell" | "docker" | "services" | "browser" | "container-job";

export type RunsOn = string | string[];

const INCOMPATIBLE_CAPABILITIES = new Set<RunnerCapability>([
  "docker",
  "services",
  "browser",
  "container-job"
]);

export function resolveRunsOn(
  runnerPolicy: RunnerPolicy,
  visibility: ProjectVisibility,
  capabilities: RunnerCapability[]
): RunsOn {
  const hasIncompatibleCapability = capabilities.some((capability) =>
    INCOMPATIBLE_CAPABILITIES.has(capability)
  );

  if (runnerPolicy === "github-hosted-first") {
    return "ubuntu-latest";
  }

  if (hasIncompatibleCapability) {
    return "ubuntu-latest";
  }

  return ["self-hosted", "synology", "shell-only", visibility === "public" ? "public" : "private"];
}

export function formatRunsOn(runsOn: RunsOn): string {
  if (typeof runsOn === "string") {
    return runsOn;
  }

  return `[${runsOn.map((value) => `'${value}'`).join(", ")}]`;
}
