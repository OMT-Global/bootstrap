import path from "node:path";
import YAML from "yaml";
import { z } from "zod";

import { readTextIfExists } from "./lib/fs.js";
import type { BootstrapManifest, CodeownerRule, EnvironmentConfig } from "./types.js";

const environmentSchema = z.object({
  reviewers: z.array(z.string()).optional(),
  requireApproval: z.boolean().optional(),
  preventSelfReview: z.boolean().optional(),
  branches: z.array(z.string()).optional()
});

const codeownerSchema = z.object({
  pattern: z.string().min(1),
  owners: z.array(z.string().min(1)).min(1)
});

const manifestSchema = z.object({
  version: z.literal(1).optional(),
  project: z.object({
    name: z.string().min(1),
    description: z.string().optional(),
    visibility: z.enum(["private", "public", "internal"]).optional(),
    owner: z.string().min(1),
    defaultBranch: z.string().min(1).optional()
  }),
  archetype: z.object({
    kind: z.enum(["nextjs-web", "node-ts-service", "python-service", "generic-empty"]),
    packageManager: z.enum(["npm", "pnpm", "yarn"]).optional(),
    moduleName: z.string().optional()
  }),
  github: z
    .object({
      createRepo: z.boolean().optional(),
      reviewers: z.array(z.string()).optional(),
      codeowners: z.array(codeownerSchema).optional(),
      autoMerge: z.boolean().optional(),
      deleteBranchOnMerge: z.boolean().optional(),
      requiredApprovals: z.number().int().min(1).max(6).optional(),
      dismissStaleReviews: z.boolean().optional(),
      requireCodeOwnerReviews: z.boolean().optional(),
      requireLastPushApproval: z.boolean().optional(),
      enforceLinearHistory: z.boolean().optional(),
      allowMergeCommit: z.boolean().optional(),
      allowSquashMerge: z.boolean().optional(),
      allowRebaseMerge: z.boolean().optional(),
      repoFeatures: z
        .object({
          hasIssues: z.boolean().optional(),
          hasProjects: z.boolean().optional(),
          hasWiki: z.boolean().optional(),
          hasDiscussions: z.boolean().optional()
        })
        .optional()
    })
    .optional(),
  ci: z
    .object({
      runnerPolicy: z.enum(["hybrid-safe", "self-hosted-first", "github-hosted-first"]).optional(),
      nodeVersion: z.string().optional(),
      pythonVersion: z.string().optional(),
      fastChecks: z.array(z.string()).optional(),
      extendedChecks: z.array(z.string()).optional(),
      nightlyCron: z.string().optional()
    })
    .optional(),
  agents: z
    .object({
      manageCodexHome: z.boolean().optional(),
      manageClaudeHome: z.boolean().optional(),
      codexProfile: z.string().optional(),
      claudeProfile: z.string().optional(),
      enableClaudeWebEnvironment: z.boolean().optional(),
      enableClaudeDevcontainer: z.boolean().optional(),
      enableClaudeGitHubAction: z.boolean().optional(),
      sharedSkills: z.array(z.string()).optional()
    })
    .optional(),
  environments: z
    .object({
      dev: environmentSchema.optional(),
      stage: environmentSchema.optional(),
      prod: environmentSchema.optional()
    })
    .optional()
});

function slugify(value: string): string {
  return value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

function moduleNameForProject(name: string): string {
  return slugify(name).replace(/-/g, "_");
}

function normalizeOwnerHandle(handle: string): string {
  return handle.startsWith("@") ? handle : `@${handle}`;
}

function applyEnvironmentDefaults(
  environment: EnvironmentConfig,
  fallbackReviewers: string[],
  defaultBranch: string,
  name: "dev" | "stage" | "prod"
): EnvironmentConfig {
  const reviewers =
    environment.requireApproval && environment.reviewers.length === 0
      ? [...fallbackReviewers]
      : [...environment.reviewers];
  const branches =
    name === "prod" && environment.branches.length === 0 ? [defaultBranch] : [...environment.branches];

  return {
    ...environment,
    reviewers,
    branches
  };
}

function normalizeCodeowners(
  codeowners: CodeownerRule[],
  fallbackReviewers: string[]
): CodeownerRule[] {
  if (codeowners.length > 0) {
    return codeowners.map((rule) => ({
      pattern: rule.pattern,
      owners: rule.owners.map(normalizeOwnerHandle)
    }));
  }

  if (fallbackReviewers.length === 0) {
    return [];
  }

  return [
    {
      pattern: "*",
      owners: fallbackReviewers.map(normalizeOwnerHandle)
    }
  ];
}

export function normalizeManifest(raw: z.input<typeof manifestSchema>): BootstrapManifest {
  const parsed = manifestSchema.parse(raw);
  const reviewers = (parsed.github?.reviewers ?? []).map((reviewer) => reviewer.replace(/^@/, ""));
  const defaultBranch = parsed.project.defaultBranch ?? "main";
  const moduleName = parsed.archetype.moduleName ?? moduleNameForProject(parsed.project.name);
  const github = parsed.github ?? {};
  const repoFeatures = github.repoFeatures ?? {};
  const environments = parsed.environments ?? {};

  const defaultEnvironment = (overrides?: z.input<typeof environmentSchema>): EnvironmentConfig => ({
    reviewers: overrides?.reviewers ?? [],
    requireApproval: overrides?.requireApproval ?? false,
    preventSelfReview: overrides?.preventSelfReview ?? false,
    branches: overrides?.branches ?? []
  });

  return {
    version: 1,
    project: {
      name: parsed.project.name,
      description:
        parsed.project.description ?? "New project bootstrapped with the platform baseline.",
      visibility: parsed.project.visibility ?? "private",
      owner: parsed.project.owner,
      defaultBranch
    },
    archetype: {
      kind: parsed.archetype.kind,
      packageManager: parsed.archetype.packageManager ?? "npm",
      moduleName
    },
    github: {
      createRepo: github.createRepo ?? true,
      reviewers,
      codeowners: normalizeCodeowners(github.codeowners ?? [], reviewers),
      autoMerge: github.autoMerge ?? true,
      deleteBranchOnMerge: github.deleteBranchOnMerge ?? true,
      requiredApprovals: github.requiredApprovals ?? 1,
      dismissStaleReviews: github.dismissStaleReviews ?? true,
      requireCodeOwnerReviews: github.requireCodeOwnerReviews ?? true,
      requireLastPushApproval: github.requireLastPushApproval ?? false,
      enforceLinearHistory: github.enforceLinearHistory ?? true,
      allowMergeCommit: github.allowMergeCommit ?? true,
      allowSquashMerge: github.allowSquashMerge ?? true,
      allowRebaseMerge: github.allowRebaseMerge ?? false,
      repoFeatures: {
        hasIssues: repoFeatures.hasIssues ?? true,
        hasProjects: repoFeatures.hasProjects ?? false,
        hasWiki: repoFeatures.hasWiki ?? false,
        hasDiscussions: repoFeatures.hasDiscussions ?? false
      }
    },
    ci: {
      runnerPolicy: parsed.ci?.runnerPolicy ?? "hybrid-safe",
      nodeVersion: parsed.ci?.nodeVersion ?? "20",
      pythonVersion: parsed.ci?.pythonVersion ?? "3.12",
      fastChecks: parsed.ci?.fastChecks ?? ["lint", "typecheck", "unit", "build", "secrets"],
      extendedChecks: parsed.ci?.extendedChecks ?? ["integration", "release-readiness"],
      nightlyCron: parsed.ci?.nightlyCron ?? "0 7 * * *"
    },
    agents: {
      manageCodexHome: parsed.agents?.manageCodexHome ?? true,
      manageClaudeHome: parsed.agents?.manageClaudeHome ?? true,
      codexProfile: parsed.agents?.codexProfile ?? "default",
      claudeProfile: parsed.agents?.claudeProfile ?? "default",
      enableClaudeWebEnvironment: parsed.agents?.enableClaudeWebEnvironment ?? true,
      enableClaudeDevcontainer: parsed.agents?.enableClaudeDevcontainer ?? true,
      enableClaudeGitHubAction: parsed.agents?.enableClaudeGitHubAction ?? true,
      sharedSkills: parsed.agents?.sharedSkills ?? []
    },
    environments: {
      dev: applyEnvironmentDefaults(defaultEnvironment(environments.dev), reviewers, defaultBranch, "dev"),
      stage: applyEnvironmentDefaults(
        defaultEnvironment({
          requireApproval: true,
          preventSelfReview: true,
          ...environments.stage
        }),
        reviewers,
        defaultBranch,
        "stage"
      ),
      prod: applyEnvironmentDefaults(
        defaultEnvironment({
          requireApproval: true,
          preventSelfReview: true,
          ...environments.prod
        }),
        reviewers,
        defaultBranch,
        "prod"
      )
    },
  };
}

export async function loadManifest(manifestPath: string): Promise<BootstrapManifest> {
  const raw = await readTextIfExists(manifestPath);
  if (!raw) {
    throw new Error(`Manifest not found: ${manifestPath}`);
  }

  const parsed = YAML.parse(raw);
  return normalizeManifest(parsed);
}

interface ManifestOverrides {
  project?: Partial<BootstrapManifest["project"]>;
  archetype?: Partial<BootstrapManifest["archetype"]>;
  github?: Partial<BootstrapManifest["github"]>;
  ci?: Partial<BootstrapManifest["ci"]>;
  agents?: Partial<BootstrapManifest["agents"]>;
  environments?: Partial<BootstrapManifest["environments"]>;
}

export function createSampleManifest(overrides?: ManifestOverrides): string {
  const manifest = normalizeManifest({
    version: 1,
    project: {
      name: overrides?.project?.name ?? "example-project",
      description:
        overrides?.project?.description ??
        "New project bootstrapped with repo governance, agent setup, and split CI.",
      visibility: overrides?.project?.visibility ?? "private",
      owner: overrides?.project?.owner ?? "your-org",
      defaultBranch: overrides?.project?.defaultBranch ?? "main"
    },
    archetype: {
      kind: overrides?.archetype?.kind ?? "node-ts-service",
      packageManager: overrides?.archetype?.packageManager ?? "npm"
    },
    github: overrides?.github,
    ci: overrides?.ci,
    agents: overrides?.agents,
    environments: overrides?.environments
  });

  return YAML.stringify(manifest, {
    lineWidth: 100
  });
}

export function stringifyManifest(manifest: BootstrapManifest): string {
  return YAML.stringify(manifest, {
    lineWidth: 100
  });
}

export function resolveManifestPath(input?: string): string {
  return input ? path.resolve(input) : path.resolve("project.bootstrap.yaml");
}
