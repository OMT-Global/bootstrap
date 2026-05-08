import path from "node:path";
import YAML from "yaml";
import { z } from "zod";

import { readTextIfExists } from "./lib/fs.js";
import type {
  AdditionalWorkflowConfig,
  BootstrapManifest,
  CodeownerRule,
  DefaultRepositoryPermission,
  EnvironmentConfig,
  IssueLabelConfig,
  OrganizationConfig
} from "./types.js";

export const DEFAULT_ISSUE_LABELS: IssueLabelConfig[] = [
  { name: "area:frontend", color: "1f77b4", description: "Frontend and user-interface work." },
  { name: "area:api", color: "2ca02c", description: "API contracts, endpoints, and integrations." },
  { name: "area:data", color: "9467bd", description: "Data models, persistence, migration, and analytics work." },
  { name: "area:ledger", color: "8c564b", description: "Ledger, accounting, transaction, or reconciliation work." },
  { name: "area:rules", color: "bcbd22", description: "Domain rules, policy logic, and decision engines." },
  { name: "area:ai", color: "17becf", description: "AI, agents, prompts, and model integration work." },
  { name: "area:infra", color: "7f7f7f", description: "Infrastructure, CI, deployment, and operations work." },
  { name: "area:security", color: "d62728", description: "Security-sensitive implementation or hardening work." },
  { name: "area:accessibility", color: "e377c2", description: "Accessibility and inclusive UX work." },
  { name: "area:qa", color: "ff7f0e", description: "Quality assurance, test coverage, and release validation." },
  { name: "risk:low", color: "0e8a16", description: "Low implementation or operational risk." },
  { name: "risk:medium", color: "fbca04", description: "Moderate implementation or operational risk." },
  { name: "risk:high", color: "d93f0b", description: "High implementation or operational risk." },
  { name: "risk:domain", color: "5319e7", description: "Domain correctness risk requiring subject-matter review." },
  { name: "risk:security", color: "b60205", description: "Security risk requiring explicit review." },
  { name: "risk:prod", color: "000000", description: "Production impact or rollout risk." },
  { name: "status:needs-spec", color: "cfd3d7", description: "Needs clearer scope, acceptance criteria, or constraints." },
  { name: "status:ready-for-agent", color: "0e8a16", description: "Ready for assigned agent implementation." },
  { name: "status:agent-building", color: "1d76db", description: "Agent implementation is in progress." },
  { name: "status:needs-review", color: "fbca04", description: "Needs review before merge or closure." },
  { name: "status:needs-human-approval", color: "d93f0b", description: "Needs explicit human approval before proceeding." },
  { name: "status:ready-to-merge", color: "0e8a16", description: "Ready to merge after required checks pass." },
  { name: "status:blocked", color: "b60205", description: "Blocked by a dependency, decision, credential, or access gate." },
  { name: "review:product", color: "0052cc", description: "Needs product review." },
  { name: "review:architecture", color: "5319e7", description: "Needs architecture review." },
  { name: "review:security", color: "b60205", description: "Needs security review." },
  { name: "review:tax", color: "d4c5f9", description: "Needs tax review." },
  { name: "review:legal", color: "c2e0c6", description: "Needs legal review." },
  { name: "review:accessibility", color: "e99695", description: "Needs accessibility review." },
  { name: "review:release", color: "f9d0c4", description: "Needs release review." }
 ];

export const DEFAULT_FLOW_LABELS: IssueLabelConfig[] = [
  { name: "lane:apollo", color: "8dd3c7", description: "Scope, backlog, synthesis, and issue-contract work." },
  { name: "lane:ares", color: "fb8072", description: "Validation, adversarial review, and test-pressure work." },
  { name: "lane:daedalus", color: "80b1d3", description: "Implementation and substantive code repair work." },
  { name: "lane:hephaestus", color: "fdb462", description: "CI, build, lockfile, mergeability, and artifact work." },
  { name: "lane:hermes", color: "bebada", description: "macOS/platform-native or special execution work." },
  { name: "lane:pheidon", color: "b3de69", description: "Orchestration, gate, governance, and controller action." },
  { name: "state:intake", color: "d9d9d9", description: "Captured but not yet planned." },
  { name: "state:ready-for-planning", color: "ccebc5", description: "Ready for planning refinement." },
  { name: "state:ready-for-implementation", color: "bc80bd", description: "Ready for assigned implementation." },
  { name: "state:needs-review", color: "ffffb3", description: "Needs review before advancing." },
  { name: "state:needs-repair", color: "fb8072", description: "Needs repair before advancing." },
  { name: "state:repairing", color: "fdb462", description: "Repair is actively assigned." },
  { name: "state:ready-for-approval", color: "b3de69", description: "Pheidon/gate approval is next." },
  { name: "state:waiting-checks", color: "ffffb3", description: "Waiting on checks or merge queue." },
  { name: "state:auto-merge-armed", color: "b3de69", description: "Auto-merge is enabled." },
  { name: "state:blocked-human", color: "e41a1c", description: "Human decision required." },
  { name: "state:blocked-infra", color: "984ea3", description: "Infrastructure/tooling/auth blocker." },
  { name: "state:blocked-scope", color: "ff7f00", description: "Scope or acceptance criteria blocker." },
  { name: "state:paused", color: "999999", description: "Intentionally paused." },
  { name: "autonomy:observe", color: "d9d9d9", description: "Class 0; observe only." },
  { name: "autonomy:safe", color: "b3de69", description: "Class 1; safe autonomous work allowed." },
  { name: "autonomy:review-gated", color: "ffffb3", description: "Class 2; review-gated autonomous work." },
  { name: "autonomy:human-required", color: "fb8072", description: "Class 3; human decision required." },
  { name: "autonomy:forbidden-unattended", color: "000000", description: "Class 4; forbidden unattended." }
];

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

const issueLabelSchema = z.object({
  name: z.string().min(1),
  color: z.string().regex(/^#?[0-9a-fA-F]{6}$/),
  description: z.string().min(1).max(100)
});

const organizationSecuritySchema = z.object({
  dependabotAlerts: z.boolean().optional(),
  dependabotSecurityUpdates: z.boolean().optional(),
  dependencyGraph: z.boolean().optional(),
  secretScanning: z.boolean().optional(),
  secretScanningPushProtection: z.boolean().optional()
});

const organizationSchema = z.object({
  defaultRepositoryPermission: z.enum(["read", "write", "admin", "none"]).optional(),
  membersCanCreateRepositories: z.boolean().optional(),
  membersCanCreatePublicRepositories: z.boolean().optional(),
  membersCanCreatePrivateRepositories: z.boolean().optional(),
  membersCanCreateInternalRepositories: z.boolean().optional(),
  webCommitSignoffRequired: z.boolean().optional(),
  newRepositorySecurity: organizationSecuritySchema.optional()
});

const additionalWorkflowSchema = z.object({
  path: z.string().min(1),
  purpose: z.string().min(1)
});

const manifestSchema = z.object({
  version: z.literal(1).optional(),
  project: z.object({
    name: z.string().min(1),
    displayName: z.string().min(1).optional(),
    description: z.string().optional(),
    visibility: z.enum(["private", "public", "internal"]).optional(),
    owner: z.string().min(1),
    defaultBranch: z.string().min(1).optional()
  }),
  repo: z
    .object({
      managedPaths: z.array(z.string().min(1)).optional()
    })
    .optional(),
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
      issueLabels: z.array(issueLabelSchema).optional(),
      flowGovernance: z.boolean().optional(),
      organization: organizationSchema.optional(),
      autoMerge: z.boolean().optional(),
      deleteBranchOnMerge: z.boolean().optional(),
      requiredApprovals: z.number().int().min(1).max(6).optional(),
      requiredStatusChecks: z.array(z.string().min(1)).min(1).optional(),
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
      nightlyCron: z.string().optional(),
      additionalWorkflows: z.array(additionalWorkflowSchema).optional(),
      aiAttestation: z
        .object({
          enabled: z.boolean().optional(),
          artifactName: z.string().min(1).optional(),
          retentionDays: z.number().int().min(1).max(365).optional(),
          provider: z.string().min(1).optional(),
          model: z.string().min(1).optional(),
          promptHash: z.string().min(1).optional(),
          reusableWorkflowRepo: z.string().min(1).optional(),
          reusableWorkflowRef: z.string().min(1).optional()
        })
        .optional()
    })
    .optional(),
  release: z
    .object({
      enabled: z.boolean().optional(),
      tagPrefix: z.string().min(1).optional(),
      createGitHubRelease: z.boolean().optional(),
      updateMajorTag: z.boolean().optional(),
      updateMinorTag: z.boolean().optional(),
      reusableWorkflowRepo: z.string().min(1).optional(),
      reusableWorkflowRef: z.string().min(1).optional()
    })
    .optional(),
  agents: z
    .object({
      manageCodexHome: z.boolean().optional(),
      codexProfile: z.string().optional(),
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

function normalizeIssueLabels(
  labels: z.input<typeof issueLabelSchema>[] | undefined,
  flowGovernance: boolean
): IssueLabelConfig[] {
  const base = labels ?? DEFAULT_ISSUE_LABELS;
  const merged = flowGovernance ? [...base, ...DEFAULT_FLOW_LABELS] : base;
  const seen = new Set<string>();
  return merged
    .filter((label) => {
      const name = label.name.trim();
      if (seen.has(name)) return false;
      seen.add(name);
      return true;
    })
    .map((label) => ({
      name: label.name.trim(),
      color: label.color.replace(/^#/, "").toLowerCase(),
      description: label.description.trim()
    }));
}

function normalizeOrganization(
  organization: z.input<typeof organizationSchema> | undefined
): OrganizationConfig | undefined {
  if (!organization) {
    return undefined;
  }

  return {
    defaultRepositoryPermission:
      (organization.defaultRepositoryPermission as DefaultRepositoryPermission | undefined) ?? "read",
    membersCanCreateRepositories: organization.membersCanCreateRepositories ?? false,
    membersCanCreatePublicRepositories: organization.membersCanCreatePublicRepositories ?? false,
    membersCanCreatePrivateRepositories: organization.membersCanCreatePrivateRepositories ?? false,
    ...(organization.membersCanCreateInternalRepositories !== undefined
      ? {
          membersCanCreateInternalRepositories: organization.membersCanCreateInternalRepositories
        }
      : {}),
    ...(organization.webCommitSignoffRequired !== undefined
      ? {
          webCommitSignoffRequired: organization.webCommitSignoffRequired
        }
      : {}),
    newRepositorySecurity: {
      dependabotAlerts: organization.newRepositorySecurity?.dependabotAlerts ?? true,
      dependabotSecurityUpdates: organization.newRepositorySecurity?.dependabotSecurityUpdates ?? true,
      dependencyGraph: organization.newRepositorySecurity?.dependencyGraph ?? true,
      secretScanning: organization.newRepositorySecurity?.secretScanning ?? true,
      secretScanningPushProtection: organization.newRepositorySecurity?.secretScanningPushProtection ?? true
    }
  };
}

function normalizeAdditionalWorkflows(
  workflows: z.input<typeof additionalWorkflowSchema>[] | undefined
): AdditionalWorkflowConfig[] {
  return (workflows ?? []).map((workflow) => ({
    path: workflow.path.replace(/\\/g, "/"),
    purpose: workflow.purpose.trim()
  }));
}

export function normalizeManifest(raw: z.input<typeof manifestSchema>): BootstrapManifest {
  const parsed = manifestSchema.parse(raw);
  const reviewers = (parsed.github?.reviewers ?? []).map((reviewer) => reviewer.replace(/^@/, ""));
  const defaultBranch = parsed.project.defaultBranch ?? "main";
  const moduleName = parsed.archetype.moduleName ?? moduleNameForProject(parsed.project.name);
  const github = parsed.github ?? {};
  const organization = normalizeOrganization(github.organization);
  const repoFeatures = github.repoFeatures ?? {};
  const flowGovernance = github.flowGovernance ?? false;
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
      ...(parsed.project.displayName ? { displayName: parsed.project.displayName } : {}),
      description:
        parsed.project.description ??
        "Manifest-first control plane for repo scaffolding, GitHub governance, and portable agent profiles.",
      visibility: parsed.project.visibility ?? "private",
      owner: parsed.project.owner,
      defaultBranch
    },
    repo: {
      managedPaths: parsed.repo?.managedPaths ?? []
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
      issueLabels: normalizeIssueLabels(github.issueLabels, flowGovernance),
      flowGovernance,
      ...(organization ? { organization } : {}),
      autoMerge: github.autoMerge ?? true,
      deleteBranchOnMerge: github.deleteBranchOnMerge ?? true,
      requiredApprovals: github.requiredApprovals ?? 1,
      requiredStatusChecks: github.requiredStatusChecks ?? ["CI Gate"],
      dismissStaleReviews: github.dismissStaleReviews ?? true,
      requireCodeOwnerReviews: github.requireCodeOwnerReviews ?? true,
      requireLastPushApproval: github.requireLastPushApproval ?? true,
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
      nightlyCron: parsed.ci?.nightlyCron ?? "0 7 * * *",
      additionalWorkflows: normalizeAdditionalWorkflows(parsed.ci?.additionalWorkflows),
      aiAttestation: {
        enabled: parsed.ci?.aiAttestation?.enabled ?? false,
        artifactName: parsed.ci?.aiAttestation?.artifactName ?? "ai-attestation",
        retentionDays: parsed.ci?.aiAttestation?.retentionDays ?? 90,
        provider: parsed.ci?.aiAttestation?.provider ?? "unknown",
        model: parsed.ci?.aiAttestation?.model ?? "unknown",
        promptHash: parsed.ci?.aiAttestation?.promptHash ?? "unknown",
        reusableWorkflowRepo:
          parsed.ci?.aiAttestation?.reusableWorkflowRepo ?? `${parsed.project.owner}/bootstrap`,
        reusableWorkflowRef: parsed.ci?.aiAttestation?.reusableWorkflowRef ?? "refs/heads/main"
      }
    },
    release: {
      enabled: parsed.release?.enabled ?? true,
      tagPrefix: parsed.release?.tagPrefix ?? "v",
      createGitHubRelease: parsed.release?.createGitHubRelease ?? true,
      updateMajorTag: parsed.release?.updateMajorTag ?? true,
      updateMinorTag: parsed.release?.updateMinorTag ?? true,
      reusableWorkflowRepo: parsed.release?.reusableWorkflowRepo ?? `${parsed.project.owner}/bootstrap`,
      reusableWorkflowRef: parsed.release?.reusableWorkflowRef ?? "refs/heads/main"
    },
    agents: {
      manageCodexHome: parsed.agents?.manageCodexHome ?? true,
      codexProfile: parsed.agents?.codexProfile ?? "default",
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
  repo?: Partial<BootstrapManifest["repo"]>;
  archetype?: Partial<BootstrapManifest["archetype"]>;
  github?: Partial<BootstrapManifest["github"]>;
  ci?: Partial<BootstrapManifest["ci"]>;
  release?: Partial<BootstrapManifest["release"]>;
  agents?: Partial<BootstrapManifest["agents"]>;
  environments?: Partial<BootstrapManifest["environments"]>;
}

export function createSampleManifest(overrides?: ManifestOverrides): string {
  const manifest = normalizeManifest({
    version: 1,
    project: {
      name: overrides?.project?.name ?? "example-project",
      ...(overrides?.project?.displayName ? { displayName: overrides.project.displayName } : {}),
      description:
        overrides?.project?.description ??
        "Manifest-first control plane for repo scaffolding, GitHub governance, and portable agent profiles.",
      visibility: overrides?.project?.visibility ?? "private",
      owner: overrides?.project?.owner ?? "your-org",
      defaultBranch: overrides?.project?.defaultBranch ?? "main"
    },
    repo: overrides?.repo,
    archetype: {
      kind: overrides?.archetype?.kind ?? "node-ts-service",
      packageManager: overrides?.archetype?.packageManager ?? "npm"
    },
    github: overrides?.github,
    ci: overrides?.ci,
    release: overrides?.release,
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
