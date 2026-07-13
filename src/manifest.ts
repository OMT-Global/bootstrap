import path from "node:path";
import YAML from "yaml";
import { z } from "zod";

import { readTextIfExists } from "./lib/fs.js";
import type {
  AdditionalWorkflowConfig,
  DependabotConfig,
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
  { name: "lane:pheidon", color: "b3de69", description: "Orchestration, gate, governance, and explicit controller action." },
  { name: "state:intake", color: "d9d9d9", description: "Captured but not yet planned." },
  { name: "state:ready-for-planning", color: "ccebc5", description: "Ready for Apollo/Pheidon planning refinement." },
  { name: "state:ready-for-implementation", color: "bc80bd", description: "Issue has enough contract to assign implementation." },
  { name: "state:implementing", color: "80b1d3", description: "Worker lane is actively implementing." },
  { name: "state:needs-review", color: "ffffb3", description: "PR needs review." },
  { name: "state:needs-repair", color: "fb8072", description: "PR or issue needs repair before it can advance." },
  { name: "state:repairing", color: "fdb462", description: "Repair is actively assigned." },
  { name: "state:ready-for-approval", color: "b3de69", description: "Pheidon/gate approval is the next action." },
  { name: "state:waiting-checks", color: "ffffb3", description: "Approved or ready but waiting on checks/merge queue." },
  { name: "state:auto-merge-armed", color: "b3de69", description: "Auto-merge is enabled and GitHub gates own completion." },
  { name: "state:blocked-human", color: "e41a1c", description: "Human decision required." },
  { name: "state:blocked-infra", color: "984ea3", description: "Blocked by tool, auth, runner, or infrastructure failure." },
  { name: "state:blocked-scope", color: "ff7f00", description: "Blocked by unclear scope or acceptance criteria." },
  { name: "state:paused", color: "999999", description: "Intentionally paused." },
  { name: "autonomy:observe", color: "d9d9d9", description: "Class 0; observe only." },
  { name: "autonomy:safe", color: "b3de69", description: "Class 1; safe autonomous work allowed." },
  { name: "autonomy:review-gated", color: "ffffb3", description: "Class 2; autonomous work allowed, review/gate required." },
  { name: "autonomy:human-required", color: "fb8072", description: "Class 3; human decision required before action/merge." },
  { name: "autonomy:forbidden-unattended", color: "000000", description: "Class 4; must not run unattended." },
  { name: "kind:feature", color: "80b1d3", description: "Feature/product behavior work." },
  { name: "kind:bug", color: "fb8072", description: "Bug fix." },
  { name: "kind:test", color: "ffffb3", description: "Test/validation work." },
  { name: "kind:ci", color: "fdb462", description: "CI/build/tooling work." },
  { name: "kind:docs", color: "ccebc5", description: "Documentation work." },
  { name: "kind:governance", color: "bc80bd", description: "Policy, flow, bootstrap, or governance work." },
  { name: "priority:p0", color: "e41a1c", description: "Critical/urgent." },
  { name: "priority:p1", color: "ff7f00", description: "High priority." },
  { name: "priority:p2", color: "ffff33", description: "Normal priority." },
  { name: "priority:p3", color: "999999", description: "Low priority/backlog." }
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

const repoDocsSchema = z.object({
  readme: z.boolean().optional(),
  contributing: z.boolean().optional(),
  security: z.boolean().optional()
});

const repoTemplatesSchema = z.object({
  pullRequest: z.enum(["standard", "none"]).optional(),
  issueTemplates: z.array(z.string().min(1)).optional()
});

const repoEnvSchema = z.object({
  exampleFile: z.boolean().optional(),
  strategy: z.enum(["required", "optional", "none"]).optional()
});

const repoHooksSchema = z.object({
  preCommit: z.enum(["standard", "none"]).optional(),
  prePush: z.enum(["standard", "none"]).optional()
});

const githubSecuritySchema = z.object({
  dependabot: z.boolean().optional(),
  secretScanningHints: z.boolean().optional()
});

const ciWorkflowsSchema = z.object({
  prFastCi: z.boolean().optional(),
  extendedValidation: z.boolean().optional(),
  claude: z.boolean().optional(),
  pagesDeploy: z.boolean().optional(),
  ci: z.boolean().optional(),
  extras: z.array(additionalWorkflowSchema).optional()
});

const capabilitiesSchema = z.object({
  pages: z
    .object({
      enabled: z.boolean().optional(),
      provider: z.string().min(1).optional(),
      outputDir: z.string().min(1).optional()
    })
    .optional(),
  release: z
    .object({
      enabled: z.boolean().optional(),
      kind: z.string().min(1).optional()
    })
    .optional(),
  docsPublish: z
    .object({
      enabled: z.boolean().optional()
    })
    .optional(),
  containers: z
    .object({
      enabled: z.boolean().optional()
    })
    .optional()
});

const policySchema = z.object({
  flow: z.object({
    ref: z.string().min(1),
    sha256: z.string().regex(/^[0-9a-fA-F]{64}$/),
    bundlePath: z.string().min(1)
  })
});

const dependabotEcosystemSchema = z.object({
  packageEcosystem: z.enum(["npm", "github-actions", "docker"]),
  directory: z.string().min(1).optional(),
  interval: z.enum(["daily", "weekly", "monthly"]).optional(),
  groupMinorAndPatch: z.boolean().optional(),
  ignoreMajorUpdates: z.boolean().optional()
});

const dependabotSchema = z.object({
  enabled: z.boolean().optional(),
  securityUpdates: z.boolean().optional(),
  versionUpdates: z.boolean().optional(),
  ecosystems: z.array(dependabotEcosystemSchema).optional()
});

const macosCheckSchema = z.object({
  enabled: z.boolean().optional(),
  paths: z.array(z.string().min(1)).optional(),
  runsOn: z.array(z.string().min(1)).optional(),
  command: z.string().min(1).optional()
});

const customScriptsSchema = z.object({
  fast: z.string().min(1).optional(),
  extended: z.string().min(1).optional(),
  releaseVerification: z.string().min(1).optional()
});

const DEFAULT_RELEASE_CHANGELOG_CATEGORIES = [
  { title: "Features", labels: ["type:feature"] },
  { title: "Fixes", labels: ["type:bug"] },
  { title: "Operations", labels: ["area:infra", "area:qa"] },
  { title: "Documentation", labels: ["kind:docs", "documentation"] }
];

const releaseChangelogCategorySchema = z.object({
  title: z.string().min(1),
  labels: z.array(z.string().min(1)).min(1)
});

const releaseChangelogSchema = z.object({
  enabled: z.boolean().optional(),
  mode: z.enum(["github-generated-notes"]).optional(),
  categories: z.array(releaseChangelogCategorySchema).optional()
});

const releaseVersionSchema = z.object({
  type: z.enum(["npm", "python", "container"]),
  path: z.string().min(1)
});

const releaseArtifactSchema = z.object({
  directory: z.string().min(1).optional(),
  checksum: z.enum(["sha256", "none"]).optional(),
  sbom: z.enum(["required", "optional", "disabled"]).optional()
});

const releaseContainerPublishSchema = z.object({
  image: z.string().min(1),
  updateMajorTag: z.boolean().optional(),
  updateMinorTag: z.boolean().optional(),
  updateLatestTag: z.boolean().optional()
});

const releasePublishSchema = z.object({
  githubReleaseAssets: z.boolean().optional(),
  packages: z.array(z.string().min(1)).optional(),
  containers: z.array(releaseContainerPublishSchema).optional()
});

const manifestSchema = z.object({
  version: z.union([z.literal(1), z.literal(2)]).optional(),
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
      class: z.enum(["application", "library", "service", "tooling", "documentation"]).optional(),
      managedPaths: z.array(z.string().min(1)).optional(),
      docs: repoDocsSchema.optional(),
      templates: repoTemplatesSchema.optional(),
      env: repoEnvSchema.optional(),
      hooks: repoHooksSchema.optional()
    })
    .optional(),
  archetype: z.object({
    kind: z.enum(["nextjs-web", "node-ts-service", "python-service", "generic-empty"]),
    packageManager: z.enum(["npm", "pnpm", "yarn", "python"]).optional(),
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
        .optional(),
      security: githubSecuritySchema.optional()
    })
    .optional(),
  ci: z
    .object({
      policy: z.enum(["standard", "standard-public", "experimental", "strict"]).optional(),
      runnerPolicy: z.enum(["hybrid-safe", "self-hosted-first", "github-hosted-first"]).optional(),
      nodeVersion: z.string().optional(),
      pythonVersion: z.string().optional(),
      fastChecks: z.array(z.string()).optional(),
      extendedChecks: z.array(z.string()).optional(),
      nightlyCron: z.string().optional(),
      workflows: ciWorkflowsSchema.optional(),
      additionalWorkflows: z.array(additionalWorkflowSchema).optional(),
      appPaths: z.array(z.string().min(1)).optional(),
      ciPaths: z.array(z.string().min(1)).optional(),
      extendedPaths: z.array(z.string().min(1)).optional(),
      macosCheck: macosCheckSchema.optional(),
      customScripts: customScriptsSchema.optional(),
      dependabot: dependabotSchema.optional(),
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
      maturity: z.enum(["none", "simple", "governed", "regulated"]).optional(),
      tagPrefix: z.string().min(1).optional(),
      createGitHubRelease: z.boolean().optional(),
      updateMajorTag: z.boolean().optional(),
      updateMinorTag: z.boolean().optional(),
      reusableWorkflowRepo: z.string().min(1).optional(),
      reusableWorkflowRef: z.string().min(1).optional(),
      changelog: releaseChangelogSchema.optional(),
      versions: z.array(releaseVersionSchema).optional(),
      artifacts: releaseArtifactSchema.optional(),
      publish: releasePublishSchema.optional()
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
  capabilities: capabilitiesSchema.optional(),
  policy: policySchema.optional(),
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

function mergeAdditionalWorkflows(
  additionalWorkflows: AdditionalWorkflowConfig[],
  extras: AdditionalWorkflowConfig[]
): AdditionalWorkflowConfig[] {
  const seen = new Set<string>();
  return [...additionalWorkflows, ...extras].filter((workflow) => {
    if (seen.has(workflow.path)) return false;
    seen.add(workflow.path);
    return true;
  });
}

function normalizeRepo(repo: z.input<typeof manifestSchema>["repo"]): BootstrapManifest["repo"] {
  return {
    ...(repo?.class ? { class: repo.class } : {}),
    managedPaths: repo?.managedPaths ?? [],
    ...(repo?.docs
      ? {
          docs: {
            readme: repo.docs.readme ?? true,
            contributing: repo.docs.contributing ?? true,
            security: repo.docs.security ?? false
          }
        }
      : {}),
    ...(repo?.templates
      ? {
          templates: {
            pullRequest: repo.templates.pullRequest ?? "standard",
            issueTemplates: repo.templates.issueTemplates ?? []
          }
        }
      : {}),
    ...(repo?.env
      ? {
          env: {
            exampleFile: repo.env.exampleFile ?? true,
            strategy: repo.env.strategy ?? "optional"
          }
        }
      : {}),
    ...(repo?.hooks
      ? {
          hooks: {
            preCommit: repo.hooks.preCommit ?? "standard",
            prePush: repo.hooks.prePush ?? "none"
          }
        }
      : {})
  };
}

function normalizeCiWorkflows(
  workflows: z.input<typeof ciWorkflowsSchema> | undefined
): BootstrapManifest["ci"]["workflows"] | undefined {
  if (!workflows) {
    return undefined;
  }

  return {
    prFastCi: workflows.prFastCi ?? true,
    extendedValidation: workflows.extendedValidation ?? true,
    claude: workflows.claude ?? false,
    pagesDeploy: workflows.pagesDeploy ?? false,
    ci: workflows.ci ?? false,
    extras: normalizeAdditionalWorkflows(workflows.extras)
  };
}

function normalizeCapabilities(
  capabilities: z.input<typeof capabilitiesSchema> | undefined
): BootstrapManifest["capabilities"] | undefined {
  if (!capabilities) {
    return undefined;
  }

  return {
    ...(capabilities.pages
      ? {
          pages: {
            enabled: capabilities.pages.enabled ?? false,
            provider: capabilities.pages.provider ?? "cloudflare-pages",
            outputDir: capabilities.pages.outputDir ?? "dist"
          }
        }
      : {}),
    ...(capabilities.release
      ? {
          release: {
            enabled: capabilities.release.enabled ?? true,
            kind: capabilities.release.kind ?? "github-release"
          }
        }
      : {}),
    ...(capabilities.docsPublish
      ? {
          docsPublish: {
            enabled: capabilities.docsPublish.enabled ?? false
          }
        }
      : {}),
    ...(capabilities.containers
      ? {
          containers: {
            enabled: capabilities.containers.enabled ?? false
          }
        }
      : {})
  };
}

function normalizeDependabot(
  dependabot: z.input<typeof dependabotSchema> | undefined
): DependabotConfig {
  const ecosystems = dependabot?.ecosystems ?? [
    { packageEcosystem: "npm" as const, directory: "/", interval: "weekly" as const },
    { packageEcosystem: "github-actions" as const, directory: "/", interval: "weekly" as const }
  ];

  return {
    enabled: dependabot?.enabled ?? true,
    securityUpdates: dependabot?.securityUpdates ?? true,
    versionUpdates: dependabot?.versionUpdates ?? true,
    ecosystems: ecosystems.map((ecosystem) => ({
      packageEcosystem: ecosystem.packageEcosystem,
      directory: (ecosystem.directory ?? "/").replace(/\\/g, "/"),
      interval: ecosystem.interval ?? "weekly",
      groupMinorAndPatch: ecosystem.groupMinorAndPatch ?? ecosystem.packageEcosystem === "npm",
      ignoreMajorUpdates: ecosystem.ignoreMajorUpdates ?? true
    }))
  };
}

function normalizePaths(paths: string[] | undefined): string[] {
  return (paths ?? []).map((entry) => entry.replace(/\\/g, "/"));
}

function normalizeMacOSCheck(
  check: z.input<typeof macosCheckSchema> | undefined
): BootstrapManifest["ci"]["macosCheck"] {
  return {
    enabled: check?.enabled ?? false,
    paths: normalizePaths(check?.paths),
    runsOn: check?.runsOn ?? ["macos-14"],
    command: check?.command ?? "xcodebuild -version"
  };
}

function normalizeCustomScripts(
  scripts: z.input<typeof customScriptsSchema> | undefined
): BootstrapManifest["ci"]["customScripts"] {
  return {
    ...(scripts?.fast ? { fast: scripts.fast } : {}),
    ...(scripts?.extended ? { extended: scripts.extended } : {}),
    ...(scripts?.releaseVerification ? { releaseVerification: scripts.releaseVerification } : {})
  };
}

export function normalizeManifest(raw: z.input<typeof manifestSchema>): BootstrapManifest {
  const parsed = manifestSchema.parse(raw);
  const version = parsed.version ?? 1;
  const reviewers = (parsed.github?.reviewers ?? []).map((reviewer) => reviewer.replace(/^@/, ""));
  const defaultBranch = parsed.project.defaultBranch ?? "main";
  const moduleName = parsed.archetype.moduleName ?? moduleNameForProject(parsed.project.name);
  const github = parsed.github ?? {};
  const organization = normalizeOrganization(github.organization);
  const repoFeatures = github.repoFeatures ?? {};
  const flowGovernance = github.flowGovernance ?? false;
  const environments = parsed.environments ?? {};
  const capabilities = normalizeCapabilities(parsed.capabilities);
  const workflows = normalizeCiWorkflows(parsed.ci?.workflows);
  const additionalWorkflows = mergeAdditionalWorkflows(
    normalizeAdditionalWorkflows(parsed.ci?.additionalWorkflows),
    workflows?.extras ?? []
  );
  const releaseEnabled = parsed.release?.enabled ?? capabilities?.release?.enabled ?? true;

  const defaultEnvironment = (overrides?: z.input<typeof environmentSchema>): EnvironmentConfig => ({
    reviewers: overrides?.reviewers ?? [],
    requireApproval: overrides?.requireApproval ?? false,
    preventSelfReview: overrides?.preventSelfReview ?? false,
    branches: overrides?.branches ?? []
  });

  return {
    version,
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
    repo: normalizeRepo(parsed.repo),
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
      },
      ...(github.security
        ? {
            security: {
              dependabot: github.security.dependabot ?? true,
              secretScanningHints: github.security.secretScanningHints ?? true
            }
          }
        : {})
    },
    ci: {
      ...(parsed.ci?.policy ? { policy: parsed.ci.policy } : {}),
      runnerPolicy: parsed.ci?.runnerPolicy ?? "hybrid-safe",
      nodeVersion: parsed.ci?.nodeVersion ?? "20",
      pythonVersion: parsed.ci?.pythonVersion ?? "3.12",
      fastChecks: parsed.ci?.fastChecks ?? ["lint", "typecheck", "unit", "build", "secrets"],
      extendedChecks: parsed.ci?.extendedChecks ?? ["integration", "release-readiness"],
      nightlyCron: parsed.ci?.nightlyCron ?? "0 7 * * *",
      additionalWorkflows,
      ...(workflows ? { workflows } : {}),
      appPaths: normalizePaths(parsed.ci?.appPaths),
      ciPaths: normalizePaths(parsed.ci?.ciPaths),
      extendedPaths: normalizePaths(parsed.ci?.extendedPaths),
      macosCheck: normalizeMacOSCheck(parsed.ci?.macosCheck),
      customScripts: normalizeCustomScripts(parsed.ci?.customScripts),
      dependabot: normalizeDependabot(parsed.ci?.dependabot),
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
      enabled: releaseEnabled,
      maturity: releaseEnabled ? (parsed.release?.maturity ?? "simple") : "none",
      tagPrefix: parsed.release?.tagPrefix ?? "v",
      createGitHubRelease: parsed.release?.createGitHubRelease ?? true,
      updateMajorTag: parsed.release?.updateMajorTag ?? true,
      updateMinorTag: parsed.release?.updateMinorTag ?? true,
      reusableWorkflowRepo: parsed.release?.reusableWorkflowRepo ?? `${parsed.project.owner}/bootstrap`,
      reusableWorkflowRef: parsed.release?.reusableWorkflowRef ?? "refs/heads/main",
      changelog: {
        enabled: parsed.release?.changelog?.enabled ?? true,
        mode: parsed.release?.changelog?.mode ?? "github-generated-notes",
        categories: parsed.release?.changelog?.categories ?? DEFAULT_RELEASE_CHANGELOG_CATEGORIES
      },
      versions: parsed.release?.versions ?? [],
      artifacts: {
        directory: parsed.release?.artifacts?.directory ?? "dist/release",
        checksum: parsed.release?.artifacts?.checksum ?? "sha256",
        sbom: parsed.release?.artifacts?.sbom ?? "optional"
      },
      publish: {
        githubReleaseAssets: parsed.release?.publish?.githubReleaseAssets ?? true,
        packages: parsed.release?.publish?.packages ?? [],
        containers:
          parsed.release?.publish?.containers?.map((container) => ({
            image: container.image,
            updateMajorTag: container.updateMajorTag ?? true,
            updateMinorTag: container.updateMinorTag ?? true,
            updateLatestTag: container.updateLatestTag ?? false
          })) ?? []
      }
    },
    agents: {
      manageCodexHome: parsed.agents?.manageCodexHome ?? true,
      ...(version === 2
        ? {
            manageClaudeHome: parsed.agents?.manageClaudeHome ?? false,
            claudeProfile: parsed.agents?.claudeProfile ?? "default",
            enableClaudeWebEnvironment: parsed.agents?.enableClaudeWebEnvironment ?? false,
            enableClaudeDevcontainer: parsed.agents?.enableClaudeDevcontainer ?? false,
            enableClaudeGitHubAction: parsed.agents?.enableClaudeGitHubAction ?? workflows?.claude ?? false
          }
        : {}),
      codexProfile: parsed.agents?.codexProfile ?? "default",
      sharedSkills: parsed.agents?.sharedSkills ?? []
    },
    ...(capabilities ? { capabilities } : {}),
    ...(parsed.policy
      ? { policy: { flow: { ...parsed.policy.flow, sha256: parsed.policy.flow.sha256.toLowerCase() } } }
      : {}),
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

function serializableManifest(manifest: BootstrapManifest): BootstrapManifest | Record<string, unknown> {
  if (manifest.version !== 2 || !manifest.capabilities?.release) {
    return manifest;
  }

  const { release: _release, ...withoutRelease } = manifest;
  return withoutRelease;
}

export function stringifyManifest(manifest: BootstrapManifest): string {
  return YAML.stringify(serializableManifest(manifest), {
    lineWidth: 100
  });
}

export function resolveManifestPath(input?: string): string {
  return input ? path.resolve(input) : path.resolve("project.bootstrap.yaml");
}
