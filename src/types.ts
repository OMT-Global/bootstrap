export type ProjectVisibility = "private" | "public" | "internal";
export type ArchetypeKind = "nextjs-web" | "node-ts-service" | "python-service" | "generic-empty";
export type RunnerPolicy = "hybrid-safe" | "self-hosted-first" | "github-hosted-first";
export type DefaultRepositoryPermission = "read" | "write" | "admin" | "none";

export interface CodeownerRule {
  pattern: string;
  owners: string[];
}

export interface IssueLabelConfig {
  name: string;
  color: string;
  description: string;
}

export interface EnvironmentConfig {
  reviewers: string[];
  requireApproval: boolean;
  preventSelfReview: boolean;
  branches: string[];
}

export interface RepoConfig {
  managedPaths: string[];
}

export interface AdditionalWorkflowConfig {
  path: string;
  purpose: string;
}

export interface OrganizationSecurityDefaults {
  dependabotAlerts: boolean;
  dependabotSecurityUpdates: boolean;
  dependencyGraph: boolean;
  secretScanning: boolean;
  secretScanningPushProtection: boolean;
}

export interface OrganizationConfig {
  defaultRepositoryPermission: DefaultRepositoryPermission;
  membersCanCreateRepositories: boolean;
  membersCanCreatePublicRepositories: boolean;
  membersCanCreatePrivateRepositories: boolean;
  membersCanCreateInternalRepositories?: boolean;
  webCommitSignoffRequired?: boolean;
  newRepositorySecurity: OrganizationSecurityDefaults;
}

export interface BootstrapManifest {
  version: 1;
  project: {
    name: string;
    displayName?: string;
    description: string;
    visibility: ProjectVisibility;
    owner: string;
    defaultBranch: string;
  };
  repo: RepoConfig;
  archetype: {
    kind: ArchetypeKind;
    packageManager: "npm" | "pnpm" | "yarn";
    moduleName: string;
  };
  github: {
    createRepo: boolean;
    reviewers: string[];
    codeowners: CodeownerRule[];
    issueLabels: IssueLabelConfig[];
    flowGovernance: boolean;
    organization?: OrganizationConfig;
    autoMerge: boolean;
    deleteBranchOnMerge: boolean;
    requiredApprovals: number;
    requiredStatusChecks: string[];
    dismissStaleReviews: boolean;
    requireCodeOwnerReviews: boolean;
    requireLastPushApproval: boolean;
    enforceLinearHistory: boolean;
    allowMergeCommit: boolean;
    allowSquashMerge: boolean;
    allowRebaseMerge: boolean;
    repoFeatures: {
      hasIssues: boolean;
      hasProjects: boolean;
      hasWiki: boolean;
      hasDiscussions: boolean;
    };
  };
  ci: {
    runnerPolicy: RunnerPolicy;
    nodeVersion: string;
    pythonVersion: string;
    fastChecks: string[];
    extendedChecks: string[];
    nightlyCron: string;
    additionalWorkflows: AdditionalWorkflowConfig[];
    aiAttestation: {
      enabled: boolean;
      artifactName: string;
      retentionDays: number;
      provider: string;
      model: string;
      promptHash: string;
      reusableWorkflowRepo: string;
      reusableWorkflowRef: string;
    };
  };
  release: {
    enabled: boolean;
    tagPrefix: string;
    createGitHubRelease: boolean;
    updateMajorTag: boolean;
    updateMinorTag: boolean;
    reusableWorkflowRepo: string;
    reusableWorkflowRef: string;
  };
  agents: {
    manageCodexHome: boolean;
    codexProfile: string;
    sharedSkills: string[];
  };
  environments: {
    dev: EnvironmentConfig;
    stage: EnvironmentConfig;
    prod: EnvironmentConfig;
  };
}

export interface RenderedFile {
  path: string;
  contents: string;
  executable?: boolean;
  reason: string;
}

export type ChangeType = "create" | "update" | "delete" | "unchanged";

export interface PlannedFileChange {
  path: string;
  type: ChangeType;
  reason: string;
}

export interface RepoState {
  manifestHash: string;
  templateVersion: string;
  managedFiles: Record<string, string>;
}

export interface PlannedGitHubAction {
  id: string;
  description: string;
}

export interface PlannedHomeAction {
  path: string;
  type: ChangeType;
  reason: string;
}

export interface BootstrapPlan {
  repo: PlannedFileChange[];
  github: PlannedGitHubAction[];
  home: PlannedHomeAction[];
}
