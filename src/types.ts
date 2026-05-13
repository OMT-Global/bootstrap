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

export interface DependabotEcosystemConfig {
  packageEcosystem: "npm" | "github-actions" | "docker";
  directory: string;
  interval: "daily" | "weekly" | "monthly";
  groupMinorAndPatch: boolean;
  ignoreMajorUpdates: boolean;
}

export interface DependabotConfig {
  enabled: boolean;
  securityUpdates: boolean;
  versionUpdates: boolean;
  ecosystems: DependabotEcosystemConfig[];
}

export interface MacOSCheckConfig {
  enabled: boolean;
  paths: string[];
  runsOn: string[];
  command: string;
}

export interface CustomScriptsConfig {
  fast?: string;
  extended?: string;
  releaseVerification?: string;
}

export type ReleaseChangelogMode = "github-generated-notes";
export type ReleaseVersionType = "npm" | "python" | "container";
export type ReleaseChecksumType = "sha256" | "none";
export type ReleaseSbomMode = "required" | "optional" | "disabled";

export interface ReleaseChangelogCategory {
  title: string;
  labels: string[];
}

export interface ReleaseChangelogConfig {
  enabled: boolean;
  mode: ReleaseChangelogMode;
  categories: ReleaseChangelogCategory[];
}

export interface ReleaseVersionSurface {
  type: ReleaseVersionType;
  path: string;
}

export interface ReleaseArtifactConfig {
  directory: string;
  checksum: ReleaseChecksumType;
  sbom: ReleaseSbomMode;
}

export interface ReleaseContainerPublishConfig {
  image: string;
  updateMajorTag: boolean;
  updateMinorTag: boolean;
  updateLatestTag: boolean;
}

export interface ReleasePublishConfig {
  githubReleaseAssets: boolean;
  packages: string[];
  containers: ReleaseContainerPublishConfig[];
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
    appPaths: string[];
    ciPaths: string[];
    extendedPaths: string[];
    macosCheck: MacOSCheckConfig;
    customScripts: CustomScriptsConfig;
    dependabot: DependabotConfig;
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
    changelog: ReleaseChangelogConfig;
    versions: ReleaseVersionSurface[];
    artifacts: ReleaseArtifactConfig;
    publish: ReleasePublishConfig;
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
