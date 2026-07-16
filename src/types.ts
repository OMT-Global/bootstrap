export type ProjectVisibility = "private" | "public" | "internal";
export type ArchetypeKind = "nextjs-web" | "node-ts-service" | "python-service" | "generic-empty";
export type PackageManager = "npm" | "pnpm" | "yarn" | "python";
export type RunnerPolicy = "hybrid-safe" | "self-hosted-first" | "github-hosted-first";
export type DefaultRepositoryPermission = "read" | "write" | "admin" | "none";
export type RepoClass =
  | "cli"
  | "library"
  | "service"
  | "infrastructure"
  | "github-action"
  | "specification"
  | "documentation";
export type LegacyRepoClass = "application" | "tooling";
export type ProductMaturity = "experimental" | "alpha" | "beta" | "stable" | "maintenance" | "archived";
export type CiPolicy = "standard" | "standard-public" | "experimental" | "strict";

export interface PolicyException {
  id: string;
  policy: string;
  scope: string;
  rationale: string;
  approvedBy: string;
  issue: string;
  permanent: boolean;
  expiresAt?: string;
  adr?: string;
}

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
  class?: RepoClass;
  classMigration?: {
    from: LegacyRepoClass;
    target: RepoClass;
  };
  managedPaths: string[];
  docs?: {
    readme: boolean;
    contributing: boolean;
    security?: boolean;
  };
  templates?: {
    pullRequest: "standard" | "none";
    issueTemplates: string[];
  };
  env?: {
    exampleFile: boolean;
    strategy: "required" | "optional" | "none";
  };
  hooks?: {
    preCommit: "standard" | "none";
    prePush: "standard" | "none";
  };
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
export type ReleaseMaturity = "none" | "simple" | "governed" | "regulated";
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
  version: 1 | 2;
  unknownSettings: string[];
  project: {
    name: string;
    displayName?: string;
    description: string;
    maturity?: ProductMaturity;
    visibility: ProjectVisibility;
    owner: string;
    defaultBranch: string;
  };
  repo: RepoConfig;
  archetype: {
    kind: ArchetypeKind;
    packageManager: PackageManager;
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
    security?: {
      dependabot: boolean;
      secretScanningHints: boolean;
    };
  };
  ci: {
    policy?: CiPolicy;
    runnerPolicy: RunnerPolicy;
    nodeVersion: string;
    pythonVersion: string;
    fastChecks: string[];
    extendedChecks: string[];
    nightlyCron: string;
    prGovernance?: {
      enforceAfter: string;
    };
    additionalWorkflows: AdditionalWorkflowConfig[];
    workflows?: {
      prFastCi: boolean;
      extendedValidation: boolean;
      claude: boolean;
      pagesDeploy: boolean;
      ci: boolean;
      extras: AdditionalWorkflowConfig[];
    };
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
    maturity: ReleaseMaturity;
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
    manageClaudeHome?: boolean;
    codexProfile: string;
    claudeProfile?: string;
    enableClaudeWebEnvironment?: boolean;
    enableClaudeDevcontainer?: boolean;
    enableClaudeGitHubAction?: boolean;
    sharedSkills: string[];
  };
  capabilities?: {
    pages?: {
      enabled: boolean;
      provider: string;
      outputDir: string;
    };
    release?: {
      enabled: boolean;
      kind: string;
    };
    docsPublish?: {
      enabled: boolean;
    };
    containers?: {
      enabled: boolean;
    };
  };
  policy?: {
    flow: {
      ref: string;
      sha256: string;
      bundlePath: string;
    };
  };
  exceptions: PolicyException[];
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
