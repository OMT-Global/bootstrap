export type ProjectVisibility = "private" | "public" | "internal";
export type ArchetypeKind = "nextjs-web" | "node-ts-service" | "python-service" | "generic-empty";
export type RunnerPolicy = "hybrid-safe" | "self-hosted-first" | "github-hosted-first";

export interface CodeownerRule {
  pattern: string;
  owners: string[];
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

export interface BootstrapManifest {
  version: 1;
  project: {
    name: string;
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
  };
  agents: {
    manageCodexHome: boolean;
    manageClaudeHome: boolean;
    codexProfile: string;
    claudeProfile: string;
    enableClaudeWebEnvironment: boolean;
    enableClaudeDevcontainer: boolean;
    enableClaudeGitHubAction: boolean;
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
