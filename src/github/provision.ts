import type { BootstrapManifest, PlannedGitHubAction } from "../types.js";
import { GitHubClient } from "./client.js";

interface GitHubRepo {
  name: string;
  full_name: string;
  private: boolean;
  visibility: string;
  allow_auto_merge?: boolean;
}

interface GitHubOwner {
  login: string;
  type: "User" | "Organization";
}

interface GitHubOrganizationSettings {
  plan?: {
    name?: string;
  };
  default_repository_permission: string;
  members_can_create_repositories: boolean;
  members_can_create_public_repositories: boolean;
  members_can_create_private_repositories: boolean;
  members_can_create_internal_repositories?: boolean;
  web_commit_signoff_required?: boolean;
  dependabot_alerts_enabled_for_new_repositories: boolean;
  dependabot_security_updates_enabled_for_new_repositories: boolean;
  dependency_graph_enabled_for_new_repositories: boolean;
  secret_scanning_enabled_for_new_repositories: boolean;
  secret_scanning_push_protection_enabled_for_new_repositories: boolean;
}

interface ReviewerIdentity {
  type: "User" | "Team";
  id: number;
}

function requiredStatusChecksLabel(manifest: BootstrapManifest): string {
  return manifest.github.requiredStatusChecks.join(", ");
}

function hasOrganizationPolicy(manifest: BootstrapManifest): boolean {
  return manifest.github.organization !== undefined;
}

function organizationPayload(manifest: BootstrapManifest): Record<string, boolean | string> | undefined {
  const organization = manifest.github.organization;
  if (!organization) {
    return undefined;
  }

  return {
    default_repository_permission: organization.defaultRepositoryPermission,
    members_can_create_repositories: organization.membersCanCreateRepositories,
    members_can_create_public_repositories: organization.membersCanCreatePublicRepositories,
    members_can_create_private_repositories: organization.membersCanCreatePrivateRepositories,
    ...(organization.membersCanCreateInternalRepositories !== undefined
      ? {
          members_can_create_internal_repositories: organization.membersCanCreateInternalRepositories
        }
      : {}),
    ...(organization.webCommitSignoffRequired !== undefined
      ? {
          web_commit_signoff_required: organization.webCommitSignoffRequired
        }
      : {}),
    dependabot_alerts_enabled_for_new_repositories: organization.newRepositorySecurity.dependabotAlerts,
    dependabot_security_updates_enabled_for_new_repositories:
      organization.newRepositorySecurity.dependabotSecurityUpdates,
    dependency_graph_enabled_for_new_repositories: organization.newRepositorySecurity.dependencyGraph,
    secret_scanning_enabled_for_new_repositories: organization.newRepositorySecurity.secretScanning,
    secret_scanning_push_protection_enabled_for_new_repositories:
      organization.newRepositorySecurity.secretScanningPushProtection
  };
}

function organizationNeedsUpdate(
  manifest: BootstrapManifest,
  organization: GitHubOrganizationSettings
): boolean {
  const desired = organizationPayload(manifest);
  if (!desired) {
    return false;
  }

  return Object.entries(desired).some(([key, value]) => organization[key as keyof GitHubOrganizationSettings] !== value);
}

function isEnvironmentProtectionPlanLimit(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error);
  return message.includes("Failed to create the environment protection rule. Please ensure the billing plan supports");
}

function isPrivateVisibility(visibility: BootstrapManifest["project"]["visibility"] | string): boolean {
  return visibility === "private" || visibility === "internal";
}

function organizationPlanDisablesPrivateRepoAutoMerge(
  manifest: BootstrapManifest,
  owner: GitHubOwner,
  organization?: GitHubOrganizationSettings
): boolean {
  return (
    manifest.github.autoMerge &&
    owner.type === "Organization" &&
    isPrivateVisibility(manifest.project.visibility) &&
    organization?.plan?.name?.toLowerCase() === "free"
  );
}

function repoDisablesAutoMerge(manifest: BootstrapManifest, repo: GitHubRepo | undefined): boolean {
  return Boolean(
    manifest.github.autoMerge &&
      repo &&
      isPrivateVisibility(repo.visibility) &&
      repo.allow_auto_merge === false
  );
}

function autoMergeFallbackAction(): PlannedGitHubAction {
  return {
    id: "auto-merge-plan-limited",
    description:
      "Use fallback merge readiness because GitHub auto-merge is unavailable for this private repository on the current plan: required checks must pass or be intentionally skipped, approvals and conversation resolution must be satisfied, no blocking review state may remain, and a maintainer performs the merge manually."
  };
}

function environmentBranchPolicy(
  manifest: BootstrapManifest,
  environmentName: "dev" | "stage" | "prod"
): { protected_branches: boolean; custom_branch_policies: boolean } | undefined {
  const environment = manifest.environments[environmentName];
  if (environment.branches.length === 0) {
    return undefined;
  }

  const onlyDefaultBranch =
    environment.branches.length === 1 && environment.branches[0] === manifest.project.defaultBranch;
  return {
    protected_branches: onlyDefaultBranch,
    custom_branch_policies: !onlyDefaultBranch
  };
}

function parseReviewer(raw: string, fallbackOrg: string): { type: "User" | "Team"; loginOrSlug: string; org?: string } {
  const cleaned = raw.replace(/^@/, "");
  if (cleaned.includes("/")) {
    const [org, slug] = cleaned.split("/", 2);
    if (!org || !slug) {
      throw new Error(`Invalid team reviewer value: ${raw}`);
    }
    return {
      type: "Team",
      org,
      loginOrSlug: slug
    };
  }

  if (cleaned.includes(":")) {
    const [org, slug] = cleaned.split(":", 2);
    if (!org || !slug) {
      throw new Error(`Invalid team reviewer value: ${raw}`);
    }
    return {
      type: "Team",
      org,
      loginOrSlug: slug
    };
  }

  return {
    type: "User",
    loginOrSlug: cleaned,
    org: fallbackOrg
  };
}

async function resolveReviewerIdentity(
  client: GitHubClient,
  reviewer: string,
  owner: string
): Promise<ReviewerIdentity> {
  const parsed = parseReviewer(reviewer, owner);
  if (parsed.type === "Team") {
    const response = await client.api<{ id: number }>(
      "GET",
      `/orgs/${parsed.org}/teams/${parsed.loginOrSlug}`
    );
    return {
      type: "Team",
      id: response.id
    };
  }

  const response = await client.api<{ id: number }>("GET", `/users/${parsed.loginOrSlug}`);
  return {
    type: "User",
    id: response.id
  };
}

async function resolveReviewerIdentities(
  client: GitHubClient,
  reviewers: string[],
  owner: string
): Promise<ReviewerIdentity[]> {
  return Promise.all(reviewers.map((reviewer) => resolveReviewerIdentity(client, reviewer, owner)));
}

async function getOwner(client: GitHubClient, owner: string): Promise<GitHubOwner> {
  return client.api<GitHubOwner>("GET", `/users/${owner}`);
}

async function getOrganizationSettings(
  client: GitHubClient,
  owner: string
): Promise<GitHubOrganizationSettings> {
  return client.api<GitHubOrganizationSettings>("GET", `/orgs/${owner}`);
}

async function getOptionalOrganizationSettings(
  client: GitHubClient,
  owner: string
): Promise<GitHubOrganizationSettings | undefined> {
  try {
    return await getOrganizationSettings(client, owner);
  } catch {
    return undefined;
  }
}

async function getRepo(
  client: GitHubClient,
  owner: string,
  repo: string
): Promise<GitHubRepo | undefined> {
  return client.tryApi<GitHubRepo>("GET", `/repos/${owner}/${repo}`);
}

export async function planGitHub(
  manifest: BootstrapManifest,
  client = new GitHubClient()
): Promise<PlannedGitHubAction[]> {
  const actions: PlannedGitHubAction[] = [];
  const isAvailable = await client.isAvailable();
  const isAuthenticated = isAvailable ? await client.isAuthenticated() : false;

  if (!isAvailable || !isAuthenticated) {
    actions.push(
      {
        id: "github-auth",
        description: "GitHub plan is static because gh is unavailable or not authenticated."
      },
      {
        id: "repo",
        description: `Create or update ${manifest.project.owner}/${manifest.project.name} with repo settings, auto-merge, and branch cleanup.`
      },
      ...(hasOrganizationPolicy(manifest)
        ? [
            {
              id: "organization",
              description:
                "Update organization defaults for repository permission, member repo creation, and new-repo security settings."
            }
          ]
        : []),
      {
        id: "branch-protection",
        description: `Protect ${manifest.project.defaultBranch} with 1 approval, last-push approval, stale-review dismissal, code owner review, linear history, and required status checks ${requiredStatusChecksLabel(manifest)}.`
      },
      {
        id: "environments",
        description: "Ensure dev, stage, and prod environments exist with reviewer gates and self-review prevention."
      }
    );
    return actions;
  }

  const repo = await getRepo(client, manifest.project.owner, manifest.project.name);
  const owner = await getOwner(client, manifest.project.owner);

  let organization: GitHubOrganizationSettings | undefined;
  if (owner.type === "Organization" && hasOrganizationPolicy(manifest)) {
    organization = await getOrganizationSettings(client, manifest.project.owner);
  } else if (owner.type === "Organization") {
    organization = await getOptionalOrganizationSettings(client, manifest.project.owner);
  }

  if (owner.type === "Organization" && hasOrganizationPolicy(manifest) && organization) {
    actions.push({
      id: organizationNeedsUpdate(manifest, organization) ? "organization" : "organization-sync",
      description: organizationNeedsUpdate(manifest, organization)
        ? `Update organization defaults for ${manifest.project.owner}.`
        : `Organization defaults for ${manifest.project.owner} already match the manifest.`
    });
  } else if (owner.type !== "Organization" && hasOrganizationPolicy(manifest)) {
    actions.push({
      id: "organization-skip",
      description: `Skip organization defaults because ${manifest.project.owner} is not an organization owner.`
    });
  }

  actions.push({
    id: "repo",
    description: repo
      ? `Update repo settings for ${manifest.project.owner}/${manifest.project.name}.`
      : `Create repo ${manifest.project.owner}/${manifest.project.name}.`
  });
  if (
    repoDisablesAutoMerge(manifest, repo) ||
    organizationPlanDisablesPrivateRepoAutoMerge(manifest, owner, organization)
  ) {
    actions.push(autoMergeFallbackAction());
  }
  actions.push({
    id: "branch-protection",
    description: `Ensure ${manifest.project.defaultBranch} requires ${manifest.github.requiredApprovals} approval(s), last-push approval, code owners, stale-review dismissal, linear history, and status checks ${requiredStatusChecksLabel(manifest)}.`
  });
  actions.push({
    id: "environments",
    description: `Ensure environments dev, stage, and prod exist with ${manifest.github.reviewers.length} default reviewer target(s).`
  });

  return actions;
}

export async function applyGitHub(
  manifest: BootstrapManifest,
  client = new GitHubClient()
): Promise<PlannedGitHubAction[]> {
  if (!(await client.isAvailable())) {
    throw new Error("gh CLI is not available.");
  }
  if (!(await client.isAuthenticated())) {
    throw new Error("gh CLI is not authenticated. Run `gh auth login` first.");
  }

  const repo = await getRepo(client, manifest.project.owner, manifest.project.name);
  const owner = await getOwner(client, manifest.project.owner);
  const actions: PlannedGitHubAction[] = [];

  let organization: GitHubOrganizationSettings | undefined;
  if (owner.type === "Organization") {
    organization = await getOptionalOrganizationSettings(client, manifest.project.owner);
  }

  if (owner.type === "Organization" && hasOrganizationPolicy(manifest)) {
    const payload = organizationPayload(manifest);
    if (payload) {
      await client.api("PATCH", `/orgs/${manifest.project.owner}`, payload);
      actions.push({
        id: "organization-update",
        description: `Updated organization defaults for ${manifest.project.owner}.`
      });
    }
  } else if (owner.type !== "Organization" && hasOrganizationPolicy(manifest)) {
    actions.push({
      id: "organization-skip",
      description: `Skipped organization defaults because ${manifest.project.owner} is not an organization owner.`
    });
  }

  const visibility: BootstrapManifest["project"]["visibility"] | "private" =
    owner.type === "User" && manifest.project.visibility === "internal"
      ? "private"
      : manifest.project.visibility;

  const repoPayload = {
    name: manifest.project.name,
    description: manifest.project.description,
    private: visibility !== "public",
    visibility,
    allow_auto_merge: manifest.github.autoMerge,
    delete_branch_on_merge: manifest.github.deleteBranchOnMerge,
    has_issues: manifest.github.repoFeatures.hasIssues,
    has_projects: manifest.github.repoFeatures.hasProjects,
    has_wiki: manifest.github.repoFeatures.hasWiki,
    has_discussions: manifest.github.repoFeatures.hasDiscussions,
    allow_merge_commit: manifest.github.allowMergeCommit,
    allow_squash_merge: manifest.github.allowSquashMerge,
    allow_rebase_merge: manifest.github.allowRebaseMerge
  };

  if (!repo && manifest.github.createRepo) {
    const createPayload = {
      ...repoPayload,
      auto_init: true
    };
    if (owner.type === "Organization") {
      await client.api("POST", `/orgs/${manifest.project.owner}/repos`, createPayload);
    } else {
      await client.api("POST", "/user/repos", createPayload);
    }
    await client.api("PATCH", `/repos/${manifest.project.owner}/${manifest.project.name}`, {
      default_branch: manifest.project.defaultBranch
    });
    actions.push({
      id: "repo-create",
      description: `Created repo ${manifest.project.owner}/${manifest.project.name}.`
    });
  } else {
    await client.api("PATCH", `/repos/${manifest.project.owner}/${manifest.project.name}`, {
      ...repoPayload,
      default_branch: manifest.project.defaultBranch
    });
    actions.push({
      id: "repo-update",
      description: `Updated repo settings for ${manifest.project.owner}/${manifest.project.name}.`
    });
  }

  const syncedRepo = await getRepo(client, manifest.project.owner, manifest.project.name);
  if (
    repoDisablesAutoMerge(manifest, syncedRepo) ||
    organizationPlanDisablesPrivateRepoAutoMerge(manifest, owner, organization)
  ) {
    actions.push(autoMergeFallbackAction());
  }

  try {
    await client.api(
      "PUT",
      `/repos/${manifest.project.owner}/${manifest.project.name}/branches/${manifest.project.defaultBranch}/protection`,
      {
        required_status_checks: {
          strict: true,
          contexts: manifest.github.requiredStatusChecks
        },
        enforce_admins: true,
        required_pull_request_reviews: {
          dismiss_stale_reviews: manifest.github.dismissStaleReviews,
          require_code_owner_reviews: manifest.github.requireCodeOwnerReviews,
          required_approving_review_count: manifest.github.requiredApprovals,
          require_last_push_approval: manifest.github.requireLastPushApproval
        },
        restrictions: null,
        required_linear_history: manifest.github.enforceLinearHistory,
        allow_force_pushes: false,
        allow_deletions: false,
        block_creations: false,
        required_conversation_resolution: true,
        lock_branch: false,
        allow_fork_syncing: true
      }
    );
    actions.push({
      id: "branch-protection",
      description: `Applied branch protection to ${manifest.project.defaultBranch}.`
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (message.includes("Upgrade to GitHub Pro or make this repository public")) {
      actions.push({
        id: "branch-protection-blocked",
        description:
          "Skipped branch protection because the current GitHub plan does not allow protected branches on this private repository."
      });
    } else {
      throw error;
    }
  }

  for (const environmentName of ["dev", "stage", "prod"] as const) {
    const environment = manifest.environments[environmentName];
    const reviewers = environment.requireApproval
      ? await resolveReviewerIdentities(client, environment.reviewers, manifest.project.owner)
      : [];
    const environmentEndpoint = `/repos/${manifest.project.owner}/${manifest.project.name}/environments/${environmentName}`;
    const environmentPayload = {
      wait_timer: 0,
      prevent_self_review: environment.preventSelfReview,
      reviewers,
      ...(environmentBranchPolicy(manifest, environmentName)
        ? {
            deployment_branch_policy: environmentBranchPolicy(manifest, environmentName)
          }
        : {})
    };

    try {
      await client.api("PUT", environmentEndpoint, environmentPayload);
      actions.push({
        id: `environment-${environmentName}`,
        description: `Synced ${environmentName} environment protection rules.`
      });
    } catch (error) {
      if (!isEnvironmentProtectionPlanLimit(error)) {
        throw error;
      }

      await client.api("PUT", environmentEndpoint, {});
      actions.push({
        id: `environment-${environmentName}-plan-limited`,
        description: `Created ${environmentName} environment without protection rules because the current GitHub plan does not support protected environments on this private repository.`
      });
    }
  }

  return actions;
}
