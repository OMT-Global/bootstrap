import type { BootstrapManifest, PlannedGitHubAction } from "../types.js";
import { GitHubClient } from "./client.js";

interface GitHubRepo {
  name: string;
  full_name: string;
  private: boolean;
  visibility: string;
}

interface GitHubOwner {
  login: string;
  type: "User" | "Organization";
}

interface ReviewerIdentity {
  type: "User" | "Team";
  id: number;
}

function requiredStatusChecksLabel(manifest: BootstrapManifest): string {
  return manifest.github.requiredStatusChecks.join(", ");
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
      {
        id: "branch-protection",
        description: `Protect ${manifest.project.defaultBranch} with 1 approval, stale-review dismissal, code owner review, linear history, and required status checks ${requiredStatusChecksLabel(manifest)}.`
      },
      {
        id: "environments",
        description: "Ensure dev, stage, and prod environments exist with reviewer gates and self-review prevention."
      }
    );
    return actions;
  }

  const repo = await getRepo(client, manifest.project.owner, manifest.project.name);
  actions.push({
    id: "repo",
    description: repo
      ? `Update repo settings for ${manifest.project.owner}/${manifest.project.name}.`
      : `Create repo ${manifest.project.owner}/${manifest.project.name}.`
  });
  actions.push({
    id: "branch-protection",
    description: `Ensure ${manifest.project.defaultBranch} requires ${manifest.github.requiredApprovals} approval(s), code owners, stale-review dismissal, linear history, and status checks ${requiredStatusChecksLabel(manifest)}.`
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

    await client.api(
      "PUT",
      `/repos/${manifest.project.owner}/${manifest.project.name}/environments/${environmentName}`,
      {
        wait_timer: 0,
        prevent_self_review: environment.preventSelfReview,
        reviewers,
        ...(environmentBranchPolicy(manifest, environmentName)
          ? {
              deployment_branch_policy: environmentBranchPolicy(manifest, environmentName)
            }
          : {})
      }
    );
    actions.push({
      id: `environment-${environmentName}`,
      description: `Synced ${environmentName} environment protection rules.`
    });
  }

  return actions;
}
