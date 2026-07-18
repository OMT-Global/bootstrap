import type { BootstrapManifest, PlannedGitHubAction } from "../types.js";
import { GitHubClient } from "./client.js";

interface GitHubRepo {
  name: string;
  full_name: string;
  private: boolean;
  visibility: string;
  allow_auto_merge?: boolean;
  security_and_analysis?: {
    secret_scanning?: { status?: string };
    secret_scanning_push_protection?: { status?: string };
  };
}

interface PrivateVulnerabilityReportingState {
  enabled?: boolean;
}

interface AutomatedSecurityFixesState {
  enabled?: boolean;
  paused?: boolean;
}

interface ActionsVariableState {
  name?: string;
  value?: string;
}

interface CodeScanningAnalysisState {
  error?: string;
  category?: string;
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

interface GitHubLabel {
  name: string;
  color: string;
  description: string | null;
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

function labelEndpoint(manifest: BootstrapManifest, labelName: string): string {
  return `/repos/${manifest.project.owner}/${manifest.project.name}/labels/${encodeURIComponent(labelName)}`;
}

function labelNeedsUpdate(
  desired: BootstrapManifest["github"]["issueLabels"][number],
  existing: GitHubLabel | undefined
): boolean {
  if (!existing) {
    return true;
  }

  return (
    existing.name !== desired.name ||
    existing.color.toLowerCase() !== desired.color.toLowerCase() ||
    (existing.description ?? "") !== desired.description
  );
}

async function getLabel(
  client: GitHubClient,
  manifest: BootstrapManifest,
  labelName: string
): Promise<GitHubLabel | undefined> {
  return client.tryApi<GitHubLabel>("GET", labelEndpoint(manifest, labelName));
}

async function planIssueLabels(
  manifest: BootstrapManifest,
  client: GitHubClient
): Promise<PlannedGitHubAction> {
  const labelStates = await Promise.all(
    manifest.github.issueLabels.map(async (label) => ({
      label,
      existing: await getLabel(client, manifest, label.name)
    }))
  );
  const driftCount = labelStates.filter(({ label, existing }) => labelNeedsUpdate(label, existing)).length;

  return {
    id: driftCount > 0 ? "issue-labels" : "issue-labels-sync",
    description:
      driftCount > 0
        ? `Create or update ${driftCount} issue label(s) for ${manifest.project.owner}/${manifest.project.name}.`
        : `Issue labels for ${manifest.project.owner}/${manifest.project.name} already match the manifest.`
  };
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
      isPrivateVisibility(manifest.project.visibility) &&
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

function publicSecurityEndpoint(manifest: BootstrapManifest, suffix: string): string {
  return `/repos/${manifest.project.owner}/${manifest.project.name}/${suffix}`;
}

function isGitHubCapabilityLimit(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error);
  return /billing plan supports|upgrade to GitHub|not available for (?:this|the current) plan|current plan does not (?:support|expose)|feature is unavailable on (?:this|your) plan/i.test(message);
}

function isPrivateReportingPlanCapabilityLimit(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error);
  return isGitHubCapabilityLimit(error) || /private vulnerability reporting is (?:not available|unavailable) (?:for|on) (?:this|the current) plan/i.test(message);
}

function isCodeScanningPlanCapabilityLimit(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error);
  return isGitHubCapabilityLimit(error) || /GitHub Advanced Security (?:must be|is not) enabled|code scanning is not available (?:for|on) (?:this|the current) plan/i.test(message);
}

async function planPublicSecurity(
  manifest: BootstrapManifest,
  repo: GitHubRepo | undefined,
  client: GitHubClient
): Promise<PlannedGitHubAction | undefined> {
  if (manifest.project.visibility !== "public") return undefined;
  const dependencyReviewVariableEndpoint = publicSecurityEndpoint(manifest, "actions/variables/DEPENDENCY_REVIEW_ENABLED");
  let privateReportingUnavailable = false;
  let codeScanningUnavailable = false;
  const codeScanningEndpoint = publicSecurityEndpoint(
    manifest,
    `code-scanning/analyses?ref=${encodeURIComponent(`refs/heads/${manifest.project.defaultBranch}`)}&tool_name=CodeQL&per_page=100`
  );
  const [alerts, automatedFixes, privateReporting, dependencyReviewVariable, codeScanningAnalyses] = await Promise.all([
    client.tryApi<Record<string, never>>("GET", publicSecurityEndpoint(manifest, "vulnerability-alerts")),
    client.tryApi<AutomatedSecurityFixesState>("GET", publicSecurityEndpoint(manifest, "automated-security-fixes")),
    client.tryApi<PrivateVulnerabilityReportingState>("GET", publicSecurityEndpoint(manifest, "private-vulnerability-reporting")).catch((error) => {
      if (!isPrivateReportingPlanCapabilityLimit(error)) throw error;
      privateReportingUnavailable = true;
      return undefined;
    }),
    client.tryApi<ActionsVariableState>("GET", dependencyReviewVariableEndpoint),
    client.tryApi<CodeScanningAnalysisState[]>("GET", codeScanningEndpoint).catch((error) => {
      if (!isCodeScanningPlanCapabilityLimit(error)) throw error;
      codeScanningUnavailable = true;
      return undefined;
    })
  ]);
  // GitHub returns 204 with no body when alerts are enabled; GitHubClient.api
  // normalizes that successful empty response to {}, while only a 404 becomes undefined.
  const alertsEnabled = alerts !== undefined;
  const successfulCodeScanningCategories = codeScanningAnalyses
    ?.filter((analysis) => analysis.error === "")
    .map((analysis) => analysis.category)
    .filter((category): category is string => Boolean(category)) ?? [];
  const codeScanningVerified = manifest.ci.codeqlLanguages.length > 0 &&
    manifest.ci.codeqlLanguages.every(
      (language) => successfulCodeScanningCategories.some(
        (category) => category.startsWith(".github/workflows/security.yml:codeql/") &&
          category.endsWith(`/language:${language}`)
      )
    );
  const disabled = [
    !alertsEnabled ? "dependency graph and Dependabot alerts" : null,
    dependencyReviewVariable?.value !== "true" ? "dependency review activation" : null,
    automatedFixes?.enabled !== true || automatedFixes.paused === true ? "Dependabot security updates" : null,
    repo?.security_and_analysis?.secret_scanning?.status !== "enabled" ? "secret scanning" : null,
    repo?.security_and_analysis?.secret_scanning_push_protection?.status !== "enabled" ? "push protection" : null,
    !codeScanningVerified ? "code scanning verification" : null,
    privateReporting?.enabled !== true ? "private vulnerability reporting" : null
  ].filter((entry): entry is string => Boolean(entry));
  const unverified = [
    !codeScanningVerified
      ? codeScanningUnavailable
        ? "code scanning is unavailable on the current plan"
        : "a successful CodeQL analysis for every configured language could not be verified on the default branch"
      : null,
    privateReportingUnavailable ? "private vulnerability reporting is unsupported" : null
  ].filter((entry): entry is string => Boolean(entry));

  return {
    id: unverified.length > 0
      ? "security-baseline-unverified"
      : disabled.length === 0
        ? "security-baseline-sync"
        : "security-baseline",
    description: unverified.length > 0
      ? `Security capabilities for ${manifest.project.owner}/${manifest.project.name} remain unverified: ${unverified.join("; ")}. Enable ${disabled.filter((entry) => entry !== "private vulnerability reporting" && entry !== "code scanning verification").join(", ") || "the remaining synchronized controls"}, then capture remediation or an approved waiver for every unsupported capability.`
      : disabled.length === 0
      ? `Public repository security settings for ${manifest.project.owner}/${manifest.project.name} already match the baseline.`
      : `Enable ${disabled.join(", ")} for ${manifest.project.owner}/${manifest.project.name}.`
  };
}

async function applySecurityCapability(
  client: GitHubClient,
  method: "PATCH" | "PUT",
  endpoint: string,
  payload: unknown,
  action: PlannedGitHubAction,
  unsupportedAction: PlannedGitHubAction,
  isUnsupported: (error: unknown) => boolean = isGitHubCapabilityLimit
): Promise<PlannedGitHubAction> {
  try {
    await client.api(method, endpoint, payload);
    return action;
  } catch (error) {
    if (!isUnsupported(error)) throw error;
    return unsupportedAction;
  }
}

async function applyPublicSecurity(
  manifest: BootstrapManifest,
  client: GitHubClient
): Promise<PlannedGitHubAction[]> {
  if (manifest.project.visibility !== "public") return [];
  const repoEndpoint = `/repos/${manifest.project.owner}/${manifest.project.name}`;
  const analysis = await applySecurityCapability(
      client,
      "PATCH",
      repoEndpoint,
      {
        security_and_analysis: {
          secret_scanning: { status: "enabled" },
          secret_scanning_push_protection: { status: "enabled" }
        }
      },
      { id: "security-analysis", description: "Enabled secret scanning and push protection." },
      { id: "security-analysis-unsupported", description: "GitHub rejected one or more scanning controls for the current plan; capture the unsupported capability and retain remediation or an approved waiver." }
    );
  const alerts = await applySecurityCapability(
      client,
      "PUT",
      publicSecurityEndpoint(manifest, "vulnerability-alerts"),
      undefined,
      { id: "security-dependabot-alerts", description: "Enabled dependency graph and Dependabot vulnerability alerts." },
      { id: "security-dependabot-alerts-unsupported", description: "GitHub does not expose dependency graph or Dependabot alerts on the current plan; capture the unsupported capability and remediation." }
    );
  let dependencyReviewActivation: PlannedGitHubAction;
  if (alerts.id === "security-dependabot-alerts") {
    const variableEndpoint = publicSecurityEndpoint(manifest, "actions/variables/DEPENDENCY_REVIEW_ENABLED");
    const existingVariable = await client.tryApi<ActionsVariableState>("GET", variableEndpoint);
    if (existingVariable) {
      await client.api("PATCH", variableEndpoint, { name: "DEPENDENCY_REVIEW_ENABLED", value: "true" });
    } else {
      await client.api("POST", publicSecurityEndpoint(manifest, "actions/variables"), { name: "DEPENDENCY_REVIEW_ENABLED", value: "true" });
    }
    dependencyReviewActivation = { id: "security-dependency-review-activation", description: "Activated dependency review after enabling dependency graph and alerts." };
  } else {
    dependencyReviewActivation = { id: "security-dependency-review-inactive", description: "Dependency review remains inactive because dependency graph and alerts could not be enabled." };
  }
  const automatedFixes = await applySecurityCapability(
      client,
      "PUT",
      publicSecurityEndpoint(manifest, "automated-security-fixes"),
      undefined,
      { id: "security-dependabot-fixes", description: "Enabled Dependabot automated security fixes." },
      { id: "security-dependabot-fixes-unsupported", description: "GitHub does not expose Dependabot automated security fixes on the current plan; capture the unsupported capability and remediation." }
    );
  const privateReporting = await applySecurityCapability(
      client,
      "PUT",
      publicSecurityEndpoint(manifest, "private-vulnerability-reporting"),
      undefined,
      { id: "security-private-reporting", description: "Enabled private vulnerability reporting." },
      { id: "security-private-reporting-unsupported", description: "GitHub does not expose private vulnerability reporting on the current plan; capture the unsupported capability and remediation." },
      isPrivateReportingPlanCapabilityLimit
    );
  return [analysis, alerts, dependencyReviewActivation, automatedFixes, privateReporting];
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
      ...(manifest.project.visibility === "public"
        ? [{ id: "security-baseline-static", description: "Enable existing-repository scanning, dependency alerts, security updates, push protection, and private vulnerability reporting; report plan limitations explicitly." }]
        : []),
      {
        id: "environments",
        description: "Ensure dev, stage, and prod environments exist with reviewer gates and self-review prevention."
      },
      {
        id: "issue-labels",
        description: `Ensure ${manifest.github.issueLabels.length} issue labels exist for issue routing, risk, status, and review gates.`
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
  const securityPlan = await planPublicSecurity(manifest, repo, client);
  if (securityPlan) actions.push(securityPlan);
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
  actions.push(await planIssueLabels(manifest, client));

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
  actions.push(...await applyPublicSecurity(manifest, client));

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

  for (const label of manifest.github.issueLabels) {
    const existingLabel = await getLabel(client, manifest, label.name);
    const payload = {
      name: label.name,
      color: label.color,
      description: label.description
    };

    if (existingLabel) {
      if (labelNeedsUpdate(label, existingLabel)) {
        await client.api("PATCH", labelEndpoint(manifest, existingLabel.name), payload);
      }
    } else {
      await client.api("POST", `/repos/${manifest.project.owner}/${manifest.project.name}/labels`, payload);
    }
  }
  actions.push({
    id: "issue-labels",
    description: `Synced ${manifest.github.issueLabels.length} issue labels.`
  });

  return actions;
}
