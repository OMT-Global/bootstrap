import { describe, expect, it } from "vitest";

import { applyGitHub, planGitHub } from "../src/github/provision.js";
import { GitHubClient } from "../src/github/client.js";
import { DEFAULT_ISSUE_LABELS, normalizeManifest } from "../src/manifest.js";
import type { CommandResult, CommandRunner } from "../src/lib/process.js";

const PUBLIC_REPO_ENDPOINT = "/repos/acme/example";
const CODE_SCANNING_ENDPOINT = `${PUBLIC_REPO_ENDPOINT}/code-scanning/analyses?ref=refs%2Fheads%2Fmain&tool_name=CodeQL&per_page=100`;

function publicManifest(createRepo?: boolean) {
  return normalizeManifest({
    project: { name: "example", owner: "acme", visibility: "public" },
    archetype: { kind: "node-ts-service" },
    ...(createRepo === undefined ? {} : { github: { createRepo } })
  });
}

function publicRepo(scanning?: "enabled" | "disabled") {
  return {
    name: "example",
    full_name: "acme/example",
    private: false,
    visibility: "public",
    ...(scanning
      ? {
          security_and_analysis: {
            secret_scanning: { status: scanning },
            secret_scanning_push_protection: { status: scanning }
          }
        }
      : {})
  };
}

function publicPlanClient(
  resolve: (endpoint: string) => unknown | Promise<unknown>,
  repo: unknown = publicRepo()
) {
  return {
    isAvailable: async () => true,
    isAuthenticated: async () => true,
    tryApi: async (_method: string, endpoint: string) => endpoint === PUBLIC_REPO_ENDPOINT ? repo : resolve(endpoint),
    api: async (_method: string, endpoint: string) => endpoint === "/users/acme" ? { login: "acme", type: "Organization" } : {}
  };
}

describe("GitHub provisioning", () => {
  it("includes optional release-publish in the static plan without claiming live protection", async () => {
    const manifest = normalizeManifest({
      project: { name: "example", owner: "acme" },
      archetype: { kind: "generic-empty" },
      environments: {
        "release-publish": {
          reviewers: ["alice"], requireApproval: true, preventSelfReview: true, branches: ["main"]
        }
      }
    } as never);
    const actions = await planGitHub(manifest, {
      isAvailable: async () => false,
      isAuthenticated: async () => false
    } as never);
    const release = actions.find((action) => action.id === "environment-release-publish");
    expect(release).toBeDefined();
    expect(release?.description).toContain("create or verify");
    expect(release?.description).toContain("protected branches");
    expect(release?.description).toContain("unverified");
  });

  it("produces a static plan when gh is unavailable", async () => {
    const manifest = normalizeManifest({
      project: {
        name: "example",
        owner: "acme"
      },
      archetype: {
        kind: "node-ts-service"
      },
      github: {
        requiredStatusChecks: ["test"]
      }
    });

    const actions = await planGitHub(manifest, {
      isAvailable: async () => false,
      isAuthenticated: async () => false
    } as never);

    expect(actions.map((action) => action.id)).toContain("github-auth");
    expect(actions.map((action) => action.id)).toContain("branch-protection");
    expect(actions.map((action) => action.id)).toContain("issue-labels");
  });

  it("applies repo settings, branch protection, and environments through gh api", async () => {
    const manifest = normalizeManifest({
      project: {
        name: "example",
        owner: "acme"
      },
      archetype: {
        kind: "node-ts-service"
      },
      github: {
        reviewers: ["alice"],
        requiredStatusChecks: ["test", "lint"],
        organization: {
          defaultRepositoryPermission: "read",
          membersCanCreateRepositories: false,
          membersCanCreatePublicRepositories: false,
          membersCanCreatePrivateRepositories: false,
          newRepositorySecurity: {
            dependencyGraph: true,
            dependabotAlerts: true,
            dependabotSecurityUpdates: true,
            secretScanning: true,
            secretScanningPushProtection: true
          }
        }
      }
    });

    const calls: Array<{ method: string; endpoint: string; payload?: unknown }> = [];
    const client = {
      isAvailable: async () => true,
      isAuthenticated: async () => true,
      tryApi: async (method: string, endpoint: string) => {
        calls.push({ method, endpoint });
        if (endpoint === "/repos/acme/example") {
          return undefined;
        }
        if (endpoint.startsWith("/repos/acme/example/labels/")) {
          return undefined;
        }
        return undefined;
      },
      api: async (method: string, endpoint: string, payload?: unknown) => {
        calls.push({ method, endpoint, payload });
        if (endpoint === "/users/acme") {
          return { login: "acme", type: "Organization" };
        }
        if (endpoint === "/users/alice") {
          return { id: 7 };
        }
        return {};
      }
    };

    const actions = await applyGitHub(manifest, client as never);
    expect(actions.map((action) => action.id)).toContain("organization-update");
    expect(actions.map((action) => action.id)).toContain("repo-create");
    expect(actions.map((action) => action.id)).toContain("issue-labels");
    expect(calls.some((call) => call.endpoint === "/orgs/acme" && call.method === "PATCH")).toBe(true);
    expect(calls.some((call) => call.endpoint === "/orgs/acme/repos" && call.method === "POST")).toBe(true);
    expect(
      calls.some(
        (call) =>
          call.endpoint === "/repos/acme/example/branches/main/protection" && call.method === "PUT"
      )
    ).toBe(true);
    const protectionCall = calls.find(
      (call) => call.endpoint === "/repos/acme/example/branches/main/protection" && call.method === "PUT"
    );
    expect(protectionCall?.payload).toMatchObject({
      required_status_checks: {
        strict: true,
        contexts: ["test", "lint"]
      },
      required_pull_request_reviews: {
        require_last_push_approval: true
      }
    });
    expect(
      calls.some(
        (call) => call.endpoint === "/repos/acme/example/environments/prod" && call.method === "PUT"
      )
    ).toBe(true);
    expect(
      calls.filter((call) => call.endpoint === "/repos/acme/example/labels" && call.method === "POST")
    ).toHaveLength(DEFAULT_ISSUE_LABELS.length);
  });

  it("reports org-policy drift in the GitHub plan when organization defaults differ", async () => {
    const manifest = normalizeManifest({
      project: {
        name: "example",
        owner: "acme"
      },
      archetype: {
        kind: "generic-empty"
      },
      github: {
        organization: {
          defaultRepositoryPermission: "read",
          membersCanCreateRepositories: false,
          membersCanCreatePublicRepositories: false,
          membersCanCreatePrivateRepositories: false,
          newRepositorySecurity: {
            dependencyGraph: true,
            dependabotAlerts: true,
            dependabotSecurityUpdates: true,
            secretScanning: true,
            secretScanningPushProtection: true
          }
        }
      }
    });

    const actions = await planGitHub(
      manifest,
      {
        isAvailable: async () => true,
        isAuthenticated: async () => true,
        tryApi: async (method: string, endpoint: string) => {
          if (endpoint === "/repos/acme/example") {
            return undefined;
          }
          if (endpoint.startsWith("/repos/acme/example/labels/")) {
            return undefined;
          }
          return undefined;
        },
        api: async (method: string, endpoint: string) => {
          if (endpoint === "/users/acme") {
            return { login: "acme", type: "Organization" };
          }
          if (endpoint === "/orgs/acme") {
            return {
              default_repository_permission: "write",
              members_can_create_repositories: true,
              members_can_create_public_repositories: true,
              members_can_create_private_repositories: true,
              dependabot_alerts_enabled_for_new_repositories: false,
              dependabot_security_updates_enabled_for_new_repositories: false,
              dependency_graph_enabled_for_new_repositories: false,
              secret_scanning_enabled_for_new_repositories: false,
              secret_scanning_push_protection_enabled_for_new_repositories: false
            };
          }
          return {};
        }
      } as never
    );

    expect(actions.find((action) => action.id === "organization")?.description).toContain(
      "Update organization defaults for acme."
    );
    expect(actions.find((action) => action.id === "issue-labels")?.description).toContain(
      `Create or update ${DEFAULT_ISSUE_LABELS.length} issue label(s)`
    );
  });

  it("plans fallback merge readiness when GitHub Free cannot auto-merge private repos", async () => {
    const manifest = normalizeManifest({
      project: {
        name: "example",
        owner: "acme",
        visibility: "private"
      },
      archetype: {
        kind: "generic-empty"
      },
      github: {
        autoMerge: true
      }
    });

    const actions = await planGitHub(
      manifest,
      {
        isAvailable: async () => true,
        isAuthenticated: async () => true,
        tryApi: async (method: string, endpoint: string) => {
          if (endpoint === "/repos/acme/example") {
            return {
              name: "example",
              full_name: "acme/example",
              private: true,
              visibility: "private",
              allow_auto_merge: false
            };
          }
          return undefined;
        },
        api: async (method: string, endpoint: string) => {
          if (endpoint === "/users/acme") {
            return { login: "acme", type: "Organization" };
          }
          if (endpoint === "/orgs/acme") {
            return { plan: { name: "free" } };
          }
          return {};
        }
      } as never
    );

    const fallback = actions.find((action) => action.id === "auto-merge-plan-limited");
    expect(fallback?.description).toContain("fallback merge readiness");
    expect(fallback?.description).toContain("maintainer performs the merge manually");
  });

  it("does not plan fallback merge readiness when making a private repo public", async () => {
    const manifest = normalizeManifest({
      project: {
        name: "example",
        owner: "acme",
        visibility: "public"
      },
      archetype: {
        kind: "generic-empty"
      },
      github: {
        autoMerge: true
      }
    });

    const actions = await planGitHub(
      manifest,
      {
        isAvailable: async () => true,
        isAuthenticated: async () => true,
        tryApi: async (method: string, endpoint: string) => {
          if (endpoint === "/repos/acme/example") {
            return {
              name: "example",
              full_name: "acme/example",
              private: true,
              visibility: "private",
              allow_auto_merge: false
            };
          }
          return undefined;
        },
        api: async (method: string, endpoint: string) => {
          if (endpoint === "/users/acme") {
            return { login: "acme", type: "Organization" };
          }
          if (endpoint === "/orgs/acme") {
            return { plan: { name: "free" } };
          }
          return {};
        }
      } as never
    );

    expect(actions.map((action) => action.id)).not.toContain("auto-merge-plan-limited");
  });

  it("falls back to bare environments when private-repo protection rules are unsupported", async () => {
    const manifest = normalizeManifest({
      project: {
        name: "example",
        owner: "acme",
        visibility: "private"
      },
      archetype: {
        kind: "generic-empty"
      },
      github: {
        createRepo: false,
        reviewers: ["alice"]
      }
    });

    const calls: Array<{ method: string; endpoint: string; payload?: unknown }> = [];
    const client = {
      isAvailable: async () => true,
      isAuthenticated: async () => true,
      tryApi: async (method: string, endpoint: string) => {
        if (endpoint.startsWith("/repos/acme/example/labels/")) {
          return undefined;
        }
        return { name: "example", full_name: "acme/example", private: true, visibility: "private" };
      },
      api: async (method: string, endpoint: string, payload?: unknown) => {
        calls.push({ method, endpoint, payload });
        if (endpoint === "/users/acme") {
          return { login: "acme", type: "Organization" };
        }
        if (endpoint === "/users/alice") {
          return { id: 7 };
        }
        if (
          (endpoint === "/repos/acme/example/environments/stage" ||
            endpoint === "/repos/acme/example/environments/prod") &&
          payload &&
          typeof payload === "object" &&
          "reviewers" in payload
        ) {
          throw new Error(
            "gh: Failed to create the environment protection rule. Please ensure the billing plan supports the required reviewers protection rule. (HTTP 422)"
          );
        }
        if (
          endpoint === "/repos/acme/example/branches/main/protection" &&
          method === "PUT"
        ) {
          throw new Error(
            "gh: Upgrade to GitHub Pro or make this repository public to enable this feature. (HTTP 403)"
          );
        }
        return {};
      }
    };

    const actions = await applyGitHub(manifest, client as never);
    expect(actions.map((action) => action.id)).toContain("branch-protection-blocked");
    expect(actions.map((action) => action.id)).toContain("environment-stage-plan-limited");
    expect(actions.map((action) => action.id)).toContain("environment-prod-plan-limited");
    expect(
      calls.filter((call) => call.endpoint === "/repos/acme/example/environments/stage").map((call) => call.payload)
    ).toEqual([
      expect.objectContaining({
        reviewers: [{ type: "User", id: 7 }]
      }),
      {}
    ]);
  });

  it("reports fallback merge readiness after apply when auto-merge remains disabled", async () => {
    const manifest = normalizeManifest({
      project: {
        name: "example",
        owner: "acme",
        visibility: "private"
      },
      archetype: {
        kind: "generic-empty"
      },
      github: {
        createRepo: false,
        autoMerge: true
      }
    });

    const client = {
      isAvailable: async () => true,
      isAuthenticated: async () => true,
      tryApi: async () => ({
        name: "example",
        full_name: "acme/example",
        private: true,
        visibility: "private",
        allow_auto_merge: false
      }),
      api: async (method: string, endpoint: string) => {
        if (endpoint === "/users/acme") {
          return { login: "acme", type: "Organization" };
        }
        if (endpoint === "/orgs/acme") {
          return { plan: { name: "free" } };
        }
        return {};
      }
    };

    const actions = await applyGitHub(manifest, client as never);
    expect(actions.map((action) => action.id)).toContain("auto-merge-plan-limited");
  });

  it("plans existing public repository security drift", async () => {
    const client = publicPlanClient(
      (endpoint) => {
        if (endpoint === `${PUBLIC_REPO_ENDPOINT}/private-vulnerability-reporting`) return { enabled: false };
        if (endpoint === CODE_SCANNING_ENDPOINT) {
          return [{ error: "", category: ".github/workflows/security.yml:codeql/language:javascript-typescript" }];
        }
        return undefined;
      },
      publicRepo("disabled")
    );

    const actions = await planGitHub(publicManifest(), client as never);
    const security = actions.find((action) => action.id === "security-baseline");

    expect(security?.description).toContain("Dependabot security updates");
    expect(security?.description).toContain("secret scanning");
    expect(security?.description).toContain("private vulnerability reporting");
  });

  it("reports synchronized public security state from dedicated endpoints", async () => {
    let fixesPaused = false;
    const client = publicPlanClient(
      (endpoint) => {
        if (endpoint === `${PUBLIC_REPO_ENDPOINT}/vulnerability-alerts`) return {};
        if (endpoint === `${PUBLIC_REPO_ENDPOINT}/automated-security-fixes`) return { enabled: true, paused: fixesPaused };
        if (endpoint === `${PUBLIC_REPO_ENDPOINT}/private-vulnerability-reporting`) return { enabled: true };
        if (endpoint === CODE_SCANNING_ENDPOINT) {
          return [{ error: "", category: ".github/workflows/security.yml:codeql/language:javascript-typescript" }];
        }
        if (endpoint === `${PUBLIC_REPO_ENDPOINT}/actions/variables/DEPENDENCY_REVIEW_ENABLED`) {
          return { name: "DEPENDENCY_REVIEW_ENABLED", value: "true" };
        }
        return undefined;
      },
      publicRepo("enabled")
    );

    const actions = await planGitHub(publicManifest(), client as never);
    expect(actions).toContainEqual(expect.objectContaining({ id: "security-baseline-sync" }));

    fixesPaused = true;
    const pausedActions = await planGitHub(publicManifest(), client as never);
    expect(pausedActions).toContainEqual(expect.objectContaining({
      id: "security-baseline",
      description: expect.stringContaining("Dependabot security updates")
    }));
  });

  it("reports an unsupported private-reporting planning capability without aborting", async () => {
    const client = publicPlanClient((endpoint) => {
      if (endpoint === `${PUBLIC_REPO_ENDPOINT}/private-vulnerability-reporting`) {
        throw new Error("gh: private vulnerability reporting is not available for this plan (HTTP 422)");
      }
      return undefined;
    });

    const actions = await planGitHub(publicManifest(), client as never);
    expect(actions).toContainEqual(expect.objectContaining({
      id: "security-baseline-unverified",
      description: expect.stringContaining("approved waiver")
    }));
  });

  it("does not report synchronization when code scanning cannot be verified", async () => {
    const client = publicPlanClient(
      (endpoint) => {
        if (endpoint === `${PUBLIC_REPO_ENDPOINT}/vulnerability-alerts`) return {};
        if (endpoint === `${PUBLIC_REPO_ENDPOINT}/automated-security-fixes`) return { enabled: true, paused: false };
        if (endpoint === `${PUBLIC_REPO_ENDPOINT}/private-vulnerability-reporting`) return { enabled: true };
        if (endpoint === `${PUBLIC_REPO_ENDPOINT}/actions/variables/DEPENDENCY_REVIEW_ENABLED`) return { value: "true" };
        if (endpoint === CODE_SCANNING_ENDPOINT) return [];
        return undefined;
      },
      publicRepo("enabled")
    );

    const actions = await planGitHub(publicManifest(), client as never);
    expect(actions).toContainEqual(expect.objectContaining({
      id: "security-baseline-unverified",
      description: expect.stringContaining("successful CodeQL analysis for every configured language")
    }));
    expect(actions).not.toContainEqual(expect.objectContaining({ id: "security-baseline-sync" }));
  });

  it("reports unavailable code scanning as unverified instead of aborting planning", async () => {
    const client = publicPlanClient((endpoint) => {
      if (endpoint.includes("/code-scanning/analyses?")) {
        throw new Error("gh: GitHub Advanced Security must be enabled (HTTP 403)");
      }
      return undefined;
    });

    const actions = await planGitHub(publicManifest(), client as never);
    expect(actions).toContainEqual(expect.objectContaining({
      id: "security-baseline-unverified",
      description: expect.stringContaining("code scanning is unavailable on the current plan")
    }));
  });

  it("reports the gh private-repository code scanning 403 as unverified instead of aborting planning", async () => {
    const client = publicPlanClient((endpoint) => {
      if (endpoint.includes("/code-scanning/analyses?")) {
        throw new Error("gh: Advanced Security must be enabled for this repository to use code scanning. (HTTP 403)");
      }
      return undefined;
    });

    const actions = await planGitHub(publicManifest(), client as never);
    expect(actions).toContainEqual(expect.objectContaining({
      id: "security-baseline-unverified",
      description: expect.stringContaining("code scanning is unavailable on the current plan")
    }));
  });

  it("fails closed on ambiguous security planning authorization and validation errors", async () => {
    const inaccessible = publicPlanClient((endpoint) => {
      if (endpoint.includes("/code-scanning/analyses?")) {
        throw new Error("gh: Resource not accessible by integration (HTTP 403)");
      }
      return undefined;
    });
    await expect(planGitHub(publicManifest(), inaccessible as never))
      .rejects.toThrow("Resource not accessible");

    const invalid = publicPlanClient((endpoint) => {
      if (endpoint === `${PUBLIC_REPO_ENDPOINT}/private-vulnerability-reporting`) {
        throw new Error("gh: Validation Failed (HTTP 422)");
      }
      return undefined;
    });
    await expect(planGitHub(publicManifest(), invalid as never)).rejects.toThrow("Validation Failed");
  });

  it("applies public security controls and reports unsupported capabilities distinctly", async () => {
    const manifest = normalizeManifest({
      project: { name: "example", owner: "acme", visibility: "public" },
      archetype: { kind: "node-ts-service" },
      github: { createRepo: false }
    });
    const calls: Array<{ method: string; endpoint: string; payload?: unknown }> = [];
    const client = {
      isAvailable: async () => true,
      isAuthenticated: async () => true,
      tryApi: async (method: string, endpoint: string) => {
        if (endpoint === "/repos/acme/example") {
          return { id: 42, name: "example", full_name: "acme/example", private: false, visibility: "public" };
        }
        if (endpoint.startsWith("/repos/acme/example/labels/")) return undefined;
        return undefined;
      },
      api: async (method: string, endpoint: string, payload?: unknown) => {
        calls.push({ method, endpoint, payload });
        if (endpoint === "/users/acme") return { login: "acme", type: "Organization" };
        if (endpoint === "/repos/acme/example/private-vulnerability-reporting" && method === "PUT") {
          throw new Error("gh: private vulnerability reporting is not available for this plan (HTTP 422)");
        }
        return {};
      }
    };

    const actions = await applyGitHub(manifest, client as never);

    expect(calls).toContainEqual(expect.objectContaining({
      method: "PATCH",
      endpoint: "/repos/acme/example",
      payload: expect.objectContaining({
        security_and_analysis: expect.objectContaining({
          secret_scanning: { status: "enabled" },
          secret_scanning_push_protection: { status: "enabled" }
        })
      })
    }));
    const securityPatch = calls.find((call) =>
      call.method === "PATCH" && call.endpoint === "/repos/acme/example" &&
      call.payload && typeof call.payload === "object" && "security_and_analysis" in call.payload
    );
    expect(securityPatch?.payload).not.toHaveProperty("security_and_analysis.dependabot_security_updates");
    expect(calls).toContainEqual(expect.objectContaining({ method: "PUT", endpoint: "/repos/acme/example/vulnerability-alerts" }));
    expect(calls).toContainEqual(expect.objectContaining({ method: "PUT", endpoint: "/repos/acme/example/automated-security-fixes" }));
    expect(calls).toContainEqual(expect.objectContaining({
      method: "POST",
      endpoint: "/repos/acme/example/actions/variables",
      payload: { name: "DEPENDENCY_REVIEW_ENABLED", value: "true" }
    }));
    expect(actions.map((action) => action.id)).toContain("security-private-reporting-unsupported");
    expect(actions.find((action) => action.id === "security-private-reporting-unsupported")?.description).toContain("remediation");
  });

  it("fails closed on ambiguous GitHub security authorization or validation errors", async () => {
    const manifest = normalizeManifest({
      project: { name: "example", owner: "acme", visibility: "public" },
      archetype: { kind: "node-ts-service" },
      github: { createRepo: false }
    });
    const client = {
      isAvailable: async () => true,
      isAuthenticated: async () => true,
      tryApi: async (method: string, endpoint: string) => endpoint === "/repos/acme/example"
        ? { name: "example", full_name: "acme/example", private: false, visibility: "public" }
        : undefined,
      api: async (method: string, endpoint: string, payload?: unknown) => {
        if (endpoint === "/users/acme") return { login: "acme", type: "Organization" };
        if (endpoint === "/repos/acme/example" && method === "PATCH" && payload && typeof payload === "object" && "security_and_analysis" in payload) {
          throw new Error("gh: Validation Failed (HTTP 422)");
        }
        return {};
      }
    };

    await expect(applyGitHub(manifest, client as never)).rejects.toThrow("Validation Failed");
  });

  it("defaults GitHub review protection to require approval from someone other than the last pusher", () => {
    const manifest = normalizeManifest({
      project: {
        name: "example",
        owner: "acme"
      },
      archetype: {
        kind: "generic-empty"
      }
    });

    expect(manifest.github.autoMerge).toBe(true);
    expect(manifest.github.requireLastPushApproval).toBe(true);
  });

  it("updates drifted labels and leaves matching labels alone", async () => {
    const manifest = normalizeManifest({
      project: {
        name: "example",
        owner: "acme"
      },
      archetype: {
        kind: "generic-empty"
      },
      github: {
        createRepo: false,
        issueLabels: [
          {
            name: "area:frontend",
            color: "1f77b4",
            description: "Frontend and user-interface work."
          },
          {
            name: "risk:high",
            color: "d93f0b",
            description: "High implementation or operational risk."
          }
        ]
      }
    });

    const calls: Array<{ method: string; endpoint: string; payload?: unknown }> = [];
    const client = {
      isAvailable: async () => true,
      isAuthenticated: async () => true,
      tryApi: async (method: string, endpoint: string) => {
        calls.push({ method, endpoint });
        if (endpoint === "/repos/acme/example") {
          return { name: "example", full_name: "acme/example", private: true, visibility: "private" };
        }
        if (endpoint === "/repos/acme/example/labels/area%3Afrontend") {
          return {
            name: "area:frontend",
            color: "1f77b4",
            description: "Frontend and user-interface work."
          };
        }
        if (endpoint === "/repos/acme/example/labels/risk%3Ahigh") {
          return {
            name: "risk:high",
            color: "cccccc",
            description: "Old description."
          };
        }
        return undefined;
      },
      api: async (method: string, endpoint: string, payload?: unknown) => {
        calls.push({ method, endpoint, payload });
        if (endpoint === "/users/acme") {
          return { login: "acme", type: "Organization" };
        }
        return {};
      }
    };

    await applyGitHub(manifest, client as never);

    const labelWrites = calls.filter((call) => call.endpoint.includes("/labels/") && call.method === "PATCH");
    expect(labelWrites).toEqual([
      {
        method: "PATCH",
        endpoint: "/repos/acme/example/labels/risk%3Ahigh",
        payload: {
          name: "risk:high",
          color: "d93f0b",
          description: "High implementation or operational risk."
        }
      }
    ]);
  });
});

const RELEASE_ENDPOINT = "/repos/acme/example/environments/release-publish";
const BRANCH_ENDPOINT = "/repos/acme/example/branches/main";
type ReleaseCall = { method: string; endpoint: string; payload?: unknown };

function releaseManifest(reviewers = ["alice"]) {
  return normalizeManifest({
    project: { name: "example", owner: "acme", visibility: "private" },
    archetype: { kind: "generic-empty" },
    github: { createRepo: false, reviewers: [] },
    environments: {
      "release-publish": { reviewers, requireApproval: true, preventSelfReview: true, branches: ["main"] }
    }
  } as never);
}

function releaseRemote(reviewers = [{ type: "User", reviewer: { id: 7 } }]) {
  return {
    name: "release-publish",
    protection_rules: [{ type: "required_reviewers", prevent_self_review: true, reviewers }],
    deployment_branch_policy: { protected_branches: true, custom_branch_policies: false }
  };
}

const protectedBranch = { name: "main", protected: true };
const classicProtection = { url: `https://api.github.com${BRANCH_ENDPOINT}/protection`, enforce_admins: { enabled: true } };

function releaseClient(options: {
  environments?: unknown[];
  branch?: unknown;
  protection?: unknown;
  user?: unknown;
  branchRead?: (read: number) => unknown;
  readError?: Error;
  putError?: Error;
} = {}) {
  const calls: ReleaseCall[] = [];
  let reads = 0;
  let branchReads = 0;
  const client = {
    isAvailable: async () => true,
    isAuthenticated: async () => true,
    getReleaseEnvironment: async () => {
      calls.push({ method: "GET", endpoint: RELEASE_ENDPOINT });
      if (options.readError) throw options.readError;
      return (options.environments ?? [undefined, releaseRemote()])[reads++];
    },
    tryApi: async (method: string, endpoint: string) => {
      calls.push({ method, endpoint });
      return endpoint === PUBLIC_REPO_ENDPOINT ? { ...publicRepo(), private: true, visibility: "private" } : undefined;
    },
    api: async (method: string, endpoint: string, payload?: unknown) => {
      calls.push({ method, endpoint, payload });
      if (endpoint === "/users/acme") return { login: "acme", type: "User" };
      if (endpoint.startsWith("/users/")) return "user" in options ? options.user : { id: 7, type: "User" };
      if (endpoint.startsWith("/orgs/") && endpoint.includes("/teams/")) return { id: 7 };
      if (method === "GET" && endpoint === BRANCH_ENDPOINT) {
        return options.branchRead ? options.branchRead(++branchReads) : "branch" in options ? options.branch : protectedBranch;
      }
      if (method === "GET" && endpoint === `${BRANCH_ENDPOINT}/protection`) {
        return "protection" in options ? options.protection : classicProtection;
      }
      if (method === "PUT" && endpoint === RELEASE_ENDPOINT && options.putError) throw options.putError;
      return {};
    }
  };
  return { calls, client };
}

function releaseWrites(calls: ReleaseCall[]) {
  return calls.filter((call) => call.endpoint === RELEASE_ENDPOINT && call.method !== "GET");
}

describe("strict optional release-publish provisioning", () => {
  it("adds a read-only authenticated plan with the protected-branches and broad-writer limits", async () => {
    const { calls, client } = releaseClient();
    const actions = await planGitHub(releaseManifest(), client as never);
    const release = actions.find((action) => action.id === "environment-release-publish");
    expect(release?.description).toContain("protected branches");
    expect(release?.description).toContain("unverified");
    expect(release?.description).toContain("Administrators");
    expect(release?.description).toContain("broad writer");
    expect(calls.every((call) => call.method === "GET")).toBe(true);
    expect(calls.some((call) => call.endpoint === RELEASE_ENDPOINT)).toBe(false);
  });

  it("creates the absent target once with full protections and verifies it", async () => {
    const { calls, client } = releaseClient();
    const actions = await applyGitHub(releaseManifest(), client as never);
    expect(releaseWrites(calls)).toEqual([{
      method: "PUT", endpoint: RELEASE_ENDPOINT,
      payload: {
        wait_timer: 0, reviewers: [{ type: "User", id: 7 }], prevent_self_review: true,
        deployment_branch_policy: { protected_branches: true, custom_branch_policies: false }
      }
    }]);
    expect(calls.filter((call) => call.endpoint === BRANCH_ENDPOINT && call.method === "GET")).toHaveLength(2);
    expect(actions.find((action) => action.id === "environment-release-publish")?.description).toContain("at readback");
    const identityIndex = calls.findIndex((call) => call.endpoint === "/users/alice");
    expect(calls.findIndex((call) => call.method !== "GET")).toBeGreaterThan(identityIndex);
  });

  it("does not rewrite matching existing policy and preserves additional protections", async () => {
    const existing = releaseRemote();
    const value = { ...existing, protection_rules: [...existing.protection_rules, { type: "wait_timer", wait_timer: 30 }] };
    const { calls, client } = releaseClient({ environments: [value] });
    const actions = await applyGitHub(releaseManifest(), client as never);
    expect(releaseWrites(calls)).toEqual([]);
    expect(value.protection_rules).toHaveLength(2);
    expect(actions.find((action) => action.id === "environment-release-publish")?.description).toContain("without rewriting");
    expect(actions.find((action) => action.id === "environment-release-publish")?.description).toContain("outside this capability");
  });

  it("compares typed identities independently of order", async () => {
    const existing = releaseRemote([{ type: "Team", reviewer: { id: 7 } }, { type: "User", reviewer: { id: 7 } }]);
    const { calls, client } = releaseClient({ environments: [existing] });
    await applyGitHub(releaseManifest(["alice", "acme/release"]), client as never);
    expect(releaseWrites(calls)).toEqual([]);
    expect(calls.some((call) => call.endpoint === "/orgs/acme/teams/release")).toBe(true);
  });

  for (const invalid of [null, {}, { reviewers: [] }, { requireApproval: false }, { preventSelfReview: false }, { branches: [] }, { branches: ["other"] }, { extra: true }]) {
    it(`rejects programmatic invalid policy before any API call: ${JSON.stringify(invalid)}`, async () => {
      const manifest = releaseManifest();
      (manifest.environments as Record<string, unknown>)["release-publish"] = invalid === null || Object.keys(invalid).length === 0
        ? invalid : { ...manifest.environments["release-publish"], ...invalid };
      const { calls, client } = releaseClient();
      await expect(applyGitHub(manifest, client as never)).rejects.toThrow("release-publish");
      expect(calls).toEqual([]);
      await expect(planGitHub(manifest, client as never)).rejects.toThrow("release-publish");
      expect(calls).toEqual([]);
    });
  }

  for (const user of [undefined, {}, { id: 0, type: "User" }, { id: -1, type: "User" }, { id: 1.5, type: "User" }, { id: Number.MAX_SAFE_INTEGER + 1, type: "User" }, { id: "7", type: "User" }, { id: 7, type: "Organization" }, { id: 7, type: "Bot" }]) {
    it(`rejects invalid resolved user identity before any mutation: ${JSON.stringify(user)}`, async () => {
      const { calls, client } = releaseClient({ user });
      await expect(applyGitHub(releaseManifest(), client as never)).rejects.toThrow("unique valid user/team");
      expect(calls.every((call) => call.method === "GET")).toBe(true);
    });
  }

  for (const reviewers of [["alice", "@alice"], ["acme/release/extra"], ["acme:release:extra"], ["../alice"]]) {
    it(`rejects aliases or ambiguous reviewer targets before mutations: ${reviewers.join(",")}`, async () => {
      const { calls, client } = releaseClient();
      await expect(applyGitHub(releaseManifest(reviewers), client as never)).rejects.toThrow("unique valid user/team");
      expect(calls.every((call) => call.method === "GET")).toBe(true);
    });
  }

  for (const branch of [undefined, {}, { name: "other", protected: true }, { name: "main", protected: false }, { name: "main", protected: "true" }]) {
    it(`blocks the release target without a verified protected default branch: ${JSON.stringify(branch)}`, async () => {
      const { calls, client } = releaseClient({ branch });
      await expect(applyGitHub(releaseManifest(), client as never)).rejects.toThrow("no verified classic protection");
      expect(releaseWrites(calls)).toEqual([]);
      expect(calls.some((call) => call.endpoint === RELEASE_ENDPOINT)).toBe(false);
    });
  }

  for (const protection of [
    undefined, {}, { url: "" }, { url: "https://api.github.com/protection", enforce_admins: {} },
    { ...classicProtection, url: "invalid" },
    { ...classicProtection, url: `http://api.github.com${BRANCH_ENDPOINT}/protection` },
    { ...classicProtection, url: "https://api.github.com/repos/acme/example/branches/other/protection" }
  ]) {
    it(`rejects missing or malformed classic protection proof: ${JSON.stringify(protection)}`, async () => {
      const { calls, client } = releaseClient({ protection });
      await expect(applyGitHub(releaseManifest(), client as never)).rejects.toThrow("no verified classic protection");
      expect(releaseWrites(calls)).toEqual([]);
    });
  }

  const mismatches: Array<[string, () => unknown]> = [
    ["missing environment", () => undefined],
    ["wrong name", () => ({ ...releaseRemote(), name: "prod" })],
    ["malformed environment", () => null],
    ["missing rules", () => ({ ...releaseRemote(), protection_rules: undefined })],
    ["empty rules", () => ({ ...releaseRemote(), protection_rules: [] })],
    ["malformed rule", () => ({ ...releaseRemote(), protection_rules: [null] })],
    ["duplicate reviewer rules", () => ({ ...releaseRemote(), protection_rules: [...releaseRemote().protection_rules, ...releaseRemote().protection_rules] })],
    ["self-review allowed", () => ({ ...releaseRemote(), protection_rules: [{ ...releaseRemote().protection_rules[0], prevent_self_review: false }] })],
    ["missing reviewers", () => ({ ...releaseRemote(), protection_rules: [{ type: "required_reviewers", prevent_self_review: true }] })],
    ["wrong reviewer", () => releaseRemote([{ type: "User", reviewer: { id: 8 } }])],
    ["wrong reviewer type", () => releaseRemote([{ type: "Team", reviewer: { id: 7 } }])],
    ["invalid reviewer id", () => releaseRemote([{ type: "User", reviewer: { id: 0 } }])],
    ["extra reviewer", () => releaseRemote([{ type: "User", reviewer: { id: 7 } }, { type: "User", reviewer: { id: 8 } }])],
    ["wrong branch flags", () => ({ ...releaseRemote(), deployment_branch_policy: { protected_branches: false, custom_branch_policies: false } })],
    ["custom branch policies", () => ({ ...releaseRemote(), deployment_branch_policy: { protected_branches: true, custom_branch_policies: true } })],
    ["missing branch flags", () => ({ ...releaseRemote(), deployment_branch_policy: {} })]
  ];
  for (const [description, value] of mismatches) {
    it(`does not report success after an incorrect readback: ${description}`, async () => {
      const { calls, client } = releaseClient({ environments: [undefined, value()] });
      await expect(applyGitHub(releaseManifest(), client as never)).rejects.toThrow("potentially partial");
      expect(releaseWrites(calls)).toHaveLength(1);
    });
    if (description !== "missing environment") {
      it(`preserves conflicting existing environment: ${description}`, async () => {
        const { calls, client } = releaseClient({ environments: [value()] });
        await expect(applyGitHub(releaseManifest(), client as never)).rejects.toThrow("separate review");
        expect(releaseWrites(calls)).toEqual([]);
      });
    }
  }

  it("does not retry a protection-plan-limited release PUT with a bare payload", async () => {
    const { calls, client } = releaseClient({ putError: new Error("billing plan required reviewers protection rule HTTP422 BODY_CANARY") });
    await expect(applyGitHub(releaseManifest(), client as never)).rejects.toThrow("potentially partial");
    expect(releaseWrites(calls)).toHaveLength(1);
    expect(releaseWrites(calls)[0]?.payload).not.toEqual({});
  });

  it("rejects duplicate typed reviewer identities even when the count matches", async () => {
    const duplicate = releaseRemote([{ type: "User", reviewer: { id: 7 } }, { type: "User", reviewer: { id: 7 } }]);
    const { calls, client } = releaseClient({ environments: [duplicate] });
    await expect(applyGitHub(releaseManifest(["alice", "acme/release"]), client as never)).rejects.toThrow("separate review");
    expect(releaseWrites(calls)).toEqual([]);
  });

  it("rechecks protection after the environment write and stops on intervening loss", async () => {
    const { calls, client } = releaseClient({ branchRead: (read) => ({ name: "main", protected: read === 1 }) });
    await expect(applyGitHub(releaseManifest(), client as never)).rejects.toThrow("potentially partial");
    expect(releaseWrites(calls)).toHaveLength(1);
  });
});

function releaseHttpClient(environmentResponse: (read: number) => CommandResult) {
  const calls: ReleaseCall[] = [];
  let reads = 0;
  const runner: CommandRunner = async (_command, args = [], options) => {
    if (args[0] !== "api") return { stdout: "", stderr: "", exitCode: 0 };
    const endpoint = args.find((arg) => arg.startsWith("/"))!;
    const method = args[args.indexOf("--method") + 1]!;
    calls.push({ method, endpoint, ...(options?.input ? { payload: JSON.parse(options.input) } : {}) });
    if (endpoint === RELEASE_ENDPOINT && method === "GET") return environmentResponse(++reads);
    let body: unknown = {};
    if (endpoint === PUBLIC_REPO_ENDPOINT) body = { ...publicRepo(), private: true, visibility: "private" };
    if (endpoint === "/users/acme") body = { login: "acme", type: "User" };
    if (endpoint === "/users/alice") body = { id: 7, type: "User" };
    if (endpoint === BRANCH_ENDPOINT && method === "GET") body = protectedBranch;
    if (endpoint === `${BRANCH_ENDPOINT}/protection` && method === "GET") body = classicProtection;
    return { stdout: JSON.stringify(body), stderr: "", exitCode: 0 };
  };
  return { calls, client: new GitHubClient({ runner }) };
}

function framedResponse(status: number, body: string, stderr = "", exitCode = status === 200 ? 0 : 1): CommandResult {
  return { stdout: `HTTP/2.0 ${status} ${status === 200 ? "OK" : "Not Found"}\nContent-Type: application/json\r\n\r\n${body}`, stderr, exitCode };
}

describe("release absence uses captured HTTP status in the actual client", () => {
  const missing = JSON.stringify({ message: "Not Found", documentation_url: "https://docs.github.com/rest", status: "404" });
  it("accepts actual endpoint404, writes once and validates the actual client readback", async () => {
    const { calls, client } = releaseHttpClient((read) => read === 1
      ? framedResponse(404, missing, "gh: Not Found (HTTP 404)\n")
      : framedResponse(200, JSON.stringify(releaseRemote())));
    const actions = await applyGitHub(releaseManifest(), client);
    expect(releaseWrites(calls)).toHaveLength(1);
    expect(actions.some((action) => action.id === "environment-release-publish")).toBe(true);
  });

  it("stops with safe partial-state diagnostics when actual readback fails after PUT", async () => {
    const { calls, client } = releaseHttpClient((read) => read === 1
      ? framedResponse(404, missing, "gh: Not Found (HTTP 404)\n")
      : framedResponse(500, '{"message":"BODY_CANARY"}', "HEADER_CANARY HTTP 500\n"));
    let error: unknown;
    try {
      await applyGitHub(releaseManifest(), client);
    } catch (caught) {
      error = caught;
    }
    expect(error).toBeInstanceOf(Error);
    expect((error as Error).message).toContain("potentially partial");
    expect((error as Error).message).not.toMatch(/BODY_CANARY|HEADER_CANARY/);
    expect(releaseWrites(calls)).toHaveLength(1);
  });

  const errors: Array<[string, CommandResult]> = [
    ["raw text404", { stdout: missing, stderr: "HTTP 404", exitCode: 1 }],
    ["body404 with HTTP200", framedResponse(200, missing)],
    ["malformed404 JSON", framedResponse(404, '{"message":', "gh: Not Found (HTTP 404)\n")],
    ["malformed200 JSON", framedResponse(200, " ".repeat(404) + "invalid")],
    ["transport failure mentioning404", framedResponse(404, missing, "transport failed HTTP 404\n")],
    ["HTTP403", framedResponse(403, missing, "gh: Forbidden (HTTP 403)\n")],
    ["HTTP500", framedResponse(500, missing, "gh: Server error (HTTP 500)\n")]
  ];
  for (const [name, response] of errors) {
    it(`does not create an environment on ${name}`, async () => {
      const { calls, client } = releaseHttpClient(() => response);
      await expect(applyGitHub(releaseManifest(), client)).rejects.toThrow("release-publish");
      expect(releaseWrites(calls)).toEqual([]);
    });
  }
});
