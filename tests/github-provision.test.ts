import { describe, expect, it } from "vitest";

import { applyGitHub, planGitHub } from "../src/github/provision.js";
import { DEFAULT_ISSUE_LABELS, normalizeManifest } from "../src/manifest.js";

describe("GitHub provisioning", () => {
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
