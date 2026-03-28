import { describe, expect, it } from "vitest";

import { applyGitHub, planGitHub } from "../src/github/provision.js";
import { normalizeManifest } from "../src/manifest.js";

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
        requiredStatusChecks: ["test", "lint"]
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
        return {};
      }
    };

    const actions = await applyGitHub(manifest, client as never);
    expect(actions.map((action) => action.id)).toContain("repo-create");
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
      }
    });
    expect(
      calls.some(
        (call) => call.endpoint === "/repos/acme/example/environments/prod" && call.method === "PUT"
      )
    ).toBe(true);
  });
});
