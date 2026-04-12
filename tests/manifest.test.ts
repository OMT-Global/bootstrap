import { describe, expect, it } from "vitest";

import { normalizeManifest } from "../src/manifest.js";

describe("normalizeManifest", () => {
  it("applies defaults and reviewer-derived governance", () => {
    const manifest = normalizeManifest({
      project: {
        name: "hello-world",
        owner: "acme"
      },
      archetype: {
        kind: "node-ts-service"
      },
      github: {
        reviewers: ["alice", "@acme/platform"]
      }
    });

    expect(manifest.project.defaultBranch).toBe("main");
    expect(manifest.project.displayName).toBeUndefined();
    expect(manifest.repo.managedPaths).toEqual([]);
    expect(manifest.github.codeowners).toEqual([
      {
        pattern: "*",
        owners: ["@alice", "@acme/platform"]
      }
    ]);
    expect(manifest.github.requiredStatusChecks).toEqual(["CI Gate"]);
    expect(manifest.agents.enableClaudeWebEnvironment).toBe(true);
    expect(manifest.agents.enableClaudeDevcontainer).toBe(true);
    expect(manifest.agents.enableClaudeGitHubAction).toBe(true);
    expect(manifest.environments.stage.reviewers).toEqual(["alice", "acme/platform"]);
    expect(manifest.environments.prod.branches).toEqual(["main"]);
  });

  it("preserves explicit environment reviewers and branches", () => {
    const manifest = normalizeManifest({
      project: {
        name: "py-service",
        owner: "acme"
      },
      archetype: {
        kind: "python-service"
      },
      environments: {
        stage: {
          reviewers: ["release-team"],
          requireApproval: true,
          preventSelfReview: true,
          branches: []
        },
        prod: {
          reviewers: ["release-team"],
          requireApproval: true,
          preventSelfReview: true,
          branches: ["main"]
        }
      }
    });

    expect(manifest.environments.stage.reviewers).toEqual(["release-team"]);
    expect(manifest.environments.prod.branches).toEqual(["main"]);
  });

  it("preserves explicit required checks and managed path selection", () => {
    const manifest = normalizeManifest({
      project: {
        name: "runner-repo",
        owner: "acme"
      },
      repo: {
        managedPaths: ["project.bootstrap.yaml", "docs/bootstrap/**"]
      },
      archetype: {
        kind: "generic-empty"
      },
      github: {
        requiredStatusChecks: ["test"]
      }
    });

    expect(manifest.repo.managedPaths).toEqual(["project.bootstrap.yaml", "docs/bootstrap/**"]);
    expect(manifest.github.requiredStatusChecks).toEqual(["test"]);
  });

  it("normalizes declared repo-specific workflow lanes", () => {
    const manifest = normalizeManifest({
      project: {
        name: "ops-repo",
        owner: "acme"
      },
      archetype: {
        kind: "generic-empty"
      },
      ci: {
        additionalWorkflows: [
          {
            path: ".github\\workflows\\deploy.yml",
            purpose: "Runs deploy orchestration after the standard CI lanes pass."
          }
        ]
      }
    });

    expect(manifest.ci.additionalWorkflows).toEqual([
      {
        path: ".github/workflows/deploy.yml",
        purpose: "Runs deploy orchestration after the standard CI lanes pass."
      }
    ]);
  });

  it("preserves an explicit docs-facing display name", () => {
    const manifest = normalizeManifest({
      project: {
        name: "bootstrap",
        displayName: "Bootstrap",
        owner: "acme"
      },
      archetype: {
        kind: "generic-empty"
      }
    });

    expect(manifest.project.name).toBe("bootstrap");
    expect(manifest.project.displayName).toBe("Bootstrap");
  });

  it("normalizes optional organization governance settings", () => {
    const manifest = normalizeManifest({
      project: {
        name: "bootstrap",
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

    expect(manifest.github.organization).toEqual({
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
    });
  });
});
