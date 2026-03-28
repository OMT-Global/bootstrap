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
    expect(manifest.github.codeowners).toEqual([
      {
        pattern: "*",
        owners: ["@alice", "@acme/platform"]
      }
    ]);
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
});
