import { describe, expect, it } from "vitest";

import { renderManagedFiles } from "../src/archetypes.js";
import { normalizeManifest } from "../src/manifest.js";

describe("renderManagedFiles", () => {
  const archetypes = ["nextjs-web", "node-ts-service", "python-service", "generic-empty"] as const;

  for (const kind of archetypes) {
    it(`renders a stable managed file set for ${kind}`, () => {
      const manifest = normalizeManifest({
        project: {
          name: `${kind}-demo`,
          owner: "acme"
        },
        archetype: {
          kind
        },
        github: {
          reviewers: ["alice"]
        }
      });

      const files = renderManagedFiles(manifest);
      expect(
        files.map((file) => ({
          path: file.path,
          executable: file.executable ?? false
        }))
      ).toMatchSnapshot();

      const prWorkflow = files.find((file) => file.path === ".github/workflows/pr-fast-ci.yml");
      expect(prWorkflow?.contents).toContain("name: CI Gate");
      expect(prWorkflow?.contents).toContain("['self-hosted', 'synology'");

      const claudeWorkflow = files.find((file) => file.path === ".github/workflows/claude.yml");
      expect(claudeWorkflow?.contents).toContain("uses: anthropics/claude-code-action@v1");

      const devcontainer = files.find((file) => file.path === ".devcontainer/devcontainer.json");
      expect(devcontainer?.contents).toContain("ghcr.io/anthropics/devcontainer-features/claude-code:1");

      const claudeCloudSetup = files.find((file) => file.path === "scripts/claude-cloud/setup.sh");
      expect(claudeCloudSetup?.contents).toContain("apt-get install -y gh");

      const contributing = files.find((file) => file.path === "CONTRIBUTING.md");
      expect(contributing?.contents).toContain("Use `.github/PULL_REQUEST_TEMPLATE.md`");

      const pullRequestTemplate = files.find((file) => file.path === ".github/PULL_REQUEST_TEMPLATE.md");
      expect(pullRequestTemplate?.contents).toContain("## Governing Issue");
    });
  }

  it("uses the primary required status check name in the generated PR workflow", () => {
    const manifest = normalizeManifest({
      project: {
        name: "runner-adoption",
        owner: "acme"
      },
      archetype: {
        kind: "generic-empty"
      },
      github: {
        requiredStatusChecks: ["test"]
      }
    });

    const files = renderManagedFiles(manifest);
    const prWorkflow = files.find((file) => file.path === ".github/workflows/pr-fast-ci.yml");
    expect(prWorkflow?.contents).toContain("name: test");
    expect(prWorkflow?.contents).not.toContain("name: CI Gate");
  });

  it("uses the display name in docs while keeping the repository slug visible", () => {
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

    const files = renderManagedFiles(manifest);
    const readme = files.find((file) => file.path === "README.md");
    const onboarding = files.find((file) => file.path === "docs/bootstrap/onboarding.md");

    expect(readme?.contents).toContain("# Bootstrap");
    expect(readme?.contents).toContain("- Repository: `acme/bootstrap`");
    expect(onboarding?.contents).toContain("- Product name: `Bootstrap`");
    expect(onboarding?.contents).toContain("- Repository: `acme/bootstrap`");
  });

  it("documents repo-specific workflow lanes without replacing the standard CI frame", () => {
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
            path: ".github/workflows/deploy.yml",
            purpose: "Runs deploy orchestration after the standard CI lanes pass."
          }
        ]
      }
    });

    const files = renderManagedFiles(manifest);
    const readme = files.find((file) => file.path === "README.md");
    const claude = files.find((file) => file.path === "CLAUDE.md");
    const onboarding = files.find((file) => file.path === "docs/bootstrap/onboarding.md");
    const prWorkflow = files.find((file) => file.path === ".github/workflows/pr-fast-ci.yml");

    expect(readme?.contents).toContain("Repo-Specific Workflow Lanes");
    expect(readme?.contents).toContain("`.github/workflows/deploy.yml`");
    expect(claude?.contents).toContain("stay adjunct to the standard PR and extended validation lanes");
    expect(onboarding?.contents).toContain("Do not repurpose them as the required PR gate");
    expect(prWorkflow?.contents).toContain("name: CI Gate");
  });
});
