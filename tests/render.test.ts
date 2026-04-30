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
      expect(prWorkflow?.contents).toContain("types: [opened, edited, synchronize, reopened, ready_for_review]");
      expect(prWorkflow?.contents).toContain("['self-hosted', 'synology'");
      expect(prWorkflow?.contents).toContain("validate-pr-description:");
      expect(prWorkflow?.contents).toContain("PR body must close/link an issue");

      const prTemplate = files.find((file) => file.path === ".github/PULL_REQUEST_TEMPLATE.md");
      expect(prTemplate?.contents).toContain("## Summary");
      expect(prTemplate?.contents).toContain("## Governing Issue");
      expect(prTemplate?.contents).toContain("## Validation");
      expect(prTemplate?.contents).toContain("## Bootstrap Governance");
      expect(prTemplate?.contents).toContain("fallback merge-readiness policy applies");
      expect(prTemplate?.contents).toContain("## Notes");

      expect(files.some((file) => file.path === "CLAUDE.md")).toBe(false);
      expect(files.some((file) => file.path === ".github/workflows/claude.yml")).toBe(false);
      expect(files.some((file) => file.path === ".devcontainer/devcontainer.json")).toBe(false);
      expect(files.some((file) => file.path === "scripts/claude-cloud/setup.sh")).toBe(false);

      const contributing = files.find((file) => file.path === "CONTRIBUTING.md");
      expect(contributing?.contents).toContain("Use `.github/PULL_REQUEST_TEMPLATE.md`");

      expect(prTemplate?.contents).toContain("Closes #");
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
    expect(readme?.contents).toContain("require approval from someone other than the most recent pusher");
    expect(readme?.contents).toContain("fallback merge-readiness policy");
    expect(onboarding?.contents).toContain("- Product name: `Bootstrap`");
    expect(onboarding?.contents).toContain("- Repository: `acme/bootstrap`");
    expect(onboarding?.contents).toContain(
      "require one approval, code owner review, and approval from someone other than the most recent pusher"
    );
    expect(onboarding?.contents).toContain("PR Fast CI validates the required PR description sections");
    expect(onboarding?.contents).toContain("allow auto-merge` are enabled when the GitHub plan supports them");
    expect(onboarding?.contents).toContain("Fallback merge readiness requires");
  });

  it("documents required PR template enforcement in generated agent instructions", () => {
    const manifest = normalizeManifest({
      project: {
        name: "template-required",
        owner: "acme"
      },
      archetype: {
        kind: "generic-empty"
      }
    });

    const files = renderManagedFiles(manifest);
    const agents = files.find((file) => file.path === "AGENTS.md");
    const prWorkflow = files.find((file) => file.path === ".github/workflows/pr-fast-ci.yml");

    expect(agents?.contents).toContain("PRs must use the generated pull request template");
    expect(prWorkflow?.contents).toContain("- validate-pr-description");
    expect(prWorkflow?.contents).toContain("validate-pr-description=${{ needs.validate-pr-description.result }}");
  });

  it("renders an AI attestation caller workflow when enabled", () => {
    const manifest = normalizeManifest({
      project: {
        name: "attested-repo",
        owner: "OMT-Global"
      },
      archetype: {
        kind: "generic-empty"
      },
      ci: {
        aiAttestation: {
          enabled: true,
          provider: "OpenAI",
          model: "gpt-5.4",
          promptHash: "sha256:abc123",
          reusableWorkflowRef: "refs/tags/bootstrap-v1"
        }
      }
    });

    const files = renderManagedFiles(manifest);
    const attestationWorkflow = files.find((file) => file.path === ".github/workflows/ai-attestation.yml");
    const readme = files.find((file) => file.path === "README.md");
    const onboarding = files.find((file) => file.path === "docs/bootstrap/onboarding.md");

    expect(attestationWorkflow?.contents).toContain("name: AI Attestation");
    expect(attestationWorkflow?.contents).toContain(
      "uses: OMT-Global/bootstrap/.github/workflows/ai-attestation-reusable.yml@refs/tags/bootstrap-v1"
    );
    expect(attestationWorkflow?.contents).toContain(
      "ai_provider: ${{ vars.AI_ATTESTATION_PROVIDER || 'OpenAI' }}"
    );
    expect(readme?.contents).toContain("Optional signed AI attestation workflow");
    expect(onboarding?.contents).toContain("AI attestation workflows");
    expect(onboarding?.contents).toContain("AI_ATTESTATION_PROVIDER");
  });

  it("renders release automation when enabled", () => {
    const manifest = normalizeManifest({
      project: {
        name: "release-repo",
        owner: "OMT-Global"
      },
      archetype: {
        kind: "generic-empty"
      },
      release: {
        enabled: true,
        tagPrefix: "v",
        reusableWorkflowRef: "refs/tags/v1"
      }
    });

    const files = renderManagedFiles(manifest);
    const releaseWorkflow = files.find((file) => file.path === ".github/workflows/release-tag.yml");
    const verifyScript = files.find((file) => file.path === "scripts/ci/run-release-verification.sh");
    const publishScript = files.find((file) => file.path === "scripts/ci/run-release-publish.sh");
    const versioningDoc = files.find((file) => file.path === "docs/bootstrap/versioning.md");

    expect(releaseWorkflow?.contents).toContain("name: Release");
    expect(releaseWorkflow?.contents).toContain(
      "uses: OMT-Global/bootstrap/.github/workflows/release.yml@refs/tags/v1"
    );
    expect(releaseWorkflow?.contents).toContain("tag-prefix: 'v'");
    expect(verifyScript?.contents).toContain("bash scripts/ci/run-fast-checks.sh");
    expect(publishScript?.contents).toContain("Create exact release tags such as v1.2.3");
    expect(versioningDoc?.contents).toContain("Semantic Versioning");
    expect(versioningDoc?.contents).toContain("release/X.Y");
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
    const onboarding = files.find((file) => file.path === "docs/bootstrap/onboarding.md");
    const prWorkflow = files.find((file) => file.path === ".github/workflows/pr-fast-ci.yml");

    expect(readme?.contents).toContain("Repo-Specific Workflow Lanes");
    expect(readme?.contents).toContain("`.github/workflows/deploy.yml`");
    expect(onboarding?.contents).toContain("Do not repurpose them as the required PR gate");
    expect(prWorkflow?.contents).toContain("name: CI Gate");
  });
});
