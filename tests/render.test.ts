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
    });
  }
});
