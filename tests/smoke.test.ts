import { mkdtemp, readFile, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { normalizeManifest } from "../src/manifest.js";
import { applyRepo, planRepo } from "../src/render.js";

const tempDirs: string[] = [];

async function makeTempDir(): Promise<string> {
  const dir = await mkdtemp(path.join(os.tmpdir(), "bootstrap-repo-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(async () => {
  await Promise.all(tempDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

describe("repo smoke", () => {
  it("renders a target repo with a single CI Gate and idempotent second plan", async () => {
    const targetDir = await makeTempDir();
    const manifest = normalizeManifest({
      project: {
        name: "hello-service",
        owner: "acme"
      },
      archetype: {
        kind: "node-ts-service"
      },
      github: {
        reviewers: ["alice"]
      }
    });

    const firstApply = await applyRepo(manifest, targetDir);
    expect(firstApply.changes.some((change) => change.path === "project.bootstrap.yaml")).toBe(true);

    const workflow = await readFile(path.join(targetDir, ".github/workflows/pr-fast-ci.yml"), "utf8");
    expect(workflow).toContain("name: CI Gate");
    expect(workflow.match(/name: CI Gate/g)?.length).toBe(1);

    const claudeWorkflow = await readFile(path.join(targetDir, ".github/workflows/claude.yml"), "utf8");
    expect(claudeWorkflow).toContain("anthropics/claude-code-action@v1");

    const devcontainer = await readFile(path.join(targetDir, ".devcontainer/devcontainer.json"), "utf8");
    expect(devcontainer).toContain("\"ghcr.io/anthropics/devcontainer-features/claude-code:1\"");

    const claudeCloudSetup = await readFile(path.join(targetDir, "scripts/claude-cloud/setup.sh"), "utf8");
    expect(claudeCloudSetup).toContain("apt-get install -y gh");

    const secondPlan = await planRepo(manifest, targetDir);
    expect(secondPlan.changes.every((change) => change.type === "unchanged")).toBe(true);
  });
});
