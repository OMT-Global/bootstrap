import { execFile } from "node:child_process";
import { access, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";

import { afterEach, describe, expect, it } from "vitest";

import { normalizeManifest } from "../src/manifest.js";
import { applyRepo, planRepo } from "../src/render.js";

const tempDirs: string[] = [];
const execFileAsync = promisify(execFile);

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

    await expect(access(path.join(targetDir, ".github/workflows/claude.yml"))).rejects.toThrow();
    await expect(access(path.join(targetDir, ".devcontainer/devcontainer.json"))).rejects.toThrow();
    await expect(access(path.join(targetDir, "scripts/claude-cloud/setup.sh"))).rejects.toThrow();

    const secondPlan = await planRepo(manifest, targetDir);
    expect(secondPlan.changes.every((change) => change.type === "unchanged")).toBe(true);
  });

  it("can adopt an existing repo by managing only selected bootstrap files", async () => {
    const targetDir = await makeTempDir();
    await writeFile(path.join(targetDir, "README.md"), "Existing README\n", "utf8");

    const manifest = normalizeManifest({
      project: {
        name: "existing-service",
        owner: "acme"
      },
      repo: {
        managedPaths: [
          "project.bootstrap.yaml",
          "AGENTS.md",
          "scripts/codex-cloud/**",
          "docs/bootstrap/**"
        ]
      },
      archetype: {
        kind: "generic-empty"
      },
      github: {
        reviewers: ["alice"],
        requiredStatusChecks: ["test"]
      }
    });

    const planBeforeApply = await planRepo(manifest, targetDir);
    expect(planBeforeApply.changes.some((change) => change.path === "README.md")).toBe(false);

    await applyRepo(manifest, targetDir);

    const preservedReadme = await readFile(path.join(targetDir, "README.md"), "utf8");
    expect(preservedReadme).toBe("Existing README\n");

    const agents = await readFile(path.join(targetDir, "AGENTS.md"), "utf8");
    expect(agents).toContain("CI baseline");

    const secondPlan = await planRepo(manifest, targetDir);
    expect(secondPlan.changes.every((change) => change.type === "unchanged")).toBe(true);
  });

  it("backs out previously managed Claude files from an already bootstrapped repo", async () => {
    const targetDir = await makeTempDir();
    const legacyPaths = [
      "CLAUDE.md",
      ".github/workflows/claude.yml",
      ".devcontainer/devcontainer.json",
      "scripts/claude-cloud/setup.sh",
      "scripts/claude/setup-devcontainer.sh",
      "docs/bootstrap/claude-environment.md"
    ];

    for (const legacyPath of legacyPaths) {
      const absolutePath = path.join(targetDir, legacyPath);
      await mkdir(path.dirname(absolutePath), { recursive: true });
      await writeFile(absolutePath, "legacy Claude bootstrap file\n", "utf8");
    }
    await mkdir(path.join(targetDir, ".bootstrap"), { recursive: true });
    await writeFile(
      path.join(targetDir, ".bootstrap/bootstrap-state.json"),
      `${JSON.stringify(
        {
          manifestHash: "legacy",
          templateVersion: "legacy",
          managedFiles: Object.fromEntries(legacyPaths.map((legacyPath) => [legacyPath, "legacy"]))
        },
        null,
        2
      )}\n`,
      "utf8"
    );

    const manifest = normalizeManifest({
      project: {
        name: "already-bootstrapped",
        owner: "acme"
      },
      archetype: {
        kind: "generic-empty"
      },
      agents: {
        manageCodexHome: true
      }
    });

    const planBeforeApply = await planRepo(manifest, targetDir);
    expect(
      legacyPaths.every((legacyPath) =>
        planBeforeApply.changes.some((change) => change.path === legacyPath && change.type === "delete")
      )
    ).toBe(true);

    await applyRepo(manifest, targetDir);

    for (const legacyPath of legacyPaths) {
      await expect(access(path.join(targetDir, legacyPath))).rejects.toThrow();
    }
  });

  it("stores bootstrap state under .git/info when the target is a git repository", async () => {
    const targetDir = await makeTempDir();
    await execFileAsync("git", ["init"], { cwd: targetDir });

    const manifest = normalizeManifest({
      project: {
        name: "git-backed-service",
        owner: "acme"
      },
      archetype: {
        kind: "generic-empty"
      }
    });

    await applyRepo(manifest, targetDir);

    await expect(
      access(path.join(targetDir, ".git/info/bootstrap-state.json"))
    ).resolves.toBeUndefined();
    await expect(access(path.join(targetDir, ".bootstrap/bootstrap-state.json"))).rejects.toThrow();
  });
});
