import { execFile } from "node:child_process";
import { access, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";

import { afterEach, describe, expect, it } from "vitest";

import { normalizeManifest } from "../src/manifest.js";
import { applyRepo, planRepo } from "../src/render.js";
import { OWNERSHIP_SIDECAR_PATH } from "../src/state.js";

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
    const ownership = JSON.parse(await readFile(path.join(targetDir, OWNERSHIP_SIDECAR_PATH), "utf8"));
    expect(ownership).toMatchObject({
      schemaVersion: 1,
      owner: "bootstrap",
      regenerationCommand: "bootstrap apply repo --manifest ./project.bootstrap.yaml"
    });
    expect(ownership.managedFiles["AGENTS.md"]).toMatchObject({ source: "bootstrap" });
  });

  it("blocks direct edits to previously managed files instead of overwriting them", async () => {
    const targetDir = await makeTempDir();
    const manifest = normalizeManifest({
      project: { name: "owned-edit", owner: "acme" },
      archetype: { kind: "generic-empty" }
    });

    await applyRepo(manifest, targetDir);
    await writeFile(path.join(targetDir, "AGENTS.md"), "product-owned direct edit\n", "utf8");

    await expect(planRepo(manifest, targetDir)).rejects.toThrow("AGENTS.md was directly modified");
  });

  it("blocks direct edits using the ownership sidecar when local state is unavailable", async () => {
    const targetDir = await makeTempDir();
    const manifest = normalizeManifest({
      project: { name: "sidecar-owned-edit", owner: "acme" },
      archetype: { kind: "generic-empty" }
    });

    await execFileAsync("git", ["init", "-q"], { cwd: targetDir });
    await execFileAsync("git", ["config", "user.name", "Bootstrap Tests"], { cwd: targetDir });
    await execFileAsync("git", ["config", "user.email", "bootstrap-tests@example.invalid"], { cwd: targetDir });
    await applyRepo(manifest, targetDir);
    await execFileAsync("git", ["add", "-A"], { cwd: targetDir });
    await execFileAsync("git", ["-c", "commit.gpgsign=false", "commit", "-qm", "test: track generated projection"], { cwd: targetDir });
    await rm(path.join(targetDir, ".git/info/bootstrap-state.json"));
    await writeFile(path.join(targetDir, "AGENTS.md"), "product-owned direct edit\n", "utf8");

    await expect(planRepo(manifest, targetDir)).rejects.toThrow(
      "AGENTS.md cannot be updated from mutable sidecar ownership alone"
    );
  });

  it("blocks direct edits when the ownership sidecar is missing a rendered managed file", async () => {
    const targetDir = await makeTempDir();
    const manifest = normalizeManifest({
      project: { name: "sidecar-missing-owned-edit", owner: "acme" },
      archetype: { kind: "generic-empty" }
    });

    await applyRepo(manifest, targetDir);
    await rm(path.join(targetDir, ".bootstrap/bootstrap-state.json"));
    const ownershipPath = path.join(targetDir, OWNERSHIP_SIDECAR_PATH);
    const ownership = JSON.parse(await readFile(ownershipPath, "utf8"));
    delete ownership.managedFiles["AGENTS.md"];
    await writeFile(ownershipPath, `${JSON.stringify(ownership, null, 2)}\n`, "utf8");
    await writeFile(path.join(targetDir, "AGENTS.md"), "product-owned direct edit\n", "utf8");

    await expect(planRepo(manifest, targetDir)).rejects.toThrow("ownership sidecar is invalid or incomplete");
  });

  it("fails closed for invalid ownership-sidecar schema", async () => {
    const targetDir = await makeTempDir();
    const manifest = normalizeManifest({ project: { name: "invalid-sidecar-schema", owner: "acme" }, archetype: { kind: "generic-empty" } });
    await applyRepo(manifest, targetDir);
    await rm(path.join(targetDir, ".bootstrap/bootstrap-state.json"));
    const ownershipPath = path.join(targetDir, OWNERSHIP_SIDECAR_PATH);
    const ownership = JSON.parse(await readFile(ownershipPath, "utf8"));
    ownership.schemaVersion = 2;
    await writeFile(ownershipPath, JSON.stringify(ownership), "utf8");
    await expect(planRepo(manifest, targetDir)).rejects.toThrow("ownership sidecar is invalid or incomplete");
  });

  it("fails closed for malformed ownership-sidecar JSON", async () => {
    const targetDir = await makeTempDir();
    const manifest = normalizeManifest({ project: { name: "malformed-sidecar", owner: "acme" }, archetype: { kind: "generic-empty" } });
    await applyRepo(manifest, targetDir);
    await rm(path.join(targetDir, ".bootstrap/bootstrap-state.json"));
    await writeFile(path.join(targetDir, OWNERSHIP_SIDECAR_PATH), "{invalid", "utf8");
    await expect(planRepo(manifest, targetDir)).rejects.toThrow("ownership sidecar is invalid or incomplete");
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
          ".githooks/pre-commit",
          ".github/PULL_REQUEST_TEMPLATE.md",
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
    await expect(access(path.join(targetDir, ".githooks/pre-commit"))).resolves.toBeUndefined();
    await expect(access(path.join(targetDir, ".github/PULL_REQUEST_TEMPLATE.md"))).resolves.toBeUndefined();

    const secondPlan = await planRepo(manifest, targetDir);
    expect(secondPlan.changes.every((change) => change.type === "unchanged")).toBe(true);
  });

  it("plans version 2 guidance companions for canonical restricted managed paths", async () => {
    const targetDir = await makeTempDir();
    const manifest = normalizeManifest({
      version: 2,
      project: {
        name: "mailplus-intelligence",
        displayName: "MailPlus Intelligence",
        description: "Intelligence and automation workspace for MailPlus-related tooling.",
        visibility: "public",
        owner: "OMT-Global",
        defaultBranch: "main"
      },
      repo: {
        class: "library",
        managedPaths: [
          "project.bootstrap.yaml",
          "AGENTS.md",
          "CLAUDE.md",
          "CODEOWNERS",
          "CONTRIBUTING.md",
          "LICENSE",
          "SECURITY.md",
          ".githooks/**",
          ".devcontainer/**",
          ".github/workflows/pr-fast-ci.yml",
          ".github/workflows/extended-validation.yml",
          ".github/workflows/claude.yml",
          ".github/workflows/release.yml",
          "scripts/check-detect-secrets.sh",
          "scripts/ci/**",
          "scripts/release/**",
          "scripts/codex-cloud/**",
          "scripts/claude-cloud/**",
          "scripts/claude/**",
          "docs/bootstrap/**"
        ],
        docs: {
          readme: true,
          contributing: true,
          security: true
        },
        templates: {
          pullRequest: "standard",
          issueTemplates: ["bug", "feature"]
        },
        env: {
          exampleFile: false,
          strategy: "optional"
        },
        hooks: {
          preCommit: "standard",
          prePush: "none"
        }
      },
      archetype: {
        kind: "generic-empty",
        packageManager: "python",
        moduleName: "mailplus_intelligence"
      },
      github: {
        createRepo: false,
        reviewers: ["jmcte"],
        codeowners: [
          {
            pattern: "*",
            owners: ["@jmcte"]
          }
        ],
        autoMerge: true,
        deleteBranchOnMerge: true,
        requiredApprovals: 1,
        requiredStatusChecks: ["CI Gate"],
        dismissStaleReviews: true,
        requireCodeOwnerReviews: true,
        requireLastPushApproval: true,
        enforceLinearHistory: true,
        allowMergeCommit: true,
        allowSquashMerge: true,
        allowRebaseMerge: true,
        repoFeatures: {
          hasIssues: true,
          hasProjects: false,
          hasWiki: false,
          hasDiscussions: false
        },
        security: {
          dependabot: true,
          secretScanningHints: true
        }
      },
      ci: {
        policy: "experimental",
        runnerPolicy: "hybrid-safe",
        nodeVersion: "20",
        pythonVersion: "3.12",
        fastChecks: ["secrets", "unit-tests"],
        extendedChecks: ["template-review", "fixture-regression"],
        nightlyCron: "0 7 * * *",
        workflows: {
          prFastCi: true,
          extendedValidation: true,
          claude: true,
          pagesDeploy: false,
          ci: false,
          extras: []
        },
        additionalWorkflows: []
      },
      agents: {
        manageCodexHome: true,
        manageClaudeHome: true,
        codexProfile: "default",
        claudeProfile: "default",
        enableClaudeWebEnvironment: true,
        enableClaudeDevcontainer: true,
        enableClaudeGitHubAction: true,
        sharedSkills: []
      },
      capabilities: {
        pages: {
          enabled: false,
          provider: "cloudflare-pages",
          outputDir: "dist"
        },
        release: {
          enabled: true,
          kind: "github-release"
        },
        docsPublish: {
          enabled: false
        },
        containers: {
          enabled: false
        }
      },
      environments: {
        dev: {
          reviewers: [],
          requireApproval: false,
          preventSelfReview: false,
          branches: []
        },
        stage: {
          reviewers: ["jmcte"],
          requireApproval: true,
          preventSelfReview: true,
          branches: []
        },
        prod: {
          reviewers: ["jmcte"],
          requireApproval: true,
          preventSelfReview: true,
          branches: ["main"]
        }
      }
    });

    const plan = await planRepo(manifest, targetDir);

    expect(plan.changes.some((change) => change.path === ".github/PULL_REQUEST_TEMPLATE.md")).toBe(true);
    expect(plan.files.some((file) => file.path === ".github/PULL_REQUEST_TEMPLATE.md")).toBe(true);
  });

  it("rejects selected guidance when repo.managedPaths excludes referenced companion files", async () => {
    const targetDir = await makeTempDir();
    const manifest = normalizeManifest({
      project: {
        name: "cloudcurator",
        displayName: "CloudCurator",
        description:
          "Native macOS menu bar organizer for keeping iCloud Drive files local, tagged, searchable, and reversible.",
        visibility: "private",
        owner: "OMT-Global"
      },
      repo: {
        managedPaths: [
          "AGENTS.md",
          "CONTRIBUTING.md",
          "CODEOWNERS",
          ".github/PULL_REQUEST_TEMPLATE.md",
          ".github/ISSUE_TEMPLATE/implementation.yml",
          ".github/ISSUE_TEMPLATE/flow_blocker.yml"
        ]
      },
      archetype: {
        kind: "generic-empty",
        packageManager: "npm",
        moduleName: "CloudCurator"
      },
      github: {
        reviewers: ["jmcte"],
        flowGovernance: true,
        requiredStatusChecks: ["CI Gate"]
      },
      release: {
        enabled: false
      },
      agents: {
        manageCodexHome: false,
        sharedSkills: ["github", "build-macos-apps"]
      }
    });

    await expect(planRepo(manifest, targetDir)).rejects.toThrow(
      "Invalid repo.managedPaths: selected bootstrap guidance excludes required companion files."
    );
    await expect(planRepo(manifest, targetDir)).rejects.toThrow(".githooks/pre-commit");
    await expect(planRepo(manifest, targetDir)).rejects.toThrow("docs/bootstrap/onboarding.md");
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
