import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import YAML from "yaml";

import { renderManagedFiles } from "../src/archetypes.js";
import { runConformance } from "../src/conformance.js";
import { runDoctor } from "../src/doctor.js";
import { normalizeManifest, stringifyManifest } from "../src/manifest.js";
import { applyRepo } from "../src/render.js";
import { resolveRunsOn } from "../src/runners.js";

const base = {
  project: { name: "hosted-image", owner: "acme", visibility: "public" as const, maturity: "stable" as const },
  repo: { class: "service" as const },
  archetype: { kind: "node-ts-service" as const },
  release: { reusableWorkflowRef: "a".repeat(40) }
};

function rendered(githubHostedImage?: "ubuntu-latest" | "ubuntu-24.04", governed = false) {
  const manifest = normalizeManifest({
    ...base,
    ci: { runnerPolicy: "github-hosted-first", githubHostedImage, workflows: { claude: true }, aiAttestation: { enabled: true, reusableWorkflowRef: "a".repeat(40) } },
    release: { ...base.release, ...(governed ? { maturity: "governed" as const } : {}) },
    agents: { enableClaudeGitHubAction: true }
  });
  return renderManagedFiles(manifest);
}

function workflow(files: ReturnType<typeof rendered>, name: string) {
  const file = files.find((entry) => entry.path === `.github/workflows/${name}.yml`);
  expect(file).toBeDefined();
  return YAML.parse(file!.contents);
}

describe("ci.githubHostedImage", () => {
  it("preserves absent normalization and accepts an explicit image through serialization", () => {
    const absent = normalizeManifest(base);
    expect(absent.ci).not.toHaveProperty("githubHostedImage");
    expect(stringifyManifest(absent)).not.toContain("githubHostedImage:");
    const configured = normalizeManifest({ ...base, ci: { githubHostedImage: "ubuntu-24.04" } });
    expect(configured.ci.githubHostedImage).toBe("ubuntu-24.04");
    expect(normalizeManifest(YAML.parse(stringifyManifest(configured))).ci.githubHostedImage).toBe("ubuntu-24.04");
  });

  it.each([
    { label: "self-hosted", input: "self-hosted" },
    { label: "unsupported hosted version", input: "ubuntu-22.04" },
    { label: "runner expression", input: "${{ inputs.runner }}" },
    { label: "runner array", input: ["ubuntu-latest"] }
  ])(
    "rejects unsupported $label",
    ({ input: githubHostedImage }) => {
      expect(() => normalizeManifest({ ...base, ci: { githubHostedImage } } as never)).toThrow();
    }
  );

  it("retains the default rendered bytes when ubuntu-latest is selected explicitly", () => {
    const output = (image?: "ubuntu-latest") => rendered(image).filter((file) => file.path !== "project.bootstrap.yaml");
    expect(output("ubuntu-latest")).toEqual(output());
  });

  it("selects the hosted image without changing capability routing or private pool labels", () => {
    expect(resolveRunsOn("github-hosted-first", "public", ["shell"], "ubuntu-24.04")).toBe("ubuntu-24.04");
    for (const capability of ["docker", "services", "browser", "container-job"] as const) {
      expect(resolveRunsOn("hybrid-safe", "private", [capability], "ubuntu-24.04")).toBe("ubuntu-24.04");
    }
    expect(resolveRunsOn("hybrid-safe", "private", ["shell"], "ubuntu-24.04")).toEqual([
      "self-hosted", "linux", "shell-only", "private"
    ]);
    expect(resolveRunsOn("self-hosted-first", "public", ["shell"], "ubuntu-24.04")).toEqual([
      "self-hosted", "linux", "shell-only", "public"
    ]);
  });

  it("renders selected ordinary CI, automation, and supported simple release runners", () => {
    const files = rendered("ubuntu-24.04");
    for (const name of ["pr-fast-ci", "extended-validation", "issue-hygiene", "claude"]) {
      for (const job of Object.values(workflow(files, name).jobs) as Array<Record<string, unknown>>) {
        expect(job["runs-on"]).toBe("ubuntu-24.04");
      }
    }
    expect(workflow(files, "release-tag").jobs.release.with["runs-on"]).toBe('["ubuntu-24.04"]');
  });

  it("keeps public security hosted and read-only on pull requests, and Swift on macOS", () => {
    const manifest = normalizeManifest({ ...base, ci: { runnerPolicy: "self-hosted-first", githubHostedImage: "ubuntu-24.04", codeqlLanguages: ["javascript-typescript", "swift"] } });
    const security = workflow(renderManagedFiles(manifest), "security");
    expect(security.on).toHaveProperty("pull_request");
    expect(security.on).not.toHaveProperty("pull_request_target");
    expect(security.permissions).toEqual({ contents: "read" });
    expect(security.jobs["dependency-review"]["runs-on"]).toBe("ubuntu-24.04");
    expect(security.jobs["dependency-review"].permissions).toEqual({ contents: "read", "pull-requests": "read" });
    expect(security.jobs.sbom["runs-on"]).toBe("ubuntu-24.04");
    expect(security.jobs.sbom.permissions).toEqual({ contents: "read" });
    expect(security.jobs.codeql["runs-on"]).toBe("${{ matrix.runner }}");
    expect(security.jobs.codeql.strategy.matrix.include).toEqual([
      { language: "javascript-typescript", "build-mode": "none", runner: "ubuntu-24.04" },
      { language: "swift", "build-mode": "autobuild", runner: "macos-14" }
    ]);
  });

  it("leaves pinned governed release caller/reusable contracts and shared attestation unchanged", () => {
    const before = rendered(undefined, true);
    const after = rendered("ubuntu-24.04", true);
    const paths = before.filter((file) => /^\.github\/workflows\/(release-|full-release-|ai-attestation)/.test(file.path));
    expect(paths).toHaveLength(9);
    for (const file of paths) expect(after.find((entry) => entry.path === file.path)).toEqual(file);
  });

  it("reports the selected ordinary runner through doctor", async () => {
    const manifest = normalizeManifest({ ...base, ci: { runnerPolicy: "github-hosted-first", githubHostedImage: "ubuntu-24.04" } });
    const checks = await runDoctor(manifest, { runner: async () => ({ stdout: "", stderr: "unavailable", exitCode: 1 }), homeDir: "/tmp/hosted-image-home" });
    expect(checks).toContainEqual({ name: "Runner policy", status: "ok", detail: "Shell-safe jobs resolve to ubuntu-24.04." });
  });

  it("accepts the selected CodeQL matrix and rejects an inconsistent Linux entry", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "bootstrap-hosted-image-"));
    try {
      const manifest = normalizeManifest({ ...base, ci: { githubHostedImage: "ubuntu-24.04" } });
      await applyRepo(manifest, directory);
      const accepted = await runConformance(manifest, directory);
      expect(accepted.results).toContainEqual(expect.objectContaining({ ruleId: "PRS-SECURITY-BASELINE-001", severity: "pass" }));
      expect(accepted.results).toContainEqual(expect.objectContaining({ ruleId: "PRS-FORK-SAFETY-001", severity: "pass" }));
      const file = path.join(directory, ".github/workflows/security.yml");
      const contents = await readFile(file, "utf8");
      expect(contents).toContain("runner: ubuntu-24.04");
      await writeFile(file, contents.replace("runner: ubuntu-24.04", "runner: ubuntu-latest"));
      const rejected = await runConformance(manifest, directory);
      expect(rejected.results).toContainEqual(expect.objectContaining({ ruleId: "PRS-SECURITY-BASELINE-001", severity: "blocking", evidence: expect.arrayContaining([expect.stringContaining("CodeQL languages do not match")]) }));
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
});
