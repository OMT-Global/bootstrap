import { execFile } from "node:child_process";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { afterEach, describe, expect, it } from "vitest";
import { parse } from "yaml";

import { renderManagedFiles } from "../src/archetypes.js";
import { normalizeManifest } from "../src/manifest.js";
import type { ArchetypeKind, RenderedFile } from "../src/types.js";

const execFileAsync = promisify(execFile);
const tempDirs: string[] = [];
const reviewedActions = {
  ".github/workflows/pr-fast-ci.yml": ["dorny/paths-filter@ceb8a2b8f2d89434be7ff52d3de7ec3738c5cc9d"],
  ".github/workflows/extended-validation.yml": ["dorny/paths-filter@ceb8a2b8f2d89434be7ff52d3de7ec3738c5cc9d"],
  ".github/workflows/security.yml": [
    "anchore/sbom-action@66cbf4bc1f1c0d2edc94016e65bc221b6bb0ad6c",
    "github/codeql-action/analyze@33d7b85da1a04171e211befe2c739303b9a4c066",
    "github/codeql-action/init@33d7b85da1a04171e211befe2c739303b9a4c066"
  ]
};

function render(kind: ArchetypeKind = "node-ts-service"): RenderedFile[] {
  return renderManagedFiles(normalizeManifest({
    project: { name: "generator-alignment", owner: "acme", visibility: "public" },
    archetype: { kind },
    release: { enabled: false },
    ci: { codeqlLanguages: ["javascript-typescript", "python", "go", "swift"] }
  }));
}

function expectReviewedActionPins(files: RenderedFile[]): void {
  for (const [filePath, expected] of Object.entries(reviewedActions)) {
    const file = files.find((file) => file.path === filePath);
    expect(file, filePath).toBeDefined();
    const workflow: { jobs: Record<string, { steps?: { uses?: string }[] }> } = parse(file!.contents);
    const selectedActions = Object.values(workflow.jobs)
      .flatMap((job) => job.steps ?? [])
      .flatMap((step) => step.uses ? [step.uses] : [])
      .filter((uses) => /^(dorny\/paths-filter|github\/codeql-action\/(init|analyze)|anchore\/sbom-action)@/.test(uses));
    expect(selectedActions.sort(), filePath).toEqual(expected);
    const codeQlRefs = selectedActions.filter((uses) => uses.startsWith("github/codeql-action/"))
      .map((uses) => uses.split("@")[1]);
    if (codeQlRefs.length > 0) expect(new Set(codeQlRefs).size, `${filePath}: coherent CodeQL pair`).toBe(1);
  }
}

async function checkGeneratedPins(files: RenderedFile[]): Promise<{ code: number; output: string }> {
  const directory = await mkdtemp(path.join(os.tmpdir(), "bootstrap-generator-alignment-"));
  tempDirs.push(directory);
  const workflows = path.join(directory, ".github/workflows");
  await mkdir(workflows, { recursive: true });
  for (const file of files.filter((file) => file.path.startsWith(".github/workflows/"))) {
    await writeFile(path.join(directory, file.path), file.contents);
  }
  const script = path.join(directory, "check-action-pins.sh");
  await writeFile(script, files.find((file) => file.path === "scripts/ci/check-action-pins.sh")!.contents);
  try {
    const result = await execFileAsync("bash", [script, workflows]);
    return { code: 0, output: result.stdout + result.stderr };
  } catch (error) {
    const result = error as { code: number; stdout: string; stderr: string };
    return { code: result.code, output: result.stdout + result.stderr };
  }
}

afterEach(async () => {
  await Promise.all(tempDirs.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

describe("reviewed generator alignment", () => {
  it.each<ArchetypeKind>(["nextjs-web", "node-ts-service", "python-service", "generic-empty"])(
    "preserves the reviewed action versions and paired CodeQL ref for %s",
    (kind) => expectReviewedActionPins(render(kind))
  );

  it.each([
    ["paths-filter", "ceb8a2b8f2d89434be7ff52d3de7ec3738c5cc9d", "7b450fff21473bca461d4b92ce414b9d0420d706"],
    ["CodeQL init", "github/codeql-action/init@33d7b85da1a04171e211befe2c739303b9a4c066", "github/codeql-action/init@7188fc363630916deb702c7fdcf4e481b751f97a"],
    ["CodeQL analyze", "github/codeql-action/analyze@33d7b85da1a04171e211befe2c739303b9a4c066", "github/codeql-action/analyze@7188fc363630916deb702c7fdcf4e481b751f97a"],
    ["SBOM", "66cbf4bc1f1c0d2edc94016e65bc221b6bb0ad6c", "e22c389904149dbc22b58101806040fa8d37a610"]
  ])("detects an immutable but stale %s output", (_name, current, stale) => {
    const downgraded = render().map((file) => ({ ...file, contents: file.contents.replaceAll(current, stale) }));
    expect(() => expectReviewedActionPins(downgraded)).toThrow();
  });

  it("emits immutable third-party refs with readable release metadata", async () => {
    const result = await checkGeneratedPins(render());
    expect(result.code, result.output).toBe(0);
    expect(result.output).toContain("PASS SA-ACTION-PIN-000");
  });

  it.each([
    ["mutable refs", "dorny/paths-filter@v4.0.3 # v4.0.3", "SA-ACTION-PIN-001"],
    ["missing metadata", "dorny/paths-filter@ceb8a2b8f2d89434be7ff52d3de7ec3738c5cc9d", "SA-ACTION-PIN-002"]
  ])("rejects generated output with %s", async (_name, replacement, diagnostic) => {
    const files = render().map((file) => ({
      ...file,
      contents: file.contents.replaceAll("dorny/paths-filter@ceb8a2b8f2d89434be7ff52d3de7ec3738c5cc9d # v4.0.3", replacement)
    }));
    const result = await checkGeneratedPins(files);
    expect(result.code).toBe(1);
    expect(result.output).toContain(diagnostic);
  });

  it("preserves onboarding evidence for fork-safe governance and immutable action refs", () => {
    const onboarding = render().find((file) => file.path === "docs/bootstrap/onboarding.md")!.contents;
    expect(onboarding).toContain("fork-safe `pull_request` event with only read permissions");
    expect(onboarding).toContain("Conventional titles, contributed-commit DCO trailers, changed-line accounting, and material-change ADR/reviewer evidence without accessing repository secrets");
    expect(onboarding).toContain("every third-party `uses:` entry is a 40-character commit SHA followed by readable tag metadata");
    expect(onboarding).toContain("fails closed on mutable references and silently ignores local or Bootstrap-owned reusable workflows");
  });
});
