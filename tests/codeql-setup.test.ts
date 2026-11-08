import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";
import { parse, stringify } from "yaml";

import { renderManagedFiles } from "../src/archetypes.js";
import { githubCapabilitySnapshotSchema, runConformance } from "../src/conformance.js";
import { sha256 } from "../src/lib/hash.js";
import { normalizeManifest, stringifyManifest } from "../src/manifest.js";
import { applyRepo } from "../src/render.js";

const directories: string[] = [];
const controls = [
  "code-scanning", "dependabot-alerts", "dependabot-security-updates", "dependency-graph",
  "private-vulnerability-reporting", "push-protection", "secret-scanning"
];
const validDefaultSetup = { state: "configured", languages: ["actions", "python"], githubHosted: true };
// Captured from parent 161d18e; only the SBOM contents permission changes from write to read.
const legacySecurityWithReadOnlySbomSha256 = "6c0a34c8b76d73249efe85de18e983c9f23e1598e6c14f21a8e79ec133ee05ae";

function input(ci: Record<string, unknown> = {}) {
  return {
    project: { name: "codeql-mode", owner: "acme", visibility: "public", maturity: "stable" },
    repo: { class: "service" },
    archetype: { kind: "node-ts-service" },
    release: { enabled: false },
    ci: { codeqlLanguages: ["python"], ...ci }
  };
}

function capabilities(defaultSetup: unknown = validDefaultSetup, status = "supported") {
  return {
    schemaVersion: 1,
    observations: controls.map((control) => ({
      control, status: control === "code-scanning" ? status : "supported",
      evidence: "Synthetic authorized configuration, successful analysis coverage, and hosted execution observation.",
      remediation: "Restore verified configuration, successful coverage, and GitHub-hosted execution.",
      ...(control === "dependency-graph" ? { dependencyReviewEnabled: true } : {}),
      ...(control === "code-scanning" && defaultSetup !== undefined ? { defaultSetup } : {})
    }))
  };
}

async function fixture(ci: Record<string, unknown> = { codeqlSetup: "default", codeqlLanguages: ["actions", "python"] }) {
  const directory = await mkdtemp(path.join(os.tmpdir(), "bootstrap-codeql-mode-"));
  directories.push(directory);
  const manifest = normalizeManifest(input(ci));
  await applyRepo(manifest, directory);
  const workflowPath = path.join(directory, ".github/workflows/security.yml");
  return { directory, manifest, workflowPath };
}

function securityFailures(report: Awaited<ReturnType<typeof runConformance>>) {
  return report.results.filter((entry) => entry.severity === "blocking" &&
    (entry.ruleId === "PRS-SECURITY-BASELINE-001" || entry.ruleId === "PRS-FORK-SAFETY-001" ||
      entry.ruleId === "PRS-SECURITY-CAPABILITY-001" || entry.ruleId === "PRS-GITHUB-CAPABILITY-001" ||
      entry.ruleId.includes("CODEQL")));
}

async function modifyWorkflow(fixtureValue: Awaited<ReturnType<typeof fixture>>, change: (workflow: any) => void) {
  const workflow = parse(await readFile(fixtureValue.workflowPath, "utf8"));
  change(workflow);
  await writeFile(fixtureValue.workflowPath, stringify(workflow));
}

afterEach(async () => {
  await Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

describe("explicit CodeQL setup mode", () => {
  it("preserves absent-mode serialization and advanced bytes except the intentional read-only SBOM permission", () => {
    const absent = normalizeManifest(input());
    const advanced = normalizeManifest(input({ codeqlSetup: "advanced" }));
    expect(parse(stringifyManifest(absent)).ci).not.toHaveProperty("codeqlSetup");
    expect(parse(stringifyManifest(advanced)).ci.codeqlSetup).toBe("advanced");
    const workflow = (manifest: typeof absent) => renderManagedFiles(manifest)
      .find((file) => file.path === ".github/workflows/security.yml")!.contents;
    expect(workflow(advanced)).toBe(workflow(absent));
    expect(sha256(workflow(absent))).toBe(legacySecurityWithReadOnlySbomSha256);
  });

  it("supports Actions coverage in explicit default mode and rejects unsupported advanced Actions projection", () => {
    const manifest = normalizeManifest(input({ codeqlSetup: "default", codeqlLanguages: ["actions", "python"] }));
    expect(manifest.ci.codeqlLanguages).toEqual(["actions", "python"]);
    expect(parse(stringifyManifest(manifest)).ci.codeqlSetup).toBe("default");
    expect(() => normalizeManifest(input({ codeqlLanguages: ["actions"] }))).toThrow();
    expect(() => normalizeManifest(input({ codeqlSetup: "advanced", codeqlLanguages: ["actions"] }))).toThrow();
    expect(() => normalizeManifest(input({ codeqlSetup: "disabled" }))).toThrow();
    expect(() => normalizeManifest(input({ codeqlSetup: "default", codeqlLanguages: [] }))).toThrow();
  });

  it("omits only the advanced CodeQL job while retaining activated read-only dependency review and trusted SBOM", async () => {
    const { workflowPath } = await fixture();
    const workflow = parse(await readFile(workflowPath, "utf8"));
    expect(Object.keys(workflow.jobs).sort()).toEqual(["dependency-review", "sbom"]);
    expect(workflow.permissions).toEqual({ contents: "read" });
    expect(workflow.on).toMatchObject({ pull_request: null, push: { branches: ["main"] } });
    expect(workflow.on.schedule).toHaveLength(1);
    expect(workflow.jobs["dependency-review"]).toMatchObject({
      if: "github.event_name == 'pull_request' && vars.DEPENDENCY_REVIEW_ENABLED == 'true'",
      "runs-on": "ubuntu-latest", permissions: { contents: "read", "pull-requests": "read" }
    });
    expect(workflow.jobs.sbom).toMatchObject({
      if: "github.event_name == 'push' || github.event_name == 'schedule'",
      "runs-on": "ubuntu-latest", permissions: { contents: "read" }
    });
    expect(workflow.jobs.sbom.steps.at(-1).with).toMatchObject({
      format: "spdx-json", "upload-release-assets": false
    });
  });

  it("passes default-mode security checks only with complete successful hosted analysis evidence", async () => {
    const f = await fixture();
    const report = await runConformance(f.manifest, f.directory, { githubCapabilities: capabilities() });
    expect(securityFailures(report)).toEqual([]);
    expect(report.results).toContainEqual(expect.objectContaining({ ruleId: "PRS-SECURITY-BASELINE-001", severity: "pass" }));
    expect(report.results).toContainEqual(expect.objectContaining({ ruleId: "PRS-FORK-SAFETY-001", severity: "pass" }));
  });

  it.each([
    ["missing proof", undefined, "supported", "unverified"],
    ["not configured", { ...validDefaultSetup, state: "not-configured" }, "supported", "misconfigured"],
    ["partial analyzed coverage", { ...validDefaultSetup, languages: ["python"] }, "supported", "misconfigured"],
    ["no analyzed coverage", { ...validDefaultSetup, languages: [] }, "supported", "misconfigured"],
    ["self-hosted execution", { ...validDefaultSetup, githubHosted: false }, "supported", "misconfigured"],
    ["failed scanning", validDefaultSetup, "misconfigured", "misconfigured"],
    ["unsupported scanning", validDefaultSetup, "unsupported", "misconfigured"]
  ])("blocks default setup with %s", async (_name, proof, status, classification) => {
    const f = await fixture();
    const snapshot = capabilities(proof, status);
    if (proof === undefined) delete (snapshot.observations.find((entry) => entry.control === "code-scanning") as any).defaultSetup;
    const report = await runConformance(f.manifest, f.directory, { githubCapabilities: snapshot });
    expect(securityFailures(report)).toContainEqual(expect.objectContaining({ severity: "blocking", classification }));
  });

  it.each(["unsupported", "misconfigured"])("preserves known scanning %s classification when proof is absent", async (status) => {
    const f = await fixture();
    const snapshot = capabilities();
    const scanning = snapshot.observations.find((entry) => entry.control === "code-scanning")!;
    scanning.status = status;
    delete scanning.defaultSetup;
    const report = await runConformance(f.manifest, f.directory, { githubCapabilities: snapshot });
    const modeResult = report.results.find((entry) => entry.evidence.some((line) => line.startsWith("CodeQL default setup:")));
    expect(modeResult).toMatchObject({ severity: "blocking", classification: "misconfigured" });
  });

  it("does not treat absent capability observations as default-setup proof", async () => {
    const f = await fixture();
    const report = await runConformance(f.manifest, f.directory);
    expect(securityFailures(report)).toContainEqual(expect.objectContaining({ severity: "blocking", classification: "unverified" }));
  });

  it("rejects configured default setup when advanced upload mode is selected", async () => {
    const f = await fixture({ codeqlSetup: "advanced" });
    const report = await runConformance(f.manifest, f.directory, { githubCapabilities: capabilities() });
    expect(securityFailures(report)).toContainEqual(expect.objectContaining({ severity: "blocking", classification: "misconfigured" }));
  });

  it("keeps legacy advanced conformance compatible with snapshots predating the new proof object", async () => {
    const f = await fixture({});
    const observations = capabilities();
    delete (observations.observations.find((entry) => entry.control === "code-scanning") as any).defaultSetup;
    const report = await runConformance(f.manifest, f.directory, { githubCapabilities: observations });
    expect(securityFailures(report)).toEqual([]);
  });

  it.each([
    ["unexpected CodeQL job", (workflow: any) => { workflow.jobs.codeql = structuredClone(workflow.jobs.sbom); }],
    ["writable fork token", (workflow: any) => { workflow.jobs["dependency-review"].permissions.contents = "write"; }],
    ["privileged fork SBOM", (workflow: any) => { workflow.jobs.sbom.if = "github.event_name == 'pull_request'"; }],
    ["self-hosted SBOM", (workflow: any) => { workflow.jobs.sbom["runs-on"] = ["self-hosted", "linux"]; }],
    ["disabled SBOM upload", (workflow: any) => { workflow.jobs.sbom.steps.at(-1).with["upload-artifact"] = false; }],
    ["unreadable SBOM contents", (workflow: any) => { workflow.jobs.sbom.permissions = { contents: "none" }; }],
    ["unnecessary SBOM write permission", (workflow: any) => { workflow.jobs.sbom.permissions = { contents: "write" }; }]
  ])("continues blocking %s in default mode", async (_name, change) => {
    const f = await fixture();
    await modifyWorkflow(f, change as (workflow: any) => void);
    const report = await runConformance(f.manifest, f.directory, { githubCapabilities: capabilities() });
    expect(securityFailures(report).length).toBeGreaterThan(0);
  });

  it("keeps private reporting and dependency configuration required in default mode", async () => {
    const f = await fixture();
    await writeFile(path.join(f.directory, "SECURITY.md"), "# No private reporting route\n");
    await rm(path.join(f.directory, ".github/dependabot.yml"));
    const report = await runConformance(f.manifest, f.directory, { githubCapabilities: capabilities() });
    const evidence = securityFailures(report).flatMap((entry) => entry.evidence).join("\n");
    expect(evidence).toContain("private vulnerability reporting route");
    expect(evidence).toContain("Dependabot");
  });

  it("limits the strict default-setup observation to the code-scanning control", () => {
    expect(() => githubCapabilitySnapshotSchema.parse({ schemaVersion: 1, observations: [{
      control: "push-protection", status: "supported", evidence: "enabled", remediation: "Keep enabled.", defaultSetup: validDefaultSetup
    }] })).toThrow();
    expect(() => githubCapabilitySnapshotSchema.parse(capabilities({ ...validDefaultSetup, extra: "ignored" }))).toThrow();
    expect(() => githubCapabilitySnapshotSchema.parse(capabilities({ ...validDefaultSetup, languages: ["unrecognized-language"] }))).toThrow();
  });
});
