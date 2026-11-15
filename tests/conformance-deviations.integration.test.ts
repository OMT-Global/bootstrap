import { afterEach, describe, expect, it, vi } from "vitest";

// Close external routes before importing the real local-file consumers.
const external = vi.hoisted(() => ({ blocked: vi.fn(() => { throw new Error("External route is closed in conformance predicate tests."); }) }));
vi.hoisted(() => { vi.stubGlobal("fetch", external.blocked); });
vi.mock("node:http", async (original) => {
  const actual = await original<typeof import("node:http")>();
  return { ...actual, request: external.blocked, get: external.blocked, default: { ...actual, request: external.blocked, get: external.blocked } };
});
vi.mock("node:https", async (original) => {
  const actual = await original<typeof import("node:https")>();
  return { ...actual, request: external.blocked, get: external.blocked, default: { ...actual, request: external.blocked, get: external.blocked } };
});
vi.mock("node:dns", async (original) => {
  const actual = await original<typeof import("node:dns")>();
  const closed = Object.fromEntries(Object.keys(actual).filter((key) => typeof actual[key as keyof typeof actual] === "function").map((key) => [key, external.blocked]));
  const promises = Object.fromEntries(Object.keys(actual.promises).map((key) => [key, external.blocked]));
  return { ...actual, ...closed, promises, default: { ...actual, ...closed, promises } };
});
vi.mock("node:dns/promises", async (original) => {
  const actual = await original<typeof import("node:dns/promises")>();
  const closed = Object.fromEntries(Object.keys(actual).filter((key) => typeof actual[key as keyof typeof actual] === "function").map((key) => [key, external.blocked]));
  return { ...actual, ...closed, default: { ...actual, ...closed } };
});
vi.mock("node:child_process", async (original) => {
  const actual = await original<typeof import("node:child_process")>();
  const closed = Object.fromEntries(["exec", "execFile", "execSync", "execFileSync", "spawn", "spawnSync", "fork"].map((key) => [key, external.blocked]));
  return { ...actual, ...closed, default: { ...actual, ...closed } };
});
afterEach(() => { expect(external.blocked).not.toHaveBeenCalled(); });

import { mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { conformanceReportSchema, formatConformanceReport, runConformance } from "../src/conformance.js";
import { normalizeManifest } from "../src/manifest.js";
import { flowPolicyDigest } from "../src/policy.js";
import { applyRepo } from "../src/render.js";
import type { BootstrapManifest, PolicyException } from "../src/types.js";

const directories: string[] = [];
async function directory(): Promise<string> {
  const target = await mkdtemp(path.join(os.tmpdir(), "bootstrap-deviation-consumer-"));
  directories.push(target);
  return target;
}
afterEach(async () => {
  await Promise.all(directories.splice(0).map((target) => rm(target, { recursive: true, force: true })));
});
type ManifestExceptions = NonNullable<Parameters<typeof normalizeManifest>[0]["exceptions"]>;
function waiver(id: string, fields: Partial<PolicyException> = {}): ManifestExceptions[number] {
  return { id, policy: "repository-files", scope: "repo.managed-artifacts", rationale: "Fabricated local migration", approvedBy: "fixture-reviewer", issue: "#62", expiresAt: "2099-01-01", ...fields };
}
function withExceptions(manifest: BootstrapManifest, exceptions: ManifestExceptions): BootstrapManifest {
  return normalizeManifest({ ...manifest, exceptions });
}
function requiredFiles(report: Awaited<ReturnType<typeof runConformance>>) {
  return report.results.filter((entry) => entry.ruleId === "PRS-REQUIRED-FILE-001");
}
async function appliedRepository() {
  const target = await directory();
  const manifest = normalizeManifest({
    project: { name: "local-predicate-fixture", owner: "fixture-owner", maturity: "stable" },
    repo: { class: "service" }, archetype: { kind: "node-ts-service" }, release: { enabled: false }
  });
  await applyRepo(manifest, target);
  return { target, manifest };
}

describe("ordinary conformance consumes shared deviation predicates", () => {
  it("preserves complete ordinary results and formatting when a matching waiver is stored for a passing rule", async () => {
    const { target, manifest } = await appliedRepository();
    const ordinary = await runConformance(manifest, target);
    const stored = await runConformance(withExceptions(manifest, [waiver("stored-files")]), target);
    expect(requiredFiles(ordinary)).toEqual([expect.objectContaining({ severity: "pass", classification: "conformant" })]);
    expect(stored.results.filter((entry) => entry.ruleId !== "PRS-EXCEPTION-001")).toEqual(ordinary.results);
    expect(conformanceReportSchema.parse(stored)).toEqual(stored);
    expect(formatConformanceReport(stored)).toContain(`Conformance: ${stored.summary.blocking} blocking, ${stored.summary.warning} warning`);
    expect(requiredFiles(stored)[0]!.evidence.join(" ")).not.toContain("approved exception");
  });

  it("keeps actual validator-ineligible exceptions from waiving an actual missing artifact", async () => {
    const { target, manifest } = await appliedRepository();
    await rm(path.join(target, "AGENTS.md"));
    const ordinary = await runConformance(manifest, target);
    const permanentWithoutAdr = waiver("permanent-without-adr", { permanent: true });
    delete permanentWithoutAdr.expiresAt;
    const rejected = await runConformance(withExceptions(manifest, [
      waiver("expired", { expiresAt: "2000-01-01" }),
      permanentWithoutAdr,
      waiver("wrong-policy", { policy: "supply-chain" }),
      waiver("wrong-scope", { scope: "repo.profile" })
    ]), target);
    expect(requiredFiles(ordinary)).toEqual([{
      ruleId: "PRS-REQUIRED-FILE-001", severity: "blocking", classification: "misconfigured",
      evidence: ["AGENTS.md"], remediation: "Run bootstrap apply repo to restore the required managed artifacts."
    }]);
    expect(requiredFiles(rejected)).toEqual(requiredFiles(ordinary));
    const invalid = rejected.results.filter((entry) => entry.ruleId === "PRS-EXCEPTION-001" && entry.severity === "blocking");
    expect(invalid).toHaveLength(2);
    expect(invalid.flatMap((entry) => entry.evidence)).toEqual(expect.arrayContaining([
      "Temporary exception expired expired on 2000-01-01.",
      "Permanent exception permanent-without-adr has no ADR."
    ]));
  });

  it("skips expired records and selects the first eligible manifest record despite validator lexical order", async () => {
    const { target, manifest } = await appliedRepository();
    await rm(path.join(target, "AGENTS.md"));
    const report = await runConformance(withExceptions(manifest, [
      waiver("0-expired", { expiresAt: "2000-01-01" }),
      waiver("z-first-valid"), waiver("a-second-valid")
    ]), target);
    expect(requiredFiles(report)).toEqual([{
      ruleId: "PRS-REQUIRED-FILE-001", severity: "pass", classification: "waived",
      evidence: ["AGENTS.md", "approved exception z-first-valid"],
      remediation: "Keep approved exception z-first-valid current until the governed deviation is resolved."
    }]);
    expect(report.exitCode).toBe(1);
    expect(conformanceReportSchema.parse(report)).toEqual(report);
  });
});

const commitments = [
  "Acknowledge a complete private report within 2 business days",
  "Triage a confirmed report within 7 calendar days",
  "Remediate or contain critical findings within 7 calendar days",
  "Remediate high findings within 30 calendar days",
  "Coordinate public disclosure with the reporter after remediation"
];
async function productPolicyRepository() {
  const target = await directory();
  // Use the unchanged checked-in released policy, never an invented positive target tuple.
  const bundleText = await readFile(new URL("../policy/flow-public-standard.json", import.meta.url), "utf8");
  const bundle = JSON.parse(bundleText);
  await writeFile(path.join(target, "flow-policy.json"), bundleText);
  const manifest = normalizeManifest({
    project: { name: "flow", owner: "OMT-Global", visibility: "public", maturity: "stable" },
    repo: { class: "specification", docs: { security: false } },
    archetype: { kind: "node-ts-service" }, release: { enabled: false },
    policy: { flow: { ref: "refs/tags/v1.0.1", sha256: flowPolicyDigest(bundle), bundlePath: "flow-policy.json" } }
  });
  await applyRepo(manifest, target);
  const document = "# Security Policy\n\nUse https://github.com/OMT-Global/flow/security/advisories/new for private reports.\n\nIf unavailable, open a Private security contact requested issue without vulnerability details.\n\n## Response Targets\n\n" + commitments.map((entry) => `- ${entry}.`).join("\n");
  await writeFile(path.join(target, "SECURITY.md"), document);
  return { target, manifest, document };
}
function baseline(report: Awaited<ReturnType<typeof runConformance>>) {
  return report.results.filter((entry) => entry.ruleId === "PRS-SECURITY-BASELINE-001");
}

describe("protected product policy consumer", () => {
  it("accepts the released commitments, preserves ordinary output, then reports the exact missing commitment", async () => {
    const { target, manifest, document } = await productPolicyRepository();
    const passing = await runConformance(manifest, target);
    expect(baseline(passing)).toEqual([expect.objectContaining({ severity: "pass", classification: "conformant" })]);
    expect(conformanceReportSchema.parse(passing)).toEqual(passing);
    await writeFile(path.join(target, "SECURITY.md"), document.replace(`- ${commitments[0]}.`, ""));
    const failing = await runConformance(manifest, target);
    expect(baseline(failing)).toEqual(expect.arrayContaining([expect.objectContaining({
      severity: "blocking", classification: "misconfigured",
      evidence: expect.arrayContaining([`SECURITY.md does not define the verified Flow response commitment: ${commitments[0]}.`])
    })]));
    expect(failing.exitCode).toBe(1);
  });

  it("rejects raw HTML without satisfying commitments from a partial parse", async () => {
    const { target, manifest, document } = await productPolicyRepository();
    await writeFile(path.join(target, "SECURITY.md"), document + "\n\n<!-- fixture raw HTML -->");
    expect(baseline(await runConformance(manifest, target))).toEqual(expect.arrayContaining([expect.objectContaining({
      severity: "blocking", evidence: expect.arrayContaining(["SECURITY.md response policy Markdown is unsupported: raw-html."])
    })]));
  });

  it("retains the protected leaf reader and rejects a SECURITY.md symlink to fabricated local content", async () => {
    const { target, manifest, document } = await productPolicyRepository();
    const outside = path.join(await directory(), "fabricated-policy.md");
    await writeFile(outside, document);
    await rm(path.join(target, "SECURITY.md"));
    await symlink(outside, path.join(target, "SECURITY.md"));
    expect(baseline(await runConformance(manifest, target))).toEqual(expect.arrayContaining([expect.objectContaining({
      severity: "blocking", evidence: expect.arrayContaining(["SECURITY.md response policy input is unsupported: unsupported-file."])
    })]));
    expect(await readFile(outside, "utf8")).toBe(document);
  });
});
