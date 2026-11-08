import { link, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { execFileSync } from "node:child_process";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

import { renderManagedFiles } from "../src/archetypes.js";
import { runConformance } from "../src/conformance.js";
import { normalizeManifest } from "../src/manifest.js";
import { flowPolicyDigest } from "../src/policy.js";
import { sha256 } from "../src/lib/hash.js";
import { applyRepo } from "../src/render.js";
import * as repositoryFiles from "../src/lib/fs.js";

const commitments = [
  "Acknowledge a complete private report within 2 business days.",
  "Triage a confirmed report within 7 calendar days.",
  "Remediate or contain critical findings within 7 calendar days.",
  "Remediate high findings within 30 calendar days.",
  "Coordinate public disclosure with the reporter after remediation."
];
const temporaryDirectories: string[] = [];

async function fixture() {
  const directory = await mkdtemp(path.join(os.tmpdir(), "bootstrap-response-policy-"));
  temporaryDirectories.push(directory);
  const bundle = JSON.parse(await readFile(new URL("../policy/flow-public-standard.json", import.meta.url), "utf8"));
  const policyPath = path.join(directory, "flow-policy.json");
  await writeFile(policyPath, JSON.stringify(bundle));
  const manifest = normalizeManifest({
    project: { name: "flow", owner: "OMT-Global", visibility: "public", maturity: "stable" },
    repo: { class: "specification", docs: { security: false } },
    archetype: { kind: "node-ts-service" },
    release: { enabled: false },
    policy: { flow: { ref: "refs/tags/v1.0.1", sha256: flowPolicyDigest(bundle), bundlePath: "flow-policy.json" } }
  });
  await applyRepo(manifest, directory);
  const header = [
    "# Security Policy",
    "",
    "Use https://github.com/OMT-Global/flow/security/advisories/new for private reports.",
    "",
    "If unavailable, open a Private security contact requested issue without vulnerability details.",
    "",
    "## Response Targets",
    ""
  ].join("\n");
  const document = header + commitments.map((commitment) => `- ${commitment}`).join("\n");
  const documentPath = path.join(directory, "SECURITY.md");
  await writeFile(documentPath, document);
  return { directory, manifest, bundle, policyPath, document, documentPath, header };
}

function baseline(report: Awaited<ReturnType<typeof runConformance>>) {
  return report.results.filter((entry) => entry.ruleId === "PRS-SECURITY-BASELINE-001");
}

function expectBaselinePass(report: Awaited<ReturnType<typeof runConformance>>) {
  expect(baseline(report)).toEqual([expect.objectContaining({ severity: "pass", classification: "conformant" })]);
}

function expectBaselineBlock(report: Awaited<ReturnType<typeof runConformance>>) {
  expect(baseline(report)).toEqual(expect.arrayContaining([expect.objectContaining({ severity: "blocking" })]));
}

afterEach(async () => {
  vi.restoreAllMocks();
  await Promise.all(temporaryDirectories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

describe("product-owned security response policy", () => {
  it("accepts the actual released Flow response commitments as separate list paragraphs", async () => {
    const { directory, manifest } = await fixture();
    const report = await runConformance(manifest, directory);
    expectBaselinePass(report);
    expect(report.results).toContainEqual(expect.objectContaining({ ruleId: "PRS-FORK-SAFETY-001", severity: "pass" }));
    expect(report.results.filter((entry) => entry.ruleId === "PRS-SECURITY-CAPABILITY-001")).toHaveLength(7);
  });

  it("keeps later promises after a genuine email autolink contact", async () => {
    const { directory, manifest, document, documentPath } = await fixture();
    await writeFile(documentPath, `Contact <security@example.org>.\n\n${document}`);
    expectBaselinePass(await runConformance(manifest, directory));
  });

  it.each([
    ["inline code", "- `Example`\n  " + commitments[0]],
    ["inline HTML", "- <span>Example</span>\n  " + commitments[0]],
    ["quoted inline HTML sibling", "> <span>Example</span>\n" + commitments[0]],
    ["HTML blank-line context", "<div>\n\n" + commitments[0] + "\n\n</div>"]
  ])("does not manufacture a promise by removing %s", async (_name, replacement) => {
    const { directory, manifest, document, documentPath } = await fixture();
    await writeFile(documentPath, document.replace(`- ${commitments[0]}`, replacement));
    expectBaselineBlock(await runConformance(manifest, directory));
  });

  it.each([
    ["separate plain paragraphs", commitments.join("\n\n")],
    ["ordered list", commitments.map((line, index) => `${index + 1}. ${line}`).join("\n")],
    ["nested list", "- Response commitments:\n" + commitments.map((line) => `  - ${line}`).join("\n")],
    ["wrapped soft breaks", commitments.map((line) => `- ${line.replace(" within ", "\n  within ")}`).join("\n")],
    ["wrapped hard breaks", commitments.map((line) => `- ${line.replace(" within ", "  \n  within ")}`).join("\n")],
    ["ASCII case and periods", commitments.map((line) => `- ${line.toUpperCase().replace(/\.$/, "")}`).join("\n")]
  ])("accepts %s without changing paragraph ownership", async (_name, body) => {
    const { directory, manifest, header, documentPath } = await fixture();
    await writeFile(documentPath, header + body);
    expectBaselinePass(await runConformance(manifest, directory));
  });

  it.each(commitments)("blocks a missing commitment: %s", async (commitment) => {
    const { directory, manifest, document, documentPath } = await fixture();
    await writeFile(documentPath, document.replace(`- ${commitment}`, ""));
    expectBaselineBlock(await runConformance(manifest, directory));
  });

  it.each([
    ["wrong units", "Acknowledge a complete private report within 2 calendar days."],
    ["wrong deadline", "Acknowledge a complete private report within 3 business days."],
    ["negation", "Do not acknowledge a complete private report within 2 business days."],
    ["prefix", "Example: " + commitments[0]],
    ["suffix", commitments[0] + " This is only an example."],
    ["unrelated numbers", "We review 2 business days of acknowledgement statistics."],
    ["Kelvin case folding", commitments[0]!.replace("k", "K")],
    ["Unicode whitespace", commitments[0]!.replace(" a ", "\u00a0a ")],
    ["Unicode deletion", commitments[0]!.replace("knowledge", "k\u200bnowledge")],
    ["emphasis", "*" + commitments[0] + "*"],
    ["strong", "**" + commitments[0] + "**"],
    ["link", `[${commitments[0]}](https://example.org/)`],
    ["image", `![${commitments[0]}](https://example.org/image.png)`],
    ["inline code", "`" + commitments[0] + "`"]
  ])("rejects %s in a candidate paragraph", async (_name, replacement) => {
    const { directory, manifest, document, documentPath } = await fixture();
    await writeFile(documentPath, document.replace(`- ${commitments[0]}`, `- ${replacement}`));
    expectBaselineBlock(await runConformance(manifest, directory));
  });

  it("does not split five lines of one paragraph into separate promises", async () => {
    const { directory, manifest, header, documentPath } = await fixture();
    await writeFile(documentPath, header + commitments.join("\n"));
    expectBaselineBlock(await runConformance(manifest, directory));
  });

  it("reads the four actual deadlines from the verified policy and supports singular day", async () => {
    const { directory, manifest, bundle, policyPath, document, documentPath } = await fixture();
    bundle.security.responseTargets.acknowledgePrivateReportBusinessDays = 1;
    bundle.security.responseTargets.highRemediateCalendarDays = 31;
    await writeFile(policyPath, JSON.stringify(bundle));
    const candidate = { ...manifest, policy: { flow: { ...manifest.policy!.flow, sha256: flowPolicyDigest(bundle) } } };
    expectBaselineBlock(await runConformance(candidate, directory));
    await writeFile(documentPath, document.replace("within 2 business days", "within 1 business day").replace("high findings within 30 calendar days", "high findings within 31 calendar days"));
    expectBaselinePass(await runConformance(candidate, directory));
  });

  it.each([
    ["missing", undefined], ["string", "2"], ["zero", 0], ["negative", -1],
    ["fraction", 1.5], ["unsafe integer", Number.MAX_SAFE_INTEGER + 1]
  ])("blocks a verified bundle with a %s response target", async (_name, value) => {
    const { directory, manifest, bundle, policyPath } = await fixture();
    if (value === undefined) delete bundle.security.responseTargets.acknowledgePrivateReportBusinessDays;
    else bundle.security.responseTargets.acknowledgePrivateReportBusinessDays = value;
    await writeFile(policyPath, JSON.stringify(bundle));
    const candidate = { ...manifest, policy: { flow: { ...manifest.policy!.flow, sha256: flowPolicyDigest(bundle) } } };
    expectBaselineBlock(await runConformance(candidate, directory));
  });

  it.each(["digest", "version", "extra target", "absent", "malformed", "mutable"])("blocks invalid declared policy (%s) without a generic fallback", async (failure) => {
    const { directory, manifest, bundle, policyPath, documentPath } = await fixture();
    const generic = renderManagedFiles({ ...manifest, repo: { ...manifest.repo, docs: { ...manifest.repo.docs, security: true } } }).find((file) => file.path === "SECURITY.md")!;
    await writeFile(documentPath, generic.contents);
    if (failure === "digest") await writeFile(policyPath, JSON.stringify({ ...bundle, version: "1.0.1" }));
    if (failure === "version") bundle.version = "2.0.0";
    if (failure === "extra target") bundle.security.responseTargets.mediumLowCalendarDays = 90;
    if (failure === "absent") await rm(policyPath);
    if (failure === "malformed") await writeFile(policyPath, "security: [");
    const candidate = { ...manifest, policy: { flow: { ...manifest.policy!.flow,
      ...(failure === "mutable" ? { ref: "refs/heads/main" } : {}),
      ...(["version", "extra target"].includes(failure) ? { sha256: flowPolicyDigest(bundle) } : {})
    } } };
    if (["version", "extra target"].includes(failure)) await writeFile(policyPath, JSON.stringify(bundle));
    expectBaselineBlock(await runConformance(candidate, directory));
  });

  it("retains the generic baseline for managed and no-policy security documents", async () => {
    const { directory, manifest, documentPath } = await fixture();
    const { policy: _flow, ...unconfigured } = manifest;
    const managed = { ...manifest, repo: { ...manifest.repo, docs: { ...manifest.repo.docs, security: true } } };
    expectBaselineBlock(await runConformance(unconfigured, directory));
    expectBaselineBlock(await runConformance(managed, directory));
    await writeFile(documentPath, renderManagedFiles(managed).find((file) => file.path === "SECURITY.md")!.contents);
    expectBaselinePass(await runConformance(unconfigured, directory));
    expectBaselinePass(await runConformance(managed, directory));
  });

  it("continues private routes, fallback, Dependabot, workflow, forks, and remote controls", async () => {
    const { directory, manifest, documentPath } = await fixture();
    await writeFile(documentPath, commitments.map((line) => `- ${line}`).join("\n"));
    await rm(path.join(directory, ".github/dependabot.yml"));
    await rm(path.join(directory, ".github/workflows/security.yml"));
    const report = await runConformance(manifest, directory);
    expect(baseline(report).flatMap((entry) => entry.evidence)).toEqual(expect.arrayContaining([
      expect.stringContaining("private vulnerability reporting route"), expect.stringContaining("fallback"),
      expect.stringContaining("Dependabot"), ".github/workflows/security.yml is absent"
    ]));
    expect(report.results).toContainEqual(expect.objectContaining({ ruleId: "PRS-FORK-SAFETY-001", severity: "blocking" }));
    expect(report.results.filter((entry) => entry.ruleId === "PRS-SECURITY-CAPABILITY-001")).toHaveLength(7);
  });

  it.each([false, true].flatMap((licensed) => ["symlink", "hardlink", "oversized", ...(process.platform === "win32" ? [] : ["FIFO"])].map((leaf) => [licensed, leaf] as const)))(
    "requires manual ownership migration for historical managed SECURITY (licensed=%s, leaf=%s)",
    async (licensed, leaf) => {
      const directory = await mkdtemp(path.join(os.tmpdir(), "bootstrap-security-ownership-"));
      temporaryDirectories.push(directory);
      const bundle = JSON.parse(await readFile(new URL("../policy/flow-public-standard.json", import.meta.url), "utf8"));
      await writeFile(path.join(directory, "flow-policy.json"), JSON.stringify(bundle));
      const template = "Copyright {{copyright_years}} {{copyright_holder}}\nSynthetic proprietary test terms.\n";
      if (licensed) await writeFile(path.join(directory, "proprietary.txt"), template);
      const managed = normalizeManifest({
        project: { name: "flow", owner: "OMT-Global", visibility: "public", maturity: "stable" },
        repo: { class: "specification", docs: { security: true } },
        archetype: { kind: "node-ts-service" },
        release: { enabled: false },
        policy: { flow: { ref: "refs/tags/v1.0.1", sha256: flowPolicyDigest(bundle), bundlePath: "flow-policy.json" } },
        ...(licensed ? { license: {
          mode: "proprietary", holder: "Test Example LLC", holderVerification: "test-fixture:holder", years: "2026",
          template: { path: "proprietary.txt", sha256: sha256(template), approval: "test-fixture:template" },
          thirdPartyNotices: []
        } } : {})
      });
      await applyRepo(managed, directory);
      const state = JSON.parse(await readFile(path.join(directory, ".bootstrap/bootstrap-state.json"), "utf8"));
      expect(state.managedFiles["SECURITY.md"]).toMatch(/^[a-f0-9]{64}$/);
      const productOwned = { ...managed, repo: { ...managed.repo, docs: { ...managed.repo.docs, security: false } } };
      const documentPath = path.join(directory, "SECURITY.md");
      await rm(documentPath);
      if (leaf === "symlink") {
        const privateTarget = path.join(directory, "private-target.txt");
        await writeFile(privateTarget, "PRIVATE_OWNERSHIP_TARGET_CONTENT");
        await symlink(privateTarget, documentPath);
      } else if (leaf === "hardlink") {
        const linkedSource = path.join(directory, "linked-source.md");
        await writeFile(linkedSource, "PRIVATE_OWNERSHIP_TARGET_CONTENT");
        await link(linkedSource, documentPath);
      } else if (leaf === "FIFO") {
        execFileSync("mkfifo", [documentPath]);
      } else {
        await writeFile(documentPath, Buffer.alloc(64 * 1_024 + 1, 0x78));
      }
      await rm(path.join(directory, ".github/dependabot.yml"));
      await rm(path.join(directory, ".github/workflows/security.yml"));
      const original = repositoryFiles.readTextIfExists;
      const legacyRead = vi.spyOn(repositoryFiles, "readTextIfExists").mockImplementation(async (filePath) => {
        if (path.resolve(filePath) === documentPath) throw new Error("LEGACY_OWNERSHIP_SECURITY_READ_OCCURRED");
        return original(filePath);
      });

      const report = await runConformance(productOwned, directory);

      expect(legacyRead.mock.calls.filter(([filePath]) => path.resolve(filePath) === documentPath)).toEqual([]);
      expectBaselineBlock(report);
      expect(report.results).toContainEqual(expect.objectContaining({
        ruleId: "PRS-OWNERSHIP-001", severity: "blocking",
        evidence: expect.arrayContaining([expect.stringMatching(/SECURITY\.md.*(?:ownership|migration)|(?:ownership|migration).*SECURITY\.md/i)])
      }));
      expect(baseline(report).flatMap((entry) => entry.evidence)).toEqual(expect.arrayContaining([
        expect.stringContaining("Dependabot"), ".github/workflows/security.yml is absent"
      ]));
      expect(report.results).toContainEqual(expect.objectContaining({ ruleId: "PRS-FORK-SAFETY-001", severity: "blocking" }));
      expect(report.results.filter((entry) => entry.ruleId === "PRS-SECURITY-CAPABILITY-001")).toHaveLength(7);
      if (licensed) expect(report.results).toContainEqual(expect.objectContaining({ ruleId: "PRS-LICENSE-001", severity: "pass" }));
      expect(JSON.stringify(report)).not.toMatch(/LEGACY_OWNERSHIP_SECURITY_READ_OCCURRED|PRIVATE_OWNERSHIP_TARGET_CONTENT|private-target\.txt/);
    }
  );

  it("selects the bounded product reader before any legacy SECURITY read and never falls back", async () => {
    const { directory, manifest, documentPath } = await fixture();
    const outside = path.join(directory, "outside-private-target.txt");
    await writeFile(outside, "PRIVATE_FILE_CONTENT_SHOULD_NOT_APPEAR");
    await rm(documentPath);
    await symlink(outside, documentPath);
    const original = repositoryFiles.readTextIfExists;
    const legacyRead = vi.spyOn(repositoryFiles, "readTextIfExists").mockImplementation(async (filePath) => {
      if (path.resolve(filePath) === documentPath) throw new Error("LEGACY_SECURITY_READ_OCCURRED");
      return original(filePath);
    });
    const report = await runConformance(manifest, directory);
    expectBaselineBlock(report);
    expect(legacyRead.mock.calls.some(([filePath]) => path.resolve(filePath) === documentPath)).toBe(false);
    expect(JSON.stringify(report)).not.toContain("PRIVATE_FILE_CONTENT_SHOULD_NOT_APPEAR");
    expect(JSON.stringify(report)).not.toContain(outside);
    expect(JSON.stringify(report)).not.toContain("LEGACY_SECURITY_READ_OCCURRED");
  });
});
