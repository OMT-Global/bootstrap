import { link, mkdir, mkdtemp, readFile, readdir, rm, symlink, writeFile } from "node:fs/promises";
import { execFileSync } from "node:child_process";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

import { renderManagedFiles } from "../src/archetypes.js";
import { runConformance } from "../src/conformance.js";
import { loadManifest, normalizeManifest, stringifyManifest } from "../src/manifest.js";
import { flowPolicyDigest, loadResolvedFlowPolicy, MAX_FLOW_POLICY_BYTES, resolveFlowPolicy } from "../src/policy.js";
import { sha256 } from "../src/lib/hash.js";
import * as repositoryFiles from "../src/lib/fs.js";
import { applyRepo, planRepo, resolveRepositoryProjection } from "../src/render.js";

const directories: string[] = [];
async function fixture(licensed = false) {
  const directory = await mkdtemp(path.join(os.tmpdir(), "bootstrap-managed-policy-"));
  directories.push(directory);
  const bundle = JSON.parse(await readFile(new URL("../policy/flow-public-standard.json", import.meta.url), "utf8"));
  await writeFile(path.join(directory, "flow-policy.json"), JSON.stringify(bundle));
  const template = "Copyright {{copyright_years}} {{copyright_holder}}\nSynthetic proprietary test terms.\n";
  if (licensed) await writeFile(path.join(directory, "proprietary.txt"), template);
  const manifest = normalizeManifest({
    project: { name: "example", owner: "acme", visibility: "public", maturity: "stable" },
    repo: { class: "service", docs: { security: true } },
    archetype: { kind: "node-ts-service" }, release: { enabled: false },
    ...(licensed ? { license: {
      mode: "proprietary", holder: "Test Example LLC", holderVerification: "test-fixture:holder", years: "2026",
      template: { path: "proprietary.txt", sha256: sha256(template), approval: "test-fixture:template" }, thirdPartyNotices: []
    } } : {}),
    policy: { flow: { ref: "refs/tags/v1.0.1", sha256: flowPolicyDigest(bundle), bundlePath: "flow-policy.json" } }
  });
  const resolved = resolveFlowPolicy(manifest, bundle, manifest.policy!.flow);
  return { directory, manifest, bundle, resolved };
}
function baseline(report: Awaited<ReturnType<typeof runConformance>>) {
  return report.results.filter((entry) => entry.ruleId === "PRS-SECURITY-BASELINE-001");
}

afterEach(async () => { vi.restoreAllMocks(); await Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true }))); });

describe("managed verified Flow response policy", () => {
  it("rejects legacy managed response text when the verified pin requires different commitments", async () => {
    const { directory, manifest } = await fixture();
    const { policy: _pin, ...legacy } = manifest;
    await applyRepo(legacy, directory);
    expect(baseline(await runConformance(manifest, directory))).toEqual(expect.arrayContaining([
      expect.objectContaining({ severity: "blocking", evidence: expect.arrayContaining([expect.stringContaining("verified Flow response commitment")]) })
    ]));
  });

  it("projects the pinned commitments rather than the generic acknowledgement", async () => {
    const { manifest, resolved } = await fixture();
    const files = renderManagedFiles(manifest, resolved);
    const document = files.find((file: { path: string }) => file.path === "SECURITY.md")!.contents;
    expect(document).toContain("Acknowledge a complete private report within 2 business days.");
    expect(document).toContain("Triage a confirmed report within 7 calendar days.");
    expect(document).toContain("Provide a status update within 10 business days");
    expect(document).toContain("90 days for moderate");
    expect(document).not.toContain("within 3 business days");
  });

  it("requires a matching runtime-verified context before pure managed rendering", async () => {
    const { manifest, resolved } = await fixture();
    expect(() => renderManagedFiles(manifest)).toThrow("PRS-POLICY-SOURCE-001");
    expect(() => renderManagedFiles(manifest, { ...resolved, source: { ...resolved.source, ref: "refs/tags/v1.0.2" } })).toThrow("PRS-POLICY-SOURCE-001");
  });

  it("fails planning and applying before output or ownership writes for a missing bundle", async () => {
    const { directory, manifest } = await fixture();
    await rm(path.join(directory, "flow-policy.json"));
    await expect(planRepo(manifest, directory)).rejects.toThrow("PRS-POLICY-SOURCE-001");
    await expect(applyRepo(manifest, directory)).rejects.toThrow("PRS-POLICY-SOURCE-001");
    expect(await readdir(directory)).toEqual([]);
  });

  it("uses alternate verified target values and preserves installed-byte hashes across clean clone planning", async () => {
    const { directory, manifest, bundle } = await fixture();
    bundle.security.responseTargets = {
      acknowledgePrivateReportBusinessDays: 1, triageCalendarDays: 8,
      criticalRemediateOrContainCalendarDays: 9, highRemediateCalendarDays: 31
    };
    await writeFile(path.join(directory, "flow-policy.json"), JSON.stringify(bundle));
    const candidate = { ...manifest, policy: { flow: { ...manifest.policy!.flow, sha256: flowPolicyDigest(bundle) } } };
    const applied = await applyRepo(candidate, directory);
    const document = await readFile(path.join(directory, "SECURITY.md"), "utf8");
    expect(document).toContain("within 1 business day.");
    expect(document).toContain("within 8 calendar days.");
    expect(document).toContain("critical findings within 9 calendar days.");
    expect(document).toContain("high findings within 31 calendar days.");
    expect(baseline(await runConformance(candidate, directory))).toEqual([expect.objectContaining({ severity: "pass" })]);
    expect((await planRepo(candidate, directory)).changes.every((entry) => entry.type === "unchanged")).toBe(true);
    const sidecar = JSON.parse(await readFile(path.join(directory, ".bootstrap/managed-files.json"), "utf8"));
    expect(sidecar.managedFiles["SECURITY.md"].sha256).toBe(sha256(document));
    // A clean checkout has portable sidecar claims but no trusted local fallback state.
    await rm(path.join(directory, ".bootstrap/bootstrap-state.json"));
    expect((await planRepo(candidate, directory)).changes.every((entry) => entry.type === "unchanged")).toBe(true);
    expect(applied.files.find((entry) => entry.path === "SECURITY.md")!.contents).toBe(document);
  });

  it.each(["mutated body", "different digest", "mutable ref", "incompatible version", "invalid target"])(
    "rejects a forged or stale pure context (%s)", async (failure) => {
      const { manifest, bundle, resolved } = await fixture();
      if (failure === "mutated body") bundle.security.responseTargets.triageCalendarDays = 8;
      if (failure === "different digest") resolved.source.sha256 = "0".repeat(64);
      if (failure === "mutable ref") manifest.policy!.flow.ref = resolved.source.ref = "refs/heads/main";
      if (failure === "incompatible version") bundle.version = "2.0.0";
      if (failure === "invalid target") bundle.security.responseTargets.triageCalendarDays = 0;
      if (["incompatible version", "invalid target"].includes(failure)) manifest.policy!.flow.sha256 = resolved.source.sha256 = flowPolicyDigest(bundle);
      expect(() => renderManagedFiles(manifest, resolved)).toThrow("PRS-POLICY-SOURCE-001");
    }
  );

  it.each(["wrong digest", "mutable ref", "incompatible version", "invalid target", "missing target", "extra target", "malformed", "outside root"])(
    "blocks invalid local sources before writes while independent controls continue (%s)", async (failure) => {
      const { directory, manifest, bundle } = await fixture(true);
      if (failure === "wrong digest") bundle.version = "1.0.1";
      if (failure === "mutable ref") manifest.policy!.flow.ref = "refs/heads/main";
      if (failure === "incompatible version") bundle.version = "2.0.0";
      if (failure === "invalid target") bundle.security.responseTargets.triageCalendarDays = 1.5;
      if (failure === "missing target") delete bundle.security.responseTargets.triageCalendarDays;
      if (failure === "extra target") bundle.security.responseTargets.extra = 90;
      if (["incompatible version", "invalid target", "missing target", "extra target"].includes(failure)) manifest.policy!.flow.sha256 = flowPolicyDigest(bundle);
      if (failure === "outside root") manifest.policy!.flow.bundlePath = "../flow-policy.json";
      await writeFile(path.join(directory, "flow-policy.json"), failure === "malformed" ? "security: [" : JSON.stringify(bundle));
      const before = await readdir(directory);
      await expect(planRepo(manifest, directory)).rejects.toThrow("PRS-POLICY-SOURCE-001");
      await expect(applyRepo(manifest, directory)).rejects.toThrow("PRS-POLICY-SOURCE-001");
      expect(await readdir(directory)).toEqual(before);
      const report = await runConformance(manifest, directory);
      expect(report.results).toContainEqual(expect.objectContaining({ ruleId: "PRS-POLICY-SOURCE-001", severity: "blocking" }));
      expect(report.results.filter((entry) => ["PRS-REQUIRED-FILE-001", "PRS-LICENSE-001"].includes(entry.ruleId)).every((entry) => entry.severity === "blocking")).toBe(true);
      expect(report.results).toContainEqual(expect.objectContaining({ ruleId: "PRS-FORK-SAFETY-001", severity: "blocking" }));
      expect(report.results.filter((entry) => entry.ruleId === "PRS-SECURITY-CAPABILITY-001")).toHaveLength(7);
      expect(baseline(report)).toEqual(expect.arrayContaining([expect.objectContaining({ severity: "blocking", evidence: expect.arrayContaining([expect.stringContaining("Dependabot")]) })]));
    }
  );

  it.each([false, true].flatMap((licensed) => ["symlink", "hardlink", "oversized", ...(process.platform === "win32" ? [] : ["FIFO"])].map((leaf) => [licensed, leaf] as const)))(
    "blocks unsupported managed input before generic presence/hash/planner reads (licensed=%s, leaf=%s)", async (licensed, leaf) => {
      const { directory, manifest } = await fixture(licensed);
      await applyRepo(manifest, directory);
      const ownershipPath = path.join(directory, ".bootstrap/managed-files.json");
      const ownership = await readFile(ownershipPath, "utf8");
      const documentPath = path.join(directory, "SECURITY.md");
      await rm(documentPath);
      const other = path.join(directory, "unmanaged-policy-source.txt");
      if (["symlink", "hardlink"].includes(leaf)) {
        await writeFile(other, "SYNTHETIC_UNMANAGED_SOURCE");
        if (leaf === "symlink") await symlink(other, documentPath);
        else await link(other, documentPath);
      } else if (leaf === "FIFO") execFileSync("mkfifo", [documentPath]);
      else await writeFile(documentPath, "x".repeat(65_537));
      const realRead = repositoryFiles.readTextIfExists;
      let genericSecurityReads = 0;
      vi.spyOn(repositoryFiles, "readTextIfExists").mockImplementation(async (file) => {
        if (file === documentPath) { genericSecurityReads++; throw new Error("Unexpected generic SECURITY read"); }
        return realRead(file);
      });
      const report = await runConformance(manifest, directory);
      expect(genericSecurityReads).toBe(0);
      expect(baseline(report)).toEqual(expect.arrayContaining([expect.objectContaining({ severity: "blocking", evidence: expect.arrayContaining([expect.stringContaining("unsupported")]) })]));
      expect(report.results).toContainEqual(expect.objectContaining({ ruleId: "PRS-REQUIRED-FILE-001", severity: "blocking" }));
      expect(report.results.filter((entry) => entry.ruleId === "PRS-SECURITY-CAPABILITY-001")).toHaveLength(7);
      expect(await readFile(ownershipPath, "utf8")).toBe(ownership);
    }
  );

  it("keeps product-owned and explicitly excluded documents outside selected managed output", async () => {
    const { directory, manifest } = await fixture();
    const product = { ...manifest, repo: { ...manifest.repo, docs: { ...manifest.repo.docs, security: false } } };
    await writeFile(path.join(directory, "SECURITY.md"), "Synthetic product-owned document bytes.\n");
    expect((await resolveRepositoryProjection(product, directory)).files.some((entry) => entry.path === "SECURITY.md")).toBe(false);
    await applyRepo(product, directory);
    expect(await readFile(path.join(directory, "SECURITY.md"), "utf8")).toBe("Synthetic product-owned document bytes.\n");
    const excluded = { ...manifest, repo: { ...manifest.repo, managedPaths: ["project.bootstrap.yaml"] } };
    expect((await resolveRepositoryProjection(excluded, directory)).files.map((entry) => entry.path)).toEqual(["project.bootstrap.yaml"]);
  });


  it("keeps the entire unconfigured SECURITY output byte-identical to the actual base", async () => {
    const { manifest } = await fixture();
    const { policy: _pin, ...unconfigured } = manifest;
    const document = renderManagedFiles(unconfigured).find((entry) => entry.path === "SECURITY.md")!.contents;
    // Captured from the same manifest against base e40248b, before implementation.
    expect(sha256(document)).toBe("35028358837797f5615480538d5f143e275e3b9aa15d5a5e7617b96db0050e6d");
  });

  it("retains independent managed-file drift evidence when policy resolution prevents legal projection", async () => {
    const { directory, manifest } = await fixture(true);
    await applyRepo(manifest, directory);
    await writeFile(path.join(directory, "README.md"), "Synthetic unexpected README drift.\n");
    manifest.policy!.flow.sha256 = "0".repeat(64);
    const report = await runConformance(manifest, directory);
    expect(report.results).toContainEqual(expect.objectContaining({ ruleId: "PRS-POLICY-SOURCE-001", severity: "blocking" }));
    expect(report.results).toContainEqual(expect.objectContaining({ ruleId: "PRS-OWNERSHIP-001", severity: "blocking", evidence: ["Managed file README.md was directly modified."] }));
    expect(report.results).toContainEqual(expect.objectContaining({ ruleId: "PRS-LICENSE-001", severity: "blocking", evidence: [expect.stringContaining("projection is unavailable")] }));
    expect(report.results.some((entry) => ["PRS-LICENSE-001", "PRS-LICENSE-NOTICES-001", "PRS-REQUIRED-FILE-001"].includes(entry.ruleId) && entry.severity === "pass")).toBe(false);
  });


  it.each(["outside leaf symlink", "outside parent symlink", "hardlink", "directory", "dangling link", "invalid UTF8", "oversized", ...(process.platform === "win32" ? [] : ["FIFO"])])(
    "rejects unsafe automatic policy sources before output or state writes (%s)", async (kind) => {
      const { directory, manifest, bundle } = await fixture();
      const policyPath = path.join(directory, "flow-policy.json");
      await rm(policyPath);
      const outside = await mkdtemp(path.join(os.tmpdir(), "bootstrap-policy-outside-"));
      directories.push(outside);
      const outsidePath = path.join(outside, "public-policy.json");
      await writeFile(outsidePath, JSON.stringify(bundle));
      if (kind === "outside leaf symlink") await symlink(outsidePath, policyPath);
      if (kind === "outside parent symlink") {
        await symlink(outside, path.join(directory, "linked-parent"));
        manifest.policy!.flow.bundlePath = "linked-parent/public-policy.json";
      }
      if (kind === "hardlink") await link(outsidePath, policyPath);
      if (kind === "directory") await mkdir(policyPath);
      if (kind === "dangling link") await symlink(path.join(outside, "missing.json"), policyPath);
      if (kind === "FIFO") execFileSync("mkfifo", [policyPath]);
      if (kind === "invalid UTF8") await writeFile(policyPath, Buffer.concat([Buffer.from(JSON.stringify(bundle)), Buffer.from([0xff])]));
      if (kind === "oversized") await writeFile(policyPath, JSON.stringify(bundle).padEnd(MAX_FLOW_POLICY_BYTES + 1, " "));
      const before = await readdir(directory);
      await expect(loadResolvedFlowPolicy(manifest, directory)).rejects.toThrow("bounded regular, singly linked UTF-8 file within the repository root");
      await expect(planRepo(manifest, directory)).rejects.toThrow("PRS-POLICY-SOURCE-001");
      await expect(applyRepo(manifest, directory)).rejects.toThrow("PRS-POLICY-SOURCE-001");
      expect(await readdir(directory)).toEqual(before);
      expect(await readFile(outsidePath, "utf8")).toBe(JSON.stringify(bundle));
    }
  );

  it("accepts exactly the bounded source size and rejects one byte more", async () => {
    const { directory, manifest, bundle } = await fixture();
    const policyPath = path.join(directory, "flow-policy.json");
    await writeFile(policyPath, JSON.stringify(bundle).padEnd(MAX_FLOW_POLICY_BYTES, " "));
    await expect(loadResolvedFlowPolicy(manifest, directory)).resolves.toMatchObject({ source: { ref: manifest.policy!.flow.ref, sha256: manifest.policy!.flow.sha256 } });
    await writeFile(policyPath, JSON.stringify(bundle).padEnd(MAX_FLOW_POLICY_BYTES + 1, " "));
    await expect(loadResolvedFlowPolicy(manifest, directory)).rejects.toThrow("bounded regular");
  });

  it("preserves installed outputs and local ownership state when a source later becomes invalid", async () => {
    const { directory, manifest } = await fixture(true);
    await applyRepo(manifest, directory);
    const paths = ["SECURITY.md", "project.bootstrap.yaml", ".bootstrap/managed-files.json", ".bootstrap/bootstrap-state.json", "LICENSE"];
    const before = await Promise.all(paths.map((entry) => readFile(path.join(directory, entry), "utf8")));
    await writeFile(path.join(directory, "flow-policy.json"), "security: [");
    await expect(applyRepo(manifest, directory)).rejects.toThrow("PRS-POLICY-SOURCE-001");
    expect(await Promise.all(paths.map((entry) => readFile(path.join(directory, entry), "utf8")))).toEqual(before);
  });


  it("uses the repository target as the policy source root for external manifests without fallback", async () => {
    const { directory, manifest, bundle } = await fixture();
    const external = await mkdtemp(path.join(os.tmpdir(), "bootstrap-external-manifest-"));
    directories.push(external);
    const manifestPath = path.join(external, "project.bootstrap.yaml");
    await writeFile(manifestPath, stringifyManifest(manifest));
    await writeFile(path.join(external, "flow-policy.json"), "security: [");
    const loaded = await loadManifest(manifestPath);
    expect((await planRepo(loaded, directory)).files.find((entry) => entry.path === "SECURITY.md")!.contents).toContain("within 2 business days.");
    await writeFile(path.join(external, "flow-policy.json"), JSON.stringify(bundle));
    await rm(path.join(directory, "flow-policy.json"));
    await expect(planRepo(loaded, directory)).rejects.toThrow("PRS-POLICY-SOURCE-001");
  });

});
