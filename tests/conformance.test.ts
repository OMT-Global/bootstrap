import { mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { describe, expect, it, vi } from "vitest";

import { conformanceReportSchema, formatConformanceReport, runConformance } from "../src/conformance.js";
import { normalizeManifest } from "../src/manifest.js";
import { applyRepo } from "../src/render.js";
import { sha256 } from "../src/lib/hash.js";

const proprietaryTemplate = "Copyright {{copyright_years}} {{copyright_holder}}\nApproved proprietary terms.\n";

async function fixtureDirectory(): Promise<string> {
  return mkdtemp(path.join(os.tmpdir(), "bootstrap-conformance-"));
}

describe("runConformance", () => {
  it("returns deterministic machine-validated blocking results for missing contract fields", async () => {
    const directory = await fixtureDirectory();
    const manifest = normalizeManifest({ project: { name: "missing-contract", owner: "acme" }, archetype: { kind: "generic-empty" } });

    const report = await runConformance(manifest, directory);

    expect(conformanceReportSchema.parse(report)).toEqual(report);
    expect(report.exitCode).toBe(1);
    expect(report.results.map((entry) => entry.ruleId)).toEqual([
      "PRS-CLASS-001",
      "PRS-LICENSE-001",
      "PRS-MATURITY-001",
      "PRS-OWNERSHIP-001",
      "PRS-PROFILE-001"
    ]);
  });

  it("passes the core for an applied canonical contract", async () => {
    const directory = await fixtureDirectory();
    await writeFile(path.join(directory, "pyproject.toml"), "[project]\nname = 'service'\n");
    await writeFile(path.join(directory, "proprietary.txt"), proprietaryTemplate);
    const manifest = normalizeManifest({
      project: { name: "canonical-contract", owner: "acme", maturity: "stable" },
      license: {
        mode: "proprietary",
        holder: "Acme LLC",
        holderVerification: "legal-entity:acme-llc",
        years: "2026",
        template: { path: "proprietary.txt", sha256: sha256(proprietaryTemplate), approval: "counsel:P-1" },
        thirdPartyNotices: []
      },
      repo: { class: "service" },
      archetype: { kind: "node-ts-service" }
    });
    await applyRepo(manifest, directory);

    const report = await runConformance(manifest, directory);

    expect(report.exitCode).toBe(0);
    expect(report.summary.warning).toBe(0);
    expect(report.results).toContainEqual(expect.objectContaining({ ruleId: "PRS-PROFILE-001", severity: "pass" }));
    expect(report.results).toContainEqual(expect.objectContaining({ ruleId: "PRS-LICENSE-RECOGNITION-001", severity: "pass" }));
    expect(formatConformanceReport(report)).toContain("Conformance: 0 blocking, 0 warning");
  });

  it("accepts a missing canonical class with a valid scoped exception that is nearing expiry", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-07-16T12:00:00.000Z"));
    const directory = await fixtureDirectory();
    const manifest = normalizeManifest({
      project: { name: "class-exception", owner: "acme", maturity: "maintenance" },
      archetype: { kind: "generic-empty" },
      exceptions: [
        {
          id: "legacy-class",
          policy: "repository-classification",
          scope: "repo.class",
          rationale: "Class selection is pending owner review.",
          approvedBy: "alice",
          issue: "#56",
          expiresAt: "2026-07-20"
        }
      ]
    });

    try {
      const report = await runConformance(manifest, directory);

      expect(report.results).toContainEqual(
        expect.objectContaining({
          ruleId: "PRS-CLASS-001",
          severity: "pass",
          evidence: ["approved exception legacy-class"]
        })
      );
      expect(report.results).toContainEqual(
        expect.objectContaining({ ruleId: "PRS-EXCEPTION-001", severity: "warning" })
      );
    } finally {
      vi.useRealTimers();
    }
  });

  it("reports an existing-license replacement as a stable legal hard stop", async () => {
    const directory = await fixtureDirectory();
    await writeFile(path.join(directory, "proprietary.txt"), proprietaryTemplate);
    await writeFile(path.join(directory, "LICENSE"), "MIT License\nCopyright prior holder\n");
    const manifest = normalizeManifest({
      project: { name: "license-transition", owner: "acme", maturity: "stable" },
      repo: { class: "service" },
      license: {
        mode: "proprietary",
        holder: "Acme LLC",
        holderVerification: "legal-entity:acme-llc",
        years: "2026",
        template: { path: "proprietary.txt", sha256: sha256(proprietaryTemplate), approval: "counsel:P-1" },
        thirdPartyNotices: []
      },
      archetype: { kind: "generic-empty" }
    });

    const report = await runConformance(manifest, directory);
    expect(report.results).toContainEqual(expect.objectContaining({ ruleId: "PRS-LICENSE-TRANSITION-001", severity: "blocking" }));
    expect(report.results).not.toContainEqual(expect.objectContaining({
      ruleId: "PRS-OWNERSHIP-001",
      severity: "blocking",
      evidence: [expect.stringContaining("PRS-LICENSE-TRANSITION-001")]
    }));
  });

  it("fails closed with a stable template rule when approved content does not match its pin", async () => {
    const directory = await fixtureDirectory();
    await writeFile(path.join(directory, "proprietary.txt"), proprietaryTemplate);
    const manifest = normalizeManifest({
      project: { name: "template-drift", owner: "acme", maturity: "stable" },
      repo: { class: "service" },
      license: {
        mode: "proprietary",
        holder: "Acme LLC",
        holderVerification: "legal-entity:acme-llc",
        years: "2026",
        template: { path: "proprietary.txt", sha256: "0".repeat(64), approval: "counsel:P-1" },
        thirdPartyNotices: []
      },
      archetype: { kind: "generic-empty" }
    });

    const report = await runConformance(manifest, directory);
    expect(report.results).toContainEqual(expect.objectContaining({ ruleId: "PRS-LICENSE-TEMPLATE-001", severity: "blocking" }));
  });

  it("reports independent ownership drift alongside a license-policy failure", async () => {
    const directory = await fixtureDirectory();
    await writeFile(path.join(directory, "proprietary.txt"), proprietaryTemplate);
    const configured = normalizeManifest({
      project: { name: "combined-failures", owner: "acme", maturity: "stable" },
      repo: { class: "service" },
      license: {
        mode: "proprietary",
        holder: "Acme LLC",
        holderVerification: "legal-entity:acme-llc",
        years: "2026",
        template: { path: "proprietary.txt", sha256: sha256(proprietaryTemplate), approval: "counsel:P-1" },
        thirdPartyNotices: []
      },
      archetype: { kind: "generic-empty" }
    });
    await applyRepo(configured, directory);
    await writeFile(path.join(directory, "AGENTS.md"), "direct edit\n");
    await writeFile(path.join(directory, "LICENSE"), "direct edit\n");
    await rm(path.join(directory, "README.md"));
    await rm(path.join(directory, "THIRD_PARTY_NOTICES.md"));

    const invalidTemplate = normalizeManifest({
      ...configured,
      license: {
        ...configured.license!,
        template: { ...configured.license!.template, sha256: "0".repeat(64) }
      }
    });
    const report = await runConformance(invalidTemplate, directory);

    expect(report.results).toContainEqual(expect.objectContaining({
      ruleId: "PRS-LICENSE-TEMPLATE-001",
      severity: "blocking"
    }));
    expect(report.results).toContainEqual(expect.objectContaining({
      ruleId: "PRS-OWNERSHIP-001",
      severity: "blocking",
      evidence: ["Managed file AGENTS.md was directly modified."]
    }));
    expect(report.results).toContainEqual(expect.objectContaining({
      ruleId: "PRS-OWNERSHIP-001",
      severity: "blocking",
      evidence: ["Managed file README.md was deleted."]
    }));
    expect(report.results).toContainEqual(expect.objectContaining({
      ruleId: "PRS-OWNERSHIP-001",
      severity: "blocking",
      evidence: ["Managed file LICENSE was directly modified."]
    }));
    expect(report.results).toContainEqual(expect.objectContaining({
      ruleId: "PRS-OWNERSHIP-001",
      severity: "blocking",
      evidence: ["Managed file THIRD_PARTY_NOTICES.md was deleted."]
    }));
  });

  it("preserves the ownership rule when a managed license is edited or deleted", async () => {
    const directory = await fixtureDirectory();
    await writeFile(path.join(directory, "proprietary.txt"), proprietaryTemplate);
    const manifest = normalizeManifest({
      project: { name: "managed-license-drift", owner: "acme", maturity: "stable" },
      repo: { class: "service" },
      license: {
        mode: "proprietary",
        holder: "Acme LLC",
        holderVerification: "legal-entity:acme-llc",
        years: "2026",
        template: { path: "proprietary.txt", sha256: sha256(proprietaryTemplate), approval: "counsel:P-1" },
        thirdPartyNotices: []
      },
      archetype: { kind: "generic-empty" }
    });
    await applyRepo(manifest, directory);

    await writeFile(path.join(directory, "LICENSE"), "direct edit\n");
    const editedReport = await runConformance(manifest, directory);
    expect(editedReport.results).toContainEqual(expect.objectContaining({
      ruleId: "PRS-OWNERSHIP-001",
      severity: "blocking",
      evidence: ["Managed file LICENSE was directly modified."]
    }));
    expect(editedReport.results.filter((entry) =>
      entry.ruleId === "PRS-OWNERSHIP-001" && entry.evidence.some((item) => /managed(?: file)? LICENSE was directly modified/i.test(item))
    ).length).toBe(1);

    await rm(path.join(directory, "LICENSE"));
    const deletedReport = await runConformance(manifest, directory);
    expect(deletedReport.results).toContainEqual(expect.objectContaining({
      ruleId: "PRS-OWNERSHIP-001",
      severity: "blocking",
      evidence: ["Managed file LICENSE was deleted."]
    }));
  });

  it("validates LICENSE path safety before reading it without a declared policy", async () => {
    const directory = await fixtureDirectory();
    await symlink(path.join(directory, "missing-license-target"), path.join(directory, "LICENSE"));
    const manifest = normalizeManifest({
      project: { name: "unsafe-unlicensed-output", owner: "acme", maturity: "stable" },
      repo: { class: "service" },
      archetype: { kind: "generic-empty" }
    });

    const report = await runConformance(manifest, directory);
    expect(report.results).toContainEqual(expect.objectContaining({
      ruleId: "PRS-OWNERSHIP-001",
      severity: "blocking",
      evidence: [expect.stringContaining("LICENSE must be a regular, non-linked repository file")]
    }));
  });
});
