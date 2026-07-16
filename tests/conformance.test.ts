import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { describe, expect, it, vi } from "vitest";

import { conformanceReportSchema, formatConformanceReport, runConformance } from "../src/conformance.js";
import { normalizeManifest } from "../src/manifest.js";
import { applyRepo } from "../src/render.js";

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
      "PRS-MATURITY-001",
      "PRS-OWNERSHIP-001",
      "PRS-PROFILE-001"
    ]);
  });

  it("passes the core for an applied canonical contract and keeps warning semantics distinct", async () => {
    const directory = await fixtureDirectory();
    await writeFile(path.join(directory, "pyproject.toml"), "[project]\nname = 'service'\n");
    const manifest = normalizeManifest({
      project: { name: "canonical-contract", owner: "acme", maturity: "stable" },
      repo: { class: "service" },
      archetype: { kind: "node-ts-service" }
    });
    await applyRepo(manifest, directory);
    await rm(path.join(directory, "src/index.ts"));

    const report = await runConformance(manifest, directory);

    expect(report.exitCode).toBe(0);
    expect(report.summary.warning).toBe(1);
    expect(report.results).toContainEqual(expect.objectContaining({ ruleId: "PRS-PROFILE-001", severity: "warning" }));
    expect(formatConformanceReport(report)).toContain("Conformance: 0 blocking, 1 warning");
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
});
