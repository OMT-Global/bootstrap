import { mkdtemp, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";

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
      archetype: { kind: "generic-empty" }
    });
    await applyRepo(manifest, directory);

    const evaluatedManifest = normalizeManifest({
      project: { name: "canonical-contract", owner: "acme", maturity: "stable" },
      repo: { class: "service" },
      archetype: { kind: "node-ts-service" }
    });

    const report = await runConformance(evaluatedManifest, directory);

    expect(report.exitCode).toBe(0);
    expect(report.summary.warning).toBe(1);
    expect(report.results).toContainEqual(expect.objectContaining({ ruleId: "PRS-PROFILE-001", severity: "warning" }));
    expect(formatConformanceReport(report)).toContain("Conformance: 0 blocking, 1 warning");
  });
});
