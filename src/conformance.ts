import path from "node:path";

import { z } from "zod";

import { validatePolicyExceptions } from "./exceptions.js";
import { readTextIfExists } from "./lib/fs.js";
import { resolveLanguageProfiles } from "./language-profiles.js";
import { planRepo } from "./render.js";
import { OWNERSHIP_SIDECAR_PATH } from "./state.js";
import type { BootstrapManifest } from "./types.js";

export const CONFORMANCE_SCHEMA_VERSION = 1;

const conformanceResultSchema = z.object({
  ruleId: z.string().regex(/^PRS-[A-Z-]+-\d{3}$/),
  severity: z.enum(["pass", "warning", "blocking"]),
  evidence: z.array(z.string()),
  remediation: z.string()
});

export const conformanceReportSchema = z.object({
  schemaVersion: z.literal(CONFORMANCE_SCHEMA_VERSION),
  results: z.array(conformanceResultSchema),
  summary: z.object({ pass: z.number().int().nonnegative(), warning: z.number().int().nonnegative(), blocking: z.number().int().nonnegative() }),
  exitCode: z.union([z.literal(0), z.literal(1)])
});

export type ConformanceResult = z.infer<typeof conformanceResultSchema>;
export type ConformanceReport = z.infer<typeof conformanceReportSchema>;

function result(
  ruleId: string,
  severity: ConformanceResult["severity"],
  evidence: string[],
  remediation: string
): ConformanceResult {
  return { ruleId, severity, evidence: [...evidence].sort(), remediation };
}

function summary(results: ConformanceResult[]): ConformanceReport["summary"] {
  return {
    pass: results.filter((entry) => entry.severity === "pass").length,
    warning: results.filter((entry) => entry.severity === "warning").length,
    blocking: results.filter((entry) => entry.severity === "blocking").length
  };
}

export async function runConformance(manifest: BootstrapManifest, targetDir: string): Promise<ConformanceReport> {
  const results: ConformanceResult[] = [];
  const exceptionReport = validatePolicyExceptions(manifest.exceptions);
  const validExceptionIds = new Set(
    exceptionReport.results.filter((entry) => entry.status !== "block").map((entry) => entry.exceptionId)
  );
  const classException = manifest.exceptions.find(
    (entry) =>
      entry.policy === "repository-classification" &&
      entry.scope === "repo.class" &&
      validExceptionIds.has(entry.id)
  );

  results.push(
    manifest.repo.class
      ? result("PRS-CLASS-001", "pass", [manifest.repo.class], "Keep the canonical repository class current.")
      : classException
        ? result(
            "PRS-CLASS-001",
            "pass",
            [`approved exception ${classException.id}`],
            "Keep the approved repository-classification exception current until a canonical class is declared."
          )
      : result("PRS-CLASS-001", "blocking", ["repo.class is absent"], "Declare a canonical repo.class or complete an explicit legacy migration.")
  );
  results.push(
    manifest.project.maturity
      ? result("PRS-MATURITY-001", "pass", [manifest.project.maturity], "Keep product maturity separate from release automation maturity.")
      : result("PRS-MATURITY-001", "blocking", ["project.maturity is absent"], "Declare project.maturity from experimental through archived.")
  );

  const profiles = await resolveLanguageProfiles(manifest, targetDir);
  if (profiles.conflicts.length === 0) {
    results.push(
      result(
        "PRS-PROFILE-001",
        "pass",
        profiles.selected.length === 0 ? ["no repository language markers"] : profiles.selected,
        "Keep selected language profiles aligned with the repository's toolchain markers."
      )
    );
  } else {
    for (const conflict of profiles.conflicts) {
      results.push(result("PRS-PROFILE-001", "warning", [conflict.reason], "Align the archetype or resolve the detected language-profile conflict."));
    }
  }

  for (const exception of exceptionReport.results) {
    results.push(
      result(
        exception.ruleId,
        exception.status === "block" ? "blocking" : exception.status === "warn" ? "warning" : "pass",
        [exception.detail],
        exception.remediation ?? "Keep the approved exception current."
      )
    );
  }

  const ownershipPath = path.join(targetDir, OWNERSHIP_SIDECAR_PATH);
  const ownershipRaw = await readTextIfExists(ownershipPath);
  if (!ownershipRaw) {
    results.push(result("PRS-OWNERSHIP-001", "blocking", [OWNERSHIP_SIDECAR_PATH], "Run bootstrap apply repo to create the managed-file ownership sidecar."));
  } else {
    try {
      const ownership = JSON.parse(ownershipRaw) as { schemaVersion?: unknown; owner?: unknown; managedFiles?: unknown };
      const valid = ownership.schemaVersion === 1 && ownership.owner === "bootstrap" && ownership.managedFiles && typeof ownership.managedFiles === "object";
      results.push(
        valid
          ? result("PRS-OWNERSHIP-001", "pass", [OWNERSHIP_SIDECAR_PATH], "Keep the ownership sidecar under Bootstrap management.")
          : result("PRS-OWNERSHIP-001", "blocking", [OWNERSHIP_SIDECAR_PATH], "Regenerate a valid Bootstrap ownership sidecar.")
      );
    } catch {
      results.push(result("PRS-OWNERSHIP-001", "blocking", [OWNERSHIP_SIDECAR_PATH], "Regenerate the malformed Bootstrap ownership sidecar."));
    }
  }

  try {
    await planRepo(manifest, targetDir);
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    results.push(result("PRS-OWNERSHIP-001", "blocking", [detail], "Restore the managed file or use an explicit migration before applying Bootstrap changes."));
  }

  const sorted = results.sort((left, right) => left.ruleId.localeCompare(right.ruleId) || left.evidence.join("\n").localeCompare(right.evidence.join("\n")));
  const report = {
    schemaVersion: CONFORMANCE_SCHEMA_VERSION,
    results: sorted,
    summary: summary(sorted),
    exitCode: sorted.some((entry) => entry.severity === "blocking") ? 1 : 0
  } as const;
  return conformanceReportSchema.parse(report);
}

export function formatConformanceReport(report: ConformanceReport): string {
  return [
    `Conformance: ${report.summary.blocking} blocking, ${report.summary.warning} warning, ${report.summary.pass} pass`,
    ...report.results.map((entry) => `- [${entry.severity}] ${entry.ruleId}: ${entry.evidence.join("; ")} — ${entry.remediation}`)
  ].join("\n");
}
