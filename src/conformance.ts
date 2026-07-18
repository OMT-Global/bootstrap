import path from "node:path";

import { z } from "zod";

import { renderManagedFiles } from "./archetypes.js";
import { validatePolicyExceptions } from "./exceptions.js";
import { readTextIfExists } from "./lib/fs.js";
import { sha256 } from "./lib/hash.js";
import { resolveLanguageProfiles } from "./language-profiles.js";
import {
  LICENSE_PATH,
  THIRD_PARTY_NOTICES_PATH,
  projectLicensePolicy,
  readManagedLegalOutputTextIfExists
} from "./licensing.js";
import { BOOTSTRAP_STATE_OUTPUT_PATHS, loadEffectiveRepoState, planRepo, selectManagedFiles } from "./render.js";
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

function pushUnique(results: ConformanceResult[], entry: ConformanceResult): void {
  const ownershipDriftKey = (evidence: string): string | undefined => {
    const match = evidence.match(/managed(?: file)? (\S+) was (deleted|directly modified)/i);
    return match ? `${match[1]!.toLowerCase()}:${match[2]!.toLowerCase()}` : undefined;
  };
  const entryDriftKey = entry.ruleId === "PRS-OWNERSHIP-001" ? ownershipDriftKey(entry.evidence.join("\n")) : undefined;
  if (!results.some((existing) =>
    existing.ruleId === entry.ruleId &&
    existing.severity === entry.severity &&
    (existing.evidence.join("\n") === entry.evidence.join("\n") ||
      (entryDriftKey !== undefined && ownershipDriftKey(existing.evidence.join("\n")) === entryDriftKey))
  )) {
    results.push(entry);
  }
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

  if (!manifest.license) {
    try {
      const existingLicense = await readManagedLegalOutputTextIfExists(targetDir, LICENSE_PATH);
      results.push(
        result(
          "PRS-LICENSE-001",
          "blocking",
          [existingLicense === undefined ? "license policy and LICENSE are absent" : "LICENSE exists without an explicit license policy"],
          "Declare an explicit SPDX or proprietary license policy; repository visibility never selects a license."
        )
      );
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      const ruleId = detail.match(/^(PRS-[A-Z][A-Z-]*-\d{3}):/)?.[1] ?? "PRS-LICENSE-001";
      results.push(result(ruleId, "blocking", [detail], "Restore the legal output as a regular repository file before conforming."));
    }
  } else {
    try {
      const selectedManagedFiles = selectManagedFiles(manifest, renderManagedFiles(manifest));
      const { state: effectiveState } = await loadEffectiveRepoState(targetDir, selectedManagedFiles);
      for (const [managedPath, managedHash] of Object.entries(effectiveState?.managedFiles ?? {})) {
        const existing = managedPath === LICENSE_PATH || managedPath === THIRD_PARTY_NOTICES_PATH
          ? await readManagedLegalOutputTextIfExists(targetDir, managedPath)
          : await readTextIfExists(path.join(targetDir, managedPath));
        const detail = existing === undefined
          ? `Managed file ${managedPath} was deleted.`
          : sha256(existing) !== managedHash
            ? `Managed file ${managedPath} was directly modified.`
            : undefined;
        if (detail) {
          pushUnique(
            results,
            result("PRS-OWNERSHIP-001", "blocking", [detail], "Restore the managed file or use an explicit migration before applying Bootstrap changes.")
          );
        }
      }
      const projection = await projectLicensePolicy(
        manifest,
        targetDir,
        effectiveState,
        [
          ...selectedManagedFiles.map((file) => file.path),
          ...Object.keys(effectiveState?.managedFiles ?? {}),
          ...BOOTSTRAP_STATE_OUTPUT_PATHS
        ]
      );
      const expectedLicense = projection?.files.find((file) => file.path === LICENSE_PATH)?.contents;
      const expectedNotices = projection?.files.find((file) => file.path === THIRD_PARTY_NOTICES_PATH)?.contents;
      const [existingLicense, existingNotices] = await Promise.all([
        readManagedLegalOutputTextIfExists(targetDir, LICENSE_PATH),
        readManagedLegalOutputTextIfExists(targetDir, THIRD_PARTY_NOTICES_PATH)
      ]);
      results.push(
        existingLicense === expectedLicense
          ? result("PRS-LICENSE-001", "pass", [`mode=${projection?.summary.afterMode}`], "Keep the approved license template and declared mode current.")
          : result("PRS-LICENSE-001", "blocking", [LICENSE_PATH], "Run bootstrap apply repo after satisfying any legal transition hard stop.")
      );
      results.push(
        existingNotices === expectedNotices
          ? result("PRS-LICENSE-NOTICES-001", "pass", [THIRD_PARTY_NOTICES_PATH], "Keep dependency, asset, font, media, and incorporated-source obligations current.")
          : result("PRS-LICENSE-NOTICES-001", "blocking", [THIRD_PARTY_NOTICES_PATH], "Generate or reconcile the separate third-party notice inventory.")
      );
      results.push(
        manifest.license.mode === "proprietary"
          ? result(
              "PRS-LICENSE-RECOGNITION-001",
              "pass",
              ["proprietary notice; SPDX and OSI recognition not claimed"],
              "Do not present the proprietary notice as an open-source license."
            )
          : result(
              "PRS-LICENSE-RECOGNITION-001",
              "warning",
              [`declared SPDX identifier ${manifest.license.identifier}; GitHub recognition not verified locally`],
              "Verify GitHub's detected license/community profile after publication."
            )
      );
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      const ruleId = detail.match(/^(PRS-[A-Z][A-Z-]*-\d{3}):/)?.[1] ?? "PRS-LICENSE-001";
      pushUnique(results, result(ruleId, "blocking", [detail], "Resolve the declared license policy or required legal evidence before applying."));
    }
  }

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
    const ruleId = detail.match(/^(PRS-[A-Z][A-Z-]*-\d{3}):/)?.[1] ?? "PRS-OWNERSHIP-001";
    pushUnique(
      results,
      result(ruleId, "blocking", [detail], "Restore the managed file or use an explicit migration before applying Bootstrap changes.")
    );
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
