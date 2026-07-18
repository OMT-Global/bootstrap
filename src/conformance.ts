import path from "node:path";
import { lstat, readdir, realpath } from "node:fs/promises";

import { z } from "zod";
import { isAlias, isMap, isScalar, isSeq, parseDocument, type Document, type Node } from "yaml";

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
import { containsCredential, redactPublicText } from "./provenance.js";
import type { BootstrapManifest, PolicyException } from "./types.js";

export const CONFORMANCE_SCHEMA_VERSION = 2;

const conformanceResultSchema = z.object({
  ruleId: z.string().regex(/^PRS-[A-Z-]+-\d{3}$/),
  severity: z.enum(["pass", "warning", "blocking"]),
  classification: z.enum(["conformant", "misconfigured", "unsupported", "waived", "unverified"]),
  evidence: z.array(z.string()),
  remediation: z.string()
});

const capabilityReportTextSchema = z.string().trim().min(1).max(512)
  .refine((value) => !/[\u0000-\u001f\u007f-\u009f\u2028\u2029]/.test(value), "Capability report text must be a single safe line.")
  .refine((value) => !containsCredential(value), "Capability report text must not contain credential-like literals.");

export const githubCapabilitySnapshotSchema = z.object({
  schemaVersion: z.literal(1),
  observations: z.array(z.object({
    control: z.string().regex(/^[a-z][a-z0-9-]*$/),
    status: z.enum(["supported", "unsupported", "misconfigured"]),
    evidence: capabilityReportTextSchema,
    remediation: capabilityReportTextSchema
  }))
}).superRefine((snapshot, context) => {
  const seen = new Set<string>();
  snapshot.observations.forEach((observation, index) => {
    if (seen.has(observation.control)) {
      context.addIssue({ code: "custom", path: ["observations", index, "control"], message: `Duplicate capability observation: ${observation.control}` });
    }
    seen.add(observation.control);
  });
});

export const conformanceReportSchema = z.object({
  schemaVersion: z.literal(CONFORMANCE_SCHEMA_VERSION),
  results: z.array(conformanceResultSchema),
  summary: z.object({ pass: z.number().int().nonnegative(), warning: z.number().int().nonnegative(), blocking: z.number().int().nonnegative() }),
  exitCode: z.union([z.literal(0), z.literal(1)])
});

export type ConformanceResult = z.infer<typeof conformanceResultSchema>;
export type ConformanceReport = z.infer<typeof conformanceReportSchema>;
export type GitHubCapabilitySnapshot = z.infer<typeof githubCapabilitySnapshotSchema>;

export interface ConformanceOptions {
  githubCapabilities?: unknown;
}

const waiverTargets = {
  requiredFiles: { policy: "repository-files", scope: "repo.managed-artifacts" },
  actionPins: { policy: "supply-chain", scope: "github.workflows.actions" },
  languageProfile: { policy: "language-profile", scope: "repo.profile" }
} as const;

function result(
  ruleId: string,
  severity: ConformanceResult["severity"],
  evidence: string[],
  remediation: string,
  classification: ConformanceResult["classification"] = severity === "pass" ? "conformant" : "misconfigured"
): ConformanceResult {
  return { ruleId, severity, classification, evidence: [...evidence].sort(), remediation };
}

function findWaiver(
  manifest: BootstrapManifest,
  validExceptionIds: Set<string>,
  target: { policy: string; scope: string }
): PolicyException | undefined {
  return manifest.exceptions.find((entry) =>
    entry.policy === target.policy && entry.scope === target.scope && validExceptionIds.has(entry.id)
  );
}

function applyWaiver(entry: ConformanceResult, waiver: PolicyException | undefined): ConformanceResult {
  if (!waiver || entry.severity === "pass") return entry;
  return result(
    entry.ruleId,
    "pass",
    [...entry.evidence, `approved exception ${waiver.id}`],
    `Keep approved exception ${waiver.id} current until the governed deviation is resolved.`,
    "waived"
  );
}

function safeEvidence(value: string): string {
  return redactPublicText(value).value.replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029]+/g, " ").slice(0, 512);
}

function compareCodePoints(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

async function workflowFiles(targetDir: string): Promise<{ files: string[]; unsafe: string[] }> {
  const root = path.join(targetDir, ".github/workflows");
  const files: string[] = [];
  const unsafe: string[] = [];
  const targetRealPath = await realpath(targetDir);
  for (const relative of [".github", ".github/workflows"]) {
    const absolute = path.join(targetDir, relative);
    let stats;
    try {
      stats = await lstat(absolute);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return { files, unsafe };
      throw error;
    }
    if (stats.isSymbolicLink() || !stats.isDirectory()) {
      unsafe.push(`${relative}: workflow root component must be a regular directory`);
      return { files, unsafe };
    }
    const resolved = await realpath(absolute);
    if (resolved !== targetRealPath && !resolved.startsWith(`${targetRealPath}${path.sep}`)) {
      unsafe.push(`${relative}: workflow root component escapes the target repository`);
      return { files, unsafe };
    }
  }
  const entries = await readdir(root, { withFileTypes: true });
  for (const entry of entries.sort((left, right) => compareCodePoints(left.name, right.name))) {
    if (!/\.ya?ml$/i.test(entry.name)) continue;
    const relative = `.github/workflows/${entry.name}`;
    if (entry.isSymbolicLink()) unsafe.push(relative);
    else if (entry.isFile()) files.push(relative);
  }
  return { files, unsafe };
}

function resolveYamlNode(node: Node | null | undefined, document: Document): Node | null | undefined {
  let current = node;
  const aliases = new Set<Node>();
  while (current && isAlias(current)) {
    if (aliases.has(current) || aliases.size >= 100) return undefined;
    aliases.add(current);
    current = current.resolve(document);
  }
  return current;
}

function asYamlNode(value: unknown): Node | undefined {
  return isAlias(value) || isMap(value) || isSeq(value) || isScalar(value) ? value : undefined;
}

function yamlLineNumber(contents: string, node: Node | null | undefined): number {
  const offset = node?.range?.[0] ?? 0;
  return contents.slice(0, offset).split("\n").length;
}

function yamlMappingEntry(map: Node | null | undefined, key: string, document: Document): { keyNode: Node; valueNode?: Node } | undefined {
  if (!isMap(map)) return undefined;
  for (const pair of map.items) {
    const rawKey = asYamlNode(pair.key);
    const resolvedKey = resolveYamlNode(rawKey, document);
    if (isScalar(resolvedKey) && resolvedKey.value === key && rawKey) {
      const valueNode = asYamlNode(pair.value);
      return { keyNode: rawKey, ...(valueNode ? { valueNode } : {}) };
    }
  }
  return undefined;
}

type WorkflowUse =
  | { value: string; metadata?: string; line: number }
  | { invalid: true; line: number };

function workflowUses(contents: string): WorkflowUse[] {
  const document = parseDocument(contents, { prettyErrors: false });
  if (document.errors.length > 0) throw document.errors[0];
  const uses: WorkflowUse[] = [];
  const inspect = (entry: { keyNode: Node; valueNode?: Node } | undefined, parentComment?: string | null): void => {
    if (!entry) return;
    const node = resolveYamlNode(entry.valueNode, document);
    if (!isScalar(node) || typeof node.value !== "string") {
      uses.push({ invalid: true, line: yamlLineNumber(contents, entry.valueNode ?? entry.keyNode) });
      return;
    }
    const metadata = (entry.valueNode?.comment ?? node.comment ?? parentComment)?.trim();
    uses.push({
      value: node.value.trim(),
      ...(metadata ? { metadata } : {}),
      line: yamlLineNumber(contents, entry.valueNode)
    });
  };
  const jobs = resolveYamlNode(yamlMappingEntry(asYamlNode(document.contents), "jobs", document)?.valueNode, document);
  if (!isMap(jobs)) return uses;
  for (const pair of jobs.items) {
    const rawJob = asYamlNode(pair.value);
    const job = resolveYamlNode(rawJob, document);
    if (!isMap(job)) continue;
    inspect(yamlMappingEntry(job, "uses", document), rawJob?.comment);
    const steps = resolveYamlNode(yamlMappingEntry(job, "steps", document)?.valueNode, document);
    if (!isSeq(steps)) continue;
    for (const rawStepValue of steps.items) {
      const rawStep = asYamlNode(rawStepValue);
      const step = resolveYamlNode(rawStep, document);
      if (isMap(step)) inspect(yamlMappingEntry(step, "uses", document), rawStep?.comment);
    }
  }
  return uses;
}

function validReleaseMetadata(value: string | undefined): boolean {
  if (!value) return false;
  const normalized = value.trim();
  if (normalized.length === 0 || normalized.length > 128) return false;
  if (/[\u0000-\u001f\u007f-\u009f\u2028\u2029]/.test(normalized)) return false;
  if (/^(?:todo|fixme|tbd|unknown|n\/a)(?:\b|\s|:|$)/i.test(normalized)) return false;
  return /[A-Za-z0-9]/.test(normalized);
}

async function actionPinResults(manifest: BootstrapManifest, targetDir: string): Promise<ConformanceResult[]> {
  const shaPattern = /^[0-9a-f]{40}$/;
  const inventory = await workflowFiles(targetDir);
  const internalWorkflowRepos = new Set([
    manifest.release.reusableWorkflowRepo,
    manifest.ci.aiAttestation.reusableWorkflowRepo
  ]);
  const failures: { evidence: string; remediation: string }[] = inventory.unsafe.map((workflow) => ({
    evidence: safeEvidence(workflow),
    remediation: "Replace the unsafe workflow path with regular directories and files contained within the repository."
  }));
  const addFailure = (evidence: string, remediation: string): void => {
    failures.push({ evidence: safeEvidence(evidence), remediation });
  };
  let checked = 0;
  for (const workflow of inventory.files) {
    const contents = await readTextIfExists(path.join(targetDir, workflow));
    let references;
    try {
      references = workflowUses(contents ?? "");
    } catch (error) {
      addFailure(
        `${workflow}: invalid workflow YAML: ${error instanceof Error ? error.message : String(error)}`,
        "Repair the workflow so it is valid YAML before evaluating its action references."
      );
      continue;
    }
    for (const reference of references) {
      if ("invalid" in reference) {
        checked += 1;
        addFailure(
          `${workflow}:${reference.line}: uses must be a string action reference`,
          "Replace the malformed uses value with a string action, reusable workflow, or Docker image reference."
        );
        continue;
      }
      if (reference.value.startsWith("docker://")) {
        checked += 1;
        if (!/^docker:\/\/[^@\s]+@sha256:[0-9a-f]{64}$/.test(reference.value)) {
          addFailure(
            `${workflow}:${reference.line}: ${reference.value} is not pinned to an immutable sha256 image digest`,
            "Pin the Docker image to an immutable 64-character sha256 digest."
          );
        } else if (!validReleaseMetadata(reference.metadata)) {
          addFailure(
            `${workflow}:${reference.line}: ${reference.value} lacks readable release metadata`,
            "Retain a readable image version or canonical release URL beside the pinned Docker digest."
          );
        }
        continue;
      }
      const separator = reference.value.lastIndexOf("@");
      if (separator <= 0) {
        if (!reference.value.startsWith("./")) {
          checked += 1;
          addFailure(
            `${workflow}:${reference.line}: ${reference.value} lacks an immutable action reference`,
            "Pin the action or reusable workflow to an immutable 40-character Git commit SHA."
          );
        }
        continue;
      }
      const action = reference.value.slice(0, separator);
      const ref = reference.value.slice(separator + 1);
      if (action.startsWith("./")) continue;
      const isInternalWorkflow = [...internalWorkflowRepos].some((repo) => action === repo || action.startsWith(`${repo}/`));
      checked += 1;
      if (!shaPattern.test(ref)) {
        addFailure(
          `${workflow}:${reference.line}: ${action}@${ref} is not pinned to a 40-character SHA`,
          "Pin the action or reusable workflow to an immutable 40-character Git commit SHA."
        );
      } else if (!isInternalWorkflow && !validReleaseMetadata(reference.metadata)) {
        addFailure(
          `${workflow}:${reference.line}: ${action}@${ref} lacks readable release metadata`,
          "Retain a readable version tag or canonical release URL beside the pinned action SHA."
        );
      }
    }
  }
  return failures.length === 0
    ? [result("PRS-ACTION-PIN-001", "pass", [`validated ${checked} third-party action pin(s)`], "Keep every third-party action pinned to an immutable SHA with readable release metadata.")]
    : failures.map((failure) => result("PRS-ACTION-PIN-001", "blocking", [failure.evidence], failure.remediation));
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

export async function runConformance(manifest: BootstrapManifest, targetDir: string, options: ConformanceOptions = {}): Promise<ConformanceReport> {
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
  const selectedManagedFiles = selectManagedFiles(manifest, renderManagedFiles(manifest));
  const missingRequiredFiles: string[] = [];
  for (const file of selectedManagedFiles) {
    if (await readTextIfExists(path.join(targetDir, file.path)) === undefined) missingRequiredFiles.push(file.path);
  }
  const requiredFileResults = missingRequiredFiles.length === 0
    ? [result("PRS-REQUIRED-FILE-001", "pass", [`${selectedManagedFiles.length} required managed artifact(s) present`], "Keep required managed artifacts present and under Bootstrap ownership.")]
    : [result("PRS-REQUIRED-FILE-001", "blocking", missingRequiredFiles, "Run bootstrap apply repo to restore the required managed artifacts.")];
  const requiredFilesWaiver = findWaiver(manifest, validExceptionIds, waiverTargets.requiredFiles);
  results.push(...requiredFileResults.map((entry) => applyWaiver(entry, requiredFilesWaiver)));
  const actionPinsWaiver = findWaiver(manifest, validExceptionIds, waiverTargets.actionPins);
  results.push(...(await actionPinResults(manifest, targetDir)).map((entry) => applyWaiver(entry, actionPinsWaiver)));

  const githubCapabilities = githubCapabilitySnapshotSchema.parse(options.githubCapabilities ?? { schemaVersion: 1, observations: [] });
  for (const capability of githubCapabilities.observations) {
    const capabilityResult = result(
      "PRS-GITHUB-CAPABILITY-001",
      capability.status === "supported" ? "pass" : capability.status === "unsupported" ? "warning" : "blocking",
      [`${capability.control}: ${capability.evidence}`],
      capability.remediation,
      capability.status === "supported" ? "conformant" : capability.status
    );
    const capabilityWaiver = findWaiver(manifest, validExceptionIds, {
      policy: "github-capability",
      scope: `github.${capability.control}`
    });
    results.push(applyWaiver(capabilityResult, capabilityWaiver));
  }

  results.push(
    manifest.repo.class
      ? result("PRS-CLASS-001", "pass", [manifest.repo.class], "Keep the canonical repository class current.")
      : classException
        ? result(
            "PRS-CLASS-001",
            "pass",
            [`approved exception ${classException.id}`],
            "Keep the approved repository-classification exception current until a canonical class is declared.",
            "waived"
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
              "Verify GitHub's detected license/community profile after publication.",
              "unverified"
            )
      );
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      const ruleId = detail.match(/^(PRS-[A-Z][A-Z-]*-\d{3}):/)?.[1] ?? "PRS-LICENSE-001";
      pushUnique(results, result(ruleId, "blocking", [detail], "Resolve the declared license policy or required legal evidence before applying."));
    }
  }

  const profiles = await resolveLanguageProfiles(manifest, targetDir);
  const languageProfileWaiver = findWaiver(manifest, validExceptionIds, waiverTargets.languageProfile);
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
      results.push(applyWaiver(
        result("PRS-PROFILE-001", "warning", [conflict.reason], "Align the archetype or resolve the detected language-profile conflict."),
        languageProfileWaiver
      ));
    }
  }

  for (const exception of exceptionReport.results) {
    results.push(
      result(
        exception.ruleId,
        exception.status === "block" ? "blocking" : exception.status === "warn" ? "warning" : "pass",
        [exception.detail],
        exception.remediation ?? "Keep the approved exception current.",
        exception.status === "block" ? "misconfigured" : "conformant"
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

  const sorted = results.sort((left, right) => compareCodePoints(left.ruleId, right.ruleId) || compareCodePoints(left.evidence.join("\n"), right.evidence.join("\n")));
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
    ...report.results.map((entry) => `- [${entry.severity}/${entry.classification}] ${entry.ruleId}: ${entry.evidence.join("; ")} — ${entry.remediation}`)
  ].join("\n");
}
