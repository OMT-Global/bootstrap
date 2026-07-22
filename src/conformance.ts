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
    remediation: capabilityReportTextSchema,
    dependencyReviewEnabled: z.boolean().optional()
  }))
}).superRefine((snapshot, context) => {
  const seen = new Set<string>();
  snapshot.observations.forEach((observation, index) => {
    if (seen.has(observation.control)) {
      context.addIssue({ code: "custom", path: ["observations", index, "control"], message: `Duplicate capability observation: ${observation.control}` });
    }
    if (observation.dependencyReviewEnabled !== undefined && observation.control !== "dependency-graph") {
      context.addIssue({
        code: "custom",
        path: ["observations", index, "dependencyReviewEnabled"],
        message: "dependencyReviewEnabled is valid only for the dependency-graph observation."
      });
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
  languageProfile: { policy: "language-profile", scope: "repo.profile" },
  securityBaseline: { policy: "security-baseline", scope: "repo.security" }
} as const;

const publicSecurityCapabilityControls = [
  "code-scanning",
  "dependabot-alerts",
  "dependabot-security-updates",
  "dependency-graph",
  "private-vulnerability-reporting",
  "push-protection",
  "secret-scanning"
] as const;

const trustedSecurityJobCondition = "github.event_name == 'push' || github.event_name == 'schedule'";
const dependencyReviewJobCondition = "github.event_name == 'pull_request' && vars.DEPENDENCY_REVIEW_ENABLED == 'true'";

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

function dependabotUpdatesActions(contents: string): boolean {
  const document = parseDocument(contents, { prettyErrors: false });
  if (document.errors.length > 0) return false;
  const version = resolveYamlNode(
    yamlMappingEntry(asYamlNode(document.contents), "version", document)?.valueNode,
    document
  );
  if (!isScalar(version) || version.value !== 2) return false;
  const updates = resolveYamlNode(
    yamlMappingEntry(asYamlNode(document.contents), "updates", document)?.valueNode,
    document
  );
  if (!isSeq(updates)) return false;
  return updates.items.some((rawUpdate) => {
    const update = resolveYamlNode(asYamlNode(rawUpdate), document);
    if (!isMap(update)) return false;
    const ecosystem = resolveYamlNode(yamlMappingEntry(update, "package-ecosystem", document)?.valueNode, document);
    if (!isScalar(ecosystem) || ecosystem.value !== "github-actions") return false;
    const directory = resolveYamlNode(yamlMappingEntry(update, "directory", document)?.valueNode, document);
    const schedule = resolveYamlNode(yamlMappingEntry(update, "schedule", document)?.valueNode, document);
    const interval = isMap(schedule)
      ? resolveYamlNode(yamlMappingEntry(schedule, "interval", document)?.valueNode, document)
      : undefined;
    const limitEntry = yamlMappingEntry(update, "open-pull-requests-limit", document);
    const limit = resolveYamlNode(limitEntry?.valueNode, document);
    const enabledLimit = limitEntry === undefined ||
      (isScalar(limit) && typeof limit.value === "number" && Number.isSafeInteger(limit.value) && limit.value > 0);
    return enabledLimit &&
      isScalar(directory) && directory.value === "/" &&
      isScalar(interval) && typeof interval.value === "string" && ["daily", "weekly", "monthly"].includes(interval.value);
  });
}

function mappingPermissionsAreReadOnly(map: Node | null | undefined, document: Document): boolean {
  const resolved = resolveYamlNode(map, document);
  if (isScalar(resolved) && resolved.value === "read-all") return true;
  if (!isMap(resolved)) return false;
  let hasContentsRead = false;
  for (const pair of resolved.items) {
    const key = resolveYamlNode(asYamlNode(pair.key), document);
    const value = resolveYamlNode(asYamlNode(pair.value), document);
    if (!isScalar(key) || typeof key.value !== "string" || !isScalar(value) || typeof value.value !== "string") {
      return false;
    }
    if (key.value === "contents" && value.value === "read") hasContentsRead = true;
    if (value.value !== "read" && value.value !== "none") return false;
  }
  return hasContentsRead;
}

function jobCondition(jobs: Node | null | undefined, jobName: string, document: Document): string | undefined {
  const job = resolveYamlNode(yamlMappingEntry(jobs, jobName, document)?.valueNode, document);
  if (!isMap(job)) return undefined;
  const condition = resolveYamlNode(yamlMappingEntry(job, "if", document)?.valueNode, document);
  return isScalar(condition) && typeof condition.value === "string" ? condition.value : undefined;
}

function jobNode(jobs: Node | null | undefined, jobName: string, document: Document): Node | null | undefined {
  return resolveYamlNode(yamlMappingEntry(jobs, jobName, document)?.valueNode, document);
}

function jobField(jobs: Node | null | undefined, jobName: string, field: string, document: Document): Node | null | undefined {
  const job = jobNode(jobs, jobName, document);
  return isMap(job) ? resolveYamlNode(yamlMappingEntry(job, field, document)?.valueNode, document) : undefined;
}

function jobHasExactActionSequence(
  jobs: Node | null | undefined,
  jobName: string,
  actions: Array<{ prefix: string; requiredInputs?: string[]; optionalInputs?: string[] }>,
  document: Document
): boolean {
  const steps = jobField(jobs, jobName, "steps", document);
  if (!isSeq(steps) || steps.items.length !== actions.length) return false;
  for (const [index, rawStep] of steps.items.entries()) {
    const step = resolveYamlNode(asYamlNode(rawStep), document);
    if (!isMap(step)) return false;
    const allowedKeys = new Set(["name", "uses", "with"]);
    for (const pair of step.items) {
      const key = resolveYamlNode(asYamlNode(pair.key), document);
      if (!isScalar(key) || typeof key.value !== "string" || !allowedKeys.has(key.value)) return false;
    }
    const uses = resolveYamlNode(yamlMappingEntry(step, "uses", document)?.valueNode, document);
    const action = actions[index];
    if (!action || !isScalar(uses) || typeof uses.value !== "string" || !uses.value.startsWith(action.prefix)) return false;
    const requiredInputs = new Set(action.requiredInputs ?? []);
    const allowedInputs = new Set([...requiredInputs, ...(action.optionalInputs ?? [])]);
    const withEntry = yamlMappingEntry(step, "with", document);
    if (allowedInputs.size === 0) {
      if (withEntry) return false;
      continue;
    }
    const withMap = resolveYamlNode(withEntry?.valueNode, document);
    if (!isMap(withMap)) return false;
    const actualInputs = new Set<string>();
    for (const pair of withMap.items) {
      const key = resolveYamlNode(asYamlNode(pair.key), document);
      if (!isScalar(key) || typeof key.value !== "string" || !allowedInputs.has(key.value)) return false;
      actualInputs.add(key.value);
    }
    if ([...requiredInputs].some((input) => !actualInputs.has(input))) return false;
  }
  return true;
}

function jobActionField(
  jobs: Node | null | undefined,
  jobName: string,
  actionPrefix: string,
  field: string,
  document: Document
): unknown {
  const steps = jobField(jobs, jobName, "steps", document);
  if (!isSeq(steps)) return undefined;
  for (const rawStep of steps.items) {
    const step = resolveYamlNode(asYamlNode(rawStep), document);
    if (!isMap(step) || yamlMappingEntry(step, "if", document)) continue;
    const uses = resolveYamlNode(yamlMappingEntry(step, "uses", document)?.valueNode, document);
    if (!isScalar(uses) || typeof uses.value !== "string" || !uses.value.startsWith(actionPrefix)) continue;
    const withMap = resolveYamlNode(yamlMappingEntry(step, "with", document)?.valueNode, document);
    const value = isMap(withMap)
      ? resolveYamlNode(yamlMappingEntry(withMap, field, document)?.valueNode, document)
      : undefined;
    return isScalar(value) ? value.value : undefined;
  }
  return undefined;
}

function yamlStringSequenceIncludes(node: Node | null | undefined, expected: string, document: Document): boolean {
  const resolved = resolveYamlNode(node, document);
  if (isScalar(resolved)) return resolved.value === expected;
  if (!isSeq(resolved)) return false;
  return resolved.items.some((item) => {
    const value = resolveYamlNode(asYamlNode(item), document);
    return isScalar(value) && value.value === expected;
  });
}

function cronFieldValues(field: string, minimum: number, maximum: number, names?: string[]): Set<number> | undefined {
  const values = new Set<number>();
  const numericValue = (raw: string | undefined): number | undefined => {
    if (raw === undefined) return undefined;
    if (/^\d+$/.test(raw)) return Number(raw);
    const namedIndex = names?.indexOf(raw.toUpperCase()) ?? -1;
    return namedIndex >= 0 ? minimum + namedIndex : undefined;
  };
  for (const component of field.split(",")) {
    const segments = component.split("/");
    if (segments.length > 2) return undefined;
    const base = segments[0] ?? "";
    const stepText = segments[1];
    if (base.length === 0) return undefined;
    if (stepText !== undefined && (!/^\d+$/.test(stepText) || Number(stepText) < 1 || Number(stepText) > maximum - minimum + 1)) {
      return undefined;
    }
    const step = stepText === undefined ? 1 : Number(stepText);
    let start: number;
    let end: number;
    if (base === "*") {
      start = minimum;
      end = maximum;
    } else {
      const range = base.match(/^([A-Za-z]+|\d+)(?:-([A-Za-z]+|\d+))?$/);
      if (!range) return undefined;
      const parsedStart = numericValue(range[1]);
      const parsedEnd = range[2] === undefined
        ? stepText === undefined ? parsedStart : maximum
        : numericValue(range[2]);
      if (parsedStart === undefined || parsedEnd === undefined) return undefined;
      start = parsedStart;
      end = parsedEnd;
    }
    if (start < minimum || end > maximum || start > end) return undefined;
    for (let value = start; value <= end; value += step) values.add(value);
  }
  return values.size > 0 ? values : undefined;
}

function validGitHubCron(value: string): boolean {
  const fields = value.trim().split(/\s+/);
  if (fields.length !== 5) return false;
  const ranges = [[0, 59], [0, 23], [1, 31], [1, 12], [0, 7]] as const;
  const names: Array<string[] | undefined> = [
    undefined,
    undefined,
    undefined,
    ["JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", "NOV", "DEC"],
    ["SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT"]
  ];
  const expanded = fields.map((field, index) => {
    const range = ranges[index];
    return range === undefined ? undefined : cronFieldValues(field, range[0], range[1], names[index]);
  });
  if (expanded.some((values) => values === undefined)) return false;
  const months = expanded[3] as Set<number>;
  const hours = expanded[1] as Set<number>;
  const minutes = expanded[0] as Set<number>;
  const daysOfMonth = expanded[2] as Set<number>;
  const daysOfWeek = new Set([...(expanded[4] as Set<number>)].map((day) => day === 7 ? 0 : day));
  const dailyMinutes = [...hours]
    .flatMap((hour) => [...minutes].map((minute) => hour * 60 + minute))
    .sort((left, right) => left - right);
  const firstDailyMinute = dailyMinutes[0];
  if (firstDailyMinute === undefined) return false;
  for (let index = 0; index < dailyMinutes.length; index += 1) {
    const current = dailyMinutes[index];
    const next = dailyMinutes[index + 1] ?? firstDailyMinute + 24 * 60;
    if (current === undefined || next - current < 5) return false;
  }
  const dayOfMonthWildcard = fields[2] === "*";
  const dayOfWeekWildcard = fields[4] === "*";
  for (let year = 2000; year < 2400; year += 1) {
    for (const month of months) {
      const daysInMonth = new Date(Date.UTC(year, month, 0)).getUTCDate();
      for (let day = 1; day <= daysInMonth; day += 1) {
        const dayOfWeek = new Date(Date.UTC(year, month - 1, day)).getUTCDay();
        const dayMatches = daysOfMonth.has(day);
        const weekMatches = daysOfWeek.has(dayOfWeek);
        if ((dayOfMonthWildcard && dayOfWeekWildcard) ||
          (dayOfMonthWildcard && weekMatches) ||
          (dayOfWeekWildcard && dayMatches) ||
          (!dayOfMonthWildcard && !dayOfWeekWildcard && (dayMatches || weekMatches))) {
          return true;
        }
      }
    }
  }
  return false;
}

function hasRunnableSchedule(events: Node | null | undefined, document: Document): boolean {
  const schedule = resolveYamlNode(yamlMappingEntry(events, "schedule", document)?.valueNode, document);
  if (!isSeq(schedule) || schedule.items.length === 0) return false;
  return schedule.items.every((rawEntry) => {
    const entry = resolveYamlNode(asYamlNode(rawEntry), document);
    if (!isMap(entry)) return false;
    const cron = resolveYamlNode(yamlMappingEntry(entry, "cron", document)?.valueNode, document);
    const timezoneEntry = yamlMappingEntry(entry, "timezone", document);
    const timezone = resolveYamlNode(timezoneEntry?.valueNode, document);
    if (timezoneEntry) {
      if (!isScalar(timezone) || typeof timezone.value !== "string") return false;
      try {
        new Intl.DateTimeFormat("en-US", { timeZone: timezone.value }).format();
      } catch {
        return false;
      }
    }
    return isScalar(cron) && typeof cron.value === "string" && validGitHubCron(cron.value);
  });
}

function hasUnfilteredEvent(events: Node | null | undefined, eventName: string, document: Document): boolean {
  const event = yamlMappingEntry(events, eventName, document);
  if (!event) return false;
  const value = resolveYamlNode(event.valueNode, document);
  return value === undefined || value === null ||
    (isScalar(value) && value.value === null) ||
    (isMap(value) && value.items.length === 0);
}

function jobRunsOnGitHubHosted(jobs: Node | null | undefined, jobName: string, document: Document): boolean {
  const runsOn = jobField(jobs, jobName, "runs-on", document);
  return isScalar(runsOn) && typeof runsOn.value === "string" &&
    new Set(["ubuntu-latest", "ubuntu-24.04", "ubuntu-22.04"]).has(runsOn.value);
}

function yamlStringSequenceValues(node: Node | null | undefined, document: Document): string[] | undefined {
  const resolved = resolveYamlNode(node, document);
  if (!isSeq(resolved)) return undefined;
  const values: string[] = [];
  for (const item of resolved.items) {
    const value = resolveYamlNode(asYamlNode(item), document);
    if (!isScalar(value) || typeof value.value !== "string") return undefined;
    values.push(value.value);
  }
  return values;
}

function mappingHasPermission(map: Node | null | undefined, permission: string, expected: string, document: Document): boolean {
  if (!isMap(map)) return false;
  const value = resolveYamlNode(yamlMappingEntry(map, permission, document)?.valueNode, document);
  return isScalar(value) && value.value === expected;
}

function yamlReferencesSecretContext(
  rawNode: Node | null | undefined,
  document: Document,
  seen = new Set<Node>()
): boolean {
  const node = resolveYamlNode(rawNode, document);
  if (!node || seen.has(node)) return false;
  seen.add(node);
  if (isScalar(node)) {
    return typeof node.value === "string" && /\$\{\{(?:(?!\}\})[\s\S])*\bsecrets\b(?:(?!\}\})[\s\S])*\}\}/i.test(node.value);
  }
  if (isSeq(node)) {
    return node.items.some((item) => yamlReferencesSecretContext(asYamlNode(item), document, seen));
  }
  if (isMap(node)) {
    return node.items.some((pair) => {
      const key = resolveYamlNode(asYamlNode(pair.key), document);
      if (isScalar(key) && typeof key.value === "string" && key.value.toLowerCase() === "secrets") return true;
      return yamlReferencesSecretContext(asYamlNode(pair.key), document, seen) ||
        yamlReferencesSecretContext(asYamlNode(pair.value), document, seen);
    });
  }
  return false;
}

async function publicSecurityResults(manifest: BootstrapManifest, targetDir: string): Promise<ConformanceResult[]> {
  if (manifest.project.visibility !== "public") {
    return [
      result("PRS-SECURITY-BASELINE-001", "pass", ["public security projection not required for non-public repository"], "Retain explicit security controls appropriate to the repository visibility."),
      result("PRS-FORK-SAFETY-001", "pass", ["public fork security workflow not projected"], "Re-evaluate fork safety before making the repository public.")
    ];
  }

  const baselineFailures: { evidence: string; remediation: string }[] = [];
  const forkFailures: { evidence: string; remediation: string }[] = [];
  const securityDoc = await readTextIfExists(path.join(targetDir, "SECURITY.md"));
  const expectedAdvisoryUrl = `https://github.com/${manifest.project.owner}/${manifest.project.name}/security/advisories/new`;
  if (!securityDoc?.includes(expectedAdvisoryUrl)) {
    baselineFailures.push({
      evidence: "SECURITY.md does not provide the private vulnerability reporting route",
      remediation: "Project SECURITY.md with the repository private-advisory URL and response targets."
    });
  }
  if (!securityDoc?.includes("Private security contact requested")) {
    baselineFailures.push({
      evidence: "SECURITY.md does not provide the detail-free fallback contact request",
      remediation: "Restore the managed fallback that requests a confidential channel without publishing vulnerability details."
    });
  }
  if (!securityDoc?.includes("3 business days") || !securityDoc.includes("10 business days")) {
    baselineFailures.push({
      evidence: "SECURITY.md does not define acknowledgement and status-update targets",
      remediation: "Project the managed 3-business-day acknowledgement and 10-business-day update targets."
    });
  }
  if (!securityDoc?.includes("7 days for critical") || !securityDoc.includes("30 days for high") || !securityDoc.includes("90 days for moderate") || !/coordinate(?:d)? disclosure/i.test(securityDoc)) {
    baselineFailures.push({
      evidence: "SECURITY.md does not define all severity remediation and coordinated-disclosure targets",
      remediation: "Restore the managed 7/30/90-day remediation targets and coordinated-disclosure commitment."
    });
  }

  const dependabot = await readTextIfExists(path.join(targetDir, ".github/dependabot.yml"));
  if (!manifest.ci.dependabot.enabled || !manifest.ci.dependabot.securityUpdates || !manifest.ci.dependabot.versionUpdates || !dependabot || !dependabotUpdatesActions(dependabot)) {
    baselineFailures.push({
      evidence: "Dependabot security updates and GitHub Actions pin updates are not fully projected",
      remediation: "Enable Dependabot security and version updates and include the github-actions ecosystem."
    });
  }

  const workflowPath = ".github/workflows/security.yml";
  const workflow = await readTextIfExists(path.join(targetDir, workflowPath));
  if (!workflow) {
    baselineFailures.push({
      evidence: `${workflowPath} is absent`,
      remediation: "Run bootstrap apply repo to project the public security workflow."
    });
    forkFailures.push({
      evidence: `${workflowPath} cannot be evaluated for fork safety`,
      remediation: "Project the managed public security workflow before accepting fork contributions."
    });
  } else {
    let document: Document;
    let workflowValid = true;
    try {
      document = parseDocument(workflow, { prettyErrors: false });
      if (document.errors.length > 0) throw document.errors[0];
    } catch (error) {
      workflowValid = false;
      const detail = error instanceof Error ? error.message : String(error);
      baselineFailures.push({ evidence: `${workflowPath} is invalid YAML: ${safeEvidence(detail)}`, remediation: "Repair the managed security workflow YAML." });
      forkFailures.push({ evidence: `${workflowPath} cannot be evaluated safely`, remediation: "Repair the workflow YAML before accepting fork contributions." });
      document = parseDocument("{}");
    }

    const root = asYamlNode(document.contents);
    const jobs = resolveYamlNode(yamlMappingEntry(root, "jobs", document)?.valueNode, document);
    const requiredJobActionSequences = [
      {
        job: "dependency-review",
        actions: [
          { prefix: "actions/checkout@" },
          { prefix: "actions/dependency-review-action@", requiredInputs: ["fail-on-severity"], optionalInputs: ["vulnerability-check", "warn-only"] }
        ]
      },
      {
        job: "codeql",
        actions: [
          { prefix: "actions/checkout@" },
          { prefix: "github/codeql-action/init@", requiredInputs: ["languages", "build-mode"] },
          { prefix: "github/codeql-action/analyze@", requiredInputs: ["category"], optionalInputs: ["upload"] }
        ]
      },
      {
        job: "sbom",
        actions: [
          { prefix: "actions/checkout@" },
          { prefix: "anchore/sbom-action@", requiredInputs: ["path", "format", "artifact-name", "upload-release-assets"], optionalInputs: ["upload-artifact"] }
        ]
      }
    ];
    const requiredJobNames = new Set(requiredJobActionSequences.map((requirement) => requirement.job));
    for (const requirement of requiredJobActionSequences) {
      if (!workflowValid || !jobHasExactActionSequence(jobs, requirement.job, requirement.actions, document)) {
        baselineFailures.push({
          evidence: `${workflowPath} job ${requirement.job} does not preserve its required action sequence`,
          remediation: `Restore the managed checkout and ${requirement.job} steps in executable order.`
        });
      }
      if (jobField(jobs, requirement.job, "needs", document) !== undefined) {
        baselineFailures.push({
          evidence: `${workflowPath} job ${requirement.job} declares a dependency that can suppress its required event lane`,
          remediation: `Remove needs from the managed ${requirement.job} job.`
        });
      }
      const continueOnError = jobField(jobs, requirement.job, "continue-on-error", document);
      if (continueOnError !== undefined && (!isScalar(continueOnError) || continueOnError.value !== false)) {
        baselineFailures.push({
          evidence: `${workflowPath} job ${requirement.job} can ignore security failures`,
          remediation: `Remove continue-on-error from the managed ${requirement.job} job.`
        });
      }
    }
    const dependencyReviewContract = {
      failOnSeverity: jobActionField(jobs, "dependency-review", "actions/dependency-review-action@", "fail-on-severity", document),
      vulnerabilityCheck: jobActionField(jobs, "dependency-review", "actions/dependency-review-action@", "vulnerability-check", document),
      warnOnly: jobActionField(jobs, "dependency-review", "actions/dependency-review-action@", "warn-only", document)
    };
    if (dependencyReviewContract.failOnSeverity !== "high" ||
      (dependencyReviewContract.vulnerabilityCheck !== undefined && dependencyReviewContract.vulnerabilityCheck !== true) ||
      (dependencyReviewContract.warnOnly !== undefined && dependencyReviewContract.warnOnly !== false)) {
      baselineFailures.push({
        evidence: `${workflowPath} dependency review inputs do not enforce blocking vulnerability checks`,
        remediation: "Restore fail-on-severity: high, keep vulnerability-check enabled, and keep warn-only disabled."
      });
    }
    const codeqlStrategy = jobField(jobs, "codeql", "strategy", document);
    const codeqlMatrix = isMap(codeqlStrategy)
      ? resolveYamlNode(yamlMappingEntry(codeqlStrategy, "matrix", document)?.valueNode, document)
      : undefined;
    const codeqlMatrixLanguages = isMap(codeqlMatrix)
      ? yamlStringSequenceValues(yamlMappingEntry(codeqlMatrix, "language", document)?.valueNode, document)
      : undefined;
    const codeqlLanguagesMatch = codeqlMatrixLanguages !== undefined &&
      codeqlMatrixLanguages.length === manifest.ci.codeqlLanguages.length &&
      codeqlMatrixLanguages.every((language, index) => language === manifest.ci.codeqlLanguages[index]);
    const codeqlMatrixHasOverrides = isMap(codeqlMatrix) &&
      (yamlMappingEntry(codeqlMatrix, "exclude", document) !== undefined || yamlMappingEntry(codeqlMatrix, "include", document) !== undefined);
    if (!codeqlLanguagesMatch || codeqlMatrixHasOverrides || jobActionField(jobs, "codeql", "github/codeql-action/init@", "languages", document) !== "${{ matrix.language }}") {
      baselineFailures.push({
        evidence: `${workflowPath} CodeQL languages do not match ci.codeqlLanguages`,
        remediation: "Configure the repository CodeQL languages explicitly and restore the managed per-language matrix and init step."
      });
    }
    if (jobActionField(jobs, "codeql", "github/codeql-action/init@", "build-mode", document) !== "none") {
      baselineFailures.push({
        evidence: `${workflowPath} CodeQL build mode is not the managed no-build contract`,
        remediation: "Restore build-mode: none and use only supported ci.codeqlLanguages values."
      });
    }
    if (jobActionField(jobs, "codeql", "github/codeql-action/analyze@", "category", document) !== "/language:${{ matrix.language }}") {
      baselineFailures.push({
        evidence: `${workflowPath} CodeQL analysis category does not preserve per-language evidence`,
        remediation: "Restore the managed /language:${{ matrix.language }} analysis category."
      });
    }
    const codeqlUpload = jobActionField(jobs, "codeql", "github/codeql-action/analyze@", "upload", document);
    if (codeqlUpload !== undefined && codeqlUpload !== true) {
      baselineFailures.push({
        evidence: `${workflowPath} CodeQL analysis upload is disabled`,
        remediation: "Remove upload: false from the managed CodeQL analyze step so default-branch results remain verifiable."
      });
    }
    const sbomContract = {
      path: jobActionField(jobs, "sbom", "anchore/sbom-action@", "path", document),
      format: jobActionField(jobs, "sbom", "anchore/sbom-action@", "format", document),
      artifactName: jobActionField(jobs, "sbom", "anchore/sbom-action@", "artifact-name", document),
      uploadReleaseAssets: jobActionField(jobs, "sbom", "anchore/sbom-action@", "upload-release-assets", document),
      uploadArtifact: jobActionField(jobs, "sbom", "anchore/sbom-action@", "upload-artifact", document)
    };
    if (sbomContract.path !== "." || sbomContract.format !== "spdx-json" || sbomContract.artifactName !== "sbom.spdx.json" ||
      sbomContract.uploadReleaseAssets !== false || (sbomContract.uploadArtifact !== undefined && sbomContract.uploadArtifact !== true)) {
      baselineFailures.push({
        evidence: `${workflowPath} SBOM inputs do not preserve the managed SPDX JSON artifact contract`,
        remediation: "Restore path '.', format spdx-json, artifact-name sbom.spdx.json, upload-artifact true, and upload-release-assets false."
      });
    }

    const events = resolveYamlNode(yamlMappingEntry(root, "on", document)?.valueNode, document);
    if (!hasUnfilteredEvent(events, "pull_request", document)) {
      forkFailures.push({ evidence: `${workflowPath} does not use an unfiltered fork-safe pull_request event`, remediation: "Use an unfiltered pull_request trigger for pre-merge dependency review." });
    }
    if (yamlMappingEntry(events, "pull_request_target", document)) {
      forkFailures.push({ evidence: `${workflowPath} uses pull_request_target`, remediation: "Remove pull_request_target from the public security workflow." });
    }
    if (isMap(events)) {
      const allowedEvents = new Set(["pull_request", "push", "schedule"]);
      for (const pair of events.items) {
        const eventName = resolveYamlNode(asYamlNode(pair.key), document);
        if (isScalar(eventName) && typeof eventName.value === "string" && !allowedEvents.has(eventName.value)) {
          forkFailures.push({ evidence: `${workflowPath} includes unapproved event ${eventName.value}`, remediation: "Limit the public security workflow to pull_request, push, and schedule." });
        }
      }
    }
    const push = resolveYamlNode(yamlMappingEntry(events, "push", document)?.valueNode, document);
    const pushBranches = isMap(push)
      ? yamlMappingEntry(push, "branches", document)?.valueNode
      : undefined;
    const pushBranchValues = yamlStringSequenceValues(pushBranches, document);
    const pushKeys = isMap(push)
      ? push.items.flatMap((pair) => {
          const key = resolveYamlNode(asYamlNode(pair.key), document);
          return isScalar(key) && typeof key.value === "string" ? [key.value] : [];
        })
      : [];
    const effectiveDefaultBranchPush = pushBranchValues?.length === 1 &&
      pushBranchValues[0] === manifest.project.defaultBranch &&
      pushKeys.length === 1 && pushKeys[0] === "branches";
    if (!effectiveDefaultBranchPush) {
      baselineFailures.push({ evidence: `${workflowPath} does not scan every trusted push to ${manifest.project.defaultBranch}`, remediation: "Use only the exact default branch filter and remove negation and path filters from the trusted push trigger." });
    }
    if (!hasRunnableSchedule(events, document)) {
      baselineFailures.push({ evidence: `${workflowPath} has no runnable scheduled security scan`, remediation: "Restore at least one valid five-field cron schedule." });
    }
    const permissions = resolveYamlNode(yamlMappingEntry(root, "permissions", document)?.valueNode, document);
    if (!mappingPermissionsAreReadOnly(permissions, document)) {
      forkFailures.push({ evidence: `${workflowPath} top-level permissions are not read-only`, remediation: "Set top-level workflow permissions to contents: read and grant trusted jobs narrowly scoped permissions." });
    }
    if (yamlReferencesSecretContext(root, document)) {
      forkFailures.push({ evidence: `${workflowPath} references GitHub Actions secrets`, remediation: "Remove secret inputs from every workflow reachable by fork pull requests." });
    }
    if (jobCondition(jobs, "dependency-review", document) !== dependencyReviewJobCondition) {
      forkFailures.push({ evidence: "dependency-review is not restricted to the activated pull_request lane", remediation: "Restrict dependency review to pull_request after GitHub provisioning activates the dependency graph control." });
    }
    if (!jobRunsOnGitHubHosted(jobs, "dependency-review", document)) {
      forkFailures.push({ evidence: "dependency-review does not use GitHub-hosted isolation", remediation: "Run untrusted public fork validation on a GitHub-hosted runner." });
    }
    const dependencyPermissions = jobField(jobs, "dependency-review", "permissions", document);
    if (!mappingPermissionsAreReadOnly(dependencyPermissions, document)) {
      forkFailures.push({ evidence: "dependency-review job permissions are not read-only", remediation: "Restrict the pull-request job to read-only contents and pull-request permissions." });
    }
    for (const trustedJob of ["codeql", "sbom"]) {
      if (jobCondition(jobs, trustedJob, document) !== trustedSecurityJobCondition) {
        forkFailures.push({ evidence: `${trustedJob} is not restricted to approved trusted events`, remediation: `Restrict ${trustedJob} to push and schedule events.` });
      }
      if (!jobRunsOnGitHubHosted(jobs, trustedJob, document)) {
        baselineFailures.push({ evidence: `${trustedJob} has no approved security executor boundary`, remediation: `Use GitHub-hosted isolation for ${trustedJob}.` });
      }
    }
    const codeqlPermissions = jobField(jobs, "codeql", "permissions", document);
    if (!mappingHasPermission(codeqlPermissions, "contents", "read", document) || !mappingHasPermission(codeqlPermissions, "security-events", "write", document)) {
      baselineFailures.push({ evidence: "codeql lacks contents: read or security-events: write", remediation: "Grant the trusted CodeQL job contents: read and security-events: write so it can upload analysis." });
    }
    const sbomPermissions = jobField(jobs, "sbom", "permissions", document);
    if (!mappingHasPermission(sbomPermissions, "contents", "write", document)) {
      baselineFailures.push({ evidence: "sbom lacks contents: write", remediation: "Grant the trusted SBOM job contents: write so the pinned action can upload its workflow artifact." });
    }
    if (isMap(jobs)) {
      for (const pair of jobs.items) {
        const name = resolveYamlNode(asYamlNode(pair.key), document);
        const job = resolveYamlNode(asYamlNode(pair.value), document);
        if (!isScalar(name) || typeof name.value !== "string" || !isMap(job)) continue;
        const condition = jobCondition(jobs, name.value, document);
        const excludedFromPullRequests = condition === trustedSecurityJobCondition;
        if (!requiredJobNames.has(name.value)) {
          baselineFailures.push({ evidence: `${workflowPath} includes unmanaged job ${name.value}`, remediation: "Remove unmanaged jobs from the public security workflow." });
        }
        if (!excludedFromPullRequests && name.value !== "dependency-review") {
          forkFailures.push({ evidence: `${name.value} may run on pull_request`, remediation: "Make dependency-review the only pull-request-reachable security job." });
        }
        if (!excludedFromPullRequests) {
          if (name.value !== "dependency-review" && !jobRunsOnGitHubHosted(jobs, name.value, document)) {
            forkFailures.push({ evidence: `${name.value} does not use GitHub-hosted isolation`, remediation: "Run every pull-request-reachable job on an approved GitHub-hosted runner." });
          }
          const jobPermissions = resolveYamlNode(yamlMappingEntry(job, "permissions", document)?.valueNode, document);
          if (!mappingPermissionsAreReadOnly(jobPermissions, document)) {
            forkFailures.push({ evidence: `${name.value} has non-read-only pull-request permissions`, remediation: "Restrict every pull-request-reachable job to read-only permissions." });
          }
        }
      }
    }
  }

  return [
    ...(baselineFailures.length === 0
      ? [result("PRS-SECURITY-BASELINE-001", "pass", ["security policy, dependency updates, code scanning, and SBOM projection validated"], "Keep the managed public security baseline current.")]
      : baselineFailures.map((failure) => result("PRS-SECURITY-BASELINE-001", "blocking", [failure.evidence], failure.remediation))),
    ...(forkFailures.length === 0
      ? [result("PRS-FORK-SAFETY-001", "pass", ["pull-request security lane is read-only and does not reference secrets"], "Keep privileged security jobs unreachable from fork pull requests.")]
      : forkFailures.map((failure) => result("PRS-FORK-SAFETY-001", "blocking", [failure.evidence], failure.remediation)))
  ];
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
  const securityBaselineWaiver = findWaiver(manifest, validExceptionIds, waiverTargets.securityBaseline);
  results.push(...(await publicSecurityResults(manifest, targetDir)).map((entry) => applyWaiver(entry, securityBaselineWaiver)));

  const githubCapabilities = githubCapabilitySnapshotSchema.parse(options.githubCapabilities ?? { schemaVersion: 1, observations: [] });
  if (manifest.project.visibility === "public") {
    const observedControls = new Set(githubCapabilities.observations.map((entry) => entry.control));
    for (const control of publicSecurityCapabilityControls) {
      if (observedControls.has(control)) continue;
      const missingObservation = result(
        "PRS-SECURITY-CAPABILITY-001",
        "warning",
        [`${control}: no authorized observation provided`],
        `Capture ${control} in a versioned GitHub capability snapshot.`,
        "unverified"
      );
      const capabilityWaiver = findWaiver(manifest, validExceptionIds, {
        policy: "github-capability",
        scope: `github.${control}`
      });
      results.push(applyWaiver(missingObservation, capabilityWaiver));
    }
  }
  for (const capability of githubCapabilities.observations) {
    const dependencyReviewActivationUnverified = capability.control === "dependency-graph" &&
      capability.status === "supported" && capability.dependencyReviewEnabled === undefined;
    const dependencyReviewActivationDisabled = capability.control === "dependency-graph" &&
      capability.status === "supported" && capability.dependencyReviewEnabled === false;
    const severity = dependencyReviewActivationUnverified
      ? "warning"
      : dependencyReviewActivationDisabled
        ? "blocking"
        : capability.status === "supported"
          ? "pass"
          : capability.status === "unsupported"
            ? "warning"
            : "blocking";
    const classification = dependencyReviewActivationUnverified
      ? "unverified"
      : dependencyReviewActivationDisabled
        ? "misconfigured"
        : capability.status === "supported"
          ? "conformant"
          : capability.status;
    const activationEvidence = capability.control === "dependency-graph" && capability.status === "supported"
      ? [capability.dependencyReviewEnabled === true
          ? "dependency review activation: enabled"
          : capability.dependencyReviewEnabled === false
            ? "dependency review activation: disabled"
            : "dependency review activation: no authorized observation provided"]
      : [];
    const capabilityResult = result(
      "PRS-GITHUB-CAPABILITY-001",
      severity,
      [`${capability.control}: ${capability.evidence}`, ...activationEvidence],
      dependencyReviewActivationUnverified || dependencyReviewActivationDisabled
        ? "Verify the dependency graph and record DEPENDENCY_REVIEW_ENABLED=true in the authorized capability observation."
        : capability.remediation,
      classification
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
