import path from "node:path";

import { capturePublicGenerator } from "./upgrade-generator.js";
import { observeUpgradeGovernance, readOwnedGovernance } from "./upgrade-governance.js";
import { decode, readRegular } from "./upgrade-host.js";
import { ObservationFailure } from "./upgrade-public-read.js";
import { captureRuntimePolicy, missingRuntimeConfiguration, parseUpgradeRuntimeRequest } from "./upgrade-runtime-policy.js";
import type { FleetUpgradePlanEntry } from "./upgrades.js";

const REQUEST_BYTES = 64 * 1024;
const PLAN_DEADLINE_MS = 300_000;
const reportScope = { schemaVersion: 1, authority: "none", publication: "unavailable" } as const;

type GovernedUpgradeReport = typeof reportScope & (
  | { status: "blocked"; reason: string }
  | {
    status: "planned";
    repositoryId: number;
    baseCommit: string;
    cohortComment: number;
    targetDigest: string;
    plan: FleetUpgradePlanEntry;
    independentReview: "pending";
    publicationBlockers: string[];
  }
);

function blocked(reason: string): GovernedUpgradeReport {
  return { ...reportScope, status: "blocked", reason };
}

/** Read the enrolled public fleet and plan one selected repository without preparing or publishing a candidate. */
export async function runGovernedUpgrade(input: unknown, options: { signal?: AbortSignal } = {}): Promise<GovernedUpgradeReport> {
  const deadline = AbortSignal.timeout(PLAN_DEADLINE_MS);
  const signal = options.signal ? AbortSignal.any([options.signal, deadline]) : deadline;
  let unavailable = "request-invalid";
  try {
    signal.throwIfAborted();
    const request = parseUpgradeRuntimeRequest(input);
    unavailable = "generator-unavailable";
    const generator = await capturePublicGenerator(request.generatorRoot, request.generatorCommit, { signal });
    unavailable = "runtime-policy-unavailable";
    const policy = await captureRuntimePolicy(generator, { signal });
    unavailable = "governance-unavailable";
    const observation = await observeUpgradeGovernance(policy, request, { signal });
    if (readOwnedGovernance(observation).runtimePolicy !== policy) return blocked(unavailable);
    const publicationBlockers = missingRuntimeConfiguration(policy);
    signal.throwIfAborted();
    const { repositoryId, baseCommit, cohortComment, targetDigest, plan, independentReview } = observation;
    return { ...reportScope, status: "planned", repositoryId, baseCommit, cohortComment, targetDigest, plan,
      independentReview, publicationBlockers };
  } catch (error) {
    // Observation failure codes are fixed producer diagnostics. Other errors may carry paths or raw input.
    return blocked(signal.aborted ? "aborted-or-deadline" : error instanceof ObservationFailure ? error.code : unavailable);
  }
}

async function planRequestFile(requestPath: string): Promise<GovernedUpgradeReport> {
  let bytes: Buffer;
  try { bytes = await readRegular(path.resolve(requestPath), REQUEST_BYTES); }
  catch { return blocked("request-unavailable"); }
  let request: unknown;
  try { request = JSON.parse(decode(bytes)); }
  catch { return blocked("request-invalid"); }
  return runGovernedUpgrade(request);
}

function formatGovernedUpgrade(report: GovernedUpgradeReport): string {
  if (report.status === "blocked") return `Fleet upgrade blocked (${report.reason}). Publication is unavailable.`;
  const { plan, repositoryId, baseCommit, cohortComment, targetDigest, publicationBlockers } = report;
  return [
    `Fleet upgrade dry run for ${plan.repo} (repository ${repositoryId}).`,
    `${plan.repoClass} · ${plan.currentPolicy} → ${plan.targetPolicy} · ${plan.risk} · ${plan.role} · ${plan.status}`,
    plan.reason,
    `Base ${baseCommit}, cohort comment ${cohortComment}, target policy digest ${targetDigest}.`,
    "Independent review is pending. Publication is unavailable.",
    ...publicationBlockers.map((reason) => `- ${reason}`)
  ].join("\n");
}

export async function runGovernedUpgradeCommand(
  requestPath: string, options: { json?: boolean; publish?: boolean }
): Promise<{ output: string; exitCode: number }> {
  const report = options.publish ? blocked("publication-unavailable") : await planRequestFile(requestPath);
  return {
    output: options.json ? JSON.stringify(report, null, 2) : formatGovernedUpgrade(report),
    exitCode: report.status === "planned" ? 0 : 1
  };
}
