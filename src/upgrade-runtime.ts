import path from "node:path";

import { discoverPublicManifests } from "./upgrade-discovery.js";
import { capturePublicGenerator } from "./upgrade-generator.js";
import { observeUpgradeGovernance, readOwnedGovernance } from "./upgrade-governance.js";
import { decode, readRegular } from "./upgrade-host.js";
import { observeManagedCi, readOwnedCiObservation } from "./upgrade-pilot-ci.js";
import { observePublicPolicies, readOwnedPolicyObservation } from "./upgrade-policy.js";
import { ObservationFailure } from "./upgrade-public-read.js";
import { captureRuntimePolicy, missingRuntimeConfiguration, parseUpgradeRuntimeRequest, readRuntimePolicy } from "./upgrade-runtime-policy.js";
import type { FleetUpgradePlanEntry } from "./upgrades.js";

const REQUEST_BYTES = 64 * 1024;
const PLAN_DEADLINE_MS = 300_000;
const reportScope = { schemaVersion: 1, authority: "none", publication: "unavailable" } as const;

type BlockedReport = typeof reportScope & { status: "blocked"; reason: string };
type GovernedUpgradeReport = BlockedReport | (typeof reportScope & {
  status: "planned";
  repositoryId: number;
  baseCommit: string;
  cohortComment: number;
  targetDigest: string;
  plan: FleetUpgradePlanEntry;
  independentReview: "pending";
  publicationBlockers: string[];
});
type PilotCiReport = {
  repository: string;
  repositoryId: number;
  head: string;
  target: { ref: string; commit: string; sha256: string; version: string };
  ci: { runId: number; attempt: number; evidenceSha256: string; workflowSha256: string };
};

function blocked(reason: string): BlockedReport {
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

async function useRequestFile<T>(requestPath: string, run: (input: unknown) => Promise<T>): Promise<T | BlockedReport> {
  let bytes: Buffer;
  try { bytes = await readRegular(path.resolve(requestPath), REQUEST_BYTES); }
  catch { return blocked("request-unavailable"); }
  let request: unknown;
  try { request = JSON.parse(decode(bytes)); }
  catch { return blocked("request-invalid"); }
  return run(request);
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
  const report = options.publish ? blocked("publication-unavailable") : await useRequestFile(requestPath, runGovernedUpgrade);
  return {
    output: options.json ? JSON.stringify(report, null, 2) : formatGovernedUpgrade(report),
    exitCode: report.status === "planned" ? 0 : 1
  };
}

/** Read the evidence for an operator's passing pilot record without creating or authorizing that record. */
async function observePilotCi(input: unknown, mergedCommit: string): Promise<PilotCiReport | BlockedReport> {
  const signal = AbortSignal.timeout(PLAN_DEADLINE_MS);
  let unavailable = "request-invalid";
  try {
    const request = parseUpgradeRuntimeRequest(input);
    unavailable = "generator-unavailable";
    const generator = await capturePublicGenerator(request.generatorRoot, request.generatorCommit, { signal });
    unavailable = "runtime-policy-unavailable";
    const runtimePolicy = await captureRuntimePolicy(generator, { signal });
    const { projection } = readRuntimePolicy(runtimePolicy);
    if (!projection.repositories.some(({ id, repository }) => id === request.repositoryId && repository === request.repository)) {
      return blocked("repository-not-authorized");
    }

    unavailable = "fleet-incomplete";
    const discovery = await discoverPublicManifests(projection.organization, { signal });
    if (discovery.status !== "complete") return blocked(unavailable);
    const repository = discovery.repositories.find(({ repositoryId, repository }) =>
      repositoryId === request.repositoryId && repository === request.repository);
    if (!repository || repository.outcome !== "managed" || repository.fork || repository.disabled || repository.archived) {
      return blocked("pilot-repository-unavailable");
    }
    if (repository.head !== mergedCommit) return blocked("pilot-merged-head-mismatch");

    unavailable = "pilot-policy-unavailable";
    const policy = await observePublicPolicies(discovery, repository, generator, request.target, { signal });
    if (policy.status !== "observed") return blocked(policy.reason ?? unavailable);
    const owned = readOwnedPolicyObservation(policy);
    const target = {
      ref: owned.targetBinding.ref, commit: owned.targetBinding.commit,
      sha256: owned.targetBinding.canonicalSha256, version: owned.target.policy.version
    };
    if (owned.repository.head !== mergedCommit || owned.repository.id !== request.repositoryId ||
        owned.repository.repository !== request.repository) return blocked("pilot-merged-head-mismatch");
    if (target.ref !== request.target.ref || target.sha256 !== request.target.sha256 ||
        owned.sourceBinding.ref !== target.ref || owned.sourceBinding.commit !== target.commit ||
        owned.sourceBinding.canonicalSha256 !== target.sha256 || owned.source.policy.version !== target.version) {
      return blocked("pilot-policy-not-target");
    }

    unavailable = "runtime-policy-unavailable";
    const finalPolicy = await captureRuntimePolicy(generator, { signal });
    if (finalPolicy.projectionDigest !== runtimePolicy.projectionDigest) return blocked("runtime-policy-changed");
    // CI's final remote read rechecks the selected repository after the controller check.
    unavailable = "pilot-ci-unavailable";
    const result = await observeManagedCi(policy, { signal });
    if (result.status !== "observed") return blocked(result.reason ?? unavailable);
    const ci = readOwnedCiObservation(result);
    if (ci.policy !== policy || ci.repositoryId !== request.repositoryId || ci.head !== mergedCommit ||
        ci.policyRef !== target.ref || ci.policyCommit !== target.commit ||
        ci.policyDigest !== target.sha256 || ci.policyVersion !== target.version) return blocked("pilot-ci-binding");
    signal.throwIfAborted();
    return {
      repository: request.repository, repositoryId: request.repositoryId, head: mergedCommit, target,
      ci: { runId: ci.run.id, attempt: ci.run.attempt, evidenceSha256: ci.evidenceSha256, workflowSha256: ci.workflowSha256 }
    };
  } catch (error) {
    return blocked(signal.aborted ? "aborted-or-deadline" : error instanceof ObservationFailure ? error.code : unavailable);
  }
}

export async function runPilotCiCommand(
  requestPath: string, mergedCommit: string, options: { json?: boolean }
): Promise<{ output: string; exitCode: number }> {
  const report = mergedCommit.length === 40 && /^[a-f0-9]{40}$/.test(mergedCommit)
    ? await useRequestFile(requestPath, (input) => observePilotCi(input, mergedCommit))
    : blocked("merged-commit-invalid");
  const success = "ci" in report;
  const output = success
    ? [
      `Pilot CI evidence for ${report.repository} at ${report.head}.`,
      `Target ${report.target.version} (${report.target.ref} at ${report.target.commit}, SHA-256 ${report.target.sha256}).`,
      JSON.stringify(report.ci)
    ].join("\n")
    : `Pilot CI evidence unavailable (${report.reason}).`;
  return { output: options.json ? JSON.stringify(report, null, 2) : output, exitCode: success ? 0 : 1 };
}
