import { z } from "zod";

import { resolveFlowPolicy, type ResolvedPolicyContract } from "./policy.js";
import type { BootstrapManifest } from "./types.js";

export const POLICY_SOURCE_FAILURE = "PRS-POLICY-SOURCE-001: The declared Flow response policy requires an immutable, digest-verified compatible local bundle and matching resolved context.";
const days = z.number().int().positive().max(Number.MAX_SAFE_INTEGER);
const responseTargetsSchema = z.object({
  acknowledgePrivateReportBusinessDays: days,
  triageCalendarDays: days,
  criticalRemediateOrContainCalendarDays: days,
  highRemediateCalendarDays: days
}).strict();

export function flowResponseCommitments(manifest: BootstrapManifest, resolved?: ResolvedPolicyContract): string[] | undefined {
  if (!manifest.policy?.flow) return undefined;
  try {
    const source = manifest.policy.flow;
    if (!resolved || resolved.source.ref !== source.ref || resolved.source.sha256.toLowerCase() !== source.sha256.toLowerCase()) throw new Error();
    const verified = resolveFlowPolicy(manifest, resolved.policy, source);
    const targets = z.object({ responseTargets: responseTargetsSchema }).parse(verified.policy.security).responseTargets;
    const deadline = (value: number, unit: "business" | "calendar"): string => `${value} ${unit} day${value === 1 ? "" : "s"}`;
    return [
      `Acknowledge a complete private report within ${deadline(targets.acknowledgePrivateReportBusinessDays, "business")}`,
      `Triage a confirmed report within ${deadline(targets.triageCalendarDays, "calendar")}`,
      `Remediate or contain critical findings within ${deadline(targets.criticalRemediateOrContainCalendarDays, "calendar")}`,
      `Remediate high findings within ${deadline(targets.highRemediateCalendarDays, "calendar")}`,
      "Coordinate public disclosure with the reporter after remediation"
    ];
  } catch {
    throw new Error(POLICY_SOURCE_FAILURE);
  }
}
