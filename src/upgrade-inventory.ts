import type { FleetUpgradeCandidate } from "./upgrades.js";

/** Validate operator-supplied JSON before classifying any candidate. */
export function parseFleetUpgradeInventory(input: unknown): FleetUpgradeCandidate[] {
  if (!Array.isArray(input)) throw new Error("Invalid fleet upgrade inventory: expected an array.");

  return input.map((item: unknown, index: number) => {
    const invalid = (field: string): never => {
      throw new Error(`Invalid fleet upgrade inventory: entry ${index}, invalid ${field}.`);
    };
    if (typeof item !== "object" || item === null || Array.isArray(item)) return invalid("candidate");
    const candidate = item as Record<string, unknown>;
    for (const field of ["repo", "repoClass"] as const) {
      if (typeof candidate[field] !== "string" || candidate[field].trim().length === 0) invalid(field);
    }
    for (const field of ["currentPolicy", "targetPolicy"] as const) {
      if (typeof candidate[field] !== "string") invalid(field);
    }
    if ("exceptionId" in candidate && (typeof candidate.exceptionId !== "string" || candidate.exceptionId.trim().length === 0)) invalid("exceptionId");
    if ("pilotOutcome" in candidate && candidate.pilotOutcome !== "pending" && candidate.pilotOutcome !== "passed" && candidate.pilotOutcome !== "failed") invalid("pilotOutcome");
    // Keep unknown operator metadata and preserve version strings for planner classification.
    return candidate as unknown as FleetUpgradeCandidate;
  });
}
