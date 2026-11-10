export type UpgradeRisk = "patch" | "minor" | "major" | "invalid";
export type PilotOutcome = "pending" | "passed" | "failed";

export interface FleetUpgradeCandidate {
  repo: string;
  repoClass: string;
  currentPolicy: string;
  targetPolicy: string;
  exceptionId?: string;
  pilotOutcome?: PilotOutcome;
}

export interface FleetUpgradePlanEntry extends FleetUpgradeCandidate {
  risk: UpgradeRisk;
  role: "pilot" | "batch";
  status: "eligible" | "review-required" | "blocked";
  reason: string;
}

type Semver = { major: string; minor: string; patch: string };

function parseVersion(value: string): Semver | undefined {
  const match = /^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/.exec(value);
  if (!match || match[0] !== value) return undefined;
  return { major: match[1]!, minor: match[2]!, patch: match[3]! };
}

export function classifyPolicyUpgrade(currentPolicy: string, targetPolicy: string): UpgradeRisk {
  const current = parseVersion(currentPolicy);
  const target = parseVersion(targetPolicy);
  if (!current || !target) return "invalid";
  for (const risk of ["major", "minor", "patch"] as const) {
    const from = current[risk];
    const to = target[risk];
    if (from === to) continue;
    // Canonical decimal components compare exactly without Number rounding.
    return to.length > from.length || (to.length === from.length && to > from) ? risk : "invalid";
  }
  return "invalid";
}

export function planFleetPolicyUpgrades(candidates: FleetUpgradeCandidate[]): FleetUpgradePlanEntry[] {
  const pilots = new Map<string, PilotOutcome>();
  return [...candidates]
    .sort((left, right) => left.repoClass.localeCompare(right.repoClass) || left.repo.localeCompare(right.repo))
    .map((candidate) => {
      const risk = classifyPolicyUpgrade(candidate.currentPolicy, candidate.targetPolicy);
      const knownPilot = pilots.get(candidate.repoClass);
      const role = knownPilot === undefined ? "pilot" : "batch";
      if (role === "pilot") pilots.set(candidate.repoClass, candidate.pilotOutcome ?? "pending");

      if (risk === "invalid") return { ...candidate, risk, role, status: "blocked", reason: "Policy versions must be increasing exact SemVer values." };
      if (knownPilot === "failed") return { ...candidate, risk, role, status: "blocked", reason: `The ${candidate.repoClass} pilot failed; stop this batch until remediation is recorded.` };
      if (role === "batch" && knownPilot !== "passed") return { ...candidate, risk, role, status: "blocked", reason: `The ${candidate.repoClass} pilot has not passed; record a passing representative pilot before rolling this class forward.` };
      if (candidate.exceptionId) return { ...candidate, risk, role, status: "review-required", reason: `Exception ${candidate.exceptionId} requires human review before a fleet upgrade PR.` };
      if (risk === "major") return { ...candidate, risk, role, status: "review-required", reason: "Major upgrades require notification and an accepted ADR before opening a PR." };
      if (risk === "minor") return { ...candidate, risk, role, status: "review-required", reason: "Minor upgrades require independent review before merge." };
      if (role === "pilot" && (candidate.pilotOutcome ?? "pending") !== "passed") return { ...candidate, risk, role, status: "review-required", reason: "Record a passing representative pilot before rolling this class forward." };
      return { ...candidate, risk, role, status: "eligible", reason: "Patch upgrade is eligible after the representative class pilot passed." };
    });
}
