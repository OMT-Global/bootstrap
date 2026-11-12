import { describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";

import { classifyPolicyUpgrade, planFleetPolicyUpgrades } from "../src/upgrades.js";

describe("fleet policy upgrades", () => {
  it("blocks every affected class when repository identities are duplicated, regardless of input order", () => {
    const base = { repo: "acme/pilot", repoClass: "service", currentPolicy: "1.0.0", targetPolicy: "1.0.1" };
    const passing = { ...base, pilotOutcome: "passed" as const };
    const failed = { ...base, repo: " ACME/PILOT ", pilotOutcome: "failed" as const };
    const batch = { ...base, repo: "acme/next" };
    const otherClass = { ...base, repo: "acme/other", repoClass: "cli", pilotOutcome: "passed" as const };
    for (const rows of [[passing, failed, batch, otherClass], [failed, passing, batch, otherClass]]) {
      const result = planFleetPolicyUpgrades(rows);
      expect(result.filter((row) => row.repoClass === "service").every((row) => row.status === "blocked" && row.reason.includes("duplicate"))).toBe(true);
      expect(result.find((row) => row.repoClass === "cli")?.status).toBe("eligible");
    }
    const crossClass = planFleetPolicyUpgrades([passing, { ...failed, repoClass: "cli" }, batch, otherClass]);
    expect(crossClass.every((row) => row.status === "blocked" && row.reason.includes("duplicate"))).toBe(true);
  });
  it("chooses the same class pilot across process locales", () => {
    const program = `import { planFleetPolicyUpgrades } from './src/upgrades.ts';
const entries = [
  { repo: 'acme/Å', repoClass: 'service', currentPolicy: '1.0.0', targetPolicy: '1.0.1', pilotOutcome: 'failed' },
  { repo: 'acme/Z', repoClass: 'service', currentPolicy: '1.0.0', targetPolicy: '1.0.1', pilotOutcome: 'passed' }
];
process.stdout.write(JSON.stringify(planFleetPolicyUpgrades(entries).map(({repo, role, status}) => ({repo, role, status}))));`;
    const observe = (locale: string) => execFileSync(process.execPath, ["--import", "tsx", "--input-type=module", "-e", program], {
      cwd: process.cwd(), encoding: "utf8", env: { PATH: process.env.PATH ?? "/usr/bin:/bin", LANG: locale, LC_ALL: locale }, timeout: 10000
    });
    const english = observe("en_US.UTF-8"), swedish = observe("sv_SE.UTF-8");
    expect(english).toBe(swedish);
    expect(JSON.parse(english)).toEqual([
      { repo: "acme/Z", role: "pilot", status: "eligible" },
      { repo: "acme/Å", role: "batch", status: "eligible" }
    ]);
  });
  it("classifies patch, minor, major, and invalid policy versions", () => {
    expect(classifyPolicyUpgrade("1.2.3", "1.2.4")).toBe("patch");
    expect(classifyPolicyUpgrade("1.2.3", "1.3.0")).toBe("minor");
    expect(classifyPolicyUpgrade("1.2.3", "2.0.0")).toBe("major");
    expect(classifyPolicyUpgrade("1.2.3", "1.2.2")).toBe("invalid");
  });

  it.each([
    ["1.2.3", "1.2.3"],
    ["v1.2.3", "1.2.3"],
    ["1.2.3", "v1.2.3"],
    ["01.2.3", "1.2.4"],
    ["1.02.3", "1.2.4"],
    ["1.2.03", "1.2.4"],
    ["1.2.3", "01.2.4"],
    ["1.2.3", "1.02.4"],
    ["1.2.3", "1.2.04"],
    ["1.2.3\n", "1.2.4"],
    ["1.2.3", "1.2.4\n"],
    ["1.2.3", "1.2.4\r\n"],
    ["1.2.3", "1.2.4\u2028"],
    ["1.2.3", "1.2.4\u2029"],
    ["9007199254740993.0.0", "9007199254740992.0.0"],
    ["1.9007199254740993.0", "1.9007199254740992.0"],
    ["1.2.9007199254740993", "1.2.9007199254740992"],
    [`${"9".repeat(400)}.0.0`, `${"8".repeat(400)}.0.0`]
  ])("rejects non-increasing or noncanonical versions %j → %j", (current, target) => {
    expect(classifyPolicyUpgrade(current, target)).toBe("invalid");
  });

  it.each([
    ["0.0.0", "0.0.1", "patch"],
    ["v1.2.3", "1.2.4", "patch"],
    ["1.2.3", "v1.2.4", "patch"],
    ["1.9.9", "v1.10.0", "minor"],
    ["v9.9.9", "10.0.0", "major"],
    ["9007199254740992.0.0", "9007199254740993.0.0", "major"],
    ["1.9007199254740992.0", "1.9007199254740993.0", "minor"],
    ["1.2.9007199254740992", "1.2.9007199254740993", "patch"],
    [`${"9".repeat(100)}.0.0`, `1${"0".repeat(100)}.0.0`, "major"]
  ])("classifies exact increasing versions %j → %j as %s", (current, target, risk) => {
    expect(classifyPolicyUpgrade(current, target)).toBe(risk);
  });

  it.each(["1.2.4-rc.1", "1.2.4+build.1", "^1.2.4", " 1.2.4", "1.2.4 ", "V1.2.4"])(
    "preserves rejection of unsupported policy version %j", (target) => {
      expect(classifyPolicyUpgrade("1.2.3", target)).toBe("invalid");
    }
  );

  it.each([
    ["1.2.3", "1.2.3"],
    ["1.2.3", "1.2.04"],
    ["1.2.3", "1.2.4\n"],
    ["9007199254740993.0.0", "9007199254740992.0.0"],
    ["1.9007199254740993.0", "1.9007199254740992.0"],
    ["1.2.9007199254740993", "1.2.9007199254740992"]
  ])("blocks invalid %j → %j despite a recorded passing class pilot", (currentPolicy, targetPolicy) => {
    const plan = planFleetPolicyUpgrades([
      { repo: "acme/a-pilot", repoClass: "service", currentPolicy: "1.0.0", targetPolicy: "1.0.1", pilotOutcome: "passed" },
      { repo: "acme/b-candidate", repoClass: "service", currentPolicy, targetPolicy, pilotOutcome: "passed" }
    ]);

    expect(plan[0]).toMatchObject({ role: "pilot", risk: "patch", status: "eligible" });
    expect(plan[1]).toMatchObject({
      role: "batch", risk: "invalid", status: "blocked",
      reason: "Policy versions must be increasing exact SemVer values."
    });
  });

  it.each([
    ["9007199254740992.0.0", "9007199254740993.0.0", "major", "Major upgrades require notification and an accepted ADR before opening a PR."],
    ["1.9007199254740992.0", "1.9007199254740993.0", "minor", "Minor upgrades require independent review before merge."]
  ])("keeps review gates for large exact %s → %s upgrades", (currentPolicy, targetPolicy, risk, reason) => {
    const [entry] = planFleetPolicyUpgrades([
      { repo: "acme/pilot", repoClass: "service", currentPolicy, targetPolicy, pilotOutcome: "passed" }
    ]);

    expect(entry).toMatchObject({ role: "pilot", risk, status: "review-required", reason });
  });

  it("requires a first-class pilot and stops later candidates after a failed pilot", () => {
    const plan = planFleetPolicyUpgrades([
      { repo: "acme/service-a", repoClass: "service", currentPolicy: "1.0.0", targetPolicy: "1.0.1", pilotOutcome: "failed" },
      { repo: "acme/service-b", repoClass: "service", currentPolicy: "1.0.0", targetPolicy: "1.0.1" },
      { repo: "acme/cli-a", repoClass: "cli", currentPolicy: "1.0.0", targetPolicy: "1.0.1", pilotOutcome: "passed" },
      { repo: "acme/cli-b", repoClass: "cli", currentPolicy: "1.0.0", targetPolicy: "1.0.1" }
    ]);

    expect(plan.find((entry) => entry.repo === "acme/cli-a")).toMatchObject({ role: "pilot", status: "eligible" });
    expect(plan.find((entry) => entry.repo === "acme/cli-b")).toMatchObject({ role: "batch", status: "eligible" });
    expect(plan.find((entry) => entry.repo === "acme/service-a")).toMatchObject({ role: "pilot", status: "blocked" });
    expect(plan.find((entry) => entry.repo === "acme/service-b")).toMatchObject({ role: "batch", status: "blocked" });
  });

  it("does not let an invalid pilot's claimed pass release the rest of its class", () => {
    const plan = planFleetPolicyUpgrades([
      { repo: "acme/a-pilot", repoClass: "service", currentPolicy: "bad", targetPolicy: "1.0.1", pilotOutcome: "passed" },
      { repo: "acme/b-next", repoClass: "service", currentPolicy: "1.0.0", targetPolicy: "1.0.1" }
    ]);
    expect(plan[0]).toMatchObject({ role: "pilot", risk: "invalid", status: "blocked" });
    expect(plan[1]).toMatchObject({ role: "batch", status: "blocked" });
  });

  it("does not apply a passing pilot to a different target release", () => {
    const plan = planFleetPolicyUpgrades([
      { repo: "acme/a-pilot", repoClass: "service", currentPolicy: "1.0.0", targetPolicy: "v1.0.1", pilotOutcome: "passed" },
      { repo: "acme/b-same", repoClass: "service", currentPolicy: "1.0.0", targetPolicy: "1.0.1" },
      { repo: "acme/c-other", repoClass: "service", currentPolicy: "1.0.0", targetPolicy: "1.0.2" }
    ]);
    expect(plan[1]).toMatchObject({ role: "batch", status: "eligible" });
    expect(plan[2]).toMatchObject({ role: "batch", status: "blocked" });
    expect(plan[2]?.reason).toContain("different target");
  });

  it("routes minor, major, and exception upgrades to human review", () => {
    const plan = planFleetPolicyUpgrades([
      { repo: "acme/minor", repoClass: "cli", currentPolicy: "1.0.0", targetPolicy: "1.1.0", pilotOutcome: "passed" },
      { repo: "acme/major", repoClass: "service", currentPolicy: "1.0.0", targetPolicy: "2.0.0", pilotOutcome: "passed" },
      { repo: "acme/excepted", repoClass: "library", currentPolicy: "1.0.0", targetPolicy: "1.0.1", exceptionId: "EX-1", pilotOutcome: "passed" }
    ]);

    expect(plan.map((entry) => entry.status)).toEqual(["review-required", "review-required", "review-required"]);
  });

  it.each([undefined, "pending"] as const)("blocks the class batch while its pilot outcome is %s", (pilotOutcome) => {
    const plan = planFleetPolicyUpgrades([
      { repo: "acme/service-patch", repoClass: "service", currentPolicy: "1.0.0", targetPolicy: "1.0.1", pilotOutcome: "passed" },
      { repo: "acme/service-a", repoClass: "service", currentPolicy: "1.0.0", targetPolicy: "1.0.1", ...(pilotOutcome === undefined ? {} : { pilotOutcome }) },
      { repo: "acme/service-minor", repoClass: "service", currentPolicy: "1.0.0", targetPolicy: "1.1.0" },
      { repo: "acme/service-major", repoClass: "service", currentPolicy: "1.0.0", targetPolicy: "2.0.0" },
      { repo: "acme/service-exception", repoClass: "service", currentPolicy: "1.0.0", targetPolicy: "1.0.1", exceptionId: "EX-1" },
      { repo: "acme/cli-a", repoClass: "cli", currentPolicy: "1.0.0", targetPolicy: "1.0.1", pilotOutcome: "passed" },
      { repo: "acme/cli-b", repoClass: "cli", currentPolicy: "1.0.0", targetPolicy: "1.0.1" }
    ]);

    expect(plan.find((entry) => entry.repo === "acme/service-a")).toMatchObject({ role: "pilot", status: "review-required" });
    const serviceBatch = plan.filter((entry) => entry.repoClass === "service" && entry.role === "batch");
    expect(serviceBatch).toHaveLength(4);
    for (const entry of serviceBatch) {
      expect(entry).toMatchObject({ status: "blocked", reason: "The service pilot has not passed; record a passing representative pilot before rolling this class forward." });
    }
    expect(plan.find((entry) => entry.repo === "acme/cli-b")).toMatchObject({ role: "batch", status: "eligible" });
  });
});
