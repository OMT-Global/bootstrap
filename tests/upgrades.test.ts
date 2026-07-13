import { describe, expect, it } from "vitest";

import { classifyPolicyUpgrade, planFleetPolicyUpgrades } from "../src/upgrades.js";

describe("fleet policy upgrades", () => {
  it("classifies patch, minor, major, and invalid policy versions", () => {
    expect(classifyPolicyUpgrade("1.2.3", "1.2.4")).toBe("patch");
    expect(classifyPolicyUpgrade("1.2.3", "1.3.0")).toBe("minor");
    expect(classifyPolicyUpgrade("1.2.3", "2.0.0")).toBe("major");
    expect(classifyPolicyUpgrade("1.2.3", "1.2.2")).toBe("invalid");
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
    expect(plan.find((entry) => entry.repo === "acme/service-a")).toMatchObject({ role: "pilot", status: "review-required" });
    expect(plan.find((entry) => entry.repo === "acme/service-b")).toMatchObject({ role: "batch", status: "blocked" });
  });

  it("routes minor, major, and exception upgrades to human review", () => {
    const plan = planFleetPolicyUpgrades([
      { repo: "acme/minor", repoClass: "cli", currentPolicy: "1.0.0", targetPolicy: "1.1.0", pilotOutcome: "passed" },
      { repo: "acme/major", repoClass: "service", currentPolicy: "1.0.0", targetPolicy: "2.0.0", pilotOutcome: "passed" },
      { repo: "acme/excepted", repoClass: "library", currentPolicy: "1.0.0", targetPolicy: "1.0.1", exceptionId: "EX-1", pilotOutcome: "passed" }
    ]);

    expect(plan.map((entry) => entry.status)).toEqual(["review-required", "review-required", "review-required"]);
  });
});
