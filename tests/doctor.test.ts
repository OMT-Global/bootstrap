import { describe, expect, it } from "vitest";

import { runDoctor } from "../src/doctor.js";
import { normalizeManifest } from "../src/manifest.js";
import type { CommandRunner } from "../src/lib/process.js";

const unavailableRunner: CommandRunner = async () => ({ stdout: "", stderr: "not installed", exitCode: 1 });

describe("runDoctor", () => {
  it("reports configured release policy locally without claiming live protection", async () => {
    const manifest = normalizeManifest({
      project: { name: "release-doctor", owner: "acme" },
      archetype: { kind: "generic-empty" },
      environments: {
        "release-publish": {
          reviewers: ["release-approver"], requireApproval: true,
          preventSelfReview: true, branches: ["main"]
        }
      }
    } as never);

    const checks = await runDoctor(manifest, { runner: unavailableRunner, homeDir: "/tmp/home" });

    expect(checks).toContainEqual(expect.objectContaining({
      name: "release-publish policy", status: "ok", detail: expect.stringContaining("unverified")
    }));
  });

  it("adds no release policy check when the optional environment is absent", async () => {
    const manifest = normalizeManifest({
      project: { name: "legacy-doctor", owner: "acme" },
      archetype: { kind: "generic-empty" }
    });
    const checks = await runDoctor(manifest, { runner: unavailableRunner, homeDir: "/tmp/home" });

    expect(checks.some((check) => check.name === "release-publish policy")).toBe(false);
  });

  const invalidPolicies: unknown[] = [
    null, false, [], {},
    { reviewers: ["release-approver"], requireApproval: false, preventSelfReview: true, branches: ["main"] },
    { reviewers: ["release-approver"], requireApproval: true, preventSelfReview: true, branches: ["other"] },
    { reviewers: ["release-approver"], requireApproval: true, preventSelfReview: true, branches: ["main"], customPolicy: true }
  ];

  it.each(invalidPolicies)("fails safely for a programmatic invalid release policy %#", async (policy) => {
    const manifest = normalizeManifest({
      project: { name: "invalid-release-doctor", owner: "acme" },
      archetype: { kind: "generic-empty" }
    });
    (manifest.environments as unknown as Record<string, unknown>)["release-publish"] = policy;

    const checks = await runDoctor(manifest, { runner: unavailableRunner, homeDir: "/tmp/home" });

    expect(checks).toContainEqual(expect.objectContaining({ name: "release-publish policy", status: "fail" }));
  });

  it("surfaces blocking exception validation with its stable rule ID", async () => {
    const manifest = normalizeManifest({
      project: { name: "doctor-exceptions", owner: "acme" },
      archetype: { kind: "generic-empty" },
      exceptions: [{ id: "temporary", policy: "release", scope: "repo", rationale: "migration", approvedBy: "alice", issue: "#55" }]
    } as never);

    const checks = await runDoctor(manifest, { runner: unavailableRunner, homeDir: "/tmp/home" });

    expect(checks).toContainEqual(
      expect.objectContaining({ name: "Policy exceptions", status: "fail", detail: expect.stringContaining("PRS-EXCEPTION-001") })
    );
  });
});
