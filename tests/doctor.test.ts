import { describe, expect, it } from "vitest";

import { runDoctor } from "../src/doctor.js";
import { normalizeManifest } from "../src/manifest.js";
import type { CommandRunner } from "../src/lib/process.js";

const unavailableRunner: CommandRunner = async () => ({ stdout: "", stderr: "not installed", exitCode: 1 });

describe("runDoctor", () => {
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
