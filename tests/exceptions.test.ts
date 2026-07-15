import { describe, expect, it } from "vitest";

import { normalizeManifest } from "../src/manifest.js";
import { validatePolicyExceptions } from "../src/exceptions.js";

const now = new Date("2026-07-13T12:00:00.000Z");

describe("validatePolicyExceptions", () => {
  it("blocks expired or incomplete temporary exceptions with stable rule IDs", () => {
    const report = validatePolicyExceptions(
      [
        { id: "missing-expiry", policy: "release", scope: "repo", rationale: "migration", approvedBy: "alice", issue: "#55", permanent: false },
        { id: "expired", policy: "security", scope: "workflow", rationale: "migration", approvedBy: "alice", issue: "#55", permanent: false, expiresAt: "2026-07-12" }
      ],
      now
    );

    expect(report.blocking).toBe(true);
    expect(report.results).toMatchObject([
      { ruleId: "PRS-EXCEPTION-001", exceptionId: "expired", status: "block" },
      { ruleId: "PRS-EXCEPTION-001", exceptionId: "missing-expiry", status: "block" }
    ]);
  });

  it("requires an ADR for permanent exceptions and emits expiring notification intents without blocking", () => {
    const report = validatePolicyExceptions(
      [
        { id: "permanent", policy: "release", scope: "repo", rationale: "required", approvedBy: "alice", issue: "#55", permanent: true },
        { id: "expiring", policy: "ci", scope: "workflow", rationale: "migration", approvedBy: "alice", issue: "#55", permanent: false, expiresAt: "2026-07-20" }
      ],
      now
    );

    expect(report.blocking).toBe(true);
    expect(report.notifications).toEqual([
      {
        ruleId: "PRS-NOTIFY-001",
        exceptionId: "expiring",
        event: "exception-expiring",
        destinations: ["governing-issue-or-pull-request", "configured-notification-mechanism"],
        continueAfterNotification: true
      }
    ]);
  });

  it("normalizes declared exceptions for deterministic validation", () => {
    const manifest = normalizeManifest({
      project: { name: "exceptions", owner: "acme" },
      archetype: { kind: "generic-empty" },
      exceptions: [{ id: "approved", policy: "security", scope: "repo", rationale: "temporary migration", approvedBy: "alice", issue: "#55", expiresAt: "2026-08-01" }]
    } as never);

    expect(manifest.exceptions).toEqual([
      { id: "approved", policy: "security", scope: "repo", rationale: "temporary migration", approvedBy: "alice", issue: "#55", permanent: false, expiresAt: "2026-08-01" }
    ]);
    expect(validatePolicyExceptions(manifest.exceptions, now).blocking).toBe(false);
  });
});
