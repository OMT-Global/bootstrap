import { describe, expect, it, vi } from "vitest";

import { GitHubClient } from "../src/github/client.js";
import { normalizeManifest, stringifyManifest } from "../src/manifest.js";
import {
  deliverExceptionNotifications,
  deliverMaterialAction,
  exceptionNotificationReportSchema,
  materialActionPlanSchema,
  planExceptionNotifications,
  planMaterialAction,
  type WebhookResolver,
  type WebhookSender
} from "../src/notifications.js";
import type { CommandRunner } from "../src/lib/process.js";

const githubPat = ["github", "pat"].join("_") + "_abcdefghijklmnopqrstuvwxyz123456";
const publicWebhookResolver: WebhookResolver = async () => [{ address: "8.8.8.8", family: 4 }];

function webhookEnvironment(url = "https://notifications.example.test/hooks/material"): NodeJS.ProcessEnv {
  const hostname = new URL(url).hostname.replace(/^\[|\]$/g, "").replace(/\.$/, "").toLowerCase();
  return {
    BOOTSTRAP_NOTIFICATION_WEBHOOK_URL: url,
    BOOTSTRAP_NOTIFICATION_WEBHOOK_ALLOWED_HOSTS: hostname
  };
}

function manifest(withNotifications = true) {
  return normalizeManifest({
    project: { name: "notifications", owner: "acme" },
    ...(withNotifications ? { notifications: { webhookUrlEnv: "BOOTSTRAP_NOTIFICATION_WEBHOOK_URL" } } : {}),
    archetype: { kind: "generic-empty" },
    github: { reviewers: ["maintainer"] }
  });
}

function action(overrides: Record<string, unknown> = {}) {
  return {
    id: "action-55",
    action: "repository-settings-change",
    summary: "Enable private vulnerability reporting.",
    governingTarget: "#55",
    ...overrides
  };
}

describe("material-action notifications", () => {
  it("plans both required destinations, redacts credentials, and preserves continue semantics", () => {
    const report = planMaterialAction(
      manifest(),
      action({ summary: `Rotate token=${githubPat} before changing repository settings.` })
    );

    expect(materialActionPlanSchema.parse(report)).toEqual(report);
    expect(report.notification).toMatchObject({ ruleId: "PRS-NOTIFY-001", status: "ready" });
    expect(report.hardStop).toMatchObject({ ruleId: "PRS-HARDSTOP-001", status: "not-applicable" });
    expect(report.continueAfterNotification).toBe(true);
    expect(report.redactions).toBeGreaterThan(0);
    expect(JSON.stringify(report)).not.toContain(githubPat);
    expect(report.notification.destinations.map((entry) => entry.destination)).toEqual([
      "governing-issue-or-pull-request",
      "configured-webhook"
    ]);
  });

  it("blocks defined hard stops without explicit approval evidence", () => {
    const report = planMaterialAction(manifest(), action({ action: "license-change" }));

    expect(report.notification.status).toBe("ready");
    expect(report.hardStop).toMatchObject({
      ruleId: "PRS-HARDSTOP-001",
      status: "blocking",
      category: "license-change"
    });
    expect(report.continueAfterNotification).toBe(false);
    expect(report.exitCode).toBe(1);
  });

  it("delivers to GitHub and the configured webhook before allowing work to continue", async () => {
    const approvalEvidence = "https://github.com/ACME/Notifications/issues/55#issuecomment-1";
    const actionInput = action({
      action: "license-change",
      summary: "Still (verification required); never copy stop pending verified human approval from summary text.",
      approval: { evidence: approvalEvidence }
    });
    const planned = planMaterialAction(manifest(), actionInput);
    const runner = vi.fn<CommandRunner>(async (_command, args) => ({
      stdout: args?.some((arg) => arg.toLowerCase() === "/repos/acme/notifications/issues/comments/1")
        ? JSON.stringify({
            body: `APPROVE PRS-HARDSTOP-001 action=action-55 category=license-change digest=${planned.approvalDigest}`,
            html_url: "https://github.com/acme/notifications/issues/55#issuecomment-1",
            issue_url: "https://api.github.com/repos/acme/notifications/issues/55",
            user: { login: "Maintainer" }
          })
        : args?.some((arg) => arg.toLowerCase() === "/repos/acme/notifications/collaborators/maintainer/permission")
          ? JSON.stringify({ permission: "write", role_name: "maintain" })
          : "{}",
      stderr: "",
      exitCode: 0
    }));
    const webhookSender = vi.fn<WebhookSender>(async () => ({ ok: true, status: 204 }));
    const report = await deliverMaterialAction(
      manifest(),
      actionInput,
      {
        githubClient: new GitHubClient({ runner }),
        environment: webhookEnvironment(),
        webhookSender,
        webhookResolver: publicWebhookResolver
      }
    );

    expect(planned.hardStop.status).toBe("verification-required");
    expect(planned.approvalDigest).toMatch(/^[0-9a-f]{64}$/);
    expect(planned.continueAfterNotification).toBe(false);
    expect(planned.exitCode).toBe(1);
    expect(report.notification.status).toBe("delivered");
    expect(report.hardStop.status).toBe("approved");
    expect(report.continueAfterNotification).toBe(true);
    expect(report.exitCode).toBe(0);
    expect(report.commentBody).toContain("- Approval evidence: ");
    expect(report.commentBody).toContain("(verified)");
    expect(report.commentBody).toContain("- Decision: continue after required notifications are delivered");
    expect(runner).toHaveBeenCalledWith(
      "gh",
      expect.arrayContaining(["/repos/acme/notifications/issues/55/comments"]),
      expect.objectContaining({ input: expect.stringContaining("PRS-NOTIFY-001") })
    );
    expect(webhookSender).toHaveBeenCalledWith(
      "https://notifications.example.test/hooks/material",
      expect.objectContaining({ ruleId: "PRS-NOTIFY-001", actionId: "action-55", hardStopCategory: "license-change" })
    );
  });

  it("rejects hard-stop approval from a configured reviewer without maintain permission", async () => {
    const approvalEvidence = "https://github.com/acme/notifications/issues/55#issuecomment-2";
    const actionInput = action({ action: "license-change", approval: { evidence: approvalEvidence } });
    const planned = planMaterialAction(manifest(), actionInput);
    const runner: CommandRunner = async (_command, args) => ({
      stdout: args?.includes("/repos/acme/notifications/issues/comments/2")
        ? JSON.stringify({
            body: `APPROVE PRS-HARDSTOP-001 action=action-55 category=license-change digest=${planned.approvalDigest}`,
            html_url: approvalEvidence,
            issue_url: "https://api.github.com/repos/acme/notifications/issues/55",
            user: { login: "maintainer" }
          })
        : args?.includes("/repos/acme/notifications/collaborators/maintainer/permission")
          ? JSON.stringify({ permission: "write", role_name: "write" })
          : "{}",
      stderr: "",
      exitCode: 0
    });
    const report = await deliverMaterialAction(
      manifest(),
      actionInput,
      {
        githubClient: new GitHubClient({ runner }),
        environment: webhookEnvironment(),
        webhookSender: async () => ({ ok: true, status: 204 }),
        webhookResolver: publicWebhookResolver
      }
    );

    expect(report.notification.status).toBe("delivered");
    expect(report.hardStop).toMatchObject({ status: "blocking", category: "license-change" });
    expect(report.continueAfterNotification).toBe(false);
    expect(report.exitCode).toBe(1);
  });

  it("rejects replaying approval after immutable action contents change", async () => {
    const approvalEvidence = "https://github.com/acme/notifications/issues/55#issuecomment-3";
    const approvedInput = action({
      action: "license-change",
      summary: "Apply the reviewed MIT license change.",
      approval: { evidence: approvalEvidence }
    });
    const approvedPlan = planMaterialAction(manifest(), approvedInput);
    const changedInput = action({
      action: "license-change",
      summary: "Apply a different proprietary license change.",
      approval: { evidence: approvalEvidence }
    });
    const runner: CommandRunner = async (_command, args) => ({
      stdout: args?.includes("/repos/acme/notifications/issues/comments/3")
        ? JSON.stringify({
            body: `APPROVE PRS-HARDSTOP-001 action=action-55 category=license-change digest=${approvedPlan.approvalDigest}`,
            html_url: approvalEvidence,
            issue_url: "https://api.github.com/repos/acme/notifications/issues/55",
            author_association: "MEMBER",
            user: { login: "maintainer" }
          })
        : "{}",
      stderr: "",
      exitCode: 0
    });

    const report = await deliverMaterialAction(manifest(), changedInput, {
      githubClient: new GitHubClient({ runner }),
      environment: webhookEnvironment(),
      webhookSender: async () => ({ ok: true, status: 204 }),
      webhookResolver: publicWebhookResolver
    });

    expect(planMaterialAction(manifest(), changedInput).approvalDigest).not.toBe(approvedPlan.approvalDigest);
    expect(report.hardStop.status).toBe("blocking");
    expect(report.continueAfterNotification).toBe(false);
    expect(report.exitCode).toBe(1);
  });

  it("rejects credential-like action IDs before building public payloads", () => {
    expect(() => planMaterialAction(manifest(), action({ id: githubPat }))).toThrow("credential-like literals");
    expect(() => planMaterialAction(manifest(), action({ governingTarget: githubPat }))).toThrow("credential-like literals");
  });

  it("rejects summaries that could mint a standalone approval marker", () => {
    const approvalEvidence = "https://github.com/acme/notifications/issues/55#issuecomment-4";
    const hardStop = planMaterialAction(
      manifest(),
      action({ action: "license-change", approval: { evidence: approvalEvidence } })
    );
    const injectedMarker = `APPROVE PRS-HARDSTOP-001 action=action-55 category=license-change digest=${hardStop.approvalDigest}`;

    expect(() =>
      planMaterialAction(
        manifest(),
        action({ id: "ordinary-action", summary: `Ordinary notification.\n${injectedMarker}` })
      )
    ).toThrow("single line");
  });

  it("escapes Markdown and HTML that could hide governing-record audit fields", () => {
    const report = planMaterialAction(
      manifest(),
      action({ summary: "Routine [change](https://example.test) <!-- hide decision" })
    );

    expect(report.commentBody).not.toContain("<!--");
    expect(report.commentBody).not.toContain("[change](https://example.test)");
    expect(report.commentBody).toContain("&lt;");
    expect(report.commentBody).toContain("- Decision: continue after required notifications are delivered");
  });

  it("does not send invalid governing targets to the configured webhook", async () => {
    const webhookSender = vi.fn<WebhookSender>(async () => ({ ok: true, status: 204 }));
    const report = await deliverMaterialAction(manifest(), action({ governingTarget: "not-a-github-target" }), {
      githubClient: new GitHubClient({ runner: async () => ({ stdout: "{}", stderr: "", exitCode: 0 }) }),
      environment: webhookEnvironment(),
      webhookSender
    });

    expect(report.governingTarget).toBe("[INVALID:GOVERNING-TARGET]");
    expect(report.notification.status).toBe("blocking");
    expect(report.notification.destinations).toContainEqual(
      expect.objectContaining({ destination: "configured-webhook", status: "failed", detail: expect.stringContaining("skipped") })
    );
    expect(webhookSender).not.toHaveBeenCalled();
    expect(JSON.stringify(report)).not.toContain("not-a-github-target");
    for (const governingTarget of ["acme/repo?x#55", "#9007199254740993"]) {
      const planned = planMaterialAction(manifest(), action({ governingTarget }));
      expect(planned.governingTarget).toBe("[INVALID:GOVERNING-TARGET]");
      expect(planned.notification.status).toBe("blocking");
      expect(planned.continueAfterNotification).toBe(false);
      expect(planned.exitCode).toBe(1);
    }
  });

  it("rejects allowlisted literal loopback, link-local, and private webhook addresses", async () => {
    const runner: CommandRunner = async () => ({ stdout: "{}", stderr: "", exitCode: 0 });
    for (const url of [
      "https://127.0.0.1/hooks/material",
      "https://169.254.169.254/hooks/material",
      "https://10.0.0.7/hooks/material",
      "https://[::1]/hooks/material",
      "https://[::ffff:127.0.0.1]/hooks/material",
      "https://[fe80::1]/hooks/material"
    ]) {
      const webhookSender = vi.fn<WebhookSender>(async () => ({ ok: true, status: 204 }));
      const report = await deliverMaterialAction(manifest(), action(), {
        githubClient: new GitHubClient({ runner }),
        environment: webhookEnvironment(url),
        webhookSender
      });

      expect(report.notification).toMatchObject({ status: "blocking" });
      expect(report.notification.destinations).toContainEqual(
        expect.objectContaining({ destination: "configured-webhook", status: "failed" })
      );
      expect(webhookSender).not.toHaveBeenCalled();
      expect(JSON.stringify(report)).not.toContain(new URL(url).hostname);
    }
  });

  it("rejects an allowlisted hostname when any DNS answer is private", async () => {
    const runner: CommandRunner = async () => ({ stdout: "{}", stderr: "", exitCode: 0 });
    const webhookSender = vi.fn<WebhookSender>(async () => ({ ok: true, status: 204 }));
    const webhookResolver = vi.fn<WebhookResolver>(async () => [
      { address: "8.8.8.8", family: 4 },
      { address: "10.0.0.7", family: 4 }
    ]);
    const report = await deliverMaterialAction(manifest(), action(), {
      githubClient: new GitHubClient({ runner }),
      environment: webhookEnvironment("https://internal.example.test/hooks/material"),
      webhookSender,
      webhookResolver
    });

    expect(webhookResolver).toHaveBeenCalledWith("internal.example.test");
    expect(report.notification).toMatchObject({ status: "blocking" });
    expect(webhookSender).not.toHaveBeenCalled();
    expect(JSON.stringify(report)).not.toContain("internal.example.test");
    expect(JSON.stringify(report)).not.toContain("10.0.0.7");
  });

  it("rejects allowlisted hostnames that resolve to reserved IPv6 documentation ranges", async () => {
    const runner: CommandRunner = async () => ({ stdout: "{}", stderr: "", exitCode: 0 });
    for (const address of ["2001:db8::1", "3fff::1"]) {
      const webhookSender = vi.fn<WebhookSender>(async () => ({ ok: true, status: 204 }));
      const report = await deliverMaterialAction(manifest(), action(), {
        githubClient: new GitHubClient({ runner }),
        environment: webhookEnvironment("https://reserved.example.test/hooks/material"),
        webhookSender,
        webhookResolver: async () => [{ address, family: 6 }]
      });

      expect(report.notification).toMatchObject({ status: "blocking" });
      expect(webhookSender).not.toHaveBeenCalled();
      expect(JSON.stringify(report)).not.toContain(address);
    }
  });

  it("rejects a public webhook hostname that is absent from the executor allowlist", async () => {
    const runner: CommandRunner = async () => ({ stdout: "{}", stderr: "", exitCode: 0 });
    const webhookSender = vi.fn<WebhookSender>(async () => ({ ok: true, status: 204 }));
    const webhookResolver = vi.fn(publicWebhookResolver);
    const report = await deliverMaterialAction(manifest(), action(), {
      githubClient: new GitHubClient({ runner }),
      environment: {
        BOOTSTRAP_NOTIFICATION_WEBHOOK_URL: "https://notifications.example.test/hooks/material",
        BOOTSTRAP_NOTIFICATION_WEBHOOK_ALLOWED_HOSTS: "approved.example.test"
      },
      webhookSender,
      webhookResolver
    });

    expect(report.notification).toMatchObject({ status: "blocking" });
    expect(webhookResolver).not.toHaveBeenCalled();
    expect(webhookSender).not.toHaveBeenCalled();
  });

  it("fails closed when allowlisted-host DNS resolution exceeds the delivery deadline", async () => {
    vi.useFakeTimers();
    const runner: CommandRunner = async () => ({ stdout: "{}", stderr: "", exitCode: 0 });
    const webhookSender = vi.fn<WebhookSender>(async () => ({ ok: true, status: 204 }));
    const delivery = deliverMaterialAction(manifest(), action(), {
      githubClient: new GitHubClient({ runner }),
      environment: webhookEnvironment(),
      webhookSender,
      webhookResolver: async () => new Promise<never>(() => undefined)
    });

    try {
      await vi.advanceTimersByTimeAsync(10_000);
      const report = await delivery;
      expect(report.notification).toMatchObject({ status: "blocking" });
      expect(webhookSender).not.toHaveBeenCalled();
    } finally {
      vi.useRealTimers();
    }
  });

  it("fails closed when the configured mechanism is absent or rejects delivery", async () => {
    const runner: CommandRunner = async () => ({ stdout: "{}", stderr: "", exitCode: 0 });
    const webhookSender: WebhookSender = async () => ({ ok: false, status: 503 });
    const missingConfiguration = planMaterialAction(manifest(false), action());
    const rejected = await deliverMaterialAction(manifest(), action(), {
      githubClient: new GitHubClient({ runner }),
      environment: webhookEnvironment(),
      webhookSender,
      webhookResolver: publicWebhookResolver
    });

    expect(missingConfiguration.notification.status).toBe("blocking");
    expect(missingConfiguration.continueAfterNotification).toBe(false);
    expect(missingConfiguration.exitCode).toBe(1);
    expect(rejected.notification).toMatchObject({ status: "blocking", ruleId: "PRS-NOTIFY-001" });
    expect(rejected.continueAfterNotification).toBe(false);
    expect(rejected.exitCode).toBe(1);
    expect(JSON.stringify(rejected)).not.toContain("notifications.example.test");
  });

  it("serializes only the webhook environment-variable reference", () => {
    const serialized = stringifyManifest(manifest());

    expect(serialized).toContain("webhookUrlEnv: BOOTSTRAP_NOTIFICATION_WEBHOOK_URL");
    expect(serialized).not.toContain("https://");
  });

  it("plans and delivers expiring-exception intents from the resolved manifest", async () => {
    const expiringManifest = normalizeManifest({
      project: { name: "notifications", owner: "acme" },
      notifications: { webhookUrlEnv: "BOOTSTRAP_NOTIFICATION_WEBHOOK_URL" },
      archetype: { kind: "generic-empty" },
      exceptions: [
        {
          id: "runner-migration",
          policy: "runner-policy",
          scope: ".github/workflows/release.yml",
          rationale: "Migration in progress.",
          approvedBy: "maintainer",
          issue: "#55",
          expiresAt: "2026-07-20"
        }
      ]
    });
    const now = new Date("2026-07-16T12:00:00.000Z");
    const runner = vi.fn<CommandRunner>(async () => ({ stdout: "{}", stderr: "", exitCode: 0 }));
    const webhookSender = vi.fn<WebhookSender>(async () => ({ ok: true, status: 204 }));
    const planned = planExceptionNotifications(expiringManifest, now);
    const delivered = await deliverExceptionNotifications(expiringManifest, {
      now,
      githubClient: new GitHubClient({ runner }),
      environment: webhookEnvironment(),
      webhookSender,
      webhookResolver: publicWebhookResolver
    });

    expect(exceptionNotificationReportSchema.parse(planned)).toEqual(planned);
    expect(planned).toMatchObject({ mode: "plan", blockingExceptions: false, exitCode: 0 });
    expect(planned.notifications).toHaveLength(1);
    expect(planned.notifications[0]).toMatchObject({
      action: "policy-exception",
      governingTarget: "acme/notifications#55",
      notification: { status: "ready" }
    });
    expect(delivered).toMatchObject({ mode: "deliver", blockingExceptions: false, exitCode: 0 });
    expect(delivered.notifications[0]?.notification.status).toBe("delivered");
  });

  it("keeps blocking exception validation fail-closed when no expiry notification is due", () => {
    const blockedManifest = normalizeManifest({
      project: { name: "notifications", owner: "acme" },
      notifications: { webhookUrlEnv: "BOOTSTRAP_NOTIFICATION_WEBHOOK_URL" },
      archetype: { kind: "generic-empty" },
      exceptions: [
        {
          id: "expired",
          policy: "runner-policy",
          scope: ".github/workflows/release.yml",
          rationale: "Migration stalled.",
          approvedBy: "maintainer",
          issue: "#55",
          expiresAt: "2026-07-15"
        }
      ]
    });

    const report = planExceptionNotifications(blockedManifest, new Date("2026-07-16T12:00:00.000Z"));

    expect(report.notifications).toEqual([]);
    expect(report.blockingExceptions).toBe(true);
    expect(report.exitCode).toBe(1);
  });

  it("normalizes unconstrained exception IDs into stable redacted notification reports", () => {
    const unsafeId = `${githubPat}\n${"x".repeat(2_100)}`;
    const expiringManifest = normalizeManifest({
      project: { name: "notifications", owner: "acme" },
      notifications: { webhookUrlEnv: "BOOTSTRAP_NOTIFICATION_WEBHOOK_URL" },
      archetype: { kind: "generic-empty" },
      exceptions: [
        {
          id: unsafeId,
          policy: "runner-policy",
          scope: "repo",
          rationale: "Migration in progress.",
          approvedBy: "maintainer",
          issue: "#55",
          expiresAt: "2026-07-20"
        }
      ]
    });

    const report = planExceptionNotifications(expiringManifest, new Date("2026-07-16T12:00:00.000Z"));

    expect(report.notifications).toHaveLength(1);
    expect(report.notifications[0]?.actionId).toMatch(/^exception-[0-9a-f]{12}-expiring$/);
    expect(report.notifications[0]?.actionId.length).toBeLessThan(100);
    expect(JSON.stringify(report)).not.toContain(githubPat);
    expect(report.notifications[0]?.webhookPayload.summary).not.toContain("\n");
    expect(report.exitCode).toBe(0);
  });
});
