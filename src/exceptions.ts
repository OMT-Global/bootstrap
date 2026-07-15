import type { PolicyException } from "./types.js";

export type ExceptionResultStatus = "pass" | "warn" | "block";

export interface ExceptionValidationResult {
  ruleId: "PRS-EXCEPTION-001";
  exceptionId: string;
  status: ExceptionResultStatus;
  detail: string;
  remediation?: string;
}

export interface ExceptionNotificationIntent {
  ruleId: "PRS-NOTIFY-001";
  exceptionId: string;
  event: "exception-expiring";
  destinations: ["governing-issue-or-pull-request", "configured-notification-mechanism"];
  continueAfterNotification: true;
}

export interface ExceptionValidationReport {
  results: ExceptionValidationResult[];
  notifications: ExceptionNotificationIntent[];
  blocking: boolean;
}

const EXPIRY_WARNING_DAYS = 14;

function utcMidnight(value: Date): number {
  return Date.UTC(value.getUTCFullYear(), value.getUTCMonth(), value.getUTCDate());
}

function parseDate(value: string): Date | undefined {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) return undefined;
  const parsed = new Date(`${value}T00:00:00.000Z`);
  return Number.isNaN(parsed.valueOf()) ? undefined : parsed;
}

export function validatePolicyExceptions(
  exceptions: PolicyException[],
  now = new Date()
): ExceptionValidationReport {
  const results: ExceptionValidationResult[] = [];
  const notifications: ExceptionNotificationIntent[] = [];

  for (const exception of [...exceptions].sort((left, right) => left.id.localeCompare(right.id))) {
    if (exception.permanent) {
      if (!exception.adr) {
        results.push({
          ruleId: "PRS-EXCEPTION-001",
          exceptionId: exception.id,
          status: "block",
          detail: `Permanent exception ${exception.id} has no ADR.`,
          remediation: "Add the accepted ADR that documents the permanent exception."
        });
      } else {
        results.push({
          ruleId: "PRS-EXCEPTION-001",
          exceptionId: exception.id,
          status: "pass",
          detail: `Permanent exception ${exception.id} has explicit approval and ADR ${exception.adr}.`
        });
      }
      continue;
    }

    if (!exception.expiresAt) {
      results.push({
        ruleId: "PRS-EXCEPTION-001",
        exceptionId: exception.id,
        status: "block",
        detail: `Temporary exception ${exception.id} has no expiry date.`,
        remediation: "Set exceptions[].expiresAt to an ISO date or mark the exception permanent with an ADR."
      });
      continue;
    }

    const expiry = parseDate(exception.expiresAt);
    if (!expiry) {
      results.push({
        ruleId: "PRS-EXCEPTION-001",
        exceptionId: exception.id,
        status: "block",
        detail: `Exception ${exception.id} has an invalid expiry date ${exception.expiresAt}.`,
        remediation: "Use an ISO date in YYYY-MM-DD format."
      });
      continue;
    }

    const remainingDays = Math.floor((utcMidnight(expiry) - utcMidnight(now)) / 86_400_000);
    if (remainingDays < 0) {
      results.push({
        ruleId: "PRS-EXCEPTION-001",
        exceptionId: exception.id,
        status: "block",
        detail: `Temporary exception ${exception.id} expired on ${exception.expiresAt}.`,
        remediation: "Renew the exception with approval or remove the deviation."
      });
      continue;
    }

    if (remainingDays <= EXPIRY_WARNING_DAYS) {
      results.push({
        ruleId: "PRS-EXCEPTION-001",
        exceptionId: exception.id,
        status: "warn",
        detail: `Temporary exception ${exception.id} expires in ${remainingDays} day(s) on ${exception.expiresAt}.`,
        remediation: "Renew with approval before the exception expires or remove the deviation."
      });
      notifications.push({
        ruleId: "PRS-NOTIFY-001",
        exceptionId: exception.id,
        event: "exception-expiring",
        destinations: ["governing-issue-or-pull-request", "configured-notification-mechanism"],
        continueAfterNotification: true
      });
      continue;
    }

    results.push({
      ruleId: "PRS-EXCEPTION-001",
      exceptionId: exception.id,
      status: "pass",
      detail: `Temporary exception ${exception.id} is valid through ${exception.expiresAt}.`
    });
  }

  return { results, notifications, blocking: results.some((result) => result.status === "block") };
}
