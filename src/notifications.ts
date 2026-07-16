import { createHash } from "node:crypto";
import { lookup } from "node:dns/promises";
import { request as httpsRequest } from "node:https";
import { BlockList, isIP, type LookupFunction } from "node:net";

import { z } from "zod";

import { GitHubClient } from "./github/client.js";
import { validatePolicyExceptions } from "./exceptions.js";
import { containsCredential, redactPublicText } from "./provenance.js";
import type { BootstrapManifest } from "./types.js";

export const MATERIAL_ACTIONS = [
  "adr-change",
  "public-api-change",
  "breaking-compatibility-change",
  "database-migration",
  "runtime-dependency-addition",
  "authentication-authorization-change",
  "security-finding-or-waiver",
  "production-deployment",
  "release-publication",
  "repository-visibility-change",
  "repository-settings-change",
  "material-recurring-cost",
  "policy-exception",
  "major-feature-removal",
  "provenance-capture-failure",
  "conformance-bypass"
] as const;

export const HUMAN_HARD_STOP_CATEGORIES = [
  "license-change",
  "public-ownership-change",
  "repository-ownership-transfer",
  "expose-previously-private-data",
  "irreversible-production-data-destruction",
  "external-legal-contractual-obligation",
  "spend-above-configured-threshold",
  "grant-organization-owner-permission",
  "grant-billing-permission",
  "permanent-policy-exception"
] as const;

export const ACTION_CATEGORIES = [...MATERIAL_ACTIONS, ...HUMAN_HARD_STOP_CATEGORIES] as const;
const hardStopCategorySet = new Set<string>(HUMAN_HARD_STOP_CATEGORIES);

export const materialActionSchema = z
  .object({
    id: z.string().regex(/^[A-Za-z0-9._-]+$/),
    action: z.enum(ACTION_CATEGORIES),
    summary: z
      .string()
      .min(1)
      .max(2_000)
      .refine((value) => !/[\r\n\u2028\u2029]/.test(value), "Material-action summaries must be a single line."),
    governingTarget: z.string().min(1),
    approval: z
      .object({
        evidence: z.string().url()
      })
      .optional()
  })
  .superRefine((action, context) => {
    if (containsCredential(action.id)) {
      context.addIssue({ code: "custom", path: ["id"], message: "Action IDs must not contain credential-like literals." });
    }
    if (action.approval && !hardStopCategorySet.has(action.action)) {
      context.addIssue({ code: "custom", path: ["approval"], message: "Approval evidence is valid only for a defined human hard-stop category." });
    }
    if (containsCredential(action.governingTarget)) {
      context.addIssue({ code: "custom", path: ["governingTarget"], message: "Governing targets must not contain credential-like literals." });
    }
  });

export type MaterialAction = z.infer<typeof materialActionSchema>;

const hardStopResultSchema = z.object({
  ruleId: z.literal("PRS-HARDSTOP-001"),
  status: z.enum(["not-applicable", "verification-required", "approved", "blocking"]),
  category: z.enum(HUMAN_HARD_STOP_CATEGORIES).optional(),
  detail: z.string()
});

const notificationResultSchema = z.object({
  ruleId: z.literal("PRS-NOTIFY-001"),
  status: z.enum(["ready", "delivered", "blocking"]),
  destinations: z.array(
    z.object({
      destination: z.enum(["governing-issue-or-pull-request", "configured-webhook"]),
      status: z.enum(["planned", "delivered", "failed"]),
      detail: z.string()
    })
  ),
  detail: z.string()
});

const webhookPayloadSchema = z.object({
  schemaVersion: z.literal(1),
  ruleId: z.literal("PRS-NOTIFY-001"),
  actionId: z.string(),
  action: z.enum(ACTION_CATEGORIES),
  summary: z.string(),
  governingTarget: z.string(),
  hardStopCategory: z.enum(HUMAN_HARD_STOP_CATEGORIES).optional(),
  approvalDigest: z.string().regex(/^[0-9a-f]{64}$/).optional(),
  approvalEvidence: z.string().optional()
});

export const materialActionPlanSchema = z.object({
  schemaVersion: z.literal(1),
  actionId: z.string(),
  action: z.enum(ACTION_CATEGORIES),
  governingTarget: z.string(),
  approvalDigest: z.string().regex(/^[0-9a-f]{64}$/).optional(),
  notification: notificationResultSchema,
  hardStop: hardStopResultSchema,
  continueAfterNotification: z.boolean(),
  redactions: z.number().int().nonnegative(),
  commentBody: z.string(),
  webhookPayload: webhookPayloadSchema,
  exitCode: z.union([z.literal(0), z.literal(1)])
});

export type MaterialActionPlan = z.infer<typeof materialActionPlanSchema>;
export type MaterialActionDeliveryReport = MaterialActionPlan;

export const exceptionNotificationReportSchema = z.object({
  schemaVersion: z.literal(1),
  mode: z.enum(["plan", "deliver"]),
  notifications: z.array(materialActionPlanSchema),
  blockingExceptions: z.boolean(),
  exitCode: z.union([z.literal(0), z.literal(1)])
});

export type ExceptionNotificationReport = z.infer<typeof exceptionNotificationReportSchema>;

interface GitHubTarget {
  owner: string;
  repo: string;
  number: number;
}

interface GitHubIssueComment {
  body?: string;
  html_url?: string;
  issue_url?: string;
  author_association?: string;
  user?: { login?: string };
}

interface GitHubCollaboratorPermission {
  permission?: string;
  role_name?: string;
}

const maintainerRoles = new Set(["admin", "maintain"]);

export interface WebhookResult {
  ok: boolean;
  status: number;
}

export type WebhookSender = (url: string, payload: MaterialActionPlan["webhookPayload"]) => Promise<WebhookResult>;
export interface ResolvedWebhookAddress {
  address: string;
  family: 4 | 6;
}
export type WebhookResolver = (hostname: string) => Promise<ResolvedWebhookAddress[]>;

export interface DeliveryOptions {
  githubClient?: GitHubClient;
  environment?: NodeJS.ProcessEnv;
  webhookSender?: WebhookSender;
  webhookResolver?: WebhookResolver;
}

export interface ExceptionDeliveryOptions extends DeliveryOptions {
  now?: Date;
}

function parseGitHubTarget(value: string, manifest: BootstrapManifest): GitHubTarget | undefined {
  const local = /^#([1-9][0-9]*)$/.exec(value);
  if (local) {
    const number = safePositiveInteger(local[1]!);
    return number && validGitHubOwner(manifest.project.owner) && validGitHubRepo(manifest.project.name)
      ? { owner: manifest.project.owner, repo: manifest.project.name, number }
      : undefined;
  }

  const shorthand = /^([^/\s]+)\/([^/#\s]+)#([1-9][0-9]*)$/.exec(value);
  if (shorthand) {
    const number = safePositiveInteger(shorthand[3]!);
    return number && validGitHubOwner(shorthand[1]!) && validGitHubRepo(shorthand[2]!)
      ? { owner: shorthand[1]!, repo: shorthand[2]!, number }
      : undefined;
  }

  const url = /^https:\/\/github\.com\/([^/\s]+)\/([^/\s]+)\/(?:issues|pull)\/([1-9][0-9]*)\/?$/.exec(value);
  if (url) {
    const number = safePositiveInteger(url[3]!);
    return number && validGitHubOwner(url[1]!) && validGitHubRepo(url[2]!)
      ? { owner: url[1]!, repo: url[2]!, number }
      : undefined;
  }

  return undefined;
}

function validGitHubOwner(value: string): boolean {
  return /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/.test(value);
}

function validGitHubRepo(value: string): boolean {
  return /^[A-Za-z0-9_.-]{1,100}$/.test(value) && value !== "." && value !== "..";
}

function safePositiveInteger(value: string): number | undefined {
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : undefined;
}

function parseApprovalEvidence(value: string): (GitHubTarget & { commentId: number }) | undefined {
  const match = /^https:\/\/github\.com\/([^/\s]+)\/([^/\s]+)\/(?:issues|pull)\/([1-9][0-9]*)#issuecomment-([1-9][0-9]*)$/.exec(value);
  if (!match) return undefined;
  const number = safePositiveInteger(match[3]!);
  const commentId = safePositiveInteger(match[4]!);
  return number && commentId && validGitHubOwner(match[1]!) && validGitHubRepo(match[2]!)
    ? { owner: match[1]!, repo: match[2]!, number, commentId }
    : undefined;
}

function parseApiIssueUrl(value: string): GitHubTarget | undefined {
  const match = /^https:\/\/api\.github\.com\/repos\/([^/\s]+)\/([^/\s]+)\/issues\/([1-9][0-9]*)\/?$/i.exec(value);
  if (!match) return undefined;
  const number = safePositiveInteger(match[3]!);
  return number && validGitHubOwner(match[1]!) && validGitHubRepo(match[2]!)
    ? { owner: match[1]!, repo: match[2]!, number }
    : undefined;
}

function sameGitHubTarget(left: GitHubTarget, right: GitHubTarget): boolean {
  return (
    left.owner.toLowerCase() === right.owner.toLowerCase() &&
    left.repo.toLowerCase() === right.repo.toLowerCase() &&
    left.number === right.number
  );
}

function approvalDigest(action: MaterialAction): string {
  const canonical = JSON.stringify({
    schemaVersion: 1,
    id: action.id,
    action: action.action,
    summary: action.summary,
    governingTarget: action.governingTarget
  });
  return createHash("sha256").update(canonical, "utf8").digest("hex");
}

async function verifiedHardStopResult(
  action: MaterialAction,
  manifest: BootstrapManifest,
  governingTarget: GitHubTarget | undefined,
  githubClient: GitHubClient
): Promise<z.infer<typeof hardStopResultSchema>> {
  const category = hardStopCategory(action);
  if (!category || !action.approval || !governingTarget) return hardStopResult(action);
  const evidence = parseApprovalEvidence(action.approval.evidence);
  if (!evidence || !sameGitHubTarget(evidence, governingTarget)) {
    return {
      ruleId: "PRS-HARDSTOP-001",
      status: "blocking",
      category,
      detail: `Approval evidence was not verified for ${category}.`
    };
  }

  try {
    const comment = await githubClient.api<GitHubIssueComment>(
      "GET",
      `/repos/${evidence.owner}/${evidence.repo}/issues/comments/${evidence.commentId}`
    );
    const author = comment.user?.login;
    const returnedEvidence = comment.html_url ? parseApprovalEvidence(comment.html_url) : undefined;
    const returnedIssue = comment.issue_url ? parseApiIssueUrl(comment.issue_url) : undefined;
    const digest = approvalDigest(action);
    const expectedMarker = `APPROVE PRS-HARDSTOP-001 action=${action.id} category=${category} digest=${digest}`;
    const markerPresent = comment.body?.split(/\r?\n/).some((line) => line.trim() === expectedMarker) ?? false;
    const commentVerified =
      returnedEvidence !== undefined &&
      returnedEvidence.commentId === evidence.commentId &&
      sameGitHubTarget(returnedEvidence, evidence) &&
      returnedIssue !== undefined &&
      sameGitHubTarget(returnedIssue, evidence) &&
      author !== undefined &&
      manifest.github.reviewers.some((reviewer) => reviewer.toLowerCase() === author.toLowerCase()) &&
      markerPresent;
    const permission = commentVerified
      ? await githubClient.api<GitHubCollaboratorPermission>(
          "GET",
          `/repos/${evidence.owner}/${evidence.repo}/collaborators/${encodeURIComponent(author!)}/permission`
        )
      : undefined;
    const verified =
      commentVerified &&
      (maintainerRoles.has(permission?.role_name?.toLowerCase() ?? "") || permission?.permission?.toLowerCase() === "admin");
    return verified
      ? {
          ruleId: "PRS-HARDSTOP-001",
          status: "approved",
          category,
          detail: `Verified GitHub approval from configured reviewer ${author}.`
        }
      : {
          ruleId: "PRS-HARDSTOP-001",
          status: "blocking",
          category,
          detail: `Approval evidence was not verified for ${category}.`
        };
  } catch {
    return {
      ruleId: "PRS-HARDSTOP-001",
      status: "blocking",
      category,
      detail: `Approval evidence was not verified for ${category}.`
    };
  }
}

function redacted(value: string): { value: string; replacements: number } {
  return redactPublicText(value);
}

function hardStopCategory(action: MaterialAction): (typeof HUMAN_HARD_STOP_CATEGORIES)[number] | undefined {
  return HUMAN_HARD_STOP_CATEGORIES.find((category) => category === action.action);
}

function hardStopResult(action: MaterialAction): z.infer<typeof hardStopResultSchema> {
  const category = hardStopCategory(action);
  if (!category) {
    return {
      ruleId: "PRS-HARDSTOP-001",
      status: "not-applicable",
      detail: "No defined human hard stop applies."
    };
  }

  if (!action.approval) {
    return {
      ruleId: "PRS-HARDSTOP-001",
      status: "blocking",
      category,
      detail: `Explicit human approval evidence is required for ${category}.`
    };
  }

  return {
    ruleId: "PRS-HARDSTOP-001",
    status: "verification-required",
    category,
    detail: `GitHub approval evidence must be verified for ${category}.`
  };
}

function buildPublicPayload(action: MaterialAction): {
  summary: string;
  approvalEvidence?: string;
  redactions: number;
} {
  const summary = redacted(action.summary);
  const approvalEvidence = action.approval ? redacted(action.approval.evidence) : undefined;
  return {
    summary: summary.value,
    ...(approvalEvidence ? { approvalEvidence: approvalEvidence.value } : {}),
    redactions: summary.replacements + (approvalEvidence?.replacements ?? 0)
  };
}

function escapeGitHubMarkdownText(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/([\\`*_{}\[\]()#+.!|~-])/g, "\\$1");
}

function materialActionCommentBody(
  action: MaterialAction,
  publicPayload: ReturnType<typeof buildPublicPayload>,
  hardStop: z.infer<typeof hardStopResultSchema>,
  digest?: string
): string {
  const renderedSummary = escapeGitHubMarkdownText(publicPayload.summary);
  const renderedApprovalEvidence = publicPayload.approvalEvidence
    ? escapeGitHubMarkdownText(publicPayload.approvalEvidence)
    : undefined;
  const approvalLine = action.approval
    ? `- Approval evidence: ${renderedApprovalEvidence} (${hardStop.status === "approved" ? "verified" : "verification required"})`
    : "- Approval: not supplied";
  const mayContinue = hardStop.status === "not-applicable" || hardStop.status === "approved";
  return [
    "## Material action notification",
    "",
    "- Rule: PRS-NOTIFY-001",
    `- Action ID: ${action.id}`,
    `- Action: ${action.action}`,
    `- Summary: ${renderedSummary}`,
    `- Hard stop: ${hardStop.category ?? "none"}`,
    ...(digest ? [`- Approval digest: ${digest}`] : []),
    approvalLine,
    `- Decision: ${mayContinue ? "continue after required notifications are delivered" : "stop pending verified human approval"}`
  ].join("\n");
}

export function planMaterialAction(manifest: BootstrapManifest, input: unknown): MaterialActionPlan {
  const action = materialActionSchema.parse(input);
  const githubTarget = parseGitHubTarget(action.governingTarget, manifest);
  const publicGoverningTarget = githubTarget
    ? `${githubTarget.owner}/${githubTarget.repo}#${githubTarget.number}`
    : "[INVALID:GOVERNING-TARGET]";
  const publicPayload = buildPublicPayload(action);
  const hardStop = hardStopResult(action);
  const digest = hardStop.category ? approvalDigest(action) : undefined;
  const configurationErrors = [
    ...(!githubTarget ? ["governingTarget must identify a GitHub issue or pull request."] : []),
    ...(!manifest.notifications ? ["notifications.webhookUrlEnv is not configured."] : [])
  ];
  const notificationStatus = configurationErrors.length === 0 ? "ready" : "blocking";
  const commentBody = materialActionCommentBody(action, publicPayload, hardStop, digest);
  const webhookPayload = webhookPayloadSchema.parse({
    schemaVersion: 1,
    ruleId: "PRS-NOTIFY-001",
    actionId: action.id,
    action: action.action,
    summary: publicPayload.summary,
    governingTarget: publicGoverningTarget,
    ...(hardStop.category ? { hardStopCategory: hardStop.category } : {}),
    ...(digest ? { approvalDigest: digest } : {}),
    ...(publicPayload.approvalEvidence ? { approvalEvidence: publicPayload.approvalEvidence } : {})
  });
  const notification = notificationResultSchema.parse({
    ruleId: "PRS-NOTIFY-001",
    status: notificationStatus,
    destinations: [
      {
        destination: "governing-issue-or-pull-request",
        status: "planned",
        detail: githubTarget ? action.governingTarget : "Invalid governing target."
      },
      {
        destination: "configured-webhook",
        status: "planned",
        detail: manifest.notifications?.webhookUrlEnv ?? "No webhook environment-variable reference is configured."
      }
    ],
    detail: configurationErrors.length === 0 ? "Both required notification destinations are configured." : configurationErrors.join(" ")
  });

  return materialActionPlanSchema.parse({
    schemaVersion: 1,
    actionId: action.id,
    action: action.action,
    governingTarget: publicGoverningTarget,
    ...(digest ? { approvalDigest: digest } : {}),
    notification,
    hardStop,
    continueAfterNotification: notification.status !== "blocking" && hardStop.status === "not-applicable",
    redactions: publicPayload.redactions,
    commentBody,
    webhookPayload,
    exitCode: notification.status === "blocking" || hardStop.status !== "not-applicable" ? 1 : 0
  });
}

const WEBHOOK_ALLOWED_HOSTS_ENV = "BOOTSTRAP_NOTIFICATION_WEBHOOK_ALLOWED_HOSTS";
const reservedWebhookIpv4Addresses = new BlockList();
const reservedWebhookIpv6Addresses = new BlockList();
const publicWebhookIpv6Addresses = new BlockList();
publicWebhookIpv6Addresses.addSubnet("2000::", 3, "ipv6");

for (const [network, prefix] of [
  ["0.0.0.0", 8],
  ["10.0.0.0", 8],
  ["100.64.0.0", 10],
  ["127.0.0.0", 8],
  ["169.254.0.0", 16],
  ["172.16.0.0", 12],
  ["192.0.0.0", 24],
  ["192.0.2.0", 24],
  ["192.88.99.0", 24],
  ["192.168.0.0", 16],
  ["198.18.0.0", 15],
  ["198.51.100.0", 24],
  ["203.0.113.0", 24],
  ["224.0.0.0", 4],
  ["240.0.0.0", 4]
] as const) {
  reservedWebhookIpv4Addresses.addSubnet(network, prefix, "ipv4");
}

for (const [network, prefix] of [
  ["::", 128],
  ["::1", 128],
  ["::ffff:0:0", 96],
  ["64:ff9b::", 96],
  ["64:ff9b:1::", 48],
  ["100::", 64],
  ["2001::", 23],
  ["2001:db8::", 32],
  ["2002::", 16],
  ["3fff::", 20],
  ["fc00::", 7],
  ["fe80::", 10],
  ["ff00::", 8]
] as const) {
  reservedWebhookIpv6Addresses.addSubnet(network, prefix, "ipv6");
}

function normalizeWebhookHostname(hostname: string): string {
  const withoutBrackets = hostname.startsWith("[") && hostname.endsWith("]") ? hostname.slice(1, -1) : hostname;
  return withoutBrackets.replace(/\.$/, "").toLowerCase();
}

function approvedWebhookHosts(environment: NodeJS.ProcessEnv): Set<string> {
  return new Set(
    (environment[WEBHOOK_ALLOWED_HOSTS_ENV] ?? "")
      .split(",")
      .map((hostname) => normalizeWebhookHostname(hostname.trim()))
      .filter(Boolean)
  );
}

function isPublicWebhookAddress(address: string): address is string {
  const family = isIP(address);
  if (family === 4) return !reservedWebhookIpv4Addresses.check(address, "ipv4");
  if (family === 6) {
    return publicWebhookIpv6Addresses.check(address, "ipv6") && !reservedWebhookIpv6Addresses.check(address, "ipv6");
  }
  return false;
}

const defaultWebhookResolver: WebhookResolver = async (hostname) => {
  const family = isIP(hostname);
  if (family === 4 || family === 6) return [{ address: hostname, family }];
  const addresses = await lookup(hostname, { all: true, verbatim: true });
  return addresses.map(({ address, family: resolvedFamily }) => ({
    address,
    family: resolvedFamily === 6 ? 6 : 4
  }));
};

async function validateWebhookDestination(
  webhookUrl: string,
  environment: NodeJS.ProcessEnv,
  resolver: WebhookResolver,
  deadline: number
): Promise<{ url: URL; addresses: ResolvedWebhookAddress[] }> {
  const url = new URL(webhookUrl);
  if (url.protocol !== "https:") throw new Error("Webhook must use HTTPS.");
  if (url.username || url.password) throw new Error("Webhook URLs must not contain credentials.");
  if (url.port && url.port !== "443") throw new Error("Webhook delivery is restricted to HTTPS port 443.");

  const hostname = normalizeWebhookHostname(url.hostname);
  if (!approvedWebhookHosts(environment).has(hostname)) {
    throw new Error(`Webhook hostname is not approved by ${WEBHOOK_ALLOWED_HOSTS_ENV}.`);
  }

  const addresses = await withDeadline(resolver(hostname), deadline, "Webhook hostname resolution timed out.");
  if (addresses.length === 0) throw new Error("Webhook hostname did not resolve.");
  const validated: ResolvedWebhookAddress[] = addresses.map(({ address }) => {
    const family = isIP(address);
    if ((family !== 4 && family !== 6) || !isPublicWebhookAddress(address)) {
      throw new Error("Webhook hostname resolved to a non-public address.");
    }
    return { address, family: family as 4 | 6 };
  });
  return { url, addresses: validated };
}

async function withDeadline<T>(operation: Promise<T>, deadline: number, message: string): Promise<T> {
  const remainingMilliseconds = deadline - Date.now();
  if (remainingMilliseconds <= 0) throw new Error(message);

  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      operation,
      new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => reject(new Error(message)), remainingMilliseconds);
      })
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

function pinnedLookup(address: ResolvedWebhookAddress): LookupFunction {
  return ((_hostname, options, callback) => {
    if (typeof options === "object" && options.all) {
      callback(null, [address]);
      return;
    }
    callback(null, address.address, address.family);
  }) as LookupFunction;
}

function sendWebhookToAddress(
  url: URL,
  body: string,
  address: ResolvedWebhookAddress,
  timeoutMilliseconds: number
): Promise<WebhookResult> {
  return new Promise((resolve, reject) => {
    const request = httpsRequest(
      url,
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "content-length": Buffer.byteLength(body)
        },
        agent: false,
        lookup: pinnedLookup(address),
        signal: AbortSignal.timeout(timeoutMilliseconds)
      },
      (response) => {
        response.once("error", reject);
        response.resume();
        response.once("end", () =>
          resolve({
            ok: response.statusCode !== undefined && response.statusCode >= 200 && response.statusCode < 300,
            status: response.statusCode ?? 0
          })
        );
      }
    );
    request.once("error", reject);
    request.end(body);
  });
}

async function defaultWebhookSender(
  url: URL,
  payload: MaterialActionPlan["webhookPayload"],
  addresses: ResolvedWebhookAddress[],
  deadline: number
): Promise<WebhookResult> {
  const body = JSON.stringify(payload);
  let lastError: unknown;

  for (const [index, address] of addresses.entries()) {
    const remainingMilliseconds = deadline - Date.now();
    if (remainingMilliseconds <= 0) break;
    const remainingAddresses = addresses.length - index;
    const attemptMilliseconds = Math.max(1, Math.floor(remainingMilliseconds / remainingAddresses));
    try {
      return await sendWebhookToAddress(url, body, address, attemptMilliseconds);
    } catch (error) {
      lastError = error;
    }
  }

  throw lastError instanceof Error ? lastError : new Error("Webhook delivery exhausted all validated addresses.");
}

export async function deliverMaterialAction(
  manifest: BootstrapManifest,
  input: unknown,
  options: DeliveryOptions = {}
): Promise<MaterialActionDeliveryReport> {
  const action = materialActionSchema.parse(input);
  const plan = planMaterialAction(manifest, input);
  const githubTarget = parseGitHubTarget(plan.governingTarget, manifest);
  const githubClient = options.githubClient ?? new GitHubClient();
  const environment = options.environment ?? process.env;
  const webhookResolver = options.webhookResolver ?? defaultWebhookResolver;
  const destinations: MaterialActionPlan["notification"]["destinations"] = [];
  const hardStop = await verifiedHardStopResult(action, manifest, githubTarget, githubClient);
  const commentBody = materialActionCommentBody(action, buildPublicPayload(action), hardStop, plan.approvalDigest);

  if (!githubTarget) {
    destinations.push({
      destination: "governing-issue-or-pull-request",
      status: "failed",
      detail: "Invalid governing target."
    });
  } else {
    try {
      await githubClient.api(
        "POST",
        `/repos/${githubTarget.owner}/${githubTarget.repo}/issues/${githubTarget.number}/comments`,
        { body: commentBody }
      );
      destinations.push({
        destination: "governing-issue-or-pull-request",
        status: "delivered",
        detail: plan.governingTarget
      });
    } catch {
      destinations.push({
        destination: "governing-issue-or-pull-request",
        status: "failed",
        detail: "GitHub comment delivery failed."
      });
    }
  }

  const webhookEnvironmentName = manifest.notifications?.webhookUrlEnv;
  const webhookUrl = webhookEnvironmentName ? environment[webhookEnvironmentName] : undefined;
  if (!githubTarget) {
    destinations.push({
      destination: "configured-webhook",
      status: "failed",
      detail: "Webhook delivery skipped because the governing target is invalid."
    });
  } else if (!webhookEnvironmentName || !webhookUrl) {
    destinations.push({
      destination: "configured-webhook",
      status: "failed",
      detail: webhookEnvironmentName
        ? `Environment variable ${webhookEnvironmentName} is not set.`
        : "No webhook environment-variable reference is configured."
    });
  } else {
    try {
      const deadline = Date.now() + 10_000;
      const destination = await validateWebhookDestination(webhookUrl, environment, webhookResolver, deadline);
      const response = options.webhookSender
        ? await withDeadline(
            options.webhookSender(webhookUrl, plan.webhookPayload),
            deadline,
            "Webhook delivery timed out."
          )
        : await defaultWebhookSender(destination.url, plan.webhookPayload, destination.addresses, deadline);
      destinations.push({
        destination: "configured-webhook",
        status: response.ok ? "delivered" : "failed",
        detail: response.ok ? `Webhook returned HTTP ${response.status}.` : `Webhook rejected delivery with HTTP ${response.status}.`
      });
    } catch {
      destinations.push({
        destination: "configured-webhook",
        status: "failed",
        detail: "Webhook delivery failed."
      });
    }
  }

  const delivered = destinations.every((destination) => destination.status === "delivered");
  const notification = notificationResultSchema.parse({
    ruleId: "PRS-NOTIFY-001",
    status: delivered ? "delivered" : "blocking",
    destinations,
    detail: delivered ? "Both required notification destinations were delivered." : "A required notification destination failed."
  });

  return materialActionPlanSchema.parse({
    ...plan,
    notification,
    hardStop,
    commentBody,
    continueAfterNotification: delivered && (hardStop.status === "not-applicable" || hardStop.status === "approved"),
    exitCode: delivered && (hardStop.status === "not-applicable" || hardStop.status === "approved") ? 0 : 1
  });
}

function exceptionMaterialActions(manifest: BootstrapManifest, now: Date): {
  actions: MaterialAction[];
  blocking: boolean;
} {
  const validation = validatePolicyExceptions(manifest.exceptions, now);
  const actions = validation.notifications.map((notification) => {
    const exception = manifest.exceptions.find((entry) => entry.id === notification.exceptionId);
    if (!exception?.expiresAt) {
      throw new Error(`Notification intent ${notification.exceptionId} has no matching expiring exception.`);
    }
    const idDigest = createHash("sha256").update(exception.id, "utf8").digest("hex").slice(0, 12);
    const displayId = redactPublicText(exception.id).value.replace(/[\r\n\u2028\u2029]+/g, " ").slice(0, 512);
    const governingTarget = containsCredential(exception.issue) ? "invalid-governing-target" : exception.issue;
    return materialActionSchema.parse({
      id: `exception-${idDigest}-expiring`,
      action: "policy-exception",
      summary: `Temporary policy exception ${displayId} expires on ${exception.expiresAt}.`,
      governingTarget
    });
  });
  return { actions, blocking: validation.blocking };
}

export function planExceptionNotifications(
  manifest: BootstrapManifest,
  now = new Date()
): ExceptionNotificationReport {
  const exceptions = exceptionMaterialActions(manifest, now);
  const notifications = exceptions.actions.map((action) => planMaterialAction(manifest, action));
  return exceptionNotificationReportSchema.parse({
    schemaVersion: 1,
    mode: "plan",
    notifications,
    blockingExceptions: exceptions.blocking,
    exitCode: exceptions.blocking || notifications.some((notification) => notification.exitCode === 1) ? 1 : 0
  });
}

export async function deliverExceptionNotifications(
  manifest: BootstrapManifest,
  options: ExceptionDeliveryOptions = {}
): Promise<ExceptionNotificationReport> {
  const exceptions = exceptionMaterialActions(manifest, options.now ?? new Date());
  const notifications: MaterialActionPlan[] = [];
  for (const action of exceptions.actions) {
    notifications.push(await deliverMaterialAction(manifest, action, options));
  }
  return exceptionNotificationReportSchema.parse({
    schemaVersion: 1,
    mode: "deliver",
    notifications,
    blockingExceptions: exceptions.blocking,
    exitCode: exceptions.blocking || notifications.some((notification) => notification.exitCode === 1) ? 1 : 0
  });
}

export function formatMaterialActionReport(report: MaterialActionPlan): string {
  return [
    `Material action ${report.actionId}: ${report.exitCode === 0 ? "ready" : "blocked"}`,
    `- [${report.notification.status}] ${report.notification.ruleId}: ${report.notification.detail}`,
    ...report.notification.destinations.map(
      (destination) => `  - [${destination.status}] ${destination.destination}: ${destination.detail}`
    ),
    `- [${report.hardStop.status}] ${report.hardStop.ruleId}: ${report.hardStop.detail}`,
    ...(report.approvalDigest ? [`- Approval digest: ${report.approvalDigest}`] : []),
    `- Continue after notification: ${report.continueAfterNotification ? "yes" : "no"}`,
    `- Redactions: ${report.redactions}`
  ].join("\n");
}

export function formatExceptionNotificationReport(report: ExceptionNotificationReport): string {
  return [
    `Exception notifications ${report.mode}: ${report.notifications.length} intent(s), ${report.blockingExceptions ? "blocking exceptions present" : "no blocking exceptions"}`,
    ...report.notifications.flatMap((notification) => formatMaterialActionReport(notification).split("\n")),
    `Exception notification result: ${report.exitCode === 0 ? "pass" : "block"}`
  ].join("\n");
}
