import { randomUUID } from "node:crypto";
import { z } from "zod";
import {
  PrivateControlError, controlBase, controlCategory, controlCounter, controlDigest, controlHash,
  controlId, controlPurpose, controlSet, controlStorage, controlSubject, controlText, controlTime, controlWire,
  parsePrivateControl, requireControl, verifyPrivateControl, type PrivateControlKey
} from "./private-provenance-control.js";

const categories = controlSet(controlCategory, 3);
const scope = { subject: controlSubject, runId: controlId, storage: controlStorage, receiptSha256: controlDigest };
export const privateReadRequestSchema = z.object({
  ...controlBase("bootstrap-private-read-request"), requestId: controlId, configEpoch: controlCounter,
  requesterId: controlId, purposeId: controlPurpose, ...scope, requestedCategoryIds: categories,
  issuedAt: controlTime, expiresAt: controlTime
}).strict();
export const privateReadApprovalSchema = z.object({
  ...controlBase("bootstrap-private-read-approval"), approvalId: controlId, delegationId: controlId,
  configEpoch: controlCounter, approverWorkloadId: controlId, requestSha256: controlDigest,
  requesterId: controlId, purposeId: controlPurpose, ...scope, categoryIds: categories,
  maxUses: z.literal(1), issuedAt: controlTime, notBefore: controlTime, expiresAt: controlTime
}).strict();
const delegationSchema = z.object({
  ...controlBase("bootstrap-codex-read-delegation"), delegationId: controlId, configEpoch: controlCounter,
  approverWorkloadId: controlId, approverKeyFingerprint: controlDigest,
  repositoryIds: controlSet(controlId), requesterIds: controlSet(controlId), categoryIds: categories,
  purposeIds: controlSet(controlPurpose, 3), maxApprovalSeconds: z.number().int().min(1).max(300),
  maxUses: z.literal(1), issuedAt: controlTime, notBefore: controlTime, expiresAt: controlTime
}).strict();
const revocationSchema = z.object({
  ...controlBase("bootstrap-private-read-revocation"), scopeType: z.literal("approval"), scopeId: controlId,
  scopeSha256: controlDigest, delegationId: controlId, configEpoch: controlCounter, sequence: controlCounter, at: controlTime
}).strict();
const phase = z.enum(["attempt", "complete", "failed", "revoked"]);
const ackSchema = z.object({
  ...controlBase("bootstrap-private-audit-ack"), eventId: controlId, eventSha256: controlDigest,
  operationId: controlId, phase, storage: controlStorage, recordedAt: controlTime,
  retainUntil: controlTime, configEpoch: controlCounter
}).strict();
const stateSchema = z.object({
  approvalId: controlId, delegationId: controlId, approvalSha256: controlDigest, configEpoch: controlCounter,
  revision: controlCounter, state: z.enum(["available", "reserved", "spent", "revoked", "failed"]),
  requestId: controlId.nullable(), operationId: controlId.nullable(), revocationSha256: controlDigest.nullable(), updatedAt: controlTime
}).strict().refine((v) => v.state === "revoked" ? v.revocationSha256 !== null
  : v.revocationSha256 === null && v.requestId !== null && (v.state === "available" ? v.operationId === null : v.operationId !== null));
export type PrivateReadRequest = z.infer<typeof privateReadRequestSchema>;
type Approval = z.infer<typeof privateReadApprovalSchema>;
type State = z.infer<typeof stateSchema>;
export class PrivateStateConflict extends Error { constructor() { super("Conditional private state conflict."); } }
export interface PrivateApprovalStore {
  read(key: string): Promise<{ bytes: Uint8Array; etag: string } | null>;
  create(key: string, bytes: Uint8Array): Promise<void>; // Provider-enforced If-None-Match: *.
  replace(key: string, etag: string, bytes: Uint8Array): Promise<void>; // Provider-enforced If-Match.
}
/** Acquired by the fixed broker from enrolled identity/current configuration, never request fields. */
export interface PrivateReadObservation {
  configEpoch: number;
  repositoryId: string;
  repository: string;
  requesterId: string;
  auditOwnerId: string;
  brokerWorkloadId: string;
  auditBucket: string;
  auditPrefix: string;
  keys: readonly PrivateControlKey[];
}
export interface PrivateReadPorts {
  observe(): Promise<PrivateReadObservation>;
  now(): Date;
  state: PrivateApprovalStore;
  /** Fixed decrypt producer verifies receipt/public binding, exact version/retention/AEAD; transfers ownership of its returned bytes. */
  loadVerifiedBundle(request: Readonly<PrivateReadRequest>): Promise<Uint8Array>;
  /** Durable audit producer returns signed exact-event acknowledgment, never a success boolean. */
  audit(event: Uint8Array): Promise<Uint8Array>;
}
export interface PrivateReadDocuments { request: Uint8Array; approval: Uint8Array; delegation: Uint8Array }
const same = (a: unknown, b: unknown) => controlWire(a).equals(controlWire(b));
const subset = (a: readonly string[], b: readonly string[]) => a.every((v) => b.includes(v));
const ms = (s: string) => Date.parse(s);
const fingerprint = (documents: Omit<PrivateReadDocuments, "request">) => controlHash(documents.approval);
const snapshot = (v: Uint8Array) => { requireControl(v instanceof Uint8Array && v.byteLength <= 16_384); return Buffer.from(v); };

function checkIssuedWindow(value: { issuedAt: string; notBefore: string; expiresAt: string }, now: Date) {
  requireControl(Number.isFinite(now.getTime()) && ms(value.issuedAt) <= now.getTime()
    && ms(value.issuedAt) <= ms(value.notBefore) && ms(value.notBefore) < ms(value.expiresAt));
}
function checkWindow(value: { notBefore: string; expiresAt: string }, now: Date) {
  requireControl(ms(value.notBefore) <= now.getTime() && now.getTime() < ms(value.expiresAt));
}
function verifyApproval(documents: Omit<PrivateReadDocuments, "request">, observed: PrivateReadObservation, now: Date, usage: "read" | "revoke" = "read"): Approval {
  controlCounter.parse(observed.configEpoch); controlId.parse(observed.repositoryId);
  controlSubject.shape.repository.parse(observed.repository); controlId.parse(observed.requesterId);
  controlId.parse(observed.auditOwnerId); controlId.parse(observed.brokerWorkloadId);
  controlStorage.shape.bucket.parse(observed.auditBucket); controlText(1024).parse(observed.auditPrefix);
  requireControl(observed.auditPrefix.endsWith("/"));
  const delegation = verifyPrivateControl(documents.delegation, delegationSchema, "deployment-root", observed.keys, now).payload;
  const verified = verifyPrivateControl(documents.approval, privateReadApprovalSchema, "codex-read-approval", observed.keys, now);
  const a = verified.payload;
  checkIssuedWindow(delegation, now); checkIssuedWindow(a, now);
  if (usage === "read") { checkWindow(delegation, now); checkWindow(a, now); }
  requireControl(a.configEpoch === observed.configEpoch && delegation.configEpoch === observed.configEpoch
    && a.delegationId === delegation.delegationId && a.approverWorkloadId === delegation.approverWorkloadId
    && verified.ownerId === a.approverWorkloadId && verified.fingerprint === delegation.approverKeyFingerprint
    && a.subject.repository === observed.repository && delegation.repositoryIds.includes(observed.repositoryId) && delegation.requesterIds.includes(a.requesterId)
    && delegation.purposeIds.includes(a.purposeId) && subset(a.categoryIds, delegation.categoryIds)
    && ms(a.expiresAt) <= ms(delegation.expiresAt) && ms(a.issuedAt) >= ms(delegation.notBefore)
    && ms(a.expiresAt) - ms(a.issuedAt) <= delegation.maxApprovalSeconds * 1000);
  return a;
}
function authorize(documents: PrivateReadDocuments, observed: PrivateReadObservation, now: Date) {
  const approval = verifyApproval(documents, observed, now);
  const verified = verifyPrivateControl(documents.request, privateReadRequestSchema, "requester-request", observed.keys, now);
  const request = verified.payload;
  requireControl(verified.ownerId === request.requesterId && request.requesterId === observed.requesterId
    && request.configEpoch === observed.configEpoch && approval.requestSha256 === verified.sha256
    && ms(request.issuedAt) <= now.getTime() && now.getTime() < ms(request.expiresAt)
    && ms(approval.issuedAt) >= ms(request.issuedAt) && ms(approval.expiresAt) <= ms(request.expiresAt));
  for (const field of ["subject", "runId", "storage", "receiptSha256", "requesterId", "purposeId"] as const) {
    requireControl(same(request[field], approval[field]));
  }
  requireControl(same([...request.requestedCategoryIds].sort(), [...approval.categoryIds].sort()));
  return { approval, request };
}
export function privateApprovalStateKey(delegationId: string, approvalId: string): string {
  return `approvals/${controlHash(controlWire({ domain: "bootstrap-approval-state-key", delegationId: controlId.parse(delegationId), approvalId: controlId.parse(approvalId) }))}.json`;
}
async function readState(store: PrivateApprovalStore, key: string, approval: Approval, digest: string) {
  const stored = await store.read(key);
  if (!stored) return null;
  requireControl(typeof stored.etag === "string" && stored.etag.length > 0 && stored.etag.length <= 1024);
  const state = stateSchema.parse(parsePrivateControl(stored.bytes));
  requireControl(state.approvalId === approval.approvalId && state.delegationId === approval.delegationId && state.approvalSha256 === digest && state.configEpoch === approval.configEpoch);
  return { state, etag: stored.etag };
}
function initial(approval: Approval, digest: string, now: Date, requestId: string | null, revocation: string | null): State {
  return stateSchema.parse({ approvalId: approval.approvalId, delegationId: approval.delegationId, approvalSha256: digest,
    configEpoch: approval.configEpoch, revision: 0, state: revocation ? "revoked" : "available",
    requestId, operationId: null, revocationSha256: revocation, updatedAt: now.toISOString() });
}
async function createOrRead(store: PrivateApprovalStore, key: string, approval: Approval, state: State) {
  try { await store.create(key, controlWire(state)); }
  catch (error) { if (!(error instanceof PrivateStateConflict)) throw error; }
  const actual = await readState(store, key, approval, state.approvalSha256);
  requireControl(actual); // Unknown/absent after acknowledgment is not authorization to retry.
  return actual;
}
async function replaceState(store: PrivateApprovalStore, key: string, prior: { state: State; etag: string }, patch: Partial<State>, now: Date) {
  const next = stateSchema.parse({ ...prior.state, ...patch, revision: prior.state.revision + 1, updatedAt: now.toISOString() });
  await store.replace(key, prior.etag, controlWire(next));
  return next;
}

const summarySchemas = {
  "decision-summary": z.object({ issue: controlText(2048), decision: controlText(4096), alternatives: z.array(controlText(4096)).max(4), reason: controlText(4096) }).strict(),
  "review-summary": z.object({ issue: controlText(2048), reviewerId: controlId, result: z.enum(["approved", "changes-requested", "commented"]), findings: z.array(controlText(512)).max(16) }).strict(),
  "validation-summary": z.object({ checkId: controlId, result: z.enum(["pass", "fail", "skipped"]), passed: z.number().int().min(0).max(1_000_000), failed: z.number().int().min(0).max(1_000_000), revision: z.string().regex(/^[0-9a-f]{40}$/) }).strict()
};
function validatePrivateBundle(bytes: Uint8Array, permitted: readonly string[]) {
  const value = z.object({ schemaVersion: z.literal(1), evidence: z.array(z.object({ category: controlCategory, text: controlText(16_384) }).strict()).min(1).max(64) }).strict()
    .parse(parsePrivateControl(bytes, 1_048_576, 4));
  requireControl(same([...new Set(value.evidence.map((e) => e.category))].sort(), [...permitted].sort()));
  for (const evidence of value.evidence) summarySchemas[evidence.category].parse(parsePrivateControl(Buffer.from(evidence.text), 16_384, 4));
}

const auditEventSchema = z.object({
  ...controlBase("bootstrap-private-audit-event"), eventId: controlId, operationId: controlId, phase,
  at: controlTime, configEpoch: controlCounter, actorId: controlId, workloadId: controlId,
  requestSha256: controlDigest.nullable(), approvalSha256: controlDigest.nullable(), delegationId: controlId.nullable(),
  receiptSha256: controlDigest.nullable(), subject: controlSubject.nullable(), runId: controlId.nullable(), storage: controlStorage.nullable(),
  purposeId: controlPurpose.nullable(), stateRevision: controlCounter.nullable(),
  resultCode: z.enum(["OK", "REVOKED", "REPLAY", "ABORTED"]), previousEventSha256: controlDigest.nullable()
}).strict();
async function acknowledgeAudit(ports: PrivateReadPorts, authority: PrivateReadObservation, value: unknown) {
  const event = auditEventSchema.parse(value); const bytes = controlWire(event); const eventHash = controlHash(bytes);
  const verified = verifyPrivateControl(await ports.audit(bytes), ackSchema, "audit-ack", authority.keys, ports.now());
  const ack = verified.payload;
  requireControl(typeof authority.auditPrefix === "string" && authority.auditPrefix.length > 0 && authority.auditPrefix.endsWith("/")
    && verified.ownerId === authority.auditOwnerId && ack.configEpoch === authority.configEpoch && ack.eventId === event.eventId
    && ack.eventSha256 === eventHash && ack.operationId === event.operationId && ack.phase === event.phase
    && ack.storage.bucket === authority.auditBucket && ack.storage.key.startsWith(authority.auditPrefix)
    && ms(ack.recordedAt) >= ms(event.at) && ms(ack.recordedAt) <= ports.now().getTime()
    && ms(ack.retainUntil) >= ms(ack.recordedAt) + 90 * 86_400_000);
  return eventHash;
}

/** Source-only coordinator: fixed authenticated runtime composition and provider qualification remain required. */
export function createPrivateReadCoordinator(ports: PrivateReadPorts) {
  async function revoke(input: Omit<PrivateReadDocuments, "request"> & { revocation: Uint8Array }): Promise<"revoked" | "already-spent"> {
    try {
      const documents = { approval: snapshot(input.approval), delegation: snapshot(input.delegation) };
      const revocation = snapshot(input.revocation);
      const observed = await ports.observe(); const now = ports.now();
      const approval = verifyApproval(documents, observed, now, "revoke");
      let signed;
      try { signed = verifyPrivateControl(revocation, revocationSchema, "deployment-root", observed.keys, now); }
      catch { signed = verifyPrivateControl(revocation, revocationSchema, "codex-read-approval", observed.keys, now);
        requireControl(signed.ownerId === approval.approverWorkloadId && signed.fingerprint ===
          verifyPrivateControl(documents.approval, privateReadApprovalSchema, "codex-read-approval", observed.keys, now).fingerprint); }
      const r = signed.payload; const digest = fingerprint(documents);
      requireControl(r.scopeId === approval.approvalId && r.delegationId === approval.delegationId && r.scopeSha256 === digest
        && r.configEpoch === observed.configEpoch && ms(r.at) <= now.getTime());
      const key = privateApprovalStateKey(approval.delegationId, approval.approvalId);
      let current = await readState(ports.state, key, approval, digest);
      if (!current) current = await createOrRead(ports.state, key, approval, initial(approval, digest, now, null, signed.sha256));
      // Bounded arbitration; repeated conflicts deny acknowledgment, never overwrite a winner.
      for (let attempt = 0; attempt < 4; attempt++) {
        if (current.state.state === "revoked" || current.state.state === "spent") {
          const spent = current.state.state === "spent";
          await acknowledgeAudit(ports, observed, { domain: "bootstrap-private-audit-event", version: 1, canonicalization: "sorted-json-v1",
            eventId: randomUUID(), operationId: randomUUID(), phase: spent ? "failed" : "revoked", at: ports.now().toISOString(),
            configEpoch: observed.configEpoch, actorId: signed.ownerId, workloadId: observed.brokerWorkloadId,
            requestSha256: approval.requestSha256, approvalSha256: digest, delegationId: approval.delegationId,
            receiptSha256: approval.receiptSha256, subject: approval.subject, runId: approval.runId, storage: approval.storage,
            purposeId: approval.purposeId, stateRevision: current.state.revision, resultCode: spent ? "REPLAY" : "REVOKED", previousEventSha256: null });
          return spent ? "already-spent" : "revoked";
        }
        requireControl(current.state.state === "available" || current.state.state === "reserved");
        try { await replaceState(ports.state, key, current, { state: "revoked", revocationSha256: signed.sha256 }, ports.now()); }
        catch (error) { if (!(error instanceof PrivateStateConflict)) throw error; }
        const refreshed = await readState(ports.state, key, approval, digest); requireControl(refreshed); current = refreshed;
      }
      throw new PrivateControlError();
    } catch { throw new PrivateControlError(); }
  }
  async function read(input: PrivateReadDocuments): Promise<Buffer> {
    let plaintext: Uint8Array | undefined;
    try {
      const documents = { request: snapshot(input.request), approval: snapshot(input.approval), delegation: snapshot(input.delegation) };
      const observed = await ports.observe(); const now = ports.now();
      const { request, approval } = authorize(documents, observed, now);
      const digest = fingerprint(documents); const key = privateApprovalStateKey(approval.delegationId, approval.approvalId);
      let current = await readState(ports.state, key, approval, digest);
      if (!current) current = await createOrRead(ports.state, key, approval, initial(approval, digest, now, request.requestId, null));
      requireControl(current.state.state === "available" && current.state.requestId === request.requestId);
      // Ledger latency must not carry an earlier authorization past its validity window.
      authorize(documents, observed, ports.now());
      const operationId = randomUUID();
      const reserved = await replaceState(ports.state, key, current, { state: "reserved", operationId }, ports.now());
      let previousEventSha256: string | null = null;
      const record = async (eventPhase: z.infer<typeof phase>, authority: PrivateReadObservation, revision: number) => {
        const event = { domain: "bootstrap-private-audit-event", version: 1, canonicalization: "sorted-json-v1",
          eventId: randomUUID(), operationId, phase: eventPhase, at: ports.now().toISOString(), configEpoch: authority.configEpoch,
          actorId: request.requesterId, workloadId: authority.brokerWorkloadId, requestSha256: controlHash(documents.request), approvalSha256: digest,
          delegationId: approval.delegationId, receiptSha256: request.receiptSha256, subject: request.subject, runId: request.runId,
          storage: request.storage, purposeId: request.purposeId, stateRevision: revision, resultCode: eventPhase === "failed" ? "ABORTED" : "OK", previousEventSha256 };
        previousEventSha256 = await acknowledgeAudit(ports, authority, event);
      };
      try {
        authorize(documents, observed, ports.now());
        await record("attempt", observed, reserved.revision);
        const beforeLoad = await ports.observe();
        authorize(documents, beforeLoad, ports.now()); requireControl(same(observed, beforeLoad));
        const beforeDecrypt = await readState(ports.state, key, approval, digest);
        requireControl(beforeDecrypt?.state.state === "reserved" && beforeDecrypt.state.operationId === operationId);
        authorize(documents, beforeLoad, ports.now());
        const loaded = await ports.loadVerifiedBundle(Object.freeze(structuredClone(request)));
        requireControl(loaded instanceof Uint8Array && loaded.byteLength > 0 && loaded.byteLength <= 1_048_576);
        plaintext = Buffer.from(loaded); loaded.fill(0);
        validatePrivateBundle(plaintext, request.requestedCategoryIds);
        const refreshed = await ports.observe();
        authorize(documents, refreshed, ports.now());
        requireControl(same(observed, refreshed));
        const latest = await readState(ports.state, key, approval, digest);
        requireControl(latest && latest.state.state === "reserved" && latest.state.operationId === operationId);
        authorize(documents, refreshed, ports.now());
        const spent = await replaceState(ports.state, key, latest, { state: "spent" }, ports.now());
        // A late CAS acknowledgment cannot establish a timely spend. Never refund terminal state.
        authorize(documents, refreshed, ports.now());
        // Confirmed timely spend is the authorization point; completion audit still gates release.
        await record("complete", refreshed, spent.revision);
        return Buffer.from(plaintext);
      } catch {
        try {
          const latest = await readState(ports.state, key, approval, digest);
          if (latest?.state.state === "reserved" && latest.state.operationId === operationId) {
            await replaceState(ports.state, key, latest, { state: "failed" }, ports.now());
          }
          await record("failed", observed, latest?.state.revision ?? reserved.revision);
        } catch { /* Failed audit/state cannot authorize release or replace a terminal tombstone. */ }
        throw new PrivateControlError();
      }
    } catch { throw new PrivateControlError(); }
    finally { plaintext?.fill(0); }
  }
  return { read, revoke };
}
