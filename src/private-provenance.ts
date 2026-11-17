import { type JsonWebKey } from "node:crypto";
import { z } from "zod";
import { type ProvenanceSigningPublicKey } from "./provenance.js";
import {
  PRIVATE_PROVENANCE_LIMITS, BUNDLE_DOMAIN, RECEIPT_DOMAIN, CANON, RETENTION_MS,
  hash, canonical, digestSchema, safeText, timestamp, subjectSchema, storageSchema,
  retentionSchema, receiptPayloadSchema, bounded, parseCanonical,
  privateProvenanceBinding, privateProvenanceKeyContext as context, privateReceiptSigningKey,
  encryptPrivateEnvelope, signPrivateReceipt, verifyPrivateReceipt, parsePrivateEnvelope, decryptPrivateEnvelope,
  type PrivateProvenanceReceipt, type PrivateProvenanceEnvelope
} from "./private-provenance-codec.js";

// This library stage accepts fabricated fixtures and injected fakes only. It is not a production broker.
export const SYNTHETIC_PRIVATE_LIMITS = PRIVATE_PROVENANCE_LIMITS;
const inputSchema = z.object({
  schemaVersion: z.literal(1),
  evidence: z.array(z.object({
    category: z.literal("synthetic-fixture"), text: safeText(SYNTHETIC_PRIVATE_LIMITS.text)
  }).strict()).max(SYNTHETIC_PRIVATE_LIMITS.entries)
}).strict();
export type SyntheticPrivateInput = z.infer<typeof inputSchema>;
export type SyntheticPrivateStorage = z.infer<typeof storageSchema>;
export type SyntheticPrivateReceipt = PrivateProvenanceReceipt;
export type SyntheticPrivateEnvelope = PrivateProvenanceEnvelope;
export interface SyntheticKeyContext { domain: typeof BUNDLE_DOMAIN; version: "1"; bindingSha256: string }
export interface SyntheticKeyService {
  readonly syntheticOnly: true;
  // Ownership of returned plaintext buffers transfers to this module; fakes must retain independent copies.
  generate(keyArn: string, context: Readonly<SyntheticKeyContext>): Promise<{
    keyArn: string; plaintext: Buffer; wrappedKey: Uint8Array;
  }>;
  unwrap(keyArn: string, wrappedKey: Uint8Array, context: Readonly<SyntheticKeyContext>): Promise<Buffer>;
}
export interface SyntheticPrivateSink {
  readonly syntheticOnly: true;
  // Fakes must implement create-only writes and exact-version reads; no remote implementation is provided.
  put(bytes: Uint8Array, retention: Readonly<z.infer<typeof retentionSchema>>): Promise<SyntheticPrivateStorage>;
  inspect(storage: Readonly<SyntheticPrivateStorage>): Promise<{ sha256: string; mode: "GOVERNANCE"; retainUntil: string }>;
  get(storage: Readonly<SyntheticPrivateStorage>): Promise<Uint8Array>;
}
export interface SyntheticReadRequest {
  requester: string; purpose: string; approvalReference: string; now: string;
  storage: SyntheticPrivateStorage; subject: z.infer<typeof subjectSchema>; runId: string;
}
export interface SyntheticReadApproval {
  readonly syntheticOnly: true;
  // A trusted fake checks scoped synthetic approval, requester, purpose, exact version, and access window.
  verify(request: Readonly<SyntheticReadRequest>): Promise<true>;
}
export interface SyntheticPrivateAudit {
  readonly syntheticOnly: true;
  record(event: Readonly<{ phase: "attempt" | "complete" | "failed"; request: Readonly<SyntheticReadRequest> }>): Promise<true>;
}
interface SyntheticBindingOptions {
  syntheticOnly: true;
  signedPublicEnvelope: Uint8Array;
  expected: { repository: string; commitSha: string; runId: string };
  trustedPublicKeys: ReadonlyArray<ProvenanceSigningPublicKey>;
  kmsKeyArn: string;
}
export interface SyntheticCaptureOptions extends SyntheticBindingOptions {
  input: Uint8Array; capturedAt: string; retentionPolicyId: string; receiptPrivateKey: JsonWebKey;
}
export interface SyntheticReadOptions extends SyntheticBindingOptions {
  receipt: Uint8Array; trustedReceiptKeys: ReadonlyArray<ProvenanceSigningPublicKey>;
  requester: string; purpose: string; approvalReference: string; now: string;
}

function fail(): never { throw new Error("Invalid synthetic private provenance."); }
function assert(value: unknown): asserts value { if (!value) fail(); }
function assertSynthetic(...values: Array<{ syntheticOnly: true }>) {
  for (const value of values) assert(value.syntheticOnly === true);
}
function binding(options: SyntheticBindingOptions) {
  assertSynthetic(options);
  return privateProvenanceBinding(options);
}
function checkInspection(value: unknown, receipt: SyntheticPrivateReceipt["payload"]) {
  const checked = z.object({ sha256: digestSchema, mode: z.literal("GOVERNANCE"), retainUntil: timestamp }).strict().parse(value);
  assert(checked.sha256 === receipt.ciphertextEnvelopeSha256 && checked.mode === receipt.retention.mode
    && checked.retainUntil === receipt.retention.retainUntil);
}
function frozenRequest(request: SyntheticReadRequest): Readonly<SyntheticReadRequest> {
  return Object.freeze({ ...request, subject: Object.freeze({ ...request.subject }), storage: Object.freeze({ ...request.storage }) });
}

export async function captureSyntheticPrivateProvenance(
  options: SyntheticCaptureOptions,
  adapters: { keys: SyntheticKeyService; sink: SyntheticPrivateSink }
): Promise<Buffer> {
  let returnedKey: Buffer | undefined;
  let key: Buffer | undefined;
  let plaintext: Buffer | undefined;
  try {
    assertSynthetic(options, adapters.keys, adapters.sink);
    const base = binding(options);
    const input = inputSchema.parse(parseCanonical(options.input, SYNTHETIC_PRIVATE_LIMITS.input, 4));
    plaintext = canonical(input);
    assert(plaintext.length <= SYNTHETIC_PRIVATE_LIMITS.input);
    const keyArn = safeText(2_048).parse(options.kmsKeyArn);
    const capturedAt = timestamp.parse(options.capturedAt);
    const retainUntil = new Date(Date.parse(capturedAt) + RETENTION_MS).toISOString();
    const retention = retentionSchema.parse({ policyId: options.retentionPolicyId, mode: "GOVERNANCE", retainUntil });
    const signingKey = privateReceiptSigningKey(options.receiptPrivateKey);
    const generated = await adapters.keys.generate(keyArn, context(base));
    if (Buffer.isBuffer(generated.plaintext)) returnedKey = generated.plaintext;
    assert(returnedKey && returnedKey.length === 32 && generated.keyArn === keyArn);
    key = Buffer.from(returnedKey);
    const bytes = encryptPrivateEnvelope(base, keyArn, key, generated.wrappedKey, plaintext);
    const storage = storageSchema.parse(await adapters.sink.put(Buffer.from(bytes), Object.freeze({ ...retention })));
    const payload = receiptPayloadSchema.parse({
      domain: RECEIPT_DOMAIN, receiptVersion: 1, canonicalization: CANON, algorithm: "ed25519",
      subject: base.subject, runId: base.runId, publicEnvelopeSha256: base.publicEnvelopeSha256,
      ciphertextEnvelopeSha256: hash(bytes), storage, capturedAt, retention, signedAt: capturedAt
    });
    checkInspection(await adapters.sink.inspect(Object.freeze({ ...storage })), payload);
    return signPrivateReceipt(payload, signingKey);
  } catch {
    throw new Error("Synthetic private capture failed.");
  } finally {
    key?.fill(0); returnedKey?.fill(0); plaintext?.fill(0);
  }
}

export async function readSyntheticPrivateProvenance(
  options: SyntheticReadOptions,
  adapters: { keys: SyntheticKeyService; sink: SyntheticPrivateSink; approval: SyntheticReadApproval; audit: SyntheticPrivateAudit }
): Promise<SyntheticPrivateInput> {
  let returnedKey: Buffer | undefined;
  let key: Buffer | undefined;
  let plaintext: Buffer | undefined;
  let request: Readonly<SyntheticReadRequest> | undefined;
  let attempted = false;
  try {
    assertSynthetic(options, adapters.keys, adapters.sink, adapters.approval, adapters.audit);
    const base = binding(options);
    const keyArn = safeText(2_048).parse(options.kmsKeyArn);
    const receipt = verifyPrivateReceipt(options.receipt, options.trustedReceiptKeys, base);
    const now = timestamp.parse(options.now);
    assert(Date.parse(now) >= Date.parse(receipt.payload.signedAt) && Date.parse(now) < Date.parse(receipt.payload.retention.retainUntil));
    request = frozenRequest({
      requester: safeText(100).parse(options.requester), purpose: safeText(512).parse(options.purpose),
      approvalReference: safeText(512).parse(options.approvalReference), now,
      storage: receipt.payload.storage, subject: base.subject, runId: base.runId
    });
    assert(await adapters.approval.verify(request) === true);
    attempted = true;
    assert(await adapters.audit.record(Object.freeze({ phase: "attempt", request })) === true);
    checkInspection(await adapters.sink.inspect(request.storage), receipt.payload);
    const bytes = bounded(await adapters.sink.get(request.storage), SYNTHETIC_PRIVATE_LIMITS.envelope);
    const expectedEnvelope = { base, kmsKeyArn: keyArn, ciphertextEnvelopeSha256: receipt.payload.ciphertextEnvelopeSha256 };
    const envelope = parsePrivateEnvelope(bytes, expectedEnvelope);
    const wrappedKey = Buffer.from(envelope.wrappedKey, "base64");
    const unwrapped = await adapters.keys.unwrap(keyArn, Buffer.from(wrappedKey), context(base));
    if (Buffer.isBuffer(unwrapped)) returnedKey = unwrapped;
    assert(returnedKey && returnedKey.length === 32);
    key = Buffer.from(returnedKey);
    plaintext = decryptPrivateEnvelope(bytes, expectedEnvelope, key);
    const result = inputSchema.parse(parseCanonical(plaintext, SYNTHETIC_PRIVATE_LIMITS.input, 4));
    assert(await adapters.audit.record(Object.freeze({ phase: "complete", request })) === true);
    return result;
  } catch {
    if (attempted && request) {
      try { await adapters.audit.record(Object.freeze({ phase: "failed", request })); } catch { /* Preserve sanitized primary failure. */ }
    }
    throw new Error("Synthetic private read failed.");
  } finally {
    key?.fill(0); returnedKey?.fill(0); plaintext?.fill(0);
  }
}
