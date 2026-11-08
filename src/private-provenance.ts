import {
  createCipheriv, createDecipheriv, createHash, createPrivateKey, createPublicKey,
  randomBytes, sign, verify, type JsonWebKey, type KeyObject
} from "node:crypto";
import { z } from "zod";
import {
  canonicalizeProvenanceJson, containsCredential, provenanceSigningKeyFingerprint,
  verifySignedPublicProvenance, type ProvenanceSigningPublicKey
} from "./provenance.js";

// This library stage accepts fabricated fixtures and injected fakes only. It is not a production broker.
export const SYNTHETIC_PRIVATE_LIMITS = {
  input: 1_048_576, publicEnvelope: 65_536, envelope: 2_097_152, receipt: 16_384,
  text: 16_384, entries: 64, wrappedKey: 6_144
} as const;
const BUNDLE_DOMAIN = "bootstrap-private-bundle";
const RECEIPT_DOMAIN = "bootstrap-private-capture-receipt";
const CANON = "sorted-json-v1";
const RETENTION_MS = 90 * 86_400_000;
const hash = (bytes: Uint8Array | string) => createHash("sha256").update(bytes).digest("hex");
const canonical = (value: unknown) => Buffer.from(canonicalizeProvenanceJson(value), "utf8");
const digestSchema = z.string().regex(/^[0-9a-f]{64}$/);
const safeText = (maximum: number) => z.string().min(1).refine(
  (value) => Buffer.byteLength(value, "utf8") <= maximum && !containsCredential(value), "Invalid text."
);
const timestamp = z.string().regex(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/).refine(
  (value) => Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value, "Invalid timestamp."
);
const subjectSchema = z.object({
  repository: safeText(201).refine((value) => /^[^/\s]+\/[^/\s]+$/.test(value)),
  commitSha: z.string().regex(/^[0-9a-f]{40}$/)
}).strict();
const runId = safeText(128).refine((value) => /^[A-Za-z0-9._-]+$/.test(value));
const expectedSchema = subjectSchema.extend({ runId }).strict();
const inputSchema = z.object({
  schemaVersion: z.literal(1),
  evidence: z.array(z.object({
    category: z.literal("synthetic-fixture"), text: safeText(SYNTHETIC_PRIVATE_LIMITS.text)
  }).strict()).max(SYNTHETIC_PRIVATE_LIMITS.entries)
}).strict();
const baseShape = {
  domain: z.literal(BUNDLE_DOMAIN), envelopeVersion: z.literal(1), canonicalization: z.literal(CANON),
  algorithm: z.literal("aes-256-gcm"), subject: subjectSchema, runId, publicEnvelopeSha256: digestSchema
};
const baseSchema = z.object(baseShape).strict();
const headerSchema = z.object({
  ...baseShape, kmsKeyArn: safeText(2_048), wrappedKeySha256: digestSchema
}).strict();
const base64 = (minimum: number, maximum: number) => z.string().min(4).max(Math.ceil(maximum / 3) * 4).refine((value) => {
  const bytes = Buffer.from(value, "base64");
  return bytes.length >= minimum && bytes.length <= maximum && bytes.toString("base64") === value;
}, "Invalid Base64.");
const envelopeSchema = z.object({
  header: headerSchema, nonce: base64(12, 12), ciphertext: base64(1, SYNTHETIC_PRIVATE_LIMITS.input),
  tag: base64(16, 16), wrappedKey: base64(1, SYNTHETIC_PRIVATE_LIMITS.wrappedKey)
}).strict();
const storageSchema = z.object({
  region: z.literal("us-east-2"), bucket: safeText(63).refine((v) => /^[a-z0-9.-]+$/.test(v)),
  key: safeText(1_024), versionId: safeText(1_024)
}).strict();
const retentionSchema = z.object({
  policyId: safeText(128).refine((v) => /^[A-Za-z0-9.-]+$/.test(v)),
  mode: z.literal("GOVERNANCE"), retainUntil: timestamp
}).strict();
const receiptPayloadSchema = z.object({
  domain: z.literal(RECEIPT_DOMAIN), receiptVersion: z.literal(1), canonicalization: z.literal(CANON),
  algorithm: z.literal("ed25519"), subject: subjectSchema, runId, publicEnvelopeSha256: digestSchema,
  ciphertextEnvelopeSha256: digestSchema, storage: storageSchema, capturedAt: timestamp,
  retention: retentionSchema, signedAt: timestamp
}).strict().refine((value) => Date.parse(value.retention.retainUntil) >= Date.parse(value.capturedAt) + RETENTION_MS
  && Date.parse(value.signedAt) >= Date.parse(value.capturedAt), "Invalid receipt chronology.");
const receiptSchema = z.object({
  payload: receiptPayloadSchema,
  signature: z.object({ keyFingerprint: digestSchema, value: base64(64, 64) }).strict()
}).strict();

export type SyntheticPrivateInput = z.infer<typeof inputSchema>;
export type SyntheticPrivateStorage = z.infer<typeof storageSchema>;
export type SyntheticPrivateReceipt = z.infer<typeof receiptSchema>;
export type SyntheticPrivateEnvelope = z.infer<typeof envelopeSchema>;
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
  // A trusted fake checks authenticated jmcte approval, requester, purpose, exact version, and access window.
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
function bounded(bytes: Uint8Array, maximum: number): Buffer {
  assert(bytes instanceof Uint8Array && bytes.byteLength > 0 && bytes.byteLength <= maximum);
  return Buffer.from(bytes);
}
function parseCanonical(bytes: Uint8Array, maximum: number, depth: number): unknown {
  const copy = bounded(bytes, maximum);
  const text = new TextDecoder("utf-8", { fatal: true }).decode(copy);
  const value: unknown = JSON.parse(text);
  const pending = [{ value, depth: 1 }];
  while (pending.length) {
    const item = pending.pop()!;
    if (item.value && typeof item.value === "object") {
      assert(item.depth <= depth);
      for (const child of Object.values(item.value)) pending.push({ value: child, depth: item.depth + 1 });
    }
  }
  assert(copy.equals(canonical(value))); // Also rejects duplicate keys and noncanonical wire encodings.
  return value;
}
function binding(options: SyntheticBindingOptions) {
  assertSynthetic(options);
  const expected = expectedSchema.parse(options.expected);
  const publicValue = parseCanonical(options.signedPublicEnvelope, SYNTHETIC_PRIVATE_LIMITS.publicEnvelope, 8);
  const manifest = verifySignedPublicProvenance(publicValue, {
    trustedPublicKeys: options.trustedPublicKeys, expectedSubject: expected
  });
  assert(manifest.runId === expected.runId);
  return baseSchema.parse({
    domain: BUNDLE_DOMAIN, envelopeVersion: 1, canonicalization: CANON, algorithm: "aes-256-gcm",
    subject: { repository: expected.repository, commitSha: expected.commitSha }, runId: expected.runId,
    publicEnvelopeSha256: hash(canonical(publicValue))
  });
}
function context(base: z.infer<typeof baseSchema>): Readonly<SyntheticKeyContext> {
  return Object.freeze({ domain: BUNDLE_DOMAIN, version: "1", bindingSha256: hash(canonical(base)) });
}
function privateKey(jwk: JsonWebKey): KeyObject {
  const key = createPrivateKey({ key: jwk, format: "jwk" });
  assert(key.asymmetricKeyType === "ed25519");
  return key;
}
function fingerprint(key: KeyObject) {
  return provenanceSigningKeyFingerprint(createPublicKey(key).export({ format: "jwk" }) as ProvenanceSigningPublicKey);
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
    const signingKey = privateKey(options.receiptPrivateKey);
    const generated = await adapters.keys.generate(keyArn, context(base));
    if (Buffer.isBuffer(generated.plaintext)) returnedKey = generated.plaintext;
    assert(returnedKey && returnedKey.length === 32 && generated.keyArn === keyArn);
    key = Buffer.from(returnedKey);
    const wrappedKey = bounded(generated.wrappedKey, SYNTHETIC_PRIVATE_LIMITS.wrappedKey);
    const header = headerSchema.parse({ ...base, kmsKeyArn: keyArn, wrappedKeySha256: hash(wrappedKey) });
    const nonce = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", key, nonce, { authTagLength: 16 });
    cipher.setAAD(canonical(header));
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const envelope = envelopeSchema.parse({
      header, nonce: nonce.toString("base64"), ciphertext: ciphertext.toString("base64"),
      tag: cipher.getAuthTag().toString("base64"), wrappedKey: wrappedKey.toString("base64")
    });
    const bytes = canonical(envelope);
    assert(bytes.length <= SYNTHETIC_PRIVATE_LIMITS.envelope);
    const storage = storageSchema.parse(await adapters.sink.put(Buffer.from(bytes), Object.freeze({ ...retention })));
    const payload = receiptPayloadSchema.parse({
      domain: RECEIPT_DOMAIN, receiptVersion: 1, canonicalization: CANON, algorithm: "ed25519",
      subject: base.subject, runId: base.runId, publicEnvelopeSha256: base.publicEnvelopeSha256,
      ciphertextEnvelopeSha256: hash(bytes), storage, capturedAt, retention, signedAt: capturedAt
    });
    checkInspection(await adapters.sink.inspect(Object.freeze({ ...storage })), payload);
    const receipt = receiptSchema.parse({ payload, signature: {
      keyFingerprint: fingerprint(signingKey), value: sign(null, canonical(payload), signingKey).toString("base64")
    } });
    const result = canonical(receipt);
    assert(result.length <= SYNTHETIC_PRIVATE_LIMITS.receipt);
    return result;
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
  let partial: Buffer | undefined;
  let request: Readonly<SyntheticReadRequest> | undefined;
  let attempted = false;
  try {
    assertSynthetic(options, adapters.keys, adapters.sink, adapters.approval, adapters.audit);
    const base = binding(options);
    const keyArn = safeText(2_048).parse(options.kmsKeyArn);
    const receipt = receiptSchema.parse(parseCanonical(options.receipt, SYNTHETIC_PRIVATE_LIMITS.receipt, 5));
    const trusted = options.trustedReceiptKeys.find((entry) => provenanceSigningKeyFingerprint(entry) === receipt.signature.keyFingerprint);
    assert(trusted && verify(null, canonical(receipt.payload), createPublicKey({ key: trusted, format: "jwk" }), Buffer.from(receipt.signature.value, "base64")));
    assert(receipt.payload.publicEnvelopeSha256 === base.publicEnvelopeSha256
      && receipt.payload.runId === base.runId && canonical(receipt.payload.subject).equals(canonical(base.subject)));
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
    assert(hash(bytes) === receipt.payload.ciphertextEnvelopeSha256);
    const envelope = envelopeSchema.parse(parseCanonical(bytes, SYNTHETIC_PRIVATE_LIMITS.envelope, 5));
    const { kmsKeyArn, wrappedKeySha256, ...envelopeBase } = envelope.header;
    assert(kmsKeyArn === keyArn && canonical(envelopeBase).equals(canonical(base)));
    const wrappedKey = Buffer.from(envelope.wrappedKey, "base64");
    assert(hash(wrappedKey) === wrappedKeySha256);
    const unwrapped = await adapters.keys.unwrap(keyArn, Buffer.from(wrappedKey), context(base));
    if (Buffer.isBuffer(unwrapped)) returnedKey = unwrapped;
    assert(returnedKey && returnedKey.length === 32);
    key = Buffer.from(returnedKey);
    const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(envelope.nonce, "base64"), { authTagLength: 16 });
    decipher.setAAD(canonical(envelope.header));
    decipher.setAuthTag(Buffer.from(envelope.tag, "base64"));
    partial = decipher.update(Buffer.from(envelope.ciphertext, "base64"));
    plaintext = Buffer.concat([partial, decipher.final()]);
    const result = inputSchema.parse(parseCanonical(plaintext, SYNTHETIC_PRIVATE_LIMITS.input, 4));
    assert(await adapters.audit.record(Object.freeze({ phase: "complete", request })) === true);
    return result;
  } catch {
    if (attempted && request) {
      try { await adapters.audit.record(Object.freeze({ phase: "failed", request })); } catch { /* Preserve sanitized primary failure. */ }
    }
    throw new Error("Synthetic private read failed.");
  } finally {
    key?.fill(0); returnedKey?.fill(0); partial?.fill(0); plaintext?.fill(0);
  }
}
