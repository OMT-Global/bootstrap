import {
  createCipheriv, createDecipheriv, createHash, createPrivateKey, createPublicKey,
  randomBytes, sign, verify, type JsonWebKey, type KeyObject
} from "node:crypto";
import { z } from "zod";
import {
  canonicalizeProvenanceJson, containsCredential, provenanceSigningKeyFingerprint,
  verifySignedPublicProvenance, type ProvenanceSigningPublicKey
} from "./provenance.js";

// Internal wire/crypto only: these functions establish no capture, storage, read, or signer authority.
export const PRIVATE_PROVENANCE_LIMITS = {
  input: 1_048_576, publicEnvelope: 65_536, envelope: 2_097_152, receipt: 16_384,
  text: 16_384, entries: 64, wrappedKey: 6_144
} as const;
export const BUNDLE_DOMAIN = "bootstrap-private-bundle";
export const RECEIPT_DOMAIN = "bootstrap-private-capture-receipt";
export const CANON = "sorted-json-v1";
export const RETENTION_MS = 90 * 86_400_000;
export const hash = (bytes: Uint8Array | string) => createHash("sha256").update(bytes).digest("hex");
export const canonical = (value: unknown) => Buffer.from(canonicalizeProvenanceJson(value), "utf8");
export const digestSchema = z.string().regex(/^[0-9a-f]{64}$/);
export const safeText = (maximum: number) => z.string().min(1).refine(
  (value) => Buffer.byteLength(value, "utf8") <= maximum && !containsCredential(value), "Invalid text."
);
export const timestamp = z.string().regex(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/).refine(
  (value) => Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value, "Invalid timestamp."
);
export const subjectSchema = z.object({
  repository: safeText(201).refine((value) => /^[^/\s]+\/[^/\s]+$/.test(value)),
  commitSha: z.string().regex(/^[0-9a-f]{40}$/)
}).strict();
const runId = safeText(128).refine((value) => /^[A-Za-z0-9._-]+$/.test(value));
const expectedSchema = subjectSchema.extend({ runId }).strict();
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
  header: headerSchema, nonce: base64(12, 12), ciphertext: base64(1, PRIVATE_PROVENANCE_LIMITS.input),
  tag: base64(16, 16), wrappedKey: base64(1, PRIVATE_PROVENANCE_LIMITS.wrappedKey)
}).strict();
export const storageSchema = z.object({
  region: z.literal("us-east-2"), bucket: safeText(63).refine((v) => /^[a-z0-9.-]+$/.test(v)),
  key: safeText(1_024), versionId: safeText(1_024)
}).strict();
export const retentionSchema = z.object({
  policyId: safeText(128).refine((v) => /^[A-Za-z0-9.-]+$/.test(v)),
  mode: z.literal("GOVERNANCE"), retainUntil: timestamp
}).strict();
export const receiptPayloadSchema = z.object({
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

export type PrivateProvenanceBinding = z.infer<typeof baseSchema>;
export type PrivateProvenanceEnvelope = z.infer<typeof envelopeSchema>;
export type PrivateProvenanceReceipt = z.infer<typeof receiptSchema>;
export interface PrivateProvenanceKeyContext { domain: typeof BUNDLE_DOMAIN; version: "1"; bindingSha256: string }
interface PrivateBindingOptions {
  signedPublicEnvelope: Uint8Array;
  expected: { repository: string; commitSha: string; runId: string };
  trustedPublicKeys: ReadonlyArray<ProvenanceSigningPublicKey>;
}
export interface PrivateEnvelopeExpectation {
  base: PrivateProvenanceBinding; kmsKeyArn: string; ciphertextEnvelopeSha256: string;
}
function assert(value: unknown): asserts value { if (!value) throw new Error("Invalid private provenance wire."); }
export function bounded(bytes: Uint8Array, maximum: number): Buffer {
  assert(bytes instanceof Uint8Array && bytes.byteLength > 0 && bytes.byteLength <= maximum);
  return Buffer.from(bytes);
}
export function parseCanonical(bytes: Uint8Array, maximum: number, depth: number): unknown {
  const copy = bounded(bytes, maximum);
  try {
    // Preserve a leading BOM so JSON parsing rejects it instead of silently normalizing wire bytes.
    const text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(copy);
    const value: unknown = JSON.parse(text);
    const pending = [{ value, depth: 1 }];
    while (pending.length) {
      const item = pending.pop()!;
      if (item.value && typeof item.value === "object") {
        assert(item.depth <= depth);
        for (const child of Object.values(item.value)) pending.push({ value: child, depth: item.depth + 1 });
      }
    }
    // String equality avoids allocating another mutable plaintext buffer for the round trip.
    assert(text === canonicalizeProvenanceJson(value));
    return value;
  } finally {
    copy.fill(0);
  }
}
export function privateProvenanceBinding(options: PrivateBindingOptions) {
  const expected = expectedSchema.parse(options.expected);
  const publicValue = parseCanonical(options.signedPublicEnvelope, PRIVATE_PROVENANCE_LIMITS.publicEnvelope, 8);
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
export function privateProvenanceKeyContext(base: z.infer<typeof baseSchema>): Readonly<PrivateProvenanceKeyContext> {
  return Object.freeze({ domain: BUNDLE_DOMAIN, version: "1", bindingSha256: hash(canonical(base)) });
}
export function privateReceiptSigningKey(jwk: JsonWebKey): KeyObject {
  const key = createPrivateKey({ key: jwk, format: "jwk" });
  assert(key.asymmetricKeyType === "ed25519");
  return key;
}
function fingerprint(key: KeyObject) {
  return provenanceSigningKeyFingerprint(createPublicKey(key).export({ format: "jwk" }) as ProvenanceSigningPublicKey);
}

export function encryptPrivateEnvelope(
  base: PrivateProvenanceBinding, keyArn: string, key: Buffer, wrapped: Uint8Array, plaintext: Buffer
): Buffer {
  assert(Buffer.isBuffer(key) && key.length === 32);
  assert(Buffer.isBuffer(plaintext) && plaintext.length > 0 && plaintext.length <= PRIVATE_PROVENANCE_LIMITS.input);
  const wrappedKey = bounded(wrapped, PRIVATE_PROVENANCE_LIMITS.wrappedKey);
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
  assert(bytes.length <= PRIVATE_PROVENANCE_LIMITS.envelope);
  return bytes;
}
export function signPrivateReceipt(payload: PrivateProvenanceReceipt["payload"], signingKey: KeyObject): Buffer {
  assert(signingKey.asymmetricKeyType === "ed25519");
  const checked = receiptPayloadSchema.parse(payload);
  const receipt = receiptSchema.parse({ payload: checked, signature: {
    keyFingerprint: fingerprint(signingKey), value: sign(null, canonical(checked), signingKey).toString("base64")
  } });
  const result = canonical(receipt);
  assert(result.length <= PRIVATE_PROVENANCE_LIMITS.receipt);
  return result;
}
export function verifyPrivateReceipt(
  bytes: Uint8Array, trustedReceiptKeys: ReadonlyArray<ProvenanceSigningPublicKey>, expectedBase: PrivateProvenanceBinding
): PrivateProvenanceReceipt {
  const base = baseSchema.parse(expectedBase);
  const receipt = receiptSchema.parse(parseCanonical(bytes, PRIVATE_PROVENANCE_LIMITS.receipt, 5));
  const trusted = trustedReceiptKeys.find((entry) => provenanceSigningKeyFingerprint(entry) === receipt.signature.keyFingerprint);
  assert(trusted && verify(null, canonical(receipt.payload), createPublicKey({ key: trusted, format: "jwk" }), Buffer.from(receipt.signature.value, "base64")));
  assert(receipt.payload.publicEnvelopeSha256 === base.publicEnvelopeSha256
    && receipt.payload.runId === base.runId && canonical(receipt.payload.subject).equals(canonical(base.subject)));
  return receipt;
}
export function parsePrivateEnvelope(bytes: Uint8Array, expected: PrivateEnvelopeExpectation): PrivateProvenanceEnvelope {
  const copy = bounded(bytes, PRIVATE_PROVENANCE_LIMITS.envelope);
  const base = baseSchema.parse(expected.base);
  assert(hash(copy) === digestSchema.parse(expected.ciphertextEnvelopeSha256));
  const envelope = envelopeSchema.parse(parseCanonical(copy, PRIVATE_PROVENANCE_LIMITS.envelope, 5));
  const { kmsKeyArn, wrappedKeySha256, ...envelopeBase } = envelope.header;
  assert(kmsKeyArn === expected.kmsKeyArn && canonical(envelopeBase).equals(canonical(base)));
  assert(hash(Buffer.from(envelope.wrappedKey, "base64")) === wrappedKeySha256);
  return envelope;
}
// Caller owns the returned plaintext and must clear it. No plaintext escapes before GCM final succeeds.
export function decryptPrivateEnvelope(bytes: Uint8Array, expected: PrivateEnvelopeExpectation, key: Buffer): Buffer {
  let partial: Buffer | undefined;
  let final: Buffer | undefined;
  try {
    assert(Buffer.isBuffer(key) && key.length === 32);
    const envelope = parsePrivateEnvelope(bytes, expected);
    const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(envelope.nonce, "base64"), { authTagLength: 16 });
    decipher.setAAD(canonical(envelope.header));
    decipher.setAuthTag(Buffer.from(envelope.tag, "base64"));
    partial = decipher.update(Buffer.from(envelope.ciphertext, "base64"));
    final = decipher.final();
    return Buffer.concat([partial, final]);
  } finally { partial?.fill(0); final?.fill(0); }
}
