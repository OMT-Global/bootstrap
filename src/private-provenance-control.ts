import { createHash, createPublicKey, verify } from "node:crypto";
import { z } from "zod";
import { canonicalizeProvenanceJson, containsCredential, provenanceSigningKeyFingerprint } from "./provenance.js";

export class PrivateControlError extends Error {
  constructor() { super("Private provenance control unavailable or invalid."); }
}
export const controlId = z.string().regex(/^[A-Za-z0-9._-]{1,128}$/);
export const controlDigest = z.string().regex(/^[0-9a-f]{64}$/);
export const controlTime = z.string().regex(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/).refine(
  (v) => Number.isFinite(Date.parse(v)) && new Date(v).toISOString() === v
);
export const controlCounter = z.number().int().nonnegative().safe();
export const controlText = (max: number) => z.string().min(1).refine(
  (v) => Buffer.byteLength(v) <= max && !containsCredential(v)
);
export const controlSubject = z.object({
  repository: controlText(201).refine((v) => /^[^/\s]+\/[^/\s]+$/.test(v)),
  commitSha: z.string().regex(/^[0-9a-f]{40}$/)
}).strict();
export const controlStorage = z.object({
  region: z.literal("us-east-2"), bucket: controlText(63).refine((v) => /^[a-z0-9.-]+$/.test(v)),
  key: controlText(1024), versionId: controlText(1024)
}).strict();
export const controlCategory = z.enum(["decision-summary", "review-summary", "validation-summary"]);
export const controlPurpose = z.enum(["security-investigation", "provenance-verification", "incident-recovery"]);
export const controlSet = <T extends z.ZodType>(item: T, max = 64) => z.array(item).min(1).max(max).refine(
  (v) => new Set(v).size === v.length
);
export const controlBase = (domain: string) => ({ domain: z.literal(domain), version: z.literal(1), canonicalization: z.literal("sorted-json-v1") });
export const controlWire = (v: unknown): Buffer => Buffer.from(canonicalizeProvenanceJson(v), "utf8");
export const controlHash = (v: Uint8Array): string => createHash("sha256").update(v).digest("hex");
export function requireControl(ok: unknown): asserts ok { if (!ok) throw new PrivateControlError(); }

/** Bounded canonical bytes reject duplicate keys, BOM, invalid UTF-8 and noncanonical encoding. */
export function parsePrivateControl(bytes: Uint8Array, maximum = 16_384, depth = 6): unknown {
  try {
    requireControl(bytes instanceof Uint8Array && bytes.byteLength > 0 && bytes.byteLength <= maximum);
    const text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
    const value: unknown = JSON.parse(text);
    const pending = [{ value, level: 1 }];
    while (pending.length) {
      const next = pending.pop()!;
      if (typeof next.value === "string") requireControl(!containsCredential(next.value));
      if (next.value !== null && typeof next.value === "object") {
        requireControl(next.level <= depth);
        for (const child of Object.values(next.value)) pending.push({ value: child, level: next.level + 1 });
      }
    }
    requireControl(text === canonicalizeProvenanceJson(value));
    return value;
  } catch { throw new PrivateControlError(); }
}
const publicKey = z.object({ kty: z.literal("OKP"), crv: z.literal("Ed25519"), x: z.string().regex(/^[A-Za-z0-9_-]{43}$/).refine((value) => {
  const bytes = Buffer.from(value, "base64url");
  return bytes.length === 32 && bytes.toString("base64url") === value;
}) }).strict();
const keySchema = z.object({
  ownerId: controlId, purpose: z.enum(["deployment-root", "requester-request", "codex-read-approval", "audit-ack"]),
  publicKey, notBefore: controlTime, notAfter: controlTime, revoked: z.boolean()
}).strict();
export type PrivateControlKey = z.infer<typeof keySchema>;
const signature = z.object({ keyFingerprint: controlDigest, value: z.string().regex(/^[A-Za-z0-9+/]{86}==$/) }).strict();

/** Keys/time are installed runtime trust, never an embedded key or requester assertion. */
export function verifyPrivateControl<S extends z.ZodType>(
  bytes: Uint8Array, payloadSchema: S, purpose: PrivateControlKey["purpose"], keys: readonly PrivateControlKey[], now: Date
): { payload: z.output<S>; ownerId: string; fingerprint: string; sha256: string } {
  try {
    const parsed = z.object({ payload: z.unknown(), signature }).strict().parse(parsePrivateControl(bytes));
    const payload = payloadSchema.parse(parsed.payload);
    const ring = z.array(keySchema).min(1).max(64).parse(keys);
    const fingerprints = ring.map((key) => provenanceSigningKeyFingerprint(key.publicKey));
    requireControl(new Set(fingerprints).size === ring.length && Number.isFinite(now.getTime()));
    const index = fingerprints.indexOf(parsed.signature.keyFingerprint);
    const key = ring[index];
    requireControl(key && key.purpose === purpose && !key.revoked && Date.parse(key.notBefore) <= now.getTime()
      && now.getTime() < Date.parse(key.notAfter));
    const bytesOfSignature = Buffer.from(parsed.signature.value, "base64");
    requireControl(bytesOfSignature.length === 64 && bytesOfSignature.toString("base64") === parsed.signature.value);
    requireControl(verify(null, controlWire(parsed.payload), createPublicKey({ key: key.publicKey, format: "jwk" }), bytesOfSignature));
    return { payload, ownerId: key.ownerId, fingerprint: parsed.signature.keyFingerprint, sha256: controlHash(bytes) };
  } catch { throw new PrivateControlError(); }
}
