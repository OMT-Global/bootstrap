import { createHash } from "node:crypto";
import { z } from "zod";
import { canonicalizeProvenanceJson, containsCredential } from "./provenance.js";

const MAX_ENVELOPE = 2_097_152;
const MAX_CIPHERTEXT = 1_048_576;
const RETENTION_MS = 90 * 86_400_000;
const OPERATION_MS = 30_000;
const sha256 = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest();
const safeText = (maximum: number) => z.string().min(1).refine(
  (value) => Buffer.byteLength(value) <= maximum && !containsCredential(value)
);
const timestamp = z.string().regex(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/).refine(
  (value) => Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value
);
const digest = z.string().regex(/^[0-9a-f]{64}$/);
const keyArn = safeText(2048).refine((value) => /^arn:aws:kms:us-east-2:\d{12}:key\/[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(value));
const captureId = z.string().regex(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
const bucket = safeText(63).refine((value) => /^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/.test(value)
  && !value.includes("..") && !/^\d+\.\d+\.\d+\.\d+$/.test(value) && !value.endsWith("--x-s3"));
const configSchema = z.object({
  region: z.literal("us-east-2"), bucket,
  prefix: safeText(800).refine((value) => /^(?:[A-Za-z0-9_-]+\/)+$/.test(value)),
  serviceKeyArn: keyArn
}).strict();
const versionId = safeText(1024).refine((value) => value !== "null");
const storageSchema = z.object({ region: z.literal("us-east-2"), bucket, key: safeText(1024), versionId }).strict();
const base64 = (minimum: number, maximum: number) => z.string().min(4).max(Math.ceil(maximum / 3) * 4).refine((value) => {
  const decoded = Buffer.from(value, "base64");
  return decoded.length >= minimum && decoded.length <= maximum && decoded.toString("base64") === value;
});
// The existing private envelope-v1 framing and bounds, without changing synthetic APIs.
const envelopeSchema = z.object({
  header: z.object({
    domain: z.literal("bootstrap-private-bundle"), envelopeVersion: z.literal(1),
    canonicalization: z.literal("sorted-json-v1"), algorithm: z.literal("aes-256-gcm"),
    subject: z.object({ repository: safeText(201).refine((v) => /^[^/\s]+\/[^/\s]+$/.test(v)), commitSha: z.string().regex(/^[0-9a-f]{40}$/) }).strict(),
    runId: safeText(128).refine((v) => /^[A-Za-z0-9._-]+$/.test(v)), publicEnvelopeSha256: digest,
    kmsKeyArn: safeText(2048), wrappedKeySha256: digest
  }).strict(),
  nonce: base64(12, 12), ciphertext: base64(1, MAX_CIPHERTEXT), tag: base64(16, 16), wrappedKey: base64(1, 6144)
}).strict();
const checksum = base64(32, 32);
const objectResponseShape = {
  statusCode: z.literal(200), VersionId: versionId, ChecksumSHA256: checksum,
  ChecksumType: z.literal("FULL_OBJECT"), ServerSideEncryption: z.literal("aws:kms"), SSEKMSKeyId: keyArn,
  BucketKeyEnabled: z.literal(false).optional()
};
const putResponse = z.object(objectResponseShape).strict();
const getResponse = z.object({
  ...objectResponseShape, ContentLength: z.number().int().min(1).max(MAX_ENVELOPE),
  Body: z.custom<AsyncIterable<Uint8Array>>((v) => v !== null && typeof v === "object" && typeof Reflect.get(v, Symbol.asyncIterator) === "function")
}).strict();
const retentionResponse = z.object({
  statusCode: z.literal(200), Retention: z.object({ Mode: z.literal("GOVERNANCE"), RetainUntilDate: timestamp }).strict()
}).strict();

export type PrivateCiphertextConfig = z.infer<typeof configSchema>;
export type PrivateCiphertextStorage = z.infer<typeof storageSchema>;
export type PrivateCaptureStorageIntent = { captureId: string; capturedAt: string; retainUntil: string };
export type PrivateCiphertextInspection = { sha256: string; mode: "GOVERNANCE"; retainUntil: string; sseKeyArn: string };
export type PrivatePutObjectRequest = Readonly<{
  Bucket: string; Key: string; Body: Uint8Array; ContentLength: number; ExpectedBucketOwner: string;
  IfNoneMatch: "*"; ChecksumAlgorithm: "SHA256"; ChecksumSHA256: string;
  ServerSideEncryption: "aws:kms"; SSEKMSKeyId: string; BucketKeyEnabled: false;
  ObjectLockMode: "GOVERNANCE"; ObjectLockRetainUntilDate: string;
}>;
export type PrivateGetObjectRequest = Readonly<{ Bucket: string; Key: string; VersionId: string; ExpectedBucketOwner: string; ChecksumMode: "ENABLED" }>;
export type PrivateGetRetentionRequest = Readonly<Omit<PrivateGetObjectRequest, "ChecksumMode">>;

/** Fixed trusted composition supplies authenticated AWS operations; no credential acquisition here.
 * Normalize only documented response fields, preserving rejection of ranges, multipart and delete markers.
 * Both operations and streaming bodies must honor AbortSignal. Do not retry writes in the transport.
 */
export interface PrivateCiphertextWriteTransport {
  readonly region: "us-east-2";
  putObject(request: PrivatePutObjectRequest, signal: AbortSignal): Promise<unknown>;
}
export interface PrivateCiphertextVerifyTransport {
  readonly region: "us-east-2";
  getObject(request: PrivateGetObjectRequest, signal: AbortSignal): Promise<unknown>;
  getObjectRetention(request: PrivateGetRetentionRequest, signal: AbortSignal): Promise<unknown>;
}
export class PrivateStorageError extends Error {
  constructor() { super("Private provenance storage unavailable or invalid."); }
}
function assert(value: unknown): asserts value { if (!value) throw new PrivateStorageError(); }
function envelope(bytes: Uint8Array, serviceKeyArn: string): Buffer {
  assert(bytes instanceof Uint8Array && bytes.length > 0 && bytes.length <= MAX_ENVELOPE);
  const owned = Buffer.from(bytes);
  const text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(owned);
  const value: unknown = JSON.parse(text);
  const pending = [{ value, depth: 1 }];
  while (pending.length) {
    const next = pending.pop()!;
    if (next.value !== null && typeof next.value === "object") {
      assert(next.depth <= 5);
      for (const child of Object.values(next.value)) pending.push({ value: child, depth: next.depth + 1 });
    }
  }
  assert(text === canonicalizeProvenanceJson(value));
  const parsed = envelopeSchema.parse(value);
  assert(parsed.header.kmsKeyArn !== serviceKeyArn);
  assert(sha256(Buffer.from(parsed.wrappedKey, "base64")).toString("hex") === parsed.header.wrappedKeySha256);
  return owned;
}
function configure(config: PrivateCiphertextConfig, region: unknown): PrivateCiphertextConfig {
  try {
    const parsed = configSchema.parse(config);
    assert(region === parsed.region);
    return Object.freeze(parsed);
  } catch { throw new PrivateStorageError(); }
}
async function boundedOperation<T>(work: (signal: AbortSignal) => Promise<T>): Promise<T> {
  const controller = new AbortController();
  let timeout: ReturnType<typeof setTimeout> | undefined;
  const deadline = new Promise<never>((_, reject) => {
    timeout = setTimeout(() => { controller.abort(); reject(new PrivateStorageError()); }, OPERATION_MS);
    timeout.unref();
  });
  try { return await Promise.race([work(controller.signal), deadline]); }
  catch { controller.abort(); throw new PrivateStorageError(); }
  finally { if (timeout) clearTimeout(timeout); }
}
function objectAddress(config: PrivateCiphertextConfig, storage: PrivateCiphertextStorage): PrivateGetRetentionRequest {
  const parsed = storageSchema.parse(storage);
  assert(parsed.region === config.region && parsed.bucket === config.bucket);
  assert(parsed.key.startsWith(config.prefix));
  captureId.parse(parsed.key.slice(config.prefix.length, -5));
  assert(parsed.key.endsWith(".json"));
  return Object.freeze({ Bucket: config.bucket, Key: parsed.key, VersionId: parsed.versionId, ExpectedBucketOwner: config.serviceKeyArn.split(":")[4]! });
}
async function readBody(body: AsyncIterable<Uint8Array>, size: number, signal: AbortSignal): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let total = 0;
  let count = 0;
  for await (const chunk of body) {
    assert(!signal.aborted && chunk instanceof Uint8Array && ++count <= 65_536);
    total += chunk.length;
    assert(total <= size && total <= MAX_ENVELOPE);
    chunks.push(Buffer.from(chunk));
  }
  assert(!signal.aborted && total === size);
  return Buffer.concat(chunks, total);
}

/** Returns only an unverified version locator. An upload is never a capture receipt. */
export function createPrivateCiphertextWriter(config: PrivateCiphertextConfig, transport: PrivateCiphertextWriteTransport) {
  let fixed: PrivateCiphertextConfig;
  let putObject: PrivateCiphertextWriteTransport["putObject"];
  try {
    const checked = z.object({ region: z.literal("us-east-2"), putObject: z.custom<PrivateCiphertextWriteTransport["putObject"]>((v) => typeof v === "function") }).strict().parse(transport);
    fixed = configure(config, checked.region);
    putObject = checked.putObject.bind(transport);
  } catch { throw new PrivateStorageError(); }
  return Object.freeze({
    async put(bytes: Uint8Array, intent: PrivateCaptureStorageIntent): Promise<PrivateCiphertextStorage> {
      return boundedOperation(async (signal) => {
        const admitted = z.object({ captureId, capturedAt: timestamp, retainUntil: timestamp }).strict().parse(intent);
        assert(Date.parse(admitted.retainUntil) >= Date.parse(admitted.capturedAt) + RETENTION_MS);
        const body = envelope(bytes, fixed.serviceKeyArn);
        const key = `${fixed.prefix}${admitted.captureId}.json`;
        const expectedChecksum = sha256(body).toString("base64");
        const request: PrivatePutObjectRequest = Object.freeze({
          Bucket: fixed.bucket, Key: key, Body: body, ContentLength: body.length,
          ExpectedBucketOwner: fixed.serviceKeyArn.split(":")[4]!, IfNoneMatch: "*",
          ChecksumAlgorithm: "SHA256", ChecksumSHA256: expectedChecksum, ServerSideEncryption: "aws:kms",
          SSEKMSKeyId: fixed.serviceKeyArn, BucketKeyEnabled: false,
          ObjectLockMode: "GOVERNANCE", ObjectLockRetainUntilDate: admitted.retainUntil
        });
        const result = putResponse.parse(await putObject(request, signal));
        assert(!signal.aborted && result.ChecksumSHA256 === expectedChecksum && result.SSEKMSKeyId === fixed.serviceKeyArn);
        return Object.freeze({ region: fixed.region, bucket: fixed.bucket, key, versionId: result.VersionId });
      });
    }
  });
}

/** Independently inspect exact ciphertext bytes/retention; cannot unwrap the client key. */
export function createPrivateCiphertextVerifier(config: PrivateCiphertextConfig, transport: PrivateCiphertextVerifyTransport) {
  let fixed: PrivateCiphertextConfig;
  let getObject: PrivateCiphertextVerifyTransport["getObject"];
  let getRetention: PrivateCiphertextVerifyTransport["getObjectRetention"];
  try {
    const checked = z.object({
      region: z.literal("us-east-2"),
      getObject: z.custom<PrivateCiphertextVerifyTransport["getObject"]>((v) => typeof v === "function"),
      getObjectRetention: z.custom<PrivateCiphertextVerifyTransport["getObjectRetention"]>((v) => typeof v === "function")
    }).strict().parse(transport);
    fixed = configure(config, checked.region);
    getObject = checked.getObject.bind(transport);
    getRetention = checked.getObjectRetention.bind(transport);
  } catch { throw new PrivateStorageError(); }
  return Object.freeze({
    async inspect(storage: PrivateCiphertextStorage): Promise<PrivateCiphertextInspection> {
      return boundedOperation(async (signal) => {
        const address = objectAddress(fixed, storage);
        const result = getResponse.parse(await getObject(Object.freeze({ ...address, ChecksumMode: "ENABLED" }), signal));
        assert(result.VersionId === address.VersionId && result.SSEKMSKeyId === fixed.serviceKeyArn);
        const body = envelope(await readBody(result.Body, result.ContentLength, signal), fixed.serviceKeyArn);
        const hash = sha256(body);
        assert(hash.toString("base64") === result.ChecksumSHA256);
        const retained = retentionResponse.parse(await getRetention(address, signal));
        assert(!signal.aborted);
        return Object.freeze({ sha256: hash.toString("hex"), mode: retained.Retention.Mode,
          retainUntil: retained.Retention.RetainUntilDate, sseKeyArn: result.SSEKMSKeyId });
      });
    }
  });
}
