import { createHash } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import { canonicalizeProvenanceJson } from "../src/provenance.js";
import {
  createPrivateCiphertextVerifier, createPrivateCiphertextWriter, PrivateStorageError,
  type PrivateCiphertextConfig, type PrivateCiphertextStorage,
  type PrivateCiphertextVerifyTransport, type PrivateCiphertextWriteTransport,
  type PrivateGetObjectRequest, type PrivateGetRetentionRequest, type PrivatePutObjectRequest
} from "../src/private-provenance-storage.js";

const wire = (value: unknown) => Buffer.from(canonicalizeProvenanceJson(value));
const hash = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest();
const capturedAt = "2026-11-15T12:00:00.000Z";
const retainUntil = new Date(Date.parse(capturedAt) + 90 * 86_400_000).toISOString();
const captureId = "12345678-1234-4123-8123-123456789abc";
const versionId = "fabricated-version-1";
const marker = "private-provider-error-must-not-escape";
const config: PrivateCiphertextConfig = {
  region: "us-east-2", bucket: "fabricated-evidence-bucket", prefix: "payloads/captures/",
  serviceKeyArn: "arn:aws:kms:us-east-2:123456789012:key/12345678-1234-4123-8123-123456789abc"
};
const fixtureEnvelope = () => {
  const wrapped = Buffer.alloc(32, 8);
  return {
    header: {
      domain: "bootstrap-private-bundle", envelopeVersion: 1, canonicalization: "sorted-json-v1", algorithm: "aes-256-gcm",
      subject: { repository: "fabricated/repository", commitSha: "a".repeat(40) }, runId: "gh-123-1",
      publicEnvelopeSha256: "b".repeat(64), kmsKeyArn: "arn:aws:kms:us-east-2:123456789012:key/22345678-1234-4123-8123-123456789abc",
      wrappedKeySha256: hash(wrapped).toString("hex")
    },
    nonce: Buffer.alloc(12, 1).toString("base64"), ciphertext: Buffer.alloc(40, 2).toString("base64"),
    tag: Buffer.alloc(16, 3).toString("base64"), wrappedKey: wrapped.toString("base64")
  };
};
async function* bodyOf(bytes: Uint8Array) { yield bytes.slice(0, 11); yield bytes.slice(11); }
function fixture() {
  const bytes = wire(fixtureEnvelope());
  const storage: PrivateCiphertextStorage = { region: config.region, bucket: config.bucket, key: `${config.prefix}${captureId}.json`, versionId };
  const common = () => ({ statusCode: 200, VersionId: versionId, ChecksumSHA256: hash(bytes).toString("base64"),
    ChecksumType: "FULL_OBJECT", ServerSideEncryption: "aws:kms", SSEKMSKeyId: config.serviceKeyArn });
  const putObject = vi.fn(async (_request: PrivatePutObjectRequest, _signal: AbortSignal): Promise<unknown> => common());
  const getObject = vi.fn(async (_request: PrivateGetObjectRequest, _signal: AbortSignal): Promise<unknown> => ({ ...common(), ContentLength: bytes.length, Body: bodyOf(bytes) }));
  const getObjectRetention = vi.fn(async (_request: PrivateGetRetentionRequest, _signal: AbortSignal): Promise<unknown> => ({ statusCode: 200, Retention: { Mode: "GOVERNANCE", RetainUntilDate: retainUntil } }));
  const writeTransport: PrivateCiphertextWriteTransport = { region: "us-east-2", putObject };
  const verifyTransport: PrivateCiphertextVerifyTransport = { region: "us-east-2", getObject, getObjectRetention };
  return { bytes, storage, common, putObject, getObject, getObjectRetention, writeTransport, verifyTransport,
    write: (input = bytes, intent = { captureId, capturedAt, retainUntil }) => createPrivateCiphertextWriter(config, writeTransport).put(input, intent),
    inspect: (input = storage) => createPrivateCiphertextVerifier(config, verifyTransport).inspect(input) };
}
afterEach(() => vi.useRealTimers());

describe("private ciphertext writer", () => {
  it("creates only ciphertext with fixed versioned encryption, checksum and retention requests", async () => {
    const f = fixture();
    expect(await f.write()).toEqual(f.storage);
    const [request, signal] = f.putObject.mock.calls[0]!;
    expect(request).toEqual({ Bucket: config.bucket, Key: f.storage.key, Body: f.bytes, ContentLength: f.bytes.length,
      ExpectedBucketOwner: "123456789012", IfNoneMatch: "*", ChecksumAlgorithm: "SHA256", ChecksumSHA256: hash(f.bytes).toString("base64"),
      ServerSideEncryption: "aws:kms", SSEKMSKeyId: config.serviceKeyArn, BucketKeyEnabled: false,
      ObjectLockMode: "GOVERNANCE", ObjectLockRetainUntilDate: retainUntil });
    expect(signal.aborted).toBe(false);
    expect(f.getObject).not.toHaveBeenCalled();
  });
  it("takes an owned snapshot of input bytes and installed configuration", async () => {
    const f = fixture(); const installed = { ...config };
    const writer = createPrivateCiphertextWriter(installed, f.writeTransport);
    installed.bucket = "other-bucket";
    f.putObject.mockImplementationOnce(async (request) => {
      f.bytes.fill(0);
      return { ...f.common(), ChecksumSHA256: hash(request.Body).toString("base64") };
    });
    expect(await writer.put(f.bytes, { captureId, capturedAt, retainUntil })).toEqual(f.storage);
  });
  it.each([
    ["unknown field", (v: any) => { v.extra = "unexpected"; }],
    ["unknown header field", (v: any) => { v.header.extra = "unexpected"; }],
    ["wrong algorithm", (v: any) => { v.header.algorithm = "plaintext"; }],
    ["wrong domain", (v: any) => { v.header.domain = "another-protocol"; }],
    ["wrong nonce length", (v: any) => { v.nonce = Buffer.alloc(11).toString("base64"); }],
    ["wrong tag length", (v: any) => { v.tag = Buffer.alloc(17).toString("base64"); }],
    ["noncanonical base64", (v: any) => { v.wrappedKey += "\n"; }],
    ["wrong wrapped-key digest", (v: any) => { v.header.wrappedKeySha256 = "f".repeat(64); }],
    ["same client/service key", (v: any) => { v.header.kmsKeyArn = config.serviceKeyArn; }],
    ["empty ciphertext", (v: any) => { v.ciphertext = ""; }],
    ["oversized decoded ciphertext", (v: any) => { v.ciphertext = Buffer.alloc(1_048_577).toString("base64"); }],
    ["credential-shaped identity", (v: any) => { v.header.runId = ["ghp", "a".repeat(40)].join("_"); }]
  ])("rejects %s before any provider operation", async (_name, change) => {
    const f = fixture(); const value = fixtureEnvelope(); change(value);
    await expect(f.write(wire(value))).rejects.toThrow(PrivateStorageError);
    expect(f.putObject).not.toHaveBeenCalled();
  });
  it.each([
    Buffer.from('{"schemaVersion":1,"evidence":[{"category":"decision-summary","text":"plaintext"}]}'),
    Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), wire(fixtureEnvelope())]),
    Buffer.concat([wire(fixtureEnvelope()), Buffer.from("\n")]),
    Buffer.from([0xff, 0xfe]), Buffer.alloc(2_097_153),
    Buffer.from('{"header":1,"header":2}')
  ])("rejects non-envelope/noncanonical bytes without upload", async (bytes) => {
    const f = fixture(); await expect(f.write(bytes)).rejects.toThrow(PrivateStorageError); expect(f.putObject).not.toHaveBeenCalled();
  });
  it.each([
    { captureId: "../escape", capturedAt, retainUntil },
    { captureId, capturedAt: "2026-02-30T00:00:00.000Z", retainUntil },
    { captureId, capturedAt, retainUntil: new Date(Date.parse(retainUntil) - 1).toISOString() },
    { captureId, capturedAt, retainUntil, extra: true }
  ])("rejects an invalid capture intent before upload", async (intent) => {
    const f = fixture(); await expect(f.write(f.bytes, intent)).rejects.toThrow(PrivateStorageError); expect(f.putObject).not.toHaveBeenCalled();
  });
  it.each([409, 412, 500, "timeout"])("does not retry an ambiguous/failed upload: %s", async (code) => {
    const f = fixture(); f.putObject.mockRejectedValueOnce(new Error(`${marker}:${code}`));
    await expect(f.write()).rejects.toThrow(/^Private provenance storage unavailable or invalid\.$/);
    expect(f.putObject).toHaveBeenCalledTimes(1); expect(f.getObject).not.toHaveBeenCalled();
  });
  it.each([
    { VersionId: undefined }, { VersionId: "null" }, { statusCode: 206 }, { ChecksumSHA256: Buffer.alloc(32).toString("base64") },
    { ChecksumType: "COMPOSITE" }, { SSEKMSKeyId: config.serviceKeyArn.replace("12345678", "22345678") },
    { ServerSideEncryption: "AES256" }, { BucketKeyEnabled: true }, { unexpected: marker }
  ])("withholds a locator for invalid upload response %j", async (change) => {
    const f = fixture(); f.putObject.mockResolvedValueOnce({ ...f.common(), ...change });
    await expect(f.write()).rejects.toThrow(/^Private provenance storage unavailable or invalid\.$/);
    expect(f.putObject).toHaveBeenCalledTimes(1);
  });
  it("preserves the existing maximum decoded ciphertext bound", async () => {
    const f = fixture(); const value = fixtureEnvelope(); value.ciphertext = Buffer.alloc(1_048_576).toString("base64");
    f.putObject.mockImplementationOnce(async (request) => ({ ...f.common(), ChecksumSHA256: request.ChecksumSHA256 }));
    await expect(f.write(wire(value))).resolves.toEqual(f.storage);
  });
  it("aborts an unacknowledged write at its deadline without retry", async () => {
    vi.useFakeTimers(); const f = fixture(); f.putObject.mockImplementationOnce(async () => new Promise(() => {}));
    const pending = expect(f.write()).rejects.toThrow(PrivateStorageError);
    await vi.advanceTimersByTimeAsync(30_000); await pending;
    expect(f.putObject.mock.calls[0]![1].aborted).toBe(true); expect(f.putObject).toHaveBeenCalledTimes(1);
  });
});

describe("private ciphertext verifier", () => {
  it("hashes complete exact-version bytes and obtains retention independently", async () => {
    const f = fixture();
    expect(await f.inspect()).toEqual({ sha256: hash(f.bytes).toString("hex"), mode: "GOVERNANCE", retainUntil, sseKeyArn: config.serviceKeyArn });
    expect(f.getObject.mock.calls[0]![0]).toEqual({ Bucket: config.bucket, Key: f.storage.key, VersionId: versionId, ExpectedBucketOwner: "123456789012", ChecksumMode: "ENABLED" });
    expect(f.getObjectRetention.mock.calls[0]![0]).toEqual({ Bucket: config.bucket, Key: f.storage.key, VersionId: versionId, ExpectedBucketOwner: "123456789012" });
    expect(f.putObject).not.toHaveBeenCalled();
  });
  it.each([
    { region: "us-west-2" }, { bucket: "another-bucket" }, { key: `other/${captureId}.json` },
    { key: `${config.prefix}../${captureId}.json` }, { key: `${config.prefix}${captureId}.json.extra` },
    { versionId: "null" }, { versionId: "" }, { unknown: marker }
  ])("rejects a wrong or incomplete exact-version locator %j", async (change) => {
    const f = fixture(); await expect(f.inspect({ ...f.storage, ...change } as PrivateCiphertextStorage)).rejects.toThrow(PrivateStorageError);
    expect(f.getObject).not.toHaveBeenCalled(); expect(f.getObjectRetention).not.toHaveBeenCalled();
  });
  it.each([
    { VersionId: "different-version" }, { ChecksumSHA256: Buffer.alloc(32).toString("base64") },
    { ChecksumType: "COMPOSITE" }, { BucketKeyEnabled: true }, { ContentRange: "bytes 0-9/100" }, { PartsCount: 2 }, { DeleteMarker: true },
    { statusCode: 206 }, { ContentLength: 2_097_153 }, { ServerSideEncryption: "AES256" },
    { SSEKMSKeyId: config.serviceKeyArn.replace("12345678", "22345678") }
  ])("rejects invalid download evidence %j", async (change) => {
    const f = fixture(); f.getObject.mockResolvedValueOnce({ ...f.common(), ContentLength: f.bytes.length, Body: bodyOf(f.bytes), ...change });
    await expect(f.inspect()).rejects.toThrow(PrivateStorageError); expect(f.getObjectRetention).not.toHaveBeenCalled();
  });
  it("detects corrupted bytes even when metadata claims the expected checksum", async () => {
    const f = fixture(); const altered = fixtureEnvelope(); altered.header.runId = "other-run";
    const bytes = wire(altered);
    f.getObject.mockResolvedValueOnce({ ...f.common(), ContentLength: bytes.length, Body: bodyOf(bytes) });
    await expect(f.inspect()).rejects.toThrow(PrivateStorageError); expect(f.getObjectRetention).not.toHaveBeenCalled();
  });
  it.each(["truncated", "oversized", "wrong-chunk-type", "stream-error"])("rejects %s body and cancels the operation", async (kind) => {
    const f = fixture();
    const body = (async function* () {
      if (kind === "truncated") { yield f.bytes.subarray(0, -1); return; }
      if (kind === "oversized") { yield Buffer.alloc(f.bytes.length + 1); return; }
      if (kind === "wrong-chunk-type") { yield marker as unknown as Uint8Array; return; }
      throw new Error(marker);
    })();
    f.getObject.mockResolvedValueOnce({ ...f.common(), ContentLength: f.bytes.length, Body: body });
    await expect(f.inspect()).rejects.toThrow(/^Private provenance storage unavailable or invalid\.$/);
    expect(f.getObjectRetention).not.toHaveBeenCalled(); expect(f.getObject.mock.calls[0]![1].aborted).toBe(true);
  });
  it("bounds a stalled body independently of provider cooperation", async () => {
    vi.useFakeTimers(); const f = fixture();
    const body = { async *[Symbol.asyncIterator]() { await new Promise(() => {}); yield Buffer.alloc(1); } };
    f.getObject.mockResolvedValueOnce({ ...f.common(), ContentLength: f.bytes.length, Body: body });
    const pending = expect(f.inspect()).rejects.toThrow(PrivateStorageError);
    await vi.advanceTimersByTimeAsync(30_000); await pending;
    expect(f.getObject.mock.calls[0]![1].aborted).toBe(true); expect(f.getObjectRetention).not.toHaveBeenCalled();
  });
  it.each([
    { statusCode: 500, Retention: { Mode: "GOVERNANCE", RetainUntilDate: retainUntil } },
    { statusCode: 200, Retention: { Mode: "COMPLIANCE", RetainUntilDate: retainUntil } },
    { statusCode: 200, Retention: { Mode: "GOVERNANCE", RetainUntilDate: "invalid" } },
    { statusCode: 200, Retention: { Mode: "GOVERNANCE", RetainUntilDate: retainUntil, EventHold: "ON" } }
  ])("rejects invalid independent retention evidence %j", async (response) => {
    const f = fixture(); f.getObjectRetention.mockResolvedValueOnce(response);
    await expect(f.inspect()).rejects.toThrow(PrivateStorageError);
  });
  it("returns an observed shorter date for the receipt consumer to reject, not a fabricated compliance pass", async () => {
    const f = fixture(); const shortDate = new Date(Date.parse(retainUntil) - 86_400_000).toISOString();
    f.getObjectRetention.mockResolvedValueOnce({ statusCode: 200, Retention: { Mode: "GOVERNANCE", RetainUntilDate: shortDate } });
    expect((await f.inspect()).retainUntil).toBe(shortDate);
  });
});

describe("trusted storage composition boundaries", () => {
  it.each([
    { region: "us-west-2" }, { bucket: "${BUCKET}" }, { prefix: "../payloads/" }, { prefix: "payloads" },
    { serviceKeyArn: "alias/not-an-immutable-key" }, { serviceKeyArn: config.serviceKeyArn.replace("us-east-2", "us-west-2") },
    { credentials: marker }
  ])("requires an exact supported deployment configuration %j", (change) => {
    const f = fixture(); const invalid = { ...config, ...change } as PrivateCiphertextConfig;
    expect(() => createPrivateCiphertextWriter(invalid, f.writeTransport)).toThrow(PrivateStorageError);
    expect(() => createPrivateCiphertextVerifier(invalid, f.verifyTransport)).toThrow(PrivateStorageError);
  });
  it("rejects mixed-role and wrong-region ports without invoking them", () => {
    const f = fixture();
    expect(() => createPrivateCiphertextWriter(config, { ...f.writeTransport, ...f.verifyTransport })).toThrow(PrivateStorageError);
    expect(() => createPrivateCiphertextVerifier(config, { ...f.writeTransport, ...f.verifyTransport })).toThrow(PrivateStorageError);
    expect(() => createPrivateCiphertextWriter(config, { ...f.writeTransport, region: "us-west-2" } as any)).toThrow(PrivateStorageError);
    expect(() => createPrivateCiphertextVerifier(config, { ...f.verifyTransport, getObjectRetention: true } as any)).toThrow(PrivateStorageError);
  });
  it("sanitizes malicious accessor and provider failures", async () => {
    const f = fixture();
    expect(() => createPrivateCiphertextWriter(config, { get region() { throw new Error(marker); }, putObject: f.putObject } as any)).toThrow(/^Private provenance storage unavailable or invalid\.$/);
    f.getObject.mockRejectedValueOnce(new Error(marker));
    await expect(f.inspect()).rejects.toThrow(/^Private provenance storage unavailable or invalid\.$/);
    f.getObjectRetention.mockRejectedValueOnce(new Error(marker));
    await expect(f.inspect()).rejects.toThrow(/^Private provenance storage unavailable or invalid\.$/);
  });
});
