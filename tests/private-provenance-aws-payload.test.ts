import { createHash } from "node:crypto";
import { PassThrough, Readable } from "node:stream";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { controlWire } from "../src/private-provenance-control.js";
import {
  disposePrivateRoleIdentity, inspectPrivateRoleCiphertext, putPrivateRoleCiphertext
} from "../src/private-provenance-identity.js";
import { capturedAt, captureId, intent, now, payloadHarness, retainUntil } from "./helpers/private-provenance-aws-fixture.js";

const hash = (b: Uint8Array) => createHash("sha256").update(b).digest();
const marker = "private-provider-detail-must-not-escape";
const denied = (value: Promise<unknown>) => expect(value).rejects.toThrow("Private provenance identity unavailable or invalid.");
const deferred = <T>() => {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => { resolve = done; });
  return { promise, resolve };
};
beforeEach(() => { vi.useFakeTimers({ toFake: ["Date"] }); vi.setSystemTime(now); });
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); vi.unstubAllEnvs(); vi.useRealTimers(); });

describe("fixed AWS private payload operations", () => {
  it("binds a write to a separately scoped owned session and only returns an unverified locator", async () => {
    const h = await payloadHarness(); const identity = await h.start();
    expect(await putPrivateRoleCiphertext(identity, h.bytes, intent)).toEqual(h.storage);
    const [put] = h.payloadCalls(); expect(h.payloadCalls()).toHaveLength(1);
    expect(put.kind).toBe("PutObjectCommand");
    expect(put.input).toEqual({ Bucket: "fabricated-payload", Key: h.storage.key, Body: h.bytes,
      ContentLength: h.bytes.length, ExpectedBucketOwner: "123456789012", IfNoneMatch: "*", ChecksumAlgorithm: "SHA256",
      ChecksumSHA256: hash(h.bytes).toString("base64"), ServerSideEncryption: "aws:kms", SSEKMSKeyId: h.f.binding.aws.keys.serviceArn,
      BucketKeyEnabled: false, ObjectLockMode: "GOVERNANCE", ObjectLockRetainUntilDate: new Date(retainUntil) });
    expect(h.stsCalls).toHaveLength(2);
    const policy = JSON.parse(h.stsCalls[1].input.Policy);
    const statements = policy.Statement; const objectArn = `arn:aws:s3:::fabricated-payload/${h.storage.key}`;
    expect(statements.find((s: any) => [s.Action].flat().includes("s3:PutObject"))).toMatchObject({ Resource: objectArn });
    expect(statements.find((s: any) => [s.Action].flat().includes("kms:GenerateDataKey"))).toMatchObject({
      Resource: h.f.binding.aws.keys.serviceArn, Condition: { StringEquals: {
        "kms:ViaService": "s3.us-east-2.amazonaws.com", "kms:EncryptionContext:aws:s3:arn": objectArn } } });
    const payloadStatements = statements.filter((s: any) => s.Resource === objectArn
      || s.Condition?.StringEquals?.["kms:EncryptionContext:aws:s3:arn"] === objectArn);
    expect(JSON.stringify(payloadStatements)).not.toMatch(/s3:GetObject|kms:Decrypt|Delete|Bypass|ListBucket|\*\//);
    expect(statements.find((s: any) => s.Action === "s3:GetObject")).toMatchObject({ Resource: "arn:aws:s3:::fabricated-config/config/active.json" });
    expect(statements.find((s: any) => s.Action === "kms:Decrypt")).toMatchObject({ Resource: h.f.binding.aws.keys.serviceArn,
      Condition: { StringEquals: { "kms:EncryptionContext:aws:s3:arn": "arn:aws:s3:::fabricated-config/config/active.json" } } });
    expect(JSON.stringify(policy)).not.toContain(h.f.binding.aws.keys.clientArn);
    expect(h.stsCalls[1].input.WebIdentityToken).toBe(h.token);
    expect(await put.config.credentials()).toMatchObject({ accessKeyId: "fabricated-access-2" });
    expect(await put.config.maxAttempts()).toBe(1); expect(await h.stsCalls[1].config.maxAttempts()).toBe(1);
    expect(h.s3Calls.filter((c) => c.input.Bucket === "fabricated-config").length).toBeGreaterThanOrEqual(3);
    expect(Object.keys(identity).sort()).toEqual(["expiresAt", "purpose", "workloadId"]);
    disposePrivateRoleIdentity(identity);
  });

  it("verifies actual complete ciphertext plus retention under an exact-version read-only session", async () => {
    const h = await payloadHarness("ciphertext-verifier"); const identity = await h.start();
    expect(await inspectPrivateRoleCiphertext(identity, h.storage, capturedAt)).toEqual({ sha256: hash(h.bytes).toString("hex"),
      mode: "GOVERNANCE", retainUntil, sseKeyArn: h.f.binding.aws.keys.serviceArn });
    expect(h.payloadCalls().map((c) => c.kind)).toEqual(["GetObjectCommand", "GetObjectRetentionCommand"]);
    const [get, retention] = h.payloadCalls();
    expect(get.input).toEqual({ Bucket: h.storage.bucket, Key: h.storage.key, VersionId: h.storage.versionId,
      ExpectedBucketOwner: "123456789012", ChecksumMode: "ENABLED" });
    expect(retention.input).toEqual({ Bucket: h.storage.bucket, Key: h.storage.key, VersionId: h.storage.versionId, ExpectedBucketOwner: "123456789012" });
    const statements = JSON.parse(h.stsCalls[1].input.Policy).Statement;
    const s3 = statements.filter((s: any) => [s.Action].flat().some((a: string) => a.startsWith("s3:"))
      && s.Resource !== "arn:aws:s3:::fabricated-config/config/active.json");
    for (const statement of s3) expect(statement.Resource).toBe(`arn:aws:s3:::fabricated-payload/${h.storage.key}`);
    expect(s3.find((s: any) => [s.Action].flat().includes("s3:GetObjectVersion"))).toMatchObject({
      Condition: { StringEquals: { "s3:VersionId": h.storage.versionId } } });
    expect(s3.find((s: any) => [s.Action].flat().includes("s3:GetObjectRetention")).Condition).toBeUndefined();
    expect(s3.flatMap((s: any) => s.Action)).toEqual(expect.arrayContaining(["s3:GetObjectVersion", "s3:GetObjectRetention"]));
    expect(JSON.stringify(statements)).not.toMatch(/PutObject|Delete|Bypass|GenerateDataKey|ListBucket/);
    expect(statements.find((s: any) => [s.Action].flat().includes("kms:Decrypt")
      && s.Condition?.StringEquals?.["kms:EncryptionContext:aws:s3:arn"] === `arn:aws:s3:::fabricated-payload/${h.storage.key}`)).toMatchObject({ Resource: h.f.binding.aws.keys.serviceArn,
      Condition: { StringEquals: { "kms:ViaService": "s3.us-east-2.amazonaws.com",
        "kms:EncryptionContext:aws:s3:arn": `arn:aws:s3:::fabricated-payload/${h.storage.key}` } } });
    expect(h.stsCalls).toHaveLength(2); expect(await get.config.maxAttempts()).toBe(1);
    disposePrivateRoleIdentity(identity);
  });

  it.each(["capture", "ciphertext-verifier"] as const)("does not combine unsupported S3 conditions in the %s session", async (purpose) => {
    const h = await payloadHarness(purpose); const identity = await h.start();
    if (purpose === "capture") await putPrivateRoleCiphertext(identity, h.bytes, intent);
    else await inspectPrivateRoleCiphertext(identity, h.storage, capturedAt);
    const supported: Record<string, string[]> = {
      "s3:PutObject": ["s3:if-none-match", "s3:object-lock-mode", "s3:object-lock-retain-until-date",
        "s3:x-amz-server-side-encryption", "s3:x-amz-server-side-encryption-aws-kms-key-id"],
      "s3:PutObjectRetention": ["s3:object-lock-mode", "s3:object-lock-retain-until-date"],
      "s3:GetObjectVersion": ["s3:VersionId"], "s3:GetObjectRetention": []
    };
    const statements = JSON.parse(h.stsCalls[1].input.Policy).Statement.filter(
      (s: any) => s.Resource === `arn:aws:s3:::fabricated-payload/${h.storage.key}`);
    for (const statement of statements) {
      const keys = Object.values(statement.Condition ?? {}).flatMap((conditions: any) => Object.keys(conditions));
      for (const action of [statement.Action].flat()) {
        expect(supported).toHaveProperty(action);
        expect(keys.filter((key) => !supported[action]!.includes(key))).toEqual([]);
      }
    }
    disposePrivateRoleIdentity(identity);
  });

  it.each(["capture", "ciphertext-verifier", "read-broker", "public-exporter"] as const)("denies mismatched %s role before payload authority", async (purpose) => {
    const h = await payloadHarness(purpose); const identity = await h.start();
    if (purpose !== "capture") await denied(putPrivateRoleCiphertext(identity, h.bytes, intent));
    if (purpose !== "ciphertext-verifier") await denied(inspectPrivateRoleCiphertext(identity, h.storage, capturedAt));
    expect(h.stsCalls).toHaveLength(1); expect(h.payloadCalls()).toHaveLength(0); disposePrivateRoleIdentity(identity);
  });

  it.each(["copied", "disposed", "expired", "pre-aborted"] as const)("refuses %s identity/operation without side effects", async (kind) => {
    const h = await payloadHarness(); const original = await h.start(); let identity = original;
    const signal = new AbortController();
    if (kind === "copied") identity = { ...original };
    if (kind === "disposed") disposePrivateRoleIdentity(original);
    if (kind === "expired") vi.setSystemTime(new Date(now.getTime() + 300_000));
    if (kind === "pre-aborted") signal.abort();
    const before = h.fetchCalls.length;
    await denied(putPrivateRoleCiphertext(identity, h.bytes, intent, signal.signal));
    expect(h.fetchCalls).toHaveLength(before); expect(h.stsCalls).toHaveLength(1); expect(h.payloadCalls()).toHaveLength(0);
    if (kind !== "disposed") disposePrivateRoleIdentity(original);
  });

  it.each([
    ["wrong run", "current", (v: any) => ({ ...v, run_attempt: 3 })],
    ["finished job", "jobs", (v: any) => ({ ...v, jobs: [{ ...v.jobs[0], status: "completed" }] })],
    ["wrong service key", "config", (v: any) => ({ ...v, SSEKMSKeyId: "wrong" })],
    ["corrupt config", "config", (v: any) => ({ ...v, Body: Readable.from([Buffer.from("bad")]), ContentLength: 3 })]
  ] as const)("fails refreshed %s before obtaining payload authority", async (_name, phase, change) => {
    const h = await payloadHarness(); const identity = await h.start();
    h.setHook((which, value) => which === phase ? change(value) : undefined);
    await denied(putPrivateRoleCiphertext(identity, h.bytes, intent)); expect(h.stsCalls).toHaveLength(1); expect(h.payloadCalls()).toHaveLength(0);
    disposePrivateRoleIdentity(identity);
  });

  it("withholds a successful write result when configuration changes after upload", async () => {
    const h = await payloadHarness(); const identity = await h.start();
    h.setHook((phase) => { if (phase === "put") h.setPointer({ ...h.f.pointer(), epoch: 5 }); });
    await denied(putPrivateRoleCiphertext(identity, h.bytes, intent)); expect(h.payloadCalls()).toHaveLength(1);
    disposePrivateRoleIdentity(identity);
  });

  it.each([
    { ...intent, captureId: "../escape" }, { ...intent, captureId: captureId.toUpperCase() },
    { ...intent, capturedAt: new Date(now.getTime() + 1).toISOString(), retainUntil: new Date(Date.parse(retainUntil) + 1).toISOString() },
    { ...intent, capturedAt: new Date(now.getTime() - 60_001).toISOString(), retainUntil: new Date(Date.parse(retainUntil) - 60_001).toISOString() },
    { ...intent, retainUntil: new Date(Date.parse(retainUntil) - 1).toISOString() },
    { ...intent, retainUntil: new Date(Date.parse(retainUntil) + 1).toISOString() }, { ...intent, extra: "unknown" }
  ])("rejects malformed, stale or nonexact retention intent before upload", async (value) => {
    const h = await payloadHarness(); const identity = await h.start();
    await denied(putPrivateRoleCiphertext(identity, h.bytes, value)); expect(h.payloadCalls()).toHaveLength(0); disposePrivateRoleIdentity(identity);
  });

  it.each(["service", "foreign"])("rejects %s client-envelope key before payload write", async (kind) => {
    const h = await payloadHarness(); const identity = await h.start(); const value = h.makeEnvelope();
    value.header.kmsKeyArn = kind === "service" ? h.f.binding.aws.keys.serviceArn : "arn:aws:kms:us-east-2:123456789012:key/99999999-9999-4999-8999-999999999999";
    await denied(putPrivateRoleCiphertext(identity, controlWire(value), intent)); expect(h.payloadCalls()).toHaveLength(0); disposePrivateRoleIdentity(identity);
  });

  it.each([
    { key: "payloads/captures/../other.json" }, { key: `payloads/captures/${captureId}.json/extra` }, { key: `other/${captureId}.json` },
    { versionId: "" }, { versionId: "null" }, { versionId: "x".repeat(1025) }, { bucket: "other-bucket" }, { region: "us-west-2" }, { extra: true }
  ])("rejects caller address escape before payload read", async (change) => {
    const h = await payloadHarness("ciphertext-verifier"); const identity = await h.start();
    await denied(inspectPrivateRoleCiphertext(identity, { ...h.storage, ...change } as any, capturedAt));
    expect(h.payloadCalls()).toHaveLength(0); disposePrivateRoleIdentity(identity);
  });

  it.each([409, 412, "timeout"])("does not retry or disclose a failed/ambiguous put (%s)", async (code) => {
    const h = await payloadHarness(); const identity = await h.start();
    h.setHook((phase) => { if (phase === "put") throw Object.assign(new Error(marker), { name: code === "timeout" ? "TimeoutError" : "S3Error", $metadata: { httpStatusCode: code } }); });
    await denied(putPrivateRoleCiphertext(identity, h.bytes, intent)); expect(h.payloadCalls()).toHaveLength(1); expect(h.stsCalls).toHaveLength(2);
    disposePrivateRoleIdentity(identity);
  });

  it.each([
    ["missing version", { VersionId: undefined }], ["wrong checksum", { ChecksumSHA256: Buffer.alloc(32, 9).toString("base64") }],
    ["composite checksum", { ChecksumType: "COMPOSITE" }], ["missing checksum type", { ChecksumType: undefined }],
    ["wrong service key", { SSEKMSKeyId: "wrong" }], ["wrong encryption", { ServerSideEncryption: "AES256" }],
    ["bucket key", { BucketKeyEnabled: true }], ["delete marker", { DeleteMarker: true }],
    ["partial content", { ContentRange: "bytes 0-9/100" }], ["multipart", { PartsCount: 2 }]
  ] as const)("rejects unsafe SDK upload metadata: %s", async (_name, change) => {
    const h = await payloadHarness(); const identity = await h.start(); h.setHook((phase, value) => phase === "put" ? { ...value, ...change } : undefined);
    await denied(putPrivateRoleCiphertext(identity, h.bytes, intent)); expect(h.payloadCalls()).toHaveLength(1); disposePrivateRoleIdentity(identity);
  });

  it.each([
    ["range", { ContentRange: "bytes 0-9/100" }], ["multipart", { PartsCount: 1 }], ["delete marker", { DeleteMarker: true }],
    ["bucket key", { BucketKeyEnabled: true }], ["wrong version", { VersionId: "different-version" }],
    ["composite checksum", { ChecksumType: "COMPOSITE" }], ["missing checksum type", { ChecksumType: undefined }],
    ["wrong checksum", { ChecksumSHA256: Buffer.alloc(32, 9).toString("base64") }], ["wrong service key", { SSEKMSKeyId: "wrong" }],
    ["missing timestamp", { LastModified: undefined }], ["early timestamp", { LastModified: new Date(now.getTime() - 60_001) }],
    ["late timestamp", { LastModified: new Date(now.getTime() + 60_001) }], ["oversized length", { ContentLength: 2_097_153 }]
  ] as const)("rejects unsafe SDK exact-version response: %s", async (_name, change) => {
    const h = await payloadHarness("ciphertext-verifier"); const identity = await h.start();
    h.setHook((phase, value) => phase === "get" ? { ...value, ...change } : undefined);
    await denied(inspectPrivateRoleCiphertext(identity, h.storage, capturedAt));
    expect(h.payloadCalls().filter((c) => c.kind === "GetObjectCommand")).toHaveLength(1); disposePrivateRoleIdentity(identity);
  });

  it.each([
    ["wrong mode", { Mode: "COMPLIANCE", RetainUntilDate: new Date(retainUntil) }],
    ["shortened", { Mode: "GOVERNANCE", RetainUntilDate: new Date(Date.parse(retainUntil) - 1) }],
    ["extended", { Mode: "GOVERNANCE", RetainUntilDate: new Date(Date.parse(retainUntil) + 1) }],
    ["missing date", { Mode: "GOVERNANCE" }]
  ] as const)("rejects %s retention without inventing compliance", async (_name, Retention) => {
    const h = await payloadHarness("ciphertext-verifier"); const identity = await h.start();
    h.setHook((phase, value) => phase === "retention" ? { ...value, Retention } : undefined);
    await denied(inspectPrivateRoleCiphertext(identity, h.storage, capturedAt)); disposePrivateRoleIdentity(identity);
  });

  it.each(["pre-payload refresh", "payload read", "retention read", "final refresh"] as const)(
    "denies retention expiry crossed during %s", async (stage) => {
      const h = await payloadHarness("ciphertext-verifier"); const identity = await h.start();
      const historicalCapture = new Date(now.getTime() - 90 * 86_400_000 + 1_000).toISOString();
      const imminentExpiry = new Date(now.getTime() + 1_000);
      let sawRetention = false; let advanced = false;
      h.setHook((phase, value) => {
        if (!advanced && ((stage === "pre-payload refresh" && phase === "config")
          || (stage === "payload read" && phase === "get") || (stage === "retention read" && phase === "retention")
          || (stage === "final refresh" && phase === "config" && sawRetention))) {
          advanced = true; vi.setSystemTime(new Date(now.getTime() + 2_000));
        }
        if (phase === "get") return { ...value, LastModified: new Date(historicalCapture) };
        if (phase === "retention") {
          sawRetention = true; return { ...value, Retention: { Mode: "GOVERNANCE", RetainUntilDate: imminentExpiry } };
        }
        return undefined;
      });
      await denied(inspectPrivateRoleCiphertext(identity, h.storage, historicalCapture));
      expect(advanced).toBe(true);
      if (stage === "pre-payload refresh") expect(h.payloadCalls()).toHaveLength(0);
      if (stage === "payload read") expect(h.payloadCalls().map((c) => c.kind)).toEqual(["GetObjectCommand"]);
      disposePrivateRoleIdentity(identity);
    });

  it("accepts the exact capture timestamp skew boundary during ciphertext verification", async () => {
    const h = await payloadHarness("ciphertext-verifier"); const identity = await h.start();
    h.setHook((phase, value) => phase === "get" ? { ...value, LastModified: new Date(now.getTime() + 60_000) } : undefined);
    expect((await inspectPrivateRoleCiphertext(identity, h.storage, capturedAt)).sha256).toBe(hash(h.bytes).toString("hex"));
    disposePrivateRoleIdentity(identity);
  });

  it("rejects a different client key even when response checksum faithfully matches stored bytes", async () => {
    const h = await payloadHarness("ciphertext-verifier"); const identity = await h.start(); const value = h.makeEnvelope();
    value.header.kmsKeyArn = "arn:aws:kms:us-east-2:123456789012:key/99999999-9999-4999-8999-999999999999";
    h.setBytes(controlWire(value)); await denied(inspectPrivateRoleCiphertext(identity, h.storage, capturedAt)); disposePrivateRoleIdentity(identity);
  });

  it.each(["truncated", "longer", "wrong bytes", "too many chunks"])("rejects %s download without retention follow-up", async (kind) => {
    const h = await payloadHarness("ciphertext-verifier"); const identity = await h.start();
    h.setHook((phase, value) => {
      if (phase !== "get") return undefined;
      const Body = kind === "truncated" ? Readable.from([h.bytes.subarray(0, -1)])
        : kind === "longer" ? Readable.from([h.bytes, Buffer.from("x")])
          : kind === "wrong bytes" ? Readable.from([Buffer.alloc(h.bytes.length, 32)])
            : (async function*() { for (let i = 0; i < 65_537; i++) yield Buffer.alloc(0); yield h.bytes; })();
      return { ...value, Body };
    });
    await denied(inspectPrivateRoleCiphertext(identity, h.storage, capturedAt));
    expect(h.payloadCalls().map((c) => c.kind)).toEqual(["GetObjectCommand"]); disposePrivateRoleIdentity(identity);
  });

  it("takes owned snapshots before refreshed authority awaits", async () => {
    const h = await payloadHarness(); const identity = await h.start(); const entered = deferred<void>(); const release = deferred<void>();
    let pause = true;
    h.setHook(async (phase) => { if (phase === "repository" && pause) { pause = false; entered.resolve(); await release.promise; } });
    const bytes = Buffer.from(h.bytes); const admitted = { ...intent }; const writing = putPrivateRoleCiphertext(identity, bytes, admitted);
    await entered.promise; bytes.fill(0); admitted.captureId = "../escape"; release.resolve();
    expect(await writing).toEqual(h.storage); expect(h.payloadCalls()[0].input.Body).toEqual(h.bytes); disposePrivateRoleIdentity(identity);
  });

  it("cancels a stalled body and prevents deferred retention calls", async () => {
    const h = await payloadHarness("ciphertext-verifier"); const identity = await h.start();
    const body = new PassThrough(); const entered = deferred<void>(); const controller = new AbortController();
    h.setHook((phase, value) => { if (phase === "get") { entered.resolve(); return { ...value, Body: body }; } });
    const checking = inspectPrivateRoleCiphertext(identity, h.storage, capturedAt, controller.signal); const failure = denied(checking);
    await entered.promise; controller.abort(); await failure;
    expect(body.destroyed).toBe(true); expect(h.payloadCalls().map((c) => c.kind)).toEqual(["GetObjectCommand"]);
    expect(h.payloadCalls()[0].options.abortSignal.aborted).toBe(true); disposePrivateRoleIdentity(identity);
  });

  it("does not issue a deferred payload call after disposal during exact-session acquisition", async () => {
    const h = await payloadHarness(); const identity = await h.start(); const entered = deferred<void>(); const release = deferred<void>();
    h.setHook(async (phase) => { if (phase === "sts") { entered.resolve(); await release.promise; } });
    const writing = putPrivateRoleCiphertext(identity, h.bytes, intent); const failure = denied(writing);
    await entered.promise; disposePrivateRoleIdentity(identity); await failure; release.resolve();
    await new Promise<void>((resolve) => setImmediate(resolve)); expect(h.payloadCalls()).toHaveLength(0);
  });

  it("bounds an uncooperative upload and never retries after the deadline", async () => {
    const h = await payloadHarness(); const identity = await h.start(); const entered = deferred<void>();
    h.setHook((phase) => { if (phase === "put") { entered.resolve(); return new Promise(() => {}); } });
    vi.useFakeTimers(); const writing = putPrivateRoleCiphertext(identity, h.bytes, intent); const failure = denied(writing);
    await entered.promise; await vi.advanceTimersByTimeAsync(30_001); await failure;
    expect(h.payloadCalls()).toHaveLength(1); expect(h.payloadCalls()[0].options.abortSignal.aborted).toBe(true);
    disposePrivateRoleIdentity(identity);
  });
});
