import { createHash } from "node:crypto";
import { PassThrough, Readable } from "node:stream";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { controlWire } from "../src/private-provenance-control.js";
import {
  createPrivateRoleApprovalStore, disposePrivateRoleIdentity, PrivateIdentityError
} from "../src/private-provenance-identity.js";
import { privateApprovalStateKey, PrivateStateConflict } from "../src/private-provenance-read.js";
import { now, payloadHarness } from "./helpers/private-provenance-aws-fixture.js";

const available = { approvalId: "approval-1", delegationId: "delegation-1", approvalSha256: "a".repeat(64),
  configEpoch: 4, revision: 0, state: "available", requestId: "request-1", operationId: null,
  revocationSha256: null, updatedAt: now.toISOString() };
const reserved = { ...available, revision: 1, state: "reserved", operationId: "operation-1" };
const revoked = { ...available, state: "revoked", requestId: null, revocationSha256: "b".repeat(64) };
const key = privateApprovalStateKey(available.delegationId, available.approvalId);
const checksum = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("base64");
const providerError = (name: string, status: number) =>
  Object.assign(new Error("private-provider-detail"), { name, $metadata: { httpStatusCode: status } });

async function fixture(signal?: AbortSignal) {
  const h = await payloadHarness("read-broker");
  const identity = await h.start();
  const store = createPrivateRoleApprovalStore(identity, signal);
  const calls = () => h.s3Calls.filter((call) => call.input.Bucket === "fabricated-state");

  let current: { bytes: Buffer; tag: string; version: string } | undefined;
  let revision = 0;
  const install = (bytes: Uint8Array) => {
    revision++;
    current = { bytes: Buffer.from(bytes), tag: `"state-etag-${revision}"`, version: `state-version-${revision}` };
    return current;
  };
  const metadata = ({ bytes, tag, version }: NonNullable<typeof current>) => ({
    $metadata: { httpStatusCode: 200 }, VersionId: version, ETag: tag, ChecksumType: "FULL_OBJECT",
    ChecksumSHA256: checksum(bytes), ServerSideEncryption: "aws:kms",
    SSEKMSKeyId: h.f.binding.aws.keys.serviceArn, BucketKeyEnabled: false
  });
  type Hook = (phase: string, value: any, command: any) => unknown;
  let before: Hook | undefined;
  let after: Hook | undefined;
  h.setHook(async (phase, baseline, command) => {
    await before?.(phase, baseline, command);
    if (phase === "get") {
      // A narrowly scoped caller cannot distinguish absent from unauthorized by reading first.
      if (!current) throw providerError("AccessDenied", 403);
      const output = { ...metadata(current), Body: Readable.from([current.bytes]), ContentLength: current.bytes.length };
      return await after?.(phase, output, command) ?? output;
    }
    if (phase === "put") {
      const input = command.input;
      if (input.IfNoneMatch === "*") {
        if (current) throw providerError("PreconditionFailed", 412);
      } else if (!current || input.IfMatch !== current.tag) {
        throw providerError("PreconditionFailed", 412);
      }
      const output = metadata(install(input.Body));
      return await after?.(phase, output, command) ?? output;
    }
    return await after?.(phase, baseline, command) ?? baseline;
  });
  return { h, identity, store, calls, install,
    before: (hook: Hook) => { before = hook; }, after: (hook: Hook) => { after = hook; } };
}

beforeEach(() => { vi.useFakeTimers({ toFake: ["Date"] }); vi.setSystemTime(now); });
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); vi.unstubAllEnvs(); vi.useRealTimers(); });

describe("fixed AWS approval-state operations", () => {
  it("creates, verifies and transitions one state object with a different exact-object lease per operation", async () => {
    const f = await fixture();
    const bytes = controlWire(available);
    await f.store.create(key, bytes);
    const read = await f.store.read(key);
    expect(read).toEqual({ bytes, etag: '"state-etag-1"', versionId: "state-version-1" });
    expect(await f.store.replace(key, read!.etag, controlWire(reserved))).toBe("state-version-2");
    expect(await f.store.read(key)).toEqual({ bytes: controlWire(reserved), etag: '"state-etag-2"', versionId: "state-version-2" });
    const calls = f.calls();
    expect(calls.map((call) => call.kind)).toEqual([
      "PutObjectCommand", "GetObjectCommand", "GetObjectCommand", "PutObjectCommand", "GetObjectCommand"
    ]);
    const [create, get, , replace] = calls;
    expect(create.input).toMatchObject({ Bucket: "fabricated-state", Key: key, ExpectedBucketOwner: "123456789012",
      IfNoneMatch: "*", ContentType: "application/json", ContentLength: bytes.length, ChecksumAlgorithm: "SHA256",
      ChecksumSHA256: checksum(bytes), ServerSideEncryption: "aws:kms", SSEKMSKeyId: f.h.f.binding.aws.keys.serviceArn,
      BucketKeyEnabled: false });
    expect(create.input.IfMatch).toBeUndefined();
    expect(create.input.ObjectLockMode).toBeUndefined();
    expect(get.input).toEqual({ Bucket: "fabricated-state", Key: key, ExpectedBucketOwner: "123456789012", ChecksumMode: "ENABLED" });
    expect(replace.input).toMatchObject({ Key: key, IfMatch: read!.etag, ChecksumSHA256: checksum(controlWire(reserved)) });
    expect(replace.input.IfNoneMatch).toBeUndefined();
    expect(await create.config.maxAttempts()).toBe(1);
    expect(f.h.stsCalls).toHaveLength(5);
    const objectArn = `arn:aws:s3:::fabricated-state/${key}`;
    const stateGrants = f.h.stsCalls.map(({ input }) => JSON.parse(input.Policy).Statement.filter((statement: any) =>
      statement.Resource === objectArn || statement.Condition?.StringEquals?.["kms:EncryptionContext:aws:s3:arn"] === objectArn));
    expect(stateGrants.map((grants) => grants.flatMap(({ Action }: any) => Action))).toEqual([
      [], ["s3:PutObject", "kms:GenerateDataKey"], ["s3:GetObject", "kms:Decrypt"],
      ["s3:GetObject", "s3:PutObject", "kms:Decrypt", "kms:GenerateDataKey"], ["s3:GetObject", "kms:Decrypt"]
    ]);
    for (const index of [1, 3]) {
      const write = stateGrants[index]?.find((grant: any) => grant.Action === "s3:PutObject");
      expect(write).toMatchObject({ Resource: objectArn, Condition: { Null: {
        [index === 1 ? "s3:if-none-match" : "s3:if-match"]: "false"
      }, StringEquals: { "s3:x-amz-server-side-encryption": "aws:kms",
        "s3:x-amz-server-side-encryption-aws-kms-key-id": f.h.f.binding.aws.keys.serviceArn } } });
    }
    for (const { input } of f.h.stsCalls) {
      expect(input.Policy).not.toMatch(/ListBucket|DeleteObject|BypassGovernanceRetention|arn:aws:s3:::[^"]*\*/);
      expect(input.Policy).not.toContain(f.h.f.binding.aws.keys.clientArn);
    }
  });

  it("requires create-first when S3 denies reads of missing objects and preserves a competing revocation", async () => {
    const f = await fixture();
    await expect(f.store.read(key)).rejects.toBeInstanceOf(PrivateIdentityError);
    const firstUse = controlWire(available);
    let finishRevocation!: () => void;
    const revocationStored = new Promise<void>((resolve) => { finishRevocation = resolve; });
    f.before((phase, _value, command) => {
      if (phase === "put" && firstUse.equals(command.input.Body)) return revocationStored;
    });
    f.after((phase) => { if (phase === "put") finishRevocation(); });
    const results = await Promise.allSettled([
      f.store.create(key, firstUse), f.store.create(key, controlWire(revoked))
    ]);
    expect(results[0]).toMatchObject({ status: "rejected", reason: expect.any(PrivateStateConflict) });
    expect(results[1]?.status).toBe("fulfilled");
    const winner = await f.store.read(key);
    expect(winner?.bytes).toEqual(controlWire(revoked));
    await expect(f.store.replace(key, winner!.etag, controlWire(reserved))).rejects.toBeInstanceOf(PrivateIdentityError);
    expect(f.calls().filter((call) => call.kind === "PutObjectCommand")).toHaveLength(2);
  });

  it("leaves an unknown write acknowledgment failed even if the provider stored the bytes", async () => {
    const f = await fixture();
    f.after((phase) => { if (phase === "put") throw providerError("Timeout", 504); });
    await expect(f.store.create(key, controlWire(available))).rejects.toBeInstanceOf(PrivateIdentityError);
    expect(f.calls().map((call) => call.kind)).toEqual(["PutObjectCommand"]);
    f.after(() => undefined);
    expect((await f.store.read(key))?.bytes).toEqual(controlWire(available));
  });

  it("uses If-Match to reject a lost CAS race after reading the previous state", async () => {
    const f = await fixture();
    const previous = f.install(controlWire(available));
    f.before((phase) => {
      if (phase === "put") f.install(controlWire({ ...available, revision: 1, state: "revoked", revocationSha256: "b".repeat(64) }));
    });
    await expect(f.store.replace(key, previous.tag, controlWire(reserved))).rejects.toBeInstanceOf(PrivateStateConflict);
    expect(f.calls().map((call) => call.kind)).toEqual(["GetObjectCommand", "PutObjectCommand"]);
    expect((await f.store.read(key))?.etag).toBe('"state-etag-2"');
  });

  it.each([
    ["ConditionalRequestConflict", 409, PrivateStateConflict],
    ["PreconditionFailed", 412, PrivateStateConflict],
    ["AccessDenied", 409, PrivateIdentityError],
    ["PreconditionFailed", 500, PrivateIdentityError]
  ] as const)("maps only recognized S3 preconditions: %s %i", async (name, status, error) => {
    const f = await fixture();
    f.before((phase) => { if (phase === "put") throw providerError(name, status); });
    await expect(f.store.create(key, controlWire(available))).rejects.toBeInstanceOf(error);
    expect(f.calls()).toHaveLength(1);
  });

  it.each([
    ["checksum mismatch", { ChecksumSHA256: "wrong-checksum" }],
    ["composite checksum", { ChecksumType: "COMPOSITE" }],
    ["different service key", { SSEKMSKeyId: "wrong-key" }],
    ["different encryption method", { ServerSideEncryption: "AES256" }],
    ["bucket key enabled", { BucketKeyEnabled: true }],
    ["unversioned response", { VersionId: "null" }],
    ["delete marker", { DeleteMarker: true }],
    ["partial response", { ContentRange: "bytes 0-1/10" }],
    ["multipart response", { PartsCount: 2 }],
    ["wildcard ETag", { ETag: "*" }]
  ])("rejects %s on read and write acknowledgment", async (_label, invalid) => {
    const f = await fixture();
    f.after((phase, output) => phase === "put" || phase === "get" ? { ...output, ...invalid } : output);
    await expect(f.store.create(key, controlWire(available))).rejects.toBeInstanceOf(PrivateIdentityError);
    await expect(f.store.read(key)).rejects.toBeInstanceOf(PrivateIdentityError);
    expect(f.calls().map((call) => call.kind)).toEqual(["PutObjectCommand", "GetObjectCommand"]);
  });

  it("rejects wrong key, epoch or malformed preconditions before reaching the state bucket", async () => {
    const f = await fixture();
    await expect(f.store.create("approvals/../config", controlWire(available))).rejects.toBeInstanceOf(PrivateIdentityError);
    await expect(f.store.read(key + "\n")).rejects.toBeInstanceOf(PrivateIdentityError);
    await expect(f.store.create(key, controlWire({ ...available, configEpoch: 5 }))).rejects.toBeInstanceOf(PrivateIdentityError);
    await expect(f.store.create(key, controlWire({ ...available, approvalId: "approval-2" }))).rejects.toBeInstanceOf(PrivateIdentityError);
    await expect(f.store.replace(key, "*", controlWire(available))).rejects.toBeInstanceOf(PrivateIdentityError);
    await expect(f.store.replace(key, '"etag"\n', controlWire(available))).rejects.toBeInstanceOf(PrivateIdentityError);
    await expect(f.store.replace(key, undefined as unknown as string, controlWire(available))).rejects.toBeInstanceOf(PrivateIdentityError);
    expect(f.calls()).toHaveLength(0);
    expect(f.h.stsCalls).toHaveLength(1);
  });

  it("checks record identity after verifying the returned object checksum", async () => {
    const f = await fixture();
    for (const invalid of [{ ...available, approvalId: "approval-2" }, { ...available, configEpoch: 5 }]) {
      f.install(controlWire(invalid));
      await expect(f.store.read(key)).rejects.toBeInstanceOf(PrivateIdentityError);
    }
  });

  it("cannot use a matching ETag to replace a different signed approval at the same key", async () => {
    const f = await fixture();
    const previous = f.install(controlWire(available));
    await expect(f.store.replace(key, previous.tag, controlWire({ ...reserved, approvalSha256: "c".repeat(64) })))
      .rejects.toBeInstanceOf(PrivateIdentityError);
    expect(f.calls().map((call) => call.kind)).toEqual(["GetObjectCommand"]);
    expect((await f.store.read(key))?.bytes).toEqual(previous.bytes);
  });

  it("rejects copies, wrong-purpose identities and disposed handles", async () => {
    const h = await payloadHarness("capture");
    const capture = await h.start();
    expect(() => createPrivateRoleApprovalStore(capture)).toThrow(PrivateIdentityError);
    expect(h.stsCalls).toHaveLength(1);
    disposePrivateRoleIdentity(capture);
    const f = await fixture();
    expect(() => createPrivateRoleApprovalStore({ ...f.identity })).toThrow(PrivateIdentityError);
    disposePrivateRoleIdentity(f.identity);
    await expect(f.store.read(key)).rejects.toBeInstanceOf(PrivateIdentityError);
    expect(f.calls()).toHaveLength(0);
  });

  it("snapshots the write bytes before awaiting the identity readback", async () => {
    const f = await fixture();
    const input = controlWire(available);
    const writing = f.store.create(key, input);
    input.fill(0);
    await writing;
    expect((await f.store.read(key))?.bytes).toEqual(controlWire(available));
  });

  it("does not send a stale write after refresh crosses the permitted state age", async () => {
    const f = await fixture();
    f.before((phase) => { if (phase === "sts") vi.setSystemTime(now.getTime() + 61_000); });
    await expect(f.store.create(key, controlWire(available))).rejects.toBeInstanceOf(PrivateIdentityError);
    expect(f.calls()).toHaveLength(0);
  });

  it("denies success when the identity expires during the provider write", async () => {
    const f = await fixture();
    f.after((phase) => { if (phase === "put") vi.setSystemTime(now.getTime() + 300_000); });
    await expect(f.store.create(key, controlWire(available))).rejects.toBeInstanceOf(PrivateIdentityError);
    expect(f.calls()).toHaveLength(1);
  });

  it("aborts an active response stream when the approved caller cancels", async () => {
    const controller = new AbortController();
    const f = await fixture(controller.signal);
    f.install(controlWire(available));
    const stream = new PassThrough();
    const nextRead = vi.spyOn(stream, Symbol.asyncIterator);
    f.after((phase, output) => phase === "get" ? { ...output, Body: stream } : output);
    const read = f.store.read(key);
    const rejected = expect(read).rejects.toBeInstanceOf(PrivateIdentityError);
    await vi.waitFor(() => expect(nextRead).toHaveBeenCalledOnce());
    controller.abort();
    await rejected;
    expect(stream.destroyed).toBe(true);
    expect(f.calls()[0].options.abortSignal.aborted).toBe(true);
  });
});
