import { createHash, generateKeyPairSync, type KeyObject, type X509Certificate } from "node:crypto";
import { Socket } from "node:net";
import { Readable } from "node:stream";
import { TLSSocket } from "node:tls";
import { S3Client } from "@aws-sdk/client-s3";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { controlHash, controlWire } from "../src/private-provenance-control.js";
import {
  createPrivateReadAuditIngress, persistPrivateRoleAuditEvent, PrivateIdentityError
} from "../src/private-provenance-identity.js";
import { encodePrivateReadAuditSubmission, privateApprovalStateKey } from "../src/private-provenance-read.js";
import { now, payloadHarness, retainUntil, type Hook } from "./helpers/private-provenance-aws-fixture.js";

const origin = "https://audit.invalid";
const audience = `${origin}/audit`;
const base = (domain: string) => ({ domain, version: 1, canonicalization: "sorted-json-v1" });
const sockets: TLSSocket[] = [];

function mockSocket(publicKey: KeyObject) {
  const socket = new TLSSocket(new Socket(), { isServer: true });
  sockets.push(socket);
  vi.spyOn(socket, "getProtocol").mockReturnValue("TLSv1.3");
  vi.spyOn(socket, "getX509Certificate").mockReturnValue({ publicKey } as X509Certificate);
  return socket;
}

async function fixture(fault?: Hook, approvalMaxSeconds = 300) {
  const { publicKey } = generateKeyPairSync("ed25519");
  const tlsSpkiSha256 = createHash("sha256").update(publicKey.export({ type: "spki", format: "der" })).digest("hex");
  let stored: Buffer | undefined;
  let metadata: Record<string, string> | undefined;
  const h = await payloadHarness("audit", async (phase, original, command) => {
    if (command?.input.Bucket === "fabricated-audit") {
      if (phase === "put") {
        stored = Buffer.from(command.input.Body);
        metadata = structuredClone(command.input.Metadata);
      }
      if (phase === "put" || phase === "get") {
        original = { ...original, ETag: '"event-etag"', VersionId: "audit-version-7",
          ChecksumSHA256: createHash("sha256").update(stored!).digest("base64"), Metadata: metadata };
      }
      if (phase === "get") original = { ...original, ContentLength: stored!.length, Body: Readable.from([stored!]) };
    }
    return await fault?.(phase, original, command) ?? original;
  }, (binding) => {
    binding.endpoints.find((endpoint) => endpoint.purpose === "audit")!.tlsSpkiSha256 = tlsSpkiSha256;
    binding.policy.approvalMaxSeconds = approvalMaxSeconds;
  });
  const id = await h.start();
  const ingress = createPrivateReadAuditIngress(id);
  const socket = mockSocket(publicKey);
  const broker = h.installed.binding.workloads.find((workload) => workload.purpose === "read-broker")!;
  const codex = h.installed.binding.workloads.find((workload) => workload.purpose === "codex-approver")!;
  const requester = h.installed.binding.principals.find((principal) => principal.kind === "requester")!;
  const at = now.toISOString();
  const startsAt = new Date(now.getTime() - 10_000).toISOString();
  const expiresAt = new Date(now.getTime() + 240_000).toISOString();
  const scope = { subject: { repository: "fixture/control", commitSha: "b".repeat(40) }, runId: "gh-100-2",
    storage: h.storage, receiptSha256: "c".repeat(64), purposeId: "provenance-verification" };
  const categoryIds = ["validation-summary"];
  const request = h.f.signed({ ...base("bootstrap-private-read-request"), requestId: "request-1", requesterId: requester.id,
    configEpoch: 4, ...scope, requestedCategoryIds: categoryIds, issuedAt: startsAt, expiresAt }, requester.signingKeyFingerprint);
  const approval = h.f.signed({ ...base("bootstrap-private-read-approval"), approvalId: "approval-1", delegationId: "delegation-1",
    configEpoch: 4, approverWorkloadId: codex.id, requesterId: requester.id, requestSha256: controlHash(request), ...scope,
    categoryIds, maxUses: 1, issuedAt: startsAt, notBefore: startsAt, expiresAt }, codex.signingKeyFingerprint!);
  const delegation = h.f.signed({ ...base("bootstrap-codex-read-delegation"), delegationId: "delegation-1",
    configEpoch: 4, approverWorkloadId: codex.id, approverKeyFingerprint: codex.signingKeyFingerprint, repositoryIds: ["123"],
    requesterIds: [requester.id], categoryIds, purposeIds: [scope.purposeId], maxApprovalSeconds: 300, maxUses: 1,
    issuedAt: startsAt, notBefore: startsAt, expiresAt });
  const stateBytes = controlWire({ approvalId: "approval-1", delegationId: "delegation-1", approvalSha256: controlHash(approval),
    configEpoch: 4, revision: 2, state: "spent", requestId: "request-1", operationId: "operation-1", revocationSha256: null, updatedAt: at });
  const state = { key: privateApprovalStateKey("delegation-1", "approval-1"), versionId: "state-version-3", bytes: stateBytes };
  const event = { ...base("bootstrap-private-audit-event"), ...scope, eventId: "event-1", operationId: "operation-1", phase: "complete",
    at, configEpoch: 4, actorId: requester.id, workloadId: broker.id, requestSha256: controlHash(request), approvalSha256: controlHash(approval),
    delegationId: "delegation-1", stateRevision: 2, resultCode: "OK", previousEventSha256: "d".repeat(64) };
  const documents = { approval, delegation, request, state };
  const body = encodePrivateReadAuditSubmission(controlWire(event), documents);
  const proofFor = (challenge: ReturnType<typeof ingress.challenge>, bytes = body, fingerprint = broker.transportKeyFingerprint!) =>
    h.f.signed({ ...base("bootstrap-workload-proof"), ...challenge, workloadId: broker.id, bodySha256: controlHash(bytes) }, fingerprint);
  const makeAdmission = async (bytes = body) => {
    const challenge = ingress.challenge(socket);
    return ingress.admit(socket, await h.peerToken(audience), proofFor(challenge, bytes), bytes);
  };
  return { h, id, ingress, socket, publicKey, proofFor, makeAdmission, body, event, state, documents,
    calls: () => h.s3Calls.filter((call) => call.input.Bucket === "fabricated-audit") };
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((complete) => { resolve = complete; });
  return { promise, resolve };
}

beforeEach(() => { vi.useFakeTimers({ toFake: ["Date"] }); vi.setSystemTime(now); });
afterEach(() => {
  for (const socket of sockets.splice(0)) socket.destroy();
  vi.restoreAllMocks(); vi.unstubAllGlobals(); vi.unstubAllEnvs(); vi.useRealTimers();
});

describe("fixed private audit ingress and storage", () => {
  it("authenticates the broker run and persists only the admitted event and exact state binding", async () => {
    const f = await fixture();
    const admitted = await f.makeAdmission();
    const evidence = await persistPrivateRoleAuditEvent(f.id, admitted);
    const key = "events/event-1.json";
    const eventBytes = controlWire(f.event);
    expect(evidence).toEqual({ eventId: "event-1", eventSha256: controlHash(eventBytes), operationId: "operation-1",
      phase: "complete", recordedAt: now.toISOString(), retainUntil, configEpoch: 4,
      storage: { region: "us-east-2", bucket: "fabricated-audit", key, versionId: "audit-version-7" } });
    expect(f.h.fetchCalls.some((call) => call.url.endsWith("/actions/runs/101/attempts/2/jobs?per_page=100"))).toBe(true);
    expect(f.calls().map(({ kind }) => kind)).toEqual(["PutObjectCommand", "GetObjectCommand", "GetObjectRetentionCommand"]);
    const [put, get, retention] = f.calls().map(({ input }) => input);
    expect(put).toMatchObject({ Bucket: "fabricated-audit", Key: key, ExpectedBucketOwner: "123456789012",
      IfNoneMatch: "*", Body: eventBytes, ChecksumAlgorithm: "SHA256",
      ChecksumSHA256: createHash("sha256").update(eventBytes).digest("base64"),
      ServerSideEncryption: "aws:kms", SSEKMSKeyId: f.h.f.binding.aws.keys.serviceArn, BucketKeyEnabled: false,
      ObjectLockMode: "GOVERNANCE", ObjectLockRetainUntilDate: new Date(retainUntil),
      Metadata: { "state-version": Buffer.from(f.state.versionId).toString("base64url"),
        "state-sha256": controlHash(f.state.bytes), "state-key": f.state.key } });
    const exact = { Bucket: "fabricated-audit", Key: key, VersionId: "audit-version-7", ExpectedBucketOwner: "123456789012" };
    expect(get).toEqual({ ...exact, ChecksumMode: "ENABLED" });
    expect(retention).toEqual(exact);
    expect(f.h.stsCalls).toHaveLength(3);
    expect(f.h.stsCalls.every((call) => call.input.RoleArn.endsWith("/audit"))).toBe(true);
    for (const call of f.h.stsCalls) {
      expect(call.input.Policy).not.toMatch(/fabricated-(payload|state|custody)|DeleteObject|BypassGovernanceRetention|ListBucket/);
    }
    const readLease = JSON.parse(f.h.stsCalls[2].input.Policy).Statement;
    expect(readLease).toContainEqual({ Effect: "Allow", Action: "s3:GetObjectVersion", Resource: `arn:aws:s3:::fabricated-audit/${key}`,
      Condition: { StringEquals: { "s3:VersionId": "audit-version-7" } } });
    await expect(persistPrivateRoleAuditEvent(f.id, admitted)).rejects.toBeInstanceOf(PrivateIdentityError);
    expect(f.calls()).toHaveLength(3);
  });

  it.each(["put", "get"] as const)("closes the audit %s lease before a late provider response", async (phaseToPause) => {
    const reached = deferred<void>();
    const release = deferred<void>();
    let closeCount = 0;
    let lateBody: Readable | undefined;
    let providerReturned = false;
    const f = await fixture(async (phase, value, command) => {
      if (phase !== phaseToPause || command?.input.Bucket !== "fabricated-audit") return value;
      const client = vi.mocked(S3Client.prototype.send).mock.contexts.at(-1);
      if (!(client instanceof S3Client)) throw new Error("Missing scoped audit client");
      const destroy = client.destroy.bind(client);
      vi.spyOn(client, "destroy").mockImplementation(() => { closeCount++; destroy(); });
      if (phase === "get") {
        if (!(value.Body instanceof Readable)) throw new Error("Missing fabricated audit response body");
        lateBody = value.Body;
      }
      reached.resolve();
      await release.promise;
      providerReturned = true;
      return value;
    });
    const admitted = await f.makeAdmission();
    const controller = new AbortController();
    const pending = persistPrivateRoleAuditEvent(f.id, admitted, controller.signal);
    const expectedCommands = phaseToPause === "put" ? ["PutObjectCommand"] : ["PutObjectCommand", "GetObjectCommand"];
    const admissionRole = f.h.installed.binding.aws.roles.find((role) => role.purpose === "audit")!.arn;
    let beforeRelease: { closeCount: number; providerReturned: boolean; bodyDestroyed: boolean | undefined };
    try {
      expect(await Promise.race([reached.promise.then(() => "provider"), pending.then(() => "resolved", () => "rejected")]))
        .toBe("provider");
      expect(f.calls().map(({ kind }) => kind)).toEqual(expectedCommands);
      expect(f.h.stsCalls.map(({ input }) => input.RoleArn)).toEqual(Array(expectedCommands.length + 1).fill(admissionRole));
      controller.abort();
      await expect(pending).rejects.toBeInstanceOf(PrivateIdentityError);
      beforeRelease = { closeCount, providerReturned, bodyDestroyed: lateBody?.destroyed };
    } finally { release.resolve(); }
    await new Promise<void>((resolve) => setImmediate(resolve));
    expect({ beforeRelease, afterRelease: { closeCount, providerReturned, bodyDestroyed: lateBody?.destroyed } }).toEqual({
      beforeRelease: { closeCount: 1, providerReturned: false, bodyDestroyed: phaseToPause === "get" ? false : undefined },
      afterRelease: { closeCount: 1, providerReturned: true, bodyDestroyed: phaseToPause === "get" ? true : undefined }
    });
    await expect(persistPrivateRoleAuditEvent(f.id, admitted)).rejects.toBeInstanceOf(PrivateIdentityError);
    expect(f.calls().map(({ kind }) => kind)).toEqual(expectedCommands);
    expect(f.h.stsCalls).toHaveLength(expectedCommands.length + 1);
  });

  it("binds the challenge to the pinned TLS connection and consumes it once", async () => {
    const f = await fixture();
    const token = await f.h.peerToken(audience);
    const challenge = f.ingress.challenge(f.socket);
    const proof = f.proofFor(challenge);
    const other = mockSocket(f.publicKey);
    f.ingress.challenge(other);
    await expect(f.ingress.admit(other, token, proof, f.body)).rejects.toBeInstanceOf(PrivateIdentityError);
    expect(await f.ingress.admit(f.socket, token, proof, f.body)).toEqual({ eventId: "event-1" });
    await expect(f.ingress.admit(f.socket, token, proof, f.body)).rejects.toBeInstanceOf(PrivateIdentityError);
    expect(() => f.ingress.challenge(mockSocket(generateKeyPairSync("ed25519").publicKey))).toThrow(PrivateIdentityError);
    expect(f.calls()).toHaveLength(0);
  });

  it.each(["closed connection", "stale event"])("denies a previously admitted event on a %s", async (scenario) => {
    const f = await fixture();
    const admitted = await f.makeAdmission();
    if (scenario === "closed connection") f.socket.destroy();
    else vi.setSystemTime(new Date(now.getTime() + 61_000));
    await expect(persistPrivateRoleAuditEvent(f.id, admitted)).rejects.toBeInstanceOf(PrivateIdentityError);
    expect(f.h.stsCalls).toHaveLength(1);
    expect(f.calls()).toHaveLength(0);
  });

  it("enforces the installed approval cap even when the signed delegation would allow a longer approval", async () => {
    const f = await fixture(undefined, 60);
    await expect(f.makeAdmission()).rejects.toBeInstanceOf(PrivateIdentityError);
    expect(f.h.stsCalls).toHaveLength(1);
    expect(f.calls()).toHaveLength(0);
  });

  it("refuses the audit write if the broker run is cancelled after admission", async () => {
    let cancelled = false;
    const f = await fixture((phase, value) => cancelled && phase === "peer-current"
      ? { ...value, status: "completed", conclusion: "cancelled" } : value);
    const admitted = await f.makeAdmission();
    cancelled = true;
    await expect(persistPrivateRoleAuditEvent(f.id, admitted)).rejects.toBeInstanceOf(PrivateIdentityError);
    expect(f.calls()).toHaveLength(0);
  });

  it.each(["changed body", "AWS audience", "other workload", "other transport key", "cancelled broker"])(
    "denies %s before audit storage access", async (scenario) => {
      const f = await fixture((phase, value) => scenario === "cancelled broker" && phase === "peer-current"
        ? { ...value, status: "completed", conclusion: "cancelled" } : value);
      const token = await f.h.peerToken(scenario === "AWS audience" ? "sts.amazonaws.com" : audience,
        scenario === "other workload" ? "controller" : "read-broker");
      const fingerprint = scenario === "other transport key"
        ? f.h.installed.binding.workloads.find((workload) => workload.purpose === "controller")!.transportKeyFingerprint! : undefined;
      const proof = f.proofFor(f.ingress.challenge(f.socket), f.body, fingerprint);
      const body = scenario === "changed body" ? Buffer.concat([f.body, Buffer.from(" ")]) : f.body;
      const fetches = f.h.fetchCalls.length;
      const s3Calls = f.h.s3Calls.length;
      await expect(f.ingress.admit(f.socket, token, proof, body)).rejects.toBeInstanceOf(PrivateIdentityError);
      expect(f.calls()).toHaveLength(0);
      expect(f.h.stsCalls).toHaveLength(1);
      if (scenario === "changed body" || scenario === "other transport key") {
        expect(f.h.fetchCalls).toHaveLength(fetches);
        expect(f.h.s3Calls).toHaveLength(s3Calls);
      }
    });

  it.each(["wrong subject", "wrong state revision", "reserved rather than spent", "wrong state key"])(
    "checks %s even under a valid broker proof", async (scenario) => {
      const f = await fixture();
      const event = { ...f.event };
      const state = { ...f.state };
      if (scenario === "wrong subject") event.subject = { ...event.subject, commitSha: "e".repeat(40) };
      if (scenario === "wrong state revision") event.stateRevision++;
      if (scenario === "reserved rather than spent") state.bytes = controlWire({ ...JSON.parse(state.bytes.toString()), state: "reserved" });
      if (scenario === "wrong state key") state.key = privateApprovalStateKey("delegation-1", "approval-2");
      const body = encodePrivateReadAuditSubmission(controlWire(event), { ...f.documents, state });
      await expect(f.makeAdmission(body)).rejects.toBeInstanceOf(PrivateIdentityError);
      expect(f.calls()).toHaveLength(0);
    });

  it.each(["ambiguous put", "wrong version", "wrong checksum", "wrong service key", "changed state metadata", "shorter retention"])(
    "denies storage evidence after %s without retrying the write", async (scenario) => {
      const f = await fixture((phase, value, command) => {
        if (command?.input.Bucket !== "fabricated-audit") return value;
        if (scenario === "ambiguous put" && phase === "put") throw new Error("simulated lost write acknowledgment");
        if (scenario === "wrong version" && phase === "get") return { ...value, VersionId: "changed-version" };
        if (scenario === "wrong checksum" && phase === "get") return { ...value, ChecksumSHA256: "altered" };
        if (scenario === "wrong service key" && phase === "get") return { ...value, SSEKMSKeyId: "other-key" };
        if (scenario === "changed state metadata" && phase === "get") return { ...value, Metadata: { ...value.Metadata, "state-version": "changed" } };
        if (scenario === "shorter retention" && phase === "retention") {
          return { ...value, Retention: { ...value.Retention, RetainUntilDate: new Date(now) } };
        }
        return value;
      });
      const admitted = await f.makeAdmission();
      await expect(persistPrivateRoleAuditEvent(f.id, { ...admitted })).rejects.toBeInstanceOf(PrivateIdentityError);
      expect(f.calls()).toHaveLength(0);
      await expect(persistPrivateRoleAuditEvent(f.id, admitted)).rejects.toBeInstanceOf(PrivateIdentityError);
      await expect(persistPrivateRoleAuditEvent(f.id, admitted)).rejects.toBeInstanceOf(PrivateIdentityError);
      expect(f.calls().filter((call) => call.kind === "PutObjectCommand")).toHaveLength(1);
      if (scenario === "ambiguous put") expect(f.calls()).toHaveLength(1);
    });
});
