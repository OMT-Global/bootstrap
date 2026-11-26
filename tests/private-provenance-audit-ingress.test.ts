import { createHash, createPrivateKey, generateKeyPairSync, type KeyObject, type X509Certificate } from "node:crypto";
import { IncomingMessage, ServerResponse, type RequestListener } from "node:http";
import { Socket } from "node:net";
import { Readable } from "node:stream";
import { TLSSocket } from "node:tls";
import { KMSClient } from "@aws-sdk/client-kms";
import { S3Client } from "@aws-sdk/client-s3";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createPrivateReadAuditRequestListener } from "../src/private-provenance-audit-http.js";
import { controlHash, controlWire, verifyPrivateControl } from "../src/private-provenance-control.js";
import type { DeploymentBinding } from "../src/private-provenance-deployment.js";
import {
  createPrivateReadAuditIngress, persistPrivateRoleAuditEvent, PrivateIdentityError, signPrivateRoleAuditAck
} from "../src/private-provenance-identity.js";
import { encodePrivateReadAuditSubmission, privateApprovalStateKey, privateAuditAckSchema } from "../src/private-provenance-read.js";
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

async function fixture(fault?: Hook, approvalMaxSeconds = 300, withAckCustody = false) {
  const { publicKey } = generateKeyPairSync("ed25519");
  const tlsSpkiSha256 = createHash("sha256").update(publicKey.export({ type: "spki", format: "der" })).digest("hex");
  let stored: Buffer | undefined;
  let metadata: Record<string, string> | undefined;
  const wrappedSigner = Buffer.alloc(48, 0x45);
  const custody = { versionId: "audit-key-version", ciphertextSha256: controlHash(wrappedSigner) };
  let unwrapped: Buffer | undefined;
  let decryptFault: ((response: Record<string, unknown>) => Record<string, unknown>) | undefined;
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
    if (command?.input.Bucket === "fabricated-custody") {
      original = { ...original, VersionId: custody.versionId, ContentLength: wrappedSigner.byteLength, Body: Readable.from([wrappedSigner]),
        ChecksumSHA256: createHash("sha256").update(wrappedSigner).digest("base64") };
    }
    return await fault?.(phase, original, command) ?? original;
  }, ({ binding }: { binding: DeploymentBinding }) => {
    binding.endpoints.find((endpoint) => endpoint.purpose === "audit")!.tlsSpkiSha256 = tlsSpkiSha256;
    binding.policy.approvalMaxSeconds = approvalMaxSeconds;
    if (withAckCustody) binding.keys.find((key) => key.purpose === "audit-ack")!.custody = custody;
  });
  const auditKey = h.installed.keys.find((entry) => entry.purpose === "audit-ack")!;
  const kms = vi.spyOn(KMSClient.prototype, "send").mockImplementation((async () => {
    expect(withAckCustody).toBe(true);
    const pair = h.f.testKeyPair(auditKey.fingerprint);
    unwrapped = createPrivateKey({ key: pair.privateKey, format: "jwk" }).export({ format: "der", type: "pkcs8" });
    const response = { $metadata: { httpStatusCode: 200 }, KeyId: h.installed.binding.aws.keys.custodyArn,
      EncryptionAlgorithm: "SYMMETRIC_DEFAULT", Plaintext: unwrapped };
    return decryptFault?.(response) ?? response;
  }) as typeof KMSClient.prototype.send);
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
  return { h, id, ingress, socket, publicKey, proofFor, makeAdmission, body, event, state, documents, auditKey, kms, wrappedSigner,
    plaintext: () => unwrapped, setDecryptFault: (inject: NonNullable<typeof decryptFault>) => { decryptFault = inject; },
    calls: () => h.s3Calls.filter((call) => call.input.Bucket === "fabricated-audit") };
}

type Reply = { status: number; headers: Record<string, string | number>; bytes: Buffer };
type Challenge = ReturnType<ReturnType<typeof createPrivateReadAuditIngress>["challenge"]>;

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((complete) => { resolve = complete; });
  return { promise, resolve };
}

/** Exercise Node's listener objects without binding a port or completing a TLS handshake. */
function dispatchAuditHttp(listener: RequestListener, socket: Socket, url: string, options: {
  headers?: readonly string[];
  chunks?: readonly Buffer[];
  complete?: boolean;
  method?: string;
} = {}) {
  const request = new IncomingMessage(socket);
  request.httpVersion = "1.1";
  request.httpVersionMajor = 1;
  request.httpVersionMinor = 1;
  request.method = options.method ?? "POST";
  request.url = url;
  request.rawHeaders = [...(options.headers ?? ["Host", "audit.invalid", "Content-Length", "0"])];
  // Supply the parser's header groups without running a real HTTP connection.
  const headersDistinct: NodeJS.Dict<string[]> = Object.create(null);
  for (let i = 0; i < request.rawHeaders.length; i += 2) {
    (headersDistinct[request.rawHeaders[i]!.toLowerCase()] ??= []).push(request.rawHeaders[i + 1]!);
  }
  request.headersDistinct = headersDistinct;
  const response = new ServerResponse(request);
  const writeHead = vi.spyOn(response, "writeHead");
  const nativeEnd = response.end.bind(response);
  const finished = deferred<Reply>();
  const end = vi.spyOn(response, "end").mockImplementation(((chunk: Buffer) => {
    const body = Buffer.from(chunk);
    const result = nativeEnd(body);
    finished.resolve({ status: response.statusCode, headers: writeHead.mock.calls[0]?.[1] as Reply["headers"], bytes: body });
    return result;
  }) as typeof response.end);
  listener(request, response);
  const requestClose = request.listeners("close")[0];
  request.complete = options.complete ?? true;
  for (const part of options.chunks ?? []) request.push(part);
  request.push(null);
  return { request, response, requestClose, writeHead, end, done: finished.promise };
}

async function challengeOverHttp(listener: RequestListener, socket: TLSSocket): Promise<Challenge> {
  const reply = await dispatchAuditHttp(listener, socket, "/challenge").done;
  expect(reply.status).toBe(200);
  expect(reply.headers.connection).toBeUndefined();
  const value = JSON.parse(reply.bytes.toString()) as Challenge;
  expect(reply.bytes).toEqual(controlWire(value));
  expect(value).toMatchObject({ origin, audience });
  expect(Buffer.from(value.nonce, "base64")).toHaveLength(32);
  return value;
}

function auditHeaders(body: Buffer, token: string, proof: Buffer): string[] {
  return ["Host", "audit.invalid", "Content-Length", String(body.byteLength), "Content-Type", "application/json",
    "Authorization", `Bearer ${token}`, "X-Bootstrap-Workload-Proof", proof.toString("base64")];
}

function expectRedactedDenial(reply: Reply) {
  expect(reply.status).toBe(400);
  expect(reply.headers).toMatchObject({ connection: "close", "cache-control": "no-store", "content-type": "application/json",
    "content-length": reply.bytes.byteLength });
  expect(reply.bytes).toEqual(controlWire({ error: "Private audit request unavailable or invalid." }));
}

beforeEach(() => { vi.useFakeTimers({ toFake: ["Date"] }); vi.setSystemTime(now); });
afterEach(() => {
  for (const socket of sockets.splice(0)) socket.destroy();
  vi.restoreAllMocks(); vi.unstubAllGlobals(); vi.unstubAllEnvs(); vi.useRealTimers();
});

describe("private audit HTTPS listener", () => {
  it("sends one canonical signed ACK only after exact retention readback and refuses a replay", async () => {
    const readingRetention = deferred<void>();
    const releaseRetention = deferred<void>();
    const f = await fixture(async (phase, value, command) => {
      if (phase === "retention" && command?.input.Bucket === "fabricated-audit") {
        readingRetention.resolve();
        await releaseRetention.promise;
      }
      return value;
    }, 300, true);
    const listener = createPrivateReadAuditRequestListener(f.id);
    const challenge = await challengeOverHttp(listener, f.socket);
    const headers = auditHeaders(f.body, await f.h.peerToken(audience), f.proofFor(challenge));
    const submitted = dispatchAuditHttp(listener, f.socket, "/audit", {
      headers, chunks: [f.body.subarray(0, 11), f.body.subarray(11)]
    });
    await readingRetention.promise;
    try {
      expect(submitted.writeHead).not.toHaveBeenCalled();
      expect(submitted.end).not.toHaveBeenCalled();
      expect(f.kms).not.toHaveBeenCalled();
    } finally { releaseRetention.resolve(); }
    const reply = await submitted.done;
    expect(reply.status).toBe(200);
    expect(reply.headers).toMatchObject({ connection: "close", "cache-control": "no-store", "content-length": reply.bytes.byteLength });
    expect(submitted.end).toHaveBeenCalledOnce();
    const { ownerId, publicJwk, notBefore, notAfter, revoked } = f.auditKey;
    const verified = verifyPrivateControl(reply.bytes, privateAuditAckSchema, "audit-ack",
      [{ ownerId, publicKey: publicJwk, purpose: "audit-ack", notBefore, notAfter, revoked }], now);
    expect(verified.ownerId).toBe("worker-audit");
    expect(verified.fingerprint).toBe(f.auditKey.fingerprint);
    expect(verified.payload).toEqual({ ...base("bootstrap-private-audit-ack"), eventId: "event-1",
      eventSha256: controlHash(controlWire(f.event)), operationId: "operation-1", phase: "complete",
      recordedAt: now.toISOString(), retainUntil, configEpoch: 4,
      storage: { region: "us-east-2", bucket: "fabricated-audit", key: "events/event-1.json", versionId: "audit-version-7" } });
    expectRedactedDenial(await dispatchAuditHttp(listener, f.socket, "/audit", { headers, chunks: [f.body] }).done);
    expect(f.calls().map(({ kind }) => kind)).toEqual(["PutObjectCommand", "GetObjectCommand", "GetObjectRetentionCommand"]);
    expect(f.kms).toHaveBeenCalledOnce();
  });

  it.each(["wrong method", "wrong host", "alternate path", "duplicate length", "chunked body", "oversize", "plain socket"])(
    "refuses %s before issuing a challenge or calling a provider", async (scenario) => {
      const f = await fixture();
      const listener = createPrivateReadAuditRequestListener(f.id);
      const headers = ["Host", scenario === "wrong host" ? "other.invalid" : "audit.invalid",
        "Content-Length", scenario === "oversize" ? "65537" : "0"];
      if (scenario === "duplicate length") headers.push("Content-Length", "0");
      if (scenario === "chunked body") headers.push("Transfer-Encoding", "chunked");
      const socket = scenario === "plain socket" ? new Socket() : f.socket;
      const calls = [f.h.fetchCalls.length, f.h.s3Calls.length];
      try {
        expectRedactedDenial(await dispatchAuditHttp(listener, socket, scenario === "alternate path" ? "/challenge?probe=1" : "/challenge",
          { headers, method: scenario === "wrong method" ? "GET" : "POST" }).done);
      } finally { if (socket !== f.socket) socket.destroy(); }
      expect([f.h.fetchCalls.length, f.h.s3Calls.length]).toEqual(calls);
      expect(f.kms).not.toHaveBeenCalled();
    });

  it.each(["duplicate bearer", "different challenged socket", "changed signed body"])(
    "refuses %s before reading deployment or writing audit storage", async (scenario) => {
      const f = await fixture();
      const listener = createPrivateReadAuditRequestListener(f.id);
      const challenge = await challengeOverHttp(listener, f.socket);
      const proof = f.proofFor(challenge);
      const token = await f.h.peerToken(audience);
      const body = scenario === "changed signed body" ? Buffer.concat([f.body, Buffer.from(" ")]) : f.body;
      const headers = auditHeaders(body, token, proof);
      if (scenario === "duplicate bearer") headers.push("Authorization", `Bearer ${token}`);
      const socket = scenario === "different challenged socket" ? mockSocket(f.publicKey) : f.socket;
      if (socket !== f.socket) await challengeOverHttp(listener, socket);
      const calls = [f.h.fetchCalls.length, f.h.s3Calls.length];
      expectRedactedDenial(await dispatchAuditHttp(listener, socket, "/audit", { headers, chunks: [body] }).done);
      expect([f.h.fetchCalls.length, f.h.s3Calls.length]).toEqual(calls);
      expect(f.kms).not.toHaveBeenCalled();
    });

  it("does not acknowledge a native request whose body ends before its declared length", async () => {
    const f = await fixture();
    const listener = createPrivateReadAuditRequestListener(f.id);
    const challenge = await challengeOverHttp(listener, f.socket);
    const headers = auditHeaders(f.body, await f.h.peerToken(audience), f.proofFor(challenge));
    const calls = [f.h.fetchCalls.length, f.h.s3Calls.length];
    const partial = dispatchAuditHttp(listener, f.socket, "/audit", { headers, chunks: [f.body.subarray(0, 11)], complete: false });
    await vi.waitFor(() => expect(partial.request.listeners("close")).not.toContain(partial.requestClose));
    expect(partial.writeHead.mock.calls.every(([status]) => status !== 200)).toBe(true);
    expect([f.h.fetchCalls.length, f.h.s3Calls.length]).toEqual(calls);
    expect(f.kms).not.toHaveBeenCalled();
  });

  it("closes the connection rather than returning an ACK when a second request is pipelined", async () => {
    const readingRetention = deferred<void>();
    const releaseRetention = deferred<void>();
    const f = await fixture(async (phase, value, command) => {
      if (phase === "retention" && command?.input.Bucket === "fabricated-audit") {
        readingRetention.resolve();
        await releaseRetention.promise;
      }
      return value;
    }, 300, true);
    const listener = createPrivateReadAuditRequestListener(f.id);
    const challenge = await challengeOverHttp(listener, f.socket);
    const headers = auditHeaders(f.body, await f.h.peerToken(audience), f.proofFor(challenge));
    const first = dispatchAuditHttp(listener, f.socket, "/audit", { headers, chunks: [f.body] });
    await readingRetention.promise;
    const duplicate = dispatchAuditHttp(listener, f.socket, "/audit", { headers, chunks: [f.body] });
    try { expect(f.socket.destroyed).toBe(true); }
    finally { releaseRetention.resolve(); }
    await vi.waitFor(() => expect(first.request.listeners("close")).not.toContain(first.requestClose));
    expect(first.end).not.toHaveBeenCalled();
    expect(duplicate.end).not.toHaveBeenCalled();
    expect(f.calls().filter((call) => call.kind === "PutObjectCommand")).toHaveLength(1);
    expect(f.kms).not.toHaveBeenCalled();
  });

  it.each(["readback", "signer"])("fails closed with a redacted response when the %s fails", async (failure) => {
    const f = await fixture((phase, value, command) => {
      if (failure === "readback" && phase === "get" && command?.input.Bucket === "fabricated-audit") {
        throw new Error("private fabricated readback detail");
      }
      return value;
    }, 300, true);
    if (failure === "signer") f.setDecryptFault(() => { throw new Error("private fabricated signer detail"); });
    const listener = createPrivateReadAuditRequestListener(f.id);
    const challenge = await challengeOverHttp(listener, f.socket);
    const headers = auditHeaders(f.body, await f.h.peerToken(audience), f.proofFor(challenge));
    expectRedactedDenial(await dispatchAuditHttp(listener, f.socket, "/audit", { headers, chunks: [f.body] }).done);
    expectRedactedDenial(await dispatchAuditHttp(listener, f.socket, "/audit", { headers, chunks: [f.body] }).done);
    expect(f.calls().filter((call) => call.kind === "PutObjectCommand")).toHaveLength(1);
    expect(f.kms).toHaveBeenCalledTimes(failure === "signer" ? 1 : 0);
  });
});

describe("fixed private audit ingress and storage", () => {
  it("signs the exact retained audit result once with only the enrolled audit-ack custody key", async () => {
    const f = await fixture(undefined, 300, true);
    const stored = await persistPrivateRoleAuditEvent(f.id, await f.makeAdmission());
    await expect(signPrivateRoleAuditAck(f.id, { ...stored })).rejects.toBeInstanceOf(PrivateIdentityError);
    await expect(signPrivateRoleAuditAck({ ...f.id }, stored)).rejects.toBeInstanceOf(PrivateIdentityError);
    expect(f.kms).not.toHaveBeenCalled();
    const signed = await signPrivateRoleAuditAck(f.id, stored);
    const { ownerId, publicJwk, notBefore, notAfter, revoked } = f.auditKey;
    const verified = verifyPrivateControl(signed, privateAuditAckSchema, "audit-ack",
      [{ ownerId, publicKey: publicJwk, purpose: "audit-ack", notBefore, notAfter, revoked }], now);
    expect(verified.payload).toEqual({ ...base("bootstrap-private-audit-ack"), ...stored });
    expect(verified.fingerprint).toBe(f.auditKey.fingerprint);
    expect(f.kms).toHaveBeenCalledTimes(1);
    const command = f.kms.mock.calls[0]?.[0] as unknown as { input: object };
    expect(command.input).toMatchObject({ CiphertextBlob: f.wrappedSigner,
      KeyId: f.h.installed.binding.aws.keys.custodyArn, EncryptionContext: {
        purpose: "audit-ack", ownerId: "worker-audit", fingerprint: f.auditKey.fingerprint, configEpoch: "4"
      } });
    const lease = f.h.stsCalls.at(-1)!.input;
    expect(lease.RoleArn).toMatch(/\/audit$/);
    expect(lease.Policy).toContain("audit-key-version");
    expect(lease.Policy).not.toMatch(/fabricated-(audit|config|payload|state)|ListBucket|kms:Sign/);
    expect(f.plaintext()?.every((byte) => byte === 0)).toBe(true);
    await expect(signPrivateRoleAuditAck(f.id, stored)).rejects.toBeInstanceOf(PrivateIdentityError);
    expect(f.kms).toHaveBeenCalledTimes(1);
  });

  it.each(["missing descriptor", "closed connection", "stale audit event", "wrong KMS key", "wrong key fingerprint"])(
    "withholds the audit acknowledgment for %s", async (failure) => {
      const f = await fixture(undefined, 300, failure !== "missing descriptor");
      const stored = await persistPrivateRoleAuditEvent(f.id, await f.makeAdmission());
      if (failure === "closed connection") f.socket.destroy();
      if (failure === "stale audit event") vi.setSystemTime(new Date(now.getTime() + 61_000));
      if (failure === "wrong KMS key") f.setDecryptFault((response) => ({ ...response, KeyId: f.h.installed.binding.aws.keys.clientArn }));
      if (failure === "wrong key fingerprint") f.setDecryptFault((response) => ({
        ...response, Plaintext: generateKeyPairSync("ed25519").privateKey.export({ format: "der", type: "pkcs8" })
      }));
      await expect(signPrivateRoleAuditAck(f.id, stored)).rejects.toBeInstanceOf(PrivateIdentityError);
      expect(f.kms).toHaveBeenCalledTimes(failure.startsWith("wrong") ? 1 : 0);
    });

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
    }, 300, true);
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
    expect(f.kms).not.toHaveBeenCalled();
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
