import { createHash, createPrivateKey, generateKeyPairSync, type KeyObject, type X509Certificate } from "node:crypto";
import { EventEmitter } from "node:events";
import { IncomingMessage, ServerResponse, type RequestListener } from "node:http";
import { Socket } from "node:net";
import { Readable } from "node:stream";
import { TLSSocket } from "node:tls";
import { KMSClient } from "@aws-sdk/client-kms";
import { decodeJwt } from "jose";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { controlHash, controlWire, verifyPrivateControl } from "../src/private-provenance-control.js";
import type { DeploymentBinding } from "../src/private-provenance-deployment.js";
import { createPrivateReadAuditRequestListener } from "../src/private-provenance-audit-http.js";
import { privateApprovalStateKey, privateAuditAckSchema } from "../src/private-provenance-read.js";
import * as identity from "../src/private-provenance-identity.js";
import { now, payloadHarness, retainUntil } from "./helpers/private-provenance-aws-fixture.js";

const https = vi.hoisted(() => ({ request: vi.fn() }));
vi.mock("node:https", async (original) => {
  const actual = await original<typeof import("node:https")>();
  return { ...actual, request: https.request };
});

const origin = "https://audit.invalid";
const audience = origin + "/audit";
const fields = (domain: string) => ({ domain, canonicalization: "sorted-json-v1", version: 1 });
const checksum = (value: Buffer) => createHash("sha256").update(value).digest("base64");
const sockets: TLSSocket[] = [];

function fakeTls(publicKey: KeyObject, server = false) {
  const socket = new TLSSocket(new Socket(), { isServer: server });
  sockets.push(socket);
  Object.defineProperty(socket, "authorized", { value: true });
  vi.spyOn(socket, "getProtocol").mockReturnValue("TLSv1.3");
  vi.spyOn(socket, "getX509Certificate").mockReturnValue({ publicKey } as X509Certificate);
  vi.spyOn(socket, "getPeerX509Certificate").mockReturnValue({ publicKey } as X509Certificate);
  return socket;
}

type Headers = Record<string, string>;
function attachHeaders(message: IncomingMessage, headers: Headers, duplicateType = false) {
  message.headersDistinct = Object.fromEntries(Object.entries(headers).map(([name, value]) => [name.toLowerCase(), [value]]));
  message.rawHeaders = Object.entries(headers).flat();
  if (duplicateType) {
    message.headersDistinct["content-type"]?.push("application/json");
    message.rawHeaders.push("Content-Type", "application/json");
  }
}

type Reply = { status: number; headers: Headers; body: Buffer };
function serve(listener: RequestListener, socket: TLSSocket, route: string, headers: Headers, body: Buffer): Promise<Reply> {
  return new Promise((resolve) => {
    const incoming = new IncomingMessage(socket);
    incoming.httpVersion = "1.1";
    incoming.method = "POST";
    incoming.url = route;
    attachHeaders(incoming, headers);
    const response = new ServerResponse(incoming);
    const write = vi.spyOn(response, "writeHead");
    const end = response.end.bind(response);
    vi.spyOn(response, "end").mockImplementation(((chunk: Buffer) => {
      const result = end(chunk);
      const outputHeaders = write.mock.calls[0]?.[1] as Record<string, string | number>;
      resolve({ status: response.statusCode, headers: Object.fromEntries(Object.entries(outputHeaders)
        .map(([name, value]) => [name, String(value)])), body: Buffer.from(chunk) });
      return result;
    }) as typeof response.end);
    listener(incoming, response);
    incoming.complete = true;
    if (body.length) incoming.push(body);
    incoming.push(null);
  });
}

type Fault = "replacement TLS" | "late audit socket" | "expired config on audit socket" | "wrong SPKI" | "wrong challenge origin" | "stale challenge" | "duplicate response type" |
  "wrong acknowledgment socket" | "short response" | "wrong signed acknowledgment" | "lost acknowledgment";
type RequestOptions = { hostname?: string; protocol?: string; method?: string; path: string; headers?: Headers;
  rejectUnauthorized?: boolean; signal?: AbortSignal; agent?: unknown };
function wire(listener: RequestListener, publicKey: KeyObject, fault: Fault | undefined,
  signWrongAck: (bytes: Buffer) => Buffer) {
  const client = fakeTls(fault === "wrong SPKI" ? generateKeyPairSync("ed25519").publicKey : publicKey);
  const server = fakeTls(publicKey, true);
  const requests: RequestOptions[] = [];
  const sends: { path: string; headers: Headers; body: Buffer }[] = [];
  const setHeaders: { path: string; name: string }[] = [];
  https.request.mockImplementation((options: RequestOptions, onResponse: (response: IncomingMessage) => void) => {
    requests.push(options);
    const request = new EventEmitter();
    const headers = { ...options.headers };
    if (onResponse) request.once("response", onResponse);
    const socket = fault === "replacement TLS" && options.path === "/audit" ? fakeTls(publicKey) : client;
    let destroyed = false;
    const handle = Object.assign(request, {
      destroy(error?: Error) {
        destroyed = true;
        if (error) queueMicrotask(() => request.emit("error", error));
        return handle;
      },
      setHeader(name: string, value: string | number) {
        setHeaders.push({ path: options.path, name: name.toLowerCase() });
        headers[name.toLowerCase()] = String(value);
        return handle;
      },
      end(value?: Uint8Array) {
        const bytes = value ? Buffer.from(value) : Buffer.alloc(0);
        const normalized = Object.fromEntries(Object.entries(headers).map(([name, value]) => [name.toLowerCase(), String(value)]));
        normalized.host ??= options.hostname ?? "";
        sends.push({ path: options.path, headers: normalized, body: bytes });
        void serve(listener, server, options.path, normalized, bytes).then((reply) => {
          if (destroyed) return;
          if (fault === "lost acknowledgment" && options.path === "/audit") {
            request.emit("error", new Error("fabricated lost audit response"));
            return;
          }
          if (fault === "wrong challenge origin" && options.path === "/challenge") {
            reply.body = controlWire({ ...JSON.parse(reply.body.toString()), origin: "https://unregistered.invalid" });
          }
          if (fault === "stale challenge" && options.path === "/challenge") vi.setSystemTime(now.getTime() + 3_000);
          if (fault === "wrong signed acknowledgment" && options.path === "/audit") reply.body = signWrongAck(reply.body);
          reply.headers["content-length"] = String(reply.body.length);
          const response = new IncomingMessage(fault === "wrong acknowledgment socket" && options.path === "/audit"
            ? fakeTls(publicKey) : socket);
          response.httpVersion = "1.1";
          response.statusCode = reply.status;
          attachHeaders(response, reply.headers, fault === "duplicate response type" && options.path === "/challenge");
          response.complete = fault !== "short response" || options.path !== "/audit";
          request.emit("response", response);
          response.push(response.complete ? reply.body : reply.body.subarray(0, reply.body.length - 1));
          response.push(null);
        }).catch((error: unknown) => request.emit("error", error));
        return handle;
      }
    });
    Object.defineProperty(handle, "destroyed", { get: () => destroyed });
    queueMicrotask(() => {
      if (destroyed) return;
      if ((fault === "late audit socket" || fault === "expired config on audit socket") && options.path === "/audit") {
        vi.setSystemTime(now.getTime() + 3_000);
      }
      request.emit("socket", socket);
    });
    return handle;
  });
  return { requests, sends, setHeaders };
}

async function fixture(fault?: Fault) {
  const { publicKey } = generateKeyPairSync("ed25519");
  const pin = createHash("sha256").update(publicKey.export({ type: "spki", format: "der" })).digest("hex");
  const wrapped = { transport: Buffer.alloc(48, 0x4a), ack: Buffer.alloc(48, 0x4b) };
  const versions = { transport: "fabricated-transport-version", ack: "fabricated-ack-version" };
  let storedEvent: Buffer | undefined;
  let metadata: object | undefined;
  const h = await payloadHarness("audit", (phase, value, command) => {
    if (command?.input.Bucket === "fabricated-custody") {
      const transport = command.input.Key.startsWith("keys/transport/");
      const object = transport ? wrapped.transport : wrapped.ack;
      return { ...value, VersionId: transport ? versions.transport : versions.ack,
        ContentLength: object.length, Body: Readable.from([object]), ChecksumSHA256: checksum(object) };
    }
    if (command?.input.Bucket !== "fabricated-audit") return value;
    if (phase === "put") { storedEvent = Buffer.from(command.input.Body); metadata = structuredClone(command.input.Metadata); }
    if (phase === "put" || phase === "get") {
      return { ...value, VersionId: "audit-object-v1", ETag: '"fabricated-audit-etag"', ChecksumSHA256: checksum(storedEvent!),
        Metadata: metadata, ContentLength: storedEvent!.length, Body: Readable.from([storedEvent!]) };
    }
    return value;
  }, ({ binding }: { binding: DeploymentBinding }) => {
    binding.endpoints.find((endpoint) => endpoint.purpose === "audit")!.tlsSpkiSha256 = pin;
    if (fault === "stale challenge" || fault === "late audit socket") binding.policy.challengeMaxSeconds = 2;
    const broker = binding.workloads.find((item) => item.purpose === "read-broker")!;
    binding.keys.find((item) => item.fingerprint === broker.transportKeyFingerprint)!.custody = {
      versionId: versions.transport, ciphertextSha256: controlHash(wrapped.transport)
    };
    binding.keys.find((item) => item.purpose === "audit-ack")!.custody = {
      versionId: versions.ack, ciphertextSha256: controlHash(wrapped.ack)
    };
  });
  if (fault === "expired config on audit socket") {
    h.setPointer({ ...h.f.pointer(), validUntil: new Date(now.getTime() + 2_000).toISOString() });
  }
  const auditor = await h.start();
  const brokerIdentity = await h.startBroker();
  const broker = h.installed.binding.workloads.find((item) => item.purpose === "read-broker")!;
  const auditKey = h.installed.keys.find((item) => item.purpose === "audit-ack")!;
  const kmsCalls: { key: string; owner: string; purpose: string; bytes: Buffer }[] = [];
  vi.spyOn(KMSClient.prototype, "send").mockImplementation((async (command: {
    input: { KeyId: string; CiphertextBlob: Uint8Array; EncryptionContext: Record<string, string> }
  }) => {
    const { fingerprint, purpose, ownerId } = command.input.EncryptionContext;
    const expectedFingerprint = purpose === "workload-transport" ? broker.transportKeyFingerprint : auditKey.fingerprint;
    const expectedBytes = purpose === "workload-transport" ? wrapped.transport : wrapped.ack;
    if (expectedFingerprint !== fingerprint || !Buffer.from(command.input.CiphertextBlob).equals(expectedBytes)
      || ownerId !== (purpose === "workload-transport" ? broker.id : auditKey.ownerId)) throw new Error("Unexpected fabricated custody scope");
    const pair = h.f.testKeyPair(fingerprint!);
    const bytes = createPrivateKey({ key: pair.privateKey, format: "jwk" }).export({ format: "der", type: "pkcs8" });
    kmsCalls.push({ key: command.input.KeyId, purpose: purpose!, owner: ownerId!, bytes });
    return { $metadata: { httpStatusCode: 200 }, KeyId: h.installed.binding.aws.keys.custodyArn,
      EncryptionAlgorithm: "SYMMETRIC_DEFAULT", Plaintext: bytes };
  }) as typeof KMSClient.prototype.send);
  const transport = wire(createPrivateReadAuditRequestListener(auditor), publicKey, fault, (reply) =>
    h.f.signed({ ...JSON.parse(reply.toString()).payload, operationId: "other-operation" }, auditKey.fingerprint));
  const requester = h.installed.binding.principals.find((item) => item.kind === "requester")!;
  const codex = h.installed.binding.workloads.find((item) => item.purpose === "codex-approver")!;
  const issuedAt = new Date(now.getTime() - 10_000).toISOString();
  const expiresAt = new Date(now.getTime() + 240_000).toISOString();
  const scope = { subject: { repository: "fixture/control", commitSha: "b".repeat(40) }, runId: "gh-100-2",
    storage: h.storage, receiptSha256: "c".repeat(64), purposeId: "provenance-verification" };
  const categoryIds = ["validation-summary"];
  const request = h.f.signed({ ...fields("bootstrap-private-read-request"), requestId: "request-1",
    requesterId: requester.id, configEpoch: 4, ...scope, requestedCategoryIds: categoryIds, issuedAt, expiresAt }, requester.signingKeyFingerprint);
  const approval = h.f.signed({ ...fields("bootstrap-private-read-approval"), approvalId: "approval-1", delegationId: "delegation-1",
    configEpoch: 4, approverWorkloadId: codex.id, requesterId: requester.id, requestSha256: controlHash(request), ...scope, categoryIds,
    maxUses: 1, issuedAt, notBefore: issuedAt, expiresAt }, codex.signingKeyFingerprint!);
  const delegation = h.f.signed({ ...fields("bootstrap-codex-read-delegation"), delegationId: "delegation-1",
    configEpoch: 4, approverWorkloadId: codex.id, approverKeyFingerprint: codex.signingKeyFingerprint, repositoryIds: ["123"],
    requesterIds: [requester.id], categoryIds, purposeIds: [scope.purposeId], maxApprovalSeconds: 300, maxUses: 1,
    issuedAt, notBefore: issuedAt, expiresAt });
  const state = { key: privateApprovalStateKey("delegation-1", "approval-1"), versionId: "state-v3",
    bytes: controlWire({ approvalId: "approval-1", delegationId: "delegation-1", approvalSha256: controlHash(approval),
      configEpoch: 4, revision: 2, state: "spent", requestId: "request-1", operationId: "operation-1",
      revocationSha256: null, updatedAt: now.toISOString() }) };
  const event = controlWire({ ...fields("bootstrap-private-audit-event"), ...scope, eventId: "event-1", operationId: "operation-1",
    phase: "complete", at: now.toISOString(), configEpoch: 4, actorId: requester.id, workloadId: broker.id,
    requestSha256: controlHash(request), approvalSha256: controlHash(approval), delegationId: "delegation-1", stateRevision: 2,
    resultCode: "OK", previousEventSha256: "d".repeat(64) });
  return { h, auditor, brokerIdentity, broker, auditKey, event, evidence: { approval, delegation, request, state },
    kmsCalls, transport, writes: () => h.s3Calls.filter((call) => call.kind === "PutObjectCommand" && call.input.Bucket === "fabricated-audit") };
}

beforeEach(() => { vi.useFakeTimers({ toFake: ["Date"] }); vi.setSystemTime(now); https.request.mockReset(); });
afterEach(() => {
  for (const socket of sockets.splice(0)) socket.destroy();
  vi.restoreAllMocks(); vi.unstubAllGlobals(); vi.unstubAllEnvs(); vi.useRealTimers();
});

describe("broker audit delivery using the actual protected listener", () => {
  it("sends one authenticated audit body on the challenged TLS socket, then verifies its exact acknowledgment", async () => {
    const f = await fixture();
    const send = identity.createPrivateRoleReadBrokerAudit(f.brokerIdentity);
    const bytes = await send(f.event, f.evidence);
    expect(f.transport.requests.map(({ path }) => path)).toEqual(["/challenge", "/audit"]);
    expect(f.transport.requests.every(({ hostname, protocol, method, rejectUnauthorized }) =>
      hostname === "audit.invalid" && protocol === "https:" && method === "POST" && rejectUnauthorized === true)).toBe(true);
    expect(f.transport.requests[1]!.agent).toBe(f.transport.requests[0]!.agent);
    expect(f.transport.sends[0]!.headers.authorization).toBeUndefined();
    expect(f.transport.sends[0]!.body).toHaveLength(0);
    const sent = f.transport.sends[1]!;
    const token = sent.headers.authorization?.slice("Bearer ".length);
    expect(token ? decodeJwt(token).aud : undefined).toBe(audience);
    expect(f.h.fetchCalls.some((call) => new URL(call.url).searchParams.get("audience") === audience)).toBe(true);
    const { ownerId, publicJwk, notBefore, notAfter, revoked } = f.auditKey;
    const verified = verifyPrivateControl(bytes, privateAuditAckSchema, "audit-ack",
      [{ ownerId, publicKey: publicJwk, purpose: "audit-ack", notBefore, notAfter, revoked }], now);
    expect(verified.payload).toMatchObject({ eventId: "event-1", operationId: "operation-1", phase: "complete",
      eventSha256: controlHash(f.event), retainUntil, storage: { bucket: "fabricated-audit", key: "events/event-1.json",
        versionId: "audit-object-v1" } });
    expect(f.writes()).toHaveLength(1);
    expect(f.writes()[0].input.Body).toEqual(f.event);
    expect(f.kmsCalls.map(({ owner, purpose }) => [owner, purpose])).toEqual([
      [f.broker.id, "workload-transport"], [ownerId, "audit-ack"]
    ]);
    const brokerCustody = f.h.stsCalls.filter((call) => call.input.RoleArn.endsWith("/read-broker")).at(-1)!;
    expect(brokerCustody.input.Policy).toContain(`keys/transport/v1/4/${f.broker.transportKeyFingerprint}.pkcs8.kms`);
    expect(brokerCustody.input.Policy).not.toMatch(/fabricated-(?:audit|payload|state)|keys\/semantic\/|ListBucket|kms:Sign/);
    expect(f.kmsCalls.every(({ bytes }) => bytes.every((byte) => byte === 0))).toBe(true);
  });

  it.each(["replacement TLS", "late audit socket", "expired config on audit socket", "wrong SPKI", "wrong challenge origin", "stale challenge", "duplicate response type"] as const)(
    "blocks %s before audit token, proof or body delivery", async (fault) => {
      const f = await fixture(fault);
      await expect(identity.createPrivateRoleReadBrokerAudit(f.brokerIdentity)(f.event, f.evidence)).rejects.toBeInstanceOf(identity.PrivateIdentityError);
      expect(f.transport.sends.every(({ path, headers }) => path === "/challenge" && !headers.authorization
        && !headers["x-bootstrap-workload-proof"])).toBe(true);
      expect(f.transport.setHeaders.some(({ name }) => name === "authorization" || name === "x-bootstrap-workload-proof")).toBe(false);
      expect(f.transport.requests.every(({ headers }) => !Object.keys(headers ?? {})
        .some((name) => ["authorization", "x-bootstrap-workload-proof"].includes(name.toLowerCase())))).toBe(true);
      const submitted = fault === "replacement TLS" || fault === "late audit socket" || fault === "expired config on audit socket";
      expect(f.transport.requests.map(({ path }) => path)).toEqual(submitted ? ["/challenge", "/audit"] : ["/challenge"]);
      if (!submitted) {
        expect(f.h.fetchCalls.some((call) => new URL(call.url).searchParams.get("audience") === audience)).toBe(false);
        expect(f.kmsCalls).toHaveLength(0);
      }
      expect(f.writes()).toHaveLength(0);
    });

  it.each(["wrong signed acknowledgment", "wrong acknowledgment socket", "short response", "lost acknowledgment"] as const)(
    "rejects %s after one write and never retries delivery", async (fault) => {
      const f = await fixture(fault);
      await expect(identity.createPrivateRoleReadBrokerAudit(f.brokerIdentity)(f.event, f.evidence)).rejects.toBeInstanceOf(identity.PrivateIdentityError);
      expect(f.transport.requests.map(({ path }) => path)).toEqual(["/challenge", "/audit"]);
      expect(f.writes()).toHaveLength(1);
    });
});
