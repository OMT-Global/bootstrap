import { createPrivateKey, sign } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import { generateProvenanceSigningKeyPair, provenanceSigningKeyFingerprint } from "../src/provenance.js";
import { controlHash, controlWire, type PrivateControlKey } from "../src/private-provenance-control.js";
import { createPrivateReadCoordinator, privateApprovalStateKey, PrivateStateConflict, type PrivateReadObservation } from "../src/private-provenance-read.js";

const start = "2026-11-15T00:00:00.000Z";
const expiry = "2026-11-15T00:05:00.000Z";
const marker = "provider-private-detail-do-not-echo";
const base = (domain: string) => ({ domain, version: 1, canonicalization: "sorted-json-v1" });
function fixture() {
  const root = generateProvenanceSigningKeyPair(); const requester = generateProvenanceSigningKeyPair();
  const approver = generateProvenanceSigningKeyPair(); const auditor = generateProvenanceSigningKeyPair();
  const signed = (payload: unknown, key = approver) => controlWire({ payload, signature: {
    keyFingerprint: provenanceSigningKeyFingerprint(key.publicKey),
    value: sign(null, controlWire(payload), createPrivateKey({ key: key.privateKey, format: "jwk" })).toString("base64")
  } });
  const keys: PrivateControlKey[] = [[root, "root", "deployment-root"], [requester, "reader", "requester-request"],
    [approver, "codex", "codex-read-approval"], [auditor, "audit", "audit-ack"]].map(([key, ownerId, purpose]) => ({
      ownerId, purpose, publicKey: (key as typeof root).publicKey, notBefore: start, notAfter: "2027-01-01T00:00:00.000Z", revoked: false
    })) as PrivateControlKey[];
  const storage = { region: "us-east-2", bucket: "fabricated-payload", key: "fixture", versionId: "v1" };
  const scope = { subject: { repository: "fixture/example", commitSha: "a".repeat(40) }, runId: "gh-1-1", storage, receiptSha256: "b".repeat(64) };
  const request = { ...base("bootstrap-private-read-request"), requestId: "request-1", configEpoch: 1,
    requesterId: "reader", purposeId: "provenance-verification", ...scope, requestedCategoryIds: ["validation-summary"], issuedAt: start, expiresAt: expiry };
  const delegation = { ...base("bootstrap-codex-read-delegation"), delegationId: "delegation-1", configEpoch: 1,
    approverWorkloadId: "codex", approverKeyFingerprint: provenanceSigningKeyFingerprint(approver.publicKey),
    repositoryIds: ["123"], requesterIds: ["reader"], categoryIds: ["validation-summary"], purposeIds: ["provenance-verification"],
    maxApprovalSeconds: 300, maxUses: 1, issuedAt: start, notBefore: start, expiresAt: "2026-11-16T00:00:00.000Z" };
  const requestBytes = signed(request, requester);
  const approval = { ...base("bootstrap-private-read-approval"), approvalId: "approval-1", delegationId: "delegation-1", configEpoch: 1,
    approverWorkloadId: "codex", requestSha256: controlHash(requestBytes), requesterId: "reader", purposeId: "provenance-verification", ...scope,
    categoryIds: ["validation-summary"], maxUses: 1, issuedAt: start, notBefore: start, expiresAt: expiry };
  const documents = { request: requestBytes, approval: signed(approval), delegation: signed(delegation, root) };
  const observed: PrivateReadObservation = { configEpoch: 1, repositoryId: "123", repository: "fixture/example", requesterId: "reader", auditOwnerId: "audit",
    brokerWorkloadId: "broker-1", auditBucket: "fabricated-audit", auditPrefix: "events/", keys };
  let time = new Date("2026-11-15T00:00:10.000Z"); let serial = 0;
  const states = new Map<string, { bytes: Buffer; etag: string }>(); const events: any[] = []; const order: string[] = []; const owned: Buffer[] = [];
  const state = {
    read: vi.fn(async (key: string) => { const value = states.get(key); return value ? { bytes: Buffer.from(value.bytes), etag: value.etag } : null; }),
    create: vi.fn(async (key: string, bytes: Uint8Array) => { if (states.has(key)) throw new PrivateStateConflict(); states.set(key, { bytes: Buffer.from(bytes), etag: String(++serial) }); }),
    replace: vi.fn(async (key: string, etag: string, bytes: Uint8Array) => { if (states.get(key)?.etag !== etag) throw new PrivateStateConflict(); states.set(key, { bytes: Buffer.from(bytes), etag: String(++serial) }); })
  };
  let plaintext = controlWire({ schemaVersion: 1, evidence: [{ category: "validation-summary", text: controlWire({
    checkId: "unit", result: "pass", passed: 4, failed: 0, revision: "a".repeat(40)
  }).toString() }] });
  const ports = {
    state, now: () => time, observe: vi.fn(async () => structuredClone(observed)),
    loadVerifiedBundle: vi.fn(async () => { order.push("load"); const value = Buffer.from(plaintext); owned.push(value); return value; }),
    audit: vi.fn(async (bytes: Uint8Array) => { const event = JSON.parse(Buffer.from(bytes).toString()); events.push(event); order.push(event.phase);
      return signed({ ...base("bootstrap-private-audit-ack"), eventId: event.eventId, eventSha256: controlHash(bytes), operationId: event.operationId,
        phase: event.phase, storage: { region: "us-east-2", bucket: observed.auditBucket, key: `events/${event.eventId}`, versionId: "audit-v1" },
        recordedAt: time.toISOString(), retainUntil: new Date(time.getTime() + 90 * 86400000).toISOString(), configEpoch: observed.configEpoch }, auditor);
    })
  };
  const coordinator = createPrivateReadCoordinator(ports);
  const revoke = (key = approver) => coordinator.revoke({ ...documents, revocation: signed({ ...base("bootstrap-private-read-revocation"),
    scopeType: "approval", scopeId: approval.approvalId, scopeSha256: controlHash(documents.approval), delegationId: approval.delegationId,
    configEpoch: 1, sequence: 1, at: time.toISOString() }, key) });
  return { root, requester, approver, auditor, signed, request, approval, delegation, documents, observed, states, ports, coordinator, revoke,
    events, order, owned, stateValue: () => JSON.parse([...states.values()][0]!.bytes.toString()),
    setTime: (value: string) => { time = new Date(value); }, setPlaintext: (value: Buffer) => { plaintext = value; } };
}

const denied = async (promise: Promise<unknown>) => expect(promise).rejects.toThrow("Private provenance control unavailable or invalid.");
describe("private read control consumer", () => {
  it("requires signed audit attempts and completion before one-use release; clears owned plaintext", async () => {
    const f = fixture(); const result = await f.coordinator.read(f.documents);
    expect(JSON.parse(result.toString()).evidence[0].category).toBe("validation-summary");
    expect(f.order).toEqual(["attempt", "load", "complete"]);
    expect(f.events[1].previousEventSha256).toBe(controlHash(controlWire(f.events[0])));
    expect(f.stateValue().state).toBe("spent"); expect(f.owned[0]?.every((v) => v === 0)).toBe(true);
    await denied(f.coordinator.read(f.documents)); expect(f.ports.loadVerifiedBundle).toHaveBeenCalledTimes(1);
  });
  it("persists revocation before the first read and across restart without a requester identity assertion", async () => {
    const f = fixture(); expect(await f.revoke(f.root)).toBe("revoked");
    expect(f.stateValue()).toMatchObject({ state: "revoked", requestId: null, operationId: null, delegationId: "delegation-1" });
    const original = [...f.states.values()][0]!.bytes.toString();
    await denied(createPrivateReadCoordinator(f.ports).read(f.documents));
    expect([...f.states.values()][0]!.bytes.toString()).toBe(original); expect(f.ports.loadVerifiedBundle).not.toHaveBeenCalled();
    expect(await f.revoke()).toBe("revoked"); expect(f.events.map((e) => e.phase)).toEqual(["revoked", "revoked"]);
  });
  it("arbitrates concurrent first use and revocation on one key, never overwriting a tombstone", async () => {
    const f = fixture();
    const outcomes = await Promise.allSettled([f.coordinator.read(f.documents), f.revoke()]);
    expect(f.states.size).toBe(1); expect(f.stateValue().state).toBe("revoked");
    expect(outcomes[0]?.status).toBe("rejected"); expect(outcomes[1]).toMatchObject({ status: "fulfilled", value: "revoked" });
    await denied(f.coordinator.read(f.documents));
  });
  it("allows only one concurrent first use", async () => {
    const f = fixture(); const outcomes = await Promise.allSettled([f.coordinator.read(f.documents), f.coordinator.read(f.documents)]);
    expect(outcomes.filter((v) => v.status === "fulfilled")).toHaveLength(1); expect(f.ports.loadVerifiedBundle).toHaveBeenCalledTimes(1);
  });
  it("does not replace a tombstone when the same approval ID carries a different signed digest", async () => {
    const f = fixture(); await f.revoke(); const before = [...f.states.values()][0]!.bytes.toString();
    f.documents.approval = f.signed({ ...f.approval, expiresAt: "2026-11-15T00:04:00.000Z" });
    await denied(f.coordinator.read(f.documents)); expect([...f.states.values()][0]!.bytes.toString()).toBe(before);
  });
  it("reports spent authorization without claiming revocation prevented an earlier release", async () => {
    const f = fixture(); await f.coordinator.read(f.documents); expect(await f.revoke()).toBe("already-spent"); expect(f.stateValue().state).toBe("spent");
  });
  it.each(["request", "approval", "delegation"] as const)("rejects tampered %s before state or payload access", async (field) => {
    const f = fixture(); const parsed = JSON.parse(f.documents[field].toString()); parsed.payload.extra = marker; f.documents[field] = controlWire(parsed);
    await denied(f.coordinator.read(f.documents)); expect(f.states.size).toBe(0); expect(f.ports.loadVerifiedBundle).not.toHaveBeenCalled();
  });
  it.each(["expired", "future", "wrong requester", "wrong repository", "wrong repository mapping", "wrong epoch", "revoked signer", "wrong key purpose", "duplicate key"])("denies %s", async (scenario) => {
    const f = fixture();
    if (scenario === "expired") f.setTime(expiry);
    if (scenario === "future") f.setTime("2026-11-14T23:59:59.999Z");
    if (scenario === "wrong requester") f.observed.requesterId = "other";
    if (scenario === "wrong repository") f.observed.repositoryId = "999";
    if (scenario === "wrong repository mapping") f.observed.repository = "fixture/other";
    if (scenario === "wrong epoch") f.observed.configEpoch++;
    if (scenario === "revoked signer") f.observed.keys[2]!.revoked = true;
    if (scenario === "wrong key purpose") f.observed.keys[2]!.purpose = "deployment-root";
    if (scenario === "duplicate key") f.observed.keys = [...f.observed.keys, f.observed.keys[0]!];
    await denied(f.coordinator.read(f.documents)); expect(f.states.size).toBe(0);
  });
  it.each(["purpose", "version", "subject", "categories", "duration", "approver owner", "delegation fingerprint"])("denies a correctly signed approval with invalid %s", async (scenario) => {
    const f = fixture(); const a: any = structuredClone(f.approval);
    if (scenario === "purpose") a.purposeId = "security-investigation";
    if (scenario === "version") a.storage.versionId = "v2";
    if (scenario === "subject") a.subject.commitSha = "c".repeat(40);
    if (scenario === "categories") a.categoryIds = ["decision-summary"];
    if (scenario === "duration") a.expiresAt = "2026-11-15T00:05:00.001Z";
    if (scenario === "approver owner") f.observed.keys[2]!.ownerId = "other";
    if (scenario === "delegation fingerprint") f.documents.delegation = f.signed({ ...f.delegation, approverKeyFingerprint: "f".repeat(64) }, f.root);
    f.documents.approval = f.signed(a); await denied(f.coordinator.read(f.documents)); expect(f.states.size).toBe(0);
  });
  it.each(["attempt outage", "complete outage", "unsigned true", "wrong event digest", "wrong audit target"])("withholds plaintext on %s", async (scenario) => {
    const f = fixture(); const original = f.ports.audit.getMockImplementation()!;
    f.ports.audit.mockImplementation(async (bytes) => {
      const event = JSON.parse(Buffer.from(bytes).toString());
      if (scenario === `${event.phase} outage`) throw new Error(marker);
      if (scenario === "unsigned true") return true as never;
      const result = await original(bytes);
      if (scenario.startsWith("wrong")) { const ack = JSON.parse(result.toString()).payload;
        if (scenario === "wrong event digest") ack.eventSha256 = "d".repeat(64); else ack.storage.bucket = "other-audit";
        return f.signed(ack, f.auditor);
      }
      return result;
    });
    await denied(f.coordinator.read(f.documents));
    expect(f.ports.loadVerifiedBundle).toHaveBeenCalledTimes(scenario === "complete outage" ? 1 : 0);
    expect(f.owned.every((bytes) => bytes.every((v) => v === 0))).toBe(true);
    expect(f.stateValue().state).toBe(scenario === "complete outage" ? "spent" : "failed");
  });
  it("rechecks expiry and revocation after attempt audit, before decryption", async () => {
    const f = fixture(); const audit = f.ports.audit.getMockImplementation()!;
    f.ports.audit.mockImplementation(async (bytes) => { const ack = await audit(bytes); if (JSON.parse(Buffer.from(bytes).toString()).phase === "attempt") f.setTime(expiry); return ack; });
    await denied(f.coordinator.read(f.documents)); expect(f.ports.loadVerifiedBundle).not.toHaveBeenCalled();
  });
  it("withholds and clears decrypted bytes if authority changes during the load", async () => {
    const f = fixture(); const load = f.ports.loadVerifiedBundle.getMockImplementation()!;
    f.ports.loadVerifiedBundle.mockImplementation(async () => { const bytes = await load(); f.observed.configEpoch++; return bytes; });
    await denied(f.coordinator.read(f.documents)); expect(f.owned[0]?.every((v) => v === 0)).toBe(true);
  });
  it("preserves reserved state on an uncertain write acknowledgment without loading plaintext", async () => {
    const f = fixture(); const replace = f.ports.state.replace.getMockImplementation()!;
    f.ports.state.replace.mockImplementationOnce(async (...args) => { await replace(...args); throw new Error(marker); });
    await denied(f.coordinator.read(f.documents)); expect(f.stateValue().state).toBe("reserved");
    await denied(createPrivateReadCoordinator(f.ports).read(f.documents)); expect(f.ports.loadVerifiedBundle).not.toHaveBeenCalled();
  });
  it("does not acknowledge an uncertain revocation until a later exact-state reconciliation", async () => {
    const f = fixture(); const create = f.ports.state.create.getMockImplementation()!;
    f.ports.state.create.mockImplementationOnce(async (...args) => { await create(...args); throw new Error(marker); });
    await denied(f.revoke()); expect(f.stateValue().state).toBe("revoked"); expect(await f.revoke()).toBe("revoked");
  });
  it.each(["raw category", "unknown field", "credential", "noncanonical text"])("revalidates returned bundle: %s", async (scenario) => {
    const f = fixture(); let text = controlWire({ checkId: "unit", result: "pass", passed: 1, failed: 0, revision: "a".repeat(40) }).toString();
    if (scenario === "credential") text = text.replace("unit", ["ghp", "A".repeat(36)].join("_"));
    if (scenario === "noncanonical text") text += " ";
    const value: any = { schemaVersion: 1, evidence: [{ category: scenario === "raw category" ? "raw-prompt" : "validation-summary", text }] };
    if (scenario === "unknown field") value.extra = marker;
    f.setPlaintext(controlWire(value)); await denied(f.coordinator.read(f.documents)); expect(f.owned[0]?.every((v) => v === 0)).toBe(true);
  });
  it.each(["whitespace", "duplicate key", "invalid utf8", "oversize"])("rejects %s in signed input", async (scenario) => {
    const f = fixture();
    if (scenario === "whitespace") f.documents.request = Buffer.concat([f.documents.request, Buffer.from(" ")]);
    if (scenario === "duplicate key") f.documents.request = Buffer.from(f.documents.request.toString().replace('"version":1', '"version":1,"version":1'));
    if (scenario === "invalid utf8") f.documents.request = Buffer.from([255]);
    if (scenario === "oversize") f.documents.request = Buffer.alloc(16385);
    await denied(f.coordinator.read(f.documents)); expect(f.states.size).toBe(0);
  });
  it.each([true, "untrusted-provider-value", { fill: () => { throw new Error(marker); } }])("sanitizes malformed load responses before assuming buffer ownership", async (value) => {
    const f = fixture(); f.ports.loadVerifiedBundle.mockResolvedValue(value as never);
    await denied(f.coordinator.read(f.documents)); expect(f.stateValue().state).toBe("failed");
  });
  it("isolates owned plaintext from later producer-buffer mutation", async () => {
    const f = fixture(); const audit = f.ports.audit.getMockImplementation()!;
    f.ports.audit.mockImplementation(async (bytes) => {
      if (JSON.parse(Buffer.from(bytes).toString()).phase === "complete") f.owned[0]?.fill(120);
      return audit(bytes);
    });
    const result = await f.coordinator.read(f.documents);
    expect(JSON.parse(result.toString()).schemaVersion).toBe(1);
  });
  it.each([1, 2, 3, 4])("checks a fresh read window after ledger read %i", async (target) => {
    const f = fixture(); let reads = 0; const readState = f.ports.state.read.getMockImplementation()!;
    f.ports.state.read.mockImplementation(async (...args) => {
      const result = await readState(...args);
      if (++reads === target) f.setTime(expiry);
      return result;
    });
    await denied(f.coordinator.read(f.documents));
    expect(f.ports.loadVerifiedBundle).toHaveBeenCalledTimes(target === 4 ? 1 : 0);
    if (target <= 2) expect(f.ports.state.replace).not.toHaveBeenCalled();
    expect(f.events.some((event) => event.phase === "complete")).toBe(false);
    expect(f.owned.every((bytes) => bytes.every((value) => value === 0))).toBe(true);
  });
  it.each(["reserved", "spent"])("withholds plaintext when %s CAS acknowledgment crosses expiry", async (transition) => {
    const f = fixture(); const replace = f.ports.state.replace.getMockImplementation()!;
    f.ports.state.replace.mockImplementation(async (...args) => {
      await replace(...args);
      if (JSON.parse(Buffer.from(args[2]).toString()).state === transition) f.setTime(expiry);
    });
    await denied(f.coordinator.read(f.documents));
    expect(f.stateValue().state).toBe(transition === "spent" ? "spent" : "failed");
    expect(f.ports.loadVerifiedBundle).toHaveBeenCalledTimes(transition === "spent" ? 1 : 0);
    expect(f.events.some((event) => event.phase === "complete")).toBe(false);
    expect(f.owned.every((bytes) => bytes.every((value) => value === 0))).toBe(true);
    await denied(f.coordinator.read(f.documents));
  });
  it("can revoke an issued future-start approval before first use and block its later active window", async () => {
    const f = fixture(); f.documents.approval = f.signed({ ...f.approval, notBefore: "2026-11-15T00:01:00.000Z" });
    expect(await f.revoke()).toBe("revoked"); expect(f.stateValue().requestId).toBeNull();
    f.setTime("2026-11-15T00:01:10.000Z"); await denied(f.coordinator.read(f.documents));
    expect(f.stateValue().state).toBe("revoked"); expect(f.ports.loadVerifiedBundle).not.toHaveBeenCalled();
  });
  it("does not confuse a future issue timestamp with an already issued future-start approval", async () => {
    const f = fixture(); f.documents.approval = f.signed({ ...f.approval, issuedAt: "2026-11-15T00:00:20.000Z", notBefore: "2026-11-15T00:01:00.000Z" });
    await denied(f.revoke()); expect(f.states.size).toBe(0);
  });
  it("keeps confirmed timely spend as the authorization point when only completion audit finishes after expiry", async () => {
    const f = fixture(); const audit = f.ports.audit.getMockImplementation()!;
    f.ports.audit.mockImplementation(async (bytes) => {
      const ack = await audit(bytes);
      if (JSON.parse(Buffer.from(bytes).toString()).phase === "complete") f.setTime(expiry);
      return ack;
    });
    const result = await f.coordinator.read(f.documents);
    expect(JSON.parse(result.toString()).schemaVersion).toBe(1); expect(f.stateValue().state).toBe("spent");
    expect(f.order).toEqual(["attempt", "load", "complete"]);
  });
  function aliasKey(key: ReturnType<typeof generateProvenanceSigningKeyPair>) {
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const x = key.publicKey.x; const last = alphabet.indexOf(x.at(-1)!);
    const alias = `${x.slice(0, -1)}${alphabet[last + 1]}`;
    expect(Buffer.from(alias, "base64url")).toEqual(Buffer.from(x, "base64url"));
    expect(Buffer.from(alias, "base64url").toString("base64url")).not.toBe(alias);
    return { privateKey: key.privateKey, publicKey: { ...key.publicKey, x: alias } };
  }
  it.each(["root", "requester", "approver"] as const)("rejects noncanonical mathematical-key aliases in %s enrollment", async (owner) => {
    const f = fixture(); const alias = aliasKey(f[owner]);
    const index = owner === "root" ? 0 : owner === "requester" ? 1 : 2;
    f.observed.keys[index]!.publicKey = alias.publicKey;
    if (owner === "root") f.documents.delegation = f.signed(f.delegation, alias);
    if (owner === "requester") {
      f.documents.request = f.signed(f.request, alias);
      f.documents.approval = f.signed({ ...f.approval, requestSha256: controlHash(f.documents.request) });
    }
    if (owner === "approver") {
      f.documents.approval = f.signed(f.approval, alias);
      f.documents.delegation = f.signed({ ...f.delegation, approverKeyFingerprint: provenanceSigningKeyFingerprint(alias.publicKey) }, f.root);
    }
    await denied(f.coordinator.read(f.documents)); expect(f.states.size).toBe(0);
  });
  it("cannot enroll one actual root key under a distinct requester-purpose fingerprint via an x alias", async () => {
    const f = fixture(); const alias = aliasKey(f.root);
    expect(provenanceSigningKeyFingerprint(alias.publicKey)).not.toBe(provenanceSigningKeyFingerprint(f.root.publicKey));
    f.observed.keys[1]!.publicKey = alias.publicKey;
    f.documents.request = f.signed(f.request, alias);
    f.documents.approval = f.signed({ ...f.approval, requestSha256: controlHash(f.documents.request) });
    await denied(f.coordinator.read(f.documents)); expect(f.states.size).toBe(0);
  });
  it("derives state only from delegation and approval identity", () => {
    expect(privateApprovalStateKey("delegation-1", "approval-1")).toMatch(/^approvals\/[0-9a-f]{64}\.json$/);
    expect(privateApprovalStateKey("delegation-1", "approval-1")).not.toBe(privateApprovalStateKey("delegation-2", "approval-1"));
  });
});
