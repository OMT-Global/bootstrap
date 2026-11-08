import { createHash, createPrivateKey, randomBytes, sign } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import {
  canonicalizeProvenanceJson, createPublicProvenance, generateProvenanceSigningKeyPair,
  signPublicProvenance
} from "../src/provenance.js";
import {
  captureSyntheticPrivateProvenance, readSyntheticPrivateProvenance,
  type SyntheticCaptureOptions, type SyntheticReadOptions, type SyntheticPrivateStorage,
  type SyntheticPrivateInput, type SyntheticPrivateReceipt, type SyntheticReadRequest
} from "../src/private-provenance.js";

const wire = (value: unknown) => Buffer.from(canonicalizeProvenanceJson(value));
const sha = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("hex");
const fabricated: SyntheticPrivateInput = { schemaVersion: 1, evidence: [{ category: "synthetic-fixture", text: "Fabricated test evidence" }] };
const captureTime = "2026-11-08T00:00:00.000Z";
const readTime = "2026-11-08T01:00:00.000Z";
const marker = "synthetic-adapter-detail-must-stay-private";
const syntheticFailure = () => { throw new Error(marker); };

function fixture() {
  const publicSigner = generateProvenanceSigningKeyPair();
  const receiptSigner = generateProvenanceSigningKeyPair();
  const expected = { repository: "synthetic/example", commitSha: "a".repeat(40), runId: "fixture-1" };
  const signedPublicEnvelope = wire(signPublicProvenance(createPublicProvenance({
    runId: expected.runId, subject: { repository: expected.repository, commitSha: expected.commitSha, ref: "refs/heads/synthetic" },
    execution: { workflow: "Synthetic test", createdAt: captureTime }, reviewers: [{ login: "reviewer", state: "approved" }]
  }), { privateKey: publicSigner.privateKey, signedAt: captureTime }));
  const options: SyntheticCaptureOptions = {
    syntheticOnly: true, signedPublicEnvelope, expected, trustedPublicKeys: [publicSigner.publicKey],
    kmsKeyArn: "synthetic-key-1", input: wire(fabricated), capturedAt: captureTime,
    retentionPolicyId: "synthetic-90days", receiptPrivateKey: receiptSigner.privateKey
  };
  const storage: SyntheticPrivateStorage = { region: "us-east-2", bucket: "synthetic-bucket", key: "fixture", versionId: "version-1" };
  const state: { bytes?: Buffer; retention?: { mode: "GOVERNANCE"; retainUntil: string }; events: string[]; ownedKeys: Buffer[] } = { events: [], ownedKeys: [] };
  const keyMaterial = new Map<string, { key: Buffer; context: string; arn: string }>();
  const own = (key: Buffer) => { const returned = Buffer.from(key); state.ownedKeys.push(returned); return returned; };
  const exactVersion = (value: Readonly<SyntheticPrivateStorage>) => {
    if (!wire(value).equals(wire(storage)) || !state.bytes) syntheticFailure();
  };
  const keys = {
    syntheticOnly: true as const,
    generate: vi.fn(async (arn: string, context: unknown) => {
      state.events.push("generate");
      const wrappedKey = randomBytes(32);
      const key = randomBytes(32);
      keyMaterial.set(wrappedKey.toString("base64"), { key, context: canonicalizeProvenanceJson(context), arn });
      return { keyArn: arn, plaintext: own(key), wrappedKey };
    }),
    unwrap: vi.fn(async (arn: string, wrapped: Uint8Array, context: unknown) => {
      state.events.push("unwrap");
      const record = keyMaterial.get(Buffer.from(wrapped).toString("base64"));
      if (!record || record.arn !== arn || record.context !== canonicalizeProvenanceJson(context)) syntheticFailure();
      return own(record!.key);
    })
  };
  const sink = {
    syntheticOnly: true as const,
    put: vi.fn(async (bytes: Uint8Array, retention: { mode: "GOVERNANCE"; retainUntil: string }) => {
      state.events.push("put");
      if (state.bytes) syntheticFailure();
      state.bytes = Buffer.from(bytes); state.retention = { mode: retention.mode, retainUntil: retention.retainUntil };
      return { ...storage };
    }),
    inspect: vi.fn(async (value: Readonly<SyntheticPrivateStorage>) => {
      state.events.push("inspect"); exactVersion(value);
      return { sha256: sha(state.bytes!), ...state.retention! };
    }),
    get: vi.fn(async (value: Readonly<SyntheticPrivateStorage>) => {
      state.events.push("get"); exactVersion(value); return Buffer.from(state.bytes!);
    })
  };
  const approval = {
    syntheticOnly: true as const,
    verify: vi.fn(async (request: Readonly<SyntheticReadRequest>) => {
      state.events.push("approve");
      if (request.requester !== "synthetic-reader" || request.purpose !== "inspect fixture" || request.approvalReference !== "jmcte-fixture-approval"
        || request.now !== readTime || request.runId !== expected.runId || !wire(request.subject).equals(wire({ repository: expected.repository, commitSha: expected.commitSha }))
        || !wire(request.storage).equals(wire(storage))) syntheticFailure();
      return true as const;
    })
  };
  const audit = { syntheticOnly: true as const, record: vi.fn(async (event: { phase: string }) => {
    state.events.push(`audit:${event.phase}`); return true as const;
  }) };
  const adapters = { keys, sink, approval, audit };
  const capture = () => captureSyntheticPrivateProvenance(options, adapters);
  const readOptions = (receipt: Buffer): SyntheticReadOptions => ({
    ...options, receipt, trustedReceiptKeys: [receiptSigner.publicKey], requester: "synthetic-reader",
    purpose: "inspect fixture", approvalReference: "jmcte-fixture-approval", now: readTime
  });
  const read = (receipt: Buffer) => readSyntheticPrivateProvenance(readOptions(receipt), adapters);
  const resign = (receipt: Buffer, mutate: (value: SyntheticPrivateReceipt) => void) => {
    const value = JSON.parse(receipt.toString()) as SyntheticPrivateReceipt; mutate(value);
    value.signature.value = sign(null, wire(value.payload), createPrivateKey({ key: receiptSigner.privateKey, format: "jwk" })).toString("base64");
    return wire(value);
  };
  return { options, state, adapters, storage, capture, readOptions, read, resign, receiptSigner };
}

async function rejected(promise: Promise<unknown>, stage: "capture" | "read") {
  await expect(promise).rejects.toEqual(new Error(`Synthetic private ${stage} failed.`));
}
const cleared = (keys: Buffer[]) => { expect(keys.length).toBeGreaterThan(0); for (const key of keys) expect(key.equals(Buffer.alloc(key.length))).toBe(true); };

describe("synthetic private provenance", () => {
  it("round trips fabricated input with exact framing, separate signing domain, and audit before release", async () => {
    const f = fixture(); const receipt = await f.capture();
    const parsed = JSON.parse(receipt.toString());
    expect(parsed.payload.domain).toBe("bootstrap-private-capture-receipt");
    expect(parsed.payload.storage).toEqual(f.storage);
    expect(Date.parse(parsed.payload.retention.retainUntil) - Date.parse(captureTime)).toBe(90 * 86_400_000);
    const envelope = JSON.parse(f.state.bytes!.toString());
    expect(Buffer.from(envelope.nonce, "base64")).toHaveLength(12);
    expect(Buffer.from(envelope.tag, "base64")).toHaveLength(16);
    expect(f.state.bytes!.toString()).not.toContain(fabricated.evidence[0]!.text);
    expect(receipt.toString()).not.toContain(fabricated.evidence[0]!.text);
    f.state.events.length = 0;
    expect(await f.read(receipt)).toEqual(fabricated);
    expect(f.state.events).toEqual(["approve", "audit:attempt", "inspect", "get", "unwrap", "audit:complete"]);
    cleared(f.state.ownedKeys);
  });

  it.each([
    ["missing synthetic flag", (f: ReturnType<typeof fixture>) => { (f.options as any).syntheticOnly = false; }],
    ["non-synthetic category", (f: ReturnType<typeof fixture>) => { f.options.input = wire({ ...fabricated, evidence: [{ category: "prompt", text: "fabricated" }] }); }],
    ["credential literal", (f: ReturnType<typeof fixture>) => { f.options.input = wire({ ...fabricated, evidence: [{ category: "synthetic-fixture", text: ["token", "fixture-credential"].join("=") }] }); }],
    ["unknown field", (f: ReturnType<typeof fixture>) => { f.options.input = wire({ ...fabricated, extra: marker }); }],
    ["wrong public trust", (f: ReturnType<typeof fixture>) => { f.options.trustedPublicKeys = []; }],
    ["wrong subject", (f: ReturnType<typeof fixture>) => { f.options.expected.commitSha = "b".repeat(40); }],
    ["wrong run", (f: ReturnType<typeof fixture>) => { f.options.expected.runId = "other-run"; }],
    ["duplicate keys", (f: ReturnType<typeof fixture>) => { f.options.input = Buffer.from('{"evidence":[],"schemaVersion":1,"schemaVersion":1}'); }],
    ["noncanonical bytes", (f: ReturnType<typeof fixture>) => { f.options.input = Buffer.from(JSON.stringify(fabricated, null, 2)); }],
    ["invalid UTF-8", (f: ReturnType<typeof fixture>) => { f.options.input = Buffer.from([0xc3, 0x28]); }],
    ["over input cap", (f: ReturnType<typeof fixture>) => { f.options.input = Buffer.alloc(1_048_577, 32); }],
    ["over public cap", (f: ReturnType<typeof fixture>) => { f.options.signedPublicEnvelope = Buffer.alloc(65_537, 32); }],
    ["too many entries", (f: ReturnType<typeof fixture>) => { f.options.input = wire({ schemaVersion: 1, evidence: Array(65).fill(fabricated.evidence[0]) }); }],
    ["deep input", (f: ReturnType<typeof fixture>) => { f.options.input = wire({ schemaVersion: 1, evidence: [{ category: "synthetic-fixture", text: { nested: { deeper: {} } } }] }); }]
  ])("rejects %s before key generation or sink mutation", async (_name, mutate) => {
    const f = fixture(); mutate(f); await rejected(f.capture(), "capture");
    expect(f.adapters.keys.generate).not.toHaveBeenCalled(); expect(f.adapters.sink.put).not.toHaveBeenCalled();
  });

  it("uses UTF-8 byte bounds rather than UTF-16 text length", async () => {
    const f = fixture(); const text = "é".repeat(8_192);
    f.options.input = wire({ schemaVersion: 1, evidence: [{ category: "synthetic-fixture", text }] });
    expect((await f.read(await f.capture())).evidence[0]!.text).toBe(text);
    const over = fixture(); over.options.input = wire({ schemaVersion: 1, evidence: [{ category: "synthetic-fixture", text: text + "x" }] });
    await rejected(over.capture(), "capture"); expect(over.adapters.keys.generate).not.toHaveBeenCalled();
  });

  it.each(["generate", "put", "inspect", "conflict", "lost acknowledgment"])("returns no receipt after %s failure and sanitizes adapter errors", async (stage) => {
    const f = fixture();
    if (stage === "generate") f.adapters.keys.generate.mockImplementationOnce(async () => syntheticFailure());
    if (stage === "put") f.adapters.sink.put.mockImplementationOnce(async () => syntheticFailure());
    if (stage === "inspect") f.adapters.sink.inspect.mockImplementationOnce(async () => syntheticFailure());
    if (stage === "conflict") f.state.bytes = Buffer.from("existing fixture");
    if (stage === "lost acknowledgment") f.adapters.sink.put.mockImplementationOnce(async (bytes, retention) => { f.state.bytes = Buffer.from(bytes); f.state.retention = { ...retention }; return syntheticFailure(); });
    await rejected(f.capture(), "capture");
    if (stage !== "generate") cleared(f.state.ownedKeys);
  });

  it.each(["key length", "key identity", "wrapped key empty", "wrapped key oversized"])("clears transferred key buffers after invalid %s", async (fault) => {
    const f = fixture(); const original = f.adapters.keys.generate.getMockImplementation()!;
    f.adapters.keys.generate.mockImplementationOnce(async (...args) => {
      const result = await original(...args);
      if (fault === "key length") { result.plaintext.fill(0); result.plaintext = Buffer.alloc(31, 7); f.state.ownedKeys.push(result.plaintext); }
      if (fault === "key identity") result.keyArn = "other-key";
      if (fault === "wrapped key empty") result.wrappedKey = Buffer.alloc(0);
      if (fault === "wrapped key oversized") result.wrappedKey = Buffer.alloc(6_145);
      return result;
    });
    await rejected(f.capture(), "capture"); cleared(f.state.ownedKeys); expect(f.adapters.sink.put).not.toHaveBeenCalled();
  });

  it.each(["digest", "retention", "mode", "region"])("rejects invalid capture sink %s evidence", async (fault) => {
    const f = fixture(); const inspect = f.adapters.sink.inspect.getMockImplementation()!;
    if (fault === "region") f.adapters.sink.put.mockResolvedValueOnce({ ...f.storage, region: "other" } as any);
    else f.adapters.sink.inspect.mockImplementationOnce(async (...args) => ({ ...await inspect(...args),
      ...(fault === "digest" ? { sha256: "0".repeat(64) } : fault === "mode" ? { mode: "COMPLIANCE" } : { retainUntil: captureTime })
    }) as any);
    await rejected(f.capture(), "capture"); cleared(f.state.ownedKeys);
  });

  it.each([
    ["unknown envelope", (v: any) => { v.extra = marker; }],
    ["header subject", (v: any) => { v.header.subject.commitSha = "b".repeat(40); }],
    ["header run", (v: any) => { v.header.runId = "other-run"; }],
    ["public digest", (v: any) => { v.header.publicEnvelopeSha256 = "0".repeat(64); }],
    ["key ARN", (v: any) => { v.header.kmsKeyArn = "other-key"; }],
    ["wrapped digest", (v: any) => { v.header.wrappedKeySha256 = "0".repeat(64); }],
    ["wrapped key", (v: any) => { v.wrappedKey = randomBytes(32).toString("base64"); }],
    ["wrapped substitution", (v: any) => { const key = randomBytes(32); v.wrappedKey = key.toString("base64"); v.header.wrappedKeySha256 = sha(key); }],
    ["nonce length", (v: any) => { v.nonce = randomBytes(11).toString("base64"); }],
    ["nonce tamper", (v: any) => { v.nonce = randomBytes(12).toString("base64"); }],
    ["ciphertext tamper", (v: any) => { const bytes = Buffer.from(v.ciphertext, "base64"); bytes[0] = bytes[0]! ^ 1; v.ciphertext = bytes.toString("base64"); }],
    ["tag length", (v: any) => { v.tag = randomBytes(15).toString("base64"); }],
    ["tag tamper", (v: any) => { v.tag = randomBytes(16).toString("base64"); }],
    ["noncanonical Base64", (v: any) => { v.tag = v.tag.replace(/=+$/, ""); }],
    ["nonzero Base64 pad bits", (v: any) => { const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"; v.tag = v.tag.slice(0, 21) + alphabet[alphabet.indexOf(v.tag[21]) | 1] + "=="; }]
  ])("rejects %s even with a re-signed matching ciphertext receipt", async (_name, mutate) => {
    const f = fixture(); let receipt = await f.capture(); const envelope = JSON.parse(f.state.bytes!.toString()); mutate(envelope);
    f.state.bytes = wire(envelope);
    receipt = f.resign(receipt, (value) => { value.payload.ciphertextEnvelopeSha256 = sha(f.state.bytes!); });
    await rejected(f.read(receipt), "read"); expect(f.state.events).not.toContain("audit:complete"); cleared(f.state.ownedKeys);
    if (["nonce tamper", "ciphertext tamper", "tag tamper", "wrapped substitution"].includes(_name)) expect(f.adapters.keys.unwrap).toHaveBeenCalledOnce();
  });

  it.each(["signature", "untrusted signer", "subject", "run", "public digest", "version", "region", "digest", "short retention", "future capture", "domain", "unknown field"])("rejects receipt %s independently of signer trust", async (fault) => {
    const f = fixture(); let receipt = await f.capture();
    if (fault === "untrusted signer") { const options = f.readOptions(receipt); options.trustedReceiptKeys = []; await rejected(readSyntheticPrivateProvenance(options, f.adapters), "read"); expect(f.adapters.approval.verify).not.toHaveBeenCalled(); expect(f.adapters.sink.get).not.toHaveBeenCalled(); expect(f.adapters.keys.unwrap).not.toHaveBeenCalled(); return; }
    receipt = f.resign(receipt, (v: any) => {
      if (fault === "subject") v.payload.subject.repository = "synthetic/other";
      if (fault === "run") v.payload.runId = "other-run";
      if (fault === "public digest") v.payload.publicEnvelopeSha256 = "0".repeat(64);
      if (fault === "version") v.payload.storage.versionId = "other-version";
      if (fault === "region") v.payload.storage.region = "other";
      if (fault === "digest") v.payload.ciphertextEnvelopeSha256 = "0".repeat(64);
      if (fault === "short retention") v.payload.retention.retainUntil = captureTime;
      if (fault === "future capture") v.payload.capturedAt = "2027-11-08T00:00:00.000Z";
      if (fault === "domain") v.payload.domain = "bootstrap-signed-provenance";
      if (fault === "unknown field") v.payload.extra = marker;
    });
    if (fault === "signature") { const value = JSON.parse(receipt.toString()); value.signature.value = randomBytes(64).toString("base64"); receipt = wire(value); }
    await rejected(f.read(receipt), "read"); expect(f.state.events).not.toContain("audit:complete");
  });

  it.each(["approval", "requester", "purpose", "approval reference", "expired approval", "false audit", "undefined audit", "inspect", "get", "unwrap", "unwrap length", "complete audit"])("denies plaintext after %s failure", async (fault) => {
    const f = fixture(); const receipt = await f.capture(); const options = f.readOptions(receipt);
    f.state.events.length = 0;
    if (fault === "approval") f.adapters.approval.verify.mockResolvedValueOnce(false as any);
    if (fault === "requester") options.requester = "other-reader";
    if (fault === "purpose") options.purpose = "other purpose";
    if (fault === "approval reference") options.approvalReference = "other approval";
    if (fault === "expired approval") options.now = "2026-11-09T01:00:00.000Z";
    if (fault === "false audit") f.adapters.audit.record.mockResolvedValueOnce(false as any);
    if (fault === "undefined audit") f.adapters.audit.record.mockResolvedValueOnce(undefined as any);
    if (fault === "inspect") f.adapters.sink.inspect.mockImplementationOnce(async () => syntheticFailure());
    if (fault === "get") f.adapters.sink.get.mockImplementationOnce(async () => syntheticFailure());
    if (fault === "unwrap") f.adapters.keys.unwrap.mockImplementationOnce(async () => syntheticFailure());
    if (fault === "unwrap length") f.adapters.keys.unwrap.mockImplementationOnce(async () => { const key = Buffer.alloc(33, 7); f.state.ownedKeys.push(key); return key; });
    if (fault === "complete audit") f.adapters.audit.record.mockImplementation(async (event) => { f.state.events.push(`audit:${event.phase}`); return event.phase === "complete" ? syntheticFailure() : true; });
    await rejected(readSyntheticPrivateProvenance(options, f.adapters), "read"); cleared(f.state.ownedKeys);
    if (["approval", "requester", "purpose", "approval reference", "expired approval", "false audit", "undefined audit"].includes(fault)) { expect(f.adapters.sink.get).not.toHaveBeenCalled(); expect(f.adapters.keys.unwrap).not.toHaveBeenCalled(); }
  });

  it("rejects receipt wire ambiguity, truncation, and oversize before approval", async () => {
    const f = fixture(); const receipt = await f.capture();
    for (const invalid of [Buffer.concat([receipt, Buffer.from(" ")]), Buffer.from([0xff]), Buffer.alloc(16_385, 32)]) await rejected(f.read(invalid), "read");
    expect(f.adapters.approval.verify).not.toHaveBeenCalled();
  });

  it("snapshots caller subject and input before an awaited key generation", async () => {
    const f = fixture(); const original = f.adapters.keys.generate.getMockImplementation()!;
    f.adapters.keys.generate.mockImplementationOnce(async (...args) => {
      f.options.expected.runId = "mutated-run"; f.options.input.fill(0); return original(...args);
    });
    const receipt = await f.capture(); expect(JSON.parse(receipt.toString()).payload.runId).toBe("fixture-1");
    f.options.expected.runId = "fixture-1"; expect(await f.read(receipt)).toEqual(fabricated);
  });

  it("does not reuse per-capture data keys or nonces", async () => {
    const first = fixture(); const second = fixture(); await first.capture(); await second.capture();
    const a = JSON.parse(first.state.bytes!.toString()); const b = JSON.parse(second.state.bytes!.toString());
    expect(a.nonce).not.toBe(b.nonce); expect(a.wrappedKey).not.toBe(b.wrappedKey);
  });
});
