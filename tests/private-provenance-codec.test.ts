import { createDecipheriv, createPrivateKey, sign, verify, createPublicKey } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import {
  canonical, hash, parseCanonical, privateProvenanceBinding, privateProvenanceKeyContext,
  privateReceiptSigningKey, encryptPrivateEnvelope, signPrivateReceipt, verifyPrivateReceipt,
  parsePrivateEnvelope, decryptPrivateEnvelope, PRIVATE_PROVENANCE_LIMITS
} from "../src/private-provenance-codec.js";
import { captureSyntheticPrivateProvenance, readSyntheticPrivateProvenance } from "../src/private-provenance.js";

vi.mock("node:crypto", async (original) => ({
  ...await original<typeof import("node:crypto")>(), randomBytes: () => Buffer.alloc(12, 0x24)
}));
// Fabricated keys and exact wire bytes captured by the pristine f286dd0 implementation.
// The fixed nonce is test-only; the codec always obtains its nonce from node:crypto.
const vector = {
  "expected": {
    "repository": "synthetic/codec",
    "commitSha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "runId": "fixture-codec-1"
  },
  "capturedAt": "2026-11-08T00:00:00.000Z",
  "input": {
    "schemaVersion": 1,
    "evidence": [
      {
        "category": "synthetic-fixture",
        "text": "Fabricated codec evidence"
      }
    ]
  },
  "publicSigner": {
    "privateKey": {
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w",
      "d": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"
    },
    "publicKey": {
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w"
    }
  },
  "receiptSigner": {
    "privateKey": {
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q",
      "d": "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI"
    },
    "publicKey": {
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q"
    }
  },
  "signedPublicEnvelope": "{\"envelopeVersion\":1,\"manifest\":{\"execution\":{\"createdAt\":\"2026-11-08T00:00:00.000Z\",\"workflow\":\"Codec fixture\"},\"metadata\":{},\"redaction\":{\"policyVersion\":1,\"replacements\":0},\"reviewers\":[{\"login\":\"fixture-reviewer\",\"state\":\"approved\"}],\"runId\":\"fixture-codec-1\",\"schemaVersion\":2,\"subject\":{\"commitSha\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"ref\":\"refs/heads/synthetic\",\"repository\":\"synthetic/codec\"}},\"signature\":{\"algorithm\":\"ed25519\",\"canonicalization\":\"sorted-json-v1\",\"fingerprint\":\"5030d178e665d62a5701fa7dc18b26d77b0304c2b9a20fbe4167418f3b9fea8e\",\"publicKey\":{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w\"},\"signedAt\":\"2026-11-08T00:00:00.000Z\",\"value\":\"/Hgs1/76fpLBVXXuHt3waB7CSZ+2MPeHTyvowQICaq3GOzmgqYdMTCeEEjNZNspvkLJjCtHBl1P8yvrQ+aQgAQ==\"}}",
  "context": {
    "domain": "bootstrap-private-bundle",
    "version": "1",
    "bindingSha256": "b6aa92f912fa9e0d759cdf757428cef09d356d92095f81046b1c719260cb43e7"
  },
  "envelope": "{\"ciphertext\":\"dRyy+GP4L84UcZwu6hj8ZPZwbofX/TJfLOJgAJ05a3iDxhIoPrMceHUg7VK/jO7N2rfcp5Vc4HrQhOzLml22doS3WBk/hljh2d4cse7oyWh3Hb0mOBRR5jT36kA2RPneRkM8zA==\",\"header\":{\"algorithm\":\"aes-256-gcm\",\"canonicalization\":\"sorted-json-v1\",\"domain\":\"bootstrap-private-bundle\",\"envelopeVersion\":1,\"kmsKeyArn\":\"synthetic-key-1\",\"publicEnvelopeSha256\":\"19f85e03fce4f27281ba707fcb8af488fad121dafd6317e3b31f9c2653fd3981\",\"runId\":\"fixture-codec-1\",\"subject\":{\"commitSha\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"repository\":\"synthetic/codec\"},\"wrappedKeySha256\":\"deb0e38ced1e41de6f92e70e80c418d2d356afaaa99e26f5939dbc7d3ef4772a\"},\"nonce\":\"JCQkJCQkJCQkJCQk\",\"tag\":\"DuUBqyMNGSzZWqZXtbsaGA==\",\"wrappedKey\":\"MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM=\"}",
  "receipt": "{\"payload\":{\"algorithm\":\"ed25519\",\"canonicalization\":\"sorted-json-v1\",\"capturedAt\":\"2026-11-08T00:00:00.000Z\",\"ciphertextEnvelopeSha256\":\"58736f8ff21cb29702a26e9b0ee9f850633bfd5d5c0a9bae4e518dbecfe061e9\",\"domain\":\"bootstrap-private-capture-receipt\",\"publicEnvelopeSha256\":\"19f85e03fce4f27281ba707fcb8af488fad121dafd6317e3b31f9c2653fd3981\",\"receiptVersion\":1,\"retention\":{\"mode\":\"GOVERNANCE\",\"policyId\":\"synthetic-90days\",\"retainUntil\":\"2027-02-06T00:00:00.000Z\"},\"runId\":\"fixture-codec-1\",\"signedAt\":\"2026-11-08T00:00:00.000Z\",\"storage\":{\"bucket\":\"synthetic-bucket\",\"key\":\"codec-fixture\",\"region\":\"us-east-2\",\"versionId\":\"version-1\"},\"subject\":{\"commitSha\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"repository\":\"synthetic/codec\"}},\"signature\":{\"keyFingerprint\":\"69506d6a92ddd7549454a20c1897cfcce103b8dd2c5dc9b32503554fefec2845\",\"value\":\"fNH2RXPo/vyKV1obH3+o7YiuGwvoMJHTHgAVyUAmVY319o1Amulic0cEcH5bCRfRmkd5omXWMBugS5/lTV+BDQ==\"}}"
} as const;
const publicBytes = Buffer.from(vector.signedPublicEnvelope);
const envelopeBytes = Buffer.from(vector.envelope);
const receiptBytes = Buffer.from(vector.receipt);
const inputBytes = canonical(vector.input);
const key = () => Buffer.alloc(32, 0x11);
const bindingOptions = () => ({ signedPublicEnvelope: publicBytes, expected: { ...vector.expected }, trustedPublicKeys: [vector.publicSigner.publicKey] });
const base = () => privateProvenanceBinding(bindingOptions());
const expected = (bytes = envelopeBytes) => ({ base: base(), kmsKeyArn: "synthetic-key-1", ciphertextEnvelopeSha256: hash(bytes) });
const receiptKey = () => privateReceiptSigningKey(vector.receiptSigner.privateKey);
function synthetic() {
  const receipt = JSON.parse(vector.receipt);
  let bytes = envelopeBytes;
  const ownedKeys: Buffer[] = [];
  const owned = () => { const value = key(); ownedKeys.push(value); return value; };
  const options = {
    ...bindingOptions(), syntheticOnly: true as const, kmsKeyArn: "synthetic-key-1", input: inputBytes,
    capturedAt: vector.capturedAt, retentionPolicyId: "synthetic-90days", receiptPrivateKey: vector.receiptSigner.privateKey,
    receipt: receiptBytes, trustedReceiptKeys: [vector.receiptSigner.publicKey], requester: "fixture-reader",
    purpose: "inspect fixture", approvalReference: "fixture-approval", now: "2026-11-08T01:00:00.000Z"
  };
  const adapters = {
    keys: { syntheticOnly: true as const,
      generate: vi.fn(async () => ({ keyArn: options.kmsKeyArn, plaintext: owned(), wrappedKey: Buffer.alloc(32, 0x33) })),
      unwrap: vi.fn(async () => owned()) },
    sink: { syntheticOnly: true as const,
      put: vi.fn(async (value: Uint8Array) => { bytes = Buffer.from(value); return receipt.payload.storage; }),
      inspect: vi.fn(async () => ({ sha256: hash(bytes), mode: "GOVERNANCE" as const, retainUntil: receipt.payload.retention.retainUntil })),
      get: vi.fn(async () => bytes) },
    approval: { syntheticOnly: true as const, verify: vi.fn(async () => true as const) },
    audit: { syntheticOnly: true as const, record: vi.fn(async () => true as const) }
  };
  return { options, adapters, ownedKeys, bytes: () => bytes };
}

describe("private provenance codec compatibility", () => {
  it("preserves the complete legacy envelope, receipt, binding context and synthetic API bytes", async () => {
    expect(privateProvenanceKeyContext(base())).toEqual(vector.context);
    expect(encryptPrivateEnvelope(base(), "synthetic-key-1", key(), Buffer.alloc(32, 0x33), inputBytes)).toEqual(envelopeBytes);
    const receipt = verifyPrivateReceipt(receiptBytes, [vector.receiptSigner.publicKey], base());
    expect(signPrivateReceipt(receipt.payload, receiptKey())).toEqual(receiptBytes);
    expect(verify(null, canonical(receipt.payload), createPublicKey({ key: vector.receiptSigner.publicKey, format: "jwk" }), Buffer.from(receipt.signature.value, "base64"))).toBe(true);
    const f = synthetic();
    expect(await captureSyntheticPrivateProvenance(f.options, f.adapters)).toEqual(receiptBytes);
    expect(f.bytes()).toEqual(envelopeBytes);
    expect(await readSyntheticPrivateProvenance(f.options, f.adapters)).toEqual(vector.input);
    for (const owned of f.ownedKeys) expect(owned).toEqual(Buffer.alloc(32));
    expect(publicBytes.toString()).toBe(vector.signedPublicEnvelope);
    expect(inputBytes).toEqual(canonical(vector.input));
  });

  it("returns caller-owned authenticated plaintext while preserving caller key and ciphertext", () => {
    const dataKey = key();
    const plaintext = decryptPrivateEnvelope(envelopeBytes, expected(), dataKey);
    expect(plaintext).toEqual(inputBytes);
    plaintext.fill(0);
    expect(inputBytes).toEqual(canonical(vector.input));
    expect(dataKey).toEqual(key());
    expect(envelopeBytes.toString()).toBe(vector.envelope);
  });

  it.each(["tag", "ciphertext", "nonce", "AAD"])("clears partial plaintext and returns nothing after %s authentication fails", (fault) => {
    const envelope = JSON.parse(vector.envelope);
    if (fault === "AAD") envelope.header.kmsKeyArn = "other-key";
    else { const field = Buffer.from(envelope[fault], "base64"); field[0] ^= 1; envelope[fault] = field.toString("base64"); }
    const bytes = canonical(envelope);
    const target = expected(bytes);
    if (fault === "AAD") target.kmsKeyArn = "other-key";
    const probe = createDecipheriv("aes-256-gcm", key(), Buffer.alloc(12), { authTagLength: 16 });
    const prototype = Object.getPrototypeOf(probe);
    const original = prototype.update;
    const partials: Buffer[] = [];
    const update = vi.spyOn(prototype, "update").mockImplementation(function (this: unknown, ...args: unknown[]) {
      const result = Reflect.apply(original, this, args) as Buffer;
      partials.push(result); return result;
    });
    let released: Buffer | undefined;
    try { expect(() => { released = decryptPrivateEnvelope(bytes, target, key()); }).toThrow(); }
    finally { update.mockRestore(); }
    expect(released).toBeUndefined();
    expect(partials).toHaveLength(1);
    for (const partial of partials) expect(partial).toEqual(Buffer.alloc(partial.length));
  });

  it.each(["options", "keys", "sink", "approval", "audit"])("preserves the read synthetic guard on %s before adapters run", async (member) => {
    for (const value of [false, undefined]) {
      const f = synthetic();
      const guarded = member === "options" ? f.options : f.adapters[member as keyof typeof f.adapters];
      (guarded as { syntheticOnly: unknown }).syntheticOnly = value;
      await expect(readSyntheticPrivateProvenance(f.options, f.adapters)).rejects.toEqual(new Error("Synthetic private read failed."));
      expect(f.adapters.keys.unwrap).not.toHaveBeenCalled(); expect(f.adapters.approval.verify).not.toHaveBeenCalled();
      expect(f.adapters.audit.record).not.toHaveBeenCalled(); expect(f.adapters.sink.get).not.toHaveBeenCalled();
    }
  });
  it.each(["options", "keys", "sink"])("preserves the capture synthetic guard on %s before adapters run", async (member) => {
    for (const value of [false, undefined]) {
      const f = synthetic();
      const guarded = member === "options" ? f.options : f.adapters[member as "keys" | "sink"];
      (guarded as { syntheticOnly: unknown }).syntheticOnly = value;
      await expect(captureSyntheticPrivateProvenance(f.options, f.adapters)).rejects.toEqual(new Error("Synthetic private capture failed."));
      expect(f.adapters.keys.generate).not.toHaveBeenCalled(); expect(f.adapters.sink.put).not.toHaveBeenCalled();
    }
  });

  it.each(["untrusted public", "subject", "run", "public whitespace"])("rejects %s binding", (fault) => {
    const options = bindingOptions();
    if (fault === "untrusted public") options.trustedPublicKeys = [];
    if (fault === "subject") options.expected.commitSha = "b".repeat(40);
    if (fault === "run") options.expected.runId = "other-run";
    if (fault === "public whitespace") options.signedPublicEnvelope = Buffer.concat([publicBytes, Buffer.from(" ")]);
    expect(() => privateProvenanceBinding(options)).toThrow();
  });

  it("rejects a prehashed receipt signature and an untrusted receipt signer", () => {
    const receipt = JSON.parse(vector.receipt);
    receipt.signature.value = sign(null, Buffer.from(hash(canonical(receipt.payload)), "hex"), createPrivateKey({ key: vector.receiptSigner.privateKey, format: "jwk" })).toString("base64");
    expect(() => verifyPrivateReceipt(canonical(receipt), [vector.receiptSigner.publicKey], base())).toThrow();
    expect(() => verifyPrivateReceipt(receiptBytes, [], base())).toThrow();
  });

  it.each(["digest", "subject", "run", "public digest", "key ARN", "wrapped digest", "unknown", "pad bits"])("rejects %s before decryption", (fault) => {
    const envelope = JSON.parse(vector.envelope);
    if (fault === "subject") envelope.header.subject.commitSha = "b".repeat(40);
    if (fault === "run") envelope.header.runId = "other-run";
    if (fault === "public digest") envelope.header.publicEnvelopeSha256 = "0".repeat(64);
    if (fault === "key ARN") envelope.header.kmsKeyArn = "other-key";
    if (fault === "wrapped digest") envelope.header.wrappedKeySha256 = "0".repeat(64);
    if (fault === "unknown") envelope.extra = "unexpected";
    if (fault === "pad bits") { const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"; envelope.tag = envelope.tag.slice(0, 21) + alphabet[alphabet.indexOf(envelope.tag[21]) | 1] + "=="; }
    const bytes = canonical(envelope); const target = expected(bytes);
    if (fault === "digest") target.ciphertextEnvelopeSha256 = "0".repeat(64);
    expect(() => parsePrivateEnvelope(bytes, target)).toThrow();
  });

  it.each(["BOM", "duplicate", "UTF-8", "depth", "oversize"])("rejects %s canonical input without changing caller bytes", (fault) => {
    const bytes = fault === "BOM" ? Buffer.from("\ufeff{}") : fault === "duplicate" ? Buffer.from('{"a":1,"a":1}')
      : fault === "UTF-8" ? Buffer.from([0xff]) : fault === "depth" ? Buffer.from('{"a":{"b":{}}}') : Buffer.alloc(33, 32);
    const original = Buffer.from(bytes);
    expect(() => parseCanonical(bytes, 32, 2)).toThrow(); expect(bytes).toEqual(original);
  });
  it("keeps exact byte caps and rejects wrong data-key lengths", () => {
    expect(PRIVATE_PROVENANCE_LIMITS).toEqual({ input: 1048576, publicEnvelope: 65536, envelope: 2097152, receipt: 16384, text: 16384, entries: 64, wrappedKey: 6144 });
    expect(() => encryptPrivateEnvelope(base(), "synthetic-key-1", Buffer.alloc(31), Buffer.alloc(32), inputBytes)).toThrow();
    expect(() => decryptPrivateEnvelope(envelopeBytes, expected(), Buffer.alloc(33))).toThrow();
    expect(() => encryptPrivateEnvelope(base(), "synthetic-key-1", key(), Buffer.alloc(6145), inputBytes)).toThrow();
    expect(() => encryptPrivateEnvelope(base(), "synthetic-key-1", key(), Buffer.alloc(32), Buffer.alloc(1048577))).toThrow();
    expect(() => parsePrivateEnvelope(Buffer.alloc(2097153), expected())).toThrow();
    expect(() => verifyPrivateReceipt(Buffer.alloc(16385), [vector.receiptSigner.publicKey], base())).toThrow();
  });
});
