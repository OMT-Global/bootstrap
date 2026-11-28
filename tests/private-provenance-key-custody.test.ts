import { createHash, createPrivateKey } from "node:crypto";
import { Readable } from "node:stream";
import { KMSClient } from "@aws-sdk/client-kms";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { controlWire } from "../src/private-provenance-control.js";
import { disposePrivateRoleIdentity, signPrivateRolePublicProvenance } from "../src/private-provenance-identity.js";
import { generateProvenanceSigningKeyPair, verifySignedPublicProvenance } from "../src/provenance.js";
import { now, payloadHarness, type Hook } from "./helpers/private-provenance-aws-fixture.js";

const subject = { repository: "fixture/control", commitSha: "c".repeat(40), pullRequest: 44 };
const sha256 = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest();
const ciphertext = Buffer.alloc(128, 11);
const wrappedVersion = "fixture-custody-version";
const marker = "private-operation-diagnostic-must-not-escape";
const deny = (promise: Promise<unknown>) =>
  expect(promise).rejects.toThrow(/^Private provenance identity unavailable or invalid\.$/);
const toDer = (privateKey: ReturnType<typeof generateProvenanceSigningKeyPair>["privateKey"]) =>
  createPrivateKey({ key: privateKey, format: "jwk" }).export({ format: "der", type: "pkcs8" });
beforeEach(() => { vi.useFakeTimers({ toFake: ["Date"] }); vi.setSystemTime(now); });
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); vi.unstubAllEnvs(); vi.useRealTimers(); });

async function signerHarness(options: { hook?: Hook; noCustody?: boolean; wrongRole?: boolean;
  alterKey?: (key: any, fixture: any) => void } = {}) {
  const target = { id: 123, full_name: "fixture/control", private: false, node_id: "fixture-repository", owner: { id: 456 } };
  const headRepository = { id: "fixture-fork", nameWithOwner: "fixture/fork", isPrivate: false };
  const pr = { number: 44, state: "open", draft: false, node_id: "fixture-pr",
    base: { repo: target, ref: "main", sha: "d".repeat(40) },
    head: { repo: { private: false, node_id: headRepository.id }, sha: subject.commitSha } };
  const queriedPr = { id: "fixture-pr", number: 44, headRefOid: subject.commitSha, headRepository,
    author: { id: "fixture-author", login: "fixture-author" }, reviewDecision: "APPROVED",
    latestOpinionatedReviews: { totalCount: 1, nodes: [{ id: "fixture-review",
      author: { id: "fixture-reviewer", login: "fixture-reviewer" }, commit: { oid: subject.commitSha },
      state: "APPROVED", submittedAt: "2026-11-15T00:59:00Z" }], pageInfo: { hasNextPage: false, endCursor: null } } };
  const gql = { data: { repository: { id: target.node_id, nameWithOwner: subject.repository,
    isPrivate: false, pullRequest: queriedPr } } };
  let fingerprint = ""; let secret: Buffer | undefined; let enrolledPublicKey;
  const h = await payloadHarness(options.wrongRole ? "ciphertext-verifier" : "public-signer", async (phase, value, command) => {
    if (phase === "pull") value = structuredClone(pr);
    if (phase === "graphql") value = structuredClone(gql);
    if (phase === "get" && command.input.Bucket === "fabricated-custody") {
      phase = "custody";
      value = { ...value, VersionId: command.input.VersionId, Body: Readable.from([ciphertext]), ContentLength: ciphertext.length,
        ChecksumSHA256: sha256(ciphertext).toString("base64") };
    }
    return await options.hook?.(phase, value, command) ?? value;
  }, (f) => {
    fingerprint = f.binding.workloads.find((worker: any) => worker.purpose === "public-signer").signingKeyFingerprint;
    const key = f.binding.keys.find((entry: any) => entry.fingerprint === fingerprint);
    if (!options.noCustody) key.custody = { versionId: wrappedVersion, ciphertextSha256: sha256(ciphertext).toString("hex") };
    options.alterKey?.(key, f);
    const pair = f.testKeyPair(fingerprint);
    secret = toDer(pair.privateKey);
    enrolledPublicKey = pair.publicKey;
  });
  const kms = vi.spyOn(KMSClient.prototype, "send").mockImplementation(async function(this: KMSClient, command: any) {
    expect(await this.config.credentials()).toMatchObject({ accessKeyId: "fabricated-access-2" });
    expect(await this.config.maxAttempts()).toBe(1);
    const response = { $metadata: { httpStatusCode: 200 }, EncryptionAlgorithm: "SYMMETRIC_DEFAULT",
      KeyId: h.f.binding.aws.keys.custodyArn, Plaintext: secret! };
    return await options.hook?.("kms", response, command) ?? response;
  } as any);
  return { ...h, kms, fingerprint, secret: secret!, publicKey: enrolledPublicKey!, queriedPr, pr };
}

describe("enrolled public provenance signing custody", () => {
  it("signs current native review lineage with only the configured exact version and KMS context", async () => {
    const h = await signerHarness();
    const identity = await h.start();
    vi.stubEnv("GH_TOKEN", "fabricated-unrelated-token");
    const bytes = await signPrivateRolePublicProvenance(identity, subject);
    const envelope = JSON.parse(bytes.toString("utf8"));
    expect(bytes).toEqual(controlWire(envelope));
    expect(verifySignedPublicProvenance(envelope, { trustedPublicKeys: [h.publicKey], expectedSubject: subject })).toMatchObject({
      runId: "gh-100-2", subject: { repository: subject.repository, commitSha: subject.commitSha, ref: "refs/pull/44/head" },
      reviewers: [{ login: "fixture-reviewer", state: "approved" }]
    });
    const key = `keys/semantic/v1/4/${h.fingerprint}.pkcs8.kms`;
    expect(h.s3Calls.filter((call) => call.input.Bucket === "fabricated-custody").map((call) => call.input)).toEqual([{
      Bucket: "fabricated-custody", Key: key, VersionId: wrappedVersion, ExpectedBucketOwner: "123456789012", ChecksumMode: "ENABLED"
    }]);
    const context = { ownerId: "worker-public-signer", purpose: "public-manifest", fingerprint: h.fingerprint, configEpoch: "4" };
    expect(h.kms).toHaveBeenCalledTimes(1);
    const command = h.kms.mock.calls[0]?.[0] as { input: unknown } | undefined;
    expect(command?.input).toEqual({
      CiphertextBlob: ciphertext, KeyId: h.f.binding.aws.keys.custodyArn, EncryptionAlgorithm: "SYMMETRIC_DEFAULT", EncryptionContext: context
    });
    expect(h.secret.every((byte) => byte === 0)).toBe(true);
    expect(h.stsCalls).toHaveLength(2);
    const policy = JSON.parse(h.stsCalls[1].input.Policy);
    expect(Buffer.byteLength(h.stsCalls[1].input.Policy)).toBeLessThanOrEqual(2048);
    expect(policy.Statement).toContainEqual({ Effect: "Allow", Action: "s3:GetObjectVersion",
      Resource: `arn:aws:s3:::fabricated-custody/${key}`, Condition: { StringEquals: { "s3:VersionId": wrappedVersion } } });
    const decrypt = policy.Statement.find((statement: any) => statement.Resource === h.f.binding.aws.keys.custodyArn);
    expect(decrypt).toMatchObject({ Action: "kms:Decrypt", Condition: { StringEquals: {
      "kms:EncryptionContext:ownerId": context.ownerId, "kms:EncryptionContext:fingerprint": context.fingerprint,
      "kms:EncryptionContext:purpose": context.purpose, "kms:EncryptionContext:configEpoch": context.configEpoch
    }, "ForAllValues:StringEquals": { "kms:EncryptionContextKeys": expect.arrayContaining(Object.keys(context)) } } });
    expect(JSON.stringify(policy)).not.toMatch(/ListBucket|PutObject|Delete|GenerateDataKey/);
    const reviewFetches = h.fetchCalls.filter(({ url }) => url === "https://api.github.com/graphql");
    expect(reviewFetches).toHaveLength(4);
    for (const { init } of reviewFetches) expect(init).toMatchObject({
      method: "POST", redirect: "error", headers: { authorization: "Bearer fabricated-github-token" }
    });
    disposePrivateRoleIdentity(identity);
  });

  it.each([{ noCustody: true }, { wrongRole: true }])("denies unbound custody or a different enrolled role (%o)", async (options) => {
    const h = await signerHarness(options); const identity = await h.start();
    await deny(signPrivateRolePublicProvenance(identity, subject));
    expect(h.stsCalls).toHaveLength(1); expect(h.kms).not.toHaveBeenCalled();
  });

  it("acquires an exact custody lease with the maximum enrolled identity and object version lengths", async () => {
    const longId = "w".repeat(128);
    const longVersion = "V".repeat(256);
    const h = await signerHarness({ alterKey: (key, f) => {
      key.custody.versionId = longVersion;
      f.binding.workloads.find((worker: any) => worker.purpose === "public-signer").id = longId;
      f.bootstrap.workloadId = longId;
    } });
    expect(await signPrivateRolePublicProvenance(await h.start(), subject)).toBeInstanceOf(Buffer);
    expect(h.stsCalls).toHaveLength(2);
    expect(Buffer.byteLength(h.stsCalls[1].input.Policy)).toBeLessThanOrEqual(2048);
  });

  it("denies a copied handle and an input with caller-selected key metadata", async () => {
    const h = await signerHarness(); const identity = await h.start();
    await deny(signPrivateRolePublicProvenance({ ...identity }, subject));
    const extra = { ...subject, versionId: "different-version" };
    await deny(signPrivateRolePublicProvenance(identity, extra));
    expect(h.stsCalls).toHaveLength(1); expect(h.kms).not.toHaveBeenCalled();
  });

  it.each([
    ["changed version", { VersionId: "different-version" }],
    ["wrong service key", { SSEKMSKeyId: "different-service-key" }],
    ["partial response", { ContentRange: "bytes 0-127/128" }],
    ["missing full checksum", { ChecksumType: undefined }],
    ["unexpected bucket key", { BucketKeyEnabled: true }],
    ["oversized object", { ContentLength: 6145 }]
  ])("rejects %s before unwrapping", async (_name, changes) => {
    const h = await signerHarness({ hook: (phase, value) => phase === "custody" ? { ...value, ...changes } : value });
    await deny(signPrivateRolePublicProvenance(await h.start(), subject));
    expect(h.kms).not.toHaveBeenCalled();
  });

  it("rejects a self-consistent provider checksum if the signed custody digest differs", async () => {
    const h = await signerHarness({ alterKey: (key) => { key.custody.ciphertextSha256 = "0".repeat(64); } });
    await deny(signPrivateRolePublicProvenance(await h.start(), subject)); expect(h.kms).not.toHaveBeenCalled();
  });

  it("rejects another Ed25519 key and wipes the returned plaintext bytes", async () => {
    const wrong = toDer(generateProvenanceSigningKeyPair().privateKey);
    const h = await signerHarness({ hook: (phase, value) => phase === "kms" ? { ...value, Plaintext: wrong } : value });
    await deny(signPrivateRolePublicProvenance(await h.start(), subject));
    expect(wrong.every((byte) => byte === 0)).toBe(true);
  });

  it("never returns a signature when identity expires during decrypt", async () => {
    const h = await signerHarness({ hook: (phase, value) => {
      if (phase === "kms") vi.setSystemTime(new Date(now.getTime() + 301_000));
      return value;
    } });
    await deny(signPrivateRolePublicProvenance(await h.start(), subject));
    expect(h.secret.every((byte) => byte === 0)).toBe(true);
  });

  it("clears unwrap output and rejects an active pointer changed during decrypt", async () => {
    let h: Awaited<ReturnType<typeof signerHarness>>;
    h = await signerHarness({ hook: (phase, value) => {
      if (phase === "kms") h.setPointer({ ...h.f.pointer(), epoch: 5 });
      return value;
    } });
    await deny(signPrivateRolePublicProvenance(await h.start(), subject));
    expect(h.kms).toHaveBeenCalledTimes(1);
    expect(h.secret.every((byte) => byte === 0)).toBe(true);
  });

  it("rejects a canonical AWS response naming the wrong custody key", async () => {
    const h = await signerHarness({ hook: (phase, value) => phase === "kms" ? { ...value, KeyId: "other-key" } : value });
    await deny(signPrivateRolePublicProvenance(await h.start(), subject));
    expect(h.secret.every((byte) => byte === 0)).toBe(true);
  });

  it("rejects an authenticated review set if the head repository does not match the PR observation", async () => {
    const h = await signerHarness({ hook: (phase, value) => {
      if (phase === "graphql") value.data.repository.pullRequest.headRepository.id = "other-fork";
      return value;
    } });
    await deny(signPrivateRolePublicProvenance(await h.start(), subject));
    expect(h.stsCalls).toHaveLength(1); expect(h.kms).not.toHaveBeenCalled();
  });

  it("rejects a PR retargeted while an otherwise stable review lookup is in progress", async () => {
    let observations = 0;
    const h = await signerHarness({ hook: (phase, value) => {
      if (phase === "pull" && ++observations === 2) value.base.ref = "different";
      return value;
    } });
    await deny(signPrivateRolePublicProvenance(await h.start(), subject));
    expect(h.stsCalls).toHaveLength(1); expect(h.kms).not.toHaveBeenCalled();
  });

  it("withholds a signature if GitHub replaces a review ID while preserving its login and state", async () => {
    let signed = false;
    const h = await signerHarness({ hook: (phase, value) => {
      if (phase === "kms") signed = true;
      if (phase === "graphql" && signed) value.data.repository.pullRequest.latestOpinionatedReviews.nodes[0].id = "replaced";
      return value;
    } });
    await deny(signPrivateRolePublicProvenance(await h.start(), subject));
    expect(h.kms).toHaveBeenCalledTimes(1);
  });

  it("denies provider failures without leaking details or retrying", async () => {
    const h = await signerHarness({ hook: (phase, value) => {
      if (phase === "kms") throw new Error(marker);
      return value;
    } });
    await deny(signPrivateRolePublicProvenance(await h.start(), subject));
    expect(h.kms).toHaveBeenCalledTimes(1);
  });
});
