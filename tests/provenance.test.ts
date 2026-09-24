import { generateKeyPairSync } from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  CURRENT_PUBLIC_PROVENANCE_SCHEMA_VERSION,
  LEGACY_PUBLIC_PROVENANCE_SCHEMA_VERSION,
  PROVENANCE_CANONICALIZATION_ID,
  PROVENANCE_SIGNATURE_ALGORITHM,
  PUBLIC_PROVENANCE_METADATA_KEYS,
  REDACTED_CREDENTIAL,
  SIGNED_PROVENANCE_ENVELOPE_VERSION,
  canonicalizeProvenanceJson,
  createPublicProvenance,
  generateProvenanceSigningKeyPair,
  provenanceSigningKeyFingerprint,
  publicProvenanceMetadataSchema,
  readLegacyPublicProvenance,
  signPublicProvenance,
  signedProvenanceSigningPayload,
  validatePublicProvenance,
  verifySignedPublicProvenance,
  type SignedPublicProvenance
} from "../src/provenance.js";

const input = {
  runId: "12345.1",
  subject: { repository: "acme/example", commitSha: "a".repeat(40), ref: "refs/heads/main" },
  execution: { workflow: "Provenance", runUrl: "https://github.com/acme/example/actions/runs/12345", createdAt: "2026-07-14T00:00:00Z" },
  reviewers: [{ login: "reviewer", state: "approved" as const }]
};
const githubPat = ["github", "pat"].join("_") + "_abcdefghijklmnopqrstuvwxyz123456";
const awsAccessKey = ["AK", "IA"].join("") + "ABCDEFGHIJKLMNOP";

describe("public provenance", () => {
  it("keeps the exported metadata allowlist synchronized with the schema", () => {
    expect(Object.keys(publicProvenanceMetadataSchema.shape)).toEqual(PUBLIC_PROVENANCE_METADATA_KEYS);
  });

  it("redacts adversarial credential literals before creating a public manifest", () => {
    const provenance = createPublicProvenance({
      ...input,
      metadata: {
        policy: githubPat,
        generator: awsAccessKey,
        aiProvider: ["token", "should-not-escape"].join("=")
      }
    });

    expect(provenance.metadata).toEqual({ policy: REDACTED_CREDENTIAL, generator: REDACTED_CREDENTIAL, aiProvider: REDACTED_CREDENTIAL });
    expect(provenance.schemaVersion).toBe(CURRENT_PUBLIC_PROVENANCE_SCHEMA_VERSION);
    expect(provenance.redaction.replacements).toBe(3);
    expect(JSON.stringify(provenance)).not.toContain("should-not-escape");
  });

  it("rejects a hand-authored public manifest containing a credential-like literal", () => {
    expect(() => validatePublicProvenance({
      ...input,
      schemaVersion: CURRENT_PUBLIC_PROVENANCE_SCHEMA_VERSION,
      metadata: { policy: ["password", "not-for-publication"].join("=") },
      redaction: { policyVersion: 1, replacements: 1 }
    })).toThrow("credential-like literal");
  });

  it("preserves public reviewer lineage and safe metadata", () => {
    const provenance = createPublicProvenance({ ...input, metadata: { policy: "public-repository-standard-v1" } });

    expect(provenance.reviewers).toEqual(input.reviewers);
    expect(provenance.metadata.policy).toBe("public-repository-standard-v1");
  });

  it("rejects metadata outside the public allowlist without echoing its value", () => {
    const unknownValue = "internal customer material";
    let message = "";

    try {
      createPublicProvenance({ ...input, metadata: { privateTrace: unknownValue } } as never);
    } catch (error) {
      message = error instanceof Error ? error.message : String(error);
    }

    expect(message).toContain("Unrecognized key");
    expect(message).toContain("privateTrace");
    expect(message).not.toContain(unknownValue);
  });

  it("rejects unknown fields at every public schema boundary", () => {
    expect(() => validatePublicProvenance({
      ...input,
      schemaVersion: CURRENT_PUBLIC_PROVENANCE_SCHEMA_VERSION,
      subject: { ...input.subject, unexpected: "not public" },
      metadata: {},
      redaction: { policyVersion: 1, replacements: 0 }
    })).toThrow("Unrecognized key");
  });

  it("redacts every repeated credential literal and records exact evidence", () => {
    const provenance = createPublicProvenance({
      ...input,
      metadata: { generator: `${githubPat} ${githubPat}` }
    });

    expect(provenance.metadata.generator).toBe(`${REDACTED_CREDENTIAL} ${REDACTED_CREDENTIAL}`);
    expect(provenance.redaction.replacements).toBe(2);
  });

  it("rejects forged redaction counts", () => {
    expect(() => validatePublicProvenance({
      ...input,
      schemaVersion: CURRENT_PUBLIC_PROVENANCE_SCHEMA_VERSION,
      metadata: { generator: REDACTED_CREDENTIAL },
      redaction: { policyVersion: 1, replacements: 0 }
    })).toThrow("redaction evidence does not match");
  });

  it("rejects credential-like literals outside redactable metadata", () => {
    expect(() => createPublicProvenance({
      ...input,
      execution: { ...input.execution, workflow: ["token", "not-public"].join("=") }
    })).toThrow("Workflow name contains a credential-like literal");
  });

  it.each([
    ["run ID", { ...input, runId: awsAccessKey }],
    ["repository", { ...input, subject: { ...input.subject, repository: `acme/${awsAccessKey}` } }],
    ["reviewer", { ...input, reviewers: [{ login: awsAccessKey, state: "approved" as const }] }]
  ])("rejects credential-like literals in the %s identity", (_label, unsafeInput) => {
    expect(() => createPublicProvenance(unsafeInput)).toThrow("credential-like literal");
  });

  it("preserves valid GitHub App reviewer logins", () => {
    const provenance = createPublicProvenance({
      ...input,
      reviewers: [{ login: "dependabot[bot]", state: "approved" }]
    });

    expect(provenance.reviewers).toEqual([{ login: "dependabot[bot]", state: "approved" }]);
  });

  it("rejects a pre-supplied reserved redaction placeholder", () => {
    expect(() => createPublicProvenance({
      ...input,
      metadata: { generator: REDACTED_CREDENTIAL }
    })).toThrow("reserved redaction placeholder");
  });

  it("continues to validate legacy version-1 manifests explicitly", () => {
    const legacyInput = {
      ...input,
      schemaVersion: LEGACY_PUBLIC_PROVENANCE_SCHEMA_VERSION,
      metadata: { trace: "public-build-trace" },
      redaction: { policyVersion: 1, replacements: 0 }
    };
    const legacy = readLegacyPublicProvenance(legacyInput);

    expect(legacy.schemaVersion).toBe(LEGACY_PUBLIC_PROVENANCE_SCHEMA_VERSION);
    expect(legacy.metadata).toEqual({ trace: "public-build-trace" });
    expect(() => validatePublicProvenance(legacyInput)).toThrow();
  });

  it("rejects unknown fields in explicit legacy reads", () => {
    expect(() => readLegacyPublicProvenance({
      ...input,
      schemaVersion: LEGACY_PUBLIC_PROVENANCE_SCHEMA_VERSION,
      subject: { ...input.subject, privatePayload: "not part of version 1" },
      metadata: {},
      redaction: { policyVersion: 1, replacements: 0 }
    })).toThrow("Unrecognized key");
  });

  it("rejects credential-like legacy metadata keys", () => {
    expect(() => readLegacyPublicProvenance({
      ...input,
      schemaVersion: LEGACY_PUBLIC_PROVENANCE_SCHEMA_VERSION,
      metadata: { [githubPat]: "public-build-trace" },
      redaction: { policyVersion: 1, replacements: 0 }
    })).toThrow("credential-like literal");
  });

  it("supports worst-case credential redaction expansion within the output bound", () => {
    const repeated = Array.from({ length: 60 }, () => ["token", "x"].join("=")).join(" ");
    const provenance = createPublicProvenance({
      ...input,
      metadata: { generator: repeated }
    });

    expect(provenance.redaction.replacements).toBe(60);
    expect(provenance.metadata.generator).toBe(
      Array.from({ length: 60 }, () => REDACTED_CREDENTIAL).join(" ")
    );
  });
});

describe("signed public provenance", () => {
  const signingKey = generateProvenanceSigningKeyPair();
  const attackerKey = generateProvenanceSigningKeyPair();
  const trustedOptions = { trustedPublicKeys: [signingKey.publicKey] };
  const signedManifest = createPublicProvenance({
    ...input,
    metadata: { policy: "public-repository-standard-v1", aiModel: "test-model" }
  });
  const signed = signPublicProvenance(signedManifest, {
    privateKey: signingKey.privateKey,
    signedAt: "2026-09-24T00:00:00Z"
  });

  it("emits a strict envelope bound to the current schema versions", () => {
    expect(signed.envelopeVersion).toBe(SIGNED_PROVENANCE_ENVELOPE_VERSION);
    expect(signed.signature.algorithm).toBe(PROVENANCE_SIGNATURE_ALGORITHM);
    expect(signed.signature.canonicalization).toBe(PROVENANCE_CANONICALIZATION_ID);
    expect(signed.manifest.schemaVersion).toBe(CURRENT_PUBLIC_PROVENANCE_SCHEMA_VERSION);
  });

  it("verifies a signed manifest after a JSON storage round-trip", () => {
    const restored = verifySignedPublicProvenance(JSON.parse(JSON.stringify(signed)), trustedOptions);
    expect(restored).toEqual(signedManifest);
  });

  it("defaults signedAt to the current time when omitted", () => {
    const envelope = signPublicProvenance(signedManifest, { privateKey: signingKey.privateKey });
    expect(verifySignedPublicProvenance(envelope, trustedOptions)).toEqual(signedManifest);
  });

  const tamperCases: Array<[string, (envelope: SignedPublicProvenance) => void]> = [
    ["subject commit SHA", (envelope) => { envelope.manifest.subject.commitSha = "b".repeat(40); }],
    ["subject repository", (envelope) => { envelope.manifest.subject.repository = "acme/other"; }],
    ["subject ref", (envelope) => { envelope.manifest.subject.ref = "refs/heads/release"; }],
    ["run ID", (envelope) => { envelope.manifest.runId = "99999.9"; }],
    ["workflow name", (envelope) => { envelope.manifest.execution.workflow = "Other workflow"; }],
    ["reviewer login", (envelope) => { const first = envelope.manifest.reviewers[0]; if (first) first.login = "someone-else"; }],
    ["added reviewer", (envelope) => { envelope.manifest.reviewers.push({ login: "extra-reviewer", state: "approved" }); }],
    ["metadata value", (envelope) => { envelope.manifest.metadata.aiModel = "smuggled-model"; }],
    ["signed timestamp", (envelope) => { envelope.signature.signedAt = "2020-01-01T00:00:00Z"; }]
  ];

  it.each(tamperCases)("rejects a tampered %s after signing", (_label, mutate) => {
    const tampered = structuredClone(signed);
    mutate(tampered);
    expect(() => verifySignedPublicProvenance(tampered, trustedOptions)).toThrow("signature does not match");
  });

  it("rejects a signature transplanted from a different manifest", () => {
    const otherManifest = createPublicProvenance({
      ...input,
      runId: "99999.1",
      subject: { ...input.subject, commitSha: "c".repeat(40) }
    });
    const otherSigned = signPublicProvenance(otherManifest, {
      privateKey: signingKey.privateKey,
      signedAt: "2026-09-24T00:00:00Z"
    });
    const tampered = structuredClone(signed);
    tampered.signature.value = otherSigned.signature.value;
    expect(() => verifySignedPublicProvenance(tampered, trustedOptions)).toThrow("signature does not match");
  });

  it("rejects an unsigned manifest passed to the signed verifier", () => {
    expect(() => verifySignedPublicProvenance(signedManifest, trustedOptions)).toThrow();
    expect(() => verifySignedPublicProvenance(null, trustedOptions)).toThrow();
  });

  it("rejects an embedded key substitution that breaks the fingerprint binding", () => {
    const tampered = structuredClone(signed);
    tampered.signature.publicKey = attackerKey.publicKey;
    expect(() => verifySignedPublicProvenance(tampered, trustedOptions)).toThrow("does not match its fingerprint");
  });

  it("verifies against the trusted key rather than a re-embedded attacker key", () => {
    const tampered = structuredClone(signed);
    tampered.signature.publicKey = attackerKey.publicKey;
    tampered.signature.fingerprint = provenanceSigningKeyFingerprint(attackerKey.publicKey);
    expect(() => verifySignedPublicProvenance(tampered, { trustedPublicKeys: [attackerKey.publicKey] })).toThrow(
      "signature does not match"
    );
  });

  it("rejects a consistently signed attacker envelope that is not in the trusted keyring", () => {
    const forged = signPublicProvenance(signedManifest, {
      privateKey: attackerKey.privateKey,
      signedAt: "2026-09-24T00:00:00Z"
    });
    expect(() => verifySignedPublicProvenance(forged, trustedOptions)).toThrow("not trusted");
  });

  it("rejects an empty trusted keyring", () => {
    expect(() => verifySignedPublicProvenance(signed, { trustedPublicKeys: [] })).toThrow("not trusted");
  });

  it("rejects a legacy version-1 manifest inside a signed envelope", () => {
    const downgraded = {
      ...structuredClone(signed),
      manifest: { ...structuredClone(signed.manifest), schemaVersion: LEGACY_PUBLIC_PROVENANCE_SCHEMA_VERSION }
    };
    expect(() => verifySignedPublicProvenance(downgraded, trustedOptions)).toThrow();
  });

  const downgradeCases: Array<[string, unknown]> = [
    ["an unknown envelope version", { ...structuredClone(signed), envelopeVersion: SIGNED_PROVENANCE_ENVELOPE_VERSION + 1 }],
    ["an unknown signature algorithm", { ...structuredClone(signed), signature: { ...signed.signature, algorithm: "rsa-sha256" } }],
    ["an unknown canonicalization", { ...structuredClone(signed), signature: { ...signed.signature, canonicalization: "none" } }],
    ["unknown envelope fields", { ...structuredClone(signed), trusted: true }],
    ["unknown signature fields", { ...structuredClone(signed), signature: { ...signed.signature, note: "escalate" } }],
    ["private key material in the embedded key", { ...structuredClone(signed), signature: { ...signed.signature, publicKey: { ...signed.signature.publicKey, d: "leaked-private-material" } } }]
  ];

  it.each(downgradeCases)("rejects %s in the signed envelope", (_label, envelope) => {
    expect(() => verifySignedPublicProvenance(envelope, trustedOptions)).toThrow();
  });

  it("refuses to sign a legacy or malformed manifest", () => {
    expect(() => signPublicProvenance(
      { ...signedManifest, schemaVersion: LEGACY_PUBLIC_PROVENANCE_SCHEMA_VERSION },
      { privateKey: signingKey.privateKey }
    )).toThrow();
    expect(() => signPublicProvenance("not-a-manifest", { privateKey: signingKey.privateKey })).toThrow();
  });

  it("refuses to sign with a non-Ed25519 key", () => {
    const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    expect(() => signPublicProvenance(signedManifest, { privateKey: privateKey.export({ format: "jwk" }) })).toThrow(
      "Ed25519"
    );
  });

  it("requires at least one approved reviewer for signed provenance", () => {
    const noReviewers = createPublicProvenance({ ...input, reviewers: [] });
    expect(() => signPublicProvenance(noReviewers, { privateKey: signingKey.privateKey })).toThrow(
      "at least one approved reviewer"
    );
    const commented = createPublicProvenance({ ...input, reviewers: [{ login: "reviewer", state: "commented" }] });
    expect(() => signPublicProvenance(commented, { privateKey: signingKey.privateKey })).toThrow(
      "at least one approved reviewer"
    );
    const tampered = structuredClone(signed);
    tampered.manifest.reviewers = [{ login: "reviewer", state: "commented" }];
    expect(() => verifySignedPublicProvenance(tampered, trustedOptions)).toThrow("at least one approved reviewer");
  });

  it("binds verification to the expected immutable subject", () => {
    const expectedSubject = { repository: input.subject.repository, commitSha: input.subject.commitSha };
    expect(verifySignedPublicProvenance(signed, { ...trustedOptions, expectedSubject })).toEqual(signedManifest);
    expect(() => verifySignedPublicProvenance(signed, {
      ...trustedOptions,
      expectedSubject: { ...expectedSubject, commitSha: "b".repeat(40) }
    })).toThrow("expected subject");
    expect(() => verifySignedPublicProvenance(signed, {
      ...trustedOptions,
      expectedSubject: { ...expectedSubject, repository: "acme/other" }
    })).toThrow("expected subject");
  });

  it("canonicalizes with recursively sorted keys and rejects non-JSON values", () => {
    expect(canonicalizeProvenanceJson({ b: 1, a: { d: [1, { z: true, y: null }], c: "x" } })).toBe(
      '{"a":{"c":"x","d":[1,{"y":null,"z":true}]},"b":1}'
    );
    expect(() => canonicalizeProvenanceJson(undefined)).toThrow("non-JSON");
    expect(() => canonicalizeProvenanceJson(() => "x")).toThrow("non-JSON");
  });

  it("produces a deterministic signing payload across key insertion orders", () => {
    const reordered = {
      subject: signedManifest.subject,
      runId: signedManifest.runId,
      metadata: signedManifest.metadata,
      schemaVersion: signedManifest.schemaVersion,
      reviewers: signedManifest.reviewers,
      redaction: signedManifest.redaction,
      execution: signedManifest.execution
    };
    const payload = signedProvenanceSigningPayload(reordered, signed.signature.signedAt);
    expect(payload).toBe(signedProvenanceSigningPayload(signedManifest, signed.signature.signedAt));
    expect(payload).toContain('"domain":"bootstrap-signed-provenance"');
  });

  it("keeps credential redaction inside signed output and leaks no key material", () => {
    const redacted = createPublicProvenance({ ...input, metadata: { generator: githubPat } });
    const envelope = signPublicProvenance(redacted, {
      privateKey: signingKey.privateKey,
      signedAt: "2026-09-24T00:00:00Z"
    });
    const serialized = JSON.stringify(envelope);
    expect(serialized).not.toContain("abcdefghijklmnopqrstuvwxyz123456");
    expect(serialized).toContain(REDACTED_CREDENTIAL);
    expect(serialized).not.toContain(String(signingKey.privateKey.d));
    const restored = verifySignedPublicProvenance(JSON.parse(serialized), trustedOptions);
    expect(restored.metadata.generator).toBe(REDACTED_CREDENTIAL);
  });

  it("derives stable distinct fingerprints for distinct keys", () => {
    expect(signed.signature.fingerprint).toBe(provenanceSigningKeyFingerprint(signingKey.publicKey));
    expect(provenanceSigningKeyFingerprint(signingKey.publicKey)).not.toBe(
      provenanceSigningKeyFingerprint(attackerKey.publicKey)
    );
    expect(signed.signature.fingerprint).toMatch(/^[0-9a-f]{64}$/);
  });
});
