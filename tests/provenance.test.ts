import { describe, expect, it } from "vitest";

import {
  CURRENT_PUBLIC_PROVENANCE_SCHEMA_VERSION,
  LEGACY_PUBLIC_PROVENANCE_SCHEMA_VERSION,
  PUBLIC_PROVENANCE_METADATA_KEYS,
  REDACTED_CREDENTIAL,
  createPublicProvenance,
  publicProvenanceMetadataSchema,
  readLegacyPublicProvenance,
  validatePublicProvenance
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
