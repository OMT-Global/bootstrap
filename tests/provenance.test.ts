import { describe, expect, it } from "vitest";

import { REDACTED_CREDENTIAL, createPublicProvenance, validatePublicProvenance } from "../src/provenance.js";

const input = {
  runId: "12345.1",
  subject: { repository: "acme/example", commitSha: "a".repeat(40), ref: "refs/heads/main" },
  execution: { workflow: "Provenance", runUrl: "https://github.com/acme/example/actions/runs/12345", createdAt: "2026-07-14T00:00:00Z" },
  reviewers: [{ login: "reviewer", state: "approved" as const }]
};
const githubPat = ["github", "pat"].join("_") + "_abcdefghijklmnopqrstuvwxyz123456";
const awsAccessKey = ["AK", "IA"].join("") + "ABCDEFGHIJKLMNOP";

describe("public provenance", () => {
  it("redacts adversarial credential literals before creating a public manifest", () => {
    const provenance = createPublicProvenance({
      ...input,
      metadata: {
        trace: githubPat,
        cloud: awsAccessKey,
        configured: "token=should-not-escape"
      }
    });

    expect(provenance.metadata).toEqual({ trace: REDACTED_CREDENTIAL, cloud: REDACTED_CREDENTIAL, configured: REDACTED_CREDENTIAL });
    expect(provenance.redaction.replacements).toBe(3);
    expect(JSON.stringify(provenance)).not.toContain("should-not-escape");
  });

  it("rejects a hand-authored public manifest containing a credential-like literal", () => {
    expect(() => validatePublicProvenance({
      ...input,
      schemaVersion: 1,
      metadata: { leaked: "password=not-for-publication" },
      redaction: { policyVersion: 1, replacements: 0 }
    })).toThrow("credential-like literal");
  });

  it("preserves public reviewer lineage and safe metadata", () => {
    const provenance = createPublicProvenance({ ...input, metadata: { policy: "public-repository-standard-v1" } });

    expect(provenance.reviewers).toEqual(input.reviewers);
    expect(provenance.metadata.policy).toBe("public-repository-standard-v1");
  });
});
