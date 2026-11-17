import { describe, expect, it, vi } from "vitest";
import { type ReviewedReleaseManifest, reviewReleaseManifest, reviewedReleaseSelectors, verifyReleaseApproval } from "../src/release-approval.js";
import { reviewedPreflightEnvironment } from "../src/release-reviewed-preflight.js";
import { packageFixture } from "./helpers/release-approved-package-fixture.js";

describe("reviewed release acquisition selectors", () => {
  it("derives immutable selectors from the reviewed manifest before package facts exist", () => {
    const source = packageFixture();
    const { actual: _actual, ...review } = source.observation;
    const fact = reviewReleaseManifest(review, source.policy, source.now);
    const selectors = reviewedReleaseSelectors(fact);
    expect(selectors).toMatchObject({ repositoryId: "100", repository: "Example/repo", targetCommit: "a".repeat(40),
      targetTree: "b".repeat(40), runId: "120", attempt: "1", artifactId: "121", archiveSha256: "d".repeat(64),
      workflowId: "122", workflowPath: ".github/workflows/preflight.yml", workflowCommit: "c".repeat(40) });
    expect(Object.isFrozen(selectors)).toBe(true);
    review.manifestBytes.fill(0);
    expect(reviewedReleaseSelectors(fact)).toEqual(selectors);
  });
  it("does not turn review into approval of different actual package facts", () => {
    const source = packageFixture();
    const { actual: _actual, ...review } = source.observation;
    const fact = reviewReleaseManifest(review, source.policy, source.now);
    expect(reviewedReleaseSelectors(fact).artifactId).toBe("121");
    source.observation.actual.preflight.artifact_id = "999";
    expect(() => verifyReleaseApproval(source.observation, source.policy, source.now)).toThrow();
  });
  it.each(["dismissed", "wrong-head", "wrong-actor", "wrong-hash"] as const)("rejects %s review evidence", (mode) => {
    const source = packageFixture();
    const { actual: _actual, ...review } = source.observation;
    if (mode === "dismissed") review.reviews[0]!.state = "DISMISSED";
    if (mode === "wrong-head") review.reviews[0]!.commit = "0".repeat(40);
    if (mode === "wrong-actor") review.publisher_id = source.policy.reviewer_id;
    if (mode === "wrong-hash") review.reviews[0]!.body = "APPROVE-RELEASE-SHA256 " + "0".repeat(64);
    expect(() => reviewReleaseManifest(review, source.policy, source.now)).toThrow();
  });
  it("rejects copied and expired selector facts", () => {
    const source = packageFixture();
    const { actual: _actual, ...review } = source.observation;
    const fact = reviewReleaseManifest(review, source.policy, source.now);
    expect(() => reviewedReleaseSelectors({ ...fact } as ReviewedReleaseManifest)).toThrow();
    expect(() => reviewedPreflightEnvironment({ ...fact } as ReviewedReleaseManifest)).toThrow();
    vi.useFakeTimers();
    try {
      const expires = JSON.parse(Buffer.from(review.manifestBytes).toString("utf8")).expires_at;
      vi.setSystemTime(new Date(expires));
      expect(() => reviewedReleaseSelectors(fact)).toThrow();
      expect(() => reviewedPreflightEnvironment(fact)).toThrow();
    } finally { vi.useRealTimers(); }
  });
});
