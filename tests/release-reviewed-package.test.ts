import { createHash } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import { type ReviewedReleaseManifest, reviewReleaseManifest } from "../src/release-approval.js";
import { approvedReleasePackageMetadata } from "../src/release-approved-package.js";
import { preparePackageForReviewedManifest } from "../src/release-reviewed-package.js";
import { packageFixture } from "./helpers/release-approved-package-fixture.js";

function sort(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sort);
  if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([key, item]) => [key, sort(item)]));
  return value;
}
function selection(source: ReturnType<typeof packageFixture>) {
  const { actual: _actual, ...review } = source.observation;
  return reviewReleaseManifest(review, source.policy, source.now);
}

describe("package binding to reviewed acquisition manifest", () => {
  it("accepts a freshly verified package tied to the same reviewed bytes", () => {
    const input = packageFixture();
    const fact = preparePackageForReviewedManifest(selection(input), input);
    expect(approvedReleasePackageMetadata(fact).approvalSha256).toBe(createHash("sha256").update(input.observation.manifestBytes).digest("hex"));
  });
  it("rejects a different independently approved manifest even when assets are identical", () => {
    const input = packageFixture();
    const reviewed = selection(input);
    const edited = JSON.parse(Buffer.from(input.observation.manifestBytes).toString("utf8"));
    edited.preflight.attempt = "2";
    input.observation.actual.preflight.attempt = "2";
    input.observation.manifestBytes = Buffer.from(`${JSON.stringify(sort(edited))}\n`);
    input.observation.reviews[0]!.body = `APPROVE-RELEASE-SHA256 ${createHash("sha256").update(input.observation.manifestBytes).digest("hex")}`;
    expect(() => preparePackageForReviewedManifest(reviewed, input)).toThrow("Reviewed release package unavailable.");
  });
  it("rejects a fresh dismissal, altered bytes and a fabricated selection", () => {
    const input = packageFixture();
    const reviewed = selection(input);
    input.observation.reviews[0]!.state = "DISMISSED";
    expect(() => preparePackageForReviewedManifest(reviewed, input)).toThrow();
    input.observation.reviews[0]!.state = "APPROVED";
    input.assets[0]!.bytes[0] = 0;
    expect(() => preparePackageForReviewedManifest(reviewed, input)).toThrow();
    expect(() => preparePackageForReviewedManifest({} as ReviewedReleaseManifest, packageFixture())).toThrow();
  });
  it("rejects an expired review fact", () => {
    const input = packageFixture();
    const reviewed = selection(input);
    const expires = JSON.parse(Buffer.from(input.observation.manifestBytes).toString("utf8")).expires_at;
    vi.useFakeTimers();
    try {
      vi.setSystemTime(new Date(expires));
      expect(() => preparePackageForReviewedManifest(reviewed, input)).toThrow();
    } finally { vi.useRealTimers(); }
  });
});
