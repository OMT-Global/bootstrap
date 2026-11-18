import { describe, expect, it, vi } from "vitest";
import { type ApprovedReleasePackage, approvedReleasePackageMetadata, copyApprovedReleaseAsset, prepareApprovedReleasePackage } from "../src/release-approved-package.js";
import { packageFixture } from "./helpers/release-approved-package-fixture.js";

describe("approved first-publication package", () => {
  it("owns verified bytes and immutable approval-bound metadata", () => {
    const input = packageFixture();
    const plan = prepareApprovedReleasePackage(input);
    const metadata = approvedReleasePackageMetadata(plan);
    expect(metadata).toMatchObject({ repositoryId: "100", repository: "Example/repo", tag: "v1.2.3", notes: "Release notes\n", prerelease: false });
    expect(Object.isFrozen(metadata) && Object.isFrozen(metadata.assets) && metadata.assets.every(Object.isFrozen)).toBe(true);
    input.assets[0]!.bytes.fill(0);
    const copied = copyApprovedReleaseAsset(plan, "archive.tar.gz");
    expect(Buffer.from(copied).toString()).toBe("asset");
    copied.fill(0);
    expect(Buffer.from(copyApprovedReleaseAsset(plan, "archive.tar.gz")).toString()).toBe("asset");
    expect(() => copyApprovedReleaseAsset(plan, "unknown")).toThrow();
  });
  it.each([
    ["mutated bytes", (i: ReturnType<typeof packageFixture>) => { i.assets[0]!.bytes[0] = 0; }],
    ["missing asset", (i: ReturnType<typeof packageFixture>) => { i.assets.pop(); }],
    ["extra asset", (i: ReturnType<typeof packageFixture>) => { i.assets.push({ name: "extra", bytes: Buffer.from("x") }); }],
    ["duplicate name", (i: ReturnType<typeof packageFixture>) => { i.assets[0]!.name = "RELEASE_NOTES.md"; }],
    ["different approved asset used as notes", (i: ReturnType<typeof packageFixture>) => { i.notesAssetName = "archive.tar.gz"; }],
    ["wrong notes name", (i: ReturnType<typeof packageFixture>) => { i.notesAssetName = "missing"; }],
    ["wrong approver", (i: ReturnType<typeof packageFixture>) => { i.observation.reviews[0]!.reviewer_id = "999"; }],
    ["wrong target", (i: ReturnType<typeof packageFixture>) => { i.observation.actual.target.commit = "c".repeat(40); }]
  ])("rejects %s", (_label, mutate) => {
    const input = packageFixture(); mutate(input);
    expect(() => prepareApprovedReleasePackage(input)).toThrow("Approved release package unavailable.");
  });
  it("rejects copied and expired package facts", () => {
    const input = packageFixture();
    const plan = prepareApprovedReleasePackage(input);
    expect(() => approvedReleasePackageMetadata({ ...plan } as ApprovedReleasePackage)).toThrow();
    vi.useFakeTimers();
    try {
      const expires = JSON.parse(Buffer.from(input.observation.manifestBytes).toString("utf8")).expires_at;
      vi.setSystemTime(new Date(expires));
      expect(() => approvedReleasePackageMetadata(plan)).toThrow();
      expect(() => copyApprovedReleaseAsset(plan, "archive.tar.gz")).toThrow();
    } finally { vi.useRealTimers(); }
  });
});
