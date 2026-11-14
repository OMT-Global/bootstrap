import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { type ApprovalObservation, type ApprovalPolicy, type ReleaseApprovalManifest, verifyReleaseApproval } from "../src/release-approval.js";

const head = "a".repeat(40);
const otherHead = "b".repeat(40);
const now = new Date("2026-11-12T12:00:00.000Z");
const policy: ApprovalPolicy = { reviewer_id: "111", manifest_path: ".github/release-approvals/pilot.json", max_validity_seconds: 3600 };
const manifest: ReleaseApprovalManifest = {
  schema_version: 1,
  approval_id: "e665169c-1234-4a62-a1f1-67bd80af3617",
  expires_at: "2026-11-12T12:30:00.000Z",
  action: "publish_new_release",
  repository: { id: "100", full_name: "example/project" },
  tag: "v1.2.3", version: "v1.2.3", channel: "stable",
  target: { commit: "c".repeat(40), tree: "d".repeat(40) },
  preflight: { workflow_path: ".github/workflows/preflight.yml", workflow_id: "122", workflow_commit: "e".repeat(40), run_id: "120", attempt: "1", artifact_id: "121", archive_sha256: "f".repeat(64), requester_id: "112", attempt_actor_id: "114" },
  assets: [{ name: "archive.tar.gz", size: 19, sha256: "1".repeat(64) }, { name: "notes.md", size: 10, sha256: "2".repeat(64) }]
};

function sorted(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sorted);
  if (value !== null && typeof value === "object") return Object.fromEntries(Object.entries(value).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([key, item]) => [key, sorted(item)]));
  return value;
}
function bytes(value: unknown): Uint8Array { return Buffer.from(`${JSON.stringify(sorted(value))}\n`, "utf8"); }
function approvalBody(content: Uint8Array): string { return `APPROVE-RELEASE-SHA256 ${createHash("sha256").update(content).digest("hex")}`; }
function fixture(): ApprovalObservation {
  const raw = bytes(manifest);
  const { approval_id: _approval, expires_at: _expiry, ...actual } = structuredClone(manifest);
  return {
    manifestBytes: raw, actual,
    pull: { repository_id: "100", state: "open", head, author_id: "112", changed_paths: [policy.manifest_path] },
    reviews: [{ id: "200", reviewer_id: "111", state: "APPROVED", commit: head, submitted_at: "2026-11-12T11:45:00.000Z", body: approvalBody(raw) }],
    publisher_id: "113", publisher_attempt_actor_id: "115"
  };
}

describe("release approval fact comparison", () => {
  it("accepts an exact, separately approved manifest and binds the result", () => {
    const observation = fixture();
    expect(verifyReleaseApproval(observation, policy, now)).toEqual({ manifest_sha256: createHash("sha256").update(observation.manifestBytes).digest("hex"), review_id: "200", head });
  });
  it("does not discard an approval or blocking review because of a later comment", () => {
    const observation = fixture();
    observation.reviews.push({ ...observation.reviews[0], id: "201", state: "COMMENTED", submitted_at: "2026-11-12T11:50:00.000Z" });
    expect(verifyReleaseApproval(observation, policy, now).review_id).toBe("200");
    observation.reviews.push({ ...observation.reviews[0], id: "202", reviewer_id: "119", state: "CHANGES_REQUESTED", submitted_at: "2026-11-12T11:48:00.000Z" });
    observation.reviews.push({ ...observation.reviews[0], id: "203", reviewer_id: "119", state: "COMMENTED", submitted_at: "2026-11-12T11:51:00.000Z" });
    expect(() => verifyReleaseApproval(observation, policy, now)).toThrow("Release approval unavailable or invalid.");
  });
  it.each([
    ["stable", "v1.2.3"], ["maintenance", "v1.2.3"],
    ["rc", "v1.2.3-rc.1"], ["beta", "v1.2.3-beta.1"], ["rc", "v1.2.3-beta.1"], ["beta", "v1.2.3-rc.1"], ["rc", "v1.2.3-rc.01"]
  ] as const)("accepts coherent %s channel and %s version", (channel, tag) => {
    const observation = fixture();
    const edited = { ...manifest, channel, tag, version: tag };
    observation.manifestBytes = bytes(edited);
    const { approval_id: _approval, expires_at: _expiry, ...actual } = edited;
    observation.actual = actual;
    observation.reviews[0].body = approvalBody(observation.manifestBytes);
    expect(verifyReleaseApproval(observation, policy, now).review_id).toBe("200");
  });
  it.each([
    ["stable", "v1.2.3-rc.1"], ["maintenance", "v1.2.3-beta.1"],
    ["rc", "v1.2.3"], ["beta", "v1.2.3"], ["stable", "v01.2.3"], ["stable", "v1.2.3-rc.01"]
  ] as const)("rejects incompatible %s channel and %s version even when approved", (channel, tag) => {
    const observation = fixture();
    const edited = { ...manifest, channel, tag, version: tag };
    observation.manifestBytes = bytes(edited);
    const { approval_id: _approval, expires_at: _expiry, ...actual } = edited;
    observation.actual = actual;
    observation.reviews[0].body = approvalBody(observation.manifestBytes);
    expect(() => verifyReleaseApproval(observation, policy, now)).toThrow();
  });
  it.each([
    ["package digest differs", (o: ApprovalObservation) => { o.actual.preflight.archive_sha256 = "0".repeat(64); }],
    ["asset bytes differ", (o: ApprovalObservation) => { o.actual.assets[0].sha256 = "0".repeat(64); }],
    ["asset missing", (o: ApprovalObservation) => { o.actual.assets.pop(); }],
    ["attempt differs", (o: ApprovalObservation) => { o.actual.preflight.attempt = "2"; }],
    ["target tree differs", (o: ApprovalObservation) => { o.actual.target.tree = otherHead; }],
    ["version does not match tag", (o: ApprovalObservation) => { o.actual.version = "v1.2.4"; o.manifestBytes = bytes({ ...manifest, version: "v1.2.4" }); o.reviews[0].body = approvalBody(o.manifestBytes); }],
    ["repository differs", (o: ApprovalObservation) => { o.pull.repository_id = "101"; }],
    ["review of a different head", (o: ApprovalObservation) => { o.reviews[0].commit = otherHead; }],
    ["approval does not name digest", (o: ApprovalObservation) => { o.reviews[0].body = "approved"; }],
    ["unrecognized reviewer", (o: ApprovalObservation) => { o.reviews[0].reviewer_id = "114"; }],
    ["requester is approver", (o: ApprovalObservation) => { o.actual.preflight.requester_id = "111"; const edited = { ...manifest, preflight: o.actual.preflight }; o.manifestBytes = bytes(edited); o.reviews[0].body = approvalBody(o.manifestBytes); }],
    ["attempt actor is approver", (o: ApprovalObservation) => { o.actual.preflight.attempt_actor_id = "111"; const edited = { ...manifest, preflight: o.actual.preflight }; o.manifestBytes = bytes(edited); o.reviews[0].body = approvalBody(o.manifestBytes); }],
    ["publisher is approver", (o: ApprovalObservation) => { o.publisher_id = "111"; }],
    ["publication attempt actor is approver", (o: ApprovalObservation) => { o.publisher_attempt_actor_id = "111"; }],
    ["PR author is approver", (o: ApprovalObservation) => { o.pull.author_id = "111"; }],
    ["closed approval PR", (o: ApprovalObservation) => { o.pull.state = "closed"; }],
    ["extra changed file", (o: ApprovalObservation) => { o.pull.changed_paths.push("scripts/publish.sh"); }],
    ["dismissed approval", (o: ApprovalObservation) => { o.reviews[0].state = "DISMISSED"; }],
    ["later changes requested", (o: ApprovalObservation) => { o.reviews.push({ ...o.reviews[0], id: "201", state: "CHANGES_REQUESTED", submitted_at: "2026-11-12T11:50:00.000Z" }); }],
    ["ambiguous review timestamps", (o: ApprovalObservation) => { o.reviews.push({ ...o.reviews[0], id: "201", state: "CHANGES_REQUESTED" }); }],
    ["duplicated review identity", (o: ApprovalObservation) => { o.reviews.push({ ...o.reviews[0] }); }],
    ["future review", (o: ApprovalObservation) => { o.reviews[0].submitted_at = "2026-11-12T12:01:00.000Z"; }],
    ["noncanonical manifest", (o: ApprovalObservation) => { o.manifestBytes = Buffer.from(JSON.stringify(manifest)); o.reviews[0].body = approvalBody(o.manifestBytes); }],
    ["unauthorized release action", (o: ApprovalObservation) => { o.manifestBytes = bytes({ ...manifest, action: "replace_existing_release" }); o.reviews[0].body = approvalBody(o.manifestBytes); }],
    ["duplicate manifest key", (o: ApprovalObservation) => { o.manifestBytes = Buffer.from(Buffer.from(o.manifestBytes).toString().replace('"approval_id":', '"approval_id":"ignored","approval_id":')); o.reviews[0].body = approvalBody(o.manifestBytes); }],
    ["invalid UTF-8", (o: ApprovalObservation) => { o.manifestBytes = Buffer.from([0xff]); }]
  ])("rejects %s", (_name, mutate) => {
    const observation = fixture();
    mutate(observation);
    expect(() => verifyReleaseApproval(observation, policy, now)).toThrow("Release approval unavailable or invalid.");
  });
  it("rejects expiry and excessive approval duration", () => {
    const observation = fixture();
    expect(() => verifyReleaseApproval(observation, policy, new Date("2026-11-12T12:30:00.000Z"))).toThrow();
    expect(() => verifyReleaseApproval(observation, { ...policy, max_validity_seconds: 10 }, now)).toThrow();
    expect(() => verifyReleaseApproval(observation, { ...policy, max_validity_seconds: 86401 }, now)).toThrow();
  });
});
