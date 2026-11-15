import { createHash } from "node:crypto";
import type { ApprovalObservation, ApprovalPolicy, ReleaseApprovalManifest } from "../../src/release-approval.js";

const digest = (value: Uint8Array) => createHash("sha256").update(value).digest("hex");
const referenceTime = Math.floor(Date.now() / 1000) * 1000;
function sorted(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sorted);
  if (value !== null && typeof value === "object") return Object.fromEntries(Object.entries(value).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([key, item]) => [key, sorted(item)]));
  return value;
}
export function packageFixture() {
  const notes = Buffer.from("Release notes\n");
  const archive = Buffer.from("asset");
  const manifest: ReleaseApprovalManifest = { schema_version: 1, approval_id: "e665169c-1234-4a62-a1f1-67bd80af3617",
    expires_at: new Date(referenceTime + 30 * 60_000).toISOString(), action: "publish_new_release",
    repository: { id: "100", full_name: "Example/repo" }, tag: "v1.2.3", version: "v1.2.3", channel: "stable",
    target: { commit: "a".repeat(40), tree: "b".repeat(40) },
    preflight: { workflow_path: ".github/workflows/preflight.yml", workflow_id: "122", workflow_commit: "c".repeat(40),
      run_id: "120", attempt: "1", artifact_id: "121", archive_sha256: "d".repeat(64), requester_id: "112", attempt_actor_id: "114" },
    assets: [{ name: "RELEASE_NOTES.md", size: notes.length, sha256: digest(notes) }, { name: "archive.tar.gz", size: archive.length, sha256: digest(archive) }] };
  const policy: ApprovalPolicy = { reviewer_id: "111", manifest_path: ".github/release-approvals/pilot.json", max_validity_seconds: 3600 };
  const manifestBytes = Buffer.from(`${JSON.stringify(sorted(manifest))}\n`);
  const { approval_id: _approval, expires_at: _expiry, ...actual } = structuredClone(manifest);
  const observation: ApprovalObservation = { manifestBytes, actual,
    pull: { repository_id: "100", state: "open", head: "f".repeat(40), author_id: "112", changed_paths: [policy.manifest_path] },
    reviews: [{ id: "200", reviewer_id: "111", state: "APPROVED", commit: "f".repeat(40),
      submitted_at: new Date(referenceTime - 15 * 60_000).toISOString(), body: `APPROVE-RELEASE-SHA256 ${digest(manifestBytes)}` }],
    publisher_id: "113", publisher_attempt_actor_id: "115" };
  return { observation, policy, now: new Date(referenceTime), notesAssetName: "RELEASE_NOTES.md",
    assets: [{ name: "archive.tar.gz", bytes: archive }, { name: "RELEASE_NOTES.md", bytes: notes }] };
}
