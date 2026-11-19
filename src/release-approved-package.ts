import { createHash } from "node:crypto";
import { type ApprovalObservation, type ApprovalPolicy, type ReleaseApprovalManifest, verifyReleaseApproval } from "./release-approval.js";

declare const brand: unique symbol;
export type ApprovedReleasePackage = { readonly [brand]: true };
type Data = { manifest: ReleaseApprovalManifest; notes: string; assets: Map<string, Buffer>; expires: number; approvalSha256: string; approvedAt: string };
const packages = new WeakMap<object, Data>();

function dataFor(value: ApprovedReleasePackage): Data {
  const data = packages.get(value);
  if (!data || Date.now() >= data.expires) throw new Error("Approved release package unavailable.");
  return data;
}

/**
 * The caller must authenticate all approval observations and source artifact
 * provenance before supplying them. This private producer verifies and owns
 * package bytes but does not establish provider or publication authority.
 */
export function prepareApprovedReleasePackage(input: {
  observation: ApprovalObservation; policy: ApprovalPolicy; now: Date; notesAssetName: string;
  assets: readonly { name: string; bytes: Uint8Array }[];
}): ApprovedReleasePackage {
  try {
    const manifestBytes = Uint8Array.from(input.observation.manifestBytes);
    const approval = verifyReleaseApproval({ ...input.observation, manifestBytes }, input.policy, input.now);
    const approvedAt = input.observation.reviews.find((review) => review.id === approval.review_id)?.submitted_at;
    if (!approvedAt) throw new Error();
    const manifest = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(manifestBytes)) as ReleaseApprovalManifest;
    if (!Array.isArray(input.assets) || input.assets.length !== manifest.assets.length) throw new Error();
    const supplied = new Map<string, Uint8Array>();
    for (const asset of input.assets) {
      if (typeof asset.name !== "string" || !(asset.bytes instanceof Uint8Array) || supplied.has(asset.name)) throw new Error();
      supplied.set(asset.name, asset.bytes);
    }
    const assets = new Map<string, Buffer>();
    for (const asset of manifest.assets) {
      const value = supplied.get(asset.name);
      if (!value || value.byteLength !== asset.size) throw new Error();
      const copy = Buffer.from(value);
      if (createHash("sha256").update(copy).digest("hex") !== asset.sha256) throw new Error();
      assets.set(asset.name, copy);
    }
    if (input.notesAssetName !== manifest.publication.notes_asset) throw new Error();
    const notesBytes = assets.get(manifest.publication.notes_asset);
    if (!notesBytes || notesBytes.byteLength > 1024 * 1024) throw new Error();
    const notes = new TextDecoder("utf-8", { fatal: true }).decode(notesBytes);
    if (notes.includes("\0")) throw new Error();
    const expires = Date.parse(manifest.expires_at);
    if (!Number.isFinite(expires) || expires <= Date.now()) throw new Error();
    const value = Object.freeze({}) as ApprovedReleasePackage;
    packages.set(value, { manifest, notes, assets, expires, approvalSha256: approval.manifest_sha256, approvedAt });
    return value;
  } catch {
    throw new Error("Approved release package unavailable.");
  }
}

/** Immutable metadata is derived from the verified approval, not caller labels. */
export function approvedReleasePackageMetadata(value: ApprovedReleasePackage): Readonly<{
  repositoryId: string; repository: string; tag: string; commit: string; notes: string; notesAssetName: string; approvalId: string; approvalSha256: string; approvedAt: string;
  prerelease: boolean; latest: boolean; assets: readonly Readonly<{ name: string; size: number; sha256: string }>[];
}> {
  const data = dataFor(value);
  return Object.freeze({ repositoryId: data.manifest.repository.id, repository: data.manifest.repository.full_name,
    tag: data.manifest.tag, commit: data.manifest.target.commit, notes: data.notes, notesAssetName: data.manifest.publication.notes_asset, approvalId: data.manifest.approval_id,
    approvalSha256: data.approvalSha256, approvedAt: data.approvedAt, prerelease: data.manifest.channel === "rc" || data.manifest.channel === "beta", latest: data.manifest.publication.latest,
    assets: Object.freeze(data.manifest.assets.map((item) => Object.freeze({ ...item }))) });
}

/** Returns a copy; trusted publisher code must protect the bytes until use. */
export function copyApprovedReleaseAsset(value: ApprovedReleasePackage, name: string): Uint8Array {
  const bytes = dataFor(value).assets.get(name);
  if (!bytes) throw new Error("Approved release package unavailable.");
  return Buffer.from(bytes);
}
