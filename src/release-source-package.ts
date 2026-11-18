import { createHash } from "node:crypto";
import YAML from "yaml";
import { copySnapshotFiles, type VerifiedGitSnapshot } from "./upgrade-git.js";
import { verifySourceReleaseArchive } from "./release-source-archive.js";

const hash = (value: Uint8Array) => createHash("sha256").update(value).digest("hex");

/** Only the selected source profile's exact known inert hook is supported.
 * Inspect approved Git data; never execute target source with publication authority. */
export function verifyBootstrapSourcePublishHook(snapshot: VerifiedGitSnapshot, selected: string): void {
  const hook = copySnapshotFiles(snapshot).find((file) => file.path === selected);
  if (selected !== "scripts/release/publish.sh" || !hook || hook.mode !== "100755" ||
      hash(hook.bytes) !== "a9a3d51032ef51514b4a89cea989ef15579fecda0d2709909ba658fe1f24e0c1") throw new Error("Unsupported source publication hook.");
}

/**
 * Verify Bootstrap's source distribution using a verified Git snapshot and
 * acquired asset bytes. Repository and snapshot origin, artifact provenance,
 * approval freshness, tag protection and publication authority are separate.
 */
export async function verifySourceReleasePackage(input: {
  snapshot: VerifiedGitSnapshot; repository: string; tag: string; channel: string; commit: string; tree: string;
  assets: readonly { name: string; bytes: Uint8Array }[];
}): Promise<void> {
  try {
    if (!/^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-(?:rc|beta)\.[0-9]+)?$/.test(input.tag) || input.tag.length > 240 ||
        !Array.isArray(input.assets)) throw new Error();
    const archiveName = `bootstrap-${input.tag}-source.tar.gz`;
    const names = ["RELEASE_NOTES.md", "artifact-manifest.json", archiveName, `${archiveName}.sha256`];
    if (input.assets.length !== names.length) throw new Error();
    const assets = new Map<string, Buffer>();
    for (const item of input.assets) {
      if (!names.includes(item.name) || assets.has(item.name) || !(item.bytes instanceof Uint8Array)) throw new Error();
      assets.set(item.name, Buffer.from(item.bytes));
    }
    const archive = assets.get(archiveName); const checksum = assets.get(`${archiveName}.sha256`);
    const notes = assets.get("RELEASE_NOTES.md"); const manifestBytes = assets.get("artifact-manifest.json");
    if (!archive || !checksum || !notes || !manifestBytes || manifestBytes.length > 65536 || notes.length > 1024 * 1024) throw new Error();
    const archiveHash = hash(archive);
    if (!checksum.equals(Buffer.from(`${archiveHash}  ${archiveName}\n`))) throw new Error();
    const noteText = new TextDecoder("utf-8", { fatal: true }).decode(notes);
    if (!noteText.trim() || noteText.includes("\0") || noteText.includes("Generated placeholder release notes.")) throw new Error();
    const sourceNotes = copySnapshotFiles(input.snapshot).find((file) => file.path === `release-notes/${input.tag}.md`);
    if (!sourceNotes || !Buffer.from(sourceNotes.bytes).equals(notes)) throw new Error();
    const text = new TextDecoder("utf-8", { fatal: true }).decode(manifestBytes);
    const guard = YAML.parseDocument(text, { uniqueKeys: true, schema: "json" });
    if (guard.errors.length) throw new Error();
    const manifest = JSON.parse(text) as Record<string, unknown>;
    if (!manifest || typeof manifest !== "object" || Array.isArray(manifest) || manifest.schema_version !== 1 ||
        manifest.repository !== input.repository || manifest.version !== input.tag || manifest.channel !== input.channel ||
        manifest.source_commit !== input.commit || manifest.source_tree !== input.tree || manifest.distribution !== "repository-source-control-plane" ||
        !Array.isArray(manifest.assets) || manifest.assets.length !== 3) throw new Error();
    const expected = new Set([archiveName, `${archiveName}.sha256`, "RELEASE_NOTES.md"]);
    for (const value of manifest.assets) {
      if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error();
      const item = value as Record<string, unknown>;
      if (typeof item.name !== "string" || !expected.delete(item.name)) throw new Error();
      const bytes = assets.get(item.name);
      if (!bytes || item.bytes !== bytes.length || item.sha256 !== hash(bytes)) throw new Error();
    }
    if (expected.size) throw new Error();
    await verifySourceReleaseArchive(input.snapshot, archive, { commit: input.commit, tree: input.tree, tag: input.tag, sha256: archiveHash });
  } catch {
    throw new Error("Source release package verification failed.");
  }
}
