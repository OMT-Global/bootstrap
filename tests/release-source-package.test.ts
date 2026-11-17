import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { gzipSync } from "node:zlib";
import { afterEach, describe, expect, it } from "vitest";
import { verifyGitSnapshot } from "../src/upgrade-git.js";
import { verifySourceReleasePackage } from "../src/release-source-package.js";

const directories: string[] = [];
const hash = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("hex");
async function fixture() {
  const root = await mkdtemp(path.join(os.tmpdir(), "release-source-package-")); directories.push(root);
  await mkdir(path.join(root, "empty"));
  const env = { PATH: "/usr/bin:/bin", HOME: root, GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_SYSTEM: "/dev/null", GIT_CONFIG_GLOBAL: "/dev/null", GIT_ATTR_NOSYSTEM: "1", GIT_TERMINAL_PROMPT: "0", GIT_AUTHOR_NAME: "Fixture", GIT_AUTHOR_EMAIL: "fixture@example.invalid", GIT_AUTHOR_DATE: "@1767225600 +0000", GIT_COMMITTER_NAME: "Fixture", GIT_COMMITTER_EMAIL: "fixture@example.invalid", GIT_COMMITTER_DATE: "@1767225600 +0000" };
  const git = (args: string[], input?: Uint8Array | string) => execFileSync("/usr/bin/git", ["-c", "core.hooksPath=/dev/null", "-c", "core.attributesFile=/dev/null", ...args], { cwd: root, env, ...(input === undefined ? {} : { input }) });
  git(["init", "-q", "--initial-branch=main", `--template=${path.join(root, "empty")}`]);
  const notes = Buffer.from("Reviewed source notes\n");
  const source = Buffer.from("Fixture source\n");
  const files = [{ path: "README.md", mode: "100644" as const, bytes: source }, { path: "release-notes/v1.2.3.md", mode: "100644" as const, bytes: notes }];
  const entries = files.map((file) => Buffer.from(`100644 ${git(["hash-object", "--stdin", "--no-filters", "-w"], file.bytes).toString().trim()}\t${file.path}\0`));
  git(["update-index", "-z", "--index-info"], Buffer.concat(entries));
  const tree = git(["write-tree"]).toString().trim();
  const commit = git(["commit-tree", tree], "fixture\n").toString().trim();
  const snapshot = verifyGitSnapshot({ baseCommit: commit, commitBytes: git(["cat-file", "commit", commit]), files });
  const archive = gzipSync(git(["archive", "--format=tar", "--prefix=bootstrap-v1.2.3/", commit]));
  const name = "bootstrap-v1.2.3-source.tar.gz";
  function assets(sourceArchive = archive, releaseNotes = notes) {
    const checksum = Buffer.from(`${hash(sourceArchive)}  ${name}\n`);
    const manifest = Buffer.from(JSON.stringify({ schema_version: 1, repository: "Example/repo", version: "v1.2.3", channel: "stable", distribution: "repository-source-control-plane", source_commit: commit, source_tree: tree,
      assets: [{ name, bytes: sourceArchive.length, sha256: hash(sourceArchive) }, { name: `${name}.sha256`, bytes: checksum.length, sha256: hash(checksum) }, { name: "RELEASE_NOTES.md", bytes: releaseNotes.length, sha256: hash(releaseNotes) }] }));
    return [{ name: "RELEASE_NOTES.md", bytes: releaseNotes }, { name: "artifact-manifest.json", bytes: manifest }, { name, bytes: sourceArchive }, { name: `${name}.sha256`, bytes: checksum }];
  }
  return { snapshot, repository: "Example/repo", tag: "v1.2.3", channel: "stable", commit, tree, archive, notes, assets };
}
afterEach(async () => { await Promise.all(directories.splice(0).map((root) => rm(root, { recursive: true, force: true }))); });

describe("source release package verification", () => {
  it("checks the committed notes, exact Git archive and four source distribution assets", async () => {
    const input = await fixture();
    await expect(verifySourceReleasePackage({ ...input, assets: input.assets() })).resolves.toBeUndefined();
  });
  it("rejects self-consistent substituted notes even if the manifest is updated", async () => {
    const input = await fixture();
    await expect(verifySourceReleasePackage({ ...input, assets: input.assets(input.archive, Buffer.from("other notes\n")) })).rejects.toThrow();
  });
  it("rejects a self-consistent substituted archive and checksum", async () => {
    const input = await fixture();
    await expect(verifySourceReleasePackage({ ...input, assets: input.assets(gzipSync(Buffer.from("other source"))) })).rejects.toThrow();
  });
  it("rejects altered checksum, missing or extra assets, and a forged snapshot", async () => {
    const input = await fixture();
    const corrupted = input.assets(); corrupted[3]!.bytes = Buffer.from("bad checksum\n");
    for (const assets of [corrupted, input.assets().slice(1), [...input.assets(), { name: "extra", bytes: Buffer.from("x") }]]) {
      await expect(verifySourceReleasePackage({ ...input, assets })).rejects.toThrow();
    }
    await expect(verifySourceReleasePackage({ ...input, snapshot: { ...input.snapshot }, assets: input.assets() })).rejects.toThrow();
  });
  it("rejects a manifest that claims a different source tree", async () => {
    const input = await fixture();
    const assets = input.assets();
    const manifest = JSON.parse(assets[1]!.bytes.toString("utf8")); manifest.source_tree = "0".repeat(40);
    assets[1]!.bytes = Buffer.from(JSON.stringify(manifest));
    await expect(verifySourceReleasePackage({ ...input, assets })).rejects.toThrow();
  });
});
