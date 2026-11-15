import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { gzipSync } from "node:zlib";
import { verifyGitSnapshot } from "../../src/upgrade-git.js";
import { readFile } from "node:fs/promises";

const hash = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("hex");
export async function sourcePublicationFixture(hookChange?: "missing" | "changed" | "not-executable") {
  const root = await mkdtemp(path.join(os.tmpdir(), "release-source-package-"));
  await mkdir(path.join(root, "empty"));
  const env = { PATH: "/usr/bin:/bin", HOME: root, GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_SYSTEM: "/dev/null", GIT_CONFIG_GLOBAL: "/dev/null", GIT_ATTR_NOSYSTEM: "1", GIT_TERMINAL_PROMPT: "0", GIT_AUTHOR_NAME: "Fixture", GIT_AUTHOR_EMAIL: "fixture@example.invalid", GIT_AUTHOR_DATE: "@1767225600 +0000", GIT_COMMITTER_NAME: "Fixture", GIT_COMMITTER_EMAIL: "fixture@example.invalid", GIT_COMMITTER_DATE: "@1767225600 +0000" };
  const git = (args: string[], input?: Uint8Array | string) => execFileSync("/usr/bin/git", ["-c", "core.hooksPath=/dev/null", "-c", "core.attributesFile=/dev/null", ...args], { cwd: root, env, ...(input === undefined ? {} : { input }) });
  git(["init", "-q", "--initial-branch=main", `--template=${path.join(root, "empty")}`]);
  const notes = Buffer.from("Reviewed source notes\n");
  const source = Buffer.from("Fixture source\n");
  const hook = { path: "scripts/release/publish.sh", mode: "100755" as const, bytes: await readFile(new URL("../../scripts/release/publish.sh", import.meta.url)) };
  if (hookChange === "changed") hook.bytes = Buffer.from("#!/bin/bash\nexit 99\n");
  const files = [...(hookChange === "missing" ? [] : [{ ...hook, mode: hookChange === "not-executable" ? "100644" as const : hook.mode }]), { path: "README.md", mode: "100644" as const, bytes: source }, { path: "release-notes/v1.2.3.md", mode: "100644" as const, bytes: notes }];
  const entries = files.map((file) => Buffer.from(`${file.mode} ${git(["hash-object", "--stdin", "--no-filters", "-w"], file.bytes).toString().trim()}\t${file.path}\0`));
  git(["update-index", "-z", "--index-info"], Buffer.concat(entries));
  const tree = git(["write-tree"]).toString().trim();
  const commit = git(["commit-tree", tree], "fixture\n").toString().trim();
  const snapshot = verifyGitSnapshot({ baseCommit: commit, commitBytes: git(["cat-file", "commit", commit]), files });
  const archive = gzipSync(git(["archive", "--format=tar", "--prefix=bootstrap-v1.2.3/", commit]));
  const name = "bootstrap-v1.2.3-source.tar.gz";
  function assets(sourceArchive = archive, releaseNotes = notes) {
    const checksum = Buffer.from(`${hash(sourceArchive)}  ${name}\n`);
    const manifest = Buffer.from(JSON.stringify({ schema_version: 1, repository: "OMT-Global/bootstrap", version: "v1.2.3", channel: "stable", distribution: "repository-source-control-plane", source_commit: commit, source_tree: tree,
      assets: [{ name, bytes: sourceArchive.length, sha256: hash(sourceArchive) }, { name: `${name}.sha256`, bytes: checksum.length, sha256: hash(checksum) }, { name: "RELEASE_NOTES.md", bytes: releaseNotes.length, sha256: hash(releaseNotes) }] }));
    return [{ name: "RELEASE_NOTES.md", bytes: releaseNotes }, { name: "artifact-manifest.json", bytes: manifest }, { name, bytes: sourceArchive }, { name: `${name}.sha256`, bytes: checksum }];
  }
  return { dispose: () => rm(root, { recursive: true, force: true }), files, snapshot, repository: "OMT-Global/bootstrap", tag: "v1.2.3", channel: "stable", commit, tree, archive, notes, assets };
}
