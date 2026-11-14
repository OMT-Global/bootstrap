import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readdir, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { gzipSync } from "node:zlib";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { IsolatedSourceFile } from "../src/isolation/node-profile.js";
import { ISOLATION_LIMITS } from "../src/isolation/node-profile.js";
import { verifySourceReleaseArchive } from "../src/release-source-archive.js";
import { openDataRepository, verifyGitSnapshot } from "../src/upgrade-git.js";

const directories: string[] = [];
const sha256 = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("hex");
const source = (name: string, bytes: string | Uint8Array, executable = false): IsolatedSourceFile => ({ path: name, mode: executable ? "100755" : "100644", bytes: Buffer.from(bytes) });

async function fixture(files: IsolatedSourceFile[] = [source("README.md", "fabricated source\n")]) {
  const root = await mkdtemp(path.join(os.tmpdir(), "bootstrap-source-archive-test-"));
  directories.push(root);
  await mkdir(path.join(root, "empty"));
  const env = { PATH: "/usr/bin:/bin", HOME: root, GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_SYSTEM: "/dev/null", GIT_CONFIG_GLOBAL: "/dev/null", GIT_ATTR_NOSYSTEM: "1", GIT_TERMINAL_PROMPT: "0", GIT_AUTHOR_NAME: "Fixture", GIT_AUTHOR_EMAIL: "fixture@example.invalid", GIT_AUTHOR_DATE: "@1767225600 +0000", GIT_COMMITTER_NAME: "Fixture", GIT_COMMITTER_EMAIL: "fixture@example.invalid", GIT_COMMITTER_DATE: "@1767225600 +0000" };
  const git = (args: string[], input?: Uint8Array | string) => execFileSync("/usr/bin/git", ["-c", "core.hooksPath=/dev/null", "-c", "core.attributesFile=/dev/null", ...args], { cwd: root, env, ...(input === undefined ? {} : { input }), maxBuffer: ISOLATION_LIMITS.outputBytes });
  git(["init", "-q", "--initial-branch=main", `--template=${path.join(root, "empty")}`]);
  const entries = files.map((file) => {
    const oid = git(["hash-object", "--stdin", "--no-filters", "-w"], file.bytes).toString().trim();
    return Buffer.from(`${file.mode} ${oid}\t${file.path}\0`);
  });
  git(["update-index", "-z", "--index-info"], Buffer.concat(entries));
  const tree = git(["write-tree"]).toString().trim();
  const commit = git(["commit-tree", tree], "synthetic source fixture\n").toString().trim();
  const commitBytes = git(["cat-file", "commit", commit]);
  const snapshot = verifyGitSnapshot({ baseCommit: commit, commitBytes, files });
  const tar = git(["archive", "--format=tar", "--prefix=bootstrap-v1.2.3/", commit]);
  const archive = gzipSync(tar);
  return { root, snapshot, archive, tar, expected: { commit, tree, tag: "v1.2.3", sha256: sha256(archive) } };
}

afterEach(async () => { vi.unstubAllEnvs(); await Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true }))); });

describe("verified source release archive", () => {
  it("matches a real Git-produced archive against an isolated verified commit", async () => {
    const data = await fixture([source("README.md", "public\n"), source("bin/run", "#!/bin/sh\nexit 0\n", true), source("assets/opaque.bin", Buffer.from([0, 255, 128]))]);
    expect(await verifySourceReleaseArchive(data.snapshot, data.archive, data.expected)).toEqual({ commit: data.expected.commit, tree: data.expected.tree, archive_sha256: sha256(data.archive), tar_sha256: sha256(data.tar) });
  });
  it("honors committed archive attributes without reading ambient attributes", async () => {
    const data = await fixture([source(".gitattributes", "private.txt export-ignore\nversion.txt export-subst\n"), source("private.txt", "excluded from the archive\n"), source("version.txt", "commit=$Format:%H$\n")]);
    const ambient = path.join(data.root, "ambient-attributes");
    await writeFile(ambient, "* export-ignore\n");
    await mkdir(path.join(data.root, ".git/info"), { recursive: true });
    await writeFile(path.join(data.root, ".git/info/attributes"), "* export-ignore\n");
    vi.stubEnv("GIT_CONFIG_COUNT", "1");
    vi.stubEnv("GIT_CONFIG_KEY_0", "core.attributesFile");
    vi.stubEnv("GIT_CONFIG_VALUE_0", ambient);
    expect((await verifySourceReleaseArchive(data.snapshot, data.archive, data.expected)).tar_sha256).toBe(sha256(data.tar));
  });
  it("accepts a differently compressed archive only when its exact bytes are approved", async () => {
    const data = await fixture();
    const recompressed = gzipSync(data.tar, { level: 1 });
    expect(await verifySourceReleaseArchive(data.snapshot, recompressed, { ...data.expected, sha256: sha256(recompressed) })).toMatchObject({ commit: data.expected.commit });
    if (!recompressed.equals(data.archive)) await expect(verifySourceReleaseArchive(data.snapshot, recompressed, data.expected)).rejects.toThrow();
  });
  it("owns archive and expected identity bytes across asynchronous materialization", async () => {
    const data = await fixture();
    const expectedDigest = data.expected.sha256;
    const pending = verifySourceReleaseArchive(data.snapshot, data.archive, data.expected);
    data.archive.fill(0);
    data.expected.sha256 = "0".repeat(64);
    expect((await pending).archive_sha256).toBe(expectedDigest);
  });
  it("refuses unsafe prefixes and use after closing the data repository", async () => {
    const data = await fixture();
    const repository = await openDataRepository(data.snapshot);
    try {
      for (const prefix of ["../escape/", "/absolute/", "--option/", "a/b/", "", "valid"]) await expect(repository.archive(prefix)).rejects.toThrow();
      expect(await repository.archive("bootstrap-v1.2.3/")).toEqual(data.tar);
    } finally { await repository.dispose(); }
    await expect(repository.archive("bootstrap-v1.2.3/")).rejects.toThrow();
  });
  it.each(["commit", "tree", "tag", "sha256"] as const)("rejects a mismatching approved %s", async (field) => {
    const data = await fixture();
    const value = field === "tag" ? "v1.2.4" : field === "sha256" ? "0".repeat(64) : "0".repeat(40);
    await expect(verifySourceReleaseArchive(data.snapshot, data.archive, { ...data.expected, [field]: value })).rejects.toThrow("Source release archive verification failed.");
  });
  it("rejects an archive from a different tree even if its bytes were separately approved", async () => {
    const original = await fixture([source("README.md", "first\n")]);
    const other = await fixture([source("README.md", "second\n")]);
    await expect(verifySourceReleaseArchive(original.snapshot, other.archive, { ...original.expected, sha256: sha256(other.archive) })).rejects.toThrow();
  });
  it("cleans the isolated Git repository after a content mismatch", async () => {
    const original = await fixture([source("README.md", "first\n")]);
    const other = await fixture([source("README.md", "different\n")]);
    const temporary = path.join(original.root, "isolated-temporaries");
    await mkdir(temporary);
    vi.stubEnv("TMPDIR", temporary);
    await expect(verifySourceReleaseArchive(original.snapshot, other.archive, { ...original.expected, sha256: sha256(other.archive) })).rejects.toThrow();
    expect(await readdir(temporary)).toEqual([]);
  });
  it("rejects a structurally similar but unauthenticated snapshot object", async () => {
    const data = await fixture();
    await expect(verifySourceReleaseArchive({ ...data.snapshot }, data.archive, data.expected)).rejects.toThrow();
  });
  it("rejects corrupt, oversized, or overexpanding gzip inputs without trusting their digest", async () => {
    const data = await fixture();
    const corrupted = Buffer.from(data.archive.subarray(0, data.archive.length - 3));
    const bomb = gzipSync(Buffer.alloc(ISOLATION_LIMITS.outputBytes + 1));
    for (const bytes of [corrupted, bomb, Buffer.alloc(0), Buffer.alloc(ISOLATION_LIMITS.archiveBytes + 1)]) {
      await expect(verifySourceReleaseArchive(data.snapshot, bytes, { ...data.expected, sha256: sha256(bytes) })).rejects.toThrow();
    }
  });
});
