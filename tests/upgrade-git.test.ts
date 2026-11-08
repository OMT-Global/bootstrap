import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { lstat, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it, vi } from "vitest";

import type { IsolatedSourceFile } from "../src/isolation/node-profile.js";
import { copySnapshotFiles, openDataRepository, verifyGitSnapshot } from "../src/upgrade-git.js";

const directories: string[] = [];
const source = (name: string, contents = "public fixture\n", executable = false): IsolatedSourceFile => ({
  path: name, mode: executable ? "100755" : "100644", bytes: Buffer.from(contents)
});
const objectId = (kind: string, bytes: Uint8Array) => createHash("sha1").update(`${kind} ${bytes.byteLength}\0`).update(bytes).digest("hex");

async function fixture(files: IsolatedSourceFile[] = [source("README.md")]) {
  const root = await mkdtemp(path.join(os.tmpdir(), "bootstrap-data-git-test-")); directories.push(root);
  await mkdir(path.join(root, "empty-template"));
  const env = { PATH: "/usr/bin:/bin:/usr/local/bin", HOME: root, GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_SYSTEM: "/dev/null",
    GIT_CONFIG_GLOBAL: "/dev/null", GIT_ATTR_NOSYSTEM: "1", GIT_TERMINAL_PROMPT: "0", GIT_AUTHOR_NAME: "Public Fixture",
    GIT_AUTHOR_EMAIL: "fixture@example.invalid", GIT_AUTHOR_DATE: "@1767225600 +0000", GIT_COMMITTER_NAME: "Public Fixture",
    GIT_COMMITTER_EMAIL: "fixture@example.invalid", GIT_COMMITTER_DATE: "@1767225600 +0000" };
  const git = (args: string[], input?: Uint8Array | string) => execFileSync("/usr/bin/git", ["-c", "core.hooksPath=/dev/null",
    "-c", "commit.gpgsign=false", "-c", "core.fsmonitor=false", "-c", "core.attributesFile=/dev/null", ...args],
  { cwd: root, env, ...(input === undefined ? {} : { input }), maxBuffer: 8 * 1024 ** 2 });
  git(["init", "-q", "--initial-branch=main", `--template=${path.join(root, "empty-template")}`]);
  const blobs = new Map<string, string>();
  const entries = files.map((file) => {
    const digest = objectId("blob", file.bytes);
    if (!blobs.has(digest)) blobs.set(digest, git(["hash-object", "--stdin", "--no-filters", "-w"], file.bytes).toString().trim());
    return Buffer.from(`${file.mode} ${blobs.get(digest)}\t${file.path}\0`);
  });
  git(["update-index", "-z", "--index-info"], Buffer.concat(entries));
  const tree = git(["write-tree"]).toString().trim();
  const baseCommit = git(["commit-tree", tree], "test: synthetic public snapshot\n").toString().trim();
  git(["update-ref", "refs/heads/main", baseCommit]);
  const commitBytes = git(["cat-file", "commit", baseCommit]);
  return { root, files, tree, baseCommit, commitBytes, git,
    snapshot: () => verifyGitSnapshot({ baseCommit, commitBytes, files }) };
}

afterEach(async () => {
  vi.unstubAllEnvs();
  await Promise.all(directories.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe("private verified Git data", () => {
  it("matches real Git tree ordering and materializes the exact regular files and executable modes", async () => {
    const data = await fixture([source("foo.bar"), source("foo/file", "nested\n"), source("unicodé.txt", "UTF-8\n"),
      source("runner.sh", "#!/bin/sh\nexit 0\n", true)]);
    const snapshot = data.snapshot();
    expect(snapshot.baseCommit).toBe(data.baseCommit);
    expect(snapshot.tree).toBe(data.tree);
    const repository = await openDataRepository(snapshot);
    try {
      expect(Reflect.set(repository, "root", data.root)).toBe(false);
      for (const entry of data.files) {
        expect(await readFile(path.join(repository.root, entry.path))).toEqual(Buffer.from(entry.bytes));
        expect(Boolean((await lstat(path.join(repository.root, entry.path))).mode & 0o100)).toBe(entry.mode === "100755");
      }
      expect((await repository.readIndex(await readFile(path.join(data.root, ".git/index")))).map((entry) => entry.path))
        .toEqual([...data.files].sort((a, b) => Buffer.compare(Buffer.from(a.path), Buffer.from(b.path))).map((entry) => entry.path));
    } finally { await repository.dispose(); }
    await expect(lstat(repository.root)).rejects.toMatchObject({ code: "ENOENT" });
    expect((await lstat(data.root)).isDirectory()).toBe(true);
  });

  it("preserves opaque binary regular-file payloads through real Git snapshot and materialization", async () => {
    const bytes = Buffer.from([0x00, 0xff, 0xfe, 0x80, 0x0d, 0x0a, 0xc3, 0x28, 0x41, 0x00]);
    const name = "assets/binary-payload.bin";
    const data = await fixture([{ path: name, mode: "100644", bytes }]);
    const snapshot = data.snapshot();
    expect(snapshot).toMatchObject({ baseCommit: data.baseCommit, tree: data.tree });
    expect(copySnapshotFiles(snapshot)).toEqual([{ path: name, mode: "100644", bytes }]);
    const repository = await openDataRepository(snapshot);
    try {
      const actual = await readFile(path.join(repository.root, name));
      expect(actual).toEqual(bytes);
      const oid = data.git(["hash-object", "--stdin", "--no-filters"], actual).toString().trim();
      expect(oid).toBe(objectId("blob", bytes));
      expect(data.git(["rev-parse", `${data.baseCommit}:${name}`]).toString().trim()).toBe(oid);
      expect(await repository.readIndex(await readFile(path.join(repository.root, ".git/index"))))
        .toEqual([{ path: name, mode: "100644", oid, stage: 0 }]);
    } finally { await repository.dispose(); }
  });

  it("owns copied snapshot bytes rather than trusting caller or returned Buffer mutations", async () => {
    const data = await fixture();
    const snapshot = data.snapshot();
    data.files[0]!.bytes.fill(0);
    data.commitBytes.fill(0);
    const exported = copySnapshotFiles(snapshot);
    exported[0]!.bytes.fill(1);
    exported[0]!.path = "changed-by-caller";
    const repository = await openDataRepository(snapshot);
    try { expect((await readFile(path.join(repository.root, "README.md"))).toString()).toBe("public fixture\n"); }
    finally { await repository.dispose(); }
    expect(copySnapshotFiles(snapshot)[0]!.path).toBe("README.md");
  });

  it("rejects a forged structural copy of a verified snapshot", async () => {
    const data = await fixture();
    const forged = { ...data.snapshot() };
    await expect(openDataRepository(forged)).rejects.toThrow();
    expect(() => copySnapshotFiles(forged)).toThrow();
  });

  it.each(["commit", "content", "mode", "missing"])("rejects a mismatched %s binding", async (change) => {
    const data = await fixture();
    const files = data.files.map((file) => ({ ...file, bytes: Buffer.from(file.bytes) }));
    if (change === "content") files[0]!.bytes = Buffer.from("different public contents\n");
    if (change === "mode") files[0]!.mode = "100755";
    if (change === "missing") files.length = 0;
    expect(() => verifyGitSnapshot({ files, commitBytes: data.commitBytes,
      baseCommit: change === "commit" ? "1".repeat(40) : data.baseCommit })).toThrow();
  });

  it("bounds raw commit bytes without accepting invalid UTF-8 replacement", async () => {
    const data = await fixture();
    const header = `tree ${data.tree}\nauthor Fixture <fixture@example.invalid> 1767225600 +0000\ncommitter Fixture <fixture@example.invalid> 1767225600 +0000\n\n`;
    const bytes = Buffer.concat([Buffer.from(header), Buffer.alloc(1024 ** 2 - Buffer.byteLength(header), 0x61)]);
    expect(verifyGitSnapshot({ baseCommit: objectId("commit", bytes), commitBytes: bytes, files: data.files }).tree).toBe(data.tree);
    const oversized = Buffer.concat([bytes, Buffer.from("x")]);
    expect(() => verifyGitSnapshot({ baseCommit: objectId("commit", oversized), commitBytes: oversized, files: data.files })).toThrow();
    const invalid = Buffer.concat([Buffer.from(header), Buffer.from([0xff])]);
    expect(() => verifyGitSnapshot({ baseCommit: objectId("commit", invalid), commitBytes: invalid, files: data.files })).toThrow();
  });

  it.each(["../escape", ".GiT/config", "node_modules/fixture", "dist/fixture", "folder\\name", "\ud800"])
    ("rejects unsupported raw path %j", async (name) => {
      const data = await fixture();
      expect(() => verifyGitSnapshot({ baseCommit: data.baseCommit, commitBytes: data.commitBytes,
        files: [source(name)] })).toThrow();
    });

  it.each(["Node_Modules", "NODE_MODULES", "Dist", "DIST"])
    ("rejects reserved dependency-root case variant %s in a valid Git tree", async (root) => {
      const data = await fixture([source(`${root}/fixture`)]);
      expect(() => data.snapshot()).toThrow("Governed upgrade Git data is unsupported.");
    });

  it("retains ordinary roots beside reserved dependency-root rejection", async () => {
    const data = await fixture([source("src/fixture"), source("distribution/fixture")]);
    expect(data.snapshot()).toMatchObject({ baseCommit: data.baseCommit, tree: data.tree });
  });

  it("counts directory expansion in the exact 10,000-entry boundary", async () => {
    const shared = Array.from({ length: 9999 }, (_, index) => source(`folder/file-${index}`, ""));
    const data = await fixture(shared);
    expect(data.snapshot().tree).toBe(data.tree);
    const expanded = Array.from({ length: 5001 }, (_, index) => source(`directory-${index}/file`, ""));
    const over = await fixture(expanded);
    expect(() => over.snapshot()).toThrow();
  }, 15_000);

  it("rejects duplicate inventories even when silently deduplicating would produce the original tree", async () => {
    const data = await fixture();
    expect(() => verifyGitSnapshot({ baseCommit: data.baseCommit, commitBytes: data.commitBytes,
      files: [...data.files, ...data.files] })).toThrow();
  });

  it("accepts the 32-component domain and rejects an otherwise valid deeper Git tree", async () => {
    const accepted = await fixture([source([...Array.from({ length: 31 }, (_, index) => `d${index}`), "file"].join("/"))]);
    expect(accepted.snapshot().tree).toBe(accepted.tree);
    const rejected = await fixture([source([...Array.from({ length: 32 }, (_, index) => `d${index}`), "file"].join("/"))]);
    expect(() => rejected.snapshot()).toThrow();
  });

  it.each([
    ["case", "Folder", "folder"],
    ["normalization", "caf\u00e9", "cafe\u0301"]
  ])("never merges distinct raw directory names on a %s-aliasing filesystem", async (_kind, first, second) => {
    const data = await fixture([source(`${first}/one`, "first\n"), source(`${second}/two`, "second\n")]);
    const probe = path.join(data.root, "filesystem-probe"); await mkdir(probe);
    await mkdir(path.join(probe, first!));
    let aliases = false;
    try { await mkdir(path.join(probe, second!)); }
    catch (error) { expect((error as NodeJS.ErrnoException).code).toBe("EEXIST"); aliases = true; }
    if (aliases) await expect(openDataRepository(data.snapshot())).rejects.toThrow();
    else {
      const repository = await openDataRepository(data.snapshot());
      try {
        expect((await readFile(path.join(repository.root, first!, "one"))).toString()).toBe("first\n");
        expect((await readFile(path.join(repository.root, second!, "two"))).toString()).toBe("second\n");
      } finally { await repository.dispose(); }
    }
  });

  it("classifies ignores from public bytes and never follows copied config includes", async () => {
    const data = await fixture([source("README.md"), source(".gitignore", "ignored/\n*.log\n!important.log\n")]);
    const repository = await openDataRepository(data.snapshot());
    try {
      expect(await repository.ignored(["ignored/private", "build.log", "important.log", "README.md"]))
        .toEqual(new Set(["ignored/private", "build.log"]));
      const outside = path.join(data.root, "outside-config");
      await writeFile(outside, "[canary]\n value = must-not-be-imported\n");
      const entries = await repository.configEntries(Buffer.from(`[include]\n path = ${outside}\n[remote "origin"]\n url = https://github.com/example/public.git\n`));
      expect(entries).toContainEqual(["include.path", outside]);
      expect(entries.some(([name]) => name === "canary.value")).toBe(false);
      await expect(repository.configEntries(Buffer.alloc(1024 ** 2 + 1))).rejects.toThrow();
      await expect(repository.readIndex(Buffer.alloc(16 * 1024 ** 2 + 1))).rejects.toThrow();
    } finally { await repository.dispose(); }
  });

  it("classifies unknown directory ignores without materializing their contents", async () => {
    const data = await fixture([source("README.md"), source(".gitignore", "cache/\n*.log\n")]);
    const repository = await openDataRepository(data.snapshot());
    try {
      await expect(lstat(path.join(repository.root, "cache"))).rejects.toMatchObject({ code: "ENOENT" });
      expect(await repository.ignored(["cache"])).toEqual(new Set());
      expect(await repository.ignored(["cache/", "unignored/", "build.log"]))
        .toEqual(new Set(["cache", "build.log"]));
      await expect(lstat(path.join(repository.root, "cache"))).rejects.toMatchObject({ code: "ENOENT" });
      await expect(lstat(path.join(repository.root, "unignored"))).rejects.toMatchObject({ code: "ENOENT" });
    } finally { await repository.dispose(); }
  });

  it.each(["/cache/", "../cache/", "cache//", "cache/../other/"])
    ("rejects unsafe directory-aware ignore path %s", async (name) => {
      const data = await fixture([source("README.md"), source(".gitignore", "cache/\n")]);
      const repository = await openDataRepository(data.snapshot());
      try { await expect(repository.ignored([name])).rejects.toThrow("Governed upgrade Git data is unsupported."); }
      finally { await repository.dispose(); }
    });

  it("ignores ambient Git configuration, tracing and PATH command canaries", async () => {
    const data = await fixture();
    const marker = path.join(data.root, "ambient-command-marker");
    const bin = path.join(data.root, "canary-bin"); await mkdir(bin);
    await writeFile(path.join(bin, "git"), `#!/bin/sh\n: > '${marker}'\nexit 73\n`, { mode: 0o755 });
    vi.stubEnv("PATH", bin);
    vi.stubEnv("GIT_TRACE", path.join(data.root, "trace-marker"));
    vi.stubEnv("GIT_CONFIG_COUNT", "1");
    vi.stubEnv("GIT_CONFIG_KEY_0", "core.fsmonitor");
    vi.stubEnv("GIT_CONFIG_VALUE_0", `sh -c ': > "${marker}"'`);
    const repository = await openDataRepository(data.snapshot());
    await repository.dispose();
    await expect(lstat(marker)).rejects.toMatchObject({ code: "ENOENT" });
    await expect(lstat(path.join(data.root, "trace-marker"))).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("rejects pre-cancelled materialization", async () => {
    const data = await fixture(); const controller = new AbortController(); controller.abort(new Error("private caller cancellation reason"));
    const error = await openDataRepository(data.snapshot(), { signal: controller.signal }).then(() => undefined, (value: unknown) => value);
    expect((error as Error).message).toBe("Governed upgrade Git data is unsupported.");
  });

  it("does not return an empty ignore result after disposal", async () => {
    const data = await fixture(); const repository = await openDataRepository(data.snapshot());
    await repository.dispose();
    await expect(repository.ignored([])).rejects.toThrow("Governed upgrade Git data is unsupported.");
    await expect(lstat(repository.root)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("does not return an empty ignore result or private reason after caller cancellation", async () => {
    const data = await fixture(); const controller = new AbortController();
    const repository = await openDataRepository(data.snapshot(), { signal: controller.signal });
    try {
      controller.abort(new Error("private caller cancellation reason"));
      const error = await repository.ignored([]).then(() => undefined, (value: unknown) => value);
      expect((error as Error).message).toBe("Governed upgrade Git data is unsupported.");
    } finally { await repository.dispose(); }
    await expect(lstat(repository.root)).rejects.toMatchObject({ code: "ENOENT" });
  });
});
