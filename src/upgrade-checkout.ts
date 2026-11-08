import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { lstat, open, opendir, realpath } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { ISOLATION_LIMITS } from "./isolation/node-profile.js";
import { copySnapshotFiles, decodeGitPath, openDataRepository, type DataRepository, type VerifiedGitSnapshot } from "./upgrade-git.js";

const failure = () => new Error("Checkout is not eligible for a governed upgrade.");
function demand(value: unknown): asserts value { if (!value) throw failure(); }
const digest = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("hex");
const decode = (bytes: Uint8Array) => new TextDecoder("utf-8", { fatal: true }).decode(bytes);
const reference = (value: string) => /^refs\/[A-Za-z0-9][A-Za-z0-9._/-]*$/.test(value) && !value.includes("..") && !value.includes("//") && value.split("/").every((part) => !part.endsWith(".") && !part.endsWith(".lock"));

async function parents(root: string, relative: string): Promise<void> {
  const parts = relative.split("/");
  for (let end = 1; end < parts.length; end++) demand((await lstat(path.join(root, ...parts.slice(0, end)))).isDirectory());
}
async function regular(root: string, relative: string, limit: number, optional = false): Promise<{ bytes: Buffer; mode: number } | undefined> {
  try {
    demand(Number.isInteger(constants.O_NOFOLLOW) && constants.O_NOFOLLOW > 0 && Number.isInteger(constants.O_NONBLOCK) && constants.O_NONBLOCK > 0);
    await parents(root, relative);
    const handle = await open(path.join(root, relative), constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    try {
      const before = await handle.stat(); demand(before.isFile() && before.nlink === 1 && before.size <= limit);
      const bytes = Buffer.alloc(before.size + 1); let count = 0;
      while (count < bytes.length) { const result = await handle.read(bytes, count, bytes.length - count, count); if (!result.bytesRead) break; count += result.bytesRead; }
      const after = await handle.stat();
      demand(count <= limit && after.isFile() && after.nlink === 1 && after.size === before.size && count === after.size && after.mtimeMs === before.mtimeMs);
      return { bytes: bytes.subarray(0, count), mode: after.mode };
    } finally { await handle.close(); }
  } catch (error) { if (optional && (error as NodeJS.ErrnoException).code === "ENOENT") return undefined; throw failure(); }
}
async function entries(root: string, relative: string): Promise<Array<{ name: string; directory: boolean; mode: number }>> {
  const result: Array<{ name: string; directory: boolean; mode: number }> = [];
  await parents(root, relative); demand((await lstat(path.join(root, relative))).isDirectory());
  // Node supports raw directory names; @types/node narrows this option to BufferEncoding.
  const directory = await opendir(path.join(root, relative), { encoding: "buffer" as BufferEncoding });
  for await (const entry of directory) {
    demand(result.length < ISOLATION_LIMITS.entries);
    const raw: unknown = entry.name; demand(Buffer.isBuffer(raw));
    if (!relative && raw.equals(Buffer.from(".git"))) continue;
    const name = decodeGitPath(raw); demand(!name.includes("/"));
    const stat = await lstat(path.join(root, relative, name)); result.push({ name, directory: stat.isDirectory(), mode: stat.mode });
  }
  return result;
}
async function absent(root: string, relative: string): Promise<void> {
  try { await parents(root, relative); await lstat(path.join(root, relative)); throw failure(); } catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw failure(); }
}
async function untracked(root: string, repository: DataRepository, tracked: Set<string>): Promise<void> {
  const parents = new Set<string>();
  for (const name of tracked) { const parts = name.split("/"); for (let end = 1; end < parts.length; end++) parents.add(parts.slice(0, end).join("/")); }
  const expectedComponents = new Map<string, Set<string>>();
  for (const name of [...tracked, ...parents]) {
    const separator = name.lastIndexOf("/"); const directory = separator < 0 ? "" : name.slice(0, separator);
    if (!expectedComponents.has(directory)) expectedComponents.set(directory, new Set());
    expectedComponents.get(directory)!.add(name.slice(separator + 1));
  }
  let count = 0;
  const walk = async (relative: string): Promise<void> => {
    const children = await entries(root, relative);
    count += children.length; demand(count <= ISOLATION_LIMITS.entries);
    const actualComponents = new Set(children.map(({ name }) => name));
    // Filesystem aliases must not turn a renamed tracked component into an ignored entry.
    for (const name of expectedComponents.get(relative) ?? []) demand(actualComponents.has(name));
    const paths = children.map(({ name }) => relative ? relative + "/" + name : name);
    const unknown = children.flatMap(({ directory }, index) => {
      const name = paths[index]!; return tracked.has(name) || parents.has(name) ? [] : [name + (directory ? "/" : "")];
    });
    const ignored = await repository.ignored(unknown);
    for (let index = 0; index < children.length; index++) {
      const entry = children[index]!; const name = paths[index]!;
      if (tracked.has(name) || ignored.has(name)) continue;
      demand(entry.directory); await walk(name);
    }
  };
  await walk("");
}
export interface CheckoutAudit { baseCommit: string; tree: string; sourceSha256: string; originalStateSha256: string }

export async function auditCheckout(root: string, snapshot: VerifiedGitSnapshot, expectedOrigin: string, options: { signal?: AbortSignal } = {}): Promise<CheckoutAudit> {
  let repository: DataRepository | undefined;
  try {
    options.signal?.throwIfAborted();
    demand(/^https:\/\/github\.com\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+\.git$/.test(expectedOrigin));
    demand((await lstat(root)).isDirectory()); root = await realpath(root);
    const temporaryRoot = await realpath(os.tmpdir());
    demand(temporaryRoot !== root && !temporaryRoot.startsWith(root + path.sep));
    demand((await lstat(path.join(root, ".git"))).isDirectory());
    await absent(root, ".git/commondir"); await absent(root, ".git/config.worktree"); await absent(root, ".git/objects/info/alternates");
    const gitEntries = await entries(root, ".git"); demand(!gitEntries.some(({ name }) => name.startsWith("sharedindex.")));
    const metadata: Array<{ path: string; sha256: string }> = [];
    const get = async (name: string, limit: number, optional = false) => {
      const value = await regular(root, name, limit, optional); if (value) metadata.push({ path: name, sha256: digest(value.bytes) }); return value?.bytes;
    };
    const head = await get(".git/HEAD", 4096); const config = await get(".git/config", ISOLATION_LIMITS.manifestBytes); const index = await get(".git/index", ISOLATION_LIMITS.lockBytes);
    demand(head && config && index); const headText = decode(head);
    let current: string;
    if (/^[a-f0-9]{40}\n?$/.test(headText)) current = headText.trimEnd();
    else {
      const match = /^ref: (refs\/heads\/[^\n]+)\n?$/.exec(headText); demand(match && reference(match[1]!));
      const loose = await get(".git/" + match[1]!, 4096, true);
      if (loose) { current = decode(loose).trimEnd(); demand(/^[a-f0-9]{40}$/.test(current)); }
      else {
        const packed = await get(".git/packed-refs", ISOLATION_LIMITS.manifestBytes); demand(packed); const found: string[] = [];
        for (const line of decode(packed).split("\n")) {
          if (!line || line.startsWith("#")) continue;
          if (/^\^[a-f0-9]{40}$/.test(line)) continue;
          const item = /^([a-f0-9]{40}) (refs\/[^\s]+)$/.exec(line); demand(item && reference(item[2]!));
          if (item[2] === match[1]) found.push(item[1]!);
        }
        demand(found.length === 1); current = found[0]!;
      }
    }
    demand(current === snapshot.baseCommit);
    repository = await openDataRepository(snapshot, options);
    const settings = await repository.configEntries(config);
    for (const [key, value] of settings) {
      const lower = key.toLowerCase();
      demand(!lower.startsWith("include.") && !lower.startsWith("includeif.") && !["core.worktree", "extensions.worktreeconfig", "core.sparsecheckout", "core.sparsecheckoutcone", "extensions.sparseindex", "core.splitindex", "core.excludesfile", "core.attributesfile"].includes(lower));
      if (lower === "core.bare") demand(value === "false");
      if (lower === "core.repositoryformatversion") demand(value === "0" || value === "1");
      if (lower.startsWith("extensions.")) demand(lower === "extensions.objectformat" && value === "sha1");
      if (lower === "core.hookspath") demand(value === ".githooks");
      if (lower.startsWith("remote.")) demand(key.startsWith("remote.origin."));
    }
    const origins = settings.filter(([key]) => key === "remote.origin.url").map(([, value]) => value);
    const pushes = settings.filter(([key]) => key === "remote.origin.pushurl").map(([, value]) => value);
    demand(origins.length === 1 && origins[0] === expectedOrigin && pushes.length <= 1 && pushes.every((value) => value === expectedOrigin));
    for (const name of ["exclude", "attributes"]) {
      const local = await get(".git/info/" + name, ISOLATION_LIMITS.manifestBytes, true);
      if (local) demand(decode(local).split("\n").every((line) => !line.trim() || line.trimStart().startsWith("#")));
    }
    try {
      const hooks = await entries(root, ".git/hooks");
      demand(hooks.every(({ name, directory, mode }) => !directory && (name.endsWith(".sample") || !(mode & 0o111))));
    } catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
    const files = copySnapshotFiles(snapshot); const indexed = await repository.readIndex(index);
    demand(indexed.length === files.length);
    const expected = new Map(files.map((file) => [file.path, file])); const seen = new Set<string>();
    if (settings.some(([key]) => key.toLowerCase() === "core.hookspath")) {
      try {
        const hooks = await entries(root, ".githooks");
        demand(hooks.every(({ name, directory, mode }) => expected.has(".githooks/" + name) ||
          !directory && (name.endsWith(".sample") || !(mode & 0o111))));
      } catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
    }
    // Verify raw spellings before reading paths that a filesystem alias could redirect.
    await untracked(root, repository, new Set(expected.keys()));
    for (const entry of indexed) {
      const file = expected.get(entry.path); demand(file && !seen.has(entry.path) && entry.stage === 0 && entry.mode === file.mode); seen.add(entry.path);
      demand(entry.oid === createHash("sha1").update(`blob ${file.bytes.byteLength}\0`).update(file.bytes).digest("hex"));
      const actual = await regular(root, entry.path, file.bytes.byteLength); demand(actual && actual.bytes.equals(Buffer.from(file.bytes)) && (actual.mode & 0o100 ? "100755" : "100644") === file.mode);
    }
    for (const item of metadata) { const after = await regular(root, item.path, item.path.endsWith("/index") ? ISOLATION_LIMITS.lockBytes : ISOLATION_LIMITS.manifestBytes); demand(after && digest(after.bytes) === item.sha256); }
    options.signal?.throwIfAborted(); await repository.ignored([]);
    return { baseCommit: snapshot.baseCommit, tree: snapshot.tree, sourceSha256: snapshot.sourceSha256,
      originalStateSha256: digest(Buffer.from(JSON.stringify({ metadata, tracked: files.map(({ path, mode, bytes }) => ({ path, mode, sha256: digest(bytes) })) }))) };
  } catch { throw failure(); }
  finally {
    if (repository) {
      try { await repository.dispose(); }
      catch {
        try { await repository.dispose(); } catch { /* Persistent cleanup failure cannot be repaired here. */ }
        // Even a successful retry cannot turn an audit with failed cleanup into success.
        throw failure();
      }
    }
  }
}
