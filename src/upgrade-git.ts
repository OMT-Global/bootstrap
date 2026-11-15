import { spawn } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { lstat, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { ISOLATION_LIMITS, type IsolatedSourceFile } from "./isolation/node-profile.js";

const failure = () => new Error("Governed upgrade Git data is unsupported.");
function demand(value: unknown): asserts value { if (!value) throw failure(); }
const digest = (value: Uint8Array) => createHash("sha256").update(value).digest("hex");
const objectId = (kind: string, bytes: Uint8Array) => createHash("sha1").update(`${kind} ${bytes.byteLength}\0`).update(bytes).digest("hex");
const text = (bytes: Uint8Array) => new TextDecoder("utf-8", { fatal: true }).decode(bytes);
function relativePath(value: string): boolean {
  return value.length > 0 && Buffer.byteLength(value) <= 4096 && Buffer.from(value).toString() === value &&
    !value.includes("\0") && !value.includes("\\") && !path.posix.isAbsolute(value) && path.posix.normalize(value) === value &&
    value.split("/").length <= ISOLATION_LIMITS.pathDepth && value.split("/").every((part) => part && part !== "." && part !== ".." && part.toLowerCase() !== ".git");
}
export function decodeGitPath(bytes: Uint8Array): string {
  try { const value = text(bytes); demand(relativePath(value) && Buffer.from(value).equals(Buffer.from(bytes))); return value; } catch { throw failure(); }
}
export interface GitSnapshotInput { baseCommit: string; commitBytes: Uint8Array; files: readonly IsolatedSourceFile[] }
export interface VerifiedGitSnapshot { readonly baseCommit: string; readonly tree: string; readonly sourceSha256: string }
interface FrozenFile { path: string; mode: "100644" | "100755"; bytes: Buffer; oid: string; sha256: string }
interface SnapshotData { files: FrozenFile[]; commit: Buffer }
const snapshots = new WeakMap<VerifiedGitSnapshot, SnapshotData>();
function snapshotData(snapshot: VerifiedGitSnapshot): SnapshotData { const data = snapshots.get(snapshot); demand(data); return data; }

// A snapshot proves raw object consistency. Its caller still authenticates visibility and the live base.
export function verifyGitSnapshot(input: GitSnapshotInput): VerifiedGitSnapshot {
  try {
    demand(/^[a-f0-9]{40}$/.test(input.baseCommit) && input.commitBytes instanceof Uint8Array &&
      input.commitBytes.byteLength > 0 && input.commitBytes.byteLength <= ISOLATION_LIMITS.manifestBytes);
    demand(Array.isArray(input.files) && input.files.length > 0 && input.files.length <= ISOLATION_LIMITS.files);
    const names = new Set<string>(); const directories = new Set<string>(); let size = 0;
    const files: FrozenFile[] = input.files.map((file) => {
      demand(typeof file.path === "string" && relativePath(file.path) && !["node_modules", "dist"].includes(file.path.split("/")[0]!.toLowerCase()) && !names.has(file.path));
      demand((file.mode === "100644" || file.mode === "100755") && file.bytes instanceof Uint8Array);
      names.add(file.path); size += file.bytes.byteLength; demand(size <= ISOLATION_LIMITS.sourceBytes);
      // File payloads are opaque Git blobs; UTF-8 validation belongs to paths and parsed metadata.
      const bytes = Buffer.from(file.bytes); return { path: file.path, mode: file.mode, bytes, oid: objectId("blob", bytes), sha256: digest(bytes) };
    }).sort((a, b) => Buffer.compare(Buffer.from(a.path), Buffer.from(b.path)));
    for (const file of files) {
      const parts = file.path.split("/");
      for (let end = 1; end < parts.length; end++) { const name = parts.slice(0, end).join("/"); demand(!names.has(name)); directories.add(name); }
      demand(files.length + directories.size <= ISOLATION_LIMITS.entries);
    }
    interface Directory { children: Map<string, Directory | FrozenFile> }
    const root: Directory = { children: new Map() };
    for (const file of files) {
      const parts = file.path.split("/"); let directory = root;
      for (const part of parts.slice(0, -1)) {
        if (!directory.children.has(part)) directory.children.set(part, { children: new Map() });
        const child = directory.children.get(part)!; demand("children" in child); directory = child;
      }
      directory.children.set(parts.at(-1)!, file);
    }
    const treeId = (directory: Directory): string => {
      const entries = [...directory.children].sort(([a, left], [b, right]) => Buffer.compare(Buffer.from(a + ("children" in left ? "/" : "")), Buffer.from(b + ("children" in right ? "/" : ""))));
      const bytes = Buffer.concat(entries.map(([name, entry]) => Buffer.concat([Buffer.from(`${"children" in entry ? "40000" : entry.mode} ${name}\0`), Buffer.from("children" in entry ? treeId(entry) : entry.oid, "hex")])));
      return objectId("tree", bytes);
    };
    const tree = treeId(root); const commit = Buffer.from(input.commitBytes); const decoded = text(commit); const boundary = decoded.indexOf("\n\n");
    demand(boundary > 0 && !decoded.includes("\0") && decoded.startsWith(`tree ${tree}\n`));
    const headers = decoded.slice(0, boundary).split("\n");
    demand(headers.filter((line) => line.startsWith("tree ")).length === 1 && headers.filter((line) => line.startsWith("author ")).length === 1 && headers.filter((line) => line.startsWith("committer ")).length === 1);
    demand(headers.every((line) => line.startsWith(" ") || /^[a-z][a-z0-9-]* .+$/.test(line)) && headers.filter((line) => line.startsWith("parent ")).every((line) => /^parent [a-f0-9]{40}$/.test(line)));
    demand(objectId("commit", commit) === input.baseCommit);
    const snapshot = Object.freeze({ baseCommit: input.baseCommit, tree, sourceSha256: digest(Buffer.from(JSON.stringify(files.map(({ path, mode, sha256 }) => ({ path, mode, sha256 }))))) });
    snapshots.set(snapshot, { files, commit }); return snapshot;
  } catch { throw failure(); }
}
export function copySnapshotFiles(snapshot: VerifiedGitSnapshot): IsolatedSourceFile[] {
  return snapshotData(snapshot).files.map(({ path, mode, bytes }) => ({ path, mode, bytes: Buffer.from(bytes) }));
}
export interface GitIndexEntry { path: string; mode: "100644" | "100755"; oid: string; stage: number }
export interface DataRepository {
  readonly root: string;
  readIndex(bytes: Uint8Array): Promise<GitIndexEntry[]>;
  configEntries(bytes: Uint8Array): Promise<Array<[string, string]>>;
  ignored(paths: readonly string[]): Promise<Set<string>>;
  archive(prefix: string): Promise<Buffer>;
  dispose(): Promise<void>;
}
async function gitExecutable(): Promise<string> {
  const binary = await realpath("/usr/bin/git"); let current = binary; let first = true;
  for (;;) {
    const stat = await lstat(current); demand(stat.uid === 0 && !(stat.mode & 0o022) && (first ? stat.isFile() && !!(stat.mode & 0o111) : stat.isDirectory()));
    if (current === path.dirname(current)) break;
    current = path.dirname(current); first = false;
  }
  return binary;
}

export async function openDataRepository(snapshot: VerifiedGitSnapshot, options: { signal?: AbortSignal } = {}): Promise<DataRepository> {
  const data = snapshotData(snapshot); const cancellation = new AbortController();
  const signal = AbortSignal.any([cancellation.signal, AbortSignal.timeout(ISOLATION_LIMITS.phaseMs), ...(options.signal ? [options.signal] : [])]);
  if (signal.aborted) throw failure();
  const directory = await mkdtemp(path.join(os.tmpdir(), "bootstrap-upgrade-data-")).catch(() => { throw failure(); });
  const root = path.join(directory, "source"); const gitdir = path.join(root, ".git"); const empty = path.join(directory, "empty"); let closed = false; let removed = false;
  try {
    const binary = await gitExecutable(); await mkdir(root); await mkdir(empty);
    const env = { PATH: "/usr/bin:/bin", HOME: empty, TMPDIR: directory, LC_ALL: "C", LANG: "C", TZ: "UTC", GIT_DIR: gitdir, GIT_WORK_TREE: root,
      GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_SYSTEM: "/dev/null", GIT_CONFIG_GLOBAL: "/dev/null", GIT_ATTR_NOSYSTEM: "1", GIT_EXEC_PATH: empty, GIT_TERMINAL_PROMPT: "0" };
    const active = new Set<Promise<Buffer>>();
    const run = async (args: string[], input?: Uint8Array, index?: string, allowed = [0]): Promise<Buffer> => {
      const pending = new Promise<Buffer>((resolve, reject) => {
      if (closed || signal.aborted) { reject(failure()); return; }
      const flags = ["core.hooksPath=" + empty, "core.fsmonitor=false", "core.attributesFile=/dev/null", "core.excludesFile=/dev/null", "core.autocrlf=false", "core.ignoreCase=false", "core.logAllRefUpdates=false", "credential.helper=", "gc.auto=0", "maintenance.auto=false"];
      const child = spawn(binary, [...flags.flatMap((value) => ["-c", value]), ...args], { cwd: directory, env: { ...env, ...(index ? { GIT_INDEX_FILE: index } : {}) }, detached: true, stdio: ["pipe", "pipe", "pipe"] });
      const chunks: Buffer[] = []; let size = 0; let settled = false; let failed = false;
      const kill = () => { if (child.pid) { try { process.kill(-child.pid, "SIGKILL"); } catch { /* Already exited. */ } } };
      const fail = () => { if (!settled) { failed = true; kill(); clearTimeout(timer); signal.removeEventListener("abort", fail); } };
      const timer = setTimeout(fail, 30_000); signal.addEventListener("abort", fail, { once: true });
      child.stdout.on("data", (chunk: Buffer) => { size += chunk.length; if (size > ISOLATION_LIMITS.outputBytes) fail(); else if (!failed) chunks.push(chunk); });
      child.stderr.on("data", (chunk: Buffer) => { size += chunk.length; if (size > ISOLATION_LIMITS.outputBytes) fail(); });
      child.once("error", fail); child.stdin.once("error", fail);
      child.once("close", (code, terminated) => {
        if (settled) return; settled = true; clearTimeout(timer); signal.removeEventListener("abort", fail);
        if (failed || terminated || code === null || !allowed.includes(code)) reject(failure()); else resolve(Buffer.concat(chunks));
      });
      if (signal.aborted) fail(); else child.stdin.end(input);
      });
      active.add(pending); try { return await pending; } finally { active.delete(pending); }
    };
    const protect = <T>(work: () => Promise<T>): Promise<T> => work().catch(() => { throw failure(); });
    await run(["init", "--quiet", "--object-format=sha1", "--initial-branch=codex/bootstrap-public-base", `--template=${empty}`]);
    const created = new Set<string>();
    for (const file of data.files) {
      const parts = file.path.split("/");
      for (let end = 1; end < parts.length; end++) {
        const name = parts.slice(0, end).join("/"); if (created.has(name)) continue;
        // Exclusive directory creation distinguishes aliases on case/normalization-insensitive filesystems.
        await mkdir(path.join(root, name)); created.add(name);
      }
      await writeFile(path.join(root, file.path), file.bytes, { flag: "wx", mode: file.mode === "100755" ? 0o755 : 0o644 });
      demand(text(await run(["hash-object", "--no-filters", "-w", "--stdin"], file.bytes)).trim() === file.oid);
    }
    const index = Buffer.concat(data.files.map((file) => Buffer.concat([Buffer.from(`${file.mode} ${file.oid}\t${file.path}\0`)])));
    await run(["update-index", "-z", "--index-info"], index);
    demand(text(await run(["write-tree"])).trim() === snapshot.tree);
    demand(text(await run(["hash-object", "-t", "commit", "-w", "--stdin"], data.commit)).trim() === snapshot.baseCommit);
    await run(["update-ref", "refs/heads/codex/bootstrap-public-base", snapshot.baseCommit]);
    return Object.freeze({ root,
      archive: (prefix: string): Promise<Buffer> => protect(async () => {
        demand(!closed && !signal.aborted && /^[A-Za-z0-9][A-Za-z0-9._-]{0,254}\/$/.test(prefix));
        return run(["archive", "--format=tar", `--prefix=${prefix}`, snapshot.baseCommit]);
      }),
      readIndex: (bytes: Uint8Array): Promise<GitIndexEntry[]> => protect(async () => {
        demand(!closed && !signal.aborted);
        demand(bytes.byteLength >= 32 && bytes.byteLength <= ISOLATION_LIMITS.lockBytes);
        const copy = Buffer.from(bytes); demand(copy.subarray(0, 4).toString() === "DIRC" && [2, 3, 4].includes(copy.readUInt32BE(4)) && copy.readUInt32BE(8) <= ISOLATION_LIMITS.files);
        demand(createHash("sha1").update(copy.subarray(0, -20)).digest().equals(copy.subarray(-20)));
        const file = path.join(directory, "index-" + randomUUID()); await writeFile(file, copy, { flag: "wx", mode: 0o600 });
        try {
          const output = await run(["ls-files", "--stage", "--sparse", "-z"], undefined, file); demand(output.length === 0 || output.at(-1) === 0);
          return output.length === 0 ? [] : output.subarray(0, -1).toString("binary").split("\0").map((record) => {
            const raw = Buffer.from(record, "binary"); const separator = raw.indexOf(9); demand(separator > 0);
            const match = /^(100644|100755) ([a-f0-9]{40}) ([0-3])$/.exec(raw.subarray(0, separator).toString("ascii")); demand(match);
            return { path: decodeGitPath(raw.subarray(separator + 1)), mode: match[1] as "100644" | "100755", oid: match[2]!, stage: Number(match[3]) };
          });
        } finally { await rm(file, { force: true }); }
      }),
      configEntries: (bytes: Uint8Array): Promise<Array<[string, string]>> => protect(async () => {
        demand(!closed && !signal.aborted);
        demand(bytes.byteLength <= ISOLATION_LIMITS.manifestBytes);
        const output = text(await run(["config", "--file", "-", "--no-includes", "--null", "--list"], bytes)); demand(!output || output.endsWith("\0"));
        return output ? output.slice(0, -1).split("\0").map((record) => { const end = record.indexOf("\n"); demand(end >= 0); return [record.slice(0, end), record.slice(end + 1)]; }) : [];
      }),
      ignored: (paths: readonly string[]): Promise<Set<string>> => protect(async () => {
        demand(!closed && !signal.aborted);
        demand(paths.length <= ISOLATION_LIMITS.entries && paths.every((name) => relativePath(name.endsWith("/") ? name.slice(0, -1) : name)));
        if (!paths.length) return new Set();
        const output = await run(["check-ignore", "--no-index", "-z", "--stdin"], Buffer.from(paths.join("\0") + "\0"), undefined, [0, 1]);
        demand(!output.length || output.at(-1) === 0);
        return new Set(!output.length ? [] : output.subarray(0, -1).toString("binary").split("\0").map((entry) => {
          const raw = Buffer.from(entry, "binary"); return decodeGitPath(raw.at(-1) === 47 ? raw.subarray(0, -1) : raw);
        }));
      }),
      dispose: () => protect(async () => { closed = true; cancellation.abort(); await Promise.allSettled(active); if (!removed) { await rm(directory, { recursive: true, force: true }); removed = true; } })
    });
  } catch {
    closed = true; cancellation.abort();
    for (let attempt = 0; attempt < 2; attempt++) {
      try { await rm(directory, { recursive: true, force: true }); break; }
      catch { /* Bounded cleanup retry; the primary sanitized failure remains authoritative. */ }
    }
    throw failure();
  }
}
