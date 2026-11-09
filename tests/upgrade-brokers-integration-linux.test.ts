import { execFileSync, spawn, type ChildProcess, type SpawnOptions } from "node:child_process";
import { createHash } from "node:crypto";
import { EventEmitter } from "node:events";
import { lstat, mkdir, mkdtemp, readFile, readdir, realpath, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { Readable } from "node:stream";
import { pathToFileURL } from "node:url";
import { afterEach, describe, expect, it, vi } from "vitest";

// Only provider metadata, one literal public-fetch URL, and the fixture home origin
// are adapted. The synthetic foreground agent alone uses checked child-only NNP;
// production trust, Linux eligibility, prlimit, Git, SSH, Docker and backend stay real.
// This composes the primitives; executor eligibility and governance policy remain a separate proof.
const fixtureState = vi.hoisted(() => ({ home: "", remote: "", base: "", prlimit: "", git: "", original: "", fetches: 0,
  launches: [] as Array<{ command: string; args: readonly string[]; agent: boolean; cwd?: string; gitdir?: string }>, requests: [] as string[] }));
vi.mock("node:os", async (original) => {
  const actual = await original<typeof import("node:os")>();
  return { ...actual, default: { ...actual, userInfo: () => ({ ...actual.userInfo(), homedir: fixtureState.home }) } };
});
vi.mock("node:child_process", async (original) => {
  const actual = await original<typeof import("node:child_process")>();
  return { ...actual, spawn: (command: string, args: readonly string[], options: SpawnOptions) => {
    fixtureState.launches.push({ command, args: [...args], agent: !!options.env?.SSH_AUTH_SOCK, ...(options.cwd ? { cwd: String(options.cwd) } : {}), ...(options.env?.GIT_DIR ? { gitdir: options.env.GIT_DIR } : {}) });
    if (command !== fixtureState.prlimit || !args.includes("fetch")) return actual.spawn(command, args, options);
    const literal = "https://github.com/example/broker-composition.git"; expect(args.filter((arg) => arg === literal)).toHaveLength(1);
    const separator = args.indexOf("--"); expect(args[separator + 1]).toBe(fixtureState.git); const rewritten = [...args];
    rewritten[rewritten.indexOf(literal)] = pathToFileURL(fixtureState.remote).href;
    rewritten.splice(separator + 2, 0, "-c", "protocol.file.allow=always"); fixtureState.fetches++;
    return actual.spawn(command, rewritten, options);
  } };
});
vi.mock("node:https", async (original) => {
  const actual = await original<typeof import("node:https")>();
  const get = (options: { hostname: string; path: string; headers: Record<string, string> }, callback: (response: Readable) => void) => {
    expect(options.hostname).toBe("api.github.com"); expect(options.headers).not.toHaveProperty("Authorization"); fixtureState.requests.push(options.path);
    const metadata = { full_name: "example/broker-composition", private: false, visibility: "public", clone_url: "https://github.com/example/broker-composition.git", default_branch: "main", disabled: false, archived: false };
    expect(["/repos/example/broker-composition", "/repos/example/broker-composition/git/ref/heads/main"]).toContain(options.path);
    const request = new EventEmitter() as EventEmitter & { setTimeout: () => void; destroy: () => void }; request.setTimeout = () => {}; request.destroy = () => {};
    queueMicrotask(() => { const response = Readable.from([Buffer.from(JSON.stringify(options.path.endsWith("/heads/main") ? { ref: "refs/heads/main", object: { type: "commit", sha: fixtureState.base } } : metadata))]); Object.assign(response, { statusCode: 200, headers: { "content-type": "application/json" } }); callback(response); }); return request;
  };
  return { ...actual, default: { ...actual, get } };
});

import { NODE_ISOLATION_IMAGE, NODE_ISOLATION_PROFILE, ISOLATION_LIMITS, freezeNodeValidation, type IsolatedSourceFile } from "../src/isolation/node-profile.js";
import { validateIsolatedNode } from "../src/isolation/node-validation.js";
import { boundedCommand, neutralEnvironment, PRLIMIT_ARGS, readRegular, requireLinuxHost, trustedExecutable } from "../src/upgrade-host.js";
import { captureGeneratorSigning, freezeCommitPlan, signAndVerify } from "../src/upgrade-signing.js";
import { acquirePublicBase, auditPublicCheckout, copyReservedSnapshotFiles, createBoundedBundle, disposePublicRepository, gitArguments, reserveUpgradePreparation, transportContext, writeFrozenTree, type PublicRepository } from "../src/upgrade-transport.js";

const required = process.env.BOOTSTRAP_REQUIRE_HOST_BROKER_TESTS === "1"; const linux = process.platform === "linux";
const roots: string[] = []; const agents: ChildProcess[] = []; const publications: PublicRepository[] = [];
const file = (name: string, contents: string, executable = false): IsolatedSourceFile => ({ path: name, mode: executable ? "100755" : "100644", bytes: Buffer.from(contents) });
const sha256 = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("hex");
interface PublicToolMetadataFs {
  realpath(file: string): Promise<string>;
  lstat(file: string): Promise<{ uid: number; gid: number; mode: number; isFile(): boolean; isDirectory(): boolean; isSymbolicLink(): boolean }>;
}
const publicToolPaths = ["/usr/bin/ssh-agent", "/usr/bin/ssh-keygen", "/usr/bin/ssh-add", "/usr/bin/python3", "/usr/bin/node"] as const;
const publicToolMetadataPrefix = "BROKER_PUBLIC_TOOL_METADATA ";
function publicToolDiagnostic(io: PublicToolMetadataFs = { realpath, lstat }, write: (line: string) => void = (line) => console.log(line)): () => Promise<void> {
  let emitted = false;
  return async () => {
    if (emitted) return;
    emitted = true;
    let expired = false; let timer: ReturnType<typeof setTimeout> | undefined;
    const errorCode = (error: unknown) => {
      const code = (error as { code?: unknown } | null)?.code;
      return typeof code === "string" && ["ENOENT", "EACCES", "EPERM", "ENOTDIR", "ELOOP", "ENAMETOOLONG", "EIO"].includes(code) ? code : "OTHER";
    };
    const collect = async () => {
      const tools: Array<Record<string, unknown>> = [];
      for (const requested of publicToolPaths) {
        if (expired) break;
        const row: Record<string, unknown> = { path: requested }; tools.push(row);
        let resolved: string;
        try { resolved = await io.realpath(requested); }
        catch (error) { row.error = errorCode(error); continue; }
        if (expired) break;
        const prefixes = ["/usr/bin", "/usr/lib", "/usr/libexec", "/usr/local/bin", "/usr/local/lib", "/bin", "/lib", "/lib64", "/opt/hostedtoolcache"];
        if (typeof resolved !== "string" || Buffer.byteLength(resolved) > 512 || path.posix.normalize(resolved) !== resolved ||
          !resolved.split("/").slice(1).every((part) => /^[A-Za-z0-9_][A-Za-z0-9._+-]*$/.test(part)) ||
          !prefixes.some((prefix) => resolved === prefix || resolved.startsWith(prefix + "/"))) {
          row.error = "NON_PUBLIC_RESOLUTION"; continue;
        }
        row.realpath = resolved;
        const ancestors: Array<Record<string, unknown>> = []; row.ancestors = ancestors;
        let current = resolved;
        for (let depth = 0; depth < 16; depth++) {
          if (expired) break;
          try {
            const stat = await io.lstat(current);
            if (expired) break;
            if (![stat.uid, stat.gid, stat.mode].every((value) => Number.isSafeInteger(value) && value >= 0 && value <= 0xffffffff)) {
              ancestors.push({ path: current, error: "INVALID_METADATA" }); break;
            }
            ancestors.push({ path: current, uid: stat.uid, gid: stat.gid, mode: (stat.mode & 0o7777).toString(8).padStart(4, "0"),
              type: stat.isFile() ? "file" : stat.isDirectory() ? "directory" : stat.isSymbolicLink() ? "symlink" : "other" });
          } catch (error) { ancestors.push({ path: current, error: errorCode(error) }); break; }
          if (current === "/") break;
          current = path.posix.dirname(current);
          if (depth === 15) row.error = "ANCESTOR_LIMIT";
        }
      }
      return { schema: 1, tools };
    };
    let record: unknown;
    try {
      record = await Promise.race([collect(), new Promise((resolve) => {
        timer = setTimeout(() => { expired = true; resolve({ schema: 1, error: "TIME_LIMIT" }); }, 2_000);
      })]);
    } catch { record = { schema: 1, error: "DIAGNOSTIC_ERROR" }; }
    finally { expired = true; if (timer !== undefined) clearTimeout(timer); }
    let line = publicToolMetadataPrefix + JSON.stringify(record);
    if (Buffer.byteLength(line + "\n") > 16_384) line = publicToolMetadataPrefix + JSON.stringify({ schema: 1, error: "OUTPUT_LIMIT" });
    try { write(line); } catch { /* Diagnostics never replace the original eligibility assertions. */ }
  };
}
const reportPublicTools = publicToolDiagnostic();

// Fixture-only SGID exception: production trustedExecutable remains unchanged.
const fixedAgentPath = "/usr/bin/ssh-agent";
const agentMetadataPaths = [fixedAgentPath, "/usr/bin", "/usr", "/"] as const;
const agentTestDeadline = ISOLATION_LIMITS.operationMs * 2 + 120_000;
function fixtureDemand(value: unknown): asserts value { if (!value) throw new Error("Synthetic SSH fixture prerequisite failed."); }
interface AgentFileStat {
  dev: bigint; ino: bigint; mode: bigint; uid: bigint; gid: bigint; size: bigint; mtimeNs: bigint; ctimeNs: bigint;
  isFile(): boolean; isDirectory(): boolean; isSymbolicLink(): boolean;
}
interface AgentMetadataIo { realpath(file: string): Promise<string>; stat(file: string): Promise<AgentFileStat> }
interface AgentFingerprint { path: string; dev: string; ino: string; mode: string; uid: string; gid: string; size: string; mtimeNs: string; ctimeNs: string }
interface AgentIdentity { uids: string[]; gids: string[]; groups: string[]; caps: string[]; nnp: number }
interface AgentProcess { pid: number; ppid: number; start: string; state: string }
interface AgentRecord { schema: number; process: Omit<AgentProcess, "state">; identity: AgentIdentity; fingerprints: AgentFingerprint[] }
const agentMetadataIo: AgentMetadataIo = { realpath, stat: (file) => lstat(file, { bigint: true }) };
async function inspectFixtureAgent(io: AgentMetadataIo = agentMetadataIo, strict = trustedExecutable): Promise<AgentFingerprint[]> {
  fixtureDemand(await io.realpath(fixedAgentPath) === fixedAgentPath);
  const rows: AgentFingerprint[] = [];
  for (const [index, file] of agentMetadataPaths.entries()) {
    const stat = await io.stat(file);
    for (const key of ["dev", "ino", "mode", "uid", "gid", "size", "mtimeNs", "ctimeNs"] as const) fixtureDemand(typeof stat[key] === "bigint");
    fixtureDemand(stat.uid === 0n && !stat.isSymbolicLink());
    if (index === 0) fixtureDemand(stat.isFile() && [0o755n, 0o2755n].includes(stat.mode & 0o7777n));
    else fixtureDemand(stat.isDirectory() && !(stat.mode & 0o6022n));
    const row = { path: file, dev: stat.dev.toString(), ino: stat.ino.toString(), mode: stat.mode.toString(), uid: stat.uid.toString(), gid: stat.gid.toString(), size: stat.size.toString(), mtimeNs: stat.mtimeNs.toString(), ctimeNs: stat.ctimeNs.toString() };
    for (const key of ["dev", "ino", "mode", "uid", "gid", "size"] as const) fixtureDemand(/^(0|[1-9]\d*)$/.test(row[key]));
    for (const key of ["mtimeNs", "ctimeNs"] as const) fixtureDemand(/^(0|-?[1-9]\d*)$/.test(row[key]));
    rows.push(row);
  }
  if (BigInt(rows[0]!.mode) & 0o2000n) {
    let rejected = false;
    try { await strict(fixedAgentPath); } catch (error) { rejected = error instanceof Error && error.message === "Governed upgrade host operation is unsupported."; }
    fixtureDemand(rejected);
  } else fixtureDemand(await strict(fixedAgentPath) === fixedAgentPath);
  return rows;
}
function exactKeys(value: unknown, names: string[]): asserts value is Record<string, unknown> {
  fixtureDemand(value && typeof value === "object" && !Array.isArray(value));
  fixtureDemand(JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...names].sort()));
}
function numericIds(value: unknown, size?: number): asserts value is string[] {
  fixtureDemand(Array.isArray(value) && (size === undefined || value.length === size));
  fixtureDemand(value.every((item: unknown) => typeof item === "string" && /^(0|[1-9]\d*)$/.test(item) && BigInt(item) <= 0xffffffffn));
}
function validateAgentIdentity(value: unknown): asserts value is AgentIdentity {
  exactKeys(value, ["uids", "gids", "groups", "caps", "nnp"]);
  numericIds(value.uids, 4); numericIds(value.gids, 4); numericIds(value.groups);
  fixtureDemand(Array.isArray(value.caps) && value.caps.length === 4 && value.caps.every((item) => item === "0"));
  fixtureDemand(value.nnp === 0 || value.nnp === 1);
}
function parseAgentStatus(bytes: Uint8Array): AgentIdentity {
  fixtureDemand(bytes.byteLength <= 65536); const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  const field = (name: string) => { const lines = text.split("\n").filter((line) => line.startsWith(name + ":")); fixtureDemand(lines.length === 1); return lines[0]!.slice(name.length + 1).trim(); };
  const ids = (name: string) => field(name).split(/\s+/).filter(Boolean);
  const caps = ["CapInh", "CapPrm", "CapEff", "CapAmb"].map((name) => { const value = field(name); fixtureDemand(/^0{1,16}$/.test(value)); return "0"; });
  const nnp = field("NoNewPrivs"); fixtureDemand(/^[01]$/.test(nnp));
  const value = { uids: ids("Uid"), gids: ids("Gid"), groups: ids("Groups"), caps, nnp: Number(nnp) }; validateAgentIdentity(value); return value;
}
function sameAgentIdentity(left: AgentIdentity, right: AgentIdentity): boolean {
  return left.nnp === right.nnp && (["uids", "gids", "groups", "caps"] as const).every((key) => JSON.stringify(left[key]) === JSON.stringify(right[key]));
}
function parseAgentProcess(bytes: Uint8Array): AgentProcess {
  fixtureDemand(bytes.byteLength > 0 && bytes.byteLength <= 4096); const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  const end = text.lastIndexOf(") "); fixtureDemand(end > 0); const pid = text.slice(0, text.indexOf(" ")); const fields = text.slice(end + 2).trim().split(/\s+/);
  fixtureDemand(/^[1-9]\d*$/.test(pid) && Number.isSafeInteger(Number(pid)) && Number(pid) <= 0x7fffffff);
  fixtureDemand(/^(0|[1-9]\d*)$/.test(fields[1] ?? "") && Number(fields[1]) <= 0x7fffffff);
  fixtureDemand(/^[1-9]\d*$/.test(fields[19] ?? "") && /^[A-Za-z]$/.test(fields[0] ?? ""));
  return { pid: Number(pid), ppid: Number(fields[1]), start: fields[19]!, state: fields[0]! };
}
function checkAgentRecord(bytes: Uint8Array, pid: number, baseline: AgentIdentity, fingerprints: AgentFingerprint[]): AgentRecord {
  fixtureDemand(bytes.byteLength > 0 && bytes.byteLength <= 16384); const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  fixtureDemand(text.endsWith("\n") && !text.slice(0, -1).includes("\n")); const row: unknown = JSON.parse(text);
  exactKeys(row, ["schema", "process", "identity", "fingerprints"]); fixtureDemand(row.schema === 1);
  exactKeys(row.process, ["pid", "ppid", "start"]); fixtureDemand(row.process.pid === pid && row.process.ppid === process.pid && typeof row.process.start === "string" && /^[1-9]\d*$/.test(row.process.start));
  validateAgentIdentity(row.identity); fixtureDemand(sameAgentIdentity(row.identity, { ...baseline, nnp: 1 }));
  fixtureDemand(Array.isArray(row.fingerprints) && row.fingerprints.length === fingerprints.length);
  for (const [index, expected] of fingerprints.entries()) { const actual: unknown = row.fingerprints[index]; exactKeys(actual, Object.keys(expected)); fixtureDemand(Object.entries(expected).every(([key, value]) => actual[key] === value)); }
  return row as unknown as AgentRecord;
}
interface AgentObserveIo {
  read(file: string, limit: number): Promise<Buffer>;
  stat(file: string): Promise<{ uid: number; mode: number; isSocket(): boolean; isDirectory(): boolean; isSymbolicLink(): boolean }>;
}
const agentObserveIo: AgentObserveIo = { read: (file, limit) => readRegular(file, limit, false, true), stat: lstat };
async function attestFixtureAgent(record: AgentRecord, socket: string, baseline: AgentIdentity, io: AgentObserveIo = agentObserveIo, checkpoint = () => {}): Promise<void> {
  const read = async (file: string, limit: number) => { checkpoint(); const result = await io.read(file, limit); checkpoint(); return result; };
  const statFile = async (file: string) => { checkpoint(); const result = await io.stat(file); checkpoint(); return result; };
  const before = parseAgentProcess(await read(`/proc/${record.process.pid}/stat`, 4096));
  fixtureDemand(before.pid === record.process.pid && before.start === record.process.start && before.ppid === process.pid && !["Z", "X", "x"].includes(before.state));
  const identity = parseAgentStatus(await read(`/proc/${before.pid}/status`, 65536));
  fixtureDemand(sameAgentIdentity(identity, { ...baseline, nnp: 1 }));
  const cmdline = await read(`/proc/${before.pid}/cmdline`, 4096); fixtureDemand(cmdline.equals(Buffer.from([fixedAgentPath, "-D", "-a", socket, ""].join("\0"))));
  const directory = await statFile(path.dirname(socket)), stat = await statFile(socket); const uid = Number(baseline.uids[0]);
  fixtureDemand(directory.isDirectory() && !directory.isSymbolicLink() && directory.uid === uid && (directory.mode & 0o7777) === 0o700);
  fixtureDemand(stat.isSocket() && !stat.isSymbolicLink() && stat.uid === uid && (stat.mode & 0o7777) === 0o600);
  const after = parseAgentProcess(await read(`/proc/${before.pid}/stat`, 4096));
  fixtureDemand(after.pid === before.pid && after.start === before.start && after.ppid === before.ppid && !["Z", "X", "x"].includes(after.state));
}
function fixtureAgentStop(child: ChildProcess, identity: () => Promise<AgentProcess | undefined>, expected: () => string | undefined): () => Promise<void> {
  let cleanup: Promise<void> | undefined; let closed = false; child.once("close", () => { closed = true; });
  const stopped = () => child.pid === undefined || child.exitCode !== null || child.signalCode !== null;
  const wait = () => new Promise<boolean>((resolve) => {
    if (closed) { resolve(true); return; }
    const finish = (value: boolean) => { clearTimeout(timer); child.removeListener("close", didClose); resolve(value); };
    const didClose = () => finish(true); const timer = setTimeout(() => finish(false), 1000); child.once("close", didClose);
  });
  return () => cleanup ??= (async () => {
    let observationFailure: unknown; let anchor = expected();
    const complete = () => { if (observationFailure) throw new Error("Owned SSH fixture cleanup observation failed."); };
    for (const signal of ["SIGTERM", "SIGKILL"] as const) {
      if (stopped()) { fixtureDemand(await wait()); complete(); return; }
      let current: AgentProcess | undefined; let failedObservation = false; let timer: ReturnType<typeof setTimeout> | undefined;
      try { current = await Promise.race([identity(), new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error("SSH fixture cleanup observation deadline expired.")), 500); })]); }
      catch (error) { observationFailure = error; failedObservation = true; }
      finally { if (timer) clearTimeout(timer); }
      // Node20 libuv can reap a batch before publishing every exit callback.
      // Drain that batch before trusting the owned live ChildProcess handle.
      await new Promise<void>((resolve) => setImmediate(resolve));
      if (stopped()) { fixtureDemand(await wait()); complete(); return; }
      anchor ??= expected() ?? current?.start;
      if (current && (current.pid !== child.pid || anchor !== current.start) || !current && !failedObservation) {
        if (await wait()) { complete(); return; }
        throw new Error("Owned SSH fixture identity could not be confirmed for cleanup.");
      }
      child.kill(signal); if (await wait()) { complete(); return; }
    }
    throw new Error("The owned synthetic SSH agent did not terminate.");
  })();
}
interface AgentOwner { stop(): Promise<void>; assert(checkpoint?: () => void): Promise<void>; expired: boolean; closed: boolean; failure?: unknown; watchdog?: ReturnType<typeof setTimeout> }
const agentOwners = new WeakMap<ChildProcess, AgentOwner>();
function readAgentRecordPipe(stream: Readable, signal: AbortSignal): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    let finished = false; let size = 0; const chunks: Buffer[] = [];
    const finish = (error?: Error) => { if (finished) return; finished = true; stream.removeListener("data", data); stream.removeListener("end", end); stream.removeListener("error", failed); signal.removeEventListener("abort", abort); if (error) { stream.destroy(); reject(error); } else resolve(Buffer.concat(chunks)); };
    const data = (chunk: Buffer) => { size += chunk.length; if (size > 16384) finish(new Error("SSH fixture evidence exceeded its bound.")); else chunks.push(chunk); };
    const end = () => finish(); const failed = () => finish(new Error("SSH fixture evidence pipe failed.")); const abort = () => finish(new Error("SSH fixture startup deadline expired."));
    stream.on("data", data); stream.once("end", end); stream.once("error", failed); signal.addEventListener("abort", abort, { once: true }); if (signal.aborted) abort();
  });
}
function checkParentAgentIdentity(baseline: AgentIdentity, uid: number, gid: number, egid: number): void {
  validateAgentIdentity(baseline); fixtureDemand(uid > 0 && baseline.uids.every((id) => id === String(uid)) && baseline.gids.every((id) => id === String(gid)) && egid === gid);
}
async function observeFixtureStartup(work: (signal: AbortSignal) => Promise<void>, stop: () => Promise<void>, failure: (error: unknown) => void): Promise<void> {
  const abort = new AbortController(); let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    await Promise.race([Promise.resolve().then(() => work(abort.signal)), new Promise<never>((_, reject) => {
      timer = setTimeout(() => { abort.abort(); void stop().catch(failure); reject(new Error("SSH fixture startup deadline expired.")); }, 5000);
    })]);
  } catch (error) { abort.abort(); await stop(); throw error; } finally { if (timer) clearTimeout(timer); }
}
async function startFixtureAgent(home: string, directory: string, socket: string, fingerprints: AgentFingerprint[]): Promise<AgentOwner> {
  fixtureDemand(required && linux); const baseline = parseAgentStatus(await readRegular(`/proc/${process.pid}/status`, 65536, false, true));
  checkParentAgentIdentity(baseline, process.getuid!(), process.getgid!(), process.getegid!());
  await lstat(socket).then(() => { throw new Error("The fixture socket must be absent before launch."); }, (error: NodeJS.ErrnoException) => { fixtureDemand(error.code === "ENOENT"); });
  const python = await trustedExecutable("/usr/bin/python3"), launcher = path.join(directory, "fixture-agent.py"), env = neutralEnvironment(home, directory);
  const config = { fingerprints, identity: baseline, socket, env }; await writeFile(launcher, fixtureAgentProgram(config), { mode: 0o600, flag: "wx" });
  // Preserve the original direct-agent inherited cwd and resource envelope.
  const child = spawn(python, ["-I", "-S", launcher], { env, stdio: ["ignore", "ignore", "ignore", "pipe"] }); agents.push(child);
  let record: AgentRecord | undefined; const stop = fixtureAgentStop(child, async () => {
    if (!child.pid) return undefined;
    try { return parseAgentProcess(await readRegular(`/proc/${child.pid}/stat`, 4096, false, true)); } catch (error) { if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined; throw error; }
  }, () => record?.process.start);
  const owner: AgentOwner = { expired: false, closed: false, stop: async () => { if (owner.watchdog) clearTimeout(owner.watchdog); await stop(); }, assert: async (checkpoint = () => {}) => {
    checkpoint(); fixtureDemand(!owner.expired && !owner.failure && record); await attestFixtureAgent(record, socket, baseline, agentObserveIo, checkpoint);
    const parent = parseAgentStatus(await readRegular(`/proc/${process.pid}/status`, 65536, false, true)); checkpoint(); fixtureDemand(sameAgentIdentity(parent, baseline));
  } }; agentOwners.set(child, owner);
  child.once("close", () => { owner.closed = true; });
  child.once("error", () => { owner.failure = new Error("SSH fixture launcher failed."); });
  owner.watchdog = setTimeout(() => { owner.expired = true; void owner.stop().catch((error) => { owner.failure = error; }); }, agentTestDeadline);
  await observeFixtureStartup(async (signal) => {
    const pipe = child.stdio[3]; fixtureDemand(pipe instanceof Readable && child.pid !== undefined);
    record = checkAgentRecord(await readAgentRecordPipe(pipe, signal), child.pid, baseline, fingerprints);
    const startupCheck = () => fixtureDemand(!signal.aborted && !owner.failure && child.exitCode === null && child.signalCode === null);
    const startupRead = async (file: string, limit: number) => { startupCheck(); const value = await readRegular(file, limit, false, true); startupCheck(); return value; };
    const wanted = Buffer.from([fixedAgentPath, "-D", "-a", socket, ""].join("\0")); const waiting = Buffer.from([python, "-I", "-S", launcher, ""].join("\0"));
    for (;;) {
      startupCheck();
      const current = parseAgentProcess(await startupRead(`/proc/${child.pid}/stat`, 4096)); fixtureDemand(current.start === record.process.start && !["Z", "X", "x"].includes(current.state));
      const args = await startupRead(`/proc/${child.pid}/cmdline`, 4096); fixtureDemand(!args.length || args.equals(wanted) || args.equals(waiting));
      startupCheck(); const ready = await lstat(socket).then(() => true, (error: NodeJS.ErrnoException) => { fixtureDemand(error.code === "ENOENT"); return false; });
      startupCheck(); if (args.equals(wanted) && ready) { await owner.assert(startupCheck); break; }
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
  }, owner.stop, (error) => { owner.failure = error; });
  return owner;
}

function fixtureAgentProgram(config: { fingerprints: AgentFingerprint[]; identity: AgentIdentity; socket: string; env: NodeJS.ProcessEnv }): string {
  return String.raw`import os

try:
    import ctypes
    import json
    import re
    import stat
    CONFIG = json.loads(${JSON.stringify(JSON.stringify(config))})
except BaseException:
    os._exit(1)


PATHS = ("/usr/bin/ssh-agent", "/usr/bin", "/usr", "/")
FINGERPRINT_KEYS = {"path", "dev", "ino", "mode", "uid", "gid", "size", "mtimeNs", "ctimeNs"}
IDENTITY_KEYS = {"uids", "gids", "groups", "caps", "nnp"}
STATUS_KEYS = (b"Uid", b"Gid", b"Groups", b"CapInh", b"CapPrm", b"CapEff", b"CapAmb", b"NoNewPrivs")


def require(condition):
    if not condition:
        raise ValueError()


def decimal(value, signed=False):
    require(type(value) is str and 1 <= len(value) <= 40)
    require(re.fullmatch(r"-?(?:0|[1-9][0-9]*)" if signed else r"(?:0|[1-9][0-9]*)", value) is not None)
    number = int(value)
    require(str(number) == value)
    return number


def validate_configuration():
    require(type(CONFIG) is dict and set(CONFIG) == {"fingerprints", "identity", "socket", "env"})
    fingerprints = CONFIG["fingerprints"]
    require(type(fingerprints) is list and len(fingerprints) == len(PATHS))
    for expected_path, fingerprint in zip(PATHS, fingerprints):
        require(type(fingerprint) is dict and set(fingerprint) == FINGERPRINT_KEYS)
        require(fingerprint["path"] == expected_path)
        for key in FINGERPRINT_KEYS - {"path"}:
            decimal(fingerprint[key], signed=key in ("mtimeNs", "ctimeNs"))
    identity = CONFIG["identity"]
    require(type(identity) is dict and set(identity) == IDENTITY_KEYS)
    for key in ("uids", "gids"):
        values = identity[key]
        require(type(values) is list and len(values) == 4)
        require(all(0 <= decimal(value) < 2 ** 32 for value in values))
        require(len(set(values)) == 1)
    require(decimal(identity["uids"][0]) > 0)
    require(type(identity["groups"]) is list)
    require(all(0 <= decimal(value) < 2 ** 32 for value in identity["groups"]))
    require(type(identity["caps"]) is list and identity["caps"] == ["0", "0", "0", "0"])
    require(type(identity["nnp"]) is int and identity["nnp"] in (0, 1))
    require(type(CONFIG["socket"]) is str and os.path.isabs(CONFIG["socket"]) and "\0" not in CONFIG["socket"])
    require(type(CONFIG["env"]) is dict)
    for key, value in CONFIG["env"].items():
        require(type(key) is str and key and "=" not in key and "\0" not in key)
        require(type(value) is str and "\0" not in value)


def read_proc(file, limit):
    require((file, limit) in (("/proc/self/status", 65536), ("/proc/self/stat", 4096)))
    descriptor = os.open(file, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        require(stat.S_ISREG(os.fstat(descriptor).st_mode))
        result = bytearray()
        while True:
            part = os.read(descriptor, min(4096, limit + 1 - len(result)))
            if not part:
                return bytes(result)
            result.extend(part)
            require(len(result) <= limit)
    finally:
        os.close(descriptor)


def identity():
    fields = {}
    for line in read_proc("/proc/self/status", 65536).split(b"\n"):
        name, separator, value = line.partition(b":")
        if name in STATUS_KEYS:
            require(separator and name not in fields)
            fields[name] = value.strip(b" \t")
    require(set(fields) == set(STATUS_KEYS))
    result = {}
    for name, key in ((b"Uid", "uids"), (b"Gid", "gids")):
        require(re.fullmatch(rb"[0-9]+(?:[ \t]+[0-9]+){3}", fields[name]) is not None)
        result[key] = [value.decode("ascii", "strict") for value in fields[name].split()]
        for value in result[key]:
            require(0 <= decimal(value) < 2 ** 32)
    groups = fields[b"Groups"]
    require(not groups or re.fullmatch(rb"[0-9]+(?:[ \t]+[0-9]+)*", groups) is not None)
    result["groups"] = [value.decode("ascii", "strict") for value in groups.split()]
    for value in result["groups"]:
        require(0 <= decimal(value) < 2 ** 32)
    result["caps"] = []
    for name in STATUS_KEYS[3:7]:
        require(re.fullmatch(rb"0+", fields[name]) is not None)
        result["caps"].append("0")
    require(fields[b"NoNewPrivs"] in (b"0", b"1"))
    result["nnp"] = int(fields[b"NoNewPrivs"])
    return result


def fingerprints():
    require(os.path.realpath("/usr/bin/ssh-agent") == "/usr/bin/ssh-agent")
    result = []
    for index, file in enumerate(PATHS):
        observed = os.lstat(file)
        require(observed.st_uid == 0)
        if index == 0:
            require(stat.S_ISREG(observed.st_mode) and stat.S_IMODE(observed.st_mode) in (0o755, 0o2755))
        else:
            require(stat.S_ISDIR(observed.st_mode) and not observed.st_mode & 0o6022)
        result.append({"path": file, "dev": str(observed.st_dev), "ino": str(observed.st_ino),
                       "mode": str(observed.st_mode), "uid": str(observed.st_uid), "gid": str(observed.st_gid),
                       "size": str(observed.st_size), "mtimeNs": str(observed.st_mtime_ns), "ctimeNs": str(observed.st_ctime_ns)})
    require(result == CONFIG["fingerprints"])
    return result


def process_identity():
    data = read_proc("/proc/self/stat", 4096)
    pid, separator, body = data.partition(b" ")
    require(separator and body.startswith(b"("))
    end = body.rfind(b") ")
    require(end >= 1)
    fields = body[end + 2:].split()
    require(len(fields) >= 20)
    pid_text = pid.decode("ascii", "strict")
    parent_text = fields[1].decode("ascii", "strict")
    start = fields[19].decode("ascii", "strict")
    actual_pid = decimal(pid_text)
    parent_pid = decimal(parent_text)
    decimal(start)
    require(0 < actual_pid < 2 ** 31 and 0 < parent_pid < 2 ** 31)
    require(actual_pid == os.getpid() and parent_pid == os.getppid())
    return {"pid": actual_pid, "ppid": parent_pid, "start": start}


def main():
    validate_configuration()
    require(identity() == CONFIG["identity"])
    observed_fingerprints = fingerprints()
    libc = ctypes.CDLL(None, use_errno=True)
    prctl = libc.prctl
    prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
    prctl.restype = ctypes.c_int
    require(prctl(38, 1, 0, 0, 0) == 0)
    require(prctl(39, 0, 0, 0, 0) == 1)
    observed_identity = identity()
    require(observed_identity == {**CONFIG["identity"], "nnp": 1})
    record = {"schema": 1, "process": process_identity(), "identity": observed_identity, "fingerprints": observed_fingerprints}
    payload = json.dumps(record, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii", "strict") + b"\n"
    require(len(payload) <= 16384)
    written = 0
    while written < len(payload):
        size = os.write(3, payload[written:])
        require(size > 0)
        written += size
    os.close(3)
    fingerprints()
    os.execve("/usr/bin/ssh-agent", ["/usr/bin/ssh-agent", "-D", "-a", CONFIG["socket"]], CONFIG["env"])


try:
    main()
except BaseException:
    os._exit(1)
`;
}

function git(root: string, env: NodeJS.ProcessEnv, args: string[], input?: string | Uint8Array): Buffer {
  return execFileSync("/usr/bin/git", ["-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-c", "commit.gpgsign=false", ...args], { cwd: root, env, ...(input !== undefined ? { input } : {}), maxBuffer: 4 * 1024 ** 2 });
}
async function rawRepository(root: string, env: NodeJS.ProcessEnv, files: readonly IsolatedSourceFile[], empty: string): Promise<{ commit: string; bytes: Buffer }> {
  await mkdir(root); git(root, env, ["init", "--quiet", "--object-format=sha1", "--initial-branch=main", `--template=${empty}`]); const index: Buffer[] = [];
  for (const entry of files) {
    await mkdir(path.dirname(path.join(root, entry.path)), { recursive: true }); await writeFile(path.join(root, entry.path), entry.bytes, { mode: entry.mode === "100755" ? 0o755 : 0o644 });
    const oid = git(root, env, ["hash-object", "--no-filters", "-w", "--stdin"], entry.bytes).toString().trim(); index.push(Buffer.from(`${entry.mode} ${oid}\t${entry.path}\0`));
  }
  git(root, env, ["update-index", "-z", "--index-info"], Buffer.concat(index)); const tree = git(root, env, ["write-tree"]).toString().trim(); const commit = git(root, env, ["commit-tree", tree], "Synthetic complete public history\n").toString().trim();
  git(root, env, ["update-ref", "refs/heads/main", commit]); return { commit, bytes: git(root, env, ["cat-file", "commit", commit]) };
}
async function fingerprint(root: string): Promise<string> {
  const rows: unknown[] = []; const walk = async (prefix: string): Promise<void> => {
    for (const name of (await readdir(path.join(root, prefix))).sort()) { const relative = prefix ? prefix + "/" + name : name; const location = path.join(root, relative); const stat = await lstat(location);
      expect(stat.isSymbolicLink()).toBe(false); rows.push([relative, stat.mode, stat.isDirectory() ? "directory" : sha256(await readFile(location))]); if (stat.isDirectory()) await walk(relative); }
  }; await walk(""); return sha256(Buffer.from(JSON.stringify(rows)));
}
async function stopAgent(agent: ChildProcess): Promise<void> {
  const owner = agentOwners.get(agent); fixtureDemand(owner); await owner.stop();
  if (owner.expired || owner.failure) throw new Error("Synthetic SSH fixture watchdog or launch failed.");
}
afterEach(async () => {
  let cleanupError: unknown; let agentCleanupFailed = false;
  for (const publication of publications.splice(0)) try { await disposePublicRepository(publication); } catch (error) { cleanupError = error; }
  for (const agent of agents.splice(0)) try { await stopAgent(agent); } catch (error) { agentCleanupFailed ||= !agentOwners.get(agent)?.closed; cleanupError = error; }
  const ownedRoots = roots.splice(0);
  if (!agentCleanupFailed) await Promise.all(ownedRoots.map((root) => rm(root, { recursive: true, force: true }))); // Preserve private recovery roots if agent stop is uncertain.
  vi.unstubAllEnvs();
  fixtureState.launches = []; fixtureState.requests = []; fixtureState.fetches = 0; fixtureState.home = ""; fixtureState.remote = ""; if (cleanupError) throw cleanupError;
});

it("bounds public-tool diagnostics without changing eligibility failures", async () => {
  const lines: string[] = []; const metadata = publicToolDiagnostic({
    realpath: async (file) => {
      if (file === "/usr/bin/node") throw { code: "ENOENT", message: "fabricated-private-detail" };
      if (file === "/usr/bin/ssh-add") return "/home/fabricated/.config/private";
      return file;
    },
    lstat: async (file) => {
      expect(file.startsWith("/home/")).toBe(false);
      const regular = publicToolPaths.includes(file as typeof publicToolPaths[number]);
      return { uid: 0, gid: 0, mode: regular ? (file.endsWith("ssh-agent") ? 0o102755 : 0o100755) : 0o40755,
        isFile: () => regular, isDirectory: () => !regular, isSymbolicLink: () => false };
    }
  }, (line) => lines.push(line));
  await metadata(); await metadata();
  expect(lines).toHaveLength(1); expect(lines[0]!.split("\n")).toHaveLength(1); expect(Buffer.byteLength(lines[0]! + "\n")).toBeLessThanOrEqual(16_384);
  expect(lines[0]).not.toMatch(/fabricated-private-detail|\/home\/fabricated/);
  const record = JSON.parse(lines[0]!.slice(publicToolMetadataPrefix.length));
  expect(record.tools.find((tool: { path: string }) => tool.path.endsWith("/node")).error).toBe("ENOENT");
  expect(record.tools.find((tool: { path: string }) => tool.path.endsWith("/ssh-add")).error).toBe("NON_PUBLIC_RESOLUTION");
  expect(record.tools[0].ancestors[0]).toMatchObject({ uid: 0, gid: 0, mode: "2755", type: "file" });
  await expect((async () => { await metadata(); throw new Error("original eligibility failure"); })()).rejects.toThrow("original eligibility failure");
});

describe("fixture-only SSH-agent eligibility and refusal proofs (no launcher)", () => {
  const baseIdentity: AgentIdentity = { uids: Array(4).fill("1001"), gids: Array(4).fill("1001"), groups: ["4", "1001"], caps: Array(4).fill("0"), nnp: 0 };
  const socket = "/tmp/owned-agent-fixture/agent.sock", pid = 4321, start = "9007199254740993";
  const status = (identity: AgentIdentity) => Buffer.from(`Uid:\t${identity.uids.join("\t")}\nGid:\t${identity.gids.join("\t")}\nGroups:\t${identity.groups.join(" ")}\n${["CapInh", "CapPrm", "CapEff", "CapAmb"].map((name, index) => name + ":\t" + identity.caps[index]).join("\n")}\nNoNewPrivs:\t${identity.nnp}\n`);
  const proc = (ticks = start, state = "S") => Buffer.from(`${pid} (fake agent ) name) ${[state, String(process.pid), ...Array(17).fill("0"), ticks].join(" ")}\n`);
  function metadata(change?: (file: string, stat: AgentFileStat) => void): AgentMetadataIo {
    return { realpath: async () => fixedAgentPath, stat: async (file) => {
      const first = file === fixedAgentPath; const value: AgentFileStat = { dev: 1n, ino: 9007199254740993n, mode: first ? 0o102755n : 0o40755n, uid: 0n, gid: first ? 104n : 0n, size: first ? 123n : 4096n, mtimeNs: 1700000000000000001n, ctimeNs: 1700000000000000002n, isFile: () => first, isDirectory: () => !first, isSymbolicLink: () => false }; change?.(file, value); return value;
    } };
  }
  const strictReject = async () => { throw new Error("Governed upgrade host operation is unsupported."); };
  it("permits only the fixed inspected 0755/2755 agent and retains strict production SGID refusal", async () => {
    const strict = vi.fn(strictReject); const rows = await inspectFixtureAgent(metadata(), strict); expect(strict).toHaveBeenCalledWith(fixedAgentPath);
    expect(rows.map((row) => row.path)).toEqual(agentMetadataPaths); expect(rows[0]!.ino).toBe("9007199254740993"); expect(rows[0]!.mtimeNs).toBe("1700000000000000001");
    await expect(inspectFixtureAgent(metadata((file, stat) => { if (file === fixedAgentPath) stat.mode = 0o100755n; }), async () => fixedAgentPath)).resolves.toHaveLength(4);
    await expect(inspectFixtureAgent(metadata(), async () => fixedAgentPath)).rejects.toThrow("prerequisite");
    await expect(inspectFixtureAgent(metadata(), async () => { throw new Error("different failure"); })).rejects.toThrow("prerequisite");
  });
  it.each(["canonical", "owner", "writable", "setuid", "mode", "symlink", "file type", "ancestor write", "ancestor setgid", "number fingerprint"])("rejects unsafe %s metadata before launch", async (kind) => {
    const io = metadata((file, stat) => {
      if (file === fixedAgentPath) {
        if (kind === "owner") stat.uid = 1001n; if (kind === "writable") stat.mode = 0o102777n; if (kind === "setuid") stat.mode = 0o106755n;
        if (kind === "mode") stat.mode = 0o101755n; if (kind === "symlink") stat.isSymbolicLink = () => true; if (kind === "file type") stat.isFile = () => false;
        if (kind === "number fingerprint") (stat as unknown as { ino: number }).ino = 9007199254740992;
      } else { if (kind === "ancestor write") stat.mode = 0o40777n; if (kind === "ancestor setgid") stat.mode = 0o42755n; }
    }); if (kind === "canonical") io.realpath = async () => "/other/ssh-agent";
    await expect(inspectFixtureAgent(io, strictReject)).rejects.toThrow("prerequisite");
  });
  it("refuses split or privileged parent identities and malformed status evidence", () => {
    expect(() => checkParentAgentIdentity(baseIdentity, 1001, 1001, 1001)).not.toThrow();
    for (const change of [{ uids: ["0", "0", "0", "0"] }, { uids: ["1001", "1001", "0", "1001"] }, { gids: ["1001", "104", "1001", "1001"] }, { caps: ["1", "0", "0", "0"] }]) expect(() => checkParentAgentIdentity({ ...baseIdentity, ...change }, 1001, 1001, 1001)).toThrow("prerequisite");
    expect(() => checkParentAgentIdentity(baseIdentity, 1001, 1001, 104)).toThrow("prerequisite");
    expect(() => parseAgentStatus(Buffer.concat([status(baseIdentity), Buffer.from("Uid:\t1001 1001 1001 1001\n")]))).toThrow("prerequisite");
    expect(() => parseAgentStatus(Buffer.alloc(65537))).toThrow("prerequisite"); expect(() => parseAgentProcess(Buffer.alloc(4097))).toThrow("prerequisite");
  });
  async function packet() { const fingerprints = await inspectFixtureAgent(metadata(), strictReject); return { schema: 1, process: { pid, ppid: process.pid, start }, identity: { ...baseIdentity, nnp: 1 }, fingerprints }; }
  it("refuses failed NNP, forged process/fingerprint and malformed/extra startup packets", async () => {
    const row = await packet(), bytes = (value: unknown) => Buffer.from(JSON.stringify(value) + "\n");
    expect(checkAgentRecord(bytes(row), pid, baseIdentity, row.fingerprints).process.start).toBe(start);
    for (const value of [{ ...row, extra: true }, { ...row, identity: { ...row.identity, nnp: 0 } }, { ...row, process: { ...row.process, pid: pid + 1 } }, { ...row, process: { ...row.process, start: Number(start) } }, { ...row, fingerprints: row.fingerprints.map((entry, index) => index ? entry : { ...entry, ino: "9007199254740992" }) }]) expect(() => checkAgentRecord(bytes(value), pid, baseIdentity, row.fingerprints)).toThrow();
    for (const value of [Buffer.from("not JSON\n"), Buffer.concat([bytes(row), bytes(row)]), Buffer.alloc(16385)]) expect(() => checkAgentRecord(value, pid, baseIdentity, row.fingerprints)).toThrow();
  });
  it.each(["uids", "gids", "groups", "caps", "nnp", "pid reuse", "dead", "argv", "socket owner", "socket mode", "directory", "missing", "oversized"])("refuses post-exec %s without importing any key", async (kind) => {
    const row = await packet(); let statReads = 0;
    const io: AgentObserveIo = { read: async (file, limit) => {
      expect(limit).toBe(file.endsWith("/status") ? 65536 : 4096);
      if (file.endsWith("/stat")) return proc(kind === "pid reuse" && ++statReads > 1 ? "9007199254740994" : start, kind === "dead" ? "Z" : "S");
      if (file.endsWith("/cmdline")) return Buffer.from([kind === "argv" ? "/other/agent" : fixedAgentPath, "-D", "-a", socket, ""].join("\0"));
      if (kind === "oversized") return Buffer.alloc(65537);
      const value = { ...row.identity };
      if (["uids", "gids", "groups"].includes(kind)) value[kind as "uids" | "gids" | "groups"] = ["0", ...value[kind as "uids" | "gids" | "groups"].slice(1)];
      if (kind === "caps") value.caps = ["1", "0", "0", "0"]; if (kind === "nnp") value.nnp = 0;
      return status(value);
    }, stat: async (file) => { if (kind === "missing") throw { code: "ENOENT" }; const directory = file === path.dirname(socket); return { uid: kind === "socket owner" ? 0 : 1001, mode: directory ? (kind === "directory" ? 0o40777 : 0o40700) : (kind === "socket mode" ? 0o140666 : 0o140600), isDirectory: () => directory, isSocket: () => !directory, isSymbolicLink: () => false }; } };
    await expect(attestFixtureAgent(row, socket, baseIdentity, io)).rejects.toThrow();
  });
  it("accepts compound process attestation and private-socket readiness, not peer PID attestation", async () => {
    const row = await packet(); const io: AgentObserveIo = { read: async (file) => file.endsWith("/stat") ? proc() : file.endsWith("/status") ? status(row.identity) : Buffer.from([fixedAgentPath, "-D", "-a", socket, ""].join("\0")), stat: async (file) => ({ uid: 1001, mode: file === socket ? 0o140600 : 0o40700, isSocket: () => file === socket, isDirectory: () => file !== socket, isSymbolicLink: () => false }) };
    await expect(attestFixtureAgent(row, socket, baseIdentity, io)).resolves.toBeUndefined();
    let reads = 0; await expect(attestFixtureAgent(row, socket, baseIdentity, { ...io, read: async (...args) => { reads++; return io.read(...args); } }, () => { throw new Error("expired"); })).rejects.toThrow("expired"); expect(reads).toBe(0);
  });
  it("admits one bounded startup packet and refuses pipe overflow/abort", async () => {
    const row = Buffer.from(JSON.stringify(await packet()) + "\n"), signal = new AbortController(); expect(await readAgentRecordPipe(Readable.from([row]), signal.signal)).toEqual(row);
    await expect(readAgentRecordPipe(Readable.from([Buffer.alloc(16385)]), signal.signal)).rejects.toThrow("bound");
    const aborted = new AbortController(); aborted.abort(); await expect(readAgentRecordPipe(new Readable({ read() {} }), aborted.signal)).rejects.toThrow("deadline");
  });
  const turn = () => new Promise<void>((resolve) => setImmediate(resolve));
  function childFixture(exitOn?: string) {
    const signals: string[] = []; const child = Object.assign(new EventEmitter(), { pid, exitCode: null as number | null, signalCode: null as string | null, kill: (signal: string) => { signals.push(signal); if (signal === exitOn) { child.exitCode = 0; child.emit("close"); } return true; } });
    return { child: child as unknown as ChildProcess, signals, exit: () => { child.exitCode = 0; child.emit("close"); } };
  }
  it("shares bounded TERM/KILL cleanup and never signals a reaped callback-pending child", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    try {
      const data = childFixture("SIGKILL"), stop = fixtureAgentStop(data.child, async () => ({ pid, ppid: process.pid, start, state: "S" }), () => start);
      const first = stop(); expect(stop()).toBe(first); await turn(); await turn(); expect(data.signals).toEqual(["SIGTERM"]);
      await vi.advanceTimersByTimeAsync(1000); await turn(); await turn(); await first; expect(data.signals).toEqual(["SIGTERM", "SIGKILL"]);
      const late = childFixture(); const noKill = fixtureAgentStop(late.child, async () => { setImmediate(late.exit); return { pid, ppid: process.pid, start, state: "S" }; }, () => start); await noKill(); expect(late.signals).toEqual([]);
    } finally { vi.useRealTimers(); }
  });
  it("cleans observation failure before reporting it, and never kills a mismatched PID identity", async () => {
    const broken = childFixture("SIGTERM"), stop = fixtureAgentStop(broken.child, async () => { throw { code: "EACCES" }; }, () => undefined);
    await expect(stop()).rejects.toThrow("observation failed"); expect(broken.signals).toEqual(["SIGTERM"]);
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    try {
      const changed = childFixture(), refusal = fixtureAgentStop(changed.child, async () => ({ pid, ppid: process.pid, start: "9007199254740994", state: "S" }), () => start); const rejected = expect(refusal()).rejects.toThrow("identity");
      await turn(); await turn(); await vi.advanceTimersByTimeAsync(1000); await rejected; expect(changed.signals).toEqual([]);
    } finally { vi.useRealTimers(); }
  });
  it.each(["known", "unknown"])("never signals after ENOENT with %s start, and surfaces unresponsive teardown", async (kind) => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    try {
      const missing = childFixture(), stop = fixtureAgentStop(missing.child, async () => undefined, () => kind === "known" ? start : undefined);
      const rejected = expect(stop()).rejects.toThrow("identity"); await turn(); await turn(); await vi.advanceTimersByTimeAsync(1000); await rejected; expect(missing.signals).toEqual([]);
      const live = childFixture(), unresponsive = fixtureAgentStop(live.child, async () => ({ pid, ppid: process.pid, start, state: "S" }), () => start);
      const failed = expect(unresponsive()).rejects.toThrow("did not terminate"); await turn(); await turn(); await vi.advanceTimersByTimeAsync(1000); await turn(); await turn(); await vi.advanceTimersByTimeAsync(1000); await failed;
      expect(live.signals).toEqual(["SIGTERM", "SIGKILL"]);
    } finally { vi.useRealTimers(); }
  });
  it("does not let an earlier observation error authorize signaling a subsequently absent PID", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    try {
      let attempts = 0; const data = childFixture(), stop = fixtureAgentStop(data.child, async () => { if (++attempts === 1) throw { code: "EACCES" }; return undefined; }, () => start);
      const rejected = expect(stop()).rejects.toThrow("identity"); await turn(); await turn(); expect(data.signals).toEqual(["SIGTERM"]);
      await vi.advanceTimersByTimeAsync(1000); await turn(); await turn(); await vi.advanceTimersByTimeAsync(1000); await rejected; expect(data.signals).toEqual(["SIGTERM"]);
    } finally { vi.useRealTimers(); }
  });
  it("bounds blocked observations and the complete startup, preserving late-work cancellation", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    try {
      const child = childFixture("SIGTERM"), stop = fixtureAgentStop(child.child, async () => new Promise<AgentProcess>(() => {}), () => undefined);
      const failed = expect(stop()).rejects.toThrow("observation failed"); await vi.advanceTimersByTimeAsync(500); await turn(); await turn(); await failed; expect(child.signals).toEqual(["SIGTERM"]);
      let release: (() => void) | undefined, continued = 0; const gate = new Promise<void>((resolve) => { release = resolve; });
      let cleanup: Promise<void> | undefined, cleaned = 0; const sharedStop = () => cleanup ??= Promise.resolve().then(() => { cleaned++; });
      const pending = observeFixtureStartup(async (signal) => { await gate; fixtureDemand(!signal.aborted); continued++; }, sharedStop, () => {});
      const expired = expect(pending).rejects.toThrow("startup deadline"); await vi.advanceTimersByTimeAsync(5000); await expired; expect(cleaned).toBe(1); release!(); await Promise.resolve(); expect(continued).toBe(0);
    } finally { vi.useRealTimers(); }
  });

});

it.skipIf(!required)("requires actual unprivileged Linux x64 host-broker enforcement when mandatory", async () => {
  if (linux) await reportPublicTools();
  expect(process.platform, "The mandatory broker/backend proof cannot be satisfied by Darwin semantic tests.").toBe("linux");
  expect(process.arch).toBe("x64"); const tools = await requireLinuxHost(); expect(tools.prlimit).toBeTruthy(); await trustedExecutable("/usr/bin/ssh-keygen"); await inspectFixtureAgent(); await trustedExecutable("/usr/bin/python3");
});

describe.skipIf(!required || !linux)("actual Linux brokers plus actual Docker backend (explicit opt-in)", () => {
  it("binds raw public acquisition, isolated hook, selected-key signing and isolated final candidate without touching the original", async () => {
    const tools = await requireLinuxHost(); fixtureState.prlimit = tools.prlimit; fixtureState.git = tools.git;
    const directory = await mkdtemp(path.join(await realpath(process.cwd()), ".broker-integration-")); roots.push(directory);
    const home = path.join(directory, "home"), empty = path.join(directory, "empty"); await mkdir(home); await mkdir(empty); fixtureState.home = home;
    for (const name of Object.keys(process.env)) if (name.startsWith("GIT_") || ["EMAIL", "XDG_CONFIG_HOME"].includes(name)) vi.stubEnv(name, undefined);
    vi.stubEnv("HOME", home); vi.stubEnv("GH_TOKEN", "inert-fabricated-integration-canary"); vi.stubEnv("GITHUB_TOKEN", "inert-fabricated-integration-canary"); vi.stubEnv("BOOTSTRAP_PRIVATE_CANARY", "inert-fabricated-integration-canary");
    const env = { ...neutralEnvironment(home, directory), GIT_AUTHOR_NAME: "Broker Fixture", GIT_AUTHOR_EMAIL: "broker@example.invalid", GIT_AUTHOR_DATE: "@1767225600 +0000", GIT_COMMITTER_NAME: "Broker Fixture", GIT_COMMITTER_EMAIL: "broker@example.invalid", GIT_COMMITTER_DATE: "@1767225600 +0000" };
    let docker: string | undefined; for (const candidate of ["/usr/bin/docker", "/usr/local/bin/docker"]) try { docker = await trustedExecutable(candidate); break; } catch { /* Supported fixed locations only. */ }
    expect(docker, "A trusted Docker CLI must already exist; this test never installs tools.").toBeTruthy(); await mkdir(path.join(home, "docker"));
    const dockerCommand = (args: string[]) => boundedCommand(docker!, ["--host", "unix:///var/run/docker.sock", "--config", path.join(home, "docker"), ...args], { cwd: directory, env: neutralEnvironment(home, directory) });
    expect((await dockerCommand(["version", "--format", "{{.Server.Os}}/{{.Server.Arch}}"])) .toString().trim()).toBe("linux/amd64");
    expect((await dockerCommand(["image", "inspect", "--format", "{{.Os}}/{{.Architecture}}", NODE_ISOLATION_IMAGE])).toString().trim()).toBe("linux/amd64");
    const key = path.join(home, "fixture-key"); const ssh = await trustedExecutable("/usr/bin/ssh-keygen"); const agentFiles = await inspectFixtureAgent(); const sshAdd = await trustedExecutable("/usr/bin/ssh-add");
    await boundedCommand(tools.prlimit, [...PRLIMIT_ARGS, ssh, "-q", "-t", "ed25519", "-N", "", "-f", key], { cwd: directory, env: neutralEnvironment(home, directory) });
    const agentDirectory = await mkdtemp(path.join(await realpath(os.tmpdir()), "broker-agent-")); roots.push(agentDirectory); const socket = path.join(agentDirectory, "agent.sock");
    const fixtureAgent = await startFixtureAgent(home, directory, socket, agentFiles);
    await boundedCommand(tools.prlimit, [...PRLIMIT_ARGS, sshAdd, key], { cwd: directory, env: { ...neutralEnvironment(home, directory), SSH_AUTH_SOCK: socket } }); await fixtureAgent.assert(); vi.stubEnv("SSH_AUTH_SOCK", socket);
    await writeFile(path.join(home, ".gitconfig"), "[user]\n name = Broker Fixture\n email = global@example.invalid\n[gpg]\n format = x509\n[gpg \"x509\"]\n program = irrelevant-fixture-program\n");
    const generator = path.join(directory, "generator"); const generatorBase = await rawRepository(generator, env, [file("README.md", "Synthetic pinned generator\n")], empty);
    for (const [name, value] of [["user.email", "broker@example.invalid"], ["gpg.format", "ssh"], ["user.signingkey", key + ".pub"]]) git(generator, env, ["config", "--local", name!, value!]);
    const captured = await captureGeneratorSigning(generator, generatorBase.commit); expect(captured.identity).toEqual({ name: "Broker Fixture", email: "broker@example.invalid" });
    const original = path.join(directory, "original"); fixtureState.original = original; const hostCanary = path.join(directory, "host-target-ran");
    const baseFiles = [file("README.md", "Original public source\n"), file(".gitignore", "ignored/\n"), file("package.json", JSON.stringify({ name: "broker-composition-fixture", version: "1.0.0", private: true })),
      file("package-lock.json", JSON.stringify({ name: "broker-composition-fixture", version: "1.0.0", lockfileVersion: 3, packages: { "": { name: "broker-composition-fixture", version: "1.0.0" } } })),
      file("scripts/ci/run-fast-checks.sh", "#!/bin/bash\nset -euo pipefail\nnode probe.cjs check\n", true), file(".githooks/pre-commit", "#!/bin/bash\nset -euo pipefail\nnode probe.cjs hook\n", true)];
    const originalBase = await rawRepository(original, env, baseFiles, empty); fixtureState.base = originalBase.commit;
    const cleanOriginal = path.join(directory, "clean-original"); const cleanBase = await rawRepository(cleanOriginal, env, baseFiles, empty);
    expect(cleanBase.commit).toBe(originalBase.commit); expect(cleanBase.bytes).toEqual(originalBase.bytes);
    git(cleanOriginal, env, ["config", "--local", "remote.origin.url", "https://github.com/example/broker-composition.git"]);
    await mkdir(path.join(cleanOriginal, "ignored")); await writeFile(path.join(cleanOriginal, "ignored/private-sentinel"), "Clean-checkout private preservation sentinel\n"); const cleanBefore = await fingerprint(cleanOriginal);
    const remote = path.join(directory, "remote.git"); const remoteEnv = { ...env, GIT_DIR: remote }; await mkdir(remote); git(directory, remoteEnv, ["init", "--quiet", "--bare", "--object-format=sha1", `--template=${empty}`]);
    const index: Buffer[] = []; for (const entry of baseFiles) { const oid = git(directory, remoteEnv, ["hash-object", "--no-filters", "-w", "--stdin"], entry.bytes).toString().trim(); index.push(Buffer.from(`${entry.mode} ${oid}\t${entry.path}\0`)); }
    git(directory, remoteEnv, ["update-index", "-z", "--index-info"], Buffer.concat(index)); git(directory, remoteEnv, ["write-tree"]); git(directory, remoteEnv, ["hash-object", "-t", "commit", "-w", "--stdin"], originalBase.bytes); git(directory, remoteEnv, ["update-ref", "refs/heads/main", originalBase.commit]); fixtureState.remote = remote;
    const trap = path.join(directory, "local-authority-canary"); await writeFile(trap, `#!/bin/sh\nprintf host-canary > '${hostCanary}'\nexit 1\n`, { mode: 0o755 });
    await mkdir(path.join(original, ".git/info"), { recursive: true }); await writeFile(path.join(original, ".git/info/attributes"), "* filter=canary diff=canary\n"); await mkdir(path.join(original, ".git/hooks")); await writeFile(path.join(original, ".git/hooks/pre-commit"), await readFile(trap), { mode: 0o755 });
    const originalConfig = await readFile(path.join(original, ".git/config"), "utf8"); await writeFile(path.join(original, ".git/config"), originalConfig + `\n[core]\n fsmonitor = ${trap}\n hooksPath = ${path.join(original, ".git/hooks")}\n[filter "canary"]\n clean = ${trap}\n smudge = ${trap}\n[diff "canary"]\n textconv = ${trap}\n[credential]\n helper = !${trap}\n[url "ext::${trap}"]\n insteadOf = https://fixture.invalid/\n`);
    await mkdir(path.join(original, "ignored")); await writeFile(path.join(original, "ignored/private-sentinel"), "Private synthetic preservation sentinel\n"); const before = await fingerprint(original);
    const repository = await acquirePublicBase("example/broker-composition", originalBase.commit); publications.push(repository);
    expect(fixtureState.fetches).toBe(1); expect(repository.snapshot.baseCommit).toBe(originalBase.commit); const reservedFiles = copyReservedSnapshotFiles(repository);
    expect(reservedFiles).toEqual([...baseFiles].sort((a, b) => Buffer.compare(Buffer.from(a.path), Buffer.from(b.path))));
    const audit = await auditPublicCheckout(repository, cleanOriginal); expect(audit).toMatchObject({ baseCommit: repository.baseCommit, tree: repository.snapshot.tree, sourceSha256: repository.snapshot.sourceSha256 }); expect(audit.originalStateSha256).toMatch(/^[a-f0-9]{64}$/);
    expect(await fingerprint(cleanOriginal)).toBe(cleanBefore);
    // The hostile copy has unsupported local hooks/attributes. It is an unexecuted
    // authority trap, never an eligible checkout or authorization to run an executor.
    const plan = freezeCommitPlan(captured.identity, repository.baseCommit, "codex/broker-composition", "test: actual broker and backend composition", ".githooks/pre-commit");
    const probe = `const a=require('node:assert/strict'),fs=require('node:fs'),cp=require('node:child_process');
if(process.cwd()!=='/repo/project')fs.writeFileSync(${JSON.stringify(hostCanary)},'target code executed on host');
a.equal(process.cwd(),'/repo/project');a.equal(process.getuid(),1000);
const p=JSON.parse(fs.readFileSync('supervisor-plan.json','utf8'));const git=(args)=>cp.execFileSync('git',args,{encoding:'utf8'}).trim();
for(const name of ['GH_TOKEN','GITHUB_TOKEN','SSH_AUTH_SOCK','BOOTSTRAP_PRIVATE_CANARY','BOOTSTRAP_REQUIRE_HOST_BROKER_TESTS'])a.equal(process.env[name],undefined);
for(const name of [${JSON.stringify(hostCanary)},'/var/run/docker.sock'])a.equal(fs.existsSync(name),false);
for(const name of ['README.md','.git/index'])a.throws(()=>fs.openSync(name,'r+'),e=>['EROFS','EACCES','EPERM'].includes(e.code));
a.equal(process.env.NPM_CONFIG_OFFLINE,'true');a.equal(git(['symbolic-ref','--short','HEAD']),p.branch);
if(process.argv[2]==='hook'){
 a.equal(process.env.GIT_INDEX_FILE,'.git/index');a.equal(process.env.GIT_PREFIX,'');a.equal(process.env.GIT_EDITOR,':');a.equal(process.env.GIT_EXEC_PATH,git(['--exec-path']));
 for(const kind of ['author','committer']){for(const field of ['name','email','date'])a.equal(process.env['GIT_'+kind.toUpperCase()+'_'+field.toUpperCase()],(field==='date'?'@':'')+p[kind][field]);a.equal(git(['var','GIT_'+kind.toUpperCase()+'_IDENT']),p[kind].name+' <'+p[kind].email+'> '+p[kind].date);}
 a.equal(git(['config','--local','--get','user.name']),p.committer.name);a.equal(git(['config','--local','--get','user.email']),p.committer.email);
 a.equal(fs.readFileSync('.git/COMMIT_EDITMSG','utf8'),p.commitMessage);a.equal(git(['rev-parse','HEAD']),p.baseCommit);a(git(['diff','--cached','--name-only','HEAD']).split('\\n').includes('README.md'));
 console.log('BROKER-INTEGRATION-HOOK-PASSED');
}else{a.equal(git(['diff','--cached','--name-only','HEAD']),'');console.log('BROKER-INTEGRATION-CHECK:'+git(['rev-parse','HEAD']));}
`;
    const files = [...reservedFiles.filter((entry) => entry.path !== "README.md"), file("README.md", "Prepared public source\n"), file("probe.cjs", probe), file("supervisor-plan.json", JSON.stringify(plan))];
    expect(files.every((entry) => !Buffer.from(entry.bytes).includes(Buffer.from(socket)) && !Buffer.from(entry.bytes).includes(Buffer.from(key)))).toBe(true);
    expect(reserveUpgradePreparation(repository, files).bytes).toBeGreaterThan(0);
    const written = await writeFrozenTree(repository, files); const baseBundle = await createBoundedBundle(repository);
    const common = { profile: NODE_ISOLATION_PROFILE, files, baseBundle, baseCommit: plan.baseCommit, branch: plan.branch, commitMessage: plan.commitMessage, author: plan.author, committer: plan.committer, hook: plan.hook } as const;
    const frozen = freezeNodeValidation({ ...common, phase: "prepared-hook" }); const independentlyHashed = [...files].sort((a, b) => Buffer.compare(Buffer.from(a.path), Buffer.from(b.path))).map(({ path, mode, bytes }) => ({ path, mode, sha256: sha256(bytes) }));
    expect(frozen.sourceSha256).toBe(sha256(Buffer.from(JSON.stringify(independentlyHashed)))); expect(frozen.commitPlanSha256).toBe(plan.commitPlanSha256);
    const expected = { profile: NODE_ISOLATION_PROFILE, image: NODE_ISOLATION_IMAGE, sourceSha256: frozen.sourceSha256, commitPlanSha256: plan.commitPlanSha256, baseCommit: repository.baseCommit, preparedTree: written.tree, hook: plan.hook };
    const replay = await validateIsolatedNode({ ...common, phase: "prepared-hook" }); expect(replay).toMatchObject({ ...expected, phase: "prepared-hook" }); if (replay.phase !== "prepared-hook") throw new Error("Expected hook phase evidence"); expect(replay.hookOutput).toContain("BROKER-INTEGRATION-HOOK-PASSED");
    const candidate = await signAndVerify(repository, written.tree, plan, captured.capability); await fixtureAgent.assert(); const context = transportContext(repository);
    const raw = (await boundedCommand(tools.prlimit, [...PRLIMIT_ARGS, tools.git, ...gitArguments(context, ["cat-file", "commit", candidate])], { cwd: context.directory, env: context.env })).toString();
    expect(raw.startsWith(`tree ${written.tree}\nparent ${plan.baseCommit}\nauthor ${plan.author.name} <${plan.author.email}> ${plan.author.date}\ncommitter ${plan.committer.name} <${plan.committer.email}> ${plan.committer.date}\ngpgsig -----BEGIN SSH SIGNATURE-----\n`)).toBe(true); expect(raw.endsWith("\n\n" + plan.commitMessage)).toBe(true);
    const header = raw.slice(0, raw.indexOf("\n\n")).split("\n"); for (const name of ["tree", "parent", "author", "committer"]) expect(header.filter((line) => line.startsWith(name + " "))).toHaveLength(1);
    expect(raw.slice(raw.indexOf("\n\n") + 2)).toBe(plan.commitMessage); expect(createHash("sha1").update(`commit ${Buffer.byteLength(raw)}\0`).update(raw).digest("hex")).toBe(candidate);
    const finalBundle = await createBoundedBundle(repository, candidate); const final = await validateIsolatedNode({ ...common, phase: "final-check", candidateCommit: candidate, baseBundle: finalBundle });
    expect(final).toMatchObject({ ...expected, phase: "final-check", candidateCommit: candidate }); if (final.phase !== "final-check") throw new Error("Expected final phase evidence"); expect(final.checkOutput).toContain("BROKER-INTEGRATION-CHECK:" + candidate);
    for (const evidence of [replay, final]) { expect(Object.keys(evidence.tools).sort()).toEqual(["bash", "git", "jq", "node", "npm", "python"]); expect(Object.values(evidence.tools).every((value) => value.length > 0)).toBe(true); }
    expect(fixtureState.requests).toEqual(["/repos/example/broker-composition", "/repos/example/broker-composition/git/ref/heads/main"]);
    for (const launch of fixtureState.launches) { for (const untouched of [original, cleanOriginal]) { expect(launch.cwd).not.toBe(untouched); expect(launch.gitdir).not.toBe(path.join(untouched, ".git")); } if (launch.command === tools.prlimit) expect(launch.args.slice(0, PRLIMIT_ARGS.length)).toEqual(PRLIMIT_ARGS); }
    const socketLaunches = fixtureState.launches.filter((launch) => launch.agent); expect(socketLaunches).toHaveLength(2);
    for (const launch of socketLaunches) { expect(launch.command).toBe(tools.prlimit); expect(launch.args[PRLIMIT_ARGS.length]).toBe(launch.args.includes("commit-tree") ? tools.git : sshAdd); }
    expect(await lstat(hostCanary).then(() => true, () => false)).toBe(false); expect(await fingerprint(original)).toBe(before); expect(await fingerprint(cleanOriginal)).toBe(cleanBefore);
  }, agentTestDeadline);
});
