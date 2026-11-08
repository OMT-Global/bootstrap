// Internal fixed-operation support. Never exported from the package or used as a runner option.
import { spawn } from "node:child_process";
import { constants } from "node:fs";
import { lstat, open, opendir, realpath } from "node:fs/promises";
import path from "node:path";

export const HOST_LIMITS = Object.freeze({ bytes: 64 * 1024 ** 2, output: 1024 ** 2, admission: 2 * 1024 ** 3, wallMs: 90_000 });
export const PRLIMIT_ARGS = ["--fsize=67108864:67108864", "--cpu=60:60", "--as=1073741824:1073741824", "--nofile=64:64", "--nproc=128:128", "--core=0:0", "--"];
export const hostFailure = () => new Error("Governed upgrade host operation is unsupported.");
export function demand(value: unknown): asserts value { if (!value) throw hostFailure(); }
export const decode = (bytes: Uint8Array) => new TextDecoder("utf-8", { fatal: true }).decode(bytes);
export async function readRegular(file: string, limit: number, trusted = false, proc = false): Promise<Buffer> {
  demand(path.isAbsolute(file) && Number.isInteger(limit) && limit >= 0 && constants.O_NOFOLLOW > 0 && constants.O_NONBLOCK > 0);
  for (let parent = path.dirname(file); ; parent = path.dirname(parent)) {
    const stat = await lstat(parent); demand(stat.isDirectory());
    if (trusted) demand((stat.uid === 0 || stat.uid === process.getuid?.()) && !(stat.mode & 0o022));
    if (parent === path.dirname(parent)) break;
  }
  const handle = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = await handle.stat(); demand(before.isFile() && before.nlink === 1 && before.size <= limit);
    if (trusted) demand((before.uid === 0 || before.uid === process.getuid?.()) && !(before.mode & 0o022));
    const bytes = Buffer.alloc(limit + 1); let size = 0;
    while (size < bytes.length) { const part = await handle.read(bytes, size, bytes.length - size, size); if (!part.bytesRead) break; size += part.bytesRead; }
    const after = await handle.stat(); demand(size <= limit && after.isFile() && after.nlink === 1 && after.size === before.size && after.mtimeMs === before.mtimeMs && (proc || size === after.size));
    return bytes.subarray(0, size);
  } finally { await handle.close(); }
}
export async function trustedExecutable(file: string): Promise<string> {
  let current = await realpath(file); const result = current; let first = true;
  for (;;) {
    const stat = await lstat(current); demand(stat.uid === 0 && !(stat.mode & 0o6022) && (first ? stat.isFile() && !!(stat.mode & 0o111) : stat.isDirectory()));
    if (current === path.dirname(current)) return result;
    current = path.dirname(current); first = false;
  }
}
export interface CommandOptions { cwd: string; env: NodeJS.ProcessEnv; signal?: AbortSignal; output?: number; combinedOutput?: number; input?: Uint8Array; allowedExit?: readonly number[] }
// Only trusted module code selects this primitive's arguments; broker capabilities expose named operations.
export function boundedCommand(executable: string, args: readonly string[], options: CommandOptions): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    if (options.signal?.aborted) { reject(hostFailure()); return; }
    let child: ReturnType<typeof spawn>;
    try { child = spawn(executable, args, { cwd: options.cwd, env: options.env, detached: true, stdio: ["pipe", "pipe", "pipe"] }); }
    catch { reject(hostFailure()); return; }
    const chunks: Buffer[] = []; let stdout = 0; let stderr = 0; let failed = false;
    const kill = () => { if (child.pid) try { process.kill(-child.pid, "SIGKILL"); } catch { /* Already exited. */ } };
    const fail = () => { failed = true; kill(); };
    const timer = setTimeout(fail, HOST_LIMITS.wallMs); options.signal?.addEventListener("abort", fail, { once: true });
    child.stdout!.on("data", (part: Buffer) => { stdout += part.length; if (stdout > (options.output ?? HOST_LIMITS.output) || stdout + stderr > (options.combinedOutput ?? HOST_LIMITS.output)) fail(); else if (!failed) chunks.push(part); });
    child.stderr!.on("data", (part: Buffer) => { stderr += part.length; if (stderr > HOST_LIMITS.output || stdout + stderr > (options.combinedOutput ?? HOST_LIMITS.output)) fail(); });
    child.once("error", fail); child.stdin!.once("error", fail);
    child.once("close", (code, signal) => {
      clearTimeout(timer); options.signal?.removeEventListener("abort", fail); kill();
      if (failed || signal || code === null || !(options.allowedExit ?? [0]).includes(code)) reject(hostFailure()); else resolve(Buffer.concat(chunks));
    });
    if (options.signal?.aborted) fail(); else child.stdin!.end(options.input);
  });
}
export function neutralEnvironment(home: string, temporary: string): NodeJS.ProcessEnv {
  return { PATH: "/usr/bin:/bin", HOME: home, TMPDIR: temporary, LC_ALL: "C", LANG: "C", TZ: "UTC", GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_SYSTEM: "/dev/null",
    GIT_CONFIG_GLOBAL: "/dev/null", GIT_ATTR_NOSYSTEM: "1", GIT_TERMINAL_PROMPT: "0", GIT_NO_REPLACE_OBJECTS: "1" };
}
export async function requireLinuxHost(): Promise<{ git: string; prlimit: string }> {
  demand(process.platform === "linux" && process.arch === "x64" && process.getuid && process.getuid() !== 0 && process.geteuid?.() === process.getuid());
  const status = decode(await readRegular(`/proc/${process.pid}/status`, 65536, false, true));
  const uids = /^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)$/m.exec(status); demand(uids && uids.slice(1).every((uid) => Number(uid) === process.getuid!()));
  for (const name of ["CapInh", "CapPrm", "CapEff", "CapAmb"]) demand(new RegExp(`^${name}:\\s+0+$`, "m").test(status));
  const limits = decode(await readRegular(`/proc/${process.pid}/limits`, 65536, false, true));
  for (const [name, minimum] of [["Max file size", 67108864], ["Max cpu time", 60], ["Max address space", 1073741824], ["Max open files", 64], ["Max processes", 128]] as const) {
    const found = new RegExp(`^${name}\\s+(\\S+)\\s+(\\S+)`, "m").exec(limits);
    demand(found && found.slice(1).every((value) => value === "unlimited" || /^\d+$/.test(value) && Number(value) >= minimum));
  }
  let threads = 0; let entries = 0;
  for await (const entry of await opendir("/proc")) {
    demand(++entries <= 100_000); const pid = entry.name; if (!/^\d+$/.test(pid)) continue;
    try {
      if ((await lstat(`/proc/${pid}`)).uid !== process.getuid()) continue;
      const value = decode(await readRegular(`/proc/${pid}/status`, 65536, false, true));
      const count = /^Threads:\s+(\d+)$/m.exec(value); demand(count); threads += Number(count[1]); demand(threads < 120);
    } catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw hostFailure(); }
  }
  return { git: await trustedExecutable("/usr/bin/git"), prlimit: await trustedExecutable("/usr/bin/prlimit") };
}
