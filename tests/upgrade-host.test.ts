import { execFileSync, type ChildProcess, type SpawnOptions } from "node:child_process";
import { chmod, link, mkdir, mkdtemp, readFile, realpath, rm, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

const faults = vi.hoisted(() => ({
  spawn: "" as "" | "throw" | "null-status", flag: "", proc: false,
  status: "", limits: "", threads: [1], unsafe: "", unsafeMode: 0, unsafeUid: 0,
  procEntries: 0, procReads: 0, procClosed: 0,
  children: [] as ChildProcess[], closed: [] as ChildProcess[], launches: 0, opens: 0
}));

// Private fault injection covers unavailable host facts, never Linux enforcement.
// Every command runs as a real subprocess except the named spawn/status fault.
vi.mock("node:child_process", async (original) => {
  const actual = await original<typeof import("node:child_process")>();
  return { ...actual, spawn: (command: string, args: readonly string[], options: SpawnOptions) => {
    faults.launches++;
    if (faults.spawn === "throw") throw new Error("private spawn canary");
    const child = actual.spawn(command, args, options); faults.children.push(child);
    child.once("close", () => faults.closed.push(child));
    if (faults.spawn === "null-status") {
      const once = child.once.bind(child);
      child.once = ((event: string | symbol, listener: (...args: unknown[]) => void) =>
        once(event, event === "close" ? () => listener(null, null) : listener)) as typeof child.once;
    }
    return child;
  } };
});
vi.mock("node:fs", async (original) => {
  const actual = await original<typeof import("node:fs")>();
  return { ...actual, constants: { ...actual.constants,
    get O_NOFOLLOW() { return faults.flag === "O_NOFOLLOW" ? 0 : actual.constants.O_NOFOLLOW; },
    get O_NONBLOCK() { return faults.flag === "O_NONBLOCK" ? 0 : actual.constants.O_NONBLOCK; }
  } };
});
vi.mock("node:fs/promises", async (original) => {
  const actual = await original<typeof import("node:fs/promises")>();
  const stat = (directory: boolean, uid = 0, mode = directory ? 0o40755 : 0o100755) => ({
    uid, mode, size: 0, nlink: 1, mtimeMs: 0, isFile: () => !directory, isDirectory: () => directory
  });
  return { ...actual,
    realpath: (file: string) => faults.proc && file.startsWith("/usr/bin/") ? Promise.resolve(file) : actual.realpath(file),
    opendir: async (file: string) => {
      if (!faults.proc || file !== "/proc") return actual.opendir(file);
      return { [Symbol.asyncIterator]: async function* () {
        try {
          for (let index = 0; index < faults.threads.length; index++) {
            faults.procReads++; yield { name: String(index + 1) };
          }
          for (let index = 0; index < faults.procEntries; index++) {
            faults.procReads++; yield { name: `fixture-nonpid-${index}` };
          }
        } finally { faults.procClosed++; }
      } };
    },
    lstat: async (file: string) => {
      if (faults.unsafe && file === faults.unsafe) return stat(file !== "/usr/bin/git", faults.unsafeUid, faults.unsafeMode);
      if (faults.proc && (file === "/" || file === "/usr" || file === "/usr/bin" || file === "/proc" || /^\/proc\/\d+$/.test(file)))
        return stat(true, file.startsWith("/proc/") ? 12345 : 0);
      if (faults.proc && file.startsWith("/usr/bin/")) return stat(false);
      return actual.lstat(file);
    },
    open: async (file: string, flags: number) => {
      faults.opens++;
      if (faults.proc && file.startsWith("/proc/")) {
        const content = Buffer.from(file.endsWith("/limits") ? faults.limits : file === `/proc/${process.pid}/status` ? faults.status :
          `Threads:\t${faults.threads[Number(file.split("/")[2]) - 1]}\n`);
        return { stat: async () => stat(false), close: async () => {},
          read: async (buffer: Buffer, offset: number, length: number, position: number) =>
            ({ bytesRead: content.copy(buffer, offset, position, position + length) }) };
      }
      return actual.open(file, flags);
    }
  };
});

import { boundedCommand, HOST_LIMITS, neutralEnvironment, readRegular, requireLinuxHost, trustedExecutable } from "../src/upgrade-host.js";

const fixed = "Governed upgrade host operation is unsupported.";
const directories: string[] = [];
const descriptors = new Map<string, PropertyDescriptor | undefined>();
async function fixture() {
  const root = await mkdtemp(path.join(await realpath(os.tmpdir()), "bootstrap-host-test-")); directories.push(root);
  return { root, options: { cwd: root, env: neutralEnvironment(root, root) } };
}
function setProcess(name: string, value: unknown) {
  if (!descriptors.has(name)) descriptors.set(name, Object.getOwnPropertyDescriptor(process, name));
  Object.defineProperty(process, name, { configurable: true, value });
}
function procFixture() {
  faults.proc = true;
  setProcess("platform", "linux"); setProcess("arch", "x64");
  setProcess("getuid", () => 12345); setProcess("geteuid", () => 12345);
  faults.status = "Uid:\t12345\t12345\t12345\t12345\n" +
    ["CapInh", "CapPrm", "CapEff", "CapAmb"].map((name) => `${name}:\t0000000000000000\n`).join("");
  faults.limits = "Max file size             67108864 67108864 bytes\nMax cpu time              60 60 seconds\n" +
    "Max address space         1073741824 1073741824 bytes\nMax open files            64 64 files\nMax processes             128 128 processes\n";
}
afterEach(async () => {
  vi.useRealTimers();
  const closing = faults.children.filter((child) => !faults.closed.includes(child)).map((child) => new Promise<void>((resolve) => child.once("close", () => resolve())));
  for (const child of faults.children) if (child.pid && !faults.closed.includes(child)) { try { process.kill(-child.pid, "SIGKILL"); } catch {} }
  await Promise.all(closing);
  for (const [name, descriptor] of descriptors) {
    if (descriptor) Object.defineProperty(process, name, descriptor); else Reflect.deleteProperty(process, name);
  }
  descriptors.clear();
  faults.spawn = ""; faults.flag = ""; faults.proc = false; faults.unsafe = ""; faults.unsafeUid = 0; faults.threads = [1];
  faults.procEntries = 0; faults.procReads = 0; faults.procClosed = 0;
  faults.children.length = 0; faults.closed.length = 0; faults.launches = 0; faults.opens = 0;
  await Promise.all(directories.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe("host process controls using real subprocesses", () => {
  it("bounds real Git stdout while preserving input and caller files", async () => {
    const { root, options } = await fixture(); const file = path.join(root, "canary");
    const bytes = Buffer.alloc(32768, 97); await writeFile(file, bytes);
    const args = ["-c", "core.hooksPath=/dev/null", "config", "--file", "-", "--get", "fixture.value"];
    const input = Buffer.from(`[fixture]\n value = ${"x".repeat(8192)}\n`);
    expect((await boundedCommand("/usr/bin/git", args, { ...options, input, output: 8193 })).length).toBe(8193);
    await expect(boundedCommand("/usr/bin/git", args, { ...options, input, output: 8192 })).rejects.toThrow(fixed);
    expect(await readFile(file)).toEqual(bytes);
    expect(input.toString()).toContain("x".repeat(8192));
    expect(faults.closed).toHaveLength(2);
  });

  it("accepts bounded stderr but rejects stderr and combined stream overflow with a redacted error", async () => {
    const { options } = await fixture();
    const output = await boundedCommand(process.execPath, ["-e", "process.stderr.write('private diagnostic');process.stdout.write('ok')"], options);
    expect(output.toString()).toBe("ok");
    for (const script of [
      `process.stderr.write(Buffer.alloc(${HOST_LIMITS.output + 1}, 120))`,
      `process.stdout.write(Buffer.alloc(600000, 120));process.stderr.write(Buffer.alloc(600000, 121))`
    ]) await expect(boundedCommand(process.execPath, ["-e", script], options)).rejects.toThrow(new Error(fixed));
    expect(faults.closed).toHaveLength(3);
  });

  it("rejects a pre-cancelled command before spawning", async () => {
    const { options } = await fixture(); const controller = new AbortController(); controller.abort("private reason");
    await expect(boundedCommand(process.execPath, ["-e", "process.exit(0)"], { ...options, signal: controller.signal })).rejects.toThrow(fixed);
    expect(faults.launches).toBe(0);
  });

  it.each(["cancel", "deadline", "signal"] as const)("waits for real closure on %s", async (mode) => {
    const { root, options } = await fixture(); const ready = path.join(root, "ready"); const controller = new AbortController();
    if (mode === "deadline") vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    const pending = boundedCommand(process.execPath, ["-e", "require('fs').writeFileSync(process.argv[1],'ready');setInterval(()=>{},1000)", ready],
      { ...options, signal: controller.signal }).catch((error: unknown) => error);
    await vi.waitFor(async () => expect(await readFile(ready, "utf8")).toBe("ready"), { timeout: 3000, interval: 10 });
    const child = faults.children[0]!;
    if (mode === "cancel") controller.abort(new Error("private cancellation reason"));
    else if (mode === "deadline") { await vi.advanceTimersByTimeAsync(HOST_LIMITS.wallMs + 1); vi.useRealTimers(); }
    else child.kill("SIGTERM");
    expect(await pending).toEqual(new Error(fixed)); expect(faults.closed).toContain(child);
    expect(child.exitCode).toBeNull(); expect(child.signalCode).toBe(mode === "signal" ? "SIGTERM" : "SIGKILL");
  });

  it("kills a descendant in the owned process group before reporting cancellation", async () => {
    const { root, options } = await fixture(); const ready = path.join(root, "descendant"); const escaped = path.join(root, "escaped");
    const descendant = `require('fs').writeFileSync(process.argv[1],String(process.pid));setTimeout(()=>require('fs').writeFileSync(process.argv[2],'survived'),400);setInterval(()=>{},1000)`;
    const parent = `require('child_process').spawn(process.execPath,['-e',${JSON.stringify(descendant)},...process.argv.slice(1)],{stdio:'inherit'});setInterval(()=>{},1000)`;
    const controller = new AbortController();
    const pending = boundedCommand(process.execPath, ["-e", parent, ready, escaped], { ...options, signal: controller.signal }).catch((error: unknown) => error);
    await vi.waitFor(async () => expect(Number(await readFile(ready, "utf8"))).toBeGreaterThan(0), { timeout: 3000, interval: 10 });
    controller.abort(); expect(await pending).toEqual(new Error(fixed)); expect(faults.closed).toHaveLength(1);
    await new Promise((resolve) => setTimeout(resolve, 500));
    await expect(readFile(escaped)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("kills an owned background descendant even when the direct command exits successfully", async () => {
    const { root, options } = await fixture(); const ready = path.join(root, "ready"); const escaped = path.join(root, "escaped");
    const descendant = `require('fs').writeFileSync(process.argv[1],'ready');setTimeout(()=>require('fs').writeFileSync(process.argv[2],'escaped'),400)`;
    const parent = `const fs=require('fs');const child=require('child_process').spawn(process.execPath,['-e',${JSON.stringify(descendant)},...process.argv.slice(1)],{stdio:'ignore'});const timer=setInterval(()=>{if(fs.existsSync(process.argv[1])){clearInterval(timer);child.unref();process.stdout.write('complete')}},5)`;
    expect((await boundedCommand(process.execPath, ["-e", parent, ready, escaped], options)).toString()).toBe("complete");
    expect(await readFile(ready, "utf8")).toBe("ready");
    await new Promise((resolve) => setTimeout(resolve, 500)); await expect(readFile(escaped)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it.each(["throw", "null-status"] as const)("fails closed for private %s injection", async (fault) => {
    const { options } = await fixture(); faults.spawn = fault;
    await expect(boundedCommand(process.execPath, ["-e", "process.exit(0)"], options)).rejects.toThrow(new Error(fixed));
  });

  it("redacts an actual missing executable and allows only explicit exit codes", async () => {
    const { root, options } = await fixture();
    await expect(boundedCommand(path.join(root, "private-missing-canary"), [], options)).rejects.toThrow(new Error(fixed));
    await expect(boundedCommand(process.execPath, ["-e", "process.exit(7)"], options)).rejects.toThrow(new Error(fixed));
    expect(await boundedCommand(process.execPath, ["-e", "process.stdout.write('allowed');process.exit(7)"], { ...options, allowedExit: [7] })).toEqual(Buffer.from("allowed"));
  });
});

describe("bounded nofollow regular-file reads", () => {
  it("accepts exact size and empty files, rejects oversized files, hardlinks, symlinks, and FIFO without blocking", async () => {
    const { root } = await fixture(); const file = path.join(root, "regular"); await writeFile(file, "canary");
    expect((await readRegular(file, 6)).toString()).toBe("canary");
    await expect(readRegular(file, 5)).rejects.toThrow(fixed);
    const empty = path.join(root, "empty"); await writeFile(empty, ""); expect(await readRegular(empty, 0)).toHaveLength(0);
    const symbolic = path.join(root, "symlink"); await symlink(file, symbolic); await expect(readRegular(symbolic, 100)).rejects.toThrow();
    const hard = path.join(root, "hardlink"); await link(file, hard); await expect(readRegular(file, 100)).rejects.toThrow(fixed);
    const fifo = path.join(root, "fifo"); execFileSync("/usr/bin/mkfifo", [fifo]); await expect(readRegular(fifo, 100)).rejects.toThrow(fixed);
    expect(await readFile(file, "utf8")).toBe("canary");
  }, 2000);

  it("rejects a symlinked ancestor and requires both protective open flags before opening", async () => {
    const { root } = await fixture(); const real = path.join(root, "real"); await mkdir(real); await writeFile(path.join(real, "data"), "safe");
    await symlink(real, path.join(root, "alias")); await expect(readRegular(path.join(root, "alias/data"), 4)).rejects.toThrow(fixed);
    for (const flag of ["O_NOFOLLOW", "O_NONBLOCK"]) {
      faults.flag = flag; const before = faults.opens;
      await expect(readRegular(path.join(real, "data"), 4)).rejects.toThrow(fixed); expect(faults.opens).toBe(before);
    }
  });

  it("rejects trusted reads through writable directories", async () => {
    const { root } = await fixture(); await chmod(root, 0o777); const file = path.join(root, "data"); await writeFile(file, "safe");
    await expect(readRegular(file, 4, true)).rejects.toThrow(fixed);
  });
});

describe("Linux eligibility flow only (simulated proc/UID/tool facts; no kernel enforcement evidence)", () => {
  it("accepts complete unprivileged facts, unlimited ceilings, and 119 UID threads", async () => {
    procFixture(); faults.threads = [59, 60];
    expect(await requireLinuxHost()).toEqual({ git: "/usr/bin/git", prlimit: "/usr/bin/prlimit" });
    faults.limits = faults.limits.replace(/67108864|1073741824|\b60\b|\b64\b|\b128\b/g, "unlimited");
    await expect(requireLinuxHost()).resolves.toHaveProperty("prlimit", "/usr/bin/prlimit");
  });

  it.each(["root", "effective UID", "saved UID", "filesystem UID", "architecture", "platform"])("rejects %s before trusting a host", async (fault) => {
    procFixture();
    if (fault === "root") setProcess("getuid", () => 0);
    else if (fault === "effective UID") setProcess("geteuid", () => 12346);
    else if (fault === "saved UID") faults.status = faults.status.replace("12345\t12345\t12345\t12345", "12345\t12345\t12346\t12345");
    else if (fault === "filesystem UID") faults.status = faults.status.replace("12345\t12345\t12345\t12345", "12345\t12345\t12345\t12346");
    else setProcess(fault === "architecture" ? "arch" : "platform", fault === "architecture" ? "arm64" : "darwin");
    await expect(requireLinuxHost()).rejects.toThrow(fixed);
  });

  it.each(["CapInh", "CapPrm", "CapEff", "CapAmb"])("rejects nonzero or missing %s", async (name) => {
    procFixture(); faults.status = faults.status.replace(`${name}:\t0000000000000000`, `${name}:\t0000000000000001`);
    await expect(requireLinuxHost()).rejects.toThrow(fixed);
    faults.status = faults.status.replace(new RegExp(`^${name}:.*\\n`, "m"), ""); await expect(requireLinuxHost()).rejects.toThrow(fixed);
  });

  it.each(["Max file size", "Max cpu time", "Max address space", "Max open files", "Max processes"])("rejects either inherited %s ceiling below the profile", async (name) => {
    for (const position of [1, 2]) {
      procFixture(); faults.limits = faults.limits.replace(new RegExp(`^(${name}\\s+)(\\S+)(\\s+)(\\S+)`, "m"),
        (_all, prefix, soft, separator, hard) => `${prefix}${position === 1 ? "1" : soft}${separator}${position === 2 ? "1" : hard}`);
      await expect(requireLinuxHost()).rejects.toThrow(fixed);
    }
  });

  it.each(["-1", "NaN", "infinity", "60x"])("rejects malformed inherited limit %s", async (value) => {
    procFixture(); faults.limits = faults.limits.replace("60 60 seconds", `${value} 60 seconds`);
    await expect(requireLinuxHost()).rejects.toThrow(fixed);
  });

  it("counts UID threads across processes and rejects no process headroom or malformed thread counts", async () => {
    procFixture(); faults.threads = [60, 60]; await expect(requireLinuxHost()).rejects.toThrow(fixed);
    faults.threads = [Number.NaN]; await expect(requireLinuxHost()).rejects.toThrow(fixed);
  });

  it("bounds the streamed proc inventory and closes iteration when the entry budget is exceeded", async () => {
    procFixture(); faults.threads = []; faults.procEntries = 100_000;
    await expect(requireLinuxHost()).resolves.toHaveProperty("prlimit", "/usr/bin/prlimit");
    expect(faults.procReads).toBe(100_000); expect(faults.procClosed).toBe(1);
    faults.procReads = 0; faults.procEntries = 1_000_000;
    await expect(requireLinuxHost()).rejects.toThrow(fixed);
    expect(faults.procReads).toBe(100_001); expect(faults.procClosed).toBe(2);
  });

  it.each([["/usr/bin/git", 0o104755], ["/usr/bin/git", 0o102755], ["/usr/bin/git", 0o100775],
    ["/usr/bin/git", 0o100644], ["/usr/bin", 0o40777]])("rejects unsafe trusted binary or ancestor %s mode %i", async (file, mode) => {
    procFixture(); faults.unsafe = file as string; faults.unsafeMode = mode as number;
    await expect(trustedExecutable("/usr/bin/git")).rejects.toThrow(fixed);
  });

  it("requires root ownership for both executable and ancestry", async () => {
    procFixture(); faults.unsafeUid = 12345;
    for (const file of ["/usr/bin/git", "/usr/bin"]) {
      faults.unsafe = file; faults.unsafeMode = file === "/usr/bin/git" ? 0o100755 : 0o40755;
      await expect(trustedExecutable("/usr/bin/git")).rejects.toThrow(fixed);
    }
  });
});
