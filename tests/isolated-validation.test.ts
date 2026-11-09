import { mkdtemp, mkdir, readFile, writeFile, appendFile, chmod, rm, access } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { validateIsolatedNode } from "../src/isolation/node-validation.js";
import { CONTAINER_SETUP } from "../src/isolation/setup.js";
import { Script } from "node:vm";
import { ISOLATION_LIMITS, type NodeValidationInput } from "../src/isolation/node-profile.js";

const transport = vi.hoisted(() => ({ executable: "", unavailable: true, uid: 0, mode: 0o100755, badAncestor: false }));
vi.mock("node:fs/promises", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs/promises")>();
  const fixed = (value: unknown) => value === "/usr/bin/docker" || value === "/usr/local/bin/docker";
  return { ...actual,
    access: async (value: Parameters<typeof actual.access>[0], mode?: number) => {
      if (fixed(value)) { if (transport.unavailable) throw Object.assign(new Error("Missing fixture tool"), { code: "ENOENT" }); return; }
      return actual.access(value, mode);
    },
    realpath: async (value: Parameters<typeof actual.realpath>[0], options?: Parameters<typeof actual.realpath>[1]) => fixed(value) ? value : actual.realpath(value, options),
    stat: async (value: Parameters<typeof actual.stat>[0]) => {
      if (fixed(value)) return { uid: transport.uid, mode: transport.mode, isFile: () => true, isDirectory: () => false };
      if (transport.badAncestor && ["/usr/bin", "/usr/local/bin"].includes(String(value))) return { uid: 0, mode: 0o40777, isDirectory: () => true };
      return actual.stat(value);
    }
  };
});
vi.mock("node:child_process", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:child_process")>();
  return { ...actual, spawn: (executable: string, args: readonly string[], options: import("node:child_process").SpawnOptions) =>
    actual.spawn(["/usr/bin/docker", "/usr/local/bin/docker"].includes(executable) && transport.executable ? transport.executable : executable, args, options) };
});
const directories: string[] = [];
const platform = Object.getOwnPropertyDescriptor(process, "platform")!;
const architecture = Object.getOwnPropertyDescriptor(process, "arch")!;
const originalPath = process.env.PATH;
function fixture(hook = false, phase: "prepared-hook" | "final-check" = "final-check"): NodeValidationInput {
  const file = (name: string, text: string, executable = false) => ({ path: name, bytes: Buffer.from(text), mode: executable ? "100755" as const : "100644" as const });
  return { ...(phase === "final-check" ? { phase, candidateCommit: "c".repeat(40) } : { phase }), profile: "node-npm-linux-v1", baseBundle: Buffer.from("synthetic bundle, validated by real Docker tests"), baseCommit: "a".repeat(40),
    author: { name: "Synthetic Author", email: "author@example.invalid", date: "1767225600 +0000" },
    committer: { name: "Synthetic Committer", email: "committer@example.invalid", date: "1767225601 +0000" },
    branch: "codex/isolated-test", commitMessage: "test: isolated validation\n\nSigned-off-by: Synthetic Tester <fixture@example.invalid>\n",
    hook: hook ? ".githooks/pre-commit" : "none", files: [file("package.json", '{"name":"fixture","version":"1.0.0"}'),
      file("package-lock.json", '{"lockfileVersion":3,"packages":{"":{"name":"fixture","version":"1.0.0"}}}'),
      file("scripts/ci/run-fast-checks.sh", "#!/bin/bash\nexit 0\n", true), ...(hook ? [file(".githooks/pre-commit", "#!/bin/bash\nexit 0\n", true)] : [])] };
}
interface FakeOptions { failAt?: string; exitCode?: number; hangAt?: string; cleanupFailure?: boolean; holdCleanup?: boolean; excessiveOutput?: boolean; platform?: string; invalidEvidence?: boolean; untrustedUid?: number; untrustedMode?: number; untrustedAncestor?: boolean; storageNotRunning?: boolean; storageLostAfterPhase?: boolean; missingJq?: boolean }
async function fakeDocker(options: FakeOptions = {}) {
  const directory = await mkdtemp(path.join(os.tmpdir(), "bootstrap-docker-control-")); directories.push(directory);
  const log = path.join(directory, "calls.jsonl"); const config = path.join(directory, "options.json");
  await writeFile(config, JSON.stringify(options)); await mkdir(path.join(directory, "bin"));
  const executable = path.join(directory, "bin/docker");
  await writeFile(executable, `#!${process.execPath}\nconst fs=require('node:fs');
const cfg=JSON.parse(fs.readFileSync(${JSON.stringify(config)},'utf8'));
const args=process.argv.slice(6), command=args[0], name=args.includes('--name')?args[args.indexOf('--name')+1]:args.at(-1);
fs.appendFileSync(${JSON.stringify(log)},JSON.stringify({args,environment:process.env,cwd:process.cwd()})+'\\n');
const phase=String(name).split('-').at(-1);
function proceed() {
  if(cfg.cleanupFailure && ((command==='rm')||(command==='volume'&&args[1]==='rm'))) process.exit(28);
  if(cfg.failAt===command || cfg.failAt===command+':'+phase) process.exit(23);
  if(cfg.hangAt===command+':'+phase) setInterval(()=>{},1000);
  else if(command==='version' || command==='image') console.log(cfg.platform||'linux/amd64');
  else if(command==='start' && phase==='prepare') console.log(JSON.stringify(cfg.invalidEvidence?{}:{tree:'b'.repeat(40),tools:{bash:'GNU bash',git:'git',python:'Python 3',node:'v24.0.0',npm:'11',...(cfg.missingJq?{}:{jq:'jq-1.6'})}}));
  else if(command==='start' && ['check','hook'].includes(phase) && cfg.excessiveOutput) process.stdout.write('x'.repeat(9*1024*1024));
  else if(command==='inspect') {
    const prefix=String(name).replace(/-storage$/,'');
    const prior=fs.readFileSync(${JSON.stringify(log)},'utf8').trim().split('\\n').filter(Boolean).map(line=>JSON.parse(line).args);
    const phaseRan=prior.some(call=>call[0]==='start' && call.at(-1).startsWith(prefix) && /-(check|hook)$/.test(call.at(-1)));
    const running=phase==='storage' && !cfg.storageNotRunning && !(cfg.storageLostAfterPhase&&phaseRan);
    console.log(JSON.stringify({Running:running,ExitCode:phase==='check'?(cfg.exitCode||0):0,OOMKilled:false,Error:''}));
  }
  else if(command==='cp') { const transfer=args[1].slice(0,-2); fs.writeFileSync(${JSON.stringify(path.join(directory, "transferred.json"))},fs.readFileSync(transfer+'/manifest.json')); }
  else if(command==='create'||command==='volume') console.log(name);
}
if(cfg.holdCleanup && command==='rm' && phase==='storage') {
  const waiting=setInterval(()=>{if(fs.existsSync(${JSON.stringify(path.join(directory, "release-cleanup"))})){clearInterval(waiting);proceed();}},10);
} else proceed();
`);
  await chmod(executable, 0o755);
  transport.executable = executable; transport.unavailable = false; transport.uid = options.untrustedUid ?? 0; transport.mode = options.untrustedMode ?? 0o100755; transport.badAncestor = options.untrustedAncestor ?? false;
  process.env.PATH = `${path.dirname(executable)}${path.delimiter}${originalPath}`;
  Object.defineProperty(process, "platform", { value: "linux" }); Object.defineProperty(process, "arch", { value: "x64" });
  const journal = () => readFile(log, "utf8").catch((error: NodeJS.ErrnoException) => { if (error.code === "ENOENT") return ""; throw error; });
  const parse = (text: string) => text.trim().split("\n").filter(Boolean).map((line) => JSON.parse(line));
  const calls = async () => parse(await journal());
  return { directory, releaseCleanup: () => writeFile(path.join(directory, "release-cleanup"), "released"), calls,
    pollCalls: async () => {
      // A child append can be observed before its final newline; completed records still parse strictly.
      const text = await journal(); return parse(text.slice(0, text.lastIndexOf("\n") + 1));
    } };
}
afterEach(async () => {
  Object.defineProperty(process, "platform", platform); Object.defineProperty(process, "arch", architecture);
  if (originalPath === undefined) delete process.env.PATH; else process.env.PATH = originalPath;
  delete process.env.BOOTSTRAP_SYNTHETIC_OPERATOR_CANARY;
  transport.executable = ""; transport.unavailable = true; transport.uid = 0; transport.mode = 0o100755; transport.badAncestor = false;
  vi.useRealTimers(); vi.restoreAllMocks();
  await Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

describe("isolated Docker supervisor lifecycle (controlled CLI, not confinement proof)", () => {
  it("waits for newline-complete journal records during polling and parses final records strictly", async () => {
    const fake = await fakeDocker(); const log = path.join(fake.directory, "calls.jsonl");
    const first = { args: ["version"] }, second = { args: ["rm", "--force", "synthetic-storage"] };
    const record = JSON.stringify(second), boundary = record.indexOf("synthetic-storage") + 5;
    await writeFile(log, `${JSON.stringify(first)}\n${record.slice(0, boundary)}`);
    await expect(fake.calls()).rejects.toBeInstanceOf(SyntaxError);
    await expect(fake.pollCalls()).resolves.toEqual([first]);
    await appendFile(log, record.slice(boundary));
    await expect(fake.pollCalls()).resolves.toEqual([first]);
    await appendFile(log, "\n");
    await expect(fake.pollCalls()).resolves.toEqual([first, second]);
    await expect(fake.calls()).resolves.toEqual([first, second]);
    await appendFile(log, '{"args":}\n');
    await expect(fake.pollCalls()).rejects.toBeInstanceOf(SyntaxError);
    await expect(fake.calls()).rejects.toBeInstanceOf(SyntaxError);
  });
  it("constructs a fixed confined profile and separately validates a declared hook", async () => {
    const fake = await fakeDocker(); process.env.BOOTSTRAP_SYNTHETIC_OPERATOR_CANARY = "fixture-only";
    const replay = await validateIsolatedNode(fixture(true, "prepared-hook"));
    expect(replay.phase).toBe("prepared-hook");
    const report = await validateIsolatedNode(fixture(true));
    expect(report.phase).toBe("final-check");
    expect(report.phase === "final-check" && report.candidateCommit).toBe("c".repeat(40));
    expect(report.preparedTree).toBe("b".repeat(40)); expect(report.tools.node).toBe("v24.0.0");
    expect(report.tools.jq).toBe("jq-1.6");
    const calls = await fake.calls(); const creates = calls.filter(({ args }) => args[0] === "create");
    expect(creates).toHaveLength(6);
    for (const { args } of creates.filter(({ args }) => args.at(-1) === "hook" || args.at(-1) === "check")) {
      for (const target of ["/repo/project/node_modules", "/tmp"]) {
        const mount = args.find((value: string, index: number) => args[index - 1] === "--tmpfs" && value.startsWith(`${target}:`));
        expect(mount, `${args.at(-1)} ${target}: required execution mount`).toBeDefined();
        const flags = mount.split(":")[1].split(",");
        expect(flags, `${args.at(-1)} ${target}: executable mount policy`).toContain("exec");
        expect(flags).not.toContain("noexec");
      }
    }
    for (const { args, environment } of creates) {
      for (const values of [["--network", "none"], ["--cap-drop", "ALL"], ["--security-opt", "no-new-privileges"], ["--user", "1000:1000"], ["--log-driver", "none"]]) {
        expect(args.slice(args.indexOf(values[0]), args.indexOf(values[0]) + 2)).toEqual(values);
      }
      expect(args).toContain("--read-only"); expect(args).toContain("--no-healthcheck");
      const keeper = args[args.indexOf("--name") + 1].endsWith("-storage");
      const phase = keeper ? "storage" : args.at(-1);
      const sizes: Record<string, number> = { "/tmp": (keeper ? 1 : 256) * 1024 ** 2 };
      if (phase === "prepare") sizes["/install"] = 512 * 1024 ** 2;
      if (phase === "hook" || phase === "check") Object.assign(sizes, {
        "/npm-cache": 1024 ** 3, "/repo/project/node_modules": 512 * 1024 ** 2, "/repo/project/dist": 128 * 1024 ** 2
      });
      const mounts = args.flatMap((value: string, index: number) => value === "--tmpfs" ? [args[index + 1] as string] : []);
      expect(mounts.map((mount: string) => mount.split(":")[0]).sort()).toEqual(Object.keys(sizes).sort());
      for (const mount of mounts) {
        const [target, options] = mount.split(":") as [string, string]; const flags = options.split(",");
        for (const required of ["rw", "nosuid", "nodev", "uid=1000", "gid=1000", "mode=0700"]) expect(flags).toContain(required);
        expect(flags.find((flag) => flag.startsWith("size="))).toBe(`size=${sizes[target]}`);
        const executionAllowed = (phase === "hook" || phase === "check") && ["/tmp", "/repo/project/node_modules"].includes(target);
        expect.soft(flags, `${phase} ${target}: executable mount policy`).toContain(executionAllowed ? "exec" : "noexec");
        expect(flags).not.toContain(executionAllowed ? "noexec" : "exec");
      }
      expect(args.filter((value: string) => value.startsWith("type="))).not.toContainEqual(expect.stringContaining("type=bind"));
      expect(environment.BOOTSTRAP_SYNTHETIC_OPERATOR_CANARY).toBeUndefined(); expect(Object.keys(environment).filter((key) => !(platform.value === "darwin" && key === "__CF_USER_TEXT_ENCODING")).sort()).toEqual(["HOME", "PATH"]);
    }
    const keepers = creates.filter(({ args }) => args[args.indexOf("--name") + 1].endsWith("-storage"));
    expect(keepers).toHaveLength(2);
    const work = creates.filter(({ args }) => !args[args.indexOf("--name") + 1].endsWith("-storage"));
    for (const { args } of work) {
      expect(args.slice(args.indexOf("--memory"), args.indexOf("--memory") + 2)).toEqual(["--memory", "4g"]);
      expect(args.slice(args.indexOf("--pids-limit"), args.indexOf("--pids-limit") + 2)).toEqual(["--pids-limit", "256"]);
    }
    for (const { args } of work.filter(({ args }) => args.at(-1) !== "prepare")) {
      const source = args.find((value: string) => value.startsWith("type=volume") && value.includes("dst=/repo"));
      const cache = args.find((value: string) => value.startsWith("type=volume") && value.includes("dst=/pristine-cache"));
      expect(source).toContain(",readonly"); expect(cache).toContain(",readonly");
    }
    expect(work.map(({ args }) => args.at(-1))).toEqual(["prepare", "hook", "prepare", "check"]);
    expect(calls.filter(({ args }) => args[0] === "rm")).toHaveLength(6);
    expect(calls.filter(({ args }) => args[0] === "volume" && args[1] === "rm")).toHaveLength(6);
    await expect(access(calls[0]!.cwd)).rejects.toThrow();
  }, 15_000);
  it("provisions input storage for every admitted payload plus bounded metadata and page tails", async () => {
    const fake = await fakeDocker(); await validateIsolatedNode(fixture());
    const volumes = (await fake.calls()).filter(({ args }) => args[0] === "volume" && args[1] === "create");
    const options = (suffix: string) => {
      const args = volumes.find(({ args }) => args.at(-1).endsWith(suffix))!.args as string[];
      return args.find((value) => value.startsWith("o=size="))!.slice(2).split(",");
    };
    const input = options("-input"), size = Number(input.find((value) => value.startsWith("size="))!.slice(5));
    const payload = ISOLATION_LIMITS.sourceBytes + ISOLATION_LIMITS.downloadBytes + ISOLATION_LIMITS.bundleBytes;
    // JSON escaping of every permitted path is covered; generated strings are separately bounded.
    const fileDescriptor = Buffer.byteLength(JSON.stringify({ path: "\u0001".repeat(4096), mode: "100755", sha256: "a".repeat(64) })) + 1;
    const metadata = ISOLATION_LIMITS.files * fileDescriptor + 1024 ** 2;
    const regularFiles = ISOLATION_LIMITS.files + ISOLATION_LIMITS.archives + 3;
    const pageTails = regularFiles * (4096 - 1);
    expect(metadata).toBeLessThan(256 * 1024 ** 2);
    expect(size).toBeGreaterThanOrEqual(payload + metadata + Buffer.byteLength(CONTAINER_SETUP) + pageTails);
    expect(size).toBe(1536 * 1024 ** 2);
    expect(input).toContain("nr_inodes=65536");
    expect(65536).toBeGreaterThanOrEqual(ISOLATION_LIMITS.entries + ISOLATION_LIMITS.archives + 7);
    expect(options("-source")).toContain(`size=${2 * 1024 ** 3}`);
    expect(options("-cache")).toContain(`size=${1024 ** 3}`);
    expect(options("-source").some((value) => value.startsWith("nr_inodes="))).toBe(false);
    expect(options("-cache").some((value) => value.startsWith("nr_inodes="))).toBe(false);
  });
  it("reserves source storage for the worktree, separate Git objects and bundle bookkeeping", async () => {
    const fake = await fakeDocker(); await validateIsolatedNode(fixture());
    const call = (await fake.calls()).find(({ args }) => args[0] === "volume" && args[1] === "create" && args.at(-1).endsWith("-source"))!;
    const option = (call.args as string[]).find((value) => value.startsWith("o=size="))!;
    const size = Number(option.slice(7).split(",")[0]);
    // An engineering reserve under the existing bounds, not a promise for every Git input or total RAM.
    const entries = ISOLATION_LIMITS.entries, page = 4096;
    const worktree = ISOLATION_LIMITS.sourceBytes;
    const looseObjectsAndTrees = Math.ceil(worktree * 1.2) + entries * (4096 + 1024);
    const pageTails = (2 * entries + 4) * (page - 1);
    const indexAndLocks = 2 * entries * (4096 + 128);
    const packAndIndexes = 5 * ISOLATION_LIMITS.bundleBytes;
    const fixedGitTemporary = 16 * 1024 ** 2;
    const envelope = worktree + looseObjectsAndTrees + pageTails + indexAndLocks + packAndIndexes + fixedGitTemporary;
    expect(1024 ** 3).toBeLessThan(2 * worktree + ISOLATION_LIMITS.bundleBytes);
    expect(size).toBeGreaterThanOrEqual(envelope);
  });
  it("reserves the same finite cache headroom for preparation and both fresh phases", async () => {
    const fake = await fakeDocker();
    await validateIsolatedNode(fixture(true, "prepared-hook"));
    await validateIsolatedNode(fixture());
    const calls = await fake.calls();
    const caches = calls.filter(({ args }) => args[0] === "volume" && args[1] === "create" && args.at(-1).endsWith("-cache"));
    expect(caches).toHaveLength(2);
    const size = (options: string) => Number(options.match(/(?:^|,)size=(\d+)(?:,|$)/)![1]);
    const seededFileAndIndexTails = ISOLATION_LIMITS.archives * ((4096 - 1) + 4096);
    // Reserve one compressed restaging archive and finite temporary/install room; expansion can still fail closed.
    const ordinaryCacheEnvelope = ISOLATION_LIMITS.downloadBytes + seededFileAndIndexTails + ISOLATION_LIMITS.archiveBytes + 256 * 1024 ** 2;
    expect(ISOLATION_LIMITS.downloadBytes).toBeLessThan(ordinaryCacheEnvelope);
    const pristineSizes = caches.map(({ args }) => size((args as string[]).find((value) => value.startsWith("o=size="))!.slice(2)));
    for (const bytes of pristineSizes) expect(bytes).toBeGreaterThanOrEqual(ordinaryCacheEnvelope);
    const phases = calls.filter(({ args }) => args[0] === "create" && ["hook", "check"].includes(args.at(-1)));
    expect(phases.map(({ args }) => args.at(-1))).toEqual(["hook", "check"]);
    for (const { args } of phases) {
      const cache = (args as string[]).find((value) => value.startsWith("/npm-cache:"))!;
      expect(size(cache.split(":")[1]!)).toBe(pristineSizes[0]);
      expect(cache.split(":")[1]!.split(",")).toContain("noexec");
      expect((args as string[]).some((value) => value.startsWith("type=volume,") && value.includes("dst=/pristine-cache,readonly"))).toBe(true);
    }
  });
  it("keeps all three bounded volumes mounted with inert, confined, finite-lived storage code", async () => {
    const fake = await fakeDocker(); await validateIsolatedNode(fixture());
    const calls = await fake.calls();
    const keeperIndex = calls.findIndex(({ args }) => args[0] === "create" && args[args.indexOf("--name") + 1].endsWith("-storage"));
    expect(keeperIndex).toBeGreaterThanOrEqual(0);
    const keeper = calls[keeperIndex]!.args as string[];
    const name = keeper[keeper.indexOf("--name") + 1]!;
    const mounts = keeper.filter((value) => value.startsWith("type=volume"));
    expect(mounts).toHaveLength(3);
    expect(mounts.map((value) => value.split(",").find((part) => part.startsWith("dst="))).sort()).toEqual(["dst=/input", "dst=/pristine-cache", "dst=/repo"]);
    expect(mounts.some((value) => value.includes(",readonly"))).toBe(false);
    expect(keeper.slice(keeper.indexOf("--cpus"), keeper.indexOf("--cpus") + 2)).toEqual(["--cpus", "0.1"]);
    expect(keeper.slice(keeper.indexOf("--memory"), keeper.indexOf("--memory") + 2)).toEqual(["--memory", "64m"]);
    expect(keeper.slice(keeper.indexOf("--memory-swap"), keeper.indexOf("--memory-swap") + 2)).toEqual(["--memory-swap", "64m"]);
    expect(keeper.slice(keeper.indexOf("--pids-limit"), keeper.indexOf("--pids-limit") + 2)).toEqual(["--pids-limit", "16"]);
    expect(keeper.find((value) => value.startsWith("/tmp:"))).toContain("size=1048576");
    expect(keeper).not.toContain("/input/setup.cjs");
    expect(keeper).toContain("-e");
    const delays: number[] = []; const exits: number[] = []; let expire: (() => void) | undefined;
    new Script(keeper[keeper.indexOf("-e") + 1]!).runInNewContext({
      setTimeout: (callback: () => void, delay: number) => { expire = callback; delays.push(delay); return 1; },
      process: { exit: (code: number) => { exits.push(code); } }
    });
    expect(delays).toHaveLength(1); expect(delays[0]).toBeGreaterThan(0); expect(delays[0]).toBeLessThanOrEqual(60 * 60_000);
    expect(expire).toBeTypeOf("function"); expire!(); expect(exits).toEqual([1]);
    const start = calls.findIndex(({ args }) => args[0] === "start" && args.at(-1) === name);
    const copied = calls.findIndex(({ args }) => args[0] === "cp");
    expect(start).toBeGreaterThan(keeperIndex); expect(start).toBeLessThan(copied);
    expect(calls[start]!.args).not.toContain("--attach");
    expect(calls.slice(start + 1, copied).some(({ args }) => args[0] === "inspect" && args.at(-1) === name)).toBe(true);
    const keeperRemoved = calls.findIndex(({ args }) => args[0] === "rm" && args.at(-1) === name);
    const prepareStarted = calls.findIndex(({ args }) => args[0] === "start" && args.at(-1).endsWith("-prepare"));
    const workStarted = calls.findIndex(({ args }) => args[0] === "start" && args.at(-1).endsWith("-check"));
    for (const [previous, next] of [[copied, prepareStarted], [prepareStarted, workStarted], [workStarted, keeperRemoved]]) {
      expect(calls.slice(previous + 1, next).some(({ args }) => args[0] === "inspect" && args.at(-1) === name)).toBe(true);
    }
    const workRemovals = calls.flatMap(({ args }, index) => args[0] === "rm" && args.at(-1) !== name ? [index] : []);
    const volumeRemovals = calls.flatMap(({ args }, index) => args[0] === "volume" && args[1] === "rm" ? [index] : []);
    expect(keeperRemoved).toBeGreaterThan(Math.max(...workRemovals));
    expect(Math.min(...volumeRemovals)).toBeGreaterThan(keeperRemoved);
  });
  it.each(["create:storage", "start:storage"])("blocks and removes tracked resources after keeper %s fails", async (failAt) => {
    const fake = await fakeDocker({ failAt });
    await expect(validateIsolatedNode(fixture())).rejects.toThrow();
    const calls = await fake.calls();
    expect(calls.some(({ args }) => args[0] === "cp")).toBe(false);
    expect(calls.some(({ args }) => args[0] === "rm" && args.at(-1).endsWith("-storage"))).toBe(true);
    expect(calls.filter(({ args }) => args[0] === "volume" && args[1] === "rm")).toHaveLength(3);
  });
  it("blocks before copying source when the storage keeper is not running", async () => {
    const fake = await fakeDocker({ storageNotRunning: true });
    await expect(validateIsolatedNode(fixture())).rejects.toThrow(/storage|keeper/i);
    const calls = await fake.calls(); expect(calls.some(({ args }) => args[0] === "cp")).toBe(false);
    expect(calls.some(({ args }) => args[0] === "rm" && args.at(-1).endsWith("-storage"))).toBe(true);
  });
  it("rejects late storage loss before releasing success evidence", async () => {
    const fake = await fakeDocker({ storageLostAfterPhase: true });
    await expect(validateIsolatedNode(fixture())).rejects.toThrow(/storage|keeper/i);
    const calls = await fake.calls(); expect(calls.some(({ args }) => args[0] === "start" && args.at(-1).endsWith("-check"))).toBe(true);
    expect(calls.some(({ args }) => args[0] === "rm" && args.at(-1).endsWith("-storage"))).toBe(true);
    expect(calls.filter(({ args }) => args[0] === "volume" && args[1] === "rm")).toHaveLength(3);
  });
  it("freezes caller bytes before asynchronous Docker work", async () => {
    const fake = await fakeDocker(); const input = fixture(); const original = Buffer.from(input.files[0]!.bytes);
    const operation = validateIsolatedNode(input); input.files[0]!.bytes.fill(0);
    const report = await operation;
    const transferred = JSON.parse(await readFile(path.join(fake.directory, "transferred.json"), "utf8"));
    const { createHash } = await import("node:crypto");
    expect(transferred.files.find((file: { path: string }) => file.path === "package.json").sha256).toBe(createHash("sha256").update(original).digest("hex"));
    expect(report.phase).toBe("final-check");
    expect("hookOutput" in report).toBe(false);
  });
  it("rejects a failed container even if docker start itself exits successfully", async () => {
    const fake = await fakeDocker({ exitCode: 17 });
    await expect(validateIsolatedNode(fixture())).rejects.toThrow("isolated process did not complete successfully");
    const calls = await fake.calls(); expect(calls.some(({ args }) => args[0] === "inspect")).toBe(true);
    expect(calls.filter(({ args }) => args[0] === "volume" && args[1] === "rm")).toHaveLength(3);
  });
  it.each(["create:prepare", "create:check", "start:prepare", "start:check", "start:hook"])("cleans partial Docker state after %s fails", async (failAt) => {
    const fake = await fakeDocker({ failAt });
    await expect(validateIsolatedNode(fixture(true, failAt.endsWith(":hook") ? "prepared-hook" : "final-check"))).rejects.toThrow();
    const calls = await fake.calls();
    expect(calls.filter(({ args }) => args[0] === "volume" && args[1] === "rm")).toHaveLength(3);
    const created = calls.filter(({ args }) => args[0] === "create").map(({ args }) => args[args.indexOf("--name") + 1]);
    const removed = calls.filter(({ args }) => args[0] === "rm").map(({ args }) => args.at(-1));
    expect(removed).toEqual(expect.arrayContaining(created));
  });
  it("does not reuse a validation container or its mutable cache for hook replay", async () => {
    const fake = await fakeDocker();
    await validateIsolatedNode(fixture(true, "prepared-hook"));
    await validateIsolatedNode(fixture(true));
    const calls = await fake.calls();
    const check = calls.find(({ args }) => args[0] === "create" && args.at(-1) === "check").args;
    const hook = calls.find(({ args }) => args[0] === "create" && args.at(-1) === "hook").args;
    expect(check[check.indexOf("--name") + 1]).not.toBe(hook[hook.indexOf("--name") + 1]);
    expect(calls.findIndex(({ args }) => args[0] === "rm" && args.at(-1).endsWith("-hook"))).toBeLessThan(calls.findIndex(({ args }) => args[0] === "create" && args.at(-1) === "check"));
    expect(check).toContainEqual(expect.stringContaining("/npm-cache:rw,nosuid,nodev,noexec,size="));
    expect(hook).toContainEqual(expect.stringContaining("/npm-cache:rw,nosuid,nodev,noexec,size="));
  }, 15_000);
  it("kills the active client and removes the actual named resource on cancellation", async () => {
    const fake = await fakeDocker({ hangAt: "start:check" }); const controller = new AbortController();
    const operation = validateIsolatedNode(fixture(), { signal: controller.signal });
    for (let attempt = 0; attempt < 200; attempt++) {
      await new Promise((resolve) => setTimeout(resolve, 10));
      if ((await fake.pollCalls()).some(({ args }) => args[0] === "start" && args.at(-1).endsWith("-check"))) break;
    }
    controller.abort(); await expect(operation).rejects.toThrow("cancelled");
    const calls = await fake.calls();
    expect(calls.some(({ args }) => args[0] === "rm" && args.at(-1).endsWith("-check"))).toBe(true);
    expect(calls.filter(({ args }) => args[0] === "volume" && args[1] === "rm")).toHaveLength(3);
  });
  it("enforces its own phase deadline and still removes the named container", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    const fake = await fakeDocker({ hangAt: "start:check" }); const controller = new AbortController();
    const operation = validateIsolatedNode(fixture(), { signal: controller.signal }).then(() => ({ passed: true, error: undefined }), (error: unknown) => ({ passed: false, error }));
    try {
      let attached = false; const until = Date.now() + 5000;
      while (Date.now() < until) {
        await new Promise<void>((resolve) => setImmediate(resolve));
        attached = (await fake.pollCalls()).some(({ args }) => args[0] === "start" && args.at(-1).endsWith("-check"));
        if (attached) break;
      }
      expect(attached).toBe(true);
      await vi.advanceTimersByTimeAsync(ISOLATION_LIMITS.phaseMs);
      const outcome = await operation;
      expect(outcome.passed).toBe(false); expect(outcome.error).toBeInstanceOf(Error);
      expect((outcome.error as Error).message).toContain("timed out");
      expect((await fake.calls()).some(({ args }) => args[0] === "rm" && args.at(-1).endsWith("-check"))).toBe(true);
    } finally { controller.abort(); vi.useRealTimers(); await operation; }
  }, 15_000);
  it("enforces its whole-operation deadline while a Docker client is active", async () => {
    const schedule = globalThis.setTimeout;
    const wholeDelays: number[] = []; let expire: (() => void) | undefined;
    vi.spyOn(globalThis, "setTimeout").mockImplementation(((callback: (...args: unknown[]) => void, delay?: number, ...args: unknown[]) => {
      if (delay !== undefined && delay > ISOLATION_LIMITS.phaseMs) {
        wholeDelays.push(delay); expire = () => callback(...args);
      }
      return schedule(callback, delay, ...args);
    }) as typeof setTimeout);
    const fake = await fakeDocker({ hangAt: "start:check" }); const controller = new AbortController();
    const operation = validateIsolatedNode(fixture(), { signal: controller.signal })
      .then(() => ({ passed: true, error: undefined }), (error: unknown) => ({ passed: false, error }));
    try {
      let attached = false; const until = performance.now() + 5000;
      while (performance.now() < until) {
        await new Promise<void>((resolve) => setImmediate(resolve));
        attached = (await fake.pollCalls()).some(({ args }) => args[0] === "start" && args.at(-1).endsWith("-check"));
        if (attached) break;
      }
      expect(attached).toBe(true); expect(wholeDelays).toHaveLength(1);
      expect(wholeDelays[0]).toBeGreaterThan(ISOLATION_LIMITS.operationMs - 1000);
      expect(wholeDelays[0]).toBeLessThanOrEqual(ISOLATION_LIMITS.operationMs);
      expect(expire).toBeTypeOf("function"); expire!();
      const result = await operation;
      expect(result.passed).toBe(false); expect(result.error).toBeInstanceOf(Error);
      expect((result.error as Error).message).toMatch(/operation.*timed out/i);
      const calls = await fake.calls();
      expect(calls.some(({ args }) => args[0] === "rm" && args.at(-1).endsWith("-check"))).toBe(true);
      expect(calls.some(({ args }) => args[0] === "rm" && args.at(-1).endsWith("-storage"))).toBe(true);
      expect(calls.filter(({ args }) => args[0] === "volume" && args[1] === "rm")).toHaveLength(3);
    } finally { controller.abort(); await operation; }
  }, 15_000);
  it.each(["caller cancellation", "watchdog expiry", "elapsed deadline"] as const)("rejects %s during cleanup while attempting every removal", async (event) => {
    const schedule = globalThis.setTimeout, clear = globalThis.clearTimeout;
    let watchdog: ReturnType<typeof setTimeout> | undefined, active = false, expire: (() => void) | undefined;
    vi.spyOn(globalThis, "setTimeout").mockImplementation(((callback: (...args: unknown[]) => void, delay?: number, ...args: unknown[]) => {
      const timer = schedule(callback, delay, ...args);
      if (delay !== undefined && delay > ISOLATION_LIMITS.phaseMs) {
        watchdog = timer; active = true; expire = () => { if (active) callback(...args); };
      }
      return timer;
    }) as typeof setTimeout);
    vi.spyOn(globalThis, "clearTimeout").mockImplementation(((timer: Parameters<typeof clearTimeout>[0]) => {
      if (timer === watchdog) active = false;
      return clear(timer);
    }) as typeof clearTimeout);
    const start = Date.now();
    const clock = event === "elapsed deadline" ? vi.spyOn(Date, "now").mockReturnValue(start) : undefined;
    const fake = await fakeDocker({ holdCleanup: true }); const controller = new AbortController();
    const operation = validateIsolatedNode(fixture(), { signal: controller.signal })
      .then(() => ({ passed: true, error: undefined }), (error: unknown) => ({ passed: false, error }));
    try {
      let cleaning = false; const until = performance.now() + 5000;
      while (performance.now() < until) {
        await new Promise<void>((resolve) => setImmediate(resolve));
        cleaning = (await fake.pollCalls()).some(({ args }) => args[0] === "rm" && args.at(-1).endsWith("-storage"));
        if (cleaning) break;
      }
      expect(cleaning).toBe(true); const guardedDuringCleanup = active;
      if (event === "caller cancellation") controller.abort();
      else if (event === "watchdog expiry") { expect(expire).toBeTypeOf("function"); expire!(); }
      else clock!.mockReturnValue(start + ISOLATION_LIMITS.operationMs);
      await fake.releaseCleanup();
      const outcome = await operation;
      expect(outcome.passed).toBe(false); expect(outcome.error).toBeInstanceOf(Error);
      expect((outcome.error as Error).message).toMatch(event === "caller cancellation" ? /cancelled/ : /operation.*timed out/i);
      expect(guardedDuringCleanup).toBe(true); expect(active).toBe(false);
      const calls = await fake.calls();
      const created = calls.filter(({ args }) => args[0] === "create").map(({ args }) => args[args.indexOf("--name") + 1]);
      expect(calls.filter(({ args }) => args[0] === "rm").map(({ args }) => args.at(-1))).toEqual(expect.arrayContaining(created));
      expect(calls.filter(({ args }) => args[0] === "volume" && args[1] === "rm")).toHaveLength(3);
      await expect(access(calls[0]!.cwd)).rejects.toThrow();
    } finally { await fake.releaseCleanup(); controller.abort(); await operation; }
  }, 15_000);
  it("keeps the original failure when Docker cleanup also fails", async () => {
    await fakeDocker({ failAt: "start:check", cleanupFailure: true });
    await expect(validateIsolatedNode(fixture())).rejects.toThrow(/Isolated phase.*Cleanup failed/);
  });
  it("enforces the retained-output bound and still cleans up", async () => {
    const fake = await fakeDocker({ excessiveOutput: true });
    await expect(validateIsolatedNode(fixture())).rejects.toThrow("output exceeded");
    expect((await fake.calls()).some(({ args }) => args[0] === "rm" && args.at(-1).endsWith("-check"))).toBe(true);
  });
  it("rejects missing jq evidence before either repository-controlled phase and cleans resources", async () => {
    for (const phase of ["prepared-hook", "final-check"] as const) {
      const fake = await fakeDocker({ missingJq: true });
      await expect(validateIsolatedNode(fixture(true, phase))).rejects.toThrow("Toolchain preparation evidence is invalid");
      const calls = await fake.calls();
      expect(calls.some(({ args }) => args[0] === "start" && /-(hook|check)$/.test(args.at(-1)))).toBe(false);
      const prepareRemoved = calls.findIndex(({ args }) => args[0] === "rm" && args.at(-1).endsWith("-prepare"));
      const keeperRemoved = calls.findIndex(({ args }) => args[0] === "rm" && args.at(-1).endsWith("-storage"));
      const volumeRemovals = calls.flatMap(({ args }, index) => args[0] === "volume" && args[1] === "rm" ? [index] : []);
      expect(prepareRemoved).toBeGreaterThanOrEqual(0); expect(keeperRemoved).toBeGreaterThan(prepareRemoved);
      expect(volumeRemovals).toHaveLength(3); expect(Math.min(...volumeRemovals)).toBeGreaterThan(keeperRemoved);
    }
  }, 15_000);
  it("rejects invalid setup evidence and incompatible Docker platforms", async () => {
    await fakeDocker({ platform: "linux/arm64" });
    await expect(validateIsolatedNode(fixture())).rejects.toThrow("supported platform");
    await fakeDocker({ invalidEvidence: true });
    await expect(validateIsolatedNode(fixture())).rejects.toThrow();
  });
  it("blocks unsupported supervisors, absent Docker, and already-cancelled requests", async () => {
    Object.defineProperty(process, "platform", { value: "darwin" });
    await expect(validateIsolatedNode(fixture())).rejects.toThrow("Linux/amd64");
    Object.defineProperty(process, "platform", { value: "linux" }); Object.defineProperty(process, "arch", { value: "x64" }); process.env.PATH = ".";
    await expect(validateIsolatedNode(fixture())).rejects.toThrow("trusted Docker CLI is unavailable");
    const controller = new AbortController(); controller.abort();
    await expect(validateIsolatedNode(fixture(), { signal: controller.signal })).rejects.toHaveProperty("name", "AbortError");
  });
  it("does not execute a repository-controlled Docker shadow from PATH", async () => {
    const fake = await fakeDocker(); transport.unavailable = true;
    await expect(validateIsolatedNode(fixture())).rejects.toThrow("trusted Docker CLI is unavailable");
    expect(await fake.calls()).toEqual([]);
  });
  it.each([{ untrustedUid: 1000 }, { untrustedMode: 0o100775 }, { untrustedAncestor: true }])("blocks a non-root or writable tool chain before execution: %j", async (options) => {
    const fake = await fakeDocker(options);
    await expect(validateIsolatedNode(fixture())).rejects.toThrow("trusted Docker CLI is unavailable");
    expect(await fake.calls()).toEqual([]);
  });
  it("parses the fixed helper without executing repository code on the host", () => expect(() => new Script(CONTAINER_SETUP)).not.toThrow());
});
