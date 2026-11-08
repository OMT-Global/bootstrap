import { lstat, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeAll, describe, expect, it } from "vitest";
import { boundedCommand, HOST_LIMITS, neutralEnvironment, PRLIMIT_ARGS, requireLinuxHost, trustedExecutable } from "../src/upgrade-host.js";

// These tests execute real kernel controls, with no proc, UID, spawn, or tool mocks.
// Run on a dedicated unprivileged Linux x64 runner:
// BOOTSTRAP_REQUIRE_HOST_BROKER_TESTS=1 npm test -- tests/upgrade-host-linux.test.ts
// The flag requires the profile; it never downgrades a missing prerequisite to a skip.
const required = process.env.BOOTSTRAP_REQUIRE_HOST_BROKER_TESTS === "1";
const linux = process.platform === "linux";
const directories: string[] = [];
const operations: { controller: AbortController; settled: Promise<unknown> }[] = [];
const fixed = "Governed upgrade host operation is unsupported.";
let tools: { git: string; prlimit: string };
let python: string;

it.skipIf(!required)("requires actual Linux x64, trusted tools, zero capabilities and a nonroot eligible UID when host proof is mandatory", async () => {
  expect(process.platform, "Mandatory host enforcement proof requires Linux; Darwin flow tests cannot satisfy it.").toBe("linux");
  tools = await requireLinuxHost(); python = await trustedExecutable("/usr/bin/python3");
  expect(tools.prlimit).toBeTruthy(); expect(python).toBeTruthy();
});

afterEach(async () => {
  for (const operation of operations) operation.controller.abort();
  await Promise.all(operations.splice(0).map((operation) => operation.settled));
  await Promise.all(directories.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

// Explicit Darwin/other-platform skip is independent of the fail-closed mandatory
// preflight above. Expensive CPU and 90-second wall proofs run only on request.
describe.skipIf(!required || !linux)("actual Linux prlimit enforcement (explicit opt-in)", () => {
  beforeAll(async () => { tools = await requireLinuxHost(); python = await trustedExecutable("/usr/bin/python3"); });
  async function fixture(source: string) {
    const root = await mkdtemp(path.join(os.tmpdir(), "bootstrap-host-linux-test-")); directories.push(root);
    const script = path.join(root, "fixture.py"); await writeFile(script, source, { mode: 0o600 });
    const run = (args: string[] = []) => {
      const controller = new AbortController();
      const pending = boundedCommand(tools.prlimit, [...PRLIMIT_ARGS, python, "-I", "-S", script, ...args],
        { cwd: root, env: neutralEnvironment(root, root), signal: controller.signal });
      operations.push({ controller, settled: pending.catch(() => {}) });
      return pending;
    };
    return { root, script, run };
  }

  it("sets exact hard/soft limits that survive exec into an inherited child", async () => {
    const source = `import json, resource, subprocess, sys
names = ['FSIZE','CPU','AS','NOFILE','NPROC','CORE']
own = {name: resource.getrlimit(getattr(resource, 'RLIMIT_' + name)) for name in names}
child = subprocess.check_output([sys.executable, '-I', '-S', '-c', 'import json,resource; print(json.dumps({n:resource.getrlimit(getattr(resource,"RLIMIT_"+n)) for n in ["FSIZE","CPU","AS","NOFILE","NPROC","CORE"]}))'])
print(json.dumps({'parent': own, 'child': json.loads(child)}))
`;
    const { run } = await fixture(source); const result = JSON.parse((await run()).toString());
    const expected = { FSIZE: [67108864, 67108864], CPU: [60, 60], AS: [1073741824, 1073741824], NOFILE: [64, 64], NPROC: [128, 128], CORE: [0, 0] };
    expect(result).toEqual({ parent: expected, child: expected });
  });

  it("stops a real file write at 64 MiB and preserves an unrelated fixture", async () => {
    const { root, run } = await fixture(`import errno, json, os, sys
fd = os.open(sys.argv[1], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
try:
    while True: os.write(fd, b'x' * 65536)
except OSError as error:
    print(json.dumps({'errno': error.errno, 'bytes': os.fstat(fd).st_size}))
finally: os.close(fd)
`);
    const canary = path.join(root, "preserved"); await writeFile(canary, "public disposable canary");
    const file = path.join(root, "bounded-output"); const result = JSON.parse((await run([file])).toString());
    expect(result).toEqual({ errno: 27, bytes: 67108864 }); expect((await lstat(file)).size).toBe(67108864);
    expect(await readFile(canary, "utf8")).toBe("public disposable canary");
  }, 20_000);

  it("denies an address mapping beyond the actual inherited address-space ceiling", async () => {
    const { run } = await fixture(`import json, mmap, resource
limit = resource.getrlimit(resource.RLIMIT_AS)
try:
    memory = mmap.mmap(-1, 2 * limit[0])
except (OSError, MemoryError): print(json.dumps({'denied': True, 'limits': limit}))
else:
    memory.close()
    raise RuntimeError('address ceiling was not enforced')
`);
    expect(JSON.parse((await run()).toString())).toEqual({ denied: true, limits: [1073741824, 1073741824] });
  });

  it("returns EMFILE before accepting descriptors above the inherited ceiling", async () => {
    const { run } = await fixture(`import errno, json, os, resource
files = []
try:
    while len(files) < 128: files.append(os.open('/dev/null', os.O_RDONLY))
except OSError as error:
    print(json.dumps({'errno': error.errno, 'opened': len(files), 'limits': resource.getrlimit(resource.RLIMIT_NOFILE)}))
finally:
    for fd in files: os.close(fd)
`);
    const result = JSON.parse((await run()).toString()); expect(result.errno).toBe(24);
    expect(result.opened).toBeGreaterThan(0); expect(result.opened).toBeLessThan(64); expect(result.limits).toEqual([64, 64]);
  });

  it("enforces real-UID NPROC and reaps every disposable child", async () => {
    // Root/capability rejection comes from the actual eligibility preflight; the
    // suite never changes UID, acquires capabilities, or raises caller ceilings.
    await requireLinuxHost();
    const { run } = await fixture(`import errno, json, os, resource, signal
children = []
failure = None
try:
    for attempt in range(129):
        try: child = os.fork()
        except OSError as error:
            failure = error.errno
            break
        if child == 0:
            signal.pause()
            os._exit(0)
        children.append(child)
finally:
    for child in children:
        try: os.kill(child, signal.SIGKILL)
        except ProcessLookupError: pass
    for child in children: os.waitpid(child, 0)
print(json.dumps({'errno': failure, 'spawned': len(children), 'reaped': len(children), 'limits': resource.getrlimit(resource.RLIMIT_NPROC)}))
`);
    const result = JSON.parse((await run()).toString()); expect(result.errno).toBe(11);
    expect(result.spawned).toBeGreaterThan(0); expect(result.spawned).toBeLessThan(128);
    expect(result.reaped).toBe(result.spawned); expect(result.limits).toEqual([128, 128]);
  }, 20_000);

  it("kills real CPU exhaustion under the fixed 60-second hard ceiling", async () => {
    const { run } = await fixture(`import json, os, resource, signal
child = os.fork()
if child == 0:
    while True: pass
_, status = os.waitpid(child, 0)
usage = resource.getrusage(resource.RUSAGE_CHILDREN)
print(json.dumps({'signal': os.WTERMSIG(status) if os.WIFSIGNALED(status) else None, 'cpu': usage.ru_utime + usage.ru_stime}))
`);
    // The waiting parent succeeds only after observing its child's actual CPU
    // signal. A wall timeout or unrelated process failure cannot satisfy this.
    const result = JSON.parse((await run()).toString()); expect(result.signal).toBe(9);
    expect(result.cpu).toBeGreaterThanOrEqual(59); expect(result.cpu).toBeLessThan(65);
  }, 100_000);

  it("enforces the real wall deadline and kills an inherited idle descendant", async () => {
    const { root, run } = await fixture(`import os, sys, time
child = os.fork()
if child == 0:
    with open(sys.argv[1], 'w') as ready: ready.write(str(os.getpid()))
    time.sleep(95)
    with open(sys.argv[2], 'w') as escaped: escaped.write('survived deadline')
else: time.sleep(120)
`);
    const ready = path.join(root, "ready"); const escaped = path.join(root, "escaped"); const start = Date.now();
    const pending = run([ready, escaped]).catch((error: unknown) => error);
    // Wait only for this disposable child, without polling unrelated processes.
    for (let attempt = 0; attempt < 100; attempt++) {
      try { await readFile(ready); break; } catch { await new Promise((resolve) => setTimeout(resolve, 20)); }
    }
    const descendant = Number(await readFile(ready, "utf8")); expect(descendant).toBeGreaterThan(0);
    expect(await pending).toEqual(new Error(fixed)); expect(Date.now() - start).toBeGreaterThanOrEqual(HOST_LIMITS.wallMs - 500);
    expect(Date.now() - start).toBeLessThan(HOST_LIMITS.wallMs + 10_000);
    // Containers with a non-reaping PID 1 may retain an exited orphan as a
    // zombie. An absent or zombie process is stopped; a sleeping one is not.
    try { expect(await readFile(`/proc/${descendant}/status`, "utf8")).toMatch(/^State:\s+Z\b/m); }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
    await expect(readFile(escaped)).rejects.toMatchObject({ code: "ENOENT" });
  }, 105_000);
});
