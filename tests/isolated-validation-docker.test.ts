import { execFile, spawn } from "node:child_process";
import { access, lstat, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { constants } from "node:fs";
import { randomUUID } from "node:crypto";
import { createServer, type Server } from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { stripVTControlCharacters } from "node:util";

import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

import { redactPublicText } from "../src/provenance.js";
import { validateIsolatedNode } from "../src/isolation/node-validation.js";
import { freezeNodeValidation, NODE_ISOLATION_IMAGE, NODE_ISOLATION_PROFILE, type IsolatedSourceFile,
  type NodeValidationInput } from "../src/isolation/node-profile.js";

interface DockerDiagnostic {
  operation: string; phase: string; code: number | null; signal: NodeJS.Signals | null; tail: Buffer;
}
const diagnostics = vi.hoisted(() => ({ active: false, session: 0, records: [] as DockerDiagnostic[] }));
vi.mock("node:child_process", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:child_process")>();
  return { ...actual, spawn: (executable: string, args: readonly string[], options: import("node:child_process").SpawnOptions) => {
    const child = actual.spawn(executable, args, options);
    if (!diagnostics.active) return child;
    const session = diagnostics.session;
    const verb = args[0] === "--host" && args[2] === "--config" ? args[4] : undefined;
    const operation = ["version", "image", "volume", "create", "inspect", "cp", "start", "rm"].includes(verb ?? "") ? verb! : "process";
    const name = args.find((value) => /^bootstrap-isolation-[a-f0-9-]+-(prepare|hook|check|storage)$/.test(value));
    const phase = name?.match(/-(prepare|hook|check|storage)$/)?.[1] ?? "none";
    const attached = operation === "start" && args[5] === "--attach";
    let tail = Buffer.alloc(0);
    const take = (chunk: Buffer) => { tail = Buffer.from(Buffer.concat([tail, chunk]).subarray(-64 * 1024)); };
    child.stdout?.on("data", take); child.stderr?.on("data", take);
    child.once("close", (code, signal) => {
      if (!diagnostics.active || diagnostics.session !== session || (!attached && code === 0 && signal === null)) return;
      diagnostics.records.push({ operation, phase, code, signal, tail });
      if (diagnostics.records.length > 4) diagnostics.records.shift();
    });
    return child;
  } };
});
function diagnosticLine(record: DockerDiagnostic): string {
  const cleaned = stripVTControlCharacters(record.tail.toString("utf8")).replace(/[\u0000-\u001f\u007f-\u009f]/g, "");
  let tail = Buffer.from(redactPublicText(cleaned).value);
  const render = () => `ISOLATION_DOCKER_DIAGNOSTIC ${JSON.stringify({ operation: record.operation, phase: record.phase,
    code: record.code, signal: record.signal, tail: tail.toString("utf8") })}`;
  let line = render();
  while (Buffer.byteLength(line) > 16 * 1024) { tail = tail.subarray(Math.max(1, Math.ceil(tail.length / 8))); line = render(); }
  return line;
}
async function withDockerDiagnostics<T>(action: () => Promise<T>): Promise<T> {
  if (diagnostics.active) throw new Error("Diagnostic observation cannot nest.");
  diagnostics.active = true; diagnostics.session += 1; diagnostics.records = [];
  try { return await action(); }
  catch (error) {
    try { for (const record of diagnostics.records) console.error(diagnosticLine(record)); }
    catch { /* Diagnostic rendering or an unavailable console must preserve the backend failure. */ }
    throw error;
  }
  finally { diagnostics.active = false; diagnostics.records = []; }
}

it("observes actual child failures without altering exit status and bounds sanitized diagnostic output", async () => {
  const failure = new Error("Synthetic positive target failed.");
  const printed = vi.spyOn(console, "error").mockImplementation(() => {});
  let retained: DockerDiagnostic[] = [];
  try {
    await expect(withDockerDiagnostics(async () => {
      for (let index = 0; index < 5; index += 1) {
        const script = index < 4 ? `process.stdout.write('discarded-${index}');process.exitCode=23;` :
          String.raw`process.stdout.write('x'.repeat(96*1024),()=>{process.stderr.write('\u001b[31mvisible\u001b[0m\u0000 token=synthetic-fixture-only end');process.exitCode=23;});`;
        const exit = await new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve, reject) => {
          const child = spawn(process.execPath, ["-e", script], { cwd: os.tmpdir(), env: { PATH: "/usr/bin:/bin", HOME: os.tmpdir() },
            stdio: ["ignore", "pipe", "pipe"] });
          child.once("error", reject); child.once("close", (code, signal) => resolve({ code, signal }));
        });
        expect(exit).toEqual({ code: 23, signal: null });
      }
      retained = diagnostics.records.slice();
      expect(retained).toHaveLength(4); expect(retained.at(-1)!.tail.length).toBe(64 * 1024);
      expect(retained.every((record) => record.code === 23 && record.signal === null)).toBe(true);
      throw failure;
    })).rejects.toBe(failure);
    expect(printed).toHaveBeenCalledTimes(4);
    for (const call of printed.mock.calls) {
      expect(call).toHaveLength(1); const line = String(call[0]);
      expect(Buffer.byteLength(line)).toBeLessThanOrEqual(16 * 1024);
      expect(line).toMatch(/^ISOLATION_DOCKER_DIAGNOSTIC /);
      const record = JSON.parse(line.slice("ISOLATION_DOCKER_DIAGNOSTIC ".length));
      expect(record).toMatchObject({ operation: "process", phase: "none", code: 23, signal: null });
      expect(record.tail).not.toMatch(/[\u0000-\u001f\u007f-\u009f]/); expect(record.tail).not.toContain("[31m");
      expect(record.tail).not.toContain("synthetic-fixture-only");
    }
    expect(String(printed.mock.calls.at(-1)![0])).toContain("[REDACTED:CREDENTIAL]");
    expect(diagnostics.active).toBe(false); expect(diagnostics.records).toHaveLength(0);
    printed.mockImplementationOnce(() => { throw new Error("Synthetic diagnostic sink failure."); });
    await expect(withDockerDiagnostics(async () => {
      diagnostics.records.push(retained.at(-1)!); throw failure;
    })).rejects.toBe(failure);
    expect(diagnostics.active).toBe(false); expect(diagnostics.records).toHaveLength(0);
  } finally { printed.mockRestore(); }
}, 10_000);

const required = process.env.BOOTSTRAP_REQUIRE_ISOLATION_TESTS === "1";
const checkout = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const dirs: string[] = [];
const servers: Server[] = [];
const originalChecks: Array<() => Promise<void>> = [];
const candidateTrees = new Map<string, string>();
let docker = "";
let toolsHome = "";
let beforeResources: { containers: string[]; volumes: string[] };
const maxOutput = 8 * 1024 * 1024;
const timeout = 20 * 60_000;

function environment(home: string): NodeJS.ProcessEnv {
  return { PATH: "/usr/local/bin:/usr/bin:/bin", HOME: home, GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_SYSTEM: "/dev/null",
    GIT_CONFIG_GLOBAL: "/dev/null", GIT_ATTR_NOSYSTEM: "1", GIT_TERMINAL_PROMPT: "0", GIT_AUTHOR_NAME: "Isolation Fixture",
    GIT_AUTHOR_EMAIL: "isolation-fixture@example.invalid", GIT_COMMITTER_NAME: "Isolation Fixture",
    GIT_COMMITTER_EMAIL: "isolation-fixture@example.invalid" };
}
async function command(binary: string, args: string[], cwd = toolsHome, input?: string | Buffer, extraEnvironment?: Record<string, string>): Promise<string> {
  const child = execFile(binary, args, { cwd, env: { ...environment(toolsHome), ...extraEnvironment }, encoding: "utf8", maxBuffer: maxOutput,
    timeout: 60_000 });
  const result = new Promise<string>((resolve, reject) => {
    let text = ""; let error = "";
    child.stdout!.on("data", (chunk) => { text += chunk; });
    child.stderr!.on("data", (chunk) => { error += chunk; });
    child.once("error", reject);
    child.once("close", (code) => code === 0 ? resolve(text) : reject(new Error(`Fixture command failed (${code}): ${error.slice(0, 1024)}`)));
  });
  if (input !== undefined) child.stdin!.end(input); else child.stdin!.end();
  return result;
}
const git = (cwd: string, args: string[], input?: string | Buffer, plan?: Pick<NodeValidationInput, "author" | "committer">) => command("/usr/bin/git", ["-c", "core.hooksPath=/dev/null",
  "-c", "core.fsmonitor=false", "-c", "core.attributesFile=/dev/null", "-c", "commit.gpgsign=false", "-c", "gc.auto=0", ...args], cwd, input,
  plan ? { GIT_AUTHOR_NAME: plan.author.name, GIT_AUTHOR_EMAIL: plan.author.email, GIT_AUTHOR_DATE: `@${plan.author.date}`,
    GIT_COMMITTER_NAME: plan.committer.name, GIT_COMMITTER_EMAIL: plan.committer.email, GIT_COMMITTER_DATE: `@${plan.committer.date}` } : undefined);
function identities(): Pick<NodeValidationInput, "author" | "committer"> {
  return { author: { name: "Isolation Fixture", email: "isolation-fixture@example.invalid", date: "1767225600 +0000" },
    committer: { name: "Isolation Fixture Committer", email: "isolation-committer@example.invalid", date: "1767225660 +0000" } };
}
const dockerCommand = (args: string[]) => command(docker, ["--host", "unix:///var/run/docker.sock", "--config", path.join(toolsHome, "docker"), ...args]);
const lines = (value: string) => value.trim().split("\n").filter(Boolean).sort();
async function resources() {
  const [containers, volumes] = await Promise.all([
    dockerCommand(["ps", "--all", "--filter", "label=bootstrap.isolation", "--format", "{{.Names}}"]),
    dockerCommand(["volume", "ls", "--filter", "label=bootstrap.isolation", "--format", "{{.Name}}"])
  ]);
  return { containers: lines(containers), volumes: lines(volumes) };
}
async function directory(): Promise<string> {
  const value = await mkdtemp(path.join(os.tmpdir(), "bootstrap-docker-fixture-")); dirs.push(value); return value;
}
function file(name: string, text: string, executable = false): IsolatedSourceFile {
  return { path: name, mode: executable ? "100755" : "100644", bytes: Buffer.from(text) };
}
async function fixture(): Promise<{ input: NodeValidationInput; original: string }> {
  const original = await directory();
  const baseFiles = [file("README.md", "public base\n"),
    file("package.json", '{"name":"isolation-fixture","version":"1.0.0","private":true}\n'),
    file("package-lock.json", '{"name":"isolation-fixture","version":"1.0.0","lockfileVersion":3,"packages":{"":{"name":"isolation-fixture","version":"1.0.0"}}}\n'),
    file("scripts/ci/run-fast-checks.sh", "#!/bin/bash\nset -euo pipefail\nnpm ci --offline --ignore-scripts --no-audit --no-fund\nprintf 'minimal fixture passed\n'\n", true)];
  const empty = path.join(original, "empty-template"); await mkdir(empty);
  await git(original, ["init", "-q", "--initial-branch=codex/public-base", `--template=${empty}`]);
  for (const entry of baseFiles) {
    await mkdir(path.dirname(path.join(original, entry.path)), { recursive: true });
    await writeFile(path.join(original, entry.path), entry.bytes, { mode: entry.mode === "100755" ? 0o755 : 0o644 });
  }
  await git(original, ["add", "--", ...baseFiles.map((entry) => entry.path)]);
  await git(original, ["commit", "-q", "--signoff", "-m", "test: create public isolation fixture"]);
  const baseCommit = (await git(original, ["rev-parse", "HEAD"])).trim();
  const bundle = path.join(original, "base.bundle"); await git(original, ["bundle", "create", bundle, "HEAD"]);
  const originalIndex = await readFile(path.join(original, ".git/index"));
  const originalHead = await readFile(path.join(original, ".git/HEAD"));
  originalChecks.push(async () => {
    for (const entry of baseFiles) expect(await readFile(path.join(original, entry.path))).toEqual(Buffer.from(entry.bytes));
    expect(await readFile(path.join(original, ".git/index"))).toEqual(originalIndex);
    expect(await readFile(path.join(original, ".git/HEAD"))).toEqual(originalHead);
  });
  const files: IsolatedSourceFile[] = baseFiles.map((entry) => ({ ...entry, bytes: Buffer.from(entry.bytes) }));
  files[0] = file("README.md", "prepared public source\n");
  return { original, input: { profile: NODE_ISOLATION_PROFILE, phase: "prepared-hook", ...identities(), files, baseBundle: await readFile(bundle), baseCommit,
    branch: "codex/isolation-fixture", commitMessage: "test: validate prepared source\n\nSigned-off-by: Isolation Fixture <isolation-fixture@example.invalid>\n", hook: "none" } };
}
function replace(input: NodeValidationInput, entry: IsolatedSourceFile): void {
  const files = input.files as IsolatedSourceFile[];
  const index = files.findIndex((existing) => existing.path === entry.path);
  if (index < 0) files.push(entry); else files[index] = entry;
}
async function finalCandidate(input: NodeValidationInput): Promise<NodeValidationInput & { phase: "final-check"; candidateCommit: string }> {
  const target = await directory(); const empty = path.join(target, "empty-template"); await mkdir(empty);
  await git(target, ["init", "-q", `--template=${empty}`]);
  const publicBase = path.join(target, "base.bundle"); await writeFile(publicBase, input.baseBundle);
  await git(target, ["fetch", "-q", "--no-tags", publicBase, input.baseCommit]);
  let index = "";
  for (const entry of input.files) {
    const oid = (await git(target, ["hash-object", "-w", "--stdin", "--no-filters"], Buffer.from(entry.bytes))).trim();
    index += `${entry.mode} ${oid}\t${entry.path}\0`;
  }
  await git(target, ["update-index", "-z", "--index-info"], index);
  const tree = (await git(target, ["write-tree"])).trim();
  const candidateCommit = (await git(target, ["commit-tree", tree, "-p", input.baseCommit], input.commitMessage, input)).trim();
  candidateTrees.set(candidateCommit, tree);
  await git(target, ["update-ref", "refs/heads/isolated-candidate", candidateCommit]);
  const bundle = path.join(target, "candidate.bundle"); await git(target, ["bundle", "create", bundle, "refs/heads/isolated-candidate"]);
  return { ...input, phase: "final-check", candidateCommit, baseBundle: await readFile(bundle) };
}
async function waitFor(action: () => Promise<boolean>, milliseconds = 90_000): Promise<void> {
  const until = Date.now() + milliseconds;
  while (Date.now() < until) { if (await action()) return; await new Promise((resolve) => setTimeout(resolve, 250)); }
  throw new Error("Timed out waiting for the actual isolated check phase.");
}

// Ordinary local suites skip actual Docker work. The manual workflow sets the required flag;
// then unsupported host, missing daemon/image, or unavailable probes fail before any test can pass.
describe.skipIf(!required)("actual isolated Node Docker backend", () => {
  beforeAll(async () => {
    expect(process.platform, "The required suite needs a Linux supervisor.").toBe("linux");
    expect(process.arch, "The required suite needs an amd64 supervisor.").toBe("x64");
    toolsHome = await mkdtemp(path.join(os.tmpdir(), "bootstrap-docker-harness-"));
    await mkdir(path.join(toolsHome, "docker"), { mode: 0o700 });
    for (const entry of (process.env.PATH ?? "").split(path.delimiter).filter(path.isAbsolute)) {
      try { const candidate = path.join(entry, "docker"); await access(candidate, constants.X_OK); docker = await realpath(candidate); break; } catch { /* Probe trusted absolute paths only. */ }
    }
    expect(docker, "Required Docker CLI is missing; this is a failure, not a skipped test.").not.toBe("");
    expect((await dockerCommand(["version", "--format", "{{.Server.Os}}/{{.Server.Arch}}"])).trim()).toBe("linux/amd64");
    expect((await dockerCommand(["image", "inspect", "--format", "{{.Os}}/{{.Architecture}}", NODE_ISOLATION_IMAGE])).trim()).toBe("linux/amd64");
  }, 60_000);

  beforeEach(async () => { beforeResources = await resources(); });
  afterEach(async () => {
    try {
      for (const check of originalChecks.splice(0)) await check();
      if (docker && toolsHome && beforeResources) expect(await resources(), "The backend leaked Docker containers or volumes.").toEqual(beforeResources);
    } finally {
      // A failing cleanup assertion remains a failure; reap only new disposable test resources so later cases stay independent.
      if (docker && toolsHome && beforeResources) {
        const remaining = await resources();
        for (const name of remaining.containers.filter((value) => !beforeResources.containers.includes(value))) await dockerCommand(["rm", "--force", name]);
        for (const name of remaining.volumes.filter((value) => !beforeResources.volumes.includes(value))) await dockerCommand(["volume", "rm", "--force", name]);
      }
      for (const server of servers.splice(0)) await new Promise<void>((resolve) => server.close(() => resolve()));
      await Promise.all(dirs.splice(0).map((target) => rm(target, { recursive: true, force: true })));
      candidateTrees.clear(); vi.unstubAllEnvs();
    }
  }, 60_000);
  afterAll(async () => { if (toolsHome) await rm(toolsHome, { recursive: true, force: true }); });

  it("runs locked offline checks and required hooks without host credentials, files, sockets, egress, or writable source/index", async () => {
    const { input, original } = await fixture();
    const outside = await directory(); const canary = path.join(outside, "outside-canary"); const socket = path.join(outside, "agent.sock");
    await writeFile(canary, "unchanged host fixture\n");
    let connections = 0;
    const server = createServer((connection) => { connections += 1; connection.destroy(); }); servers.push(server);
    await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(socket, resolve); });
    const trap = path.join(outside, "host-git-trap"); const marker = path.join(outside, "host-git-ran");
    await writeFile(trap, `#!${process.execPath}\nrequire('node:fs').writeFileSync(${JSON.stringify(marker)}, 'unexpected host Git execution');\nprocess.exitCode = 1;\n`, { mode: 0o755 });
    await mkdir(path.join(original, ".git/info"), { recursive: true });
    await writeFile(path.join(original, ".git/info/attributes"), "* filter=canary diff=canary\n");
    const oldConfig = await readFile(path.join(original, ".git/config"), "utf8");
    await writeFile(path.join(original, ".git/config"), `${oldConfig}\n[core]\n\tfsmonitor = ${trap}\n\thooksPath = ${outside}\n[filter "canary"]\n\tclean = ${trap}\n\tsmudge = ${trap}\n[diff "canary"]\n\ttextconv = ${trap}\n[credential]\n\thelper = !${trap}\n[url "ext::${trap}"]\n\tinsteadOf = https://fixture.invalid/\n`);
    vi.stubEnv("GH_TOKEN", `fabricated-${randomUUID()}`); vi.stubEnv("SSH_AUTH_SOCK", socket);
    vi.stubEnv("BOOTSTRAP_FLEET_CANARY", `fabricated-${randomUUID()}`);
    const probe = `const assert = require('node:assert/strict'), fs = require('node:fs'), net = require('node:net'), dns = require('node:dns'), cp = require('node:child_process');
(async () => {
  assert.equal(process.getuid(), 1000);
  for (const name of ['GH_TOKEN', 'SSH_AUTH_SOCK', 'BOOTSTRAP_FLEET_CANARY', 'BOOTSTRAP_REQUIRE_ISOLATION_TESTS']) assert.equal(process.env[name], undefined);
  for (const name of [${JSON.stringify(canary)}, ${JSON.stringify(socket)}, '/var/run/docker.sock']) assert.throws(() => fs.readFileSync(name));
  assert.throws(() => fs.writeFileSync(${JSON.stringify(canary)}, 'changed'));
  for (const name of ['README.md', '.git/index']) assert.throws(() => fs.writeFileSync(name, 'changed'), error => ['EROFS', 'EACCES', 'EPERM'].includes(error.code));
  assert.equal(fs.existsSync('/npm-cache/installer-lifecycle-ran'), false);
  assert.equal(require('picocolors').createColors(false).red('fixture'), 'fixture');
  console.log('ISOLATED-LOCKED-DEPENDENCY-PASSED:' + process.argv[2]);
  assert.equal(cp.execFileSync('./node_modules/.bin/tsc', ['--version'], {encoding:'utf8'}).trim(), 'Version 5.9.3');
  console.log('ISOLATED-LOCKED-BIN-PASSED:' + process.argv[2]);
  const temporaryHelperDir = fs.mkdtempSync('/tmp/isolation-helper-');
  try {
    const helper = temporaryHelperDir + '/helper';
    fs.writeFileSync(helper, '#!' + process.execPath + String.fromCharCode(10) + 'process.stdout.write(JSON.stringify({phase:process.argv[2],uid:process.getuid()}));', {mode:0o755});
    fs.chmodSync(helper, 0o755);
    assert.equal(fs.statSync(helper).uid, 1000);
    assert.deepEqual(JSON.parse(cp.execFileSync(helper, [process.argv[2]], {encoding:'utf8'})), {phase:process.argv[2],uid:1000});
  } finally { fs.rmSync(temporaryHelperDir, {recursive:true,force:true}); }
  console.log('ISOLATED-TEMPORARY-EXEC-PASSED:' + process.argv[2]);
  const capabilities = fs.readFileSync('/proc/self/status', 'utf8').split(String.fromCharCode(10)).find(line => line.startsWith('CapEff:'));
  assert.equal(capabilities.split(':')[1].trim(), '0000000000000000');
  assert.equal(cp.execFileSync('git', ['symbolic-ref', '--short', 'HEAD'], {encoding:'utf8'}).trim(), 'codex/isolation-fixture');
  if (process.argv[2] === 'hook') {
    const planned = ${JSON.stringify({author: input.author, committer: input.committer})};
    assert.equal(process.env.GIT_INDEX_FILE, '.git/index');
    assert.equal(process.env.GIT_PREFIX, '');
    assert.equal(process.env.GIT_EDITOR, ':');
    for (const kind of ['author', 'committer']) {
      for (const field of ['name', 'email', 'date']) {
        const variableName = 'GIT_' + kind.toUpperCase() + '_' + field.toUpperCase();
        assert.equal(process.env[variableName], (field === 'date' ? '@' : '') + planned[kind][field]);
      }
      assert.equal(cp.execFileSync('git', ['var', 'GIT_' + kind.toUpperCase() + '_IDENT'], {encoding:'utf8'}).trim(), planned[kind].name + ' <' + planned[kind].email + '> ' + planned[kind].date);
    }
    assert.equal(cp.execFileSync('git', ['config', '--local', '--get', 'user.name'], {encoding:'utf8'}).trim(), planned.committer.name);
    assert.equal(cp.execFileSync('git', ['config', '--local', '--get', 'user.email'], {encoding:'utf8'}).trim(), planned.committer.email);
    console.log('ISOLATED-HOOK-CONTEXT-PASSED');
    assert.equal(cp.execFileSync('git', ['rev-parse', 'HEAD'], {encoding:'utf8'}).trim(), ${JSON.stringify(input.baseCommit)});
    assert(cp.execFileSync('git', ['diff', '--cached', '--name-only', '-z', 'HEAD'], {encoding:'utf8'}).split(String.fromCharCode(0)).includes('README.md'));
  } else {
    assert.equal(cp.execFileSync('git', ['diff', '--cached', '--name-only', 'HEAD'], {encoding:'utf8'}), '');
    console.log('ISOLATED-CHECK-COMMIT:' + cp.execFileSync('git', ['rev-parse', 'HEAD'], {encoding:'utf8'}).trim());
  }
  for (const host of ['1.1.1.1', '169.254.169.254']) await new Promise((resolve, reject) => {
    const connection = net.connect({host,port:80}); connection.setTimeout(1000);
    connection.once('connect', () => {connection.destroy(); reject(Error('External connection succeeded'));});
    connection.once('error', () => resolve()); connection.once('timeout', () => {connection.destroy(); resolve();});
  });
  await new Promise((resolve, reject) => {
    const resolver = new dns.Resolver(); resolver.setServers(['1.1.1.1']);
    const timer = setTimeout(() => {resolver.cancel(); resolve();}, 1000);
    resolver.resolve4('registry.npmjs.org', error => {clearTimeout(timer); error ? resolve() : reject(Error('External DNS succeeded'));});
  });
  await new Promise((resolve, reject) => {const connection=net.connect(${JSON.stringify(socket)}); connection.once('connect',()=>{connection.destroy();reject(Error('Host socket connected'));});connection.once('error',()=>resolve());});
  await new Promise((resolve,reject)=>{const listener=net.createServer(connection=>connection.end('local'));listener.listen(0,'127.0.0.1',()=>{const connection=net.connect(listener.address().port,'127.0.0.1');connection.once('data',data=>{try{assert.equal(String(data),'local');connection.destroy();listener.close(resolve);}catch(error){reject(error);}});connection.once('error',reject);});});
  console.log('ISOLATED-PROBE-PASSED:' + process.argv[2]);
})().catch(error=>{console.error(error.message);process.exitCode=1;});\n`;
    const packageData = JSON.parse(Buffer.from(input.files.find((entry) => entry.path === "package.json")!.bytes).toString());
    const publicLock = JSON.parse(await readFile(path.join(checkout, "package-lock.json"), "utf8"));
    const dependency = publicLock.packages["node_modules/picocolors"];
    expect(dependency.version).toBe("1.1.1");
    const compiler = publicLock.packages["node_modules/typescript"];
    expect(compiler.version).toBe("5.9.3");
    packageData.dependencies = { picocolors: dependency.version, typescript: compiler.version };
    const lockData = JSON.parse(Buffer.from(input.files.find((entry) => entry.path === "package-lock.json")!.bytes).toString());
    lockData.packages[""].dependencies = packageData.dependencies;
    lockData.packages["node_modules/picocolors"] = { version: dependency.version, resolved: dependency.resolved,
      integrity: dependency.integrity, license: dependency.license };
    lockData.packages["node_modules/typescript"] = { version: compiler.version, resolved: compiler.resolved,
      integrity: compiler.integrity, license: compiler.license, bin: compiler.bin, engines: compiler.engines };
    replace(input, file("package-lock.json", JSON.stringify(lockData)));
    packageData.scripts = { postinstall: "node -e \"require('node:fs').writeFileSync('/pristine-cache/installer-lifecycle-ran', 'unexpected lifecycle')\"" };
    replace(input, file("package.json", JSON.stringify(packageData)));
    replace(input, file("probe.cjs", probe));
    replace(input, file("scripts/ci/run-fast-checks.sh", "#!/bin/bash\nset -euo pipefail\nnode probe.cjs checks\n", true));
    replace(input, file(".githooks/pre-commit", "#!/bin/bash\nset -euo pipefail\nnode probe.cjs hook\n", true)); input.hook = ".githooks/pre-commit";
    const frozen = freezeNodeValidation(input);
    const hook = await withDockerDiagnostics(() => validateIsolatedNode(input));
    const candidate = await finalCandidate(input);
    const report = await withDockerDiagnostics(() => validateIsolatedNode(candidate));
    if (hook.phase !== "prepared-hook" || report.phase !== "final-check") throw new Error("Wrong validation phase evidence.");
    expect(report.profile).toBe(NODE_ISOLATION_PROFILE); expect(report.image).toBe(NODE_ISOLATION_IMAGE);
    expect(report.sourceSha256).toBe(frozen.sourceSha256); expect(report.preparedTree).toBe(candidateTrees.get(candidate.candidateCommit)); expect(report.baseCommit).toBe(input.baseCommit);
    expect(hook.phase).toBe("prepared-hook"); expect(report.phase).toBe("final-check"); expect(report.candidateCommit).toBe(candidate.candidateCommit);
    expect(hook.preparedTree).toBe(report.preparedTree);
    expect(hook).toMatchObject({ profile: report.profile, image: report.image, sourceSha256: report.sourceSha256, baseCommit: report.baseCommit, hook: report.hook });
    expect(hook.commitPlanSha256).toBe(frozen.commitPlanSha256); expect(report.commitPlanSha256).toBe(frozen.commitPlanSha256);
    expect(Object.keys(report.tools).sort()).toEqual(["bash", "git", "node", "npm", "python"]);
    expect(report.tools.node).toMatch(/^v24\./); for (const value of Object.values(report.tools)) expect(value.length).toBeGreaterThan(0);
    expect(report.checkOutput).toContain("ISOLATED-PROBE-PASSED:checks"); expect(hook.hookOutput).toContain("ISOLATED-PROBE-PASSED:hook");
    expect(hook.hookOutput).toContain("ISOLATED-HOOK-CONTEXT-PASSED");
    expect(hook.hookOutput).toContain("ISOLATED-LOCKED-DEPENDENCY-PASSED:hook");
    expect(report.checkOutput).toContain("ISOLATED-LOCKED-DEPENDENCY-PASSED:checks");
    expect(hook.hookOutput).toContain("ISOLATED-LOCKED-BIN-PASSED:hook");
    expect(report.checkOutput).toContain("ISOLATED-LOCKED-BIN-PASSED:checks");
    expect(hook.hookOutput).toContain("ISOLATED-TEMPORARY-EXEC-PASSED:hook");
    expect(report.checkOutput).toContain("ISOLATED-TEMPORARY-EXEC-PASSED:checks");
    expect(report.checkOutput).toContain(`ISOLATED-CHECK-COMMIT:${candidate.candidateCommit}`); expect("hookOutput" in report).toBe(false);
    expect(await readFile(canary, "utf8")).toBe("unchanged host fixture\n"); expect(connections).toBe(0);
    await expect(access(marker)).rejects.toThrow(); expect(freezeNodeValidation(input).sourceSha256).toBe(frozen.sourceSha256);
  }, timeout);

  it.each(["failed hook", "source-mutating hook", "index-mutating hook"])("blocks a %s and cleans up before returning failure", async (kind) => {
    const { input } = await fixture(); input.hook = ".githooks/pre-commit";
    const body = kind === "failed hook" ? "exit 23" : kind === "source-mutating hook" ? "printf changed > README.md" : "printf changed > .git/index";
    replace(input, file(".githooks/pre-commit", `#!/bin/bash\nset -euo pipefail\n${body}\n`, true));
    await expect(validateIsolatedNode(input)).rejects.toThrow(/Isolated/);
    expect(await resources()).toEqual(beforeResources);
  }, timeout);

  it.each(["base parent", "message", "prepared tree", "author", "committer"])("rejects a wrong final candidate %s before starting target checks", async (kind) => {
    const { input } = await fixture(); const candidate = await finalCandidate(input);
    if (kind === "base parent") candidate.baseCommit = candidate.candidateCommit;
    else if (kind === "message") candidate.commitMessage += "Different signed message body.\n";
    else if (kind === "author") candidate.author = { ...candidate.author, name: "Different Public Author" };
    else if (kind === "committer") candidate.committer = { ...candidate.committer, date: "1767225720 +0000" };
    else replace(candidate, file("README.md", "Different prepared source bytes.\n"));
    const since = new Date().toISOString();
    await expect(validateIsolatedNode(candidate)).rejects.toThrow(/Isolated/);
    const until = new Date().toISOString();
    const starts = lines(await dockerCommand(["events", "--since", since, "--until", until, "--filter", "type=container",
      "--filter", "event=start", "--filter", "label=bootstrap.isolation", "--format", "{{.Actor.Attributes.name}}"]));
    expect(starts.some((name) => name.endsWith("-check")), "Target checks started before candidate identity was verified.").toBe(false);
  }, timeout);

  it("rejects a validation script that tries to mutate prepared source", async () => {
    const { input } = await fixture(); replace(input, file("scripts/ci/run-fast-checks.sh", "#!/bin/bash\nset -euo pipefail\nprintf changed > README.md\n", true));
    await expect(validateIsolatedNode(await finalCandidate(input))).rejects.toThrow(/Isolated/);
  }, timeout);

  it("cancels an actual running target and removes its containers and volumes", async () => {
    const { input } = await fixture();
    replace(input, file("scripts/ci/run-fast-checks.sh", "#!/bin/bash\nset -euo pipefail\ntouch /tmp/isolation-long-check-ready\nnode -e 'setInterval(() => {}, 1000)'\n", true));
    const cancellation = new AbortController();
    let completed: { passed: boolean; error: unknown } | undefined;
    const outcome = validateIsolatedNode(await finalCandidate(input), { signal: cancellation.signal }).then(
      () => completed = { passed: true, error: undefined }, (error: unknown) => completed = { passed: false, error });
    try {
      await waitFor(async () => {
        if (completed) throw completed.error ?? new Error("The long-running fixture completed unexpectedly.");
        const current = await resources();
        for (const name of current.containers.filter((entry) => !beforeResources.containers.includes(entry) && entry.endsWith("-check"))) {
          try { await dockerCommand(["exec", name, "/usr/bin/test", "-f", "/tmp/isolation-long-check-ready"]); return true; } catch { /* Target has not reached its long-running check yet. */ }
        }
        return false;
      });
    } finally { cancellation.abort(); }
    const result = await outcome; expect(result.passed).toBe(false); expect(result.error).toBeInstanceOf(Error);
    expect((result.error as Error).message).toContain("cancelled"); expect(await resources()).toEqual(beforeResources);
  }, timeout);

  it.each(["hook", "check"] as const)("rejects loss of the live storage keeper during the actual %s phase", async (mode) => {
    const { input } = await fixture();
    replace(input, file("hold.cjs", "const fs=require('node:fs');fs.writeFileSync('/tmp/isolation-storage-phase-ready','ready');const timer=setInterval(()=>{if(fs.existsSync('/tmp/isolation-storage-phase-release'))clearInterval(timer);},25);\n"));
    const entry = mode === "hook" ? ".githooks/pre-commit" : "scripts/ci/run-fast-checks.sh";
    replace(input, file(entry, "#!/bin/bash\nset -euo pipefail\nnode hold.cjs\n", true));
    if (mode === "hook") input.hook = ".githooks/pre-commit";
    const prepared = mode === "check" ? await finalCandidate(input) : input;
    const cancellation = new AbortController();
    let completed: { passed: boolean; error: unknown } | undefined;
    const outcome = validateIsolatedNode(prepared, { signal: cancellation.signal }).then(
      () => completed = { passed: true, error: undefined }, (error: unknown) => completed = { passed: false, error });
    let active = "";
    try {
      await waitFor(async () => {
        if (completed) throw completed.error ?? new Error("The held target completed unexpectedly.");
        const current = await resources();
        for (const name of current.containers.filter((value) => !beforeResources.containers.includes(value) && value.endsWith(`-${mode}`))) {
          try {
            await dockerCommand(["exec", name, "/usr/bin/test", "-f", "/tmp/isolation-storage-phase-ready"]);
            active = name; return true;
          } catch { /* Target has not reached its held phase yet. */ }
        }
        return false;
      });
      const storage = active.replace(/-(?:hook|check)$/, "-storage");
      const [keeper, phase] = JSON.parse(await dockerCommand(["inspect", storage, active]));
      expect(keeper.State.Running).toBe(true); expect(phase.State.Running).toBe(true);
      for (const container of [keeper, phase]) {
        expect(container.Config.User).toBe("1000:1000"); expect(container.HostConfig.NetworkMode).toBe("none");
        expect(container.HostConfig.ReadonlyRootfs).toBe(true); expect(container.HostConfig.CapDrop).toContain("ALL");
        expect(container.HostConfig.SecurityOpt).toContain("no-new-privileges");
        expect(container.HostConfig.LogConfig.Type).toBe("none");
      }
      expect(keeper.HostConfig.NanoCpus).toBe(100_000_000);
      expect(keeper.HostConfig.Memory).toBe(64 * 1024 ** 2); expect(keeper.HostConfig.MemorySwap).toBe(64 * 1024 ** 2);
      expect(keeper.HostConfig.PidsLimit).toBe(16); expect(keeper.HostConfig.Tmpfs["/tmp"]).toContain("size=1048576");
      expect(Object.keys(keeper.HostConfig.Tmpfs)).toEqual(["/tmp"]);
      expect(keeper.HostConfig.Tmpfs["/tmp"].split(",")).toContain("noexec");
      expect(keeper.HostConfig.Tmpfs["/tmp"].split(",")).not.toContain("exec");
      expect(phase.HostConfig.NanoCpus).toBe(2_000_000_000);
      expect(phase.HostConfig.Memory).toBe(4 * 1024 ** 3); expect(phase.HostConfig.MemorySwap).toBe(4 * 1024 ** 3);
      expect(phase.HostConfig.PidsLimit).toBe(256); expect(phase.HostConfig.Tmpfs["/tmp"].split(",")).toContain("size=268435456");
      const keeperMountinfo = (await dockerCommand(["exec", storage, "/usr/bin/cat", "/proc/self/mountinfo"])).trim().split("\n");
      const keeperTemporary = keeperMountinfo.map((line) => line.split(" ")).find((fields) => fields[4] === "/tmp");
      if (!keeperTemporary) throw new Error("Required keeper temporary mount is missing.");
      expect(keeperTemporary[keeperTemporary.indexOf("-") + 1]).toBe("tmpfs");
      expect(keeperTemporary[5]!.split(",")).toContain("noexec");
      const executableMounts = new Set(["/tmp", "/repo/project/node_modules"]);
      const phaseTmpfs = phase.HostConfig.Tmpfs as Record<string, string>;
      expect(Object.keys(phaseTmpfs).sort()).toEqual([...executableMounts, "/npm-cache", "/repo/project/dist"].sort());
      const mountinfo = (await dockerCommand(["exec", active, "/usr/bin/cat", "/proc/self/mountinfo"])).trim().split("\n");
      for (const [target, options] of Object.entries(phaseTmpfs)) {
        const flags = options.split(","), executable = executableMounts.has(target);
        expect(flags).toContain(executable ? "exec" : "noexec"); expect(flags).not.toContain(executable ? "noexec" : "exec");
        expect(flags).toContain("nosuid"); expect(flags).toContain("nodev");
        expect(flags).toContain("uid=1000"); expect(flags).toContain("gid=1000"); expect(flags).toContain("mode=0700");
        const row = mountinfo.map((line) => line.split(" ")).find((fields) => fields[4] === target);
        if (!row) throw new Error(`Required isolated tmpfs mount is missing: ${target}`);
        expect(row[row.indexOf("-") + 1]).toBe("tmpfs");
        expect(row[5]!.split(",").includes("noexec")).toBe(!executable);
      }
      const mounted = (container: typeof keeper) => container.Mounts.filter((mount: { Type: string }) => mount.Type === "volume") as Array<{
        Name: string; Destination: string; Driver: string; RW: boolean;
      }>;
      const keeperMounts = mounted(keeper), phaseMounts = mounted(phase);
      expect(keeperMounts).toHaveLength(3); expect(phaseMounts).toHaveLength(3);
      expect(keeperMounts.map((mount) => mount.Destination).sort()).toEqual(["/input", "/pristine-cache", "/repo"]);
      expect(keeperMounts.map((mount) => mount.Name).sort()).toEqual(phaseMounts.map((mount) => mount.Name).sort());
      for (const mount of keeperMounts) { expect(mount.Driver).toBe("local"); expect(mount.RW).toBe(true); }
      for (const mount of phaseMounts) { expect(mount.Driver).toBe("local"); expect(mount.RW).toBe(false); }
      const volumes = JSON.parse(await dockerCommand(["volume", "inspect", ...keeperMounts.map((mount) => mount.Name)]));
      expect(volumes).toHaveLength(3);
      for (const volume of volumes) {
        expect(volume.Driver).toBe("local"); expect(volume.Options.type).toBe("tmpfs"); expect(volume.Options.device).toBe("tmpfs");
        expect(volume.Options.o).toContain("nosuid,nodev");
        const bytes = volume.Name.endsWith("-source") ? 1024 ** 3 : volume.Name.endsWith("-cache") ? 512 * 1024 ** 2 : 768 * 1024 ** 2;
        expect(volume.Options.o).toContain(`size=${bytes}`);
      }
      await dockerCommand(["kill", storage]);
      expect(JSON.parse(await dockerCommand(["inspect", "--format", "{{json .State}}", storage])).Running).toBe(false);
      // Let the target finish successfully: only the trusted storage-liveness guard should reject its evidence.
      try { await dockerCommand(["exec", active, "/usr/bin/touch", "/tmp/isolation-storage-phase-release"]); }
      catch { expect((await resources()).containers).not.toContain(active); }
      const result = await outcome;
      expect(result.passed).toBe(false); expect(result.error).toBeInstanceOf(Error);
      expect((result.error as Error).message).toContain("storage lifetime ended");
      expect(await resources()).toEqual(beforeResources);
    } finally { cancellation.abort(); await outcome; }
  }, timeout);

  it("runs Bootstrap's actual frozen fast checks using the integrity-verified offline cache", async () => {
    const target = await directory();
    const baseCommit = (await git(checkout, ["rev-parse", "HEAD"])).trim();
    const bundle = path.join(target, "bootstrap.bundle"); await git(checkout, ["bundle", "create", bundle, "HEAD"]);
    const tracked = await git(checkout, ["ls-files", "--stage", "-z"]);
    const modes = new Map<string, "100644" | "100755">();
    for (const row of tracked.split("\0").filter(Boolean)) {
      const match = row.match(/^(100644|100755) [a-f0-9]{40} 0\t([\s\S]+)$/);
      if (!match) throw new Error("Bootstrap integration source contains an unsupported Git entry.");
      modes.set(match[2]!, match[1] as "100644" | "100755");
    }
    // These are explicit new public source files during local preparation, never a glob of ignored or machine-local files.
    for (const name of ["src/isolation/node-profile.ts", "src/isolation/node-validation.ts", "src/isolation/setup.ts",
      "tests/isolation-profile.test.ts", "tests/isolated-validation.test.ts", "tests/isolation-hook-context.test.ts", "tests/isolated-validation-docker.test.ts",
      ".github/workflows/fleet-isolation-validation.yml", "docs/security/fleet-isolation-design.md",
      "docs/decisions/ADR-0013-isolated-node-validation-backend.md", "docs/bootstrap/fleet-isolation-backend.md"]) {
      try { await access(path.join(checkout, name)); if (!modes.has(name)) modes.set(name, "100644"); } catch { /* Only already-created explicit sources are included. */ }
    }
    const files: IsolatedSourceFile[] = [];
    for (const [name, mode] of modes) {
      if (name === ".git" || name.startsWith(".git/") || name.startsWith("node_modules/") || name.startsWith("dist/")) throw new Error("Machine-local data cannot enter a public source snapshot.");
      const info = await lstat(path.join(checkout, name));
      if (!info.isFile() || info.nlink !== 1) throw new Error("Bootstrap source snapshot requires regular singly linked files.");
      files.push({ path: name, mode, bytes: await readFile(path.join(checkout, name)) });
    }
    const input: NodeValidationInput = { profile: NODE_ISOLATION_PROFILE, phase: "prepared-hook", ...identities(), files, baseBundle: await readFile(bundle), baseCommit,
      branch: "codex/isolation-bootstrap", commitMessage: "test: validate public Bootstrap snapshot\n\nSigned-off-by: Isolation Fixture <isolation-fixture@example.invalid>\n", hook: ".githooks/pre-commit" };
    const before = freezeNodeValidation(input).sourceSha256;
    const hook = await withDockerDiagnostics(() => validateIsolatedNode(input)); expect(hook.phase).toBe("prepared-hook");
    const candidate = await finalCandidate(input);
    const report = await withDockerDiagnostics(() => validateIsolatedNode(candidate));
    if (hook.phase !== "prepared-hook" || report.phase !== "final-check") throw new Error("Wrong validation phase evidence.");
    expect(report.sourceSha256).toBe(before); expect(report.baseCommit).toBe(baseCommit); expect(report.image).toBe(NODE_ISOLATION_IMAGE);
    expect(report.phase).toBe("final-check"); expect(report.candidateCommit).toBe(candidate.candidateCommit); expect(report.preparedTree).toBe(hook.preparedTree);
    expect(report.preparedTree).toBe(candidateTrees.get(candidate.candidateCommit));
    expect(report.checkOutput).toContain("Test Files"); expect(report.checkOutput).toContain("Tests");
    expect(report.checkOutput).toContain("> bootstrap@0.1.0 build"); expect(report.tools.node).toMatch(/^v24\./);
    expect(freezeNodeValidation(input).sourceSha256).toBe(before);
  }, timeout);
});
