import { execFile } from "node:child_process";
import { access, lstat, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { constants } from "node:fs";
import { randomUUID } from "node:crypto";
import { createServer, type Server } from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

import { validateIsolatedNode } from "../src/isolation/node-validation.js";
import { freezeNodeValidation, NODE_ISOLATION_IMAGE, NODE_ISOLATION_PROFILE, type IsolatedSourceFile,
  type NodeValidationInput } from "../src/isolation/node-profile.js";

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
    packageData.scripts = { postinstall: "node -e \"require('node:fs').writeFileSync('/pristine-cache/installer-lifecycle-ran', 'unexpected lifecycle')\"" };
    replace(input, file("package.json", JSON.stringify(packageData)));
    replace(input, file("probe.cjs", probe));
    replace(input, file("scripts/ci/run-fast-checks.sh", "#!/bin/bash\nset -euo pipefail\nnpm ci --offline --ignore-scripts --no-audit --no-fund\nnode probe.cjs checks\n", true));
    replace(input, file(".githooks/pre-commit", "#!/bin/bash\nset -euo pipefail\nnode probe.cjs hook\n", true)); input.hook = ".githooks/pre-commit";
    const frozen = freezeNodeValidation(input);
    const hook = await validateIsolatedNode(input);
    const candidate = await finalCandidate(input);
    const report = await validateIsolatedNode(candidate);
    if (hook.phase !== "prepared-hook" || report.phase !== "final-check") throw new Error("Wrong validation phase evidence.");
    expect(report.profile).toBe(NODE_ISOLATION_PROFILE); expect(report.image).toBe(NODE_ISOLATION_IMAGE);
    expect(report.sourceSha256).toBe(frozen.sourceSha256); expect(report.preparedTree).toBe(candidateTrees.get(candidate.candidateCommit)); expect(report.baseCommit).toBe(input.baseCommit);
    expect(hook.phase).toBe("prepared-hook"); expect(report.phase).toBe("final-check"); expect(report.candidateCommit).toBe(candidate.candidateCommit);
    expect(hook.preparedTree).toBe(report.preparedTree);
    expect(hook.commitPlanSha256).toBe(frozen.commitPlanSha256); expect(report.commitPlanSha256).toBe(frozen.commitPlanSha256);
    expect(Object.keys(report.tools).sort()).toEqual(["bash", "git", "node", "npm", "python"]);
    expect(report.tools.node).toMatch(/^v24\./); for (const value of Object.values(report.tools)) expect(value.length).toBeGreaterThan(0);
    expect(report.checkOutput).toContain("ISOLATED-PROBE-PASSED:checks"); expect(hook.hookOutput).toContain("ISOLATED-PROBE-PASSED:hook");
    expect(hook.hookOutput).toContain("ISOLATED-HOOK-CONTEXT-PASSED");
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
    const hook = await validateIsolatedNode(input); expect(hook.phase).toBe("prepared-hook");
    const candidate = await finalCandidate(input);
    const report = await validateIsolatedNode(candidate);
    if (hook.phase !== "prepared-hook" || report.phase !== "final-check") throw new Error("Wrong validation phase evidence.");
    expect(report.sourceSha256).toBe(before); expect(report.baseCommit).toBe(baseCommit); expect(report.image).toBe(NODE_ISOLATION_IMAGE);
    expect(report.phase).toBe("final-check"); expect(report.candidateCommit).toBe(candidate.candidateCommit); expect(report.preparedTree).toBe(hook.preparedTree);
    expect(report.preparedTree).toBe(candidateTrees.get(candidate.candidateCommit));
    expect(report.checkOutput).toContain("Test Files"); expect(report.checkOutput).toContain("Tests");
    expect(report.checkOutput).toContain("> bootstrap@0.1.0 build"); expect(report.tools.node).toMatch(/^v24\./);
    expect(freezeNodeValidation(input).sourceSha256).toBe(before);
  }, timeout);
});
