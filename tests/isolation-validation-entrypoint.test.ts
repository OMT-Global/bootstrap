import { execFile } from "node:child_process";
import { mkdtemp, mkdir, readFile, writeFile, chmod, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { afterEach, describe, expect, it } from "vitest";
import { loadManifest } from "../src/manifest.js";
import { loadResolvedFlowPolicy } from "../src/policy.js";
import { renderManagedFiles } from "../src/archetypes.js";
import { NODE_ISOLATION_IMAGE } from "../src/isolation/node-profile.js";
const execute = promisify(execFile);
const directories: string[] = [];
afterEach(async () => { await Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true }))); });
async function fixture(profile: string, failure = "") {
  const target = await mkdtemp(path.join(os.tmpdir(), "bootstrap-full-entrypoint-")); directories.push(target);
  await mkdir(path.join(target, "scripts/ci"), { recursive: true }); await mkdir(path.join(target, "bin"));
  await writeFile(path.join(target, "scripts/ci/run-fast-checks.sh"), '#!/bin/bash\nset -eu\nprintf "fast:%s\\n" "${BOOTSTRAP_REQUIRE_ISOLATION_TESTS:-unset}" >> "$ENTRY_LOG"\n[[ "${ENTRY_FAIL:-}" != fast ]] || exit 13\n');
  for (const name of ["docker", "npm", "python3"]) {
    const file = path.join(target, "bin", name);
    await writeFile(file, `#!/bin/bash\nset -eu\nprintf '${name}:%s:%s\\n' "$*" "\${BOOTSTRAP_REQUIRE_ISOLATION_TESTS:-unset}" >> "$ENTRY_LOG"\n[[ "\${ENTRY_FAIL:-}" != ${name} ]] || exit 17\n`);
    await chmod(file, 0o755);
  }
  const script = await readFile("scripts/ci/run-extended-validation.sh", "utf8");
  await writeFile(path.join(target, "extended.sh"), script);
  let status = 0; let stdout = "";
  try { stdout = (await execute("/bin/bash", ["extended.sh"], { cwd: target, env: { PATH: `${target}/bin:/usr/bin:/bin`, HOME: target,
    RELEASE_PROFILE: profile, ENTRY_LOG: path.join(target, "events"), ENTRY_FAIL: failure } })).stdout; }
  catch (error) { const result = error as { code: number; stdout: string }; status = result.code; stdout = result.stdout; }
  return { status, stdout, events: (await readFile(path.join(target, "events"), "utf8")).trim().split("\n") };
}
describe("registered full-validation isolation entry point", () => {
  it("checks artifact parsers, extraction and bounds without downloads or native execution", async () => {
    const result = await execute("python3", ["-B", "-I", "-S", "tests/reviewer-artifacts.test.py"], {
      env: { PATH: process.env.PATH ?? "/usr/bin:/bin", PYTHONDONTWRITEBYTECODE: "1" },
      timeout: 30_000, maxBuffer: 256 * 1024
    });
    expect(result.stderr).toContain("OK");
  });
  it("matches the supported manifest projection exactly", async () => {
    const manifest = await loadManifest("project.bootstrap.yaml");
    const projection = renderManagedFiles(manifest, await loadResolvedFlowPolicy(manifest, process.cwd())).find((file) => file.path === "scripts/ci/run-extended-validation.sh");
    expect(projection?.contents).toBe(await readFile("scripts/ci/run-extended-validation.sh", "utf8"));
  });
  it.each(["", "smoke", "standard"])("keeps profile %s cheap and explicitly reports Docker tests were not run", async (profile) => {
    const result = await fixture(profile);
    expect(result.status).toBe(0); expect(result.events).toEqual(["fast:unset"]);
    expect(result.stdout).toContain("require the full release-validation profile");
  });
  it("requires actual Docker tests only after normal checks and the immutable image pull", async () => {
    const result = await fixture("full");
    expect(result.status).toBe(0);
    expect(result.events).toEqual(["fast:unset", `docker:pull --platform linux/amd64 ${NODE_ISOLATION_IMAGE}:unset`,
      "npm:test -- tests/isolated-validation-docker.test.ts --maxWorkers=1 --minWorkers=1:1",
      "python3:scripts/ci/controlled-reviewer-probe.py:unset"]);
  });
  it.each(["fast", "docker", "npm", "python3"])("fails instead of passing a full run when %s fails", async (failure) => {
    const result = await fixture("full", failure);
    expect(result.status).not.toBe(0);
    if (failure === "fast") expect(result.events).toHaveLength(1);
    if (failure === "docker") expect(result.events).toHaveLength(2);
    if (failure === "npm") expect(result.events).toHaveLength(3);
    if (failure === "python3") expect(result.events).toHaveLength(4);
  });
});


const driverHarness = String.raw`
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile

source = Path.cwd() / 'scripts/ci/controlled-reviewer-probe.py'
spec = importlib.util.spec_from_file_location('driver_under_test', source)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)
probe.DOCKER = ['test-owned-docker-never-executed']
mode, methods = sys.argv[1], json.loads(sys.argv[2])
with tempfile.TemporaryDirectory(prefix='bootstrap-reviewer-driver-') as temporary:
    target = Path(temporary)
    pending, operations = [], []
    if mode == 'create-failure':
        observed = {}
        def create_failure(arguments, **kwargs):
            name = arguments[arguments.index('--name') + 1]
            observed.update(claimedAtCreate=name in pending, name=name)
            raise probe.Unsupported('injected-create-timeout')
        probe.command = create_failure
        try:
            probe.case_run('mechanical', 'test-image', target, pending, '')
        except probe.Unsupported as error:
            assert str(error) == 'injected-create-timeout'
        print(json.dumps({'claimedAtCreate': observed['claimedAtCreate'],
                          'retainedForCleanup': pending == [observed['name']]}))
    elif mode == 'notices':
        content = b'public license fixture'
        elf = b'\x7fELF\x02\x01' + bytes(14)
        entries = {name: elf for name in ('bin/codex', 'bin/codex-code-mode-host',
                   'bin/codex-exec-server', 'codex-path/rg', 'codex-resources/bwrap')}
        entries['codex-package.json'] = json.dumps({'layoutVersion': 1, 'version': '0.167.0',
            'target': 'x86_64-unknown-linux-musl', 'variant': 'codex', 'entrypoint': 'bin/codex'}).encode()
        entries['licenses/LICENSE.txt'] = content
        probe.NATIVE = {name: hashlib.sha256(elf).hexdigest() for name in probe.NATIVE}
        package = target / 'package.tar.gz'
        with tarfile.open(package, 'w:gz') as archive:
            directory = tarfile.TarInfo('licenses')
            directory.type, directory.mode = tarfile.DIRTYPE, 0o755
            archive.addfile(directory)
            for name, data in entries.items():
                item = tarfile.TarInfo(name)
                item.size, item.mode = len(data), 0o755 if data == elf else 0o644
                archive.addfile(item, io.BytesIO(data))
        destination = target / 'expanded'
        destination.mkdir()
        result = probe.extract(package, destination)
        print(json.dumps({'notices': result['packageNoticesPreserved'],
                          'directoryPreserved': (destination / 'licenses').is_dir(),
                          'allPackageFilesPreserved': all((destination / name).read_bytes() == data
                                                        for name, data in entries.items())}))
    else:
        state = {'running': False}
        def command(arguments, **kwargs):
            operation = arguments[len(probe.DOCKER)]
            operations.append(operation)
            if operation == 'start':
                state['running'] = True
                callback = kwargs['on_line']
                callback(json.dumps({'event': 'ready', 'uid': os.getuid(), 'gid': os.getgid()}).encode(), io.BytesIO())
                callback(json.dumps({'event': 'result', 'case': 'api', 'ok': mode != 'api-failure',
                    'providerRequests': 0 if mode == 'api-failure' else 2, 'mockMethods': methods}).encode(), io.BytesIO())
                state['running'] = False
            return b''
        probe.command = command
        probe.inspect = lambda name: {'State': {'Running': state['running'], 'Pid': 123},
            'HostConfig': {'NetworkMode': 'none', 'ReadonlyRootfs': True}}
        probe.cgroup_for = lambda pid: target / 'absent-test-cgroup'
        try:
            result = probe.case_run('api', 'test-image', target, pending, '')
            output = {'result': result, 'rejected': False}
        except probe.Unsupported as error:
            output = {'rejected': True, 'reason': str(error)}
        output['cleanupCalled'] = operations[-1] == 'rm' and not pending
        print(json.dumps(output))
`;
async function driverCase(mode: string, methods: Record<string, number | boolean> = {}) {
  const result = await execute("python3", ["-B", "-I", "-S", "-c", driverHarness, mode, JSON.stringify(methods)], {
    cwd: process.cwd(), timeout: 10_000, maxBuffer: 64 * 1024,
    env: { PATH: process.env.PATH, PYTHONDONTWRITEBYTECODE: "1" }
  });
  return JSON.parse(result.stdout) as { claimedAtCreate?: boolean; retainedForCleanup?: boolean;
    notices?: Record<string, string>; directoryPreserved?: boolean; allPackageFilesPreserved?: boolean;
    rejected?: boolean; cleanupCalled?: boolean; reason?: string; result?: { ok?: boolean; providerRequests?: number; mockMethods?: Record<string, number> } };
}
describe("controlled reviewer driver regressions", () => {
  it("keeps the owned name available for cleanup when Docker create times out after daemon acceptance", async () => {
    expect(await driverCase("create-failure")).toEqual({ claimedAtCreate: true, retainedForCleanup: true });
  });
  it("hashes regular notice files while preserving a matching licenses directory and every package file", async () => {
    const result = await driverCase("notices");
    expect(Object.keys(result.notices ?? {})).toEqual(["licenses/LICENSE.txt"]);
    expect(result.notices?.["licenses/LICENSE.txt"]).toMatch(/^[a-f0-9]{64}$/);
    expect(result.directoryPreserved).toBe(true);
    expect(result.allPackageFilesPreserved).toBe(true);
  });
  it("retains the real API GET/POST request evidence after validation and cleanup", async () => {
    const result = await driverCase("api", { GET: 1, POST: 1 });
    expect(result.rejected).toBe(false);
    expect(result.cleanupCalled).toBe(true);
    expect(result.result?.mockMethods).toEqual({ GET: 1, POST: 1 });
  });
  it("retains zero GET/POST evidence when the native API fixture fails before making a request", async () => {
    const result = await driverCase("api-failure", { GET: 0, POST: 0 });
    expect(result.rejected).toBe(false);
    expect(result.cleanupCalled).toBe(true);
    expect(result.result).toMatchObject({ ok: false, providerRequests: 0, mockMethods: { GET: 0, POST: 0 } });
  });
  it.each([
    { GET: 1, POST: 1, DELETE: 0 }, { GET: true, POST: 1 }, { GET: 0.5, POST: 1.5 },
    { GET: -1, POST: 3 }, { GET: 9, POST: 1 }, { GET: 1, POST: 2 }, { GET: 2, POST: 0 }, { GET: 2 }
  ])("rejects malformed or inconsistent API method evidence %j and still cleans up", async (methods) => {
    const result = await driverCase("api", methods);
    expect(result.rejected).toBe(true);
    expect(result.reason).toBe("output");
    expect(result.cleanupCalled).toBe(true);
  });
});
