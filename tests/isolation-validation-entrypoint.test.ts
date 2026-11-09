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
import time

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
        artifacts = probe.artifacts
        artifacts.NATIVE = {name: hashlib.sha256(elf).hexdigest() for name in artifacts.NATIVE}
        artifacts.DEADLINE = time.monotonic() + 10
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
        result = artifacts.extract(package, destination)
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
                callback(json.dumps({'event': 'ready', 'uid': os.getuid(), 'gid': os.getgid(),
                    'addressSpace': {'soft': 17179869184, 'hard': 17179869184}}).encode(), io.BytesIO())
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

const orchestrationHarness = String.raw`
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import stat
import sys
import tempfile
import time
import types
from unittest import mock

spec = importlib.util.spec_from_file_location('runtime_orchestration', Path.cwd() / 'scripts/ci/controlled-reviewer-probe.py')
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)
# Synthetic-only fixture data for the inherited-credential rejection check.
ENV_CANARY = 'fabricated-env-key-must-not-forward'
mode = sys.argv[1]
if mode == 'cleanup-clock':
    before_handler = signal.getsignal(signal.SIGALRM)
    before_timer = signal.getitimer(signal.ITIMER_REAL)
    probe.CLEANUP_DEADLINE, probe.DEADLINE = 17, 99
    try:
        with probe.cleanup_clock():
            assert 59 < probe.CLEANUP_DEADLINE - time.monotonic() <= 60
            assert probe.DEADLINE == 99
            signal.getsignal(signal.SIGALRM)(signal.SIGALRM, None)
    except probe.Unsupported as error:
        assert str(error) == 'cleanup'
    else:
        raise AssertionError('cleanup expiry did not interrupt work')
    assert probe.CLEANUP_DEADLINE == 17 and probe.DEADLINE == 99
    assert signal.getsignal(signal.SIGALRM) == before_handler
    assert before_timer == (0.0, 0.0) and signal.getitimer(signal.ITIMER_REAL) == before_timer
    print(json.dumps({'bounded': True, 'restored': True, 'reason': 'cleanup'}))
    sys.exit(0)
real_mkdtemp, real_rmtree = tempfile.mkdtemp, probe.shutil.rmtree
real_write_bytes, real_read_bytes = Path.write_bytes, Path.read_bytes
with tempfile.TemporaryDirectory(prefix='bootstrap-runtime-orchestration-') as outer:
    outer = Path(outer)
    probe.HERE = outer / 'scripts/ci'
    probe.HERE.mkdir(parents=True)
    for name in ('controlled-reviewer-probe.py', 'controlled-reviewer-fixture.py', 'controlled-reviewer-probe.Dockerfile'):
        (probe.HERE / name).write_text('public synthetic test source')
    state = {'roots': [], 'stageCalls': 0, 'buildCalls': 0, 'caseOrder': [], 'providerRequests': 0,
             'mockMethods': {'GET': 0, 'POST': 0}, 'emittedWhileRootPresent': False,
             'reportWrittenWhileRootPresent': False, 'provenancePreservedAtBuild': False,
             'binaryEvidenceWrites': 0, 'binaryFlushes': 0, 'outputEvents': []}
    initial_artifact_env = {'test-only-artifact-env': 'independent'}
    probe.artifacts.ENV = initial_artifact_env
    provenance = b'{\n  "publicSyntheticArtifactProvenance": true\n}\n'
    verified = {name: ('verified synthetic ' + name).encode() for name in ('package', 'native', 'bwrap')}
    stage_evidence = {'head': ('e' if mode == 'stage-head-mismatch' else 'a') * 40,
                      'signatureVerified': True, 'stageSourceSha256': 'c' * 64,
                      'package': {'packageNoticesPreserved': {'licenses/LICENSE.txt': 'd' * 64}},
                      'bundles': {name: {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
                                  for name, data in verified.items()}}
    if mode == 'oversized-evidence':
        stage_evidence['padding'] = '🧪' * 20000

    def owned_mkdtemp(*args, **kwargs):
        result = real_mkdtemp(*args, dir=outer, **kwargs)
        state['roots'].append(Path(result))
        return result

    def stage(directory, absolute_deadline=None):
        state['stageCalls'] += 1
        assert directory.is_absolute() and directory.is_dir() and not directory.is_symlink()
        assert directory.parent == state['roots'][0] and not list(directory.iterdir())
        assert stat.S_IMODE(directory.stat().st_mode) == 0o700 and directory.stat().st_uid == os.getuid()
        assert absolute_deadline == probe.DEADLINE and 899 < absolute_deadline - started <= 901
        assert probe.artifacts.ENV is initial_artifact_env and probe.artifacts.ENV is not probe.ENV
        assert probe.ENV['HOME'] == str(directory.parent) and probe.ENV['TMPDIR'] == str(directory.parent)
        assert probe.ENV['DOCKER_CONFIG'] == str(directory.parent / 'docker-config')
        assert not any(key in probe.ENV for key in ('OPENAI_API_KEY', 'CODEX_HOME', 'GITHUB_TOKEN'))
        state['stageContract'] = True
        state['deadline'] = absolute_deadline
        if mode in ('stage-failure', 'stage-deadline'):
            (directory / 'partial-public-download').write_bytes(b'public synthetic partial data')
            raise probe.Unsupported('deadline' if mode == 'stage-deadline' else 'bundle/package/pinned-hash/mismatch')
        context = directory / 'selected-context'
        package = context / 'verified-codex-package'
        package.mkdir(parents=True)
        (context / 'public-provenance.json').write_bytes(provenance)
        for name, data in verified.items():
            (directory / (name + '.standard.json')).write_bytes(data)
        state['context'] = context
        return {'context': context, 'package': package, 'evidence': stage_evidence, 'verifiedBundleBytes': verified}

    def forbidden(*args, **kwargs):
        raise AssertionError('duplicate acquisition/preparation or unverified bundle read')

    def read_bytes(path):
        if path.name.endswith('.standard.json'):
            forbidden()
        return real_read_bytes(path)

    def command(arguments, **kwargs):
        if arguments[0] == '/usr/bin/git':
            return b'a' * 40 + b'\n'
        operation = arguments[3]
        if operation == 'info':
            return json.dumps({'OSType': 'linux', 'Architecture': 'x86_64', 'CgroupVersion': '2', 'SecurityOptions': []}).encode()
        if operation == 'build':
            state['buildCalls'] += 1
            assert Path(arguments[-1]) == state['context']
            assert arguments[4:7] == ['--network', 'none', '--pull=false']
            state['provenancePreservedAtBuild'] = (state['context'] / 'public-provenance.json').read_bytes() == provenance
            assert state['provenancePreservedAtBuild']
            for name in verified:
                (state['context'].parent / (name + '.standard.json')).write_bytes(b'later unverified synthetic bytes')
        if operation == 'image' and arguments[4] == 'inspect':
            return json.dumps([{'Id': 'sha256:' + 'b' * 64}]).encode()
        if operation == 'image' and arguments[4] == 'rm' and mode == 'image-cleanup-failure':
            raise probe.Unsupported('injected-image-cleanup-failure')
        return b''

    def case_run(case, *args):
        state['caseOrder'].append(case)
        result = {'case': case, 'ok': not (mode == 'native-unsupported' and case == 'sandbox'), 'providerRequests': 0}
        if case == 'api':
            result.update(providerRequests=2, mockMethods={'GET': 1, 'POST': 1})
            state['providerRequests'] += 2
            state['mockMethods'] = result['mockMethods']
        return result

    def rmtree(path, *args, **kwargs):
        if mode == 'temp-cleanup-failure' and Path(path) in state['roots']:
            raise OSError('injected temporary cleanup failure')
        return real_rmtree(path, *args, **kwargs)

    def write_bytes(path, *args, **kwargs):
        if path.name == 'controlled-reviewer-evidence.json':
            state['reportWrittenWhileRootPresent'] = any(root.exists() for root in state['roots'])
            state['outputEvents'].append('report')
        return real_write_bytes(path, *args, **kwargs)

    class OutputBuffer(io.BytesIO):
        def write(self, value):
            if value.startswith(b'CONTROLLED_REVIEWER_EVIDENCE '):
                state['emittedWhileRootPresent'] = any(root.exists() for root in state['roots'])
                state['binaryEvidenceWrites'] += 1
                state['outputEvents'].append('wire-write')
            return super().write(value)
        def flush(self):
            state['binaryFlushes'] += 1
            state['outputEvents'].append('wire-flush')
            return super().flush()

    raw_output = OutputBuffer()
    output = io.TextIOWrapper(raw_output, encoding='utf-16' if mode == 'non-utf8-output' else 'utf-8', write_through=True)
    if mode == 'non-utf8-output':
        original_encode_evidence = probe.encode_evidence
        def exact_wire_boundary(evidence):
            evidence['wirePadding'] = ''
            overhead = len(b'CONTROLLED_REVIEWER_EVIDENCE ') + len(json.dumps(evidence, ensure_ascii=False, separators=(',', ':')).encode('utf-8')) + 1
            available = 65536 - overhead
            evidence['wirePadding'] = '🧪' * (available // 4) + 'x' * (available % 4)
            return original_encode_evidence(evidence)
        probe.encode_evidence = exact_wire_boundary
    probe.self_test, probe.command, probe.case_run = lambda: None, command, case_run
    started = time.monotonic()
    with mock.patch.object(probe.tempfile, 'mkdtemp', side_effect=owned_mkdtemp), \
            mock.patch.object(probe.shutil, 'rmtree', side_effect=rmtree), \
            mock.patch.object(probe.sys, 'platform', 'linux'), \
            mock.patch.object(probe.os, 'uname', return_value=types.SimpleNamespace(machine='x86_64')), \
            mock.patch.dict(probe.os.environ, {'RELEASE_PROFILE': 'full', 'GITHUB_REPOSITORY': 'OMT-Global/bootstrap',
                           'GITHUB_RUN_ID': '1' * 100000 if mode == 'oversized-run-id' else '123',
                           'OPENAI_API_KEY': ENV_CANARY}, clear=True), \
            mock.patch.object(probe.artifacts, 'stage', side_effect=stage), \
            mock.patch.object(probe.artifacts, 'main', side_effect=forbidden), \
            mock.patch.object(probe.artifacts, 'prepare_metadata', side_effect=forbidden), \
            mock.patch.object(probe.artifacts, 'prepare_with_clock', side_effect=forbidden), \
            mock.patch.object(probe.artifacts, 'normalize_bundle', side_effect=forbidden), \
            mock.patch.object(probe.artifacts, 'download', side_effect=forbidden), \
            mock.patch.object(probe.artifacts, 'extract', side_effect=forbidden), \
            mock.patch.object(probe.artifacts, 'verify_signatures', side_effect=forbidden), \
            mock.patch.object(Path, 'read_bytes', read_bytes), \
            mock.patch.object(Path, 'write_bytes', write_bytes), contextlib.redirect_stdout(output):
        status = probe.main()
    wire = raw_output.getvalue()
    lines = [line for line in wire.decode('utf-8', 'strict').splitlines() if line.startswith('CONTROLLED_REVIEWER_EVIDENCE ')]
    assert len(lines) == 1
    evidence = json.loads(lines[0].split(' ', 1)[1])
    report_bytes = (outer / 'dist/release/controlled-reviewer-evidence.json').read_bytes()
    assert report_bytes == lines[0].split(' ', 1)[1].encode('utf-8') + b'\n'
    assert wire == b'CONTROLLED_REVIEWER_EVIDENCE ' + report_bytes
    assert state['binaryEvidenceWrites'] == 1 and state['binaryFlushes'] >= 1
    assert state['outputEvents'][:3] == ['report', 'wire-write', 'wire-flush']
    assert len(lines[0].encode('utf-8')) + 1 <= 65536 and len(report_bytes) <= 65536
    state['reportBytes'], state['wireBytes'] = len(report_bytes), len(wire)
    state['literalMultibyteUtf8'] = '🧪'.encode('utf-8') in wire
    state['utf8PrefixWithoutBom'] = wire.startswith(b'CONTROLLED_REVIEWER_EVIDENCE ')
    report = json.loads(report_bytes)
    assert report == evidence and probe.DEADLINE == state['deadline']
    assert probe.artifacts.ENV is initial_artifact_env
    if state['buildCalls'] and evidence.get('reason') != 'evidence-limit':
        assert all(evidence[key] == value for key, value in stage_evidence.items())
    state['allRootsRemoved'] = not any(root.exists() for root in state['roots'])
    for root in state['roots']:
        if root.exists():
            real_rmtree(root)
    state.pop('roots')
    state.pop('context', None)
    state.pop('deadline')
    evidence_summary = {key: value for key, value in evidence.items() if key != 'wirePadding'}
    print(json.dumps({'status': status, 'evidence': evidence_summary, **state}))
`;

interface OrchestrationResult {
  status: number;
  stageCalls: number;
  stageContract: boolean;
  buildCalls: number;
  caseOrder: string[];
  providerRequests: number;
  mockMethods: { GET: number; POST: number };
  allRootsRemoved: boolean;
  emittedWhileRootPresent: boolean;
  reportWrittenWhileRootPresent: boolean;
  provenancePreservedAtBuild: boolean;
  reportBytes: number;
  wireBytes: number;
  binaryEvidenceWrites: number;
  binaryFlushes: number;
  outputEvents: string[];
  literalMultibyteUtf8: boolean;
  utf8PrefixWithoutBom: boolean;
  evidence: { ok: boolean; cleanup: boolean; reason?: string; signatureVerified?: boolean;
    stageSourceSha256?: string; bundles?: Record<string, { bytes: number; sha256: string }>;
    package?: { packageNoticesPreserved: Record<string, string> }; cases: { providerRequests: number }[] };
}

async function orchestrationCase(mode: string): Promise<OrchestrationResult> {
  const result = await execute("python3", ["-B", "-I", "-S", "-c", orchestrationHarness, mode], {
    cwd: process.cwd(), timeout: 10_000, maxBuffer: 64 * 1024,
    env: { PATH: process.env.PATH ?? "/usr/bin:/bin", PYTHONDONTWRITEBYTECODE: "1" }
  });
  return JSON.parse(result.stdout) as OrchestrationResult;
}

describe("controlled reviewer artifact orchestration", () => {
  it("stages once in a fresh private child under the original deadline and retains the returned provenance", async () => {
    const result = await orchestrationCase("success");
    expect(result.stageCalls).toBe(1);
    expect(result.stageContract).toBe(true);
    expect(result.status).toBe(0);
    expect(result.buildCalls).toBe(1);
    expect(result.caseOrder).toEqual(["mechanical", "bytes", "inodes", "detached", "sandbox", "status-api", "status-oauth",
      "status-unknown", "status-auto", "status-keyring", "api", "persistence"]);
    expect(result.provenancePreservedAtBuild).toBe(true);
    expect(result.evidence).toMatchObject({ ok: true, cleanup: true, signatureVerified: true, stageSourceSha256: "c".repeat(64),
      package: { packageNoticesPreserved: { "licenses/LICENSE.txt": "d".repeat(64) } } });
    expect(Object.keys(result.evidence.bundles ?? {})).toEqual(["package", "native", "bwrap"]);
    expect(result.mockMethods).toEqual({ GET: 1, POST: 1 });
    expect(result.allRootsRemoved).toBe(true);
    expect(result.emittedWhileRootPresent).toBe(false);
    expect(result.reportWrittenWhileRootPresent).toBe(false);
  });

  it.each([
    ["stage-failure", "bundle/package/pinned-hash/mismatch"], ["stage-deadline", "deadline"],
    ["stage-head-mismatch", "ci-context"]
  ])("cleans partial artifacts and stops before build or native execution for %s", async (mode, reason) => {
    const result = await orchestrationCase(mode);
    expect(result.status).toBe(1);
    expect(result.stageCalls).toBe(1);
    expect(result.stageContract).toBe(true);
    expect(result.buildCalls).toBe(0);
    expect(result.caseOrder).toEqual([]);
    expect(result.mockMethods).toEqual({ GET: 0, POST: 0 });
    expect(result.evidence).toMatchObject({ ok: false, cleanup: true, reason });
    expect(result.evidence.signatureVerified).toBeUndefined();
    expect(result.allRootsRemoved).toBe(true);
    expect(result.emittedWhileRootPresent).toBe(false);
  });

  it("stops at the first unsupported native sandbox before any auth or mock API case and still removes artifacts", async () => {
    const result = await orchestrationCase("native-unsupported");
    expect(result.status).toBe(1);
    expect(result.caseOrder).toEqual(["mechanical", "bytes", "inodes", "detached", "sandbox"]);
    expect(result.providerRequests).toBe(0);
    expect(result.mockMethods).toEqual({ GET: 0, POST: 0 });
    expect(result.evidence.cases.every((entry) => entry.providerRequests === 0)).toBe(true);
    expect(result.evidence).toMatchObject({ ok: false, cleanup: true, reason: "native-sandbox", signatureVerified: true });
    expect(result.allRootsRemoved).toBe(true);
    expect(result.emittedWhileRootPresent).toBe(false);
  });

  it("reports cleanup failure instead of success when the temporary artifact and auth root cannot be deleted", async () => {
    const result = await orchestrationCase("temp-cleanup-failure");
    expect(result.status).toBe(1);
    expect(result.evidence).toMatchObject({ ok: false, cleanup: false, reason: "cleanup" });
    expect(result.allRootsRemoved).toBe(false);
  });

  it("still deletes the private root when Docker image cleanup fails and reports the cleanup failure", async () => {
    const result = await orchestrationCase("image-cleanup-failure");
    expect(result.status).toBe(1);
    expect(result.evidence).toMatchObject({ ok: false, cleanup: false, reason: "cleanup" });
    expect(result.allRootsRemoved).toBe(true);
    expect(result.emittedWhileRootPresent).toBe(false);
  });

  it("bounds cleanup separately from runtime and restores the alarm and both clocks after interruption", async () => {
    const result = await execute("python3", ["-B", "-I", "-S", "-c", orchestrationHarness, "cleanup-clock"], {
      cwd: process.cwd(), timeout: 10_000, maxBuffer: 64 * 1024,
      env: { PATH: process.env.PATH ?? "/usr/bin:/bin", PYTHONDONTWRITEBYTECODE: "1" }
    });
    expect(JSON.parse(result.stdout)).toEqual({ bounded: true, restored: true, reason: "cleanup" });
  });

  it.each(["oversized-evidence", "oversized-run-id"])("writes the exact checked compact fallback to the report for %s", async (mode) => {
    const result = await orchestrationCase(mode);
    expect(result.status).toBe(1);
    expect(result.evidence).toMatchObject({ ok: false, cleanup: true, reason: "evidence-limit" });
    expect(result.wireBytes).toBe(result.reportBytes + Buffer.byteLength("CONTROLLED_REVIEWER_EVIDENCE "));
    expect(result.wireBytes).toBeLessThanOrEqual(65536);
    expect(result.allRootsRemoved).toBe(true);
    expect(result.emittedWhileRootPresent).toBe(false);
    expect(result.reportWrittenWhileRootPresent).toBe(false);
  });

  it("writes the exact checked UTF-8 wire bytes under a UTF-16 stdout text wrapper without a BOM or transcoding", async () => {
    const result = await orchestrationCase("non-utf8-output");
    expect(result.status).toBe(0);
    expect(result.wireBytes).toBe(65536);
    expect(result.wireBytes).toBe(result.reportBytes + Buffer.byteLength("CONTROLLED_REVIEWER_EVIDENCE "));
    expect(result.literalMultibyteUtf8).toBe(true);
    expect(result.utf8PrefixWithoutBom).toBe(true);
    expect(result.binaryEvidenceWrites).toBe(1);
    expect(result.binaryFlushes).toBeGreaterThanOrEqual(1);
    expect(result.outputEvents.slice(0, 3)).toEqual(["report", "wire-write", "wire-flush"]);
    expect(result.emittedWhileRootPresent).toBe(false);
    expect(result.reportWrittenWhileRootPresent).toBe(false);
  });
});

const evidenceHarness = String.raw`
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
from unittest import mock

spec = importlib.util.spec_from_file_location('runtime_evidence', Path.cwd() / 'scripts/ci/controlled-reviewer-probe.py')
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)
case = json.loads(sys.argv[1])
prefix = b'CONTROLLED_REVIEWER_EVIDENCE '
if case['mode'] == 'boundary':
    evidence = {'schema': 1, 'ok': True, 'cleanup': True, 'payload': ''}
    overhead = len(prefix) + len(json.dumps(evidence, ensure_ascii=False, separators=(',', ':')).encode('utf-8')) + 1
    available = 65536 - overhead
    character = case['character']
    width = len(character.encode('utf-8'))
    evidence['payload'] = character * (available // width) + 'x' * (available % width + case['extra'])
elif case['mode'] == 'fallback':
    evidence = {'schema': 999, 'ok': True, 'cleanup': case['cleanup'], 'payload': '🧪' * 20000,
                **case['context']}
elif case['mode'] == 'unexpected-fallback-overflow':
    output = io.StringIO()
    with mock.patch.object(probe, 'EVIDENCE_PREFIX', 'X' * 65536), contextlib.redirect_stdout(output):
        try:
            probe.encode_evidence({'schema': 1, 'ok': True, 'cleanup': True})
        except probe.Unsupported as error:
            assert str(error) == 'evidence-limit'
        else:
            raise AssertionError('oversized fallback accepted')
    assert output.getvalue() == ''
    print(json.dumps({'rejected': True, 'reason': 'evidence-limit', 'emittedBytes': 0}))
    sys.exit(0)
else:
    raise AssertionError('unsupported synthetic test mode')
original = json.dumps(evidence, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
final, encoded = probe.encode_evidence(evidence)
assert isinstance(encoded, bytes) and json.loads(encoded) == final
assert encoded == json.dumps(final, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
wire = prefix + encoded + b'\n'
assert len(wire) <= 65536
fallback = final.get('reason') == 'evidence-limit'
if fallback:
    assert final['schema'] == 1 and final['ok'] is False and type(final['cleanup']) is bool
    assert final['cleanup'] is (evidence.get('cleanup') is True)
    assert final['omittedBytes'] == len(original)
    assert final['omittedSha256'] == hashlib.sha256(original).hexdigest()
    assert 'payload' not in final
else:
    assert final == evidence
print(json.dumps({'fallback': fallback, 'wireBytes': len(wire), 'compactBytes': len(encoded),
                  'originalBytes': len(original), 'context': {key: final[key] for key in ('repository', 'head', 'runId') if key in final},
                  'cleanup': final['cleanup'], 'omittedBytes': final.get('omittedBytes'),
                  'omittedSha256': final.get('omittedSha256'),
                  'literalMultibyteUtf8': any(value >= 128 for value in encoded)}))
`;

interface EvidenceResult {
  fallback: boolean;
  wireBytes: number;
  compactBytes: number;
  originalBytes: number;
  context: Record<string, string>;
  cleanup: boolean;
  omittedBytes?: number;
  omittedSha256?: string;
  literalMultibyteUtf8: boolean;
}

async function evidenceCase(input: Record<string, unknown>): Promise<EvidenceResult> {
  const result = await execute("python3", ["-B", "-I", "-S", "-c", evidenceHarness, JSON.stringify(input)], {
    cwd: process.cwd(), timeout: 10_000, maxBuffer: 64 * 1024,
    env: { PATH: process.env.PATH ?? "/usr/bin:/bin", PYTHONDONTWRITEBYTECODE: "1" }
  });
  return JSON.parse(result.stdout) as EvidenceResult;
}

describe("controlled reviewer evidence byte limit", () => {
  it.each(["x", "é", "🧪"])("accepts exactly 65536 wire bytes and falls back one byte over for %s", async (character) => {
    const boundary = await evidenceCase({ mode: "boundary", character, extra: 0 });
    expect(boundary.fallback).toBe(false);
    expect(boundary.wireBytes).toBe(65536);
    expect(boundary.literalMultibyteUtf8).toBe(character !== "x");
    const over = await evidenceCase({ mode: "boundary", character, extra: 1 });
    expect(over.fallback).toBe(true);
    expect(over.originalBytes).toBe(boundary.originalBytes + 1);
    expect(over.omittedBytes).toBe(over.originalBytes);
    expect(over.omittedSha256).toMatch(/^[a-f0-9]{64}$/);
    expect(over.wireBytes).toBeLessThanOrEqual(65536);
  });

  it.each([true, false, 1, "true", null])("retains only a strict cleanup truth value in the bounded fallback for %j", async (cleanup) => {
    const context = { repository: "OMT-Global/bootstrap", head: "a".repeat(40), runId: "1".repeat(32) };
    const result = await evidenceCase({ mode: "fallback", cleanup, context });
    expect(result.fallback).toBe(true);
    expect(result.cleanup).toBe(cleanup === true);
    expect(result.context).toEqual(context);
    expect(result.omittedBytes).toBe(result.originalBytes);
    expect(result.omittedSha256).toMatch(/^[a-f0-9]{64}$/);
    expect(result.wireBytes).toBeLessThanOrEqual(65536);
  });

  it.each([
    ["wrong repository, uppercase head, long run ID", { repository: "other/repository", head: "A".repeat(40), runId: "1".repeat(33) }],
    ["oversized run ID", { repository: "OMT-Global/bootstrap-extra", head: "a".repeat(41), runId: "1".repeat(100000) }],
    ["unsupported characters", { repository: false, head: "g".repeat(40), runId: "123x" }],
    ["trailing newlines", { repository: "OMT-Global/bootstrap\n", head: "a".repeat(40) + "\n", runId: "123\n" }],
    ["unsupported types", { repository: ["OMT-Global/bootstrap"], head: false, runId: 123 }]
  ])("omits unsafe or unbounded context instead of copying it into fallback (%s)", async (_label, context) => {
    const result = await evidenceCase({ mode: "fallback", cleanup: true, context });
    expect(result.fallback).toBe(true);
    expect(result.context).toEqual({});
    expect(result.wireBytes).toBeLessThanOrEqual(65536);
    expect(result.omittedBytes).toBe(result.originalBytes);
  });

  it("rejects an unexpectedly oversized fallback before producing any output", async () => {
    const result = await evidenceCase({ mode: "unexpected-fallback-overflow" });
    expect(result).toEqual({ rejected: true, reason: "evidence-limit", emittedBytes: 0 });
  });
});


const publicDiagnosticHarness = String.raw`
"""Public diagnostic proposal fixtures: FakePopen only, never a native/Docker/auth adapter."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import types
import unittest
from unittest import mock

source = Path.cwd() / 'scripts/ci/controlled-reviewer-probe.py'
spec = importlib.util.spec_from_file_location('public_diagnostic_under_test', source)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)
PHASES = ('image-history', 'mechanical-create', 'mechanical-start',
          'mechanical-inspect-running', 'mechanical-inspect-stopped', 'mechanical-remove')
FIELDS = {'phase', 'exitCode', 'exitObservedBeforeCleanup', 'stdoutBytes', 'stderrBytes',
          'stdoutSha256', 'stderrSha256', 'streamsComplete'}


@contextlib.contextmanager
def processes(specifications):
    remaining, registry, created = list(specifications), {}, []
    class Input(io.BytesIO):
        def __init__(self):
            super().__init__()
            self.written = bytearray()
        def write(self, value):
            self.written.extend(value)
            return super().write(value)
    class Stream:
        def __init__(self, fd, content):
            self.fd, self.content, self.closed = fd, content, False
            registry[fd] = self
        def fileno(self):
            return self.fd
        def close(self):
            self.closed = True
    class FakePopen:
        def __init__(self, *args, **kwargs):
            if not remaining:
                raise AssertionError('unexpected fake command')
            stdout, stderr, self.desired_exit = remaining.pop(0)
            self.pid, self.returncode, self.killed = 5000 + len(created), None, False
            self.stdin = Input()
            self.stdout = Stream(self.pid * 2, stdout)
            self.stderr = Stream(self.pid * 2 + 1, stderr)
            created.append(self)
        def wait(self, timeout):
            if self.returncode is None:
                self.returncode = self.desired_exit
            return self.returncode
        def poll(self):
            return self.returncode
    class Selector:
        def __init__(self):
            self.entries = {}
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def register(self, stream, events, data):
            self.entries[stream.fd] = types.SimpleNamespace(fd=stream.fd, fileobj=stream, data=data)
        def unregister(self, stream):
            del self.entries[stream.fd]
        def get_map(self):
            return self.entries
        def select(self, timeout):
            return [(entry, 1) for entry in list(self.entries.values())]
    def read(fd, amount):
        stream = registry[fd]
        result, stream.content = stream.content[:amount], stream.content[amount:]
        return result
    def kill(pid, sig):
        child = next(child for child in created if child.pid == pid)
        child.killed = True
        if child.returncode is None:
            child.returncode = -9
    with mock.patch.object(probe.subprocess, 'Popen', FakePopen), \
            mock.patch.object(probe.selectors, 'DefaultSelector', Selector), \
            mock.patch.object(probe.os, 'read', side_effect=read), \
            mock.patch.object(probe.os, 'killpg', side_effect=kill):
        yield created
    assert not remaining
    assert all(child.killed and child.stdin.closed and child.stdout.closed and child.stderr.closed for child in created)


def mechanical(mode, include_history=False, capture=None):
    diagnostic = {'stage': 'image-history', 'commands': [], 'readyEventSeen': False,
                  'resultEventSeen': False, 'resultOk': None}
    ready = json.dumps({'event': 'ready', 'uid': os.getuid(), 'gid': os.getgid(),
                       'addressSpace': {'soft': 17179869184, 'hard': 17179869184}}).encode() + b'\n'
    result = json.dumps({'event': 'result', 'case': 'mechanical', 'ok': mode != 'pre-ready', 'providerRequests': 0}).encode() + b'\n'
    running = json.dumps([{'State': {'Running': True, 'Pid': 123},
                           'HostConfig': {'NetworkMode': 'none', 'ReadonlyRootfs': True}}]).encode()
    stopped = json.dumps([{'State': {'Running': False}}]).encode()
    queue = [(b'public history', b'', 0)] if include_history else []
    queue += [(b'public container id', b'public synthetic create diagnostic', 17 if mode == 'create' else 0)]
    launcher_exit = {'launcher-missing': 127, 'launcher-nonexec': 126, 'launcher-limit-failure': 1}.get(mode)
    if mode != 'create':
        if launcher_exit is not None:
            queue.append((b'', b'public synthetic launcher failure', launcher_exit))
        else:
            queue.append((result if mode == 'pre-ready' else ready + result, b'', 1 if mode == 'pre-ready' else 0))
        if mode != 'pre-ready' and launcher_exit is None:
            queue.append((running, b'', 0))
        if mode not in ('pre-ready', 'cgroup') and launcher_exit is None:
            queue.append((stopped, b'', 0))
        queue.append((b'', b'public remove diagnostic', 17 if mode == 'remove' else 0))
    with tempfile.TemporaryDirectory(prefix='bootstrap-public-diagnostic-fixture-') as temporary:
        pending = []
        def cgroup(pid):
            if mode == 'cgroup':
                raise probe.Unsupported('mechanical')
            return Path(temporary) / 'absent-synthetic-cgroup'
        with processes(queue) as children, mock.patch.object(probe, 'cgroup_for', side_effect=cgroup):
            if include_history:
                probe.command(['never-executed', 'history'], trace=diagnostic['commands'], phase='image-history')
            try:
                value = probe.case_run('mechanical', 'synthetic-image', Path(temporary), pending, '', diagnostic)
                reason = None
            except probe.Unsupported as error:
                value, reason = None, str(error)
            if capture is not None:
                capture.update(commands=len(children), inputWrites=[bytes(child.stdin.written) for child in children])
        return diagnostic, value, reason, pending


class PublicDiagnosticTests(unittest.TestCase):
    def setUp(self):
        probe.DEADLINE = probe.CLEANUP_DEADLINE = time.monotonic() + 10
        probe.ENV, probe.DOCKER = {'PUBLIC_TEST_SENTINEL': 'environment-must-not-be-published'}, ['never-executed']

    def test_all_six_nonzero_phases_keep_only_public_counts_hashes_and_observed_exit(self):
        stdout, stderr = b'public raw stdout DO_NOT_PUBLISH\n', b'public raw stderr DO_NOT_PUBLISH\n'
        for phase in PHASES:
            with self.subTest(phase=phase), processes([(stdout, stderr, 17)]):
                trace = []
                with self.assertRaisesRegex(probe.Unsupported, '^process$'):
                    probe.command(['never-executed', 'argument-must-not-be-published'], trace=trace, phase=phase)
                self.assertEqual(trace, [{'phase': phase, 'exitCode': 17, 'exitObservedBeforeCleanup': True,
                    'stdoutBytes': len(stdout), 'stderrBytes': len(stderr), 'stdoutSha256': hashlib.sha256(stdout).hexdigest(),
                    'stderrSha256': hashlib.sha256(stderr).hexdigest(), 'streamsComplete': True}])
                self.assertEqual(set(trace[0]), FIELDS)
                self.assertNotIn('DO_NOT_PUBLISH', json.dumps(trace))
                self.assertNotIn('must-not-be-published', json.dumps(trace))

    def test_start_exit_one_and_137_remain_accepted_with_the_existing_line_protocol(self):
        for code in (1, 137):
            with self.subTest(code=code), processes([(b'public-line\n', b'', code)]):
                trace, lines = [], []
                self.assertEqual(probe.command(['never-executed'], on_line=lambda line, stdin: lines.append(line),
                    trace=trace, phase='mechanical-start'), b'')
                self.assertEqual(lines, [b'public-line'])
                self.assertEqual(trace[0]['exitCode'], code)
                self.assertTrue(trace[0]['exitObservedBeforeCleanup'] and trace[0]['streamsComplete'])

    def test_untraced_commands_do_not_hash_or_change_stdout(self):
        with processes([(b'public stdout', b'public stderr', 0)]), \
                mock.patch.object(probe.hashlib, 'sha256', side_effect=AssertionError('untraced hashing')):
            self.assertEqual(probe.command(['never-executed']), b'public stdout')

    def test_enum_and_six_entry_cap_fail_before_any_process_object(self):
        for trace, phase in (([], 'status-api'), ([], None), ([{}] * 6, 'image-history')):
            with self.subTest(phase=phase, count=len(trace)), processes([]):
                before = list(trace)
                with self.assertRaisesRegex(probe.Unsupported, '^diagnostic$'):
                    probe.command(['never-executed'], trace=trace, phase=phase)
                self.assertEqual(trace, before)

    def test_output_and_deadline_controls_still_abort_and_identify_observer_cleanup(self):
        trace = []
        with processes([(b'x' * 80, b'', 0)]):
            with self.assertRaisesRegex(probe.Unsupported, '^output$'):
                probe.command(['never-executed'], limit=32, trace=trace, phase='mechanical-create')
        self.assertFalse(trace[0]['streamsComplete'] or trace[0]['exitObservedBeforeCleanup'])
        self.assertEqual(trace[0]['exitCode'], -9)
        self.assertEqual(trace[0]['stdoutBytes'], 0)
        self.assertEqual(trace[0]['stdoutSha256'], hashlib.sha256(b'').hexdigest())
        trace = []
        probe.DEADLINE = 1
        with processes([(b'', b'', 0)]), mock.patch.object(probe.time, 'monotonic', side_effect=[0, 0, 2]):
            with self.assertRaisesRegex(probe.Unsupported, '^deadline$'):
                probe.command(['never-executed'], trace=trace, phase='mechanical-start')
        self.assertFalse(trace[0]['streamsComplete'] or trace[0]['exitObservedBeforeCleanup'])
        self.assertEqual(trace[0]['exitCode'], -9)

    def test_mechanical_failure_stages_survive_cleanup_and_retained_names(self):
        for mode, stage, ready, result, ok, retained in (
                ('create', 'mechanical-create', False, False, None, True),
                ('pre-ready', 'post-case-cgroup', False, True, False, False),
                ('cgroup', 'host-cgroup', True, False, None, False),
                ('remove', 'mechanical-remove', True, True, True, True)):
            with self.subTest(mode=mode):
                diagnostic, value, reason, pending = mechanical(mode)
                self.assertIsNone(value)
                self.assertIsNotNone(reason)
                self.assertEqual(diagnostic.get('failureStage', diagnostic['stage']), stage)
                self.assertEqual((diagnostic['readyEventSeen'], diagnostic['resultEventSeen'], diagnostic['resultOk']), (ready, result, ok))
                self.assertEqual(bool(pending), retained)
                if not retained:
                    self.assertEqual(diagnostic['stage'], 'container-removed')

    def test_history_and_complete_mechanical_use_exactly_the_six_public_slots(self):
        diagnostic, value, reason, pending = mechanical('success', include_history=True)
        self.assertIsNone(reason)
        self.assertEqual(value, {'case': 'mechanical', 'ok': True, 'providerRequests': 0,
                                'addressSpace': {'soft': 17179869184, 'hard': 17179869184}})
        self.assertEqual(pending, [])
        self.assertEqual([entry['phase'] for entry in diagnostic['commands']], list(PHASES))
        self.assertTrue(diagnostic['readyEventSeen'] and diagnostic['resultEventSeen'] and diagnostic['resultOk'])
        self.assertNotIn('failureStage', diagnostic)
        self.assertEqual(diagnostic['stage'], 'container-removed')

    def test_diagnostics_are_rejected_before_auth_or_native_cases(self):
        with tempfile.TemporaryDirectory(prefix='bootstrap-no-auth-diagnostic-fixture-') as temporary, processes([]):
            for case in ('sandbox', 'status-api', 'api', 'persistence'):
                with self.subTest(case=case), self.assertRaisesRegex(probe.Unsupported, '^diagnostic$'):
                    probe.case_run(case, 'synthetic-image', Path(temporary), [], '', {'commands': []})
            self.assertEqual(list(Path(temporary).iterdir()), [])

    def test_missing_nonexecutable_or_failed_limit_launcher_never_advances_or_falls_back(self):
        for mode, code in (('launcher-missing', 127), ('launcher-nonexec', 126), ('launcher-limit-failure', 1)):
            with self.subTest(mode=mode):
                capture = {}
                diagnostic, value, reason, pending = mechanical(mode, capture=capture)
                self.assertIsNone(value)
                self.assertIsNotNone(reason)
                self.assertEqual(pending, [])
                self.assertFalse(diagnostic['readyEventSeen'] or diagnostic['resultEventSeen'])
                self.assertIsNone(diagnostic['resultOk'])
                self.assertEqual(diagnostic['stage'], 'container-removed')
                self.assertEqual([entry['phase'] for entry in diagnostic['commands']],
                                 ['mechanical-create', 'mechanical-start', 'mechanical-remove'])
                self.assertEqual(diagnostic['commands'][1]['exitCode'], code)
                self.assertEqual(capture, {'commands': 3, 'inputWrites': [b'', b'', b'']})


log = io.StringIO()
result = unittest.TextTestRunner(stream=log).run(unittest.defaultTestLoader.loadTestsFromTestCase(PublicDiagnosticTests))
if not result.wasSuccessful():
    print(log.getvalue(), file=sys.stderr)
    sys.exit(1)
print(json.dumps({'testCases': result.testsRun, 'publicPhases': list(PHASES),
                  'nativeDockerAuthNetworkProcesses': 0, 'allProcessesWereFakePopen': True}))
`;

describe("controlled reviewer public pre-auth diagnostic", () => {
  it("records bounded public command metadata and failure stages using only fake process fixtures", async () => {
    const result = await execute("python3", ["-B", "-I", "-S", "-c", publicDiagnosticHarness], {
      cwd: process.cwd(), timeout: 10_000, maxBuffer: 64 * 1024,
      env: { PATH: process.env.PATH ?? "/usr/bin:/bin", PYTHONDONTWRITEBYTECODE: "1" }
    });
    expect(JSON.parse(result.stdout)).toEqual({ testCases: 9,
      publicPhases: ["image-history", "mechanical-create", "mechanical-start", "mechanical-inspect-running",
        "mechanical-inspect-stopped", "mechanical-remove"],
      nativeDockerAuthNetworkProcesses: 0, allProcessesWereFakePopen: true });
  });
});


const addressSpaceHarness = String.raw`
"""Inherited address-space fixtures; every resource setter and Linux observation is mocked."""
import contextlib
import ctypes
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import types
import unittest
from unittest import mock

ROOT = Path.cwd()


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts/ci' / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


fixture = load('inherited_address_space_fixture', 'controlled-reviewer-fixture.py')
host = load('inherited_address_space_host', 'controlled-reviewer-probe.py')
LIMIT = 17179869184
PAIR = {'soft': LIMIT, 'hard': LIMIT}


@contextlib.contextmanager
def admission(pair, setter):
    order = []
    def getter(resource):
        order.append(('get', resource))
        return pair
    def set_limit(resource, values):
        order.append(('set', resource, values))
        return setter(resource, values)
    with mock.patch.object(fixture.sys, 'platform', 'linux'), \
            mock.patch.object(fixture.os, 'getpid', return_value=1), \
            mock.patch.object(fixture.os, 'getuid', return_value=1000), \
            mock.patch.object(fixture.os, 'getgid', return_value=1000), \
            mock.patch.object(fixture.os, 'umask'), \
            mock.patch.object(fixture.resource, 'getrlimit', side_effect=getter), \
            mock.patch.object(fixture.resource, 'setrlimit', side_effect=set_limit), \
            mock.patch.object(fixture, 'emit') as emit, \
            mock.patch.object(fixture, 'native', side_effect=AssertionError('native forbidden')) as native:
        yield order, emit, native


class SetterReached(Exception):
    pass


def stop_at_setter(resource, values):
    raise SetterReached('synthetic first-setter sentinel')


def host_case(fields):
    state = {'running': False, 'go': bytearray(), 'resultSent': False, 'operations': [], 'createArguments': []}
    class Input(io.BytesIO):
        def write(self, value):
            state['go'].extend(value)
            return super().write(value)
    def command(arguments, **kwargs):
        operation = arguments[len(host.DOCKER)]
        state['operations'].append(operation)
        if operation == 'create':
            state['createArguments'] = arguments
        if operation == 'start':
            state['running'] = True
            callback = kwargs['on_line']
            callback(json.dumps({'event': 'ready', 'uid': os.getuid(), 'gid': os.getgid(), **fields}).encode(), Input())
            state['resultSent'] = True
            callback(json.dumps({'event': 'result', 'case': 'mechanical', 'ok': True, 'providerRequests': 0}).encode(), Input())
            state['running'] = False
        return b''
    with tempfile.TemporaryDirectory(prefix='bootstrap-as-ready-fixture-') as temporary, \
            mock.patch.object(host, 'command', side_effect=command), \
            mock.patch.object(host, 'inspect', side_effect=lambda name: {
                'State': {'Running': state['running'], 'Pid': 123},
                'HostConfig': {'NetworkMode': 'none', 'ReadonlyRootfs': True}}), \
            mock.patch.object(host, 'cgroup_for', return_value=Path(temporary) / 'absent-cgroup'):
        pending = []
        host.DOCKER = ['never-executed']
        try:
            value = host.case_run('mechanical', 'public-fixture-image', Path(temporary), pending, '')
            reason = None
        except host.Unsupported as error:
            value, reason = None, str(error)
        assert not pending and state['operations'][-1] == 'rm'
    return state, value, reason


class InheritedAddressSpaceTests(unittest.TestCase):
    def test_invalid_inherited_pairs_fail_before_any_setter_ready_or_native_call(self):
        for pair in ((-1, -1), (LIMIT, -1), (-1, LIMIT), (LIMIT - 1, LIMIT - 1),
                     (LIMIT + 1, LIMIT + 1), (0, 0), (LIMIT - 1, LIMIT), (LIMIT, LIMIT + 1)):
            with self.subTest(pair=pair), admission(pair, stop_at_setter) as (order, emit, native):
                with self.assertRaisesRegex(RuntimeError, '^fixture-check-failed$'):
                    fixture.gate()
                self.assertEqual(order, [('get', fixture.resource.RLIMIT_AS)])
                emit.assert_not_called()
                native.assert_not_called()

    def test_exact_inherited_pair_reaches_the_original_first_setter_only_after_admission(self):
        with admission((LIMIT, LIMIT), stop_at_setter) as (order, emit, native):
            with self.assertRaises(SetterReached):
                fixture.gate()
            first_resource, first_value = next(iter(fixture.LIMITS.values()))
            self.assertEqual(order, [('get', fixture.resource.RLIMIT_AS), ('set', first_resource, (first_value, first_value))])
            emit.assert_not_called()
            native.assert_not_called()

    def test_setter_failure_after_valid_admission_has_no_ready_native_or_fallback(self):
        def fail(resource, values):
            raise OSError('synthetic limit setter failure')
        with admission((LIMIT, LIMIT), fail) as (order, emit, native):
            with self.assertRaisesRegex(OSError, '^synthetic limit setter failure$'):
                fixture.gate()
            self.assertEqual(len(order), 2)
            self.assertEqual(order[0], ('get', fixture.resource.RLIMIT_AS))
            emit.assert_not_called()
            native.assert_not_called()

    def test_ready_reports_the_measured_inherited_pair_after_the_unchanged_mocked_gate(self):
        values = {'memory.max': '2147483648', 'memory.swap.max': '0', 'pids.max': '128', 'cpu.max': '200000 100000'}
        status = '\n'.join(name + ': 0' for name in ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb')) + '\nNoNewPrivs: 1\n'
        elf = b'\x7fELF\x02\x01\x01' + bytes(11) + b'\x3e\x00'
        with tempfile.TemporaryDirectory(prefix='bootstrap-as-full-gate-fixture-') as temporary:
            def read_text(path, *args, **kwargs):
                if str(path) == '/proc/self/status':
                    return status
                if str(path) == '/proc/self/mountinfo':
                    return '1 0 0:0 / / ro - ext4 root ro\n2 1 0:1 / ' + temporary + ' rw - tmpfs tmpfs rw\n'
                return values[path.name]
            def statfs(path, raw):
                ctypes.cast(raw, ctypes.POINTER(ctypes.c_long))[0] = 0x01021994
                return 0
            with admission((LIMIT, LIMIT), lambda resource, value: None) as (order, emit, native), \
                    mock.patch.object(fixture, 'ROOT', Path(temporary)), \
                    mock.patch.object(fixture.os, 'environ', {}), \
                    mock.patch.object(Path, 'read_text', read_text), \
                    mock.patch.object(Path, 'lstat', return_value=types.SimpleNamespace(st_mode=stat.S_IFREG | 0o755, st_uid=0, st_nlink=1)), \
                    mock.patch.object(Path, 'open', side_effect=lambda *args, **kwargs: io.BytesIO(elf)), \
                    mock.patch.object(fixture.os.path, 'exists', return_value=False), \
                    mock.patch.object(fixture.os, 'access', return_value=False), \
                    mock.patch.object(fixture.os, 'statvfs', return_value=types.SimpleNamespace(f_blocks=64, f_frsize=4096, f_files=16384)), \
                    mock.patch.object(fixture.ctypes, 'CDLL', return_value=types.SimpleNamespace(statfs=statfs)), \
                    mock.patch.object(fixture.os, 'uname', return_value=types.SimpleNamespace(machine='x86_64')), \
                    mock.patch.object(fixture.sys, 'stdin', types.SimpleNamespace(buffer=io.BytesIO(b'GO\n'))):
                fixture.gate()
                expected = [('get', fixture.resource.RLIMIT_AS)] + [('set', resource, (value, value)) for resource, value in fixture.LIMITS.values()]
                self.assertEqual(order, expected)
                emit.assert_called_once()
                self.assertEqual(emit.call_args.args[0]['addressSpace'], PAIR)
                self.assertTrue(emit.call_args.args[0]['pid1'])
                native.assert_not_called()

    def test_host_rejects_malformed_pairs_before_go_and_retains_the_valid_mechanical_pair(self):
        malformed = [{}, {'addressSpace': None}, {'addressSpace': []}, {'addressSpace': {}},
                     {'addressSpace': {'soft': LIMIT}}, {'addressSpace': {**PAIR, 'extra': 0}},
                     {'addressSpace': {'soft': True, 'hard': LIMIT}}, {'addressSpace': {'soft': str(LIMIT), 'hard': LIMIT}},
                     {'addressSpace': {'soft': float(LIMIT), 'hard': LIMIT}}, {'addressSpace': {'soft': -1, 'hard': -1}},
                     {'addressSpace': {'soft': LIMIT - 1, 'hard': LIMIT}}, {'addressSpace': {'soft': LIMIT, 'hard': LIMIT + 1}}]
        for fields in malformed:
            with self.subTest(fields=fields):
                state, value, reason = host_case(fields)
                self.assertIsNone(value)
                self.assertEqual(reason, 'address-space')
                self.assertFalse(state['go'] or state['resultSent'])
                self.assertEqual(state['operations'], ['create', 'start', 'rm'])
        state, value, reason = host_case({'addressSpace': PAIR})
        self.assertIsNone(reason)
        self.assertEqual(value, {'case': 'mechanical', 'ok': True, 'providerRequests': 0, 'addressSpace': PAIR})
        self.assertEqual(state['go'], b'GO\n')
        arguments = state['createArguments']
        self.assertEqual([arguments[index + 1] for index, argument in enumerate(arguments) if argument == '--ulimit'],
                         ['core=0:0', 'fsize=67108864:67108864', 'nofile=256:256', 'nproc=128:128', 'cpu=3600:3600'])
        self.assertEqual(arguments[-3:], ['public-fixture-image', '--case', 'mechanical'])


log = io.StringIO()
result = unittest.TextTestRunner(stream=log).run(unittest.defaultTestLoader.loadTestsFromTestCase(InheritedAddressSpaceTests))
if not result.wasSuccessful():
    print(log.getvalue(), file=sys.stderr)
    sys.exit(1)
print(json.dumps({'testCases': result.testsRun, 'actualResourceSetters': 0, 'nativeOrLauncherProcesses': 0}))
`;

describe("controlled reviewer inherited address space", () => {
  it("admits the inherited pair before setters and checks the measured ready pair before GO using pure fixtures", async () => {
    const result = await execute("python3", ["-B", "-I", "-S", "-c", addressSpaceHarness], {
      cwd: process.cwd(), timeout: 10_000, maxBuffer: 64 * 1024,
      env: { PATH: process.env.PATH ?? "/usr/bin:/bin", PYTHONDONTWRITEBYTECODE: "1" }
    });
    expect(JSON.parse(result.stdout)).toEqual({ testCases: 5, actualResourceSetters: 0, nativeOrLauncherProcesses: 0 });
  });

  it("uses the fixed prlimit exec form before Python with no shell, PID selector or fallback", async () => {
    const dockerfile = await readFile("scripts/ci/controlled-reviewer-probe.Dockerfile", "utf8");
    const lines = dockerfile.split("\n").filter((line) => line.startsWith("ENTRYPOINT "));
    expect(lines).toHaveLength(1);
    expect(JSON.parse(lines[0]!.slice("ENTRYPOINT ".length))).toEqual([
      "/usr/bin/prlimit", "--as=17179869184:17179869184", "--", "/usr/bin/python3", "-I", "-S", "-u",
      "/opt/bootstrap-review/reviewer-gate.py"
    ]);
  });
});
