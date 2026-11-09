import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { describe, expect, it } from "vitest";
const execute = promisify(execFile);

const driverHarness = String.raw`
READY_SECURITY = {'pid1': True, 'root_ro': True, 'mounts_safe': True, 'caps_zero': True, 'no_new_privs': True, 'seccomp': 2, 'apparmor': 'docker-default (enforce)', 'tmpfs': {'type': 0x01021994, 'bytes': 268435456, 'inodes': 16384, 'flags': 14}}
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
                callback(json.dumps({'event': 'ready', 'uid': os.getuid(), 'gid': os.getgid(), **READY_SECURITY,
                    'addressSpace': {'soft': 17179869184, 'hard': 17179869184}}).encode(), io.BytesIO())
                callback(json.dumps({'event': 'result', 'case': 'api', 'ok': mode != 'api-failure',
                    'providerRequests': 0 if mode == 'api-failure' else 2, 'mockMethods': methods,
                    **({'admissionFailure': {'raw': 'private-later-case-canary'}} if mode == 'api-extra-admission' else {})}).encode(), io.BytesIO())
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
async function driverCase(mode: string, methods: Record<string, number | boolean | undefined> = {}) {
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
  it("does not publish an admission-shaped field from a later untraced API fixture", async () => {
    const result = await driverCase("api-extra-admission", { GET: 1, POST: 1 });
    expect(result.rejected).toBe(false);
    expect(result.cleanupCalled).toBe(true);
    expect(result.result).not.toHaveProperty("admissionFailure");
    expect(result.result).not.toHaveProperty("fixtureAdmissionFailure");
    expect(JSON.stringify(result)).not.toContain("private-later-case-canary");
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
READY_SECURITY = {'pid1': True, 'root_ro': True, 'mounts_safe': True, 'caps_zero': True, 'no_new_privs': True, 'seccomp': 2, 'apparmor': 'docker-default (enforce)', 'tmpfs': {'type': 0x01021994, 'bytes': 268435456, 'inodes': 16384, 'flags': 14}}
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
import urllib.error
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
real_write_bytes, real_read_bytes, real_mkdir = Path.write_bytes, Path.read_bytes, Path.mkdir
with tempfile.TemporaryDirectory(prefix='bootstrap-runtime-orchestration-') as outer:
    outer = Path(outer)
    probe.HERE = outer / 'scripts/ci'
    probe.HERE.mkdir(parents=True)
    for name in ('controlled-reviewer-probe.py', 'controlled-reviewer-fixture.py', 'controlled-reviewer-probe.Dockerfile'):
        (probe.HERE / name).write_text('public synthetic test source')
    state = {'roots': [], 'stageCalls': 0, 'buildCalls': 0, 'caseOrder': [], 'providerRequests': 0,
             'mockMethods': {'GET': 0, 'POST': 0}, 'emittedWhileRootPresent': False,
             'reportWrittenWhileRootPresent': False, 'provenancePreservedAtBuild': False,
             'binaryEvidenceWrites': 0, 'binaryFlushes': 0, 'outputEvents': [],
             'deadline': None, 'stageContract': False, 'stageReturned': False, 'directCodeReads': []}
    retained_cleanup = mode.startswith('retained-cleanup-')
    cleanup_clock_state = {'now': 1000.0, 'handler': object(), 'timer': (0.0, 0.0), 'timerCalls': []}
    if retained_cleanup:
        state.update(cleanupAttempts=[], cleanupClockEntries=0, rootRemovalAttempted=False,
                     alreadyAbsentExitZero=False, retainedAdded=False)
        original_cleanup_clock = probe.cleanup_clock
        def set_timer(which, seconds, interval=0.0):
            previous = cleanup_clock_state['timer']
            cleanup_clock_state['timer'] = (seconds, interval)
            cleanup_clock_state['timerCalls'].append(seconds)
            return previous
        def set_handler(which, handler):
            previous = cleanup_clock_state['handler']
            cleanup_clock_state['handler'] = handler
            return previous
        @contextlib.contextmanager
        def observed_cleanup_clock():
            previous = probe.CLEANUP_DEADLINE
            handler = cleanup_clock_state['handler']
            state['cleanupClockEntries'] += 1
            try:
                with mock.patch.object(probe.time, 'monotonic', side_effect=lambda: cleanup_clock_state['now']), \
                        mock.patch.object(probe.signal, 'getsignal', side_effect=lambda _: cleanup_clock_state['handler']), \
                        mock.patch.object(probe.signal, 'signal', side_effect=set_handler), \
                        mock.patch.object(probe.signal, 'getitimer', side_effect=lambda _: cleanup_clock_state['timer']), \
                        mock.patch.object(probe.signal, 'setitimer', side_effect=set_timer):
                    with original_cleanup_clock():
                        state['observedCleanupDeadline'] = probe.CLEANUP_DEADLINE
                        yield
            finally:
                state['cleanupClockRestored'] = (probe.CLEANUP_DEADLINE == previous and
                                                cleanup_clock_state['handler'] is handler)
                state['cleanupTimerCalls'] = cleanup_clock_state['timerCalls']
                state['cleanupTimerRestored'] = cleanup_clock_state['timer'] == (0.0, 0.0)
        probe.cleanup_clock = observed_cleanup_clock
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
        if mode in ('stage-failure', 'stage-deadline', 'bootstrap-stage', 'bootstrap-http'):
            (directory / 'partial-public-download').write_bytes(b'public synthetic partial data')
            if mode == 'bootstrap-stage':
                raise RuntimeError('private-bootstrap-canary')
            if mode == 'bootstrap-http':
                raise urllib.error.HTTPError('https://private.invalid/private-bootstrap-canary', 429, 'private-bootstrap-canary', {'Private': 'private-bootstrap-canary'}, None)
            raise probe.Unsupported('deadline' if mode == 'stage-deadline' else 'bundle/package/pinned-hash/mismatch')
        context = directory / 'selected-context'
        package = context / 'verified-codex-package'
        package.mkdir(parents=True)
        (context / 'public-provenance.json').write_bytes(provenance)
        for name, data in verified.items():
            (directory / (name + '.standard.json')).write_bytes(data)
        state['context'] = context
        class RetentionFailure:
            def __getitem__(self, key):
                assert key == 'head'
                return stage_evidence[key]
            def keys(self):
                raise MemoryError('private-bootstrap-canary')
        state['stageReturned'] = True
        return {'context': context, 'package': package, 'evidence': RetentionFailure() if mode == 'bootstrap-retention' else stage_evidence,
                'verifiedBundleBytes': verified}

    def forbidden(*args, **kwargs):
        raise AssertionError('duplicate acquisition/preparation or unverified bundle read')

    def read_bytes(path):
        if path.name.endswith('.standard.json'):
            forbidden()
        return real_read_bytes(path)

    actual_case_run = probe.case_run
    def command(arguments, **kwargs):
        if arguments[0] == '/usr/bin/git':
            return b'a' * 40 + b'\n'
        operation = arguments[3]
        if retained_cleanup and kwargs.get('cleanup'):
            target = 'image' if operation == 'image' else arguments[-1]
            allowed = cleanup_clock_state['now'] < probe.CLEANUP_DEADLINE
            state['cleanupAttempts'].append({'target': target, 'deadline': probe.CLEANUP_DEADLINE,
                                             'timeout': kwargs.get('timeout'), 'cleanup': kwargs.get('cleanup'),
                                             'startAllowed': allowed})
            assert kwargs.get('timeout') == 20 and kwargs.get('cleanup') is True
            if not allowed:
                raise probe.Unsupported('cleanup')
            cleanup_clock_state['now'] += 1
            if mode == 'retained-cleanup-deadline' and target == 'retained-first':
                cleanup_clock_state['now'] = probe.CLEANUP_DEADLINE
                raise probe.Unsupported('injected cleanup deadline')
            if mode == 'retained-cleanup-cancel' and target == 'retained-first':
                raise KeyboardInterrupt('synthetic cleanup cancellation')
            if ((mode == 'retained-cleanup-first' and target == 'retained-first') or
                    (mode == 'retained-cleanup-middle' and target == 'retained-middle') or
                    (mode == 'retained-cleanup-image' and target == 'image')):
                raise probe.Unsupported('synthetic individual removal failure')
            if mode == 'retained-cleanup-already-absent' and target == 'retained-first':
                state['alreadyAbsentExitZero'] = True
            return b''
        if operation == 'info':
            if mode == 'bootstrap-docker-command':
                raise probe.Unsupported('process')
            if mode == 'bootstrap-docker-parse':
                return b'private-bootstrap-canary invalid JSON'
            options = json.loads(mode.partition(':')[2]) if mode.startswith('daemon-options:') else ['name=apparmor', 'name=seccomp,profile=builtin']
            return json.dumps({'OSType': 'linux', 'Architecture': 'wrong-fixture-machine' if mode == 'bootstrap-docker-admission' else 'x86_64', 'CgroupVersion': '2', 'SecurityOptions': options}).encode()
        if operation == 'build':
            state['buildCalls'] += 1
            assert Path(arguments[-1]) == state['context']
            assert arguments[4:7] == ['--network', 'none', '--pull=false']
            state['provenancePreservedAtBuild'] = (state['context'] / 'public-provenance.json').read_bytes() == provenance
            assert state['provenancePreservedAtBuild']
            for name in verified:
                (state['context'].parent / (name + '.standard.json')).write_bytes(b'later unverified synthetic bytes')
            if mode == 'bootstrap-later-http':
                raise urllib.error.HTTPError('https://private.invalid/private-bootstrap-canary', 503, 'private-bootstrap-canary', {'Private': 'private-bootstrap-canary'}, None)
        if operation == 'image' and arguments[4] == 'inspect':
            return json.dumps([{'Id': 'sha256:' + 'b' * 64}]).encode()
        if operation == 'image' and arguments[4] == 'rm' and mode == 'image-cleanup-failure':
            raise probe.Unsupported('injected-image-cleanup-failure')
        if operation == 'start' and mode in ('admission-failure', 'admission-cleanup-failure', 'process-mounts-failure', 'process-mounts-cleanup-failure'):
            failure = {'stage': 'inherited-as', 'addressSpace': {'soft': -1, 'hard': -1}}
            if mode.startswith('process-mounts'):
                failure = {'stage': 'process-mounts', 'addressSpace': {'soft': 17179869184, 'hard': 17179869184},
                           'processMounts': {'substage': 'combined-predicate', 'capsZero': True, 'rootRo': True, 'mountsSafe': True, 'noNewPrivs': False}}
            kwargs['on_line'](json.dumps({'event': 'result', 'case': 'mechanical', 'ok': False, 'providerRequests': 0,
                'admissionFailure': failure}).encode(), io.BytesIO())
        return b''

    def case_run(case, *args):
        state['caseOrder'].append(case)
        if retained_cleanup and not state['retainedAdded']:
            args[2].extend(['retained-first', 'retained-middle', 'retained-last'])
            state['retainedAdded'] = True
        if mode in ('admission-failure', 'admission-cleanup-failure', 'process-mounts-failure', 'process-mounts-cleanup-failure'):
            assert case == 'mechanical'
            return actual_case_run(case, *args)
        result = {'case': case, 'ok': not (mode == 'native-unsupported' and case == 'sandbox'), 'providerRequests': 0}
        if case == 'api':
            result.update(providerRequests=2, mockMethods={'GET': 1, 'POST': 1})
            state['providerRequests'] += 2
            state['mockMethods'] = result['mockMethods']
        return result

    def rmtree(path, *args, **kwargs):
        if retained_cleanup and Path(path) in state['roots']:
            state['rootRemovalAttempted'] = True
            if mode == 'retained-cleanup-filesystem':
                raise OSError('synthetic root removal failure')
        if mode in ('temp-cleanup-failure', 'admission-cleanup-failure', 'process-mounts-cleanup-failure') and Path(path) in state['roots']:
            raise OSError('injected temporary cleanup failure')
        return real_rmtree(path, *args, **kwargs)

    def write_bytes(path, *args, **kwargs):
        if path.name == 'controlled-reviewer-evidence.json':
            state['reportWrittenWhileRootPresent'] = any(root.exists() for root in state['roots'])
            state['outputEvents'].append('report')
        return real_write_bytes(path, *args, **kwargs)

    def mkdir(path, *args, **kwargs):
        if mode == 'bootstrap-directory' and path.name == 'artifacts' and path.parent in state['roots']:
            raise OSError('private-bootstrap-canary')
        return real_mkdir(path, *args, **kwargs)

    class DirectDictionary:
        @staticmethod
        def get(mapping, key):
            state['directCodeReads'].append(key)
            return dict.get(mapping, key)

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
            mock.patch.object(Path, 'write_bytes', write_bytes), mock.patch.object(Path, 'mkdir', mkdir), \
            (mock.patch.object(probe, 'dict', DirectDictionary, create=True) if mode in ('bootstrap-http', 'bootstrap-later-http') else contextlib.nullcontext()), \
            contextlib.redirect_stdout(output):
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
    assert report == evidence and 899 < probe.DEADLINE - started <= 901
    if state['stageCalls']:
        assert probe.DEADLINE == state['deadline']
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
  stageReturned: boolean;
  directCodeReads: string[];
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
    bootstrapStage?: string; bootstrapHttpStatus?: number;
    stageSourceSha256?: string; bundles?: Record<string, { bytes: number; sha256: string }>;
    package?: { packageNoticesPreserved: Record<string, string> }; cases: { providerRequests: number }[];
    preAuthDiagnostic?: { fixtureAdmissionFailure?: { stage: string; addressSpace?: { soft: number; hard: number };
      processMounts?: { substage: string; capsZero?: boolean; rootRo?: boolean; mountsSafe?: boolean; noNewPrivs?: boolean } };
      readyEventSeen: boolean; resultEventSeen: boolean; resultOk: boolean | null; failureStage?: string; stage: string } };
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

  it.each(["admission-failure", "admission-cleanup-failure", "process-mounts-failure", "process-mounts-cleanup-failure"])("retains fixture and host failures separately through outer cleanup for %s", async (mode) => {
    const result = await orchestrationCase(mode);
    const cleanup = !mode.includes("cleanup-failure");
    expect(result.status).toBe(1);
    expect(result.caseOrder).toEqual(["mechanical"]);
    expect(result.providerRequests).toBe(0);
    expect(result.mockMethods).toEqual({ GET: 0, POST: 0 });
    expect(result.evidence).toMatchObject({ ok: false, reason: "cleanup", cleanup });
    expect(result.evidence.preAuthDiagnostic).toMatchObject({
      fixtureAdmissionFailure: mode.startsWith("process-mounts") ? {
        stage: "process-mounts", addressSpace: { soft: 17179869184, hard: 17179869184 },
        processMounts: { substage: "combined-predicate", capsZero: true, rootRo: true, mountsSafe: true, noNewPrivs: false }
      } : { stage: "inherited-as", addressSpace: { soft: -1, hard: -1 } },
      readyEventSeen: false, resultEventSeen: true, resultOk: false,
      failureStage: "post-case-cgroup", stage: "container-removed"
    });
    expect(result.allRootsRemoved).toBe(cleanup);
  });

  it.each([
    ["bootstrap-docker-command", "docker-info-command", "process", false, false],
    ["bootstrap-docker-parse", "docker-info-parse", "unsupported", false, false],
    ["bootstrap-docker-admission", "docker-info-admission", "platform", false, false],
    ["bootstrap-directory", "artifact-directory", "unsupported", false, false],
    ["bootstrap-stage", "artifact-stage-call", "unsupported", true, false],
    ["stage-head-mismatch", "staged-head-admission", "ci-context", true, true],
    ["bootstrap-retention", "staged-evidence-retention", "unsupported", true, true]
  ] as const)("retains the attempted bootstrap operation and separate API-return facts for %s", async (mode, stage, reason, entered, returned) => {
    const result = await orchestrationCase(mode);
    expect(result.status).toBe(1);
    expect(result.evidence).toMatchObject({ ok: false, cleanup: true, reason, bootstrapStage: stage });
    expect(result.stageCalls).toBe(entered ? 1 : 0);
    expect(result.stageReturned).toBe(returned);
    expect(result.buildCalls).toBe(0);
    expect(result.caseOrder).toEqual([]);
    expect(result.evidence.signatureVerified).toBeUndefined();
    expect(result.evidence.bootstrapHttpStatus).toBeUndefined();
    expect(result.allRootsRemoved).toBe(true);
    expect(result.reportWrittenWhileRootPresent).toBe(false);
    expect(result.emittedWhileRootPresent).toBe(false);
    expect(JSON.stringify(result)).not.toContain("private-bootstrap-canary");
  });

  it.each(["bootstrap-http", "bootstrap-later-http"])("observes only an early direct HTTP status and leaves later errors uninspected for %s", async (mode) => {
    const result = await orchestrationCase(mode);
    expect(result.status).toBe(1);
    expect(result.evidence).toMatchObject({ ok: false, cleanup: true, reason: "unsupported" });
    expect(result.caseOrder).toEqual([]);
    expect(result.mockMethods).toEqual({ GET: 0, POST: 0 });
    if (mode === "bootstrap-http") {
      expect(result.evidence.bootstrapStage).toBe("artifact-stage-call");
      expect(result.evidence.bootstrapHttpStatus).toBe(429);
      expect(result.directCodeReads).toEqual(["code"]);
      expect(result.stageReturned).toBe(false);
    } else {
      expect(result.evidence.bootstrapStage).toBeUndefined();
      expect(result.evidence.bootstrapHttpStatus).toBeUndefined();
      expect(result.directCodeReads).toEqual([]);
      expect(result.stageReturned).toBe(true);
      expect(result.evidence.signatureVerified).toBe(true);
    }
    expect(result.allRootsRemoved).toBe(true);
    expect(JSON.stringify(result)).not.toContain("private-bootstrap-canary");
  });
});


const evidenceHarness = String.raw`
READY_SECURITY = {'pid1': True, 'root_ro': True, 'mounts_safe': True, 'caps_zero': True, 'no_new_privs': True, 'seccomp': 2, 'apparmor': 'docker-default (enforce)', 'tmpfs': {'type': 0x01021994, 'bytes': 268435456, 'inodes': 16384, 'flags': 14}}
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
READY_SECURITY = {'pid1': True, 'root_ro': True, 'mounts_safe': True, 'caps_zero': True, 'no_new_privs': True, 'seccomp': 2, 'apparmor': 'docker-default (enforce)', 'tmpfs': {'type': 0x01021994, 'bytes': 268435456, 'inodes': 16384, 'flags': 14}}
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


def mechanical(mode, include_history=False, capture=None, failure_fields=None):
    diagnostic = {'stage': 'image-history', 'commands': [], 'readyEventSeen': False,
                  'resultEventSeen': False, 'resultOk': None}
    ready = json.dumps({'event': 'ready', 'uid': os.getuid(), 'gid': os.getgid(), **READY_SECURITY,
                       'addressSpace': {'soft': 17179869184, 'hard': 17179869184}}).encode() + b'\n'
    pre_ready = mode in ('pre-ready', 'pre-ready-remove')
    failed_result = pre_ready or mode == 'post-ready-failure'
    result = json.dumps({'event': 'result', 'case': 'mechanical', 'ok': not failed_result, 'providerRequests': 0,
                         **(failure_fields or {})}).encode() + b'\n'
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
            queue.append((result if pre_ready else ready + result, b'', 1 if failed_result else 0))
        if not pre_ready and launcher_exit is None:
            queue.append((running, b'', 0))
        if not pre_ready and mode != 'cgroup' and launcher_exit is None:
            queue.append((stopped, b'', 0))
        queue.append((b'', b'public remove diagnostic', 17 if mode in ('remove', 'pre-ready-remove') else 0))
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

    def test_optional_admission_payload_preserves_absence_and_retains_valid_observed_bounds(self):
        diagnostic, value, reason, pending = mechanical('pre-ready')
        self.assertEqual(reason, 'cleanup')
        self.assertEqual(diagnostic['failureStage'], 'post-case-cgroup')
        self.assertNotIn('fixtureAdmissionFailure', diagnostic)
        stages = ('platform', 'inherited-as', 'resource-setters', 'environment-directories', 'process-mounts',
                  'shared-memory', 'tmpfs', 'cgroup', 'architecture', 'package-binaries')
        payloads = [{'stage': stage} for stage in stages]
        payloads += [{'stage': 'inherited-as', 'addressSpace': {'soft': number, 'hard': number}}
                     for number in (-1, 0, (1 << 64) - 1)]
        for payload in payloads:
            with self.subTest(payload=payload):
                capture = {}
                diagnostic, value, reason, pending = mechanical('pre-ready', capture=capture,
                    failure_fields={'admissionFailure': payload})
                self.assertEqual(reason, 'cleanup')
                self.assertEqual(diagnostic['fixtureAdmissionFailure'], payload)
                self.assertEqual(diagnostic['failureStage'], 'post-case-cgroup')
                self.assertEqual(diagnostic['stage'], 'container-removed')
                self.assertEqual((diagnostic['readyEventSeen'], diagnostic['resultEventSeen'], diagnostic['resultOk']), (False, True, False))
                self.assertEqual(pending, [])
                self.assertEqual(capture, {'commands': 3, 'inputWrites': [b'', b'', b'']})

    def test_malformed_present_admission_fields_fail_before_retention_and_go(self):
        malformed = [None, [], True, {}, {'stage': 'ready'}, {'stage': 'unknown'}, {'stage': True},
                     {'stage': 'platform', 'raw': 'private-admission-canary'},
                     {'stage': 'inherited-as', 'addressSpace': None}, {'stage': 'inherited-as', 'addressSpace': []}]
        pairs = [{}, {'soft': 0}, {'soft': 0, 'hard': 0, 'extra': 0}, {'soft': True, 'hard': 0},
                 {'soft': 0.0, 'hard': 0}, {'soft': '0', 'hard': 0}, {'soft': -2, 'hard': 0}, {'soft': 1 << 64, 'hard': 0}]
        malformed += [{'stage': 'inherited-as', 'addressSpace': pair} for pair in pairs]
        for payload in malformed:
            with self.subTest(payload=payload):
                capture = {}
                diagnostic, value, reason, pending = mechanical('pre-ready', capture=capture,
                    failure_fields={'admissionFailure': payload})
                self.assertEqual(reason, 'output')
                self.assertNotIn('fixtureAdmissionFailure', diagnostic)
                self.assertNotIn('private-admission-canary', json.dumps(diagnostic))
                self.assertEqual(diagnostic['stage'], 'container-removed')
                self.assertEqual(pending, [])
                self.assertEqual(capture, {'commands': 3, 'inputWrites': [b'', b'', b'']})

    def test_post_ready_privacy_and_cleanup_failure_do_not_overwrite_fixture_facts(self):
        private = {'raw': 'private-admission-canary'}
        diagnostic, value, reason, pending = mechanical('post-ready-failure', failure_fields={'admissionFailure': private})
        self.assertIsNone(reason)
        self.assertFalse(value['ok'])
        self.assertNotIn('fixtureAdmissionFailure', diagnostic)
        self.assertNotIn('private-admission-canary', json.dumps([diagnostic, value]))
        payload = {'stage': 'inherited-as', 'addressSpace': {'soft': -1, 'hard': -1}}
        diagnostic, value, reason, pending = mechanical('pre-ready-remove', failure_fields={'admissionFailure': payload})
        self.assertEqual(reason, 'process')
        self.assertTrue(pending)
        self.assertEqual(diagnostic['fixtureAdmissionFailure'], payload)
        self.assertEqual(diagnostic['failureStage'], 'post-case-cgroup')
        self.assertEqual(diagnostic['stage'], 'mechanical-remove')

    def test_process_mounts_closed_boolean_schema_retains_false_and_unavailable(self):
        substages = ('status-read', 'status-parse', 'capabilities', 'mountinfo-read', 'mountinfo-parse', 'root-ro', 'mounts-safe', 'combined-predicate')
        for substage in substages:
            for fields in ({}, {'capsZero': False, 'rootRo': True, 'mountsSafe': False, 'noNewPrivs': False}):
                payload = {'stage': 'process-mounts', 'processMounts': {'substage': substage, **fields}}
                with self.subTest(payload=payload):
                    diagnostic, value, reason, pending = mechanical('pre-ready', failure_fields={'admissionFailure': payload})
                    self.assertEqual(reason, 'cleanup')
                    self.assertEqual(diagnostic['fixtureAdmissionFailure'], payload)
                    self.assertEqual(diagnostic['failureStage'], 'post-case-cgroup')
                    self.assertEqual(pending, [])
        private = {'stage': 'process-mounts', 'processMounts': {'raw': 'private-process-canary'}}
        diagnostic, value, reason, pending = mechanical('post-ready-failure', failure_fields={'admissionFailure': private})
        self.assertIsNone(reason)
        self.assertNotIn('fixtureAdmissionFailure', diagnostic)
        self.assertNotIn('private-process-canary', json.dumps([diagnostic, value]))

    def test_malformed_or_wrong_stage_process_context_is_never_retained(self):
        malformed = [None, [], True, {}, {'substage': 'unknown'}, {'substage': True},
                     {'substage': 'status-read', 'raw': 'private-process-canary'}, {'substage': 'status-read', 'caps_zero': True}]
        malformed += [{'substage': 'combined-predicate', 'noNewPrivs': value} for value in (0, 1, 0.0, 'false', None)]
        payloads = [{'stage': 'process-mounts', 'processMounts': context} for context in malformed]
        payloads += [{'stage': stage, 'processMounts': {'substage': 'status-read'}} for stage in ('platform', 'shared-memory')]
        for payload in payloads:
            with self.subTest(payload=payload):
                capture = {}
                diagnostic, value, reason, pending = mechanical('pre-ready', capture=capture, failure_fields={'admissionFailure': payload})
                self.assertEqual(reason, 'output')
                self.assertNotIn('fixtureAdmissionFailure', diagnostic)
                self.assertNotIn('private-process-canary', json.dumps(diagnostic))
                self.assertEqual(pending, [])
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
    expect(JSON.parse(result.stdout)).toEqual({ testCases: 14,
      publicPhases: ["image-history", "mechanical-create", "mechanical-start", "mechanical-inspect-running",
        "mechanical-inspect-stopped", "mechanical-remove"],
      nativeDockerAuthNetworkProcesses: 0, allProcessesWereFakePopen: true });
  });
});


const hostAddressSpaceHarness = String.raw`
READY_SECURITY = {'pid1': True, 'root_ro': True, 'mounts_safe': True, 'caps_zero': True, 'no_new_privs': True, 'seccomp': 2, 'apparmor': 'docker-default (enforce)', 'tmpfs': {'type': 0x01021994, 'bytes': 268435456, 'inodes': 16384, 'flags': 14}}
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
spec = importlib.util.spec_from_file_location('inherited_address_space_host', Path.cwd() / 'scripts/ci/controlled-reviewer-probe.py')
host = importlib.util.module_from_spec(spec)
spec.loader.exec_module(host)
LIMIT = 17179869184
PAIR = {'soft': LIMIT, 'hard': LIMIT}
def host_case(fields):
    fields = {**READY_SECURITY, **fields}
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

class InheritedAddressSpaceHostTests(unittest.TestCase):
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
        self.assertEqual([arguments[index + 1] for index, argument in enumerate(arguments) if argument == '--tmpfs'][-1],
                         '/dev/mqueue:ro,nosuid,nodev,noexec,size=4096,nr_inodes=16,uid=0,gid=0,mode=0555')
        self.assertEqual(arguments.count('--tmpfs'), 2)
        self.assertEqual(arguments[-3:], ['public-fixture-image', '--case', 'mechanical'])

log = io.StringIO()
result = unittest.TextTestRunner(stream=log).run(unittest.defaultTestLoader.loadTestsFromTestCase(InheritedAddressSpaceHostTests))
if not result.wasSuccessful():
    print(log.getvalue(), file=sys.stderr)
    sys.exit(1)
print(json.dumps({'testCases': result.testsRun, 'actualResourceSetters': 0, 'nativeOrLauncherProcesses': 0}))
`;
describe("controlled reviewer host inherited address space", () => {
  it("checks the measured ready pair before GO using pure fixtures", async () => {
    const result = await execute("python3", ["-B", "-I", "-S", "-c", hostAddressSpaceHarness], {
      cwd: process.cwd(), timeout: 10_000, maxBuffer: 64 * 1024,
      env: { PATH: process.env.PATH ?? "/usr/bin:/bin", PYTHONDONTWRITEBYTECODE: "1" }
    });
    expect(JSON.parse(result.stdout)).toEqual({ testCases: 1, actualResourceSetters: 0, nativeOrLauncherProcesses: 0 });
  });
});

const bootstrapStatusHarness = String.raw`
READY_SECURITY = {'pid1': True, 'root_ro': True, 'mounts_safe': True, 'caps_zero': True, 'no_new_privs': True, 'seccomp': 2, 'apparmor': 'docker-default (enforce)', 'tmpfs': {'type': 0x01021994, 'bytes': 268435456, 'inodes': 16384, 'flags': 14}}
"""Portable closed bootstrap-status and wire checks; local exception objects only."""
import ast
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import unittest
from unittest import mock
import urllib.error

source = Path.cwd() / 'scripts/ci/controlled-reviewer-probe.py'
spec = importlib.util.spec_from_file_location('bootstrap_status_under_test', source)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)
parsed = ast.parse(source.read_text())
main = next(node for node in parsed.body if isinstance(node, ast.FunctionDef) and node.name == 'main')
outer = next(node for node in main.body if isinstance(node, ast.Try))
HANDLER = compile(ast.fix_missing_locations(ast.Module(body=outer.handlers[0].body, type_ignores=[])), str(source), 'exec')
CANARY = 'private-bootstrap-status-canary'
STAGES = ('docker-info-command', 'docker-info-parse', 'docker-info-admission', 'artifact-directory',
          'artifact-stage-call', 'staged-head-admission', 'staged-evidence-retention')


def error(code=403):
    return urllib.error.HTTPError('https://private.invalid/' + CANARY, code, CANARY, {'Private': CANARY}, io.BytesIO(CANARY.encode()))


def observe(failure, active=True):
    selected = []
    class Dictionary:
        @staticmethod
        def get(mapping, key):
            selected.append(key)
            return dict.get(mapping, key)
    evidence = {'bootstrapStage': 'artifact-stage-call'} if active else {}
    exec(HANDLER, {'error': failure, 'evidence': evidence, 'Unsupported': probe.Unsupported, 'urllib': urllib, 'dict': Dictionary})
    return evidence, selected


class BootstrapStatusTests(unittest.TestCase):
    def test_exact_status_allowlist_types_and_non_http_errors_have_closed_output(self):
        for code in (403, 404, 408, 429, 500, 502, 503, 504):
            with self.subTest(code=code):
                evidence, selected = observe(error(code))
                self.assertEqual(selected, ['code'])
                self.assertEqual(evidence, {'bootstrapStage': 'artifact-stage-call', 'reason': 'unsupported', 'bootstrapHttpStatus': code})
                self.assertNotIn(CANARY, json.dumps(evidence))
        class Integer(int):
            pass
        for code in (200, 401, 418, 501, 505, -1, 0, 999, True, 403.0, '403', None, Integer(403)):
            with self.subTest(code=code):
                evidence, selected = observe(error(code))
                self.assertEqual(selected, ['code'])
                self.assertEqual(evidence, {'bootstrapStage': 'artifact-stage-call', 'reason': 'unsupported'})
        class HttpSubclass(urllib.error.HTTPError):
            @property
            def code(self):
                raise AssertionError('subclass property must not be read')
        subclass = HttpSubclass.__new__(HttpSubclass)
        for failure in (subclass, urllib.error.URLError(CANARY), ValueError(CANARY)):
            evidence, selected = observe(failure)
            self.assertEqual(selected, [])
            self.assertEqual(evidence, {'bootstrapStage': 'artifact-stage-call', 'reason': 'unsupported'})
        evidence, selected = observe(probe.Unsupported('deadline'))
        self.assertEqual((evidence['reason'], selected), ('deadline', []))

    def test_missing_code_body_properties_mapping_overrides_and_later_errors_are_not_observed(self):
        body_reads = []
        class Body(io.BytesIO):
            @property
            def code(self):
                body_reads.append('body-code')
                return 403
        missing = urllib.error.HTTPError('https://private.invalid/' + CANARY, 404, CANARY, {'Private': CANARY}, Body(CANARY.encode()))
        del missing.code
        incomplete = urllib.error.HTTPError.__new__(urllib.error.HTTPError)
        for failure in (missing, incomplete):
            evidence, selected = observe(failure)
            self.assertEqual(selected, ['code'])
            self.assertNotIn('bootstrapHttpStatus', evidence)
        self.assertEqual(body_reads, [])
        class Mapping(dict):
            def get(self, *args):
                raise AssertionError('overridden get must not run')
            def __iter__(self):
                raise AssertionError('dictionary must not be enumerated')
            def keys(self):
                raise AssertionError('keys must not be read')
            def items(self):
                raise AssertionError('items must not be read')
            def values(self):
                raise AssertionError('values must not be read')
        failure = error(503)
        failure.__dict__ = Mapping(object.__getattribute__(failure, '__dict__'))
        with mock.patch.object(urllib.error.HTTPError, 'code', property(lambda self: (_ for _ in ()).throw(AssertionError('code property read'))), create=True):
            self.assertEqual(observe(failure)[0]['bootstrapHttpStatus'], 503)
        original_getattribute = urllib.error.HTTPError.__getattribute__
        def attribute(self, name):
            if name in ('url', 'headers', 'hdrs', 'msg', 'reason', 'fp', 'file', 'filename', 'code'):
                raise AssertionError('private exception attribute must not be read')
            return original_getattribute(self, name)
        with mock.patch.object(urllib.error.HTTPError, '__getattribute__', attribute):
            self.assertEqual(observe(failure)[1], ['code'])
            evidence, selected = observe(failure, active=False)
        self.assertEqual((evidence, selected), ({'reason': 'unsupported'}, []))
        self.assertEqual(body_reads, [])

    def test_seven_literal_stage_writes_clear_immediately_after_retention_before_context(self):
        assignments = [node for node in outer.body if isinstance(node, ast.Assign) and
                       ast.unparse(node.targets[0]) == "evidence['bootstrapStage']"]
        self.assertEqual(tuple(node.value.value for node in assignments), STAGES)
        index = next(index for index, node in enumerate(outer.body) if isinstance(node, ast.Expr) and
                     ast.unparse(node) == "evidence.update(staged['evidence'])")
        self.assertEqual(ast.unparse(outer.body[index + 1]), "evidence.pop('bootstrapStage')")
        self.assertEqual(ast.unparse(outer.body[index + 2]), "context = staged['context']")

    def test_legacy_closed_optional_and_oversized_packets_keep_the_existing_compact_wire_contract(self):
        packets = [
            ({'schema': 1, 'ok': False, 'cleanup': True, 'reason': 'unsupported'},
             b'{"schema":1,"ok":false,"cleanup":true,"reason":"unsupported"}'),
            ({'schema': 1, 'ok': True, 'cleanup': True}, b'{"schema":1,"ok":true,"cleanup":true}'),
            ({'schema': 1, 'ok': False, 'cleanup': True, 'reason': 'unsupported', 'head': 'a' * 40},
             b'{"schema":1,"ok":false,"cleanup":true,"reason":"unsupported","head":"' + b'a' * 40 + b'"}'),
            ({'schema': 1, 'ok': False, 'cleanup': True, 'reason': 'unsupported', 'bootstrapStage': 'artifact-stage-call', 'bootstrapHttpStatus': 503},
             b'{"schema":1,"ok":false,"cleanup":true,"reason":"unsupported","bootstrapStage":"artifact-stage-call","bootstrapHttpStatus":503}')]
        prefix = b'CONTROLLED_REVIEWER_EVIDENCE '
        for packet, expected in packets:
            with self.subTest(packet=packet):
                final, encoded = probe.encode_evidence(packet)
                self.assertEqual((final, encoded), (packet, expected))
                self.assertLessEqual(len(prefix + encoded + b'\n'), 65536)
        oversized = {'schema': 1, 'ok': True, 'cleanup': True, 'repository': 'OMT-Global/bootstrap',
                     'head': 'a' * 40, 'runId': '1' * 100000, 'payload': 'é' * 40000 + CANARY,
                     'bootstrapStage': 'artifact-stage-call', 'bootstrapHttpStatus': 503}
        original = json.dumps(oversized, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
        final, encoded = probe.encode_evidence(oversized)
        self.assertEqual(set(final), {'schema', 'ok', 'cleanup', 'reason', 'omittedBytes', 'omittedSha256', 'repository', 'head'})
        self.assertEqual(final['reason'], 'evidence-limit')
        self.assertIs(final['ok'], False)
        self.assertIs(final['cleanup'], True)
        self.assertEqual(final['omittedBytes'], len(original))
        self.assertEqual(final['omittedSha256'], hashlib.sha256(original).hexdigest())
        self.assertEqual((final['repository'], final['head']), ('OMT-Global/bootstrap', 'a' * 40))
        self.assertLessEqual(len(prefix + encoded + b'\n'), 65536)
        self.assertNotIn(CANARY, encoded.decode('utf-8'))


log = io.StringIO()
result = unittest.TextTestRunner(stream=log).run(unittest.defaultTestLoader.loadTestsFromTestCase(BootstrapStatusTests))
if not result.wasSuccessful():
    print(log.getvalue(), file=sys.stderr)
    raise SystemExit(1)
print(json.dumps({'testCases': result.testsRun, 'statusObservationIsLocalOnly': True, 'networkOrNativeCalls': 0}))
`;

describe("controlled reviewer closed bootstrap diagnostics", () => {
  it("keeps exact HTTP member selection, fixed stage boundaries and the legacy compact wire using local fixtures", async () => {
    const result = await execute("python3", ["-B", "-I", "-S", "-c", bootstrapStatusHarness], {
      cwd: process.cwd(), timeout: 10_000, maxBuffer: 64 * 1024,
      env: { PATH: process.env.PATH ?? "/usr/bin:/bin", PYTHONDONTWRITEBYTECODE: "1" }
    });
    expect(JSON.parse(result.stdout)).toEqual({ testCases: 4, statusObservationIsLocalOnly: true, networkOrNativeCalls: 0 });
  });
});


const reviewerTeardownHarness = String.raw`
READY_SECURITY = {'pid1': True, 'root_ro': True, 'mounts_safe': True, 'caps_zero': True, 'no_new_privs': True, 'seccomp': 2, 'apparmor': 'docker-default (enforce)', 'tmpfs': {'type': 0x01021994, 'bytes': 268435456, 'inodes': 16384, 'flags': 14}}
import ast
import contextlib
import errno
import json
from pathlib import Path, PurePosixPath
import sys
import types

source = ast.parse(Path('scripts/ci/controlled-reviewer-probe.py').read_text())
functions = [node for node in source.body if isinstance(node, ast.FunctionDef) and node.name in {'require', 'case_run'}]
assert len(functions) == 2
subject = compile(ast.Module(body=functions, type_ignores=[]), '<actual-reviewer-teardown>', 'exec')


class Unsupported(Exception):
    pass


class Clock:
    def __init__(self, clock_error=None, sleep_error=None):
        self.value, self.reads, self.sleeps = 0.0, 0, 0
        self.clock_error, self.sleep_error = clock_error, sleep_error

    def monotonic(self):
        self.reads += 1
        if self.clock_error is not None and self.reads == 2:
            raise self.clock_error
        self.value += 0.1
        return self.value

    def sleep(self, value):
        assert value == 0.02
        if self.sleep_error is not None:
            raise self.sleep_error
        self.value += value
        self.sleeps += 1


class Group:
    def __init__(self, values, exists):
        self.values, self.present, self.reads = list(values), exists, 0

    def __truediv__(self, name):
        assert name == 'cgroup.procs'
        return self

    def exists(self):
        return self.present

    def read_text(self):
        self.reads += 1
        value = self.values.pop(0) if len(self.values) > 1 else self.values[0]
        if isinstance(value, BaseException):
            raise value
        return value


def run(values, exists=True, identity_error=None, clock_error=None, sleep_error=None,
        post_inspect_error=None, remove_error=None):
    group, clock = Group(values, exists), Clock(clock_error, sleep_error)
    state = {'operations': [], 'identityCalls': 0, 'inspectCalls': 0, 'go': b''}
    pending = []

    class Input:
        def write(self, value):
            state['go'] += value

        def flush(self):
            pass

    def inspect(name):
        state['inspectCalls'] += 1
        if state['inspectCalls'] == 2 and post_inspect_error is not None:
            raise post_inspect_error
        return {'State': {'Running': state['inspectCalls'] == 1, 'Pid': 123},
                'HostConfig': {'NetworkMode': 'none', 'ReadonlyRootfs': True}}

    def cgroup_for(pid):
        assert pid == 123
        state['identityCalls'] += 1
        if identity_error is not None:
            raise identity_error
        return group

    def command(arguments, **kwargs):
        operation = arguments[3]
        state['operations'].append(operation)
        assert operation in ('create', 'start', 'rm')
        if operation == 'rm' and remove_error is not None:
            raise remove_error
        if operation == 'start':
            kwargs['on_line'](json.dumps({'event': 'ready', 'uid': 1000, 'gid': 1000, **READY_SECURITY,
                                         'addressSpace': {'soft': 17179869184, 'hard': 17179869184}}).encode(), Input())
            kwargs['on_line'](json.dumps({'event': 'result', 'case': 'mechanical', 'ok': True,
                                         'providerRequests': 0}).encode(), Input())
        return b''

    namespace = {'Unsupported': Unsupported, 'contextlib': contextlib, 'time': clock, 'json': json,
                 'os': types.SimpleNamespace(getuid=lambda: 1000, getgid=lambda: 1000),
                 'uuid': types.SimpleNamespace(uuid4=lambda: types.SimpleNamespace(hex='a' * 32)),
                 'DOCKER': ['synthetic-docker', '--host', 'synthetic-socket'],
                 'command': command, 'cgroup_for': cgroup_for, 'inspect': inspect}
    exec(subject, namespace)
    error, result = None, None
    try:
        result = namespace['case_run']('mechanical', 'synthetic-image', PurePosixPath('/synthetic'), pending, '')
    except BaseException as raised:
        error = raised
    assert state['operations'] == ['create', 'start', 'rm']
    assert bool(pending) == (remove_error is not None)
    assert state['identityCalls'] == 1
    if error is None:
        assert result == {'case': 'mechanical', 'ok': True, 'providerRequests': 0,
                          'addressSpace': {'soft': 17179869184, 'hard': 17179869184}}
        assert state['inspectCalls'] == 2 and state['go'] == b'GO\n'
    return error, state, group, clock


mode, cases = sys.argv[1], 0
if mode in ('poll-deletion', 'final-deletion'):
    missing = FileNotFoundError(errno.ENOENT, 'synthetic-cgroup-disappeared')
    values = [missing] if mode == 'poll-deletion' else ['', missing]
    error, state, group, clock = run(values)
    assert error is None, ('teardown deletion was rejected', type(error).__name__)
    assert group.reads == (1 if mode == 'poll-deletion' else 2)
    cases = 1
elif mode == 'quiescence':
    for values, present in [([FileNotFoundError(errno.ENOENT, 'synthetic-absent')], False), ([''], True),
                            (['123\n', '', ''], True)]:
        error, state, group, clock = run(values, exists=present)
        assert error is None
        assert clock.sleeps == (1 if len(values) == 3 else 0)
        cases += 1
elif mode == 'populated':
    error, state, group, clock = run(['123\n'])
    assert type(error) is Unsupported and str(error) == 'cleanup'
    assert state['inspectCalls'] == 1 and clock.sleeps > 0 and group.reads > 1
    cases = 1
elif mode == 'other-errors':
    for error in [PermissionError(errno.EACCES, 'synthetic'), OSError(errno.EIO, 'synthetic'),
                  NotADirectoryError(errno.ENOTDIR, 'synthetic'), OSError(errno.EOPNOTSUPP, 'synthetic'),
                  UnicodeError('synthetic')]:
        observed, state, group, clock = run([error])
        assert observed is error and state['inspectCalls'] == 1
        cases += 1
elif mode == 'deadline-cancel':
    for phase in ('clock_error', 'sleep_error'):
        for error in [TimeoutError('synthetic'), KeyboardInterrupt(), Unsupported('deadline'), Unsupported('cleanup')]:
            observed, state, group, clock = run(['123\n'], **{phase: error})
            assert observed is error and state['inspectCalls'] == 1
            cases += 1
elif mode == 'identity-before-go':
    error = FileNotFoundError(errno.ENOENT, 'synthetic-initial-identity')
    observed, state, group, clock = run([''], identity_error=error)
    assert observed is error and state['go'] == b'' and group.reads == 0
    cases = 1
elif mode == 'later-io':
    for phase in ('post_inspect_error', 'remove_error'):
        for error in [FileNotFoundError(errno.ENOENT, 'synthetic-later'), PermissionError(errno.EACCES, 'synthetic-later')]:
            observed, state, group, clock = run([''], **{phase: error})
            assert observed is error and state['inspectCalls'] == 2
            cases += 1
elif mode == 'scope':
    case = next(node for node in functions if node.name == 'case_run')
    blocks = [node for node in ast.walk(case) if isinstance(node, ast.With)]
    assert len(blocks) == 1
    block = blocks[0]
    assert ast.unparse(block.items[0].context_expr) == 'contextlib.suppress(FileNotFoundError)'
    assert len(block.body) == 2 and isinstance(block.body[0], ast.While) and isinstance(block.body[1], ast.Expr)
    calls = [ast.unparse(node.func) for item in block.body for node in ast.walk(item) if isinstance(node, ast.Call)]
    expected = ["(group / 'cgroup.procs').read_text().strip", 'time.monotonic', 'time.sleep',
                "(group / 'cgroup.procs').read_text", 'require',
                "(group / 'cgroup.procs').read_text().strip", "(group / 'cgroup.procs').read_text"]
    assert sorted(calls) == sorted(expected)
    assert ast.unparse(block.body[0].body[0]) == 'time.sleep(0.02)'
    assert ast.unparse(block.body[1].value) == "require(not (group / 'cgroup.procs').read_text().strip(), 'cleanup')"
    cases = 1
else:
    raise AssertionError('unknown synthetic mode')
print(json.dumps({'cases': cases, 'actualResourceOrNativeCalls': 0, 'actualSourceAST': True}))
`;

describe("controlled reviewer cgroup teardown", () => {
  it.each([
    ["poll-deletion", 1], ["final-deletion", 1], ["quiescence", 3], ["populated", 1], ["other-errors", 5],
    ["deadline-cancel", 8], ["identity-before-go", 1], ["later-io", 4], ["scope", 1]
  ] as const)("preserves teardown invariants for %s with actual source and fabricated operations", async (mode, cases) => {
    const result = await execute("python3", ["-B", "-I", "-S", "-c", reviewerTeardownHarness, mode], {
      cwd: process.cwd(), timeout: 10_000, maxBuffer: 64 * 1024,
      env: { PATH: process.env.PATH ?? "/usr/bin:/bin", PYTHONDONTWRITEBYTECODE: "1" }
    });
    expect(JSON.parse(result.stdout)).toEqual({ cases, actualResourceOrNativeCalls: 0, actualSourceAST: true });
  });
});



const effectiveReadyHarness = String.raw`
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
from unittest import mock
spec = importlib.util.spec_from_file_location('effective_ready_host', Path.cwd() / 'scripts/ci/controlled-reviewer-probe.py')
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)
fields = json.loads(sys.argv[1])
state = {'running': False, 'go': bytearray(), 'writes': 0, 'resultSent': False, 'operations': []}
class Input(io.BytesIO):
    def write(self, value):
        state['go'].extend(value)
        state['writes'] += 1
        return super().write(value)
def command(arguments, **kwargs):
    operation = arguments[len(probe.DOCKER)]
    state['operations'].append(operation)
    if operation == 'start':
        state['running'] = True
        callback = kwargs['on_line']
        callback(json.dumps({'event': 'ready', 'uid': os.getuid(), 'gid': os.getgid(), **fields}).encode(), Input())
        state['resultSent'] = True
        callback(json.dumps({'event': 'result', 'case': 'mechanical', 'ok': True, 'providerRequests': 0}).encode(), Input())
        state['running'] = False
    return b''
with tempfile.TemporaryDirectory(prefix='bootstrap-effective-ready-') as temporary, \
        mock.patch.object(probe, 'command', side_effect=command), \
        mock.patch.object(probe, 'inspect', side_effect=lambda _: {
            'State': {'Running': state['running'], 'Pid': 123},
            'HostConfig': {'NetworkMode': 'none', 'ReadonlyRootfs': True}}), \
        mock.patch.object(probe, 'cgroup_for', return_value=Path(temporary) / 'absent-cgroup'):
    pending = []
    probe.DOCKER = ['never-executed']
    try:
        result = probe.case_run('mechanical', 'synthetic-image', Path(temporary), pending, '')
        reason = None
    except probe.Unsupported as error:
        result, reason = None, str(error)
    assert not pending and state['operations'][-1] == 'rm'
print(json.dumps({'go': state['go'].decode('ascii'), 'writes': state['writes'],
                  'resultSent': state['resultSent'], 'operations': state['operations'],
                  'result': result, 'reason': reason, 'actualNativeOrProviderCalls': 0}))
`;
function supportedReady(): Record<string, unknown> {
  return { addressSpace: { soft: 17179869184, hard: 17179869184 }, pid1: true,
    root_ro: true, mounts_safe: true, caps_zero: true, no_new_privs: true,
    seccomp: 2, apparmor: "docker-default (enforce)",
    tmpfs: { type: 0x01021994, bytes: 268435456, inodes: 16384, flags: 14 } };
}
type ReadyMutation = { name: string; path: string[]; value?: unknown; remove?: boolean };
const readyMutations: ReadyMutation[] = [];
for (const name of ["pid1", "root_ro", "mounts_safe", "caps_zero", "no_new_privs", "seccomp", "apparmor", "tmpfs"]) {
  readyMutations.push({ name: `missing-${name}`, path: [name], remove: true });
}
for (const name of ["type", "bytes", "inodes", "flags"]) readyMutations.push({ name: `missing-tmpfs-${name}`, path: ["tmpfs", name], remove: true });
for (const name of ["pid1", "root_ro", "mounts_safe", "caps_zero", "no_new_privs"]) {
  for (const value of [false, 1]) readyMutations.push({ name: `${name}-${JSON.stringify(value)}`, path: [name], value });
}
for (const value of [0, 1, 3, true, "2"]) readyMutations.push({ name: `seccomp-${JSON.stringify(value)}`, path: ["seccomp"], value });
for (const value of ["unconfined", "docker-default (complain)", "docker-default (enforce)\n", true]) {
  readyMutations.push({ name: `apparmor-${JSON.stringify(value)}`, path: ["apparmor"], value });
}
for (const value of [12, 10, 6, 0, 15, -1, 2 ** 64, true, "14"]) readyMutations.push({ name: `flags-${JSON.stringify(value)}`, path: ["tmpfs", "flags"], value });
readyMutations.push({ name: "tmpfs-array", path: ["tmpfs"], value: [] });
for (const [name, path, value] of [
  ["tmpfs-wrong-magic", ["tmpfs", "type"], 0], ["tmpfs-boolean-magic", ["tmpfs", "type"], true],
  ["tmpfs-zero-bytes", ["tmpfs", "bytes"], 0], ["tmpfs-excess-bytes", ["tmpfs", "bytes"], 268435457],
  ["tmpfs-zero-inodes", ["tmpfs", "inodes"], 0], ["tmpfs-excess-inodes", ["tmpfs", "inodes"], 16385],
] as const) readyMutations.push({ name, path: [...path], value });
async function effectiveReadyCase(wire: string) {
  const result = await execute("python3", ["-B", "-I", "-S", "-c", effectiveReadyHarness, wire], {
    cwd: process.cwd(), timeout: 10_000, maxBuffer: 64 * 1024,
    env: { PATH: process.env.PATH ?? "/usr/bin:/bin", PYTHONDONTWRITEBYTECODE: "1" }
  });
  return JSON.parse(result.stdout) as { go: string; writes: number; resultSent: boolean;
    reason: string | null; result: unknown; operations: string[]; actualNativeOrProviderCalls: number };
}
describe("controlled reviewer effective READY admission", () => {
  it.each(readyMutations)("sends no GO and runs no later case for $name", async ({ path, value, remove }) => {
    const fields = supportedReady();
    let target = fields;
    for (const name of path.slice(0, -1)) target = target[name] as Record<string, unknown>;
    if (remove) delete target[path.at(-1)!]; else target[path.at(-1)!] = value;
    const result = await effectiveReadyCase(JSON.stringify(fields));
    expect(result.go).toBe(""); expect(result.writes).toBe(0); expect(result.resultSent).toBe(false);
    expect(result.reason).toBe("mechanical"); expect(result.result).toBeNull();
    expect(result.operations).toEqual(["create", "start", "rm"]);
    expect(result.actualNativeOrProviderCalls).toBe(0);
  });
  it.each([['"seccomp":2', '"seccomp":2.0'], ['"flags":14', '"flags":14.0']])("rejects a JSON float without coercion: %s", async (from, to) => {
    const wire = JSON.stringify(supportedReady());
    expect(wire.split(from)).toHaveLength(2);
    const result = await effectiveReadyCase(wire.replace(from, to));
    expect(result.go).toBe(""); expect(result.writes).toBe(0); expect(result.resultSent).toBe(false);
    expect(result.reason).toBe("mechanical"); expect(result.actualNativeOrProviderCalls).toBe(0);
  });
  it.each(["required", "relatime-and-extras", "uint64-boundary"])("sends exactly one GO for valid %s observations", async (mode) => {
    const fields = supportedReady();
    if (mode === "relatime-and-extras") {
      Object.assign(fields.tmpfs as object, { flags: 4110, extraObservation: "ignored" });
      fields.extraObservation = { ignored: true };
    }
    let wire = JSON.stringify(fields);
    if (mode === "uint64-boundary") wire = wire.replace('"flags":14', '"flags":18446744073709551614');
    const result = await effectiveReadyCase(wire);
    expect(result.go).toBe("GO\n"); expect(result.writes).toBe(1); expect(result.resultSent).toBe(true);
    expect(result.reason).toBeNull(); expect(result.actualNativeOrProviderCalls).toBe(0);
    expect(result.result).toEqual({ case: "mechanical", ok: true, providerRequests: 0,
      addressSpace: { soft: 17179869184, hard: 17179869184 } });
  });
});

const unsupportedDaemonOptions: Array<[string, unknown]> = [
  ["missing-apparmor", ["name=seccomp,profile=builtin"]], ["missing-seccomp", ["name=apparmor"]],
  ["unconfined", ["name=apparmor", "name=seccomp,profile=unconfined"]],
  ["custom", ["name=apparmor", "name=seccomp,profile=/custom.json"]],
  ["legacy-default", ["name=apparmor", "name=seccomp,profile=default"]],
  ["duplicate", ["name=apparmor", "name=seccomp,profile=builtin", "name=seccomp,profile=builtin"]],
  ["conflicting", ["name=apparmor", "name=seccomp,profile=builtin", "name=seccomp,profile=unconfined"]],
  ["apparmor-alternative", ["name=apparmor,profile=default", "name=seccomp,profile=builtin"]],
  ["rootless", ["name=apparmor", "name=seccomp,profile=builtin", "name=rootless"]],
  ["not-a-list", "name=apparmor"], ["null", null], ["nonstring", [null]],
];
describe("controlled reviewer daemon security admission", () => {
  it.each(unsupportedDaemonOptions)("stops %s before staging/build/native cases", async (_name, options) => {
    const result = await orchestrationCase("daemon-options:" + JSON.stringify(options));
    expect(result.status).toBe(1); expect(result.stageCalls).toBe(0); expect(result.buildCalls).toBe(0);
    expect(result.caseOrder).toEqual([]); expect(result.providerRequests).toBe(0);
    expect(result.evidence).toMatchObject({ ok: false, cleanup: true, reason: "platform" });
    expect(result.allRootsRemoved).toBe(true);
  });
  it.each([false, true])("admits the fixed daemon with benign extras: %s", async (extra) => {
    const options = ["name=apparmor", "name=seccomp,profile=builtin", ...(extra ? ["name=cgroupns"] : [])];
    const result = await orchestrationCase("daemon-options:" + JSON.stringify(options));
    expect(result.status).toBe(0); expect(result.stageCalls).toBe(1); expect(result.buildCalls).toBe(1);
    expect(result.evidence).toMatchObject({ ok: true, cleanup: true });
  });
});

interface RetainedCleanupResult extends OrchestrationResult {
  cleanupAttempts: Array<{ target: string; deadline: number; timeout: number; cleanup: boolean; startAllowed: boolean }>;
  cleanupClockEntries: number; observedCleanupDeadline: number; cleanupClockRestored: boolean;
  cleanupTimerCalls: number[]; cleanupTimerRestored: boolean; rootRemovalAttempted: boolean;
  alreadyAbsentExitZero: boolean;
}
async function retainedCleanupCase(mode: string) {
  const result = await execute("python3", ["-B", "-I", "-S", "-c", orchestrationHarness, "retained-cleanup-" + mode], {
    cwd: process.cwd(), timeout: 10_000, maxBuffer: 256 * 1024,
    env: { PATH: process.env.PATH ?? "/usr/bin:/bin", PYTHONDONTWRITEBYTECODE: "1" }
  });
  return JSON.parse(result.stdout) as RetainedCleanupResult;
}
describe("controlled reviewer retained cleanup attempts", () => {
  it.each(["first", "middle", "image", "success", "already-absent", "deadline", "cancel", "filesystem"])("keeps the original shared cleanup budget for %s", async (mode) => {
    const result = await retainedCleanupCase(mode);
    expect(result.cleanupAttempts.map((attempt) => attempt.target)).toEqual(["retained-first", "retained-middle", "retained-last", "image"]);
    expect(result.cleanupClockEntries).toBe(1); expect(result.observedCleanupDeadline).toBe(1060);
    expect(result.cleanupAttempts.every((attempt) => attempt.deadline === 1060 && attempt.timeout === 20 && attempt.cleanup)).toBe(true);
    expect(result.cleanupClockRestored).toBe(true); expect(result.cleanupTimerRestored).toBe(true);
    expect(result.cleanupTimerCalls).toEqual([60, 0]);
    if (mode === "deadline") {
      expect(result.cleanupAttempts.map((attempt) => attempt.startAllowed)).toEqual([true, false, false, false]);
      expect(result.rootRemovalAttempted).toBe(false); expect(result.allRootsRemoved).toBe(false);
    } else {
      expect(result.cleanupAttempts.every((attempt) => attempt.startAllowed)).toBe(true);
      expect(result.rootRemovalAttempted).toBe(true);
      expect(result.allRootsRemoved).toBe(mode !== "filesystem");
    }
    if (["success", "already-absent"].includes(mode)) {
      expect(result.status).toBe(0); expect(result.evidence).toMatchObject({ ok: true, cleanup: true });
    } else {
      expect(result.status).toBe(1); expect(result.evidence).toMatchObject({ ok: false, cleanup: false, reason: "cleanup" });
    }
    expect(result.alreadyAbsentExitZero).toBe(mode === "already-absent");
  });
});
