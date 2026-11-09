#!/usr/bin/env python3
"""Bounded, synthetic-only native reviewer proof for the full Linux CI profile."""
import argparse
import base64
import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import urllib.error
import uuid

HERE = Path(__file__).resolve().parent
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('reviewer_artifacts', HERE / 'reviewer-artifacts.py')
artifacts = importlib.util.module_from_spec(spec)
spec.loader.exec_module(artifacts)
Unsupported = artifacts.Unsupported
DEADLINE = 0.0
CLEANUP_DEADLINE = 0.0
ENV = {}
DOCKER = []
EVIDENCE_PREFIX = 'CONTROLLED_REVIEWER_EVIDENCE '
MECHANICAL_ADMISSION_STAGES = {'platform', 'inherited-as', 'resource-setters',
                               'environment-directories', 'process-mounts', 'shared-memory',
                               'tmpfs', 'cgroup', 'architecture', 'package-binaries'}
PROCESS_MOUNT_SUBSTAGES = {'status-read', 'status-parse', 'capabilities', 'mountinfo-read',
                           'mountinfo-parse', 'root-ro', 'mounts-safe', 'combined-predicate'}
PUBLIC_COMMAND_PHASES = {'image-history', 'mechanical-create', 'mechanical-start',
                         'mechanical-inspect-running', 'mechanical-inspect-stopped', 'mechanical-remove'}
SANDBOX_FAILURE_STAGES = {'gate', 'dispatch', 'version-call', 'version-exit', 'version-stdout',
                          'version-stderr', 'workspace-setup', 'loopback-control', 'sandbox-call',
                          'sandbox-exit', 'listener-postcheck', 'listener-close'}


def require(value, phase='mechanical'):
    if not value:
        raise Unsupported(phase)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def command(arguments, timeout=60, limit=1 << 20, on_line=None, cleanup=False, trace=None, phase=None):
    end = min(time.monotonic() + timeout, CLEANUP_DEADLINE if cleanup and CLEANUP_DEADLINE else DEADLINE)
    require(time.monotonic() < end, 'cleanup' if cleanup else 'deadline')
    observation = None
    if trace is not None:
        require(type(trace) is list and len(trace) < 6 and phase in PUBLIC_COMMAND_PHASES, 'diagnostic')
        observation = {'phase': phase, 'exitCode': None, 'exitObservedBeforeCleanup': False,
                       'stdoutBytes': 0, 'stderrBytes': 0, 'stdoutSha256': sha(b''), 'stderrSha256': sha(b''),
                       'streamsComplete': False}
        trace.append(observation)
        digests = [hashlib.sha256(), hashlib.sha256()]
    process = subprocess.Popen(arguments, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               env=ENV, start_new_session=True)
    result, pending, total = bytearray(), bytearray(), 0
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ, 0)
            selector.register(process.stderr, selectors.EVENT_READ, 1)
            while selector.get_map():
                require(time.monotonic() < end, 'deadline')
                for key, _ in selector.select(0.1):
                    block = os.read(key.fd, 65536)
                    if not block:
                        selector.unregister(key.fileobj)
                        continue
                    total += len(block)
                    require(total <= limit, 'output')
                    if observation is not None:
                        observation['stdoutBytes' if key.data == 0 else 'stderrBytes'] += len(block)
                        digests[key.data].update(block)
                    if key.data == 0:
                        if on_line:
                            pending.extend(block)
                            while b'\n' in pending:
                                line, _, remaining = pending.partition(b'\n')
                                pending[:] = remaining
                                on_line(line, process.stdin)
                        else:
                            result.extend(block)
            if observation is not None:
                observation['streamsComplete'] = True
            require(not pending, 'output')
            code = process.wait(timeout=2)
            require(code == 0 or on_line and code in (1, 137), 'process')
            return code if on_line else bytes(result)
    finally:
        if observation is not None:
            observation['exitCode'] = process.poll()
            observation['exitObservedBeforeCleanup'] = observation['exitCode'] is not None
            observation['stdoutSha256'], observation['stderrSha256'] = (value.hexdigest() for value in digests)
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        if process.poll() is None:
            process.wait(timeout=2)
        if observation is not None and observation['exitCode'] is None:
            observation['exitCode'] = process.poll()
        process.stdin.close()
        process.stdout.close()
        process.stderr.close()


def inspect(name, trace=None, phase=None):
    return json.loads(command([*DOCKER, 'inspect', name], trace=trace, phase=phase))[0]


def cgroup_for(pid):
    require(Path('/proc/self/ns/pid').readlink() != Path(f'/proc/{pid}/ns/pid').readlink())
    lines = Path(f'/proc/{pid}/cgroup').read_text().splitlines()
    require(len(lines) == 1 and lines[0].startswith('0::/'))
    location = Path('/sys/fs/cgroup', lines[0][4:]).resolve()
    require(location.is_relative_to('/sys/fs/cgroup') and str(pid) in (location / 'cgroup.procs').read_text().split())
    return location


def auth_snapshot(directory):
    return [(p.name, tuple(getattr(p.stat(), field) for field in ('st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')), sha(p.read_bytes())) for p in sorted(directory.iterdir())]


def case_run(case, image, directory, containers, image_record, diagnostic=None, sandbox_failure=None):
    require(diagnostic is None or case == 'mechanical', 'diagnostic')
    require(sandbox_failure is None or (case == 'sandbox' and type(sandbox_failure) is dict and not sandbox_failure), 'diagnostic')
    if case == 'sandbox' and sandbox_failure is None:
        sandbox_failure = {}
    trace = diagnostic['commands'] if diagnostic is not None else None
    if diagnostic is not None:
        diagnostic['stage'] = 'mechanical-create'
    name = 'bootstrap-reviewer-' + uuid.uuid4().hex
    arguments = [*DOCKER, 'create', '--name', name, '-i', '--read-only', '--network', 'none', '--cap-drop', 'ALL',
                 '--security-opt', 'no-new-privileges', '--memory', '2147483648', '--memory-swap', '2147483648',
                 '--pids-limit', '128', '--cpus', '2', '--ipc', 'none', '--log-driver', 'none', '--restart', 'no',
                 '--user', f'{os.getuid()}:{os.getgid()}', '--tmpfs', f'/run/review:rw,nosuid,nodev,noexec,size=268435456,nr_inodes=16384,uid={os.getuid()},gid={os.getgid()},mode=0700',
                 '--tmpfs', '/dev/mqueue:ro,nosuid,nodev,noexec,size=4096,nr_inodes=16,uid=0,gid=0,mode=0555']
    for limit in ['core=0:0', 'fsize=67108864:67108864', 'nofile=256:256', 'nproc=128:128', 'cpu=3600:3600']:
        arguments += ['--ulimit', limit]
    before, auth = None, directory / ('auth-' + uuid.uuid4().hex)
    if case.startswith('status-') or case in ('api', 'persistence'):
        auth.mkdir()
        fixture = 'bootstrap-fixture-' + uuid.uuid4().hex
        value = {'OPENAI_API_KEY': fixture}
        if case == 'status-oauth':
            claims = {'sub': 'synthetic', 'exp': int(time.time()) + 3600, 'https://api.openai.com/auth': {'chatgpt_account_id': 'synthetic'}}
            fixture_jwt = '.'.join(base64.urlsafe_b64encode(json.dumps(part).encode()).rstrip(b'=').decode() for part in ({'alg': 'none', 'typ': 'JWT'}, claims)) + '.fixture'
            value = {'auth_mode': 'chatgpt', 'tokens': {'id_token': fixture_jwt, 'access_token': 'fixture', 'refresh_token': 'fixture', 'account_id': 'synthetic'}}
        if case == 'status-unknown':
            value = {'auth_mode': 'unsupported'}
        (auth / 'auth.json').write_text(json.dumps(value))
        mode = case.removeprefix('status-') if case in ('status-keyring', 'status-auto') else 'file'
        (auth / 'config.toml').write_text('cli_auth_credentials_store=' + json.dumps(mode) + '\n')
        for target in auth.iterdir():
            target.chmod(0o600)
            arguments += ['--mount', f'type=bind,src={target},dst=/operator/.codex/{target.name},readonly']
        before = auth_snapshot(auth)
    containers.append(name)
    command([*arguments, image, '--case', case], trace=trace, phase='mechanical-create' if trace is not None else None)
    events, group = [], None
    detached_completed = False

    def event(line, stdin):
        nonlocal group, detached_completed
        data = json.loads(line)
        require(isinstance(data, dict) and len(events) < 4, 'output')
        require(not (sandbox_failure and data.get('event') == 'result'), 'output')
        if 'sandboxFailure' in data:
            require(case == 'sandbox' and data.get('event') == 'result' and data.get('case') == 'sandbox' and
                    data.get('ok') is False and data.get('phase') == 'native-sandbox' and
                    type(data.get('providerRequests')) is int and data['providerRequests'] == 0, 'output')
            failure = data['sandboxFailure']
            require(type(failure) is dict and {'stage'} <= set(failure) <= {'stage', 'exitCode'} and
                    type(failure.get('stage')) is str and failure['stage'] in SANDBOX_FAILURE_STAGES, 'output')
            if 'exitCode' in failure:
                require(failure['stage'] in {'version-exit', 'sandbox-exit'} and
                        type(failure['exitCode']) is int and -255 <= failure['exitCode'] <= 255, 'output')
            require((failure['stage'] == 'gate' and not events) or
                    (failure['stage'] != 'gate' and group is not None and len(events) == 1 and events[0].get('event') == 'ready'), 'output')
            sandbox_failure.update(failure)
        events.append(data)
        if data.get('event') == 'ready':
            if diagnostic is not None:
                diagnostic.update(stage='ready-validation', readyEventSeen=True)
            require(len(events) == 1 and data.get('uid') == os.getuid() and data.get('gid') == os.getgid())
            address_space = data.get('addressSpace')
            require(isinstance(address_space, dict) and set(address_space) == {'soft', 'hard'} and
                    all(type(value) is int and value == 17179869184 for value in address_space.values()), 'address-space')
            require(all(data.get(key) is True for key in ('pid1', 'root_ro', 'mounts_safe', 'caps_zero', 'no_new_privs')))
            require(type(data.get('seccomp')) is int and data['seccomp'] == 2 and
                    type(data.get('apparmor')) is str and data['apparmor'] == 'docker-default (enforce)')
            tmpfs = data.get('tmpfs')
            require(type(tmpfs) is dict and {'type', 'bytes', 'inodes', 'flags'} <= set(tmpfs) and
                    all(type(tmpfs[key]) is int for key in ('type', 'bytes', 'inodes', 'flags')))
            require(tmpfs['type'] == 0x01021994 and 0 < tmpfs['bytes'] <= 256 << 20 and
                    0 < tmpfs['inodes'] <= 16384 and 0 <= tmpfs['flags'] < (1 << 64) and
                    tmpfs['flags'] & 14 == 14 and not tmpfs['flags'] & 1)
            observed = inspect(name) if trace is None else inspect(name, trace, 'mechanical-inspect-running')
            require(observed['State']['Running'] and observed['HostConfig']['NetworkMode'] == 'none' and observed['HostConfig']['ReadonlyRootfs'])
            if diagnostic is not None:
                diagnostic['stage'] = 'host-cgroup'
            group = cgroup_for(observed['State']['Pid'])
            if diagnostic is not None:
                diagnostic['stage'] = 'fixture-running'
            if before and 'OPENAI_API_KEY' in value:
                require(value['OPENAI_API_KEY'] not in json.dumps(observed) + image_record, 'privacy')
            stdin.write(b'GO\n')
            stdin.flush()
        elif data.get('event') == 'result':
            require(type(data.get('ok')) is bool and type(data.get('providerRequests')) is int and 0 <= data['providerRequests'] <= 8, 'output')
            if diagnostic is not None:
                diagnostic.update(stage='fixture-result', resultEventSeen=True, resultOk=data['ok'])
                if not diagnostic['readyEventSeen'] and not data['ok'] and 'admissionFailure' in data:
                    failure = data.get('admissionFailure')
                    require(type(failure) is dict and {'stage'} <= set(failure) <= {'stage', 'addressSpace', 'processMounts'} and
                            type(failure.get('stage')) is str and failure['stage'] in MECHANICAL_ADMISSION_STAGES, 'output')
                    if 'addressSpace' in failure:
                        space = failure['addressSpace']
                        require(type(space) is dict and set(space) == {'soft', 'hard'} and
                                all(type(value) is int and -1 <= value < (1 << 64) for value in space.values()), 'output')
                    if 'processMounts' in failure:
                        process = failure['processMounts']
                        keys = {'substage', 'rootRo', 'mountsSafe', 'capsZero', 'noNewPrivs'}
                        require(failure['stage'] == 'process-mounts' and type(process) is dict and
                                {'substage'} <= set(process) <= keys and type(process['substage']) is str and
                                process['substage'] in PROCESS_MOUNT_SUBSTAGES and
                                all(type(value) is bool for key, value in process.items() if key != 'substage'), 'output')
                    diagnostic['fixtureAdmissionFailure'] = failure
        elif data.get('event') == 'detached':
            require(case == 'detached' and group and len((group / 'cgroup.procs').read_text().split()) >= 2)
            command([*DOCKER, 'kill', '--signal', 'KILL', name])
            detached_completed = True
    try:
        if diagnostic is not None:
            diagnostic['stage'] = 'mechanical-start'
        code = command([*DOCKER, 'start', '-a', '-i', name], on_line=event, timeout=70, trace=trace, phase='mechanical-start' if trace is not None else None)
        if diagnostic is not None:
            diagnostic['stage'] = 'post-case-cgroup'
        require(group is not None, 'cleanup')
        end = time.monotonic() + 2
        with contextlib.suppress(FileNotFoundError):
            while (group / 'cgroup.procs').read_text().strip() and time.monotonic() < end:
                time.sleep(0.02)
            require(not (group / 'cgroup.procs').read_text().strip(), 'cleanup')
        observed = inspect(name) if trace is None else inspect(name, trace, 'mechanical-inspect-stopped')
        require(not observed['State']['Running'], 'cleanup')
        exit_code = observed['State'].get('ExitCode')
        if case != 'detached':
            result = events[-1]
            require(result.get('event') == 'result' and result.get('case') == case and type(result.get('ok')) is bool, 'native-sandbox' if case == 'sandbox' else case)
            require(result.get('providerRequests') == 0 if case != 'api' else (0 < result.get('providerRequests', 0) <= 8 if result['ok'] else 0 <= result.get('providerRequests', 0) <= 8), case)
            require(not result['ok'] or (type(code) is int and code == 0 and
                    type(exit_code) is int and exit_code == 0), 'process')
        else:
            require(detached_completed and type(code) is int and code in (0, 137) and
                    type(exit_code) is int and exit_code == 137, 'process')
            result = {'case': case, 'ok': True, 'providerRequests': 0}
        if before:
            require(auth_snapshot(auth) == before, 'auth-persistence')
            require(all(value['OPENAI_API_KEY'] not in json.dumps(event) for event in events) if 'OPENAI_API_KEY' in value else True, 'privacy')
        public = {key: result[key] for key in ('case', 'ok', 'providerRequests')}
        if case == 'mechanical':
            public['addressSpace'] = events[0]['addressSpace']
        if case == 'api' and (result['ok'] or 'mockMethods' in result):
            methods = result.get('mockMethods')
            require(isinstance(methods, dict) and set(methods) == {'GET', 'POST'}, 'output')
            require(all(type(value) is int and 0 <= value <= 8 for value in methods.values()), 'output')
            require(sum(methods.values()) == result['providerRequests'] and (not result['ok'] or methods['POST'] > 0), 'output')
            public['mockMethods'] = methods
        return public
    except BaseException:
        if diagnostic is not None:
            diagnostic['failureStage'] = diagnostic['stage']
        raise
    finally:
        if diagnostic is not None:
            diagnostic['stage'] = 'mechanical-remove'
        command([*DOCKER, 'rm', '-f', name], cleanup=True, timeout=20, trace=trace, phase='mechanical-remove' if trace is not None else None)
        containers.remove(name)
        if diagnostic is not None:
            diagnostic['stage'] = 'container-removed'


def self_test():
    global DEADLINE, ENV
    if sys.platform == 'linux':
        previous = DEADLINE, ENV
        DEADLINE, ENV = time.monotonic() + 10, {'PATH': '/usr/bin:/bin'}
        try:
            require(command([sys.executable, '-I', '-S', '-c', 'print(123)']) == b'123\n')
            for source, kwargs, phase in [('print("x" * 32)', {'limit': 16}, 'output'), ('print(123, end="")', {'on_line': lambda line, stdin: None}, 'output'), ('import time; time.sleep(1)', {'timeout': 0.01}, 'deadline')]:
                try:
                    command([sys.executable, '-I', '-S', '-c', source], **kwargs)
                except Unsupported as error:
                    require(str(error) == phase)
                    continue
                raise AssertionError('unbounded command accepted')
        finally:
            DEADLINE, ENV = previous
    spec = importlib.util.spec_from_file_location('fixture', HERE / 'controlled-reviewer-fixture.py')
    fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)
    require(fixture.policy_allowed({'cli_auth_credentials_store': 'file'}))
    require(not fixture.policy_allowed({'cli_auth_credentials_store': 'auto'}))
    require(not fixture.classify_status(1, b'', b'API key configured - fake\n'))
    print('Controlled reviewer static negative checks passed; no native execution.')


@contextlib.contextmanager
def cleanup_clock():
    global CLEANUP_DEADLINE
    started = time.monotonic()
    previous, handler = CLEANUP_DEADLINE, signal.getsignal(signal.SIGALRM)
    timer = signal.getitimer(signal.ITIMER_REAL)
    CLEANUP_DEADLINE = started + 60
    def expired(signum, frame):
        raise Unsupported('cleanup')
    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, 60)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, handler)
        if timer[0] > 0:
            signal.setitimer(signal.ITIMER_REAL, max(0.001, timer[0] - (time.monotonic() - started)), timer[1])
        CLEANUP_DEADLINE = previous


def encode_evidence(evidence):
    encoded = json.dumps(evidence, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
    if len(EVIDENCE_PREFIX.encode('utf-8')) + len(encoded) + 1 > 65536:
        fallback = {'schema': 1, 'ok': False, 'cleanup': evidence.get('cleanup') is True,
                    'reason': 'evidence-limit', 'omittedBytes': len(encoded), 'omittedSha256': sha(encoded)}
        if evidence.get('repository') == 'OMT-Global/bootstrap':
            fallback['repository'] = evidence['repository']
        for key, pattern in (('head', '[a-f0-9]{40}'), ('runId', '[0-9]{1,32}')):
            value = evidence.get(key)
            if isinstance(value, str) and re.fullmatch(pattern, value):
                fallback[key] = value
        evidence = fallback
        encoded = json.dumps(evidence, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
    require(len(EVIDENCE_PREFIX.encode('utf-8')) + len(encoded) + 1 <= 65536, 'evidence-limit')
    return evidence, encoded


def main():
    global DEADLINE, ENV, DOCKER
    require(sys.platform == 'linux' and os.uname().machine == 'x86_64' and os.getuid() > 0, 'platform')
    require(os.environ.get('RELEASE_PROFILE') == 'full' and os.environ.get('GITHUB_REPOSITORY') == 'OMT-Global/bootstrap' and re.fullmatch('[0-9]+', os.environ.get('GITHUB_RUN_ID', '')), 'ci-context')
    DEADLINE = time.monotonic() + 900
    os.umask(0o077)
    evidence = {'schema': 1, 'repository': 'OMT-Global/bootstrap', 'runId': os.environ['GITHUB_RUN_ID'], 'codexSourceCommit': artifacts.SOURCE, 'cases': [], 'ok': False, 'cleanup': False}
    containers, image, directory = [], None, None
    sandbox_failure = {}
    try:
        directory = Path(tempfile.mkdtemp(prefix='bootstrap-reviewer-probe-'))
        ENV = {'PATH': '/usr/bin:/bin', 'HOME': str(directory), 'TMPDIR': str(directory), 'LANG': 'C.UTF-8', 'DOCKER_CONFIG': str(directory / 'docker-config'), 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null'}
        DOCKER = ['/usr/bin/docker', '--host', 'unix:///var/run/docker.sock']
        self_test()
        evidence['head'] = command(['/usr/bin/git', '-C', str(HERE.parent.parent), 'rev-parse', 'HEAD']).decode().strip()
        require(re.fullmatch('[a-f0-9]{40}', evidence['head']), 'ci-context')
        evidence['bootstrapStage'] = 'docker-info-command'
        info_bytes = command([*DOCKER, 'info', '--format', '{{json .}}'])
        evidence['bootstrapStage'] = 'docker-info-parse'
        info = json.loads(info_bytes)
        evidence['bootstrapStage'] = 'docker-info-admission'
        require(info['OSType'] == 'linux' and info['Architecture'] == 'x86_64' and info['CgroupVersion'] == '2', 'platform')
        security_options = info['SecurityOptions']
        require(type(security_options) is list and all(type(value) is str for value in security_options), 'platform')
        seccomp = [value for value in security_options if value.split(',', 1)[0] == 'name=seccomp']
        apparmor = [value for value in security_options if value.split(',', 1)[0] == 'name=apparmor']
        require(seccomp == ['name=seccomp,profile=builtin'] and apparmor == ['name=apparmor'] and
                not any('rootless' in value or 'unconfined' in value for value in security_options), 'platform')
        evidence['bootstrapStage'] = 'artifact-directory'
        artifact_directory = directory / 'artifacts'
        artifact_directory.mkdir(mode=0o700)
        evidence['bootstrapStage'] = 'artifact-stage-call'
        staged = artifacts.stage(artifact_directory, absolute_deadline=DEADLINE)
        evidence['bootstrapStage'] = 'staged-head-admission'
        require(staged['evidence']['head'] == evidence['head'], 'ci-context')
        evidence['bootstrapStage'] = 'staged-evidence-retention'
        evidence.update(staged['evidence'])
        evidence.pop('bootstrapStage')
        context = staged['context']
        evidence['sourceHashes'] = {name: sha((HERE / name).read_bytes()) for name in ('controlled-reviewer-probe.py', 'controlled-reviewer-fixture.py', 'controlled-reviewer-probe.Dockerfile')}
        shutil.copyfile(HERE / 'controlled-reviewer-fixture.py', context / 'reviewer-gate.py')
        shutil.copyfile(HERE / 'controlled-reviewer-probe.Dockerfile', context / 'Dockerfile')
        image = 'bootstrap-reviewer-probe:' + uuid.uuid4().hex
        command([*DOCKER, 'build', '--network', 'none', '--pull=false', '--tag', image, str(context)], timeout=180, limit=4 << 20)
        image_record = command([*DOCKER, 'image', 'inspect', image]).decode()
        evidence['image'] = json.loads(image_record)[0]['Id']
        diagnostic = {'stage': 'image-history', 'commands': [], 'readyEventSeen': False, 'resultEventSeen': False, 'resultOk': None}
        evidence['preAuthDiagnostic'] = diagnostic
        image_record += command([*DOCKER, 'history', '--no-trunc', '--format', '{{json .}}', image], trace=diagnostic['commands'], phase='image-history').decode()
        require(re.fullmatch('sha256:[a-f0-9]{64}', evidence['image']), 'image')
        for case in ('mechanical', 'bytes', 'inodes', 'detached', 'sandbox', 'status-api', 'status-oauth', 'status-unknown', 'status-auto', 'status-keyring', 'api', 'persistence'):
            result = case_run(case, image, directory, containers, image_record,
                              diagnostic if case == 'mechanical' else None, sandbox_failure if case == 'sandbox' else None)
            evidence['cases'].append(result)
            require(result['ok'], 'native-sandbox' if case == 'sandbox' else case)
        evidence['ok'] = True
    except BaseException as error:
        evidence['reason'] = str(error) if isinstance(error, Unsupported) else 'unsupported'
        if sandbox_failure:
            evidence['sandboxFailure'] = sandbox_failure.copy()
        if 'bootstrapStage' in evidence and type(error) is urllib.error.HTTPError:
            status = dict.get(object.__getattribute__(error, '__dict__'), 'code')
            if type(status) is int and status in {403, 404, 408, 429, 500, 502, 503, 504}:
                evidence['bootstrapHttpStatus'] = status
    finally:
        try:
            with cleanup_clock():
                try:
                    cleanup_ok = True
                    for name in list(containers):
                        try:
                            command([*DOCKER, 'rm', '-f', name], cleanup=True, timeout=20)
                        except BaseException:
                            cleanup_ok = False
                    if image:
                        try:
                            command([*DOCKER, 'image', 'rm', image], cleanup=True, timeout=20)
                        except BaseException:
                            cleanup_ok = False
                    require(cleanup_ok, 'cleanup')
                finally:
                    require(time.monotonic() < CLEANUP_DEADLINE, 'cleanup')
                    if directory is not None:
                        shutil.rmtree(directory)
                        require(not directory.exists(), 'cleanup')
            evidence['cleanup'] = True
        except BaseException:
            evidence.update(ok=False, cleanup=False, reason='cleanup')
    evidence, encoded = encode_evidence(evidence)
    report = HERE.parent.parent / 'dist/release/controlled-reviewer-evidence.json'
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_bytes(encoded + b'\n')
    sys.stdout.buffer.write(EVIDENCE_PREFIX.encode('utf-8') + encoded + b'\n')
    sys.stdout.buffer.flush()
    return 0 if evidence['ok'] and evidence['cleanup'] else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args()
    if args.self_test:
        self_test()
    else:
        sys.exit(main())
