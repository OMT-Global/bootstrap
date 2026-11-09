#!/usr/bin/env python3
"""Synthetic Linux-only PID1 fixture; never an application execution adapter."""
import argparse
import ctypes
import errno
import hashlib
import http.server
import json
import os
from pathlib import Path
import resource
import selectors
import signal
import socket
import stat
import subprocess
import sys
import threading
import time
import tomllib

ROOT = Path('/run/review')
SOURCE = Path('/operator/.codex/auth.json')
CODEX = '/opt/codex/bin/codex'
CASES = ('mechanical', 'bytes', 'inodes', 'detached', 'sandbox', 'status-api',
         'status-oauth', 'status-unknown', 'status-auto', 'status-keyring', 'api', 'persistence')
MOCK_REQUESTS = 0
ADMISSION = {'stage': 'platform'}
SANDBOX_FAILURE = {}
LIMITS = {'core': (resource.RLIMIT_CORE, 0), 'fsize': (resource.RLIMIT_FSIZE, 64 << 20),
          'nofile': (resource.RLIMIT_NOFILE, 256), 'nproc': (resource.RLIMIT_NPROC, 128),
          'as': (resource.RLIMIT_AS, 16 << 30), 'cpu': (resource.RLIMIT_CPU, 3600)}


def require(value):
    if not value:
        raise RuntimeError('fixture-check-failed')


def emit(value):
    print(json.dumps(value, separators=(',', ':')), flush=True)


def sandbox_stage(stage, code=None):
    SANDBOX_FAILURE.clear()
    SANDBOX_FAILURE['stage'] = stage
    if (stage in ('version-exit', 'sandbox-exit') and
            type(code) is int and -255 <= code <= 255):
        SANDBOX_FAILURE['exitCode'] = code


def classify_status(returncode, stdout, stderr):
    lines = stderr.splitlines()
    return (returncode == 0 and stdout == b'' and len(stderr) <= 16384 and len(lines) >= 2 and
            lines[-2].startswith(b'API key configured - ') and len(lines[-2]) > 21 and
            lines[-1] == b'Authentication is checked when you send a request.' and
            all(line.startswith(b'WARNING: proceeding, even though we could not create PATH aliases: ')
                for line in lines[:-2]))


def policy_allowed(config):
    allowed = {'cli_auth_credentials_store', 'forced_login_method', 'forced_chatgpt_workspace_id'}
    return (isinstance(config, dict) and set(config) <= allowed and
            config.get('cli_auth_credentials_store', 'file') == 'file' and
            config.get('forced_login_method') in (None, 'api') and
            config.get('forced_chatgpt_workspace_id') in (None, ''))


def native(args, input_bytes=b'', cap=16384):
    """Keep potentially key-bearing native output in bounded private memory only."""
    proc = subprocess.Popen([CODEX, *args], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, env=dict(os.environ), start_new_session=True)
    collected = [bytearray(), bytearray()]
    deadline = time.monotonic() + 45
    try:
        proc.stdin.write(input_bytes)
        proc.stdin.close()
        with selectors.DefaultSelector() as selector:
            selector.register(proc.stdout, selectors.EVENT_READ, 0)
            selector.register(proc.stderr, selectors.EVENT_READ, 1)
            while selector.get_map():
                require(time.monotonic() < deadline)
                for key, _ in selector.select(0.1):
                    block = os.read(key.fd, min(4096, cap + 1 - sum(map(len, collected))))
                    if not block:
                        selector.unregister(key.fileobj)
                    else:
                        collected[key.data].extend(block)
                        require(sum(map(len, collected)) <= cap)
            return proc.wait(timeout=2), bytes(collected[0]), bytes(collected[1])
    finally:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        if proc.poll() is None:
            proc.wait(timeout=2)
        proc.stdout.close()
        proc.stderr.close()
        for value in collected:
            value.clear()


def gate():
    ADMISSION.clear()
    ADMISSION['stage'] = 'platform'
    require(sys.platform == 'linux' and os.getpid() == 1 and os.getuid() != 0)
    os.umask(0o077)
    ADMISSION['stage'] = 'inherited-as'
    address_space = resource.getrlimit(resource.RLIMIT_AS)
    ADMISSION['addressSpace'] = {'soft': address_space[0], 'hard': address_space[1]}
    require(address_space == (16 << 30, 16 << 30))
    ADMISSION['stage'] = 'resource-setters'
    for limit, value in LIMITS.values():
        resource.setrlimit(limit, (value, value))
    ADMISSION['stage'] = 'environment-directories'
    os.environ.clear()
    os.environ.update(PATH='/opt/codex/bin:/opt/codex/codex-resources:/usr/local/bin:/usr/bin:/bin',
                      HOME=str(ROOT / 'home'), TMPDIR=str(ROOT / 'tmp'),
                      CODEX_HOME=str(ROOT / 'codex-home'), LANG='C.UTF-8')
    for name in ('home', 'tmp', 'codex-home', 'workspace', 'private', 'state', 'log'):
        (ROOT / name).mkdir(mode=0o700)
    for kind in ('CACHE', 'CONFIG', 'DATA', 'STATE'):
        target = ROOT / ('xdg-' + kind.lower())
        target.mkdir(mode=0o700)
        os.environ['XDG_' + kind + '_HOME'] = str(target)
    ADMISSION['stage'] = 'process-mounts'
    process_context = {'substage': 'status-read'}
    ADMISSION['processMounts'] = process_context
    status_text = Path('/proc/self/status').read_text()
    process_context['substage'] = 'status-parse'
    status = dict(line.split(':', 1) for line in status_text.splitlines() if ':' in line)
    require(status['Seccomp'].strip() == '2')
    apparmor = Path('/proc/self/attr/apparmor/current').read_bytes()
    require(apparmor == b'docker-default (enforce)\n')
    process_context['substage'] = 'capabilities'
    caps_zero = all(int(status[name].strip(), 16) == 0 for name in ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb'))
    process_context['capsZero'] = caps_zero
    process_context['substage'] = 'mountinfo-read'
    mountinfo_text = Path('/proc/self/mountinfo').read_text()
    process_context['substage'] = 'mountinfo-parse'
    mounts = [line.split() for line in mountinfo_text.splitlines()]
    process_context['substage'] = 'root-ro'
    root_ro = any(row[4] == '/' and 'ro' in row[5].split(',') for row in mounts)
    process_context['rootRo'] = root_ro
    process_context['substage'] = 'mounts-safe'
    mounts_safe = all(row[4] == str(ROOT) or 'rw' not in row[5].split(',') or
                      (row[4] == '/proc' or row[4].startswith('/proc/')) or not os.access(row[4], os.W_OK) or
                      stat.S_ISCHR(os.stat(row[4]).st_mode) for row in mounts)
    process_context['mountsSafe'] = mounts_safe
    process_context['substage'] = 'combined-predicate'
    no_new_privs = None
    try:
        require(root_ro and mounts_safe and caps_zero and (no_new_privs := status['NoNewPrivs'].strip() == '1'))
    finally:
        if type(no_new_privs) is bool:
            process_context['noNewPrivs'] = no_new_privs
    ADMISSION.pop('processMounts')

    ADMISSION['stage'] = 'shared-memory'
    require(not os.path.exists('/dev/shm') or not os.access('/dev/shm', os.W_OK))
    ADMISSION['stage'] = 'tmpfs'
    fs = os.statvfs(ROOT)
    raw = ctypes.create_string_buffer(256)
    require(ctypes.CDLL(None).statfs(bytes(ROOT), raw) == 0)
    magic = ctypes.cast(raw, ctypes.POINTER(ctypes.c_long))[0]
    require(magic == 0x01021994 and 0 < fs.f_blocks * fs.f_frsize <= 256 << 20 and 0 < fs.f_files <= 16384)
    flags = fs.f_flag
    required_flags = os.ST_NOSUID | os.ST_NODEV | os.ST_NOEXEC
    require(type(flags) is int and 0 <= flags < (1 << 64) and
            flags & required_flags == required_flags and not flags & os.ST_RDONLY)
    ADMISSION['stage'] = 'cgroup'
    values = {name: Path('/sys/fs/cgroup', name).read_text().strip()
              for name in ('memory.max', 'memory.swap.max', 'pids.max', 'cpu.max')}
    require(values == {'memory.max': '2147483648', 'memory.swap.max': '0', 'pids.max': '128', 'cpu.max': '200000 100000'})
    ADMISSION['stage'] = 'architecture'
    require(sys.version_info >= (3, 11) and os.uname().machine == 'x86_64')
    ADMISSION['stage'] = 'package-binaries'
    for name in ('bin/codex', 'bin/codex-code-mode-host', 'bin/codex-exec-server', 'codex-resources/bwrap', 'codex-path/rg'):
        file = Path('/opt/codex', name)
        info = file.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1 and
                info.st_mode & 0o111 and not info.st_mode & 0o6022)
        with file.open('rb') as source:
            header = source.read(20)
        require(header[:7] == b'\x7fELF\x02\x01\x01' and header[18:20] == b'\x3e\x00')
    ADMISSION['stage'] = 'ready'
    emit({'event': 'ready', 'uid': os.getuid(), 'gid': os.getgid(), 'pid1': True,
          'root_ro': root_ro, 'mounts_safe': mounts_safe, 'caps_zero': caps_zero, 'no_new_privs': True,
          'seccomp': 2, 'apparmor': 'docker-default (enforce)',
          'tmpfs': {'type': magic, 'bytes': fs.f_blocks * fs.f_frsize, 'inodes': fs.f_files, 'flags': flags},
          'addressSpace': {'soft': address_space[0], 'hard': address_space[1]},
          'limits': {name: value for name, (_, value) in LIMITS.items()}, 'cgroup': values})
    require(sys.stdin.buffer.readline(4) == b'GO\n')


def policy():
    return ['--ask-for-approval', 'never', '-c', 'cli_auth_credentials_store="file"',
            '-c', 'project_doc_max_bytes=0',
            '-c', 'features.hooks=false', '-c', 'features.plugins=false',
            '-c', 'features.shell_snapshot=false', '-c', 'skills.include_instructions=false',
            '-c', 'skills.config=[]', '-c', 'allow_login_shell=false',
            '-c', 'default_permissions="autoreview"',
            '-c', 'permissions.autoreview.filesystem={":minimal"="read",":workspace_roots"="read","/opt/codex"="read"}',
            '-c', 'permissions.autoreview.network.enabled=false',
            '-c', 'sqlite_home="/run/review/state"', '-c', 'log_dir="/run/review/log"']


def exhaustion(kind):
    directory = ROOT / 'fill'
    directory.mkdir()
    written = 0
    try:
        for number in range(17000 if kind == 'inodes' else 20):
            with (directory / str(number)).open('xb') as output:
                if kind == 'bytes':
                    for _ in range(16):
                        written += output.write(b'x' * (1 << 20))
    except OSError as error:
        require(error.errno == errno.ENOSPC and written <= 256 << 20)
        return
    raise RuntimeError('resource-limit-not-enforced')


def sandbox():
    sandbox_stage('version-call')
    result, stdout, stderr = native(['--version'])
    sandbox_stage('version-exit', result)
    require(result == 0)
    sandbox_stage('version-stdout')
    require(stdout.strip() == b'codex-cli 0.167.0')
    sandbox_stage('version-stderr')
    require(stderr == b'')
    sandbox_stage('workspace-setup')
    workspace = ROOT / 'workspace'
    (workspace / 'public').write_text('public fixture')
    private = ROOT / 'private' / 'canary'
    private.write_text('synthetic private canary')
    sandbox_stage('loopback-control')
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen()
    address = listener.getsockname()
    control = socket.create_connection(address, timeout=1)
    accepted, _ = listener.accept()
    control.close()
    accepted.close()
    command = f'''from pathlib import Path
import socket
assert Path('public').read_text() == 'public fixture'
for operation in [lambda: Path({str(private)!r}).read_bytes(), lambda: Path('forbidden').write_text('x'), lambda: socket.create_connection({address!r}, timeout=1)]:
    try: operation()
    except OSError: pass
    else: raise RuntimeError('sandbox boundary failed')
'''
    try:
        sandbox_stage('sandbox-call')
        result, stdout, stderr = native([*policy(), 'sandbox', '--permission-profile', 'autoreview',
                                 '--cd', str(workspace), '--', '/usr/bin/python3', '-I', '-S', '-c', command])
        sandbox_stage('sandbox-exit', result)
        require(result == 0)
        sandbox_stage('listener-postcheck')
        listener.settimeout(0.1)
        try:
            accepted, _ = listener.accept()
            accepted.close()
            raise RuntimeError('sandbox-network-escaped')
        except TimeoutError:
            pass
    finally:
        try:
            listener.close()
        except BaseException:
            sandbox_stage('listener-close')
            raise


def file_auth():
    info = SOURCE.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1)
    require(stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= 1000000 and not os.access(SOURCE, os.W_OK))
    config = tomllib.loads(Path('/operator/.codex/config.toml').read_text())
    if not policy_allowed(config):
        return False
    (ROOT / 'codex-home' / 'auth.json').symlink_to(SOURCE)
    result, stdout, stderr = native(['-c', 'cli_auth_credentials_store="file"', 'login', 'status'])
    accepted = classify_status(result, stdout, stderr)
    del stdout, stderr
    return accepted


def api():
    require(file_auth())
    fake_key = json.loads(SOURCE.read_bytes())['OPENAI_API_KEY']
    require(isinstance(fake_key, str) and fake_key.startswith('bootstrap-fixture-'))
    requests = []
    methods = {'GET': 0, 'POST': 0}
    message = {'id': 'msg_fixture', 'type': 'message', 'role': 'assistant', 'status': 'completed',
               'content': [{'type': 'output_text', 'text': '{"status":"fixture-ok"}', 'annotations': []}]}

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            global MOCK_REQUESTS
            MOCK_REQUESTS += 1
            methods['GET'] += 1
            valid = (MOCK_REQUESTS <= 8 and self.path == '/v1/responses' and
                     self.headers.get('Authorization') == 'Bearer ' + fake_key)
            requests.append(valid)
            require(valid)
            self.send_response(426)
            self.end_headers()

        def do_POST(self):
            global MOCK_REQUESTS
            MOCK_REQUESTS += 1
            methods['POST'] += 1
            requests.append(False)
            self.connection.settimeout(2)
            length = int(self.headers.get('Content-Length', '0'))
            require(0 < length <= 2 << 20 and MOCK_REQUESTS <= 8)
            body = self.rfile.read(length)
            valid = (self.headers.get('Authorization') == 'Bearer ' + fake_key and
                     fake_key.encode() not in body and self.path == '/v1/responses')
            requests[-1] = valid
            require(valid)
            events = [{'type': 'response.created', 'response': {'id': 'resp_fixture'}},
                      {'type': 'response.output_item.done', 'output_index': 0, 'item': message},
                      {'type': 'response.completed', 'response': {'id': 'resp_fixture', 'output': [message],
                       'usage': {'input_tokens': 1, 'output_tokens': 1, 'total_tokens': 2}}}]
            encoded = ''.join('data: ' + json.dumps(event) + '\n\n' for event in events).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.send_header('Content-Length', str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

    class Server(http.server.HTTPServer):
        def handle_error(self, *args):
            pass

    server = Server(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.05}, daemon=True)
    thread.start()
    schema = ROOT / 'schema.json'
    schema.write_text(json.dumps({'type': 'object', 'properties': {'status': {'const': 'fixture-ok'}},
                                 'required': ['status'], 'additionalProperties': False}))
    output_path = ROOT / 'response.json'
    try:
        endpoint = 'http://127.0.0.1:' + str(server.server_port) + '/v1'
        result, stdout, stderr = native([*policy(), '--model', 'gpt-5.6-sol', '-c', 'openai_base_url=' + json.dumps(endpoint),
                                'exec', '--ignore-user-config', '--ignore-rules', '--skip-git-repo-check', '--ephemeral',
                                '-C', str(ROOT / 'workspace'), '--output-schema', str(schema),
                                '--output-last-message', str(output_path), '-'], b'Return the requested fixture JSON.\n', 65536)
        require(fake_key.encode() not in stdout + stderr and result == 0 and methods['POST'] > 0 and all(requests))
        require(output_path.stat().st_size <= 1024 and json.loads(output_path.read_text()) == {'status': 'fixture-ok'})
        return {'providerRequests': MOCK_REQUESTS, 'mockMethods': methods}
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def run_case(case):
    if case in ('bytes', 'inodes'):
        exhaustion(case)
    elif case == 'detached':
        if os.fork() == 0:
            os.setsid()
            if os.fork() != 0:
                os._exit(0)
            while True:
                time.sleep(1)
        emit({'event': 'detached'})
        while True:
            time.sleep(1)
    elif case == 'sandbox':
        sandbox()
    elif case.startswith('status-'):
        accepted = file_auth()
        require(accepted == (case == 'status-api'))
        return {'method': 'api-file' if accepted else 'unsupported', 'providerRequests': 0}
    elif case == 'api':
        return api()
    elif case == 'persistence':
        require(file_auth())
        before = hashlib.sha256(SOURCE.read_bytes()).digest()
        fake_key = json.loads(SOURCE.read_bytes())['OPENAI_API_KEY']
        result, stdout, stderr = native(['-c', 'cli_auth_credentials_store="file"', 'login', '--with-api-key'], fake_key.encode() + b'\n')
        require(result != 0 and before == hashlib.sha256(SOURCE.read_bytes()).digest())
        require(sorted(path.name for path in SOURCE.parent.iterdir()) == ['auth.json', 'config.toml'])
    return {'providerRequests': 0}


if __name__ == '__main__':
    SANDBOX_FAILURE.clear()
    case = 'platform'
    try:
        parser = argparse.ArgumentParser()
        parser.add_argument('--case', choices=CASES, required=True)
        case = parser.parse_args().case
        if case == 'sandbox':
            sandbox_stage('gate')
        gate()
        if case == 'sandbox':
            sandbox_stage('dispatch')
        details = run_case(case)
        SANDBOX_FAILURE.clear()
        emit({'event': 'result', 'case': case, 'ok': True, 'phase': case, **details})
    except BaseException:
        failure = {'event': 'result', 'case': case, 'ok': False, 'phase': 'native-sandbox' if case == 'sandbox' else case,
                   'reason': 'unsupported', 'providerRequests': MOCK_REQUESTS}
        if case == 'sandbox' and SANDBOX_FAILURE:
            failure['sandboxFailure'] = SANDBOX_FAILURE.copy()
        if case == 'mechanical' and ADMISSION['stage'] != 'ready':
            failure['admissionFailure'] = ADMISSION
        emit(failure)
        sys.exit(1)
