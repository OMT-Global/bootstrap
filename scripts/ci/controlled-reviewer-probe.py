#!/usr/bin/env python3
"""Bounded, synthetic-only native reviewer proof for the full Linux CI profile."""
import argparse
import base64
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import selectors
import shutil
import signal
import ssl
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.parse
import urllib.request
import uuid

SOURCE = '086ccc833bc9cf01024ad2dd6af7dbd421b6bf9a'
RELEASE = 'https://github.com/openai/codex/releases/download/rust-v0.167.0/'
RAW = 'https://raw.githubusercontent.com/openai/codex/' + SOURCE + '/'
BASE = 'mcr.microsoft.com/devcontainers/javascript-node@sha256:447fa75fbc7123952284b50229148e933ea756c40718601fa0ec46edd29fd0c6'
ASSETS = {
    'package.tar.gz': (RELEASE + 'codex-package-x86_64-unknown-linux-musl.tar.gz', 200178910, '3bbf75e83de6b58aed28f2cf6e33ad423ec31fd4700a1457b94be557ea5a7c6e'),
    'package.sigstore': (RELEASE + 'codex-package-x86_64-unknown-linux-musl.tar.gz.sigstore', 8489, '11270497f2551719504256f77e832345c15a1de580479eeff76f7e3a4b6169e8'),
    'native.sigstore': (RELEASE + 'codex-x86_64-unknown-linux-musl.sigstore', 8509, 'cf219ae625e9cd189443e5753e6cb83b4925bf2674eafe21d081a75503103774'),
    'bwrap.sigstore': (RELEASE + 'bwrap-x86_64-unknown-linux-musl.sigstore', 8509, '9b1fa9713fe278f26eefdddabcbb54d46eb431f9f62ab89f09a93bfc86814b34'),
    'cosign': ('https://github.com/sigstore/cosign/releases/download/v3.1.4/cosign-linux-amd64', 145688404, '424e2c97d0b45fd7a6b608a87f090f35633f4c23ece5f092d48bba11aaf4bbfa'),
    'trusted-root.json': ('https://raw.githubusercontent.com/sigstore/root-signing/c9bda74ad2221f938f7d2e0295ca3aad2da710a8/targets/trusted_root.json', 6787, '6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66'),
    'LICENSE': (RAW + 'LICENSE', 10926, 'd17f227e4df5da1600391338865ce0f3055211760a36688f816941d58232d8dc'),
    'NOTICE': (RAW + 'NOTICE', 242, '9d71575ecfd9a843fc1677b0efb08053c6ba9fd686a0de1a6f5382fd3c220915'),
    'bubblewrap-COPYING': (RAW + 'codex-rs/vendor/bubblewrap/COPYING', 25383, 'b7993225104d90ddd8024fd838faf300bea5e83d91203eab98e29512acebd69c'),
    'ripgrep-LICENSE-MIT': ('https://raw.githubusercontent.com/BurntSushi/ripgrep/e89fff89ac9af12e8d4ce9d5fd07beb408ca730f/LICENSE-MIT', 1081, '0f96a83840e146e43c0ec96a22ec1f392e0680e6c1226e6f3ba87e0740af850f'),
    'ripgrep-UNLICENSE': ('https://raw.githubusercontent.com/BurntSushi/ripgrep/e89fff89ac9af12e8d4ce9d5fd07beb408ca730f/UNLICENSE', 1211, '7e12e5df4bae12cb21581ba157ced20e1986a0508dd10d0e8a4ab9a4cf94e85c'),
}
NATIVE = {'bin/codex': 'cdcb45aaa01d0f14e298985e09465aebccd47f64ecd298aea44814af7b62bbda',
          'codex-resources/bwrap': '77360cb751ccedc5971391444ac86a8a33c15b04d6b4a6fe45f5d25496e62c4c'}
ALLOWED_HOSTS = {'github.com', 'release-assets.githubusercontent.com', 'objects.githubusercontent.com', 'raw.githubusercontent.com'}
HERE = Path(__file__).resolve().parent
sys.dont_write_bytecode = True
DEADLINE = 0.0
ENV = {}
DOCKER = []


class Unsupported(RuntimeError):
    pass


def require(value, phase='mechanical'):
    if not value:
        raise Unsupported(phase)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def allowed_url(value):
    url = urllib.parse.urlsplit(value)
    return url.scheme == 'https' and url.hostname in ALLOWED_HOSTS and url.username is None and url.password is None and url.port in (None, 443)


class Redirect(urllib.request.HTTPRedirectHandler):
    max_redirections = 3

    def redirect_request(self, request, fp, code, message, headers, url):
        require(allowed_url(url), 'download')
        return super().redirect_request(request, fp, code, message, headers, url)


def download(directory, name, specification):
    url, expected_size, expected_hash = specification
    require(allowed_url(url), 'download')
    context = ssl.create_default_context(cafile='/etc/ssl/certs/ca-certificates.crt')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), Redirect(), urllib.request.HTTPSHandler(context=context))
    target = directory / name
    digest, size = hashlib.sha256(), 0
    request = urllib.request.Request(url, headers={'User-Agent': 'Bootstrap-public-native-proof'})
    with opener.open(request, timeout=10) as response, target.open('xb') as output:
        require(response.status == 200 and allowed_url(response.url), 'download')
        while True:
            require(time.monotonic() < DEADLINE, 'deadline')
            block = response.read(min(1 << 20, expected_size + 1 - size))
            if not block:
                break
            size += len(block)
            require(size <= expected_size, 'download')
            digest.update(block)
            output.write(block)
    require(size == expected_size and digest.hexdigest() == expected_hash, 'download')
    return target


def command(arguments, timeout=60, limit=1 << 20, on_line=None, cleanup=False):
    end = time.monotonic() + timeout
    if not cleanup:
        end = min(end, DEADLINE)
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
                    if key.data == 0:
                        if on_line:
                            pending.extend(block)
                            while b'\n' in pending:
                                line, _, remaining = pending.partition(b'\n')
                                pending[:] = remaining
                                on_line(line, process.stdin)
                        else:
                            result.extend(block)
            require(not pending, 'output')
            code = process.wait(timeout=2)
            require(code == 0 or on_line and code in (1, 137), 'process')
            return bytes(result)
    finally:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        if process.poll() is None:
            process.wait(timeout=2)
        process.stdin.close()
        process.stdout.close()
        process.stderr.close()


def archive_entries(archive):
    inventory, names, total = [], set(), 0
    for item in archive:
        name = item.name
        pure = PurePosixPath(name)
        require(name and len(name.encode('utf-8', 'strict')) <= 4096 and str(pure) == name and
                not pure.is_absolute() and all(part not in ('.', '..') for part in pure.parts) and
                len(pure.parts) <= 32 and '\\' not in name and '\x00' not in name, 'archive')
        require(name not in names and (item.isfile() or item.isdir()) and not item.mode & 0o7022, 'archive')
        require(item.size >= 0 and (item.isfile() or item.size == 0), 'archive')
        names.add(name)
        total += item.size
        require(len(names) <= 4096 and total <= 2 << 30, 'archive')
        inventory.append(item)
    files = {item.name for item in inventory if item.isfile()}
    require(all(not any(str(parent) in files for parent in PurePosixPath(name).parents if str(parent) != '.') for name in names), 'archive')
    return inventory, total


def extract(package, directory):
    with tarfile.open(package, 'r:gz') as archive:
        inventory, expanded = archive_entries(archive)
        for item in inventory:
            destination = directory / item.name
            if item.isdir():
                destination.mkdir(parents=True, exist_ok=True)
            else:
                destination.parent.mkdir(parents=True, exist_ok=True)
                with archive.extractfile(item) as source, destination.open('xb') as output:
                    shutil.copyfileobj(source, output, 1 << 20)
                require(destination.stat().st_size == item.size, 'archive')
                destination.chmod(0o755 if item.mode & 0o111 else 0o644)
    for target in [directory, *(p for p in directory.rglob('*') if p.is_dir())]:
        target.chmod(0o755)
    required = ['bin/codex', 'bin/codex-code-mode-host', 'bin/codex-exec-server', 'codex-path/rg', 'codex-resources/bwrap']
    for name in required:
        target = directory / name
        with target.open('rb') as source:
            require(source.read(20)[:6] == b'\x7fELF\x02\x01', 'package')
        require(target.stat().st_mode & 0o111, 'package')
    for name, expected in NATIVE.items():
        require(sha((directory / name).read_bytes()) == expected, 'package')
    metadata = json.loads((directory / 'codex-package.json').read_bytes())
    require(all(metadata.get(key) == value for key, value in {'layoutVersion': 1, 'version': '0.167.0', 'target': 'x86_64-unknown-linux-musl', 'variant': 'codex', 'entrypoint': 'bin/codex'}.items()), 'package')
    notices = [item.name for item in inventory if item.isfile() and re.search(r'(^|/)(LICENSE[^/]*|NOTICE[^/]*|COPYING[^/]*|licenses/)', item.name, re.I)]
    if (directory / 'codex-resources/voice').exists():
        require(all((directory / 'codex-resources/voice' / name).is_file() for name in ('NOTICE.md', 'sources.json', 'licenses/LGPL-2.1.txt', 'licenses/Opus.txt', 'licenses/PCRE2.md', 'licenses/libffi.txt', 'licenses/proxy-libintl.txt', 'licenses/sljit.txt', 'licenses/zlib.txt')), 'notices')
    require(all((directory / name).stat().st_size <= 1 << 20 for name in notices), 'notices')
    return {'members': len(inventory), 'expandedBytes': expanded, 'inventorySha256': sha(json.dumps([(i.name, i.size, i.mode) for i in inventory]).encode()), 'packageNoticesPreserved': {name: sha((directory / name).read_bytes()) for name in notices}}


def verify_signatures(directory, package):
    cosign = directory / 'cosign'
    cosign.chmod(0o700)
    for name, binary in [('package', directory / 'package.tar.gz'), ('native', package / 'bin/codex'), ('bwrap', package / 'codex-resources/bwrap')]:
        command([str(cosign), 'verify-blob', '--offline', '--trusted-root', str(directory / 'trusted-root.json'),
                 '--certificate-identity', 'https://github.com/openai/codex/.github/workflows/rust-release.yml@refs/tags/rust-v0.167.0',
                 '--certificate-oidc-issuer', 'https://token.actions.githubusercontent.com', '--bundle', str(directory / (name + '.sigstore')), str(binary)])


def inspect(name):
    return json.loads(command([*DOCKER, 'inspect', name]))[0]


def cgroup_for(pid):
    require(Path('/proc/self/ns/pid').readlink() != Path(f'/proc/{pid}/ns/pid').readlink())
    lines = Path(f'/proc/{pid}/cgroup').read_text().splitlines()
    require(len(lines) == 1 and lines[0].startswith('0::/'))
    location = Path('/sys/fs/cgroup', lines[0][4:]).resolve()
    require(location.is_relative_to('/sys/fs/cgroup') and str(pid) in (location / 'cgroup.procs').read_text().split())
    return location


def auth_snapshot(directory):
    return [(p.name, tuple(getattr(p.stat(), field) for field in ('st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')), sha(p.read_bytes())) for p in sorted(directory.iterdir())]


def case_run(case, image, directory, containers, image_record):
    name = 'bootstrap-reviewer-' + uuid.uuid4().hex
    arguments = [*DOCKER, 'create', '--name', name, '-i', '--read-only', '--network', 'none', '--cap-drop', 'ALL',
                 '--security-opt', 'no-new-privileges', '--memory', '2147483648', '--memory-swap', '2147483648',
                 '--pids-limit', '128', '--cpus', '2', '--ipc', 'none', '--log-driver', 'none', '--restart', 'no',
                 '--user', f'{os.getuid()}:{os.getgid()}', '--tmpfs', f'/run/review:rw,nosuid,nodev,noexec,size=268435456,nr_inodes=16384,uid={os.getuid()},gid={os.getgid()},mode=0700']
    for limit in ['core=0:0', 'fsize=67108864:67108864', 'nofile=256:256', 'nproc=128:128', 'as=17179869184:17179869184', 'cpu=3600:3600']:
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
    command([*arguments, image, '--case', case])
    events, group = [], None

    def event(line, stdin):
        nonlocal group
        data = json.loads(line)
        require(isinstance(data, dict) and len(events) < 4, 'output')
        events.append(data)
        if data.get('event') == 'ready':
            require(len(events) == 1 and data.get('uid') == os.getuid() and data.get('gid') == os.getgid())
            observed = inspect(name)
            require(observed['State']['Running'] and observed['HostConfig']['NetworkMode'] == 'none' and observed['HostConfig']['ReadonlyRootfs'])
            group = cgroup_for(observed['State']['Pid'])
            if before and 'OPENAI_API_KEY' in value:
                require(value['OPENAI_API_KEY'] not in json.dumps(observed) + image_record, 'privacy')
            stdin.write(b'GO\n')
            stdin.flush()
        elif data.get('event') == 'result':
            require(type(data.get('ok')) is bool and type(data.get('providerRequests')) is int and 0 <= data['providerRequests'] <= 8, 'output')
        elif data.get('event') == 'detached':
            require(case == 'detached' and group and len((group / 'cgroup.procs').read_text().split()) >= 2)
            command([*DOCKER, 'kill', '--signal', 'KILL', name])
    try:
        command([*DOCKER, 'start', '-a', '-i', name], on_line=event, timeout=70)
        require(group is not None, 'cleanup')
        end = time.monotonic() + 2
        while group.exists() and (group / 'cgroup.procs').read_text().strip() and time.monotonic() < end:
            time.sleep(0.02)
        require(not group.exists() or not (group / 'cgroup.procs').read_text().strip(), 'cleanup')
        require(not inspect(name)['State']['Running'], 'cleanup')
        if case != 'detached':
            result = events[-1]
            require(result.get('event') == 'result' and result.get('case') == case and type(result.get('ok')) is bool, 'native-sandbox' if case == 'sandbox' else case)
            require(result.get('providerRequests') == 0 if case != 'api' else (0 < result.get('providerRequests', 0) <= 8 if result['ok'] else 0 <= result.get('providerRequests', 0) <= 8), case)
        else:
            result = {'case': case, 'ok': True, 'providerRequests': 0}
        if before:
            require(auth_snapshot(auth) == before, 'auth-persistence')
            require(all(value['OPENAI_API_KEY'] not in json.dumps(event) for event in events) if 'OPENAI_API_KEY' in value else True, 'privacy')
        public = {key: result[key] for key in ('case', 'ok', 'providerRequests')}
        if case == 'api':
            methods = result.get('mockMethods')
            require(isinstance(methods, dict) and set(methods) == {'GET', 'POST'}, 'output')
            require(all(type(value) is int and 0 <= value <= 8 for value in methods.values()), 'output')
            require(sum(methods.values()) == result['providerRequests'] and (not result['ok'] or methods['POST'] > 0), 'output')
            public['mockMethods'] = methods
        return public
    finally:
        command([*DOCKER, 'rm', '-f', name], cleanup=True, timeout=20)
        containers.remove(name)


def self_test():
    global DEADLINE, ENV
    for name in ['../escape', '/absolute', 'a/../b', 'a\\b', 'a//b']:
        item = tarfile.TarInfo(name)
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode='w') as archive:
            archive.addfile(item)
        stream.seek(0)
        try:
            with tarfile.open(fileobj=stream) as archive:
                archive_entries(archive)
        except Unsupported:
            continue
        raise AssertionError('unsafe archive accepted')
    for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE):
        item = tarfile.TarInfo('unsafe'); item.type = kind
        try:
            archive_entries([item])
        except Unsupported:
            continue
        raise AssertionError('unsafe archive type accepted')
    item = tarfile.TarInfo('valid'); item.size = 3
    require(archive_entries([item])[1] == 3)
    for items in ([item, item], [item] * 4097):
        try:
            archive_entries(items)
        except Unsupported:
            continue
        raise AssertionError('unsafe archive inventory accepted')
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
    require(allowed_url(RELEASE) and not allowed_url('https://github.com.evil.invalid/a') and not allowed_url('https://fixture@github.com/a') and not allowed_url('https://:@github.com/a'))
    spec = importlib.util.spec_from_file_location('fixture', HERE / 'controlled-reviewer-fixture.py')
    fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)
    require(fixture.policy_allowed({'cli_auth_credentials_store': 'file'}))
    require(not fixture.policy_allowed({'cli_auth_credentials_store': 'auto'}))
    require(not fixture.classify_status(1, b'', b'API key configured - fake\n'))
    print('Controlled reviewer static negative checks passed; no native execution.')


def main():
    global DEADLINE, ENV, DOCKER
    require(sys.platform == 'linux' and os.uname().machine == 'x86_64' and os.getuid() > 0, 'platform')
    require(os.environ.get('RELEASE_PROFILE') == 'full' and os.environ.get('GITHUB_REPOSITORY') == 'OMT-Global/bootstrap' and re.fullmatch('[0-9]+', os.environ.get('GITHUB_RUN_ID', '')), 'ci-context')
    DEADLINE = time.monotonic() + 900
    os.umask(0o077)
    evidence = {'schema': 1, 'repository': 'OMT-Global/bootstrap', 'runId': os.environ['GITHUB_RUN_ID'], 'codexSourceCommit': SOURCE, 'cases': [], 'ok': False, 'cleanup': False}
    containers, image = [], None
    with tempfile.TemporaryDirectory(prefix='bootstrap-reviewer-probe-') as temporary:
        directory = Path(temporary)
        ENV = {'PATH': '/usr/bin:/bin', 'HOME': temporary, 'TMPDIR': temporary, 'LANG': 'C.UTF-8', 'DOCKER_CONFIG': str(directory / 'docker-config'), 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null'}
        DOCKER = ['/usr/bin/docker', '--host', 'unix:///var/run/docker.sock']
        try:
            self_test()
            evidence['head'] = command(['/usr/bin/git', '-C', str(HERE.parent.parent), 'rev-parse', 'HEAD']).decode().strip()
            require(re.fullmatch('[a-f0-9]{40}', evidence['head']), 'ci-context')
            info = json.loads(command([*DOCKER, 'info', '--format', '{{json .}}']))
            require(info['OSType'] == 'linux' and info['Architecture'] == 'x86_64' and info['CgroupVersion'] == '2' and not any('rootless' in value for value in info['SecurityOptions']), 'platform')
            for name, specification in ASSETS.items():
                download(directory, name, specification)
            context = directory / 'context'
            context.mkdir()
            package = context / 'verified-codex-package'
            package.mkdir()
            evidence['package'] = extract(directory / 'package.tar.gz', package)
            verify_signatures(directory, package)
            evidence['signatureVerified'] = True
            notices = context / 'public-notices'
            notices.mkdir(mode=0o755)
            for name in ('LICENSE', 'NOTICE', 'bubblewrap-COPYING', 'ripgrep-LICENSE-MIT', 'ripgrep-UNLICENSE'):
                shutil.copyfile(directory / name, notices / name)
                (notices / name).chmod(0o644)
            evidence['artifacts'] = {name: spec[2] for name, spec in ASSETS.items()}
            evidence['sourceHashes'] = {name: sha((HERE / name).read_bytes()) for name in ('controlled-reviewer-probe.py', 'controlled-reviewer-fixture.py', 'controlled-reviewer-probe.Dockerfile')}
            (context / 'public-provenance.json').write_text(json.dumps(evidence))
            shutil.copyfile(HERE / 'controlled-reviewer-fixture.py', context / 'reviewer-gate.py')
            shutil.copyfile(HERE / 'controlled-reviewer-probe.Dockerfile', context / 'Dockerfile')
            image = 'bootstrap-reviewer-probe:' + uuid.uuid4().hex
            command([*DOCKER, 'build', '--network', 'none', '--pull=false', '--tag', image, str(context)], timeout=180, limit=4 << 20)
            image_record = command([*DOCKER, 'image', 'inspect', image]).decode()
            evidence['image'] = json.loads(image_record)[0]['Id']
            image_record += command([*DOCKER, 'history', '--no-trunc', '--format', '{{json .}}', image]).decode()
            require(re.fullmatch('sha256:[a-f0-9]{64}', evidence['image']), 'image')
            for case in ('mechanical', 'bytes', 'inodes', 'detached', 'sandbox', 'status-api', 'status-oauth', 'status-unknown', 'status-auto', 'status-keyring', 'api', 'persistence'):
                result = case_run(case, image, directory, containers, image_record)
                evidence['cases'].append(result)
                require(result['ok'], 'native-sandbox' if case == 'sandbox' else case)
            evidence['ok'] = True
        except BaseException as error:
            evidence['reason'] = str(error) if isinstance(error, Unsupported) else 'unsupported'
        finally:
            try:
                for name in list(containers):
                    command([*DOCKER, 'rm', '-f', name], cleanup=True, timeout=20)
                if image:
                    command([*DOCKER, 'image', 'rm', image], cleanup=True, timeout=20)
                evidence['cleanup'] = True
            except BaseException:
                evidence['ok'] = False
                evidence['reason'] = 'cleanup'
        encoded = json.dumps(evidence, separators=(',', ':'))
        if len(encoded.encode()) > 65536:
            evidence = {**{key: evidence[key] for key in ('schema', 'repository', 'runId', 'head', 'cleanup') if key in evidence}, 'ok': False, 'reason': 'evidence-limit', 'omittedBytes': len(encoded.encode()), 'omittedSha256': sha(encoded.encode())}
            encoded = json.dumps(evidence, separators=(',', ':'))
        report = HERE.parent.parent / 'dist/release/controlled-reviewer-evidence.json'
        report.parent.mkdir(parents=True, exist_ok=True)
        report.write_text(json.dumps(evidence, indent=2) + '\n')
        print('CONTROLLED_REVIEWER_EVIDENCE ' + encoded)
        return 0 if evidence['ok'] and evidence['cleanup'] else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args()
    if args.self_test:
        self_test()
    else:
        sys.exit(main())
