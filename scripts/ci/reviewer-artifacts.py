#!/usr/bin/env python3
"""Fixed public Codex artifact staging; metadata preparation is explicitly online."""
import argparse
import base64
import contextlib
import hashlib
import json
import math
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

SOURCE = '086ccc833bc9cf01024ad2dd6af7dbd421b6bf9a'
RELEASE = 'https://github.com/openai/codex/releases/download/rust-v0.167.0/'
RAW = 'https://raw.githubusercontent.com/openai/codex/' + SOURCE + '/'
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
BUNDLE_PINS = {}  # Populated only from reviewed, successful preparation evidence.
BUNDLE_DIRECTORY = HERE / 'reviewer-artifact-bundles'
IDENTITY = 'https://github.com/openai/codex/.github/workflows/rust-release.yml@refs/tags/rust-v0.167.0'


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
            block = response.read1(min(1 << 20, expected_size + 1 - size))
            if not block:
                break
            size += len(block)
            require(size <= expected_size, 'download')
            digest.update(block)
            output.write(block)
    require(size == expected_size and digest.hexdigest() == expected_hash, 'download')
    return target


def command(arguments, timeout=60, limit=65536, diagnostic=None):
    end = min(time.monotonic() + timeout, DEADLINE)
    process = subprocess.Popen(arguments, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               env=ENV, start_new_session=True)
    output, error, total = bytearray(), bytearray(), 0
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
                    (output if key.data == 0 else error).extend(block)
            try:
                code = process.wait(timeout=max(0.001, min(2, end - time.monotonic())))
            except subprocess.TimeoutExpired:
                raise Unsupported('deadline') from None
            if diagnostic:
                require(diagnostic in ('package', 'native', 'bwrap'), 'diagnostic')
                print('REVIEWER_SIGNATURE_DIAGNOSTIC ' + json.dumps({'artifact': diagnostic, 'exitCode': code,
                      'stderr': error.decode('utf-8', 'replace')}), flush=True)
            require(code == 0, 'process')
            return bytes(output)
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
        require(time.monotonic() < DEADLINE, 'deadline')
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
    require(directory.is_dir() and not directory.is_symlink() and not any(directory.iterdir()), 'directory')
    with tarfile.open(package, 'r:gz') as archive:
        inventory, expanded = archive_entries(archive)
        for item in inventory:
            destination = directory / item.name
            if item.isdir():
                destination.mkdir(parents=True, exist_ok=True)
            else:
                destination.parent.mkdir(parents=True, exist_ok=True)
                with archive.extractfile(item) as source, destination.open('xb') as output:
                    while True:
                        require(time.monotonic() < DEADLINE, 'deadline')
                        block = source.read(1 << 20)
                        if not block:
                            break
                        output.write(block)
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


def read_bounded(path):
    metadata = path.lstat()
    require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1 and metadata.st_size <= 65536, 'bundle')
    with path.open('rb') as source:
        data = source.read(65537)
    require(len(data) == metadata.st_size, 'bundle')
    return data


def decode64(value):
    require(isinstance(value, str), 'bundle')
    return base64.b64decode(value, validate=True)


def integer(value):
    require(type(value) is int or isinstance(value, str) and re.fullmatch('0|[1-9][0-9]*', value), 'bundle')
    result = int(value)
    require(0 <= result <= (1 << 63) - 1, 'bundle')
    return result


def bundle_tag(artifact, field, failure):
    require(artifact in ('package', 'native', 'bwrap') and failure in ('shape', 'mismatch') and field in (
        'legacy-file', 'raw-file', 'standard-file', 'pinned-file', 'pinned-hash', 'legacy-json', 'standard-json', 'legacy-keys',
        'media-type', 'verification-material', 'certificate-pem', 'certificate-der', 'signature', 'kind-version',
        'rekor-body', 'rekor-log-id', 'rekor-log-index', 'rekor-integrated-time', 'rekor-set', 'digest-algorithm',
        'artifact-digest', 'proof', 'proof-index', 'proof-root-hash', 'proof-hashes', 'proof-checkpoint', 'candidate-json',
        'verified-bytes', 'candidate-bytes'),
        'bundle/diagnostic/shape')
    return 'bundle/' + artifact + '/' + field + '/' + failure


def read_bundle(path, artifact, field):
    tag = bundle_tag(artifact, field, 'shape')
    try:
        return read_bounded(path)
    except Unsupported as error:
        if str(error) != 'bundle':
            raise
        raise Unsupported(tag) from None
    except (OSError, TypeError, ValueError):
        raise Unsupported(tag) from None


def immutable_bundle_fields(legacy_data, standard_data, expected_digest, artifact='package'):
    """Bind immutable fields and both existing SET representations; no cryptography."""
    field = 'legacy-json'
    bundle_tag(artifact, field, 'shape')
    def check(value, failure='mismatch'):
        require(value, bundle_tag(artifact, field, failure))
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'bundle')
            result[key] = value
        return result
    def invalid_constant(value):
        raise Unsupported('bundle')
    def finite_float(value):
        number = float(value)
        require(math.isfinite(number), 'bundle')
        return number
    try:
        legacy = json.loads(legacy_data, object_pairs_hook=unique, parse_constant=invalid_constant, parse_float=finite_float)
        field = 'standard-json'
        standard = json.loads(standard_data, object_pairs_hook=unique, parse_constant=invalid_constant, parse_float=finite_float)
        field = 'legacy-keys'
        check(set(legacy) == {'base64Signature', 'cert', 'rekorBundle'}, 'shape')
        field = 'media-type'
        check(standard['mediaType'] == 'application/vnd.dev.sigstore.bundle+json;version=0.3')
        field = 'verification-material'
        material, message = standard['verificationMaterial'], standard['messageSignature']
        check(isinstance(material['tlogEntries'], list) and len(material['tlogEntries']) == 1 and
              'x509CertificateChain' not in material, 'shape')
        entry, old = material['tlogEntries'][0], legacy['rekorBundle']
        field = 'certificate-pem'
        pem = decode64(legacy['cert']).decode('ascii')
        check(re.fullmatch(r'-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----\s*', pem), 'shape')
        field = 'certificate-der'
        check(decode64(material['certificate']['rawBytes']) == ssl.PEM_cert_to_DER_cert(pem))
        field = 'signature'
        check(decode64(message['signature']) == decode64(legacy['base64Signature']))
        field = 'kind-version'
        check(entry['kindVersion'] == {'kind': 'hashedrekord', 'version': '0.0.1'})
        field = 'rekor-body'
        check(decode64(entry['canonicalizedBody']) == decode64(old['Payload']['body']))
        field = 'rekor-log-id'
        check(decode64(entry['logId']['keyId']) == bytes.fromhex(old['Payload']['logID']))
        field = 'rekor-log-index'
        check(integer(entry['logIndex']) == integer(old['Payload']['logIndex']))
        field = 'rekor-integrated-time'
        check(integer(entry['integratedTime']) == integer(old['Payload']['integratedTime']))
        field = 'rekor-set'
        original_set = decode64(old['SignedEntryTimestamp'])
        converted_set = decode64(entry['inclusionPromise']['signedEntryTimestamp'])
        check(original_set and converted_set, 'shape')
        field = 'digest-algorithm'
        check(message['messageDigest']['algorithm'] == 'SHA2_256')
        field = 'artifact-digest'
        check(decode64(message['messageDigest']['digest']) == bytes.fromhex(expected_digest))
        field = 'proof'
        proof = entry['inclusionProof']
        field = 'proof-index'
        check(integer(proof['logIndex']) < integer(proof['treeSize']))
        field = 'proof-root-hash'
        check(len(decode64(proof['rootHash'])) == 32)
        field = 'proof-hashes'
        check(isinstance(proof['hashes'], list), 'shape')
        check(all(len(decode64(value)) == 32 for value in proof['hashes']))
        field = 'proof-checkpoint'
        check(isinstance(proof['checkpoint']['envelope'], str) and proof['checkpoint']['envelope'], 'shape')
        return legacy, standard, original_set, converted_set
    except Unsupported as error:
        if str(error) != 'bundle':
            raise
        raise Unsupported(bundle_tag(artifact, field, 'shape')) from None
    except (KeyError, IndexError, TypeError, ValueError, UnicodeError):
        raise Unsupported(bundle_tag(artifact, field, 'shape')) from None


def audit_bundle(legacy_data, standard_data, expected_digest, artifact='package'):
    """Require the pinned original SET as well as every immutable field."""
    _, _, original_set, converted_set = immutable_bundle_fields(legacy_data, standard_data, expected_digest, artifact)
    require(original_set == converted_set, bundle_tag(artifact, 'rekor-set', 'mismatch'))


def normalize_bundle(legacy_data, raw_data, expected_digest, artifact='package'):
    """Change only the existing SET leaf after binding every immutable field."""
    _, standard, original_set, _ = immutable_bundle_fields(legacy_data, raw_data, expected_digest, artifact)
    standard['verificationMaterial']['tlogEntries'][0]['inclusionPromise']['signedEntryTimestamp'] = base64.b64encode(original_set).decode('ascii')
    try:
        candidate = (json.dumps(standard, indent=2, ensure_ascii=False, allow_nan=False) + '\n').encode('utf-8')
    except (TypeError, ValueError, UnicodeError):
        raise Unsupported(bundle_tag(artifact, 'candidate-json', 'shape')) from None
    require(len(candidate) <= 65536, bundle_tag(artifact, 'candidate-json', 'shape'))
    audit_bundle(legacy_data, candidate, expected_digest, artifact)
    return candidate

def binaries(directory, package):
    return [('package', directory / 'package.tar.gz'), ('native', package / 'bin/codex'),
            ('bwrap', package / 'codex-resources/bwrap')]


def verify_signatures(directory, package):
    cosign = directory / 'cosign'
    cosign.chmod(0o700)
    for name, binary in binaries(directory, package):
        command([str(cosign), 'verify-blob', '--offline', '--trusted-root', str(directory / 'trusted-root.json'),
                 '--certificate-identity', IDENTITY, '--certificate-oidc-issuer', 'https://token.actions.githubusercontent.com',
                 '--bundle', str(directory / (name + '.standard.json')), str(binary)], diagnostic=name)


@contextlib.contextmanager
def acquisition_clock(absolute_deadline=None):
    global DEADLINE
    started = time.monotonic()
    previous_deadline, handler = DEADLINE, signal.getsignal(signal.SIGALRM)
    timer = signal.getitimer(signal.ITIMER_REAL)
    DEADLINE = min(started + 900, absolute_deadline if absolute_deadline is not None else float('inf'),
                   started + timer[0] if timer[0] > 0 else float('inf'))
    require(DEADLINE > started, 'deadline')
    def expired(signum, frame):
        raise Unsupported('deadline')
    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, DEADLINE - started)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, handler)
        if timer[0] > 0:
            signal.setitimer(signal.ITIMER_REAL, max(0.001, timer[0] - (time.monotonic() - started)), timer[1])
        DEADLINE = previous_deadline


def acquire(directory):
    global ENV
    require(sys.platform == 'linux' and os.uname().machine == 'x86_64' and os.getuid() > 0, 'platform')
    require(os.environ.get('RELEASE_PROFILE') == 'full' and os.environ.get('GITHUB_REPOSITORY') == 'OMT-Global/bootstrap' and
            re.fullmatch('[0-9]+', os.environ.get('GITHUB_RUN_ID', '')), 'ci-context')
    require(directory.is_absolute() and directory.is_dir() and not directory.is_symlink() and
            directory.stat().st_uid == os.getuid() and not directory.stat().st_mode & 0o077 and not any(directory.iterdir()), 'directory')
    ENV = {'PATH': '/usr/bin:/bin', 'HOME': str(directory), 'TMPDIR': str(directory), 'LANG': 'C.UTF-8',
           'XDG_CONFIG_HOME': str(directory / 'config'), 'XDG_CACHE_HOME': str(directory / 'cache'),
           'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null'}
    head = command(['/usr/bin/git', '-C', str(HERE.parent.parent), 'rev-parse', 'HEAD']).decode().strip()
    require(re.fullmatch('[a-f0-9]{40}', head), 'ci-context')
    for name, specification in ASSETS.items():
        download(directory, name, specification)
    context = directory / 'context'
    context.mkdir()
    package = context / 'verified-codex-package'
    package.mkdir()
    evidence = {'schema': 1, 'repository': 'OMT-Global/bootstrap', 'runId': os.environ['GITHUB_RUN_ID'], 'head': head,
                'codexSourceCommit': SOURCE, 'package': extract(directory / 'package.tar.gz', package),
                'stageSourceSha256': sha(Path(__file__).read_bytes()),
                'artifacts': {name: specification[2] for name, specification in ASSETS.items()}}
    return package, evidence


def finish(directory, package, evidence, expected_candidates):
    candidates = {}
    for name, _ in binaries(directory, package):
        candidates[name] = read_bundle(directory / (name + '.standard.json'), name, 'standard-file')
        audit_bundle(read_bundle(directory / (name + '.sigstore'), name, 'legacy-file'), candidates[name],
                     ASSETS['package.tar.gz'][2] if name == 'package' else NATIVE['bin/codex' if name == 'native' else 'codex-resources/bwrap'], name)
        require(candidates[name] == expected_candidates[name], bundle_tag(name, 'candidate-bytes', 'mismatch'))
    verify_signatures(directory, package)
    for name, data in candidates.items():
        require(read_bundle(directory / (name + '.standard.json'), name, 'standard-file') == data,
                bundle_tag(name, 'verified-bytes', 'mismatch'))
    evidence['signatureVerified'] = True
    evidence['bundles'] = {name: {'bytes': len(data), 'sha256': sha(data)} for name, data in candidates.items()}
    notices = package.parent / 'public-notices'
    notices.mkdir(mode=0o755)
    for name in ('LICENSE', 'NOTICE', 'bubblewrap-COPYING', 'ripgrep-LICENSE-MIT', 'ripgrep-UNLICENSE'):
        shutil.copyfile(directory / name, notices / name)
        (notices / name).chmod(0o644)
    (package.parent / 'public-provenance.json').write_text(json.dumps(evidence, indent=2) + '\n')
    return {'package': package, 'context': package.parent, 'evidence': evidence, 'verifiedBundleBytes': candidates}


def stage(directory, absolute_deadline=None):
    """Stage only verified public artifacts; caller owns the fresh directory and cleanup."""
    require(set(BUNDLE_PINS) == {'package', 'native', 'bwrap'}, 'metadata-unpinned')
    with acquisition_clock(absolute_deadline):
        package, evidence = acquire(directory)
        pinned = {}
        for name, (expected_size, expected_hash) in BUNDLE_PINS.items():
            data = read_bundle(BUNDLE_DIRECTORY / (name + '.json'), name, 'pinned-file')
            require(len(data) == expected_size and sha(data) == expected_hash, bundle_tag(name, 'pinned-hash', 'mismatch'))
            (directory / (name + '.standard.json')).write_bytes(data)
            pinned[name] = data
        return finish(directory, package, evidence, pinned)


def prepare_metadata(directory):
    """Explicit public Rekor lookup; never called by stage() or its offline verifier."""
    with acquisition_clock():
        return prepare_with_clock(directory)


def prepare_with_clock(directory):
    package, evidence = acquire(directory)
    cosign = directory / 'cosign'
    cosign.chmod(0o700)
    raw_bundles, created = {}, {}
    for name, binary in binaries(directory, package):
        command([str(cosign), 'bundle', 'create', '--rekor-url', 'https://rekor.sigstore.dev', '--artifact', str(binary),
                 '--bundle', str(directory / (name + '.sigstore')), '--out', str(directory / (name + '.raw.json'))])
        raw = read_bundle(directory / (name + '.raw.json'), name, 'raw-file')
        legacy = read_bundle(directory / (name + '.sigstore'), name, 'legacy-file')
        expected = ASSETS['package.tar.gz'][2] if name == 'package' else NATIVE['bin/codex' if name == 'native' else 'codex-resources/bwrap']
        candidate = normalize_bundle(legacy, raw, expected, name)
        (directory / (name + '.standard.json')).write_bytes(candidate)
        created[name] = candidate
        raw_bundles[name] = {'bytes': len(raw), 'sha256': sha(raw), 'base64': base64.b64encode(raw).decode('ascii')}
    evidence['rawBundles'] = {name: {key: value for key, value in record.items() if key != 'base64'} for name, record in raw_bundles.items()}
    evidence['bundlePreparation'] = 'original-set-only'
    result = finish(directory, package, evidence, created)
    result['rawBundles'] = raw_bundles
    result['publicBundles'] = {name: {'bytes': pin['bytes'], 'sha256': pin['sha256'],
                                    'base64': base64.b64encode(result['verifiedBundleBytes'][name]).decode('ascii')}
                              for name, pin in evidence['bundles'].items()}
    return result


def emit_evidence(evidence, raw_payloads):
    successful = evidence.get('ok') and evidence.get('cleanup') and evidence.get('signatureVerified')
    if successful and evidence['preparation']:
        successful = set(raw_payloads) == {'package', 'native', 'bwrap'} and set(evidence.get('publicBundles', {})) == set(raw_payloads)
    if not successful:
        evidence['ok'] = False
        evidence.setdefault('reason', 'unverified')
        evidence.pop('publicBundles', None)
        evidence.pop('signatureVerified', None)
        raw_payloads = {}
    raw_lines = ['REVIEWER_ARTIFACT_RAW ' + json.dumps({'schema': 1, 'artifact': name, **raw_payloads[name]}, separators=(',', ':'))
                 for name in ('package', 'native', 'bwrap') if name in raw_payloads]
    summary = 'REVIEWER_ARTIFACT_EVIDENCE ' + json.dumps(evidence, separators=(',', ':'))
    if any(len(line.encode()) + 1 > 131072 for line in raw_lines) or sum(len(line.encode()) + 1 for line in [*raw_lines, summary]) > 262144:
        evidence = {'schema': 1, 'preparation': evidence['preparation'], 'ok': False,
                    'cleanup': evidence['cleanup'], 'reason': 'evidence-limit'}
        raw_lines = []
        summary = 'REVIEWER_ARTIFACT_EVIDENCE ' + json.dumps(evidence, separators=(',', ':'))
    for line in [*raw_lines, summary]:
        print(line, flush=True)
    return bool(evidence['ok'] and evidence['cleanup'])


def main(prepare):
    os.umask(0o077)
    evidence = {'schema': 1, 'preparation': prepare, 'ok': False, 'cleanup': False}
    raw_payloads = {}
    temporary = None
    try:
        require(sys.platform == 'linux', 'platform')
        temporary = Path(tempfile.mkdtemp(prefix='bootstrap-reviewer-artifacts-'))
        result = prepare_metadata(temporary) if prepare else stage(temporary)
        evidence.update(result['evidence'])
        if prepare:
            evidence['publicBundles'] = result['publicBundles']
            raw_payloads = result['rawBundles']
        evidence['ok'] = True
    except BaseException as error:
        evidence['reason'] = str(error) if isinstance(error, Unsupported) else 'unsupported'
    finally:
        started = time.monotonic()
        try:
            if temporary is not None:
                with acquisition_clock(started + 60):
                    shutil.rmtree(temporary)
                    require(not temporary.exists(), 'cleanup')
            require(time.monotonic() - started < 60, 'cleanup')
            evidence['cleanup'] = True
        except BaseException:
            evidence.update(ok=False, reason='cleanup')
    return 0 if emit_evidence(evidence, raw_payloads) else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prepare-metadata', action='store_true', help='explicit online public Rekor preparation; CI only')
    sys.exit(main(parser.parse_args().prepare_metadata))
