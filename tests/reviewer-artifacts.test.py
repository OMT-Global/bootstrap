"""Static regressions: public synthetic bytes only; no downloads or native execution."""
import base64
import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import ssl
import sys
import tarfile
import tempfile
import time
import unittest
from unittest import mock

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('artifacts', ROOT / 'scripts/ci/reviewer-artifacts.py')
artifacts = importlib.util.module_from_spec(spec)
spec.loader.exec_module(artifacts)


def b64(value):
    return base64.b64encode(value).decode('ascii')


def bundles():
    certificate = b'synthetic certificate representation; no cryptographic assertion'
    signature, body, log_id = b'synthetic signature', b'synthetic Rekor body', bytes(range(32))
    legacy = {'base64Signature': b64(signature), 'cert': b64(ssl.DER_cert_to_PEM_cert(certificate).encode()),
              'rekorBundle': {'SignedEntryTimestamp': b64(b'synthetic SET'), 'Payload': {
                  'body': b64(body), 'integratedTime': 1700000000, 'logIndex': 42, 'logID': log_id.hex()}}}
    entry = {'canonicalizedBody': b64(body), 'integratedTime': '1700000000', 'logIndex': '42',
             'kindVersion': {'kind': 'hashedrekord', 'version': '0.0.1'},
             'logId': {'keyId': b64(log_id)}, 'inclusionPromise': {'signedEntryTimestamp': b64(b'synthetic SET')},
             'inclusionProof': {'logIndex': '2', 'treeSize': '64', 'rootHash': b64(b'x' * 32),
                                'hashes': [b64(b'y' * 32)], 'checkpoint': {'envelope': 'synthetic checkpoint'}}}
    standard = {'mediaType': 'application/vnd.dev.sigstore.bundle+json;version=0.3',
                'verificationMaterial': {'certificate': {'rawBytes': b64(certificate)}, 'tlogEntries': [entry]},
                'messageSignature': {'messageDigest': {'algorithm': 'SHA2_256', 'digest': b64(b'z' * 32)},
                                     'signature': b64(signature)}}
    return legacy, standard


class ArtifactTests(unittest.TestCase):
    def setUp(self):
        artifacts.DEADLINE = time.monotonic() + 10
        artifacts.ENV = {'PATH': '/usr/bin:/bin'}

    def audit(self, old, new):
        artifacts.audit_bundle(json.dumps(old).encode(), json.dumps(new).encode(), (b'z' * 32).hex())

    def test_bundle_field_equality_and_proof_retention(self):
        old, new = bundles()
        original = copy.deepcopy(new)
        self.audit(old, new)
        self.assertEqual(new, original)
        paths = [('verificationMaterial', 'certificate', 'rawBytes'), ('messageSignature', 'signature'),
                 ('verificationMaterial', 'tlogEntries', 0, 'canonicalizedBody'),
                 ('verificationMaterial', 'tlogEntries', 0, 'logId', 'keyId'),
                 ('verificationMaterial', 'tlogEntries', 0, 'logIndex'),
                 ('verificationMaterial', 'tlogEntries', 0, 'integratedTime'),
                 ('verificationMaterial', 'tlogEntries', 0, 'inclusionPromise', 'signedEntryTimestamp'),
                 ('messageSignature', 'messageDigest', 'digest')]
        for path in paths:
            changed = copy.deepcopy(new)
            target = changed
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = '43' if path[-1] in ('logIndex', 'integratedTime') else b64(b'changed')
            with self.subTest(path=path), self.assertRaises(artifacts.Unsupported):
                self.audit(old, changed)
        for invalid in ({}, {'mediaType': 'unsupported'}, {**new, 'verificationMaterial': {'tlogEntries': []}}):
            with self.assertRaises(artifacts.Unsupported):
                self.audit(old, invalid)
        for key in ('inclusionPromise', 'inclusionProof'):
            changed = copy.deepcopy(new)
            del changed['verificationMaterial']['tlogEntries'][0][key]
            with self.assertRaises(artifacts.Unsupported):
                self.audit(old, changed)

    def test_default_never_prepares_or_downloads_without_pins(self):
        with mock.patch.object(artifacts, 'BUNDLE_PINS', {}), mock.patch.object(artifacts, 'acquire') as acquire:
            with self.assertRaisesRegex(artifacts.Unsupported, '^metadata-unpinned$'):
                artifacts.stage(Path('/unused'))
            acquire.assert_not_called()

    def test_absolute_acquisition_clock_interrupts_blocking_work_and_restores_state(self):
        previous = artifacts.DEADLINE
        started = time.monotonic()
        with self.assertRaisesRegex(artifacts.Unsupported, '^deadline$'):
            with artifacts.acquisition_clock(started + 0.03):
                time.sleep(10)
        self.assertLess(time.monotonic() - started, 1)
        self.assertEqual(artifacts.DEADLINE, previous)

    def test_archive_names_types_modes_collisions_and_bounds(self):
        for name in ('../escape', '/absolute', 'a/../b', 'a//b', 'a\\b', './a', 'a/' * 33 + 'b', 'x' * 4097):
            with self.subTest(name=name), self.assertRaises(artifacts.Unsupported):
                artifacts.archive_entries([tarfile.TarInfo(name)])
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE, tarfile.BLKTYPE, tarfile.FIFOTYPE):
            item = tarfile.TarInfo('unsafe')
            item.type = kind
            with self.assertRaises(artifacts.Unsupported):
                artifacts.archive_entries([item])
        for mode in (0o4755, 0o2755, 0o1755, 0o777):
            item = tarfile.TarInfo('unsafe')
            item.mode = mode
            with self.assertRaises(artifacts.Unsupported):
                artifacts.archive_entries([item])
        file, child = tarfile.TarInfo('parent'), tarfile.TarInfo('parent/child')
        for items in ([file, file], [file, child], [child, file], [tarfile.TarInfo(str(i)) for i in range(4097)]):
            with self.assertRaises(artifacts.Unsupported):
                artifacts.archive_entries(items)
        file.size = (2 << 30) + 1
        with self.assertRaises(artifacts.Unsupported):
            artifacts.archive_entries([file])
        file.size = 3
        self.assertEqual(artifacts.archive_entries([file])[1], 3)
        artifacts.DEADLINE = time.monotonic() - 1
        with self.assertRaisesRegex(artifacts.Unsupported, '^deadline$'):
            artifacts.archive_entries([file])

    def test_extraction_requires_fresh_directory_and_bundle_is_bounded_regular(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'occupied').write_text('synthetic')
            with self.assertRaisesRegex(artifacts.Unsupported, '^directory$'):
                artifacts.extract(root / 'unused.tar.gz', root)
            (root / 'linked').symlink_to(root / 'occupied')
            with self.assertRaises(artifacts.Unsupported):
                artifacts.read_bounded(root / 'linked')
            (root / 'large').write_bytes(b'x' * 65537)
            with self.assertRaises(artifacts.Unsupported):
                artifacts.read_bounded(root / 'large')
            self.assertEqual(artifacts.read_bounded(root / 'occupied'), b'synthetic')

    def test_commands_combine_output_bound_timeout_and_clean_process(self):
        for source in ('print("x" * 1024)', 'import sys;sys.stderr.write("x" * 1024)',
                       'import sys;sys.stdout.write("x" * 40);sys.stderr.write("x" * 40)'):
            with self.assertRaisesRegex(artifacts.Unsupported, '^output$'):
                artifacts.command([sys.executable, '-I', '-S', '-c', source], limit=64)
        with self.assertRaisesRegex(artifacts.Unsupported, '^deadline$'):
            artifacts.command([sys.executable, '-I', '-S', '-c', 'import time;time.sleep(10)'], timeout=0.05)
        with self.assertRaisesRegex(artifacts.Unsupported, '^process$'):
            artifacts.command([sys.executable, '-I', '-S', '-c', 'raise SystemExit(23)'])
        captured = io.StringIO()
        with contextlib.redirect_stdout(captured):
            result = artifacts.command([sys.executable, '-I', '-S', '-c',
                                        'import sys;print(123);sys.stderr.write("::error::synthetic\\nline")'], diagnostic='package')
        self.assertEqual(result, b'123\n')
        lines = captured.getvalue().splitlines()
        self.assertEqual(len(lines), 1)
        diagnostic = json.loads(lines[0].split(' ', 1)[1])
        self.assertEqual(diagnostic, {'artifact': 'package', 'exitCode': 0, 'stderr': '::error::synthetic\nline'})
        with self.assertRaisesRegex(artifacts.Unsupported, '^diagnostic$'):
            artifacts.command([sys.executable, '-I', '-S', '-c', 'pass'], diagnostic='native-status')

    def test_fixed_https_allowlist(self):
        self.assertTrue(artifacts.allowed_url(artifacts.RELEASE))
        for url in ('http://github.com/a', 'https://github.com.evil.invalid/a', 'https://fixture@github.com/a',
                    'https://:@github.com/a', 'https://github.com:444/a', 'https://rekor.sigstore.dev/a'):
            self.assertFalse(artifacts.allowed_url(url))


if __name__ == '__main__':
    unittest.main()
