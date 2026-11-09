"""Static regressions: public synthetic bytes only; no downloads or native execution."""
import base64
import contextlib
import copy
import importlib.util
import io
import json
import os
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


    def assert_bundle_diagnostic(self, old, new, expected):
        output, errors = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            with self.assertRaises(artifacts.Unsupported) as failure:
                self.audit(old, new)
        self.assertEqual(str(failure.exception), expected)
        captured = str(failure.exception) + output.getvalue() + errors.getvalue()
        marker = 'synthetic-private-looking-value-never-to-log'
        self.assertNotIn(marker, captured)
        self.assertNotIn(b64(marker.encode()), captured)

    def test_diagnostic_signature_shape_vs_mismatch(self):
        old, new = bundles()
        for value, failure in (('%synthetic-private-looking-value-never-to-log', 'shape'),
                               (b64(b'synthetic-private-looking-value-never-to-log'), 'mismatch')):
            changed = copy.deepcopy(new)
            changed['messageSignature']['signature'] = value
            with self.subTest(failure=failure):
                self.assert_bundle_diagnostic(old, changed, 'bundle/package/signature/' + failure)

    def test_diagnostic_integer_shape_vs_mismatch_and_proof_field(self):
        old, new = bundles()
        for value, failure in (('synthetic-private-looking-value-never-to-log', 'shape'), ('43', 'mismatch')):
            changed = copy.deepcopy(new)
            changed['verificationMaterial']['tlogEntries'][0]['logIndex'] = value
            with self.subTest(failure=failure):
                self.assert_bundle_diagnostic(old, changed, 'bundle/package/rekor-log-index/' + failure)
        changed = copy.deepcopy(new)
        del changed['verificationMaterial']['tlogEntries'][0]['inclusionProof']['checkpoint']
        self.assert_bundle_diagnostic(old, changed, 'bundle/package/proof-checkpoint/shape')

    def test_diagnostic_duplicate_json_never_echoes_the_key(self):
        old, _ = bundles()
        marker = 'synthetic-private-looking-value-never-to-log'
        duplicate = ('{"' + marker + '":0,"' + marker + '":1}').encode()
        output, errors = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            with self.assertRaises(artifacts.Unsupported) as failure:
                artifacts.audit_bundle(json.dumps(old).encode(), duplicate, (b'z' * 32).hex())
        self.assertEqual(str(failure.exception), 'bundle/package/standard-json/shape')
        self.assertNotIn(marker, str(failure.exception) + output.getvalue() + errors.getvalue())
        self.assertNotIn(b64(marker.encode()), str(failure.exception) + output.getvalue() + errors.getvalue())

    def test_diagnostic_failure_cannot_verify_or_emit_derived_bundles(self):
        old, new = bundles()
        new['messageSignature']['signature'] = b64(b'synthetic-private-looking-value-never-to-log')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package, evidence = root / 'context/verified-codex-package', {}
            package.mkdir(parents=True)
            for name in ('package', 'native', 'bwrap'):
                (root / (name + '.sigstore')).write_text(json.dumps(old))
                (root / (name + '.raw.json')).write_text(json.dumps(new))
            (root / 'cosign').write_bytes(b'synthetic; never executed')
            output, errors = io.StringIO(), io.StringIO()
            with mock.patch.object(artifacts, 'acquire', return_value=(package, evidence)), \
                    mock.patch.object(artifacts, 'command') as command, \
                    mock.patch.object(artifacts, 'verify_signatures') as verify, \
                    contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                with self.assertRaises(artifacts.Unsupported) as failure:
                    artifacts.prepare_metadata(root)
                self.assertEqual(str(failure.exception), 'bundle/package/signature/mismatch')
                verify.assert_not_called()
                self.assertEqual(command.call_count, 1)
            self.assertNotIn('signatureVerified', evidence)
            self.assertNotIn('publicBundles', evidence)
            self.assertEqual(output.getvalue() + errors.getvalue(), '')

    def test_diagnostic_does_not_relabel_deadline(self):
        old, new = bundles()
        with mock.patch.object(artifacts.ssl, 'PEM_cert_to_DER_cert', side_effect=artifacts.Unsupported('deadline')):
            with self.assertRaisesRegex(artifacts.Unsupported, '^deadline$'):
                self.audit(old, new)

    def test_renewed_set_is_strictly_rejected_before_normalization_and_audited_after(self):
        old, raw = bundles()
        raw['verificationMaterial']['tlogEntries'][0]['inclusionPromise']['signedEntryTimestamp'] = b64(b'renewed synthetic SET')
        legacy_data, raw_data = json.dumps(old).encode(), json.dumps(raw).encode()
        digest = (b'z' * 32).hex()
        with self.assertRaises(artifacts.Unsupported):
            artifacts.audit_bundle(legacy_data, raw_data, digest)
        with mock.patch.object(artifacts, 'immutable_bundle_fields', wraps=artifacts.immutable_bundle_fields) as parser, \
                mock.patch.object(artifacts, 'audit_bundle', wraps=artifacts.audit_bundle) as strict_audit:
            candidate = artifacts.normalize_bundle(legacy_data, raw_data, digest)
            strict_audit.assert_called_once()
            self.assertEqual(strict_audit.call_args.args[:3], (legacy_data, candidate, digest))
            self.assertGreaterEqual(parser.call_count, 2)
        artifacts.audit_bundle(legacy_data, candidate, digest)
        with self.assertRaises(TypeError):
            artifacts.audit_bundle(legacy_data, raw_data, digest, allow_different_set=True)

    def test_normalization_changes_one_leaf_and_preserves_full_tree_types_and_order(self):
        old, raw = bundles()
        raw['supplemental'] = {'z': [True, 1, 1.25, None, 'unicode \u03bb', {'b': 2, 'a': False}], 'a': []}
        material = raw['verificationMaterial']
        material['supplemental'] = {'second': 'retained', 'first': 7}
        entry = material['tlogEntries'][0]
        entry['supplemental'] = [{'y': None, 'x': [3, False]}]
        entry['inclusionProof']['checkpoint']['supplemental'] = {'k': ['retained']}
        entry['inclusionPromise']['supplemental'] = ['promise member retained']
        entry['inclusionPromise']['signedEntryTimestamp'] = b64(b'renewed synthetic SET')
        expected = copy.deepcopy(raw)
        expected['verificationMaterial']['tlogEntries'][0]['inclusionPromise']['signedEntryTimestamp'] = old['rekorBundle']['SignedEntryTimestamp']
        raw_data = ('  ' + json.dumps(raw, ensure_ascii=False) + '\n').encode()
        preserved_raw = bytes(raw_data)
        candidate = artifacts.normalize_bundle(json.dumps(old).encode(), raw_data, (b'z' * 32).hex())
        def same_tree(left, right):
            self.assertIs(type(left), type(right))
            if isinstance(left, dict):
                self.assertEqual(list(left), list(right))
                for key in left:
                    same_tree(left[key], right[key])
            elif isinstance(left, list):
                self.assertEqual(len(left), len(right))
                for first, second in zip(left, right):
                    same_tree(first, second)
            else:
                self.assertEqual(left, right)
        same_tree(json.loads(candidate), expected)
        self.assertEqual(raw_data, preserved_raw)
        self.assertEqual(entry['inclusionPromise']['signedEntryTimestamp'], b64(b'renewed synthetic SET'))
        self.assertTrue(candidate.endswith(b'\n'))
        self.assertIn(b'\n  "', candidate)
        unchanged_old, unchanged = bundles()
        roundtrip = artifacts.normalize_bundle(json.dumps(unchanged_old).encode(), json.dumps(unchanged).encode(), (b'z' * 32).hex())
        same_tree(json.loads(roundtrip), unchanged)

    def test_normalization_rejects_every_immutable_tamper_before_candidate_writes(self):
        old, raw = bundles()
        paths = [
            (('verificationMaterial', 'certificate', 'rawBytes'), b64(b'changed DER')),
            (('messageSignature', 'signature'), b64(b'changed signature')),
            (('messageSignature', 'messageDigest', 'algorithm'), 'SHA2_512'),
            (('messageSignature', 'messageDigest', 'digest'), b64(b'changed digest')),
            (('verificationMaterial', 'tlogEntries', 0, 'canonicalizedBody'), b64(b'changed body')),
            (('verificationMaterial', 'tlogEntries', 0, 'logId', 'keyId'), b64(b'changed log ID')),
            (('verificationMaterial', 'tlogEntries', 0, 'logIndex'), '43'),
            (('verificationMaterial', 'tlogEntries', 0, 'integratedTime'), '1700000001'),
            (('verificationMaterial', 'tlogEntries', 0, 'kindVersion', 'version'), '0.0.2')]
        with mock.patch.object(Path, 'write_bytes') as writes, mock.patch.object(Path, 'write_text') as text_writes:
            for path, value in paths:
                changed = copy.deepcopy(raw)
                target = changed
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = value
                with self.subTest(field=path), self.assertRaises(artifacts.Unsupported):
                    artifacts.normalize_bundle(json.dumps(old).encode(), json.dumps(changed).encode(), (b'z' * 32).hex())
            writes.assert_not_called()
            text_writes.assert_not_called()

    def test_normalization_requires_existing_nonempty_valid_original_and_raw_sets(self):
        for source in ('original', 'raw'):
            for value in (None, '', '%invalid', 7, False):
                old, raw = bundles()
                target = old['rekorBundle'] if source == 'original' else raw['verificationMaterial']['tlogEntries'][0]['inclusionPromise']
                target['SignedEntryTimestamp' if source == 'original' else 'signedEntryTimestamp'] = value
                with self.subTest(source=source, value_type=type(value).__name__), self.assertRaises(artifacts.Unsupported):
                    artifacts.normalize_bundle(json.dumps(old).encode(), json.dumps(raw).encode(), (b'z' * 32).hex())
        for missing in ('original-set', 'raw-set', 'promise', 'proof', 'checkpoint', 'sole-entry'):
            old, raw = bundles()
            entry = raw['verificationMaterial']['tlogEntries'][0]
            if missing == 'original-set':
                del old['rekorBundle']['SignedEntryTimestamp']
            elif missing == 'raw-set':
                del entry['inclusionPromise']['signedEntryTimestamp']
            elif missing == 'promise':
                del entry['inclusionPromise']
            elif missing == 'proof':
                del entry['inclusionProof']
            elif missing == 'checkpoint':
                del entry['inclusionProof']['checkpoint']
            else:
                raw['verificationMaterial']['tlogEntries'].append(copy.deepcopy(entry))
            with self.subTest(missing=missing), self.assertRaises(artifacts.Unsupported):
                artifacts.normalize_bundle(json.dumps(old).encode(), json.dumps(raw).encode(), (b'z' * 32).hex())

    def test_normalization_rejects_duplicate_keys_in_original_and_supplemental_json(self):
        old, raw = bundles()
        old_data, raw_data = json.dumps(old).encode(), json.dumps(raw).encode()
        duplicate_original = old_data[:-1] + b',"cert":' + json.dumps(old['cert']).encode() + b'}'
        duplicate_raw = raw_data[:-1] + b',"unknown":0,"unknown":1}'
        for legacy, converted in ((duplicate_original, raw_data), (old_data, duplicate_raw)):
            with self.assertRaises(artifacts.Unsupported):
                artifacts.normalize_bundle(legacy, converted, (b'z' * 32).hex())
        raw['unknown'] = float('nan')
        with self.assertRaises(artifacts.Unsupported):
            artifacts.normalize_bundle(old_data, json.dumps(raw).encode(), (b'z' * 32).hex())

    def emission_fixture(self, size=3):
        names = ('package', 'native', 'bwrap')
        payload = b'x' * size
        record = {'bytes': len(payload), 'sha256': artifacts.sha(payload), 'base64': b64(payload)}
        raw = {name: dict(record) for name in names}
        evidence = {'schema': 1, 'preparation': True, 'ok': True, 'cleanup': True,
                    'signatureVerified': True, 'publicBundles': copy.deepcopy(raw)}
        return evidence, raw

    def test_raw_and_candidate_payloads_emit_only_after_all_success_flags(self):
        evidence, raw = self.emission_fixture()
        captured = io.StringIO()
        with contextlib.redirect_stdout(captured):
            self.assertTrue(artifacts.emit_evidence(evidence, raw))
        lines = captured.getvalue().splitlines()
        self.assertEqual(len(lines), 4)
        for line, name in zip(lines[:3], ('package', 'native', 'bwrap')):
            self.assertTrue(line.startswith('REVIEWER_ARTIFACT_RAW '))
            record = json.loads(line.split(' ', 1)[1])
            self.assertEqual(record['artifact'], name)
            self.assertEqual(base64.b64decode(record['base64']), b'x' * record['bytes'])
            self.assertEqual(record['sha256'], raw[name]['sha256'])
            self.assertLessEqual(len((line + '\n').encode()), 131072)
        summary = json.loads(lines[-1].split(' ', 1)[1])
        self.assertTrue(lines[-1].startswith('REVIEWER_ARTIFACT_EVIDENCE '))
        self.assertEqual(summary['publicBundles'], evidence['publicBundles'])
        self.assertLessEqual(len(captured.getvalue().encode()), 262144)
        for flag in ('ok', 'cleanup', 'signatureVerified'):
            evidence, raw = self.emission_fixture()
            evidence[flag] = False
            captured = io.StringIO()
            with contextlib.redirect_stdout(captured):
                self.assertFalse(artifacts.emit_evidence(evidence, raw))
            lines = captured.getvalue().splitlines()
            self.assertEqual(len(lines), 1)
            self.assertNotIn('REVIEWER_ARTIFACT_RAW ', lines[0])
            summary = json.loads(lines[0].split(' ', 1)[1])
            self.assertNotIn('publicBundles', summary)
            self.assertFalse(summary.get('signatureVerified', False))

    def test_emission_checks_aggregate_and_each_raw_record_before_any_payload(self):
        for limit in ('aggregate', 'raw-record'):
            evidence, raw = self.emission_fixture(65536 if limit == 'aggregate' else 3)
            if limit == 'raw-record':
                payload = b'x' * 98304
                raw['package'] = {'bytes': len(payload), 'sha256': artifacts.sha(payload), 'base64': b64(payload)}
            captured = io.StringIO()
            with contextlib.redirect_stdout(captured):
                self.assertFalse(artifacts.emit_evidence(evidence, raw))
            lines = captured.getvalue().splitlines()
            self.assertEqual(len(lines), 1)
            self.assertTrue(lines[0].startswith('REVIEWER_ARTIFACT_EVIDENCE '))
            summary = json.loads(lines[0].split(' ', 1)[1])
            self.assertFalse(summary['ok'])
            self.assertEqual(summary['reason'], 'evidence-limit')
            self.assertNotIn('publicBundles', summary)
            self.assertNotIn('base64', lines[0])

    def preparation_fixture(self, fail_verification=None, tamper=False, fail_cleanup=False, prepare=True,
                            mutate_after_verify=False, mutate_before_finish=False, mutate_payload_read=False):
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent) / 'owned'
            root.mkdir(mode=0o700)
            package, evidence = root / 'context/verified-codex-package', {'schema': 1}
            package.mkdir(parents=True)
            raw_by_name, original_by_name, pins = {}, {}, {}
            pin_directory = Path(parent) / 'pins'
            pin_directory.mkdir()
            for name in ('package', 'native', 'bwrap'):
                old, raw = bundles()
                raw['verificationMaterial']['tlogEntries'][0]['inclusionPromise']['signedEntryTimestamp'] = b64(b'renewed synthetic SET')
                raw['supplemental'] = {'list': [True, 1, None], 'retained': 'public synthetic data'}
                expected = artifacts.ASSETS['package.tar.gz'][2] if name == 'package' else artifacts.NATIVE['bin/codex' if name == 'native' else 'codex-resources/bwrap']
                raw['messageSignature']['messageDigest']['digest'] = b64(bytes.fromhex(expected))
                if tamper and name == 'package':
                    raw['messageSignature']['signature'] = b64(b'changed synthetic immutable signature')
                raw_by_name[name] = (' \n' + json.dumps(raw) + '\n').encode()
                original_by_name[name] = old
                (root / (name + '.sigstore')).write_text(json.dumps(old))
                pinned_tree = copy.deepcopy(raw)
                pinned_tree['verificationMaterial']['tlogEntries'][0]['inclusionPromise']['signedEntryTimestamp'] = old['rekorBundle']['SignedEntryTimestamp']
                pinned_data = (json.dumps(pinned_tree, indent=2) + '\n').encode()
                (pin_directory / (name + '.json')).write_bytes(pinned_data)
                pins[name] = (len(pinned_data), artifacts.sha(pinned_data))
            (root / 'cosign').write_bytes(b'public synthetic fixture; never executed')
            for name in ('LICENSE', 'NOTICE', 'bubblewrap-COPYING', 'ripgrep-LICENSE-MIT', 'ripgrep-UNLICENSE'):
                (root / name).write_text('public synthetic notice')
            verifies, candidates, writes = [], {}, []
            original_write = Path.write_bytes
            def write(path, data):
                if path.name.endswith('.standard.json'):
                    writes.append(path.name)
                return original_write(path, data)
            def command(arguments, **kwargs):
                if arguments[1:3] == ['bundle', 'create']:
                    self.assertEqual(arguments[3:5], ['--rekor-url', 'https://rekor.sigstore.dev'])
                    output = Path(arguments[arguments.index('--out') + 1])
                    name = output.name.split('.', 1)[0]
                    output.write_bytes(raw_by_name[name])
                else:
                    name = kwargs['diagnostic']
                    binary = root / 'package.tar.gz' if name == 'package' else package / ('bin/codex' if name == 'native' else 'codex-resources/bwrap')
                    expected = [str(root / 'cosign'), 'verify-blob', '--offline', '--trusted-root', str(root / 'trusted-root.json'),
                                '--certificate-identity', 'https://github.com/openai/codex/.github/workflows/rust-release.yml@refs/tags/rust-v0.167.0',
                                '--certificate-oidc-issuer', 'https://token.actions.githubusercontent.com',
                                '--bundle', str(root / (name + '.standard.json')), str(binary)]
                    self.assertEqual(arguments, expected)
                    verifies.append(name)
                    candidates[name] = (root / (name + '.standard.json')).read_bytes()
                    if mutate_after_verify and name == 'bwrap':
                        path = root / 'package.standard.json'
                        path.write_bytes(changed_bytes(path.read_bytes()))
                    if name == fail_verification:
                        raise artifacts.Unsupported('process')
                return b''
            def changed_bytes(data):
                changed = data.replace(b'\n', b' ', 1)
                self.assertNotEqual(changed, data)
                self.assertEqual(len(changed), len(data))
                self.assertEqual(json.loads(changed), json.loads(data))
                return changed
            original_finish, original_read = artifacts.finish, artifacts.read_bundle
            def finish(*arguments):
                if mutate_before_finish:
                    path = root / 'bwrap.standard.json'
                    path.write_bytes(changed_bytes(path.read_bytes()))
                return original_finish(*arguments)
            reads = {}
            def read(path, *arguments):
                data = original_read(path, *arguments)
                if path.name.endswith('.standard.json'):
                    reads[path.name] = reads.get(path.name, 0) + 1
                    if mutate_payload_read and reads[path.name] >= 3:
                        return changed_bytes(data)
                return data
            case = self
            class AfterCleanup(io.StringIO):
                def write(self, value):
                    if value.startswith('REVIEWER_ARTIFACT_RAW '):
                        case.assertFalse(root.exists(), 'raw payload emitted before cleanup')
                    return super().write(value)
            output, errors = AfterCleanup(), io.StringIO()
            previous_mask = os.umask(0o077)
            try:
                with mock.patch.object(artifacts, 'acquire', return_value=(package, evidence)), \
                        mock.patch.object(artifacts, 'command', side_effect=command), \
                        mock.patch.object(artifacts, 'finish', side_effect=finish), \
                        mock.patch.object(artifacts, 'read_bundle', side_effect=read), \
                        mock.patch.object(artifacts, 'BUNDLE_PINS', pins), \
                        mock.patch.object(artifacts, 'BUNDLE_DIRECTORY', pin_directory), \
                        mock.patch.object(artifacts.tempfile, 'mkdtemp', return_value=str(root)), \
                        mock.patch.object(artifacts.sys, 'platform', 'linux'), \
                        mock.patch.object(Path, 'write_bytes', autospec=True, side_effect=write), \
                        contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                    if fail_cleanup:
                        with mock.patch.object(artifacts.shutil, 'rmtree', side_effect=artifacts.Unsupported('cleanup')):
                            status = artifacts.main(prepare)
                    else:
                        status = artifacts.main(prepare)
            finally:
                os.umask(previous_mask)
            return status, output.getvalue().splitlines(), errors.getvalue(), verifies, candidates, raw_by_name, original_by_name, writes, not root.exists()

    def test_renewed_set_preparation_reaches_the_exact_offline_verifiers(self):
        status, lines, errors, verifies, candidates, raw, originals, writes, removed = self.preparation_fixture()
        self.assertEqual(status, 0)
        self.assertEqual(errors, '')
        self.assertEqual(verifies, ['package', 'native', 'bwrap'])
        self.assertEqual(writes, [name + '.standard.json' for name in verifies])
        self.assertTrue(removed)
        self.assertEqual(len(lines), 4)
        summary = json.loads(lines[-1].split(' ', 1)[1])
        self.assertTrue(summary['ok'] and summary['cleanup'] and summary['signatureVerified'])
        self.assertEqual(summary['bundlePreparation'], 'original-set-only')
        for line, name in zip(lines[:3], verifies):
            self.assertTrue(line.startswith('REVIEWER_ARTIFACT_RAW '))
            record = json.loads(line.split(' ', 1)[1])
            self.assertEqual(record['artifact'], name)
            self.assertEqual(base64.b64decode(record['base64']), raw[name])
            self.assertEqual(record['bytes'], len(raw[name]))
            self.assertEqual(record['sha256'], artifacts.sha(raw[name]))
            expected_tree = json.loads(raw[name])
            expected_tree['verificationMaterial']['tlogEntries'][0]['inclusionPromise']['signedEntryTimestamp'] = originals[name]['rekorBundle']['SignedEntryTimestamp']
            self.assertEqual(json.loads(candidates[name]), expected_tree)
            public = summary['publicBundles'][name]
            self.assertEqual(base64.b64decode(public['base64']), candidates[name])
            self.assertEqual(public['sha256'], artifacts.sha(candidates[name]))
            self.assertEqual(public['bytes'], len(candidates[name]))
            self.assertEqual(summary['rawBundles'][name], {'bytes': len(raw[name]), 'sha256': artifacts.sha(raw[name])})

    def test_each_offline_verification_failure_cleans_and_suppresses_payloads(self):
        for index, name in enumerate(('package', 'native', 'bwrap')):
            with self.subTest(artifact=name):
                status, lines, _, verifies, _, _, _, _, removed = self.preparation_fixture(fail_verification=name)
                self.assertEqual(status, 1)
                self.assertEqual(verifies, ['package', 'native', 'bwrap'][:index + 1])
                self.assertTrue(removed)
                self.assertEqual(len(lines), 1)
                summary = json.loads(lines[0].split(' ', 1)[1])
                self.assertEqual(summary['reason'], 'process')
                self.assertTrue(summary['cleanup'])
                self.assertNotIn('publicBundles', summary)
                self.assertNotIn('signatureVerified', summary)
                self.assertNotIn('base64', lines[0])

    def test_preparation_rejects_immutable_tamper_before_candidate_write(self):
        status, lines, _, verifies, _, _, _, writes, removed = self.preparation_fixture(tamper=True)
        self.assertEqual(status, 1)
        self.assertEqual(verifies, [])
        self.assertEqual(writes, [])
        self.assertTrue(removed)
        summary = json.loads(lines[0].split(' ', 1)[1])
        self.assertEqual(summary['reason'], 'bundle/package/signature/mismatch')
        self.assertNotIn('publicBundles', summary)

    def test_preparation_cleanup_failure_suppresses_raw_and_candidate_payloads(self):
        status, lines, _, verifies, _, _, _, _, removed = self.preparation_fixture(fail_cleanup=True)
        self.assertEqual(status, 1)
        self.assertEqual(verifies, ['package', 'native', 'bwrap'])
        self.assertFalse(removed)
        self.assertEqual(len(lines), 1)
        summary = json.loads(lines[0].split(' ', 1)[1])
        self.assertEqual(summary['reason'], 'cleanup')
        self.assertFalse(summary['cleanup'])
        self.assertNotIn('publicBundles', summary)
        self.assertNotIn('signatureVerified', summary)
        self.assertNotIn('base64', lines[0])

    def test_candidate_change_during_third_verification_fails_stage_and_preparation(self):
        for prepare in (False, True):
            with self.subTest(preparation=prepare):
                status, lines, _, verifies, _, _, _, _, removed = self.preparation_fixture(prepare=prepare, mutate_after_verify=True)
                self.assertEqual(status, 1)
                self.assertEqual(verifies, ['package', 'native', 'bwrap'])
                self.assertTrue(removed)
                self.assertEqual(len(lines), 1)
                summary = json.loads(lines[0].split(' ', 1)[1])
                self.assertEqual(summary['reason'], 'bundle/package/verified-bytes/mismatch')
                self.assertTrue(summary['cleanup'])
                self.assertNotIn('publicBundles', summary)
                self.assertNotIn('signatureVerified', summary)
                self.assertNotIn('base64', lines[0])

    def test_audited_candidates_equal_created_pins_or_normalized_bytes(self):
        for prepare in (False, True):
            with self.subTest(preparation=prepare):
                status, lines, _, verifies, _, _, _, _, removed = self.preparation_fixture(prepare=prepare, mutate_before_finish=True)
                self.assertEqual(status, 1)
                self.assertEqual(verifies, [])
                self.assertTrue(removed)
                summary = json.loads(lines[0].split(' ', 1)[1])
                self.assertEqual(summary['reason'], 'bundle/bwrap/candidate-bytes/mismatch')
                self.assertNotIn('publicBundles', summary)
                self.assertNotIn('signatureVerified', summary)

    def test_preparation_emits_retained_verified_bytes_without_a_late_read(self):
        status, lines, _, verifies, candidates, _, _, _, removed = self.preparation_fixture(mutate_payload_read=True)
        self.assertEqual(status, 0)
        self.assertEqual(verifies, ['package', 'native', 'bwrap'])
        self.assertTrue(removed)
        summary = json.loads(lines[-1].split(' ', 1)[1])
        for name in verifies:
            payload = summary['publicBundles'][name]
            self.assertEqual(base64.b64decode(payload['base64']), candidates[name])
            self.assertEqual(payload['sha256'], artifacts.sha(candidates[name]))
            self.assertEqual(payload['bytes'], len(candidates[name]))
    def test_default_stage_forwards_exact_public_pins_to_mandatory_finish_without_preparation(self):
        pins = {
            'package': (10474, '2b02dffae24ea92c8dda61a466d2e182958272cd60272d4d5d4105ca6a5038f0'),
            'native': (10494, '1c92b7154e5bbd76ec2b6b5fd4e7aeb5dedfdc862b619df22649a1443d37d67b'),
            'bwrap': (10494, 'fbd20983759d802697db32d9c8fc2eb5f31edc3afad89ddbb95296b023f9f315')}
        self.assertEqual(artifacts.BUNDLE_PINS, pins)
        payloads = {name: (artifacts.BUNDLE_DIRECTORY / (name + '.json')).read_bytes() for name in pins}
        self.assertEqual({name: (len(data), artifacts.sha(data)) for name, data in payloads.items()}, pins)
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            package, evidence = directory / 'context/verified-codex-package', {'schema': 1}
            expected_result = {'fixture': 'mandatory finish result'}
            def mandatory_finish(staged_directory, staged_package, staged_evidence, expected_candidates):
                self.assertEqual(staged_directory, directory)
                self.assertEqual(staged_package, package)
                self.assertIs(staged_evidence, evidence)
                self.assertEqual(expected_candidates, payloads)
                self.assertEqual({name: (directory / (name + '.standard.json')).read_bytes() for name in pins}, payloads)
                return expected_result
            with mock.patch.object(artifacts, 'acquire', return_value=(package, evidence)), \
                    mock.patch.object(artifacts, 'finish', side_effect=mandatory_finish) as finish, \
                    mock.patch.object(artifacts, 'prepare_metadata') as prepare, \
                    mock.patch.object(artifacts, 'prepare_with_clock') as prepare_with_clock, \
                    mock.patch.object(artifacts, 'normalize_bundle') as normalize, \
                    mock.patch.object(artifacts, 'command') as command, \
                    mock.patch.object(artifacts, 'download') as download, \
                    mock.patch.object(artifacts, 'verify_signatures') as verify:
                self.assertIs(artifacts.stage(directory), expected_result)
                finish.assert_called_once()
                for forbidden in (prepare, prepare_with_clock, normalize, command, download, verify):
                    forbidden.assert_not_called()

    def test_default_stage_rejects_missing_modified_and_truncated_pins_without_fallback(self):
        payloads = {name: (artifacts.BUNDLE_DIRECTORY / (name + '.json')).read_bytes()
                    for name in ('package', 'native', 'bwrap')}
        pins = {name: (len(data), artifacts.sha(data)) for name, data in payloads.items()}
        for artifact in pins:
            for failure in ('missing', 'same-size-modified', 'truncated'):
                with self.subTest(artifact=artifact, failure=failure), tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    pinned_directory, directory = root / 'pins', root / 'stage'
                    pinned_directory.mkdir()
                    directory.mkdir()
                    for name, data in payloads.items():
                        (pinned_directory / (name + '.json')).write_bytes(data)
                    target = pinned_directory / (artifact + '.json')
                    if failure == 'missing':
                        target.unlink()
                    elif failure == 'same-size-modified':
                        original = payloads[artifact]
                        target.write_bytes(bytes([original[0] ^ 1]) + original[1:])
                        self.assertEqual(target.stat().st_size, len(original))
                    else:
                        target.write_bytes(payloads[artifact][:-1])
                    package, evidence = directory / 'context/verified-codex-package', {'schema': 1}
                    output, errors = io.StringIO(), io.StringIO()
                    with mock.patch.object(artifacts, 'BUNDLE_DIRECTORY', pinned_directory), \
                            mock.patch.object(artifacts, 'BUNDLE_PINS', pins), \
                            mock.patch.object(artifacts, 'acquire', return_value=(package, evidence)), \
                            mock.patch.object(artifacts, 'finish') as finish, \
                            mock.patch.object(artifacts, 'verify_signatures') as verify, \
                            mock.patch.object(artifacts, 'prepare_metadata') as prepare, \
                            mock.patch.object(artifacts, 'prepare_with_clock') as prepare_with_clock, \
                            mock.patch.object(artifacts, 'normalize_bundle') as normalize, \
                            mock.patch.object(artifacts, 'command') as command, \
                            mock.patch.object(artifacts, 'download') as download, \
                            contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                        with self.assertRaises(artifacts.Unsupported) as rejected:
                            artifacts.stage(directory)
                        suffix = 'pinned-file/shape' if failure == 'missing' else 'pinned-hash/mismatch'
                        self.assertEqual(str(rejected.exception), 'bundle/' + artifact + '/' + suffix)
                        for forbidden in (finish, verify, prepare, prepare_with_clock, normalize, command, download):
                            forbidden.assert_not_called()
                    self.assertEqual(output.getvalue() + errors.getvalue(), '')
                    self.assertNotIn('signatureVerified', evidence)
                    self.assertNotIn('publicBundles', evidence)
if __name__ == '__main__':
    unittest.main()
