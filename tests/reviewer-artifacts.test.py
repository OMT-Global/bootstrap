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
import urllib.error
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


DIAGNOSTIC_PREFIX = 'REVIEWER_ARTIFACT_DIAGNOSTIC '
EXPECTED_DIAGNOSTIC_STAGES = ('workspace', 'clock', 'context', 'command', 'download-setup', 'download-open',
                              'download-read', 'download-write', 'download-hash', 'layout', 'extract',
                              'candidate-read', 'candidate-write', 'bundle-audit', 'cosign', 'finalize',
                              'cleanup', 'evidence')


def failure_records(case, lines):
    case.assertEqual(len(lines), 2, 'failure must retain its summary and add one bounded diagnostic')
    case.assertTrue(lines[0].startswith(DIAGNOSTIC_PREFIX))
    diagnostic = json.loads(lines[0][len(DIAGNOSTIC_PREFIX):])
    case.assertEqual(list(diagnostic), ['schema', 'stage', 'assetIndex', 'lastHttpState', 'lastHttpStatus'])
    case.assertIs(type(diagnostic['schema']), int)
    case.assertEqual(diagnostic['schema'], 1)
    case.assertIn(diagnostic['stage'], EXPECTED_DIAGNOSTIC_STAGES)
    case.assertIs(type(diagnostic['assetIndex']), int)
    case.assertIn(diagnostic['assetIndex'], range(-1, 11))
    case.assertIn(diagnostic['lastHttpState'], ('not-observed', 'response', 'http-error'))
    case.assertIs(type(diagnostic['lastHttpStatus']), int)
    case.assertTrue(diagnostic['lastHttpStatus'] == 0 or 100 <= diagnostic['lastHttpStatus'] <= 599)
    case.assertEqual(lines[0], DIAGNOSTIC_PREFIX + json.dumps(diagnostic, separators=(',', ':')))
    case.assertLessEqual(len((lines[0] + '\n').encode()), 192)
    case.assertTrue(lines[1].startswith('REVIEWER_ARTIFACT_EVIDENCE '))
    return diagnostic, json.loads(lines[1].split(' ', 1)[1])


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
            _, summary = failure_records(self, lines)
            self.assertNotIn('REVIEWER_ARTIFACT_RAW ', '\n'.join(lines))
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
            _, summary = failure_records(self, lines)
            self.assertFalse(summary['ok'])
            self.assertEqual(summary['reason'], 'evidence-limit')
            self.assertNotIn('publicBundles', summary)
            self.assertNotIn('base64', '\n'.join(lines))

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
                _, summary = failure_records(self, lines)
                self.assertEqual(summary['reason'], 'process')
                self.assertTrue(summary['cleanup'])
                self.assertNotIn('publicBundles', summary)
                self.assertNotIn('signatureVerified', summary)
                self.assertNotIn('base64', '\n'.join(lines))

    def test_preparation_rejects_immutable_tamper_before_candidate_write(self):
        status, lines, _, verifies, _, _, _, writes, removed = self.preparation_fixture(tamper=True)
        self.assertEqual(status, 1)
        self.assertEqual(verifies, [])
        self.assertEqual(writes, [])
        self.assertTrue(removed)
        _, summary = failure_records(self, lines)
        self.assertEqual(summary['reason'], 'bundle/package/signature/mismatch')
        self.assertNotIn('publicBundles', summary)

    def test_preparation_cleanup_failure_suppresses_raw_and_candidate_payloads(self):
        status, lines, _, verifies, _, _, _, _, removed = self.preparation_fixture(fail_cleanup=True)
        self.assertEqual(status, 1)
        self.assertEqual(verifies, ['package', 'native', 'bwrap'])
        self.assertFalse(removed)
        _, summary = failure_records(self, lines)
        self.assertEqual(summary['reason'], 'cleanup')
        self.assertFalse(summary['cleanup'])
        self.assertNotIn('publicBundles', summary)
        self.assertNotIn('signatureVerified', summary)
        self.assertNotIn('base64', '\n'.join(lines))

    def test_candidate_change_during_third_verification_fails_stage_and_preparation(self):
        for prepare in (False, True):
            with self.subTest(preparation=prepare):
                status, lines, _, verifies, _, _, _, _, removed = self.preparation_fixture(prepare=prepare, mutate_after_verify=True)
                self.assertEqual(status, 1)
                self.assertEqual(verifies, ['package', 'native', 'bwrap'])
                self.assertTrue(removed)
                _, summary = failure_records(self, lines)
                self.assertEqual(summary['reason'], 'bundle/package/verified-bytes/mismatch')
                self.assertTrue(summary['cleanup'])
                self.assertNotIn('publicBundles', summary)
                self.assertNotIn('signatureVerified', summary)
                self.assertNotIn('base64', '\n'.join(lines))

    def test_audited_candidates_equal_created_pins_or_normalized_bytes(self):
        for prepare in (False, True):
            with self.subTest(preparation=prepare):
                status, lines, _, verifies, _, _, _, _, removed = self.preparation_fixture(prepare=prepare, mutate_before_finish=True)
                self.assertEqual(status, 1)
                self.assertEqual(verifies, [])
                self.assertTrue(removed)
                _, summary = failure_records(self, lines)
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
class FailureObservationTests(unittest.TestCase):
    """Exercise real module paths with external boundaries replaced by inert fixtures."""

    class PrivateFailure(RuntimeError):
        def __str__(self):
            raise AssertionError('exception text must not be inspected')

        def __repr__(self):
            raise AssertionError('exception repr must not be inspected')

    def setUp(self):
        artifacts.DEADLINE = time.monotonic() + 10
        self.real_stage = artifacts.stage
        self.real_acquire = artifacts.acquire
        self.real_rmtree = artifacts.shutil.rmtree

    def main_fixture(self, action, *, cleanup=None, temporary_error=None):
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent) / 'owned'
            root.mkdir(mode=0o700)
            captured, errors = io.StringIO(), io.StringIO()

            def stage(directory):
                self.assertEqual(directory, root)
                result = action(directory)
                return result if isinstance(result, dict) and 'evidence' in result else {'evidence': {'signatureVerified': True}}

            def remove(directory):
                self.assertEqual(directory, root)
                if cleanup is not None:
                    cleanup(directory)
                self.real_rmtree(directory)

            temporary = mock.Mock(side_effect=temporary_error) if temporary_error is not None else mock.Mock(return_value=str(root))
            with mock.patch.object(artifacts.sys, 'platform', 'linux'), \
                    mock.patch.object(artifacts.os, 'umask', return_value=0o022), \
                    mock.patch.object(artifacts.tempfile, 'mkdtemp', temporary), \
                    mock.patch.object(artifacts, 'stage', side_effect=stage), \
                    mock.patch.object(artifacts.shutil, 'rmtree', side_effect=remove), \
                    mock.patch.object(artifacts, 'acquisition_clock', side_effect=lambda *args: contextlib.nullcontext()), \
                    contextlib.redirect_stdout(captured), contextlib.redirect_stderr(errors):
                status = artifacts.main(False)
            return status, captured.getvalue().splitlines(), errors.getvalue(), root.exists()

    @contextlib.contextmanager
    def response_fixture(self, *, status=200, payload=b'body', fault=None, trace=None):
        trace = trace if trace is not None else []
        case = self

        class Response:
            reads = 0

            def __enter__(self):
                trace.append('response.enter')
                return self

            def __exit__(self, *args):
                trace.append('response.exit')

            @property
            def status(self):
                trace.append('status')
                self.reads += 1
                case.assertEqual(self.reads, 1, 'the original winning status operand must be read exactly once')
                if fault == 'status':
                    raise case.PrivateFailure()
                return status

            @property
            def url(self):
                trace.append('url')
                if fault == 'url':
                    raise case.PrivateFailure()
                return 'https://github.com/public-fixture'

            def read1(self, amount):
                trace.append('read')
                if fault == 'read':
                    raise case.PrivateFailure()
                result = self.payload
                self.payload = b''
                return result

        response = Response()
        response.payload = payload

        class Output:
            def __enter__(self):
                trace.append('output.enter')
                return self

            def __exit__(self, *args):
                trace.append('output.exit')

            def write(self, data):
                trace.append('write')
                if fault == 'write':
                    raise case.PrivateFailure()
                case.assertEqual(data, payload)

        class Target:
            def open(self, mode):
                case.assertEqual(mode, 'xb')
                trace.append('target.open')
                if fault == 'target-open':
                    raise case.PrivateFailure()
                return Output()

        target = Target()

        class Directory:
            def __truediv__(self, name):
                trace.append('target')
                return target

        def open_response(request, *, timeout):
            case.assertEqual(timeout, 10)
            trace.append('open')
            if fault == 'open':
                raise case.PrivateFailure()
            return response

        opener = mock.Mock()
        opener.open.side_effect = open_response
        with mock.patch.object(artifacts.ssl, 'create_default_context', return_value=object()), \
                mock.patch.object(artifacts.urllib.request, 'build_opener', return_value=opener):
            yield Directory(), target, trace

    def download(self, directory, name='package.tar.gz', payload=b'body'):
        return artifacts.download(directory, name, ('https://github.com/public-fixture', len(payload), artifacts.sha(payload)))

    def test_actual_frontiers_report_fixed_operation_without_exception_data(self):
        def clock(root):
            with mock.patch.object(artifacts, 'acquisition_clock', side_effect=self.PrivateFailure()):
                return self.real_stage(root)

        def context(root):
            with mock.patch.object(artifacts.os, 'uname', side_effect=self.PrivateFailure()):
                return self.real_acquire(root)

        def command(root):
            with mock.patch.object(artifacts.subprocess, 'Popen', side_effect=self.PrivateFailure()):
                return artifacts.command(['/fixed/public-fixture'])

        def setup(root):
            with mock.patch.object(artifacts.ssl, 'create_default_context', side_effect=self.PrivateFailure()):
                return self.download(root)

        def download_fault(kind):
            def action(root):
                with self.response_fixture(fault=kind) as (directory, _, trace):
                    return self.download(directory)
            return action

        def digest(root):
            digest = mock.Mock()
            digest.hexdigest.side_effect = self.PrivateFailure()
            with self.response_fixture(payload=b'') as (directory, _, _), \
                    mock.patch.object(artifacts.hashlib, 'sha256', return_value=digest):
                return artifacts.download(directory, 'package.tar.gz', ('https://github.com/public-fixture', 0, 'fixed'))

        def acquire_fault(point):
            def action(root):
                real_mkdir = Path.mkdir

                def mkdir(path, *args, **kwargs):
                    if point == 'layout' and path == root / 'context':
                        raise self.PrivateFailure()
                    return real_mkdir(path, *args, **kwargs)

                with mock.patch.dict(artifacts.os.environ, {'RELEASE_PROFILE': 'full', 'GITHUB_REPOSITORY': 'OMT-Global/bootstrap', 'GITHUB_RUN_ID': '123'}), \
                        mock.patch.object(artifacts.os, 'uname', return_value=mock.Mock(machine='x86_64')), \
                        mock.patch.object(artifacts, 'command', return_value=b'f' * 40), \
                        mock.patch.object(artifacts, 'download'), \
                        mock.patch.object(Path, 'mkdir', new=mkdir), \
                        mock.patch.object(artifacts, 'extract', side_effect=self.PrivateFailure()):
                    return self.real_acquire(root)
            return action

        def candidate_fault(point):
            def action(root):
                with mock.patch.object(artifacts, 'acquire', return_value=(root / 'package', {})):
                    if point == 'candidate-read':
                        with mock.patch.object(artifacts, 'BUNDLE_DIRECTORY', root / 'missing-pins'):
                            return self.real_stage(root)
                    with mock.patch.object(Path, 'write_bytes', side_effect=self.PrivateFailure()):
                        return self.real_stage(root)
            return action

        def finish_fault(point):
            def action(root):
                package = root / 'package'
                package.mkdir()
                legacy, candidate = bundles()
                data = json.dumps(candidate).encode()
                (root / 'package.sigstore').write_text(json.dumps(legacy))
                (root / 'package.standard.json').write_bytes(data)
                assets = {**artifacts.ASSETS, 'package.tar.gz': ('https://github.com/public-fixture', 0, (b'z' * 32).hex())}
                real_mkdir = Path.mkdir

                def mkdir(path, *args, **kwargs):
                    if point == 'finalize' and path == root / 'public-notices':
                        raise self.PrivateFailure()
                    return real_mkdir(path, *args, **kwargs)

                with mock.patch.object(artifacts, 'binaries', return_value=[('package', root / 'public-binary')]), \
                        mock.patch.object(artifacts, 'ASSETS', assets), \
                        mock.patch.object(artifacts, 'verify_signatures'), \
                        mock.patch.object(Path, 'mkdir', new=mkdir):
                    if point == 'bundle-audit':
                        with mock.patch.object(artifacts.json, 'loads', side_effect=self.PrivateFailure()):
                            return artifacts.finish(root, package, {}, {'package': data})
                    return artifacts.finish(root, package, {}, {'package': data})
            return action

        def cosign(root):
            (root / 'cosign').write_bytes(b'synthetic; never executed')
            with mock.patch.object(artifacts, 'binaries', return_value=[('package', root / 'public-binary')]), \
                    mock.patch.object(artifacts.subprocess, 'Popen', side_effect=self.PrivateFailure()):
                return artifacts.verify_signatures(root, root / 'package')

        cases = [('workspace', None, self.PrivateFailure()), ('clock', clock, None), ('context', context, None),
                 ('command', command, None), ('download-setup', setup, None), ('download-open', download_fault('open'), None),
                 ('download-open', download_fault('target-open'), None), ('download-open', download_fault('status'), None),
                 ('download-open', download_fault('url'), None), ('download-read', download_fault('read'), None),
                 ('download-write', download_fault('write'), None), ('download-hash', digest, None),
                 ('layout', acquire_fault('layout'), None), ('extract', acquire_fault('extract'), None),
                 ('candidate-read', candidate_fault('candidate-read'), None), ('candidate-write', candidate_fault('candidate-write'), None),
                 ('bundle-audit', finish_fault('bundle-audit'), None), ('cosign', cosign, None),
                 ('finalize', finish_fault('finalize'), None)]
        for stage, action, temporary_error in cases:
            with self.subTest(stage=stage, action=action):
                status, lines, errors, _ = self.main_fixture(action or (lambda root: None), temporary_error=temporary_error)
                diagnostic, summary = failure_records(self, lines)
                self.assertEqual(status, 1)
                self.assertEqual(diagnostic['stage'], stage)
                self.assertTrue(summary['cleanup'])
                self.assertFalse(summary['ok'])
                self.assertEqual(summary['reason'], 'bundle/package/pinned-file/shape' if stage == 'candidate-read' else 'unsupported')
                self.assertEqual(errors, '')
                self.assertNotIn('PrivateFailure', '\n'.join(lines))
                self.assertNotIn('/fixed/public-fixture', '\n'.join(lines))
                self.assertNotIn('https://', '\n'.join(lines))

    def test_response_status_original_read_order_and_short_circuit_are_preserved(self):
        for status, accepted, expected_suffix in [(200, True, ['status', 'url', 'read', 'write', 'read']),
                                                   (403, False, ['status']), (True, False, ['status'])]:
            with self.subTest(status=status), self.response_fixture(status=status) as (directory, target, trace):
                if accepted:
                    self.assertIs(self.download(directory), target)
                else:
                    with self.assertRaisesRegex(artifacts.Unsupported, '^download$'):
                        self.download(directory)
                self.assertEqual(trace, ['target', 'open', 'response.enter', 'target.open', 'output.enter',
                                         *expected_suffix, 'output.exit', 'response.exit'])
        class EqualTo200:
            def __eq__(self, other):
                self.assertion = other
                return True

            def __int__(self):
                raise AssertionError('status must not be coerced')
        status = EqualTo200()
        with self.response_fixture(status=status) as (directory, target, trace):
            self.assertIs(self.download(directory), target)
            self.assertEqual(status.assertion, 200)
            self.assertEqual(trace.count('status'), 1)
            self.assertIn('url', trace)

    def test_exact_http_error_owned_code_only_without_body_or_value_delegation(self):
        accessed = []
        class Body(io.BytesIO):
            @property
            def code(self):
                accessed.append('body.code')
                raise AssertionError('body code must not be delegated')

            def read(self, *args):
                accessed.append('body.read')
                raise AssertionError('body must not be read')
        class Uncoercible:
            def __int__(self):
                raise AssertionError('HTTP code must not be coerced')

            def __repr__(self):
                raise AssertionError('HTTP code repr must not be inspected')
        class Subclass(urllib.error.HTTPError):
            def __getattribute__(self, name):
                if name == 'code' and object.__getattribute__(self, '__dict__').get('_trap_code', False):
                    raise AssertionError('subclass code must not be delegated')
                return super().__getattribute__(name)

            def __str__(self):
                raise AssertionError('HTTP error must not be formatted')
        for value, expected in [(100, 100), (599, 599), (99, 0), (600, 0), (False, 0), ('403', 0), (Uncoercible(), 0), (None, 0)]:
            body = Body(b'synthetic secret-looking body')
            error = urllib.error.HTTPError('https://private.invalid/token', 403, 'secret header body', {}, body)
            error.__dict__['code'] = value
            if value is None:
                del error.__dict__['code']
            def action(root):
                with mock.patch.object(artifacts.urllib.request, 'build_opener', return_value=mock.Mock(open=mock.Mock(side_effect=error))), \
                        mock.patch.object(artifacts.ssl, 'create_default_context', return_value=object()):
                    return self.download(root)
            status, lines, errors, _ = self.main_fixture(action)
            error.close()
            diagnostic, summary = failure_records(self, lines)
            self.assertEqual(status, 1)
            self.assertEqual(summary['reason'], 'unsupported')
            self.assertEqual(diagnostic['stage'], 'download-open')
            self.assertEqual(diagnostic['assetIndex'], 0)
            self.assertEqual(diagnostic['lastHttpState'], 'http-error')
            self.assertEqual(diagnostic['lastHttpStatus'], expected)
            self.assertEqual(errors, '')
            self.assertNotIn('private.invalid', '\n'.join(lines))
            self.assertNotIn('secret', '\n'.join(lines))
            body.close()
        error = Subclass('https://private.invalid/token', 403, 'private', {}, Body())
        error.__dict__['_trap_code'] = True
        status, lines, _, _ = self.main_fixture(lambda root: (_ for _ in ()).throw(error))
        error.close()
        diagnostic, summary = failure_records(self, lines)
        self.assertEqual(diagnostic['lastHttpState'], 'not-observed')
        self.assertEqual(diagnostic['lastHttpStatus'], 0)
        self.assertEqual(summary['reason'], 'unsupported')
        self.assertEqual(accessed, [])

    def test_download_and_main_reset_last_http_observation(self):
        def action(root):
            with self.response_fixture(status=200) as (directory, _, _):
                self.download(directory)
            with mock.patch.object(artifacts.ssl, 'create_default_context', side_effect=self.PrivateFailure()):
                self.download(root, 'package.sigstore')
        _, lines, _, _ = self.main_fixture(action)
        diagnostic, _ = failure_records(self, lines)
        self.assertEqual(diagnostic, {'schema': 1, 'stage': 'download-setup', 'assetIndex': 1,
                                      'lastHttpState': 'not-observed', 'lastHttpStatus': 0})
        _, lines, _, _ = self.main_fixture(lambda root: (_ for _ in ()).throw(self.PrivateFailure()))
        diagnostic, _ = failure_records(self, lines)
        self.assertEqual(diagnostic, {'schema': 1, 'stage': 'workspace', 'assetIndex': -1,
                                      'lastHttpState': 'not-observed', 'lastHttpStatus': 0})

    def test_later_extract_failure_reports_last_http_observation_without_cause_claim(self):
        payload = b'body'
        assets = {'package.tar.gz': ('https://github.com/public-fixture', len(payload), artifacts.sha(payload))}
        def action(root):
            with mock.patch.dict(artifacts.os.environ, {'RELEASE_PROFILE': 'full', 'GITHUB_REPOSITORY': 'OMT-Global/bootstrap', 'GITHUB_RUN_ID': '123'}), \
                    mock.patch.object(artifacts.os, 'uname', return_value=mock.Mock(machine='x86_64')), \
                    mock.patch.object(artifacts, 'command', return_value=b'f' * 40), \
                    mock.patch.object(artifacts, 'ASSETS', assets), \
                    mock.patch.object(artifacts, 'extract', side_effect=self.PrivateFailure()), \
                    self.response_fixture(payload=payload):
                return self.real_acquire(root)
        status, lines, _, _ = self.main_fixture(action)
        diagnostic, summary = failure_records(self, lines)
        self.assertEqual(status, 1)
        self.assertEqual(summary['reason'], 'unsupported')
        self.assertEqual(diagnostic, {'schema': 1, 'stage': 'extract', 'assetIndex': -1,
                                      'lastHttpState': 'response', 'lastHttpStatus': 200})
        self.assertNotIn('cause', diagnostic)

    def test_cosign_selector_read_and_wait_failures_keep_cleanup_trace_without_execution(self):
        for point in ('selector', 'read', 'wait'):
            trace = []
            process = mock.Mock(pid=123456)
            process.poll.side_effect = lambda: trace.append('poll') or 0
            for name in ('stdin', 'stdout', 'stderr'):
                getattr(process, name).close.side_effect = lambda name=name: trace.append(name + '.close')
            process.wait.side_effect = self.PrivateFailure() if point == 'wait' else lambda **kwargs: 0
            key = mock.Mock(fd=11, fileobj=process.stdout, data=0)
            selector = mock.MagicMock()
            selector.__enter__.return_value = selector
            selector.get_map.return_value = point == 'read'
            selector.select.return_value = [(key, 0)]
            def spawned(*args, **kwargs):
                trace.append('spawn')
                self.assertEqual(args, (['/never-executed/cosign'],))
                self.assertTrue(kwargs['start_new_session'])
                return process
            def killed(pid, sig):
                self.assertEqual(pid, process.pid)
                self.assertEqual(sig, artifacts.signal.SIGKILL)
                trace.append('killpg')
            def action(root):
                with mock.patch.object(artifacts.subprocess, 'Popen', side_effect=spawned), \
                        mock.patch.object(artifacts.selectors, 'DefaultSelector', side_effect=self.PrivateFailure() if point == 'selector' else None,
                                          return_value=selector), \
                        mock.patch.object(artifacts.os, 'read', side_effect=self.PrivateFailure()), \
                        mock.patch.object(artifacts.os, 'killpg', side_effect=killed):
                    return artifacts.command(['/never-executed/cosign'], diagnostic='package')
            with self.subTest(point=point):
                status, lines, errors, _ = self.main_fixture(action)
                diagnostic, summary = failure_records(self, lines)
                self.assertEqual(status, 1)
                self.assertEqual(diagnostic['stage'], 'cosign')
                self.assertEqual(summary['reason'], 'unsupported')
                self.assertTrue(summary['cleanup'])
                self.assertEqual(errors, '')
                self.assertEqual(trace, ['spawn', 'killpg', 'poll', 'stdin.close', 'stdout.close', 'stderr.close'])
                self.assertEqual(process.wait.call_count, 1 if point == 'wait' else 0)
                self.assertNotIn('REVIEWER_SIGNATURE_DIAGNOSTIC', '\n'.join(lines))

    def test_failure_snapshot_precedes_cleanup_and_cleanup_reason_still_wins(self):
        def action(root):
            with self.response_fixture(status=200, fault='read') as (directory, _, _):
                return self.download(directory)
        def mutate(directory):
            state = artifacts.__dict__.get('_OBSERVATION')
            if isinstance(state, dict):
                state.update(stage='cleanup', assetIndex=-1, lastHttpState='not-observed', lastHttpStatus=0)
        _, lines, _, removed = self.main_fixture(action, cleanup=mutate)
        diagnostic, summary = failure_records(self, lines)
        self.assertEqual(diagnostic, {'schema': 1, 'stage': 'download-read', 'assetIndex': 0,
                                      'lastHttpState': 'response', 'lastHttpStatus': 200})
        self.assertTrue(summary['cleanup'])
        self.assertFalse(removed)
        def cleanup_failure(directory):
            raise self.PrivateFailure()
        _, lines, _, remains = self.main_fixture(action, cleanup=cleanup_failure)
        diagnostic, summary = failure_records(self, lines)
        self.assertEqual(summary['reason'], 'cleanup')
        self.assertFalse(summary['cleanup'])
        self.assertTrue(remains)
        self.assertEqual(diagnostic, {'schema': 1, 'stage': 'cleanup', 'assetIndex': -1,
                                      'lastHttpState': 'response', 'lastHttpStatus': 200})

    def test_success_wire_and_evidence_limit_remain_unchanged(self):
        result = {'evidence': {'fixture': 'synthetic-public-only', 'signatureVerified': True}}
        status, lines, errors, remains = self.main_fixture(lambda root: result)
        self.assertEqual(status, 0)
        self.assertEqual(lines, ['REVIEWER_ARTIFACT_EVIDENCE {"schema":1,"preparation":false,"ok":true,"cleanup":true,"fixture":"synthetic-public-only","signatureVerified":true}'])
        self.assertEqual(errors, '')
        self.assertFalse(remains)
        huge = {'evidence': {'signatureVerified': True, 'padding': 'x' * 262144}}
        status, lines, _, _ = self.main_fixture(lambda root: huge)
        diagnostic, summary = failure_records(self, lines)
        self.assertEqual(status, 1)
        self.assertEqual(diagnostic['stage'], 'evidence')
        self.assertEqual(summary, {'schema': 1, 'preparation': False, 'ok': False, 'cleanup': True, 'reason': 'evidence-limit'})
        self.assertLessEqual(len(('\n'.join(lines) + '\n').encode()), 262144)

    def test_umask_failure_stays_outside_the_protected_main_boundary(self):
        failure = self.PrivateFailure()
        captured = io.StringIO()
        with mock.patch.object(artifacts.os, 'umask', side_effect=failure), \
                mock.patch.object(artifacts.tempfile, 'mkdtemp') as temporary, \
                contextlib.redirect_stdout(captured):
            with self.assertRaises(self.PrivateFailure) as observed:
                artifacts.main(False)
        self.assertIs(observed.exception, failure)
        temporary.assert_not_called()
        self.assertEqual(captured.getvalue(), '')


if __name__ == '__main__':
    unittest.main()
