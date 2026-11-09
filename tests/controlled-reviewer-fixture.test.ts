import { execFile } from "node:child_process";
import { readFile } from "node:fs/promises";
import { promisify } from "node:util";
import { describe, expect, it } from "vitest";

const execute = promisify(execFile);

// All Linux observations, resource setters and native entry points are fake adapters.
const fixtureAdmissionSetup = String.raw`"""Inherited address-space fixtures; every resource setter and Linux observation is mocked."""
import ast
import copy
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

LIMIT = 17179869184
PAIR = {'soft': LIMIT, 'hard': LIMIT}
CANARY = 'fixture-private-admission-canary'
MISSING = object()
UNREADABLE = object()
tree = ast.parse(Path(fixture.__file__).read_text())
entry = next(node for node in tree.body if isinstance(node, ast.If) and ast.unparse(node.test) == "__name__ == '__main__'")
ENTRY = compile(ast.fix_missing_locations(ast.Module(body=entry.body, type_ignores=[])), fixture.__file__, 'exec')

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

@contextlib.contextmanager
def mocked_gate(fault=None, process_probe=None, security=None, security_probe=None):
    values = {'memory.max': '2147483648', 'memory.swap.max': '0', 'pids.max': '128', 'cpu.max': '200000 100000'}
    counts = process_probe if process_probe is not None else {}
    counts.update(reads=[], nnpLookup=0, nnpStrip=0)
    profile = {'seccomp': '2', 'apparmor': b'docker-default (enforce)\n', 'flags': 14}
    profile.update(security or {})
    probe = security_probe if security_probe is not None else {}
    probe.update(goReads=0, apparmorPaths=[], fallbackReads=0)
    class Value(str):
        def __new__(cls, key, value):
            result = super().__new__(cls, value)
            result.key = key
            return result
        def strip(self):
            if self.key == 'NoNewPrivs':
                counts['nnpStrip'] += 1
                if fault == 'nnp-raises':
                    raise OSError(CANARY)
            return super().strip()
    class StatusLine(str):
        def __new__(cls, key, value):
            result = super().__new__(cls, key + ': ' + value)
            result.key, result.value = key, value
            return result
        def split(self, *args):
            return [self.key, Value(self.key, self.value)]
    class Status(dict):
        def __getitem__(self, key):
            if key == 'NoNewPrivs':
                counts['nnpLookup'] += 1
            return super().__getitem__(key)
    class StatusText:
        def splitlines(self):
            if fault == 'status-parse':
                raise MemoryError(CANARY)
            entries = [(name, '1' if fault == 'caps-false' and name == 'CapEff' else
                        CANARY if fault == 'capabilities' and name == 'CapEff' else '0')
                       for name in ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb')]
            if fault != 'nnp-missing':
                entries.append(('NoNewPrivs', '0' if fault == 'nnp-false' else '1'))
            if profile['seccomp'] is not MISSING:
                entries.append(('Seccomp', profile['seccomp']))
            return [StatusLine(key, value) for key, value in entries]
    elf = b'\x7fELF\x02\x01\x01' + bytes(11) + b'\x3e\x00'
    original_mkdir = Path.mkdir
    with tempfile.TemporaryDirectory(prefix='bootstrap-as-full-gate-fixture-') as temporary:
        def read_text(path, *args, **kwargs):
            if str(path) == '/proc/self/status':
                counts['reads'].append('status')
                if fault in ('process-mounts', 'status-read'):
                    raise OSError(CANARY)
                return StatusText()
            if str(path) == '/proc/self/mountinfo':
                counts['reads'].append('mountinfo')
                if fault == 'mountinfo-read':
                    raise OSError(CANARY)
                class MountText:
                    def splitlines(self):
                        if fault == 'mountinfo-parse':
                            raise MemoryError(CANARY)
                        if fault == 'root-ro':
                            return ['malformed-row']
                        rows = ['1 0 0:0 / / ' + ('rw' if fault == 'root-false' else 'ro'),
                                '2 1 0:1 / ' + temporary + ' rw']
                        if fault in ('mounts-safe', 'mounts-false'):
                            rows.append('3 1 0:2 / /' + CANARY + ' rw')
                        return rows
                return MountText()
            if fault == 'cgroup':
                raise OSError(CANARY)
            return values[path.name]
        def read_bytes(path):
            if str(path) == '/proc/self/attr/apparmor/current':
                probe['apparmorPaths'].append(str(path))
                if profile['apparmor'] is MISSING:
                    raise FileNotFoundError(CANARY)
                if profile['apparmor'] is UNREADABLE:
                    raise OSError(CANARY)
                return profile['apparmor']
            if str(path) == '/proc/self/attr/current':
                probe['fallbackReads'] += 1
                return b'docker-default (enforce)\n'
            raise AssertionError('unexpected fabricated byte-read path')
        class GoInput(io.BytesIO):
            def readline(self, *args, **kwargs):
                probe['goReads'] += 1
                return super().readline(*args, **kwargs)
        fs = types.SimpleNamespace(f_blocks=0 if fault == 'tmpfs' else 64, f_frsize=4096, f_files=16384)
        if profile['flags'] is not MISSING:
            fs.f_flag = profile['flags']
        def mkdir(path, *args, **kwargs):
            if fault == 'environment-directories':
                raise OSError(CANARY)
            return original_mkdir(path, *args, **kwargs)
        def setter(resource, value):
            if fault == 'resource-setters':
                raise OSError(CANARY)
        def statfs(path, raw):
            ctypes.cast(raw, ctypes.POINTER(ctypes.c_long))[0] = 0x01021994
            return 0
        def access(path, mode):
            if fault == 'mounts-safe':
                raise OSError(CANARY)
            return fault in ('mounts-false', 'shared-memory')
        pair = (-1, -1) if fault == 'inherited-as' else (LIMIT, LIMIT)
        with admission(pair, setter) as (order, emit, native), \
                mock.patch.object(fixture, 'ROOT', Path(temporary)), \
                mock.patch.object(fixture, 'dict', Status, create=True), \
                mock.patch.object(fixture.os, 'getpid', return_value=2 if fault == 'platform' else 1), \
                mock.patch.object(fixture.os, 'environ', {}), \
                mock.patch.object(Path, 'read_text', read_text), mock.patch.object(Path, 'read_bytes', read_bytes), \
                mock.patch.object(Path, 'mkdir', mkdir), \
                mock.patch.object(Path, 'lstat', side_effect=OSError(CANARY) if fault == 'package-binaries' else None,
                    return_value=types.SimpleNamespace(st_mode=stat.S_IFREG | 0o755, st_uid=0, st_nlink=1)), \
                mock.patch.object(Path, 'open', side_effect=lambda *args, **kwargs: io.BytesIO(elf)), \
                mock.patch.object(fixture.os.path, 'exists', return_value=fault == 'shared-memory'), \
                mock.patch.object(fixture.os, 'access', side_effect=access), \
                mock.patch.object(fixture.os, 'stat', return_value=types.SimpleNamespace(st_mode=stat.S_IFREG | 0o600)), \
                mock.patch.object(fixture.os, 'statvfs', return_value=fs), \
                mock.patch.multiple(fixture.os, ST_NOSUID=2, ST_NODEV=4, ST_NOEXEC=8, ST_RDONLY=1, create=True), \
                mock.patch.object(fixture.ctypes, 'CDLL', return_value=types.SimpleNamespace(statfs=statfs)), \
                mock.patch.object(fixture.os, 'uname', return_value=types.SimpleNamespace(machine=CANARY if fault == 'architecture' else 'x86_64')), \
                mock.patch.object(fixture.sys, 'stdin', types.SimpleNamespace(buffer=GoInput(b'BAD\n' if fault == 'after-ready' else b'GO\n'))):
            emitted = []
            emit.side_effect = lambda value: emitted.append(json.loads(json.dumps(value)))
            yield order, emit, native, emitted

def fixture_entry(case):
    with mock.patch.object(fixture.sys, 'argv', ['fixture', '--case', case]), \
            mock.patch.object(fixture, 'run_case', side_effect=RuntimeError(CANARY)) as run_case:
        try:
            exec(ENTRY, fixture.__dict__)
        except SystemExit as error:
            assert error.code == 1
        else:
            raise AssertionError('failure fixture did not exit')
        return run_case.call_count

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
        with mocked_gate() as (order, emit, native, emitted):
            fixture.gate()
            expected = [('get', fixture.resource.RLIMIT_AS)] + [('set', resource, (value, value)) for resource, value in fixture.LIMITS.values()]
            self.assertEqual(order, expected)
            emit.assert_called_once()
            self.assertEqual(emit.call_args.args[0]['addressSpace'], PAIR)
            self.assertTrue(emit.call_args.args[0]['pid1'])
            native.assert_not_called()

    def test_actual_catch_publishes_each_admission_stage_without_ready_native_or_private_text(self):
        stages = ('platform', 'inherited-as', 'resource-setters', 'environment-directories', 'process-mounts',
                  'shared-memory', 'tmpfs', 'cgroup', 'architecture', 'package-binaries')
        for stage in stages:
            with self.subTest(stage=stage), mocked_gate(stage) as (order, emit, native, emitted):
                self.assertEqual(fixture_entry('mechanical'), 0)
                self.assertEqual(len(emitted), 1)
                failure = emitted[0]
                self.assertEqual((failure['event'], failure['case'], failure['ok'], failure['providerRequests']), ('result', 'mechanical', False, 0))
                self.assertEqual(set(failure), {'event', 'case', 'ok', 'phase', 'reason', 'providerRequests', 'admissionFailure'})
                self.assertEqual((failure['phase'], failure['reason']), ('mechanical', 'unsupported'))
                expected = {'stage': stage}
                if stage != 'platform':
                    expected['addressSpace'] = {'soft': -1, 'hard': -1} if stage == 'inherited-as' else PAIR
                if stage == 'process-mounts':
                    expected['processMounts'] = {'substage': 'status-read'}
                self.assertEqual(failure['admissionFailure'], expected)
                self.assertNotIn(CANARY, json.dumps(emitted))
                setters = [entry for entry in order if entry[0] == 'set']
                self.assertEqual(len(setters), 0 if stage in ('platform', 'inherited-as') else 1 if stage == 'resource-setters' else len(fixture.LIMITS))
                native.assert_not_called()

    def test_getter_failure_has_no_invented_pair_and_next_gate_resets_stale_admission(self):
        with mocked_gate() as (order, emit, native, emitted):
            with mock.patch.object(fixture.resource, 'getrlimit', side_effect=OSError(CANARY)):
                self.assertEqual(fixture_entry('mechanical'), 0)
            self.assertEqual(emitted[0]['admissionFailure'], {'stage': 'inherited-as'})
            self.assertEqual(order, [])
            native.assert_not_called()
        with mocked_gate() as (order, emit, native, emitted):
            fixture.gate()
            self.assertEqual(fixture.ADMISSION['stage'], 'ready')
        with mocked_gate('platform') as (order, emit, native, emitted):
            self.assertEqual(fixture_entry('mechanical'), 0)
            self.assertEqual(emitted[0]['admissionFailure'], {'stage': 'platform'})
            self.assertNotIn('addressSpace', emitted[0]['admissionFailure'])

    def test_nonmechanical_and_post_ready_failure_publication_remains_private(self):
        for case in fixture.CASES:
            if case == 'mechanical':
                continue
            with self.subTest(case=case), mocked_gate('platform') as (order, emit, native, emitted):
                self.assertEqual(fixture_entry(case), 0)
                self.assertNotIn('admissionFailure', emitted[0])
                self.assertEqual(set(emitted[0]), {'event', 'case', 'ok', 'phase', 'reason', 'providerRequests'})
                self.assertNotIn(CANARY, json.dumps(emitted))
                self.assertEqual(order, [])
                native.assert_not_called()
        for fault, calls in (('after-ready', 0), (None, 1)):
            with self.subTest(fault=fault), mocked_gate(fault) as (order, emit, native, emitted):
                self.assertEqual(fixture_entry('mechanical'), calls)
                self.assertEqual(emitted[0]['event'], 'ready')
                self.assertNotIn('admissionFailure', emitted[-1])
                self.assertEqual(set(emitted[-1]), {'event', 'case', 'ok', 'phase', 'reason', 'providerRequests'})
                self.assertNotIn(CANARY, json.dumps(emitted))
                native.assert_not_called()

    def test_actual_process_read_parse_and_computation_failures_publish_only_completed_booleans(self):
        cases = [('status-read', 'status-read', {}), ('status-parse', 'status-parse', {}),
                 ('capabilities', 'capabilities', {}), ('mountinfo-read', 'mountinfo-read', {'capsZero': True}),
                 ('mountinfo-parse', 'mountinfo-parse', {'capsZero': True}), ('root-ro', 'root-ro', {'capsZero': True}),
                 ('mounts-safe', 'mounts-safe', {'capsZero': True, 'rootRo': True}),
                 ('nnp-raises', 'combined-predicate', {'capsZero': True, 'rootRo': True, 'mountsSafe': True})]
        for fault, substage, predicates in cases:
            counts = {}
            with self.subTest(fault=fault), mocked_gate(fault, counts) as (order, emit, native, emitted):
                self.assertEqual(fixture_entry('mechanical'), 0)
                self.assertEqual(len(emitted), 1)
                self.assertEqual(emitted[0]['admissionFailure'], {
                    'stage': 'process-mounts', 'addressSpace': PAIR, 'processMounts': {'substage': substage, **predicates}})
                self.assertEqual(counts['reads'], ['status'] if fault in ('status-read', 'status-parse', 'capabilities') else ['status', 'mountinfo'])
                self.assertEqual(counts['nnpLookup'], int(fault == 'nnp-raises'))
                self.assertEqual(counts['nnpStrip'], int(fault == 'nnp-raises'))
                self.assertNotIn(CANARY, json.dumps(emitted))
                native.assert_not_called()

    def test_false_unevaluated_and_exceptional_nnp_remain_distinct_and_success_clears_context(self):
        cases = [('root-false', 'rootRo', 0, 0), ('mounts-false', 'mountsSafe', 0, 0),
                 ('caps-false', 'capsZero', 0, 0), ('nnp-false', 'noNewPrivs', 1, 1),
                 ('nnp-missing', None, 1, 0), ('nnp-raises', None, 1, 1)]
        for fault, field, lookups, strips in cases:
            counts = {}
            with self.subTest(fault=fault), mocked_gate(fault, counts) as (order, emit, native, emitted):
                self.assertEqual(fixture_entry('mechanical'), 0)
                context = emitted[0]['admissionFailure']['processMounts']
                self.assertEqual(context['substage'], 'combined-predicate')
                if field is not None:
                    self.assertIs(context[field], False)
                self.assertEqual('noNewPrivs' in context, fault == 'nnp-false')
                self.assertEqual(counts, {'reads': ['status', 'mountinfo'], 'nnpLookup': lookups, 'nnpStrip': strips})
                native.assert_not_called()
        self.assertIn('processMounts', fixture.ADMISSION)
        with mocked_gate('platform') as (order, emit, native, emitted):
            self.assertEqual(fixture_entry('mechanical'), 0)
            self.assertEqual(emitted[0]['admissionFailure'], {'stage': 'platform'})
            self.assertNotIn('processMounts', fixture.ADMISSION)
        counts = {}
        with mocked_gate(process_probe=counts) as (order, emit, native, emitted):
            fixture.gate()
            self.assertEqual(counts, {'reads': ['status', 'mountinfo'], 'nnpLookup': 1, 'nnpStrip': 1})
            self.assertNotIn('processMounts', fixture.ADMISSION)
            self.assertNotIn('processMounts', emitted[0])

    def test_nnp_observation_unwraps_to_the_canonical_predicate_and_preserves_truth_call_order(self):
        gate = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'gate')
        observed = next(node for node in gate.body if isinstance(node, ast.Try))
        initialization = next(node for node in gate.body if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == 'no_new_privs' for target in node.targets))
        canonical = ast.parse("require(root_ro and mounts_safe and caps_zero and status['NoNewPrivs'].strip() == '1')").body[0]
        class Unwrap(ast.NodeTransformer):
            def visit_NamedExpr(self, node):
                return self.visit(node.value)
        self.assertEqual(ast.dump(canonical.value.args[0]), ast.dump(Unwrap().visit(copy.deepcopy(observed.body[0].value.args[0]))))
        for values in ((False, True, True, True), (True, False, True, True), (True, True, False, True),
                       (True, True, True, False), (True, True, True, True)):
            outcomes = []
            for statements in ([canonical], [initialization, observed]):
                calls = []
                class Truth:
                    def __init__(self, name, value):
                        self.name, self.value = name, value
                    def __bool__(self):
                        calls.append(self.name)
                        return self.value
                class Nnp(str):
                    def strip(self):
                        calls.append('NNP-strip')
                        return super().strip()
                class Status(dict):
                    def __getitem__(self, key):
                        calls.append('NNP-lookup')
                        return super().__getitem__(key)
                context = {'substage': 'combined-predicate'}
                namespace = {'root_ro': Truth('root', values[0]), 'mounts_safe': Truth('mounts', values[1]),
                             'caps_zero': Truth('caps', values[2]), 'status': Status(NoNewPrivs=Nnp('1' if values[3] else '0')),
                             'require': fixture.require, 'process_context': context}
                try:
                    exec(compile(ast.fix_missing_locations(ast.Module(body=statements, type_ignores=[])), '<predicate-fixture>', 'exec'), namespace)
                    failed = False
                except RuntimeError:
                    failed = True
                outcomes.append((calls, failed, context))
            self.assertEqual(outcomes[0][:2], outcomes[1][:2])
            evaluated = all(values[:3])
            self.assertEqual(outcomes[1][0].count('NNP-lookup'), int(evaluated))
            self.assertEqual(outcomes[1][0].count('NNP-strip'), int(evaluated))
            self.assertEqual('noNewPrivs' in outcomes[1][2], evaluated)
            if evaluated:
                self.assertIs(outcomes[1][2]['noNewPrivs'], values[3])
`;

const fixtureAdmissionHarness = fixtureAdmissionSetup + String.raw`log = io.StringIO()
result = unittest.TextTestRunner(stream=log).run(unittest.defaultTestLoader.loadTestsFromTestCase(InheritedAddressSpaceTests))
if not result.wasSuccessful():
    print(log.getvalue(), file=sys.stderr)
    sys.exit(1)
print(json.dumps({'testCases': result.testsRun, 'actualResourceSetters': 0, 'nativeOrLauncherProcesses': 0}))
`;

const fixtureSecurityHarness = fixtureAdmissionSetup + String.raw`
OBSERVATIONS = []


class FixtureSecurityTests(unittest.TestCase):
    def rejected(self, label, security, stage):
        probe = {}
        with mocked_gate(security=security, security_probe=probe) as (order, emit, native, emitted):
            calls = fixture_entry('mechanical')
            events = [value['event'] for value in emitted]
            OBSERVATIONS.append({'case': label, 'expected': 'rejected', 'ready': 'ready' in events,
                                 'goReads': probe['goReads'], 'runCaseCalls': calls,
                                 'nativeCalls': native.call_count, 'fallbackReads': probe['fallbackReads']})
            self.assertEqual(calls, 0)
            self.assertEqual(events, ['result'])
            self.assertEqual(probe['goReads'], 0)
            self.assertEqual(probe['fallbackReads'], 0)
            self.assertEqual(emitted[0]['providerRequests'], 0)
            self.assertEqual(emitted[0]['admissionFailure']['stage'], stage)
            self.assertNotIn(CANARY, json.dumps(emitted))
            native.assert_not_called()

    def test_rejects_missing_zero_and_other_seccomp_modes_before_ready_go(self):
        for label, value in [('missing', MISSING), ('zero', '0'), ('strict', '1'),
                             ('unknown', '3'), ('empty', ''), ('wrong-frame', '2.0')]:
            with self.subTest(label=label):
                self.rejected('seccomp-' + label, {'seccomp': value}, 'process-mounts')

    def test_rejects_missing_unreadable_and_wrong_framed_apparmor_before_ready_go(self):
        values = [('missing', MISSING), ('unreadable', UNREADABLE),
                  ('complain', b'docker-default (complain)\n'), ('unconfined', b'unconfined\n'),
                  ('other', b'another-profile (enforce)\n'), ('no-lf', b'docker-default (enforce)'),
                  ('crlf', b'docker-default (enforce)\r\n'), ('extra-lf', b'docker-default (enforce)\n\n'),
                  ('leading-space', b' docker-default (enforce)\n'),
                  ('trailing-space', b'docker-default (enforce) \n'), ('nul', b'docker-default (enforce)\x00\n')]
        for label, value in values:
            with self.subTest(label=label):
                self.rejected('apparmor-' + label, {'apparmor': value}, 'process-mounts')

    def test_rejects_missing_mount_bits_or_readonly_before_ready_go(self):
        for label, value in [('missing', MISSING), ('none', 0), ('nosuid', 2), ('nodev', 4),
                             ('noexec', 8), ('no-noexec', 6), ('no-nodev', 10), ('no-nosuid', 12),
                             ('readonly', 15), ('readonly-extra', 4111)]:
            with self.subTest(label=label):
                self.rejected('flags-' + label, {'flags': value}, 'tmpfs')

    def test_rejects_non_builtin_or_outside_uint64_flags_before_ready_go(self):
        for label, value in [('true', True), ('false', False), ('negative', -1), ('overflow', 1 << 64),
                             ('float', 14.0), ('string', '14'), ('null', None)]:
            with self.subTest(label=label):
                self.rejected('flags-' + label, {'flags': value}, 'tmpfs')

    def test_valid_flag_mask_and_exact_single_lf_emit_the_measured_private_wire(self):
        for flags in (14, 4110, (1 << 64) - 2):
            probe = {}
            with self.subTest(flags=flags), mocked_gate(security={'flags': flags}, security_probe=probe) as (order, emit, native, emitted):
                fixture.gate()
                self.assertEqual(len(emitted), 1)
                ready = emitted[0]
                self.assertEqual(ready['event'], 'ready')
                self.assertIs(type(ready['seccomp']), int)
                self.assertEqual(ready['seccomp'], 2)
                self.assertEqual(ready['apparmor'], 'docker-default (enforce)')
                self.assertEqual(ready['tmpfs'], {'type': 0x01021994, 'bytes': 64 * 4096, 'inodes': 16384, 'flags': flags})
                self.assertEqual(ready['addressSpace'], PAIR)
                self.assertTrue(all(ready[key] is True for key in ('pid1', 'root_ro', 'mounts_safe', 'caps_zero', 'no_new_privs')))
                self.assertEqual(probe, {'goReads': 1, 'apparmorPaths': ['/proc/self/attr/apparmor/current'], 'fallbackReads': 0})
                self.assertEqual(fixture.ADMISSION['stage'], 'ready')
                native.assert_not_called()
                OBSERVATIONS.append({'case': 'valid-flags-' + str(flags), 'expected': 'accepted', 'ready': True,
                                     'goReads': probe['goReads'], 'nativeCalls': native.call_count})

    def test_seccomp_is_stripped_but_apparmor_uses_only_the_exact_byte_path(self):
        probe = {}
        with mocked_gate(security={'seccomp': ' \t2 \t'}, security_probe=probe) as (order, emit, native, emitted):
            fixture.gate()
            self.assertEqual(emitted[0]['seccomp'], 2)
            self.assertEqual(probe['goReads'], 1)
            self.assertEqual(probe['apparmorPaths'], ['/proc/self/attr/apparmor/current'])
            self.assertEqual(probe['fallbackReads'], 0)
            native.assert_not_called()
            OBSERVATIONS.append({'case': 'valid-stripped-seccomp', 'expected': 'accepted', 'ready': True,
                                 'goReads': probe['goReads'], 'nativeCalls': native.call_count})


suite = unittest.defaultTestLoader.loadTestsFromTestCase(FixtureSecurityTests)
if len(sys.argv) > 1 and sys.argv[1] == 'negative-controls':
    suite = unittest.TestSuite(test for test in suite if test._testMethodName.startswith('test_rejects'))
log = io.StringIO()
result = unittest.TextTestRunner(stream=log).run(suite)
print(json.dumps({'testCases': result.testsRun, 'ok': result.wasSuccessful(),
                  'invalidScenarios': sum(value['expected'] == 'rejected' for value in OBSERVATIONS),
                  'positiveScenarios': sum(value['expected'] == 'accepted' for value in OBSERVATIONS),
                  'observations': OBSERVATIONS, 'actualResourceSetters': 0, 'nativeOrLauncherProcesses': 0}))
if not result.wasSuccessful():
    print(log.getvalue(), file=sys.stderr)
    sys.exit(1)
`;

describe("controlled reviewer fixture producer", () => {
  it("preserves all ten inherited-admission producer methods with pure adapters", async () => {
    const result = await execute("python3", ["-B", "-I", "-S", "-c", fixtureAdmissionHarness], {
      cwd: process.cwd(), timeout: 10_000, maxBuffer: 64 * 1024,
      env: { PATH: process.env.PATH ?? "/usr/bin:/bin", PYTHONDONTWRITEBYTECODE: "1" }
    });
    expect(JSON.parse(result.stdout)).toEqual({ testCases: 10, actualResourceSetters: 0, nativeOrLauncherProcesses: 0 });
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

  it("rejects unsupported process/tmpfs profiles before READY or GO and retains the exact private wire", async () => {
    const result = await execute("python3", ["-B", "-I", "-S", "-c", fixtureSecurityHarness], {
      cwd: process.cwd(), timeout: 10_000, maxBuffer: 128 * 1024,
      env: { PATH: process.env.PATH ?? "/usr/bin:/bin", PYTHONDONTWRITEBYTECODE: "1" }
    });
    const report = JSON.parse(result.stdout);
    expect(report).toMatchObject({ testCases: 6, ok: true, invalidScenarios: 34, positiveScenarios: 4,
      actualResourceSetters: 0, nativeOrLauncherProcesses: 0 });
    expect(report.observations).toHaveLength(38);
    for (const observation of report.observations) {
      expect(observation.nativeCalls).toBe(0);
      if (observation.expected === "rejected") {
        expect(observation).toMatchObject({ ready: false, goReads: 0, runCaseCalls: 0, fallbackReads: 0 });
      }
    }
  });
});

const reviewerMountPolicyHarness = String.raw`import ast, json, stat, types
from pathlib import Path, PurePosixPath
source = ast.parse(Path('scripts/ci/controlled-reviewer-fixture.py').read_text())
gate = next(node for node in source.body if isinstance(node, ast.FunctionDef) and node.name == 'gate')
assignment = next(node for node in gate.body if isinstance(node, ast.Assign) and
                  any(isinstance(target, ast.Name) and target.id == 'mounts_safe' for target in node.targets))
policy = compile(ast.Expression(assignment.value), '<actual-mount-policy>', 'eval')
base = ['1 0 0:1 / / ro - overlay overlay ro', '2 1 0:2 / /run/review rw - tmpfs tmpfs rw',
        '3 1 0:3 / /proc rw - proc proc rw', '4 3 0:3 / /proc/sys ro - proc proc ro',
        '5 1 0:4 / /dev rw - tmpfs tmpfs rw', '6 5 0:5 / /dev/pts rw - devpts devpts rw',
        '7 1 0:6 / /sys ro - sysfs sysfs ro', '8 7 0:7 / /sys/fs/cgroup ro - cgroup2 cgroup ro',
        '9 1 0:8 / /etc/hosts ro - ext4 hosts ro', '10 5 0:9 / /dev/null rw - tmpfs null rw']
def admitted(extra, writable):
    calls = []
    def access(path, mode):
        calls.append(('access', path))
        return path in writable
    def metadata(path):
        calls.append(('stat', path))
        return types.SimpleNamespace(st_mode=(stat.S_IFCHR | 0o666) if path == '/dev/null' else (stat.S_IFDIR | 0o1777))
    namespace = {'ROOT': PurePosixPath('/run/review'), 'mounts': [row.split() for row in base + extra], 'stat': stat,
                 'os': types.SimpleNamespace(W_OK=2, access=access, stat=metadata)}
    return eval(policy, namespace), calls
unmasked = ['11 5 0:10 / /dev/mqueue rw,nosuid,nodev,noexec - mqueue mqueue rw']
masked = ['11 5 0:10 / /dev/mqueue ro,nosuid,nodev,noexec - tmpfs tmpfs ro']
result, calls = admitted(unmasked, {'/dev/null', '/dev/mqueue'})
assert result is False and ('stat', '/dev/mqueue') in calls
result, calls = admitted(masked, {'/dev/null', '/dev/mqueue'})
assert result is True and not any(path == '/dev/mqueue' for _, path in calls)
assert admitted(masked + ['12 1 0:11 / /unexpected rw - tmpfs tmpfs rw'], {'/dev/null', '/unexpected'})[0] is False
assert admitted(masked, {'/dev/null', '/dev'})[0] is False
assert admitted(masked, {'/dev/null', '/dev/pts'})[0] is False
assert admitted(masked + ['12 5 0:11 / /dev/shm rw - tmpfs shm rw'], {'/dev/null', '/dev/shm'})[0] is False
print(json.dumps({'scenarios': 6, 'mountsOrNativeCalls': 0, 'predicateSourceIsUnchanged': True}))
`;

describe('controlled reviewer readonly mqueue mask', () => {
  it('retains the actual mount predicate and refuses writable directory siblings using fabricated mount rows', async () => {
    const result = await execute('python3', ['-B', '-I', '-S', '-c', reviewerMountPolicyHarness], {
      cwd: process.cwd(), timeout: 10_000, maxBuffer: 64 * 1024,
      env: { PATH: process.env.PATH ?? '/usr/bin:/bin', PYTHONDONTWRITEBYTECODE: '1' }
    });
    expect(JSON.parse(result.stdout)).toEqual({ scenarios: 6, mountsOrNativeCalls: 0, predicateSourceIsUnchanged: true });
  });
});
