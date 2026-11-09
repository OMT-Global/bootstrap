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
                if case == 'sandbox':
                    self.assertEqual(set(emitted[0]), {'event', 'case', 'ok', 'phase', 'reason', 'providerRequests', 'sandboxFailure'})
                    self.assertEqual(emitted[0]['sandboxFailure'], {'stage': 'gate'})
                else:
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

const fixtureDiscriminatorHarness = String.raw`import argparse
import ast
import hashlib
import json
from pathlib import Path, PurePosixPath
import sys
import types
import unittest
from unittest import mock
import io

SOURCE = Path(sys.argv[1]) if len(sys.argv) > 1 else Path('scripts/ci/controlled-reviewer-fixture.py')
MODE = sys.argv[2] if len(sys.argv) > 2 else 'current'
TEXT = SOURCE.read_text()
TREE = ast.parse(TEXT)
FUNCTIONS = [node for node in TREE.body if isinstance(node, ast.FunctionDef) and
             node.name in {'require', 'sandbox_stage', 'policy', 'sandbox', 'run_case'}]
ENTRY_NODE = next(node for node in TREE.body if isinstance(node, ast.If) and
                  ast.unparse(node.test) == "__name__ == '__main__'")
ENTRY = compile(ast.Module(body=[ENTRY_NODE], type_ignores=[]), str(SOURCE), 'exec')
DEFINITIONS = compile(ast.Module(body=FUNCTIONS, type_ignores=[]), str(SOURCE), 'exec')
CASES = ast.literal_eval(next(node.value for node in TREE.body if isinstance(node, ast.Assign) and
                             any(isinstance(target, ast.Name) and target.id == 'CASES' for target in node.targets)))
STAGES = ('gate', 'dispatch', 'version-call', 'version-exit', 'version-stdout', 'version-stderr',
          'workspace-setup', 'loopback-control', 'sandbox-call', 'sandbox-exit', 'listener-postcheck', 'listener-close')
CANARY = 'private-discriminator-canary'
OBSERVATIONS = []
EXPECTED_POLICY = ['--ask-for-approval', 'never', '-c', 'cli_auth_credentials_store="file"',
                   '-c', 'project_doc_max_bytes=0', '-c', 'features.hooks=false', '-c', 'features.plugins=false',
                   '-c', 'features.shell_snapshot=false', '-c', 'skills.include_instructions=false',
                   '-c', 'skills.config=[]', '-c', 'allow_login_shell=false', '-c', 'default_permissions="autoreview"',
                   '-c', 'permissions.autoreview.filesystem={":minimal"="read",":workspace_roots"="read"}',
                   '-c', 'permissions.autoreview.network.enabled=false', '-c', 'sqlite_home="/run/review/state"',
                   '-c', 'log_dir="/run/review/log"']
EXPECTED_COMMAND = """from pathlib import Path
import socket
assert Path('public').read_text() == 'public fixture'
for operation in [lambda: Path('/synthetic/private/canary').read_bytes(), lambda: Path('forbidden').write_text('x'), lambda: socket.create_connection(('127.0.0.1', 31337), timeout=1)]:
    try: operation()
    except OSError: pass
    else: raise RuntimeError('sandbox boundary failed')
"""


class PrimaryFailure(RuntimeError):
    pass


class CloseFailure(OSError):
    pass


def exercise(fault='success', code=7, case='sandbox', direct=False, stale=False):
    state = {'nativeCalls': [], 'writes': [], 'socketCalls': [], 'gateCalls': 0,
             'stdoutStrips': 0, 'stderrComparisons': 0, 'forbiddenCalls': [], 'emitted': []}
    primary, closing = PrimaryFailure(CANARY), CloseFailure(CANARY)

    def forbidden(*args, **kwargs):
        state['forbiddenCalls'].append(True)
        raise AssertionError('real native/resource/socket/provider work is forbidden')

    class Forbidden:
        def __getattr__(self, name):
            return forbidden

    class FakePath(PurePosixPath):
        def write_text(self, value):
            state['writes'].append(str(self))
            if (fault == 'public-write' and self.name == 'public') or (fault == 'private-write' and self.name == 'canary'):
                raise primary
            return len(value)

    class Output:
        def strip(self):
            state['stdoutStrips'] += 1
            if fault == 'version-code':
                raise AssertionError('stdout evaluated after failed version exit')
            return b'wrong-' + CANARY.encode() if fault == 'version-stdout' else b'codex-cli 0.167.0'

    class ErrorOutput(bytes):
        def __new__(cls):
            value = (b'WARNING: proceeding, even though we could not create PATH aliases: ' + CANARY.encode()
                     if fault == 'version-warning' else CANARY.encode() if fault == 'version-stderr' else b'')
            return super().__new__(cls, value)
        def __eq__(self, other):
            state['stderrComparisons'] += 1
            if fault in ('version-code', 'version-stdout'):
                raise AssertionError('stderr evaluated before earlier version admission')
            return super().__eq__(other)

    class Connection:
        def close(self):
            state['socketCalls'].append('connection-close')

    class Listener:
        accepts = 0
        def bind(self, address):
            state['socketCalls'].append('bind')
            if fault == 'socket-bind':
                raise primary
        def listen(self):
            state['socketCalls'].append('listen')
        def getsockname(self):
            state['socketCalls'].append('getsockname')
            return ('127.0.0.1', 31337)
        def accept(self):
            self.accepts += 1
            state['socketCalls'].append('accept-' + str(self.accepts))
            if self.accepts == 1:
                if fault == 'socket-accept':
                    raise primary
                return Connection(), ('127.0.0.1', 31338)
            if fault in ('listener-error', 'close-after-postcheck'):
                raise primary
            if fault == 'listener-escaped':
                return Connection(), ('127.0.0.1', 31338)
            raise TimeoutError('synthetic postcheck timeout')
        def settimeout(self, timeout):
            state['socketCalls'].append('settimeout')
            assert timeout == 0.1
            if fault == 'listener-settimeout':
                raise primary
        def close(self):
            state['socketCalls'].append('listener-close')
            if fault in ('close-after-native', 'close-after-code', 'close-after-success', 'close-after-postcheck'):
                raise closing

    listener = Listener()
    def socket():
        state['socketCalls'].append('socket')
        if fault == 'socket-create':
            raise primary
        return listener
    def connect(address, timeout):
        state['socketCalls'].append('connect')
        assert address == ('127.0.0.1', 31337) and timeout == 1
        if fault == 'socket-connect':
            raise primary
        return Connection()

    def native(args, input_bytes=b'', cap=16384):
        state['nativeCalls'].append(list(args))
        assert input_bytes == b'' and cap == 16384
        if len(state['nativeCalls']) == 1:
            assert args == ['--version']
            if fault == 'version-call':
                raise primary
            result = code if fault == 'version-code' else 0
            return result, Output(), ErrorOutput()
        assert len(state['nativeCalls']) == 2
        assert args == [*EXPECTED_POLICY, 'sandbox', '--permission-profile', 'autoreview', '--cd',
                        '/synthetic/workspace', '--', '/usr/bin/python3', '-I', '-S', '-c', EXPECTED_COMMAND]
        if fault in ('sandbox-call', 'close-after-native'):
            raise primary
        return (code if fault in ('sandbox-code', 'close-after-code') else 0), CANARY.encode(), CANARY.encode()

    def gate():
        state['gateCalls'] += 1
        if fault == 'gate':
            raise primary

    emitted = state['emitted']
    emit_calls = 0
    def emit(value):
        nonlocal emit_calls
        emit_calls += 1
        if fault == 'success-emit' and emit_calls == 1:
            raise primary
        emitted.append(json.loads(json.dumps(value)))

    namespace = {'__name__': '__main__', 'argparse': argparse, 'sys': sys,
                 'ROOT': FakePath('/synthetic'), 'SOURCE': FakePath('/synthetic/auth.json'),
                 'CASES': CASES, 'MOCK_REQUESTS': 0, 'ADMISSION': {'stage': 'ready'},
                 'SANDBOX_FAILURE': {'stage': 'sandbox-exit', 'exitCode': 9} if stale else {},
                 'socket': types.SimpleNamespace(socket=socket, create_connection=connect),
                 'native': native, 'gate': gate, 'emit': emit, 'subprocess': Forbidden(),
                 'resource': Forbidden(), 'http': Forbidden(), 'urllib': Forbidden(), 'os': Forbidden()}
    exec(DEFINITIONS, namespace)
    if fault == 'policy-build':
        namespace['policy'] = lambda: (_ for _ in ()).throw(primary)
    if fault == 'dispatch':
        namespace['run_case'] = lambda case: (_ for _ in ()).throw(primary)
    if fault == 'non-sandbox-success':
        namespace['run_case'] = lambda case: {'providerRequests': 0}

    caught = None
    if direct:
        try:
            namespace['sandbox']()
        except BaseException as error:
            caught = error
    else:
        with mock.patch.object(sys, 'argv', ['synthetic-fixture', '--case', case]):
            try:
                exec(ENTRY, namespace)
            except SystemExit as error:
                assert error.code == 1
    assert not state['forbiddenCalls']
    state.update(snapshot=namespace['SANDBOX_FAILURE'].copy(), caught=caught,
                 primary=primary, closing=closing, namespace=namespace)
    if not direct:
        assert len(emitted) == 1
        assert CANARY not in json.dumps(emitted) and '/synthetic' not in json.dumps(emitted)
        OBSERVATIONS.append({'fault': fault, 'case': case, 'ok': emitted[0]['ok'],
                             'sandboxFailure': emitted[0].get('sandboxFailure'),
                             'mockedNativeCalls': len(state['nativeCalls']), 'actualUnsafeCalls': 0})
    return state


class SandboxDiscriminatorTests(unittest.TestCase):
    def failure(self, fault, stage, expected_code=None, **kwargs):
        result = exercise(fault, **kwargs)
        event = result['emitted'][0]
        self.assertEqual({k: event[k] for k in ('event', 'case', 'ok', 'phase', 'reason', 'providerRequests')},
                         {'event': 'result', 'case': 'sandbox', 'ok': False, 'phase': 'native-sandbox',
                          'reason': 'unsupported', 'providerRequests': 0})
        expected = {'stage': stage}
        if expected_code is not None:
            expected['exitCode'] = expected_code
        if MODE == 'legacy-comparison':
            self.assertEqual(set(event), {'event', 'case', 'ok', 'phase', 'reason', 'providerRequests'})
            self.assertNotIn('sandboxFailure', event)
        else:
            self.assertEqual(set(event), {'event', 'case', 'ok', 'phase', 'reason', 'providerRequests', 'sandboxFailure'})
            self.assertEqual(event['sandboxFailure'], expected)
            self.assertEqual(result['snapshot'], expected)
        return result

    def test_failure_version_helper_raise_has_no_exit_or_setup(self):
        value = self.failure('version-call', 'version-call')
        self.assertEqual(value['nativeCalls'], [['--version']])
        self.assertEqual(value['writes'], [])
        self.assertEqual(value['socketCalls'], [])

    def test_failure_version_exit_codes_preserve_short_circuit(self):
        for code in (1, -15, 255, -255):
            with self.subTest(code=code):
                value = self.failure('version-code', 'version-exit', expected_code=code, code=code)
                self.assertEqual((value['stdoutStrips'], value['stderrComparisons']), (0, 0))
                self.assertEqual(len(value['nativeCalls']), 1)
                self.assertEqual(value['writes'], [])

    def test_failure_version_stdout_prevents_stderr_and_stale_zero(self):
        value = self.failure('version-stdout', 'version-stdout')
        self.assertEqual((value['stdoutStrips'], value['stderrComparisons']), (1, 0))
        self.assertEqual(value['writes'], [])

    def test_failure_nonempty_stderr_and_path_warning_stay_private(self):
        for fault in ('version-stderr', 'version-warning'):
            with self.subTest(fault=fault):
                value = self.failure(fault, 'version-stderr')
                self.assertEqual((value['stdoutStrips'], value['stderrComparisons']), (1, 1))
                self.assertEqual(value['writes'], [])

    def test_failure_workspace_setup_has_no_stale_exit_or_socket(self):
        for fault in ('public-write', 'private-write'):
            with self.subTest(fault=fault):
                value = self.failure(fault, 'workspace-setup')
                self.assertEqual(len(value['nativeCalls']), 1)
                self.assertEqual(value['socketCalls'], [])

    def test_failure_socket_controls_have_no_second_native_or_close_move(self):
        for fault in ('socket-create', 'socket-bind', 'socket-connect', 'socket-accept'):
            with self.subTest(fault=fault):
                value = self.failure(fault, 'loopback-control')
                self.assertEqual(len(value['nativeCalls']), 1)
                self.assertNotIn('listener-close', value['socketCalls'])

    def test_failure_second_native_or_policy_raise_clears_prior_code(self):
        for fault, calls in (('sandbox-call', 2), ('policy-build', 1)):
            with self.subTest(fault=fault):
                value = self.failure(fault, 'sandbox-call')
                self.assertEqual(len(value['nativeCalls']), calls)
                self.assertEqual(value['socketCalls'][-1], 'listener-close')

    def test_failure_second_native_nonzero_survives_successful_close(self):
        for code in (7, -9):
            with self.subTest(code=code):
                value = self.failure('sandbox-code', 'sandbox-exit', expected_code=code, code=code)
                self.assertEqual(value['socketCalls'][-1], 'listener-close')
                self.assertEqual(len(value['nativeCalls']), 2)

    def test_failure_postcheck_error_or_escape_has_no_stale_exit(self):
        for fault in ('listener-settimeout', 'listener-error', 'listener-escaped'):
            with self.subTest(fault=fault):
                value = self.failure(fault, 'listener-postcheck')
                self.assertEqual(value['socketCalls'][-1], 'listener-close')

    def test_failure_gate_and_dispatch_do_not_claim_native_entry(self):
        for fault in ('gate', 'dispatch'):
            with self.subTest(fault=fault):
                value = self.failure(fault, fault)
                self.assertEqual(value['gateCalls'], 1)
                self.assertEqual(value['nativeCalls'], [])
                self.assertEqual(value['writes'], [])

    def test_close_exception_precedence_matches_actual_sandbox(self):
        for fault in ('close-after-native', 'close-after-code', 'close-after-success', 'close-after-postcheck'):
            with self.subTest(fault=fault):
                value = exercise(fault, direct=True)
                self.assertIs(value['caught'], value['closing'])
                self.assertEqual(value['snapshot'], {'stage': 'listener-close'})
                self.failure(fault, 'listener-close')
        value = exercise('sandbox-call', direct=True)
        self.assertIs(value['caught'], value['primary'])
        self.assertEqual(value['snapshot'], {'stage': 'sandbox-call'})

    def test_successful_actual_sandbox_and_handler_have_exact_legacy_fields(self):
        value = exercise()
        self.assertEqual(value['emitted'], [{'event': 'result', 'case': 'sandbox', 'ok': True,
                                           'phase': 'sandbox', 'providerRequests': 0}])
        self.assertEqual(value['snapshot'], {})
        self.assertEqual(value['namespace']['policy'](), EXPECTED_POLICY)
        self.assertEqual(len(value['nativeCalls']), 2)

    def test_entry_reset_omits_stale_stage_from_all_other_cases(self):
        for case in CASES:
            if case == 'sandbox':
                continue
            with self.subTest(case=case):
                failed = exercise('gate', case=case, stale=True)
                self.assertEqual(set(failed['emitted'][0]), {'event', 'case', 'ok', 'phase', 'reason', 'providerRequests'})
                self.assertEqual(failed['snapshot'], {})
                self.assertEqual(failed['nativeCalls'], [])
                success = exercise('non-sandbox-success', case=case, stale=True)
                self.assertEqual(success['emitted'], [{'event': 'result', 'case': case, 'ok': True,
                                                     'phase': case, 'providerRequests': 0}])
                self.assertEqual(success['snapshot'], {})

    def test_success_clears_stage_before_a_later_emit_failure(self):
        value = exercise('success-emit')
        self.assertEqual(set(value['emitted'][0]), {'event', 'case', 'ok', 'phase', 'reason', 'providerRequests'})
        self.assertEqual(value['snapshot'], {})
        self.assertEqual(len(value['nativeCalls']), 2)

    def test_setter_replaces_map_and_omits_non_builtin_or_unbounded_codes(self):
        namespace = exercise()['namespace']
        setter = namespace['sandbox_stage']
        class Integer(int):
            pass
        for code in (-256, 256, True, False, '7', 1.0, None, Integer(7), object()):
            with self.subTest(codeType=type(code).__name__):
                setter('version-exit', code)
                self.assertEqual(namespace['SANDBOX_FAILURE'], {'stage': 'version-exit'})
        for stage in STAGES:
            setter('sandbox-exit', -255)
            self.assertEqual(namespace['SANDBOX_FAILURE'], {'stage': 'sandbox-exit', 'exitCode': -255})
            setter(stage, 255)
            expected = {'stage': stage, **({'exitCode': 255} if stage in ('version-exit', 'sandbox-exit') else {})}
            self.assertEqual(namespace['SANDBOX_FAILURE'], expected)
        additions = []
        for stage in STAGES:
            values = [{'stage': stage}]
            if stage in ('version-exit', 'sandbox-exit'):
                values += [{'stage': stage, 'exitCode': code} for code in (-255, 0, 255)]
            additions += [len((',"sandboxFailure":' + json.dumps(value, separators=(',', ':'))).encode()) for value in values]
        self.assertEqual(max(additions), 58)

    def test_failure_unexpected_return_codes_never_serialize_objects(self):
        class Integer(int):
            pass
        for fault, stage in (('version-code', 'version-exit'), ('sandbox-code', 'sandbox-exit')):
            for code in (True, -256, 256, Integer(7), CANARY):
                with self.subTest(fault=fault, codeType=type(code).__name__):
                    self.failure(fault, stage, **{'code': code})


suite = unittest.defaultTestLoader.loadTestsFromTestCase(SandboxDiscriminatorTests)
if MODE in ('comparison', 'legacy-comparison'):
    suite = unittest.TestSuite(test for test in suite if test._testMethodName.startswith('test_failure_') and
                               test._testMethodName != 'test_failure_unexpected_return_codes_never_serialize_objects')
log = io.StringIO()
result = unittest.TextTestRunner(stream=log).run(suite)
print(json.dumps({'testCases': result.testsRun, 'ok': result.wasSuccessful(), 'sourceSha256': hashlib.sha256(TEXT.encode()).hexdigest(),
                  'failureCount': len(result.failures), 'errorCount': len(result.errors),
                  'observations': OBSERVATIONS, 'actualNativeResourceSocketProviderCalls': 0,
                  'mode': MODE}))
if not result.wasSuccessful():
    print(log.getvalue(), file=sys.stderr)
    sys.exit(1)
`;

describe("controlled reviewer pre-auth sandbox failure discriminator", () => {
  it("executes actual sandbox and handler transitions with only fabricated native, filesystem and socket work", async () => {
    const result = await execute("python3", ["-B", "-I", "-S", "-c", fixtureDiscriminatorHarness], {
      cwd: process.cwd(), timeout: 10_000, maxBuffer: 256 * 1024,
      env: { PATH: process.env.PATH ?? "/usr/bin:/bin", PYTHONDONTWRITEBYTECODE: "1" }
    });
    const report = JSON.parse(result.stdout);
    expect(report).toMatchObject({ testCases: 16, ok: true, actualNativeResourceSocketProviderCalls: 0, mode: "current" });
    expect(new Set(report.observations.flatMap((value: { sandboxFailure?: { stage: string } }) =>
      value.sandboxFailure ? [value.sandboxFailure.stage] : []))).toEqual(new Set([
      "gate", "dispatch", "version-call", "version-exit", "version-stdout", "version-stderr", "workspace-setup",
      "loopback-control", "sandbox-call", "sandbox-exit", "listener-postcheck", "listener-close"
    ]));
    expect(report.observations.every((value: { actualUnsafeCalls: number }) => value.actualUnsafeCalls === 0)).toBe(true);
    expect(JSON.stringify(report)).not.toContain("private-discriminator-canary");
    expect(JSON.stringify(report)).not.toContain("/synthetic");
  });
});
