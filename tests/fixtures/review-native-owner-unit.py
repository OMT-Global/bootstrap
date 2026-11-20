"""Pure/owned-process tests only. Linux cgroup/prctl qualification is not run."""
import ast
import contextlib
import importlib.util
import json
import os
import pathlib
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock
from types import SimpleNamespace

SOURCE = pathlib.Path(sys.argv.pop(1)).resolve()
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("review_native_owner_under_test", SOURCE)
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)


def frame_child():
    try:
        native.Frames(0).read(0.5)
    except Exception:
        return 1
    print("parsed")
    return 0


def barrier_child(payload, correct_parent):
    reader, writer = os.pipe()
    os.write(writer, payload)
    extra = os.open(os.devnull, os.O_RDONLY)
    values = {}
    class Executed(Exception):
        pass
    def pretend_exec(_file, _arguments, _environment):
        try:
            os.fstat(extra)
        except OSError:
            print("released-with-private-fds-closed")
            raise Executed()
        raise AssertionError("private descriptor survived")
    def set_limit(kind, value):
        values[kind] = value
    def get_limit(kind):
        return values.get(kind, (native.resource.RLIM_INFINITY, native.resource.RLIM_INFINITY))
    with tempfile.TemporaryDirectory(prefix="review-native-barrier-unit-") as directory:
        os.mkdir(directory + "/source")
        parent = os.getppid() if correct_parent else os.getppid() + 1
        try:
            with mock.patch.object(native, "prctl") as prctl, \
                    mock.patch.object(native.os, "environ", {"FIXTURE_MARKER": "fabricated"}), \
                    mock.patch.object(native.resource, "setrlimit", side_effect=set_limit), \
                    mock.patch.object(native.resource, "getrlimit", side_effect=get_limit), \
                    mock.patch.object(native.os, "execve", side_effect=pretend_exec):
                native.barrier(reader, writer, parent, ["/never-executed"], directory, time.monotonic() + 1)
        except Executed:
            return 0
        except native.Unsupported:
            print("denied")
            return 1
        finally:
            os.chdir(os.path.realpath("/tmp"))
            for fd in (reader, writer, extra):
                try:
                    os.close(fd)
                except OSError:
                    pass
    return 1


class ParserTests(unittest.TestCase):
    def test_membership_preserves_exact_path(self):
        self.assertEqual(native.membership("0::/bootstrap-g04-v1/u501/control\n"), "/bootstrap-g04-v1/u501/control")

    def test_membership_rejects_incomplete_or_multiple_hierarchies(self):
        for value in ("0::/x", "0::/x\r\n", "0::/x\n0::/y\n", "1:memory:/x\n", "0::/x\nextra"):
            with self.subTest(value=value), self.assertRaises(native.Unsupported):
                native.membership(value)

    def test_mount_identity_requires_one_full_root_cgroup_mount(self):
        line = "29 23 0:26 / /sys/fs/cgroup rw,nosuid - cgroup2 cgroup rw\n"
        self.assertEqual(native.mount_identity(line), 29)
        for value in (line + line, line.replace(" / /sys", " /nested /sys"),
                      line.replace("cgroup2", "tmpfs"), line.replace("/sys/fs/cgroup", "/other"), "malformed\n"):
            with self.subTest(value=value), self.assertRaises(Exception):
                native.mount_identity(value)

    def test_mount_metadata_cap_is_enforced(self):
        with self.assertRaises(native.Unsupported):
            native.mount_identity("x" * 1048577)

    def test_bounded_read_accepts_exact_cap_and_rejects_next_byte(self):
        with tempfile.TemporaryFile() as stream:
            stream.write(b"abcd")
            stream.flush()
            self.assertEqual(native.bounded(stream.fileno(), 4), b"abcd")
            with self.assertRaises(native.Unsupported):
                native.bounded(stream.fileno(), 3)

    def test_duplicate_object_keys_are_rejected(self):
        with self.assertRaises(native.Unsupported):
            native.unique_object([("v", 1), ("v", 1)])

    def test_wrong_host_denies_before_reading_kernel_metadata(self):
        with mock.patch.object(native.sys, "platform", "unsupported"), \
                mock.patch.object(native, "proc", side_effect=AssertionError("kernel read reached")):
            with self.assertRaises(native.Unsupported):
                native.host()


class MetadataEnvironmentUnitTests(unittest.TestCase):
    """All environment mappings and canonical paths are fabricated, never inherited."""
    def test_constructor_keeps_only_three_metadata_fields_and_fixed_task_paths(self):
        environment = {
            "CODEX_HOME": "/fixture/operator/.codex", "DBUS_SESSION_BUS_ADDRESS": "unix:path=/fixture/runtime/bus",
            "XDG_RUNTIME_DIR": "/fixture/runtime/user501", "HOME": "/fixture/wrong-home", "PATH": "/fixture/wrong-bin",
            "TMPDIR": "/fixture/wrong-temp", "XDG_CONFIG_HOME": "/fixture/wrong-xdg",
            "SSH_AUTH_SOCK": "/fixture/blocked-signer", "AWS_PROFILE": "fabricated-profile",
            "PYTHONPATH": "/fixture/blocked-python", "NODE_OPTIONS": "fabricated-options", "GIT_CONFIG_COUNT": "1",
        }
        with mock.patch.object(native.os, "environ", environment), \
                mock.patch.object(native.os.path, "realpath", side_effect=lambda value: value):
            result = native.helper_environment({"directory": "/fixture/workspace"})
        self.assertEqual(set(result), {"PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "TZ", "CODEX_HOME",
                                     "DBUS_SESSION_BUS_ADDRESS", "XDG_RUNTIME_DIR", "XDG_CACHE_HOME", "XDG_CONFIG_HOME",
                                     "XDG_DATA_HOME", "XDG_STATE_HOME"})
        self.assertEqual(result["CODEX_HOME"], environment["CODEX_HOME"])
        self.assertEqual(result["DBUS_SESSION_BUS_ADDRESS"], environment["DBUS_SESSION_BUS_ADDRESS"])
        self.assertEqual(result["XDG_RUNTIME_DIR"], environment["XDG_RUNTIME_DIR"])
        self.assertEqual(result["HOME"], "/fixture/workspace/runtime/home")
        self.assertEqual(result["TMPDIR"], "/fixture/workspace/runtime/tmp")
        self.assertEqual(result["XDG_CONFIG_HOME"], "/fixture/workspace/runtime/home/.config")
        self.assertEqual(result["PATH"], "/usr/local/bin:/usr/bin:/bin")

    def test_optional_metadata_absence_and_empty_values_preserve_presence(self):
        environment = {"CODEX_HOME": "/fixture/operator/.codex"}
        with mock.patch.object(native.os, "environ", environment), \
                mock.patch.object(native.os.path, "realpath", side_effect=lambda value: value):
            result = native.helper_environment({"directory": "/fixture/workspace"})
        self.assertNotIn("DBUS_SESSION_BUS_ADDRESS", result)
        self.assertNotIn("XDG_RUNTIME_DIR", result)
        environment.update({"DBUS_SESSION_BUS_ADDRESS": "", "XDG_RUNTIME_DIR": ""})
        with mock.patch.object(native.os, "environ", environment), \
                mock.patch.object(native.os.path, "realpath", side_effect=lambda value: value):
            result = native.helper_environment({"directory": "/fixture/workspace"})
        self.assertEqual(result["DBUS_SESSION_BUS_ADDRESS"], "")
        self.assertEqual(result["XDG_RUNTIME_DIR"], "")

    def test_unsupported_mode_presence_denies_before_any_value_or_path_read(self):
        names = ("OPENAI_API_KEY", "CODEX_API_KEY", "AZURE_OPENAI_API_KEY", "AZURE_OPENAI_ENDPOINT",
                 "OPENAI_BASE_URL", "OPENAI_ORGANIZATION", "OPENAI_PROJECT", "HTTP_PROXY", "HTTPS_PROXY",
                 "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy")
        class Environment(dict):
            def __getitem__(self, key):
                raise AssertionError("environment value was read before unsupported-mode rejection")
            def get(self, key, default=None):
                raise AssertionError("environment value was read before unsupported-mode rejection")
        for name in names:
            with self.subTest(name=name), \
                    mock.patch.object(native.os, "environ", Environment({name: object()})), \
                    mock.patch.object(native.os.path, "realpath", side_effect=AssertionError("path read")):
                with self.assertRaises(native.Unsupported):
                    native.helper_environment({"directory": "/fixture/workspace"})

    def test_missing_relative_noncanonical_or_workspace_codex_root_is_denied(self):
        for value in ("", "relative", "/fixture/workspace/auth"):
            with self.subTest(value=value), mock.patch.object(native.os, "environ", {"CODEX_HOME": value}), \
                    mock.patch.object(native.os.path, "realpath", side_effect=lambda path: path):
                with self.assertRaises(native.Unsupported):
                    native.helper_environment({"directory": "/fixture/workspace"})
        with mock.patch.object(native.os, "environ", {"CODEX_HOME": "/fixture/alias"}), \
                mock.patch.object(native.os.path, "realpath", return_value="/fixture/canonical"):
            with self.assertRaises(native.Unsupported):
                native.helper_environment({"directory": "/fixture/workspace"})


class CgroupOwnershipUnitTests(unittest.TestCase):
    """Fabricated descriptor/fsid/fdinfo checks; no Linux syscall is executed."""
    def test_directory_ownership_is_exact_but_trusted_root_controls_remain_allowed(self):
        class Library:
            def fstatfs(self, _descriptor, buffer):
                native.ctypes.cast(buffer, native.ctypes.POINTER(native.ctypes.c_long))[0] = 0x63677270
                return 0
        cases = [
            (True, 0, 501, False),
            (False, 0, 501, True),
            (False, 501, 501, True),
            (True, 0, 0, True),
            (True, 501, 501, True),
        ]
        for directory, actual_uid, declared_uid, allowed in cases:
            with self.subTest(directory=directory, actual_uid=actual_uid, declared_uid=declared_uid):
                kind = stat.S_IFDIR if directory else stat.S_IFREG
                metadata = SimpleNamespace(st_uid=actual_uid, st_mode=kind | 0o700)
                with mock.patch.object(native.os, "fstat", return_value=metadata), \
                        mock.patch.object(native.ctypes, "CDLL", return_value=Library()), \
                        mock.patch.object(native.os, "open", return_value=999), \
                        mock.patch.object(native.os, "close"), \
                        mock.patch.object(native, "bounded", return_value=b"pos: 0\nmnt_id: 123\n"):
                    if allowed:
                        native.cgroup_fd(777, 123, declared_uid, directory)
                    else:
                        with self.assertRaises(native.Unsupported):
                            native.cgroup_fd(777, 123, declared_uid, directory)


class FrameTests(unittest.TestCase):
    def pair(self):
        left, right = socket.socketpair()
        self.addCleanup(left.close)
        self.addCleanup(right.close)
        return native.Frames(left.fileno()), right

    def test_roundtrip_complete_object(self):
        receiver, sender = self.pair()
        sender.sendall(b'{"v":1,"type":"cancel"}\n')
        self.assertEqual(receiver.read(0.1), {"v": 1, "type": "cancel"})

    def test_fragmented_frame_survives_observation_timeout(self):
        receiver, sender = self.pair()
        sender.sendall(b'{"v":')
        self.assertIsNone(receiver.read(0.01))
        sender.sendall(b'1}\n')
        self.assertEqual(receiver.read(0.1), {"v": 1})

    def test_multiple_frames_remain_separate(self):
        receiver, sender = self.pair()
        sender.sendall(b'{"v":1}\n{"v":2}\n')
        self.assertEqual(receiver.read(0.1), {"v": 1})
        self.assertEqual(receiver.read(0.1), {"v": 2})

    def test_partial_eof_is_not_a_complete_frame(self):
        receiver, sender = self.pair()
        sender.sendall(b'{"v":1')
        sender.shutdown(socket.SHUT_WR)
        with self.assertRaises(EOFError):
            receiver.read(0.1)

    def test_frame_exact_cap_and_cap_plus_one(self):
        receiver, sender = self.pair()
        exact = b'{"x":"' + b'x' * (native.FRAME - 9) + b'"}\n'
        self.assertEqual(len(exact), native.FRAME)
        sender.sendall(exact)
        self.assertEqual(len(receiver.read(0.1)["x"]), native.FRAME - 9)
        sender.sendall(exact[:-2] + b'x}\n')
        with self.assertRaises(native.Unsupported):
            receiver.read(0.1)

    def test_receive_total_cap_counts_native_bytes(self):
        receiver, sender = self.pair()
        exact = b'{"x":"' + b'x' * (native.FRAME - 9) + b'"}\n'
        for _ in range(native.TOTAL // native.FRAME):
            sender.sendall(exact)
            receiver.read(0.1)
        self.assertEqual(receiver.received, native.TOTAL)
        sender.sendall(b'{}\n')
        with self.assertRaises(native.Unsupported):
            receiver.read(0.1)

    def test_send_total_cap_does_not_write_the_excess_frame(self):
        output, peer = self.pair()
        value = {"x": "x" * (native.FRAME - 9)}
        for _ in range(native.TOTAL // native.FRAME):
            output.send(value)
            received = bytearray()
            peer.settimeout(0.5)
            while len(received) < native.FRAME:
                received.extend(peer.recv(native.FRAME - len(received)))
            self.assertEqual(len(received), native.FRAME)
        with self.assertRaises(native.Unsupported):
            output.send({})
        peer.setblocking(False)
        with self.assertRaises(BlockingIOError):
            peer.recv(1)

    def test_malformed_frames_fail_in_real_owned_subprocesses(self):
        for value in (b'{"v":1,"v":1}\n', b'[]\n', b'null\n', b'{"x":"\xff"}\n', b'{broken}\n', b'{"v":1'):
            with self.subTest(value=value):
                result = subprocess.run([sys.executable, "-I", __file__, str(SOURCE), "--frame-child"],
                                        input=value, capture_output=True, timeout=3)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertEqual(result.stdout, b"")
        result = subprocess.run([sys.executable, "-I", __file__, str(SOURCE), "--frame-child"],
                                input=b'{"v":1}\n', capture_output=True, timeout=3)
        self.assertEqual((result.returncode, result.stdout), (0, b"parsed\n"), result.stderr)


class StartAndCleanupTests(unittest.TestCase):
    @contextlib.contextmanager
    def workspace(self):
        # Exclusive creation never replaces another task's similarly named directory.
        for _ in range(10):
            selected = pathlib.Path(os.path.realpath("/tmp")) / ("bootstrap-review-workspace-" + os.urandom(3).hex())
            try:
                selected.mkdir(mode=0o700)
                break
            except FileExistsError:
                pass
        else:
            raise AssertionError("could not reserve owned fixture directory")
        import shutil
        try:
            for relative in ("source/.git", "empty", "runtime/home", "runtime/tmp", "output"):
                path = selected / relative
                path.mkdir(parents=True, mode=0o700, exist_ok=True)
            for relative in ("", "source", "source/.git", "empty", "runtime", "runtime/home", "runtime/tmp", "output"):
                os.chmod(selected / relative, 0o700)
            yield selected
        finally:
            shutil.rmtree(selected)

    def record(self, directory):
        return {"v": 1, "type": "start", "directory": str(directory), "base": "a" * 40, "candidate": "b" * 40}

    def test_start_requires_exact_owned_layout_and_no_existing_reports(self):
        with self.workspace() as root:
            value = self.record(root)
            self.assertEqual(native.start_record(value), value)
            (root / "output/review.json").write_text("old result")
            with self.assertRaises(native.Unsupported):
                native.start_record(value)

    def test_start_rejects_extra_input_and_noncanonical_scalar_types(self):
        with self.workspace() as root:
            good = self.record(root)
            values = [dict(good, v=True), dict(good, command="ignored"), dict(good, base="A" * 40),
                      dict(good, candidate=123), dict(good, directory=str(root) + "/../" + root.name)]
            for value in values:
                with self.subTest(value=value), self.assertRaises(native.Unsupported):
                    native.start_record(value)

    def test_start_rejects_symlink_or_publicly_writable_owned_directory(self):
        with self.workspace() as root:
            output = root / "output"
            output.rename(root / "original-output")
            output.symlink_to(root / "original-output", target_is_directory=True)
            with self.assertRaises(native.Unsupported):
                native.start_record(self.record(root))
            output.unlink()
            (root / "original-output").rename(output)
            os.chmod(output, 0o755)
            with self.assertRaises(native.Unsupported):
                native.start_record(self.record(root))

    def test_failed_constructor_closes_owned_descriptors_and_removes_only_created_leaf(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = pathlib.Path(temporary)
            seen = []
            def fail(scope):
                scope.runs = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
                scope.fds.append(scope.runs)
                seen.append(scope.runs)
                scope.name = "owned-leaf"
                os.mkdir(scope.name, dir_fd=scope.runs)
                scope.created = True
                raise native.Unsupported()
            with mock.patch.object(native.Scope, "initialize", fail), self.assertRaises(native.Unsupported):
                native.Scope()
            self.assertFalse((parent / "owned-leaf").exists())
            with self.assertRaises(OSError):
                os.fstat(seen[0])

    def test_collision_never_adopts_or_removes_foreign_leaf(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = pathlib.Path(temporary)
            foreign = parent / "foreign"
            foreign.mkdir()
            def fail(scope):
                scope.runs = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
                scope.fds.append(scope.runs)
                scope.name = "foreign"
                raise FileExistsError()
            with mock.patch.object(native.Scope, "initialize", fail), self.assertRaises(FileExistsError):
                native.Scope()
            self.assertTrue(foreign.is_dir())

    def test_occupied_scope_is_not_removed(self):
        with tempfile.TemporaryDirectory() as temporary, tempfile.TemporaryFile() as events:
            path = pathlib.Path(temporary)
            (path / "owned").mkdir()
            events.write(b"populated 1\nfrozen 0\n")
            events.flush()
            scope = object.__new__(native.Scope)
            scope.events, scope.runs, scope.name, scope.removed = events.fileno(), os.open(path, os.O_RDONLY), "owned", False
            try:
                with self.assertRaises(native.Unsupported):
                    scope.remove()
                self.assertTrue((path / "owned").is_dir())
            finally:
                os.close(scope.runs)


class GuardianLimitUnitTests(unittest.TestCase):
    """Fabricated OS primitives test ordering, not Linux execution or containment."""
    def simulate(self, fault=None):
        events = []
        limits = {}
        class Scope:
            removed = False
            def attach(self, pid):
                events.append(("attach", pid))
            def stop(self):
                events.append(("stop",))
            def empty(self):
                return True
            def remove(self):
                self.removed = True
                events.append(("remove",))
        class Frames:
            def __init__(self, _descriptor):
                self.reads = iter((None, None, {"v": 1, "type": "removed"}))
            def read(self, _timeout):
                return next(self.reads)
            def send(self, value):
                events.append(("frame", value["type"]))
        def prlimit(pid, kind, value=None):
            events.append(("limit", kind, value))
            if value is not None:
                if fault == "write":
                    raise OSError("fabricated limit write failure")
                limits[kind] = value
            if fault == "readback" and kind == native.resource.RLIMIT_FSIZE and value is None:
                return (1, 1)
            if fault == "cpu" and kind == native.resource.RLIMIT_CPU:
                return (60, 60)
            return limits.get(kind, (native.resource.RLIM_INFINITY, native.resource.RLIM_INFINITY))
        def release(_descriptor, value):
            events.append(("release", value))
            return len(value)
        reaps = iter((([(123, 0)], True), ([], True)))
        with mock.patch.object(native, "prctl"), \
                mock.patch.object(native, "Frames", Frames), \
                mock.patch.object(native, "reap", side_effect=lambda: next(reaps)), \
                mock.patch.object(native.os, "fork", return_value=123), \
                mock.patch.object(native.os, "pipe2", side_effect=lambda _flags: os.pipe(), create=True), \
                mock.patch.object(native.os, "write", side_effect=release), \
                mock.patch.object(native.resource, "prlimit", side_effect=prlimit, create=True):
            result = native.guardian(Scope(), 99, ["/not-executed"], "/unused", time.monotonic() + 1)
        return result, events

    def test_all_selected_child_limits_are_checked_before_release(self):
        result, events = self.simulate()
        self.assertEqual(result, 0)
        release = events.index(("release", b"R"))
        self.assertLess(events.index(("attach", 123)), release)
        for kind in (native.resource.RLIMIT_FSIZE, native.resource.RLIMIT_CORE,
                     native.resource.RLIMIT_CPU, native.resource.RLIMIT_AS):
            self.assertTrue(any(event[:2] == ("limit", kind) and event[2] is None for event in events[:release]))
        self.assertEqual([event for event in events if event[0] == "frame"], [("frame", "started"), ("frame", "drained")])

    def test_failed_limit_or_short_cpu_precondition_never_releases_helper(self):
        for fault in ("write", "readback", "cpu"):
            with self.subTest(fault=fault):
                result, events = self.simulate(fault)
                self.assertEqual(result, 1)
                self.assertFalse(any(event[0] == "release" for event in events))
                self.assertIn(("stop",), events)
                self.assertIn(("remove",), events)


class CallerFailureUnitTests(unittest.TestCase):
    """Fabricated child/kernel primitives verify only caller withdrawal sequencing."""
    def test_cancel_kills_only_unreaped_guardian_before_claiming_owned_drain(self):
        events = []
        clock = [100.0]
        child = {"alive": True, "reaped": False}
        class Scope:
            removed = False
            def stop(self):
                events.append(("leaf-kill",))
            def empty(self):
                return True
            def remove(self):
                self.removed = True
                events.append(("leaf-remove",))
            def close(self):
                events.append(("controls-close",))
        scope = Scope()
        class Socket:
            def __init__(self, fd):
                self.fd = fd
            def close(self):
                pass
            def detach(self):
                return self.fd
        class Frames:
            def __init__(self, fd):
                self.fd = fd
                self.reads = 0
            def send(self, value):
                events.append(("frame", value["type"]))
            def read(self, _timeout):
                self.reads += 1
                if self.fd == 3:
                    return {"v": 1, "type": "start"} if self.reads == 1 else {"v": 1, "type": "cancel"}
                return {"v": 1, "type": "started", "helper": 456}
        def waitpid(pid, flags):
            self.assertIn(pid, (123, -1))
            self.assertEqual(flags, os.WNOHANG)
            events.append(("wait", pid))
            if child["alive"]:
                return 0, 0
            if not child["reaped"]:
                child["reaped"] = True
                return 123, signal.SIGKILL
            raise ChildProcessError()
        def kill(pid, selected_signal):
            self.assertEqual((pid, selected_signal), (123, signal.SIGKILL))
            self.assertFalse(child["reaped"])
            child["alive"] = False
            events.append(("guardian-kill",))
        def advance(_seconds):
            clock[0] += 1.0
        with mock.patch.object(native.sys, "argv", [str(SOURCE)]), \
                mock.patch.object(native, "Frames", Frames), \
                mock.patch.object(native, "start_record", return_value={"directory": "/unused"}), \
                mock.patch.object(native, "helper_arguments", return_value=["/never-executed"]), \
                mock.patch.object(native, "helper_environment", return_value={"FIXTURE_MARKER": "fabricated"}), \
                mock.patch.object(native.os, "environ", {}), \
                mock.patch.object(native, "Scope", return_value=scope), \
                mock.patch.object(native, "prctl"), \
                mock.patch.object(native.socket, "socketpair", return_value=(Socket(11), Socket(12))), \
                mock.patch.object(native.os, "fork", return_value=123), \
                mock.patch.object(native.os, "waitpid", side_effect=waitpid), \
                mock.patch.object(native.os, "kill", side_effect=kill), \
                mock.patch.object(native.os, "close"), \
                mock.patch.object(native.time, "monotonic", side_effect=lambda: clock[0]), \
                mock.patch.object(native.time, "sleep", side_effect=advance):
            with self.assertRaises(native.Unsupported):
                native.main()
        self.assertIn(("guardian-kill",), events)
        self.assertTrue(child["reaped"])
        self.assertTrue(scope.removed)
        self.assertLess(events.index(("wait", 123)), events.index(("guardian-kill",)))
        self.assertFalse(any(event == ("frame", "complete") for event in events))


class ProcessTests(unittest.TestCase):
    def test_actual_owned_child_wait_status_is_observed(self):
        child = os.fork()
        if child == 0:
            os._exit(7)
        status = native.wait_guardian(child, time.monotonic() + 2)
        self.assertEqual(os.waitstatus_to_exitcode(status), 7)
        with self.assertRaises(ChildProcessError):
            os.waitpid(child, os.WNOHANG)

    def test_expired_wait_kills_only_the_held_unreaped_child_and_reports_failure(self):
        child = os.fork()
        if child == 0:
            time.sleep(5)
            os._exit(0)
        try:
            with self.assertRaises(native.Unsupported):
                native.wait_guardian(child, time.monotonic())
            found, status = os.waitpid(child, 0)
            self.assertEqual(found, child)
            self.assertEqual(os.waitstatus_to_exitcode(status), -signal.SIGKILL)
        finally:
            try:
                found, _ = os.waitpid(child, os.WNOHANG)
                if not found:
                    os.kill(child, signal.SIGKILL)
                    os.waitpid(child, 0)
            except ChildProcessError:
                pass

    def test_barrier_requires_release_byte_and_eof_before_its_fixed_exec_boundary(self):
        for payload, expected in ((b"R", 0), (b"", 1), (b"RR", 1), (b"RX", 1), (b"Rextra", 1)):
            with self.subTest(payload=payload):
                result = subprocess.run([sys.executable, "-I", __file__, str(SOURCE), "--barrier-child", payload.hex(), "valid"],
                                        capture_output=True, timeout=3)
                self.assertEqual(result.returncode, expected, result.stderr)
                self.assertEqual(result.stdout, b"released-with-private-fds-closed\n" if expected == 0 else b"denied\n")

    def test_barrier_parent_mismatch_denies_even_with_valid_release(self):
        result = subprocess.run([sys.executable, "-I", __file__, str(SOURCE), "--barrier-child", "52", "wrong"],
                                capture_output=True, timeout=3)
        self.assertEqual((result.returncode, result.stdout), (1, b"denied\n"), result.stderr)

    def test_entrypoint_propagates_clean_and_failed_main_status(self):
        tree = ast.parse(SOURCE.read_text())
        entry = tree.body[-1]
        self.assertIsInstance(entry, ast.If)
        program = compile(ast.Module(body=[entry], type_ignores=[]), str(SOURCE), "exec")
        for code in (0, 1):
            with self.subTest(code=code), self.assertRaises(SystemExit) as result:
                exec(program, {"__name__": "__main__", "main": lambda: code})
            self.assertEqual(result.exception.code, code)
        def fail():
            raise RuntimeError("fabricated failure")
        with self.assertRaises(SystemExit) as result:
            exec(program, {"__name__": "__main__", "main": fail})
        self.assertEqual(result.exception.code, 1)


class ProfileTests(unittest.TestCase):
    def test_current_fixed_review_arguments(self):
        record = {"directory": "/fixture/workspace", "base": "a" * 40, "candidate": "b" * 40}
        with mock.patch.dict(native.os.environ, {"CODEX_HOME": "/fixture/codex"}, clear=True), \
                mock.patch.object(native.os.path, "realpath", side_effect=lambda value: value), \
                mock.patch.object(native, "trusted_file", side_effect=lambda value, *args, **kwargs: value), \
                mock.patch.object(native.os, "open", return_value=42), \
                mock.patch.object(native.os, "close"), \
                mock.patch.object(native, "bounded", return_value=b"fabricated helper"), \
                mock.patch.object(native.hashlib, "sha256") as digest:
            digest.return_value.hexdigest.return_value = native.HELPER_SHA256
            arguments = native.helper_arguments(record)
        self.assertEqual(arguments[arguments.index("--model") + 1], "gpt-6.1-sol")
        self.assertEqual(arguments[arguments.index("--thinking") + 1], "high")
        self.assertIn("--codex-no-fallback", arguments)
        self.assertEqual(arguments[arguments.index("--max-priority") + 1], "P3")
        self.assertEqual(arguments[arguments.index("--status-output") + 1], "/fixture/workspace/output/status.json")
        self.assertNotIn("resume", arguments)


if __name__ == "__main__":
    if sys.argv[1:2] == ["--frame-child"]:
        raise SystemExit(frame_child())
    if sys.argv[1:2] == ["--barrier-child"]:
        raise SystemExit(barrier_child(bytes.fromhex(sys.argv[2]), sys.argv[3] == "valid"))
    unittest.main(verbosity=2)
