#!/usr/bin/python3
"""Private G04 Linux owner. Fixed helper only; no imported completion authority."""
import ctypes
import hashlib
import json
import os
import platform
import re
import resource
import select
import signal
import socket
import stat
import sys
import time

PROFILE = "bootstrap-g04-linux-cgroup-v1"
HELPER_SHA256 = "fa51b49fb8e835f314a3dc8a94f01c143222386daee9fd10c6609a4fe5d282f3"
FRAME = 4096
TOTAL = 131072
META = 65536
STARTUP = 5.0
CLEANUP = 30.0
VALUES = {"memory.max": "4294967296", "memory.swap.max": "0", "memory.oom.group": "1",
          "pids.max": "256", "cgroup.max.depth": "0", "cgroup.max.descendants": "0"}


class Unsupported(Exception):
    pass


def require(condition):
    if not condition:
        raise Unsupported()


def bounded(fd, limit=META):
    os.lseek(fd, 0, os.SEEK_SET)
    data = bytearray()
    while len(data) <= limit:
        part = os.read(fd, min(65536, limit + 1 - len(data)))
        if not part:
            break
        data.extend(part)
    require(len(data) <= limit)
    return bytes(data)


def proc(name, pid=None, limit=META):
    require(name in ("cgroup", "mountinfo", "status") and (pid is None or type(pid) is int and pid > 0))
    fd = os.open("/proc/" + str(pid or os.getpid()) + "/" + name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        return bounded(fd, limit).decode("ascii", "strict")
    finally:
        os.close(fd)


def membership(text):
    require(len(text.encode()) <= META and re.fullmatch(r"0::/[^\r\n]*\n", text) is not None)
    return text[3:-1]


def mount_identity(text):
    require(len(text.encode()) <= 1048576)
    found = []
    for line in text.splitlines():
        fields = line.split(" ")
        require("-" in fields and len(fields) >= 10)
        split = fields.index("-")
        if fields[4] == "/sys/fs/cgroup":
            require(fields[3] == "/" and fields[split + 1] == "cgroup2" and fields[0].isdigit())
            found.append(int(fields[0]))
    require(len(found) == 1)
    return found[0]


def host():
    require(sys.platform == "linux" and platform.machine() == "x86_64" and os.getuid() != 0)
    require(os.getuid() == os.geteuid() and os.getgid() == os.getegid())
    text = proc("status")
    uid = re.search(r"^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)$", text, re.M)
    require(uid is not None and all(int(value) == os.getuid() for value in uid.groups()))
    for name in ("CapInh", "CapPrm", "CapEff", "CapAmb"):
        require(re.search(r"^" + name + r":\s+0+$", text, re.M) is not None)
    for kind in (resource.RLIMIT_CPU, resource.RLIMIT_AS):
        require(resource.getrlimit(kind) == (resource.RLIM_INFINITY, resource.RLIM_INFINITY))
    return os.getuid()


def prctl(kind, value):
    libc = ctypes.CDLL(None, use_errno=True)
    require(libc.prctl(ctypes.c_int(kind), ctypes.c_ulong(value), 0, 0, 0) == 0)


def open_beneath(directory, relative, flags):
    require(type(relative) is str and relative and not relative.startswith("/") and
            all(part not in ("", ".", "..") for part in relative.split("/")))
    class How(ctypes.Structure):
        _fields_ = [("flags", ctypes.c_uint64), ("mode", ctypes.c_uint64), ("resolve", ctypes.c_uint64)]
    how = How(flags | os.O_CLOEXEC | os.O_NOFOLLOW, 0, 0x08 | 0x04 | 0x02)
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    result = libc.syscall(437, directory, relative.encode("ascii"), ctypes.byref(how), ctypes.sizeof(how))
    if result < 0:
        raise Unsupported()
    return result


def cgroup_fd(fd, mount_id, uid, directory=False):
    info = os.fstat(fd)
    require((info.st_uid == uid if directory else info.st_uid in (0, uid)) and not info.st_mode & 0o022 and
            (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)))
    buffer = ctypes.create_string_buffer(512)
    libc = ctypes.CDLL(None, use_errno=True)
    require(libc.fstatfs(fd, ctypes.byref(buffer)) == 0 and
            ctypes.c_long.from_buffer(buffer).value == 0x63677270)
    descriptor = os.open("/proc/" + str(os.getpid()) + "/fdinfo/" + str(fd), os.O_RDONLY | os.O_CLOEXEC)
    try:
        match = re.search(rb"^mnt_id:\s+(\d+)$", bounded(descriptor), re.M)
        require(match is not None and int(match[1]) == mount_id)
    finally:
        os.close(descriptor)


class Scope:
    """Real opened control descriptors, never a serialized path capability."""
    def __init__(self):
        self.fds = []
        self.name = None
        self.removed = False
        self.created = False
        try:
            self.initialize()
        except BaseException:
            try:
                if self.created:
                    os.rmdir(self.name, dir_fd=self.runs)
            finally:
                self.close()
            raise

    def initialize(self):
        self.uid = host()
        self.path = "/bootstrap-g04-v1/u" + str(self.uid)
        require(membership(proc("cgroup")) == self.path + "/control")
        self.mount = mount_identity(proc("mountinfo", limit=1048576))
        root = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        self.fds.append(root)
        for relative in ("sys", "sys/fs"):
            fd = open_beneath(root, relative, os.O_RDONLY | os.O_DIRECTORY)
            self.fds.append(fd)
            value = os.fstat(fd)
            require(value.st_uid == 0 and stat.S_ISDIR(value.st_mode) and not value.st_mode & 0o022)
        cg = open_beneath(root, "sys/fs/cgroup", os.O_RDONLY | os.O_DIRECTORY)
        self.fds.append(cg)
        cgroup_fd(cg, self.mount, 0, True)
        self.parents = []
        for relative, owner in (("bootstrap-g04-v1", 0), ("bootstrap-g04-v1/u" + str(self.uid), self.uid)):
            fd = open_beneath(cg, relative, os.O_RDONLY | os.O_DIRECTORY)
            self.fds.append(fd)
            cgroup_fd(fd, self.mount, owner, True)
            require(os.fstat(fd).st_uid == owner)
            self.parents.append((fd, owner))
        self.parent = self.parents[-1][0]
        self.control = self.directory(self.parent, "control")
        self.runs = self.directory(self.parent, "runs")
        self.parents.append((self.runs, self.uid))
        self.verify_parents()
        self.name = "run-" + os.urandom(16).hex()
        os.mkdir(self.name, 0o700, dir_fd=self.runs)
        self.created = True
        self.leaf = self.directory(self.runs, self.name)
        require(self.read(self.leaf, "cgroup.procs") == "" and self.read(self.leaf, "cgroup.type") == "domain")
        self.controls = {name: self.file(self.leaf, name, os.O_RDWR) for name in VALUES}
        self.kill = self.file(self.leaf, "cgroup.kill", os.O_WRONLY)
        self.events = self.file(self.leaf, "cgroup.events", os.O_RDONLY)
        self.procs = self.file(self.leaf, "cgroup.procs", os.O_RDWR)
        for name, value in VALUES.items():
            self.write(self.controls[name], value)
        self.verify()

    def directory(self, parent, name):
        fd = open_beneath(parent, name, os.O_RDONLY | os.O_DIRECTORY)
        self.fds.append(fd)
        cgroup_fd(fd, self.mount, self.uid, True)
        require(os.fstat(fd).st_uid == self.uid)
        return fd

    def file(self, parent, name, flags):
        fd = open_beneath(parent, name, flags)
        self.fds.append(fd)
        owner = os.fstat(parent).st_uid
        cgroup_fd(fd, self.mount, owner)
        return fd

    def read(self, parent, name):
        fd = self.file(parent, name, os.O_RDONLY)
        try:
            return bounded(fd).decode("ascii").strip()
        finally:
            os.close(fd)
            self.fds.remove(fd)

    @staticmethod
    def write(fd, value):
        os.lseek(fd, 0, os.SEEK_SET)
        data = (value + "\n").encode("ascii")
        require(os.write(fd, data) == len(data))

    def verify_parents(self):
        require(membership(proc("cgroup")) == self.path + "/control")
        for fd, owner in self.parents:
            cgroup_fd(fd, self.mount, owner, True)
            require(self.read(fd, "cgroup.type") == "domain" and self.read(fd, "cgroup.procs") == "")
            require({"memory", "pids"}.issubset(self.read(fd, "cgroup.subtree_control").split()))
        require(self.read(self.control, "cgroup.type") == "domain" and self.read(self.control, "cgroup.subtree_control") == "")

    def verify(self):
        self.verify_parents()
        cgroup_fd(self.leaf, self.mount, self.uid, True)
        require(self.read(self.leaf, "cgroup.type") == "domain")
        for name, value in VALUES.items():
            require(bounded(self.controls[name]).decode("ascii").strip() == value)

    def attach(self, pid):
        self.verify()
        require(membership(proc("cgroup", pid)) == self.path + "/control")
        self.write(self.procs, str(pid))
        require(membership(proc("cgroup", pid)) == self.path + "/runs/" + self.name and
                bounded(self.procs).decode("ascii").split() == [str(pid)])

    def empty(self):
        values = dict(line.split(" ") for line in bounded(self.events).decode("ascii").splitlines())
        require(values.get("populated") in ("0", "1"))
        return values["populated"] == "0"

    def stop(self):
        self.write(self.kill, "1")

    def remove(self):
        require(self.empty())
        os.rmdir(self.name, dir_fd=self.runs)
        try:
            os.stat(self.name, dir_fd=self.runs, follow_symlinks=False)
        except FileNotFoundError:
            self.removed = True
        require(self.removed)

    def close(self):
        for fd in reversed(self.fds):
            os.close(fd)
        self.fds.clear()


class Frames:
    def __init__(self, fd):
        self.fd = fd
        self.buffer = bytearray()
        self.received = self.sent = 0

    def send(self, value):
        data = json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode() + b"\n"
        require(len(data) <= FRAME and self.sent + len(data) <= TOTAL)
        self.sent += len(data)
        while data:
            count = os.write(self.fd, data)
            require(count > 0)
            data = data[count:]

    def read(self, timeout):
        end = time.monotonic() + timeout
        while b"\n" not in self.buffer:
            require(len(self.buffer) < FRAME)
            if not select.select([self.fd], [], [], max(0, end - time.monotonic()))[0]:
                return None
            data = os.read(self.fd, min(FRAME - len(self.buffer), 4096))
            if not data:
                raise EOFError()
            self.received += len(data)
            require(self.received <= TOTAL)
            self.buffer.extend(data)
        line, _, tail = self.buffer.partition(b"\n")
        self.buffer = bytearray(tail)
        require(len(line) + 1 <= FRAME)
        value = json.loads(line.decode("utf-8", "strict"), object_pairs_hook=unique_object)
        require(type(value) is dict)
        return value


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def owned_directory(path):
    value = os.lstat(path)
    require(stat.S_ISDIR(value.st_mode) and value.st_uid == os.getuid() and not value.st_mode & 0o077)


def start_record(record):
    require(set(record) == {"v", "type", "directory", "base", "candidate"} and
            type(record["v"]) is int and record["v"] == 1 and record["type"] == "start")
    directory = record["directory"]
    require(type(directory) is str and os.path.dirname(directory) == os.path.realpath("/tmp") and
            re.fullmatch(r"bootstrap-review-workspace-[A-Za-z0-9]{6}", os.path.basename(directory)) is not None)
    for name in ("base", "candidate"):
        require(type(record[name]) is str and re.fullmatch(r"[a-f0-9]{40}", record[name]) is not None)
    for relative in ("", "source", "source/.git", "empty", "runtime", "runtime/home", "runtime/tmp", "output"):
        owned_directory(os.path.join(directory, relative))
    for name in ("review.json", "review.txt", "status.json"):
        require(not os.path.lexists(os.path.join(directory, "output", name)))
    return record


def trusted_file(path, executable=False, owner=0):
    require(os.path.isabs(path) and path == os.path.realpath(path))
    current = path
    while True:
        value = os.lstat(current)
        require(value.st_uid in (0, owner) and not value.st_mode & 0o6022)
        require(stat.S_ISREG(value.st_mode) if current == path else stat.S_ISDIR(value.st_mode))
        if current == path and executable:
            require(value.st_mode & 0o111)
        parent = os.path.dirname(current)
        if parent == current:
            return path
        current = parent


def helper_environment(record):
    unsupported = ("OPENAI_API_KEY", "CODEX_API_KEY", "AZURE_OPENAI_API_KEY", "AZURE_OPENAI_ENDPOINT",
                   "OPENAI_BASE_URL", "OPENAI_ORGANIZATION", "OPENAI_PROJECT", "HTTP_PROXY", "HTTPS_PROXY",
                   "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy")
    require(not any(name in os.environ for name in unsupported))
    codex_home = os.environ.get("CODEX_HOME", "")
    require(os.path.isabs(codex_home) and codex_home == os.path.realpath(codex_home) and
            os.path.commonpath((codex_home, record["directory"])) != record["directory"])
    directory = record["directory"]
    result = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": directory + "/runtime/home",
              "TMPDIR": directory + "/runtime/tmp", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "TZ": "UTC"}
    for name, relative in (("XDG_CACHE_HOME", ".cache"), ("XDG_CONFIG_HOME", ".config"),
                           ("XDG_DATA_HOME", ".local/share"), ("XDG_STATE_HOME", ".local/state")):
        result[name] = result["HOME"] + "/" + relative
    for name in ("CODEX_HOME", "DBUS_SESSION_BUS_ADDRESS", "XDG_RUNTIME_DIR"):
        if name in os.environ:
            result[name] = os.environ[name]
    return result


def helper_arguments(record):
    python = trusted_file(os.path.realpath("/usr/bin/python3"), True)
    codex = trusted_file(os.path.realpath("/usr/local/bin/codex"), True)
    home = os.environ.get("CODEX_HOME", "")
    require(os.path.isabs(home) and home == os.path.realpath(home) and
            not os.path.commonpath((home, record["directory"])) == record["directory"])
    helper = trusted_file(os.path.join(home, "skills/autoreview/scripts/autoreview"), owner=os.getuid())
    fd = os.open(helper, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        data = bounded(fd, 1048576)
        require(hashlib.sha256(data).hexdigest() == HELPER_SHA256)
    finally:
        os.close(fd)
    return [python, "-I", helper, "--engine", "codex", "--model", "gpt-6.1-sol", "--thinking", "high",
            "--mode", "branch", "--base", record["base"], "--codex-bin", codex,
            "--codex-no-fallback", "--max-priority", "P3",
            "--status-output", record["directory"] + "/output/status.json",
            "--json-output", record["directory"] + "/output/review.json",
            "--output", record["directory"] + "/output/review.txt", "--stream-engine-output"]


def reap():
    statuses = []
    while True:
        try:
            pid, value = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return statuses, True
        if pid == 0:
            return statuses, False
        statuses.append((pid, value))


def wait_guardian(pid, deadline):
    while time.monotonic() < deadline:
        found, status = os.waitpid(pid, os.WNOHANG)
        if found:
            return status
        time.sleep(0.01)
    os.kill(pid, signal.SIGKILL)
    raise Unsupported()


def kill_and_reap(scope, deadline):
    scope.stop()
    while time.monotonic() < deadline:
        _, ended = reap()
        if ended and scope.empty():
            return
        time.sleep(0.01)
    raise Unsupported()


def barrier(reader, writer, guardian_pid, argv, directory, deadline):
    os.close(writer)
    prctl(1, signal.SIGKILL)
    require(os.getppid() == guardian_pid)
    data = bytearray()
    while len(data) < 2:
        require(time.monotonic() < deadline)
        require(select.select([reader], [], [], max(0, deadline - time.monotonic()))[0])
        part = os.read(reader, 2 - len(data))
        if not part:
            break
        data.extend(part)
    require(data == b"R" and os.getppid() == guardian_pid)
    os.close(reader)
    resource.setrlimit(resource.RLIMIT_FSIZE, (67108864, 67108864))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    require(resource.getrlimit(resource.RLIMIT_FSIZE) == (67108864, 67108864) and
            resource.getrlimit(resource.RLIMIT_CORE) == (0, 0))
    for kind in (resource.RLIMIT_CPU, resource.RLIMIT_AS):
        require(resource.getrlimit(kind) == (resource.RLIM_INFINITY, resource.RLIM_INFINITY))
    os.chdir(directory + "/source")
    null = os.open("/dev/null", os.O_RDONLY)
    os.dup2(null, 0)
    os.closerange(3, 1048576)
    os.execve(argv[0], argv, dict(os.environ))


def guardian(scope, channel, argv, directory, deadline):
    prctl(36, 1)
    frames = Frames(channel)
    reader, writer = os.pipe2(os.O_CLOEXEC)
    helper = None
    cleanup_deadline = None
    guardian_pid = os.getpid()
    try:
        helper = os.fork()
        if helper == 0:
            try:
                barrier(reader, writer, guardian_pid, argv, directory, deadline)
            finally:
                os._exit(126)
        os.close(reader)
        require(time.monotonic() < deadline)
        resource.prlimit(helper, resource.RLIMIT_FSIZE, (67108864, 67108864))
        resource.prlimit(helper, resource.RLIMIT_CORE, (0, 0))
        require(resource.prlimit(helper, resource.RLIMIT_FSIZE) == (67108864, 67108864) and
                resource.prlimit(helper, resource.RLIMIT_CORE) == (0, 0))
        for kind in (resource.RLIMIT_CPU, resource.RLIMIT_AS):
            require(resource.prlimit(helper, kind) == (resource.RLIM_INFINITY, resource.RLIM_INFINITY))
        scope.attach(helper)
        require(frames.read(0) is None and time.monotonic() < deadline)
        require(os.write(writer, b"R") == 1)
        os.close(writer)
        writer = None
        frames.send({"v": 1, "type": "started", "helper": helper})
        status = None
        while status is None:
            message = frames.read(0.02)
            if message is not None:
                require(set(message) == {"v", "type"} and message == {"v": 1, "type": "cancel"})
                raise Unsupported()
            for pid, value in reap()[0]:
                if pid == helper:
                    status = value
        cleanup_deadline = time.monotonic() + CLEANUP
        kill_and_reap(scope, cleanup_deadline)
        code = os.waitstatus_to_exitcode(status)
        frames.send({"v": 1, "type": "drained", "exit": code,
                     "deadlineNs": str(int(cleanup_deadline * 1000000000))})
        message = frames.read(max(0, cleanup_deadline - time.monotonic()))
        require(message == {"v": 1, "type": "removed"})
        return 0 if code == 0 else 1
    except BaseException:
        if writer is not None:
            os.close(writer)
        cleanup_deadline = cleanup_deadline or time.monotonic() + CLEANUP
        try:
            kill_and_reap(scope, cleanup_deadline)
            if not scope.removed:
                scope.remove()
        except BaseException:
            pass
        return 1


def main():
    require(sys.argv == [sys.argv[0]])
    started = time.monotonic()
    frames = Frames(3)
    record = start_record(frames.read(STARTUP))
    environment = helper_environment(record)
    argv = helper_arguments(record)
    os.environ.clear()
    os.environ.update(environment)
    scope = None
    guardian_pid = None
    channel = None
    guardian_status = None
    finalizing = None
    try:
        prctl(36, 1)
        scope = Scope()
        require(time.monotonic() < started + STARTUP)
        left, right = socket.socketpair()
        guardian_pid = os.fork()
        if guardian_pid == 0:
            left.close()
            os.close(3)
            try:
                result = guardian(scope, right.detach(), argv, record["directory"], started + STARTUP)
            finally:
                scope.close()
            os._exit(result)
        right.close()
        channel = Frames(left.detach())
        launched = False
        while True:
            message = channel.read(0.01)
            if message is not None:
                if message.get("type") == "started":
                    require(not launched and set(message) == {"v", "type", "helper"} and
                            message["v"] == 1 and type(message["helper"]) is int and message["helper"] > 0)
                    launched = True
                    frames.send({"v": 1, "type": "started", "helper": message["helper"]})
                else:
                    require(launched and set(message) == {"v", "type", "exit", "deadlineNs"} and message["v"] == 1 and
                            message["type"] == "drained" and type(message["exit"]) is int and
                            type(message["deadlineNs"]) is str and re.fullmatch(r"[0-9]{1,19}", message["deadlineNs"]))
                    finalizing = int(message["deadlineNs"]) / 1000000000
                    require(time.monotonic() < finalizing <= time.monotonic() + CLEANUP)
                    scope.verify()
                    require(scope.empty())
                    scope.remove()
                    channel.send({"v": 1, "type": "removed"})
                    guardian_status = wait_guardian(guardian_pid, finalizing)
                    require(os.waitstatus_to_exitcode(guardian_status) == (0 if message["exit"] == 0 else 1))
                    frames.send({"v": 1, "type": "drained", "exit": message["exit"]})
                    require(frames.read(max(0, finalizing - time.monotonic())) == {"v": 1, "type": "finish"})
                    remaining = int((finalizing - time.monotonic()) * 1000000000)
                    require(remaining > 0)
                    frames.send({"v": 1, "type": "complete", "exit": message["exit"], "remainingNs": str(remaining)})
                    return 0
            command = frames.read(0)
            if command is not None:
                require(command == {"v": 1, "type": "cancel"})
                raise Unsupported()
            pid, value = os.waitpid(guardian_pid, os.WNOHANG)
            if pid:
                guardian_status = value
                raise Unsupported()
            require(launched or time.monotonic() < started + STARTUP)
    finally:
        if scope is not None:
            try:
                if not scope.removed:
                    if channel is not None:
                        try:
                            channel.send({"v": 1, "type": "cancel"})
                        except BaseException:
                            pass
                    if guardian_pid is not None and guardian_pid > 0 and guardian_status is None:
                        try:
                            found, guardian_status = os.waitpid(guardian_pid, os.WNOHANG)
                        except ChildProcessError:
                            pass
                        else:
                            if found == 0:
                                os.kill(guardian_pid, signal.SIGKILL)
                    kill_and_reap(scope, finalizing or time.monotonic() + CLEANUP)
                    scope.remove()
            finally:
                if channel is not None:
                    os.close(channel.fd)
                scope.close()


if __name__ == "__main__":
    try:
        result = main()
    except BaseException:
        result = 1
    raise SystemExit(result)
