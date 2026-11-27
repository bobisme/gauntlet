#!/usr/bin/env python3
"""Authenticated host process accounting for the M1 cold-agent skeleton.

The monitor is deliberately a strict-subset collector.  It launches the exact
foreground rootless-Podman command under a pinned host ``strace``, reconstructs
the one Codex JSONL stdout stream, and accounts every command subtree.  Any
parse ambiguity, unpinned executable, unqualified signal, overlapping command,
unsupported stdout operation, or incomplete tree invalidates the run.  There is no
transcript-only fallback.

Raw strace output is private referee material: it can contain worker output.
Only the normalized, HMAC-authenticated projection belongs in trial evidence.
"""

from __future__ import annotations

from concurrent.futures import Future, ThreadPoolExecutor, TimeoutError as FutureTimeout
from dataclasses import dataclass, field, replace
import hashlib
import hmac
import json
import os
from pathlib import Path, PurePosixPath
import re
import signal
import stat
import subprocess
import threading
import time
from typing import Iterable, Mapping, Sequence


SCHEMA = "scourge.skeleton-host-process-trace.v1"
EVENTS_SCHEMA = "scourge.skeleton-process-events.v1"
MONITOR_SCHEMA = "scourge.skeleton-process-monitor.v1"
DOMAIN = SCHEMA.encode("ascii") + b"\0"
PIN_DOMAIN = MONITOR_SCHEMA.encode("ascii") + b"\0"
PODMAN_ARGV_DOMAIN = b"scourge.skeleton-podman-argv.v1\0"
LAUNCH_DOMAIN = b"scourge.skeleton-process-launch.v1\0"
EVIDENCE_BINDING_DOMAIN = b"scourge.skeleton-evidence-binding.v1\0"

STRACE_SHA256 = "28ed5493ecf611b83ac0d0398cc1c4f09a228afaa7fce4737d14c8599cc796e2"
PODMAN_SHA256 = "1190c1780a6db1fdffb324a4691236c0f2c1e5f3bd14caaf37d0318222fb9cfe"
CRUN_SHA256 = "020c71c0442702addd9ea129c3c7d23a3a9ff185d73f415d6980aeddac55447a"
CONMON_SHA256 = "0be2c64e33a07d54c1921605a06de80ac33d500bf701a9ab1bcda12011e425cd"
REQUEST_REFERENCE_TEAPOT_SHA256 = (
    "c03bd1dfb40cdcbba7ab97b5f5ab16cb00a8f5ed33c7c59c6ab59a980326abae"
)
PREPARATION_TEAPOT_SHA256 = (
    "6d15d625e10afa768a221f64eb7a2a245a64a7babbe61cf74ce8d4ff33b2f458"
)
INVESTIGATION_SHA256 = "c368ab4d8e0511524674692b039c4f248cee2b5676d143a23f5ab9025a31d4fc"

# No -v/--abbrev=none, environment expansion, or decoded environment.  -xx
# makes retained bytes unambiguous and the high string ceiling prevents argv
# or stdout truncation; the parser still rejects an ellipsis.
FIXED_STRACE_ARGS = (
    "-f",
    "-ttt",
    "-xx",
    "--decode-pids=pidns",
    "-s",
    "262144",
    "--inject=execve:delay_exit=250ms",
    "--inject=execveat:delay_exit=250ms",
    "-e",
    "trace=%process,write,writev,pwrite64,pwritev,pwritev2,sendfile,splice,vmsplice,copy_file_range,io_uring_enter",
)
MAX_TRACE_BYTES = 64 << 20
MAX_RAW_BYTES = 64 << 20
MAX_TRACE_OVERSHOOT = (262144 * 4) + (64 << 10)
WATCH_LOOP_SECONDS = 0.002
TRACER_SCAN_SECONDS = 0.05
MAX_WATCH_GAP_NS = 200_000_000
EXEC_HASH_WORKERS = 2
MAX_PENDING_EXEC_HASHES = 32
MAX_PENDING_EXEC_HASH_BYTES = 512 << 20
MAX_EXEC_HASH_BYTES = 384 << 20
MAX_EXEC_HASH_SECONDS = 5.0
MAX_EXEC_HASH_QUEUE_SECONDS = 10.0
EXEC_HASH_CHUNK_BYTES = 1 << 20
CODEX_THREAD_CLONE_FLAGS = (
    "CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|"
    "CLONE_SETTLS|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID|0x400000"
)
CODEX_PROCESS_SETUP_CLONE_FLAGS = "CLONE_VM|CLONE_VFORK|SIGCHLD"
PROXY_PROBE_OUTPUT = b"offline supervisor proxy probe\n"
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}\Z")
_CONTAINER_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_IMAGE_ID = re.compile(r"[0-9a-f]{64}\Z")
_ENVIRONMENT_NAME = re.compile(r"[A-Z][A-Z0-9_]{0,63}\Z")
_CREDENTIAL_ENVIRONMENT_NAME = re.compile(
    r"(?:^|_)(?:api_?key|auth|bearer|credential|password|secret|token)(?:_|$)", re.I
)
_PREFIX = re.compile(r"(?P<pid>[1-9][0-9]*) (?P<stamp>[0-9]+\.[0-9]{6}) (?P<body>.*)\Z")
_EXIT = re.compile(r"\+\+\+ exited with (?P<code>[0-9]+) \+\+\+\Z")
_KILLED = re.compile(r"\+\+\+ killed by (?P<signal>SIG[A-Z0-9]+).*")
_SIGNAL_DELIVERY = re.compile(
    r"--- (?P<signal>SIG[A-Z0-9]+) \{(?P<fields>.*)\} ---\Z"
)
_HEX_ESCAPE = re.compile(r"\\x([0-9a-fA-F]{2})")
_UNSUPPORTED_STDOUT = ("pwrite64(", "sendfile(", "splice(", "vmsplice(",
                       "pwritev(", "pwritev2(", "copy_file_range(", "io_uring_enter(")
_FIXED_WORKER_ENVIRONMENT = {
    "CODEX_HOME": "/runtime/codex-home",
    "HOME": "/runtime/home",
    "HOSTNAME": "scourge-worker",
    "LANG": "C.UTF-8",
    "NO_COLOR": "1",
    "PATH": "/opt/scourge-bin:/usr/bin:/bin",
    "TERM": "dumb",
    "TMPDIR": "/runtime/tmp",
    "XDG_CACHE_HOME": "/runtime/cache",
    "XDG_CONFIG_HOME": "/runtime/config",
    "XDG_DATA_HOME": "/runtime/data",
    "XDG_RUNTIME_DIR": "/runtime/run",
    "XDG_STATE_HOME": "/runtime/state",
}
_OPTIONAL_WORKER_ENVIRONMENT = frozenset({"M0_PROXY_PORT"})


class MonitorError(ValueError):
    """A stable, fail-closed collector refusal."""

    def __init__(self, code: str, detail: str | None = None):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


def canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def podman_argv_digest(argv: Sequence[str]) -> str:
    """Bind the exact, ordered assignment-specific Podman command."""
    if isinstance(argv, (str, bytes)) or not argv:
        raise MonitorError("invalid-podman-argv")
    if any(not isinstance(word, str) or "\0" in word for word in argv):
        raise MonitorError("invalid-podman-argv")
    return digest(PODMAN_ARGV_DOMAIN + canonical(list(argv)))


def _validate_worker_environment_rows(rows: tuple[tuple[str, str], ...]) -> None:
    if type(rows) is not tuple:
        raise MonitorError("invalid-worker-environment")
    names: set[str] = set()
    values: dict[str, str] = {}
    for row in rows:
        if type(row) is not tuple or len(row) != 2:
            raise MonitorError("invalid-worker-environment")
        name, value = row
        if (not isinstance(name, str) or _ENVIRONMENT_NAME.fullmatch(name) is None
                or _CREDENTIAL_ENVIRONMENT_NAME.search(name) or name in names
                or not isinstance(value, str) or "\0" in value or "\n" in value):
            raise MonitorError("unsafe-worker-environment", str(name))
        names.add(name)
        values[name] = value
    if rows != tuple(sorted(rows)):
        raise MonitorError("noncanonical-worker-environment")
    if not rows:
        return
    if (names != set(_FIXED_WORKER_ENVIRONMENT)
            and names != set(_FIXED_WORKER_ENVIRONMENT) | set(_OPTIONAL_WORKER_ENVIRONMENT)):
        raise MonitorError("unexpected-worker-environment")
    if any(values[name] != expected for name, expected in _FIXED_WORKER_ENVIRONMENT.items()):
        raise MonitorError("unexpected-worker-environment")
    if "M0_PROXY_PORT" in values:
        try:
            port = int(values["M0_PROXY_PORT"])
        except ValueError as error:
            raise MonitorError("unexpected-worker-environment") from error
        if str(port) != values["M0_PROXY_PORT"] or not 1 <= port <= 65535 or port == 18080:
            raise MonitorError("unexpected-worker-environment")


def worker_environment_rows(environment: Mapping[str, str]) -> tuple[tuple[str, str], ...]:
    """Freeze the exact credential-free environment admitted to the worker."""
    if not isinstance(environment, Mapping):
        raise MonitorError("invalid-worker-environment")
    rows = tuple(sorted(environment.items(), key=lambda row: str(row[0])))
    _validate_worker_environment_rows(rows)
    return rows


def file_digest(path: os.PathLike[str] | str) -> str:
    value = hashlib.sha256()
    with open(path, "rb") as reader:
        for block in iter(lambda: reader.read(1 << 20), b""):
            value.update(block)
    return value.hexdigest()


def fd_digest(fd: int) -> str:
    value = hashlib.sha256()
    os.lseek(fd, 0, os.SEEK_SET)
    for block in iter(lambda: os.read(fd, 1 << 20), b""):
        value.update(block)
    os.lseek(fd, 0, os.SEEK_SET)
    return value.hexdigest()


def _ordinary_id(value: str, label: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise MonitorError("invalid-identity", label)
    return value


def _expected_digest(value: str, label: str) -> str:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise MonitorError("invalid-digest", label)
    return value


@dataclass
class PrivateRoot:
    path: Path
    fd: int
    device: int
    inode: int

    @classmethod
    def open(cls, path: Path) -> "PrivateRoot":
        path = path.absolute()
        before = path.lstat()
        if (not stat.S_ISDIR(before.st_mode) or before.st_uid != os.geteuid()
                or stat.S_IMODE(before.st_mode) != 0o700):
            raise MonitorError("unsafe-control-root", str(path))
        try:
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
        except OSError as error:
            raise MonitorError("unsafe-control-root", str(path)) from error
        after = os.fstat(fd)
        if (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino):
            os.close(fd)
            raise MonitorError("control-root-race", str(path))
        return cls(path, fd, after.st_dev, after.st_ino)

    def close(self) -> None:
        os.close(self.fd)

    def verify(self) -> None:
        try:
            current = self.path.lstat()
        except FileNotFoundError as error:
            raise MonitorError("control-root-replaced", str(self.path)) from error
        held = os.fstat(self.fd)
        if ((current.st_dev, current.st_ino) != (self.device, self.inode)
                or (held.st_dev, held.st_ino) != (self.device, self.inode)):
            raise MonitorError("control-root-replaced", str(self.path))

    def child(self, name: str) -> Path:
        if "/" in name or name in {"", ".", ".."}:
            raise MonitorError("unsafe-private-name")
        return self.path / name

    def create_fd(self, name: str) -> int:
        self.child(name)
        return os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
            dir_fd=self.fd,
        )

    def write(self, name: str, data: bytes) -> Path:
        fd = self.create_fd(name)
        try:
            offset = 0
            while offset < len(data):
                offset += os.write(fd, data[offset:])
            os.fsync(fd)
        finally:
            os.close(fd)
        return self.child(name)

    def read(self, name: str, ceiling: int) -> bytes:
        self.child(name)
        fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=self.fd)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > ceiling):
                raise MonitorError("unsafe-monitor-output", str(self.child(name)))
            value = b""
            while len(value) <= ceiling:
                block = os.read(fd, min(1 << 20, ceiling + 1 - len(value)))
                if not block:
                    break
                value += block
            if len(value) > ceiling:
                raise MonitorError("unsafe-monitor-output", str(self.child(name)))
            return value
        finally:
            os.close(fd)

    def proc_child(self, name: str) -> str:
        self.child(name)
        return f"/proc/{os.getpid()}/fd/{self.fd}/{name}"


def create_monitor_key(control_root: os.PathLike[str] | str, name: str = "monitor.key") -> Path:
    root = PrivateRoot.open(Path(control_root))
    try:
        # os.urandom is backed by the kernel CSPRNG (getrandom on supported Linux).
        return root.write(name, os.urandom(32))
    finally:
        root.close()


def read_monitor_key(path: os.PathLike[str] | str) -> bytes:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError as error:
        raise MonitorError("unsafe-monitor-key") from error
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600:
        os.close(fd)
        raise MonitorError("unsafe-monitor-key")
    try:
        value = b""
        while len(value) <= 32:
            block = os.read(fd, 33 - len(value))
            if not block:
                break
            value += block
    finally:
        os.close(fd)
    if len(value) != 32:
        raise MonitorError("invalid-monitor-key")
    return value


@dataclass(frozen=True)
class ExecutablePin:
    """An executable frozen by the outer read-only image or mount boundary."""

    path: str
    sha256: str
    source: str
    read_only: bool = True

    def __post_init__(self) -> None:
        path = PurePosixPath(self.path)
        if not path.is_absolute() or ".." in path.parts or path.as_posix() != self.path:
            raise MonitorError("unsafe-executable-path", self.path)
        _expected_digest(self.sha256, self.path)
        if self.source not in {"image", "read-only-mount"} or self.read_only is not True:
            raise MonitorError("writable-executable-pin", self.path)

    def json(self) -> dict[str, object]:
        return {
            "path": self.path,
            "sha256": self.sha256,
            "source": self.source,
            "read_only": True,
        }


@dataclass(frozen=True)
class MountPin:
    """Live host identity and exact container projection of one bind mount."""

    source: str
    destination: str
    read_only: bool
    source_class: str
    device: int
    inode: int
    mode: int
    owner_uid: int
    sha256: str | None = None

    def __post_init__(self) -> None:
        for value, label in ((self.source, "source"), (self.destination, "destination")):
            path = PurePosixPath(value)
            if not path.is_absolute() or ".." in path.parts or path.as_posix() != value:
                raise MonitorError("unsafe-mount-pin", label)
        if self.source_class not in {
            "private-writable", "gateway-sockets", "pinned-executable"
        }:
            raise MonitorError("unsafe-mount-pin", self.source_class)
        if (type(self.read_only) is not bool or type(self.device) is not int
                or type(self.inode) is not int or type(self.mode) is not int
                or type(self.owner_uid) is not int or self.device <= 0 or self.inode <= 0):
            raise MonitorError("unsafe-mount-pin", self.source)
        if self.source_class == "pinned-executable":
            if not self.read_only or self.sha256 is None:
                raise MonitorError("unsafe-mount-pin", self.source)
            _expected_digest(self.sha256, "mount")
        elif self.sha256 is not None:
            raise MonitorError("unsafe-mount-pin", self.source)

    @classmethod
    def capture(
        cls,
        source: os.PathLike[str] | str,
        destination: str,
        *,
        read_only: bool,
        source_class: str,
        sha256: str | None = None,
    ) -> "MountPin":
        path = Path(source)
        try:
            resolved = path.resolve(strict=True)
            info = path.lstat()
        except OSError as error:
            raise MonitorError("unsafe-mount-source", os.fspath(path)) from error
        if resolved != path or stat.S_ISLNK(info.st_mode):
            raise MonitorError("unsafe-mount-source", os.fspath(path))
        return cls(
            os.fspath(path), destination, read_only, source_class,
            info.st_dev, info.st_ino, stat.S_IMODE(info.st_mode), info.st_uid, sha256,
        )

    def json(self) -> dict[str, object]:
        return {
            "source": self.source,
            "destination": self.destination,
            "read_only": self.read_only,
            "source_class": self.source_class,
            "device": self.device,
            "inode": self.inode,
            "mode": self.mode,
            "owner_uid": self.owner_uid,
            "sha256": self.sha256,
        }


@dataclass(frozen=True)
class SupervisorPin:
    """Exact production PID 1 and its two loopback-to-UDS routes."""

    exec_path: str
    sha256: str
    argv: tuple[str, ...]
    codex_argv: tuple[str, ...]
    proxy_port: int
    model_port: int = 18080
    model_socket: str = "/gateway/model.sock"
    proxy_socket: str = "/gateway/proxy.sock"
    child_reaper_contract: str = "container-pid1-v1"

    def __post_init__(self) -> None:
        for value in (self.exec_path, self.model_socket, self.proxy_socket):
            path = PurePosixPath(value)
            if not path.is_absolute() or ".." in path.parts or path.as_posix() != value:
                raise MonitorError("unsafe-supervisor-path", value)
        _expected_digest(self.sha256, "supervisor")
        if (not self.argv or self.argv[0] != self.exec_path or not self.codex_argv
                or any(not isinstance(word, str) or not word or "\0" in word
                       for word in (*self.argv, *self.codex_argv))):
            raise MonitorError("invalid-supervisor-argv")
        if (len(self.argv) < 7
                or self.argv[1:3] != ("--self-sha256", self.sha256)
                or self.argv[3] != "--codex-sha256"
                or _DIGEST.fullmatch(self.argv[4]) is None
                or self.argv[5] != "--"
                or self.argv[6:] != self.codex_argv):
            raise MonitorError("invalid-supervisor-wrapper")
        if (self.model_port != 18080 or type(self.proxy_port) is not int
                or not 1 <= self.proxy_port <= 65535 or self.proxy_port == self.model_port
                or self.child_reaper_contract != "container-pid1-v1"):
            raise MonitorError("invalid-supervisor-port")

    def json(self) -> dict[str, object]:
        return {
            "exec_path": self.exec_path,
            "sha256": self.sha256,
            "argv": list(self.argv),
            "codex_argv": list(self.codex_argv),
            "forwarding": {
                "model": {"port": self.model_port, "socket": self.model_socket},
                "proxy": {"port": self.proxy_port, "socket": self.proxy_socket},
            },
            "child_reaper_contract": self.child_reaper_contract,
        }

    def stable_json(self) -> dict[str, object]:
        return {
            "exec_path": self.exec_path,
            "sha256": self.sha256,
            "model_port": self.model_port,
            "model_socket": self.model_socket,
            "proxy_socket": self.proxy_socket,
            "child_reaper_contract": self.child_reaper_contract,
        }


@dataclass(frozen=True)
class MonitorConfig:
    strace: str
    podman: str
    crun: str
    codex_path: str
    scourge_path: str
    executables: tuple[ExecutablePin, ...]
    podman_argv_sha256: str
    mounts: tuple[MountPin, ...] = ()
    mount_root: str | None = None
    protected_mount_roots: tuple[str, ...] = ()
    supervisor: SupervisorPin | None = None
    worker_environment: tuple[tuple[str, str], ...] = ()
    teapot_path: str | None = None
    teapot_sha256: str | None = None
    preparation_teapot_path: str | None = None
    preparation_teapot_sha256: str | None = None
    preparation_root: str | None = None
    investigation_path: str | None = None
    investigation_sha256: str | None = None
    codex_bootstrap: bool = False
    codex_setup_device: int | None = None
    codex_setup_inode: int | None = None
    codex_setup_fd_ceiling: int | None = None
    codex_setup_fd_access_modes: tuple[int, int] | None = None
    worker_image_id: str | None = None
    login_profile_sha256: str | None = None
    login_profile_inventory: tuple[str, ...] | None = None
    qualification_child_pins: bool = False
    max_trace_bytes: int = MAX_TRACE_BYTES
    max_raw_bytes: int = MAX_RAW_BYTES
    max_prompt_bytes: int = 1 << 20

    def __post_init__(self) -> None:
        _expected_digest(self.podman_argv_sha256, "podman-argv")
        _validate_worker_environment_rows(self.worker_environment)
        if self.mounts:
            if self.mount_root is None:
                raise MonitorError("missing-mount-root")
            if (len({row.destination for row in self.mounts}) != len(self.mounts)
                    or len({row.source for row in self.mounts}) != len(self.mounts)):
                raise MonitorError("duplicate-mount-pin")
        elif not self.qualification_child_pins:
            raise MonitorError("missing-mount-manifest")
        if self.mount_root is not None:
            mount_root = PurePosixPath(self.mount_root)
            if (not mount_root.is_absolute() or ".." in mount_root.parts
                    or mount_root.as_posix() != self.mount_root):
                raise MonitorError("unsafe-mount-root")
        for protected in self.protected_mount_roots:
            path = PurePosixPath(protected)
            if (not path.is_absolute() or ".." in path.parts
                    or path.as_posix() != protected):
                raise MonitorError("unsafe-protected-mount-root", protected)
        paths_to_check = [self.strace, self.podman, self.crun, self.codex_path, self.scourge_path]
        if self.supervisor is not None:
            paths_to_check.append(self.supervisor.exec_path)
        for path, expected, label in (
            (self.teapot_path, self.teapot_sha256, "teapot"),
            (self.preparation_teapot_path, self.preparation_teapot_sha256,
             "preparation-teapot"),
            (self.investigation_path, self.investigation_sha256, "investigation"),
        ):
            if path is not None:
                paths_to_check.append(path)
                if expected is None:
                    raise MonitorError(f"missing-{label}-digest")
                _expected_digest(expected, label)
            elif expected is not None:
                raise MonitorError(f"unexpected-{label}-digest")
        if self.worker_image_id is not None and _IMAGE_ID.fullmatch(self.worker_image_id) is None:
            raise MonitorError("invalid-worker-image")
        if (self.codex_setup_device is None) != (self.codex_setup_inode is None):
            raise MonitorError("incomplete-codex-setup-identity")
        if self.codex_setup_device is not None and (
            type(self.codex_setup_device) is not int or self.codex_setup_device <= 0
            or type(self.codex_setup_inode) is not int or self.codex_setup_inode <= 0
        ):
            raise MonitorError("invalid-codex-setup-identity")
        setup_identity = self.codex_setup_device is not None
        if setup_identity != (self.codex_setup_fd_ceiling is not None) or setup_identity != (
            self.codex_setup_fd_access_modes is not None
        ):
            raise MonitorError("incomplete-codex-setup-fd-contract")
        if self.codex_setup_fd_ceiling is not None and (
            type(self.codex_setup_fd_ceiling) is not int
            or not 5 <= self.codex_setup_fd_ceiling <= 65535
            or self.codex_setup_fd_access_modes not in {
                (os.O_RDONLY, os.O_RDONLY), (os.O_RDONLY, os.O_WRONLY),
                (os.O_WRONLY, os.O_RDONLY), (os.O_WRONLY, os.O_WRONLY),
            }
        ):
            raise MonitorError("invalid-codex-setup-fd-contract")
        if self.login_profile_sha256 is not None:
            _expected_digest(self.login_profile_sha256, "login-profile")
            if self.worker_image_id is None or self.login_profile_inventory is None:
                raise MonitorError("incomplete-login-profile-binding")
            if self.login_profile_inventory != ():
                raise MonitorError("nonempty-login-profile-inventory")
        elif self.login_profile_inventory is not None:
            raise MonitorError("unexpected-login-profile-inventory")
        if self.preparation_root is not None:
            paths_to_check.append(self.preparation_root)
            if (self.preparation_teapot_path is None
                    or self.preparation_teapot_sha256 is None):
                raise MonitorError("incomplete-preparation-binding")
        elif self.preparation_teapot_path is not None:
            raise MonitorError("missing-preparation-root")
        for path in paths_to_check:
            value = PurePosixPath(path)
            if not value.is_absolute() or ".." in value.parts or value.as_posix() != path:
                raise MonitorError("unsafe-executable-path", path)
        if (type(self.max_trace_bytes) is not int or type(self.max_raw_bytes) is not int
                or type(self.max_prompt_bytes) is not int):
            raise MonitorError("invalid-monitor-limit")
        if type(self.qualification_child_pins) is not bool or type(self.codex_bootstrap) is not bool:
            raise MonitorError("invalid-qualification-mode")
        if not (1 <= self.max_trace_bytes <= 1 << 30 and 1 <= self.max_raw_bytes <= 1 << 30
                and 1 <= self.max_prompt_bytes <= 16 << 20):
            raise MonitorError("invalid-monitor-limit")
        paths = [pin.path for pin in self.executables]
        required = {self.codex_path, self.scourge_path}
        if self.teapot_path is not None:
            required.add(self.teapot_path)
        if self.preparation_teapot_path is not None:
            required.add(self.preparation_teapot_path)
        if self.investigation_path is not None:
            required.add(self.investigation_path)
        if self.supervisor is not None:
            required.add(self.supervisor.exec_path)
        if len(paths) != len(set(paths)) or not required <= set(paths):
            raise MonitorError("incomplete-executable-pins")
        if self.teapot_path is not None and self.pins[self.teapot_path].sha256 != self.teapot_sha256:
            raise MonitorError("teapot-pin-mismatch")
        if (self.preparation_teapot_path is not None
                and self.pins[self.preparation_teapot_path].sha256
                != self.preparation_teapot_sha256):
            raise MonitorError("preparation-teapot-pin-mismatch")
        if (self.investigation_path is not None
                and self.pins[self.investigation_path].sha256 != self.investigation_sha256):
            raise MonitorError("investigation-pin-mismatch")
        if not self.qualification_child_pins:
            if self.teapot_path is not None and self.teapot_sha256 != REQUEST_REFERENCE_TEAPOT_SHA256:
                raise MonitorError("unqualified-teapot-digest")
            if (self.preparation_teapot_path is not None
                    and self.preparation_teapot_sha256 != PREPARATION_TEAPOT_SHA256):
                raise MonitorError("unqualified-preparation-teapot-digest")
            if (self.investigation_path is not None
                    and self.investigation_sha256 != INVESTIGATION_SHA256):
                raise MonitorError("unqualified-investigation-digest")
            if self.supervisor is None:
                raise MonitorError("missing-production-supervisor")
        if self.supervisor is not None:
            worker = dict(self.worker_environment)
            if (self.supervisor.exec_path not in self.pins
                    or self.pins[self.supervisor.exec_path].sha256 != self.supervisor.sha256
                    or self.supervisor.codex_argv[0] != self.codex_path
                    or self.supervisor.argv[4] != self.pins[self.codex_path].sha256
                    or worker.get("M0_PROXY_PORT") != str(self.supervisor.proxy_port)):
                raise MonitorError("supervisor-pin-mismatch")

    @property
    def pins(self) -> dict[str, ExecutablePin]:
        return {pin.path: pin for pin in self.executables}

    def frozen(self) -> dict[str, object]:
        return {
            "schema": MONITOR_SCHEMA,
            "strace": {"path": self.strace, "sha256": STRACE_SHA256},
            "podman": {"path": self.podman, "sha256": PODMAN_SHA256},
            "crun": {"path": self.crun, "sha256": CRUN_SHA256},
            "fixed_strace_argv": list(FIXED_STRACE_ARGS),
            "podman_argv_sha256": self.podman_argv_sha256,
            "mounts": [row.json() for row in self.mounts],
            "mount_root": self.mount_root,
            "protected_mount_roots": list(self.protected_mount_roots),
            "worker_environment": [
                {"name": name, "value": value} for name, value in self.worker_environment
            ],
            "supervisor": None if self.supervisor is None else self.supervisor.json(),
            "codex_path": self.codex_path,
            "scourge_path": self.scourge_path,
            "teapot_path": self.teapot_path,
            "teapot_sha256": self.teapot_sha256,
            "preparation_teapot_path": self.preparation_teapot_path,
            "preparation_teapot_sha256": self.preparation_teapot_sha256,
            "preparation_root": self.preparation_root,
            "investigation_path": self.investigation_path,
            "investigation_sha256": self.investigation_sha256,
            "codex_bootstrap": self.codex_bootstrap,
            "codex_setup_device": self.codex_setup_device,
            "codex_setup_inode": self.codex_setup_inode,
            "codex_setup_fd_ceiling": self.codex_setup_fd_ceiling,
            "codex_setup_fd_access_modes": (
                None if self.codex_setup_fd_access_modes is None
                else list(self.codex_setup_fd_access_modes)
            ),
            "worker_image_id": self.worker_image_id,
            "login_profile_sha256": self.login_profile_sha256,
            "login_profile_inventory": (
                None if self.login_profile_inventory is None
                else list(self.login_profile_inventory)
            ),
            "qualification_child_pins": self.qualification_child_pins,
            "executables": [pin.json() for pin in sorted(self.executables, key=lambda row: row.path)],
            "max_trace_bytes": self.max_trace_bytes,
            "max_raw_bytes": self.max_raw_bytes,
            "max_prompt_bytes": self.max_prompt_bytes,
        }

    def stable(self) -> dict[str, object]:
        """Configuration shared by every cell; excludes per-attempt launch data."""
        value = self.frozen()
        value.pop("podman_argv_sha256")
        value.pop("worker_environment")
        value.pop("mounts")
        value.pop("mount_root")
        value.pop("protected_mount_roots")
        if self.supervisor is not None:
            value["supervisor"] = self.supervisor.stable_json()
        return value


def freeze_monitor(config: MonitorConfig) -> dict[str, object]:
    source = Path(__file__).resolve()
    actual = {
        config.strace: file_digest(config.strace),
        config.podman: file_digest(config.podman),
        config.crun: file_digest(config.crun),
    }
    expected = {
        config.strace: STRACE_SHA256,
        config.podman: PODMAN_SHA256,
        config.crun: CRUN_SHA256,
    }
    if actual != expected:
        raise MonitorError("monitor-tool-pin-mismatch", repr(actual))
    frozen = config.frozen()
    stable = config.stable()
    source_sha256 = file_digest(source)
    monitor_sha256 = digest(PIN_DOMAIN + canonical({
        "source_sha256": source_sha256,
        "configuration": stable,
    }))
    return {
        "schema": MONITOR_SCHEMA,
        "source_sha256": source_sha256,
        "configuration": frozen,
        "stable_configuration": stable,
        "stable_configuration_sha256": digest(canonical(stable)),
        "monitor_sha256": monitor_sha256,
    }


def freeze_launch(config: MonitorConfig, monitor_sha256: str, prompt: bytes) -> dict[str, object]:
    if not isinstance(prompt, bytes) or not prompt or len(prompt) > config.max_prompt_bytes:
        raise MonitorError("invalid-trusted-prompt")
    prompt_sha256 = digest(prompt)
    value = {
        "monitor_sha256": _expected_digest(monitor_sha256, "monitor"),
        "podman_argv_sha256": config.podman_argv_sha256,
        "worker_environment_sha256": digest(canonical(config.worker_environment)),
        "prompt_sha256": prompt_sha256,
        "prompt_size_bytes": len(prompt),
    }
    return {**value, "launch_sha256": digest(LAUNCH_DOMAIN + canonical(value))}


@dataclass
class ExecImage:
    stamp: float
    path: str
    argv: list[str]
    syscall: str


@dataclass
class WriteEvent:
    stamp: float
    data: bytes
    exec_epoch: int


@dataclass(frozen=True)
class NonStdoutWrite:
    stamp: float
    descriptor: int
    syscall: str
    returned: int
    declared: int | None
    nul_signal: bool
    exec_epoch: int

    def json(self) -> dict[str, object]:
        return {
            "timestamp": self.stamp,
            "descriptor": self.descriptor,
            "syscall": self.syscall,
            "returned": self.returned,
            "declared": self.declared,
            "nul_signal": self.nul_signal,
            "exec_epoch": self.exec_epoch,
        }


@dataclass(frozen=True)
class SignalEvent:
    stamp: float
    signal: str
    code: str
    sender_pid: int
    sender_host_pid: int | None
    sender_uid: int
    status: int | None
    exec_epoch: int
    raw_sha256: str

    def json(self) -> dict[str, object]:
        return {
            "timestamp": self.stamp,
            "signal": self.signal,
            "code": self.code,
            "sender_pid": self.sender_pid,
            "sender_host_pid": self.sender_host_pid,
            "sender_uid": self.sender_uid,
            "status": self.status,
            "exec_epoch": self.exec_epoch,
            "raw_sha256": self.raw_sha256,
        }


@dataclass
class Process:
    pid: int
    namespace_pid: int | None = None
    parent: int | None = None
    thread: bool = False
    clone_flags: str | None = None
    started: float | None = None
    ended: float | None = None
    exit_code: int | None = None
    signal: str | None = None
    execs: list[ExecImage] = field(default_factory=list)
    failed_execs: list[ExecImage] = field(default_factory=list)
    stdout: list[WriteEvent] = field(default_factory=list)
    nonstdout_writes: list[NonStdoutWrite] = field(default_factory=list)
    unsupported_stdout: list[str] = field(default_factory=list)
    parse_failures: list[str] = field(default_factory=list)
    signal_events: list[SignalEvent] = field(default_factory=list)

    @property
    def final(self) -> ExecImage | None:
        return self.execs[-1] if self.execs else None


@dataclass
class ParsedTrace:
    processes: dict[int, Process]
    first_stamp: float
    last_stamp: float


@dataclass(frozen=True)
class ExecFdSnapshot:
    """One argv-referenced descriptor observed at the exec stop."""

    number: int
    target: str
    device: int
    inode: int
    mode: int
    flags: int

    def json(self) -> dict[str, object]:
        return {
            "number": self.number,
            "target": self.target,
            "device": self.device,
            "inode": self.inode,
            "mode": self.mode,
            "flags": self.flags,
        }


@dataclass(frozen=True)
class ExecSnapshot:
    """Host observation of one executable inode while strace holds exec-stop."""

    process_id: int
    process_start_ticks: int
    sequence: int
    target: str
    sha256: str
    device: int
    inode: int
    mode: int
    owner_uid: int
    size_bytes: int
    regular: bool
    parent_device: int | None
    parent_inode: int | None
    parent_mode: int | None
    parent_owner_uid: int | None
    observed_monotonic_ns: int
    process_setup_fds: tuple[ExecFdSnapshot, ...] = ()
    process_setup_observations: int = 0
    process_setup_topology_status: str = "not-applicable"
    tracer_task_id: int | None = None
    hash_pre_fstat: tuple[int, int, int, int, int, int, int] | None = None
    hash_post_fstat: tuple[int, int, int, int, int, int, int] | None = None
    hash_started_monotonic_ns: int | None = None
    hash_completed_monotonic_ns: int | None = None
    hash_bytes: int | None = None
    hash_cache_reused: bool = False
    requested_exec_path: str | None = None
    resolution_chain: tuple[str, ...] = ()
    alias_requested_fstat: tuple[int, int, int, int, int, int, int] | None = None

    def json(self) -> dict[str, object]:
        return {
            "process_id": self.process_id,
            "process_start_ticks": self.process_start_ticks,
            "sequence": self.sequence,
            "target": self.target,
            "sha256": self.sha256,
            "device": self.device,
            "inode": self.inode,
            "mode": self.mode,
            "owner_uid": self.owner_uid,
            "size_bytes": self.size_bytes,
            "regular": self.regular,
            "parent_device": self.parent_device,
            "parent_inode": self.parent_inode,
            "parent_mode": self.parent_mode,
            "parent_owner_uid": self.parent_owner_uid,
            "observed_monotonic_ns": self.observed_monotonic_ns,
            "process_setup_fds": [row.json() for row in self.process_setup_fds],
            "process_setup_observations": self.process_setup_observations,
            "process_setup_topology_status": self.process_setup_topology_status,
            "tracer_task_id": self.tracer_task_id,
            "executable_hash": {
                "contract": "held-fd-sha256-v1",
                "pre_fstat": _hash_fstat_json(self.hash_pre_fstat),
                "post_fstat": _hash_fstat_json(self.hash_post_fstat),
                "started_monotonic_ns": self.hash_started_monotonic_ns,
                "completed_monotonic_ns": self.hash_completed_monotonic_ns,
                "bytes": self.hash_bytes,
                "cache_reused_after_completion": self.hash_cache_reused,
            },
            "path_resolution": {
                "requested": self.requested_exec_path,
                "resolved": self.target,
                "chain": list(self.resolution_chain),
                "requested_fstat": _hash_fstat_json(self.alias_requested_fstat),
                "same_inode": (
                    self.alias_requested_fstat == self.hash_pre_fstat
                    if self.alias_requested_fstat is not None else None
                ),
            },
        }


@dataclass(frozen=True)
class _ExecHashResult:
    sha256: str
    pre_fstat: tuple[int, int, int, int, int, int, int]
    post_fstat: tuple[int, int, int, int, int, int, int]
    started_monotonic_ns: int
    completed_monotonic_ns: int
    bytes: int


@dataclass
class _PendingExecSnapshot:
    process_id: int
    process_start_ticks: int
    sequence: int
    target: str
    device: int
    inode: int
    mode: int
    owner_uid: int
    size_bytes: int
    regular: bool
    parent_device: int | None
    parent_inode: int | None
    parent_mode: int | None
    parent_owner_uid: int | None
    observed_monotonic_ns: int
    process_setup_fds: tuple[ExecFdSnapshot, ...]
    process_setup_observations: int
    process_setup_topology_status: str
    tracer_task_id: int | None
    requested_exec_path: str | None
    resolution_chain: tuple[str, ...]
    alias_requested_fstat: tuple[int, int, int, int, int, int, int] | None

    def finish(self, hashed: _ExecHashResult, *, cache_reused: bool) -> ExecSnapshot:
        return ExecSnapshot(
            process_id=self.process_id,
            process_start_ticks=self.process_start_ticks,
            sequence=self.sequence,
            target=self.target,
            sha256=hashed.sha256,
            device=self.device,
            inode=self.inode,
            mode=self.mode,
            owner_uid=self.owner_uid,
            size_bytes=self.size_bytes,
            regular=self.regular,
            parent_device=self.parent_device,
            parent_inode=self.parent_inode,
            parent_mode=self.parent_mode,
            parent_owner_uid=self.parent_owner_uid,
            observed_monotonic_ns=self.observed_monotonic_ns,
            process_setup_fds=self.process_setup_fds,
            process_setup_observations=self.process_setup_observations,
            process_setup_topology_status=self.process_setup_topology_status,
            tracer_task_id=self.tracer_task_id,
            hash_pre_fstat=hashed.pre_fstat,
            hash_post_fstat=hashed.post_fstat,
            hash_started_monotonic_ns=hashed.started_monotonic_ns,
            hash_completed_monotonic_ns=hashed.completed_monotonic_ns,
            hash_bytes=hashed.bytes,
            hash_cache_reused=cache_reused,
            requested_exec_path=self.requested_exec_path,
            resolution_chain=self.resolution_chain,
            alias_requested_fstat=self.alias_requested_fstat,
        )


@dataclass(frozen=True)
class _SnapshotPin:
    """Digest identity proven from the live exec-stop inode, not argv."""

    path: str
    sha256: str


def _proc_parent_and_start(pid: int) -> tuple[int, int]:
    data = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
    fields = data[data.rfind(")") + 2:].split()
    return int(fields[1]), int(fields[19])


def _proc_descendants(root: int) -> dict[int, int]:
    """Walk kernel-maintained child lists without scanning all of /proc."""
    found: dict[int, int] = {}
    pending = [root]
    while pending:
        pid = pending.pop()
        if pid in found:
            continue
        try:
            _parent, start = _proc_parent_and_start(pid)
            children = set()
            for task in Path(f"/proc/{pid}/task").iterdir():
                value = (task / "children").read_text(encoding="ascii")
                children.update(int(item) for item in value.split())
        except (FileNotFoundError, ProcessLookupError, PermissionError, ValueError, IndexError):
            continue
        found[pid] = start
        pending.extend(children - found.keys())
    return found


def _admit_tracer_id(value: int, tracer_tasks: set[int]) -> bool:
    return value > 0 and value in tracer_tasks


def _tracer_identity(pid: int) -> tuple[int, int, int]:
    _parent, start_ticks = _proc_parent_and_start(pid)
    target = os.readlink(f"/proc/{pid}/exe")
    fd = os.open(f"/proc/{pid}/exe", os.O_RDONLY | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        sha256 = fd_digest(fd)
    finally:
        os.close(fd)
    if target != "/usr/bin/strace" or sha256 != STRACE_SHA256:
        raise MonitorError("unqualified-strace-monitor")
    return start_ticks, info.st_dev, info.st_ino


def _terminal_vanish_candidate(root_pid: int, health: Mapping[str, int]) -> bool:
    if (health.get("loop_count", 0) < 2
            or health.get("last_healthy_identity_ns", 0) <= 0
            or Path(f"/proc/{root_pid}/exe").exists()):
        return False
    root = Path(f"/proc/{root_pid}")
    if not root.exists():
        return True
    try:
        _parent, start_ticks = _proc_parent_and_start(root_pid)
        status = (root / "status").read_text(encoding="ascii")
        state = re.search(r"^State:\s+([A-Z])", status, re.MULTILINE)
        tasks = {
            int(entry.name) for entry in (root / "task").iterdir()
            if entry.name.isdigit()
        }
    except (FileNotFoundError, ProcessLookupError, PermissionError, ValueError, IndexError):
        return False
    return bool(
        start_ticks == health.get("strace_start_ticks")
        and state is not None and state.group(1) == "Z"
        and tasks == {root_pid}
    )


def _verify_terminal_vanish(root_pid: int, health: Mapping[str, int], returncode: int) -> None:
    if health.get("strace_terminal_vanished", 0) and (
        returncode != 0 or Path(f"/proc/{root_pid}").exists()
    ):
        raise MonitorError("unproved-strace-terminal-state")


def _proc_traced_by(
    root: int, expected_identity: tuple[int, int, int]
) -> dict[int, tuple[int, int]]:
    _parent, start_ticks = _proc_parent_and_start(root)
    target = os.readlink(f"/proc/{root}/exe")
    info = os.stat(f"/proc/{root}/exe")
    device, inode = info.st_dev, info.st_ino
    if (start_ticks, device, inode) != expected_identity:
        raise MonitorError("strace-monitor-reused")
    if target != "/usr/bin/strace":
        raise MonitorError("unqualified-strace-monitor")
    try:
        tracer_tasks = {
            int(entry.name) for entry in Path(f"/proc/{root}/task").iterdir()
            if entry.name.isdigit()
        }
    except (FileNotFoundError, ProcessLookupError, PermissionError):
        raise MonitorError("strace-monitor-vanished")
    if root not in tracer_tasks:
        raise MonitorError("strace-monitor-task-set")
    found = {}
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        try:
            status = (entry / "status").read_text(encoding="ascii")
            match = re.search(r"^TracerPid:\s*([0-9]+)$", status, re.MULTILINE)
            tracer = int(match.group(1)) if match is not None else 0
            if _admit_tracer_id(tracer, tracer_tasks):
                _parent, start = _proc_parent_and_start(pid)
                found[pid] = (start, tracer)
        except (FileNotFoundError, ProcessLookupError, PermissionError, ValueError, IndexError):
            continue
    return found


def _process_setup_fds(pid: int) -> tuple[tuple[ExecFdSnapshot, ...], str]:
    cmdline = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
    if len(cmdline) < 4 or cmdline[1] != b"--codex-run-as-process-setup":
        return (), "not-applicable"
    result = []
    for token in cmdline[2:4]:
        if not token.isdigit() or len(token) > 5:
            raise MonitorError("codex-process-setup-fd")
        number = int(token)
        descriptor = Path(f"/proc/{pid}/fd/{number}")
        try:
            target = os.readlink(descriptor)
            info = descriptor.stat()
            fdinfo = Path(f"/proc/{pid}/fdinfo/{number}").read_text(encoding="ascii")
        except (FileNotFoundError, ProcessLookupError, PermissionError, OSError) as error:
            return (), f"unavailable-fd-{number}"
        match = re.search(r"^flags:\s+([0-7]+)$", fdinfo, re.MULTILINE)
        if match is None:
            raise MonitorError("codex-process-setup-fd")
        result.append(ExecFdSnapshot(
            number, target, info.st_dev, info.st_ino, info.st_mode, int(match.group(1), 8)
        ))
    return tuple(result), "observed"


def _hash_fstat(info: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _hash_fstat_json(
    value: tuple[int, int, int, int, int, int, int] | None,
) -> dict[str, int] | None:
    if value is None:
        return None
    return dict(zip(
        ("device", "inode", "mode", "link_count", "size_bytes", "mtime_ns", "ctime_ns"),
        value,
        strict=True,
    ))


def _hash_held_executable(fd: int, expected: str) -> _ExecHashResult:
    """Hash one held regular executable under strict size/time/identity bounds."""
    started = time.monotonic_ns()
    deadline = time.monotonic() + MAX_EXEC_HASH_SECONDS
    try:
        pre_info = os.fstat(fd)
        pre = _hash_fstat(pre_info)
        if (not stat.S_ISREG(pre_info.st_mode) or pre_info.st_nlink < 1
                or pre_info.st_size < 1 or pre_info.st_size > MAX_EXEC_HASH_BYTES):
            predicates = {
                "regular": stat.S_ISREG(pre_info.st_mode),
                "link_count_positive": pre_info.st_nlink >= 1,
                "size_positive": pre_info.st_size >= 1,
                "size_within_limit": pre_info.st_size <= MAX_EXEC_HASH_BYTES,
            }
            raise MonitorError(
                "exec-hash-unsafe-file",
                json.dumps({
                    "fstat": _hash_fstat_json(pre),
                    "uid": pre_info.st_uid,
                    "gid": pre_info.st_gid,
                    "predicates": predicates,
                }, sort_keys=True, separators=(",", ":")),
            )
        value = hashlib.sha256()
        offset = 0
        while offset < pre_info.st_size:
            if time.monotonic() > deadline:
                raise MonitorError("exec-hash-time-limit")
            block = os.pread(
                fd,
                min(EXEC_HASH_CHUNK_BYTES, pre_info.st_size - offset),
                offset,
            )
            if not block:
                raise MonitorError("exec-hash-short-read")
            value.update(block)
            offset += len(block)
        post_info = os.fstat(fd)
        post = _hash_fstat(post_info)
        completed = time.monotonic_ns()
        actual = value.hexdigest()
        if pre != post:
            raise MonitorError("exec-hash-identity-changed")
        if actual != expected:
            raise MonitorError("exec-hash-digest-mismatch", actual)
        if completed - started > int(MAX_EXEC_HASH_SECONDS * 1_000_000_000):
            raise MonitorError("exec-hash-time-limit")
        return _ExecHashResult(actual, pre, post, started, completed, offset)
    finally:
        os.close(fd)


def _check_exec_hash_queue(
    pending_jobs: int, outstanding_bytes: int, next_bytes: int
) -> None:
    if (pending_jobs >= MAX_PENDING_EXEC_HASHES
            or outstanding_bytes + next_bytes > MAX_PENDING_EXEC_HASH_BYTES):
        raise MonitorError("exec-hash-queue-limit")


_DYNAMIC_INVESTIGATION_TARGET = re.compile(
    r"demo-runtime-[0-9a-f-]{36}/evidence-root/scratch/"
    r"scourge-investigation-[A-Za-z0-9]{6}/investigation\Z"
)


def _expected_exec_digest(target: str, config: MonitorConfig) -> str:
    direct = {
        config.strace: STRACE_SHA256,
        config.podman: PODMAN_SHA256,
        config.crun: CRUN_SHA256,
        "/usr/bin/conmon": CONMON_SHA256,
        **{path: pin.sha256 for path, pin in config.pins.items()},
    }
    if target in direct:
        return direct[target]
    resolved_aliases = {"/usr/bin/bash": "/bin/bash"}
    configured_alias = resolved_aliases.get(target)
    if configured_alias is not None and configured_alias in config.pins:
        return config.pins[configured_alias].sha256
    if target == "/":
        return CRUN_SHA256
    if config.preparation_root is not None:
        try:
            relative = PurePosixPath(target).relative_to(config.preparation_root)
        except ValueError:
            relative = None
        if relative is not None:
            if (len(relative.parts) == 2 and relative.name == "teapot"
                    and config.preparation_teapot_sha256 is not None):
                return config.preparation_teapot_sha256
            if (_DYNAMIC_INVESTIGATION_TARGET.fullmatch(relative.as_posix()) is not None
                    and config.investigation_sha256 is not None):
                return config.investigation_sha256
    raise MonitorError("unqualified-exec-hash-target", target)


def _open_resolved_executable(
    pid: int, target: str,
) -> tuple[
    int,
    os.stat_result,
    str | None,
    tuple[str, ...],
    tuple[int, int, int, int, int, int, int] | None,
]:
    """Hold the exec inode; use a no-follow resolved path whenever it is meaningful."""
    proc_fd = os.open(f"/proc/{pid}/exe", os.O_RDONLY | os.O_CLOEXEC)
    proc_info = os.fstat(proc_fd)
    if (not target.startswith("/") or target == "/" or "(deleted)" in target
            or target.startswith("/memfd:")):
        return proc_fd, proc_info, None, (), None
    try:
        resolved_fd = os.open(
            f"/proc/{pid}/root/{target.lstrip('/')}",
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
    except BaseException:
        os.close(proc_fd)
        raise
    resolved_info = os.fstat(resolved_fd)
    if (resolved_info.st_dev, resolved_info.st_ino) != (proc_info.st_dev, proc_info.st_ino):
        os.close(resolved_fd)
        os.close(proc_fd)
        raise MonitorError(
            "exec-hash-resolved-identity",
            repr({
                "pid": pid,
                "target": target,
                "proc": (proc_info.st_dev, proc_info.st_ino),
                "resolved": (resolved_info.st_dev, resolved_info.st_ino),
            }),
        )
    requested_path = None
    resolution_chain: tuple[str, ...] = ()
    requested_fstat = None
    if target == "/usr/bin/bash":
        bin_link = os.readlink(f"/proc/{pid}/root/bin")
        if bin_link != "usr/bin":
            os.close(resolved_fd)
            os.close(proc_fd)
            raise MonitorError("exec-hash-alias-chain")
        requested_fd = os.open(
            f"/proc/{pid}/root/bin/bash", os.O_RDONLY | os.O_CLOEXEC
        )
        try:
            requested_info = os.fstat(requested_fd)
        finally:
            os.close(requested_fd)
        if _hash_fstat(requested_info) != _hash_fstat(resolved_info):
            os.close(resolved_fd)
            os.close(proc_fd)
            raise MonitorError("exec-hash-alias-identity")
        requested_path = "/bin/bash"
        resolution_chain = ("/bin", "usr/bin", "/usr/bin/bash")
        requested_fstat = _hash_fstat(requested_info)
    os.close(proc_fd)
    return resolved_fd, resolved_info, requested_path, resolution_chain, requested_fstat


def _watch_exec_snapshots(
    root_pid: int,
    stop: threading.Event,
    rows: list[ExecSnapshot],
    errors: list[str],
    trace_path: Path | None = None,
    trace_limit: int | None = None,
    health: dict[str, int] | None = None,
    config: MonitorConfig | None = None,
) -> None:
    last: dict[tuple[int, int], tuple[int, int, tuple[int, ...], str]] = {}
    cached: dict[tuple[object, ...], _ExecHashResult] = {}
    sequences: dict[tuple[int, int], int] = {}
    tracked: dict[int, int] = {}
    traced_by: dict[int, int] = {}
    setup_rows: dict[tuple[int, int], int] = {}
    pending_by_process: dict[tuple[int, int], _PendingExecSnapshot] = {}
    pending: dict[
        Future[_ExecHashResult],
        tuple[tuple[object, ...], _PendingExecSnapshot, int],
    ] = {}
    next_tracer_scan = 0.0
    previous_loop_ns = 0
    tracer_identity = None
    executor = ThreadPoolExecutor(
        max_workers=EXEC_HASH_WORKERS,
        thread_name_prefix="scourge-exec-hash",
    )

    def complete_hashes(*, wait: bool) -> None:
        while pending:
            progressed = False
            now_ns = time.monotonic_ns()
            for future, (cache_key, observation, submitted_ns) in list(pending.items()):
                if (now_ns - submitted_ns
                        > int(MAX_EXEC_HASH_QUEUE_SECONDS * 1_000_000_000)):
                    raise MonitorError("exec-hash-queue-time-limit")
                if not future.done():
                    continue
                try:
                    hashed = future.result()
                except MonitorError as error:
                    raise MonitorError(
                        error.code,
                        f"{observation.process_id}:{observation.target}:{error.detail or '-'}",
                    ) from error
                if hashed.pre_fstat != cache_key[1:]:
                    raise MonitorError("exec-hash-cache-identity")
                cached[cache_key] = hashed
                index = len(rows)
                rows.append(observation.finish(hashed, cache_reused=False))
                key = (observation.process_id, observation.process_start_ticks)
                if pending_by_process.get(key) is observation:
                    pending_by_process.pop(key)
                if observation.process_setup_topology_status != "not-applicable":
                    current = setup_rows.get(key)
                    if current is None or rows[current].sequence < observation.sequence:
                        setup_rows[key] = index
                pending.pop(future)
                progressed = True
                if health is not None:
                    health["exec_hash_completed"] = health.get("exec_hash_completed", 0) + 1
                    health["exec_hash_max_duration_ns"] = max(
                        health.get("exec_hash_max_duration_ns", 0),
                        hashed.completed_monotonic_ns - hashed.started_monotonic_ns,
                    )
            if not wait or not pending:
                return
            if not progressed:
                oldest = min(row[2] for row in pending.values())
                remaining = (
                    MAX_EXEC_HASH_QUEUE_SECONDS
                    - (time.monotonic_ns() - oldest) / 1_000_000_000
                )
                if remaining <= 0:
                    raise MonitorError("exec-hash-queue-time-limit")
                try:
                    next(iter(pending)).result(timeout=min(remaining, 0.05))
                except FutureTimeout:
                    pass

    try:
        while not stop.is_set():
            complete_hashes(wait=False)
            loop_ns = time.monotonic_ns()
            if health is not None:
                health["loop_count"] = health.get("loop_count", 0) + 1
                if previous_loop_ns:
                    health["max_gap_ns"] = max(
                        health.get("max_gap_ns", 0), loop_ns - previous_loop_ns
                    )
                health.setdefault("first_loop_ns", loop_ns)
                health["last_loop_ns"] = loop_ns
            previous_loop_ns = loop_ns
            if (trace_path is not None and trace_limit is not None
                    and trace_path.stat().st_size > trace_limit + MAX_TRACE_OVERSHOOT):
                errors.append("trace-size-limit")
                try:
                    os.killpg(root_pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                return
            if tracer_identity is None:
                tracer_identity = _tracer_identity(root_pid)
                if health is not None:
                    health.update({
                        "strace_start_ticks": tracer_identity[0],
                        "strace_device": tracer_identity[1],
                        "strace_inode": tracer_identity[2],
                    })
            tracked.update(_proc_descendants(root_pid))
            now = time.monotonic()
            if now >= next_tracer_scan:
                try:
                    discoveries = _proc_traced_by(root_pid, tracer_identity)
                except (FileNotFoundError, ProcessLookupError) as error:
                    if health is not None and _terminal_vanish_candidate(root_pid, health):
                        health["strace_terminal_vanished"] = 1
                        health["terminal_vanished_ns"] = time.monotonic_ns()
                        health["terminal_vanished_loop"] = health["loop_count"]
                        break
                    raise error
                except MonitorError as error:
                    if (error.code == "strace-monitor-vanished"
                            and health is not None
                            and _terminal_vanish_candidate(root_pid, health)):
                        health["strace_terminal_vanished"] = 1
                        health["terminal_vanished_ns"] = time.monotonic_ns()
                        health["terminal_vanished_loop"] = health["loop_count"]
                        break
                    raise
                tracked.update({pid: row[0] for pid, row in discoveries.items()})
                traced_by.update({pid: row[1] for pid, row in discoveries.items()})
                next_tracer_scan = now + TRACER_SCAN_SECONDS
                if health is not None:
                    health["tracer_scan_count"] = health.get("tracer_scan_count", 0) + 1
                    health["tracer_discovery_count"] = (
                        health.get("tracer_discovery_count", 0) + len(discoveries)
                    )
                    health["tracer_task_set_max"] = max(
                        health.get("tracer_task_set_max", 0),
                        len({row[1] for row in discoveries.values()}),
                    )
                    health["last_healthy_identity_ns"] = time.monotonic_ns()
                    health["last_healthy_loop"] = health["loop_count"]
            for pid, start_ticks in list(tracked.items()):
                try:
                    _parent, current_start = _proc_parent_and_start(pid)
                except (FileNotFoundError, ProcessLookupError, PermissionError, ValueError, IndexError):
                    tracked.pop(pid, None)
                    continue
                if current_start != start_ticks:
                    tracked.pop(pid, None)
                    continue
                key = (pid, start_ticks)
                try:
                    target = os.readlink(f"/proc/{pid}/exe")
                    (fd, info, requested_exec_path, resolution_chain,
                     alias_requested_fstat) = _open_resolved_executable(pid, target)
                    setup_fds, setup_status = _process_setup_fds(pid)
                    identity = (
                        info.st_dev, info.st_ino,
                        tuple(row.number for row in setup_fds), setup_status,
                    )
                    if last.get(key) == identity:
                        os.close(fd)
                        if setup_status != "not-applicable":
                            index = setup_rows.get(key)
                            pending_observation = pending_by_process.get(key)
                            if (pending_observation is not None
                                    and pending_observation.process_setup_fds == setup_fds
                                    and pending_observation.process_setup_topology_status
                                    == setup_status):
                                pending_observation.process_setup_observations += 1
                            elif index is not None:
                                if (rows[index].process_setup_fds != setup_fds
                                        or rows[index].process_setup_topology_status
                                        != setup_status):
                                    raise MonitorError("codex-process-setup-fd-drift")
                                rows[index] = replace(
                                    rows[index],
                                    process_setup_observations=(
                                        rows[index].process_setup_observations + 1
                                    ),
                                )
                            else:
                                raise MonitorError("codex-process-setup-fd-drift")
                        continue
                    if config is None:
                        os.close(fd)
                        raise MonitorError("missing-exec-hash-config")
                    try:
                        expected = _expected_exec_digest(target, config)
                    except BaseException:
                        os.close(fd)
                        raise
                    pre_fstat = _hash_fstat(info)
                    cache_key = (expected, *pre_fstat)
                    parent_info = None
                    if target.startswith("/") and "(deleted)" not in target:
                        try:
                            parent_info = os.stat(
                                f"/proc/{pid}/root/{PurePosixPath(target).parent.as_posix().lstrip('/')}"
                            )
                        except (FileNotFoundError, ProcessLookupError, PermissionError, OSError):
                            pass
                except (FileNotFoundError, ProcessLookupError, PermissionError, OSError):
                    continue
                sequence = sequences.get(key, 0) + 1
                sequences[key] = sequence
                last[key] = identity
                observation = _PendingExecSnapshot(
                    process_id=pid,
                    process_start_ticks=start_ticks,
                    sequence=sequence,
                    target=target,
                    device=info.st_dev,
                    inode=info.st_ino,
                    mode=stat.S_IMODE(info.st_mode),
                    owner_uid=info.st_uid,
                    size_bytes=info.st_size,
                    regular=stat.S_ISREG(info.st_mode),
                    parent_device=None if parent_info is None else parent_info.st_dev,
                    parent_inode=None if parent_info is None else parent_info.st_ino,
                    parent_mode=None if parent_info is None else stat.S_IMODE(parent_info.st_mode),
                    parent_owner_uid=None if parent_info is None else parent_info.st_uid,
                    observed_monotonic_ns=time.monotonic_ns(),
                    process_setup_fds=setup_fds,
                    process_setup_observations=(
                        1 if setup_status != "not-applicable" else 0
                    ),
                    process_setup_topology_status=setup_status,
                    tracer_task_id=traced_by.get(pid),
                    requested_exec_path=requested_exec_path,
                    resolution_chain=resolution_chain,
                    alias_requested_fstat=alias_requested_fstat,
                )
                hashed = cached.get(cache_key)
                if hashed is not None:
                    os.close(fd)
                    index = len(rows)
                    rows.append(observation.finish(hashed, cache_reused=True))
                    if setup_status != "not-applicable":
                        setup_rows[key] = index
                    if health is not None:
                        health["exec_hash_cache_reuses"] = (
                            health.get("exec_hash_cache_reuses", 0) + 1
                        )
                    continue
                pending_bytes = sum(
                    row[1].size_bytes for row in pending.values()
                )
                try:
                    _check_exec_hash_queue(len(pending), pending_bytes, info.st_size)
                except BaseException:
                    os.close(fd)
                    raise
                submitted_ns = time.monotonic_ns()
                future = executor.submit(_hash_held_executable, fd, expected)
                pending[future] = (cache_key, observation, submitted_ns)
                pending_by_process[key] = observation
                if health is not None:
                    health["exec_hash_submitted"] = health.get("exec_hash_submitted", 0) + 1
                    health["exec_hash_max_pending"] = max(
                        health.get("exec_hash_max_pending", 0), len(pending)
                    )
                    health["exec_hash_max_pending_bytes"] = max(
                        health.get("exec_hash_max_pending_bytes", 0),
                        pending_bytes + info.st_size,
                    )
            stop.wait(WATCH_LOOP_SECONDS)
        complete_hashes(wait=True)
    except BaseException as error:  # fail closed in the monitor thread
        errors.append(f"{type(error).__name__}:{error}")
    finally:
        for future in pending:
            future.cancel()
        executor.shutdown(wait=True, cancel_futures=True)


def _capture_stream(
    stream: object,
    output_fd: int,
    ceiling: int,
    process_pid: int,
    label: str,
    errors: list[str],
) -> None:
    total = 0
    try:
        while True:
            block = stream.read(64 << 10)  # type: ignore[attr-defined]
            if not block:
                break
            remaining = max(0, ceiling - total)
            retained = block[:remaining]
            offset = 0
            while offset < len(retained):
                offset += os.write(output_fd, retained[offset:])
            total += len(block)
            if total > ceiling and f"{label}-size-limit" not in errors:
                errors.append(f"{label}-size-limit")
                try:
                    os.killpg(process_pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
    except BaseException as error:
        errors.append(f"{label}-capture:{type(error).__name__}:{error}")
    finally:
        try:
            stream.close()  # type: ignore[attr-defined]
        except Exception:
            pass


def _feed_prompt(stream: object, prompt: bytes, errors: list[str]) -> None:
    try:
        offset = 0
        while offset < len(prompt):
            written = stream.write(prompt[offset:])  # type: ignore[attr-defined]
            if not isinstance(written, int) or written <= 0:
                raise OSError("short prompt write")
            offset += written
        stream.flush()  # type: ignore[attr-defined]
    except (BrokenPipeError, OSError) as error:
        errors.append(f"prompt-write:{type(error).__name__}")
    finally:
        try:
            stream.close()  # type: ignore[attr-defined]
        except Exception:
            pass


def _decode_strace_string(token: str) -> bytes:
    if len(token) < 2 or token[0] != '"' or token[-1] != '"':
        raise MonitorError("malformed-strace-string")
    value = token[1:-1]
    result = bytearray()
    index = 0
    while index < len(value):
        if value[index] != "\\":
            # -xx should encode every byte.  Refuse a drifted strace mode.
            raise MonitorError("nonhex-strace-string")
        if value.startswith("\\x", index) and index + 4 <= len(value):
            try:
                result.append(int(value[index + 2:index + 4], 16))
            except ValueError as error:
                raise MonitorError("malformed-strace-string") from error
            index += 4
            continue
        raise MonitorError("nonhex-strace-string")
    return bytes(result)


def _decode_text(token: str) -> str:
    try:
        return _decode_strace_string(token).decode("utf-8")
    except UnicodeDecodeError as error:
        raise MonitorError("non-utf8-exec-argument") from error


def _quoted_tokens(value: str) -> list[str]:
    tokens = re.findall(r'"(?:\\x[0-9a-fA-F]{2})*"', value)
    if "..." in value:
        raise MonitorError("truncated-strace-value")
    return tokens


def _syscall_result(body: str) -> int | None:
    match = re.search(r"\)\s+=\s+(-?[0-9]+)(?:\s|\Z)", body)
    return int(match.group(1)) if match else None


def _clone_child(body: str) -> tuple[int, int, bool, str] | None:
    name = body.split("(", 1)[0]
    if name not in {"clone", "clone3", "fork", "vfork"} and not body.startswith("<... clone"):
        return None
    result = _syscall_result(body)
    if result is None or result <= 0:
        return None
    # Combined -f traces use host PIDs as the ordinary return value.  Retain a
    # decoded-PID comment only when strace presents one explicitly.
    comments = re.findall(r"/\*\s*([1-9][0-9]*)\s+in strace's PID NS\s*\*/", body)
    child = int(comments[-1]) if comments else result
    is_thread = "CLONE_THREAD" in body
    flags = re.search(r"flags=([^,)]*)", body)
    if flags is None and name in {"fork", "vfork"}:
        return child, result, False, name
    if flags is None:
        raise MonitorError("missing-clone-flags")
    return child, result, is_thread, flags.group(1).strip()


def _parse_signal_delivery(
    body: str, stamp: float, exec_epoch: int
) -> SignalEvent | None:
    match = _SIGNAL_DELIVERY.fullmatch(body)
    if match is None:
        return None
    fields: dict[str, str] = {}
    for row in match.group("fields").split(", "):
        if "=" not in row:
            raise MonitorError("malformed-signal-delivery")
        name, value = row.split("=", 1)
        if name in fields:
            raise MonitorError("malformed-signal-delivery")
        fields[name] = value
    signal_name = match.group("signal")
    if (fields.get("si_signo") != signal_name
            or not isinstance(fields.get("si_code"), str)):
        raise MonitorError("malformed-signal-delivery")
    sender = fields.get("si_pid")
    uid = fields.get("si_uid")
    if sender is None or uid is None:
        raise MonitorError("malformed-signal-delivery")
    sender_match = re.fullmatch(
        r"([0-9]+)(?: /\* ([1-9][0-9]*) in strace's PID NS \*/)?", sender
    )
    if sender_match is None or not uid.isdecimal():
        raise MonitorError("malformed-signal-delivery")
    status_text = fields.get("si_status")
    if status_text is not None and not re.fullmatch(r"-?[0-9]+", status_text):
        raise MonitorError("malformed-signal-delivery")
    return SignalEvent(
        stamp=stamp,
        signal=signal_name,
        code=fields["si_code"],
        sender_pid=int(sender_match.group(1)),
        sender_host_pid=(
            None if sender_match.group(2) is None else int(sender_match.group(2))
        ),
        sender_uid=int(uid),
        status=None if status_text is None else int(status_text),
        exec_epoch=exec_epoch,
        raw_sha256=digest(body.encode("ascii")),
    )


def _parse_exec(body: str, *, admit_failure: bool = False) -> ExecImage | None:
    if not (body.startswith("execve(") or body.startswith("execveat(")):
        return None
    result = _syscall_result(body)
    if result != 0 and not admit_failure:
        raise MonitorError("failed-exec")
    syscall = "execveat" if body.startswith("execveat(") else "execve"
    if syscall == "execveat":
        return ExecImage(0.0, "", [], syscall)
    tokens = _quoted_tokens(body)
    if len(tokens) < 2:
        raise MonitorError("malformed-exec")
    path = _decode_text(tokens[0])
    # All remaining quoted strings before the environment pointer are argv.
    argv_region = body[body.find("[") + 1:body.rfind("]")]
    argv = [_decode_text(token) for token in _quoted_tokens(argv_region)]
    if not argv:
        raise MonitorError("empty-exec-argv")
    return ExecImage(0.0, path, argv, syscall)


def _parse_write(body: str) -> tuple[int, bytes] | None:
    result = _syscall_result(body)
    descriptor = re.match(r"writev?\(([0-9]+),", body)
    if descriptor is not None and int(descriptor.group(1)) != 1:
        # Only fd 1 is evidence. In particular, do not decode or reject a
        # truncated write of staged executable bytes to another descriptor.
        return int(descriptor.group(1)), b""
    if result is None and re.search(r"\)\s+=\s+\?\s+ERESTART[A-Z]*", body):
        return (int(descriptor.group(1)), b"") if descriptor else None
    if result is not None and result < 0:
        return (int(descriptor.group(1)), b"") if descriptor else None
    if body.startswith("write("):
        match = re.match(r'write\(([0-9]+),\s*("(?:\\x[0-9a-fA-F]{2})*"),\s*([0-9]+)\s*\)\s+=\s+(-?[0-9]+)', body)
        if not match:
            raise MonitorError("malformed-write")
        fd, declared, returned = int(match.group(1)), int(match.group(3)), int(match.group(4))
        data = _decode_strace_string(match.group(2))
        if declared != len(data) or returned > declared:
            raise MonitorError("incoherent-write")
        return fd, data[:returned]
    if body.startswith("writev("):
        fd_match = re.match(r"writev\(([0-9]+),", body)
        returned = _syscall_result(body)
        if not fd_match or returned is None:
            raise MonitorError("malformed-writev")
        pieces = [_decode_strace_string(token) for token in _quoted_tokens(body)]
        data = b"".join(pieces)
        if returned > len(data):
            raise MonitorError("incoherent-writev")
        return int(fd_match.group(1)), data[:returned]
    return None


def _parse_nonstdout_write(body: str, stamp: float, exec_epoch: int) -> NonStdoutWrite | None:
    match = re.match(r"(write|writev)\(([0-9]+),", body)
    if match is None or int(match.group(2)) == 1:
        return None
    returned = _syscall_result(body)
    if returned is None:
        return None
    declared = None
    if match.group(1) == "write":
        declared_match = re.match(
            r'write\([0-9]+,\s*"(?:\\x[0-9a-fA-F]{2})*",\s*([0-9]+)\s*\)', body
        )
        if declared_match is not None:
            declared = int(declared_match.group(1))
    nul_signal = bool(re.fullmatch(
        r'write\([0-9]+,\s*"\\x00",\s*1\s*\)\s*=\s*1', body
    ))
    return NonStdoutWrite(
        stamp, int(match.group(2)), match.group(1), returned, declared,
        nul_signal, exec_epoch,
    )


def _unsupported_stdout_call(body: str) -> str | None:
    """Name a successful output syscall that can target fd 1 but is not decoded."""
    result = _syscall_result(body)
    if result is None or result < 0:
        return None
    name = body.split("(", 1)[0]
    if name == "io_uring_enter":
        # The submitted SQEs are not visible in this trace contract.
        return name
    arguments = body.split("(", 1)[1]
    descriptors = [int(value) for value in re.findall(r"(?:^|,\s*)([0-9]+)(?:,|\s)", arguments)]
    if name in {"pwrite64", "pwritev", "pwritev2", "sendfile", "vmsplice"}:
        return name if descriptors[:1] == [1] else None
    if name in {"splice", "copy_file_range"}:
        return name if 1 in descriptors[:2] else None
    return None


def parse_trace(data: bytes, *, max_bytes: int = MAX_TRACE_BYTES) -> ParsedTrace:
    if len(data) > max_bytes:
        raise MonitorError("trace-size-limit")
    try:
        lines = data.decode("ascii").splitlines()
    except UnicodeDecodeError as error:
        raise MonitorError("non-ascii-trace") from error
    processes: dict[int, Process] = {}
    pending: dict[tuple[int, str], tuple[str, float]] = {}
    first = float("inf")
    last = 0.0
    for number, line in enumerate(lines, 1):
        match = _PREFIX.fullmatch(line)
        if not match:
            raise MonitorError("malformed-trace-line", f"line {number}")
        pid, stamp, body = int(match.group("pid")), float(match.group("stamp")), match.group("body")
        first, last = min(first, stamp), max(last, stamp)
        process = processes.setdefault(pid, Process(pid))
        if process.ended is not None:
            raise MonitorError("reused-process-id", str(pid))
        process.started = stamp if process.started is None else min(process.started, stamp)
        if "<unfinished ...>" in body:
            name = body.split("(", 1)[0]
            key = (pid, name)
            if key in pending:
                raise MonitorError("nested-unfinished-syscall", f"{pid}:{name}")
            pending[key] = (body.replace("<unfinished ...>", ""), stamp)
            continue
        syscall_stamp = stamp
        resumed = re.match(r"<\.\.\. ([a-zA-Z0-9_]+) resumed>(.*)", body)
        if resumed:
            key = (pid, resumed.group(1))
            pending_row = pending.pop(key, None)
            if pending_row is None:
                process.parse_failures.append(body)
                continue
            initial, syscall_stamp = pending_row
            body = initial + resumed.group(2)
        child = _clone_child(body)
        if child is not None:
            child_pid, namespace_pid, is_thread, clone_flags = child
            target = processes.setdefault(child_pid, Process(child_pid))
            if (target.parent is not None
                    or target.started is not None and target.started < syscall_stamp):
                raise MonitorError("reused-process-id", str(child_pid))
            if target.clone_flags is not None or target.namespace_pid is not None:
                raise MonitorError("reused-process-id", str(child_pid))
            target.parent = pid
            target.namespace_pid = namespace_pid
            target.thread = is_thread
            target.clone_flags = clone_flags
            target.started = syscall_stamp if target.started is None else min(
                target.started, syscall_stamp
            )
            continue
        if body.startswith("execve"):
            try:
                result = _syscall_result(body)
                image = _parse_exec(body, admit_failure=True)
            except MonitorError as error:
                process.parse_failures.append(error.code)
                continue
            if image is not None:
                image.stamp = stamp
                (process.execs if result == 0 else process.failed_execs).append(image)
            continue
        try:
            nonstdout = (
                _parse_nonstdout_write(body, stamp, len(process.execs))
                if body.startswith(("write(", "writev(")) else None
            )
            write = _parse_write(body) if body.startswith(("write(", "writev(")) else None
        except MonitorError as error:
            process.parse_failures.append(error.code)
            continue
        if nonstdout is not None:
            process.nonstdout_writes.append(nonstdout)
        if write is not None:
            fd, payload = write
            if fd == 1 and payload:
                process.stdout.append(WriteEvent(stamp, payload, len(process.execs)))
            continue
        if body.startswith(_UNSUPPORTED_STDOUT):
            if unsupported := _unsupported_stdout_call(body):
                process.unsupported_stdout.append(unsupported)
            continue
        try:
            signal_event = _parse_signal_delivery(body, stamp, len(process.execs))
        except MonitorError as error:
            process.parse_failures.append(error.code)
            continue
        if signal_event is not None:
            process.signal_events.append(signal_event)
            continue
        if body.startswith("--- SIG"):
            process.parse_failures.append("malformed-signal-delivery")
            continue
        exited = _EXIT.fullmatch(body)
        if exited:
            process.ended = stamp
            process.exit_code = int(exited.group("code"))
            continue
        killed = _KILLED.fullmatch(body)
        if killed:
            process.ended = stamp
            process.signal = killed.group("signal")
            continue
    if not lines:
        raise MonitorError("empty-trace")
    for (pid, name), _row in pending.items():
        processes[pid].parse_failures.append(f"unfinished:{name}")
    return ParsedTrace(processes, first, last)


def _children(trace: ParsedTrace) -> dict[int, list[int]]:
    result: dict[int, list[int]] = {}
    for pid, process in trace.processes.items():
        if process.parent is not None:
            result.setdefault(process.parent, []).append(pid)
    for values in result.values():
        values.sort(key=lambda pid: (trace.processes[pid].started or 0, pid))
    return result


def _descendants(children: Mapping[int, Sequence[int]], roots: Iterable[int]) -> set[int]:
    pending = list(roots)
    found = set(pending)
    while pending:
        parent = pending.pop()
        for child in children.get(parent, ()):
            if child not in found:
                found.add(child)
                pending.append(child)
    return found


def _thread_group(trace: ParsedTrace, children: Mapping[int, Sequence[int]], root: int) -> set[int]:
    group = {root}
    pending = [root]
    while pending:
        parent = pending.pop()
        for child in children.get(parent, ()):
            if trace.processes[child].thread and child not in group:
                group.add(child)
                pending.append(child)
    return group


def _stdout(
    trace: ParsedTrace,
    pids: Iterable[int],
    *,
    final_epoch: bool = False,
    epoch_start: float | None = None,
) -> bytes:
    events = [
        event
        for pid in pids
        for event in trace.processes[pid].stdout
        if ((not final_epoch or not trace.processes[pid].execs
             or event.exec_epoch == len(trace.processes[pid].execs))
            and (epoch_start is None or event.stamp >= epoch_start))
    ]
    events.sort(key=lambda event: event.stamp)
    return b"".join(event.data for event in events)


def _native_commands(raw: bytes) -> tuple[str, list[dict[str, object]]]:
    thread_ids: list[str] = []
    commands: list[dict[str, object]] = []
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise MonitorError("non-utf8-codex-jsonl") from error
    for number, line in enumerate(text.splitlines(), 1):
        try:
            event = json.loads(line)
        except (json.JSONDecodeError, TypeError) as error:
            raise MonitorError("invalid-codex-jsonl", f"line {number}") from error
        if not isinstance(event, dict) or not isinstance(event.get("type"), str):
            raise MonitorError("invalid-codex-event", f"line {number}")
        if event["type"] == "thread.started":
            thread = event.get("thread_id")
            if not isinstance(thread, str):
                raise MonitorError("invalid-codex-session")
            thread_ids.append(thread)
        if event["type"] == "item.completed" and isinstance(event.get("item"), dict):
            item = event["item"]
            if item.get("type") == "command_execution":
                required = ("id", "command", "aggregated_output", "exit_code", "status")
                if not all(key in item for key in required):
                    raise MonitorError("incomplete-command-item")
                if not all(isinstance(item[key], str) for key in ("id", "command", "aggregated_output", "status")):
                    raise MonitorError("invalid-command-item")
                if type(item["exit_code"]) is not int or item["status"] not in {"completed", "failed"}:
                    raise MonitorError("invalid-command-item")
                _ordinary_id(item["id"], "native item")
                commands.append(item)
    if len(thread_ids) != 1 or len(set(thread_ids)) != 1:
        raise MonitorError("ambiguous-codex-session")
    if len({item["id"] for item in commands}) != len(commands):
        raise MonitorError("duplicate-command-item")
    return thread_ids[0], commands


_PROC_FD = re.compile(r"/proc/self/fd/[0-9]+\Z")
_CODEX_ARG0_TOOL = re.compile(
    r"(/runtime/codex-home/tmp/arg0-linux/codex-arg0[A-Za-z0-9]{6})/(lsb_release|getconf)\Z"
)
_LOOPBACK_DEMO_URL = re.compile(r"http://127\.0\.0\.1:[1-9][0-9]{0,4}/app/api/me\Z")
_DEMO_RUNTIME_ID = re.compile(r"[0-9a-f]{32}\Z")
_DEMO_LISTENER = re.compile(r"127\.0\.0\.1:([1-9][0-9]{0,4})\Z")
_DEMO_STARTED_AT = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"\.[0-9]{1,9}Z\Z"
)
_DEMO_CONTROL_SOCKET = re.compile(
    r"/tmp/scourge-demo-[A-Za-z0-9]{6}/teapot/([0-9a-f]{32})/control\.sock\Z"
)
_INVESTIGATION_RECEIPT = re.compile(
    r"scourge/(?:record|verification-publication)/[0-9a-f]{64}\Z"
)


def _safe_absolute_argument(value: str) -> bool:
    path = PurePosixPath(value)
    return path.is_absolute() and ".." not in path.parts and path.as_posix() == value


def _investigation_argv(argv: Sequence[str], exec_path: str) -> bool:
    if not argv or argv[0] != exec_path or len(argv) > 32:
        return False
    if any(not isinstance(value, str) or not value or len(value.encode()) > 4096 for value in argv):
        return False
    args = list(argv[1:])
    if args == ["--version"]:
        return True
    if args[:4] != ["--format", "json", "--actor", "agent:scourge"]:
        return False
    args = args[4:]
    if (len(args) == 5 and args[0] == "init" and _safe_absolute_argument(args[1])
            and args[2] == "--no-vault" and args[3] == "--import-root"
            and _safe_absolute_argument(args[4])):
        return True
    if args[:1] == ["--workspace"]:
        if len(args) < 3 or not _safe_absolute_argument(args[1]):
            return False
        args = args[2:]
    recognized = (
        args == ["config", "get", "import_roots"]
        or len(args) == 3 and args[:2] == ["ingest", "--input"] and _safe_absolute_argument(args[2])
        or len(args) == 4 and args[0] == "capture" and args[1] in {"begin", "attach", "finalize"}
            and args[2:] == ["--input", "-"]
        or len(args) == 4 and args[:2] == ["capture", "recover"] and args[2] == "--handle"
            and _ID.fullmatch(args[3]) is not None
        or len(args) == 2 and args[0] == "receipt"
            and (args[1] == "scourge/evidence/case-v1"
                 or _INVESTIGATION_RECEIPT.fullmatch(args[1]) is not None)
        or args == ["case", "new", "Scourge evidence", "--mode", "record", "--command-id",
                    "scourge/evidence/case-v1"]
        or len(args) == 6 and args[0] == "--case" and _ID.fullmatch(args[1]) is not None
            and args[2] == "show" and _ID.fullmatch(args[3]) is not None
            and args[4:] == ["--depth", "full"]
        or len(args) == 7 and args[0] == "--case" and _ID.fullmatch(args[1]) is not None
            and args[2:4] == ["evidence", "read"] and _ID.fullmatch(args[4]) is not None
            and args[5:] == ["--selector-file", "-"]
    )
    return bool(recognized)


def _historical_teapot_argv(
    argv: Sequence[str], exec_path: str, preparation_root: str
) -> bool:
    """Admit only the native calls made by the built-in protected demo prep."""
    path = PurePosixPath(exec_path)
    root = PurePosixPath(preparation_root)
    try:
        relative = path.relative_to(root)
    except ValueError:
        return False
    if (len(relative.parts) != 2 or relative.name != "teapot" or not argv
            or argv[0] != exec_path or len(argv) > 16):
        return False
    project = path.parent / "project"
    prefix = [exec_path, "--project", project.as_posix(), "--json"]
    if list(argv[:4]) != prefix:
        return False
    args = list(argv[4:])
    sessions = {
        "alice", "bob", "alice_same", "alice_verify", "bob_verify",
        "alice_verify_same", "scourge_anonymous",
    }
    if args in (
        ["version"], ["projects", "init"], ["scope", "add", "127.0.0.1"],
        ["config", "set", "pass.relay", "block"],
        ["config", "set", "pass.required", "true"],
        ["pass", "show"], ["proxy", "status"], ["proxy", "stop"],
        ["rules", "list"], ["intercept", "status"],
        ["intercept", "rules", "list"], ["scripts", "list"],
        ["config", "list"],
    ):
        return True
    if len(args) == 3 and args[:2] == ["sessions", "create"]:
        return args[2] == "scourge_anonymous"
    if (len(args) == 7 and args[:2] == ["sessions", "create"]
            and args[2] in sessions and args[3:] == [
                "--domain", "127.0.0.1", "--cookie", "scourge_session=-"
            ]):
        return True
    if (len(args) == 6 and args[:3] == ["requests", "send", "GET"]
            and _LOOPBACK_DEMO_URL.fullmatch(args[3]) is not None
            and args[4] == "--session" and args[5] in sessions):
        return True
    if (len(args) == 7 and args[:2] == ["flows", "show"] and args[2].isdecimal()
            and args[3:] == ["--part", "response", "--max-body", "4096"]):
        return True
    if len(args) == 3 and args[:2] == ["sessions", "show"] and args[2] in sessions:
        return True
    return bool(
        len(args) == 7
        and args[:4] == ["proxy", "start", "--listen", "127.0.0.1:0"]
        and args[4:6] == ["--lock-policy", "--pass"]
        and args[6] == (path.parent / "demo.pass.toml").as_posix()
    )


def _demo_start_argv(argv: Sequence[str], config: MonitorConfig) -> bool:
    return bool(
        config.preparation_teapot_path is not None
        and config.investigation_path is not None
        and list(argv) == [
            config.scourge_path, "--format", "json", "demo", "/workspace/demo",
            "--teapot", config.preparation_teapot_path,
            "--investigation", config.investigation_path,
            "--managed-guide", "false", "--referee-root", "/runtime/referee",
        ]
    )


def _demo_stop_argv(argv: Sequence[str], config: MonitorConfig) -> bool:
    return list(argv) == [
        config.scourge_path, "--format", "json", "demo", "--stop", "/workspace/demo"
    ]


def _exact_json_lines(data: bytes, count: int, label: str) -> list[dict[str, object]]:
    """Decode the historical engine's compact JSONL without normalizing bytes."""
    lines = data.splitlines(keepends=True)
    if len(lines) != count or any(not line.endswith(b"\n") for line in lines):
        raise MonitorError("demo-engine-output", label)
    values: list[dict[str, object]] = []
    for line in lines:
        try:
            value = json.loads(line)
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError) as error:
            raise MonitorError("demo-engine-output", label) from error
        if (not isinstance(value, dict)
                or json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode()
                + b"\n" != line):
            raise MonitorError("demo-engine-output", label)
        values.append(value)
    return values


def _demo_engine_output_receipt(
    trace: ParsedTrace,
    children: Mapping[int, Sequence[int]],
    engine_start: Process,
    engine_stop: Process,
    external_stop: Process,
) -> dict[str, object]:
    """Bind the exact historical proxy start/stop result pair and its ordering."""
    assert engine_start.final is not None and engine_stop.final is not None
    start_group = _thread_group(trace, children, engine_start.pid)
    stop_group = _thread_group(trace, children, engine_stop.pid)
    start_events = sorted(
        (
            (pid, event)
            for pid in start_group
            for event in trace.processes[pid].stdout
            if event.exec_epoch == len(trace.processes[pid].execs)
            and event.stamp >= engine_start.final.stamp
        ),
        key=lambda row: (row[1].stamp, row[0]),
    )
    stop_events = sorted(
        (
            (pid, event)
            for pid in stop_group
            for event in trace.processes[pid].stdout
            if event.exec_epoch == len(trace.processes[pid].execs)
            and event.stamp >= engine_stop.final.stamp
        ),
        key=lambda row: (row[1].stamp, row[0]),
    )
    if (len(start_events) != 2 or len(stop_events) != 1
            or any(pid != engine_start.pid for pid, _event in start_events)
            or stop_events[0][0] != engine_stop.pid):
        raise MonitorError("demo-engine-output-events")
    start_data = b"".join(event.data for _pid, event in start_events)
    stop_data = b"".join(event.data for _pid, event in stop_events)
    start_values = _exact_json_lines(start_data, 2, "start")
    stop_values = _exact_json_lines(stop_data, 1, "stop")
    engine, stopped = start_values
    stop_value = stop_values[0]
    engine_keys = [
        "build", "control_socket", "enforced", "instance", "listener", "mode",
        "pass", "pid", "policy_locked", "project", "project_id", "started_at",
    ]
    if list(engine) != engine_keys:
        raise MonitorError("demo-engine-output", "start-engine-keys")
    instance = engine.get("instance")
    project_id = engine.get("project_id")
    listener = engine.get("listener")
    control_socket = engine.get("control_socket")
    started_at = engine.get("started_at")
    listener_match = (
        _DEMO_LISTENER.fullmatch(listener) if isinstance(listener, str) else None
    )
    control_match = (
        _DEMO_CONTROL_SOCKET.fullmatch(control_socket)
        if isinstance(control_socket, str) else None
    )
    expected_project = engine_start.final.argv[2]
    expected_pass = engine_start.final.argv[-1]
    if (engine.get("build") != "0.1.0" or engine.get("enforced") is not False
            or engine.get("mode") != "regular" or engine.get("policy_locked") is not True
            or engine.get("project") != expected_project or engine.get("pass") != expected_pass
            or not isinstance(instance, str) or _DEMO_RUNTIME_ID.fullmatch(instance) is None
            or not isinstance(project_id, str) or _DEMO_RUNTIME_ID.fullmatch(project_id) is None
            or listener_match is None or int(listener_match.group(1)) > 65535
            or control_match is None or control_match.group(1) != project_id
            or type(engine.get("pid")) is not int or engine["pid"] <= 0
            or not isinstance(started_at, str) or _DEMO_STARTED_AT.fullmatch(started_at) is None):
        raise MonitorError("demo-engine-output", "start-engine")
    expected_stopped = {
        "advice": [],
        "proxy": {
            "engine": engine,
            "state": "stopped",
            "stopped": {
                "capture_error": None,
                "control_error": None,
                "lines": [],
                "quiescent": True,
                "self_stop": None,
            },
        },
    }
    expected_stop = {
        "advice": [],
        "proxy": {
            "instance": instance,
            "pid": engine["pid"],
            "stopped": True,
            "was_running": True,
        },
    }
    if stopped != expected_stopped or stop_value != expected_stop:
        raise MonitorError("demo-engine-output", "stop-pair")
    if (external_stop.started is None
            or not (engine_start.final.stamp < start_events[0][1].stamp
                    < external_stop.started <= engine_stop.final.stamp
                    < min(start_events[1][1].stamp, stop_events[0][1].stamp))):
        raise MonitorError("demo-engine-output-order")

    completion_order = [
        role for _stamp, role in sorted((
            (start_events[1][1].stamp, "start-settled"),
            (stop_events[0][1].stamp, "stop-ack"),
        ))
    ]

    def receipt_events(rows: Sequence[tuple[int, WriteEvent]]) -> list[dict[str, object]]:
        return [
            {
                "process_id": pid,
                "timestamp": event.stamp,
                "bytes": len(event.data),
                "sha256": digest(event.data),
            }
            for pid, event in rows
        ]

    return {
        "contract": "historical-teapot-proxy-start-stop-v1",
        "start_process_id": engine_start.pid,
        "stop_process_id": engine_stop.pid,
        "external_stop_process_id": external_stop.pid,
        "start_exec_timestamp": engine_start.final.stamp,
        "stop_exec_timestamp": engine_stop.final.stamp,
        "external_stop_started": external_stop.started,
        "start_ended": engine_start.ended,
        "stop_ended": engine_stop.ended,
        "start_stdout_sha256": digest(start_data),
        "start_stdout_bytes": len(start_data),
        "start_stdout_events": receipt_events(start_events),
        "stop_stdout_sha256": digest(stop_data),
        "stop_stdout_bytes": len(stop_data),
        "stop_stdout_events": receipt_events(stop_events),
        "completion_write_order": completion_order,
        "instance": instance,
        "project_id": project_id,
    }


def _proxy_probe_argv(argv: Sequence[str], config: MonitorConfig) -> bool:
    port = (
        config.supervisor.proxy_port if config.supervisor is not None
        else dict(config.worker_environment).get("M0_PROXY_PORT")
    )
    if port is None or not str(port).isdecimal():
        return False
    return list(argv) == [
        "/bin/bash", "-c",
        ("printf '%s\\n' 'offline supervisor proxy probe' > "
         f"/dev/tcp/127.0.0.1/{port}"),
    ]


def _strict_child_argv(
    role: str, argv: Sequence[str], config: MonitorConfig, exec_path: str
) -> bool:
    configured = config.teapot_path if role == "teapot" else config.investigation_path
    if configured is None or not argv or argv[0] != configured:
        if role != "investigation" or not argv or argv[0] != exec_path:
            return False
    if role == "investigation":
        return _investigation_argv(argv, exec_path)
    return (len(argv) <= 64
            and all(isinstance(value, str) and value and len(value.encode()) <= 16384 for value in argv))


def _preparation_teapot(
    process: Process,
    config: MonitorConfig,
    snapshots: Sequence[ExecSnapshot],
) -> tuple[_SnapshotPin, ExecSnapshot] | None:
    image = process.final
    if (image is None or config.preparation_root is None
            or config.preparation_teapot_sha256 is None):
        return None
    if not _historical_teapot_argv(image.argv, image.path, config.preparation_root):
        return None
    _require_role_first_exec(process)
    snapshot = _final_snapshot(process, snapshots)
    if (snapshot.target != image.path or snapshot.sha256 != config.preparation_teapot_sha256
            or not snapshot.regular or snapshot.mode != 0o500
            or snapshot.owner_uid != os.geteuid() or snapshot.parent_mode != 0o700
            or snapshot.parent_owner_uid != os.geteuid()
            or snapshot.parent_device is None or snapshot.parent_inode is None
            or "(deleted)" in snapshot.target or snapshot.target.startswith("/memfd:")):
        raise MonitorError("unsafe-preparation-teapot", str(process.pid))
    return _SnapshotPin(image.path, snapshot.sha256), snapshot


def _require_role_first_exec(process: Process) -> None:
    """Reject any approved native-role lifetime with a launcher/prefix epoch."""

    if (len(process.execs) != 1 or process.failed_execs
            or any(row.exec_epoch == 0 for row in process.stdout)
            or any(row.exec_epoch == 0 for row in process.nonstdout_writes)):
        raise MonitorError("approved-child-role-prefix", str(process.pid))


def _final_snapshot(process: Process, snapshots: Sequence[ExecSnapshot]) -> ExecSnapshot:
    candidates = [row for row in snapshots if row.process_id == process.pid]
    if not candidates:
        raise MonitorError("missing-exec-stop-snapshot", str(process.pid))
    if len({row.process_start_ticks for row in candidates}) != 1:
        raise MonitorError("ambiguous-exec-stop-snapshot", str(process.pid))
    return max(candidates, key=lambda row: (row.sequence, row.observed_monotonic_ns))


def _codex_process_setup(
    process: Process,
    pins: Mapping[str, ExecutablePin],
    config: MonitorConfig,
    snapshots: Sequence[ExecSnapshot],
) -> tuple[ExecSnapshot | None, ExecSnapshot, NonStdoutWrite] | None:
    """Authenticate Codex 0.172's one process-setup re-exec for a tool root."""
    if not config.codex_bootstrap or len(process.execs) != 2:
        return None
    setup, shell = process.execs
    first_fd = setup.argv[2] if len(setup.argv) > 2 else ""
    second_fd = setup.argv[3] if len(setup.argv) > 3 else ""
    expected_shell = ["/bin/sh", "-lc", shell.argv[2] if len(shell.argv) == 3 else ""]
    expected_setup = [
        "/proc/self/exe", "--codex-run-as-process-setup", first_fd, second_fd, "pipe", "",
        "/workspace", "/bin/sh", *expected_shell,
    ]
    if (setup.syscall != "execve" or setup.path != "/proc/self/exe"
            or setup.argv != expected_setup or shell.syscall != "execve"
            or shell.path != "/bin/sh" or shell.argv != expected_shell
            or process.exit_code != 0 or not first_fd.isdecimal()
            or not second_fd.isdecimal()
            or process.clone_flags != CODEX_PROCESS_SETUP_CLONE_FLAGS):
        return None
    first_number, second_number = int(first_fd), int(second_fd)
    rows = sorted(
        (row for row in snapshots if row.process_id == process.pid),
        key=lambda row: (row.sequence, row.observed_monotonic_ns),
    )
    codex_pin = pins.get(config.codex_path)
    shell_pin = pins.get("/bin/sh")
    if (not rows or len(rows) > 3
            or [row.sequence for row in rows] != list(range(1, len(rows) + 1))
            or len({row.process_start_ticks for row in rows}) != 1
            or codex_pin is None or shell_pin is None
            or config.codex_setup_device is None or config.codex_setup_inode is None
            or config.codex_setup_fd_ceiling is None
            or config.codex_setup_fd_access_modes is None):
        raise MonitorError("codex-process-setup-snapshot", str(process.pid))
    signal_writes = [
        row for row in process.nonstdout_writes if row.exec_epoch == 1
    ]
    if (not 4 < first_number <= config.codex_setup_fd_ceiling
            or second_number != 4 or first_number == second_number
            or len(signal_writes) != 1):
        raise MonitorError("codex-process-setup-fd", str(process.pid))
    signal_write = signal_writes[0]
    if (signal_write.descriptor != first_number or signal_write.syscall != "write"
            or signal_write.returned != 1 or signal_write.declared != 1
            or not signal_write.nul_signal
            or not setup.stamp < signal_write.stamp < shell.stamp):
        raise MonitorError("codex-process-setup-signal", str(process.pid))
    setup_rows = [row for row in rows if row.process_setup_fds]
    if len(setup_rows) > 1:
        raise MonitorError("codex-process-setup-fd", str(process.pid))
    marker_rows = [
        row for row in rows
        if row.process_setup_topology_status != "not-applicable"
    ]
    if (len(marker_rows) > 2 or any(
        row.process_setup_observations < 1
        or (row.process_setup_topology_status != "observed"
            and not row.process_setup_topology_status.startswith("unavailable-fd-"))
        or (row.process_setup_topology_status == "observed") != bool(row.process_setup_fds)
        for row in marker_rows
    )):
        raise MonitorError("codex-process-setup-fd", str(process.pid))
    first = setup_rows[0] if setup_rows else None
    second = rows[-1]
    if first is not None:
        if (len(first.process_setup_fds) != 2
                or first.process_setup_observations < 2
                or tuple(row.number for row in first.process_setup_fds)
                != (first_number, second_number)):
            raise MonitorError("codex-process-setup-fd", str(process.pid))
        pipe_inodes = set()
        for descriptor, access_mode in zip(
            first.process_setup_fds, config.codex_setup_fd_access_modes, strict=True
        ):
            match = re.fullmatch(r"pipe:\[([1-9][0-9]*)\]", descriptor.target)
            if (match is None or not stat.S_ISFIFO(descriptor.mode)
                    or descriptor.inode != int(match.group(1))
                    or descriptor.flags & os.O_ACCMODE != access_mode):
                raise MonitorError("codex-process-setup-fd", str(process.pid))
            pipe_inodes.add((descriptor.device, descriptor.inode))
        if len(pipe_inodes) != 2:
            raise MonitorError("codex-process-setup-fd", str(process.pid))
    codex_rows = rows[:-1]
    if (first is not None and first not in codex_rows) or any(
        row.target != config.codex_path or row.sha256 != codex_pin.sha256
        or not row.regular or row.mode & 0o022
        or (row.device, row.inode)
        != (config.codex_setup_device, config.codex_setup_inode)
        for row in codex_rows
    ):
        raise MonitorError("codex-process-setup-snapshot", str(process.pid))
    if (any(row.process_setup_fds for row in rows if row is not first)
            or second.target != "/usr/bin/dash" or second.sha256 != shell_pin.sha256
            or not second.regular or second.mode & 0o022):
        raise MonitorError("codex-process-setup-snapshot", str(process.pid))
    return first, second, signal_write


def _bound_child(
    process: Process,
    config: MonitorConfig,
    snapshots: Sequence[ExecSnapshot],
) -> tuple[str, ExecutablePin, ExecSnapshot]:
    image = process.final
    assert image is not None
    _require_role_first_exec(process)
    if image.syscall != "execve" or _PROC_FD.fullmatch(image.path) is None:
        raise MonitorError("unsafe-executable-path", image.path)
    snapshot = _final_snapshot(process, snapshots)
    if (not snapshot.regular or snapshot.mode != 0o500 or snapshot.owner_uid != os.geteuid()
            or not snapshot.target.startswith("/") or "(deleted)" in snapshot.target
            or snapshot.target.startswith("/memfd:") or snapshot.parent_mode != 0o700
            or snapshot.parent_owner_uid != os.geteuid()
            or snapshot.parent_device is None or snapshot.parent_inode is None):
        raise MonitorError("unsafe-bound-executable", str(process.pid))
    candidates = (
        ("teapot", config.teapot_path, config.teapot_sha256),
        ("investigation", config.investigation_path, config.investigation_sha256),
    )
    for role, configured, expected in candidates:
        argv0_matches = image.argv[0] == (image.path if role == "investigation" else configured)
        if (configured is not None and expected is not None and argv0_matches
                and snapshot.sha256 == expected
                and _strict_child_argv(role, image.argv, config, image.path)):
            return role, config.pins[configured], snapshot
    raise MonitorError("unqualified-bound-executable", str(process.pid))


def _validate_image(
    process: Process,
    pins: Mapping[str, ExecutablePin],
    config: MonitorConfig,
    snapshots: Sequence[ExecSnapshot],
) -> tuple[ExecutablePin | _SnapshotPin, str | None, ExecSnapshot | None]:
    image = process.final
    if image is None:
        raise MonitorError("unresolved-executable", str(process.pid))
    if image.syscall != "execve":
        raise MonitorError("execveat-refused", str(process.pid))
    path = PurePosixPath(image.path)
    if image.path.startswith("/proc/"):
        pin, role, snapshot = None, None, None
        role, pin, snapshot = _bound_child(process, config, snapshots)
        if len(process.execs) != 1:
            raise MonitorError("unresolved-exec-chain", image.path)
        return pin, role, snapshot
    if (not path.is_absolute() or ".." in path.parts
            or "(deleted)" in image.path or image.path.startswith("/memfd:")):
        raise MonitorError("unsafe-executable-path", image.path)
    pin = pins.get(image.path)
    if pin is None:
        preparation = _preparation_teapot(process, config, snapshots)
        if preparation is None:
            raise MonitorError("unresolved-executable", image.path)
        pin, snapshot = preparation
        if len(process.execs) != 1:
            raise MonitorError("unresolved-exec-chain", image.path)
        return pin, "teapot-preparation", snapshot
    if config.teapot_path is not None and image.path == config.teapot_path:
        _require_role_first_exec(process)
    if image.path == "/bin/bash" and config.worker_image_id is not None:
        alias_snapshot = _final_snapshot(process, snapshots)
        if (alias_snapshot.target != "/usr/bin/bash"
                or alias_snapshot.requested_exec_path != "/bin/bash"
                or alias_snapshot.resolution_chain
                != ("/bin", "usr/bin", "/usr/bin/bash")
                or alias_snapshot.alias_requested_fstat is None
                or alias_snapshot.alias_requested_fstat != alias_snapshot.hash_pre_fstat
                or alias_snapshot.hash_pre_fstat != alias_snapshot.hash_post_fstat
                or alias_snapshot.sha256 != pin.sha256
                or not alias_snapshot.regular or alias_snapshot.mode & 0o022):
            raise MonitorError("exec-hash-alias-identity", str(process.pid))
    setup = _codex_process_setup(process, pins, config, snapshots)
    if setup is not None:
        return pin, "codex-tool-launcher", setup[1]
    for prior in process.execs:
        if prior.syscall != "execve" or prior.path not in pins:
            raise MonitorError("unresolved-exec-chain", prior.path or "execveat")
    return pin, None, None


def _thread_leader(trace: ParsedTrace, pid: int) -> int:
    seen: set[int] = set()
    current = pid
    while trace.processes[current].thread:
        if current in seen:
            raise MonitorError("cyclic-process-tree", str(pid))
        seen.add(current)
        parent = trace.processes[current].parent
        if parent is None or parent not in trace.processes:
            raise MonitorError("orphan-thread", str(pid))
        current = parent
    return current


def _signal_rows(
    trace: ParsedTrace, group: Iterable[int]
) -> list[dict[str, object]]:
    rows = [
        {"process_id": pid, **event.json()}
        for pid in group
        for event in trace.processes[pid].signal_events
    ]
    return sorted(rows, key=lambda row: (row["timestamp"], row["process_id"]))


def _descends_from_group(
    trace: ParsedTrace, process: Process, group: set[int]
) -> bool:
    """Prove the retained clone-parent chain reaches one exact thread group."""
    seen: set[int] = set()
    parent = process.parent
    while parent is not None:
        if parent in group:
            return True
        if parent in seen or parent not in trace.processes:
            return False
        seen.add(parent)
        parent = trace.processes[parent].parent
    return False


def _authenticated_exec_group(
    trace: ParsedTrace,
    leader: int,
    group: set[int],
    path: str,
    argv: Sequence[str],
    expected_sha256: str,
    snapshots: Sequence[ExecSnapshot],
) -> bool:
    """Bind one exact executable TGID and every observed member thread."""

    process = trace.processes[leader]
    image = process.final
    if (process.thread or image is None or process.failed_execs
            or image.syscall != "execve" or image.path != path
            or image.argv != list(argv) or process.started is None
            or process.ended is None or process.exit_code != 0
            or process.signal is not None or process.parse_failures
            or process.unsupported_stdout):
        return False
    try:
        snapshot = _final_snapshot(process, snapshots)
    except MonitorError:
        return False
    if (snapshot.target != path or snapshot.sha256 != expected_sha256
            or not snapshot.regular or snapshot.mode & 0o022):
        return False
    for member in group:
        if _thread_leader(trace, member) != leader:
            return False
        if member == leader:
            continue
        thread = trace.processes[member]
        if (not thread.thread or thread.clone_flags != CODEX_THREAD_CLONE_FLAGS
                or thread.execs or thread.failed_execs or thread.started is None
                or thread.ended is None or thread.exit_code != 0
                or thread.signal is not None or thread.parse_failures
                or thread.unsupported_stdout
                or thread.started < process.started or thread.ended > process.ended):
            return False
    return True


def _reparented_demo_fixture_signal(
    trace: ParsedTrace,
    child: Process,
    recipient_group: set[int],
    recipient_is_supervisor: bool,
    codex_group: set[int] | None,
    pins: Mapping[str, ExecutablePin],
    config: MonitorConfig,
    snapshots: Sequence[ExecSnapshot],
) -> bool:
    """Recognize the one long-lived demo fixture reaped by container PID 1.

    The exact demo-start Scourge parent intentionally exits after publishing
    the fixture.  The still-running ``--_scourge-demo-fixture`` child is then
    reparented to the pinned supervisor's documented container-PID-1 reaper
    group and produces one normal SIGCHLD when authenticated demo-stop
    completes.  Its original clone lineage must independently reach the one
    authenticated Codex TGID.  No other orphan class is admitted.
    Executable pins and settled exits are independently checked for every
    process immediately after signal reconciliation.
    """
    if child.parent is None or child.parent in recipient_group:
        return False
    parent = trace.processes.get(child.parent)
    image = child.final
    parent_image = None if parent is None else parent.final
    scourge_pin = pins.get(config.scourge_path)
    try:
        child_snapshot = _final_snapshot(child, snapshots)
    except MonitorError:
        child_snapshot = None
    return bool(
        recipient_is_supervisor
        and codex_group is not None
        and config.preparation_root is not None
        and parent is not None
        and image is not None
        and parent_image is not None
        and scourge_pin is not None
        and child_snapshot is not None
        and len(child.execs) == 1
        and not child.failed_execs
        and image.syscall == "execve"
        and image.path == config.scourge_path
        and image.argv == [config.scourge_path, "--_scourge-demo-fixture"]
        and child_snapshot.target == config.scourge_path
        and child_snapshot.sha256 == scourge_pin.sha256
        and child_snapshot.regular
        and not child_snapshot.mode & 0o022
        and parent_image.path == config.scourge_path
        and _demo_start_argv(parent_image.argv, config)
        and parent.exit_code == 0
        and child.exit_code == 0
        and parent.ended is not None
        and child.ended is not None
        and parent.ended < child.ended
        and _descends_from_group(trace, parent, codex_group)
    )


def _reconcile_signals(
    trace: ParsedTrace,
    assessed: set[int],
    pins: Mapping[str, ExecutablePin],
    config: MonitorConfig,
    snapshots: Sequence[ExecSnapshot],
) -> None:
    """Admit only exact child-exit delivery and Codex setup preemption signals."""
    children = _children(trace)
    groups: dict[int, set[int]] = {}
    for pid in assessed:
        leader = _thread_leader(trace, pid)
        groups.setdefault(leader, set()).add(pid)
    all_groups: dict[int, set[int]] = {}
    for pid in trace.processes:
        leader = _thread_leader(trace, pid)
        all_groups.setdefault(leader, set()).add(pid)
    codex_groups: list[tuple[int, set[int]]] = []
    if config.supervisor is not None:
        codex_pin = pins.get(config.codex_path)
        if codex_pin is not None:
            for candidate_leader, candidate_group in all_groups.items():
                if _authenticated_exec_group(
                    trace, candidate_leader, candidate_group,
                    config.codex_path, config.supervisor.codex_argv,
                    codex_pin.sha256, snapshots,
                ):
                    codex_groups.append((candidate_leader, candidate_group))
    reconciled_children: set[int] = set()
    for pid in assessed:
        process = trace.processes[pid]
        leader = _thread_leader(trace, pid)
        group = groups[leader]
        for event in process.signal_events:
            if event.signal == "SIGCHLD":
                candidates = []
                for child_pid, child in trace.processes.items():
                    identity_matches = (
                        child_pid == event.sender_pid
                        or child.namespace_pid == event.sender_pid
                        or event.sender_host_pid == child_pid
                    )
                    if identity_matches:
                        candidates.append(child)
                if (event.code != "CLD_EXITED" or event.status is None
                        or len(candidates) != 1):
                    raise MonitorError("unreconciled-signal", f"{pid}:{event.signal}")
                child = candidates[0]
                directly_parented = child.parent in group
                recipient_is_supervisor = False
                if config.supervisor is not None:
                    recipient_is_supervisor = _authenticated_exec_group(
                        trace, leader, group, config.supervisor.exec_path,
                        config.supervisor.argv, config.supervisor.sha256, snapshots,
                    )
                leader_process = trace.processes[leader]
                origin_groups = [candidate_group
                                 for codex_leader, candidate_group in codex_groups
                                 if trace.processes[codex_leader].parent in group
                                 and trace.processes[codex_leader].started is not None
                                 and trace.processes[codex_leader].ended is not None
                                 and leader_process.started is not None
                                 and leader_process.ended is not None
                                 and trace.processes[codex_leader].started
                                 >= leader_process.started
                                 and trace.processes[codex_leader].ended
                                 <= leader_process.ended
                                 and _descends_from_group(trace, child, candidate_group)]
                codex_group = origin_groups[0] if len(origin_groups) == 1 else None
                reparented_demo = _reparented_demo_fixture_signal(
                    trace, child, group, recipient_is_supervisor, codex_group,
                    pins, config, snapshots,
                )
                if (not directly_parented and not reparented_demo
                        or child.pid in reconciled_children
                        or child.exit_code != event.status or child.ended is None
                        or child.ended > event.stamp
                        or process.ended is not None and event.stamp > process.ended):
                    raise MonitorError("unreconciled-signal", f"{pid}:{event.signal}")
                reconciled_children.add(child.pid)
                continue
            if event.signal == "SIGURG":
                leader_process = trace.processes[leader]
                setup = _codex_process_setup(
                    leader_process, pins, config, snapshots
                )
                sender_matches = any(
                    member == event.sender_pid
                    or trace.processes[member].namespace_pid == event.sender_pid
                    or member == event.sender_host_pid
                    for member in group
                )
                setup_image = leader_process.execs[0] if setup is not None else None
                shell_image = leader_process.execs[1] if setup is not None else None
                if (event.code != "SI_TKILL" or event.status is not None
                        or setup is None or not sender_matches
                        or setup_image is None or shell_image is None
                        or event.exec_epoch != 1
                        or event.stamp < setup_image.stamp
                        or event.stamp >= shell_image.stamp
                        or leader_process.started is None
                        or event.stamp < leader_process.started
                        or (leader_process.ended is not None
                            and event.stamp > leader_process.ended)):
                    raise MonitorError("unreconciled-signal", f"{pid}:{event.signal}")
                continue
            raise MonitorError("unreconciled-signal", f"{pid}:{event.signal}")


def _settled(
    trace: ParsedTrace,
    pids: Iterable[int],
    pins: Mapping[str, ExecutablePin],
    config: MonitorConfig,
    snapshots: Sequence[ExecSnapshot],
) -> None:
    assessed = set(pids)
    _reconcile_signals(trace, assessed, pins, config, snapshots)
    for pid in assessed:
        process = trace.processes[pid]
        if process.thread and not process.execs:
            if process.parse_failures:
                raise MonitorError("unfinished-assessed-syscall", str(pid))
            if process.signal is not None:
                raise MonitorError("signalled-process", f"{pid}:{process.signal}")
            if process.ended is None or process.exit_code is None:
                raise MonitorError("unclosed-process-tree", str(pid))
            if process.unsupported_stdout:
                raise MonitorError("unsupported-stdout-syscall", str(pid))
            continue
        _validate_image(process, pins, config, snapshots)
        if process.parse_failures:
            raise MonitorError("unfinished-assessed-syscall", f"{pid}:{process.parse_failures!r}")
        if process.failed_execs:
            raise MonitorError("failed-exec", str(pid))
        if process.signal is not None:
            raise MonitorError("signalled-process", f"{pid}:{process.signal}")
        if process.ended is None or process.exit_code is None:
            raise MonitorError("unclosed-process-tree", str(pid))
        if process.unsupported_stdout:
            raise MonitorError("unsupported-stdout-syscall", str(pid))


def _execution(trace: ParsedTrace, process: Process, pin: ExecutablePin | _SnapshotPin,
               group: set[int], pins: Mapping[str, ExecutablePin],
               bound_role: str | None, snapshot: ExecSnapshot | None,
               snapshots: Sequence[ExecSnapshot] = ()) -> dict[str, object]:
    image = process.final
    assert image is not None and process.exit_code is not None
    data = _stdout(trace, group, final_epoch=True, epoch_start=image.stamp)
    row = {
        "process_id": process.pid,
        "parent_process_id": process.parent,
        "argv": image.argv,
        "exec_path": image.path,
        "binary_sha256": pin.sha256,
        "exit_code": process.exit_code,
        "stdout_sha256": digest(data),
        "stdout_bytes": len(data),
        "stdout_offset": None,
        "exec_chain": [],
        "signals": _signal_rows(trace, group),
    }
    snapshot_rows = sorted(
        (entry for entry in snapshots if entry.process_id == process.pid),
        key=lambda entry: (entry.sequence, entry.observed_monotonic_ns),
    )
    for index, entry in enumerate(process.execs):
        if entry.path.startswith("/proc/"):
            if index >= len(snapshot_rows):
                raise MonitorError("missing-exec-stop-snapshot", str(process.pid))
            binary_sha256 = snapshot_rows[index].sha256
        else:
            binary_sha256 = pin.sha256 if entry is image else pins[entry.path].sha256
        row["exec_chain"].append({
            "path": entry.path,
            "argv": entry.argv,
            "syscall": entry.syscall,
            "binary_sha256": binary_sha256,
        })
    if bound_role is not None:
        assert snapshot is not None
        row["resolved_executable"] = snapshot.json()
    if image.path == "/bin/bash" and any(
        entry.process_id == process.pid for entry in snapshots
    ):
        alias_snapshot = _final_snapshot(process, snapshots)
        if alias_snapshot.requested_exec_path == "/bin/bash":
            row["exec_resolution"] = alias_snapshot.json()["path_resolution"]
    return row


def _bind_command_root(
    process: Process,
    item: Mapping[str, object],
    config: MonitorConfig,
    codex_group: set[int],
    snapshots: Sequence[ExecSnapshot],
) -> None:
    """Bind a native item to its direct shell root and native root status."""
    if not process.execs or process.exit_code != item["exit_code"]:
        raise MonitorError("command-root-exit-mismatch", str(process.pid))
    setup = _codex_process_setup(process, config.pins, config, snapshots)
    if setup is not None and process.parent not in codex_group:
        raise MonitorError("codex-process-setup-parent", str(process.pid))
    root = process.final if setup is not None else process.execs[0]
    assert root is not None
    shell = PurePosixPath(root.path).name
    expected = item["command"]
    rendered = None
    if len(root.argv) == 3 and root.argv[1] in {"-c", "-lc"}:
        escaped = root.argv[2].replace("\\", "\\\\").replace('"', '\\"')
        rendered = f'{root.path} {root.argv[1]} "{escaped}"'
    if (root.path not in config.pins or shell not in {"sh", "bash"}
            or root.argv[0] not in {root.path, shell}
            or (root.argv[1:] not in (["-c", expected], ["-lc", expected])
                and expected != rendered)):
        raise MonitorError("command-root-argv-mismatch", str(process.pid))


def _codex_parent_membership(
    trace: ParsedTrace,
    process: Process,
    codex_pid: int,
    codex_group: set[int],
    pins: Mapping[str, ExecutablePin],
    config: MonitorConfig,
    snapshots: Sequence[ExecSnapshot],
) -> dict[str, object]:
    if process.parent not in codex_group or process.clone_flags != CODEX_PROCESS_SETUP_CLONE_FLAGS:
        raise MonitorError("codex-process-setup-parent", str(process.pid))
    leader = trace.processes[codex_pid]
    leader_snapshot = _final_snapshot(leader, snapshots)
    codex_pin = pins[config.codex_path]
    if (leader.final is None or leader.final.path != config.codex_path
            or leader_snapshot.target != config.codex_path
            or leader_snapshot.sha256 != codex_pin.sha256
            or (leader_snapshot.device, leader_snapshot.inode)
            != (config.codex_setup_device, config.codex_setup_inode)):
        raise MonitorError("codex-process-setup-leader", str(codex_pid))
    chain = []
    current = process.parent
    seen = set()
    while current != codex_pid:
        if current is None or current in seen or current not in codex_group:
            raise MonitorError("codex-process-setup-parent", str(process.pid))
        seen.add(current)
        thread = trace.processes[current]
        if (not thread.thread or thread.clone_flags != CODEX_THREAD_CLONE_FLAGS
                or thread.execs or thread.failed_execs or thread.signal is not None
                or thread.ended is None or thread.exit_code is None):
            raise MonitorError("codex-process-setup-thread", str(current))
        chain.append({
            "thread_id": current,
            "created_by": thread.parent,
            "clone_flags": thread.clone_flags,
            "started": thread.started,
            "ended": thread.ended,
            "exit_code": thread.exit_code,
        })
        current = thread.parent
    return {
        "leader_process_id": codex_pid,
        "leader_start_ticks": leader_snapshot.process_start_ticks,
        "leader_exec_path": config.codex_path,
        "leader_binary_sha256": codex_pin.sha256,
        "leader_device": leader_snapshot.device,
        "leader_inode": leader_snapshot.inode,
        "direct_parent_thread_id": process.parent,
        "child_clone_flags": process.clone_flags,
        "thread_chain": chain,
    }


def _login_profile_helpers(
    trace: ParsedTrace,
    children: Mapping[int, Sequence[int]],
    root: int,
    pins: Mapping[str, ExecutablePin],
    config: MonitorConfig,
    snapshots: Sequence[ExecSnapshot],
) -> dict[int, str]:
    """Bind the immutable Debian login-profile prefix of the Codex tool shell."""
    if config.login_profile_sha256 is None:
        return {}
    if _codex_process_setup(trace.processes[root], pins, config, snapshots) is None:
        raise MonitorError("login-profile-root", str(root))
    direct = [
        pid for pid in children.get(root, ()) if not trace.processes[pid].thread
    ]
    direct.sort(key=lambda pid: (trace.processes[pid].started or 0, pid))
    if len(direct) < 4:
        raise MonitorError("login-profile-count", str(root))
    expected = (
        ("/usr/bin/id", ["id", "-u"], b"1000\n", "login-profile-id"),
        ("/usr/bin/id", ["id", "-u"], b"1000\n", "login-profile-id"),
        ("/usr/bin/run-parts", [
            "run-parts", "--list", "--regex",
            r"^[a-zA-Z0-9_][a-zA-Z0-9._-]*\.sh$", "/etc/profile.d",
        ], b"", "login-profile-run-parts"),
    )
    result: dict[int, str] = {}
    prior_end = trace.processes[root].started or 0
    for pid, (path, argv, output, profile_role) in zip(direct[:3], expected, strict=True):
        process = trace.processes[pid]
        group = _thread_group(trace, children, pid)
        pin = pins.get(path)
        snapshot = _final_snapshot(process, snapshots)
        descendants = [
            child for member in group for child in children.get(member, ())
            if not trace.processes[child].thread
        ]
        if (pin is None or process.parent != root or process.final is None
                or len(process.execs) != 1 or process.final.path != path
                or process.final.argv != argv or process.exit_code != 0
                or process.signal is not None or process.parse_failures
                or process.unsupported_stdout or descendants
                or _stdout(trace, group) != output
                or snapshot.target != path or snapshot.sha256 != pin.sha256
                or not snapshot.regular or snapshot.mode & 0o022
                or process.started is None or process.ended is None
                or process.started < prior_end):
            raise MonitorError("login-profile-helper", str(pid))
        prior_end = process.ended
        result[pid] = profile_role
    next_process = trace.processes[direct[3]]
    if next_process.started is None or prior_end > next_process.started:
        raise MonitorError("login-profile-overlap", str(root))
    return result


@dataclass(frozen=True)
class CapturedStdout:
    scourge: dict[int, bytes]
    teapot: dict[int, bytes]
    investigation: dict[int, bytes]


def _codex_bootstrap(
    trace: ParsedTrace,
    children: Mapping[int, Sequence[int]],
    codex_group: set[int],
    roots: Sequence[int],
    pins: Mapping[str, ExecutablePin],
) -> tuple[list[int], list[dict[str, object]]]:
    """Authenticate Codex 0.172's exact short-lived OS detection sequence."""
    if len(roots) < 6:
        raise MonitorError("codex-bootstrap-count-mismatch")
    bootstrap = list(roots[:6])
    expected_kind = ["lsb_release", "getconf"] * 3
    rows = []
    arg0_roots: set[str] = set()
    for pid, kind in zip(bootstrap, expected_kind, strict=True):
        process = trace.processes[pid]
        if (process.parent not in codex_group or process.thread or process.signal is not None
                or process.ended is None or process.unsupported_stdout or process.parse_failures
                or any(not trace.processes[child].thread for child in children.get(pid, ()))):
            raise MonitorError("codex-bootstrap-lineage", str(pid))
        group = _thread_group(trace, children, pid)
        if group != {pid}:
            raise MonitorError("codex-bootstrap-thread", str(pid))
        if kind == "lsb_release":
            attempts = process.failed_execs
            expected_paths = [
                "arg0", "/opt/scourge-bin/lsb_release", "/usr/bin/lsb_release",
                "/bin/lsb_release",
            ]
            if process.execs or process.exit_code != 127 or _stdout(trace, group) != b"":
                raise MonitorError("codex-bootstrap-lsb-release", str(pid))
        else:
            attempts = process.failed_execs
            expected_paths = ["arg0", "/opt/scourge-bin/getconf"]
            final = process.final
            pin = pins.get("/usr/bin/getconf")
            if (final is None or final.path != "/usr/bin/getconf"
                    or final.argv != ["getconf", "LONG_BIT"] or pin is None
                    or process.exit_code != 0 or _stdout(trace, group) != b"64\n"):
                raise MonitorError("codex-bootstrap-getconf", str(pid))
        if len(attempts) != len(expected_paths):
            raise MonitorError("codex-bootstrap-path-search", str(pid))
        rendered_attempts = []
        for index, (attempt, expected_path) in enumerate(
            zip(attempts, expected_paths, strict=True)
        ):
            argv = [kind, "-a"] if kind == "lsb_release" else [kind, "LONG_BIT"]
            match = _CODEX_ARG0_TOOL.fullmatch(attempt.path) if index == 0 else None
            if (attempt.syscall != "execve" or attempt.argv != argv
                    or (index == 0 and (match is None or match.group(2) != kind))
                    or (index > 0 and attempt.path != expected_path)):
                raise MonitorError("codex-bootstrap-path-search", str(pid))
            if match is not None:
                arg0_roots.add(match.group(1))
            rendered_attempts.append({"path": attempt.path, "argv": attempt.argv, "exit_code": 127})
        row = {
            "process_id": pid,
            "parent_process_id": process.parent,
            "role": "support",
            "infrastructure_role": f"codex-os-detection-{kind}",
            "attempted_execs": rendered_attempts,
            "exit_code": process.exit_code,
            "stdout_sha256": digest(_stdout(trace, group)),
            "stdout_bytes": len(_stdout(trace, group)),
        }
        if kind == "getconf":
            assert process.final is not None
            row.update(exec_path=process.final.path, argv=process.final.argv,
                       binary_sha256=pins["/usr/bin/getconf"].sha256)
        rows.append(row)
    if len(arg0_roots) != 1:
        raise MonitorError("codex-bootstrap-arg0-root")
    remaining = list(roots[6:])
    if (not remaining or max(trace.processes[pid].ended or float("inf") for pid in bootstrap)
            >= min(trace.processes[pid].started or 0 for pid in remaining)):
        raise MonitorError("codex-bootstrap-overlap")
    return remaining, rows


def project_trace(
    trace: ParsedTrace,
    raw: bytes,
    config: MonitorConfig,
    *,
    attempt_id: str,
    assignment_sha256: str,
    monitor_sha256: str,
    launch_sha256: str,
    prompt_sha256: str,
    prompt_size_bytes: int,
    raw_trace_sha256: str,
    producer_manifest_sha256: str = "0" * 64,
    monitor_key_commitment: str = "0" * 64,
    exec_snapshots: Sequence[ExecSnapshot] = (),
) -> tuple[dict[str, object], CapturedStdout]:
    """Project a complete trace or fail closed.

    Returns the normalized trace plus exact stdout for every pinned Scourge
    execution and approved native Teapot child, keyed by host PID.
    """
    _ordinary_id(attempt_id, "attempt")
    _expected_digest(assignment_sha256, "assignment")
    _expected_digest(monitor_sha256, "monitor")
    _expected_digest(launch_sha256, "launch")
    _expected_digest(prompt_sha256, "prompt")
    if type(prompt_size_bytes) is not int or prompt_size_bytes < 1:
        raise MonitorError("invalid-trusted-prompt")
    _expected_digest(raw_trace_sha256, "raw trace")
    _expected_digest(producer_manifest_sha256, "producer manifest")
    _expected_digest(monitor_key_commitment, "monitor key commitment")
    if (not config.qualification_child_pins
            and (producer_manifest_sha256 == "0" * 64
                 or monitor_key_commitment == "0" * 64)):
        raise MonitorError("unbound-producer-provenance")
    pins = config.pins
    children = _children(trace)

    codex_candidates: list[tuple[int, set[int]]] = []
    for pid, process in trace.processes.items():
        if process.final is None or process.final.path != config.codex_path:
            continue
        exact_codex_argv = (
            (config.supervisor is None and process.final.argv[:1] == [config.codex_path])
            or (config.supervisor is not None
                and tuple(process.final.argv) == config.supervisor.codex_argv)
        )
        if exact_codex_argv:
            group = _thread_group(trace, children, pid)
            if _stdout(trace, group, final_epoch=True, epoch_start=process.final.stamp) == raw:
                codex_candidates.append((pid, group))
    if len(codex_candidates) != 1:
        observed = [
            (pid, digest(_stdout(
                trace, _thread_group(trace, children, pid), final_epoch=True,
                epoch_start=process.final.stamp,
            )), len(_stdout(
                trace, _thread_group(trace, children, pid), final_epoch=True,
                epoch_start=process.final.stamp,
            )))
            for pid, process in trace.processes.items()
            if process.final is not None and process.final.path == config.codex_path
        ]
        raise MonitorError(
            "codex-stdout-mismatch",
            repr({"expected": (digest(raw), len(raw)), "observed": observed}),
        )
    codex_pid, codex_group = codex_candidates[0]
    _settled(trace, codex_group, pins, config, exec_snapshots)
    infrastructure: dict[str, object]
    if config.supervisor is None:
        if not config.qualification_child_pins:
            raise MonitorError("missing-production-supervisor")
        infrastructure = {"mode": "direct-qualification", "executions": []}
    else:
        supervisor_pid = trace.processes[codex_pid].parent
        supervisor_process = trace.processes.get(supervisor_pid or -1)
        if (supervisor_process is None or supervisor_process.final is None
                or supervisor_process.final.path != config.supervisor.exec_path
                or tuple(supervisor_process.final.argv) != config.supervisor.argv):
            raise MonitorError("supervisor-lineage-mismatch")
        supervisor_group = _thread_group(trace, children, supervisor_process.pid)
        direct_children = {
            child
            for member in supervisor_group
            for child in children.get(member, ())
            if not trace.processes[child].thread
        }
        if direct_children != {codex_pid}:
            raise MonitorError("supervisor-child-mismatch", repr(sorted(direct_children)))
        _settled(trace, supervisor_group, pins, config, exec_snapshots)
        if (supervisor_process.exit_code != trace.processes[codex_pid].exit_code
                or supervisor_process.exit_code != 0):
            raise MonitorError("supervisor-exit-mismatch")
        supervisor_pin, role, snapshot = _validate_image(
            supervisor_process, pins, config, exec_snapshots
        )
        if role is not None or snapshot is not None:
            raise MonitorError("invalid-production-supervisor")
        codex_pin, role, snapshot = _validate_image(
            trace.processes[codex_pid], pins, config, exec_snapshots
        )
        supervisor_row = _execution(
            trace, supervisor_process, supervisor_pin, supervisor_group, pins, None, None
        )
        codex_row = _execution(
            trace, trace.processes[codex_pid], codex_pin, codex_group, pins, role, snapshot
        )
        supervisor_row.update(role="support", infrastructure_role="supervisor")
        codex_row.update(role="support", infrastructure_role="codex")
        infrastructure = {
            "mode": "two-socket-supervisor",
            "forwarding": config.supervisor.json()["forwarding"],
            "executions": [supervisor_row, codex_row],
        }
    session_id, native = _native_commands(raw)

    roots = []
    for member in codex_group:
        for child in children.get(member, ()):
            if not trace.processes[child].thread:
                roots.append(child)
    roots = sorted(set(roots), key=lambda pid: (trace.processes[pid].started or 0, pid))
    if config.codex_bootstrap:
        roots, bootstrap_rows = _codex_bootstrap(
            trace, children, codex_group, roots, pins
        )
        infrastructure["bootstrap"] = bootstrap_rows
        infrastructure["bootstrap_contract"] = "codex-0.172-os-detection-v1"
    if len(roots) != len(native):
        raise MonitorError("command-tree-count-mismatch", f"{len(roots)} != {len(native)}")

    commands: list[dict[str, object]] = []
    scourge_outputs: dict[int, bytes] = {}
    teapot_outputs: dict[int, bytes] = {}
    investigation_outputs: dict[int, bytes] = {}
    prior_end = 0.0
    for root, item in zip(roots, native):
        tree = _descendants(children, [root])
        if tree & codex_group:
            raise MonitorError("cyclic-process-tree")
        _settled(trace, tree, pins, config, exec_snapshots)
        _bind_command_root(trace.processes[root], item, config, codex_group, exec_snapshots)
        root_membership = None
        if _codex_process_setup(trace.processes[root], pins, config, exec_snapshots) is not None:
            root_membership = _codex_parent_membership(
                trace, trace.processes[root], codex_pid, codex_group,
                pins, config, exec_snapshots,
            )
        profile_helpers = _login_profile_helpers(
            trace, children, root, pins, config, exec_snapshots
        )
        start = min(trace.processes[pid].started or float("inf") for pid in tree)
        end = max(trace.processes[pid].ended or 0.0 for pid in tree)
        if start < prior_end:
            raise MonitorError("overlapping-command-trees")
        prior_end = end
        executions = []
        approved_children: dict[int, tuple[int, str]] = {}
        demo_starts: list[int] = []
        demo_stops: list[int] = []
        demo_fixtures: list[int] = []
        demo_engine_starts: list[int] = []
        demo_engine_stops: list[int] = []
        preparation_children: list[int] = []
        proxy_probes: list[int] = []
        demo_preparation: dict[str, object] | None = None
        for pid in sorted(tree, key=lambda value: (trace.processes[value].started or 0, value)):
            process = trace.processes[pid]
            if process.thread and not process.execs:
                continue
            pin, bound_role, snapshot = _validate_image(process, pins, config, exec_snapshots)
            group = _thread_group(trace, children, pid)
            row = _execution(
                trace, process, pin, group, pins, bound_role, snapshot, exec_snapshots
            )
            if bound_role == "codex-tool-launcher":
                row["launcher_contract"] = "codex-0.172-process-setup-v1"
                setup_snapshots = _codex_process_setup(
                    process, pins, config, exec_snapshots
                )
                assert setup_snapshots is not None
                setup_snapshot, _shell_snapshot, setup_signal = setup_snapshots
                row["exec_chain"][0]["binary_sha256"] = pins[config.codex_path].sha256
                row["process_setup"] = {
                    "provenance": "trace-derived",
                    "exec_stop": (
                        None if setup_snapshot is None else setup_snapshot.json()
                    ),
                    "first_fd": process.execs[0].argv[2],
                    "second_literal": process.execs[0].argv[3],
                    "signal": setup_signal.json(),
                    "live_topology": (
                        "unobserved" if setup_snapshot is None else "observed-matching"
                    ),
                    "topology_observations": [
                        entry.json() for entry in exec_snapshots
                        if entry.process_id == process.pid
                        and entry.process_setup_topology_status != "not-applicable"
                    ],
                    "fd_ceiling": config.codex_setup_fd_ceiling,
                    "fd_access_modes": list(config.codex_setup_fd_access_modes or ()),
                    "codex_parent_membership": root_membership,
                }
            executions.append(row)
            names = {PurePosixPath(process.final.path).name, PurePosixPath(process.final.argv[0]).name}
            if any(image.path == config.scourge_path for image in process.execs[:-1]):
                raise MonitorError("nonfinal-scourge-exec", str(pid))
            exact_scourge = (
                process.final.path == config.scourge_path
                and process.final.argv[0] in {config.scourge_path, "scourge"}
                and pin.sha256 == pins[config.scourge_path].sha256
            )
            is_demo_fixture = bool(
                exact_scourge
                and config.preparation_root is not None
                and process.final.argv == [config.scourge_path, "--_scourge-demo-fixture"]
            )
            is_scourge = exact_scourge and not is_demo_fixture
            normal_teapot = (
                config.teapot_path is not None
                and process.final.path == config.teapot_path
                and process.final.argv[0] == config.teapot_path
                and pin.sha256 == pins[config.teapot_path].sha256
            )
            role = (
                "scourge" if is_scourge else
                "scourge-demo-fixture" if is_demo_fixture else
                ("support" if bound_role == "codex-tool-launcher" else
                 (bound_role or ("teapot" if normal_teapot else "support")))
            )
            row["role"] = role
            nested_shell = (
                role == "support" and PurePosixPath(process.final.path).name in {"sh", "bash"}
                and pid != root
            )
            if nested_shell:
                group_children = [
                    child for member in group for child in children.get(member, ())
                    if not trace.processes[child].thread
                ]
                proxy_writes = [
                    event for event in process.stdout
                    if event.exec_epoch == len(process.execs)
                    and event.stamp >= process.final.stamp
                ]
                if (process.parent != root or not _proxy_probe_argv(process.final.argv, config)
                        or process.exit_code != 0 or group_children
                        or process.nonstdout_writes
                        or len(proxy_writes) != 1
                        or proxy_writes[0].data != PROXY_PROBE_OUTPUT
                        or _stdout(trace, group, final_epoch=True,
                                   epoch_start=process.final.stamp) != PROXY_PROBE_OUTPUT):
                    raise MonitorError("unqualified-shell-helper", str(pid))
                row["infrastructure_role"] = "loopback-proxy-probe"
                proxy_probes.append(pid)
            if role == "support":
                if pid in profile_helpers:
                    row["support_role"] = "login-profile"
                    row["infrastructure_role"] = profile_helpers[pid]
                elif pid != root and pid not in proxy_probes:
                    raise MonitorError("unexpected-support-process", str(pid))
            if "scourge" in names and role not in {"scourge", "scourge-demo-fixture"}:
                raise MonitorError("unqualified-scourge-executable", process.final.path)
            if "teapot" in names and role not in {"teapot", "teapot-preparation"}:
                raise MonitorError("unqualified-teapot-executable", process.final.path)
            if "investigation" in names and role != "investigation":
                raise MonitorError("unqualified-investigation-executable", process.final.path)
            if is_scourge:
                if _demo_start_argv(process.final.argv, config):
                    demo_starts.append(pid)
                if _demo_stop_argv(process.final.argv, config):
                    demo_stops.append(pid)
                nonthreads = [
                    child
                    for member in group
                    for child in children.get(member, ())
                    if not trace.processes[child].thread
                ]
                approved = []
                for child in nonthreads:
                    child_process = trace.processes[child]
                    child_pin, child_bound_role, _child_snapshot = _validate_image(
                        child_process, pins, config, exec_snapshots
                    )
                    exact_teapot = (
                        config.teapot_path is not None
                        and child_process.final is not None
                        and child_process.final.path == config.teapot_path
                        and child_process.final.argv[0] == config.teapot_path
                        and child_pin.sha256 == pins[config.teapot_path].sha256
                    )
                    child_role = child_bound_role or ("teapot" if exact_teapot else None)
                    child_fixture = bool(
                        child_process.final is not None
                        and child_process.final.path == config.scourge_path
                        and child_process.final.argv
                        == [config.scourge_path, "--_scourge-demo-fixture"]
                        and child_pin.sha256 == pins[config.scourge_path].sha256
                        and _demo_start_argv(process.final.argv, config)
                    )
                    if child_fixture:
                        child_role = "scourge-demo-fixture"
                    if child_role not in {
                        "teapot", "teapot-preparation", "investigation",
                        "scourge-demo-fixture",
                    }:
                        raise MonitorError("scourge-child-process", str(child))
                    if child_process.exit_code != 0:
                        raise MonitorError("failed-approved-child", str(child))
                    child_group = _thread_group(trace, children, child)
                    grandchildren = [
                        grandchild
                        for member in child_group
                        for grandchild in children.get(member, ())
                        if not trace.processes[grandchild].thread
                    ]
                    if grandchildren and child_role != "scourge-demo-fixture":
                        raise MonitorError("approved-child-process", str(child))
                    approved.append(child)
                    approved_children[child] = (pid, child_role)
                if process.exit_code != item["exit_code"]:
                    raise MonitorError("hidden-scourge-failure", str(pid))
                scourge_outputs[pid] = _stdout(
                    trace, group, final_epoch=True, epoch_start=process.final.stamp
                )
                row["approved_child_processes"] = approved
            elif role == "scourge-demo-fixture":
                approval = approved_children.get(pid)
                if approval is None or approval[1] != role:
                    raise MonitorError("orphan-demo-fixture", str(pid))
                row["parent_process_id"] = approval[0]
                fixture_children = [
                    child
                    for member in group
                    for child in children.get(member, ())
                    if not trace.processes[child].thread
                ]
                if len(fixture_children) != 2:
                    raise MonitorError("demo-fixture-child-mismatch", str(pid))
                fixture_children.sort(
                    key=lambda child: (trace.processes[child].started or 0, child)
                )
                for index, child in enumerate(fixture_children):
                    child_process = trace.processes[child]
                    child_pin, child_role, _snapshot = _validate_image(
                        child_process, pins, config, exec_snapshots
                    )
                    image = child_process.final
                    assert image is not None
                    args = image.argv[4:]
                    expected_kind = (
                        len(args) == 7 and args[:4] == [
                            "proxy", "start", "--listen", "127.0.0.1:0"
                        ] and args[4:6] == ["--lock-policy", "--pass"]
                    ) if index == 0 else args == ["proxy", "stop"]
                    if (child_role != "teapot-preparation" or child_process.exit_code != 0
                            or child_pin.sha256 != PREPARATION_TEAPOT_SHA256
                            or not expected_kind):
                        raise MonitorError("demo-engine-mismatch", str(child))
                    child_group = _thread_group(trace, children, child)
                    if any(
                        not trace.processes[grandchild].thread
                        for member in child_group
                        for grandchild in children.get(member, ())
                    ):
                        raise MonitorError("approved-child-process", str(child))
                    approved_children[child] = (pid, child_role)
                    (demo_engine_starts if index == 0 else demo_engine_stops).append(child)
                row["approved_child_processes"] = fixture_children
                demo_fixtures.append(pid)
            elif role in {"teapot", "teapot-preparation", "investigation"}:
                approval = approved_children.get(pid)
                if approval is None or approval[1] != role:
                    raise MonitorError("orphan-approved-child", str(pid))
                row["parent_process_id"] = approval[0]
                if role in {"teapot", "teapot-preparation"}:
                    teapot_outputs[pid] = _stdout(
                        trace, group, final_epoch=True, epoch_start=process.final.stamp
                    )
                    if role == "teapot-preparation":
                        preparation_children.append(pid)
                else:
                    investigation_outputs[pid] = _stdout(
                        trace, group, final_epoch=True, epoch_start=process.final.stamp
                    )
        if demo_fixtures or preparation_children or demo_starts or demo_stops:
            if not (
                len(demo_starts) == len(demo_stops) == len(demo_fixtures) == 1
                and len(demo_engine_starts) == len(demo_engine_stops) == 1
                and len(proxy_probes) == 1 and preparation_children
            ):
                raise MonitorError("incomplete-demo-preparation-lineage")
            fixture = trace.processes[demo_fixtures[0]]
            start = trace.processes[demo_starts[0]]
            stop = trace.processes[demo_stops[0]]
            proxy_probe = trace.processes[proxy_probes[0]]
            engine_start = trace.processes[demo_engine_starts[0]]
            engine_stop = trace.processes[demo_engine_stops[0]]
            if (fixture.parent != start.pid or start.exit_code != 0 or stop.exit_code != 0
                    or start.ended is None or stop.started is None or stop.ended is None
                    or fixture.ended is None or start.ended > stop.started
                    or stop.started > fixture.ended or proxy_probe.ended is None
                    or start.started is None or proxy_probe.ended > start.started
                    or engine_start.started is None or engine_start.ended is None
                    or engine_stop.started is None or engine_stop.ended is None
                    or engine_start.started >= stop.started
                    or engine_stop.started < stop.started
                    or engine_stop.ended > fixture.ended
                    or engine_start.ended > fixture.ended
                    or engine_stop.ended > stop.ended
                    or engine_start.ended > stop.ended):
                raise MonitorError("unauthenticated-demo-stop")
            demo_preparation = _demo_engine_output_receipt(
                trace, children, engine_start, engine_stop, stop
            )
            demo_preparation.update({
                "fixture_process_id": fixture.pid,
                "fixture_ended": fixture.ended,
                "external_stop_ended": stop.ended,
                "fixture_quiescent": True,
            })
        if len({row["process_id"] for row in executions}) != len(executions):
            raise MonitorError("duplicate-execution-id")
        command_receipt = {
            "native_item": item["id"],
            "command": item["command"],
            "output_sha256": digest(item["aggregated_output"].encode("utf-8")),
            "exit_code": item["exit_code"],
            "tree_closed": True,
            "lost_events": 0,
            "executions": executions,
        }
        if demo_preparation is not None:
            command_receipt["demo_preparation"] = demo_preparation
        commands.append(command_receipt)

    historical_count = sum(
        row["role"] == "teapot-preparation"
        for command_row in commands for row in command_row["executions"]
    )
    request_reference_count = sum(
        row["role"] == "teapot"
        for command_row in commands for row in command_row["executions"]
    )
    value = {
        "schema": SCHEMA,
        "attempt_id": attempt_id,
        "assignment_sha256": assignment_sha256,
        "session_id": session_id,
        "raw_sha256": digest(raw),
        "raw_trace_sha256": raw_trace_sha256,
        "producer_manifest_sha256": producer_manifest_sha256,
        "monitor_key_commitment": monitor_key_commitment,
        "exec_stop_snapshots_sha256": digest(canonical([row.json() for row in exec_snapshots])),
        "exec_stop_snapshot_count": len(exec_snapshots),
        "monitor_sha256": monitor_sha256,
        "podman_argv_sha256": config.podman_argv_sha256,
        "launch_sha256": launch_sha256,
        "prompt_sha256": prompt_sha256,
        "prompt_size_bytes": prompt_size_bytes,
        "drained": True,
        "lost_events": 0,
        "elapsed_milliseconds": max(0, round((trace.last_stamp - trace.first_stamp) * 1000)),
        "commands": commands,
        "codex_process_id": codex_pid,
        "infrastructure": infrastructure,
        "teapot_lanes": {
            "historical_engine_child": {
                "sha256": PREPARATION_TEAPOT_SHA256,
                "execution_count": historical_count,
            },
            "c03_request_reference_standalone": {
                "sha256": REQUEST_REFERENCE_TEAPOT_SHA256,
                "execution_count": request_reference_count,
                "scourge_runtime_binding": False,
            },
        },
    }
    return value, CapturedStdout(scourge_outputs, teapot_outputs, investigation_outputs)


def authenticate_trace(trace: Mapping[str, object], key: bytes) -> dict[str, object]:
    if not isinstance(key, bytes) or len(key) != 32:
        raise MonitorError("invalid-monitor-key")
    return {
        "trace": dict(trace),
        "hmac_sha256": hmac.digest(key, DOMAIN + canonical(trace), "sha256").hex(),
    }


def verify_envelope(envelope: Mapping[str, object], key: bytes) -> bool:
    if set(envelope) != {"trace", "hmac_sha256"} or not isinstance(envelope["trace"], dict):
        return False
    mac = envelope["hmac_sha256"]
    return (isinstance(mac, str) and _DIGEST.fullmatch(mac) is not None
            and len(key) == 32
            and hmac.compare_digest(mac, hmac.digest(key, DOMAIN + canonical(envelope["trace"]), "sha256").hex()))


@dataclass(frozen=True)
class PodmanLaunch:
    name: str
    cidfile: Path
    image: str
    entrypoint: str
    mounts: tuple[str, ...]
    worker_argv: tuple[str, ...]


def _take_pair(argv: Sequence[str], index: int, option: str) -> tuple[str, int]:
    if index + 1 >= len(argv) or argv[index] != option:
        raise MonitorError("unsafe-podman-boundary", option)
    return argv[index + 1], index + 2


def _overlapping_paths(left: Path | PurePosixPath, right: Path | PurePosixPath) -> bool:
    return left == right or left in right.parents or right in left.parents


def _validate_mount_manifest(
    parsed: Sequence[Mapping[str, str]], config: MonitorConfig
) -> None:
    if not config.mounts:
        if config.qualification_child_pins:
            return
        raise MonitorError("missing-mount-manifest")
    if len(parsed) != len(config.mounts):
        raise MonitorError("mount-manifest-mismatch")
    root = Path(config.mount_root or "")
    try:
        root_info = root.lstat()
    except OSError as error:
        raise MonitorError("unsafe-mount-root") from error
    if (root.resolve(strict=True) != root or stat.S_ISLNK(root_info.st_mode)
            or not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid != os.geteuid()
            or stat.S_IMODE(root_info.st_mode) != 0o700):
        raise MonitorError("unsafe-mount-root")
    default_protected = (
        Path("/etc"), Path.home() / ".ssh", Path.home() / ".aws",
        Path.home() / ".config", Path.home() / ".codex", Path.home() / ".agents",
    )
    protected = (*default_protected, *(Path(row) for row in config.protected_mount_roots))
    sources: list[Path] = []
    destinations: list[PurePosixPath] = []
    observed: set[str] = set()
    for fields, pin in zip(parsed, config.mounts, strict=True):
        source = fields.get("src")
        destination = fields.get("dst")
        read_only = fields.get("ro") == "true"
        if (source != pin.source or destination != pin.destination
                or read_only != pin.read_only
                or (pin.read_only and set(fields) != {"type", "src", "dst", "ro"})
                or (not pin.read_only and set(fields) != {"type", "src", "dst"})):
            raise MonitorError("mount-manifest-mismatch")
        source_path = Path(pin.source)
        destination_path = PurePosixPath(pin.destination)
        try:
            info = source_path.lstat()
            resolved = source_path.resolve(strict=True)
        except OSError as error:
            raise MonitorError("unsafe-mount-source", pin.source) from error
        if (resolved != source_path or stat.S_ISLNK(info.st_mode)
                or (info.st_dev, info.st_ino, stat.S_IMODE(info.st_mode), info.st_uid)
                != (pin.device, pin.inode, pin.mode, pin.owner_uid)
                or any(_overlapping_paths(source_path, row) for row in protected)):
            raise MonitorError("unsafe-mount-source", pin.source)
        if any(_overlapping_paths(source_path, row) for row in sources):
            raise MonitorError("overlapping-mount-sources")
        if any(_overlapping_paths(destination_path, row) for row in destinations):
            raise MonitorError("overlapping-mount-destinations")
        if pin.source_class == "private-writable":
            if (pin.destination not in {"/workspace", "/runtime"} or pin.read_only
                    or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) != 0o700
                    or not source_path.is_relative_to(root)):
                raise MonitorError("unsafe-writable-mount", pin.destination)
        elif pin.source_class == "gateway-sockets":
            if (pin.destination != "/gateway" or not pin.read_only
                    or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) != 0o700
                    or not source_path.is_relative_to(root)):
                raise MonitorError("unsafe-gateway-mount")
        else:
            executable = config.pins.get(pin.destination)
            if (executable is None or executable.source != "read-only-mount"
                    or not pin.read_only or not stat.S_ISREG(info.st_mode)
                    or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o022
                    or pin.sha256 != executable.sha256
                    or file_digest(source_path) != executable.sha256):
                raise MonitorError("unsafe-executable-mount", pin.destination)
        sources.append(source_path)
        destinations.append(destination_path)
        observed.add(pin.destination)
    required = {"/workspace", "/runtime", "/gateway"} | {
        pin.path for pin in config.executables if pin.source == "read-only-mount"
    }
    if observed != required:
        raise MonitorError("incomplete-mount-manifest")


def validate_podman_argv(argv: Sequence[str], config: MonitorConfig) -> PodmanLaunch:
    actual_digest = podman_argv_digest(argv)
    if not hmac.compare_digest(actual_digest, config.podman_argv_sha256):
        raise MonitorError("podman-argv-mismatch")
    prefix = [
        config.podman, "--remote=false", f"--runtime={config.crun}", "run",
        "--rm", "--unsetenv-all", "--interactive", "--pull=never", "--network=none",
        "--read-only", "--http-proxy=false", "--cap-drop=all",
        "--security-opt=no-new-privileges", "--pids-limit=128", "--userns=keep-id",
        "--hostname=scourge-worker",
    ]
    if list(argv[:len(prefix)]) != prefix:
        raise MonitorError("unexpected-podman-command")
    index = len(prefix)
    name, index = _take_pair(argv, index, "--name")
    if _CONTAINER_NAME.fullmatch(name) is None:
        raise MonitorError("unsettled-podman-boundary")
    cidfile_text, index = _take_pair(argv, index, "--cidfile")
    cidfile = Path(cidfile_text)
    if not cidfile.is_absolute() or "\0" in cidfile_text or "\n" in cidfile_text:
        raise MonitorError("unsafe-podman-boundary")
    mounts: list[str] = []
    parsed_mounts: list[dict[str, str]] = []
    destinations: set[str] = set()
    while index < len(argv) and argv[index] == "--mount":
        mount, index = _take_pair(argv, index, "--mount")
        parts = mount.split(",")
        if any(part.count("=") != 1 for part in parts):
            raise MonitorError("unsafe-podman-mount")
        rows = [part.split("=", 1) for part in parts]
        if (len({key for key, _value in rows}) != len(rows)
                or not {key for key, _value in rows} <= {"type", "src", "dst", "ro"}):
            raise MonitorError("unsafe-podman-mount")
        fields = dict(rows)
        source = fields.get("src")
        destination = fields.get("dst")
        if (fields.get("type") != "bind" or not source or not destination
                or not _safe_absolute_argument(source) or not _safe_absolute_argument(destination)
                or fields.get("ro") not in {None, "true"} or destination in destinations):
            raise MonitorError("unsafe-podman-mount")
        destinations.add(destination)
        mounts.append(mount)
        parsed_mounts.append(fields)
    if not mounts:
        raise MonitorError("unsafe-podman-boundary")
    _validate_mount_manifest(parsed_mounts, config)

    environment: list[tuple[str, str]] = []
    while index < len(argv) and argv[index] == "--env":
        row, index = _take_pair(argv, index, "--env")
        if "=" not in row:
            raise MonitorError("unsafe-worker-environment")
        environment.append(tuple(row.split("=", 1)))
    if tuple(environment) != config.worker_environment:
        raise MonitorError("unsafe-worker-environment")
    entrypoint, index = _take_pair(argv, index, "--entrypoint")
    expected_entrypoint = (
        config.codex_path if config.supervisor is None else config.supervisor.exec_path
    )
    if entrypoint != expected_entrypoint or index >= len(argv):
        raise MonitorError("unsafe-podman-entrypoint")
    image = argv[index]
    if (_IMAGE_ID.fullmatch(image) is None
            or (config.worker_image_id is not None and image != config.worker_image_id)):
        raise MonitorError("unpinned-podman-image")
    worker_argv = tuple(argv[index + 1:])
    required_disabled = {"code_mode", "code_mode_host", "shell_snapshot"}
    disabled = [
        worker_argv[i + 1]
        for i, word in enumerate(worker_argv[:-1])
        if word == "--disable"
    ]
    if (not worker_argv or worker_argv[-1] != "-"
            or any(not word or "\0" in word for word in worker_argv)
            or not required_disabled <= set(disabled)
            or any(disabled.count(feature) != 1 for feature in required_disabled)):
        raise MonitorError("unsafe-worker-argv")
    if config.supervisor is not None and tuple([entrypoint, *worker_argv]) != config.supervisor.argv:
        raise MonitorError("invalid-supervisor-argv")
    return PodmanLaunch(name, cidfile, image, entrypoint, tuple(mounts), worker_argv)


def monitor_environment(source: Mapping[str, str] | None = None) -> dict[str, str]:
    """Return the exact non-secret host environment admitted to Podman."""
    source = os.environ if source is None else source
    value = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "TZ": "UTC"}
    for name in ("HOME", "XDG_RUNTIME_DIR", "USER", "LOGNAME"):
        item = source.get(name)
        if item is not None and "\0" not in item:
            value[name] = item
    return value


def _podman_control(
    config: MonitorConfig,
    arguments: Sequence[str],
    environment: Mapping[str, str],
    *,
    timeout: float = 30,
) -> int:
    return subprocess.run(
        [config.podman, "--remote=false", *arguments],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
        env=dict(environment),
        timeout=timeout,
        check=False,
    ).returncode


def _podman_query(
    config: MonitorConfig,
    arguments: Sequence[str],
    environment: Mapping[str, str],
) -> tuple[int, bytes]:
    completed = subprocess.run(
        [config.podman, "--remote=false", *arguments],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        close_fds=True,
        env=dict(environment),
        timeout=30,
        check=False,
    )
    return completed.returncode, completed.stdout


def _container_absent(
    config: MonitorConfig, identity: str, environment: Mapping[str, str]
) -> bool:
    deadline = time.monotonic() + 5
    while True:
        status = _podman_control(config, ["container", "exists", identity], environment)
        if status == 1:
            return True
        if status not in {0, 1} or time.monotonic() >= deadline:
            return False
        time.sleep(0.05)


def _read_owned_cid(private: PrivateRoot, launch: PodmanLaunch) -> str | None:
    if launch.cidfile.parent != private.path:
        raise MonitorError("unsafe-container-id-file")
    name = launch.cidfile.name
    try:
        fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=private.fd)
    except FileNotFoundError:
        return None
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_nlink != 1 or info.st_size > 128):
            raise MonitorError("unsafe-container-id-file")
        value = os.read(fd, 129)
    finally:
        os.close(fd)
    cid = value.decode("ascii", errors="strict").strip()
    if _IMAGE_ID.fullmatch(cid) is None:
        raise MonitorError("unsafe-container-id-file")
    return cid


def _watch_owned_cid(
    private: PrivateRoot,
    launch: PodmanLaunch,
    stop: threading.Event,
    observed: list[str],
    errors: list[str],
) -> None:
    """Retain the attempt CID before Podman ``--rm`` removes its cidfile."""
    try:
        while not stop.is_set():
            try:
                cid = _read_owned_cid(private, launch)
            except MonitorError:
                # Podman creates then fills the file. Re-read until the launch
                # settles; the main thread validates any surviving file.
                stop.wait(0.002)
                continue
            if cid is not None:
                if observed and observed[0] != cid:
                    errors.append("container-id-changed")
                    return
                if not observed:
                    observed.append(cid)
            stop.wait(0.002)
    except BaseException as error:
        errors.append(f"cid-watch:{type(error).__name__}:{error}")


def _verify_owned_container(
    config: MonitorConfig, launch: PodmanLaunch, cid: str, environment: Mapping[str, str]
) -> None:
    status, output = _podman_query(
        config, ["inspect", "--format", "{{.Id}}\n{{.Name}}", cid], environment
    )
    if status != 0 or output.decode("utf-8", errors="strict").splitlines() != [cid, launch.name]:
        raise MonitorError("container-identity-mismatch")


def _remove_owned_container(
    config: MonitorConfig,
    launch: PodmanLaunch,
    cid: str | None,
    environment: Mapping[str, str],
) -> bool:
    if cid is None:
        return _container_absent(config, launch.name, environment)
    if _container_absent(config, cid, environment):
        return _container_absent(config, launch.name, environment)
    _verify_owned_container(config, launch, cid, environment)
    status = _podman_control(config, ["rm", "--force", cid], environment)
    return (status == 0 and _container_absent(config, cid, environment)
            and _container_absent(config, launch.name, environment))


def assert_canaries_absent(data: bytes, canaries: Sequence[bytes], label: str) -> None:
    """Reject plaintext and strace ``-xx`` renderings of protected canaries."""
    for canary in canaries:
        if not isinstance(canary, bytes) or not canary or len(canary) > 4096:
            raise MonitorError("invalid-canary", label)
        hex_lower = b"".join(f"\\x{byte:02x}".encode("ascii") for byte in canary)
        hex_upper = hex_lower.upper().replace(b"\\X", b"\\x")
        if canary in data or hex_lower in data or hex_upper in data:
            raise MonitorError("canary-exposure", label)


def _artifact_ref(retained_path: str, name: str, data: bytes) -> dict[str, str]:
    return {
        "path": f"{retained_path}/{name}",
        "sha256": digest(data),
    }


def _open_private_relative(root: PrivateRoot, relative: str) -> PrivateRoot:
    path = PurePosixPath(relative)
    if (path.is_absolute() or not path.parts or any(
        part in {"", ".", ".."} for part in path.parts
    ) or path.as_posix() != relative):
        raise MonitorError("unsafe-evidence-path", relative)
    current = os.dup(root.fd)
    try:
        for part in path.parts:
            following = os.open(
                part,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=current,
            )
            info = os.fstat(following)
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) != 0o700):
                os.close(following)
                raise MonitorError("unsafe-evidence-directory", relative)
            os.close(current)
            current = following
        info = os.fstat(current)
        result_path = root.path.joinpath(*path.parts)
        return PrivateRoot(result_path, current, info.st_dev, info.st_ino)
    except BaseException:
        os.close(current)
        raise


def resolve_evidence_ref(
    evidence_root: os.PathLike[str] | str,
    reference: Mapping[str, object],
    *,
    maximum_bytes: int = MAX_RAW_BYTES,
) -> bytes:
    if set(reference) != {"path", "sha256"}:
        raise MonitorError("invalid-evidence-reference")
    path_text = reference.get("path")
    expected = reference.get("sha256")
    if not isinstance(path_text, str) or not isinstance(expected, str):
        raise MonitorError("invalid-evidence-reference")
    _expected_digest(expected, "evidence")
    path = PurePosixPath(path_text)
    if (path.is_absolute() or len(path.parts) < 2 or any(
        part in {"", ".", ".."} for part in path.parts
    ) or path.as_posix() != path_text):
        raise MonitorError("unsafe-evidence-path", path_text)
    root = PrivateRoot.open(Path(evidence_root))
    directory = None
    try:
        directory = _open_private_relative(root, PurePosixPath(*path.parts[:-1]).as_posix())
        fd = os.open(
            path.parts[-1], os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=directory.fd,
        )
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) != 0o600
                    or info.st_size > maximum_bytes):
                raise MonitorError("unsafe-evidence-file", path_text)
            value = b""
            while len(value) <= maximum_bytes:
                block = os.read(fd, min(1 << 20, maximum_bytes + 1 - len(value)))
                if not block:
                    break
                value += block
            if len(value) > maximum_bytes or digest(value) != expected:
                raise MonitorError("evidence-digest-mismatch", path_text)
            return value
        finally:
            os.close(fd)
    except OSError as error:
        raise MonitorError("unresolved-evidence-reference", path_text) from error
    finally:
        if directory is not None:
            directory.close()
        root.close()


def verify_evidence_projection(
    evidence_root: os.PathLike[str] | str,
    envelope_ref: Mapping[str, object],
    events_ref: Mapping[str, object],
    key: bytes,
) -> tuple[dict[str, object], dict[str, object]]:
    try:
        envelope = json.loads(resolve_evidence_ref(evidence_root, envelope_ref))
        events = json.loads(resolve_evidence_ref(evidence_root, events_ref))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise MonitorError("invalid-evidence-json") from error
    if (not isinstance(envelope, dict) or not isinstance(events, dict)
            or not verify_envelope(envelope, key)):
        raise MonitorError("invalid-evidence-envelope")
    trace = envelope["trace"]
    if (events.get("schema") != EVENTS_SCHEMA
            or events.get("session_id") != trace.get("session_id")
            or events.get("raw_sha256") != trace.get("raw_sha256")
            or events.get("commands") != trace.get("commands")
            or events.get("complete") is not True):
        raise MonitorError("events-projection-mismatch")
    nested = [
        row.get("stdout") for row in events.get("calls", [])
    ] + [
        row.get("file") for row in events.get("child_originals", [])
    ]
    paths: list[str] = []
    for reference in nested:
        if not isinstance(reference, dict):
            raise MonitorError("invalid-evidence-reference")
        resolve_evidence_ref(evidence_root, reference)
        paths.append(reference["path"])
    if len(paths) != len(set(paths)):
        raise MonitorError("duplicate-evidence-reference")
    return envelope, events


def evidence_binding(
    evidence_root: os.PathLike[str] | str,
    envelope_ref: Mapping[str, object],
    events_ref: Mapping[str, object],
    events: Mapping[str, object],
    key: bytes,
) -> dict[str, object]:
    """Bind exported projections and every nested artifact reference."""

    envelope_data = resolve_evidence_ref(evidence_root, envelope_ref)
    events_data = resolve_evidence_ref(evidence_root, events_ref)
    nested_refs = [
        row.get("stdout") for row in events.get("calls", [])
    ] + [
        row.get("file") for row in events.get("child_originals", [])
    ]
    rows: list[dict[str, object]] = []
    for reference in nested_refs:
        if not isinstance(reference, dict):
            raise MonitorError("invalid-evidence-reference")
        data = resolve_evidence_ref(evidence_root, reference)
        rows.append({
            "path": reference["path"],
            "bytes": len(data),
            "sha256": reference["sha256"],
        })
    rows.sort(key=lambda row: str(row["path"]))
    if len({str(row["path"]) for row in rows}) != len(rows):
        raise MonitorError("duplicate-evidence-reference")
    manifest = {
        "schema": "scourge.skeleton-evidence-binding.v1",
        "envelope_sha256": envelope_ref["sha256"],
        "events_sha256": events_ref["sha256"],
        "nested": rows,
    }
    if (digest(envelope_data) != manifest["envelope_sha256"]
            or digest(events_data) != manifest["events_sha256"]):
        raise MonitorError("evidence-digest-mismatch")
    return {
        "manifest": manifest,
        "hmac_sha256": hmac.digest(
            key, EVIDENCE_BINDING_DOMAIN + canonical(manifest), "sha256"
        ).hex(),
    }


def verify_evidence_binding(
    evidence_root: os.PathLike[str] | str,
    envelope_ref: Mapping[str, object],
    events_ref: Mapping[str, object],
    events: Mapping[str, object],
    binding: Mapping[str, object],
    key: bytes,
) -> bool:
    try:
        expected = evidence_binding(
            evidence_root, envelope_ref, events_ref, events, key
        )
    except MonitorError:
        return False
    return dict(binding) == expected and hmac.compare_digest(
        str(binding.get("hmac_sha256", "")), str(expected["hmac_sha256"])
    )


@dataclass(frozen=True)
class MonitorResult:
    envelope: dict[str, object]
    events: dict[str, object]
    envelope_path: Path
    events_path: Path
    envelope_ref: dict[str, str]
    events_ref: dict[str, str]
    evidence_binding: dict[str, object]
    raw_path: Path
    stderr_path: Path
    call_stdout: tuple[Path, ...]
    teapot_stdout: tuple[Path, ...]
    investigation_stdout: tuple[Path, ...]
    exec_snapshots_path: Path
    container_absent: bool
    container_id: str
    container_name: str


def run_monitored(
    podman_argv: Sequence[str],
    *,
    prompt: bytes,
    config: MonitorConfig,
    attempt_id: str,
    assignment_sha256: str,
    key_path: os.PathLike[str] | str,
    private_control_root: os.PathLike[str] | str,
    evidence_root: os.PathLike[str] | str,
    retained_path: str,
    producer_manifest_sha256: str = "0" * 64,
    monitor_key_commitment: str = "0" * 64,
    forbidden_canaries: Sequence[bytes] = (),
    timeout_seconds: float = 900.0,
) -> MonitorResult:
    """Run and settle one foreground worker under the pinned monitor."""
    launch = validate_podman_argv(podman_argv, config)
    _ordinary_id(attempt_id, "attempt")
    if retained_path != f"{attempt_id}/retained/artifacts":
        raise MonitorError("invalid-retained-evidence-path")
    _expected_digest(assignment_sha256, "assignment")
    _expected_digest(producer_manifest_sha256, "producer manifest")
    _expected_digest(monitor_key_commitment, "monitor key commitment")
    if (not config.qualification_child_pins
            and (producer_manifest_sha256 == "0" * 64
                 or monitor_key_commitment == "0" * 64)):
        raise MonitorError("unbound-producer-provenance")
    if not isinstance(timeout_seconds, (int, float)) or not (0 < timeout_seconds <= 3600):
        raise MonitorError("invalid-monitor-timeout")
    private = PrivateRoot.open(Path(private_control_root))
    retained = None
    evidence = None
    raw_fd = None
    stderr_fd = None
    try:
        evidence = PrivateRoot.open(Path(evidence_root))
        retained = _open_private_relative(evidence, retained_path)
        key = read_monitor_key(key_path)
        monitor = freeze_monitor(config)
        launch_pin = freeze_launch(config, monitor["monitor_sha256"], prompt)
        trace_name = f"{attempt_id}.strace"
        raw_name = f"{attempt_id}.jsonl"
        stderr_name = f"{attempt_id}.stderr"
        snapshot_name = f"{attempt_id}.exec-snapshots.json"
        trace_path = private.child(trace_name)
        raw_path = private.child(raw_name)
        stderr_path = private.child(stderr_name)
        trace_fd = private.create_fd(trace_name)
        os.close(trace_fd)
        raw_fd = private.create_fd(raw_name)
        stderr_fd = private.create_fd(stderr_name)
        command = [
            config.strace, *FIXED_STRACE_ARGS, "-o", private.proc_child(trace_name),
            "--", *podman_argv,
        ]
        environment = monitor_environment()
        if launch.cidfile.parent != private.path:
            raise MonitorError("unsafe-container-id-file")
        try:
            os.stat(launch.cidfile.name, dir_fd=private.fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise MonitorError("container-id-file-exists")
        if _podman_control(config, ["container", "exists", launch.name], environment) != 1:
            raise MonitorError("container-name-not-absent")
    except BaseException:
        for fd in (raw_fd, stderr_fd):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
        if retained is not None:
            retained.close()
        if evidence is not None:
            evidence.close()
        private.close()
        raise
    assert retained is not None and raw_fd is not None and stderr_fd is not None
    started = time.monotonic()
    process = None
    watcher = None
    watcher_stop = threading.Event()
    snapshots: list[ExecSnapshot] = []
    watcher_health: dict[str, int] = {}
    watcher_errors: list[str] = []
    stream_errors: list[str] = []
    stream_threads: list[threading.Thread] = []
    cid_thread = None
    observed_cids: list[str] = []
    container_settled = False
    owned_cid = None
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            close_fds=True,
            env=environment,
        )
        assert process.stdin is not None and process.stdout is not None and process.stderr is not None
        cid_thread = threading.Thread(
            target=_watch_owned_cid,
            args=(private, launch, watcher_stop, observed_cids, watcher_errors),
            name="scourge-container-id-watcher",
            daemon=True,
        )
        cid_thread.start()
        for label, stream, fd in (
            ("raw", process.stdout, raw_fd), ("stderr", process.stderr, stderr_fd),
        ):
            thread = threading.Thread(
                target=_capture_stream,
                args=(stream, fd, config.max_raw_bytes, process.pid, label, stream_errors),
                name=f"scourge-{label}-capture",
                daemon=True,
            )
            thread.start()
            stream_threads.append(thread)
        prompt_thread = threading.Thread(
            target=_feed_prompt,
            args=(process.stdin, prompt, stream_errors),
            name="scourge-prompt-writer",
            daemon=True,
        )
        prompt_thread.start()
        stream_threads.append(prompt_thread)
        watcher = threading.Thread(
            target=_watch_exec_snapshots,
            args=(process.pid, watcher_stop, snapshots, watcher_errors, trace_path,
                  config.max_trace_bytes, watcher_health, config),
            name="scourge-exec-snapshot-watcher",
            daemon=True,
        )
        watcher.start()
        try:
            returncode = process.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired as error:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            watcher_stop.set()
            watcher.join(timeout=5)
            cid_thread.join(timeout=5)
            for thread in stream_threads:
                thread.join(timeout=5)
            owned_cid = observed_cids[0] if observed_cids else _read_owned_cid(private, launch)
            container_settled = _remove_owned_container(
                config, launch, owned_cid, environment
            )
            if not container_settled:
                raise MonitorError("container-teardown-unproved") from error
            raise MonitorError("worker-timeout") from error
        watcher_stop.set()
        watcher.join(timeout=5)
        cid_thread.join(timeout=5)
        for thread in stream_threads:
            thread.join(timeout=5)
        os.fsync(raw_fd)
        os.fsync(stderr_fd)
        if (watcher.is_alive() or cid_thread.is_alive()
                or any(thread.is_alive() for thread in stream_threads)):
            raise MonitorError("monitor-thread-failed")
        _verify_terminal_vanish(process.pid, watcher_health, returncode)
        if watcher_errors or stream_errors:
            raise MonitorError("monitor-resource-limit", repr(watcher_errors + stream_errors))
        if (watcher_health.get("loop_count", 0) < 2
                or watcher_health.get("tracer_scan_count", 0) < 1
                or watcher_health.get("exec_hash_submitted", 0)
                != watcher_health.get("exec_hash_completed", 0)
                or watcher_health.get("max_gap_ns", MAX_WATCH_GAP_NS + 1)
                > MAX_WATCH_GAP_NS):
            raise MonitorError("exec-snapshot-monitor-starvation", repr(watcher_health))
        current_cid = _read_owned_cid(private, launch)
        if current_cid is not None and observed_cids and current_cid != observed_cids[0]:
            raise MonitorError("container-id-changed")
        owned_cid = observed_cids[0] if observed_cids else current_cid
        container_settled = _remove_owned_container(config, launch, owned_cid, environment)
        if not container_settled:
            raise MonitorError("container-teardown-unproved")
        if returncode != 0:
            raise MonitorError("worker-or-monitor-failed", str(returncode))
        if owned_cid is None:
            raise MonitorError("missing-container-id")
        private.verify()
        retained.verify()
        trace_bytes = private.read(trace_name, config.max_trace_bytes)
        raw = private.read(raw_name, config.max_raw_bytes)
        stderr = private.read(stderr_name, config.max_raw_bytes)
        assert_canaries_absent(trace_bytes, forbidden_canaries, "raw-trace")
        assert_canaries_absent(raw, forbidden_canaries, "codex-jsonl")
        assert_canaries_absent(stderr, forbidden_canaries, "monitor-stderr")
        ordered_snapshots = sorted(
            snapshots, key=lambda row: (row.observed_monotonic_ns, row.process_id, row.sequence)
        )
        snapshots_path = private.write(
            snapshot_name, canonical([row.json() for row in ordered_snapshots]) + b"\n"
        )
        parsed = parse_trace(trace_bytes, max_bytes=config.max_trace_bytes)
        projected, outputs = project_trace(
            parsed,
            raw,
            config,
            attempt_id=attempt_id,
            assignment_sha256=assignment_sha256,
            monitor_sha256=monitor["monitor_sha256"],
            launch_sha256=launch_pin["launch_sha256"],
            prompt_sha256=launch_pin["prompt_sha256"],
            prompt_size_bytes=launch_pin["prompt_size_bytes"],
            raw_trace_sha256=digest(trace_bytes),
            producer_manifest_sha256=producer_manifest_sha256,
            monitor_key_commitment=monitor_key_commitment,
            exec_snapshots=ordered_snapshots,
        )
        # Wall time is supplemental only; signed elapsed time comes from trace.
        projected["collector_wall_milliseconds"] = round((time.monotonic() - started) * 1000)
        projected["exec_snapshot_monitor"] = {
            "loop_interval_milliseconds": round(WATCH_LOOP_SECONDS * 1000),
            "tracer_scan_interval_milliseconds": round(TRACER_SCAN_SECONDS * 1000),
            "loop_count": watcher_health["loop_count"],
            "tracer_scan_count": watcher_health["tracer_scan_count"],
            "tracer_discovery_count": watcher_health.get("tracer_discovery_count", 0),
            "used_tracer_task_count_max": watcher_health.get("tracer_task_set_max", 0),
            "strace_start_ticks": watcher_health["strace_start_ticks"],
            "strace_device": watcher_health["strace_device"],
            "strace_inode": watcher_health["strace_inode"],
            "last_healthy_identity_ns": watcher_health.get("last_healthy_identity_ns", 0),
            "last_healthy_loop": watcher_health.get("last_healthy_loop", 0),
            "strace_terminal_vanished": bool(
                watcher_health.get("strace_terminal_vanished", 0)
            ),
            "terminal_vanished_ns": watcher_health.get("terminal_vanished_ns"),
            "terminal_vanished_loop": watcher_health.get("terminal_vanished_loop"),
            "max_gap_nanoseconds": watcher_health.get("max_gap_ns", 0),
            "maximum_allowed_gap_nanoseconds": MAX_WATCH_GAP_NS,
            "executable_hash": {
                "contract": "held-fd-sha256-v1",
                "worker_count": EXEC_HASH_WORKERS,
                "maximum_pending_jobs": MAX_PENDING_EXEC_HASHES,
                "maximum_outstanding_bytes": MAX_PENDING_EXEC_HASH_BYTES,
                "maximum_file_bytes": MAX_EXEC_HASH_BYTES,
                "maximum_hash_seconds": MAX_EXEC_HASH_SECONDS,
                "maximum_queue_seconds": MAX_EXEC_HASH_QUEUE_SECONDS,
                "chunk_bytes": EXEC_HASH_CHUNK_BYTES,
                "submitted": watcher_health.get("exec_hash_submitted", 0),
                "completed": watcher_health.get("exec_hash_completed", 0),
                "cache_reuses_after_completion": watcher_health.get(
                    "exec_hash_cache_reuses", 0
                ),
                "observed_max_pending": watcher_health.get("exec_hash_max_pending", 0),
                "observed_max_outstanding_bytes": watcher_health.get(
                    "exec_hash_max_pending_bytes", 0
                ),
                "observed_max_duration_nanoseconds": watcher_health.get(
                    "exec_hash_max_duration_ns", 0
                ),
            },
        }
        projected["container_absent"] = True
        projected["container_identity"] = {
            "id": owned_cid,
            "name": launch.name,
        }
        envelope = authenticate_trace(projected, key)
        call_paths = []
        teapot_paths = []
        investigation_paths = []
        calls = []
        child_originals = []
        number = 0
        for command_row in projected["commands"]:
            for execution in command_row["executions"]:
                pid = execution["process_id"]
                role = execution["role"]
                if role == "scourge":
                    number += 1
                    data = outputs.scourge[pid]
                    path = retained.write(f"call-{number:03d}.stdout", data)
                    call_paths.append(path)
                    calls.append({
                        "number": number,
                        "native_item": command_row["native_item"],
                        "process_id": pid,
                        "argv": execution["argv"],
                        "exec_path": execution["exec_path"],
                        "binary_sha256": execution["binary_sha256"],
                        "exit_code": execution["exit_code"],
                        "format": "unknown",
                        "stdout": _artifact_ref(retained_path, path.name, data),
                    })
                elif role in {"teapot", "teapot-preparation", "investigation"}:
                    output_role = "teapot" if role in {"teapot", "teapot-preparation"} else role
                    data = (outputs.teapot if output_role == "teapot" else outputs.investigation)[pid]
                    child_number = 1 + sum(
                        1 for row in child_originals
                        if row["file"]["path"].split("/")[-1].startswith(f"{role}-")
                    )
                    path = retained.write(f"{role}-{child_number:03d}.stdout", data)
                    (teapot_paths if output_role == "teapot" else investigation_paths).append(path)
                    child_originals.append({
                        "process_id": pid,
                        "file": _artifact_ref(retained_path, path.name, data),
                    })
        events = {
            "schema": EVENTS_SCHEMA,
            "source": "process-monitor",
            "session_id": projected["session_id"],
            "raw_sha256": projected["raw_sha256"],
            "complete": True,
            "elapsed_milliseconds": projected["elapsed_milliseconds"],
            "commands": projected["commands"],
            "calls": calls,
            "child_originals": child_originals,
        }
        envelope_data = canonical(envelope) + b"\n"
        events_data = canonical(events) + b"\n"
        envelope_path = retained.write("host-trace.json", envelope_data)
        events_path = retained.write("events.json", events_data)
        envelope_ref = _artifact_ref(
            retained_path, envelope_path.name, envelope_data
        )
        events_ref = _artifact_ref(
            retained_path, events_path.name, events_data
        )
        verified_envelope, verified_events = verify_evidence_projection(
            evidence.path, envelope_ref, events_ref, key
        )
        if verified_envelope != envelope or verified_events != events:
            raise MonitorError("evidence-roundtrip-mismatch")
        binding = evidence_binding(
            evidence.path, envelope_ref, events_ref, verified_events, key
        )
        if not verify_evidence_binding(
            evidence.path, envelope_ref, events_ref, verified_events, binding, key
        ):
            raise MonitorError("invalid-evidence-binding")
        private.verify()
        retained.verify()
        evidence.verify()
        return MonitorResult(
            envelope, events, envelope_path, events_path, envelope_ref, events_ref,
            binding,
            raw_path, stderr_path,
            tuple(call_paths), tuple(teapot_paths), tuple(investigation_paths), snapshots_path,
            True, owned_cid, launch.name,
        )
    finally:
        watcher_stop.set()
        if watcher is not None and watcher.is_alive():
            watcher.join(timeout=5)
        if cid_thread is not None and cid_thread.is_alive():
            cid_thread.join(timeout=5)
        if process is not None and process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
        cleanup_error = None
        if process is not None and not container_settled:
            try:
                owned_cid = (owned_cid or (observed_cids[0] if observed_cids else None)
                             or _read_owned_cid(private, launch))
                container_settled = _remove_owned_container(
                    config, launch, owned_cid, environment
                )
            except MonitorError as error:
                cleanup_error = error
        for fd in (raw_fd, stderr_fd):
            try:
                os.close(fd)
            except OSError:
                pass
        private.close()
        retained.close()
        if evidence is not None:
            evidence.close()
        if process is not None and not container_settled:
            raise MonitorError("container-teardown-unproved") from cleanup_error
