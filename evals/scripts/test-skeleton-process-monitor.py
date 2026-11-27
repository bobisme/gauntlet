#!/usr/bin/env python3
"""Adversarial offline checks for the authenticated process collector."""

from __future__ import annotations

from dataclasses import replace
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent / "lib"))
import skeleton_process_monitor as monitor  # noqa: E402


def hx(value: bytes | str) -> str:
    if isinstance(value, str):
        value = value.encode()
    return '"' + "".join(f"\\x{byte:02x}" for byte in value) + '"'


def line(pid: int, stamp: float, body: str) -> str:
    return f"{pid} {stamp:.6f} {body}\n"


def execve(pid: int, stamp: float, path: str, argv: list[str], syscall: str = "execve") -> str:
    args = ", ".join(hx(value) for value in argv)
    if syscall == "execveat":
        return line(pid, stamp, f"execveat(3, {hx('')}, [{args}], 0x0 /* 0 vars */, AT_EMPTY_PATH) = 0")
    return line(pid, stamp, f"execve({hx(path)}, [{args}], 0x0 /* 0 vars */) = 0")


def failed_execve(pid: int, stamp: float, path: str, argv: list[str]) -> str:
    args = ", ".join(hx(value) for value in argv)
    return line(pid, stamp, f"execve({hx(path)}, [{args}], 0x0 /* 0 vars */) = -1 ENOENT")


def clone(pid: int, stamp: float, child: int, flags: str = "SIGCHLD") -> str:
    return line(pid, stamp, f"clone(child_stack=NULL, flags={flags}) = {child}")


def write(pid: int, stamp: float, data: bytes, *, fd: int = 1, returned: int | None = None) -> str:
    returned = len(data) if returned is None else returned
    return line(pid, stamp, f"write({fd}, {hx(data)}, {len(data)}) = {returned}")


def writev(pid: int, stamp: float, parts: list[bytes], *, fd: int = 1) -> str:
    rows = ", ".join(
        f"{{iov_base={hx(part)}, iov_len={len(part)}}}" for part in parts
    )
    return line(pid, stamp, f"writev({fd}, [{rows}], {len(parts)}) = {sum(map(len, parts))}")


def exited(pid: int, stamp: float, code: int) -> str:
    return line(pid, stamp, f"+++ exited with {code} +++")


def delivered_signal(
    pid: int,
    stamp: float,
    signal_name: str,
    *,
    code: str,
    sender: int,
    status: int | None = None,
) -> str:
    fields = (
        f"si_signo={signal_name}, si_code={code}, si_pid={sender}, si_uid={os.geteuid()}"
    )
    if status is not None:
        fields += f", si_status={status}, si_utime=0, si_stime=0"
    return line(pid, stamp, f"--- {signal_name} {{{fields}}} ---")


def native(session: str, items: list[dict]) -> bytes:
    events = [{"type": "thread.started", "thread_id": session}]
    events.extend({"type": "item.completed", "item": item} for item in items)
    return b"".join(json.dumps(row, separators=(",", ":")).encode() + b"\n" for row in events)


def command(item_id: str, text: str, output: str, code: int = 0) -> dict:
    return {
        "id": item_id,
        "type": "command_execution",
        "command": text,
        "aggregated_output": output,
        "exit_code": code,
        "status": "completed" if code == 0 else "failed",
    }


def native_boundary_environment(*, proxy_port: int | None = None) -> dict[str, str]:
    """Exact bn-3plk worker_environment production fixture at e75d5a8."""
    value = {
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
    if proxy_port is not None:
        value["M0_PROXY_PORT"] = str(proxy_port)
    return value


class Fixture:
    CODEX = "/opt/codex"
    SCOURGE = "/opt/scourge-bin/scourge"
    SHELL = "/bin/sh"
    BASH = "/bin/bash"
    HELPER = "/opt/helper"
    TEAPOT = "/opt/teapot/bin/teapot"
    INVESTIGATION = "/opt/investigation/bin/investigation"
    PREPARATION_TEAPOT = "/opt/scourge-bin/teapot-preparation"
    PREPARATION_ROOT = "/runtime/state/scourge"
    STAGED_TEAPOT = "/runtime/state/scourge/demo-private/teapot"

    def __init__(self):
        self.pins = tuple(
            monitor.ExecutablePin(path, hashlib.sha256(path.encode()).hexdigest(), "read-only-mount")
            for path in (
                self.CODEX, self.SCOURGE, self.SHELL, self.BASH, self.HELPER,
                self.TEAPOT, self.INVESTIGATION,
            )
        )
        self.environment = monitor.worker_environment_rows(native_boundary_environment())
        self.podman_argv = [
            "/usr/bin/podman", "--remote=false", "--runtime=/usr/bin/crun", "run", "--rm",
            "--unsetenv-all", "--interactive", "--pull=never", "--network=none",
            "--read-only", "--http-proxy=false", "--cap-drop=all",
            "--security-opt=no-new-privileges", "--pids-limit=128", "--userns=keep-id",
            "--hostname=scourge-worker", "--name", "trial",
            "--cidfile", "/tmp/scourge-control/trial.cid",
            "--mount", "type=bind,src=/srv/workspace,dst=/workspace",
        ]
        for name, value in self.environment:
            self.podman_argv.extend(("--env", f"{name}={value}"))
        self.podman_argv.extend((
            "--entrypoint", self.CODEX, "a" * 64, "exec", "--json",
            "--disable", "code_mode", "--disable", "code_mode_host",
            "--disable", "shell_snapshot", "-",
        ))
        self.config = monitor.MonitorConfig(
            "/usr/bin/strace",
            "/usr/bin/podman",
            "/usr/bin/crun",
            self.CODEX,
            self.SCOURGE,
            self.pins,
            monitor.podman_argv_digest(self.podman_argv),
            worker_environment=self.environment,
            teapot_path=self.TEAPOT,
            teapot_sha256=hashlib.sha256(self.TEAPOT.encode()).hexdigest(),
            investigation_path=self.INVESTIGATION,
            investigation_sha256=hashlib.sha256(self.INVESTIGATION.encode()).hexdigest(),
            qualification_child_pins=True,
        )
        self.items = [command("item-1", f"{self.SCOURGE} direct", "direct\n")]
        self.raw = native("session-1", self.items)
        self.trace = "".join([
            execve(100, 1.0, "/usr/bin/podman", ["podman"]),
            clone(100, 1.1, 200),
            execve(200, 1.2, self.CODEX, [self.CODEX]),
            clone(200, 2.0, 300),
            execve(300, 2.05, self.SHELL, [self.SHELL, "-c", self.items[0]["command"]]),
            execve(300, 2.1, self.SCOURGE, [self.SCOURGE, "direct"]),
            write(300, 2.2, b"direct\n"),
            exited(300, 2.3, 0),
            writev(200, 2.4, [self.raw[:20], self.raw[20:]]),
            exited(200, 2.5, 0),
            exited(100, 2.6, 0),
        ]).encode()

    def project(self, trace: bytes | None = None, raw: bytes | None = None, snapshots=()):
        trace = trace or self.trace
        return monitor.project_trace(
            monitor.parse_trace(trace),
            raw or self.raw,
            self.config,
            attempt_id="attempt-1",
            assignment_sha256="a" * 64,
            monitor_sha256="b" * 64,
            launch_sha256="c" * 64,
            prompt_sha256="d" * 64,
            prompt_size_bytes=1,
            raw_trace_sha256=hashlib.sha256(trace).hexdigest(),
            exec_snapshots=snapshots,
        )

    def child_trace(self, exec_path: str, argv: list[str], output: bytes):
        raw = native("session-1", [command("item-1", "approved child", "done\n", 0)])
        trace = "".join([
            execve(100, 1.0, "/usr/bin/podman", ["podman"]),
            clone(100, 1.1, 200), execve(200, 1.2, self.CODEX, [self.CODEX]),
            clone(200, 2.0, 300),
            execve(300, 2.05, self.SHELL, [self.SHELL, "-c", "approved child"]),
            execve(300, 2.1, self.SCOURGE, [self.SCOURGE, "child"]),
            clone(300, 2.2, 301), execve(301, 2.3, exec_path, argv),
            write(301, 2.4, output), exited(301, 2.5, 0),
            write(300, 2.6, b"done\n"), exited(300, 2.7, 0),
            write(200, 2.8, raw), exited(200, 2.9, 0), exited(100, 3.0, 0),
        ]).encode()
        return trace, raw

    def snapshot(self, pid: int, sha256: str, **changes):
        values = {
            "process_id": pid, "process_start_ticks": 10, "sequence": 2,
            "target": "/tmp/scourge-private/child", "sha256": sha256,
            "device": 11, "inode": 12, "mode": 0o500, "owner_uid": os.geteuid(),
            "size_bytes": 42, "regular": True, "parent_device": 11, "parent_inode": 13,
            "parent_mode": 0o700, "parent_owner_uid": os.geteuid(),
            "observed_monotonic_ns": 100,
        }
        values.update(changes)
        return monitor.ExecSnapshot(**values)


class ProcessMonitorTest(unittest.TestCase):
    def setUp(self):
        self.fixture = Fixture()

    def test_held_fd_hash_is_bounded_async_ready_and_rejects_mutation_or_failure(self):
        with tempfile.TemporaryDirectory(
            prefix="scourge-exec-hash-", dir=Path.cwd()
        ) as directory:
            executable = Path(directory) / "large-executable"
            payload = b"0123456789abcdef" * (512 << 10)
            executable.write_bytes(payload)
            executable.chmod(0o500)
            expected = hashlib.sha256(payload).hexdigest()
            real_pread = os.pread

            def slow_pread(fd, size, offset):
                time.sleep(0.001)
                return real_pread(fd, size, offset)

            fd = os.open(executable, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
            with mock.patch.object(monitor.os, "pread", side_effect=slow_pread):
                hashed = monitor._hash_held_executable(fd, expected)
            self.assertEqual(hashed.sha256, expected)
            self.assertEqual(hashed.bytes, len(payload))
            self.assertEqual(hashed.pre_fstat, hashed.post_fstat)
            self.assertGreater(hashed.completed_monotonic_ns, hashed.started_monotonic_ns)

            mutated = False

            def mutating_pread(fd, size, offset):
                nonlocal mutated
                data = real_pread(fd, size, offset)
                if not mutated:
                    os.fchmod(fd, 0o400)
                    mutated = True
                return data

            fd = os.open(executable, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
            with (mock.patch.object(monitor.os, "pread", side_effect=mutating_pread),
                  self.assertRaisesRegex(monitor.MonitorError, "exec-hash-identity-changed")):
                monitor._hash_held_executable(fd, expected)
            executable.chmod(0o500)
            fd = os.open(executable, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
            with self.assertRaisesRegex(monitor.MonitorError, "exec-hash-digest-mismatch"):
                monitor._hash_held_executable(fd, "f" * 64)

            exact_limit = Path(directory) / "exact-limit"
            with exact_limit.open("wb") as output:
                output.truncate(monitor.MAX_EXEC_HASH_BYTES)
            zero_block = b"\0" * monitor.EXEC_HASH_CHUNK_BYTES
            zero_digest = hashlib.sha256()
            for _ in range(monitor.MAX_EXEC_HASH_BYTES // len(zero_block)):
                zero_digest.update(zero_block)
            fd = os.open(exact_limit, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
            exact = monitor._hash_held_executable(fd, zero_digest.hexdigest())
            self.assertEqual(exact.bytes, monitor.MAX_EXEC_HASH_BYTES)

            over_limit = Path(directory) / "over-limit"
            with over_limit.open("wb") as output:
                output.truncate(monitor.MAX_EXEC_HASH_BYTES + 1)
            fd = os.open(over_limit, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
            with self.assertRaisesRegex(monitor.MonitorError, "exec-hash-unsafe-file"):
                monitor._hash_held_executable(fd, "0" * 64)

            monitor._check_exec_hash_queue(1, 384 << 20, 128 << 20)
            with self.assertRaisesRegex(monitor.MonitorError, "exec-hash-queue-limit"):
                monitor._check_exec_hash_queue(1, 384 << 20, (128 << 20) + 1)

            self.assertEqual(
                monitor._expected_exec_digest("/usr/bin/bash", self.fixture.config),
                self.fixture.config.pins[Fixture.BASH].sha256,
            )
            with self.assertRaisesRegex(monitor.MonitorError, "unqualified-exec-hash-target"):
                monitor._expected_exec_digest("/usr/local/bin/bash", self.fixture.config)

            bash_process = monitor.parse_trace(
                (execve(901, 1.0, Fixture.BASH, [Fixture.BASH, "-c", "true"])
                 + exited(901, 1.1, 0)).encode()
            ).processes[901]
            alias_fstat = (11, 12, stat.S_IFREG | 0o755, 1, 42, 13, 14)
            alias_snapshot = self.fixture.snapshot(
                901,
                self.fixture.config.pins[Fixture.BASH].sha256,
                target="/usr/bin/bash",
                mode=0o755,
                hash_pre_fstat=alias_fstat,
                hash_post_fstat=alias_fstat,
                requested_exec_path=Fixture.BASH,
                resolution_chain=("/bin", "usr/bin", "/usr/bin/bash"),
                alias_requested_fstat=alias_fstat,
            )
            alias_config = replace(self.fixture.config, worker_image_id="1" * 64)
            monitor._validate_image(
                bash_process, alias_config.pins, alias_config, [alias_snapshot]
            )
            with self.assertRaisesRegex(monitor.MonitorError, "exec-hash-alias-identity"):
                monitor._validate_image(
                    bash_process, alias_config.pins, alias_config,
                    [replace(alias_snapshot, resolution_chain=("/bin", "other"))],
                )

    def test_tracer_task_admission_rejects_zero_foreign_and_stale_ids(self):
        current = {4100, 4101}
        self.assertTrue(monitor._admit_tracer_id(4100, current))
        self.assertTrue(monitor._admit_tracer_id(4101, current))
        self.assertFalse(monitor._admit_tracer_id(0, current))
        self.assertFalse(monitor._admit_tracer_id(4099, current))
        self.assertFalse(monitor._admit_tracer_id(4101, {4100}))

    def test_terminal_strace_vanish_requires_clean_wait_and_no_pid_reuse(self):
        health = {
            "loop_count": 9,
            "last_healthy_identity_ns": 100,
            "strace_start_ticks": 77,
            "strace_terminal_vanished": 1,
        }
        with mock.patch.object(Path, "exists", return_value=False):
            self.assertTrue(monitor._terminal_vanish_candidate(123, health))
            monitor._verify_terminal_vanish(123, health, 0)
            with self.assertRaisesRegex(monitor.MonitorError, "unproved-strace-terminal"):
                monitor._verify_terminal_vanish(123, health, 1)
        with mock.patch.object(Path, "exists", return_value=True):
            self.assertFalse(monitor._terminal_vanish_candidate(123, health))
            with self.assertRaisesRegex(monitor.MonitorError, "unproved-strace-terminal"):
                monitor._verify_terminal_vanish(123, health, 0)

        task = mock.Mock()
        task.name = "123"
        with (mock.patch.object(Path, "exists", side_effect=[False, True]),
              mock.patch.object(Path, "read_text", return_value="State:\tZ (zombie)\n"),
              mock.patch.object(Path, "iterdir", return_value=[task]),
              mock.patch.object(monitor, "_proc_parent_and_start", return_value=(1, 77))):
            self.assertTrue(monitor._terminal_vanish_candidate(123, health))
        with (mock.patch.object(Path, "exists", side_effect=[False, True]),
              mock.patch.object(Path, "read_text", return_value="State:\tS (sleeping)\n"),
              mock.patch.object(Path, "iterdir", return_value=[task]),
              mock.patch.object(monitor, "_proc_parent_and_start", return_value=(1, 77))):
            self.assertFalse(monitor._terminal_vanish_candidate(123, health))

    def test_direct_trace_reconstructs_codex_and_scourge_stdout(self):
        trace, outputs = self.fixture.project()
        self.assertEqual(trace["session_id"], "session-1")
        self.assertEqual(trace["raw_sha256"], hashlib.sha256(self.fixture.raw).hexdigest())
        self.assertEqual(len(trace["commands"]), 1)
        execution = trace["commands"][0]["executions"][0]
        self.assertEqual(execution["exec_path"], Fixture.SCOURGE)
        self.assertEqual(execution["argv"], [Fixture.SCOURGE, "direct"])
        self.assertEqual(execution["exit_code"], 0)
        self.assertEqual(outputs.scourge, {300: b"direct\n"})
        self.assertEqual(trace["raw_trace_sha256"], hashlib.sha256(self.fixture.trace).hexdigest())

    def test_partial_writes_and_writev_use_successful_byte_count(self):
        raw = self.fixture.raw
        trace = self.fixture.trace.decode().replace(
            write(300, 2.2, b"direct\n"),
            write(300, 2.2, b"direct\nTRAIL", returned=7),
        ).encode()
        value, outputs = self.fixture.project(trace)
        self.assertEqual(outputs.scourge[300], b"direct\n")
        self.assertEqual(value["commands"][0]["executions"][0]["stdout_bytes"], 7)
        self.assertEqual(monitor._native_commands(raw)[0], "session-1")
        self.assertEqual(
            monitor._parse_write('write(1, "\\x78", 1) = ? ERESTARTSYS (To be restarted)'),
            (1, b""),
        )
        self.assertEqual(
            monitor._parse_write('write(6, "\\x7f\\x45"..., 10485760) = 10485760'),
            (6, b""),
        )

    def test_unfinished_clone_is_reassembled(self):
        trace = self.fixture.trace.decode().replace(
            clone(200, 2.0, 300),
            line(200, 2.0, "clone(child_stack=NULL, flags=SIGCHLD <unfinished ...>")
            + line(200, 2.01, "<... clone resumed>) = 300"),
        ).encode()
        value, _ = self.fixture.project(trace)
        self.assertEqual(value["commands"][0]["executions"][0]["process_id"], 300)
        trace = self.fixture.trace.decode().replace(
            write(300, 2.2, b"direct\n"),
            line(300, 2.2, f"write(1, {hx(b'direct\n')}, 7 <unfinished ...>")
            + line(300, 2.21, "<... write resumed>) = 7"),
        ).encode()
        _value, outputs = self.fixture.project(trace)
        self.assertEqual(outputs.scourge[300], b"direct\n")

    def test_spoofed_argv0_and_unknown_or_writable_executables_fail(self):
        spoof = self.fixture.trace.decode().replace(
            execve(300, 2.1, Fixture.SCOURGE, [Fixture.SCOURGE, "direct"]),
            execve(300, 2.1, Fixture.HELPER, ["scourge", "direct"]),
        ).encode()
        with self.assertRaisesRegex(monitor.MonitorError, "unqualified-scourge"):
            self.fixture.project(spoof)

        unknown = self.fixture.trace.decode().replace(hx(Fixture.SCOURGE), hx("/workspace/scourge"))
        with self.assertRaisesRegex(monitor.MonitorError, "unresolved-executable"):
            self.fixture.project(unknown.encode())
        with self.assertRaisesRegex(monitor.MonitorError, "writable-executable"):
            monitor.ExecutablePin("/workspace/tool", "a" * 64, "read-only-mount", False)

    def test_execveat_relative_deleted_memfd_and_truncated_exec_fail(self):
        base = execve(300, 2.1, Fixture.SCOURGE, [Fixture.SCOURGE, "direct"])
        substitutions = [
            execve(300, 2.1, Fixture.SCOURGE, [Fixture.SCOURGE, "direct"], "execveat"),
            execve(300, 2.1, "scourge", ["scourge", "direct"]),
            execve(300, 2.1, "/memfd:scourge", ["scourge", "direct"]),
            execve(300, 2.1, "/opt/scourge (deleted)", ["scourge", "direct"]),
            line(300, 2.1, f"execve({hx(Fixture.SCOURGE)}, [{hx(Fixture.SCOURGE)}, ...], 0x0) = 0"),
        ]
        for replacement in substitutions:
            with self.subTest(replacement=replacement):
                with self.assertRaises(monitor.MonitorError):
                    self.fixture.project(self.fixture.trace.decode().replace(base, replacement).encode())

    def test_child_failure_hidden_by_shell_success_is_refused(self):
        raw = native("session-1", [command("item-1", "wrapped", "", 0)])
        trace = "".join([
            execve(100, 1.0, "/usr/bin/podman", ["podman"]),
            clone(100, 1.1, 200), execve(200, 1.2, Fixture.CODEX, [Fixture.CODEX]),
            clone(200, 2.0, 300), execve(300, 2.1, Fixture.SHELL, [Fixture.SHELL, "-c", "wrapped"]),
            clone(300, 2.2, 301), execve(301, 2.3, Fixture.SCOURGE, [Fixture.SCOURGE, "fail"]),
            exited(301, 2.4, 7), exited(300, 2.5, 0),
            write(200, 2.6, raw), exited(200, 2.7, 0), exited(100, 2.8, 0),
        ]).encode()
        with self.assertRaisesRegex(monitor.MonitorError, "hidden-scourge-failure"):
            self.fixture.project(trace, raw)

    def test_scourge_child_signal_unsupported_stdout_and_unclosed_tree_fail(self):
        child = self.fixture.trace.decode().replace(
            write(300, 2.2, b"direct\n"),
            clone(300, 2.15, 301) + execve(301, 2.16, Fixture.HELPER, [Fixture.HELPER])
            + exited(301, 2.17, 0) + write(300, 2.2, b"direct\n"),
        ).encode()
        with self.assertRaisesRegex(monitor.MonitorError, "scourge-child-process"):
            self.fixture.project(child)

        signalled = self.fixture.trace.decode().replace(exited(300, 2.3, 0), line(300, 2.3, "+++ killed by SIGKILL +++")).encode()
        with self.assertRaisesRegex(monitor.MonitorError, "signalled-process"):
            self.fixture.project(signalled)

        unsupported = self.fixture.trace.decode().replace(
            write(300, 2.2, b"direct\n"),
            line(300, 2.2, "sendfile(1, 3, NULL, 7) = 7"),
        ).encode()
        with self.assertRaisesRegex(monitor.MonitorError, "unsupported-stdout"):
            self.fixture.project(unsupported)

        unclosed = self.fixture.trace.decode().replace(exited(300, 2.3, 0), "").encode()
        with self.assertRaisesRegex(monitor.MonitorError, "unclosed-process"):
            self.fixture.project(unclosed)

    def test_signal_deliveries_are_parsed_reconciled_and_fail_closed(self):
        sigchld = self.fixture.trace.decode().replace(
            writev(200, 2.4, [self.fixture.raw[:20], self.fixture.raw[20:]]),
            delivered_signal(
                200, 2.35, "SIGCHLD", code="CLD_EXITED", sender=300, status=0
            ) + writev(200, 2.4, [self.fixture.raw[:20], self.fixture.raw[20:]]),
        ).encode()
        parsed = monitor.parse_trace(sigchld)
        self.assertEqual(parsed.processes[200].signal_events[0].signal, "SIGCHLD")
        self.fixture.project(sigchld)

        mutations = (
            delivered_signal(300, 2.25, "SIGUSR1", code="SI_USER", sender=300),
            delivered_signal(300, 2.25, "SIGUSR1", code="SI_TKILL", sender=300),
            delivered_signal(200, 2.35, "SIGCHLD", code="CLD_EXITED", sender=999, status=0),
            delivered_signal(200, 2.35, "SIGCHLD", code="CLD_EXITED", sender=300, status=7),
        )
        for signal_row in mutations:
            with self.subTest(signal=signal_row):
                changed = self.fixture.trace.decode().replace(
                    exited(300, 2.3, 0), signal_row + exited(300, 2.3, 0)
                ).encode()
                with self.assertRaisesRegex(monitor.MonitorError, "unreconciled-signal"):
                    self.fixture.project(changed)

        malformed = self.fixture.trace.decode().replace(
            exited(300, 2.3, 0),
            line(300, 2.25, "--- SIGUSR1 {si_signo=SIGUSR1, malformed} ---")
            + exited(300, 2.3, 0),
        ).encode()
        with self.assertRaisesRegex(monitor.MonitorError, "malformed-signal-delivery"):
            self.fixture.project(malformed)

    def test_pid_reuse_and_post_terminal_events_fail_closed(self):
        reused = self.fixture.trace.decode().replace(
            writev(200, 2.4, [self.fixture.raw[:20], self.fixture.raw[20:]]),
            clone(200, 2.35, 300)
            + execve(300, 2.36, Fixture.SCOURGE, [Fixture.SCOURGE, "second"])
            + exited(300, 2.37, 0)
            + writev(200, 2.4, [self.fixture.raw[:20], self.fixture.raw[20:]]),
        ).encode()
        with self.assertRaisesRegex(monitor.MonitorError, "reused-process-id"):
            monitor.parse_trace(reused)
        after_exit = self.fixture.trace.decode().replace(
            exited(300, 2.3, 0),
            exited(300, 2.3, 0) + write(300, 2.31, b"late"),
        ).encode()
        with self.assertRaisesRegex(monitor.MonitorError, "reused-process-id"):
            monitor.parse_trace(after_exit)

    def test_only_exact_reparented_demo_fixture_sigchld_is_reconciled(self):
        preparation_pin = monitor.ExecutablePin(
            self.fixture.PREPARATION_TEAPOT,
            monitor.PREPARATION_TEAPOT_SHA256,
            "read-only-mount",
        )
        environment = monitor.worker_environment_rows(
            native_boundary_environment(proxy_port=19080)
        )
        supervisor = monitor.SupervisorPin(
            self.fixture.HELPER,
            self.fixture.config.pins[self.fixture.HELPER].sha256,
            (
                self.fixture.HELPER,
                "--self-sha256", self.fixture.config.pins[self.fixture.HELPER].sha256,
                "--codex-sha256", self.fixture.config.pins[self.fixture.CODEX].sha256,
                "--", self.fixture.CODEX,
            ),
            (self.fixture.CODEX,),
            19080,
        )
        config = replace(
            self.fixture.config,
            executables=(*self.fixture.config.executables, preparation_pin),
            worker_environment=environment,
            supervisor=supervisor,
            preparation_teapot_path=self.fixture.PREPARATION_TEAPOT,
            preparation_teapot_sha256=monitor.PREPARATION_TEAPOT_SHA256,
            preparation_root=self.fixture.PREPARATION_ROOT,
        )
        supervisor_process = monitor.Process(
            150, started=0.5, ended=9.0, exit_code=0,
            execs=[monitor.ExecImage(
                0.5, self.fixture.HELPER, list(supervisor.argv), "execve"
            )],
        )
        recipient = monitor.Process(
            151, parent=150, thread=True, clone_flags=monitor.CODEX_THREAD_CLONE_FLAGS,
            started=0.6, ended=8.9, exit_code=0,
        )
        codex = monitor.Process(
            200, parent=150, started=1.0, ended=8.0, exit_code=0,
            execs=[monitor.ExecImage(1.0, self.fixture.CODEX, [self.fixture.CODEX], "execve")],
        )
        codex_thread = monitor.Process(
            201, parent=200, thread=True, clone_flags=monitor.CODEX_THREAD_CLONE_FLAGS,
            started=1.1, ended=8.0, exit_code=0,
        )
        shell = monitor.Process(
            300, parent=201, started=2.0, ended=7.0, exit_code=0,
            execs=[monitor.ExecImage(2.0, self.fixture.SHELL,
                                     [self.fixture.SHELL, "-c", "demo"], "execve")],
        )
        demo_argv = [
            self.fixture.SCOURGE, "--format", "json", "demo", "/workspace/demo",
            "--teapot", self.fixture.PREPARATION_TEAPOT,
            "--investigation", self.fixture.INVESTIGATION,
            "--managed-guide", "false", "--referee-root", "/runtime/referee",
        ]
        demo = monitor.Process(
            400, parent=300, started=2.1, ended=4.0, exit_code=0,
            execs=[monitor.ExecImage(2.1, self.fixture.SCOURGE, demo_argv, "execve")],
        )
        fixture = monitor.Process(
            401, namespace_pid=17, parent=400, started=2.2, ended=5.0, exit_code=0,
            execs=[monitor.ExecImage(
                2.2, self.fixture.SCOURGE,
                [self.fixture.SCOURGE, "--_scourge-demo-fixture"], "execve",
            )],
        )
        recipient.signal_events.append(monitor.SignalEvent(
            5.1, "SIGCHLD", "CLD_EXITED", 17, 401, os.geteuid(), 0, 0, "a" * 64,
        ))
        trace = monitor.ParsedTrace(
            {row.pid: row for row in (
                supervisor_process, recipient, codex, codex_thread, shell, demo, fixture,
            )},
            0.5,
            9.0,
        )
        codex_snapshot = self.fixture.snapshot(
            200, config.pins[self.fixture.CODEX].sha256,
            target=self.fixture.CODEX, mode=0o755,
        )
        supervisor_snapshot = self.fixture.snapshot(
            150, config.pins[self.fixture.HELPER].sha256,
            target=self.fixture.HELPER, mode=0o755,
        )
        fixture_snapshot = self.fixture.snapshot(
            401, config.pins[self.fixture.SCOURGE].sha256,
            target=self.fixture.SCOURGE, mode=0o755,
        )
        snapshots = (supervisor_snapshot, codex_snapshot, fixture_snapshot)
        monitor._reconcile_signals(
            trace, {150, 151}, config.pins, config, snapshots,
        )

        for label, mutate in (
            ("duplicate", lambda: recipient.signal_events.append(recipient.signal_events[0])),
            ("late-parent", lambda: setattr(demo, "ended", 5.0)),
            ("wrong-role", lambda: fixture.execs[0].argv.__setitem__(1, "--version")),
            ("wrong-supervisor", lambda: supervisor_process.execs[0].argv.__setitem__(0, "/bad")),
            ("wrong-codex-origin", lambda: setattr(shell, "parent", 150)),
            ("codex-before-supervisor", lambda: setattr(codex, "started", 0.4)),
        ):
            with self.subTest(label=label):
                recipient.signal_events[:] = recipient.signal_events[:1]
                demo.ended = 4.0
                fixture.execs[0].argv[1] = "--_scourge-demo-fixture"
                supervisor_process.execs[0].argv[0] = self.fixture.HELPER
                shell.parent = 201
                codex.started = 1.0
                mutate()
                with self.assertRaisesRegex(monitor.MonitorError, "unreconciled-signal"):
                    monitor._reconcile_signals(
                        trace, {150, 151}, config.pins, config, snapshots,
                    )
        recipient.signal_events[:] = recipient.signal_events[:1]
        demo.ended = 4.0
        fixture.execs[0].argv[1] = "--_scourge-demo-fixture"
        supervisor_process.execs[0].argv[0] = self.fixture.HELPER
        shell.parent = 201
        codex.started = 1.0
        with self.assertRaisesRegex(monitor.MonitorError, "unreconciled-signal"):
            monitor._reconcile_signals(
                trace, {150, 151}, config.pins, config,
                (supervisor_snapshot, replace(codex_snapshot, sha256="f" * 64),
                 fixture_snapshot),
            )
        with self.assertRaisesRegex(monitor.MonitorError, "unreconciled-signal"):
            monitor._reconcile_signals(
                trace, {150, 151}, config.pins, config,
                (replace(supervisor_snapshot, sha256="f" * 64), codex_snapshot,
                 fixture_snapshot),
            )

    def test_exact_teapot_child_is_retained_but_mismatch_and_grandchild_fail(self):
        argv = [Fixture.TEAPOT, "--json", "rules", "list"]
        trace, raw = self.fixture.child_trace(Fixture.TEAPOT, argv, b'{"ok":true}\n')
        value, outputs = self.fixture.project(trace, raw)
        child = value["commands"][0]["executions"][1]
        self.assertEqual((child["role"], child["parent_process_id"], child["exit_code"]), ("teapot", 300, 0))
        self.assertEqual(outputs.teapot, {301: b'{"ok":true}\n'})

        mismatch = trace.decode().replace(hx(Fixture.TEAPOT), hx(Fixture.HELPER)).encode()
        with self.assertRaises(monitor.MonitorError):
            self.fixture.project(mismatch, raw)
        grandchild = trace.decode().replace(
            write(301, 2.4, b'{"ok":true}\n'),
            clone(301, 2.35, 302) + execve(302, 2.36, Fixture.HELPER, [Fixture.HELPER])
            + exited(302, 2.37, 0) + write(301, 2.4, b'{"ok":true}\n'),
        ).encode()
        with self.assertRaisesRegex(monitor.MonitorError, "approved-child-process"):
            self.fixture.project(grandchild, raw)
        laundered = trace.decode().replace(
            execve(301, 2.3, Fixture.TEAPOT, argv),
            execve(301, 2.21, Fixture.SHELL, [Fixture.SHELL, "-c", "true"])
            + write(301, 2.22, b"forged", fd=3)
            + execve(301, 2.3, Fixture.TEAPOT, argv),
        ).encode()
        with self.assertRaisesRegex(monitor.MonitorError, "approved-child-role-prefix"):
            self.fixture.project(laundered, raw)

    def test_bound_teapot_requires_exact_live_snapshot(self):
        path = "/proc/self/fd/7"
        trace, raw = self.fixture.child_trace(
            path, [Fixture.TEAPOT, "--json", "proxy", "status"], b'{"ok":true}\n'
        )
        sha = self.fixture.config.teapot_sha256
        snapshot = self.fixture.snapshot(301, sha)
        value, outputs = self.fixture.project(trace, raw, [snapshot])
        child = value["commands"][0]["executions"][1]
        self.assertEqual(child["role"], "teapot")
        self.assertEqual(child["resolved_executable"]["sha256"], sha)
        self.assertEqual(outputs.teapot[301], b'{"ok":true}\n')
        for bad in (
            [], [self.fixture.snapshot(301, "f" * 64)],
            [self.fixture.snapshot(301, sha, mode=0o700)],
            [self.fixture.snapshot(301, sha, target="/tmp/child (deleted)")],
            [self.fixture.snapshot(301, sha, regular=False)],
            [self.fixture.snapshot(301, sha, parent_mode=0o755)],
        ):
            with self.subTest(snapshot=bad):
                with self.assertRaises(monitor.MonitorError):
                    self.fixture.project(trace, raw, bad)

    def test_bound_investigation_has_fd_argv0_and_recognized_grammar(self):
        path = "/proc/self/fd/9"
        argv = [path, "--format", "json", "--actor", "agent:scourge", "--workspace", "/case/work",
                "capture", "begin", "--input", "-"]
        trace, raw = self.fixture.child_trace(path, argv, b'{"capture":"ok"}\n')
        snapshot = self.fixture.snapshot(301, self.fixture.config.investigation_sha256)
        value, outputs = self.fixture.project(trace, raw, [snapshot])
        self.assertEqual(value["commands"][0]["executions"][1]["role"], "investigation")
        self.assertEqual(outputs.investigation[301], b'{"capture":"ok"}\n')

        bad_argv = [path, "--format", "json", "--actor", "agent:scourge", "shell", "-c", "id"]
        bad_trace, bad_raw = self.fixture.child_trace(path, bad_argv, b"bad\n")
        with self.assertRaisesRegex(monitor.MonitorError, "unqualified-bound"):
            self.fixture.project(bad_trace, bad_raw, [snapshot])

        laundered = trace.decode().replace(
            execve(301, 2.3, path, argv),
            execve(301, 2.21, Fixture.SHELL, [Fixture.SHELL, "-c", "true"])
            + write(301, 2.22, b"forged", fd=3)
            + execve(301, 2.3, path, argv),
        ).encode()
        with self.assertRaisesRegex(monitor.MonitorError, "approved-child-role-prefix"):
            self.fixture.project(laundered, raw, [snapshot])
        base = [
            path, "--format", "json", "--actor", "agent:scourge", "--workspace", "/case/work",
        ]
        self.assertTrue(monitor._investigation_argv(
            base + ["--case", "case-1", "show", "record-1", "--depth", "full"], path
        ))
        self.assertTrue(monitor._investigation_argv(
            base + ["--case", "case-1", "evidence", "read", "artifact-1", "--selector-file", "-"], path
        ))
        for near_miss in (
            [path, "--format", "json", "--actor", "scourge", *base[5:]],
            base + ["--case", "case-1", "show", "record-1", "--depth", "shallow"],
            base + ["--case", "case-1", "evidence", "read", "artifact-1", "--selector", "-"],
            [Fixture.INVESTIGATION, *base[1:], "--case", "case-1", "show", "record-1", "--depth", "full"],
        ):
            self.assertFalse(monitor._investigation_argv(near_miss, path))

    def test_investigation_parser_matches_every_native_transport_form(self):
        path = "/proc/self/fd/19"
        actor = [path, "--format", "json", "--actor", "agent:scourge"]
        workspace = [*actor, "--workspace", "/runtime/investigation"]
        digest = "a" * 64
        accepted = [
            [path, "--version"],
            [*actor, "init", "/runtime/investigation", "--no-vault", "--import-root", "/workspace"],
            [*workspace, "config", "get", "import_roots"],
            [*workspace, "ingest", "--input", "/workspace/manifest.json"],
            [*workspace, "capture", "begin", "--input", "-"],
            [*workspace, "capture", "attach", "--input", "-"],
            [*workspace, "capture", "finalize", "--input", "-"],
            [*workspace, "capture", "recover", "--handle", "capture-1"],
            [*workspace, "receipt", "scourge/evidence/case-v1"],
            [*workspace, "receipt", f"scourge/record/{digest}"],
            [*workspace, "receipt", f"scourge/verification-publication/{digest}"],
            [*workspace, "case", "new", "Scourge evidence", "--mode", "record",
             "--command-id", "scourge/evidence/case-v1"],
            [*workspace, "--case", "case-1", "show", "record-1", "--depth", "full"],
            [*workspace, "--case", "case-1", "evidence", "read", "artifact-1",
             "--selector-file", "-"],
        ]
        for argv in accepted:
            with self.subTest(argv=argv):
                self.assertTrue(monitor._investigation_argv(argv, path))
        rejected = [
            [path, "init", "/runtime/investigation", "--no-vault", "--import-root", "/workspace"],
            [path, "--format", "json", "--actor", "scourge", *workspace[5:]],
            [*workspace, "receipt", "scourge/evidence/case-v2"],
            [*workspace, "receipt", f"scourge/record/{digest}", "--extra"],
            [*workspace, "case", "new", "Scourge evidence", "--mode", "record",
             "--command-id", "other"],
            [*workspace, "--case", "case-1", "show", "record-1", "--depth", "summary"],
            [*workspace, "--case", "case-1", "evidence", "read", "artifact-1",
             "--selector-file", "/tmp/selector"],
        ]
        for argv in rejected:
            with self.subTest(argv=argv):
                self.assertFalse(monitor._investigation_argv(argv, path))

    def test_historical_demo_teapot_and_fixture_are_exact_and_quiescent(self):
        preparation_pin = monitor.ExecutablePin(
            Fixture.PREPARATION_TEAPOT,
            monitor.PREPARATION_TEAPOT_SHA256,
            "read-only-mount",
        )
        config = replace(
            self.fixture.config,
            executables=(*self.fixture.config.executables, preparation_pin),
            worker_environment=monitor.worker_environment_rows(
                native_boundary_environment(proxy_port=19080)
            ),
            preparation_teapot_path=Fixture.PREPARATION_TEAPOT,
            preparation_teapot_sha256=monitor.PREPARATION_TEAPOT_SHA256,
            preparation_root=Fixture.PREPARATION_ROOT,
        )
        start_argv = [
            Fixture.SCOURGE, "--format", "json", "demo", "/workspace/demo",
            "--teapot", Fixture.PREPARATION_TEAPOT,
            "--investigation", Fixture.INVESTIGATION,
            "--managed-guide", "false", "--referee-root", "/runtime/referee",
        ]
        stop_argv = [
            Fixture.SCOURGE, "--format", "json", "demo", "--stop", "/workspace/demo",
        ]
        project = "/runtime/state/scourge/demo-private/project"
        configure_argv = [
            Fixture.STAGED_TEAPOT, "--project", project, "--json", "projects", "init",
        ]
        engine_argv = [
            Fixture.STAGED_TEAPOT, "--project", project, "--json", "proxy", "start",
            "--listen", "127.0.0.1:0", "--lock-policy", "--pass",
            "/runtime/state/scourge/demo-private/demo.pass.toml",
        ]
        engine_stop_argv = [
            Fixture.STAGED_TEAPOT, "--project", project, "--json", "proxy", "stop",
        ]
        engine = {
            "build": "0.1.0",
            "control_socket": (
                "/tmp/scourge-demo-Ab12z9/teapot/"
                "0123456789abcdef0123456789abcdef/control.sock"
            ),
            "enforced": False,
            "instance": "fedcba9876543210fedcba9876543210",
            "listener": "127.0.0.1:19001",
            "mode": "regular",
            "pass": "/runtime/state/scourge/demo-private/demo.pass.toml",
            "pid": 91,
            "policy_locked": True,
            "project": project,
            "project_id": "0123456789abcdef0123456789abcdef",
            "started_at": "2026-11-26T12:34:56.123456789Z",
        }
        engine_started = json.dumps(engine, separators=(",", ":")).encode() + b"\n"
        engine_settled = json.dumps({
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
        }, separators=(",", ":")).encode() + b"\n"
        engine_stopped = json.dumps({
            "advice": [],
            "proxy": {
                "instance": engine["instance"],
                "pid": engine["pid"],
                "stopped": True,
                "was_running": True,
            },
        }, separators=(",", ":")).encode() + b"\n"
        item = command("item-demo", "protected demo", "start\nstop\n")
        raw = native("session-demo", [item])
        trace = "".join([
            execve(100, 1.0, "/usr/bin/podman", ["podman"]),
            clone(100, 1.1, 200), execve(200, 1.2, Fixture.CODEX, [Fixture.CODEX]),
            clone(200, 2.0, 300),
            execve(300, 2.01, Fixture.SHELL, [Fixture.SHELL, "-c", "protected demo"]),
            clone(300, 2.04, 305),
            execve(305, 2.05, Fixture.BASH, [
                Fixture.BASH, "-c",
                "printf '%s\\n' 'offline supervisor proxy probe' > /dev/tcp/127.0.0.1/19080",
            ]),
            write(305, 2.055, monitor.PROXY_PROBE_OUTPUT), exited(305, 2.06, 0),
            clone(300, 2.1, 310), execve(310, 2.11, Fixture.SCOURGE, start_argv),
            clone(310, 2.2, 320),
            execve(320, 2.21, Fixture.SCOURGE, [Fixture.SCOURGE, "--_scourge-demo-fixture"]),
            clone(320, 2.3, 340), execve(340, 2.31, Fixture.STAGED_TEAPOT, engine_argv),
            write(340, 2.32, engine_started),
            clone(310, 2.4, 330), execve(330, 2.41, Fixture.STAGED_TEAPOT, configure_argv),
            write(330, 2.42, b'{"configured":true}\n'), exited(330, 2.43, 0),
            write(310, 2.5, b"start\n"), exited(310, 2.51, 0),
            clone(300, 2.6, 350), execve(350, 2.61, Fixture.SCOURGE, stop_argv),
            clone(320, 2.62, 345), execve(345, 2.63, Fixture.STAGED_TEAPOT, engine_stop_argv),
            write(340, 2.64, engine_settled), write(345, 2.65, engine_stopped),
            exited(340, 2.66, 0), exited(345, 2.67, 0), exited(320, 2.68, 0),
            write(350, 2.69, b"stop\n"), exited(350, 2.70, 0), exited(300, 2.71, 0),
            write(200, 2.8, raw), exited(200, 2.9, 0), exited(100, 3.0, 0),
        ]).encode()
        snapshots = [
            self.fixture.snapshot(
                pid, monitor.PREPARATION_TEAPOT_SHA256,
                target=Fixture.STAGED_TEAPOT,
            )
            for pid in (330, 340, 345)
        ]
        value, outputs = monitor.project_trace(
            monitor.parse_trace(trace), raw, config,
            attempt_id="attempt-demo", assignment_sha256="a" * 64,
            monitor_sha256="b" * 64, launch_sha256="c" * 64,
            prompt_sha256="d" * 64, prompt_size_bytes=1,
            raw_trace_sha256=hashlib.sha256(trace).hexdigest(),
            exec_snapshots=snapshots,
        )
        roles = [row["role"] for row in value["commands"][0]["executions"]]
        self.assertEqual(roles.count("scourge-demo-fixture"), 1)
        self.assertEqual(roles.count("teapot-preparation"), 3)
        self.assertEqual(value["teapot_lanes"]["historical_engine_child"]["execution_count"], 3)
        self.assertEqual(outputs.teapot[330], b'{"configured":true}\n')
        self.assertEqual(outputs.teapot[340], engine_started + engine_settled)
        self.assertEqual(outputs.teapot[345], engine_stopped)
        pair = value["commands"][0]["demo_preparation"]
        self.assertEqual(pair["contract"], "historical-teapot-proxy-start-stop-v1")
        self.assertEqual(pair["start_process_id"], 340)
        self.assertEqual(pair["stop_process_id"], 345)
        self.assertEqual(pair["start_stdout_sha256"], hashlib.sha256(
            engine_started + engine_settled
        ).hexdigest())
        self.assertEqual(pair["stop_stdout_sha256"], hashlib.sha256(engine_stopped).hexdigest())
        self.assertEqual(pair["completion_write_order"], ["start-settled", "stop-ack"])

        raced_completion = trace.decode().replace(
            write(340, 2.64, engine_settled) + write(345, 2.65, engine_stopped),
            write(345, 2.64, engine_stopped) + write(340, 2.65, engine_settled),
        ).encode()
        raced_value, _raced_outputs = monitor.project_trace(
            monitor.parse_trace(raced_completion), raw, config,
            attempt_id="attempt-demo", assignment_sha256="a" * 64,
            monitor_sha256="b" * 64, launch_sha256="c" * 64,
            prompt_sha256="d" * 64, prompt_size_bytes=1,
            raw_trace_sha256=hashlib.sha256(raced_completion).hexdigest(),
            exec_snapshots=snapshots,
        )
        self.assertEqual(
            raced_value["commands"][0]["demo_preparation"]["completion_write_order"],
            ["stop-ack", "start-settled"],
        )

        early_completion = trace.decode().replace(
            write(340, 2.64, engine_settled), write(340, 2.625, engine_settled)
        ).encode()
        with self.assertRaisesRegex(monitor.MonitorError, "demo-engine-output-order"):
            monitor.project_trace(
                monitor.parse_trace(early_completion), raw, config,
                attempt_id="attempt-demo", assignment_sha256="a" * 64,
                monitor_sha256="b" * 64, launch_sha256="c" * 64,
                prompt_sha256="d" * 64, prompt_size_bytes=1,
                raw_trace_sha256=hashlib.sha256(early_completion).hexdigest(),
                exec_snapshots=snapshots,
            )

        missing_engine_stop_text = trace.decode()
        for event in (
            clone(320, 2.62, 345),
            execve(345, 2.63, Fixture.STAGED_TEAPOT, engine_stop_argv),
            write(345, 2.65, engine_stopped),
            exited(345, 2.67, 0),
        ):
            missing_engine_stop_text = missing_engine_stop_text.replace(event, "")
        missing_engine_stop = missing_engine_stop_text.encode()
        with self.assertRaisesRegex(monitor.MonitorError, "demo-fixture-child-mismatch"):
            monitor.project_trace(
                monitor.parse_trace(missing_engine_stop), raw, config,
                attempt_id="attempt-demo", assignment_sha256="a" * 64,
                monitor_sha256="b" * 64, launch_sha256="c" * 64,
                prompt_sha256="d" * 64, prompt_size_bytes=1,
                raw_trace_sha256=hashlib.sha256(missing_engine_stop).hexdigest(),
                exec_snapshots=snapshots,
            )
        extra_engine_stop = trace.decode().replace(
            clone(320, 2.62, 345),
            clone(320, 2.615, 346) + clone(320, 2.62, 345)
            + execve(346, 2.625, Fixture.STAGED_TEAPOT, engine_stop_argv)
            + exited(346, 2.626, 0),
        ).encode()
        extra_snapshots = [
            *snapshots,
            self.fixture.snapshot(
                346, monitor.PREPARATION_TEAPOT_SHA256,
                target=Fixture.STAGED_TEAPOT,
            ),
        ]
        with self.assertRaisesRegex(monitor.MonitorError, "demo-fixture-child-mismatch"):
            monitor.project_trace(
                monitor.parse_trace(extra_engine_stop), raw, config,
                attempt_id="attempt-demo", assignment_sha256="a" * 64,
                monitor_sha256="b" * 64, launch_sha256="c" * 64,
                prompt_sha256="d" * 64, prompt_size_bytes=1,
                raw_trace_sha256=hashlib.sha256(extra_engine_stop).hexdigest(),
                exec_snapshots=extra_snapshots,
            )
        reordered_engine_stop = trace.decode().replace(
            clone(320, 2.62, 345), clone(320, 2.25, 345)
        ).encode()
        with self.assertRaisesRegex(monitor.MonitorError, "demo-engine-mismatch"):
            monitor.project_trace(
                monitor.parse_trace(reordered_engine_stop), raw, config,
                attempt_id="attempt-demo", assignment_sha256="a" * 64,
                monitor_sha256="b" * 64, launch_sha256="c" * 64,
                prompt_sha256="d" * 64, prompt_size_bytes=1,
                raw_trace_sha256=hashlib.sha256(reordered_engine_stop).hexdigest(),
                exec_snapshots=snapshots,
            )
        wrong_binary_snapshots = [
            replace(snapshot, sha256="f" * 64) if snapshot.process_id == 345 else snapshot
            for snapshot in snapshots
        ]
        with self.assertRaisesRegex(monitor.MonitorError, "unsafe-preparation-teapot"):
            monitor.project_trace(
                monitor.parse_trace(trace), raw, config,
                attempt_id="attempt-demo", assignment_sha256="a" * 64,
                monitor_sha256="b" * 64, launch_sha256="c" * 64,
                prompt_sha256="d" * 64, prompt_size_bytes=1,
                raw_trace_sha256=hashlib.sha256(trace).hexdigest(),
                exec_snapshots=wrong_binary_snapshots,
            )
        tampered_output = trace.replace(b'\\x74\\x72\\x75\\x65', b'\\x6e\\x75\\x6c\\x6c', 1)
        with self.assertRaisesRegex(monitor.MonitorError, "demo-engine-output"):
            monitor.project_trace(
                monitor.parse_trace(tampered_output), raw, config,
                attempt_id="attempt-demo", assignment_sha256="a" * 64,
                monitor_sha256="b" * 64, launch_sha256="c" * 64,
                prompt_sha256="d" * 64, prompt_size_bytes=1,
                raw_trace_sha256=hashlib.sha256(tampered_output).hexdigest(),
                exec_snapshots=snapshots,
            )
        split_probe = trace.decode().replace(
            write(305, 2.055, monitor.PROXY_PROBE_OUTPUT),
            write(305, 2.054, monitor.PROXY_PROBE_OUTPUT[:10])
            + write(305, 2.055, monitor.PROXY_PROBE_OUTPUT[10:]),
        ).encode()
        with self.assertRaisesRegex(monitor.MonitorError, "unqualified-shell-helper"):
            monitor.project_trace(
                monitor.parse_trace(split_probe), raw, config,
                attempt_id="attempt-demo", assignment_sha256="a" * 64,
                monitor_sha256="b" * 64, launch_sha256="c" * 64,
                prompt_sha256="d" * 64, prompt_size_bytes=1,
                raw_trace_sha256=hashlib.sha256(split_probe).hexdigest(),
                exec_snapshots=snapshots,
            )
        probe_command = (
            "printf '%s\\n' 'offline supervisor proxy probe' > /dev/tcp/127.0.0.1/19080"
        )
        wrong_destination = trace.decode().replace(
            hx(probe_command), hx(probe_command.replace("19080", "19081"))
        ).encode()
        with self.assertRaisesRegex(monitor.MonitorError, "unqualified-shell-helper"):
            monitor.project_trace(
                monitor.parse_trace(wrong_destination), raw, config,
                attempt_id="attempt-demo", assignment_sha256="a" * 64,
                monitor_sha256="b" * 64, launch_sha256="c" * 64,
                prompt_sha256="d" * 64, prompt_size_bytes=1,
                raw_trace_sha256=hashlib.sha256(wrong_destination).hexdigest(),
                exec_snapshots=snapshots,
            )
        self.assertFalse(monitor._historical_teapot_argv(
            [Fixture.STAGED_TEAPOT, "--project", project, "--json", "shell", "-c", "id"],
            Fixture.STAGED_TEAPOT,
            Fixture.PREPARATION_ROOT,
        ))

    def test_codex_bootstrap_helpers_are_exact_pretool_infrastructure(self):
        getconf = "/usr/bin/getconf"
        config = replace(
            self.fixture.config,
            executables=(*self.fixture.config.executables, monitor.ExecutablePin(
                getconf, "e" * 64, "image"
            )),
            codex_bootstrap=True,
        )
        base = "/runtime/codex-home/tmp/arg0-linux/codex-arg0abc123"
        rows = []
        stamp = 1.3
        for cycle in range(3):
            lsb = 210 + cycle * 2
            get = lsb + 1
            rows.extend([
                clone(200, stamp, lsb),
                failed_execve(lsb, stamp + .01, f"{base}/lsb_release", ["lsb_release", "-a"]),
                failed_execve(lsb, stamp + .02, "/opt/scourge-bin/lsb_release", ["lsb_release", "-a"]),
                failed_execve(lsb, stamp + .03, "/usr/bin/lsb_release", ["lsb_release", "-a"]),
                failed_execve(lsb, stamp + .04, "/bin/lsb_release", ["lsb_release", "-a"]),
                exited(lsb, stamp + .05, 127),
                clone(200, stamp + .06, get),
                failed_execve(get, stamp + .07, f"{base}/getconf", ["getconf", "LONG_BIT"]),
                failed_execve(get, stamp + .08, "/opt/scourge-bin/getconf", ["getconf", "LONG_BIT"]),
                execve(get, stamp + .09, getconf, ["getconf", "LONG_BIT"]),
                write(get, stamp + .10, b"64\n"),
                exited(get, stamp + .11, 0),
            ])
            stamp += .2
        trace = self.fixture.trace.decode().replace(
            clone(200, 2.0, 300), "".join(rows) + clone(200, 2.0, 300)
        ).encode()
        value, _outputs = monitor.project_trace(
            monitor.parse_trace(trace), self.fixture.raw, config,
            attempt_id="attempt-bootstrap", assignment_sha256="a" * 64,
            monitor_sha256="b" * 64, launch_sha256="c" * 64,
            prompt_sha256="d" * 64, prompt_size_bytes=1,
            raw_trace_sha256=hashlib.sha256(trace).hexdigest(),
        )
        bootstrap = value["infrastructure"]["bootstrap"]
        self.assertEqual(len(bootstrap), 6)
        self.assertEqual(
            [row["infrastructure_role"] for row in bootstrap],
            ["codex-os-detection-lsb_release", "codex-os-detection-getconf"] * 3,
        )
        self.assertEqual(value["infrastructure"]["bootstrap_contract"],
                         "codex-0.172-os-detection-v1")

        wrong = trace.decode().replace(write(211, 1.4, b"64\n"), write(211, 1.4, b"32\n")).encode()
        with self.assertRaises(monitor.MonitorError):
            monitor.project_trace(
                monitor.parse_trace(wrong), self.fixture.raw, config,
                attempt_id="attempt-bootstrap", assignment_sha256="a" * 64,
                monitor_sha256="b" * 64, launch_sha256="c" * 64,
                prompt_sha256="d" * 64, prompt_size_bytes=1,
                raw_trace_sha256=hashlib.sha256(wrong).hexdigest(),
            )

    def test_codex_process_setup_is_one_exact_pinned_tool_launcher(self):
        config = replace(
            self.fixture.config, codex_bootstrap=True,
            codex_setup_device=20, codex_setup_inode=21,
            codex_setup_fd_ceiling=256,
            codex_setup_fd_access_modes=(os.O_WRONLY, os.O_WRONLY),
        )
        command_text = self.fixture.items[0]["command"]
        setup_argv = [
            "/proc/self/exe", "--codex-run-as-process-setup", "40", "4", "pipe", "",
            "/workspace", Fixture.SHELL, Fixture.SHELL, "-lc", command_text,
        ]
        trace = "".join([
            execve(200, 1.0, Fixture.CODEX, [Fixture.CODEX]),
            clone(200, 1.1, 300, monitor.CODEX_PROCESS_SETUP_CLONE_FLAGS),
            execve(300, 1.2, "/proc/self/exe", setup_argv),
            write(300, 1.25, b"\0", fd=40),
            execve(300, 1.3, Fixture.SHELL, [Fixture.SHELL, "-lc", command_text]),
            exited(300, 1.4, 0), exited(200, 1.5, 0),
        ]).encode()
        codex_sha = config.pins[Fixture.CODEX].sha256
        shell_sha = config.pins[Fixture.SHELL].sha256
        snapshots = [
            self.fixture.snapshot(
                200, codex_sha, sequence=1, target=Fixture.CODEX,
                device=20, inode=21, mode=0o755,
            ),
            self.fixture.snapshot(
                300, codex_sha, sequence=1, target=Fixture.CODEX,
                device=20, inode=21, mode=0o755, observed_monotonic_ns=101,
                process_setup_fds=(
                    monitor.ExecFdSnapshot(40, "pipe:[401]", 50, 401,
                                           stat.S_IFIFO | 0o600, os.O_WRONLY),
                    monitor.ExecFdSnapshot(4, "pipe:[402]", 50, 402,
                                           stat.S_IFIFO | 0o600, os.O_WRONLY),
                ),
                process_setup_observations=3,
                process_setup_topology_status="observed",
            ),
            self.fixture.snapshot(
                300, shell_sha, sequence=2, target="/usr/bin/dash",
                device=30, inode=31, mode=0o755, observed_monotonic_ns=102,
            ),
        ]
        parsed = monitor.parse_trace(trace)
        process = parsed.processes[300]
        pin, role, snapshot = monitor._validate_image(
            process, config.pins, config, snapshots
        )
        self.assertEqual(role, "codex-tool-launcher")
        self.assertEqual(pin.sha256, shell_sha)
        self.assertEqual(snapshot.target, "/usr/bin/dash")
        process.signal_events.append(monitor.SignalEvent(
            1.26, "SIGURG", "SI_TKILL", 300, 300, os.geteuid(), None, 1,
            "a" * 64,
        ))
        monitor._reconcile_signals(parsed, {300}, config.pins, config, snapshots)
        for stamp, epoch in ((1.19, 0), (1.31, 2), (1.6, 2)):
            with self.subTest(sigurg_stamp=stamp, sigurg_epoch=epoch):
                process.signal_events[0] = replace(
                    process.signal_events[0], stamp=stamp, exec_epoch=epoch
                )
                with self.assertRaisesRegex(monitor.MonitorError, "unreconciled-signal"):
                    monitor._reconcile_signals(
                        parsed, {300}, config.pins, config, snapshots
                    )
        process.signal_events[0] = replace(
            process.signal_events[0], stamp=1.26, exec_epoch=1
        )
        monitor._bind_command_root(process, self.fixture.items[0], config, {200}, snapshots)
        membership = monitor._codex_parent_membership(
            parsed, process, 200, {200}, config.pins, config, snapshots
        )
        self.assertEqual(membership["direct_parent_thread_id"], 200)
        self.assertEqual(membership["thread_chain"], [])
        row = monitor._execution(
            parsed, process, pin, {300}, config.pins, role, snapshot, snapshots
        )
        self.assertEqual(
            [entry["binary_sha256"] for entry in row["exec_chain"]],
            [codex_sha, shell_sha],
        )
        fallback_pin, fallback_role, fallback_snapshot = monitor._validate_image(
            process, config.pins, config, [snapshots[0], replace(snapshots[2], sequence=1)]
        )
        self.assertEqual((fallback_pin.sha256, fallback_role, fallback_snapshot.target),
                         (shell_sha, "codex-tool-launcher", "/usr/bin/dash"))
        unavailable = replace(
            snapshots[1], process_setup_fds=(),
            process_setup_topology_status="unavailable-fd-4",
        )
        unavailable_pin, unavailable_role, _ = monitor._validate_image(
            process, config.pins, config, [snapshots[0], unavailable, snapshots[2]]
        )
        self.assertEqual((unavailable_pin.sha256, unavailable_role),
                         (shell_sha, "codex-tool-launcher"))

        mutations = {
            "fd": [*setup_argv[:2], "41", *setup_argv[3:]],
            "mode": [*setup_argv[:4], "socketpair", *setup_argv[5:]],
            "workspace": [*setup_argv[:6], "/tmp", *setup_argv[7:]],
            "shell": [*setup_argv[:-1], "other"],
        }
        for label, argv in mutations.items():
            with self.subTest(label=label):
                changed = trace.decode().replace(
                    execve(300, 1.2, "/proc/self/exe", setup_argv),
                    execve(300, 1.2, "/proc/self/exe", argv),
                ).encode()
                expected_error = (
                    "codex-process-setup-signal" if label == "fd" else "unresolved-exec-chain"
                )
                with self.assertRaisesRegex(monitor.MonitorError, expected_error):
                    monitor._validate_image(
                        monitor.parse_trace(changed).processes[300],
                        config.pins, config, snapshots,
                    )
        with self.assertRaisesRegex(monitor.MonitorError, "codex-process-setup-parent"):
            monitor._bind_command_root(process, self.fixture.items[0], config, {201}, snapshots)
        wrong_signal = trace.decode().replace(
            write(300, 1.25, b"\0", fd=40), write(300, 1.25, b"x", fd=40)
        ).encode()
        with self.assertRaisesRegex(monitor.MonitorError, "codex-process-setup-signal"):
            monitor._validate_image(
                monitor.parse_trace(wrong_signal).processes[300],
                config.pins, config, snapshots,
            )
        extra_signal = trace.decode().replace(
            write(300, 1.25, b"\0", fd=40),
            write(300, 1.24, b"x", fd=41) + write(300, 1.25, b"\0", fd=40),
        ).encode()
        with self.assertRaisesRegex(monitor.MonitorError, "codex-process-setup-fd"):
            monitor._validate_image(
                monitor.parse_trace(extra_signal).processes[300],
                config.pins, config, snapshots,
            )
        replaced_snapshot = replace(snapshots[1], inode=999)
        with self.assertRaisesRegex(monitor.MonitorError, "codex-process-setup-snapshot"):
            monitor._validate_image(
                process, config.pins, config,
                [snapshots[0], replaced_snapshot, snapshots[2]],
            )
        replaced_digest = replace(snapshots[1], sha256="9" * 64)
        with self.assertRaisesRegex(monitor.MonitorError, "codex-process-setup-snapshot"):
            monitor._validate_image(
                process, config.pins, config,
                [snapshots[0], replaced_digest, snapshots[2]],
            )
        aliased_fds = replace(
            snapshots[1],
            process_setup_fds=(
                snapshots[1].process_setup_fds[0],
                replace(snapshots[1].process_setup_fds[1], inode=401, target="pipe:[401]"),
            ),
        )
        with self.assertRaisesRegex(monitor.MonitorError, "codex-process-setup-fd"):
            monitor._validate_image(
                process, config.pins, config, [snapshots[0], aliased_fds, snapshots[2]]
            )
        non_pipe = replace(
            snapshots[1],
            process_setup_fds=(
                replace(snapshots[1].process_setup_fds[0], mode=stat.S_IFREG | 0o600),
                snapshots[1].process_setup_fds[1],
            ),
        )
        with self.assertRaisesRegex(monitor.MonitorError, "codex-process-setup-fd"):
            monitor._validate_image(
                process, config.pins, config, [snapshots[0], non_pipe, snapshots[2]]
            )
        wrong_parent_pin = replace(
            config,
            executables=tuple(
                replace(pin, sha256="8" * 64) if pin.path == Fixture.CODEX else pin
                for pin in config.executables
            ),
        )
        with self.assertRaisesRegex(monitor.MonitorError, "codex-process-setup-snapshot"):
            monitor._validate_image(
                process, wrong_parent_pin.pins, wrong_parent_pin, snapshots[1:]
            )

    def test_login_profile_helpers_are_exact_precommand_support(self):
        id_path = "/usr/bin/id"
        run_parts = "/usr/bin/run-parts"
        extra_pins = (
            monitor.ExecutablePin(id_path, "1" * 64, "image"),
            monitor.ExecutablePin(run_parts, "2" * 64, "image"),
        )
        config = replace(
            self.fixture.config,
            executables=(*self.fixture.config.executables, *extra_pins),
            codex_bootstrap=True,
            codex_setup_device=20,
            codex_setup_inode=21,
            codex_setup_fd_ceiling=256,
            codex_setup_fd_access_modes=(os.O_WRONLY, os.O_WRONLY),
            worker_image_id="3" * 64,
            login_profile_sha256="4" * 64,
            login_profile_inventory=(),
        )
        command_text = self.fixture.items[0]["command"]
        setup_argv = [
            "/proc/self/exe", "--codex-run-as-process-setup", "40", "4", "pipe", "",
            "/workspace", Fixture.SHELL, Fixture.SHELL, "-lc", command_text,
        ]
        run_parts_argv = [
            "run-parts", "--list", "--regex",
            r"^[a-zA-Z0-9_][a-zA-Z0-9._-]*\.sh$", "/etc/profile.d",
        ]
        trace = "".join([
            execve(200, 1.0, Fixture.CODEX, [Fixture.CODEX]),
            clone(200, 1.1, 300, monitor.CODEX_PROCESS_SETUP_CLONE_FLAGS),
            execve(300, 1.2, "/proc/self/exe", setup_argv),
            write(300, 1.25, b"\0", fd=40),
            execve(300, 1.3, Fixture.SHELL, [Fixture.SHELL, "-lc", command_text]),
            clone(300, 1.4, 301), execve(301, 1.41, id_path, ["id", "-u"]),
            write(301, 1.42, b"1000\n"), exited(301, 1.43, 0),
            clone(300, 1.5, 302), execve(302, 1.51, id_path, ["id", "-u"]),
            write(302, 1.52, b"1000\n"), exited(302, 1.53, 0),
            clone(300, 1.6, 303), execve(303, 1.61, run_parts, run_parts_argv),
            exited(303, 1.63, 0),
            clone(300, 1.7, 304), execve(304, 1.71, Fixture.BASH, [Fixture.BASH, "-c", "next"]),
            exited(304, 1.72, 0), exited(300, 1.8, 0), exited(200, 1.9, 0),
        ]).encode()
        codex_sha = config.pins[Fixture.CODEX].sha256
        shell_sha = config.pins[Fixture.SHELL].sha256
        snapshots = [
            self.fixture.snapshot(200, codex_sha, sequence=1, target=Fixture.CODEX,
                                  device=20, inode=21, mode=0o755),
            self.fixture.snapshot(300, codex_sha, sequence=1, target=Fixture.CODEX,
                                  device=20, inode=21, mode=0o755,
                                  observed_monotonic_ns=101,
                                  process_setup_fds=(
                                      monitor.ExecFdSnapshot(
                                          40, "pipe:[401]", 50, 401,
                                          stat.S_IFIFO | 0o600, os.O_WRONLY),
                                      monitor.ExecFdSnapshot(
                                          4, "pipe:[402]", 50, 402,
                                          stat.S_IFIFO | 0o600, os.O_WRONLY),
                                  ), process_setup_observations=3,
                                  process_setup_topology_status="observed"),
            self.fixture.snapshot(300, shell_sha, sequence=2, target="/usr/bin/dash",
                                  mode=0o755, observed_monotonic_ns=102),
            self.fixture.snapshot(301, "1" * 64, sequence=1, target=id_path, mode=0o755),
            self.fixture.snapshot(302, "1" * 64, sequence=1, target=id_path, mode=0o755),
            self.fixture.snapshot(303, "2" * 64, sequence=1, target=run_parts, mode=0o755),
        ]
        parsed = monitor.parse_trace(trace)
        children = monitor._children(parsed)
        self.assertEqual(
            monitor._login_profile_helpers(
                parsed, children, 300, config.pins, config, snapshots
            ),
            {301: "login-profile-id", 302: "login-profile-id",
             303: "login-profile-run-parts"},
        )
        wrong_argv = trace.decode().replace(
            execve(302, 1.51, id_path, ["id", "-u"]),
            execve(302, 1.51, id_path, ["id", "-g"]),
        ).encode()
        with self.assertRaisesRegex(monitor.MonitorError, "login-profile-helper"):
            wrong = monitor.parse_trace(wrong_argv)
            monitor._login_profile_helpers(
                wrong, monitor._children(wrong), 300, config.pins, config, snapshots
            )
        wrong_output = trace.decode().replace(write(301, 1.42, b"1000\n"),
                                               write(301, 1.42, b"0\n")).encode()
        with self.assertRaisesRegex(monitor.MonitorError, "login-profile-helper"):
            wrong = monitor.parse_trace(wrong_output)
            monitor._login_profile_helpers(
                wrong, monitor._children(wrong), 300, config.pins, config, snapshots
            )
        with self.assertRaisesRegex(monitor.MonitorError, "nonempty-login-profile-inventory"):
            replace(config, login_profile_inventory=("unexpected.sh",))

    def test_command_root_epoch_exit_and_bare_scourge_argv0_are_bound(self):
        bare = self.fixture.trace.decode().replace(
            execve(300, 2.1, Fixture.SCOURGE, [Fixture.SCOURGE, "direct"]),
            write(300, 2.075, b"shell-before\n")
            + execve(300, 2.1, Fixture.SCOURGE, ["scourge", "direct"]),
        ).encode()
        value, outputs = self.fixture.project(bare)
        execution = value["commands"][0]["executions"][0]
        self.assertEqual(execution["argv"][0], "scourge")
        self.assertEqual(outputs.scourge[300], b"direct\n")

        wrong_command = bare.decode().replace(hx(self.fixture.items[0]["command"]), hx("other"), 1).encode()
        with self.assertRaisesRegex(monitor.MonitorError, "command-root-argv"):
            self.fixture.project(wrong_command)
        wrong_exit = bare.decode().replace(exited(300, 2.3, 0), exited(300, 2.3, 9)).encode()
        with self.assertRaisesRegex(monitor.MonitorError, "command-root-exit"):
            self.fixture.project(wrong_exit)
        nonfinal = bare.decode().replace(
            write(300, 2.2, b"direct\n"),
            execve(300, 2.15, Fixture.HELPER, [Fixture.HELPER]) + write(300, 2.2, b"direct\n"),
        ).encode()
        with self.assertRaisesRegex(monitor.MonitorError, "nonfinal-scourge"):
            self.fixture.project(nonfinal)

    def test_overlapping_or_missing_command_trees_and_raw_drift_fail(self):
        raw = native("session-1", [
            command("item-1", "one", "one\n"), command("item-2", "two", "two\n")
        ])
        trace = "".join([
            execve(100, 1, "/usr/bin/podman", ["podman"]), clone(100, 1.1, 200),
            execve(200, 1.2, Fixture.CODEX, [Fixture.CODEX]),
            clone(200, 2.0, 300), execve(300, 2.01, Fixture.SHELL, [Fixture.SHELL, "-c", "one"]),
            execve(300, 2.1, Fixture.SCOURGE, [Fixture.SCOURGE, "one"]),
            clone(200, 2.2, 301), execve(301, 2.21, Fixture.SHELL, [Fixture.SHELL, "-c", "two"]),
            execve(301, 2.3, Fixture.SCOURGE, [Fixture.SCOURGE, "two"]),
            write(300, 2.4, b"one\n"), exited(300, 2.6, 0),
            write(301, 2.5, b"two\n"), exited(301, 2.7, 0),
            write(200, 2.8, raw), exited(200, 2.9, 0), exited(100, 3, 0),
        ]).encode()
        with self.assertRaisesRegex(monitor.MonitorError, "overlapping-command"):
            self.fixture.project(trace, raw)
        with self.assertRaisesRegex(monitor.MonitorError, "codex-stdout-mismatch"):
            self.fixture.project(raw=self.fixture.raw + b"{}\n")
        fewer = native("session-1", [])
        changed = self.fixture.trace.decode().replace(
            writev(200, 2.4, [self.fixture.raw[:20], self.fixture.raw[20:]]),
            write(200, 2.4, fewer),
        ).encode()
        with self.assertRaisesRegex(monitor.MonitorError, "command-tree-count"):
            self.fixture.project(changed, fewer)

    def test_hmac_is_domain_separated_and_tamper_evident(self):
        trace, _ = self.fixture.project()
        key = bytes(range(32))
        envelope = monitor.authenticate_trace(trace, key)
        self.assertTrue(monitor.verify_envelope(envelope, key))
        envelope["trace"]["lost_events"] = 1
        self.assertFalse(monitor.verify_envelope(envelope, key))
        self.assertFalse(monitor.verify_envelope(monitor.authenticate_trace(trace, key), b"x" * 32))

    def test_key_and_private_directory_contract(self):
        with tempfile.TemporaryDirectory(prefix="scourge-monitor-test-") as directory:
            root = Path(directory)
            os.chmod(root, 0o700)
            path = monitor.create_monitor_key(root)
            self.assertEqual(stat_mode(path), 0o600)
            self.assertEqual(len(monitor.read_monitor_key(path)), 32)
            os.chmod(path, 0o644)
            with self.assertRaisesRegex(monitor.MonitorError, "unsafe-monitor-key"):
                monitor.read_monitor_key(path)
            path.unlink()
            target = root / "other"
            target.write_bytes(b"x" * 32)
            os.chmod(target, 0o600)
            path.symlink_to(target)
            with self.assertRaisesRegex(monitor.MonitorError, "unsafe-monitor-key"):
                monitor.read_monitor_key(path)

    def test_monitor_environment_does_not_inherit_credentials(self):
        environment = monitor.monitor_environment({
            "HOME": "/home/test", "XDG_RUNTIME_DIR": "/run/user/1",
            "OPENAI_API_KEY": "secret", "AWS_SECRET_ACCESS_KEY": "secret",
            "SCOURGE_MONITOR_CREDENTIAL_CANARY": "secret", "PATH": "/host/bin",
        })
        self.assertEqual(environment["PATH"], "/usr/bin:/bin")
        self.assertNotIn("OPENAI_API_KEY", environment)
        self.assertNotIn("AWS_SECRET_ACCESS_KEY", environment)
        self.assertNotIn("SCOURGE_MONITOR_CREDENTIAL_CANARY", environment)

    def test_fixed_strace_and_podman_policy_are_fail_closed(self):
        rendered = " ".join(monitor.FIXED_STRACE_ARGS)
        self.assertNotIn(" -v", " " + rendered)
        self.assertNotIn("--abbrev=none", rendered)
        self.assertNotIn("-E", monitor.FIXED_STRACE_ARGS)
        good = self.fixture.podman_argv
        monitor.validate_podman_argv(good, self.fixture.config)
        with self.assertRaisesRegex(monitor.MonitorError, "podman-argv-mismatch"):
            monitor.validate_podman_argv(good + ["--label=unbound"], self.fixture.config)
        unsafe = (
            good + ["--network=bridge"],
            good + ["--network", "slirp4netns"],
            good + ["--privileged=true"],
            good + ["--cap-add=NET_ADMIN"],
            good + ["--device=/dev/null"],
            good + ["--name", "other"],
            good + ["run"],
            good + ["--read-only=false"],
            good + ["--security-opt=label=disable"],
        )
        for bad in unsafe:
            bound = replace(
                self.fixture.config,
                podman_argv_sha256=monitor.podman_argv_digest(bad),
            )
            with self.assertRaises(monitor.MonitorError):
                monitor.validate_podman_argv(bad, bound)
        with self.assertRaisesRegex(monitor.MonitorError, "unqualified-teapot-digest"):
            monitor.MonitorConfig(
                "/usr/bin/strace", "/usr/bin/podman", "/usr/bin/crun",
                Fixture.CODEX, Fixture.SCOURGE, self.fixture.pins,
                monitor.podman_argv_digest(good),
                mounts=(monitor.MountPin(
                    "/srv/workspace", "/workspace", False, "private-writable",
                    1, 1, 0o700, os.geteuid(),
                ),),
                mount_root="/srv",
                teapot_path=Fixture.TEAPOT,
                teapot_sha256=hashlib.sha256(Fixture.TEAPOT.encode()).hexdigest(),
            )

    def test_native_boundary_production_argv_composes_with_exact_worker_environment(self):
        environment = monitor.worker_environment_rows(
            native_boundary_environment(proxy_port=19080)
        )
        argv = [
            "/usr/bin/podman", "--remote=false", "--runtime=/usr/bin/crun", "run",
            "--rm", "--unsetenv-all", "--interactive", "--pull=never", "--network=none", "--read-only",
            "--http-proxy=false", "--cap-drop=all",
            "--security-opt=no-new-privileges", "--pids-limit=128",
            "--userns=keep-id", "--hostname=scourge-worker", "--name", "scourge-production",
            "--cidfile", "/runtime/worker.cid",
            "--mount", "type=bind,src=/srv/workspace,dst=/workspace",
            "--mount", "type=bind,src=/srv/runtime,dst=/runtime",
            "--mount", "type=bind,src=/srv/gateway,dst=/gateway,ro=true",
        ]
        for name, value in environment:
            argv.extend(("--env", f"{name}={value}"))
        argv.extend((
            "--entrypoint", Fixture.CODEX, "a" * 64, "exec", "--json",
            "--disable", "code_mode", "--disable", "code_mode_host",
            "--disable", "shell_snapshot", "-",
        ))
        config = replace(
            self.fixture.config,
            podman_argv_sha256=monitor.podman_argv_digest(argv),
            worker_environment=environment,
        )
        monitor.validate_podman_argv(argv, config)

        # Production composition must select these three explicit builder
        # parameters. The bn-3plk inspection-only qualifier may use
        # auto_remove=false outside this collector.
        relative_podman = list(argv)
        relative_podman[0] = "podman"
        incompatible = (
            relative_podman,
            [word for word in argv if word != "--runtime=/usr/bin/crun"],
            [word for word in argv if word != "--rm"],
        )
        for bad in incompatible:
            rebound = replace(config, podman_argv_sha256=monitor.podman_argv_digest(bad))
            with self.assertRaises(monitor.MonitorError):
                monitor.validate_podman_argv(bad, rebound)

        injected_rows = (
            ("HOME", "/runtime/home"),
            ("UNKNOWN", "value"),
            ("OPENAI_API_KEY", "secret"),
        )
        for name, value in injected_rows:
            bad = [*argv, "--env", f"{name}={value}"]
            rebound = replace(config, podman_argv_sha256=monitor.podman_argv_digest(bad))
            with self.assertRaises(monitor.MonitorError):
                monitor.validate_podman_argv(bad, rebound)
        equals_form = [
            "--env=HOME=/runtime/home" if word == "--env" else word for word in argv
        ]
        rebound = replace(config, podman_argv_sha256=monitor.podman_argv_digest(equals_form))
        with self.assertRaises(monitor.MonitorError):
            monitor.validate_podman_argv(equals_form, rebound)

        with self.assertRaisesRegex(monitor.MonitorError, "unexpected-worker-environment"):
            monitor.worker_environment_rows({**native_boundary_environment(), "UNKNOWN": "x"})
        with self.assertRaisesRegex(monitor.MonitorError, "unsafe-worker-environment"):
            monitor.worker_environment_rows({
                **native_boundary_environment(), "OPENAI_API_KEY": "secret",
            })
        with self.assertRaisesRegex(monitor.MonitorError, "unsafe-worker-environment"):
            replace(config, worker_environment=environment + (("HOME", "/runtime/home"),))

    def test_mount_manifest_binds_sources_destinations_modes_and_protected_roots(self):
        with tempfile.TemporaryDirectory(prefix="scourge-mounts-", dir=Path.cwd()) as directory:
            root = Path(directory)
            root.chmod(0o700)
            workspace, runtime, gateway = (
                root / "workspace", root / "runtime", root / "gateway"
            )
            for path in (workspace, runtime, gateway):
                path.mkdir(mode=0o700)
            codex, scourge = root / "codex", root / "scourge"
            codex.write_bytes(b"codex")
            scourge.write_bytes(b"scourge")
            codex.chmod(0o500)
            scourge.chmod(0o500)
            codex_sha = hashlib.sha256(b"codex").hexdigest()
            scourge_sha = hashlib.sha256(b"scourge").hexdigest()
            pins = (
                monitor.ExecutablePin(Fixture.CODEX, codex_sha, "read-only-mount"),
                monitor.ExecutablePin(Fixture.SCOURGE, scourge_sha, "read-only-mount"),
            )
            mounts = (
                monitor.MountPin.capture(
                    workspace, "/workspace", read_only=False,
                    source_class="private-writable",
                ),
                monitor.MountPin.capture(
                    runtime, "/runtime", read_only=False,
                    source_class="private-writable",
                ),
                monitor.MountPin.capture(
                    gateway, "/gateway", read_only=True,
                    source_class="gateway-sockets",
                ),
                monitor.MountPin.capture(
                    codex, Fixture.CODEX, read_only=True,
                    source_class="pinned-executable", sha256=codex_sha,
                ),
                monitor.MountPin.capture(
                    scourge, Fixture.SCOURGE, read_only=True,
                    source_class="pinned-executable", sha256=scourge_sha,
                ),
            )
            environment = monitor.worker_environment_rows(native_boundary_environment())
            argv = [
                "/usr/bin/podman", "--remote=false", "--runtime=/usr/bin/crun", "run",
                "--rm", "--unsetenv-all", "--interactive", "--pull=never",
                "--network=none", "--read-only", "--http-proxy=false", "--cap-drop=all",
                "--security-opt=no-new-privileges", "--pids-limit=128", "--userns=keep-id",
                "--hostname=scourge-worker", "--name", "mount-test", "--cidfile",
                os.fspath(root / "worker.cid"),
            ]
            for row in mounts:
                value = f"type=bind,src={row.source},dst={row.destination}"
                if row.read_only:
                    value += ",ro=true"
                argv.extend(("--mount", value))
            for name, value in environment:
                argv.extend(("--env", f"{name}={value}"))
            argv.extend((
                "--entrypoint", Fixture.CODEX, "a" * 64, "exec", "--json",
                "--disable", "code_mode", "--disable", "code_mode_host",
                "--disable", "shell_snapshot", "-",
            ))
            config = monitor.MonitorConfig(
                "/usr/bin/strace", "/usr/bin/podman", "/usr/bin/crun",
                Fixture.CODEX, Fixture.SCOURGE, pins, monitor.podman_argv_digest(argv),
                mounts=mounts, mount_root=os.fspath(root),
                protected_mount_roots=(os.fspath(Path.home() / ".ssh"),),
                worker_environment=environment, qualification_child_pins=True,
            )
            monitor.validate_podman_argv(argv, config)

            for source in (Path("/etc"), Path.home() / ".ssh"):
                bad_mount = monitor.MountPin.capture(
                    source, "/workspace", read_only=False,
                    source_class="private-writable",
                )
                bad_mounts = (bad_mount, *mounts[1:])
                bad_argv = list(argv)
                mount_index = bad_argv.index("--mount") + 1
                bad_argv[mount_index] = (
                    f"type=bind,src={source},dst=/workspace"
                )
                bad_config = replace(
                    config, mounts=bad_mounts,
                    podman_argv_sha256=monitor.podman_argv_digest(bad_argv),
                )
                with self.subTest(source=source):
                    with self.assertRaisesRegex(monitor.MonitorError, "unsafe-mount-source"):
                        monitor.validate_podman_argv(bad_argv, bad_config)

            writable_shadow = list(argv)
            scourge_mount = next(
                index for index, value in enumerate(writable_shadow)
                if value.startswith("type=bind") and "dst=/opt/scourge-bin/scourge" in value
            )
            writable_shadow[scourge_mount] = writable_shadow[scourge_mount].removesuffix(
                ",ro=true"
            )
            shadow_config = replace(
                config, podman_argv_sha256=monitor.podman_argv_digest(writable_shadow)
            )
            with self.assertRaises(monitor.MonitorError):
                monitor.validate_podman_argv(writable_shadow, shadow_config)

    def test_evidence_refs_resolve_without_following_or_rewriting_paths(self):
        with tempfile.TemporaryDirectory(prefix="scourge-evidence-", dir=Path.cwd()) as directory:
            root = Path(directory)
            root.chmod(0o700)
            retained = root / "attempt-1" / "retained" / "artifacts"
            retained.mkdir(parents=True, mode=0o700)
            for parent in (root / "attempt-1", root / "attempt-1" / "retained"):
                parent.chmod(0o700)

            output = b"native output\n"
            output_path = retained / "call-001.stdout"
            output_path.write_bytes(output)
            output_path.chmod(0o600)
            output_ref = {
                "path": "attempt-1/retained/artifacts/call-001.stdout",
                "sha256": hashlib.sha256(output).hexdigest(),
            }
            trace = {"session_id": "session-1", "raw_sha256": "a" * 64, "commands": []}
            key = b"k" * 32
            envelope = monitor.authenticate_trace(trace, key)
            events = {
                "schema": monitor.EVENTS_SCHEMA, "source": "process-monitor",
                "session_id": "session-1", "raw_sha256": "a" * 64,
                "complete": True, "commands": [],
                "calls": [{"stdout": output_ref}], "child_originals": [],
            }
            envelope_data = monitor.canonical(envelope) + b"\n"
            events_data = monitor.canonical(events) + b"\n"
            envelope_path = retained / "host-trace.json"
            events_path = retained / "events.json"
            envelope_path.write_bytes(envelope_data)
            events_path.write_bytes(events_data)
            envelope_path.chmod(0o600)
            events_path.chmod(0o600)
            envelope_ref = {
                "path": "attempt-1/retained/artifacts/host-trace.json",
                "sha256": hashlib.sha256(envelope_data).hexdigest(),
            }
            events_ref = {
                "path": "attempt-1/retained/artifacts/events.json",
                "sha256": hashlib.sha256(events_data).hexdigest(),
            }
            self.assertEqual(
                monitor.verify_evidence_projection(root, envelope_ref, events_ref, key),
                (envelope, events),
            )
            binding = monitor.evidence_binding(
                root, envelope_ref, events_ref, events, key
            )
            self.assertTrue(monitor.verify_evidence_binding(
                root, envelope_ref, events_ref, events, binding, key
            ))
            changed_binding = json.loads(json.dumps(binding))
            changed_binding["manifest"]["nested"][0]["bytes"] += 1
            self.assertFalse(monitor.verify_evidence_binding(
                root, envelope_ref, events_ref, events, changed_binding, key
            ))
            self.assertFalse(monitor.verify_evidence_binding(
                root, envelope_ref, events_ref, events, binding, b"x" * 32
            ))

            bad = dict(output_ref, path="attempt-1/retained/call-001.stdout")
            with self.assertRaisesRegex(monitor.MonitorError, "unresolved-evidence-reference"):
                monitor.resolve_evidence_ref(root, bad)
            with self.assertRaisesRegex(monitor.MonitorError, "evidence-digest-mismatch"):
                monitor.resolve_evidence_ref(root, dict(output_ref, sha256="0" * 64))
            output_path.unlink()
            output_path.symlink_to("/etc/passwd")
            with self.assertRaisesRegex(monitor.MonitorError, "unresolved-evidence-reference"):
                monitor.resolve_evidence_ref(root, output_ref)

    def test_attempt_history_is_private_append_only_and_crash_honest(self):
        script = Path(__file__).resolve().parent / "qualify-skeleton-process-monitor-native.py"
        spec = importlib.util.spec_from_file_location("bn6_history_driver", script)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        driver = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(driver)
        with tempfile.TemporaryDirectory(prefix="scourge-history-", dir=Path.cwd()) as directory:
            root = Path(directory)
            root.chmod(0o700)
            path = root / "attempt-history.jsonl"
            started = {
                "schema": "scourge.skeleton-attempt-history-row.v1",
                "attempt": "v1", "event": "attempt_started",
                "producer_revision": "a" * 40, "producer_manifest_sha256": "b" * 64,
            }
            driver.append_history(path, started)
            snapshot = driver.history_snapshot(path)
            self.assertEqual(
                (snapshot["events"], snapshot["attempts"], snapshot["incomplete_attempts"]),
                (1, 1, ["v1"]),
            )
            with self.assertRaisesRegex(RuntimeError, "invalid attempt-history transition"):
                driver.append_history(path, started)
            finished = {
                **started, "event": "attempt_finished", "disposition": "rejected",
                "reason": "test", "trace_started": False,
                "artifact_retention": {"state": "hash_only", "root": None, "files": []},
                "teardown": {"container_absent": None},
            }
            driver.append_history(path, finished)
            snapshot = driver.history_snapshot(path)
            self.assertEqual(snapshot["incomplete_attempts"], [])
            self.assertEqual(snapshot["event_log_sha256"], hashlib.sha256(path.read_bytes()).hexdigest())
            with self.assertRaisesRegex(RuntimeError, "invalid attempt-history transition"):
                driver.append_history(path, finished)
            path.chmod(0o644)
            with self.assertRaisesRegex(RuntimeError, "unsafe attempt-history file"):
                driver.history_snapshot(path)

    def test_history_seed_resumes_every_partial_migration_without_rewriting(self):
        script = Path(__file__).resolve().parent / "qualify-skeleton-process-monitor-native.py"
        spec = importlib.util.spec_from_file_location("bn6_seed_driver", script)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        driver = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(driver)
        with tempfile.TemporaryDirectory(prefix="scourge-history-seed-", dir=Path.cwd()) as directory:
            root = Path(directory)
            root.chmod(0o700)
            prior = root / "prior.json"
            prior.write_text(json.dumps({"rejected_attempts": [
                {"attempt": "v1", "reason": "one", "container_absent": True},
                {"attempt": "v2", "reason": "two", "container_absent": False},
            ]}), encoding="utf-8")
            expected = driver._seed_history_rows(prior)
            for cut in range(len(expected) + 1):
                path = root / f"history-{cut}.jsonl"
                for row in expected[:cut]:
                    driver.append_history(path, row)
                prefix = path.read_bytes() if path.exists() else b""
                driver.seed_history(path, prior)
                self.assertEqual(driver._history_rows(path), expected)
                self.assertTrue(path.read_bytes().startswith(prefix))
                complete = path.read_bytes()
                driver.seed_history(path, prior)
                self.assertEqual(path.read_bytes(), complete)

            live = root / "live.jsonl"
            driver.seed_history(live, prior)
            driver.append_history(live, {
                "schema": "scourge.skeleton-attempt-history-row.v1",
                "attempt": "v99", "event": "attempt_started",
                "producer_revision": "f" * 40,
                "producer_manifest_sha256": "e" * 64,
            })
            driver.seed_history(live, prior)
            snapshot = driver.history_snapshot(live)
            self.assertEqual(snapshot["incomplete_migration_attempts"], [])
            self.assertEqual(snapshot["incomplete_live_attempts"], ["v99"])

    def test_prepublication_history_uses_started_only_v2_after_frozen_v1(self):
        script = Path(__file__).resolve().parent / "qualify-skeleton-process-monitor-native.py"
        spec = importlib.util.spec_from_file_location("bn6_prepublication", script)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        driver = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(driver)
        legacy = {
            "incomplete_attempts": [],
            "incomplete_migration_attempts": [],
            "incomplete_live_attempts": [],
        }
        prior_start = {
            "attempt": "v38", "event": "attempt_started",
            "attempt_nonce": "8" * 64,
        }
        prior_finish = {
            "attempt": "v38", "event": "attempt_finished",
            "attempt_nonce": "8" * 64, "disposition": "rejected",
        }
        current = {
            "attempt": "v41", "event": "attempt_started",
            "attempt_nonce": "a" * 64,
            "observed_at": "2026-11-26T22:30:00+00:00",
            "producer_revision": "b" * 40,
            "producer_manifest_sha256": "c" * 64,
        }
        rows = [
            {"event": prior_start}, {"event": prior_finish}, {"event": current},
        ]
        arguments = {
            "attempt": "v41", "attempt_nonce": "a" * 64,
            "producer_revision": "b" * 40,
            "producer_manifest_sha256": "c" * 64,
        }
        self.assertTrue(driver.prepublication_history_valid(
            legacy, rows, **arguments
        ))
        old_legacy_expectation = dict(
            legacy, incomplete_live_attempts=["v41"]
        )
        self.assertFalse(driver.prepublication_history_valid(
            old_legacy_expectation, rows, **arguments
        ))
        self.assertFalse(driver.prepublication_history_valid(
            legacy, [{"event": prior_start}, {"event": current}], **arguments
        ))
        self.assertFalse(driver.prepublication_history_valid(
            legacy,
            [*rows, {"event": {
                "attempt": "v41", "event": "publication_prepared",
                "attempt_nonce": "a" * 64,
            }}],
            **arguments,
        ))
        self.assertFalse(driver.prepublication_history_valid(
            legacy, rows, **{**arguments, "attempt_nonce": "d" * 64}
        ))

    def test_v2_publication_is_crash_honest_and_externally_accepted(self):
        script = Path(__file__).resolve().parent / "qualify-skeleton-process-monitor-native.py"
        spec = importlib.util.spec_from_file_location("bn6_publication_driver", script)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        driver = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(driver)

        def receipt(identity):
            build_receipt = {"fixture": "isolated-build"}
            build_sha256 = hashlib.sha256(
                driver.BUILD_RECEIPT_DOMAIN + driver.compact(build_receipt)
            ).hexdigest()
            manifest = {"git_commit": "a" * 40,
                        "scourge_build_receipt_sha256": build_sha256}
            manifest_sha256 = hashlib.sha256(
                driver.PRODUCER_MANIFEST_DOMAIN + driver.compact(manifest)
            ).hexdigest()
            assignment = {
                "producer_manifest_sha256": manifest_sha256,
                "scourge_build_receipt_sha256": build_sha256,
            }
            return {
                "valid": True,
                "collector": {
                    "container_absent": True,
                    "container_identity": identity,
                },
                "producer": {
                    "manifest": manifest,
                    "manifest_sha256": manifest_sha256,
                    "assignment": assignment,
                    "assignment_sha256": hashlib.sha256(
                        driver.ASSIGNMENT_DOMAIN + driver.compact(assignment)
                    ).hexdigest(),
                },
                "scourge_build": {
                    "receipt": build_receipt, "receipt_sha256": build_sha256,
                },
            }

        def initial_manifest_sha256():
            value = receipt({
                "id": "0" * 64, "name": "scourge-bn6zcm-native"
            })
            manifest = dict(value["producer"]["manifest"])
            manifest["scourge_build_receipt_sha256"] = None
            return hashlib.sha256(
                driver.PRODUCER_MANIFEST_DOMAIN + driver.compact(manifest)
            ).hexdigest()

        phases = (
            "after_candidate_dir_fsync", "after_publication_prepared",
            "after_output_link_before_dir_fsync", "after_output_dir_fsync",
            "after_accepted_event",
        )
        with tempfile.TemporaryDirectory(
            prefix="scourge-publication-", dir=Path.cwd()
        ) as directory:
            parent = Path(directory)
            parent.chmod(0o700)
            for number, phase in enumerate(phases, start=1):
                case = parent / f"case-{number}"
                case.mkdir(mode=0o700)
                artifacts = case / "artifacts"
                artifacts.mkdir(mode=0o700)
                retained = artifacts / "evidence.bin"
                retained.write_bytes(b"durable evidence")
                retained.chmod(0o600)
                root = case / "history.v2"
                attempt = f"v{100 + number}"
                nonce = f"{number:064x}"
                driver.append_history_v2(root, {
                    "attempt": attempt, "event": "attempt_started",
                    "attempt_nonce": nonce,
                    "producer_revision": "a" * 40,
                    "producer_manifest_sha256": initial_manifest_sha256(),
                })
                output = case / "receipt.json"

                def crash(boundary, expected=phase):
                    if boundary == expected:
                        raise RuntimeError(f"crash:{boundary}")

                with self.assertRaisesRegex(RuntimeError, f"crash:{phase}"):
                    identity = {"id": "d" * 64,
                                "name": "scourge-bn6zcm-native"}
                    driver.publish_accepted_receipt(
                        output=output, attempt=attempt, attempt_nonce=nonce,
                        receipt=receipt(identity),
                        legacy_history={"event_log_sha256": "0" * 64},
                        history_root=root, artifact_root=artifacts,
                        container_absent=True,
                        container_identity=identity,
                        absence_check=lambda _identity: True, fault=crash,
                    )
                driver.recover_history_v2(root, absence_check=lambda _identity: True)
                rows = [row["event"] for row in driver.read_history_v2(root)]
                terminal = rows[-1]
                if phase == "after_candidate_dir_fsync":
                    self.assertEqual(terminal["disposition"], "rejected")
                    self.assertFalse(output.exists())
                else:
                    self.assertEqual(terminal["disposition"], "accepted")
                    self.assertTrue(driver.verify_published_acceptance(
                        root, output, attempt, terminal["receipt_sha256"],
                        absence_check=lambda _identity: True,
                    ))
                    before = [path.read_bytes() for path in sorted(root.glob("*.json"))]
                    driver.recover_history_v2(
                        root, absence_check=lambda _identity: True
                    )
                    self.assertEqual(
                        before,
                        [path.read_bytes() for path in sorted(root.glob("*.json"))],
                    )

            # A linked event left before temp unlink is an exact recoverable
            # transaction; a temp without a final link is an anomaly.
            linked_root = parent / "linked.v2"
            with self.assertRaisesRegex(RuntimeError, "crash-after-link"):
                driver.append_history_v2(
                    linked_root,
                    {"attempt": "v200", "event": "attempt_started",
                     "attempt_nonce": "a" * 64},
                    fault=lambda phase: (_ for _ in ()).throw(
                        RuntimeError("crash-after-link")
                    ) if phase == "after_no_replace_link" else None,
                )
            self.assertEqual(len(driver.read_history_v2(linked_root)), 1)
            orphan_root = parent / "orphan.v2"
            with self.assertRaisesRegex(RuntimeError, "crash-before-link"):
                driver.append_history_v2(
                    orphan_root,
                    {"attempt": "v201", "event": "attempt_started",
                     "attempt_nonce": "b" * 64},
                    fault=lambda phase: (_ for _ in ()).throw(
                        RuntimeError("crash-before-link")
                    ) if phase == "after_temp_fsync" else None,
                )
            with self.assertRaisesRegex(RuntimeError, "orphan or conflicting"):
                driver.read_history_v2(orphan_root)

            tamper = parent / "tamper"
            tamper.mkdir(mode=0o700)
            artifacts = tamper / "artifacts"
            artifacts.mkdir(mode=0o700)
            evidence = artifacts / "evidence.bin"
            evidence.write_bytes(b"before")
            evidence.chmod(0o600)
            root = tamper / "history.v2"
            driver.append_history_v2(root, {
                "attempt": "v300", "event": "attempt_started",
                "attempt_nonce": "c" * 64,
                "producer_revision": "a" * 40,
                "producer_manifest_sha256": initial_manifest_sha256(),
            })
            with self.assertRaisesRegex(RuntimeError, "stop-after-prepared"):
                identity = {"id": "e" * 64,
                            "name": "scourge-bn6zcm-native"}
                driver.publish_accepted_receipt(
                    output=tamper / "receipt.json", attempt="v300",
                    attempt_nonce="c" * 64, receipt=receipt(identity),
                    legacy_history={}, history_root=root, artifact_root=artifacts,
                    container_absent=True,
                    container_identity=identity,
                    absence_check=lambda _identity: True,
                    fault=lambda phase: (_ for _ in ()).throw(
                        RuntimeError("stop-after-prepared")
                    ) if phase == "after_publication_prepared" else None,
                )
            evidence.write_bytes(b"after")
            with self.assertRaises(RuntimeError):
                driver.recover_history_v2(root, absence_check=lambda _identity: True)
            self.assertEqual(
                driver.read_history_v2(root)[-1]["event"]["disposition"], "rejected"
            )

            conflict = parent / "conflict"
            conflict.mkdir(mode=0o700)
            artifacts = conflict / "artifacts"
            artifacts.mkdir(mode=0o700)
            root = conflict / "history.v2"
            driver.append_history_v2(root, {
                "attempt": "v301", "event": "attempt_started",
                "attempt_nonce": "d" * 64,
                "producer_revision": "a" * 40,
                "producer_manifest_sha256": initial_manifest_sha256(),
            })
            output = conflict / "receipt.json"
            with self.assertRaisesRegex(RuntimeError, "stop-after-prepared"):
                identity = {"id": "f" * 64,
                            "name": "scourge-bn6zcm-native"}
                driver.publish_accepted_receipt(
                    output=output, attempt="v301", attempt_nonce="d" * 64,
                    receipt=receipt(identity), legacy_history={},
                    history_root=root, artifact_root=artifacts,
                    container_absent=True,
                    container_identity=identity,
                    absence_check=lambda _identity: True,
                    fault=lambda phase: (_ for _ in ()).throw(
                        RuntimeError("stop-after-prepared")
                    ) if phase == "after_publication_prepared" else None,
                )
            candidate = driver._publication_candidate_path(output, "v301")
            output.write_bytes(candidate.read_bytes())
            output.chmod(0o600)
            with self.assertRaises(RuntimeError):
                driver.recover_history_v2(
                    root, absence_check=lambda _identity: True
                )
            self.assertEqual(
                driver.read_history_v2(root)[-1]["event"]["disposition"], "rejected"
            )

    def test_publication_manifest_holds_private_tree_and_rejects_unsafe_modes(self):
        script = Path(__file__).resolve().parent / "qualify-skeleton-process-monitor-native.py"
        spec = importlib.util.spec_from_file_location("bn6_publication_manifest", script)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        driver = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(driver)
        with tempfile.TemporaryDirectory(
            prefix="scourge-publication-manifest-", dir=Path.cwd()
        ) as directory:
            parent = Path(directory)
            parent.chmod(0o700)
            root = parent / "artifacts"
            root.mkdir(mode=0o700)
            immutable = root / "immutable"
            private = root / "private"
            executable = root / "executable"
            for path in (immutable, private, executable):
                path.mkdir(mode=0o700)
                payload = path / "payload"
                payload.write_bytes(path.name.encode("ascii"))
                payload.chmod(0o600)
            immutable.chmod(0o500)
            executable.chmod(0o755)
            try:
                rows = driver.publication_artifact_manifest(root)
                modes = {
                    row["path"]: row["fstat"]["mode"]
                    for row in rows if row["kind"] in {"root", "directory"}
                }
                self.assertEqual(modes, {
                    ".": "0700", "executable": "0755",
                    "immutable": "0500", "private": "0700",
                })
                self.assertEqual(
                    {row["path"] for row in rows if row["kind"] == "file"},
                    {"executable/payload", "immutable/payload", "private/payload"},
                )

                for unsafe_mode in (0o775, 0o730):
                    private.chmod(unsafe_mode)
                    with self.assertRaisesRegex(
                        RuntimeError, "unsafe publication artifact directory"
                    ):
                        driver.publication_artifact_manifest(root)
                private.chmod(0o700)

                private_info = private.stat()
                with mock.patch.object(
                    driver.os, "geteuid", return_value=private_info.st_uid + 1
                ), self.assertRaisesRegex(RuntimeError, "unsafe publication artifact"):
                    driver.publication_artifact_manifest(root)

                escaped = root / "escaped"
                escaped.symlink_to(Path("/tmp"), target_is_directory=True)
                with self.assertRaisesRegex(
                    RuntimeError, "unsafe publication artifact file"
                ):
                    driver.publication_artifact_manifest(root)
                escaped.unlink()

                replacement = root / "replacement"
                replacement.mkdir(mode=0o700)
                (replacement / "new").write_bytes(b"new")
                victim = root / "victim"
                victim.mkdir(mode=0o700)
                (victim / "old").write_bytes(b"old")
                real_open = driver.os.open
                replaced = False

                def replace_before_open(path, flags, mode=0o777, *, dir_fd=None):
                    nonlocal replaced
                    if path == "victim" and dir_fd is not None and not replaced:
                        replaced = True
                        os.rename("victim", "victim-old", src_dir_fd=dir_fd,
                                  dst_dir_fd=dir_fd)
                        os.rename("replacement", "victim", src_dir_fd=dir_fd,
                                  dst_dir_fd=dir_fd)
                    return real_open(path, flags, mode, dir_fd=dir_fd)

                with mock.patch.object(
                    driver.os, "open", side_effect=replace_before_open
                ), self.assertRaisesRegex(
                    RuntimeError, "publication artifact directory changed"
                ):
                    driver.publication_artifact_manifest(root)
                self.assertTrue(replaced)
            finally:
                for path in root.rglob("*"):
                    if path.is_dir() and not path.is_symlink():
                        path.chmod(0o700)

    def test_publication_recovery_requires_exact_link_topology_and_readback(self):
        script = Path(__file__).resolve().parent / "qualify-skeleton-process-monitor-native.py"
        spec = importlib.util.spec_from_file_location("bn6_publication_topology", script)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        driver = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(driver)

        def receipt(identity):
            build_receipt = {"fixture": "isolated-build"}
            build_sha = hashlib.sha256(
                driver.BUILD_RECEIPT_DOMAIN + driver.compact(build_receipt)
            ).hexdigest()
            manifest = {"git_commit": "a" * 40,
                        "scourge_build_receipt_sha256": build_sha}
            manifest_sha = hashlib.sha256(
                driver.PRODUCER_MANIFEST_DOMAIN + driver.compact(manifest)
            ).hexdigest()
            assignment = {
                "producer_manifest_sha256": manifest_sha,
                "scourge_build_receipt_sha256": build_sha,
            }
            return {
                "valid": True,
                "collector": {"container_absent": True,
                              "container_identity": identity},
                "producer": {
                    "manifest": manifest, "manifest_sha256": manifest_sha,
                    "assignment": assignment,
                    "assignment_sha256": hashlib.sha256(
                        driver.ASSIGNMENT_DOMAIN + driver.compact(assignment)
                    ).hexdigest(),
                },
                "scourge_build": {"receipt": build_receipt,
                                  "receipt_sha256": build_sha},
            }

        def initial_manifest_sha256():
            value = receipt({
                "id": "0" * 64, "name": "scourge-bn6zcm-native"
            })
            manifest = dict(value["producer"]["manifest"])
            manifest["scourge_build_receipt_sha256"] = None
            return hashlib.sha256(
                driver.PRODUCER_MANIFEST_DOMAIN + driver.compact(manifest)
            ).hexdigest()

        with tempfile.TemporaryDirectory(
            prefix="scourge-publication-topology-", dir=Path.cwd()
        ) as directory:
            parent = Path(directory)
            parent.chmod(0o700)
            serial = 0

            def prepared(name, phase):
                nonlocal serial
                serial += 1
                case = parent / name
                case.mkdir(mode=0o700)
                artifacts = case / "artifacts"
                artifacts.mkdir(mode=0o700)
                evidence = artifacts / "evidence.bin"
                evidence.write_bytes(b"bound evidence")
                evidence.chmod(0o600)
                root = case / "history.v2"
                attempt = f"v{400 + serial}"
                nonce = f"{400 + serial:064x}"
                identity = {"id": f"{serial:x}" * 64,
                            "name": "scourge-bn6zcm-native"}
                identity["id"] = identity["id"][:64]
                driver.append_history_v2(root, {
                    "attempt": attempt, "event": "attempt_started",
                    "attempt_nonce": nonce,
                    "producer_revision": "a" * 40,
                    "producer_manifest_sha256": initial_manifest_sha256(),
                })
                output = case / "receipt.json"
                with self.assertRaisesRegex(RuntimeError, f"stop:{phase}"):
                    driver.publish_accepted_receipt(
                        output=output, attempt=attempt, attempt_nonce=nonce,
                        receipt=receipt(identity), legacy_history={},
                        history_root=root, artifact_root=artifacts,
                        container_absent=True, container_identity=identity,
                        absence_check=lambda _identity: True,
                        fault=lambda boundary: (_ for _ in ()).throw(
                            RuntimeError(f"stop:{phase}")
                        ) if boundary == phase else None,
                    )
                candidate = driver._publication_candidate_path(output, attempt)
                return root, artifacts, output, candidate, attempt, identity

            # Recovery after the link but before the original directory fsync
            # must fsync that parent before it can append accepted.
            root, _artifacts, output, _candidate, attempt, _identity = prepared(
                "order", "after_output_link_before_dir_fsync"
            )
            operations = []
            real_fsync = driver._fsync_directory
            real_append = driver.append_history_v2

            def observed_fsync(path):
                if path == output.parent:
                    operations.append("output-parent-fsync")
                return real_fsync(path)

            def observed_append(path, event, **kwargs):
                if (event.get("event") == "attempt_finished"
                        and event.get("disposition") == "accepted"):
                    operations.append("accepted-event")
                return real_append(path, event, **kwargs)

            with mock.patch.object(driver, "_fsync_directory", side_effect=observed_fsync), \
                    mock.patch.object(driver, "append_history_v2", side_effect=observed_append):
                driver.recover_history_v2(root, absence_check=lambda _identity: True)
            self.assertLess(
                operations.index("output-parent-fsync"),
                operations.index("accepted-event"),
            )

            # Equal bytes in a distinct inode are a conflict, never a
            # recoverable publication.
            root, _artifacts, output, candidate, _attempt, _identity = prepared(
                "distinct", "after_publication_prepared"
            )
            output.write_bytes(candidate.read_bytes())
            output.chmod(0o600)
            with self.assertRaises(RuntimeError):
                driver.recover_history_v2(root, absence_check=lambda _identity: True)
            self.assertNotEqual(candidate.stat().st_ino, output.stat().st_ino)
            self.assertEqual(
                driver.read_history_v2(root)[-1]["event"]["disposition"], "rejected"
            )

            mutations = {}
            root, _artifacts, output, candidate, _attempt, _identity = prepared(
                "third-link", "after_output_link_before_dir_fsync"
            )
            extra = output.parent / "third-link"
            os.link(candidate, extra)
            mutations["third-link"] = (root, None)

            root, _artifacts, output, candidate, _attempt, _identity = prepared(
                "wrong-mode", "after_output_link_before_dir_fsync"
            )
            candidate.chmod(0o640)
            mutations["wrong-mode"] = (root, None)

            root, _artifacts, output, candidate, _attempt, _identity = prepared(
                "symlink", "after_publication_prepared"
            )
            output.symlink_to(candidate)
            mutations["symlink"] = (root, None)

            for name, (root, patcher) in mutations.items():
                with self.subTest(name=name):
                    context = patcher if patcher is not None else contextlib.nullcontext()
                    with context, self.assertRaises((OSError, RuntimeError)):
                        driver.recover_history_v2(
                            root, absence_check=lambda _identity: True
                        )
                    self.assertEqual(
                        driver.read_history_v2(root)[-1]["event"]["disposition"],
                        "rejected",
                    )

            root, _artifacts, output, candidate, _attempt, _identity = prepared(
                "wrong-owner", "after_output_link_before_dir_fsync"
            )
            real_read = driver._read_publication_at
            candidate_reads = 0

            class WrongOwner:
                def __init__(self, info):
                    self.info = info
                    self.st_uid = info.st_uid + 1

                def __getattr__(self, name):
                    return getattr(self.info, name)

            def wrong_owner_during_pair(parent_fd, name):
                nonlocal candidate_reads
                data, info = real_read(parent_fd, name)
                if name == candidate.name:
                    candidate_reads += 1
                    if candidate_reads == 2:
                        info = WrongOwner(info)
                return data, info

            with mock.patch.object(
                driver, "_read_publication_at", side_effect=wrong_owner_during_pair
            ), self.assertRaises(RuntimeError):
                driver.recover_history_v2(root, absence_check=lambda _identity: True)
            self.assertEqual(
                driver.read_history_v2(root)[-1]["event"]["disposition"], "rejected"
            )

            # A name replacement during the held-dirfd proof cannot pass.
            root, _artifacts, output, candidate, _attempt, _identity = prepared(
                "replacement", "after_output_link_before_dir_fsync"
            )
            real_read = driver._read_publication_at
            candidate_reads = 0

            def replace_during_pair(parent_fd, name):
                nonlocal candidate_reads
                result = real_read(parent_fd, name)
                if name == candidate.name:
                    candidate_reads += 1
                    if candidate_reads == 2:
                        output.unlink()
                        output.write_bytes(result[0])
                        output.chmod(0o600)
                return result

            with mock.patch.object(
                driver, "_read_publication_at", side_effect=replace_during_pair
            ), self.assertRaises(RuntimeError):
                driver.recover_history_v2(root, absence_check=lambda _identity: True)
            self.assertEqual(
                driver.read_history_v2(root)[-1]["event"]["disposition"], "rejected"
            )

            # A settled readback revalidates current artifacts and the current
            # container-absence predicate, rather than trusting prior booleans.
            root, artifacts, output, _candidate, attempt, _identity = prepared(
                "readback", "after_accepted_event"
            )
            terminal = driver.read_history_v2(root)[-1]["event"]
            self.assertTrue(driver.verify_published_acceptance(
                root, output, attempt, terminal["receipt_sha256"],
                absence_check=lambda _identity: True,
            ))
            self.assertFalse(driver.verify_published_acceptance(
                root, output, attempt, terminal["receipt_sha256"],
                absence_check=lambda _identity: False,
            ))
            evidence = artifacts / "evidence.bin"
            evidence.write_bytes(b"tampered evidence")
            self.assertFalse(driver.verify_published_acceptance(
                root, output, attempt, terminal["receipt_sha256"],
                absence_check=lambda _identity: True,
            ))

            root, _artifacts, output, _candidate, attempt, _identity = prepared(
                "missing-pair", "after_accepted_event"
            )
            event_path = sorted(root.glob("*.json"))[-1]
            row = json.loads(event_path.read_bytes())
            row["event"].pop("publication_pair")
            event_path.write_bytes(driver.compact(row) + b"\n")
            event_path.chmod(0o600)
            self.assertFalse(driver.verify_published_acceptance(
                root, output, attempt, row["event"]["receipt_sha256"],
                absence_check=lambda _identity: True,
            ))

    def test_history_refuses_torn_records_and_durable_write_faults(self):
        script = Path(__file__).resolve().parent / "qualify-skeleton-process-monitor-native.py"
        spec = importlib.util.spec_from_file_location("bn6_history_fault_driver", script)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        driver = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(driver)
        with tempfile.TemporaryDirectory(
            prefix="scourge-history-fault-", dir=Path.cwd()
        ) as directory:
            root = Path(directory)
            root.chmod(0o700)
            torn = root / "legacy.jsonl"
            torn.write_bytes(b'{"event":"attempt_started"')
            torn.chmod(0o600)
            with self.assertRaisesRegex(RuntimeError, "torn legacy"):
                driver._history_rows(torn)
            with mock.patch.object(
                driver.os, "write", return_value=0
            ), self.assertRaises(RuntimeError):
                driver._write_exclusive_durable(root / "short.json", b"x\n")
            with mock.patch.object(
                driver.os, "write", side_effect=OSError(28, "no space")
            ), self.assertRaises(OSError):
                driver._write_exclusive_durable(root / "enospc.json", b"x\n")
            with mock.patch.object(
                driver.os, "fsync", side_effect=OSError(5, "I/O error")
            ), self.assertRaises(OSError):
                driver._write_exclusive_durable(root / "eio.json", b"x\n")
            with mock.patch.object(
                driver, "_fsync_directory", side_effect=OSError(5, "dir I/O error")
            ), self.assertRaises(OSError):
                driver._write_exclusive_durable(root / "dir-eio.json", b"x\n")

            concurrent = root / "concurrent.v2"
            event = {"attempt": "v400", "event": "attempt_started",
                     "attempt_nonce": "f" * 64}
            failures = []
            def append_concurrently():
                try:
                    driver.append_history_v2(concurrent, event)
                except BaseException as error:
                    failures.append(repr(error))
            threads = [threading.Thread(
                target=append_concurrently,
                name=f"history-append-{index}",
            ) for index in range(2)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
                if thread.is_alive():
                    failures.append(thread.name)
            self.assertEqual(failures, [])
            self.assertEqual(len(driver.read_history_v2(concurrent)), 1)

    def test_native_bootstrap_rejects_import_shadows_and_postcheck_changes(self):
        script = Path(__file__).resolve().parent / "bootstrap-skeleton-process-monitor-native.py"
        source = script.read_text(encoding="utf-8")
        self.assertNotIn("sys.path.insert", source)
        self.assertNotIn("importlib", source)
        spec = importlib.util.spec_from_file_location("bn6_native_bootstrap", script)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        bootstrap = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(bootstrap)
        committed = b"committed bootstrap\n"
        committed_sha = hashlib.sha256(committed).hexdigest()
        identity = {"sha256": committed_sha}
        bootstrap.validate_private_bootstrap_bytes(
            requested_oid="a" * 40, requested_sha256=committed_sha,
            committed_oid="a" * 40, committed=committed,
            staged_identity=identity, staged=committed,
        )
        for changed in (
            {"requested_oid": "b" * 40},
            {"requested_sha256": "0" * 64},
            {"staged": b"changed"},
            {"staged_identity": {"sha256": "1" * 64}},
        ):
            arguments = {
                "requested_oid": "a" * 40, "requested_sha256": committed_sha,
                "committed_oid": "a" * 40, "committed": committed,
                "staged_identity": identity, "staged": committed,
            }
            arguments.update(changed)
            with self.assertRaisesRegex(RuntimeError, "exact committed blob"):
                bootstrap.validate_private_bootstrap_bytes(**arguments)
        self.assertEqual(
            bootstrap.validate_exact_argv(b"/usr/bin/python3\0-I\0", [
                "/usr/bin/python3", "-I"
            ], "test"),
            ["/usr/bin/python3", "-I"],
        )
        with self.assertRaisesRegex(RuntimeError, "argv mismatch"):
            bootstrap.validate_exact_argv(
                b"/usr/bin/python3\0-S\0", ["/usr/bin/python3", "-I"], "test"
            )
        with mock.patch.object(
            bootstrap, "run_git", return_value=b"b" * 40 + b"\n"
        ), self.assertRaisesRegex(RuntimeError, "does not resolve exactly"):
            bootstrap.validate_expected_commit(Path("/unused"), "a" * 40)
        with self.assertRaisesRegex(RuntimeError, "exact lowercase"):
            bootstrap.validate_expected_commit(Path("/unused"), "A" * 40)
        with mock.patch.object(
            bootstrap, "run_git",
            return_value=(
                b"evals/scripts/lib/shadow.py\0"
                b"evals/scripts/lib/__pycache__/responses_relay.cpython-314.pyc\0"
            ),
        ):
            self.assertEqual(
                bootstrap.ignored_import_shadows(Path("/unused")),
                [
                    "evals/scripts/lib/__pycache__/responses_relay.cpython-314.pyc",
                    "evals/scripts/lib/shadow.py",
                ],
            )
        with tempfile.TemporaryDirectory(prefix="scourge-bootstrap-race-") as directory:
            repo = Path(directory)
            relative = "evals/scripts/lib/control.py"
            path = repo / relative
            path.parent.mkdir(parents=True)
            path.write_bytes(b"committed\n")

            def git_bytes(_repo, command, argument):
                self.assertEqual(_repo, repo)
                if command == "show":
                    return b"committed\n"
                self.assertEqual(command, "rev-parse")
                return b"a" * 40 + b"\n"

            with mock.patch.object(bootstrap, "run_git", side_effect=git_bytes):
                rows = bootstrap.verified_control_blobs(
                    repo, "f" * 40, (relative,)
                )
                self.assertEqual(rows[0][1], b"committed\n")
                path.write_bytes(b"restored-after-check-but-modified-in-memory\n")
                with self.assertRaisesRegex(RuntimeError, "changed after clean check"):
                    bootstrap.verified_control_blobs(repo, "f" * 40, (relative,))

    def test_native_launcher_executes_committed_bootstrap_blob_not_checkout_bytes(self):
        script = Path(__file__).resolve().parent / "bootstrap-skeleton-process-monitor-native.py"
        spec = importlib.util.spec_from_file_location("bn6_trusted_launcher", script)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        bootstrap = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(bootstrap)
        with tempfile.TemporaryDirectory(prefix="scourge-bootstrap-blob-") as directory:
            repo = Path(directory)
            subprocess.run(["/usr/bin/git", "init", "-q", repo], check=True)
            relative = Path("evals/scripts/bootstrap-skeleton-process-monitor-native.py")
            checkout = repo / relative
            checkout.parent.mkdir(parents=True)
            marker = repo / "committed-ran"
            committed = (
                "from pathlib import Path\nimport sys\n"
                "Path(sys.argv[-1]).write_bytes(Path(__file__).read_bytes())\n"
                "raise SystemExit(23)\n"
            ).encode("ascii")
            checkout.write_bytes(committed)
            subprocess.run(["/usr/bin/git", "-C", repo, "add", os.fspath(relative)], check=True)
            subprocess.run([
                "/usr/bin/git", "-C", repo, "-c", "user.name=test",
                "-c", "user.email=test@example.invalid", "commit", "-qm", "bootstrap",
            ], check=True)
            commit = subprocess.run(
                ["/usr/bin/git", "-C", repo, "rev-parse", "HEAD"], check=True,
                capture_output=True, text=True,
            ).stdout.strip()
            checkout.write_bytes(
                b"from pathlib import Path\nPath('modified-ran').touch()\n"
            )
            output = repo / "qualification.json"
            arguments = [
                os.fspath(repo), commit, os.fspath(output), "prep", "reference",
                "investigation", "v999", "history", "prior", os.fspath(marker),
            ]
            result = subprocess.run([
                "/bin/bash", "-eu", "-o", "pipefail", "-c",
                bootstrap.TRUSTED_LAUNCHER_SCRIPT, "--", *arguments,
            ], capture_output=True)
            self.assertEqual(result.returncode, 23)
            self.assertEqual(marker.read_bytes(), committed)
            self.assertFalse((repo / "modified-ran").exists())
            staged = output.with_suffix(
                output.suffix + ".artifacts"
            ) / "control/bootstrap-stage/bootstrap-skeleton-process-monitor-native.py"
            self.assertEqual(staged.read_bytes(), committed)
            wrong = subprocess.run([
                "/bin/bash", "-eu", "-o", "pipefail", "-c",
                bootstrap.TRUSTED_LAUNCHER_SCRIPT, "--", os.fspath(repo),
                "0" * 40, os.fspath(repo / "wrong.json"), *arguments[3:],
            ], capture_output=True)
            self.assertNotEqual(wrong.returncode, 0)
            self.assertFalse((repo / "wrong.json.artifacts").exists())

    def test_producer_manifest_redacts_every_private_launcher_path(self):
        script = Path(__file__).resolve().parent / "qualify-skeleton-process-monitor-native.py"
        spec = importlib.util.spec_from_file_location("bn6_public_producer", script)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        driver = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(driver)
        root = Path("/private/evidence/attempt.json.artifacts")
        output = Path("/private/evidence/attempt.json")
        history = Path("/private/evidence/history.jsonl")
        dispatch = Path("/tmp/private-dispatch.log")
        launcher_argv = [
            "/bin/bash", "-c", "trusted literal", "--", os.fspath(output),
            os.fspath(history), os.fspath(dispatch),
        ]
        bootstrap = {
            "git_commit": "a" * 40,
            "git_tree": "b" * 40,
            "runtime_sources": [],
            "bootstrap": {
                "private_stage": {
                    "path": os.fspath(
                        root / "control/bootstrap-stage/bootstrap.py"
                    ),
                    "sha256": "c" * 64,
                },
                "argv": [
                    "/usr/bin/python3", "-I", "-S", "-B",
                    os.fspath(root / "control/bootstrap-stage/bootstrap.py"),
                    "--output", os.fspath(output),
                    "--attempt-history", os.fspath(history),
                    "--legacy-dispatch-failure-log", os.fspath(dispatch),
                ],
                "trusted_launcher": {
                    "argv": launcher_argv,
                    "argv_sha256": hashlib.sha256(
                        b"\0".join(part.encode() for part in launcher_argv) + b"\0"
                    ).hexdigest(),
                    "cmdline": {
                        "path": os.fspath(root / "control/launcher.cmdline"),
                        "sha256": "d" * 64,
                    },
                    "root_owned_tools_only_before_bootstrap": True,
                },
                "python": {"requested": "/usr/bin/python3"},
                "git": {"requested": "/usr/bin/git"},
            },
        }
        manifest, manifest_sha256 = driver.producer_manifest(
            bootstrap, "e" * 64
        )
        self.assertRegex(manifest_sha256, r"^[0-9a-f]{64}$")
        execution = manifest["bootstrap_execution"]
        self.assertNotIn("argv", execution)
        self.assertNotIn("argv", execution["trusted_launcher"])
        self.assertEqual(
            execution["private_stage"]["path"],
            "control/bootstrap-stage/bootstrap.py",
        )
        self.assertEqual(
            execution["trusted_launcher"]["cmdline"]["path"],
            "control/launcher.cmdline",
        )
        for reference in (
            execution["private_stage"]["path"],
            execution["trusted_launcher"]["cmdline"]["path"],
        ):
            self.assertFalse(Path(reference).is_absolute())
            self.assertEqual((root / reference).relative_to(root), Path(reference))
        unsafe_references = (
            (Path("relative-root"), root / "control/launcher.cmdline",
             "control/launcher.cmdline"),
            (root, root / "control/launcher.cmdline", "../launcher.cmdline"),
            (root, root / "control/launcher.cmdline", "/control/launcher.cmdline"),
            (root, Path("/other/control/launcher.cmdline"),
             "control/launcher.cmdline"),
        )
        for evidence_root, source, reference in unsafe_references:
            with self.subTest(reference=reference, source=source), self.assertRaisesRegex(
                RuntimeError, "unsafe public private-evidence reference"
            ):
                driver.private_evidence_ref(evidence_root, source, reference)
        receipt = {"producer": {"manifest": manifest}}
        forbidden = (root, output, history, dispatch)
        self.assertEqual(
            driver.public_receipt_private_path_hits(receipt, forbidden), []
        )
        receipt["leak"] = {
            "nested": [{"path": os.fspath(root / "control/private.key")}]
        }
        self.assertEqual(
            driver.public_receipt_private_path_hits(receipt, forbidden),
            [("/leak/nested/0/path", os.fspath(root / "control/private.key"))],
        )

    def test_native_just_target_is_explicitly_non_authoritative(self):
        repo = Path(__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory(prefix="scourge-native-just-") as directory:
            root = Path(directory)
            output = root / "launcher-witness.json"
            result = subprocess.run(
                [
                    "just", "--justfile", os.fspath(repo / "justfile"),
                    "qualify-skeleton-process-monitor-native",
                    os.fspath(output), os.fspath(root / "missing-preparation"),
                    os.fspath(root / "missing-request-reference"),
                    os.fspath(root / "missing-investigation"), "v999999",
                    os.fspath(root / "history.jsonl"),
                    os.fspath(root / "missing-prior.json"),
                ],
                cwd=repo,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("non-authoritative", result.stderr)
            self.assertFalse(output.with_suffix(output.suffix + ".artifacts").exists())

    def test_private_vendor_uses_lock_checked_archives_not_registry_sources(self):
        script = Path(__file__).resolve().parent / "qualify-skeleton-process-monitor-native.py"
        spec = importlib.util.spec_from_file_location("bn6_vendor_driver", script)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        driver = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(driver)
        self.assertNotIn(".cargo/registry/src", script.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory(prefix="scourge-vendor-") as directory:
            root = Path(directory)
            cache = root / "cache/index"
            cache.mkdir(parents=True)
            crate_buffer = io.BytesIO()
            with tarfile.open(fileobj=crate_buffer, mode="w:gz") as bundle:
                package = tarfile.TarInfo("itoa-1.0.19")
                package.type = tarfile.DIRTYPE
                package.mode = 0o755
                bundle.addfile(package)
                payload = b"pub fn trusted() {}\n"
                member = tarfile.TarInfo("itoa-1.0.19/src/lib.rs")
                member.size = len(payload)
                member.mode = 0o644
                bundle.addfile(member, io.BytesIO(payload))
            crate = crate_buffer.getvalue()
            archive = cache / "itoa-1.0.19.crate"
            archive.write_bytes(crate)
            checksum = hashlib.sha256(crate).hexdigest()
            lock = root / "Cargo.lock"
            lock.write_text(
                'version = 4\n\n[[package]]\nname = "itoa"\nversion = "1.0.19"\n'
                'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
                f'checksum = "{checksum}"\n', encoding="utf-8",
            )
            registry_source = root / "registry-src/itoa-1.0.19/src/lib.rs"
            registry_source.parent.mkdir(parents=True)
            registry_source.write_bytes(b"attacker controlled source\n")

            manifests = []
            roots = []
            try:
                for suffix in ("first", "after-source-mutation"):
                    vendor = root / f"vendor-{suffix}"
                    retained = root / f"archives-{suffix}"
                    vendor.mkdir(mode=0o700)
                    retained.mkdir(mode=0o700)
                    roots.extend((vendor, retained))
                    manifests.append(driver._vendor_locked_archives(
                        lock, root / "cache", vendor, retained
                    ))
                    registry_source.write_bytes(b"different attacker bytes\n")
                self.assertEqual(
                    manifests[0]["private_manifest_sha256"],
                    manifests[1]["private_manifest_sha256"],
                )
                archive.chmod(0o600)
                archive.write_bytes(crate + b"tamper")
                refused_vendor = root / "vendor-refused"
                refused_archives = root / "archives-refused"
                refused_vendor.mkdir(mode=0o700)
                refused_archives.mkdir(mode=0o700)
                roots.extend((refused_vendor, refused_archives))
                with self.assertRaisesRegex(RuntimeError, "checksum mismatch"):
                    driver._vendor_locked_archives(
                        lock, root / "cache", refused_vendor, refused_archives
                    )
                unsafe = io.BytesIO()
                with tarfile.open(fileobj=unsafe, mode="w:gz") as bundle:
                    package = tarfile.TarInfo("itoa-1.0.19")
                    package.type = tarfile.DIRTYPE
                    bundle.addfile(package)
                    link = tarfile.TarInfo("itoa-1.0.19/src/lib.rs")
                    link.type = tarfile.SYMTYPE
                    link.linkname = "/etc/passwd"
                    bundle.addfile(link)
                with self.assertRaisesRegex(RuntimeError, "unsafe crate archive member"):
                    driver._safe_crate_members(unsafe.getvalue(), "itoa-1.0.19")
            finally:
                for tree in roots:
                    for path, names, _files in os.walk(tree, topdown=False):
                        Path(path).chmod(0o700)

    def test_build_exec_trace_exhaustively_reassembles_v37_split_records(self):
        script = Path(__file__).resolve().parent / "qualify-skeleton-process-monitor-native.py"
        spec = importlib.util.spec_from_file_location("bn6_build_trace_driver", script)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        driver = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(driver)
        same_paths = [f"/private/toolchain/bin/tool-{index:02d}" for index in range(18)]
        split_paths = [
            f"/private/target/debug/build/package-{index:02d}/build-script-build"
            for index in range(7)
        ]
        rows = []
        for index in range(230):
            pid = 1000 + index
            path = same_paths[index % len(same_paths)]
            rows.append(
                f'{pid} {1 + index / 1000:.6f} '
                f'execve("{path}", ["{path}"], 0x0 /* 0 vars */) = 0'
            )
        for index in range(39):
            pid = 2000 + index
            path = split_paths[index % len(split_paths)]
            rows.extend([
                f'{pid} {2 + index / 1000:.6f} '
                f'execve("{path}", ["{path}"], 0x0 /* 0 vars */ <unfinished ...>',
                f'{pid} {3 + index / 1000:.6f} <... execve resumed>) = 0',
            ])
        payload = ("\n".join(rows) + "\n").encode("utf-8")
        old = []
        for row in payload.decode().splitlines():
            match = re.search(
                r'execve\(("(?:\\.|[^"\\])*")\s*,.*\)\s*=\s*0$', row
            )
            if match:
                old.append(match.group(1))
        self.assertEqual((len(old), len(set(old))), (230, 18))
        parsed = driver.parse_build_exec_trace(payload)
        paths = [row["path"] for row in parsed]
        self.assertEqual((len(parsed), len(set(paths))), (269, 25))
        self.assertEqual(sum(bool(row["split"]) for row in parsed), 39)
        self.assertEqual(set(split_paths), set(paths) - set(same_paths))
        production_lines = payload.decode().splitlines()
        successes = 0
        for index, line in enumerate(production_lines):
            if line.endswith(") = 0") or line.endswith("resumed>) = 0"):
                if successes:
                    production_lines[index] += " (DELAYED)"
                successes += 1
        production_payload = ("\n".join(production_lines) + "\n").encode()
        production_parsed = driver.parse_build_exec_trace(production_payload)
        self.assertEqual(sum(bool(row["delayed"]) for row in production_parsed), 268)
        with tempfile.TemporaryDirectory(
            prefix="build-trace-verifier-", dir=Path.cwd()
        ) as directory:
            artifacts = Path(directory)
            trace = artifacts / "build.strace"
            trace.write_bytes(production_payload)
            receipt = {
                "schema": driver.BUILD_EXEC_TRACE_SCHEMA,
                "files": [{"path": "build.strace", "bytes": len(production_payload),
                           "sha256": hashlib.sha256(production_payload).hexdigest()}],
                "bytes": len(production_payload),
                "lines": len(production_payload.splitlines()),
                "successful_execs": 269, "unique_execs": 25,
                "delayed_successful_execs": 268,
                "events_sha256": hashlib.sha256(
                    driver.compact(production_parsed)
                ).hexdigest(),
                "syscalls": ["execve", "execveat"],
                "signals": driver.BUILD_TRACE_SIGNALS,
                "delay_exit_milliseconds": driver.BUILD_TRACE_DELAY_EXIT_MILLISECONDS,
                "delay_exit_semantics": "timing-only-no-result-injection",
                "detached_records": "refused",
                "successful_execveat": "refused",
                "maximum_bytes": driver.MAX_BUILD_EXEC_TRACE_BYTES,
                "maximum_lines": driver.MAX_BUILD_EXEC_TRACE_LINES,
                "maximum_successful_execs": driver.MAX_BUILD_SUCCESSFUL_EXECS,
            }
            self.assertEqual(
                driver.verify_build_exec_trace(artifacts, receipt), production_parsed
            )
            receipt["delayed_successful_execs"] = 267
            self.assertIsNone(driver.verify_build_exec_trace(artifacts, receipt))
            receipt["delayed_successful_execs"] = 268
            wrong_pattern = list(production_lines)
            wrong_pattern[0] += " (DELAYED)"
            later = next(
                index for index, line in enumerate(wrong_pattern[1:], 1)
                if line.endswith(" (DELAYED)")
            )
            wrong_pattern[later] = wrong_pattern[later].removesuffix(" (DELAYED)")
            wrong_payload = ("\n".join(wrong_pattern) + "\n").encode()
            wrong_parsed = driver.parse_build_exec_trace(wrong_payload)
            trace.write_bytes(wrong_payload)
            receipt["files"] = [{"path": "build.strace", "bytes": len(wrong_payload),
                                 "sha256": hashlib.sha256(wrong_payload).hexdigest()}]
            receipt["bytes"] = len(wrong_payload)
            receipt["events_sha256"] = hashlib.sha256(
                driver.compact(wrong_parsed)
            ).hexdigest()
            self.assertIsNone(driver.verify_build_exec_trace(artifacts, receipt))
            trace.write_bytes(production_payload)
            receipt["files"] = [{"path": "build.strace",
                                 "bytes": len(production_payload),
                                 "sha256": hashlib.sha256(production_payload).hexdigest()}]
            receipt["bytes"] = len(production_payload)
            receipt["events_sha256"] = hashlib.sha256(
                driver.compact(production_parsed)
            ).hexdigest()
            receipt["successful_execs"] = 230
            receipt["unique_execs"] = 18
            self.assertIsNone(driver.verify_build_exec_trace(artifacts, receipt))

    def test_build_exec_trace_rejects_loss_ambiguity_and_execveat(self):
        script = Path(__file__).resolve().parent / "qualify-skeleton-process-monitor-native.py"
        spec = importlib.util.spec_from_file_location("bn6_build_trace_refusal", script)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        driver = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(driver)
        failures = {
            "unmatched": '10 1.000000 <... execve resumed>) = 0\n',
            "unfinished": (
                '10 1.000000 execve("/bin/a", ["/bin/a"], 0x0 '
                '/* 0 vars */ <unfinished ...>\n'
            ),
            "duplicate": (
                '10 1.000000 execve("/bin/a", ["/bin/a"], 0x0 '
                '/* 0 vars */ <unfinished ...>\n'
                '10 1.100000 execve("/bin/b", ["/bin/b"], 0x0 '
                '/* 0 vars */ <unfinished ...>\n'
            ),
            "malformed": '10 1.000000 unexpected() = 0\n',
            "execveat": (
                '10 1.000000 execveat(3, "tool", ["tool"], 0x0, '
                'AT_EMPTY_PATH) = 0\n'
            ),
            "sigchld": (
                '10 1.000000 --- SIGCHLD {si_signo=SIGCHLD, '
                'si_code=CLD_EXITED, si_pid=11, si_status=0} ---\n'
            ),
            "sigusr1": (
                '10 1.000000 --- SIGUSR1 {si_signo=SIGUSR1, '
                'si_code=SI_TKILL, si_pid=11} ---\n'
            ),
        }
        for name, payload in failures.items():
            with self.subTest(name=name), self.assertRaises(RuntimeError):
                driver.parse_build_exec_trace(payload.encode())
        failed_execveat = (
            '10 1.000000 execveat(3, "missing", ["missing"], 0x0, 0) '
            '= -1 ENOENT (No such file or directory)\n'
        )
        self.assertEqual(driver.parse_build_exec_trace(failed_execveat.encode()), [])
        delayed = (
            '10 1.000000 execve("/bin/a", ["/bin/a"], 0x0) = 0\n'
            '11 1.100000 execve("/bin/b", ["/bin/b"], 0x0) = 0 (DELAYED)\n'
            '12 1.200000 execve("/missing", ["/missing"], 0x0) '
            '= -1 ENOENT (No such file or directory) (DELAYED)\n'
        )
        delayed_rows = driver.parse_build_exec_trace(delayed.encode())
        self.assertEqual([row["delayed"] for row in delayed_rows], [False, True])
        with self.assertRaisesRegex(RuntimeError, "delay marker"):
            driver.parse_build_exec_trace(delayed.replace(
                " (DELAYED)\n", " (DELAYED) extra\n", 1
            ).encode())

    def test_build_exec_trace_command_suppresses_signal_records(self):
        script = Path(__file__).resolve().parent / "qualify-skeleton-process-monitor-native.py"
        source = script.read_text(encoding="utf-8")
        self.assertIn('"trace=execve,execveat", "-e", f"signal={BUILD_TRACE_SIGNALS}"', source)
        self.assertIn('f"--inject=execve:delay_exit={BUILD_TRACE_DELAY_EXIT_MILLISECONDS}ms"', source)
        self.assertIn('f"--inject=execveat:delay_exit={BUILD_TRACE_DELAY_EXIT_MILLISECONDS}ms"', source)
        self.assertIn('"CARGO_BUILD_JOBS": "1"', source)
        self.assertIn('"--jobs", "1"', source)
        self.assertIn('"signals": BUILD_TRACE_SIGNALS', source)
        self.assertIn('trace_receipt["signals"] != BUILD_TRACE_SIGNALS', source)

    def test_exact_v38_detached_build_trace_remains_refused(self):
        script = Path(__file__).resolve().parent / "qualify-skeleton-process-monitor-native.py"
        spec = importlib.util.spec_from_file_location("bn6_build_trace_v38", script)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        driver = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(driver)
        trace = Path(
            "/home/bob/src/scourge/.maw/evidence/"
            "bn-6zcm-native-qualification-v38.json.artifacts/control/"
            "scourge-build.execve"
        )
        data = trace.read_bytes()
        self.assertEqual(len(data), driver.V38_BUILD_TRACE_BYTES)
        self.assertEqual(hashlib.sha256(data).hexdigest(), driver.V38_BUILD_TRACE_SHA256)
        with self.assertRaisesRegex(RuntimeError, "unexpected build exec trace record"):
            driver.parse_build_exec_trace(data)

    def test_isolated_scourge_build_refuses_shared_or_nonempty_target(self):
        script = Path(__file__).resolve().parent / "qualify-skeleton-process-monitor-native.py"
        source = script.read_text(encoding="utf-8")
        self.assertNotIn('parser.add_argument("--scourge"', source)
        self.assertNotIn('parser.add_argument("--scourge-sha256"', source)
        spec = importlib.util.spec_from_file_location("bn6_build_driver", script)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        driver = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(driver)
        with tempfile.TemporaryDirectory(prefix="scourge-build-target-", dir=Path.cwd()) as directory:
            artifacts = Path(directory)
            artifacts.chmod(0o700)
            for name in ("control", "tools", "build-target"):
                driver.private_directory(artifacts / name)
            marker = artifacts / "build-target/shared-incremental-state"
            marker.write_bytes(b"refused\n")
            marker.chmod(0o600)
            with self.assertRaisesRegex(RuntimeError, "build roots were not empty"):
                driver.isolated_scourge_build(
                    type("Args", (), {"source_repo": os.fspath(Path.cwd())})(),
                    artifacts, artifacts / "tools",
                    {"git_commit": "f" * 40, "git_tree": "e" * 40},
                )

    def test_cargo_output_dealias_is_exact_and_domain_bound(self):
        script = Path(__file__).resolve().parent / "qualify-skeleton-process-monitor-native.py"
        spec = importlib.util.spec_from_file_location("bn6_build_dealias", script)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        driver = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(driver)

        def fixture(parent: Path, name: str, *, alias_path=None, mode=0o700):
            target = parent / name / "build-target"
            primary = target / driver.CARGO_OUTPUT_PATH
            alias = target / (alias_path or driver.CARGO_OUTPUT_ALIAS_PATH)
            primary.parent.mkdir(parents=True, mode=0o700)
            alias.parent.mkdir(parents=True, mode=0o700)
            primary.write_bytes(b"exact isolated Scourge output\n")
            primary.chmod(mode)
            os.link(primary, alias)
            return target, primary, alias

        def resign(row):
            value = dict(row)
            value.pop("domain_sha256", None)
            value["domain_sha256"] = hashlib.sha256(
                driver.BUILD_DEALIAS_DOMAIN + driver.compact(value)
            ).hexdigest()
            return value

        with tempfile.TemporaryDirectory(
            prefix="scourge-build-dealias-", dir=Path.cwd()
        ) as directory:
            parent = Path(directory)
            parent.chmod(0o700)
            target, primary, alias = fixture(parent, "accepted")
            receipt = driver.dealias_cargo_scourge_output(target)
            self.assertTrue(driver.verify_cargo_output_dealias(target, receipt))
            self.assertNotEqual(primary.stat().st_ino, alias.stat().st_ino)
            self.assertEqual((primary.stat().st_nlink, alias.stat().st_nlink), (1, 1))
            self.assertEqual((stat_mode(primary), stat_mode(alias)), (0o500, 0o700))

            wrong_digest = dict(receipt)
            wrong_digest["sha256"] = "0" * 64
            self.assertFalse(
                driver.verify_cargo_output_dealias(target, resign(wrong_digest))
            )
            wrong_reference = dict(receipt)
            wrong_reference["alias_path"] = "build-target/debug/other"
            self.assertFalse(
                driver.verify_cargo_output_dealias(target, resign(wrong_reference))
            )
            missing_pre = dict(receipt)
            missing_pre.pop("pre")
            self.assertFalse(
                driver.verify_cargo_output_dealias(target, resign(missing_pre))
            )

            target, primary, alias = fixture(parent, "third-link")
            third = target / "debug/third"
            os.link(primary, third)
            with self.assertRaisesRegex(
                RuntimeError, "unexpected Cargo output hard-link identity"
            ):
                driver.dealias_cargo_scourge_output(target)

            target, primary, alias = fixture(parent, "outside-link")
            outside = parent / "external-hardlink"
            os.link(primary, outside)
            with self.assertRaisesRegex(
                RuntimeError, "unexpected Cargo output hard-link identity"
            ):
                driver.dealias_cargo_scourge_output(target)

            target, primary, alias = fixture(
                parent, "wrong-path",
                alias_path="debug/build/scourge/0000000000000000/out/scourge",
            )
            with self.assertRaises(FileNotFoundError):
                driver.dealias_cargo_scourge_output(target)

            target, primary, alias = fixture(parent, "wrong-mode", mode=0o600)
            with self.assertRaisesRegex(
                RuntimeError, "unexpected Cargo output hard-link identity"
            ):
                driver.dealias_cargo_scourge_output(target)

            target, primary, alias = fixture(parent, "replacement-race")
            real_replace = driver.os.replace

            def replace_after_alias_change(src, dst, *, src_dir_fd, dst_dir_fd):
                alias.unlink()
                alias.write_bytes(b"raced alias\n")
                alias.chmod(0o700)
                return real_replace(
                    src, dst, src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd
                )

            with mock.patch.object(
                driver.os, "replace", side_effect=replace_after_alias_change
            ), self.assertRaisesRegex(
                RuntimeError, "Cargo output de-alias verification failed"
            ):
                driver.dealias_cargo_scourge_output(target)

    def test_stable_monitor_pin_excludes_per_attempt_launch_values(self):
        first = self.fixture.config
        second_argv = list(self.fixture.podman_argv)
        second_argv[second_argv.index("trial")] = "trial-two"
        second = replace(
            first,
            podman_argv_sha256=monitor.podman_argv_digest(second_argv),
            worker_environment=monitor.worker_environment_rows(
                native_boundary_environment(proxy_port=19080)
            ),
        )
        self.assertEqual(first.stable(), second.stable())
        first_launch = monitor.freeze_launch(first, "a" * 64, b"first prompt\n")
        second_launch = monitor.freeze_launch(second, "a" * 64, b"second prompt\n")
        self.assertNotEqual(first_launch["launch_sha256"], second_launch["launch_sha256"])
        self.assertNotEqual(first_launch["podman_argv_sha256"], second_launch["podman_argv_sha256"])
        self.assertNotEqual(first_launch["prompt_sha256"], second_launch["prompt_sha256"])

    def test_two_socket_supervisor_lineage_is_exact_and_separate(self):
        environment = monitor.worker_environment_rows(
            native_boundary_environment(proxy_port=19080)
        )
        supervisor = monitor.SupervisorPin(
            Fixture.HELPER,
            self.fixture.config.pins[Fixture.HELPER].sha256,
            (
                Fixture.HELPER,
                "--self-sha256", self.fixture.config.pins[Fixture.HELPER].sha256,
                "--codex-sha256", self.fixture.config.pins[Fixture.CODEX].sha256,
                "--", Fixture.CODEX,
            ),
            (Fixture.CODEX,),
            19080,
        )
        config = replace(
            self.fixture.config,
            worker_environment=environment,
            supervisor=supervisor,
        )
        trace = self.fixture.trace.decode().replace(
            clone(100, 1.1, 200) + execve(200, 1.2, Fixture.CODEX, [Fixture.CODEX]),
            clone(100, 1.05, 150)
            + execve(150, 1.1, Fixture.HELPER, list(supervisor.argv))
            + clone(150, 1.15, 200)
            + execve(200, 1.2, Fixture.CODEX, [Fixture.CODEX]),
        ).replace(
            exited(100, 2.6, 0),
            exited(150, 2.55, 0) + exited(100, 2.6, 0),
        ).encode()
        value, _outputs = monitor.project_trace(
            monitor.parse_trace(trace), self.fixture.raw, config,
            attempt_id="attempt-1", assignment_sha256="a" * 64,
            monitor_sha256="b" * 64, launch_sha256="c" * 64,
            prompt_sha256="d" * 64, prompt_size_bytes=1,
            raw_trace_sha256=hashlib.sha256(trace).hexdigest(),
        )
        self.assertEqual(value["infrastructure"]["mode"], "two-socket-supervisor")
        rows = value["infrastructure"]["executions"]
        self.assertEqual(
            [(row["infrastructure_role"], row["process_id"], row["parent_process_id"])
             for row in rows],
            [("supervisor", 150, 100), ("codex", 200, 150)],
        )
        self.assertEqual(value["infrastructure"]["forwarding"]["proxy"], {
            "port": 19080, "socket": "/gateway/proxy.sock",
        })
        extra = trace.decode().replace(
            execve(200, 1.2, Fixture.CODEX, [Fixture.CODEX]),
            clone(150, 1.16, 151) + execve(151, 1.17, Fixture.HELPER, [Fixture.HELPER, "extra"])
            + exited(151, 1.18, 0) + execve(200, 1.2, Fixture.CODEX, [Fixture.CODEX]),
        ).encode()
        with self.assertRaisesRegex(monitor.MonitorError, "supervisor-child"):
            monitor.project_trace(
                monitor.parse_trace(extra), self.fixture.raw, config,
                attempt_id="attempt-1", assignment_sha256="a" * 64,
                monitor_sha256="b" * 64, launch_sha256="c" * 64,
                prompt_sha256="d" * 64, prompt_size_bytes=1,
                raw_trace_sha256=hashlib.sha256(extra).hexdigest(),
            )

    def test_pwritev_resource_limits_and_hex_canaries_fail_closed(self):
        for syscall in ("pwritev", "pwritev2"):
            trace = self.fixture.trace.decode().replace(
                write(300, 2.2, b"direct\n"),
                line(300, 2.2, f'{syscall}(1, [{{iov_base={hx(b"direct\\n")}, iov_len=7}}], 1, 0) = 7'),
            ).encode()
            with self.subTest(syscall=syscall):
                with self.assertRaisesRegex(monitor.MonitorError, "unsupported-stdout"):
                    self.fixture.project(trace)
        canary = b"secret-canary"
        monitor.assert_canaries_absent(b"ordinary", [canary], "test")
        for exposed in (canary, b"".join(f"\\x{byte:02x}".encode() for byte in canary)):
            with self.assertRaisesRegex(monitor.MonitorError, "canary-exposure"):
                monitor.assert_canaries_absent(b"prefix" + exposed + b"suffix", [canary], "test")
        with tempfile.TemporaryFile() as output:
            errors = []
            with mock.patch.object(monitor.os, "killpg") as kill:
                monitor._capture_stream(io.BytesIO(b"abcdefgh"), output.fileno(), 4, 123, "raw", errors)
            self.assertEqual(errors, ["raw-size-limit"])
            output.seek(0)
            self.assertEqual(output.read(), b"abcd")
            kill.assert_called_once_with(123, monitor.signal.SIGKILL)
        stop = threading.Event()
        oversized = mock.Mock()
        oversized.stat.return_value.st_size = monitor.MAX_TRACE_OVERSHOOT + 100
        errors = []
        with mock.patch.object(monitor.os, "killpg") as kill:
            monitor._watch_exec_snapshots(321, stop, [], errors, oversized, 1)
        self.assertEqual(errors, ["trace-size-limit"])
        kill.assert_called_once_with(321, monitor.signal.SIGKILL)

    def test_cleanup_never_removes_unowned_or_mismatched_container(self):
        launch = monitor.PodmanLaunch(
            "trial", Path("/tmp/control/trial.cid"), "a" * 64,
            Fixture.CODEX, (), ("-",),
        )
        environment = monitor.monitor_environment({})
        with mock.patch.object(monitor, "_container_absent", return_value=False), \
                mock.patch.object(monitor, "_podman_control") as control:
            self.assertFalse(monitor._remove_owned_container(
                self.fixture.config, launch, None, environment
            ))
            control.assert_not_called()
        cid = "b" * 64
        with mock.patch.object(monitor, "_container_absent", return_value=False), \
                mock.patch.object(monitor, "_podman_query", return_value=(0, f"{cid}\nother\n".encode())), \
                mock.patch.object(monitor, "_podman_control") as control:
            with self.assertRaisesRegex(monitor.MonitorError, "container-identity"):
                monitor._remove_owned_container(self.fixture.config, launch, cid, environment)
            control.assert_not_called()
        with mock.patch.object(monitor, "_container_absent", side_effect=[False, True, True]), \
                mock.patch.object(monitor, "_podman_query", return_value=(0, f"{cid}\ntrial\n".encode())), \
                mock.patch.object(monitor, "_podman_control", return_value=0) as control:
            self.assertTrue(monitor._remove_owned_container(
                self.fixture.config, launch, cid, environment
            ))
            control.assert_called_once_with(
                self.fixture.config, ["rm", "--force", cid], environment
            )


def stat_mode(path: Path) -> int:
    return path.stat().st_mode & 0o777


if __name__ == "__main__":
    unittest.main()
