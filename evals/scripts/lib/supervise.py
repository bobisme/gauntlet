"""Keep an owned session leader alive until trial teardown on Linux."""

import ctypes
import os
from pathlib import Path
import signal
import subprocess
import sys
import time


def publish(prefix, name, value):
    destination = prefix.with_suffix(f".{name}")
    temporary = prefix.with_suffix(f".{name}.tmp")
    temporary.write_text(f"{value}\n", encoding="ascii")
    temporary.replace(destination)


def adopt_orphans():
    # Reap descendants whose original parent exited before trial teardown.
    pr_set_child_subreaper = 36  # linux/prctl.h
    if ctypes.CDLL(None, use_errno=True).prctl(pr_set_child_subreaper, 1, 0, 0, 0):
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def reap_exited(child):
    if child.poll() is not None:
        try:
            while os.waitpid(-1, os.WNOHANG)[0] != 0:
                pass
        except ChildProcessError:
            pass


def group_has_children(group):
    for process in Path("/proc").iterdir():
        if not process.name.isdecimal() or int(process.name) == group:
            continue
        try:
            stat = (process / "stat").read_bytes()
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            continue
        state, _, process_group, *_ = stat.rsplit(b") ", 1)[1].split()
        if int(process_group) == group and state not in (b"Z", b"X"):
            return True
    return False


def stop_children(prefix, child):
    # This process is still the leader of this private session. These signals
    # can reach only its own group, even if the main command has already exited.
    group = os.getpgrp()
    os.killpg(group, signal.SIGTERM)
    grace_deadline = time.monotonic() + 3
    while True:
        reap_exited(child)
        if not group_has_children(group):
            reap_exited(child)
            publish(prefix, "stopped", "clean")
            return
        if time.monotonic() >= grace_deadline:
            publish(prefix, "stopped", "forced")
            os.killpg(group, signal.SIGKILL)
        time.sleep(0.05)


def supervise(owner, limit, prefix, key_fd, command):
    os.setsid()
    adopt_orphans()
    interrupted = False

    def request_stop(_signal, _frame):
        nonlocal interrupted
        interrupted = True

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    if os.getppid() != owner:
        return

    try:
        child = subprocess.Popen(command, pass_fds=(key_fd,) if key_fd else ())
    finally:
        if key_fd:
            os.close(key_fd)

    deadline = time.monotonic() + limit
    exit_file_written = False
    while not interrupted and os.getppid() == owner and not prefix.with_suffix(".stop").exists():
        if not exit_file_written:
            code = child.poll()
            if code is not None:
                publish(prefix, "exit", code if code >= 0 else 128 - code)
                exit_file_written = True
        if time.monotonic() >= deadline:
            if not exit_file_written:
                publish(prefix, "exit", 124)
            break
        time.sleep(0.05)
    stop_children(prefix, child)


if __name__ == "__main__":
    owner, limit, prefix, key_fd, *command = sys.argv[1:]
    supervise(int(owner), int(limit), Path(prefix), int(key_fd), command)
