"""Observe shared Rite files and visible Linux processes without a live client."""

import hashlib
import json
import os
from pathlib import Path
import re
import sys


def rite_fingerprints(store):
    fingerprints = {}
    for directory, log in ((store, "hooks"), (store / "channels", "projects")):
        try:
            names = os.listdir(directory)
        except FileNotFoundError:
            continue
        for name in names:
            if not re.fullmatch(rf"{log}(\.[0-9]+)?\.jsonl", name):
                continue
            path = directory / name
            with path.open("rb") as stream:
                fingerprints[str(path.relative_to(store))] = hashlib.file_digest(stream, "sha256").hexdigest()
    return fingerprints


def trial_processes(run):
    count = 0
    root_arg = os.fsencode(run)
    for process in Path("/proc").iterdir():
        if not process.name.isdecimal() or process.name == str(os.getpid()):
            continue
        try:
            cwd = Path(os.readlink(process / "cwd"))
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            cwd = None
        try:
            args = (process / "cmdline").read_bytes().split(b"\0")
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            args = []
        has_run_argument = any(
            part == root_arg or part.startswith(root_arg + b"/")
            for arg in args for part in (arg, arg.partition(b"=")[2])
        )
        if (cwd is not None and cwd.is_relative_to(run)) or has_run_argument:
            count += 1
    return count


if __name__ == "__main__":
    run = Path(sys.argv[1])
    stores = [rite_fingerprints(path) for path in dict.fromkeys(map(Path, sys.argv[2:]))]
    print(json.dumps({"rite": stores, "trial_processes": trial_processes(run)}, sort_keys=True))
