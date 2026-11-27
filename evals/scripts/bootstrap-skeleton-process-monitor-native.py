#!/usr/bin/python3
"""Trusted-stdlib bootstrap for the native skeleton collector qualification.

The trusted host launcher first materializes this exact committed Git blob in a
fresh private directory, then invokes that copy with ``/usr/bin/python3 -I -S
-B``.  Thus no checkout Python is imported or executed before committed
identity, a completely clean worktree, and import-shadow absence are proved.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess
import sys


GIT = "/usr/bin/git"
PYTHON = "/usr/bin/python3"
BOOTSTRAP_SCHEMA = "scourge.skeleton-native-bootstrap.v2"
CONTROL_SOURCES = (
    "evals/scripts/bootstrap-skeleton-process-monitor-native.py",
    "evals/scripts/qualify-skeleton-process-monitor-native.py",
    "evals/scripts/lib/skeleton_process_monitor.py",
    "evals/scripts/lib/native_codex_boundary.py",
    "evals/scripts/lib/responses_relay.py",
    "evals/scripts/qualify-installed-codex-compatibility.py",
    "evals/scripts/fixtures/native-codex-supervisor.rs",
)
IMPORTABLE_SUFFIXES = (".py", ".pyc", ".so", ".pyd")
TRUSTED_LAUNCHER_SCRIPT = (
    'repo=$1; expected=$2; output=$3; preparation=$4; reference=$5; '
    'investigation=$6; attempt=$7; history=$8; prior=$9; dispatch=${10}; '
    'umask 077; test ${#expected} -eq 40; case "$expected" in '
    '*[!0-9a-f]*) exit 64;; esac; resolved=$(/usr/bin/git -C "$repo" '
    'rev-parse "$expected^{commit}"); test "$resolved" = "$expected"; '
    'artifacts="${output}.artifacts"; control="$artifacts/control"; '
    'stage_root="$control/bootstrap-stage"; '
    'stage="$stage_root/bootstrap-skeleton-process-monitor-native.py"; '
    'launcher="$control/launcher.cmdline"; test ! -e "$output"; '
    'test ! -e "$artifacts"; /usr/bin/mkdir -m 0700 -- "$artifacts"; '
    '/usr/bin/mkdir -m 0700 -- "$control"; /usr/bin/mkdir -m 0700 -- '
    '"$stage_root"; /usr/bin/dd if="/proc/$$/cmdline" of="$launcher" '
    'status=none; /usr/bin/chmod 0400 -- "$launcher"; '
    'blob=$(/usr/bin/git -C "$repo" rev-parse '
    '"$expected:evals/scripts/bootstrap-skeleton-process-monitor-native.py"); '
    'set -C; /usr/bin/git -C "$repo" cat-file blob "$blob" > "$stage"; '
    'set +C; /usr/bin/chmod 0500 -- "$stage"; '
    'sha=$(/usr/bin/sha256sum -- "$stage"); sha=${sha%% *}; '
    'exec /usr/bin/python3 -I -S -B "$stage" --source-repo "$repo" '
    '--expected-commit "$expected" --launcher-cmdline "$launcher" '
    '--bootstrap-blob-oid "$blob" --bootstrap-sha256 "$sha" '
    '--output "$output" --preparation-teapot "$preparation" '
    '--request-reference-teapot "$reference" --investigation "$investigation" '
    '--attempt "$attempt" --attempt-history "$history" '
    '--prior-receipt "$prior" --legacy-dispatch-failure-log "$dispatch"'
)


def compact(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, allow_nan=False,
    ).encode("ascii")


def run_git(repo: Path, *arguments: str) -> bytes:
    return subprocess.run(
        [GIT, "-C", os.fspath(repo), *arguments], check=True,
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"},
    ).stdout


def ignored_import_shadows(repo: Path) -> list[str]:
    ignored = run_git(
        repo, "ls-files", "--others", "--ignored", "--exclude-standard", "-z", "--",
        "evals/scripts",
    ).split(b"\0")
    return sorted(
        raw.decode("utf-8") for raw in ignored if raw and (
            raw.decode("utf-8").endswith(IMPORTABLE_SUFFIXES)
            or "__pycache__" in PurePosixPath(raw.decode("utf-8")).parts
        )
    )


def verified_control_blobs(
    repo: Path, commit: str, sources: tuple[str, ...] = CONTROL_SOURCES
) -> list[tuple[str, bytes, str]]:
    """Read committed blobs and prove the mutable spellings still match."""

    rows = []
    for relative in sources:
        blob = run_git(repo, "show", f"{commit}:{relative}")
        if (repo / relative).read_bytes() != blob:
            raise RuntimeError(f"control source changed after clean check: {relative}")
        oid = run_git(repo, "rev-parse", f"{commit}:{relative}").decode("ascii").strip()
        rows.append((relative, blob, oid))
    return rows


def executable_identity(path: str) -> dict[str, object]:
    requested = Path(path)
    resolved = requested.resolve(strict=True)
    info = resolved.stat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
            or stat.S_IMODE(info.st_mode) & 0o022):
        raise RuntimeError(f"unsafe bootstrap executable: {path}")
    data = resolved.read_bytes()
    return {
        "requested": path,
        "resolved": os.fspath(resolved),
        "device": info.st_dev,
        "inode": info.st_ino,
        "mode": f"{stat.S_IMODE(info.st_mode):04o}",
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def held_file_identity(path: Path, *, expected_mode: int) -> tuple[dict[str, object], bytes]:
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
                or stat.S_IMODE(before.st_mode) != expected_mode or before.st_nlink != 1):
            raise RuntimeError(f"unsafe private bootstrap file: {path}")
        blocks = []
        while True:
            block = os.read(fd, 1 << 20)
            if not block:
                break
            blocks.append(block)
        after = os.fstat(fd)
    finally:
        os.close(fd)
    fields = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_uid", "st_gid",
              "st_size", "st_mtime_ns", "st_ctime_ns")
    if any(getattr(before, field) != getattr(after, field) for field in fields):
        raise RuntimeError("private bootstrap changed while hashing")
    data = b"".join(blocks)
    return ({
        "path": os.fspath(path), "device": before.st_dev, "inode": before.st_ino,
        "mode": f"{stat.S_IMODE(before.st_mode):04o}", "link_count": before.st_nlink,
        "owner_uid": before.st_uid, "owner_gid": before.st_gid,
        "bytes": before.st_size, "mtime_ns": before.st_mtime_ns,
        "ctime_ns": before.st_ctime_ns, "sha256": hashlib.sha256(data).hexdigest(),
    }, data)


def require_private_directory(path: Path) -> None:
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700):
        raise RuntimeError(f"unsafe bootstrap directory: {path}")


def mkdir_private(parent: Path, name: str) -> Path:
    parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        os.mkdir(name, 0o700, dir_fd=parent_fd)
        fd = os.open(
            name, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=parent_fd,
        )
        try:
            info = os.fstat(fd)
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) != 0o700):
                raise RuntimeError(f"unsafe bootstrap directory: {parent / name}")
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)
    return parent / name


def ensure_private_tree(root: Path, relative_parent: PurePosixPath) -> Path:
    current = root
    for part in relative_parent.parts:
        candidate = current / part
        try:
            info = candidate.lstat()
        except FileNotFoundError:
            candidate = mkdir_private(current, part)
        else:
            if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
                    or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) != 0o700):
                raise RuntimeError(f"unsafe runtime source directory: {candidate}")
        current = candidate
    return current


def write_private(path: Path, data: bytes, mode: int = 0o600) -> None:
    parent_fd = os.open(
        path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    )
    try:
        fd = os.open(
            path.name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            mode,
            dir_fd=parent_fd,
        )
        try:
            offset = 0
            while offset < len(data):
                written = os.write(fd, data[offset:])
                if written <= 0:
                    raise RuntimeError("short bootstrap write")
                offset += written
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)


def validate_expected_commit(repo: Path, expected: str) -> str:
    if (len(expected) != 40
            or any(character not in "0123456789abcdef" for character in expected)):
        raise RuntimeError("operator expected commit must be an exact lowercase object id")
    resolved = run_git(repo, "rev-parse", f"{expected}^{{commit}}").decode(
        "ascii"
    ).strip()
    if resolved != expected:
        raise RuntimeError("operator expected commit does not resolve exactly")
    return resolved


def validate_exact_argv(raw: bytes, expected: list[str], label: str) -> list[str]:
    parts = raw.split(b"\0")
    if parts and parts[-1] == b"":
        parts.pop()
    try:
        actual = [part.decode("utf-8") for part in parts]
    except UnicodeDecodeError as error:
        raise RuntimeError(f"{label} argv is not UTF-8") from error
    if actual != expected:
        raise RuntimeError(f"{label} argv mismatch")
    return actual


def validate_private_bootstrap_bytes(
    *, requested_oid: str, requested_sha256: str,
    committed_oid: str, committed: bytes,
    staged_identity: dict[str, object], staged: bytes,
) -> None:
    committed_sha256 = hashlib.sha256(committed).hexdigest()
    if (requested_oid != committed_oid or requested_sha256 != committed_sha256
            or staged != committed or staged_identity.get("sha256") != requested_sha256):
        raise RuntimeError("private bootstrap is not the exact committed blob")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-repo", required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--launcher-cmdline", required=True)
    parser.add_argument("--bootstrap-blob-oid", required=True)
    parser.add_argument("--bootstrap-sha256", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--preparation-teapot", required=True)
    parser.add_argument("--request-reference-teapot", required=True)
    parser.add_argument("--investigation", required=True)
    parser.add_argument("--attempt", required=True)
    parser.add_argument("--attempt-history", required=True)
    parser.add_argument("--prior-receipt", required=True)
    parser.add_argument("--legacy-dispatch-failure-log", required=True)
    args = parser.parse_args(argv)

    script = Path(__file__).absolute()
    if script.resolve(strict=True) != script:
        raise RuntimeError("bootstrap requires one canonical absolute spelling")
    repo = Path(args.source_repo).absolute()
    if repo.resolve(strict=True) != repo:
        raise RuntimeError("source repository requires one canonical absolute spelling")
    if Path(run_git(repo, "rev-parse", "--show-toplevel").decode().strip()) != repo:
        raise RuntimeError("bootstrap repository root mismatch")
    status = run_git(repo, "status", "--porcelain=v1", "--untracked-files=all")
    if status:
        raise RuntimeError("producer tree must be fully committed and clean")
    shadows = ignored_import_shadows(repo)
    if shadows:
        raise RuntimeError(f"ignored import shadow refused: {shadows!r}")
    expected_commit = validate_expected_commit(repo, args.expected_commit)
    commit = run_git(repo, "rev-parse", "HEAD").decode("ascii").strip()
    tree = run_git(repo, "rev-parse", "HEAD^{tree}").decode("ascii").strip()
    if commit != expected_commit or len(commit) != 40 or len(tree) != 40:
        raise RuntimeError("unexpected producer object identity")

    committed_bootstrap = run_git(repo, "show", f"{commit}:{CONTROL_SOURCES[0]}")
    committed_oid = run_git(
        repo, "rev-parse", f"{commit}:{CONTROL_SOURCES[0]}"
    ).decode("ascii").strip()
    stage_identity, staged_bootstrap = held_file_identity(script, expected_mode=0o500)
    validate_private_bootstrap_bytes(
        requested_oid=args.bootstrap_blob_oid,
        requested_sha256=args.bootstrap_sha256,
        committed_oid=committed_oid, committed=committed_bootstrap,
        staged_identity=stage_identity, staged=staged_bootstrap,
    )

    output = Path(args.output).absolute()
    if not output.is_absolute() or output.parent.resolve(strict=True) != output.parent:
        raise RuntimeError("output parent must be canonical")
    if output.exists():
        raise RuntimeError("qualification output already exists")
    artifacts = output.with_suffix(output.suffix + ".artifacts")
    control = artifacts / "control"
    stage_root = control / "bootstrap-stage"
    for directory in (artifacts, control, stage_root):
        require_private_directory(directory)
    expected_script = stage_root / CONTROL_SOURCES[0].rsplit("/", 1)[-1]
    if script != expected_script:
        raise RuntimeError("private bootstrap staging path mismatch")
    launcher_path = Path(args.launcher_cmdline).absolute()
    if launcher_path != control / "launcher.cmdline":
        raise RuntimeError("trusted launcher cmdline path mismatch")
    launcher_identity, launcher_cmdline = held_file_identity(
        launcher_path, expected_mode=0o400
    )
    expected_launcher_argv = [
        "/bin/bash", "-eu", "-o", "pipefail", "-c", TRUSTED_LAUNCHER_SCRIPT,
        "--", os.fspath(repo), args.expected_commit, args.output,
        args.preparation_teapot, args.request_reference_teapot,
        args.investigation, args.attempt, args.attempt_history,
        args.prior_receipt, args.legacy_dispatch_failure_log,
    ]
    validate_exact_argv(launcher_cmdline, expected_launcher_argv, "trusted launcher")
    if (list(artifacts.iterdir()) != [control]
            or set(control.iterdir()) != {stage_root, launcher_path}
            or list(stage_root.iterdir()) != [script]):
        raise RuntimeError("private bootstrap staging inventory mismatch")
    runtime_source = mkdir_private(control, "runtime-source")

    expected_argv = [
        PYTHON, "-I", "-S", "-B", os.fspath(script),
        "--source-repo", os.fspath(repo),
        "--expected-commit", args.expected_commit,
        "--launcher-cmdline", os.fspath(launcher_path),
        "--bootstrap-blob-oid", args.bootstrap_blob_oid,
        "--bootstrap-sha256", args.bootstrap_sha256,
        "--output", args.output,
        "--preparation-teapot", args.preparation_teapot,
        "--request-reference-teapot", args.request_reference_teapot,
        "--investigation", args.investigation,
        "--attempt", args.attempt,
        "--attempt-history", args.attempt_history,
        "--prior-receipt", args.prior_receipt,
        "--legacy-dispatch-failure-log", args.legacy_dispatch_failure_log,
    ]
    actual_argv = validate_exact_argv(
        Path("/proc/self/cmdline").read_bytes(), expected_argv, "private bootstrap"
    )

    sources: list[dict[str, object]] = []
    for relative, blob, blob_oid in verified_control_blobs(repo, commit):
        destination = runtime_source / relative
        ensure_private_tree(runtime_source, PurePosixPath(relative).parent)
        write_private(destination, blob, 0o500 if relative.endswith(".py") else 0o400)
        sources.append({
            "path": relative,
            "blob_oid": blob_oid,
            "bytes": len(blob),
            "sha256": hashlib.sha256(blob).hexdigest(),
            "executed_private_copy": (
                relative.endswith(".py") and relative != CONTROL_SOURCES[0]
            ),
        })

    if run_git(repo, "status", "--porcelain=v1", "--untracked-files=all"):
        raise RuntimeError("producer tree changed while private sources were staged")
    if ignored_import_shadows(repo):
        raise RuntimeError("import shadow appeared while private sources were staged")
    if (run_git(repo, "rev-parse", "HEAD").decode("ascii").strip() != commit
            or run_git(repo, "rev-parse", "HEAD^{tree}").decode("ascii").strip() != tree):
        raise RuntimeError("producer object identity changed while staging")

    receipt = {
        "schema": BOOTSTRAP_SCHEMA,
        "git_commit": commit,
        "git_tree": tree,
        "operator_expected_commit": args.expected_commit,
        "source_repo": os.fspath(repo),
        "full_status_clean": True,
        "ignored_import_shadows": [],
        "bootstrap": {
            "source": CONTROL_SOURCES[0],
            "blob_oid": committed_oid,
            "committed_sha256": args.bootstrap_sha256,
            "private_stage": stage_identity,
            "argv": actual_argv,
            "python": executable_identity(PYTHON),
            "git": executable_identity(GIT),
            "trusted_launcher": {
                "argv": expected_launcher_argv,
                "argv_sha256": hashlib.sha256(launcher_cmdline).hexdigest(),
                "cmdline": launcher_identity,
                "root_owned_tools_only_before_bootstrap": True,
            },
            "isolated": True,
            "no_site": True,
        },
        "runtime_sources": sources,
    }
    receipt_path = control / "bootstrap.json"
    write_private(receipt_path, compact(receipt) + b"\n")

    qualifier = runtime_source / "evals/scripts/qualify-skeleton-process-monitor-native.py"
    command = [
        PYTHON, "-I", "-S", "-B", os.fspath(qualifier),
        "--source-repo", os.fspath(repo),
        "--runtime-source-root", os.fspath(runtime_source),
        "--bootstrap-receipt", os.fspath(receipt_path),
        "--output", os.fspath(output),
        "--preparation-teapot", args.preparation_teapot,
        "--request-reference-teapot", args.request_reference_teapot,
        "--investigation", args.investigation,
        "--attempt", args.attempt,
        "--attempt-history", args.attempt_history,
        "--prior-receipt", args.prior_receipt,
        "--legacy-dispatch-failure-log", args.legacy_dispatch_failure_log,
    ]
    environment = {
        "HOME": "/home/bob",
        "PATH": "/usr/bin:/bin",
        "XDG_RUNTIME_DIR": "/run/user/1000",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PYTHONHASHSEED": "0",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    os.execve(PYTHON, command, environment)
    return 127


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
