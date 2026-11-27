#!/usr/bin/env python3
"""Run the collector over the exact offline Codex protected-prep workflow.

The real Scourge demo uses the historical preparation engine (6d15). The c03
request-reference binary is authenticated and directly qualified in the same
immutable fixture, but is not misrepresented as a public Scourge binding.
"""

from __future__ import annotations

import argparse
import ast
from datetime import datetime, timezone
import fcntl
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
import tomllib
from typing import Mapping


SCRIPT_DIR = Path(__file__).resolve().parent
RUNTIME_SOURCE_ROOT = SCRIPT_DIR.parent.parent
LIB = SCRIPT_DIR / "lib"
sys.path.insert(0, os.fspath(LIB))
import native_codex_boundary as boundary  # noqa: E402
import responses_relay as relay  # noqa: E402
import skeleton_process_monitor as monitor  # noqa: E402


_SPEC = importlib.util.spec_from_file_location(
    "scourge_installed_codex_compatibility",
    SCRIPT_DIR / "qualify-installed-codex-compatibility.py",
)
assert _SPEC is not None and _SPEC.loader is not None
compat = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(compat)


PODMAN = "/usr/bin/podman"
CRUN = "/usr/bin/crun"
STRACE = "/usr/bin/strace"
CODEX = compat.CODEX
CODEX_SHA256 = compat.CODEX_SHA256
SUPERVISOR_SHA256 = "454370dfa1a99c6db817e54f81be3d5f2af6b570cab0148e1a58c288d7894fbc"
SUPERVISOR_SOURCE_SHA256 = "23fde581710731dcffd4146cee61623aaea3ee9c7180639e0a8aa6827b244062"
PREMERGE_SUPERVISOR_SHA256 = "9dfa1e6b263754a379f98dcba970f72a77cd0ca2d34c3ee05dca4d07cb3868e4"
MODEL = "gpt-5.5"
PROXY_PORT = 19080
BASE_DIGEST = "sha256:bec21ac47b497b76f343c1ccd4e5c70756bb6c8ae99dd1b60a836e5d51f264ec"
BASE_IMAGE_ID = "700999f0a45a7e0913104cb38f5cedb6ebdd27f5af31b0e261a1888e182116f0"
BOOKWORM_IMAGE_ID = boundary.PRODUCTION_IMAGE_ID
DERIVED_IMAGE_ID = "a2553148a410b908069a86c6455b9ea0e969221d140ac5c191f6a31a724fa510"
DERIVED_IMAGE_DIGEST = "sha256:a59663bd27256a7067ee79572a9e436b20c190e15ca518c8d0be0fad2a69c18c"
PREPARATION_SHA256 = monitor.PREPARATION_TEAPOT_SHA256
REQUEST_REFERENCE_SHA256 = monitor.REQUEST_REFERENCE_TEAPOT_SHA256
INVESTIGATION_SHA256 = monitor.INVESTIGATION_SHA256
PROVIDER_CANARY = b"bn-6zcm-offline-provider-auth-canary"
PROXY_PAYLOAD = compat.PROXY_PAYLOAD
PROMPT = (
    b"Run the prepared protected Scourge demo command exactly once with exec_command. "
    b"Do not run any other command. Then report completion.\n"
)
COMMAND = (
    f"/bin/bash -c \"printf '%s\\n' 'offline supervisor proxy probe' "
    f"> /dev/tcp/127.0.0.1/{PROXY_PORT}\"; "
    "/opt/scourge-bin/scourge --format json demo /workspace/demo "
    "--teapot /opt/scourge-bin/teapot-preparation "
    "--investigation /opt/scourge-bin/investigation "
    "--managed-guide false --referee-root /runtime/referee; "
    "/opt/scourge-bin/scourge --format json demo --stop /workspace/demo"
)
RUNTIME_FILES = (
    (Path("/usr/lib64/ld-linux-x86-64.so.2"), Path("/usr/lib/ld-linux-x86-64.so.2"),
     "ld-linux-x86-64.so.2", 0o755, 263152,
     "f5e11cc62f8f2c24dff532982559f4303dba3b17e7450551372a88c8e7ea8757"),
    (Path("/usr/lib/libc.so.6"), Path("/usr/lib/libc.so.6"), "libc.so.6", 0o755, 2215072,
     "02c8c3d06180beee9c7d0392aa85736c7d19f274a81e7f8f0b3d9e28e0641524"),
    (Path("/usr/lib/libm.so.6"), Path("/usr/lib/libm.so.6"), "libm.so.6", 0o755, 1268336,
     "965106704753eefe8c31ae7da6daba3ead3d18c52b19b5fcc41178bcc4aa999d"),
    (Path("/usr/lib/libgcc_s.so.1"), Path("/usr/lib/libgcc_s.so.1"),
     "libgcc_s.so.1", 0o644, 182512,
     "e618cb9c90c2eb3a1dad1cfea5b6c1eebcf2e799ad805976f4ae47bdd61c716a"),
)
CONTAINERFILE = f'''FROM docker.io/library/debian@{BASE_DIGEST}
LABEL org.scourge.qualification-only="true"
LABEL org.scourge.base-digest="{BASE_DIGEST}"
LABEL org.scourge.glibc-version="2.44"
COPY --chmod=0755 ld-linux-x86-64.so.2 /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
COPY --chmod=0755 libc.so.6 /usr/lib/x86_64-linux-gnu/libc.so.6
COPY --chmod=0755 libm.so.6 /usr/lib/x86_64-linux-gnu/libm.so.6
COPY --chmod=0644 libgcc_s.so.1 /usr/lib/x86_64-linux-gnu/libgcc_s.so.1
'''.encode("ascii")
PRODUCER_MANIFEST_DOMAIN = b"scourge.skeleton-producer-manifest.v3\0"
ASSIGNMENT_DOMAIN = b"scourge.skeleton-assignment.v4\0"
KEY_COMMITMENT_DOMAIN = b"scourge.skeleton-monitor-key-commitment.v1\0"
BUILD_RECEIPT_DOMAIN = b"scourge.skeleton-scourge-build.v3\0"
BUILD_DEALIAS_DOMAIN = b"scourge.skeleton-cargo-output-dealias.v1\0"
V43_LEGACY_ACCEPTED_EVENT_SHA256 = (
    "bb0332149c7677873283672c9d4029b5aacb6d6a9e83e03f2bc10774a4234810"
)
CARGO_REGISTRY_CACHE = Path("/home/bob/.cargo/registry/cache")
RUST_TOOLCHAIN = Path("/home/bob/.rustup/toolchains/1.100.0-x86_64-unknown-linux-gnu")
MAX_BUILD_EXEC_TRACE_BYTES = 8 << 20
MAX_BUILD_EXEC_TRACE_LINES = 10_000
MAX_BUILD_SUCCESSFUL_EXECS = 5_000
BUILD_EXEC_TRACE_SCHEMA = "scourge.skeleton-build-exec-trace.v3"
BUILD_TRACE_SIGNALS = "none"
BUILD_TRACE_DELAY_EXIT_MILLISECONDS = 250
CARGO_OUTPUT_PATH = "debug/scourge"
CARGO_OUTPUT_ALIAS_PATH = (
    "debug/build/scourge/d2b4a4cdecdcb55f/out/scourge"
)
HISTORY_V2_SCHEMA = "scourge.skeleton-attempt-history-event.v2"
HISTORY_V2_SNAPSHOT_SCHEMA = "scourge.skeleton-attempt-history.v2"
RECEIPT_CORE_DOMAIN = b"scourge.skeleton-native-receipt-core.v1\0"
V36_DISPATCH_FAILURE_SHA256 = "323633e76665d84e4f3ab5847c21650a24ac091cb87d99e053e2a7226a8e8f30"
V37_RECEIPT_SHA256 = "4b0faaf489abb5e95af9244f14484df32a566022ef615b43852f28dba0bbba37"
V37_BUILD_TRACE_SHA256 = "2852c4b03136c7a2542d719625784b4dc685ea67678595a391613555de0f2b8e"
V38_BUILD_TRACE_SHA256 = "73d580148028f115c372e4fee9b9edcbfe1db9b0c1a33403cf12f14f3d7b0d06"
V38_BUILD_TRACE_BYTES = 959_916
V37_OMITTED_BUILD_SCRIPTS = (
    "crc32fast", "getrandom", "httparse", "libc", "rustix", "serde_json", "thiserror",
)
CONTROL_SOURCES = (
    "evals/scripts/bootstrap-skeleton-process-monitor-native.py",
    "evals/scripts/qualify-skeleton-process-monitor-native.py",
    "evals/scripts/lib/skeleton_process_monitor.py",
    "evals/scripts/lib/native_codex_boundary.py",
    "evals/scripts/lib/responses_relay.py",
    "evals/scripts/qualify-installed-codex-compatibility.py",
    "evals/scripts/fixtures/native-codex-supervisor.rs",
)


_BUILD_TRACE_LINE = re.compile(
    r"^(?P<pid>[1-9][0-9]*) (?P<timestamp>[0-9]+\.[0-9]{6}) (?P<body>.+)$"
)
_BUILD_EXECVE_START = re.compile(
    r'^execve\((?P<path>"(?:\\.|[^"\\])*")\s*,'
)
_BUILD_EXECVEAT_START = re.compile(
    r'^execveat\([^,\r\n]+,\s*(?P<path>"(?:\\.|[^"\\])*")\s*,'
)
_BUILD_RESUMED = re.compile(
    r'^<\.\.\. (?P<syscall>execve|execveat) resumed>\)\s+=\s+'
    r'(?P<result>-?[0-9]+)(?P<suffix>.*)$'
)
_BUILD_RETURN = re.compile(
    r'\)\s+=\s+(?P<result>-?[0-9]+)(?P<suffix>.*)$'
)


def _build_exec_result(result_text: str, suffix: str) -> tuple[bool, bool]:
    """Validate one complete exec result and report success/delay marker."""

    result = int(result_text)
    delayed = suffix.endswith(" (DELAYED)")
    if delayed:
        suffix = suffix.removesuffix(" (DELAYED)")
    if "DELAYED" in suffix:
        raise RuntimeError("malformed build exec delay marker")
    if result == 0 and suffix == "":
        return True, delayed
    if result == -1 and re.fullmatch(r" [A-Z][A-Z0-9_]+(?: \(.*\))?", suffix):
        return False, delayed
    raise RuntimeError("malformed build exec result")


def parse_build_exec_trace(data: bytes) -> list[dict[str, object]]:
    """Exhaustively parse execve/execveat records, including split syscalls.

    The build tracer is intentionally restricted to these two syscalls.  Every
    line must therefore be consumed by this grammar.  Successful execveat is
    refused because a pathname alone does not bind its dirfd/flags authority.
    """

    try:
        lines = data.decode("utf-8", errors="strict").splitlines()
    except UnicodeDecodeError as error:
        raise RuntimeError("non-UTF-8 build exec trace") from error
    pending: dict[int, tuple[str, str, str]] = {}
    successful: list[dict[str, object]] = []
    for line_number, line in enumerate(lines, 1):
        parsed = _BUILD_TRACE_LINE.fullmatch(line)
        if parsed is None:
            raise RuntimeError(f"malformed build exec trace line {line_number}")
        pid = int(parsed.group("pid"))
        timestamp = parsed.group("timestamp")
        body = parsed.group("body")
        resumed = _BUILD_RESUMED.fullmatch(body)
        if resumed is not None:
            prior = pending.pop(pid, None)
            syscall = resumed.group("syscall")
            if prior is None or prior[0] != syscall:
                raise RuntimeError("unmatched build exec resumed record")
            succeeded, delayed = _build_exec_result(
                resumed.group("result"), resumed.group("suffix")
            )
            if succeeded:
                if syscall == "execveat":
                    raise RuntimeError("successful build execveat refused")
                successful.append({
                    "pid": pid, "syscall": syscall, "path": prior[1],
                    "started_at": prior[2], "finished_at": timestamp,
                    "split": True, "delayed": delayed,
                })
            continue

        start = _BUILD_EXECVE_START.match(body)
        syscall = "execve"
        if start is None:
            start = _BUILD_EXECVEAT_START.match(body)
            syscall = "execveat"
        if start is None:
            raise RuntimeError("unexpected build exec trace record")
        try:
            path = ast.literal_eval(start.group("path"))
        except (SyntaxError, ValueError) as error:
            raise RuntimeError("malformed build exec path") from error
        if not isinstance(path, str) or not path:
            raise RuntimeError("non-string build exec path")
        if body.endswith(" <unfinished ...>"):
            if pid in pending:
                raise RuntimeError("duplicate unfinished build exec record")
            pending[pid] = (syscall, path, timestamp)
            continue
        returned = _BUILD_RETURN.search(body)
        if returned is None:
            raise RuntimeError("incomplete build exec record")
        succeeded, delayed = _build_exec_result(
            returned.group("result"), returned.group("suffix")
        )
        if succeeded:
            if syscall == "execveat":
                raise RuntimeError("successful build execveat refused")
            successful.append({
                "pid": pid, "syscall": syscall, "path": path,
                "started_at": timestamp, "finished_at": timestamp,
                "split": False, "delayed": delayed,
            })
    if pending:
        raise RuntimeError("unfinished build exec record")
    return successful


def compact(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def digest(path: os.PathLike[str] | str) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _git(repo: Path, *arguments: str) -> bytes:
    return subprocess.run(
        ["/usr/bin/git", "-C", os.fspath(repo), *arguments], check=True,
        stdin=subprocess.DEVNULL, capture_output=True,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"},
    ).stdout


def _ignored_import_shadows(repo: Path) -> list[str]:
    rows = _git(
        repo, "ls-files", "--others", "--ignored", "--exclude-standard", "-z", "--",
        "evals/scripts",
    ).split(b"\0")
    return sorted(
        row.decode("utf-8") for row in rows if row and (
            row.decode("utf-8").endswith((".py", ".pyc", ".so", ".pyd"))
            or "__pycache__" in Path(row.decode("utf-8")).parts
        )
    )


def load_bootstrap(args) -> dict[str, object]:
    source_repo = Path(args.source_repo)
    runtime_root = Path(args.runtime_source_root)
    receipt_path = Path(args.bootstrap_receipt)
    if (source_repo.resolve(strict=True) != source_repo
            or runtime_root.resolve(strict=True) != runtime_root
            or receipt_path.resolve(strict=True) != receipt_path
            or Path(__file__).resolve(strict=True)
            != runtime_root / "evals/scripts/qualify-skeleton-process-monitor-native.py"):
        raise RuntimeError("bootstrap path identity mismatch")
    receipt = json.loads(receipt_path.read_bytes())
    if (receipt.get("schema") != "scourge.skeleton-native-bootstrap.v2"
            or receipt.get("source_repo") != os.fspath(source_repo)
            or receipt.get("operator_expected_commit") != receipt.get("git_commit")
            or receipt.get("full_status_clean") is not True
            or receipt.get("ignored_import_shadows") != []
            or set(row.get("path") for row in receipt.get("runtime_sources", []))
            != set(CONTROL_SOURCES)):
        raise RuntimeError("invalid bootstrap receipt")
    if _git(source_repo, "status", "--porcelain=v1", "--untracked-files=all"):
        raise RuntimeError("producer tree changed after bootstrap")
    if _ignored_import_shadows(source_repo):
        raise RuntimeError("import shadow appeared after bootstrap")
    commit = _git(source_repo, "rev-parse", "HEAD").decode().strip()
    tree = _git(source_repo, "rev-parse", "HEAD^{tree}").decode().strip()
    if (commit != receipt.get("git_commit") or tree != receipt.get("git_tree")):
        raise RuntimeError("producer object identity changed after bootstrap")
    bootstrap = receipt.get("bootstrap")
    if not isinstance(bootstrap, dict):
        raise RuntimeError("bootstrap execution identity missing")
    expected_stage = receipt_path.parent / "bootstrap-stage" / CONTROL_SOURCES[0].rsplit("/", 1)[-1]
    stage_row = bootstrap.get("private_stage")
    committed_bootstrap = _git(source_repo, "show", f"{commit}:{CONTROL_SOURCES[0]}")
    committed_oid = _git(
        source_repo, "rev-parse", f"{commit}:{CONTROL_SOURCES[0]}"
    ).decode().strip()
    if (not isinstance(stage_row, dict)
            or Path(str(stage_row.get("path"))) != expected_stage
            or bootstrap.get("blob_oid") != committed_oid
            or bootstrap.get("committed_sha256")
            != hashlib.sha256(committed_bootstrap).hexdigest()):
        raise RuntimeError("bootstrap committed identity mismatch")
    fd = os.open(expected_stage, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        staged = b""
        while len(staged) < info.st_size:
            block = os.read(fd, min(1 << 20, info.st_size - len(staged)))
            if not block:
                break
            staged += block
        after = os.fstat(fd)
    finally:
        os.close(fd)
    actual_stage = {
        "path": os.fspath(expected_stage), "device": info.st_dev, "inode": info.st_ino,
        "mode": f"{stat.S_IMODE(info.st_mode):04o}", "link_count": info.st_nlink,
        "owner_uid": info.st_uid, "owner_gid": info.st_gid, "bytes": info.st_size,
        "mtime_ns": info.st_mtime_ns, "ctime_ns": info.st_ctime_ns,
        "sha256": hashlib.sha256(staged).hexdigest(),
    }
    if (staged != committed_bootstrap or actual_stage != stage_row
            or _fstat_row(info) != _fstat_row(after)):
        raise RuntimeError("private bootstrap stage changed after execution")
    launcher = bootstrap.get("trusted_launcher")
    launcher_path = receipt_path.parent / "launcher.cmdline"
    if not isinstance(launcher, dict):
        raise RuntimeError("trusted launcher execution identity missing")
    descriptor = os.open(
        launcher_path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    )
    try:
        launcher_info = os.fstat(descriptor)
        launcher_bytes = b""
        while len(launcher_bytes) < launcher_info.st_size:
            block = os.read(
                descriptor, min(1 << 20, launcher_info.st_size - len(launcher_bytes))
            )
            if not block:
                break
            launcher_bytes += block
        launcher_after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    launcher_identity = {
        "path": os.fspath(launcher_path), "device": launcher_info.st_dev,
        "inode": launcher_info.st_ino,
        "mode": f"{stat.S_IMODE(launcher_info.st_mode):04o}",
        "link_count": launcher_info.st_nlink, "owner_uid": launcher_info.st_uid,
        "owner_gid": launcher_info.st_gid, "bytes": launcher_info.st_size,
        "mtime_ns": launcher_info.st_mtime_ns, "ctime_ns": launcher_info.st_ctime_ns,
        "sha256": hashlib.sha256(launcher_bytes).hexdigest(),
    }
    actual_launcher_argv = [part.decode("utf-8") for part in launcher_bytes.split(b"\0")
                            if part]
    if (launcher_identity != launcher.get("cmdline")
            or launcher.get("argv_sha256")
            != hashlib.sha256(launcher_bytes).hexdigest()
            or launcher.get("argv") != actual_launcher_argv
            or launcher.get("root_owned_tools_only_before_bootstrap") is not True
            or _fstat_row(launcher_info) != _fstat_row(launcher_after)):
        raise RuntimeError("trusted launcher identity changed after bootstrap")
    for row in receipt["runtime_sources"]:
        relative = row["path"]
        copied = runtime_root / relative
        data = copied.read_bytes()
        committed = _git(source_repo, "show", f"{commit}:{relative}")
        if (data != committed or len(data) != row["bytes"]
                or hashlib.sha256(data).hexdigest() != row["sha256"]
                or _git(source_repo, "rev-parse", f"{commit}:{relative}").decode().strip()
                != row["blob_oid"]):
            raise RuntimeError(f"runtime source identity mismatch: {relative}")
    return receipt


def private_evidence_ref(root: Path, source: Path, relative: str) -> str:
    """Bind a public relative reference to one exact private evidence root."""

    reference = Path(relative)
    if (not root.is_absolute() or not source.is_absolute()
            or reference.is_absolute() or not reference.parts
            or any(part in {".", ".."} for part in reference.parts)
            or source != root / reference):
        raise RuntimeError("unsafe public private-evidence reference")
    return reference.as_posix()


def producer_manifest(
    bootstrap: dict[str, object], build_receipt_sha256: str | None = None
) -> tuple[dict[str, object], str]:
    execution = bootstrap["bootstrap"]
    private_stage = dict(execution["private_stage"])
    private_stage_path = Path(str(private_stage["path"]))
    if len(private_stage_path.parents) < 3:
        raise RuntimeError("unsafe private bootstrap stage path")
    artifact_root = private_stage_path.parents[2]
    private_stage["path"] = private_evidence_ref(
        artifact_root,
        private_stage_path,
        "control/bootstrap-stage/"
        + private_stage_path.name,
    )
    trusted_launcher = dict(execution["trusted_launcher"])
    launcher_cmdline = dict(trusted_launcher["cmdline"])
    launcher_cmdline["path"] = private_evidence_ref(
        artifact_root,
        Path(str(launcher_cmdline["path"])),
        "control/launcher.cmdline",
    )
    trusted_launcher["cmdline"] = launcher_cmdline
    trusted_launcher.pop("argv", None)
    public_execution = {
        key: value for key, value in execution.items()
        if key not in {"private_stage", "argv", "trusted_launcher"}
    }
    public_execution["private_stage"] = private_stage
    public_execution["trusted_launcher"] = trusted_launcher
    public_execution["argv_sha256"] = hashlib.sha256(
        compact(execution["argv"])
    ).hexdigest()
    value = {
        "schema": "scourge.skeleton-producer-manifest.v3",
        "git_commit": bootstrap["git_commit"],
        "git_tree": bootstrap["git_tree"],
        "bootstrap_sha256": hashlib.sha256(compact(bootstrap)).hexdigest(),
        "bootstrap_execution": public_execution,
        "sources": bootstrap["runtime_sources"],
        "executed_from_private_copy": True,
        "scourge_build_receipt_sha256": build_receipt_sha256,
    }
    return value, hashlib.sha256(PRODUCER_MANIFEST_DOMAIN + compact(value)).hexdigest()


def public_receipt_private_path_hits(
    value: object, forbidden_paths: tuple[Path, ...]
) -> list[tuple[str, str]]:
    """Return every public string that embeds an attempt-private host path."""

    forbidden = tuple(os.fspath(path).encode() for path in forbidden_paths)
    hits: list[tuple[str, str]] = []

    def visit(current: object, location: str) -> None:
        if isinstance(current, dict):
            for key, nested in current.items():
                visit(nested, f"{location}/{key}")
        elif isinstance(current, list):
            for index, nested in enumerate(current):
                visit(nested, f"{location}/{index}")
        elif isinstance(current, str):
            encoded = current.encode("utf-8")
            if any(path in encoded for path in forbidden):
                hits.append((location or "/", current))

    visit(value, "")
    return hits


def verify_producer_manifest(
    value: dict[str, object], expected: str, args, artifacts: Path,
    build_receipt: dict[str, object]
) -> bool:
    try:
        bootstrap = load_bootstrap(args)
        build_sha = hashlib.sha256(
            BUILD_RECEIPT_DOMAIN + compact(build_receipt)
        ).hexdigest()
        current, actual = producer_manifest(bootstrap, build_sha)
    except (OSError, subprocess.SubprocessError, RuntimeError, ValueError):
        return False
    return (current == value and actual == expected
            and verify_scourge_build(artifacts, build_receipt, build_sha))


def key_commitment(key_path: Path) -> str:
    key = monitor.read_monitor_key(key_path)
    return hashlib.sha256(KEY_COMMITMENT_DOMAIN + key).hexdigest()


def artifact_file_manifest(root: Path) -> list[dict[str, object]]:
    if not root.exists():
        return []
    rows = []
    for path in sorted(root.rglob("*")):
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise RuntimeError(f"symlink in attempt evidence: {path}")
        if not stat.S_ISREG(info.st_mode):
            continue
        rows.append({
            "path": path.relative_to(root).as_posix(),
            "bytes": info.st_size,
            "sha256": digest(path),
        })
    return rows


def _history_rows(path: Path) -> list[dict[str, object]]:
    if not path.exists():
        return []
    payload = _legacy_history_payload(path)
    if payload and not payload.endswith(b"\n"):
        raise RuntimeError("torn legacy attempt-history suffix")
    rows = []
    for line in payload.splitlines():
        value = json.loads(line)
        if not isinstance(value, dict):
            raise RuntimeError("invalid attempt-history row")
        rows.append(value)
    states: dict[object, str] = {}
    for row in rows:
        attempt = row.get("attempt")
        event = row.get("event")
        if not isinstance(attempt, str) or event not in {"attempt_started", "attempt_finished"}:
            raise RuntimeError("invalid attempt-history lifecycle")
        if event == "attempt_started":
            if attempt in states:
                raise RuntimeError("duplicate attempt-history start")
            states[attempt] = "started"
        elif states.get(attempt) != "started":
            raise RuntimeError("orphan or duplicate attempt-history finish")
        else:
            states[attempt] = "finished"
    return rows


def _legacy_history_payload(path: Path) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        payload = b""
        while len(payload) < info.st_size:
            block = os.read(descriptor, min(1 << 20, info.st_size - len(payload)))
            if not block:
                break
            payload += block
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
            or _fstat_row(info) != _fstat_row(after) or len(payload) != info.st_size):
        raise RuntimeError("unsafe attempt-history file")
    return payload


def _history_states(rows: list[dict[str, object]]) -> dict[str, str]:
    states: dict[str, str] = {}
    for row in rows:
        states[row["attempt"]] = (
            "started" if row["event"] == "attempt_started" else "finished"
        )
    return states


def append_history(path: Path, row: dict[str, object]) -> None:
    parent = path.parent
    info = parent.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o700 or parent.resolve(strict=True) != parent):
        raise RuntimeError("unsafe attempt-history root")
    existing = _history_rows(path)
    states = _history_states(existing)
    attempt = row.get("attempt")
    event = row.get("event")
    if (event == "attempt_started" and attempt in states
            or event == "attempt_finished" and states.get(attempt) != "started"):
        raise RuntimeError(f"invalid attempt-history transition: {attempt}:{event}")
    existed = path.exists()
    fd = os.open(
        path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600,
    )
    try:
        opened = os.fstat(fd)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_uid != os.geteuid()
                or stat.S_IMODE(opened.st_mode) != 0o600 or opened.st_nlink != 1):
            raise RuntimeError("unsafe attempt-history file")
        data = compact(row) + b"\n"
        if os.write(fd, data) != len(data):
            raise RuntimeError("short attempt-history append")
        os.fsync(fd)
    finally:
        os.close(fd)
    if not existed:
        directory_fd = os.open(
            parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
        )
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)


def history_snapshot(path: Path) -> dict[str, object]:
    rows = _history_rows(path)
    data = _legacy_history_payload(path)
    projected: dict[str, dict[str, object]] = {}
    order: list[str] = []
    for row in rows:
        attempt = row["attempt"]
        if row["event"] == "attempt_started":
            order.append(attempt)
            projected[attempt] = {
                "attempt": attempt,
                "disposition": "incomplete",
                "reason": "attempt_started_without_terminal_event",
                "producer_revision": row.get("producer_revision"),
                "producer_manifest_sha256": row.get("producer_manifest_sha256"),
            }
        else:
            projected[attempt] = {
                key: value for key, value in row.items()
                if key not in {"schema", "event"}
            }
    projection = [projected[attempt] for attempt in order]
    incomplete = [
        row for row in projection if row["disposition"] == "incomplete"
    ]
    return {
        "schema": "scourge.skeleton-attempt-history.v1",
        "events": len(rows),
        "attempts": len(projection),
        "first_attempt": order[0] if order else None,
        "last_attempt": order[-1] if order else None,
        "incomplete_attempts": [row["attempt"] for row in incomplete],
        "incomplete_migration_attempts": [
            row["attempt"] for row in incomplete
            if row.get("producer_revision") == "unrecorded-historical"
        ],
        "incomplete_live_attempts": [
            row["attempt"] for row in incomplete
            if row.get("producer_revision") != "unrecorded-historical"
        ],
        "event_log_sha256": hashlib.sha256(data).hexdigest(),
        "projection_sha256": hashlib.sha256(compact(projection)).hexdigest(),
    }


def _legacy_hash_files(row: dict[str, object]) -> list[dict[str, object]]:
    result = []
    for name in ("raw_trace", "codex_jsonl", "monitor_stderr"):
        sha = row.get(f"{name}_sha256")
        if isinstance(sha, str):
            result.append({
                "path": None,
                "kind": name,
                "bytes": row.get(f"{name}_bytes"),
                "sha256": sha,
            })
    return result


def _seed_history_rows(prior_receipt: Path) -> list[dict[str, object]]:
    prior = json.loads(prior_receipt.read_bytes())
    expected: list[dict[str, object]] = []
    for legacy in prior.get("rejected_attempts", []):
        expected.append({
            "schema": "scourge.skeleton-attempt-history-row.v1",
            "attempt": legacy["attempt"],
            "event": "attempt_started",
            "producer_revision": "unrecorded-historical",
            "producer_manifest_sha256": None,
        })
        expected.append({
            "schema": "scourge.skeleton-attempt-history-row.v1",
            "attempt": legacy["attempt"],
            "event": "attempt_finished",
            "disposition": "rejected",
            "reason": legacy["reason"],
            "trace_started": isinstance(legacy.get("raw_trace_sha256"), str),
            "producer_revision": "unrecorded-historical",
            "producer_manifest_sha256": None,
            "artifact_retention": {
                "state": "hash_only", "root": None,
                "files": _legacy_hash_files(legacy),
            },
            "teardown": {"container_absent": legacy.get("container_absent")},
        })
    evidence = prior_receipt.parent
    historical = (
        ("v25", "accepted_superseded", "superseded_by_v27"),
        ("v26", "rejected", "partial_preflight"),
        ("v27", "accepted_superseded", "superseded_by_v29"),
        ("v28", "rejected", "historical_teapot_completion_write_order"),
        ("v29", "accepted_superseded", "blocked_by_cr-3gczto"),
    )
    for attempt, disposition, reason in historical:
        root = evidence / f"bn-6zcm-native-qualification-{attempt}.json.artifacts"
        files = artifact_file_manifest(root)
        expected.append({
            "schema": "scourge.skeleton-attempt-history-row.v1",
            "attempt": attempt,
            "event": "attempt_started",
            "producer_revision": "unrecorded-historical",
            "producer_manifest_sha256": None,
        })
        expected.append({
            "schema": "scourge.skeleton-attempt-history-row.v1",
            "attempt": attempt,
            "event": "attempt_finished",
            "disposition": disposition,
            "reason": reason,
            "trace_started": any(row["path"].endswith(".strace") for row in files),
            "producer_revision": "unrecorded-historical",
            "producer_manifest_sha256": None,
            "artifact_retention": {
                "state": "private_evidence_preserved" if files else "hash_only",
                "root": os.fspath(root) if files else None,
                "files": files,
            },
            "teardown": {"container_absent": True if attempt != "v26" else None},
        })
    return expected


def seed_history(path: Path, prior_receipt: Path) -> None:
    """Idempotently complete the deterministic legacy migration.

    Each append is fsynced by ``append_history``.  A crash after either member
    of any start/finish pair is therefore resumed without rewriting bytes that
    already reached the journal.  Live incomplete attempts are outside the
    deterministic migration ID set and remain visible to the caller.
    """

    expected = _seed_history_rows(prior_receipt)
    by_attempt: dict[str, list[dict[str, object]]] = {}
    for row in expected:
        by_attempt.setdefault(str(row["attempt"]), []).append(row)
    if any(len(rows) != 2 or [row["event"] for row in rows]
           != ["attempt_started", "attempt_finished"] for rows in by_attempt.values()):
        raise RuntimeError("invalid deterministic history migration")
    existing = _history_rows(path)
    existing_by_attempt: dict[str, list[dict[str, object]]] = {}
    for row in existing:
        existing_by_attempt.setdefault(str(row["attempt"]), []).append(row)
    for attempt, rows in by_attempt.items():
        present = existing_by_attempt.get(attempt, [])
        if len(present) > 2 or present != rows[:len(present)]:
            raise RuntimeError(f"history migration mismatch: {attempt}")
        for row in rows[len(present):]:
            append_history(path, row)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(
        path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _history_v2_root(legacy_path: Path) -> Path:
    return legacy_path.with_name(legacy_path.name + ".v2")


def _ensure_history_v2_root(root: Path) -> None:
    try:
        os.mkdir(root, 0o700)
        _fsync_directory(root.parent)
    except FileExistsError:
        pass
    info = root.lstat()
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700
            or root.resolve(strict=True) != root):
        raise RuntimeError("unsafe v2 attempt-history root")


def _history_v2_lock(root: Path) -> int:
    _ensure_history_v2_root(root)
    created = not (root / ".lock").exists()
    descriptor = os.open(
        root / ".lock",
        os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
    )
    info = os.fstat(descriptor)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
        os.close(descriptor)
        raise RuntimeError("unsafe v2 attempt-history lock")
    if created:
        os.fsync(descriptor)
        _fsync_directory(root)
    fcntl.flock(descriptor, fcntl.LOCK_EX)
    return descriptor


def _repair_linked_history_temp(root: Path) -> None:
    events: dict[int, Path] = {}
    for path in root.iterdir():
        if re.fullmatch(r"[0-9]{20}\.json", path.name):
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
                raise RuntimeError("unsafe v2 attempt-history event entry")
            events[info.st_ino] = path
    for temporary in sorted(root.glob(".tmp-*")):
        info = temporary.lstat()
        target = events.get(info.st_ino)
        temporary_data, opened_temporary = _read_publication_file(temporary)
        if target is not None:
            target_data, opened_target = _read_publication_file(target)
        else:
            target_data, opened_target = b"", None
        if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
                or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_nlink != 2 or target is None
                or opened_target is None
                or (opened_temporary.st_dev, opened_temporary.st_ino,
                    opened_temporary.st_nlink)
                != (opened_target.st_dev, opened_target.st_ino,
                    opened_target.st_nlink)
                or temporary_data != target_data):
            raise RuntimeError(f"orphan or conflicting history temp: {temporary.name}")
        # This is the exact second link left by a crash after the no-replace
        # link. Removing it completes that known transaction; unknown temps are
        # never removed or overwritten.
        temporary.unlink()
        _fsync_directory(root)


def _read_history_v2_locked(root: Path) -> list[dict[str, object]]:
    _repair_linked_history_temp(root)
    names = {path.name for path in root.iterdir()}
    allowed = {".lock"} | {
        name for name in names if re.fullmatch(r"[0-9]{20}\.json", name)
    }
    if names != allowed:
        raise RuntimeError("unknown v2 attempt-history entry")
    rows: list[dict[str, object]] = []
    previous = "0" * 64
    states: dict[str, str] = {}
    for index, path in enumerate(sorted(
        root / name for name in names if name.endswith(".json")
    ), start=1):
        if path.name != f"{index:020d}.json":
            raise RuntimeError("noncontiguous v2 attempt-history sequence")
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            info = os.fstat(descriptor)
            data = b""
            while len(data) < info.st_size:
                block = os.read(descriptor, min(1 << 20, info.st_size - len(data)))
                if not block:
                    break
                data += block
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                or _fstat_row(info) != _fstat_row(after) or not data.endswith(b"\n")):
            raise RuntimeError("unsafe v2 attempt-history event")
        row = json.loads(data)
        if (not isinstance(row, dict) or compact(row) + b"\n" != data
                or row.get("schema") != HISTORY_V2_SCHEMA
                or row.get("sequence") != index
                or row.get("previous_event_sha256") != previous
                or not isinstance(row.get("event"), dict)):
            raise RuntimeError("invalid v2 attempt-history event")
        event = row["event"]
        attempt = event.get("attempt")
        kind = event.get("event")
        if not isinstance(attempt, str) or kind not in {
            "attempt_started", "publication_prepared", "attempt_finished"
        }:
            raise RuntimeError("invalid v2 attempt-history lifecycle")
        state = states.get(attempt)
        if kind == "attempt_started":
            if state is not None:
                raise RuntimeError("duplicate v2 attempt-history start")
            states[attempt] = "started"
        elif kind == "publication_prepared":
            if state != "started":
                raise RuntimeError("orphan v2 publication preparation")
            states[attempt] = "prepared"
        else:
            disposition = event.get("disposition")
            if state not in {"started", "prepared"} or disposition not in {
                "accepted", "rejected"
            } or disposition == "accepted" and state != "prepared":
                raise RuntimeError("invalid v2 terminal transition")
            states[attempt] = disposition
        previous = hashlib.sha256(data).hexdigest()
        rows.append(row)
    return rows


def read_history_v2(root: Path) -> list[dict[str, object]]:
    descriptor = _history_v2_lock(root)
    try:
        return _read_history_v2_locked(root)
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def append_history_v2(
    root: Path,
    event: dict[str, object],
    *,
    fault=None,
) -> dict[str, object]:
    """Durably append one immutable event by same-filesystem no-replace link."""

    descriptor = _history_v2_lock(root)
    try:
        rows = _read_history_v2_locked(root)
        if rows and rows[-1]["event"] == event:
            return rows[-1]
        sequence = len(rows) + 1
        previous = hashlib.sha256(compact(rows[-1]) + b"\n").hexdigest() \
            if rows else "0" * 64
        row = {
            "schema": HISTORY_V2_SCHEMA,
            "sequence": sequence,
            "previous_event_sha256": previous,
            "event": event,
        }
        data = compact(row) + b"\n"
        temporary = root / f".tmp-{sequence:020d}-{os.urandom(16).hex()}"
        final = root / f"{sequence:020d}.json"
        temp_fd = os.open(
            temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
            | os.O_NOFOLLOW, 0o600,
        )
        try:
            offset = 0
            while offset < len(data):
                written = os.write(temp_fd, data[offset:])
                if written <= 0:
                    raise RuntimeError("short v2 attempt-history write")
                offset += written
            os.fsync(temp_fd)
        finally:
            os.close(temp_fd)
        if fault is not None:
            fault("after_temp_fsync")
        os.link(temporary, final, follow_symlinks=False)
        if fault is not None:
            fault("after_no_replace_link")
        _fsync_directory(root)
        if fault is not None:
            fault("after_event_dir_fsync")
        temporary.unlink()
        _fsync_directory(root)
        if fault is not None:
            fault("after_temp_unlink_fsync")
        return row
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def history_v2_snapshot(root: Path) -> dict[str, object]:
    rows = read_history_v2(root)
    return _history_v2_snapshot_rows(rows)


def _history_v2_snapshot_rows(
    rows: list[dict[str, object]],
) -> dict[str, object]:
    events = [row["event"] for row in rows]
    files = [{
        "path": f"{index:020d}.json",
        "sha256": hashlib.sha256(compact(row) + b"\n").hexdigest(),
        "bytes": len(compact(row) + b"\n"),
    } for index, row in enumerate(rows, start=1)]
    return {
        "schema": HISTORY_V2_SNAPSHOT_SCHEMA,
        "events": len(rows),
        "last_event_sha256": files[-1]["sha256"] if files else "0" * 64,
        "event_manifest_sha256": hashlib.sha256(compact(files)).hexdigest(),
        "projection_sha256": hashlib.sha256(compact(events)).hexdigest(),
        "files": files,
    }


def prepublication_history_valid(
    legacy: Mapping[str, object],
    rows: list[dict[str, object]],
    *,
    attempt: str,
    attempt_nonce: str,
    producer_revision: str,
    producer_manifest_sha256: str,
) -> bool:
    """Bind qualification to one started-only v2 attempt after frozen v1."""

    if (legacy.get("incomplete_attempts") != []
            or legacy.get("incomplete_migration_attempts") != []
            or legacy.get("incomplete_live_attempts") != []
            or not rows):
        return False
    events = [row.get("event") for row in rows]
    if not all(isinstance(event, dict) for event in events):
        return False
    by_attempt: dict[str, list[dict[str, object]]] = {}
    for event in events:
        assert isinstance(event, dict)
        event_attempt = event.get("attempt")
        if not isinstance(event_attempt, str):
            return False
        by_attempt.setdefault(event_attempt, []).append(event)
    current = by_attempt.get(attempt)
    if current is None or len(current) != 1 or events[-1] is not current[0]:
        return False
    started = current[0]
    if set(started) != {
        "attempt", "attempt_nonce", "event", "observed_at",
        "producer_manifest_sha256", "producer_revision",
    } or started != {
        "attempt": attempt,
        "attempt_nonce": attempt_nonce,
        "event": "attempt_started",
        "observed_at": started.get("observed_at"),
        "producer_manifest_sha256": producer_manifest_sha256,
        "producer_revision": producer_revision,
    }:
        return False
    observed_at = started.get("observed_at")
    try:
        observed = datetime.fromisoformat(str(observed_at))
    except ValueError:
        return False
    if observed.tzinfo is None or observed.utcoffset() != timezone.utc.utcoffset(observed):
        return False
    for prior_attempt, prior in by_attempt.items():
        if prior_attempt == attempt:
            continue
        kinds = [str(event.get("event")) for event in prior]
        if (kinds not in (
                ["attempt_started", "attempt_finished"],
                ["attempt_started", "publication_prepared", "attempt_finished"],
            )
                or prior[-1].get("disposition") not in {"accepted", "rejected"}
                or (prior[-1].get("disposition") == "accepted"
                    and kinds[1] != "publication_prepared")):
            return False
    return True


def _write_exclusive_durable(path: Path, data: bytes, *, mode: int = 0o600) -> None:
    descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        mode,
    )
    try:
        offset = 0
        while offset < len(data):
            written = os.write(descriptor, data[offset:])
            if written <= 0:
                raise RuntimeError(f"short durable write: {path}")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    _fsync_directory(path.parent)


def _publication_candidate_path(output: Path, attempt: str) -> Path:
    return output.with_name(f".{output.name}.{attempt}.candidate")


def _publication_manifest_digest(files: list[dict[str, object]]) -> str:
    return hashlib.sha256(compact(files)).hexdigest()


PUBLICATION_DIRECTORY_MODES = frozenset({0o500, 0o700, 0o755})


def _safe_publication_directory(
    info: os.stat_result, *, root: bool = False
) -> bool:
    mode = stat.S_IMODE(info.st_mode)
    return (
        stat.S_ISDIR(info.st_mode)
        and not stat.S_ISLNK(info.st_mode)
        and info.st_uid == os.geteuid()
        and mode & 0o500 == 0o500
        and mode & 0o022 == 0
        and mode in ({0o700} if root else PUBLICATION_DIRECTORY_MODES)
    )


def _same_publication_identity(
    expected: os.stat_result, observed: os.stat_result
) -> bool:
    return _fstat_row(expected) == _fstat_row(observed)


def _publication_parent(path: Path) -> tuple[int, os.stat_result]:
    if (not path.is_absolute() or not path.name or path.name in {".", ".."}
            or "/" in path.name or "\0" in path.name
            or path.parent.resolve(strict=True) != path.parent):
        raise RuntimeError("unsafe publication path")
    descriptor = os.open(
        path.parent,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    info = os.fstat(descriptor)
    if (not _safe_publication_directory(info)
            or not _same_publication_identity(path.parent.lstat(), info)):
        os.close(descriptor)
        raise RuntimeError("unsafe publication parent")
    return descriptor, info


def _read_publication_at(
    parent_descriptor: int, name: str
) -> tuple[bytes, os.stat_result]:
    before = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    descriptor = os.open(
        name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        dir_fd=parent_descriptor,
    )
    try:
        info = os.fstat(descriptor)
        if not _same_publication_identity(before, info):
            raise RuntimeError("publication file changed before open")
        blocks = []
        byte_count = 0
        while byte_count < info.st_size:
            block = os.read(descriptor, min(1 << 20, info.st_size - byte_count))
            if not block:
                break
            blocks.append(block)
            byte_count += len(block)
        after = os.fstat(descriptor)
        named_after = os.stat(
            name, dir_fd=parent_descriptor, follow_symlinks=False
        )
    finally:
        os.close(descriptor)
    data = b"".join(blocks)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600
            or not _same_publication_identity(info, after)
            or not _same_publication_identity(info, named_after)
            or len(data) != info.st_size):
        raise RuntimeError("unsafe publication file")
    return data, info


def _verify_published_pair(
    candidate: Path,
    output: Path,
    *,
    attempt: str,
    expected_data: bytes,
    expected_sha256: str,
) -> dict[str, object]:
    """Prove the official receipt is exactly the candidate's second link."""

    if (candidate != _publication_candidate_path(output, attempt)
            or candidate.parent != output.parent):
        raise RuntimeError("unexpected publication candidate/output paths")
    parent_descriptor, parent_before = _publication_parent(output)
    try:
        candidate_data, candidate_info = _read_publication_at(
            parent_descriptor, candidate.name
        )
        output_data, output_info = _read_publication_at(
            parent_descriptor, output.name
        )
        parent_after = os.fstat(parent_descriptor)
        named_parent_after = output.parent.lstat()
    finally:
        os.close(parent_descriptor)
    digest = hashlib.sha256(expected_data).hexdigest()
    if (candidate_data != expected_data or output_data != expected_data
            or digest != expected_sha256
            or candidate_info.st_uid != os.geteuid()
            or output_info.st_uid != os.geteuid()
            or stat.S_IMODE(candidate_info.st_mode) != 0o600
            or stat.S_IMODE(output_info.st_mode) != 0o600
            or (candidate_info.st_dev, candidate_info.st_ino)
            != (output_info.st_dev, output_info.st_ino)
            or candidate_info.st_nlink != 2 or output_info.st_nlink != 2
            or candidate_info.st_size != len(expected_data)
            or output_info.st_size != len(expected_data)
            or not _same_publication_identity(parent_before, parent_after)
            or not _same_publication_identity(parent_before, named_parent_after)):
        raise RuntimeError("publication candidate/output topology mismatch")
    return {
        "schema": "scourge.skeleton-publication-pair.v1",
        "candidate_path": os.fspath(candidate),
        "official_output": os.fspath(output),
        "bytes": len(expected_data),
        "sha256": expected_sha256,
        "candidate_fstat": _fstat_row(candidate_info),
        "output_fstat": _fstat_row(output_info),
        "same_device_inode": True,
        "expected_link_count": 2,
    }


def publication_artifact_manifest(root: Path) -> list[dict[str, object]]:
    """Hash a private tree through held directory fds without following links."""

    if (not root.is_absolute() or root.resolve(strict=True) != root
            or not _safe_publication_directory(root.lstat(), root=True)):
        raise RuntimeError("unsafe publication artifact root")
    root_descriptor = os.open(
        root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    )
    rows: list[dict[str, object]] = []

    def walk(directory_descriptor: int, prefix: str) -> None:
        directory_before = os.fstat(directory_descriptor)
        if not _safe_publication_directory(
            directory_before, root=not prefix
        ):
            raise RuntimeError("unsafe publication artifact directory")
        rows.append({
            "kind": "root" if not prefix else "directory",
            "path": "." if not prefix else prefix,
            "fstat": _fstat_row(directory_before),
        })
        for name in sorted(os.listdir(directory_descriptor)):
            if (not isinstance(name, str) or not name or name in {".", ".."}
                    or "/" in name or "\0" in name):
                raise RuntimeError("unsafe publication artifact path")
            relative = name if not prefix else f"{prefix}/{name}"
            before = os.stat(
                name, dir_fd=directory_descriptor, follow_symlinks=False
            )
            if stat.S_ISDIR(before.st_mode) and not stat.S_ISLNK(before.st_mode):
                if not _safe_publication_directory(before):
                    raise RuntimeError("unsafe publication artifact directory")
                child = os.open(
                    name,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                    dir_fd=directory_descriptor,
                )
                try:
                    if not _same_publication_identity(before, os.fstat(child)):
                        raise RuntimeError("publication artifact directory changed")
                    walk(child, relative)
                    if not _same_publication_identity(before, os.fstat(child)):
                        raise RuntimeError("publication artifact directory changed")
                finally:
                    os.close(child)
                continue
            if not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode):
                raise RuntimeError("unsafe publication artifact file")
            descriptor = os.open(
                name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=directory_descriptor,
            )
            try:
                opened = os.fstat(descriptor)
                if not _same_publication_identity(before, opened):
                    raise RuntimeError("publication artifact file changed")
                hasher = hashlib.sha256()
                byte_count = 0
                while byte_count < opened.st_size:
                    block = os.read(
                        descriptor, min(1 << 20, opened.st_size - byte_count)
                    )
                    if not block:
                        break
                    hasher.update(block)
                    byte_count += len(block)
                after = os.fstat(descriptor)
            finally:
                os.close(descriptor)
            if (not stat.S_ISREG(opened.st_mode)
                    or opened.st_uid != os.geteuid()
                    or stat.S_IMODE(opened.st_mode) & 0o022
                    or opened.st_nlink != 1
                    or not _same_publication_identity(opened, after)
                    or byte_count != opened.st_size):
                raise RuntimeError("unsafe publication artifact file")
            rows.append({
                "kind": "file", "path": relative, "bytes": byte_count,
                "sha256": hasher.hexdigest(), "fstat": _fstat_row(opened),
            })
        if not _same_publication_identity(
            directory_before, os.fstat(directory_descriptor)
        ):
            raise RuntimeError("publication artifact directory changed")

    try:
        root_before = os.fstat(root_descriptor)
        if (not _safe_publication_directory(root_before, root=True)
                or not _same_publication_identity(root.lstat(), root_before)):
            raise RuntimeError("unsafe publication artifact root")
        walk(root_descriptor, "")
        if (not _same_publication_identity(root_before, os.fstat(root_descriptor))
                or not _same_publication_identity(root_before, root.lstat())):
            raise RuntimeError("publication artifact root changed")
    finally:
        os.close(root_descriptor)
    rows.sort(key=lambda row: (str(row["path"]), str(row["kind"])))
    return rows


def prove_publication_container_absence(identity: Mapping[str, object]) -> bool:
    cid = identity.get("id")
    name = identity.get("name")
    if (not isinstance(cid, str) or re.fullmatch(r"[0-9a-f]{64}", cid) is None
            or name != "scourge-bn6zcm-native"):
        return False
    environment = monitor.monitor_environment()
    for value in (cid, name):
        completed = subprocess.run(
            [PODMAN, "--remote=false", "container", "exists", value],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, env=environment, timeout=30, check=False,
        )
        if completed.returncode != 1:
            return False
    return True


def publish_accepted_receipt(
    *,
    output: Path,
    attempt: str,
    attempt_nonce: str,
    receipt: dict[str, object],
    legacy_history: dict[str, object],
    history_root: Path,
    artifact_root: Path,
    container_absent: bool,
    container_identity: Mapping[str, object],
    absence_check=prove_publication_container_absence,
    fault=None,
) -> tuple[dict[str, object], str]:
    """Publish exact receipt bytes before the journal may say accepted."""

    if not container_absent or not absence_check(container_identity):
        raise RuntimeError("accepted publication requires proved container absence")
    prefix = history_v2_snapshot(history_root)
    files = publication_artifact_manifest(artifact_root)
    manifest_sha256 = _publication_manifest_digest(files)
    candidate_receipt = dict(receipt)
    candidate_receipt["attempt_history"] = {
        "legacy_frozen": legacy_history,
        "v2_backward_prefix": prefix,
        "scope": "post-authenticated-bootstrap",
    }
    core_sha256 = hashlib.sha256(
        RECEIPT_CORE_DOMAIN + compact(candidate_receipt)
    ).hexdigest()
    candidate_receipt["publication"] = {
        "schema": "scourge.skeleton-receipt-publication.v1",
        "attempt": attempt,
        "attempt_nonce": attempt_nonce,
        "receipt_core_sha256": core_sha256,
        "artifact_root": "private-attempt-artifact-root",
        "artifact_manifest": files,
        "artifact_manifest_sha256": manifest_sha256,
        "container_absence_sha256": hashlib.sha256(
            compact({"container_absent": True, "identity": container_identity})
        ).hexdigest(),
        "container_identity": dict(container_identity),
        "journal_prefix_sha256": prefix["event_manifest_sha256"],
        "acceptance": "external-v2-event-plus-durable-exact-output",
        "candidate_and_output_excluded_from_artifact_manifest": True,
    }
    data = compact(candidate_receipt) + b"\n"
    candidate = _publication_candidate_path(output, attempt)
    _write_exclusive_durable(candidate, data)
    if fault is not None:
        fault("after_candidate_dir_fsync")
    candidate_sha256 = hashlib.sha256(data).hexdigest()
    prepared = {
        "attempt": attempt,
        "event": "publication_prepared",
        "attempt_nonce": attempt_nonce,
        "candidate_path": os.fspath(candidate),
        "candidate_bytes": len(data),
        "candidate_sha256": candidate_sha256,
        "official_output": os.fspath(output),
        "receipt_core_sha256": core_sha256,
        "artifact_root": os.fspath(artifact_root),
        "artifact_manifest_sha256": manifest_sha256,
        "container_absence_sha256": candidate_receipt["publication"][
            "container_absence_sha256"
        ],
        "container_identity": dict(container_identity),
    }
    append_history_v2(history_root, prepared)
    if fault is not None:
        fault("after_publication_prepared")
    os.link(candidate, output, follow_symlinks=False)
    if fault is not None:
        fault("after_output_link_before_dir_fsync")
    _fsync_directory(output.parent)
    pair = _verify_published_pair(
        candidate, output, attempt=attempt, expected_data=data,
        expected_sha256=candidate_sha256,
    )
    if fault is not None:
        fault("after_output_dir_fsync")
    finished = {
        "attempt": attempt,
        "event": "attempt_finished",
        "disposition": "accepted",
        "reason": "durable_receipt_published",
        "attempt_nonce": attempt_nonce,
        "receipt_path": os.fspath(output),
        "receipt_sha256": candidate_sha256,
        "receipt_core_sha256": core_sha256,
        "artifact_manifest_sha256": manifest_sha256,
        "publication_pair": pair,
        "teardown": {"container_absent": True},
    }
    append_history_v2(history_root, finished)
    if fault is not None:
        fault("after_accepted_event")
    return candidate_receipt, candidate_sha256


def _verify_prepared_publication(event: Mapping[str, object]) -> bytes:
    candidate = Path(str(event["candidate_path"]))
    output = Path(str(event["official_output"]))
    attempt = event.get("attempt")
    if (type(attempt) is not str
            or candidate != _publication_candidate_path(output, attempt)
            or candidate.parent != output.parent):
        raise RuntimeError("invalid prepared publication paths")
    data, info = _read_publication_file(candidate)
    if (info.st_nlink not in {1, 2}
            or len(data) != event["candidate_bytes"]
            or hashlib.sha256(data).hexdigest() != event["candidate_sha256"]
            or not data.endswith(b"\n")):
        raise RuntimeError("invalid prepared receipt candidate")
    receipt = json.loads(data)
    publication = receipt.get("publication", {})
    receipt_core = dict(receipt)
    receipt_core.pop("publication", None)
    files = publication_artifact_manifest(Path(str(event["artifact_root"])))
    producer = receipt.get("producer")
    build = receipt.get("scourge_build")
    collector = receipt.get("collector")
    producer_valid = False
    if isinstance(producer, dict) and isinstance(build, dict):
        manifest = producer.get("manifest")
        assignment = producer.get("assignment")
        build_receipt = build.get("receipt")
        if (isinstance(manifest, dict) and isinstance(assignment, dict)
                and isinstance(build_receipt, dict)):
            manifest_sha256 = hashlib.sha256(
                PRODUCER_MANIFEST_DOMAIN + compact(manifest)
            ).hexdigest()
            assignment_sha256 = hashlib.sha256(
                ASSIGNMENT_DOMAIN + compact(assignment)
            ).hexdigest()
            build_sha256 = hashlib.sha256(
                BUILD_RECEIPT_DOMAIN + compact(build_receipt)
            ).hexdigest()
            producer_valid = (
                producer.get("manifest_sha256") == manifest_sha256
                and producer.get("assignment_sha256") == assignment_sha256
                and build.get("receipt_sha256") == build_sha256
                and manifest.get("scourge_build_receipt_sha256") == build_sha256
                and assignment.get("producer_manifest_sha256") == manifest_sha256
                and assignment.get("scourge_build_receipt_sha256") == build_sha256
            )
    absence_value = {
        "container_absent": True, "identity": event.get("container_identity")
    }
    if (not isinstance(publication, dict)
            or receipt.get("valid") is not True
            or not isinstance(collector, dict)
            or collector.get("container_absent") is not True
            or collector.get("container_identity") != event.get("container_identity")
            or not producer_valid
            or publication.get("attempt") != attempt
            or publication.get("attempt_nonce") != event.get("attempt_nonce")
            or publication.get("receipt_core_sha256")
            != event.get("receipt_core_sha256")
            or hashlib.sha256(RECEIPT_CORE_DOMAIN + compact(receipt_core)).hexdigest()
            != event.get("receipt_core_sha256")
            or _publication_manifest_digest(files)
            != event.get("artifact_manifest_sha256")
            or publication.get("artifact_manifest") != files
            or publication.get("artifact_manifest_sha256")
            != event.get("artifact_manifest_sha256")
            or publication.get("container_absence_sha256")
            != event.get("container_absence_sha256")
            or publication.get("container_identity")
            != event.get("container_identity")
            or hashlib.sha256(compact(absence_value)).hexdigest()
            != event.get("container_absence_sha256")
            or output.parent.resolve(strict=True) != output.parent):
        raise RuntimeError("prepared receipt evidence changed")
    return data


def _read_publication_file(path: Path) -> tuple[bytes, os.stat_result]:
    parent_descriptor, parent_before = _publication_parent(path)
    try:
        data, info = _read_publication_at(parent_descriptor, path.name)
        parent_after = os.fstat(parent_descriptor)
        named_parent_after = path.parent.lstat()
    finally:
        os.close(parent_descriptor)
    if (not _same_publication_identity(parent_before, parent_after)
            or not _same_publication_identity(parent_before, named_parent_after)):
        raise RuntimeError("publication parent changed")
    return data, info


def recover_history_v2(
    root: Path, *, absence_check=prove_publication_container_absence
) -> None:
    """Deterministically reject starts or finish a durable prepared publish."""

    rows = read_history_v2(root)
    attempts: dict[str, list[dict[str, object]]] = {}
    for row in rows:
        event = row["event"]
        attempts.setdefault(str(event["attempt"]), []).append(event)
    for attempt, events in attempts.items():
        if events[-1]["event"] == "attempt_finished":
            if events[-1].get("disposition") == "accepted":
                output = Path(str(events[-1]["receipt_path"]))
                if not verify_published_acceptance(
                    root, output, attempt, str(events[-1]["receipt_sha256"]),
                    absence_check=absence_check,
                ):
                    raise RuntimeError("accepted history has missing or changed receipt")
            continue
        if events[-1]["event"] == "attempt_started":
            append_history_v2(root, {
                "attempt": attempt,
                "event": "attempt_finished",
                "disposition": "rejected",
                "reason": "interrupted_before_publication_prepared",
                "attempt_nonce": events[0].get("attempt_nonce"),
                "teardown": {"container_absent": None},
            })
            continue
        prepared = events[-1]
        try:
            data = _verify_prepared_publication(prepared)
            if not absence_check(prepared.get("container_identity", {})):
                raise RuntimeError("prepared publication container absence changed")
            output = Path(str(prepared["official_output"]))
            try:
                output.lstat()
            except FileNotFoundError:
                os.link(Path(str(prepared["candidate_path"])), output,
                        follow_symlinks=False)
            # This fsync is unconditional.  In particular, recovery from a
            # crash after link(2) but before the first directory fsync cannot
            # infer durability merely because the official name now exists.
            _fsync_directory(output.parent)
            pair = _verify_published_pair(
                Path(str(prepared["candidate_path"])), output,
                attempt=attempt, expected_data=data,
                expected_sha256=str(prepared["candidate_sha256"]),
            )
            append_history_v2(root, {
                "attempt": attempt,
                "event": "attempt_finished",
                "disposition": "accepted",
                "reason": "recovered_durable_receipt_publication",
                "attempt_nonce": prepared.get("attempt_nonce"),
                "receipt_path": os.fspath(output),
                "receipt_sha256": prepared["candidate_sha256"],
                "receipt_core_sha256": prepared["receipt_core_sha256"],
                "artifact_manifest_sha256": prepared["artifact_manifest_sha256"],
                "publication_pair": pair,
                "teardown": {"container_absent": True},
            })
        except (KeyError, OSError, RuntimeError, TypeError, ValueError) as error:
            append_history_v2(root, {
                "attempt": attempt,
                "event": "attempt_finished",
                "disposition": "rejected",
                "reason": f"publication_recovery_failed:{type(error).__name__}",
                "attempt_nonce": prepared.get("attempt_nonce"),
                "teardown": {"container_absent": None},
            })
            raise


def verify_published_acceptance(
    root: Path,
    output: Path,
    attempt: str,
    receipt_sha256: str,
    *,
    absence_check=prove_publication_container_absence,
) -> bool:
    try:
        rows = read_history_v2(root)
    except (OSError, RuntimeError, TypeError, ValueError):
        return False
    try:
        matching_rows = [row for row in rows
                         if row["event"].get("attempt") == attempt]
        matching = [row["event"] for row in matching_rows]
        if (len(matching) != 3
                or [event.get("event") for event in matching] != [
                    "attempt_started", "publication_prepared", "attempt_finished"
                ]):
            return False
        started, prepared, finished = matching
        nonce = started.get("attempt_nonce")
        if (type(nonce) is not str or len(nonce) != 64
                or prepared.get("attempt_nonce") != nonce
                or finished.get("attempt_nonce") != nonce
                or finished.get("disposition") != "accepted"
                or finished.get("receipt_path") != os.fspath(output)
                or finished.get("receipt_sha256") != receipt_sha256
                or finished.get("receipt_core_sha256")
                != prepared.get("receipt_core_sha256")
                or finished.get("artifact_manifest_sha256")
                != prepared.get("artifact_manifest_sha256")
                or finished.get("teardown") != {"container_absent": True}):
            return False
        data = _verify_prepared_publication(prepared)
        if (hashlib.sha256(data).hexdigest() != receipt_sha256
                or prepared.get("candidate_sha256") != receipt_sha256
                or not absence_check(prepared.get("container_identity", {}))):
            return False
        pair = _verify_published_pair(
            Path(str(prepared["candidate_path"])), output,
            attempt=attempt, expected_data=data, expected_sha256=receipt_sha256,
        )
        legacy_v43 = (
            attempt == "v43"
            and "publication_pair" not in finished
            and hashlib.sha256(compact(matching_rows[-1]) + b"\n").hexdigest()
            == V43_LEGACY_ACCEPTED_EVENT_SHA256
        )
        if finished.get("publication_pair") != pair and not legacy_v43:
            return False
        receipt = json.loads(data)
        publication = receipt.get("publication")
        producer = receipt.get("producer")
        attempt_history = receipt.get("attempt_history")
        prepared_index = rows.index(matching_rows[1])
        expected_prefix = _history_v2_snapshot_rows(rows[:prepared_index])
        initial_manifest = dict(producer.get("manifest", {})) \
            if isinstance(producer, dict) else {}
        initial_manifest["scourge_build_receipt_sha256"] = None
        initial_manifest_sha256 = hashlib.sha256(
            PRODUCER_MANIFEST_DOMAIN + compact(initial_manifest)
        ).hexdigest()
        absence_sha256 = hashlib.sha256(compact({
            "container_absent": True,
            "identity": prepared.get("container_identity"),
        })).hexdigest()
        if (not isinstance(publication, dict)
                or not isinstance(producer, dict)
                or not isinstance(producer.get("manifest"), dict)
                or started.get("producer_revision")
                != producer["manifest"].get("git_commit")
                or started.get("producer_manifest_sha256")
                != initial_manifest_sha256
                or not isinstance(attempt_history, dict)
                or attempt_history.get("v2_backward_prefix") != expected_prefix
                or publication.get("journal_prefix_sha256")
                != expected_prefix["event_manifest_sha256"]
                or publication.get("artifact_manifest_sha256")
                != prepared.get("artifact_manifest_sha256")
                or publication.get("receipt_core_sha256")
                != prepared.get("receipt_core_sha256")
                or publication.get("container_absence_sha256")
                != absence_sha256
                or publication.get("container_identity")
                != prepared.get("container_identity")):
            return False
    except (KeyError, OSError, RuntimeError, TypeError, ValueError):
        return False
    return True


def run(command, *, timeout=90, check=True, environment=None, input_data=None, cwd=None):
    completed = subprocess.run(command, check=False, capture_output=True, timeout=timeout,
                               env=environment, input=input_data, cwd=cwd)
    if check and completed.returncode:
        raise RuntimeError(
            f"command failed ({completed.returncode}): {command[0]}: "
            f"{completed.stderr.decode(errors='replace')}"
        )
    return completed


def response_sse(attempt: int, poll_session: int | None) -> bytes:
    if attempt == 0:
        item = {
            "id": "fc_bn6zcm_protected_prep", "type": "function_call", "status": "completed",
            "name": "exec_command", "call_id": "call_bn6zcm_protected_prep",
            "arguments": json.dumps({"cmd": COMMAND, "workdir": "/workspace",
                                      "yield_time_ms": 30000, "max_output_tokens": 20000},
                                     separators=(",", ":")),
        }
    elif poll_session is not None:
        item = {
            "id": f"fc_bn6zcm_poll_{attempt}", "type": "function_call", "status": "completed",
            "name": "write_stdin", "call_id": f"call_bn6zcm_poll_{attempt}",
            "arguments": json.dumps({"session_id": poll_session, "chars": "",
                                      "yield_time_ms": 30000, "max_output_tokens": 20000},
                                     separators=(",", ":")),
        }
    else:
        item = {
            "id": "msg_bn6zcm_done", "type": "message", "status": "completed",
            "role": "assistant", "content": [{"type": "output_text",
                "text": "protected preparation complete.", "annotations": [], "logprobs": []}],
        }
    output_tokens = 20 if attempt == 0 or poll_session is not None else 5
    response = {
        "id": f"resp_bn6zcm_{attempt}", "object": "response", "created_at": 0,
        "status": "completed", "model": MODEL, "output": [item],
        "usage": {"input_tokens": 32, "input_tokens_details": {"cached_tokens": 0},
                  "output_tokens": output_tokens,
                  "output_tokens_details": {"reasoning_tokens": 0},
                  "total_tokens": 32 + output_tokens},
    }
    rows = [{"type": "response.output_item.done", "output_index": 0, "item": item},
            {"type": "response.completed", "response": response}]
    return b"".join(b"event: " + row["type"].encode() + b"\n" +
                    b"data: " + compact(row) + b"\n\n" for row in rows)


class FakeResponse:
    status = 200

    def __init__(self, attempt: int, poll_session: int | None):
        self.body = response_sse(attempt, poll_session)
        self.offset = 0

    def read(self, amount):
        block = self.body[self.offset:self.offset + amount]
        self.offset += len(block)
        return block

    def getheaders(self):
        return [("Content-Type", "text/event-stream"), ("Content-Encoding", "identity")]


class FakeConnection:
    def __init__(self, attempts: list[dict[str, object]]):
        self.attempts = attempts
        self.attempt = len(attempts)
        self.poll_session = None

    def request(self, method, path, *, body, headers):
        if (method, path) != ("POST", "/v1/responses"):
            raise AssertionError("unexpected offline upstream request")
        if headers.get("Authorization") != f"Bearer {PROVIDER_CANARY.decode()}":
            raise AssertionError("relay authentication source changed")
        value = json.loads(body)
        outputs = [row.get("output") for row in value.get("input", [])
                   if isinstance(row, dict) and row.get("type") == "function_call_output"]
        if outputs:
            latest = outputs[-1]
            if not isinstance(latest, str):
                raise AssertionError("non-text Codex tool result")
            match = re.search(r"Process running with session ID ([1-9][0-9]*)", latest)
            self.poll_session = int(match.group(1)) if match else None
        self.attempts.append({"body_bytes": len(body),
                              "body_sha256": hashlib.sha256(body).hexdigest(),
                              "accept_encoding": headers.get("Accept-Encoding"),
                              "poll_session": self.poll_session})

    def getresponse(self):
        return FakeResponse(self.attempt, self.poll_session)

    def close(self):
        pass


def private_directory(path: Path) -> None:
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        info = path.lstat()
        if (path.is_symlink() or not stat.S_ISDIR(info.st_mode)
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o700
                or path.resolve(strict=True) != path):
            raise RuntimeError(f"existing directory is not private: {path}")


def evidence_root_preflight(path: Path) -> dict[str, object]:
    resolved = path.resolve(strict=True)
    if resolved != path or path.is_symlink():
        raise RuntimeError("qualification evidence root is not an ordinary resolved path")
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700
            or info.st_uid != os.geteuid()):
        raise RuntimeError("qualification evidence root is not private")
    mount = None
    for line in Path("/proc/self/mountinfo").read_text(encoding="ascii").splitlines():
        left, right = line.split(" - ", 1)
        fields, tail = left.split(), right.split()
        mountpoint = Path(fields[4].replace("\\040", " "))
        try:
            resolved.relative_to(mountpoint)
        except ValueError:
            continue
        if mount is None or len(mountpoint.parts) > len(Path(mount[0]).parts):
            mount = (os.fspath(mountpoint), tail[0], tail[1])
    if mount is None:
        raise RuntimeError("qualification evidence filesystem is unresolved")
    filesystem = os.statvfs(path)
    return {
        "absolute_root": os.fspath(path),
        "owner_uid": info.st_uid,
        "owner_gid": info.st_gid,
        "mode": f"{stat.S_IMODE(info.st_mode):04o}",
        "device": info.st_dev,
        "inode": info.st_ino,
        "ordinary_directory": True,
        "symlink": False,
        "filesystem_type": mount[1],
        "filesystem_source": mount[2],
        "mountpoint": mount[0],
        "total_bytes": filesystem.f_frsize * filesystem.f_blocks,
        "free_bytes": filesystem.f_frsize * filesystem.f_bfree,
        "available_bytes": filesystem.f_frsize * filesystem.f_bavail,
    }


def stage_exact(source: Path, destination: Path, expected: str) -> dict[str, object]:
    if source.resolve(strict=True) != source or not source.is_file() or digest(source) != expected:
        raise RuntimeError(f"exact executable pin changed: {source}")
    shutil.copyfile(source, destination)
    destination.chmod(0o500)
    if digest(destination) != expected:
        raise RuntimeError("staged executable changed")
    return {"source": os.fspath(source), "sha256": expected, "bytes": source.stat().st_size}


def _write_private(path: Path, data: bytes, mode: int = 0o600) -> None:
    fd = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        mode,
    )
    try:
        offset = 0
        while offset < len(data):
            written = os.write(fd, data[offset:])
            if written <= 0:
                raise RuntimeError(f"short private write: {path}")
            offset += written
        os.fsync(fd)
    finally:
        os.close(fd)


def retain_legacy_dispatch_failure(source: Path, control: Path) -> dict[str, object]:
    descriptor = os.open(source, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        data = b""
        while len(data) < info.st_size:
            block = os.read(descriptor, min(1 << 20, info.st_size - len(data)))
            if not block:
                break
            data += block
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or _fstat_row(info) != _fstat_row(after)
            or hashlib.sha256(data).hexdigest() != V36_DISPATCH_FAILURE_SHA256
            or b"syntax error near unexpected token" not in data
            or not data.rstrip().endswith(b"exit code 2")):
        raise RuntimeError("legacy v36 dispatch failure evidence changed")
    retained = control / "legacy-v36-dispatch-failure.log"
    _write_private(retained, data)
    return {
        "schema": "scourge.skeleton-external-dispatch-failure.v1",
        "attempt": "v36",
        "scope": "pre-authenticated-bootstrap-non-authoritative-just-launcher",
        "journal_scope": "excluded-from-post-bootstrap-v2-history",
        "command_retained_verbatim": True,
        "exit_code": 2,
        "reason": "shell_syntax_error_before_bootstrap",
        "container_state": "unknown_not_fabricated",
        "source_sha256": V36_DISPATCH_FAILURE_SHA256,
        "retained": {
            "path": "control/legacy-v36-dispatch-failure.log",
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        },
    }


def retain_v37_method_rejection(
    prior_receipt: Path, control: Path
) -> dict[str, object]:
    """Retain the exact formerly accepted receipt and raw trace as rejected evidence."""

    receipt_data, receipt_info = _held_bytes(prior_receipt)
    trace_path = prior_receipt.with_suffix(
        prior_receipt.suffix + ".artifacts"
    ) / "control/scourge-build.execve"
    trace_data, trace_info = _held_bytes(trace_path)
    try:
        prior = json.loads(receipt_data)
        old_trace = prior["scourge_build"]["receipt"]["exec_trace"]
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise RuntimeError("v37 rejected receipt is malformed") from error
    if (prior_receipt.name != "bn-6zcm-native-qualification-v37.json"
            or hashlib.sha256(receipt_data).hexdigest() != V37_RECEIPT_SHA256
            or hashlib.sha256(trace_data).hexdigest() != V37_BUILD_TRACE_SHA256
            or receipt_info.st_uid != os.geteuid() or trace_info.st_uid != os.geteuid()
            or stat.S_IMODE(receipt_info.st_mode) != 0o600
            or stat.S_IMODE(trace_info.st_mode) != 0o600
            or receipt_info.st_nlink != 1 or trace_info.st_nlink != 1
            or prior.get("valid") is not True
            or old_trace.get("successful_execs") != 230
            or old_trace.get("unique_execs", 18) != 18
            or old_trace.get("bytes") != len(trace_data)
            or b"<unfinished ...>" not in trace_data
            or b"--- SIG" not in trace_data):
        raise RuntimeError("v37 rejected method evidence changed")
    retained_receipt = control / "rejected-v37-receipt.json"
    retained_trace = control / "rejected-v37-build-exec.strace"
    _write_private(retained_receipt, receipt_data)
    _write_private(retained_trace, trace_data)
    return {
        "schema": "scourge.skeleton-external-method-rejection.v1",
        "attempt": "v37", "disposition": "rejected",
        "reason": "build_exec_trace_incomplete_and_non_exhaustive",
        "former_projection": {"successful_execs": 230, "unique_execs": 18},
        "exhaustive_audit": {
            "successful_execs": 269, "unique_execs": 25,
            "split_successful_execs": 39,
            "omitted_unique_build_scripts": list(V37_OMITTED_BUILD_SCRIPTS),
            "omitted_unique_count": len(V37_OMITTED_BUILD_SCRIPTS),
            "signal_lines_also_refused_by_current_parser": True,
        },
        "retained_receipt": {"path": "control/rejected-v37-receipt.json",
            "bytes": len(receipt_data), "sha256": V37_RECEIPT_SHA256},
        "retained_raw_trace": {"path": "control/rejected-v37-build-exec.strace",
            "bytes": len(trace_data), "sha256": V37_BUILD_TRACE_SHA256},
    }


def retain_v38_method_rejection(
    evidence_root: Path, control: Path
) -> dict[str, object]:
    """Retain the exact fail-closed detached-record build trace from v38."""

    trace_path = evidence_root / (
        "bn-6zcm-native-qualification-v38.json.artifacts/control/"
        "scourge-build.execve"
    )
    trace_data, trace_info = _held_bytes(trace_path)
    detached = [line for line in trace_data.decode("utf-8", errors="strict").splitlines()
                if line.endswith("???( <detached ...>")]
    if (hashlib.sha256(trace_data).hexdigest() != V38_BUILD_TRACE_SHA256
            or len(trace_data) != V38_BUILD_TRACE_BYTES
            or trace_info.st_uid != os.geteuid()
            or stat.S_IMODE(trace_info.st_mode) != 0o600
            or trace_info.st_nlink != 1
            or detached != [
                "1434187 1795728533.402532 ???( <detached ...>",
                "1434251 1795728533.485591 ???( <detached ...>",
            ]):
        raise RuntimeError("v38 rejected method evidence changed")
    try:
        parse_build_exec_trace(trace_data)
    except RuntimeError as error:
        if str(error) != "unexpected build exec trace record":
            raise RuntimeError("v38 refusal reason changed") from error
    else:
        raise RuntimeError("v38 detached trace unexpectedly accepted")
    retained_trace = control / "rejected-v38-build-exec.strace"
    _write_private(retained_trace, trace_data)
    return {
        "schema": "scourge.skeleton-external-method-rejection.v1",
        "attempt": "v38", "disposition": "rejected",
        "reason": "strace_detached_record_is_unresolved_trace_loss",
        "detached_records": detached,
        "container_absence": "unknown_in_immutable_attempt_event",
        "independent_absence_corroboration": "reported_separately_not_folded_in",
        "retained_raw_trace": {"path": "control/rejected-v38-build-exec.strace",
            "bytes": len(trace_data), "sha256": V38_BUILD_TRACE_SHA256},
    }


def _fstat_row(info: os.stat_result) -> dict[str, object]:
    return {
        "device": info.st_dev, "inode": info.st_ino,
        "mode": f"{stat.S_IMODE(info.st_mode):04o}",
        "link_count": info.st_nlink, "owner_uid": info.st_uid,
        "owner_gid": info.st_gid, "bytes": info.st_size,
        "mtime_ns": info.st_mtime_ns, "ctime_ns": info.st_ctime_ns,
    }


def _tool_identity(path: str, version_arguments: list[str]) -> dict[str, object]:
    requested = Path(path)
    requested_info = requested.lstat()
    resolved = requested.resolve(strict=True)
    info = resolved.stat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
            or stat.S_IMODE(info.st_mode) & 0o022):
        raise RuntimeError(f"unsafe build tool: {path}")
    version = subprocess.run(
        [path, *version_arguments], check=True, stdin=subprocess.DEVNULL,
        capture_output=True,
        env={"HOME": "/", "PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"},
    )
    return {
        "requested": path, "resolved": os.fspath(resolved),
        "requested_symlink": stat.S_ISLNK(requested_info.st_mode),
        "requested_target": os.readlink(requested) if stat.S_ISLNK(requested_info.st_mode) else None,
        "sha256": digest(resolved), "fstat": _fstat_row(info),
        "version_argv": [path, *version_arguments],
        "version_stdout": version.stdout.decode("utf-8", errors="strict"),
        "version_stderr": version.stderr.decode("utf-8", errors="strict"),
    }


def _held_bytes(path: Path) -> tuple[bytes, os.stat_result]:
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise RuntimeError(f"non-regular build input: {path}")
        blocks = []
        while True:
            block = os.read(fd, 1 << 20)
            if not block:
                break
            blocks.append(block)
        after = os.fstat(fd)
    finally:
        os.close(fd)
    if _fstat_row(before) != _fstat_row(after):
        raise RuntimeError(f"build input changed while hashing: {path}")
    data = b"".join(blocks)
    if len(data) != before.st_size:
        raise RuntimeError(f"short build input read: {path}")
    return data, before


def _tree_manifest(root: Path) -> list[dict[str, object]]:
    """Return a complete no-symlink manifest rooted at one canonical directory."""

    if root.resolve(strict=True) != root or not root.is_dir():
        raise RuntimeError(f"non-canonical manifest root: {root}")
    rows: list[dict[str, object]] = []
    for directory, names, files in os.walk(root, topdown=True, followlinks=False):
        base = Path(directory)
        names.sort()
        files.sort()
        info = base.lstat()
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise RuntimeError(f"unsafe build directory: {base}")
        relative = base.relative_to(root).as_posix() or "."
        rows.append({"path": relative, "kind": "directory",
                     "mode": f"{stat.S_IMODE(info.st_mode):04o}"})
        for name in names:
            candidate = base / name
            child = candidate.lstat()
            if not stat.S_ISDIR(child.st_mode) or stat.S_ISLNK(child.st_mode):
                raise RuntimeError(f"unsafe build tree child: {candidate}")
        for name in files:
            candidate = base / name
            data, child = _held_bytes(candidate)
            rows.append({
                "path": candidate.relative_to(root).as_posix(), "kind": "file",
                "mode": f"{stat.S_IMODE(child.st_mode):04o}", "bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            })
    return rows


def _copy_toolchain(source: Path, destination: Path) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    """Copy one fully manifested toolchain into a private read-only tree."""

    source_before = _tree_manifest(source)
    source_files = {row["path"]: row for row in source_before if row["kind"] == "file"}
    for row in source_before:
        if row["path"] == ".":
            continue
        target = destination / str(row["path"])
        if row["kind"] == "directory":
            target.mkdir(mode=0o700)
            continue
        data, _info = _held_bytes(source / str(row["path"]))
        expected = source_files[str(row["path"])]
        if (len(data) != expected["bytes"]
                or hashlib.sha256(data).hexdigest() != expected["sha256"]):
            raise RuntimeError(f"toolchain changed during copy: {row['path']}")
        mode = 0o500 if int(str(row["mode"]), 8) & 0o111 else 0o400
        _write_private(target, data, mode)
    for directory, _names, _files in os.walk(destination, topdown=False):
        Path(directory).chmod(0o500)
    source_after = _tree_manifest(source)
    private_rows = _tree_manifest(destination)
    if source_before != source_after:
        raise RuntimeError("Rust toolchain changed while it was copied")
    expected_private = []
    for row in source_before:
        expected = dict(row)
        if row["kind"] == "directory":
            expected["mode"] = "0500"
        else:
            expected["mode"] = "0500" if int(str(row["mode"]), 8) & 0o111 else "0400"
        expected_private.append(expected)
    if private_rows != expected_private:
        raise RuntimeError("private Rust toolchain differs from held source manifest")
    return source_before, private_rows


def _safe_crate_members(data: bytes, package_root: str) -> list[tuple[str, int, bytes | None]]:
    rows: list[tuple[str, int, bytes | None]] = []
    seen: set[str] = set()
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as bundle:
        for member in bundle.getmembers():
            pure = Path(member.name)
            if (pure.is_absolute() or ".." in pure.parts or not pure.parts
                    or pure.parts[0] != package_root or member.name in seen
                    or not (member.isdir() or member.isfile())):
                raise RuntimeError(f"unsafe crate archive member: {member.name}")
            seen.add(member.name)
            relative = Path(*pure.parts[1:]).as_posix()
            if not relative or relative == ".":
                if not member.isdir():
                    raise RuntimeError("crate root must be a directory")
                continue
            stream = bundle.extractfile(member) if member.isfile() else None
            payload = stream.read() if stream is not None else None
            rows.append((relative, member.mode & 0o7777, payload))
    return rows


def _vendor_locked_archives(
    lock_path: Path, cache_root: Path, vendor_root: Path, archive_root: Path
) -> dict[str, object]:
    """Verify Cargo.lock archives and construct one private directory source."""

    lock_data, _lock_info = _held_bytes(lock_path)
    lock = tomllib.loads(lock_data.decode("utf-8"))
    packages = [row for row in lock.get("package", [])
                if str(row.get("source", "")).startswith("registry+")]
    if not packages:
        raise RuntimeError("Cargo.lock contains no registry packages")
    archives: list[dict[str, object]] = []
    files: list[dict[str, object]] = []
    identities: set[tuple[str, str]] = set()
    for package in sorted(packages, key=lambda row: (str(row["name"]), str(row["version"]))):
        name, version = str(package["name"]), str(package["version"])
        checksum = package.get("checksum")
        identity = (name, version)
        if (identity in identities or not isinstance(checksum, str)
                or re.fullmatch(r"[0-9a-f]{64}", checksum) is None
                or package.get("source") != "registry+https://github.com/rust-lang/crates.io-index"):
            raise RuntimeError(f"unsupported locked registry package: {identity!r}")
        identities.add(identity)
        candidates = sorted(cache_root.glob(f"*/{name}-{version}.crate"))
        if len(candidates) != 1:
            raise RuntimeError(f"expected one cached archive for {name}-{version}")
        archive = candidates[0]
        data, info = _held_bytes(archive)
        actual = hashlib.sha256(data).hexdigest()
        if actual != checksum:
            raise RuntimeError(f"cached crate checksum mismatch: {name}-{version}")
        package_name = f"{name}-{version}"
        retained_archive = archive_root / f"{package_name}.crate"
        _write_private(retained_archive, data, 0o400)
        destination = vendor_root / package_name
        destination.mkdir(mode=0o700)
        package_files: dict[str, str] = {}
        for relative, mode, payload in _safe_crate_members(data, package_name):
            target = destination / relative
            if payload is None:
                target.mkdir(parents=True, exist_ok=True, mode=0o700)
                continue
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            if target.exists():
                raise RuntimeError(f"duplicate crate output: {package_name}/{relative}")
            _write_private(target, payload, 0o500 if mode & 0o111 else 0o400)
            package_files[relative] = hashlib.sha256(payload).hexdigest()
            files.append({"package": package_name, "path": relative,
                          "bytes": len(payload), "sha256": package_files[relative]})
        checksum_bytes = compact({"files": package_files, "package": checksum})
        _write_private(destination / ".cargo-checksum.json", checksum_bytes, 0o400)
        files.append({"package": package_name, "path": ".cargo-checksum.json",
                      "bytes": len(checksum_bytes),
                      "sha256": hashlib.sha256(checksum_bytes).hexdigest()})
        for directory, _names, _children in os.walk(destination, topdown=False):
            Path(directory).chmod(0o500)
        archives.append({
            "name": name, "version": version, "lock_checksum": checksum,
            "archive_name": archive.name, "archive_bytes": len(data),
            "archive_sha256": actual, "source_fstat": _fstat_row(info),
            "retained_path": f"build-crate-archives/{package_name}.crate",
        })
    files.sort(key=lambda row: (str(row["package"]), str(row["path"])))
    private_manifest = _tree_manifest(vendor_root)
    return {
        "archives": archives, "files": files,
        "files_sha256": hashlib.sha256(compact(files)).hexdigest(),
        "private_manifest": private_manifest,
        "private_manifest_sha256": hashlib.sha256(compact(private_manifest)).hexdigest(),
        "lock_sha256": hashlib.sha256(lock_data).hexdigest(),
    }


def _external_tool_candidates() -> dict[str, dict[str, object]]:
    requested = [Path(path) for path in (
        "/usr/bin/cc", "/usr/bin/gcc", "/usr/bin/ld", "/usr/bin/as",
        "/usr/bin/ar", "/usr/bin/strip", "/bin/sh", "/usr/bin/env",
        "/usr/bin/pkg-config", "/usr/bin/cmake", "/usr/bin/make",
        "/usr/bin/ninja", "/usr/bin/perl", "/usr/bin/python3",
    )]
    requested.extend(sorted(
        path for path in Path("/usr/lib/gcc").glob("*/*/*") if path.is_file()
    ))
    requested.extend(sorted(Path("/usr/bin").glob("x86_64-linux-gnu-*")))
    result: dict[str, dict[str, object]] = {}
    for path in requested:
        try:
            resolved = path.resolve(strict=True)
            info = resolved.stat()
        except FileNotFoundError:
            continue
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                or stat.S_IMODE(info.st_mode) & 0o022
                or not stat.S_IMODE(info.st_mode) & 0o111):
            continue
        row = {"requested": os.fspath(path), "resolved": os.fspath(resolved),
               "sha256": digest(resolved), "fstat": _fstat_row(info)}
        result[os.fspath(path)] = row
        result[os.fspath(resolved)] = row
    return result


def _open_directory_beneath(root_descriptor: int, components: list[str]) -> int:
    descriptor = os.dup(root_descriptor)
    try:
        for component in components:
            if (not component or component in {".", ".."}
                    or "/" in component or "\0" in component):
                raise RuntimeError("unsafe Cargo output path")
            before = os.stat(
                component, dir_fd=descriptor, follow_symlinks=False
            )
            child = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=descriptor,
            )
            if (not stat.S_ISDIR(before.st_mode)
                    or _fstat_row(before) != _fstat_row(os.fstat(child))):
                os.close(child)
                raise RuntimeError("Cargo output directory changed")
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_file_beneath(
    root_descriptor: int, relative: str
) -> tuple[int, os.stat_result]:
    parts = relative.split("/")
    parent = _open_directory_beneath(root_descriptor, parts[:-1])
    try:
        before = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
        descriptor = os.open(
            parts[-1], os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=parent,
        )
        if (not stat.S_ISREG(before.st_mode)
                or _fstat_row(before) != _fstat_row(os.fstat(descriptor))):
            os.close(descriptor)
            raise RuntimeError("Cargo output file changed")
        return descriptor, before
    finally:
        os.close(parent)


def _hash_open_file(
    descriptor: int, expected: os.stat_result, *, retain: bool = False
) -> tuple[str, bytes | None, os.stat_result]:
    os.lseek(descriptor, 0, os.SEEK_SET)
    hasher = hashlib.sha256()
    blocks = [] if retain else None
    byte_count = 0
    while byte_count < expected.st_size:
        block = os.read(descriptor, min(1 << 20, expected.st_size - byte_count))
        if not block:
            break
        hasher.update(block)
        byte_count += len(block)
        if blocks is not None:
            blocks.append(block)
    after = os.fstat(descriptor)
    if (byte_count != expected.st_size
            or _fstat_row(expected) != _fstat_row(after)):
        raise RuntimeError("Cargo output changed while hashing")
    return hasher.hexdigest(), b"".join(blocks) if blocks is not None else None, after


def _target_inode_aliases(
    root_descriptor: int, device: int, inode: int
) -> list[str]:
    aliases: list[str] = []

    def walk(directory_descriptor: int, prefix: str) -> None:
        directory_before = os.fstat(directory_descriptor)
        for name in sorted(os.listdir(directory_descriptor)):
            if (not isinstance(name, str) or not name or name in {".", ".."}
                    or "/" in name or "\0" in name):
                raise RuntimeError("unsafe Cargo target path")
            relative = name if not prefix else f"{prefix}/{name}"
            before = os.stat(
                name, dir_fd=directory_descriptor, follow_symlinks=False
            )
            if stat.S_ISDIR(before.st_mode) and not stat.S_ISLNK(before.st_mode):
                child = os.open(
                    name,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                    dir_fd=directory_descriptor,
                )
                try:
                    if _fstat_row(before) != _fstat_row(os.fstat(child)):
                        raise RuntimeError("Cargo target directory changed")
                    walk(child, relative)
                    if _fstat_row(before) != _fstat_row(os.fstat(child)):
                        raise RuntimeError("Cargo target directory changed")
                finally:
                    os.close(child)
            elif stat.S_ISREG(before.st_mode):
                if before.st_dev == device and before.st_ino == inode:
                    aliases.append(relative)
            else:
                raise RuntimeError("unsafe Cargo target entry")
        if _fstat_row(directory_before) != _fstat_row(os.fstat(directory_descriptor)):
            raise RuntimeError("Cargo target directory changed")

    walk(root_descriptor, "")
    return sorted(aliases)


def dealias_cargo_scourge_output(target: Path) -> dict[str, object]:
    """Break only Cargo's exact two-name final-output hard link."""

    if not target.is_absolute() or target.resolve(strict=True) != target:
        raise RuntimeError("unsafe Cargo target root")
    root_descriptor = os.open(
        target, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    )
    primary_descriptor = alias_descriptor = debug_descriptor = None
    temp_name = ".scourge.dealias.tmp"
    replaced = False
    try:
        primary_descriptor, primary_before = _open_file_beneath(
            root_descriptor, CARGO_OUTPUT_PATH
        )
        alias_descriptor, alias_before = _open_file_beneath(
            root_descriptor, CARGO_OUTPUT_ALIAS_PATH
        )
        if (primary_before.st_dev != alias_before.st_dev
                or primary_before.st_ino != alias_before.st_ino
                or primary_before.st_nlink != 2 or alias_before.st_nlink != 2
                or primary_before.st_uid != os.geteuid()
                or stat.S_IMODE(primary_before.st_mode) != 0o700
                or _fstat_row(primary_before) != _fstat_row(alias_before)):
            raise RuntimeError("unexpected Cargo output hard-link identity")
        primary_sha256, binary, _primary_after = _hash_open_file(
            primary_descriptor, primary_before, retain=True
        )
        alias_sha256, _unused, _alias_after = _hash_open_file(
            alias_descriptor, alias_before
        )
        if binary is None or alias_sha256 != primary_sha256:
            raise RuntimeError("Cargo output hard-link digest mismatch")
        aliases_before = _target_inode_aliases(
            root_descriptor, primary_before.st_dev, primary_before.st_ino
        )
        expected_paths = sorted([CARGO_OUTPUT_PATH, CARGO_OUTPUT_ALIAS_PATH])
        if aliases_before != expected_paths:
            raise RuntimeError("unexpected Cargo output hard-link aliases")

        debug_descriptor = _open_directory_beneath(root_descriptor, ["debug"])
        temp_descriptor = os.open(
            temp_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o500,
            dir_fd=debug_descriptor,
        )
        try:
            offset = 0
            while offset < len(binary):
                written = os.write(temp_descriptor, binary[offset:offset + (1 << 20)])
                if written <= 0:
                    raise RuntimeError("short Cargo output de-alias write")
                offset += written
            os.fchmod(temp_descriptor, 0o500)
            os.fsync(temp_descriptor)
            temp_info = os.fstat(temp_descriptor)
            if (not stat.S_ISREG(temp_info.st_mode)
                    or temp_info.st_uid != os.geteuid()
                    or stat.S_IMODE(temp_info.st_mode) != 0o500
                    or temp_info.st_nlink != 1 or temp_info.st_size != len(binary)):
                raise RuntimeError("unsafe Cargo output de-alias temporary")
        finally:
            os.close(temp_descriptor)

        check_primary, check_primary_info = _open_file_beneath(
            root_descriptor, CARGO_OUTPUT_PATH
        )
        check_alias, check_alias_info = _open_file_beneath(
            root_descriptor, CARGO_OUTPUT_ALIAS_PATH
        )
        try:
            if (_fstat_row(check_primary_info) != _fstat_row(primary_before)
                    or _fstat_row(check_alias_info) != _fstat_row(alias_before)):
                raise RuntimeError("Cargo output changed before de-alias replace")
        finally:
            os.close(check_primary)
            os.close(check_alias)
        os.replace(
            temp_name, "scourge", src_dir_fd=debug_descriptor,
            dst_dir_fd=debug_descriptor,
        )
        replaced = True
        os.fsync(debug_descriptor)

        post_primary_descriptor, primary_post = _open_file_beneath(
            root_descriptor, CARGO_OUTPUT_PATH
        )
        post_alias_descriptor, alias_post = _open_file_beneath(
            root_descriptor, CARGO_OUTPUT_ALIAS_PATH
        )
        try:
            primary_post_sha256, _unused, _ = _hash_open_file(
                post_primary_descriptor, primary_post
            )
            alias_post_sha256, _unused, _ = _hash_open_file(
                post_alias_descriptor, alias_post
            )
        finally:
            os.close(post_primary_descriptor)
            os.close(post_alias_descriptor)
        if (primary_post.st_ino == alias_post.st_ino
                or primary_post.st_nlink != 1 or alias_post.st_nlink != 1
                or primary_post.st_uid != os.geteuid()
                or alias_post.st_uid != os.geteuid()
                or stat.S_IMODE(primary_post.st_mode) != 0o500
                or stat.S_IMODE(alias_post.st_mode) != 0o700
                or primary_post.st_size != alias_post.st_size
                or primary_post_sha256 != primary_sha256
                or alias_post_sha256 != primary_sha256
                or _target_inode_aliases(
                    root_descriptor, primary_post.st_dev, primary_post.st_ino
                ) != [CARGO_OUTPUT_PATH]
                or _target_inode_aliases(
                    root_descriptor, alias_post.st_dev, alias_post.st_ino
                ) != [CARGO_OUTPUT_ALIAS_PATH]):
            raise RuntimeError("Cargo output de-alias verification failed")
        row: dict[str, object] = {
            "schema": "scourge.skeleton-cargo-output-dealias.v1",
            "operation": "o_excl-copy-fsync-atomic-replace-primary-fsync-parent",
            "primary_path": f"build-target/{CARGO_OUTPUT_PATH}",
            "alias_path": f"build-target/{CARGO_OUTPUT_ALIAS_PATH}",
            "sha256": primary_sha256, "bytes": len(binary),
            "aliases_before": [f"build-target/{path}" for path in aliases_before],
            "pre": {
                "primary": _fstat_row(primary_before),
                "alias": _fstat_row(alias_before),
            },
            "post": {
                "primary": _fstat_row(primary_post),
                "alias": _fstat_row(alias_post),
            },
            "temporary_mode": "0500", "parent_directory_fsynced": True,
        }
        row["domain_sha256"] = hashlib.sha256(
            BUILD_DEALIAS_DOMAIN + compact(row)
        ).hexdigest()
        return row
    finally:
        if debug_descriptor is not None:
            if not replaced:
                try:
                    os.unlink(temp_name, dir_fd=debug_descriptor)
                except FileNotFoundError:
                    pass
            os.close(debug_descriptor)
        if primary_descriptor is not None:
            os.close(primary_descriptor)
        if alias_descriptor is not None:
            os.close(alias_descriptor)
        os.close(root_descriptor)


def verify_cargo_output_dealias(
    target: Path, receipt: Mapping[str, object]
) -> bool:
    try:
        row = dict(receipt)
        domain_sha256 = row.pop("domain_sha256")
        expected_fields = {
            "schema", "operation", "primary_path", "alias_path", "sha256",
            "bytes", "aliases_before", "pre", "post", "temporary_mode",
            "parent_directory_fsynced",
        }
        fstat_fields = {
            "device", "inode", "mode", "link_count", "owner_uid",
            "owner_gid", "bytes", "mtime_ns", "ctime_ns",
        }
        pre = row["pre"]
        post = row["post"]
        if (set(row) != expected_fields
                or not isinstance(pre, dict) or set(pre) != {"primary", "alias"}
                or not isinstance(post, dict) or set(post) != {"primary", "alias"}
                or not all(
                    isinstance(value, dict) and set(value) == fstat_fields
                    for value in (*pre.values(), *post.values())
                )
                or pre["primary"] != pre["alias"]
                or pre["primary"]["mode"] != "0700"
                or pre["primary"]["link_count"] != 2
                or pre["primary"]["owner_uid"] != os.geteuid()
                or pre["primary"]["bytes"] != row["bytes"]
                or not isinstance(row["bytes"], int) or row["bytes"] <= 0
                or not isinstance(row["sha256"], str)
                or re.fullmatch(r"[0-9a-f]{64}", row["sha256"]) is None
                or hashlib.sha256(BUILD_DEALIAS_DOMAIN + compact(row)).hexdigest()
                != domain_sha256
                or row["schema"] != "scourge.skeleton-cargo-output-dealias.v1"
                or row["operation"]
                != "o_excl-copy-fsync-atomic-replace-primary-fsync-parent"
                or row["primary_path"] != f"build-target/{CARGO_OUTPUT_PATH}"
                or row["alias_path"] != f"build-target/{CARGO_OUTPUT_ALIAS_PATH}"
                or row["aliases_before"] != [
                    f"build-target/{path}" for path in sorted(
                        [CARGO_OUTPUT_PATH, CARGO_OUTPUT_ALIAS_PATH]
                    )
                ]
                or row["temporary_mode"] != "0500"
                or row["parent_directory_fsynced"] is not True):
            return False
        root_descriptor = os.open(
            target, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
        )
        try:
            primary_descriptor, primary = _open_file_beneath(
                root_descriptor, CARGO_OUTPUT_PATH
            )
            alias_descriptor, alias = _open_file_beneath(
                root_descriptor, CARGO_OUTPUT_ALIAS_PATH
            )
            try:
                primary_sha256, _unused, _ = _hash_open_file(
                    primary_descriptor, primary
                )
                alias_sha256, _unused, _ = _hash_open_file(alias_descriptor, alias)
            finally:
                os.close(primary_descriptor)
                os.close(alias_descriptor)
            return bool(
                _fstat_row(primary) == row["post"]["primary"]
                and _fstat_row(alias) == row["post"]["alias"]
                and primary.st_ino != alias.st_ino
                and primary.st_nlink == alias.st_nlink == 1
                and primary.st_uid == alias.st_uid == os.geteuid()
                and stat.S_IMODE(primary.st_mode) == 0o500
                and stat.S_IMODE(alias.st_mode) == 0o700
                and primary.st_size == alias.st_size == row["bytes"]
                and primary_sha256 == alias_sha256 == row["sha256"]
                and _target_inode_aliases(
                    root_descriptor, primary.st_dev, primary.st_ino
                ) == [CARGO_OUTPUT_PATH]
                and _target_inode_aliases(
                    root_descriptor, alias.st_dev, alias.st_ino
                ) == [CARGO_OUTPUT_ALIAS_PATH]
            )
        finally:
            os.close(root_descriptor)
    except (KeyError, OSError, RuntimeError, TypeError, ValueError):
        return False


def isolated_scourge_build(
    args, artifacts: Path, tools: Path, bootstrap: dict[str, object]
) -> tuple[dict[str, object], str]:
    """Build from committed source, lock-checked archives and a private toolchain."""

    source_repo = Path(args.source_repo)
    commit = str(bootstrap["git_commit"])
    tree = str(bootstrap["git_tree"])
    control = artifacts / "control"
    export_root = artifacts / "build-source"
    target = artifacts / "build-target"
    build_tmp = artifacts / "build-tmp"
    vendor = artifacts / "build-vendor"
    archive_root = artifacts / "build-crate-archives"
    toolchain = artifacts / "build-toolchain"
    cargo_home = artifacts / "build-cargo-home"
    build_home = artifacts / "build-home"
    for path in (export_root, target, build_tmp, vendor, archive_root,
                 toolchain, cargo_home, build_home):
        private_directory(path)
    if any(any(path.iterdir()) for path in (
        export_root, target, build_tmp, vendor, archive_root, toolchain,
        cargo_home, build_home,
    )):
        raise RuntimeError("isolated build roots were not empty")

    archive = _git(source_repo, "archive", "--format=tar", commit)
    archive_path = control / "scourge-source.tar"
    _write_private(archive_path, archive)
    export_rows: list[dict[str, object]] = []
    with tarfile.open(archive_path, "r:") as bundle:
        members = bundle.getmembers()
        for member in members:
            path = Path(member.name)
            if (path.is_absolute() or ".." in path.parts
                    or not (member.isdir() or member.isfile())):
                raise RuntimeError(f"unsafe committed archive member: {member.name}")
            destination = export_root / path
            if member.isdir():
                destination.mkdir(parents=True, exist_ok=True, mode=0o700)
                destination.chmod(0o700)
                continue
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            for parent in (destination.parent, *destination.parents):
                if parent == export_root.parent:
                    break
                if parent.is_relative_to(export_root):
                    parent.chmod(0o700)
            extracted = bundle.extractfile(member)
            if extracted is None:
                raise RuntimeError(f"missing committed archive data: {member.name}")
            data = extracted.read()
            _write_private(destination, data, 0o500 if member.mode & 0o111 else 0o400)
            export_rows.append({
                "path": path.as_posix(), "mode": f"{member.mode & 0o7777:04o}",
                "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
            })
    export_rows.sort(key=lambda row: str(row["path"]))
    if not export_rows:
        raise RuntimeError("empty committed source export")
    cargo_inputs = [
        row for row in export_rows
        if row["path"] == "Cargo.lock" or str(row["path"]).endswith("Cargo.toml")
    ]
    if not cargo_inputs or cargo_inputs[0]["path"] != "Cargo.lock":
        raise RuntimeError("committed Cargo inputs missing")

    vendor_full = _vendor_locked_archives(
        export_root / "Cargo.lock", CARGO_REGISTRY_CACHE, vendor, archive_root
    )
    vendor_bytes = compact(vendor_full)
    vendor_manifest_path = control / "cargo-vendor-manifest.json"
    _write_private(vendor_manifest_path, vendor_bytes + b"\n")

    source_toolchain_rows, private_toolchain_rows = _copy_toolchain(
        RUST_TOOLCHAIN, toolchain
    )
    toolchain_full = {
        "source": source_toolchain_rows,
        "private": private_toolchain_rows,
    }
    toolchain_bytes = compact(toolchain_full)
    toolchain_manifest_path = control / "rust-toolchain-manifest.json"
    _write_private(toolchain_manifest_path, toolchain_bytes + b"\n")

    cargo_config = (
        "[source.crates-io]\nreplace-with = \"vendored-sources\"\n"
        "[source.vendored-sources]\ndirectory = "
        + json.dumps(os.fspath(vendor))
        + "\n[net]\noffline = true\n"
    ).encode("utf-8")
    _write_private(cargo_home / "config.toml", cargo_config, 0o400)
    cargo_home_preflight = _tree_manifest(cargo_home)
    if [row["path"] for row in cargo_home_preflight] != [".", "config.toml"]:
        raise RuntimeError("private Cargo home preflight was not config-only")

    private_cargo = toolchain / "bin/cargo"
    private_rustc = toolchain / "bin/rustc"
    version_environment = {
        "HOME": os.fspath(build_home), "CARGO_HOME": os.fspath(cargo_home),
        "PATH": f"{toolchain / 'bin'}:/usr/bin:/bin", "LC_ALL": "C", "LANG": "C",
    }
    tool_versions = {}
    for name, executable in (("cargo", private_cargo), ("rustc", private_rustc)):
        result = subprocess.run(
            [executable, "-Vv"], check=True, stdin=subprocess.DEVNULL,
            capture_output=True, env=version_environment,
        )
        tool_versions[name] = {
            "path": f"build-toolchain/bin/{name}",
            "sha256": digest(executable), "fstat": _fstat_row(executable.stat()),
            "argv": [f"<private-toolchain>/bin/{name}", "-Vv"],
            "stdout": result.stdout.decode("utf-8", errors="strict"),
            "stderr": result.stderr.decode("utf-8", errors="strict"),
        }

    external_before = _external_tool_candidates()
    build_tracer = _tool_identity(STRACE, ["--version"])
    if Path("/.cargo").exists():
        raise RuntimeError("root Cargo configuration search path is not empty")
    environment = {
        "HOME": os.fspath(build_home),
        "PATH": f"{toolchain / 'bin'}:/usr/bin:/bin",
        "CARGO_HOME": os.fspath(cargo_home),
        "CARGO_TARGET_DIR": os.fspath(target),
        "CARGO_BUILD_JOBS": "1",
        "CARGO_NET_OFFLINE": "true", "CARGO_INCREMENTAL": "0",
        "RUSTC": os.fspath(private_rustc),
        "RUSTDOC": os.fspath(toolchain / "bin/rustdoc"),
        "CC": "/usr/bin/cc", "AR": "/usr/bin/ar",
        "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER": "/usr/bin/cc",
        "TMPDIR": os.fspath(build_tmp), "SOURCE_DATE_EPOCH": "0",
        "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
    }
    command = [
        os.fspath(private_cargo), "build", "--manifest-path",
        os.fspath(export_root / "Cargo.toml"), "--offline", "--locked",
        "-p", "scourge", "--bin", "scourge", "--jobs", "1",
    ]
    trace_prefix = control / "scourge-build.execve"
    traced_command = [
        STRACE, "-f", "-qq", "-ttt", "-s", "4096",
        f"--inject=execve:delay_exit={BUILD_TRACE_DELAY_EXIT_MILLISECONDS}ms",
        f"--inject=execveat:delay_exit={BUILD_TRACE_DELAY_EXIT_MILLISECONDS}ms", "-e",
        "trace=execve,execveat", "-e", f"signal={BUILD_TRACE_SIGNALS}",
        "-o", os.fspath(trace_prefix), *command,
    ]
    completed = subprocess.run(
        traced_command, cwd=Path("/"), env=environment, stdin=subprocess.DEVNULL,
        capture_output=True, timeout=1800,
    )
    stdout_path = control / "scourge-build.stdout"
    stderr_path = control / "scourge-build.stderr"
    _write_private(stdout_path, completed.stdout)
    _write_private(stderr_path, completed.stderr)
    if completed.returncode != 0:
        raise RuntimeError(
            f"isolated Scourge build failed ({completed.returncode}): "
            f"{completed.stderr[-4096:].decode(errors='replace')}"
        )
    if _tool_identity(STRACE, ["--version"]) != build_tracer:
        raise RuntimeError("build exec tracer changed during build")

    toolchain_after = _tree_manifest(toolchain)
    vendor_after = _tree_manifest(vendor)
    if toolchain_after != private_toolchain_rows:
        raise RuntimeError("private Rust toolchain changed during build")
    if vendor_after != vendor_full["private_manifest"]:
        raise RuntimeError("private vendored directory source changed during build")

    successful_records: list[dict[str, object]] = []
    trace_rows: list[dict[str, object]] = []
    trace_lines = 0
    trace_bytes = 0
    for trace_path in sorted(control.glob("scourge-build.execve*")):
        trace_data, _trace_info = _held_bytes(trace_path)
        trace_bytes += len(trace_data)
        trace_lines += len(trace_data.splitlines())
        if (trace_bytes > MAX_BUILD_EXEC_TRACE_BYTES
                or trace_lines > MAX_BUILD_EXEC_TRACE_LINES):
            raise RuntimeError("build exec trace exceeded its frozen bound")
        trace_rows.append({
            "path": f"control/{trace_path.name}", "bytes": len(trace_data),
            "sha256": hashlib.sha256(trace_data).hexdigest(),
        })
        successful_records.extend(parse_build_exec_trace(trace_data))
        if len(successful_records) > MAX_BUILD_SUCCESSFUL_EXECS:
            raise RuntimeError("successful build exec count exceeded its frozen bound")
    successful_execs = [str(row["path"]) for row in successful_records]
    if (len(trace_rows) != 1 or not successful_records
            or successful_execs[0] != os.fspath(private_cargo)
            or successful_records[0]["delayed"] is not False
            or any(row["delayed"] is not True for row in successful_records[1:])):
        raise RuntimeError("build exec trace did not begin with private Cargo")

    toolchain_files = {
        str(row["path"]): row for row in private_toolchain_rows if row["kind"] == "file"
    }
    actual_execs: list[dict[str, object]] = []
    for path in dict.fromkeys(successful_execs):
        candidate = Path(path)
        if candidate.is_relative_to(toolchain):
            relative = candidate.relative_to(toolchain).as_posix()
            row = toolchain_files.get(relative)
            if row is None:
                raise RuntimeError(f"unmanifested private toolchain executable: {path}")
            actual_execs.append({"path": f"build-toolchain/{relative}",
                                 "class": "private-toolchain", "identity": row})
            continue
        if candidate.is_relative_to(target):
            data, info = _held_bytes(candidate)
            actual_execs.append({
                "path": f"build-target/{candidate.relative_to(target).as_posix()}",
                "class": "fresh-target-product", "sha256": hashlib.sha256(data).hexdigest(),
                "fstat": _fstat_row(info),
            })
            continue
        before_external = external_before.get(path)
        if before_external is None:
            raise RuntimeError(f"unapproved external build executable: {path}")
        resolved = Path(str(before_external["resolved"]))
        after_external = {"requested": before_external["requested"],
                          "resolved": before_external["resolved"],
                          "sha256": digest(resolved), "fstat": _fstat_row(resolved.stat())}
        if after_external != before_external:
            raise RuntimeError(f"external build executable changed: {path}")
        actual_execs.append({"path": path, "class": "root-external",
                             "identity_before": before_external,
                             "identity_after": after_external})

    dealias_receipt = dealias_cargo_scourge_output(target)
    output = target / CARGO_OUTPUT_PATH
    binary, before = _held_bytes(output)
    after = output.stat()
    if _fstat_row(before) != _fstat_row(after):
        raise RuntimeError("isolated Scourge output changed while hashing")
    staged = tools / "scourge"
    _write_private(staged, binary, 0o500)
    staged_info = staged.stat()
    binary_sha256 = hashlib.sha256(binary).hexdigest()
    if digest(staged) != binary_sha256 or stat.S_IMODE(staged_info.st_mode) != 0o500:
        raise RuntimeError("isolated Scourge staged copy changed")

    receipt = {
        "schema": "scourge.skeleton-scourge-build.v3",
        "git_commit": commit, "git_tree": tree,
        "source_archive": {
            "path": "control/scourge-source.tar", "bytes": len(archive),
            "sha256": hashlib.sha256(archive).hexdigest(),
        },
        "export_manifest": {
            "files": export_rows,
            "sha256": hashlib.sha256(compact(export_rows)).hexdigest(),
        },
        "cargo_inputs": cargo_inputs,
        "vendor": {
            "manifest": {"path": "control/cargo-vendor-manifest.json",
                         "bytes": len(vendor_bytes) + 1,
                         "sha256": hashlib.sha256(vendor_bytes + b"\n").hexdigest()},
            "archive_count": len(vendor_full["archives"]),
            "file_count": len(vendor_full["files"]),
            "lock_sha256": vendor_full["lock_sha256"],
            "private_manifest_sha256": vendor_full["private_manifest_sha256"],
        },
        "toolchain": {
            "manifest": {"path": "control/rust-toolchain-manifest.json",
                         "bytes": len(toolchain_bytes) + 1,
                         "sha256": hashlib.sha256(toolchain_bytes + b"\n").hexdigest()},
            "source": "rustup-toolchain-1.100.0-x86_64-unknown-linux-gnu",
            "source_path": os.fspath(RUST_TOOLCHAIN),
            "source_file_count": sum(row["kind"] == "file" for row in source_toolchain_rows),
            "private_manifest_sha256": hashlib.sha256(
                compact(private_toolchain_rows)
            ).hexdigest(),
            "versions": tool_versions,
        },
        "external_executables": actual_execs,
        "cargo_output_dealias": dealias_receipt,
        "build_tracer": build_tracer,
        "exec_trace": {"schema": BUILD_EXEC_TRACE_SCHEMA,
                       "files": trace_rows, "bytes": trace_bytes,
                       "lines": trace_lines, "successful_execs": len(successful_execs),
                       "delayed_successful_execs": sum(
                           bool(row["delayed"]) for row in successful_records
                       ),
                       "unique_execs": len(dict.fromkeys(successful_execs)),
                       "events_sha256": hashlib.sha256(
                           compact(successful_records)
                       ).hexdigest(),
                       "syscalls": ["execve", "execveat"],
                       "signals": BUILD_TRACE_SIGNALS,
                       "delay_exit_milliseconds": BUILD_TRACE_DELAY_EXIT_MILLISECONDS,
                       "delay_exit_semantics": "timing-only-no-result-injection",
                       "detached_records": "refused",
                       "successful_execveat": "refused",
                       "maximum_bytes": MAX_BUILD_EXEC_TRACE_BYTES,
                       "maximum_lines": MAX_BUILD_EXEC_TRACE_LINES,
                       "maximum_successful_execs": MAX_BUILD_SUCCESSFUL_EXECS},
        "cargo_home": {
            "preflight": cargo_home_preflight,
            "post_build_manifest": _tree_manifest(cargo_home),
            "config_sha256": hashlib.sha256(cargo_config).hexdigest(),
        },
        "command": ["<private-toolchain>/bin/cargo", "build", "--manifest-path",
                    "<private-source>/Cargo.toml", *command[4:]],
        "traced_command": [STRACE, "-f", "-qq", "-ttt", "-s", "4096",
                           "--inject=execve:delay_exit=250ms",
                           "--inject=execveat:delay_exit=250ms",
                           "-e", "trace=execve,execveat", "-e",
                           f"signal={BUILD_TRACE_SIGNALS}",
                           "-o", "<private-exec-trace>",
                           "<private-toolchain>/bin/cargo", "build", "--manifest-path",
                           "<private-source>/Cargo.toml", *command[4:]],
        "environment": {
            key: ("<private-cargo-home>" if key == "CARGO_HOME" else
                  "<private-target>" if key == "CARGO_TARGET_DIR" else
                  "<private-build-tmp>" if key == "TMPDIR" else
                  "<private-build-home>" if key == "HOME" else
                  "<private-toolchain>/bin/rustc" if key == "RUSTC" else
                  "<private-toolchain>/bin/rustdoc" if key == "RUSTDOC" else
                  "<private-toolchain>/bin:/usr/bin:/bin" if key == "PATH" else value)
            for key, value in sorted(environment.items())
        },
        "offline": True, "locked": True, "incremental": False,
        "wrapper": None, "target_preflight_empty": True,
        "working_directory": "/", "root_cargo_config_absent": True,
        "build_log": {
            "stdout": {"path": "control/scourge-build.stdout",
                       "bytes": len(completed.stdout),
                       "sha256": hashlib.sha256(completed.stdout).hexdigest()},
            "stderr": {"path": "control/scourge-build.stderr",
                       "bytes": len(completed.stderr),
                       "sha256": hashlib.sha256(completed.stderr).hexdigest()},
            "exit_code": completed.returncode,
        },
        "output": {
            "source_fstat_before": _fstat_row(before),
            "source_fstat_after": _fstat_row(after),
            "sha256": binary_sha256, "bytes": len(binary),
            "staged_path": "tools/scourge",
            "staged_fstat": _fstat_row(staged_info),
        },
    }
    receipt_sha256 = hashlib.sha256(
        BUILD_RECEIPT_DOMAIN + compact(receipt)
    ).hexdigest()
    _write_private(control / "scourge-build.json", compact(receipt) + b"\n")
    return receipt, receipt_sha256


def verify_build_exec_trace(
    artifacts: Path, trace_receipt: Mapping[str, object]
) -> list[dict[str, object]] | None:
    """Reparse raw trace bytes and reject any receipt projection drift."""

    try:
        files = trace_receipt["files"]
        if not isinstance(files, list) or len(files) != 1:
            return None
        records: list[dict[str, object]] = []
        byte_count = 0
        line_count = 0
        for row in files:
            if not isinstance(row, dict):
                return None
            data = (artifacts / str(row["path"])).read_bytes()
            if (len(data) != row["bytes"]
                    or hashlib.sha256(data).hexdigest() != row["sha256"]):
                return None
            byte_count += len(data)
            line_count += len(data.splitlines())
            records.extend(parse_build_exec_trace(data))
        paths = [str(row["path"]) for row in records]
        if (trace_receipt.get("schema") != BUILD_EXEC_TRACE_SCHEMA
                or byte_count != trace_receipt["bytes"]
                or line_count != trace_receipt["lines"]
                or len(paths) != trace_receipt["successful_execs"]
                or sum(bool(row["delayed"]) for row in records)
                != trace_receipt["delayed_successful_execs"]
                or not records or records[0]["delayed"] is not False
                or any(row["delayed"] is not True for row in records[1:])
                or len(dict.fromkeys(paths)) != trace_receipt["unique_execs"]
                or hashlib.sha256(compact(records)).hexdigest()
                != trace_receipt["events_sha256"]
                or trace_receipt["syscalls"] != ["execve", "execveat"]
                or trace_receipt["signals"] != BUILD_TRACE_SIGNALS
                or trace_receipt["delay_exit_milliseconds"]
                != BUILD_TRACE_DELAY_EXIT_MILLISECONDS
                or trace_receipt["delay_exit_semantics"]
                != "timing-only-no-result-injection"
                or trace_receipt["detached_records"] != "refused"
                or trace_receipt["successful_execveat"] != "refused"
                or trace_receipt["maximum_bytes"] != MAX_BUILD_EXEC_TRACE_BYTES
                or trace_receipt["maximum_lines"] != MAX_BUILD_EXEC_TRACE_LINES
                or trace_receipt["maximum_successful_execs"]
                != MAX_BUILD_SUCCESSFUL_EXECS
                or byte_count > MAX_BUILD_EXEC_TRACE_BYTES
                or line_count > MAX_BUILD_EXEC_TRACE_LINES
                or len(paths) > MAX_BUILD_SUCCESSFUL_EXECS):
            return None
        return records
    except (KeyError, OSError, RuntimeError, TypeError, ValueError):
        return None


def verify_scourge_build(
    artifacts: Path, receipt: dict[str, object], expected_sha256: str
) -> bool:
    """Independently reopen and recompute every retained build authority."""

    try:
        if hashlib.sha256(BUILD_RECEIPT_DOMAIN + compact(receipt)).hexdigest() != expected_sha256:
            return False
        stored = json.loads((artifacts / "control/scourge-build.json").read_bytes())
        if stored != receipt:
            return False
        archive_row = receipt["source_archive"]
        archive_path = artifacts / str(archive_row["path"])
        archive = archive_path.read_bytes()
        if (len(archive) != archive_row["bytes"]
                or hashlib.sha256(archive).hexdigest() != archive_row["sha256"]):
            return False
        rows: list[dict[str, object]] = []
        lock_payload = None
        with tarfile.open(archive_path, "r:") as bundle:
            for member in bundle.getmembers():
                if member.isdir():
                    continue
                if not member.isfile():
                    return False
                stream = bundle.extractfile(member)
                if stream is None:
                    return False
                data = stream.read()
                if member.name == "Cargo.lock":
                    lock_payload = data
                rows.append({
                    "path": member.name, "mode": f"{member.mode & 0o7777:04o}",
                    "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
                })
        rows.sort(key=lambda row: str(row["path"]))
        export = receipt["export_manifest"]
        if (rows != export["files"]
                or hashlib.sha256(compact(rows)).hexdigest() != export["sha256"]):
            return False
        cargo_inputs = [
            row for row in rows
            if row["path"] == "Cargo.lock" or str(row["path"]).endswith("Cargo.toml")
        ]
        if cargo_inputs != receipt["cargo_inputs"]:
            return False
        vendor_ref = receipt["vendor"]["manifest"]
        vendor_data = (artifacts / str(vendor_ref["path"])).read_bytes()
        if (len(vendor_data) != vendor_ref["bytes"]
                or hashlib.sha256(vendor_data).hexdigest() != vendor_ref["sha256"]):
            return False
        vendor_full = json.loads(vendor_data)
        if (len(vendor_full["archives"]) != receipt["vendor"]["archive_count"]
                or len(vendor_full["files"]) != receipt["vendor"]["file_count"]
                or vendor_full["lock_sha256"] != receipt["vendor"]["lock_sha256"]
                or vendor_full["private_manifest_sha256"]
                != receipt["vendor"]["private_manifest_sha256"]
                or _tree_manifest(artifacts / "build-vendor")
                != vendor_full["private_manifest"]):
            return False
        if lock_payload is None:
            return False
        locked_registry = {
            (str(row["name"]), str(row["version"])): str(row["checksum"])
            for row in tomllib.loads(lock_payload.decode("utf-8")).get("package", [])
            if str(row.get("source", "")).startswith("registry+")
        }
        manifested_registry = {
            (str(row["name"]), str(row["version"])): str(row["lock_checksum"])
            for row in vendor_full["archives"]
        }
        if (manifested_registry != locked_registry
                or hashlib.sha256(compact(vendor_full["files"])).hexdigest()
                != vendor_full["files_sha256"]):
            return False
        for archive in vendor_full["archives"]:
            retained_archive = artifacts / str(archive["retained_path"])
            data, retained_info = _held_bytes(retained_archive)
            if (len(data) != archive["archive_bytes"]
                    or hashlib.sha256(data).hexdigest() != archive["lock_checksum"]
                    or archive["archive_sha256"] != archive["lock_checksum"]
                    or retained_info.st_uid != os.geteuid()
                    or stat.S_IMODE(retained_info.st_mode) != 0o400
                    or retained_info.st_nlink != 1):
                return False

        toolchain_ref = receipt["toolchain"]["manifest"]
        toolchain_data = (artifacts / str(toolchain_ref["path"])).read_bytes()
        if (len(toolchain_data) != toolchain_ref["bytes"]
                or hashlib.sha256(toolchain_data).hexdigest() != toolchain_ref["sha256"]):
            return False
        toolchain_full = json.loads(toolchain_data)
        private_toolchain = _tree_manifest(artifacts / "build-toolchain")
        if (private_toolchain != toolchain_full["private"]
                or hashlib.sha256(compact(private_toolchain)).hexdigest()
                != receipt["toolchain"]["private_manifest_sha256"]):
            return False
        if (_tool_identity(STRACE, ["--version"]) != receipt["build_tracer"]
                or receipt["toolchain"]["source_path"] != os.fspath(RUST_TOOLCHAIN)):
            return False

        cargo_config = (
            "[source.crates-io]\nreplace-with = \"vendored-sources\"\n"
            "[source.vendored-sources]\ndirectory = "
            + json.dumps(os.fspath(artifacts / "build-vendor"))
            + "\n[net]\noffline = true\n"
        ).encode("utf-8")
        if (hashlib.sha256(cargo_config).hexdigest()
                != receipt["cargo_home"]["config_sha256"]
                or (artifacts / "build-cargo-home/config.toml").read_bytes()
                != cargo_config):
            return False
        if not verify_cargo_output_dealias(
            artifacts / "build-target", receipt["cargo_output_dealias"]
        ):
            return False

        traced_records = verify_build_exec_trace(artifacts, receipt["exec_trace"])
        if traced_records is None:
            return False
        traced_paths = [str(row["path"]) for row in traced_records]
        private_files = {str(row["path"]): row for row in private_toolchain
                         if row["kind"] == "file"}
        for row in receipt["external_executables"]:
            path = str(row["path"])
            if row["class"] == "private-toolchain":
                relative = path.removeprefix("build-toolchain/")
                if private_files.get(relative) != row["identity"]:
                    return False
            elif row["class"] == "fresh-target-product":
                executable = artifacts / path
                data, info = _held_bytes(executable)
                if (hashlib.sha256(data).hexdigest() != row["sha256"]
                        or _fstat_row(info) != row["fstat"]):
                    return False
            elif row["class"] == "root-external":
                before = row["identity_before"]
                resolved = Path(str(before["resolved"]))
                actual = {"requested": before["requested"], "resolved": before["resolved"],
                          "sha256": digest(resolved), "fstat": _fstat_row(resolved.stat())}
                if actual != before or row["identity_after"] != before:
                    return False
            else:
                return False
        normalized_paths = []
        for path in dict.fromkeys(traced_paths):
            candidate = Path(path)
            if candidate.is_relative_to(artifacts / "build-toolchain"):
                normalized_paths.append(
                    "build-toolchain/"
                    + candidate.relative_to(artifacts / "build-toolchain").as_posix()
                )
            elif candidate.is_relative_to(artifacts / "build-target"):
                normalized_paths.append(
                    "build-target/"
                    + candidate.relative_to(artifacts / "build-target").as_posix()
                )
            else:
                normalized_paths.append(path)
        if normalized_paths != [str(row["path"]) for row in receipt["external_executables"]]:
            return False
        for stream in ("stdout", "stderr"):
            row = receipt["build_log"][stream]
            data = (artifacts / str(row["path"])).read_bytes()
            if (len(data) != row["bytes"]
                    or hashlib.sha256(data).hexdigest() != row["sha256"]):
                return False
        output = receipt["output"]
        staged = artifacts / str(output["staged_path"])
        info = staged.stat()
        expected_environment = {
            "AR": "/usr/bin/ar", "CC": "/usr/bin/cc",
            "CARGO_BUILD_JOBS": "1", "CARGO_HOME": "<private-cargo-home>",
            "CARGO_INCREMENTAL": "0", "CARGO_NET_OFFLINE": "true",
            "CARGO_TARGET_DIR": "<private-target>",
            "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER": "/usr/bin/cc",
            "HOME": "<private-build-home>", "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8", "PATH": "<private-toolchain>/bin:/usr/bin:/bin",
            "RUSTC": "<private-toolchain>/bin/rustc",
            "RUSTDOC": "<private-toolchain>/bin/rustdoc",
            "SOURCE_DATE_EPOCH": "0", "TMPDIR": "<private-build-tmp>",
        }
        return bool(
            digest(staged) == output["sha256"]
            and info.st_size == output["bytes"]
            and _fstat_row(info) == output["staged_fstat"]
            and output["source_fstat_before"] == output["source_fstat_after"]
            and receipt["schema"] == "scourge.skeleton-scourge-build.v3"
            and receipt["command"] == [
                "<private-toolchain>/bin/cargo", "build", "--manifest-path",
                "<private-source>/Cargo.toml", "--offline", "--locked",
                "-p", "scourge", "--bin", "scourge", "--jobs", "1",
            ]
            and receipt["traced_command"] == [
                STRACE, "-f", "-qq", "-ttt", "-s", "4096",
                "--inject=execve:delay_exit=250ms",
                "--inject=execveat:delay_exit=250ms",
                "-e", "trace=execve,execveat", "-e", "signal=none",
                "-o", "<private-exec-trace>",
                "<private-toolchain>/bin/cargo", "build", "--manifest-path",
                "<private-source>/Cargo.toml", "--offline", "--locked",
                "-p", "scourge", "--bin", "scourge", "--jobs", "1",
            ]
            and receipt["environment"] == expected_environment
            and receipt["offline"] is True and receipt["locked"] is True
            and receipt["incremental"] is False and receipt["wrapper"] is None
            and receipt["target_preflight_empty"] is True
            and receipt["working_directory"] == "/"
            and receipt["root_cargo_config_absent"] is True
            and not Path("/.cargo").exists()
            and receipt["build_log"]["exit_code"] == 0
        )
    except (KeyError, OSError, ValueError, TypeError, tarfile.TarError,
            subprocess.SubprocessError):
        return False


def derived_fixture(context: Path, environment: dict[str, str]) -> dict[str, object]:
    manifest = []
    for source, expected_resolved, name, mode, expected_size, expected in RUNTIME_FILES:
        resolved = source.resolve(strict=True)
        if resolved != expected_resolved:
            raise RuntimeError(f"host glibc qualification path changed: {source}")
        parent_symlink = None
        if source.parent == Path("/usr/lib64"):
            parent = source.parent.lstat()
            target_name = os.readlink(source.parent)
            if (not stat.S_ISLNK(parent.st_mode) or parent.st_uid != 0
                    or stat.S_IMODE(parent.st_mode) != 0o777 or target_name != "lib"):
                raise RuntimeError("approved /usr/lib64 loader parent changed")
            parent_symlink = {"path": "/usr/lib64", "target": target_name,
                              "mode": "0777", "owner_uid": 0}
        elif source != resolved:
            raise RuntimeError(f"unexpected host runtime symlink: {source}")
        fd = os.open(resolved, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                    or stat.S_IMODE(info.st_mode) != mode or info.st_size != expected_size):
                raise RuntimeError(f"host glibc qualification inode changed: {source}")
            blocks = []
            while True:
                block = os.read(fd, 1 << 20)
                if not block:
                    break
                blocks.append(block)
            source_bytes = b"".join(blocks)
        finally:
            os.close(fd)
        if len(source_bytes) != expected_size or hashlib.sha256(source_bytes).hexdigest() != expected:
            raise RuntimeError(f"host glibc qualification input changed: {source}")
        target = context / name
        out = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                      mode)
        try:
            offset = 0
            while offset < len(source_bytes):
                offset += os.write(out, source_bytes[offset:])
            os.fsync(out)
        finally:
            os.close(out)
        info = target.stat()
        manifest.append({"source": os.fspath(source), "resolved_source": os.fspath(resolved),
                         "requested_parent_symlink": parent_symlink,
                         "name": name, "mode": f"{mode:04o}",
                         "size_bytes": info.st_size, "sha256": expected})
    (context / "Containerfile").write_bytes(CONTAINERFILE)
    (context / "Containerfile").chmod(0o600)
    manifest_bytes = compact(manifest) + b"\n"
    (context / "runtime-manifest.json").write_bytes(manifest_bytes)
    (context / "runtime-manifest.json").chmod(0o600)
    iidfile = context / "image.id"
    build = run([PODMAN, "--remote=false", "build", "--pull=never", "--network=none",
                 "--no-cache", "--timestamp=0", "--format=oci", "--iidfile", os.fspath(iidfile),
                 "-f", os.fspath(context / "Containerfile"), os.fspath(context)],
                timeout=180, environment=environment)
    image_id = iidfile.read_text(encoding="ascii").strip().removeprefix("sha256:")
    if image_id != DERIVED_IMAGE_ID:
        raise RuntimeError(f"derived qualification image changed: {image_id}")
    inspected = run([PODMAN, "--remote=false", "image", "inspect", "--format",
                     "{{.Digest}} {{json .Labels}}", image_id],
                    environment=environment).stdout.decode().strip()
    if DERIVED_IMAGE_DIGEST not in inspected or BASE_DIGEST not in inspected:
        raise RuntimeError("derived qualification image labels changed")
    return {
        "name": "Debian-unstable-derived qualification fixture", "base_digest": BASE_DIGEST,
        "base_image_id": BASE_IMAGE_ID, "runtime_manifest": manifest,
        "runtime_manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "containerfile_sha256": hashlib.sha256(CONTAINERFILE).hexdigest(),
        "build_input_sha256": hashlib.sha256(CONTAINERFILE + b"\0" + manifest_bytes).hexdigest(),
        "image_id": image_id, "image_digest": DERIVED_IMAGE_DIGEST,
        "build_stdout_sha256": hashlib.sha256(build.stdout).hexdigest(),
        "no_package_install": True, "build_network": "none", "pull": "never",
    }


def direct_probe(image_id: str, executable: Path, environment: dict[str, str]):
    completed = run([PODMAN, "--remote=false", f"--runtime={CRUN}", "run", "--rm",
        "--pull=never", "--network=none", "--read-only", "--unsetenv-all",
        "--mount", f"type=bind,src={executable},dst=/opt/teapot,ro=true",
        "--entrypoint", "/opt/teapot", image_id, "--version"],
        check=False, environment=environment)
    return {"image_id": image_id, "exit_code": completed.returncode,
            "stdout_bytes": len(completed.stdout),
            "stdout_sha256": hashlib.sha256(completed.stdout).hexdigest(),
            "stderr_bytes": len(completed.stderr),
            "stderr_sha256": hashlib.sha256(completed.stderr).hexdigest(),
            "glibc_2_44_missing": b"GLIBC_2.44" in completed.stderr}


def image_executable_pins(
    image_id: str, environment: dict[str, str]
) -> tuple[dict[str, str], dict[str, object]]:
    paths = (
        "/bin/bash", "/usr/bin/bash", "/bin/sh", "/usr/bin/dash", "/usr/bin/getconf",
        "/usr/bin/id", "/usr/bin/run-parts", "/etc/profile",
    )
    output = run([PODMAN, "--remote=false", f"--runtime={CRUN}", "run", "--rm",
        "--pull=never", "--network=none", "--read-only", "--entrypoint", "/usr/bin/sha256sum",
        image_id, *paths],
        environment=environment).stdout.decode("ascii")
    rows = {path.strip(): value for value, path in (line.split(None, 1)
                                                     for line in output.splitlines())}
    if set(rows) != set(paths):
        raise RuntimeError("derived image executable inventory changed")
    resolved_bash = rows.pop("/usr/bin/bash")
    parent_target = run([
        PODMAN, "--remote=false", f"--runtime={CRUN}", "run", "--rm",
        "--pull=never", "--network=none", "--read-only", "--entrypoint",
        "/usr/bin/readlink", image_id, "/bin",
    ], environment=environment).stdout
    if parent_target != b"usr/bin\n" or resolved_bash != rows["/bin/bash"]:
        raise RuntimeError("derived image bash alias changed")
    profile_inventory = run([
        PODMAN, "--remote=false", f"--runtime={CRUN}", "run", "--rm",
        "--pull=never", "--network=none", "--read-only", "--entrypoint", "/usr/bin/find",
        image_id, "/etc/profile.d", "-mindepth", "1", "-maxdepth", "1", "-printf", "%f\n",
    ], environment=environment).stdout
    if profile_inventory != b"":
        raise RuntimeError("derived image profile inventory changed")
    return rows, {
        "requested": "/bin/bash",
        "parent": "/bin",
        "parent_target": "usr/bin",
        "resolved": "/usr/bin/bash",
        "sha256": resolved_bash,
        "same_digest": True,
    }


def qualify(
    args, bootstrap: dict[str, object], attempt_nonce: str
) -> tuple[dict[str, object], Path]:
    output = Path(args.output)
    if not output.is_absolute() or output.resolve() != output:
        raise RuntimeError("qualification output must use one resolved absolute spelling")
    private_directory(output.parent)
    artifacts = output.with_suffix(output.suffix + ".artifacts")
    if output.exists() or not artifacts.exists():
        raise RuntimeError("bootstrap qualification artifacts are unavailable")
    root_preflight = evidence_root_preflight(artifacts)
    control = artifacts / "control"
    private_directory(control)
    if (Path(args.bootstrap_receipt) != control / "bootstrap.json"
            or Path(args.runtime_source_root) != control / "runtime-source"):
        raise RuntimeError("bootstrap artifact layout mismatch")
    dispatch_failure = retain_legacy_dispatch_failure(
        Path(args.legacy_dispatch_failure_log).absolute(), control
    )
    v37_method_rejection = retain_v37_method_rejection(
        Path(args.prior_receipt).absolute(), control
    )
    v38_method_rejection = retain_v38_method_rejection(
        Path(args.prior_receipt).absolute().parent, control
    )
    for name in ("workspace", "runtime", "gateway", "tools", "build-context"):
        private_directory(artifacts / name)
    runtime, workspace, gateway = artifacts / "runtime", artifacts / "workspace", artifacts / "gateway"
    tools = artifacts / "tools"
    attempt_id = f"bn-6zcm-native-{args.attempt}"
    attempt_root = artifacts / attempt_id
    private_directory(attempt_root)
    private_directory(attempt_root / "retained")
    retained = attempt_root / "retained" / "artifacts"
    private_directory(retained)
    root_preflight_path = control / "evidence-root-preflight.json"
    root_preflight_path.write_bytes(compact(root_preflight) + b"\n")
    root_preflight_path.chmod(0o600)
    for path in (runtime / "artifacts", runtime / "codex-home", runtime / "home",
                 runtime / "tmp", runtime / "cache", runtime / "config", runtime / "data",
                 runtime / "run", runtime / "state", runtime / "referee"):
        private_directory(path)
    (runtime / "codex-home/config.toml").write_text(
        boundary.codex_provider_config(MODEL, "high"), encoding="utf-8")

    environment = monitor.monitor_environment()
    rootless = run([PODMAN, "--remote=false", "info", "--format",
                    "{{.Host.Security.Rootless}}"], environment=environment)
    if rootless.stdout.strip() != b"true":
        raise RuntimeError("rootless Podman is required")
    build_receipt, build_receipt_sha256 = isolated_scourge_build(
        args, artifacts, tools, bootstrap
    )
    producer, producer_sha256 = producer_manifest(
        bootstrap, build_receipt_sha256
    )
    scourge_sha256 = build_receipt["output"]["sha256"]
    source_pins = {
        "scourge": {
            "sha256": scourge_sha256,
            "bytes": build_receipt["output"]["bytes"],
            "retained_path": "tools/scourge",
            "mode": "0500",
            "build_receipt_sha256": build_receipt_sha256,
        },
        "preparation_teapot": stage_exact(Path(args.preparation_teapot).resolve(),
                                          tools / "teapot-preparation", PREPARATION_SHA256),
        "request_reference_teapot": stage_exact(Path(args.request_reference_teapot).resolve(),
            tools / "teapot-request-reference", REQUEST_REFERENCE_SHA256),
        "investigation": stage_exact(Path(args.investigation).resolve(), tools / "investigation",
                                     INVESTIGATION_SHA256),
        # The installed Codex package lives below the host's protected
        # ~/.codex root.  Never mount through that credential-bearing tree:
        # retain the exact pinned bytes in this attempt's private tool root and
        # bind only that 0500 copy into the worker.
        "codex": stage_exact(CODEX, tools / "codex", CODEX_SHA256),
    }
    supervisor, supervisor_build = compat.compile_supervisor(tools, environment)
    if (digest(compat.SUPERVISOR_SOURCE) != SUPERVISOR_SOURCE_SHA256
            or digest(supervisor) != SUPERVISOR_SHA256):
        raise RuntimeError("supervisor binary changed")
    fixture = derived_fixture(artifacts / "build-context", environment)
    stock_refusals = {
        "bookworm": direct_probe(BOOKWORM_IMAGE_ID, tools / "teapot-request-reference", environment),
        "unstable": direct_probe(BASE_IMAGE_ID, tools / "teapot-request-reference", environment),
    }
    if not all(row["exit_code"] != 0 and row["glibc_2_44_missing"]
               for row in stock_refusals.values()):
        raise RuntimeError("stock image loader refusal witness changed")
    c03_probe = direct_probe(DERIVED_IMAGE_ID, tools / "teapot-request-reference", environment)
    if c03_probe["exit_code"] != 0:
        raise RuntimeError("c03 request-reference executable failed in derived fixture")
    image_pins, image_alias = image_executable_pins(DERIVED_IMAGE_ID, environment)
    retained_codex = tools / "codex"
    codex_info = retained_codex.stat()
    if (not stat.S_ISREG(codex_info.st_mode) or stat.S_IMODE(codex_info.st_mode) & 0o022
            or codex_info.st_uid != os.geteuid() or digest(CODEX) != CODEX_SHA256):
        raise RuntimeError("unsafe installed Codex identity")

    auth_read, auth_write = os.pipe()
    try:
        os.write(auth_write, PROVIDER_CANARY)
    finally:
        os.close(auth_write)
    attempts: list[dict[str, object]] = []
    state = relay.RelayState.create(relay.RelayPolicy(
        MODEL, max_request_bytes=2 << 20, max_response_bytes=256 << 10,
        max_requests=8, max_total_bytes=24 << 20, max_output_tokens=32768,
        max_tools=64, max_tool_calls_per_response=1, timeout_seconds=10),
        artifacts / "relay-evidence",
        boundary.ContextExpectation("executable", None, forbidden_fragments=()),
        lambda: FakeConnection(attempts), auth_fd=auth_read)
    stop = threading.Event()
    errors: list[BaseException] = []

    def serve_model() -> None:
        try:
            relay.serve_unix(state, gateway / "model.sock", stop)
        except BaseException as error:
            errors.append(error)

    model_thread = threading.Thread(target=serve_model, name="bn6zcm-model-relay")
    proxy_attempts: list[dict[str, object]] = []
    proxy_thread = threading.Thread(target=compat.serve_fake_proxy,
        args=(gateway / "proxy.sock", stop, errors, proxy_attempts), name="bn6zcm-proxy-relay")
    model_thread.start()
    proxy_thread.start()
    compat.wait_for(gateway / "model.sock", errors, model_thread)
    compat.wait_for(gateway / "proxy.sock", errors, proxy_thread)

    codex_argv = boundary.codex_exec_argv(boundary.CODEX_CONTAINER_PATH, MODEL, "high",
        "executable", project="/workspace", final_message="/runtime/artifacts/final-message.txt")
    supervised = boundary.SupervisedCodex(
        boundary.PinnedExecutable(supervisor, boundary.SUPERVISOR_CONTAINER_PATH,
                                  SUPERVISOR_SHA256),
        boundary.PinnedExecutable(
            retained_codex, boundary.CODEX_CONTAINER_PATH, CODEX_SHA256
        ),
        tuple(codex_argv))
    cidfile = control / "worker.cid"
    production_argv = boundary.build_podman_argv(
        podman_executable=PODMAN, oci_runtime=CRUN, auto_remove=True, interactive=True,
        image_id=BOOKWORM_IMAGE_ID, name="scourge-bn6zcm-native", cidfile=cidfile,
        workspace=workspace, runtime=runtime, gateway=gateway,
        readonly_mounts=(
            boundary.ReadOnlyMount(tools / "scourge", "/opt/scourge-bin/scourge"),
            boundary.ReadOnlyMount(tools / "teapot-preparation",
                                   "/opt/scourge-bin/teapot-preparation"),
            boundary.ReadOnlyMount(tools / "teapot-request-reference",
                                   "/opt/scourge-bin/teapot-request-reference"),
            boundary.ReadOnlyMount(tools / "investigation", "/opt/scourge-bin/investigation"),
        ), protected_roots=(Path(args.source_repo), Path(args.runtime_source_root), retained),
        supervised_codex=supervised,
        proxy_port=PROXY_PORT)
    podman_argv = list(production_argv)
    image_index = podman_argv.index(BOOKWORM_IMAGE_ID)
    podman_argv[image_index] = DERIVED_IMAGE_ID
    if [*podman_argv[:image_index], BOOKWORM_IMAGE_ID,
        *podman_argv[image_index + 1:]] != production_argv:
        raise RuntimeError("qualification image departure is not one exact token")

    env_rows = monitor.worker_environment_rows(boundary.worker_environment(proxy_port=PROXY_PORT))
    pins = (
        monitor.ExecutablePin(boundary.SUPERVISOR_CONTAINER_PATH, SUPERVISOR_SHA256,
                              "read-only-mount"),
        monitor.ExecutablePin(boundary.CODEX_CONTAINER_PATH, CODEX_SHA256, "read-only-mount"),
        monitor.ExecutablePin("/opt/scourge-bin/scourge", scourge_sha256,
                              "read-only-mount"),
        monitor.ExecutablePin("/opt/scourge-bin/teapot-preparation", PREPARATION_SHA256,
                              "read-only-mount"),
        monitor.ExecutablePin("/opt/scourge-bin/teapot-request-reference",
                              REQUEST_REFERENCE_SHA256, "read-only-mount"),
        monitor.ExecutablePin("/opt/scourge-bin/investigation", INVESTIGATION_SHA256,
                              "read-only-mount"),
        monitor.ExecutablePin("/bin/bash", image_pins["/bin/bash"], "image"),
        monitor.ExecutablePin("/bin/sh", image_pins["/bin/sh"], "image"),
        monitor.ExecutablePin("/usr/bin/dash", image_pins["/usr/bin/dash"], "image"),
        monitor.ExecutablePin("/usr/bin/getconf", image_pins["/usr/bin/getconf"], "image"),
        monitor.ExecutablePin("/usr/bin/id", image_pins["/usr/bin/id"], "image"),
        monitor.ExecutablePin("/usr/bin/run-parts", image_pins["/usr/bin/run-parts"], "image"),
    )
    supervisor_pin = monitor.SupervisorPin(boundary.SUPERVISOR_CONTAINER_PATH,
        SUPERVISOR_SHA256, tuple([boundary.SUPERVISOR_CONTAINER_PATH,
                                  *podman_argv[image_index + 1:]]),
        tuple(codex_argv), PROXY_PORT)
    mount_manifest = (
        monitor.MountPin.capture(
            workspace, "/workspace", read_only=False, source_class="private-writable"
        ),
        monitor.MountPin.capture(
            runtime, "/runtime", read_only=False, source_class="private-writable"
        ),
        monitor.MountPin.capture(
            gateway, "/gateway", read_only=True, source_class="gateway-sockets"
        ),
        monitor.MountPin.capture(
            supervisor, boundary.SUPERVISOR_CONTAINER_PATH, read_only=True,
            source_class="pinned-executable", sha256=SUPERVISOR_SHA256,
        ),
        monitor.MountPin.capture(
            retained_codex, boundary.CODEX_CONTAINER_PATH, read_only=True,
            source_class="pinned-executable", sha256=CODEX_SHA256,
        ),
        monitor.MountPin.capture(
            tools / "scourge", "/opt/scourge-bin/scourge", read_only=True,
            source_class="pinned-executable", sha256=scourge_sha256,
        ),
        monitor.MountPin.capture(
            tools / "teapot-preparation", "/opt/scourge-bin/teapot-preparation",
            read_only=True, source_class="pinned-executable", sha256=PREPARATION_SHA256,
        ),
        monitor.MountPin.capture(
            tools / "teapot-request-reference",
            "/opt/scourge-bin/teapot-request-reference", read_only=True,
            source_class="pinned-executable", sha256=REQUEST_REFERENCE_SHA256,
        ),
        monitor.MountPin.capture(
            tools / "investigation", "/opt/scourge-bin/investigation", read_only=True,
            source_class="pinned-executable", sha256=INVESTIGATION_SHA256,
        ),
    )
    config = monitor.MonitorConfig(STRACE, PODMAN, CRUN, boundary.CODEX_CONTAINER_PATH,
        "/opt/scourge-bin/scourge", pins, monitor.podman_argv_digest(podman_argv),
        mounts=mount_manifest, mount_root=os.fspath(artifacts),
        protected_mount_roots=(os.fspath(Path(args.source_repo)),
                               os.fspath(Path(args.runtime_source_root)),
                               os.fspath(retained)),
        supervisor=supervisor_pin, worker_environment=env_rows,
        teapot_path="/opt/scourge-bin/teapot-request-reference",
        teapot_sha256=REQUEST_REFERENCE_SHA256,
        preparation_teapot_path="/opt/scourge-bin/teapot-preparation",
        preparation_teapot_sha256=PREPARATION_SHA256,
        preparation_root="/runtime/state/scourge",
        investigation_path="/opt/scourge-bin/investigation",
        investigation_sha256=INVESTIGATION_SHA256, codex_bootstrap=True,
        codex_setup_device=codex_info.st_dev, codex_setup_inode=codex_info.st_ino,
        codex_setup_fd_ceiling=256,
        codex_setup_fd_access_modes=(os.O_WRONLY, os.O_WRONLY),
        worker_image_id=DERIVED_IMAGE_ID,
        login_profile_sha256=image_pins["/etc/profile"],
        login_profile_inventory=())
    key_path = monitor.create_monitor_key(control)
    monitor_key_commitment = key_commitment(key_path)
    assignment = {"bone": "bn-6zcm",
        "image": DERIVED_IMAGE_ID, "command": COMMAND,
        "pins": {name: row["sha256"] for name, row in source_pins.items()},
        "producer_manifest_sha256": producer_sha256,
        "scourge_build_receipt_sha256": build_receipt_sha256,
        "monitor_key_commitment": monitor_key_commitment}
    assignment_sha256 = hashlib.sha256(
        ASSIGNMENT_DOMAIN + compact(assignment)
    ).hexdigest()
    result = None
    try:
        result = monitor.run_monitored(podman_argv, prompt=PROMPT, config=config,
            attempt_id=attempt_id, assignment_sha256=assignment_sha256,
            key_path=key_path, private_control_root=control, evidence_root=artifacts,
            retained_path=f"{attempt_id}/retained/artifacts",
            producer_manifest_sha256=producer_sha256,
            monitor_key_commitment=monitor_key_commitment,
            forbidden_canaries=(PROVIDER_CANARY,), timeout_seconds=180)
    finally:
        stop.set()
        model_thread.join(timeout=5)
        proxy_thread.join(timeout=5)
    if errors:
        raise errors[0]
    if model_thread.is_alive() or proxy_thread.is_alive() or result is None:
        raise RuntimeError("offline relay did not settle")
    relay_receipt = state.finalize()
    monitor_key = monitor.read_monitor_key(key_path)
    resolved_envelope, resolved_events = monitor.verify_evidence_projection(
        artifacts, result.envelope_ref, result.events_ref, monitor_key
    )
    evidence_binding_valid = monitor.verify_evidence_binding(
        artifacts, result.envelope_ref, result.events_ref, resolved_events,
        result.evidence_binding, monitor_key,
    )
    worker_receipt_path = runtime / "artifacts/native-codex-supervisor.json"
    worker_receipt = json.loads(worker_receipt_path.read_bytes())
    trace = result.envelope["trace"]
    snapshot_rows = json.loads(result.exec_snapshots_path.read_bytes())
    roles = [row["role"] for command_row in trace["commands"]
             for row in command_row["executions"]]
    profile_rows = [
        row for command_row in trace["commands"] for row in command_row["executions"]
        if row.get("support_role") == "login-profile"
    ]
    launcher_rows = [
        row for command_row in trace["commands"] for row in command_row["executions"]
        if row.get("launcher_contract") == "codex-0.172-process-setup-v1"
    ]
    proxy_rows = [
        row for command_row in trace["commands"] for row in command_row["executions"]
        if row.get("infrastructure_role") == "loopback-proxy-probe"
    ]
    alias_rows = [
        row for command_row in trace["commands"] for row in command_row["executions"]
        if "exec_resolution" in row
    ]
    raw_trace_path = control / f"{attempt_id}.strace"
    raw_trace_bytes = raw_trace_path.stat().st_size
    poll_sessions = [row["poll_session"] for row in attempts if row["poll_session"] is not None]
    refs = result.events["child_originals"]
    demo_pairs = [
        command_row["demo_preparation"] for command_row in trace["commands"]
        if "demo_preparation" in command_row
    ]
    referee_files = sorted(path.relative_to(runtime / "referee").as_posix()
        for path in (runtime / "referee").rglob("*") if path.is_file())
    hash_health = trace["exec_snapshot_monitor"]["executable_hash"]
    preterminal_history = history_snapshot(args.attempt_history)
    preterminal_v2 = read_history_v2(_history_v2_root(args.attempt_history))
    initial_producer, initial_producer_sha256 = producer_manifest(bootstrap)
    valid = bool(
        monitor.verify_envelope(result.envelope, monitor.read_monitor_key(key_path))
        and resolved_envelope == result.envelope and resolved_events == result.events
        and evidence_binding_valid
        and verify_producer_manifest(
            producer, producer_sha256, args, artifacts, build_receipt
        )
        and trace["producer_manifest_sha256"] == producer_sha256
        and trace["monitor_key_commitment"] == monitor_key_commitment
        and trace["assignment_sha256"] == assignment_sha256
        and prepublication_history_valid(
            preterminal_history,
            preterminal_v2,
            attempt=args.attempt,
            attempt_nonce=attempt_nonce,
            producer_revision=initial_producer["git_commit"],
            producer_manifest_sha256=initial_producer_sha256,
        )
        and trace["lost_events"] == 0 and trace["drained"] is True
        and trace["container_absent"] is True and result.container_absent
        and roles.count("scourge-demo-fixture") == 1
        and roles.count("teapot-preparation") > 1 and roles.count("investigation") > 1
        and roles.count("teapot") == 0
        and [row["infrastructure_role"] for row in profile_rows] == [
            "login-profile-id", "login-profile-id", "login-profile-run-parts"
        ]
        and len(launcher_rows) == 1
        and len(proxy_rows) == 1 and len(alias_rows) == 1
        and alias_rows[0]["exec_resolution"] == {
            "requested": "/bin/bash", "resolved": "/usr/bin/bash",
            "chain": ["/bin", "usr/bin", "/usr/bin/bash"],
            "requested_fstat": alias_rows[0]["exec_resolution"]["requested_fstat"],
            "same_inode": True,
        }
        and trace["infrastructure"]["bootstrap_contract"]
        == "codex-0.172-os-detection-v1"
        and len(trace["infrastructure"]["bootstrap"]) == 6
        and launcher_rows[0]["process_setup"]["provenance"] == "trace-derived"
        and launcher_rows[0]["process_setup"]["second_literal"] == "4"
        and launcher_rows[0]["process_setup"]["signal"]["nul_signal"] is True
        and launcher_rows[0]["process_setup"]["codex_parent_membership"][
            "leader_process_id"
        ] == trace["codex_process_id"]
        and launcher_rows[0]["process_setup"]["live_topology"] in {
            "unobserved", "observed-matching"
        }
        and raw_trace_bytes <= config.max_trace_bytes
        and trace["teapot_lanes"]["historical_engine_child"]["execution_count"] > 1
        and trace["teapot_lanes"]["c03_request_reference_standalone"] == {
            "sha256": REQUEST_REFERENCE_SHA256, "execution_count": 0,
            "scourge_runtime_binding": False}
        and len(demo_pairs) == 1
        and demo_pairs[0]["contract"] == "historical-teapot-proxy-start-stop-v1"
        and len(demo_pairs[0]["start_stdout_events"]) == 2
        and len(demo_pairs[0]["stop_stdout_events"]) == 1
        and demo_pairs[0]["fixture_quiescent"] is True
        and hash_health["submitted"] == hash_health["completed"]
        and hash_health["observed_max_pending"] <= hash_health["maximum_pending_jobs"]
        and hash_health["observed_max_outstanding_bytes"]
        <= hash_health["maximum_outstanding_bytes"]
        and trace["exec_snapshot_monitor"]["max_gap_nanoseconds"]
        <= trace["exec_snapshot_monitor"]["maximum_allowed_gap_nanoseconds"]
        and len(snapshot_rows) == trace["exec_stop_snapshot_count"]
        and all(
            row["executable_hash"]["pre_fstat"]
            == row["executable_hash"]["post_fstat"]
            and row["executable_hash"]["bytes"] == row["size_bytes"]
            and row["executable_hash"]["completed_monotonic_ns"]
            >= row["executable_hash"]["started_monotonic_ns"]
            for row in snapshot_rows
        )
        and len(result.call_stdout) == 2
        and len(refs) == len(result.teapot_stdout) + len(result.investigation_stdout)
        and all(row["file"]["path"].startswith(f"{attempt_id}/retained/artifacts/")
                for row in refs)
        and relay_receipt["valid"] is True
        and relay_receipt["terminals"][-1]["tool_call_count"] == 0
        and 3 <= len(attempts) <= 8
        and 1 <= len(poll_sessions) <= 6 and len(set(poll_sessions)) == 1
        and len(trace["commands"]) == 1 and trace["commands"][0]["exit_code"] == 0
        and proxy_attempts == [{"request_bytes": len(PROXY_PAYLOAD),
            "request_sha256": hashlib.sha256(PROXY_PAYLOAD).hexdigest(),
            "payload_exact": True}]
        and worker_receipt["self_sha256"] == SUPERVISOR_SHA256
        and worker_receipt["codex_sha256"] == CODEX_SHA256
        and worker_receipt["prompt"]["bytes"] == len(PROMPT)
        and worker_receipt["prompt"]["sha256"] == hashlib.sha256(PROMPT).hexdigest()
        and worker_receipt["teardown"]["complete"] is True
        and worker_receipt["routes"]["model"]["sessions"] == len(attempts)
        and worker_receipt["routes"]["proxy"]["sessions"] == 1
        and "settlement.json" in referee_files and "preparation.json" in referee_files)
    attempt_history = {
        "legacy_frozen": history_snapshot(args.attempt_history),
        "v2_backward_prefix": history_v2_snapshot(
            _history_v2_root(args.attempt_history)
        ),
        "scope": "post-authenticated-bootstrap",
    }
    receipt = {
        "schema": "scourge.skeleton-process-monitor-native-qualification", "schema_version": 1,
        "observed_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "status": "settled" if valid else "unsettled", "valid": valid,
        "producer": {
            "manifest": producer,
            "manifest_sha256": producer_sha256,
            "monitor_key_commitment": monitor_key_commitment,
            "assignment": assignment,
            "assignment_sha256": assignment_sha256,
        },
        "attempt_history": attempt_history,
        "external_dispatch_failures": [dispatch_failure],
        "external_method_rejections": [
            v37_method_rejection, v38_method_rejection,
        ],
        "boundary": {"real_scourge_lane": "historical_engine_child",
            "request_reference_lane": "c03_request_reference_standalone",
            "c03_public_scourge_runtime_binding": False,
            "c03_evidence": "official recovery-fixture-check and M1 request-reference qualification"},
        "fixture": fixture, "stock_loader_refusals": stock_refusals,
        "private_evidence_root": {
            "preflight_path": "control/evidence-root-preflight.json",
            "preflight_sha256": digest(root_preflight_path),
            "private": True,
        },
        "request_reference_direct_probe": c03_probe, "sources": source_pins,
        "scourge_build": {
            "receipt": build_receipt,
            "receipt_sha256": build_receipt_sha256,
        },
        "supervisor_build": {**supervisor_build,
            "pin_provenance": "merged 8a53199 approved installed compatibility receipt",
            "merged_source_sha256": SUPERVISOR_SOURCE_SHA256,
            "merged_binary_sha256": SUPERVISOR_SHA256,
            "premerge_rejected_binary_sha256": PREMERGE_SUPERVISOR_SHA256},
        "image_executables": image_pins,
        "image_executable_aliases": [image_alias],
        "launch": {"podman_argv_sha256": monitor.podman_argv_digest(podman_argv),
            "production_builder_difference": "one image-id token",
            "derived_image_id": DERIVED_IMAGE_ID,
            "login_profile_sha256": image_pins["/etc/profile"],
            "login_profile_inventory": []},
        "collector": {"envelope": result.envelope_ref,
            "events": result.events_ref,
            "evidence_binding": result.evidence_binding,
            "raw_trace_sha256": trace["raw_trace_sha256"],
            "raw_trace_bytes": raw_trace_bytes,
            "max_trace_bytes": config.max_trace_bytes,
            "max_raw_bytes": config.max_raw_bytes,
            "exec_hash": hash_health,
            "exec_stop_snapshots_sha256": trace["exec_stop_snapshots_sha256"],
            "monitor_sha256": trace["monitor_sha256"], "launch_sha256": trace["launch_sha256"],
            "prompt_sha256": trace["prompt_sha256"],
            "prompt_size_bytes": trace["prompt_size_bytes"], "lost_events": trace["lost_events"],
            "container_absent": trace["container_absent"],
            "container_identity": trace["container_identity"],
            "roles": {role: roles.count(role) for role in sorted(set(roles))},
            "calls": len(result.call_stdout), "child_originals": len(refs),
            "teapot_lanes": trace["teapot_lanes"], "demo_preparation": demo_pairs[0],
            "process_accounting": {
                "supervisor_to_codex": trace["infrastructure"]["executions"],
                "bootstrap_contract": trace["infrastructure"]["bootstrap_contract"],
                "bootstrap": trace["infrastructure"]["bootstrap"],
                "login_profile": profile_rows,
                "process_setup": launcher_rows[0]["process_setup"],
                "proxy_probe": proxy_rows[0],
                "usr_merge_alias": alias_rows[0]["exec_resolution"],
            }},
        "supervisor": {"receipt_sha256": digest(worker_receipt_path),
            "prompt": worker_receipt["prompt"], "routes": worker_receipt["routes"],
            "codex": worker_receipt["codex"], "teardown": worker_receipt["teardown"]},
        "offline_relay": {"receipt_valid": relay_receipt["valid"],
                          "model_requests": len(attempts),
                          "continuation_calls": len(poll_sessions),
                          "continuation_session_count": len(set(poll_sessions)),
                          "continuation_chars": "", "poll_yield_milliseconds": 30000,
                          "maximum_continuation_calls": 6, "monitor_wall_limit_seconds": 180,
                          "proxy_sessions": len(proxy_attempts)},
        "credential_boundary": {
            "provider_or_model_network": False,
            "provider_credentials_read": False,
            "host_credential_environment_inherited": False,
            "credential_canary_absent_from_raw_and_retained": True,
            "upstreams": ["private model Unix socket fake", "private proxy Unix socket fake"],
        },
        "protected_preparation": {"files": referee_files,
            "settlement_sha256": digest(runtime / "referee/settlement.json"),
            "preparation_sha256": digest(runtime / "referee/preparation.json")},
        "limits": ["offline fake Responses upstream; no provider or model network",
            "Debian-unstable-derived qualification fixture, not stock Debian production parity",
            "c03 authenticated standalone; no unsupported public Scourge authority rewrite"],
    }
    data = compact(receipt) + b"\n"
    private_path_hits = public_receipt_private_path_hits(
        receipt,
        (
            artifacts,
            Path(args.output).absolute(),
            args.attempt_history,
            args.legacy_dispatch_failure_log.absolute(),
        ),
    )
    if PROVIDER_CANARY in data or private_path_hits:
        raise RuntimeError("private qualification material reached receipt")
    return receipt, artifacts


def main(argv=sys.argv[1:]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--source-repo", required=True)
    parser.add_argument("--runtime-source-root", required=True)
    parser.add_argument("--bootstrap-receipt", required=True)
    parser.add_argument("--preparation-teapot", required=True)
    parser.add_argument("--request-reference-teapot", required=True)
    parser.add_argument("--investigation", required=True)
    parser.add_argument("--attempt", required=True, help="append-only attempt label such as v30")
    parser.add_argument("--attempt-history", required=True, type=Path)
    parser.add_argument("--prior-receipt", required=True, type=Path)
    parser.add_argument("--legacy-dispatch-failure-log", required=True, type=Path)
    args = parser.parse_args(argv)
    if re.fullmatch(r"v[1-9][0-9]*", args.attempt) is None:
        raise RuntimeError("attempt must use the append-only vN spelling")
    args.attempt_history = args.attempt_history.absolute()
    if (args.attempt_history.parent.resolve(strict=True) != args.attempt_history.parent
            or args.prior_receipt.resolve(strict=True) != args.prior_receipt.absolute()
            or args.legacy_dispatch_failure_log.resolve(strict=True)
            != args.legacy_dispatch_failure_log.absolute()):
        raise RuntimeError("history and prior receipt require canonical absolute paths")
    bootstrap = load_bootstrap(args)
    seed_history(args.attempt_history, args.prior_receipt.absolute())
    history_root = _history_v2_root(args.attempt_history)
    recover_history_v2(history_root)
    producer, producer_sha256 = producer_manifest(bootstrap)
    if any(row["event"].get("attempt") == args.attempt
           for row in read_history_v2(history_root)):
        raise RuntimeError("v2 attempt identity already exists")
    attempt_nonce = os.urandom(32).hex()
    append_history_v2(history_root, {
        "attempt": args.attempt,
        "event": "attempt_started",
        "attempt_nonce": attempt_nonce,
        "producer_revision": producer["git_commit"],
        "producer_manifest_sha256": producer_sha256,
        "observed_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
    })
    try:
        receipt, artifacts = qualify(args, bootstrap, attempt_nonce)
        if receipt.get("valid") is not True:
            append_history_v2(history_root, {
                "attempt": args.attempt,
                "event": "attempt_finished",
                "disposition": "rejected",
                "reason": "qualification_predicate_failed",
                "attempt_nonce": attempt_nonce,
                "teardown": {"container_absent": receipt.get("collector", {}).get(
                    "container_absent"
                )},
            })
            sys.stdout.buffer.write(compact(receipt) + b"\n")
            return 2
        published, receipt_sha256 = publish_accepted_receipt(
            output=Path(args.output), attempt=args.attempt,
            attempt_nonce=attempt_nonce, receipt=receipt,
            legacy_history=history_snapshot(args.attempt_history),
            history_root=history_root, artifact_root=artifacts,
            container_absent=bool(receipt["collector"]["container_absent"]),
            container_identity=receipt["collector"]["container_identity"],
        )
        if not verify_published_acceptance(
            history_root, Path(args.output), args.attempt, receipt_sha256
        ):
            raise RuntimeError("published receipt lacks external acceptance")
    except BaseException as error:
        attempt_events = [row["event"] for row in read_history_v2(history_root)
                          if row["event"].get("attempt") == args.attempt]
        if attempt_events and attempt_events[-1]["event"] == "attempt_started":
            artifacts = Path(args.output).with_suffix(
                Path(args.output).suffix + ".artifacts"
            )
            append_history_v2(history_root, {
                "attempt": args.attempt,
                "event": "attempt_finished",
                "disposition": "rejected",
                "reason": f"{type(error).__name__}:{str(error)[:512]}",
                "attempt_nonce": attempt_nonce,
                "trace_started": any(
                    row["path"].endswith(".strace")
                    for row in artifact_file_manifest(artifacts)
                ),
                "teardown": {"container_absent": None},
            })
        raise
    sys.stdout.buffer.write(compact(published) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
