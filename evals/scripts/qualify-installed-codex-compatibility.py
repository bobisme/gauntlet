#!/usr/bin/env python3
"""Qualify the pinned installed Codex request against the offline relay."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time


SCRIPT_DIR = Path(__file__).resolve().parent
REPO = SCRIPT_DIR.parent.parent
LIB = SCRIPT_DIR / "lib"
sys.path.insert(0, str(LIB))
import native_codex_boundary as boundary  # noqa: E402
import responses_relay as relay  # noqa: E402


PODMAN = ["/usr/bin/podman", "--remote=false"]
OCI_RUNTIME = "/usr/bin/crun"
IMAGE = "docker.io/library/debian:bookworm-slim"
IMAGE_ID = boundary.PRODUCTION_IMAGE_ID
MODEL = "gpt-5.5"
CODEX_VERSION = "codex-cli 0.172.0"
CODEX = Path(
    "/home/bob/.codex/packages/standalone/releases/"
    "0.172.0-x86_64-unknown-linux-musl/bin/codex"
)
CODEX_SHA256 = "ad83b94c093f0cdd8176a6bc8005a461bdf23a759863e157d40f562b8a9d664d"
RUSTC = Path("/home/bob/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin/rustc")
RUSTC_SHA256 = "5073422953727c9427a76b7fce03aa9404da46315e5a1e4965389512a41e8db0"
SUPERVISOR_SOURCE = SCRIPT_DIR / "fixtures/native-codex-supervisor.rs"
SUPERVISOR_SOURCE_ARGUMENT = Path("evals/scripts/fixtures/native-codex-supervisor.rs")
SUPERVISOR_COMPILE = (
    "--edition=2021",
    "--target",
    "x86_64-unknown-linux-musl",
    "-D",
    "warnings",
    "-C",
    "opt-level=s",
    "-C",
    "strip=symbols",
    "-C",
    "panic=abort",
)
SUPERVISOR_TEST_COMPILE = (
    "--edition=2021",
    "--target",
    "x86_64-unknown-linux-musl",
    "-D",
    "warnings",
    "--test",
)
SUPERVISOR_TIMEOUT_TEST = (
    "tests::timeout_tracks_direct_child_sigkill_and_group_quiescence"
)
PROVIDER_CANARY = b"offline-installed-codex-provider-canary"
TOOL_CALL_ID = "call_offline_codex_exec"
TOOL_MARKER = "offline Codex tool roundtrip"
TOOL_PATH = "/workspace/installed-codex-tool-roundtrip.txt"
PROXY_PORT = 19080
PROXY_PAYLOAD = b"offline supervisor proxy probe\n"
EXPECTED_CLIENT_TOOLS = (
    "exec_command",
    "write_stdin",
    "request_user_input",
    "apply_patch",
    "view_image",
    "get_goal",
    "create_goal",
    "update_goal",
)
EXPECTED_MOUNTS = {
    "/workspace": True,
    "/runtime": True,
    "/gateway": False,
    "/opt/scourge-bin/codex": False,
    "/opt/scourge-bin/native-codex-supervisor": False,
}
PROMPT = (
    b"Use exec_command to write exactly 'offline Codex tool roundtrip' followed by a newline "
    b"to /workspace/installed-codex-tool-roundtrip.txt, then confirm completion.\n"
)
MANAGED_BLOCK = (
    "<!-- scourge:managed-start -->\n"
    "Use only the prepared Scourge workflow.\n"
    "<!-- scourge:managed-end -->\n"
)
_CREDENTIAL_ENV = re.compile(
    r"(?:^|_)(?:api_?key|auth|bearer|credential|password|secret|token)(?:_|$)", re.I
)
_SAFE_TOOL_VALUE = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")


def compact(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def digest(path: os.PathLike[str] | str) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def run(command, *, timeout=60, check=True, environment=None, input_data=None, cwd=None):
    completed = subprocess.run(
        command,
        check=False,
        capture_output=True,
        timeout=timeout,
        env=environment,
        input=input_data,
        cwd=cwd,
    )
    if check and completed.returncode:
        raise RuntimeError(
            f"command failed ({completed.returncode}): {command[0]}: "
            f"{completed.stderr.decode(errors='replace')}"
        )
    return completed


def sanitized_log(data: bytes, run_root: Path) -> str:
    text = data.decode("utf-8", errors="replace")
    for source, replacement in (
        (os.fspath(run_root), "<RUN_ROOT>"),
        (os.fspath(REPO), "<CHECKOUT>"),
        (os.fspath(CODEX), "<PINNED_CODEX>"),
    ):
        text = text.replace(source, replacement)
    encoded = text.encode("utf-8")
    if len(encoded) > 16384:
        return encoded[:16384].decode("utf-8", errors="replace") + "\n<TRUNCATED>\n"
    return text


def response_sse(mode: str, attempt: int) -> bytes:
    if attempt == 0:
        response_id = f"resp_offline_codex_{mode}_tool"
        item = {
            "id": f"fc_offline_codex_{mode}",
            "type": "function_call",
            "status": "completed",
            "name": "exec_command",
            "call_id": TOOL_CALL_ID,
            "arguments": json.dumps({
                "cmd": (
                    f"/bin/bash -c \"printf '%s\\\\n' 'offline supervisor proxy probe' "
                    f"> /dev/tcp/127.0.0.1/{PROXY_PORT}\"; "
                    f"sleep 0.25; printf '%s\\n' '{TOOL_MARKER}' | tee {TOOL_PATH}"
                ),
                "workdir": "/workspace",
                "yield_time_ms": 1000,
            }, separators=(",", ":")),
        }
        output_tokens = 12
    else:
        response_id = f"resp_offline_codex_{mode}_final"
        item = {
            "id": f"msg_offline_codex_{mode}",
            "type": "message",
            "status": "completed",
            "role": "assistant",
            "content": [{
                "type": "output_text",
                "text": "offline Codex compatibility confirmed.",
                "annotations": [],
                "logprobs": [],
            }],
        }
        output_tokens = 6
    usage = {
        "input_tokens": 23,
        "input_tokens_details": {"cached_tokens": 0},
        "output_tokens": output_tokens,
        "output_tokens_details": {"reasoning_tokens": 0},
        "total_tokens": 23 + output_tokens,
    }
    if item["type"] == "message":
        text = item["content"][0]["text"]
        seed = dict(item, status="in_progress", content=[])
        events = [
            {"type": "response.created", "response": {
                "id": response_id, "status": "in_progress",
            }},
            {"type": "response.output_item.added", "output_index": 0,
             "item": seed},
            {"type": "response.content_part.added", "item_id": item["id"],
             "output_index": 0, "content_index": 0,
             "part": {"type": "output_text", "text": "", "annotations": [],
                      "logprobs": []}},
            {"type": "response.output_text.delta", "item_id": item["id"],
             "output_index": 0, "content_index": 0, "delta": text},
            {"type": "response.output_text.done", "item_id": item["id"],
             "output_index": 0, "content_index": 0, "text": text},
            {"type": "response.content_part.done", "item_id": item["id"],
             "output_index": 0, "content_index": 0,
             "part": item["content"][0]},
            {"type": "response.output_item.done", "output_index": 0,
             "item": item},
        ]
    else:
        events = [{
            "type": "response.output_item.done",
            "output_index": 0,
            "item": item,
        }]
    events.append(
        {
            "type": "response.completed",
            "response": {
                "id": response_id,
                "object": "response",
                "created_at": 0,
                "status": "completed",
                "model": MODEL,
                "output": [item],
                "usage": usage,
            },
        }
    )
    return b"".join(
        b"event: " + event["type"].encode("ascii") + b"\n"
        + b"data: " + compact(event) + b"\n\n"
        for event in events
    )


class FakeResponse:
    status = 200

    def __init__(self, mode: str, attempt: int):
        self.body = response_sse(mode, attempt)
        self.offset = 0

    def read(self, amount):
        chunk = self.body[self.offset:self.offset + amount]
        self.offset += len(chunk)
        return chunk

    def getheaders(self):
        return [("Content-Type", "text/event-stream"), ("Content-Encoding", "identity")]


class FakeConnection:
    def __init__(self, mode: str, attempts: list[dict[str, object]]):
        self.mode = mode
        self.attempts = attempts
        self.attempt = len(attempts)

    def request(self, method, path, *, body, headers):
        if method != "POST" or path != "/v1/responses":
            raise AssertionError("relay changed the fixed upstream request")
        if headers.get("Authorization") != f"Bearer {PROVIDER_CANARY.decode('ascii')}":
            raise AssertionError("relay did not use descriptor-owned authentication")
        if headers.get("Accept-Encoding") != "identity":
            raise AssertionError("relay did not pin identity encoding")
        value = boundary.strict_json(body)
        if not isinstance(value, dict):
            raise AssertionError("relay forwarded a non-object provider body")
        provider_cache_key = value.get("prompt_cache_key")
        self.attempts.append({
            "method": method,
            "path": path,
            "request_body_bytes": len(body),
            "request_body_sha256": hashlib.sha256(body).hexdigest(),
            "authorization_source": "host-descriptor-canary",
            "accept_encoding": headers.get("Accept-Encoding"),
            "client_metadata_present": "client_metadata" in value,
            "max_output_tokens": value.get("max_output_tokens"),
            "model": value.get("model"),
            "prompt_cache_key_bytes": len(provider_cache_key.encode("utf-8"))
            if isinstance(provider_cache_key, str) else None,
            "prompt_cache_key_sha256": hashlib.sha256(
                provider_cache_key.encode("utf-8")
            ).hexdigest() if isinstance(provider_cache_key, str) else None,
            "prompt_cache_key_host_scoped": bool(
                isinstance(provider_cache_key, str)
                and re.fullmatch(r"scourge-[0-9a-f]{32}-[0-9]{6}", provider_cache_key)
            ),
        })

    def getresponse(self):
        return FakeResponse(self.mode, self.attempt)

    def close(self):
        pass


def wait_for(path: Path, errors: list[BaseException], thread: threading.Thread) -> None:
    deadline = time.monotonic() + 5
    while not path.exists():
        if errors:
            raise errors[0]
        if not thread.is_alive():
            raise RuntimeError("relay exited before socket readiness")
        if time.monotonic() >= deadline:
            raise RuntimeError("relay socket readiness timeout")
        time.sleep(0.02)


def serve_fake_proxy(
    path: Path,
    stop: threading.Event,
    errors: list[BaseException],
    attempts: list[dict[str, object]],
) -> None:
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    identity = None
    try:
        listener.bind(os.fspath(path))
        os.chmod(path, 0o600)
        identity = path.lstat()
        listener.listen(2)
        listener.settimeout(0.2)
        while not stop.is_set():
            try:
                connection, _address = listener.accept()
            except socket.timeout:
                continue
            with connection:
                connection.settimeout(3)
                body = b""
                while chunk := connection.recv(4096):
                    body += chunk
                    if len(body) > 4096:
                        raise RuntimeError("fake proxy request exceeded qualification budget")
                attempts.append({
                    "request_bytes": len(body),
                    "request_sha256": hashlib.sha256(body).hexdigest(),
                    "payload_exact": body == PROXY_PAYLOAD,
                })
    except BaseException as error:
        errors.append(error)
    finally:
        listener.close()
        try:
            current = path.lstat()
            if identity is not None and stat.S_ISSOCK(current.st_mode) and (
                current.st_dev, current.st_ino
            ) == (identity.st_dev, identity.st_ino):
                path.unlink()
        except FileNotFoundError:
            pass


def serve_sink_socket(
    path: Path,
    stop: threading.Event,
    errors: list[BaseException],
) -> None:
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    identity = None
    try:
        listener.bind(os.fspath(path))
        os.chmod(path, 0o600)
        identity = path.lstat()
        listener.listen(2)
        listener.settimeout(0.2)
        while not stop.is_set():
            try:
                connection, _address = listener.accept()
            except socket.timeout:
                continue
            with connection:
                connection.settimeout(1)
                try:
                    while connection.recv(4096):
                        pass
                except (OSError, TimeoutError):
                    pass
    except BaseException as error:
        errors.append(error)
    finally:
        listener.close()
        try:
            current = path.lstat()
            if identity is not None and stat.S_ISSOCK(current.st_mode) and (
                current.st_dev, current.st_ino
            ) == (identity.st_dev, identity.st_ino):
                path.unlink()
        except FileNotFoundError:
            pass


def create_dead_socket(path: Path) -> None:
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(os.fspath(path))
    os.chmod(path, 0o600)
    listener.close()


def compile_supervisor(tools: Path, host_environment: dict[str, str]) -> tuple[Path, dict[str, object]]:
    if RUSTC.resolve(strict=True) != RUSTC or digest(RUSTC) != RUSTC_SHA256:
        raise RuntimeError("pinned supervisor compiler changed")
    outputs = [tools / "native-codex-supervisor", tools / "native-codex-supervisor.second"]
    for index, output in enumerate(outputs):
        build_root = tools.parent / f"supervisor-build-{index}"
        staged_source = build_root / SUPERVISOR_SOURCE_ARGUMENT
        staged_source.parent.mkdir(mode=0o700, parents=True)
        shutil.copyfile(SUPERVISOR_SOURCE, staged_source)
        if digest(staged_source) != digest(SUPERVISOR_SOURCE):
            raise RuntimeError("staged supervisor source changed")
        run(
            [
                os.fspath(RUSTC),
                *SUPERVISOR_COMPILE,
                os.fspath(SUPERVISOR_SOURCE_ARGUMENT),
                "-o",
                os.fspath(output),
            ],
            environment=host_environment,
            cwd=build_root,
        )
    hashes = [digest(output) for output in outputs]
    if len(set(hashes)) != 1:
        raise RuntimeError("supervisor build is not byte-reproducible")
    outputs[1].unlink()
    test_root = tools.parent / "supervisor-test-build"
    test_source = test_root / SUPERVISOR_SOURCE_ARGUMENT
    test_source.parent.mkdir(mode=0o700, parents=True)
    shutil.copyfile(SUPERVISOR_SOURCE, test_source)
    if digest(test_source) != digest(SUPERVISOR_SOURCE):
        raise RuntimeError("staged supervisor test source changed")
    test_binary = tools / "native-codex-supervisor-tests"
    run(
        [
            os.fspath(RUSTC),
            *SUPERVISOR_TEST_COMPILE,
            os.fspath(SUPERVISOR_SOURCE_ARGUMENT),
            "-o",
            os.fspath(test_binary),
        ],
        environment=host_environment,
        cwd=test_root,
    )
    test_environment = dict(host_environment)
    test_environment["RUST_TEST_THREADS"] = "1"
    timeout_test = run(
        [
            os.fspath(test_binary),
            "--exact",
            SUPERVISOR_TIMEOUT_TEST,
            "--nocapture",
        ],
        timeout=10,
        environment=test_environment,
    )
    return outputs[0], {
        "source_sha256": digest(SUPERVISOR_SOURCE),
        "rustc": "rustc-1.100.0-x86_64-unknown-linux-gnu",
        "rustc_sha256": RUSTC_SHA256,
        "rustc_version": "rustc 1.100.0 (0ef1bc386 2026-11-09)",
        "arguments": list(SUPERVISOR_COMPILE),
        "source_argument": os.fspath(SUPERVISOR_SOURCE_ARGUMENT),
        "working_directory": "isolated-build-root",
        "binary_sha256": hashes[0],
        "binary_bytes": outputs[0].stat().st_size,
        "static_musl": True,
        "reproducible_two_builds": True,
        "path_independent_two_builds": True,
        "timeout_helper_test": {
            "test": SUPERVISOR_TIMEOUT_TEST,
            "source_helper": "wait_child_with_limits",
            "passed": True,
            "production_timeout_seconds": 900,
            "test_timeout_milliseconds": 40,
            "test_term_grace_milliseconds": 40,
            "exact_900_seconds_executed": False,
            "stdout_bytes": len(timeout_test.stdout),
            "stdout_sha256": hashlib.sha256(timeout_test.stdout).hexdigest(),
            "stderr_bytes": len(timeout_test.stderr),
            "stderr_sha256": hashlib.sha256(timeout_test.stderr).hexdigest(),
        },
    }


def watch_container_processes(
    cidfile: Path,
    stop: threading.Event,
    relay_state: relay.RelayState,
    host_environment: dict[str, str],
    observations: list[dict[str, object]],
) -> None:
    deadline = time.monotonic() + 10
    container_id = None
    while not stop.is_set() and time.monotonic() < deadline:
        if cidfile.is_file():
            candidate = cidfile.read_text(encoding="ascii").strip()
            if candidate:
                container_id = candidate
                break
        time.sleep(0.002)
    if container_id is None:
        return
    seen: set[int] = set()
    while not stop.is_set():
        completed = subprocess.run(
            [*PODMAN, "top", container_id, "pid", "ppid", "args"],
            check=False,
            capture_output=True,
            env=host_environment,
        )
        if completed.returncode != 0:
            time.sleep(0.002)
            continue
        for line in completed.stdout.decode("utf-8", errors="replace").splitlines()[1:]:
            fields = line.split(None, 2)
            if len(fields) != 3 or not fields[0].isdecimal() or not fields[1].isdecimal():
                continue
            process_id, parent_id, command = int(fields[0]), int(fields[1]), fields[2]
            if process_id in seen:
                continue
            seen.add(process_id)
            command_bytes = command.encode("utf-8", errors="replace")
            observations.append({
                "pid": process_id,
                "ppid": parent_id,
                "before_first_model_request": relay_state.inbound_requests == 0,
                "supervisor": command.startswith(boundary.SUPERVISOR_CONTAINER_PATH),
                "codex": command.startswith(boundary.CODEX_CONTAINER_PATH),
                "expected_tool_command": TOOL_MARKER in command and TOOL_PATH in command,
                "command_bytes": len(command_bytes),
                "command_sha256": hashlib.sha256(command_bytes).hexdigest(),
            })
        time.sleep(0.002)


def summarize_process_lineage(observations: list[dict[str, object]]) -> dict[str, object]:
    supervisors = [row for row in observations if row["supervisor"] is True]
    codex_rows = [row for row in observations if row["codex"] is True]
    supervisor_pid = supervisors[0]["pid"] if len(supervisors) == 1 else None
    codex_pid = codex_rows[0]["pid"] if len(codex_rows) == 1 else None
    parents = {row["pid"]: row["ppid"] for row in observations}
    tool_roots = {
        row["pid"] for row in observations
        if row["expected_tool_command"] is True and row["ppid"] == codex_pid
    }

    def beneath(process_id: object, roots: set[object]) -> bool:
        visited: set[object] = set()
        current = process_id
        while current in parents and current not in visited:
            if current in roots:
                return True
            visited.add(current)
            current = parents[current]
        return current in roots

    unexpected = [
        row for row in observations
        if row["pid"] not in {supervisor_pid, codex_pid}
        and not beneath(row["pid"], tool_roots)
    ]
    pre_request_codex_children = [
        row for row in observations
        if row["ppid"] == codex_pid and row["before_first_model_request"] is True
    ]
    rows = [
        {key: value for key, value in row.items() if key not in {"pid", "ppid"}}
        | {
            "parent": (
                "supervisor" if row["ppid"] == supervisor_pid
                else "codex" if row["ppid"] == codex_pid
                else "tool" if beneath(row["ppid"], tool_roots)
                else "outside"
            )
        }
        for row in observations
    ]
    valid = bool(
        len(supervisors) == 1
        and len(codex_rows) == 1
        and codex_rows[0]["ppid"] == supervisor_pid
        and not unexpected
        and not pre_request_codex_children
        and tool_roots
    )
    return {
        "attempted": True,
        "supervisor_count": len(supervisors),
        "codex_count": len(codex_rows),
        "codex_child_of_supervisor": bool(
            len(codex_rows) == 1 and codex_rows[0]["ppid"] == supervisor_pid
        ),
        "pre_request_codex_children": len(pre_request_codex_children),
        "expected_tool_roots": len(tool_roots),
        "unexpected_descendants": len(unexpected),
        "rows": rows,
        "valid": valid,
    }


def inspect_codex_capabilities(
    root: Path, host_environment: dict[str, str]
) -> dict[str, object]:
    """Read only the exact binary's bundled model and feature metadata."""

    catalog_home = root / "catalog-home"
    catalog_home.mkdir(mode=0o700)
    environment = dict(host_environment)
    environment.update({"CODEX_HOME": os.fspath(catalog_home), "HOME": os.fspath(root)})
    catalog = run(
        [os.fspath(CODEX), "debug", "models", "--bundled"],
        environment=environment,
    )
    value = json.loads(catalog.stdout)
    models = value.get("models") if isinstance(value, dict) else None
    matches = [
        row for row in models or []
        if isinstance(row, dict) and row.get("slug") == MODEL
    ]
    if len(matches) != 1:
        raise RuntimeError("pinned model is not unique in the bundled catalog")
    selected = matches[0]
    if (
        selected.get("shell_type") != "unified_exec"
        or selected.get("supported_in_api") is not True
        or selected.get("tool_mode") is not None
    ):
        raise RuntimeError("pinned model is not the stable unified-exec client-tool path")

    feature_run = run([os.fspath(CODEX), "features", "list"], environment=environment)
    features: dict[str, dict[str, object]] = {}
    for line in feature_run.stdout.decode("utf-8").splitlines():
        match = re.fullmatch(r"(\S+)\s+(.+?)\s+(true|false)", line)
        if match:
            name, stage, enabled = match.groups()
            features[name] = {"stage": stage, "default_enabled": enabled == "true"}
    expected_features = {
        "code_mode": {"stage": "under development", "default_enabled": False},
        "code_mode_host": {"stage": "stable", "default_enabled": True},
        "shell_snapshot": {"stage": "stable", "default_enabled": True},
    }
    if {name: features.get(name) for name in expected_features} != expected_features:
        raise RuntimeError("pinned Codex worker feature metadata changed")
    return {
        "bundled_catalog_bytes": len(catalog.stdout),
        "bundled_catalog_sha256": hashlib.sha256(catalog.stdout).hexdigest(),
        "model": {
            "slug": selected["slug"],
            "shell_type": selected["shell_type"],
            "supported_in_api": selected["supported_in_api"],
            "tool_mode": selected.get("tool_mode"),
            "tool_mode_field_present": "tool_mode" in selected,
            "visibility": selected.get("visibility"),
        },
        "feature_list_bytes": len(feature_run.stdout),
        "feature_list_sha256": hashlib.sha256(feature_run.stdout).hexdigest(),
        "features": expected_features,
    }


def summarize_tool(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        return {"shape": type(value).__name__}
    result: dict[str, object] = {"keys": sorted(value), "type": value.get("type")}
    name = value.get("name")
    if isinstance(name, str) and _SAFE_TOOL_VALUE.fullmatch(name):
        result["name"] = name
    description = value.get("description")
    if isinstance(description, str):
        result["description_bytes"] = len(description.encode("utf-8"))
    for field in ("parameters", "format"):
        nested = value.get(field)
        if isinstance(nested, dict):
            result[f"{field}_keys"] = sorted(nested)
            result[f"{field}_sha256"] = hashlib.sha256(compact(nested)).hexdigest()
            for key in ("type", "syntax"):
                item = nested.get(key)
                if isinstance(item, str) and _SAFE_TOOL_VALUE.fullmatch(item):
                    result[f"{field}_{key}"] = item
    return result


def strings(value: object):
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for item in value:
            yield from strings(item)
    elif isinstance(value, dict):
        for item in value.values():
            yield from strings(item)


def summarize_request(raw: bytes) -> dict[str, object]:
    value = boundary.strict_json(raw)
    if not isinstance(value, dict):
        raise RuntimeError("Codex request body is not an object")
    tools = value.get("tools")
    include = value.get("include")
    client_metadata = value.get("client_metadata")
    tool_choice = value.get("tool_choice")
    prompt_cache_key = value.get("prompt_cache_key")
    input_value = value.get("input")
    input_items = input_value if isinstance(input_value, list) else []
    function_outputs = [
        item for item in input_items
        if isinstance(item, dict) and item.get("type") == "function_call_output"
    ]
    summary = {
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "top_level_fields": sorted(value),
        "model": value.get("model"),
        "stream": value.get("stream"),
        "store": value.get("store"),
        "max_output_tokens": value.get("max_output_tokens"),
        "include": include if isinstance(include, list) else None,
        "previous_response_id_present": "previous_response_id" in value,
        "client_metadata_fields": sorted(client_metadata)
        if isinstance(client_metadata, dict) else [],
        "client_metadata_sha256": hashlib.sha256(compact(client_metadata)).hexdigest()
        if isinstance(client_metadata, dict) else None,
        "client_metadata_value_types": {
            key: type(item).__name__ for key, item in sorted(client_metadata.items())
        } if isinstance(client_metadata, dict) else {},
        "input_kind": type(input_value).__name__,
        "input_items": len(input_items) if isinstance(input_value, list) else None,
        "input_item_types": [
            item.get("type") for item in input_items
            if isinstance(item, dict) and isinstance(item.get("type"), str)
        ],
        "function_call_output_count": len(function_outputs),
        "offline_tool_call_id_present": any(
            item.get("call_id") == TOOL_CALL_ID for item in function_outputs
        ),
        "offline_tool_output_marker_present": any(
            TOOL_MARKER in text for item in function_outputs for text in strings(item)
        ),
        "function_call_output_sha256": [
            hashlib.sha256(compact(item)).hexdigest() for item in function_outputs
        ],
        "reasoning_fields": sorted(value["reasoning"])
        if isinstance(value.get("reasoning"), dict) else [],
        "reasoning": value.get("reasoning")
        if value.get("reasoning") == {"effort": "high"} else None,
        "text_fields": sorted(value["text"])
        if isinstance(value.get("text"), dict) else [],
        "text": value.get("text")
        if value.get("text") in ({"verbosity": "low"}, {"verbosity": "medium"}) else None,
        "prompt_cache_key_bytes": len(prompt_cache_key.encode("utf-8"))
        if isinstance(prompt_cache_key, str) else None,
        "prompt_cache_key_sha256": hashlib.sha256(prompt_cache_key.encode("utf-8")).hexdigest()
        if isinstance(prompt_cache_key, str) else None,
        "tools": [summarize_tool(tool) for tool in tools]
        if isinstance(tools, list) else None,
        "tool_count": len(tools) if isinstance(tools, list) else None,
        "tool_choice": tool_choice
        if isinstance(tool_choice, str) and _SAFE_TOOL_VALUE.fullmatch(tool_choice)
        else summarize_tool(tool_choice),
    }
    return summary


def prepare_runtime(runtime: Path, config: bytes) -> None:
    for path in (
        runtime / "artifacts",
        runtime / "codex-home",
        runtime / "home",
        runtime / "tmp",
        runtime / "cache",
        runtime / "config",
        runtime / "data",
        runtime / "run",
        runtime / "state",
    ):
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
    (runtime / "codex-home/config.toml").write_bytes(config)


def qualify_supervisor_probe(
    kind: str,
    *,
    root: Path,
    image_id: str,
    supervisor: Path,
    referee: Path,
    host_environment: dict[str, str],
) -> dict[str, object]:
    probe_root = root / "supervisor-probes" / kind
    workspace = probe_root / "workspace"
    runtime = probe_root / "runtime"
    gateway = probe_root / "gateway"
    for path in (probe_root, workspace, runtime, gateway):
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
    prepare_runtime(runtime, boundary.codex_provider_config(MODEL, "high").encode())

    scripts = {
        "dead_model": "#!/bin/sh\ncat >/dev/null\n/bin/bash -c \"printf model > /dev/tcp/127.0.0.1/18080\"\nsleep 1\n",
        "dead_proxy": f"#!/bin/sh\ncat >/dev/null\n/bin/bash -c \"printf proxy > /dev/tcp/127.0.0.1/{PROXY_PORT}\"\nsleep 1\n",
        "broken_stdin": "#!/bin/sh\nexec 0<&-\nsleep 0.2\nexit 0\n",
        "stubborn_group": (
            "#!/bin/sh\n"
            "/bin/bash -c 'trap \"\" TERM; exec sleep 60' <&0 &\n"
            "echo $! > /runtime/artifacts/stubborn.pid\n"
            "exit 0\n"
        ),
        "direct_term_ignore": (
            "#!/bin/sh\n"
            "trap '' TERM\n"
            "cat >/dev/null\n"
            "echo ready > /runtime/artifacts/direct-term-ready\n"
            "while :; do sleep 60; done\n"
        ),
        "signal_escape": "#!/bin/sh\ncat >/dev/null\nsetsid sleep 60 >/dev/null 2>&1 &\necho $! > /runtime/artifacts/escaped.pid\nwait\n",
        "sigkill": "#!/bin/sh\ncat >/dev/null\necho ready > /runtime/artifacts/kill-ready\nsleep 60\n",
    }
    fake_codex = probe_root / "fake-codex"
    fake_codex.write_text(scripts[kind], encoding="ascii")
    fake_codex.chmod(0o700)

    stop = threading.Event()
    errors: list[BaseException] = []
    threads: list[threading.Thread] = []
    dead = {"model.sock"} if kind == "dead_model" else (
        {"proxy.sock"} if kind == "dead_proxy" else set()
    )
    for name in ("model.sock", "proxy.sock"):
        path = gateway / name
        if name in dead:
            create_dead_socket(path)
        else:
            thread = threading.Thread(
                target=serve_sink_socket,
                args=(path, stop, errors),
                name=f"supervisor-probe-{kind}-{name}",
            )
            thread.start()
            threads.append(thread)
            wait_for(path, errors, thread)

    codex_argv = boundary.codex_exec_argv(
        boundary.CODEX_CONTAINER_PATH,
        MODEL,
        "high",
        "executable",
    )
    contract = boundary.SupervisedCodex(
        supervisor=boundary.PinnedExecutable(
            supervisor,
            boundary.SUPERVISOR_CONTAINER_PATH,
            digest(supervisor),
        ),
        codex=boundary.PinnedExecutable(
            fake_codex,
            boundary.CODEX_CONTAINER_PATH,
            digest(fake_codex),
        ),
        codex_argv=tuple(codex_argv),
    )
    cidfile = probe_root / "worker.cid"
    podman_argv = boundary.build_podman_argv(
        podman_executable=PODMAN[0],
        oci_runtime=OCI_RUNTIME,
        auto_remove=False,
        interactive=True,
        image_id=image_id,
        name=f"scourge-supervisor-probe-{kind}",
        cidfile=cidfile,
        workspace=workspace,
        runtime=runtime,
        gateway=gateway,
        readonly_mounts=(),
        protected_roots=(REPO, referee),
        supervised_codex=contract,
        proxy_port=PROXY_PORT,
    )
    prompt = b"x" * (256 * 1024) if kind in {"broken_stdin", "stubborn_group"} else PROMPT
    process = subprocess.Popen(
        podman_argv,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=host_environment,
    )
    escaped_host_pid = None
    try:
        if kind in {
            "direct_term_ignore", "signal_escape", "sigkill", "stubborn_group"
        }:
            assert process.stdin is not None
            process.stdin.write(prompt)
            process.stdin.close()
            marker_name = {
                "signal_escape": "escaped.pid",
                "sigkill": "kill-ready",
                "stubborn_group": "stubborn.pid",
                "direct_term_ignore": "direct-term-ready",
            }[kind]
            marker = runtime / "artifacts" / marker_name
            deadline = time.monotonic() + 10
            while not marker.is_file() and time.monotonic() < deadline:
                if process.poll() is not None:
                    break
                time.sleep(0.01)
            if not marker.is_file():
                raise RuntimeError(f"supervisor {kind} probe did not reach its marker")
            container_id = cidfile.read_text(encoding="ascii").strip()
            top = run(
                [*PODMAN, "top", container_id, "hpid", "args"],
                check=False,
                environment=host_environment,
            )
            for line in top.stdout.decode(errors="replace").splitlines()[1:]:
                fields = line.split(None, 1)
                if len(fields) == 2 and fields[0].isdecimal() and "sleep 60" in fields[1]:
                    escaped_host_pid = int(fields[0])
            if kind != "stubborn_group":
                signal_name = "KILL" if kind == "sigkill" else "TERM"
                run(
                    [*PODMAN, "kill", "--signal", signal_name, container_id],
                    check=False,
                    environment=host_environment,
                )
            process.wait(timeout=15)
            stdout = process.stdout.read() if process.stdout else b""
            stderr = process.stderr.read() if process.stderr else b""
        else:
            stdout, stderr = process.communicate(prompt, timeout=15)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        stop.set()
        for thread in threads:
            thread.join(timeout=3)
        container_id = cidfile.read_text(encoding="ascii").strip() if cidfile.is_file() else ""
        if container_id:
            run([*PODMAN, "rm", "--force", container_id], check=False, environment=host_environment)
            removed = run(
                [*PODMAN, "container", "exists", container_id],
                check=False,
                environment=host_environment,
            ).returncode == 1
        else:
            removed = False
        for name in dead:
            try:
                (gateway / name).unlink()
            except FileNotFoundError:
                pass
    if errors:
        raise errors[0]
    receipt_path = runtime / "artifacts/native-codex-supervisor.json"
    receipt = json.loads(receipt_path.read_bytes()) if receipt_path.is_file() else None
    escaped_absent = bool(
        escaped_host_pid is None or not Path(f"/proc/{escaped_host_pid}").exists()
    )
    common = bool(process.returncode != 0 and removed and escaped_absent)
    if kind == "dead_model":
        valid = common and receipt is not None and receipt["fatal_route_failure"] is True \
            and receipt["routes"]["model"]["refused"] >= 1
    elif kind == "dead_proxy":
        valid = common and receipt is not None and receipt["fatal_route_failure"] is True \
            and receipt["routes"]["proxy"]["refused"] >= 1
    elif kind == "broken_stdin":
        valid = common and receipt is not None \
            and receipt["prompt"]["write_complete"] is False
    elif kind == "stubborn_group":
        valid = common and receipt is not None \
            and receipt["prompt"]["write_complete"] is False \
            and receipt["teardown"]["process_group_quiescent"] is True \
            and receipt["teardown"]["sigkill_escalated"] is True \
            and receipt["teardown"]["complete"] is True
    elif kind == "direct_term_ignore":
        valid = common and receipt is not None \
            and receipt["codex"]["signal"] == 9 \
            and receipt["codex"]["timed_out"] is False \
            and receipt["codex"]["interrupted_by_signal"] == 15 \
            and receipt["teardown"]["sigkill_escalated"] is True \
            and receipt["teardown"]["process_group_quiescent"] is True \
            and receipt["teardown"]["routes_inactive"] is True \
            and receipt["teardown"]["complete"] is True
    elif kind == "signal_escape":
        valid = common and receipt is not None \
            and receipt["codex"]["interrupted_by_signal"] == 15 \
            and receipt["teardown"]["complete"] is True
    else:
        valid = common and receipt is None
    return {
        "case": kind,
        "valid": bool(valid),
        "exit_code": process.returncode,
        "receipt_present": receipt is not None,
        "fatal_route_failure": receipt.get("fatal_route_failure")
        if isinstance(receipt, dict) else None,
        "prompt_write_complete": receipt.get("prompt", {}).get("write_complete")
        if isinstance(receipt, dict) else None,
        "prompt_write_timed_out": receipt.get("prompt", {}).get("write_timed_out")
        if isinstance(receipt, dict) else None,
        "interrupted_by_signal": receipt.get("codex", {}).get("interrupted_by_signal")
        if isinstance(receipt, dict) else None,
        "codex_signal": receipt.get("codex", {}).get("signal")
        if isinstance(receipt, dict) else None,
        "codex_timed_out": receipt.get("codex", {}).get("timed_out")
        if isinstance(receipt, dict) else None,
        "target_route_refusals": receipt.get("routes", {}).get(
            "model" if kind == "dead_model" else "proxy", {}
        ).get("refused") if isinstance(receipt, dict) else None,
        "process_group_quiescent": receipt.get("teardown", {}).get(
            "process_group_quiescent"
        ) if isinstance(receipt, dict) else None,
        "sigkill_escalated": receipt.get("teardown", {}).get("sigkill_escalated")
        if isinstance(receipt, dict) else None,
        "routes_inactive": receipt.get("teardown", {}).get("routes_inactive")
        if isinstance(receipt, dict) else None,
        "teardown_complete": receipt.get("teardown", {}).get("complete")
        if isinstance(receipt, dict) else None,
        "escaped_child_absent": escaped_absent,
        "container_removed": removed,
        "stdout_bytes": len(stdout),
        "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
        "stderr_bytes": len(stderr),
        "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
    }


def qualify_mode(
    mode: str,
    *,
    root: Path,
    image_id: str,
    tools: Path,
    referee: Path,
    host_environment: dict[str, str],
) -> dict[str, object]:
    mode_root = root / mode
    workspace = mode_root / "workspace"
    runtime = mode_root / "runtime"
    gateway = mode_root / "gateway"
    evidence = mode_root / "relay-evidence"
    logs = mode_root / "logs"
    for path in (mode_root, workspace, runtime, gateway, logs):
        path.mkdir(mode=0o700)

    config = boundary.codex_provider_config(MODEL, "high").encode("utf-8")
    prepare_runtime(runtime, config)
    if mode == "managed":
        (workspace / "AGENTS.md").write_text(
            "# Prepared worker guide\n\n" + MANAGED_BLOCK,
            encoding="utf-8",
        )

    auth_read, auth_write = os.pipe()
    try:
        os.write(auth_write, PROVIDER_CANARY)
    finally:
        os.close(auth_write)
    attempts: list[dict[str, object]] = []
    expectation = boundary.ContextExpectation(
        mode,
        MANAGED_BLOCK if mode == "managed" else None,
        forbidden_fragments=(
            ("host-checkout", os.fspath(REPO)),
            ("host-edict", "edict:managed-start"),
        ),
    )
    state = relay.RelayState.create(
        relay.RelayPolicy(
            MODEL,
            max_request_bytes=2 << 20,
            max_response_bytes=256 << 10,
            max_requests=2,
            max_total_bytes=6 << 20,
            max_output_tokens=32768,
            max_tools=64,
            timeout_seconds=10,
        ),
        evidence,
        expectation,
        lambda: FakeConnection(mode, attempts),
        auth_fd=auth_read,
    )
    stop = threading.Event()
    server_errors: list[BaseException] = []

    def serve() -> None:
        try:
            relay.serve_unix(state, gateway / "model.sock", stop)
        except BaseException as error:
            server_errors.append(error)

    server = threading.Thread(target=serve, name=f"installed-codex-relay-{mode}")
    proxy_attempts: list[dict[str, object]] = []
    proxy_server = threading.Thread(
        target=serve_fake_proxy,
        args=(gateway / "proxy.sock", stop, server_errors, proxy_attempts),
        name=f"installed-codex-proxy-{mode}",
    )
    server.start()
    proxy_server.start()
    wait_for(gateway / "model.sock", server_errors, server)
    wait_for(gateway / "proxy.sock", server_errors, proxy_server)

    final_message = f"/runtime/artifacts/{mode}-final-message.txt"
    codex_argv = boundary.codex_exec_argv(
        "/opt/scourge-bin/codex",
        MODEL,
        "high",
        mode,
        project="/workspace",
        final_message=final_message,
    )
    cidfile = mode_root / "worker.cid"
    run_suffix = hashlib.sha256(os.fspath(root).encode("utf-8")).hexdigest()[:12]
    container_name = f"scourge-codex-compat-{mode}-{run_suffix}"
    supervised_codex = boundary.SupervisedCodex(
        supervisor=boundary.PinnedExecutable(
            tools / "native-codex-supervisor",
            boundary.SUPERVISOR_CONTAINER_PATH,
            digest(tools / "native-codex-supervisor"),
        ),
        codex=boundary.PinnedExecutable(
            CODEX,
            boundary.CODEX_CONTAINER_PATH,
            CODEX_SHA256,
        ),
        codex_argv=tuple(codex_argv),
    )
    podman_argv = boundary.build_podman_argv(
        podman_executable=PODMAN[0],
        oci_runtime=OCI_RUNTIME,
        auto_remove=False,
        interactive=True,
        image_id=image_id,
        name=container_name,
        cidfile=cidfile,
        workspace=workspace,
        runtime=runtime,
        gateway=gateway,
        readonly_mounts=(),
        protected_roots=(REPO, referee),
        supervised_codex=supervised_codex,
        proxy_port=PROXY_PORT,
    )
    production_podman_argv = boundary.build_podman_argv(
        podman_executable=PODMAN[0],
        oci_runtime=OCI_RUNTIME,
        auto_remove=True,
        interactive=True,
        image_id=image_id,
        name=f"scourge-production-{mode}-{run_suffix}",
        cidfile=mode_root / "production-worker.cid",
        workspace=workspace,
        runtime=runtime,
        gateway=gateway,
        readonly_mounts=(),
        protected_roots=(REPO, referee),
        supervised_codex=supervised_codex,
        proxy_port=PROXY_PORT,
    )

    completed = None
    inspection = None
    container_id = None
    remove_attempted = False
    exists_exit = None
    process_observations: list[dict[str, object]] = []
    process_stop = threading.Event()
    process_watcher = threading.Thread(
        target=watch_container_processes,
        args=(cidfile, process_stop, state, host_environment, process_observations),
        name=f"installed-codex-process-watcher-{mode}",
    )
    process_watcher.start()
    try:
        completed = run(
            podman_argv,
            timeout=60,
            check=False,
            environment=host_environment,
            input_data=PROMPT,
        )
        (logs / "worker.stdout").write_bytes(completed.stdout)
        (logs / "worker.stderr").write_bytes(completed.stderr)
        if cidfile.is_file():
            container_id = cidfile.read_text(encoding="ascii").strip()
            if container_id:
                inspected = run([*PODMAN, "inspect", container_id], environment=host_environment)
                inspection = json.loads(inspected.stdout)[0]
    finally:
        process_stop.set()
        process_watcher.join(timeout=5)
        if cidfile.is_file():
            candidate = cidfile.read_text(encoding="ascii").strip()
            if candidate:
                container_id = candidate
                remove_attempted = True
                run([*PODMAN, "rm", "--force", candidate], check=False, environment=host_environment)
                exists_exit = run(
                    [*PODMAN, "container", "exists", candidate],
                    check=False,
                    environment=host_environment,
                ).returncode
        stop.set()
        server.join(timeout=5)
        proxy_server.join(timeout=5)

    if server.is_alive() or proxy_server.is_alive():
        raise RuntimeError("relay did not stop")
    if process_watcher.is_alive():
        raise RuntimeError("process-lineage watcher did not stop")
    if server_errors:
        raise server_errors[0]
    relay_receipt = state.finalize()
    request_summaries = []
    for request_record in relay_receipt["requests"]:
        request_path = request_record.get("request_body_path")
        if isinstance(request_path, str):
            request_summaries.append(summarize_request((evidence / request_path).read_bytes()))
    worker_receipt_path = runtime / "artifacts/native-codex-supervisor.json"
    worker_receipt = (
        json.loads(worker_receipt_path.read_bytes()) if worker_receipt_path.is_file() else None
    )
    worker_environ_path = runtime / "artifacts/worker-environ.bin"
    environment_evidence = boundary.effective_worker_environment_evidence(
        worker_environ_path.read_bytes() if worker_environ_path.is_file() else b"",
        inspection or {},
        proxy_port=PROXY_PORT,
    )
    if completed is None:
        raise RuntimeError("Codex worker did not start")
    final_path = runtime / f"artifacts/{mode}-final-message.txt"
    final_data = final_path.read_bytes() if final_path.is_file() else b""
    first_request = request_summaries[0] if len(request_summaries) == 2 else None
    tool_result_request = request_summaries[1] if len(request_summaries) == 2 else None
    request_records = relay_receipt["requests"]
    tool_names = {
        tool.get("name") for tool in (first_request or {}).get("tools", [])
        if isinstance(tool, dict)
    }
    disabled_features = {
        codex_argv[index + 1]
        for index, value in enumerate(codex_argv[:-1])
        if value == "--disable"
    }
    production_manifest = boundary.podman_manifest(production_podman_argv)
    qualification_manifest = boundary.podman_manifest(podman_argv)
    image_position = production_podman_argv.index(image_id)
    production_parity = bool(
        production_podman_argv[:4]
        == [PODMAN[0], "--remote=false", f"--runtime={OCI_RUNTIME}", "run"]
        and production_podman_argv.count("--rm") == 1
        and production_podman_argv.count("--unsetenv-all") == 1
        and production_podman_argv.count("--interactive") == 1
        and production_podman_argv.index("--rm") < image_position
        and production_podman_argv.index("--unsetenv-all") < image_position
        and production_podman_argv.index("--interactive") < image_position
        and production_manifest["hostname"] == boundary.WORKER_HOSTNAME
        and production_manifest["environment_names"]
        == sorted(boundary.worker_environment(proxy_port=PROXY_PORT))
        and production_podman_argv[
            production_podman_argv.index("--entrypoint") + 1
        ] == boundary.SUPERVISOR_CONTAINER_PATH
        and production_manifest["supervised_codex"]["valid"] is True
        and production_podman_argv[-1] == "-"
    )
    process_lineage = summarize_process_lineage(process_observations)
    mount_access = {
        row["Destination"]: bool(row["RW"])
        for row in (inspection or {}).get("Mounts", [])
        if isinstance(row, dict)
    }
    tool_file = workspace / "installed-codex-tool-roundtrip.txt"
    tool_file_data = tool_file.read_bytes() if tool_file.is_file() else b""
    valid = bool(
        completed.returncode == 0
        and relay_receipt["valid"] is True
        and relay_receipt["accounting"]["accepted_requests"] == 2
        and relay_receipt["accounting"]["reconciled"] is True
        and len(attempts) == 2
        and len(request_records) == 2
        and all(
            attempt["request_body_sha256"] == record["provider_body_sha256"]
            for attempt, record in zip(attempts, request_records, strict=True)
        )
        and first_request is not None
        and first_request["previous_response_id_present"] is False
        and first_request["max_output_tokens"] is None
        and tool_names == set(EXPECTED_CLIENT_TOOLS)
        and tool_result_request is not None
        and tool_result_request["offline_tool_call_id_present"] is True
        and tool_result_request["offline_tool_output_marker_present"] is True
        and all(
            record["provider_body_transformations"] == [
                "client-metadata-stripped",
                "prompt-cache-key-replaced",
                "host-output-token-cap-injected",
            ]
            for record in request_records
        )
        and all(
            attempt["client_metadata_present"] is False
            and attempt["max_output_tokens"] == state.policy.max_output_tokens
            and attempt["model"] == MODEL
            and attempt["prompt_cache_key_host_scoped"] is True
            for attempt in attempts
        )
        and len({attempt["prompt_cache_key_sha256"] for attempt in attempts}) == 2
        and all(
            attempt["prompt_cache_key_sha256"]
            != request["prompt_cache_key_sha256"]
            for attempt, request in zip(attempts, request_summaries, strict=True)
        )
        and [row["tool_call_count"] for row in relay_receipt["terminals"]] == [1, 0]
        and relay_receipt["first_request_context"]["valid"] is True
        and worker_receipt is not None
        and worker_receipt["codex"]["exit_code"] == 0
        and worker_receipt["codex"]["timed_out"] is False
        and worker_receipt["self_sha256"]
        == production_manifest["supervised_codex"]["supervisor_sha256"]
        and worker_receipt["codex_sha256"] == CODEX_SHA256
        and worker_receipt["prompt"]["bytes"] == len(PROMPT)
        and worker_receipt["prompt"]["sha256"] == hashlib.sha256(PROMPT).hexdigest()
        and worker_receipt["prompt"]["write_complete"] is True
        and worker_receipt["prompt"]["write_timed_out"] is False
        and worker_receipt["fatal_route_failure"] is False
        and worker_receipt["codex"]["interrupted_by_signal"] is None
        and worker_receipt["routes"]["model"]["loopback_port"] == 18080
        and worker_receipt["routes"]["model"]["unix_socket"] == "/gateway/model.sock"
        and worker_receipt["routes"]["model"]["sessions"] == 2
        and worker_receipt["routes"]["model"]["refused"] == 0
        and worker_receipt["routes"]["model"]["client_to_unix_bytes"] > 0
        and worker_receipt["routes"]["model"]["unix_to_client_bytes"] > 0
        and worker_receipt["routes"]["model"]["active"] == 0
        and worker_receipt["routes"]["proxy"]["loopback_port"] == PROXY_PORT
        and worker_receipt["routes"]["proxy"]["unix_socket"] == "/gateway/proxy.sock"
        and worker_receipt["routes"]["proxy"]["sessions"] == 1
        and worker_receipt["routes"]["proxy"]["refused"] == 0
        and worker_receipt["routes"]["proxy"]["client_to_unix_bytes"]
        == len(PROXY_PAYLOAD)
        and worker_receipt["routes"]["proxy"]["active"] == 0
        and worker_receipt["teardown"] == {
            "routes_inactive": True,
            "process_group_quiescent": True,
            "sigkill_escalated": False,
            "complete": True,
        }
        and process_lineage["valid"] is True
        and proxy_attempts == [{
            "request_bytes": len(PROXY_PAYLOAD),
            "request_sha256": hashlib.sha256(PROXY_PAYLOAD).hexdigest(),
            "payload_exact": True,
        }]
        and tool_file_data == (TOOL_MARKER + "\n").encode("ascii")
        and final_data.strip() == b"offline Codex compatibility confirmed."
        and inspection is not None
        and inspection["HostConfig"]["NetworkMode"] == "none"
        and inspection["HostConfig"]["ReadonlyRootfs"] is True
        and mount_access == EXPECTED_MOUNTS
        and {"code_mode", "code_mode_host"} <= disabled_features
        and "shell_snapshot" in disabled_features
        and environment_evidence["valid"] is True
        and qualification_manifest["required_flags_complete"] is True
        and qualification_manifest["podman_executable"] == PODMAN[0]
        and qualification_manifest["oci_runtime"] == OCI_RUNTIME
        and qualification_manifest["auto_remove"] is False
        and qualification_manifest["interactive"] is True
        and qualification_manifest["unsetenv_all"] is True
        and qualification_manifest["hostname"] == boundary.WORKER_HOSTNAME
        and qualification_manifest["supervised_codex"]["valid"] is True
        and production_parity
        and remove_attempted
        and exists_exit == 1
    )
    manifest = qualification_manifest
    return {
        "mode": mode,
        "status": "settled" if valid else "unsettled",
        "valid": valid,
        "score": None,
        "request": first_request,
        "requests": request_summaries,
        "relay": relay_receipt,
        "fake_upstream_attempts": attempts,
        "fake_proxy_attempts": proxy_attempts,
        "provider_config": {
            "bytes": len(config),
            "sha256": hashlib.sha256(config).hexdigest(),
            "base_url": boundary.PROVIDER_BASE_URL,
            "wire_api": "responses",
            "requires_openai_auth": False,
        },
        "codex_argv": {
            "sha256": hashlib.sha256(
                b"\0".join(value.encode("utf-8") for value in codex_argv)
            ).hexdigest(),
            "sandbox": codex_argv[codex_argv.index("--sandbox") + 1],
            "ignore_rules": "--ignore-rules" in codex_argv,
            "ignore_user_config": "--ignore-user-config" in codex_argv,
            "project_doc_max_bytes": 0 if mode == "executable" else 65536,
            "provider": boundary.PROVIDER_NAME,
            "disabled_features": sorted(disabled_features),
            "code_mode_enabled": "code_mode" not in disabled_features,
            "code_mode_host_enabled": "code_mode_host" not in disabled_features,
            "shell_snapshot_enabled": "shell_snapshot" not in disabled_features,
        },
        "container": {
            "container_id": container_id,
            "network": inspection["HostConfig"]["NetworkMode"] if inspection else None,
            "read_only_rootfs": inspection["HostConfig"]["ReadonlyRootfs"]
            if inspection else None,
            "launch_argv_sha256": manifest["argv_sha256"],
            "required_flags_complete": manifest["required_flags_complete"],
            "launch_shape_valid": manifest["launch_shape_valid"],
            "podman_executable": manifest["podman_executable"],
            "oci_runtime": manifest["oci_runtime"],
            "auto_remove": manifest["auto_remove"],
            "interactive": manifest["interactive"],
            "unsetenv_all": manifest["unsetenv_all"],
            "hostname": manifest["hostname"],
            "supervised_codex": manifest["supervised_codex"],
            "environment_names": manifest["environment_names"],
            "credential_environment_names": manifest["credential_environment_names"],
            "mount_access": mount_access,
            "remove_attempted": remove_attempted,
            "exists_probe_exit_code": exists_exit,
            "removed": exists_exit == 1,
        },
        "effective_environment": environment_evidence,
        "production_collector_parity": {
            "valid": production_parity,
            "argv_sha256": production_manifest["argv_sha256"],
            "podman_executable": production_manifest["podman_executable"],
            "oci_runtime": production_manifest["oci_runtime"],
            "auto_remove": production_manifest["auto_remove"],
            "interactive": production_manifest["interactive"],
            "unsetenv_all": production_manifest["unsetenv_all"],
            "hostname": production_manifest["hostname"],
            "environment_names": production_manifest["environment_names"],
            "entrypoint": boundary.SUPERVISOR_CONTAINER_PATH,
            "supervised_codex": production_manifest["supervised_codex"],
            "stdin_prompt": "bounded-supervisor-stdin-to-final-dash",
        },
        "worker": worker_receipt,
        "process_lineage": process_lineage,
        "worker_log": {
            "stdout": sanitized_log(completed.stdout, root),
            "stderr": sanitized_log(completed.stderr, root),
            "stdout_sha256": hashlib.sha256(completed.stdout).hexdigest(),
            "stderr_sha256": hashlib.sha256(completed.stderr).hexdigest(),
        },
        "final_message": {
            "present": final_path.is_file(),
            "bytes": len(final_data),
            "sha256": hashlib.sha256(final_data).hexdigest(),
            "matches_offline_terminal": (
                final_data.strip() == b"offline Codex compatibility confirmed."
            ),
        },
        "tool_roundtrip": {
            "tool": "exec_command",
            "call_id": TOOL_CALL_ID,
            "request_count": len(request_summaries),
            "result_request_observed": bool(
                tool_result_request
                and tool_result_request["offline_tool_call_id_present"] is True
                and tool_result_request["offline_tool_output_marker_present"] is True
            ),
            "workspace_file_present": tool_file.is_file(),
            "workspace_file_bytes": len(tool_file_data),
            "workspace_file_sha256": hashlib.sha256(tool_file_data).hexdigest(),
            "valid": (
                tool_file_data == (TOOL_MARKER + "\n").encode("ascii")
                and bool(
                    tool_result_request
                    and tool_result_request["offline_tool_call_id_present"] is True
                    and tool_result_request["offline_tool_output_marker_present"] is True
                )
            ),
        },
    }


def qualify() -> dict[str, object]:
    if CODEX.resolve(strict=True) != CODEX or not CODEX.is_file():
        raise RuntimeError("pinned Codex path is not one canonical regular file")
    if digest(CODEX) != CODEX_SHA256:
        raise RuntimeError("pinned Codex digest changed")
    host_environment = {
        key: value for key, value in os.environ.items() if not _CREDENTIAL_ENV.search(key)
    }
    with tempfile.TemporaryDirectory(prefix="scourge-installed-codex-compat-") as temporary:
        root = Path(temporary).resolve()
        root.chmod(0o700)
        tools = root / "tools"
        referee = root / "referee"
        tools.mkdir(mode=0o700)
        referee.mkdir(mode=0o700)
        sources = {
            "native_codex_boundary.py": LIB / "native_codex_boundary.py",
            "responses_relay.py": LIB / "responses_relay.py",
            "native-codex-supervisor.rs": SUPERVISOR_SOURCE,
            "qualification_driver.py": Path(__file__).resolve(),
        }
        supervisor, supervisor_build = compile_supervisor(tools, host_environment)

        rootless = run(
            [*PODMAN, "info", "--format", "{{.Host.Security.Rootless}}"],
            environment=host_environment,
        )
        if rootless.stdout.strip() != b"true":
            raise RuntimeError("rootless Podman is required")
        image_id = run(
            [*PODMAN, "image", "inspect", "--format", "{{.Id}}", IMAGE],
            environment=host_environment,
        ).stdout.decode("ascii").strip().removeprefix("sha256:")
        if image_id != IMAGE_ID:
            raise RuntimeError("pinned Debian worker image changed")
        version_home = root / "version-home"
        version_home.mkdir(mode=0o700)
        version_environment = dict(host_environment)
        version_environment.update({"CODEX_HOME": os.fspath(version_home), "HOME": os.fspath(root)})
        version = run([os.fspath(CODEX), "--version"], environment=version_environment)
        version_text = version.stdout.decode("utf-8").strip()
        if version_text != CODEX_VERSION:
            raise RuntimeError("pinned Codex version output changed")
        capabilities = inspect_codex_capabilities(root, host_environment)

        modes = {
            mode: qualify_mode(
                mode,
                root=root,
                image_id=image_id,
                tools=tools,
                referee=referee,
                host_environment=host_environment,
            )
            for mode in ("executable", "managed")
        }
        supervisor_probes = {
            kind: qualify_supervisor_probe(
                kind,
                root=root,
                image_id=image_id,
                supervisor=supervisor,
                referee=referee,
                host_environment=host_environment,
            )
            for kind in (
                "dead_model",
                "dead_proxy",
                "broken_stdin",
                "stubborn_group",
                "direct_term_ignore",
                "signal_escape",
                "sigkill",
            )
        }
        valid = all(row["valid"] is True for row in modes.values()) and all(
            row["valid"] is True for row in supervisor_probes.values()
        )
        result = {
            "schema": "scourge.installed-codex-compatibility",
            "schema_version": 1,
            "observed_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
            "status": "settled" if valid else "unsettled",
            "valid": valid,
            "score": None,
            "limits": [
                "exact installed Codex request compatibility only",
                "offline fake Responses upstream",
                "rootless Podman network none",
                "no live provider or model call",
                "exact compiled production supervisor and two-socket topology",
                (
                    "production 900-second timeout helper exercised at 40 ms; "
                    "exact 900-second wall clock not run"
                ),
                "fake local proxy payload only; frozen Teapot is qualified separately",
            ],
            "codex": {
                "path": os.fspath(CODEX),
                "sha256": CODEX_SHA256,
                "bytes": CODEX.stat().st_size,
                "version": version_text,
                "capabilities": capabilities,
            },
            "runtime": {
                "image": IMAGE,
                "image_id": image_id,
                "rootless": True,
                "network": "none",
                "supervisor": supervisor_build,
            },
            "sources": {name: digest(path) for name, path in sources.items()},
            "modes": modes,
            "supervisor_probes": supervisor_probes,
        }
        encoded = compact(result) + b"\n"
        if PROVIDER_CANARY in encoded:
            raise RuntimeError("provider canary reached compatibility receipt")
        if os.fspath(root).encode() in encoded or os.fspath(REPO).encode() in encoded:
            raise RuntimeError("host path reached compatibility receipt")
        return result


def main(argv=sys.argv[1:]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output")
    args = parser.parse_args(argv)
    result = qualify()
    data = compact(result) + b"\n"
    if args.output:
        Path(args.output).write_bytes(data)
    sys.stdout.buffer.write(data)
    return 0 if result["valid"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
