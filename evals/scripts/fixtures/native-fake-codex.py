#!/usr/bin/env python3
"""Credential-free fake Codex and in-worker probe for offline qualification."""

import glob
import hashlib
import http.client
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time


PROTECTED = {
    "fixture_source": "/referee/fixture-source",
    "ground_truth": "/referee/ground-truth.json",
    "admin_secret": "/referee/admin-secret",
    "hidden_canaries": "/referee/hidden-canaries",
    "grading_state": "/referee/grading-state",
}
PAYLOAD = b"scourge native boundary probe\n"


def client_tools():
    tools = [
        {
            "type": "function",
            "name": name,
            "parameters": {
                "type": "object",
                "properties": {},
                "additionalProperties": False,
            },
            "strict": False,
        }
        for name in (
            "exec_command",
            "write_stdin",
            "request_user_input",
            "view_image",
            "get_goal",
            "create_goal",
            "update_goal",
        )
    ]
    tools.insert(3, {
        "type": "custom",
        "name": "apply_patch",
        "format": {
            "type": "grammar",
            "syntax": "lark",
            "definition": "start: /.+/",
        },
    })
    return tools


def refused(path, flags):
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as error:
        return {
            "attempted": True,
            "refused": True,
            "errno": error.errno if error.errno else -1,
            "error": error.strerror or type(error).__name__,
            "path": path,
        }
    else:
        os.close(descriptor)
        return {"attempted": True, "refused": False, "errno": 0, "error": "opened", "path": path}


def writable(directory):
    path = Path(directory) / ".scourge-boundary-write-probe"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    cleaned = False
    try:
        with os.fdopen(descriptor, "wb") as writer:
            written = writer.write(PAYLOAD)
            writer.flush()
            os.fsync(writer.fileno())
        path.unlink()
        cleaned = True
        parent = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
    return {
        "attempted": True,
        "succeeded": written == len(PAYLOAD),
        "bytes_written": written,
        "cleaned": cleaned,
        "path": directory,
    }


def direct_egress():
    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connection.settimeout(1)
    try:
        connection.connect(("192.0.2.1", 443))
    except OSError as error:
        return {
            "attempted": True,
            "destination": "192.0.2.1:443",
            "connected": False,
            "errno": error.errno if error.errno else -1,
            "error": error.strerror or type(error).__name__,
        }
    finally:
        connection.close()
    return {
        "attempted": True,
        "destination": "192.0.2.1:443",
        "connected": True,
        "errno": 0,
        "error": "connected",
    }


def proxy_forwarding():
    port_text = os.environ.get("M0_PROXY_PORT")
    if port_text is None:
        return None
    payload = b"offline proxy topology probe"
    connection = socket.create_connection(("127.0.0.1", int(port_text)), timeout=3)
    try:
        connection.sendall(payload)
        connection.shutdown(socket.SHUT_WR)
        response = b""
        while chunk := connection.recv(4096):
            response += chunk
    finally:
        connection.close()
    return {
        "attempted": True,
        "port": int(port_text),
        "connected": True,
        "request_bytes": len(payload),
        "request_sha256": hashlib.sha256(payload).hexdigest(),
        "response_bytes": len(response),
        "response_sha256": hashlib.sha256(response).hexdigest(),
    }


def capture_proc(artifacts):
    proc = artifacts / "proc"
    proc.mkdir()
    (artifacts / "worker-environ.bin").write_bytes(Path("/proc/self/environ").read_bytes())
    for value in sorted(glob.glob("/proc/[0-9]*/cmdline")):
        path = Path(value)
        try:
            data = path.read_bytes()
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
        (proc / f"{path.parent.name}.cmdline").write_bytes(data)


def runtime_security():
    fields = {}
    for line in Path("/proc/self/status").read_text(encoding="ascii").splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            fields[key] = value.strip()
    return {
        "cap_eff": fields.get("CapEff", ""),
        "no_new_privs": int(fields.get("NoNewPrivs", "-1")),
    }


def main(model):
    artifacts = Path("/runtime/artifacts")
    forwarder = subprocess.Popen([
        sys.executable, "-I", "/opt/adapter/native-responses-forwarder.py"
    ])
    deadline = time.monotonic() + 5
    while not Path("/runtime/forwarder.ready").is_file():
        if forwarder.poll() is not None:
            raise RuntimeError("forwarder exited before readiness")
        if time.monotonic() >= deadline:
            raise RuntimeError("forwarder readiness timeout")
        time.sleep(0.02)

    protected = {}
    for label, path in PROTECTED.items():
        protected[label] = {
            "read": refused(path, os.O_RDONLY | os.O_NOFOLLOW),
            "write": refused(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW),
        }
    write_probes = {
        "workspace": writable("/workspace"),
        "runtime": writable("/runtime"),
        "binaries": [
            refused("/opt/scourge-bin/native-fake-codex.py", os.O_WRONLY | os.O_NOFOLLOW),
            refused("/opt/adapter/native-responses-forwarder.py", os.O_WRONLY | os.O_NOFOLLOW),
        ],
        "gateway": refused(
            "/gateway/.scourge-boundary-write-probe",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        ),
        "rootfs": refused(
            "/.scourge-boundary-write-probe",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        ),
    }
    # Bind directory-level probes to the receipt paths expected by the host.
    write_probes["gateway"]["path"] = "/gateway"
    write_probes["rootfs"]["path"] = "/"
    egress = direct_egress()
    capture_proc(artifacts)
    proxy = proxy_forwarding()

    body = json.dumps({
        "model": model,
        "input": [{
            "role": "user",
            "content": [{
                "type": "input_text",
                "text": "prepared executable-only cell",
            }],
        }],
        "stream": True,
        "store": False,
        "max_output_tokens": 64,
        "client_metadata": {
            "root_turn_id": "root-offline",
            "session_id": "session-offline",
            "thread_id": "thread-offline",
            "turn_id": "turn-offline",
            "x-codex-installation-id": "install-offline",
            "x-codex-turn-metadata": "{}",
            "x-codex-window-id": "window-offline",
        },
        "include": ["reasoning.encrypted_content"],
        "parallel_tool_calls": True,
        "prompt_cache_key": "018f0f70-4b2d-7000-8000-000000000002",
        "reasoning": {"effort": "high"},
        "text": {"verbosity": "low"},
        "tool_choice": "auto",
        "tools": client_tools(),
    }, separators=(",", ":")).encode("ascii")
    connection = http.client.HTTPConnection("127.0.0.1", 18080, timeout=5)
    connection.request("POST", "/v1/responses", body=body, headers={
        "Content-Type": "application/json",
        "Authorization": "Bearer worker-header-canary",
        "X-Api-Key": "worker-api-key-canary",
        "Connection": "close",
    })
    response = connection.getresponse()
    response_body = response.read()
    connection.close()

    forwarder.terminate()
    try:
        forwarder_exit = forwarder.wait(timeout=3)
    except subprocess.TimeoutExpired:
        forwarder.kill()
        forwarder_exit = forwarder.wait(timeout=3)
    receipt = {
        "protected_paths": protected,
        "direct_egress": egress,
        "proxy_forwarding": proxy,
        "write_probes": write_probes,
        "forwarder": {
            "attempted": True,
            "stopped": forwarder.poll() is not None,
            "exit_code": forwarder_exit if forwarder_exit >= 0 else 128 - forwarder_exit,
        },
        "runtime_security": runtime_security(),
        "fake_codex": {
            "response_status": response.status,
            "response_bytes": len(response_body),
            "response_sha256": hashlib.sha256(response_body).hexdigest(),
        },
    }
    (artifacts / "worker-probes.json").write_text(
        json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n", encoding="ascii"
    )
    okay = (
        response.status == 200
        and not egress["connected"]
        and all(
            operation["refused"]
            for row in protected.values()
            for operation in row.values()
        )
        and write_probes["workspace"]["succeeded"]
        and write_probes["runtime"]["succeeded"]
        and all(row["refused"] for row in write_probes["binaries"])
        and write_probes["gateway"]["refused"]
        and write_probes["rootfs"]["refused"]
    )
    return 0 if okay else 2


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: native-fake-codex.py MODEL")
    raise SystemExit(main(sys.argv[1]))
