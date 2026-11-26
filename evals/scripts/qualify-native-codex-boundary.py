#!/usr/bin/env python3
"""Offline rootless-Podman qualification for the native Codex boundary."""

from __future__ import annotations

import argparse
import base64
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
IMAGE = "docker.io/library/python:3.12-alpine"
MODEL = "gpt-offline-boundary-qualification"
PROXY_PORT = 19080
PROVIDER_CANARY = b"offline-provider-canary-bn-3plk"
_CREDENTIAL_ENV = re.compile(
    r"(?:^|_)(?:api_?key|auth|bearer|credential|password|secret|token)(?:_|$)", re.I
)


def compact(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def run(command, *, timeout=30, check=True, environment=None):
    completed = subprocess.run(
        command,
        check=False,
        capture_output=True,
        timeout=timeout,
        env=environment,
    )
    if check and completed.returncode:
        raise RuntimeError(
            f"command failed ({completed.returncode}): {command[0]}: "
            f"{completed.stderr.decode(errors='replace')}"
        )
    return completed


class FakeResponse:
    status = 200

    def __init__(self):
        event = {
            "type": "response.completed",
            "response": {
                "id": "resp_offline_qualification",
                "status": "completed",
                "usage": {"input_tokens": 19, "output_tokens": 5, "total_tokens": 24},
            },
        }
        self.body = b"event: response.completed\n" + b"data: " + compact(event) + b"\n\n"
        self.offset = 0

    def read(self, amount):
        chunk = self.body[self.offset:self.offset + amount]
        self.offset += len(chunk)
        return chunk

    def getheaders(self):
        return [("Content-Type", "text/event-stream"), ("Content-Encoding", "identity")]


class FakeConnection:
    def __init__(self, attempts):
        self.attempts = attempts

    def request(self, method, path, *, body, headers):
        if method != "POST" or path != "/v1/responses":
            raise AssertionError("relay changed the fixed upstream request")
        if headers.get("Authorization") != f"Bearer {PROVIDER_CANARY.decode('ascii')}":
            raise AssertionError("relay did not use descriptor-owned authentication")
        if headers.get("Accept-Encoding") != "identity":
            raise AssertionError("relay did not pin identity encoding")
        if "worker-header-canary" in json.dumps(headers) or "worker-api-key-canary" in json.dumps(headers):
            raise AssertionError("worker credential header reached fake upstream")
        self.attempts.append({
            "method": method,
            "path": path,
            "request_body_bytes": len(body),
            "request_body_sha256": hashlib.sha256(body).hexdigest(),
            "authorization_source": "host-descriptor-canary",
            "accept_encoding": headers.get("Accept-Encoding"),
        })

    def getresponse(self):
        return FakeResponse()

    def close(self):
        pass


def wait_for(path, errors, thread):
    deadline = time.monotonic() + 5
    while not path.exists():
        if errors:
            raise errors[0]
        if not thread.is_alive():
            raise RuntimeError("relay exited before socket readiness")
        if time.monotonic() >= deadline:
            raise RuntimeError("relay socket readiness timeout")
        time.sleep(0.02)


def serve_fake_proxy(path, stop, errors, attempts):
    response = b"offline proxy topology ok\n"
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
                connection.sendall(response)
                attempts.append({
                    "request_bytes": len(body),
                    "request_sha256": hashlib.sha256(body).hexdigest(),
                    "response_bytes": len(response),
                    "response_sha256": hashlib.sha256(response).hexdigest(),
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


def sanitized_log(data, run_root):
    text = data.decode("utf-8", errors="replace")
    return text.replace(os.fspath(run_root), "<RUN_ROOT>").replace(os.fspath(REPO), "<CHECKOUT>")


def qualify():
    host_environment = {
        key: value for key, value in os.environ.items() if not _CREDENTIAL_ENV.search(key)
    }
    with tempfile.TemporaryDirectory(prefix="scourge-native-qualification-") as temporary:
        root = Path(temporary).resolve()
        root.chmod(0o700)
        workspace = root / "workspace"
        runtime = root / "runtime"
        gateway = root / "gateway"
        evidence = root / "relay-evidence"
        tools = root / "tools"
        referee = root / "referee"
        logs = root / "logs"
        for path in (workspace, runtime, gateway, tools, referee, logs):
            path.mkdir(mode=0o700)
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
            path.mkdir(mode=0o700)

        sources = {
            "native_codex_boundary.py": LIB / "native_codex_boundary.py",
            "responses_relay.py": LIB / "responses_relay.py",
            "native-fake-codex.py": SCRIPT_DIR / "fixtures/native-fake-codex.py",
            "native-responses-forwarder.py": SCRIPT_DIR / "fixtures/native-responses-forwarder.py",
            "qualification_driver.py": Path(__file__).resolve(),
        }
        staged_fake = tools / "native-fake-codex.py"
        staged_forwarder = tools / "native-responses-forwarder.py"
        shutil.copyfile(sources["native-fake-codex.py"], staged_fake)
        shutil.copyfile(sources["native-responses-forwarder.py"], staged_forwarder)

        rootless = run([*PODMAN, "info", "--format", "{{.Host.Security.Rootless}}"], environment=host_environment)
        if rootless.stdout.strip() != b"true":
            raise RuntimeError("rootless Podman is required")
        image = run(
            [*PODMAN, "image", "inspect", "--format", "{{.Id}}", IMAGE],
            environment=host_environment,
        ).stdout.decode("ascii").strip()
        if image.startswith("sha256:"):
            image = image.removeprefix("sha256:")
        version = run([*PODMAN, "--version"], environment=host_environment).stdout.decode().strip()

        auth_read, auth_write = os.pipe()
        try:
            os.write(auth_write, PROVIDER_CANARY)
        finally:
            os.close(auth_write)
        attempts = []
        state = relay.RelayState.create(
            relay.RelayPolicy(
                MODEL,
                max_request_bytes=65536,
                max_response_bytes=65536,
                max_requests=1,
                max_total_bytes=131072,
                max_output_tokens=128,
                timeout_seconds=10,
            ),
            evidence,
            boundary.ContextExpectation(
                "executable",
                forbidden_fragments=(
                    ("host-checkout", os.fspath(REPO)),
                    ("host-agents", "edict:managed-start"),
                ),
            ),
            lambda: FakeConnection(attempts),
            auth_fd=auth_read,
        )
        stop = threading.Event()
        server_errors = []
        proxy_attempts = []

        def serve():
            try:
                relay.serve_unix(state, gateway / "model.sock", stop)
            except BaseException as error:  # retained and raised in the main thread
                server_errors.append(error)

        server = threading.Thread(target=serve, name="offline-responses-relay")
        proxy_server = threading.Thread(
            target=serve_fake_proxy,
            args=(gateway / "proxy.sock", stop, server_errors, proxy_attempts),
            name="offline-proxy-relay",
        )
        server.start()
        proxy_server.start()
        wait_for(gateway / "model.sock", server_errors, server)
        wait_for(gateway / "proxy.sock", server_errors, proxy_server)
        expected_gateway_sockets = ["model.sock", "proxy.sock"]
        observed_gateway_sockets = sorted(path.name for path in gateway.iterdir())
        gateway_modes = {
            path.name: stat.S_IMODE(path.lstat().st_mode) for path in gateway.iterdir()
        }

        cidfile = root / "worker.cid"
        name = "scourge-native-offline-" + hashlib.sha256(os.fspath(root).encode()).hexdigest()[:16]
        argv = boundary.build_podman_argv(
            podman_executable=PODMAN[0],
            oci_runtime=OCI_RUNTIME,
            auto_remove=False,
            interactive=False,
            image_id=image,
            name=name,
            cidfile=cidfile,
            workspace=workspace,
            runtime=runtime,
            gateway=gateway,
            readonly_mounts=(
                boundary.ReadOnlyMount(staged_fake, "/opt/scourge-bin/native-fake-codex.py"),
                boundary.ReadOnlyMount(staged_forwarder, "/opt/adapter/native-responses-forwarder.py"),
            ),
            protected_roots=(REPO, referee),
            entrypoint="/usr/local/bin/python3",
            command=("-I", "/opt/scourge-bin/native-fake-codex.py", MODEL),
            proxy_port=PROXY_PORT,
        )

        completed = None
        container_id = None
        mounts = []
        inspection = None
        inspect_exit_code = None
        remove_attempted = False
        exists_exit = None
        try:
            completed = run(argv, timeout=30, check=False, environment=host_environment)
            (logs / "worker.stdout").write_bytes(completed.stdout)
            (logs / "worker.stderr").write_bytes(completed.stderr)
            if not cidfile.is_file():
                raise RuntimeError("Podman did not publish a container ID")
            container_id = cidfile.read_text(encoding="ascii").strip()
            inspected = run([*PODMAN, "inspect", container_id], environment=host_environment)
            inspect_exit_code = inspected.returncode
            inspection = json.loads(inspected.stdout)[0]
            mounts = inspection["Mounts"]
        finally:
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
        if server_errors:
            raise server_errors[0]
        relay_receipt = state.finalize()
        if completed is None:
            raise RuntimeError("worker did not start")
        worker_receipt_path = runtime / "artifacts/worker-probes.json"
        if not worker_receipt_path.is_file():
            raise RuntimeError(
                "worker probe missing: " + sanitized_log(completed.stderr, root)
            )
        worker = json.loads(worker_receipt_path.read_bytes())
        if inspection is None:
            raise RuntimeError("container inspection missing")
        launch_manifest = boundary.podman_manifest(argv)
        worker_proxy = worker["proxy_forwarding"]
        host_proxy = proxy_attempts[0] if len(proxy_attempts) == 1 else None
        proxy_reconciled = (
            isinstance(worker_proxy, dict)
            and host_proxy is not None
            and {
                key: worker_proxy[key]
                for key in (
                    "request_bytes", "request_sha256", "response_bytes", "response_sha256"
                )
            } == host_proxy
        )

        expected_destinations = sorted([
            "/gateway",
            "/opt/adapter/native-responses-forwarder.py",
            "/opt/scourge-bin/native-fake-codex.py",
            "/runtime",
            "/workspace",
        ])
        observed_destinations = sorted(row["Destination"] for row in mounts)
        proc_blobs = [
            path.read_bytes() for path in sorted((runtime / "artifacts/proc").glob("*.cmdline"))
        ]
        worker_environ = (runtime / "artifacts/worker-environ.bin").read_bytes()
        proc_blobs.append(worker_environ)
        environment_evidence = boundary.effective_worker_environment_evidence(
            worker_environ,
            inspection,
            proxy_port=PROXY_PORT,
        )
        canary = boundary.credential_canary_evidence(
            PROVIDER_CANARY,
            worker_environment_values=boundary.worker_environment(proxy_port=PROXY_PORT),
            worker_proc_blobs=proc_blobs,
            worker_roots=(workspace, runtime, tools),
            artifact_roots=(runtime / "artifacts", evidence, logs),
        )
        probes = {
            "schema": boundary.PROBE_SCHEMA,
            "schema_version": boundary.SCHEMA_VERSION,
            "credential_canary_absence": canary,
            "environment": environment_evidence,
            "protected_paths": worker["protected_paths"],
            "direct_egress": worker["direct_egress"],
            "mounts": {
                "container_id": container_id,
                "allowlist": {
                    "attempted": True,
                    "expected_destinations": expected_destinations,
                    "observed_destinations": observed_destinations,
                    "exact": observed_destinations == expected_destinations,
                },
                "write_probes": worker["write_probes"],
            },
            "gateway": {
                "container_id": container_id,
                "inspect": {
                    "attempted": True,
                    "expected_sockets": expected_gateway_sockets,
                    "observed_sockets": observed_gateway_sockets,
                    "exact": observed_gateway_sockets == expected_gateway_sockets,
                    "modes": gateway_modes,
                },
                "proxy": {
                    "attempted": worker_proxy["attempted"],
                    "port": worker_proxy["port"],
                    "connected": worker_proxy["connected"],
                    "worker": {
                        key: worker_proxy[key]
                        for key in (
                            "request_bytes",
                            "request_sha256",
                            "response_bytes",
                            "response_sha256",
                        )
                    },
                    "host": {"attempts": len(proxy_attempts), **(host_proxy or {})},
                    "reconciled": proxy_reconciled,
                },
            },
            "isolation": {
                "container_id": container_id,
                "podman_info": {
                    "attempted": True,
                    "exit_code": rootless.returncode,
                    "rootless": rootless.stdout.strip() == b"true",
                    "remote": False,
                },
                "launch": {
                    "attempted": True,
                    "argv_sha256": launch_manifest["argv_sha256"],
                    "required_flags_present": launch_manifest["required_flags_present"],
                    "required_flags_complete": launch_manifest["required_flags_complete"],
                    "launch_shape_valid": launch_manifest["launch_shape_valid"],
                    "podman_executable": launch_manifest["podman_executable"],
                    "oci_runtime": launch_manifest["oci_runtime"],
                    "auto_remove": launch_manifest["auto_remove"],
                    "interactive": launch_manifest["interactive"],
                    "unsetenv_all": launch_manifest["unsetenv_all"],
                    "hostname": launch_manifest["hostname"],
                    "environment_names": launch_manifest["environment_names"],
                    "proxy_port": PROXY_PORT,
                    "credential_environment_names": launch_manifest[
                        "credential_environment_names"
                    ],
                },
                "inspect": {
                    "attempted": True,
                    "exit_code": inspect_exit_code,
                    "network_mode": inspection["HostConfig"]["NetworkMode"],
                    "read_only_rootfs": inspection["HostConfig"]["ReadonlyRootfs"],
                    "cap_add": sorted(
                        value.lower() for value in (inspection["HostConfig"]["CapAdd"] or [])
                    ),
                    "cap_drop": sorted(
                        value.lower() for value in (inspection["HostConfig"]["CapDrop"] or [])
                    ),
                    "security_opt": sorted(inspection["HostConfig"]["SecurityOpt"] or []),
                    "pids_limit": inspection["HostConfig"]["PidsLimit"],
                    "userns_mode": inspection["HostConfig"]["UsernsMode"],
                },
                "worker": worker["runtime_security"],
            },
            "teardown": {
                "worker": {
                    "attempted": True,
                    "stopped": completed.returncode is not None,
                    "exit_code": completed.returncode,
                },
                "forwarder": worker["forwarder"],
                "container": {
                    "container_id": container_id,
                    "remove_attempted": remove_attempted,
                    "exists_probe_exit_code": exists_exit,
                    "removed": exists_exit == 1,
                },
            },
        }
        boundary_receipt = boundary.settle_boundary(relay_receipt, probes)
        request_path = relay_receipt["requests"][0]["request_body_path"]
        exact_request = (evidence / request_path).read_bytes()
        result = {
            "schema": "scourge.native-codex-offline-qualification",
            "schema_version": 1,
            "observed_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
            "status": boundary_receipt["status"],
            "valid": boundary_receipt["valid"],
            "score": None,
            "limits": [
                "offline fake Codex process",
                "offline fake upstream",
                "no live provider or model call",
                "native Codex integration remains runner acceptance",
            ],
            "runtime": {
                "podman": version,
                "rootless": True,
                "image": IMAGE,
                "image_id": image,
                "network": "none",
                "gateway_sockets": expected_gateway_sockets,
                "proxy_port": PROXY_PORT,
                "worker_exit_code": completed.returncode,
            },
            "sources": {name: digest(path) for name, path in sources.items()},
            "fake_upstream_attempts": attempts,
            "fake_proxy_attempts": proxy_attempts,
            "worker_log": {
                "stdout": sanitized_log(completed.stdout, root),
                "stderr": sanitized_log(completed.stderr, root),
                "stdout_sha256": hashlib.sha256(completed.stdout).hexdigest(),
                "stderr_sha256": hashlib.sha256(completed.stderr).hexdigest(),
            },
            "retained_first_request": {
                "encoding": "base64",
                "bytes": len(exact_request),
                "sha256": hashlib.sha256(exact_request).hexdigest(),
                "data": base64.b64encode(exact_request).decode("ascii"),
            },
            "boundary": boundary_receipt,
        }
        encoded = compact(result) + b"\n"
        if PROVIDER_CANARY in encoded:
            raise RuntimeError("provider canary reached qualification receipt")
        if not boundary_receipt["valid"]:
            raise RuntimeError(encoded.decode("ascii"))
        return result


def main(argv=sys.argv[1:]):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output")
    args = parser.parse_args(argv)
    result = qualify()
    data = compact(result) + b"\n"
    if args.output:
        destination = Path(args.output)
        destination.write_bytes(data)
    sys.stdout.buffer.write(data)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
