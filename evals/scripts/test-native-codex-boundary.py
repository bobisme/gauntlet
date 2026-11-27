#!/usr/bin/env python3
"""Adversarial offline checks for the native Codex worker boundary."""

from __future__ import annotations

from io import BytesIO
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock


LIB = Path(__file__).resolve().parent / "lib"
sys.path.insert(0, str(LIB))
import native_codex_boundary as boundary  # noqa: E402
import responses_relay as relay  # noqa: E402


PROVIDER_CREDENTIAL = b"provider-canary-5f319bd1"
WORKER_CREDENTIAL = "worker-supplied-credential"
MODEL = "gpt-test-pinned"
MANAGED_BLOCK = (
    "<!-- scourge:managed-start -->\n"
    "Use only the prepared Scourge workflow.\n"
    "<!-- scourge:managed-end -->\n"
)
PROMPT_CACHE_KEY = "018f0f70-4b2d-7000-8000-000000000001"


def client_tools():
    function_names = (
        "exec_command",
        "write_stdin",
        "request_user_input",
        "view_image",
        "get_goal",
        "create_goal",
        "update_goal",
    )
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
        for name in function_names
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


def request_body(*, model=MODEL, instructions="prepared task", suffix=None):
    value = {
        "model": model,
        "input": [{
            "role": "user",
            "content": [{"type": "input_text", "text": instructions}],
        }],
        "stream": True,
        "store": False,
        "max_output_tokens": 1024,
        "client_metadata": {
            "root_turn_id": "root-1",
            "session_id": "session-1",
            "thread_id": "thread-1",
            "turn_id": "turn-1",
            "x-codex-installation-id": "install-1",
            "x-codex-turn-metadata": "{}",
            "x-codex-window-id": "window-1",
        },
        "include": ["reasoning.encrypted_content"],
        "parallel_tool_calls": True,
        "prompt_cache_key": PROMPT_CACHE_KEY,
        "reasoning": {"effort": "high"},
        "text": {"verbosity": "low"},
        "tool_choice": "auto",
        "tools": client_tools(),
    }
    if suffix:
        value.update(suffix)
    return json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def completed_sse(response_id="resp_offline"):
    event = {
        "type": "response.completed",
        "response": {
            "id": response_id,
            "status": "completed",
            "usage": {"input_tokens": 31, "output_tokens": 7, "total_tokens": 38},
        },
    }
    return b"event: response.completed\n" + b"data: " + json.dumps(event).encode("ascii") + b"\n\n"


def tool_sse(
    response_id="resp_tool", *, item_id="fc_tool", call_id="call_tool",
    status="completed",
):
    item = {
        "id": item_id,
        "type": "function_call",
        "status": status,
        "name": "exec_command",
        "call_id": call_id,
        "arguments": "{}",
    }
    done = {
        "type": "response.output_item.done",
        "output_index": 0,
        "item": item,
    }
    terminal = {
        "type": "response.completed",
        "response": {
            "id": response_id,
            "status": "completed",
            "output": [item],
            "usage": {"input_tokens": 31, "output_tokens": 7, "total_tokens": 38},
        },
    }
    return (
        b"event: response.output_item.done\n"
        + b"data: " + json.dumps(done).encode("ascii") + b"\n\n"
        + b"event: response.completed\n"
        + b"data: " + json.dumps(terminal).encode("ascii") + b"\n\n"
    )


def incremental_message_sse(
    response_id="resp_incremental", *, streamed="SAFE", terminal=None,
):
    item_id = "msg_incremental"
    terminal_text = streamed if terminal is None else terminal
    seed = {
        "id": item_id, "type": "message", "status": "in_progress",
        "role": "assistant", "content": [],
    }
    done_item = {
        "id": item_id, "type": "message", "status": "completed",
        "role": "assistant", "content": [{
            "type": "output_text", "text": terminal_text,
            "annotations": [], "logprobs": [],
        }],
    }
    events = [
        {"type": "response.created", "response": {
            "id": response_id, "status": "in_progress",
        }},
        {"type": "response.output_item.added", "output_index": 0,
         "item": seed},
        {"type": "response.content_part.added", "item_id": item_id,
         "output_index": 0, "content_index": 0,
         "part": {"type": "output_text", "text": "", "annotations": [],
                  "logprobs": []}},
        {"type": "response.output_text.delta", "item_id": item_id,
         "output_index": 0, "content_index": 0, "delta": streamed},
        {"type": "response.output_text.done", "item_id": item_id,
         "output_index": 0, "content_index": 0, "text": streamed},
        {"type": "response.content_part.done", "item_id": item_id,
         "output_index": 0, "content_index": 0,
         "part": {"type": "output_text", "text": streamed,
                  "annotations": [], "logprobs": []}},
        {"type": "response.output_item.done", "output_index": 0,
         "item": done_item},
        {"type": "response.completed", "response": {
            "id": response_id, "status": "completed", "output": [done_item],
            "usage": {"input_tokens": 1, "output_tokens": 1,
                      "total_tokens": 2},
        }},
    ]
    return b"".join(
        b"event: " + event["type"].encode("ascii") + b"\n"
        + b"data: " + json.dumps(event).encode("ascii") + b"\n\n"
        for event in events
    )


def incremental_tool_sse(item_type="function_call"):
    function = item_type == "function_call"
    item_id = "fc_incremental" if function else "ctc_incremental"
    name = "exec_command" if function else "apply_patch"
    value_key = "arguments" if function else "input"
    event_prefix = (
        "response.function_call_arguments" if function
        else "response.custom_tool_call_input"
    )
    seed = {
        "id": item_id, "type": item_type, "status": "in_progress",
        "name": name, "call_id": "call_incremental", value_key: "",
    }
    done_item = dict(seed, status="completed", **{value_key: "{}"})
    events = [
        {"type": "response.output_item.added", "output_index": 0,
         "item": seed},
        {"type": f"{event_prefix}.delta", "item_id": item_id,
         "output_index": 0, "delta": "{}"},
        {"type": f"{event_prefix}.done", "item_id": item_id,
         "output_index": 0, value_key: "{}"},
        {"type": "response.output_item.done", "output_index": 0,
         "item": done_item},
        {"type": "response.completed", "response": {
            "id": "resp_incremental_tool", "status": "completed",
            "output": [done_item],
            "usage": {"input_tokens": 1, "output_tokens": 1,
                      "total_tokens": 2},
        }},
    ]
    return b"".join(
        b"event: " + event["type"].encode("ascii") + b"\n"
        + b"data: " + json.dumps(event).encode("ascii") + b"\n\n"
        for event in events
    )


def decode_sse(body):
    return [json.loads(record.split(b"\n")[1][6:])
            for record in body.split(b"\n\n")[:-1]]


def encode_sse(events):
    return b"".join(
        b"event: " + event["type"].encode("ascii") + b"\n"
        + b"data: " + json.dumps(event).encode("ascii") + b"\n\n"
        for event in events
    )


class FakeResponse:
    def __init__(
        self, body=None, *, status=200, content_type="text/event-stream", content_encoding=None
    ):
        self.body = body if body is not None else completed_sse()
        self.status = status
        self.offset = 0
        self.headers = [("Content-Type", content_type), ("X-Ignored-Upstream", "value")]
        if content_encoding is not None:
            self.headers.append(("Content-Encoding", content_encoding))

    def read(self, amount):
        chunk = self.body[self.offset:self.offset + amount]
        self.offset += len(chunk)
        return chunk

    def getheaders(self):
        return list(self.headers)


class FakeConnection:
    def __init__(self, response=None):
        self.response = response or FakeResponse()
        self.requests = []
        self.closed = False

    def request(self, method, path, *, body, headers):
        self.requests.append((method, path, body, dict(headers)))

    def getresponse(self):
        return self.response

    def close(self):
        self.closed = True


class ConnectionPool:
    def __init__(self, responses):
        self.responses = list(responses)
        self.connections = []

    def __call__(self):
        connection = FakeConnection(self.responses.pop(0))
        self.connections.append(connection)
        return connection


class BoundaryTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="scourge-native-boundary-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()

    def state(self, *, context=None, policy=None, connection=None, connection_factory=None):
        evidence = self.root / f"evidence-{len(list(self.root.glob('evidence-*')))}"
        connection = connection or FakeConnection()
        auth_read, auth_write = os.pipe()
        os.write(auth_write, PROVIDER_CREDENTIAL)
        os.close(auth_write)
        factory = connection_factory or (lambda: connection)
        state = relay.RelayState.create(
            policy or relay.RelayPolicy(MODEL, max_requests=4),
            evidence,
            context or boundary.ContextExpectation(
                "executable", forbidden_fragments=(("host-checkout", "/host/project/context"),)
            ),
            factory,
            auth_fd=auth_read,
        )
        return state, connection_factory or connection, evidence

    def valid_request(self, state, body=None, headers=None):
        return state.handle(
            "POST",
            "/v1/responses",
            "HTTP/1.1",
            headers or [
                ("Host", "127.0.0.1:18080"),
                ("Content-Type", "application/json"),
                ("Authorization", f"Bearer {WORKER_CREDENTIAL}"),
                ("X-Api-Key", WORKER_CREDENTIAL),
            ],
            body or request_body(),
        )

    def test_append_only_tool_history_binds_only_known_completed_chains(self):
        first = {
            "id": "fc_first", "type": "function_call", "status": "completed",
            "name": "exec_command", "call_id": "call_first", "arguments": "{}",
        }
        second = {
            "id": "fc_second", "type": "function_call", "status": "completed",
            "name": "write_stdin", "call_id": "call_second", "arguments": "{}",
        }
        first_output = {"type": "function_call_output", "id": "fco_first",
                        "call_id": "call_first", "output": "running"}
        second_output = {"type": "function_call_output", "id": "fco_second",
                         "call_id": "call_second", "output": "done"}
        previous = [{"type": "message", "id": "msg_user", "role": "user", "content": []},
                    first, first_output]
        history = [*previous, second, second_output]
        self.assertTrue(relay._request_binds_tool_chain(
            history, previous, [second],
        ))
        adversarial = (
            history + [{"type": "function_call_output", "id": "fco_unknown",
                        "call_id": "call_unknown", "output": "x"}],
            [dict(previous[0], role="assistant"), *history[1:]],
            [*previous, second_output, second],
            [*previous, second],
            [*previous, second, second_output, second_output],
            [*previous, {"type": "message", "id": "msg_injected", "role": "assistant",
                         "content": []}, second, second_output],
            [*previous, dict(second, arguments='{"changed":true}'), second_output],
            [*previous, second, dict(second_output, call_id="call_foreign")],
            [*previous, second, dict(second_output, id="msg_user")],
            [*previous, dict(second, id="msg_user"), second_output],
            [*previous, second, dict(second_output, id="fc_second")],
        )
        for rows in adversarial:
            with self.subTest(rows=rows):
                self.assertFalse(relay._request_binds_tool_chain(rows, previous, [second]))

    def test_fd_auth_custom_provider_and_native_argv_are_credential_free(self):
        read_fd, write_fd = os.pipe()
        os.write(write_fd, PROVIDER_CREDENTIAL)
        os.close(write_fd)
        self.assertEqual(boundary.read_provider_credential(read_fd), PROVIDER_CREDENTIAL)
        with self.assertRaises(OSError):
            os.read(read_fd, 1)
        auth_file = self.root / "auth-file"
        auth_file.write_bytes(PROVIDER_CREDENTIAL)
        with self.assertRaisesRegex(boundary.BoundaryError, "auth-file-descriptor-refused"):
            boundary.read_provider_credential(os.open(auth_file, os.O_RDONLY))

        config = boundary.codex_provider_config(MODEL, "high")
        self.assertIn('base_url = "http://127.0.0.1:18080/v1"', config)
        self.assertIn('wire_api = "responses"', config)
        self.assertIn("requires_openai_auth = false", config)
        argv = boundary.codex_exec_argv(
            "/opt/scourge-bin/codex", MODEL, "high", "executable"
        )
        serialized = "\x00".join(argv)
        self.assertNotIn(PROVIDER_CREDENTIAL.decode(), serialized)
        self.assertNotIn("codex-launch.py", serialized)
        self.assertNotIn("CODEX_API_KEY", serialized)
        self.assertIn("project_doc_max_bytes=0", argv)
        self.assertEqual(argv[argv.index("--sandbox") + 1], "danger-full-access")
        self.assertIn("--ignore-rules", argv)
        self.assertIn("code_mode", argv)
        self.assertIn("code_mode_host", argv)
        self.assertIn("shell_snapshot", argv)
        self.assertEqual(argv[argv.index("code_mode") - 1], "--disable")
        self.assertEqual(argv[argv.index("code_mode_host") - 1], "--disable")
        self.assertEqual(argv[argv.index("shell_snapshot") - 1], "--disable")
        self.assertEqual(argv[argv.index("--add-dir") + 1], "/runtime")
        managed = boundary.codex_exec_argv(
            "/opt/scourge-bin/codex", MODEL, "high", "managed"
        )
        self.assertIn("--ignore-rules", managed)
        self.assertEqual(managed[managed.index("shell_snapshot") - 1], "--disable")
        self.assertEqual(managed[managed.index("--sandbox") + 1], "danger-full-access")
        self.assertIn("project_doc_max_bytes=65536", managed)

    def test_rootless_podman_argv_has_exact_mount_and_environment_boundary(self):
        workspace = self.root / "workspace"
        runtime = self.root / "runtime"
        gateway = self.root / "gateway"
        tools = self.root / "tools"
        protected = self.root / "referee"
        for path in (workspace, runtime, gateway, tools, protected):
            path.mkdir()
        gateway.chmod(0o700)
        codex = tools / "codex"
        forwarder = tools / "forward.js"
        podman = tools / "podman"
        crun = tools / "crun"
        codex.write_bytes(b"binary")
        codex.chmod(0o700)
        forwarder.write_text("// pinned", encoding="ascii")
        podman.write_bytes(b"podman")
        crun.write_bytes(b"crun")
        podman.chmod(0o700)
        crun.chmod(0o700)
        hidden = protected / "ground-truth.json"
        hidden.write_text("withheld", encoding="ascii")
        socket_path = gateway / "model.sock"
        socket_path.touch()
        socket_paths = {socket_path}
        actual_lstat = Path.lstat

        def socket_lstat(path):
            info = actual_lstat(path)
            if path in socket_paths:
                values = list(info)
                values[0] = stat.S_IFSOCK | 0o600
                return os.stat_result(values)
            return info

        # This execution sandbox prohibits AF_UNIX bind. Keep the product's
        # real socket-type check and replace only that one lstat witness here.
        with mock.patch.object(Path, "lstat", socket_lstat):
            argv = boundary.build_podman_argv(
                podman_executable=podman,
                oci_runtime=crun,
                auto_remove=True,
                interactive=True,
                image_id="a" * 64,
                name="scourge-native-test",
                cidfile=self.root / "worker.cid",
                workspace=workspace,
                runtime=runtime,
                gateway=gateway,
                readonly_mounts=(
                    boundary.ReadOnlyMount(codex, "/opt/scourge-bin/codex"),
                    boundary.ReadOnlyMount(forwarder, "/opt/adapter/forward.js"),
                ),
                protected_roots=(protected, hidden),
                entrypoint="/opt/scourge-bin/codex",
                command=("--version",),
            )
        manifest = boundary.podman_manifest(argv)
        self.assertTrue(manifest["required_flags_complete"])
        self.assertTrue(manifest["launch_shape_valid"])
        self.assertEqual(
            argv[:4],
            [os.fspath(podman), "--remote=false", f"--runtime={crun}", "run"],
        )
        image_position = argv.index("a" * 64)
        for option in ("--rm", "--unsetenv-all", "--interactive"):
            self.assertEqual(argv.count(option), 1)
            self.assertLess(argv.index(option), image_position)
        self.assertIn(f"--hostname={boundary.WORKER_HOSTNAME}", argv[:image_position])
        self.assertIn(f"HOSTNAME={boundary.WORKER_HOSTNAME}", argv[:image_position])
        self.assertEqual(manifest["credential_environment_names"], [])
        self.assertIn("--network=none", argv)
        self.assertIn("--read-only", argv)
        self.assertIn("--cap-drop=all", argv)
        self.assertIn("--security-opt=no-new-privileges", argv)
        self.assertFalse(any(os.fspath(protected) in value for value in argv))
        duplicate_interactive = list(argv)
        duplicate_interactive.insert(image_position, "--interactive")
        self.assertFalse(
            boundary.podman_manifest(duplicate_interactive)["launch_shape_valid"]
        )
        after_image = [value for value in argv if value != "--interactive"]
        after_image.insert(after_image.index("a" * 64) + 1, "--interactive")
        self.assertFalse(boundary.podman_manifest(after_image)["launch_shape_valid"])
        misplaced_runtime = list(argv)
        runtime_word = misplaced_runtime.pop(2)
        misplaced_runtime.insert(misplaced_runtime.index("a" * 64), runtime_word)
        self.assertFalse(
            boundary.podman_manifest(misplaced_runtime)["launch_shape_valid"]
        )
        self.assertEqual(
            [value for value in manifest["mounts"] if "ro=true" not in value],
            [
                f"type=bind,src={workspace},dst=/workspace",
                f"type=bind,src={runtime},dst=/runtime",
            ],
        )
        with mock.patch.object(Path, "lstat", socket_lstat):
            with self.assertRaisesRegex(boundary.BoundaryError, "protected-root-mounted"):
                boundary.build_podman_argv(
                    podman_executable=podman,
                    oci_runtime=crun,
                    auto_remove=False,
                    interactive=False,
                    image_id="a" * 64,
                    name="scourge-native-test-2",
                    cidfile=self.root / "worker-2.cid",
                    workspace=workspace,
                    runtime=runtime,
                    gateway=gateway,
                    readonly_mounts=(boundary.ReadOnlyMount(hidden, "/opt/forbidden"),),
                    protected_roots=(protected,),
                    entrypoint="/opt/forbidden",
                    command=("--version",),
                )

        proxy_socket = gateway / "proxy.sock"
        proxy_socket.touch()
        socket_paths.add(proxy_socket)
        with mock.patch.object(Path, "lstat", socket_lstat):
            with self.assertRaisesRegex(boundary.BoundaryError, "gateway-socket-set-not-exact"):
                boundary.build_podman_argv(
                    podman_executable=podman,
                    oci_runtime=crun,
                    auto_remove=False,
                    interactive=False,
                    image_id="a" * 64,
                    name="scourge-native-test-extra-socket",
                    cidfile=self.root / "worker-extra.cid",
                    workspace=workspace,
                    runtime=runtime,
                    gateway=gateway,
                    readonly_mounts=(
                        boundary.ReadOnlyMount(codex, "/opt/scourge-bin/codex"),
                        boundary.ReadOnlyMount(forwarder, "/opt/adapter/forward.js"),
                    ),
                    protected_roots=(protected,),
                    entrypoint="/opt/scourge-bin/codex",
                    command=("--version",),
                )
            proxy_argv = boundary.build_podman_argv(
                podman_executable=podman,
                oci_runtime=crun,
                auto_remove=False,
                interactive=False,
                image_id="a" * 64,
                name="scourge-native-test-proxy",
                cidfile=self.root / "worker-proxy.cid",
                workspace=workspace,
                runtime=runtime,
                gateway=gateway,
                readonly_mounts=(
                    boundary.ReadOnlyMount(codex, "/opt/scourge-bin/codex"),
                    boundary.ReadOnlyMount(forwarder, "/opt/adapter/forward.js"),
                ),
                protected_roots=(protected,),
                entrypoint="/opt/scourge-bin/codex",
                command=("--version",),
                proxy_port=19080,
            )
        self.assertIn("M0_PROXY_PORT=19080", proxy_argv)
        self.assertEqual(boundary.worker_environment(proxy_port=19080)["M0_PROXY_PORT"], "19080")
        supervisor = tools / "native-codex-supervisor"
        supervisor.write_bytes(b"static supervisor")
        supervisor.chmod(0o700)
        codex_argv = boundary.codex_exec_argv(
            boundary.CODEX_CONTAINER_PATH, MODEL, "high", "executable"
        )
        contract = boundary.SupervisedCodex(
            supervisor=boundary.PinnedExecutable(
                supervisor,
                boundary.SUPERVISOR_CONTAINER_PATH,
                hashlib.sha256(supervisor.read_bytes()).hexdigest(),
            ),
            codex=boundary.PinnedExecutable(
                codex,
                boundary.CODEX_CONTAINER_PATH,
                hashlib.sha256(codex.read_bytes()).hexdigest(),
            ),
            codex_argv=tuple(codex_argv),
        )
        with mock.patch.object(Path, "lstat", socket_lstat):
            supervised_argv = boundary.build_podman_argv(
                podman_executable=podman,
                oci_runtime=crun,
                auto_remove=True,
                interactive=True,
                image_id=boundary.PRODUCTION_IMAGE_ID,
                name="scourge-native-supervised",
                cidfile=self.root / "supervised.cid",
                workspace=workspace,
                runtime=runtime,
                gateway=gateway,
                readonly_mounts=(),
                protected_roots=(protected,),
                supervised_codex=contract,
                proxy_port=19080,
            )
        supervised_manifest = boundary.podman_manifest(supervised_argv)
        self.assertTrue(
            supervised_manifest["launch_shape_valid"],
            msg=repr((supervised_manifest, supervised_argv)),
        )
        self.assertTrue(supervised_manifest["supervised_codex"]["valid"])
        self.assertEqual(
            supervised_manifest["entrypoint"],
            boundary.SUPERVISOR_CONTAINER_PATH,
        )
        self.assertEqual(supervised_argv[-1], "-")
        self.assertEqual(
            supervised_manifest["supervised_codex"]["codex_argv_sha256"],
            hashlib.sha256(b"\0".join(value.encode() for value in codex_argv)).hexdigest(),
        )
        duplicate_supervisor_pin = list(supervised_argv)
        duplicate_supervisor_pin.insert(-1, "--self-sha256")
        self.assertFalse(
            boundary.podman_manifest(duplicate_supervisor_pin)["launch_shape_valid"]
        )
        supervised_after_image = list(supervised_argv)
        supervised_after_image.insert(
            supervised_after_image.index(boundary.PRODUCTION_IMAGE_ID) + 1,
            "--interactive",
        )
        self.assertFalse(
            boundary.podman_manifest(supervised_after_image)["launch_shape_valid"]
        )
        tampered_supervisor = boundary.SupervisedCodex(
            supervisor=boundary.PinnedExecutable(
                supervisor,
                boundary.SUPERVISOR_CONTAINER_PATH,
                "0" * 64,
            ),
            codex=contract.codex,
            codex_argv=contract.codex_argv,
        )
        with mock.patch.object(Path, "lstat", socket_lstat):
            with self.assertRaisesRegex(boundary.BoundaryError, "pinned-executable-mismatch"):
                boundary.build_podman_argv(
                    podman_executable=podman,
                    oci_runtime=crun,
                    auto_remove=True,
                    interactive=True,
                    image_id=boundary.PRODUCTION_IMAGE_ID,
                    name="scourge-native-supervisor-tamper",
                    cidfile=self.root / "supervisor-tamper.cid",
                    workspace=workspace,
                    runtime=runtime,
                    gateway=gateway,
                    readonly_mounts=(),
                    protected_roots=(protected,),
                    supervised_codex=tampered_supervisor,
                    proxy_port=19080,
                )
        with self.assertRaisesRegex(boundary.BoundaryError, "invalid-proxy-port"):
            boundary.worker_environment(proxy_port=18080)

    def test_effective_environment_rejects_cached_image_and_credential_inheritance(self):
        expected = boundary.worker_environment(proxy_port=19080)
        rows = [f"{name}={value}" for name, value in sorted(expected.items())]
        inspection = {
            "Config": {"Env": rows, "Hostname": boundary.WORKER_HOSTNAME}
        }
        exact = boundary.effective_worker_environment_evidence(
            b"\0".join(row.encode("ascii") for row in rows) + b"\0",
            inspection,
            proxy_port=19080,
        )
        self.assertTrue(exact["valid"])
        self.assertEqual(exact["observed_names"], sorted(expected))

        inherited = rows + [
            "GPG_KEY=image-default-canary",
            "PYTHON_VERSION=3.12.12",
            "PYTHON_SHA256=image-default-digest-canary",
        ]
        inherited_evidence = boundary.effective_worker_environment_evidence(
            b"\0".join(row.encode("ascii") for row in inherited) + b"\0",
            {"Config": {"Env": inherited, "Hostname": boundary.WORKER_HOSTNAME}},
            proxy_port=19080,
        )
        self.assertFalse(inherited_evidence["valid"])
        self.assertEqual(
            inherited_evidence["unexpected_names"],
            ["GPG_KEY", "PYTHON_SHA256", "PYTHON_VERSION"],
        )
        credential = rows + ["OPENAI_API_KEY=worker-secret-canary"]
        credential_evidence = boundary.effective_worker_environment_evidence(
            b"\0".join(row.encode("ascii") for row in credential) + b"\0",
            {"Config": {"Env": credential, "Hostname": boundary.WORKER_HOSTNAME}},
            proxy_port=19080,
        )
        self.assertFalse(credential_evidence["valid"])
        self.assertEqual(credential_evidence["credential_like_names"], ["OPENAI_API_KEY"])
        self.assertIsNone(credential_evidence["observed_sha256"])

    def test_relay_strips_worker_auth_and_records_exact_body_and_terminal(self):
        connection = FakeConnection()
        state, _connection, evidence = self.state(connection=connection)
        body = request_body(instructions="exact first request")
        status, headers, returned = self.valid_request(state, body)
        self.assertEqual(status, 200)
        self.assertEqual(headers["Content-Type"], "text/event-stream")
        self.assertEqual(returned, completed_sse())
        receipt = state.finalize()
        self.assertTrue(receipt["valid"])
        self.assertTrue(receipt["accounting"]["reconciled"])
        self.assertEqual(receipt["accounting"]["upstream_attempts"], 1)
        self.assertEqual(receipt["terminals"][0]["usage"]["total_tokens"], 38)
        self.assertEqual(receipt["requests"][0]["stripped_worker_headers"], [
            "authorization", "x-api-key"
        ])
        self.assertEqual((evidence / receipt["requests"][0]["request_body_path"]).read_bytes(), body)

        method, path, forwarded_body, forwarded_headers = connection.requests[0]
        self.assertEqual((method, path), ("POST", "/v1/responses"))
        forwarded = json.loads(forwarded_body)
        self.assertNotIn("client_metadata", forwarded)
        self.assertNotEqual(forwarded["prompt_cache_key"], PROMPT_CACHE_KEY)
        self.assertEqual(forwarded["max_output_tokens"], 1024)
        self.assertEqual(
            receipt["requests"][0]["provider_body_sha256"],
            hashlib.sha256(forwarded_body).hexdigest(),
        )
        self.assertEqual(
            forwarded_headers["Authorization"],
            f"Bearer {PROVIDER_CREDENTIAL.decode('ascii')}",
        )
        self.assertEqual(forwarded_headers["Accept-Encoding"], "identity")
        self.assertNotIn(WORKER_CREDENTIAL, json.dumps(forwarded_headers))
        artifacts = b"".join(path.read_bytes() for path in evidence.rglob("*") if path.is_file())
        self.assertNotIn(PROVIDER_CREDENTIAL, artifacts)

        compressed = FakeConnection(FakeResponse(content_encoding="gzip"))
        state, connection, _evidence = self.state(connection=compressed)
        self.assertEqual(self.valid_request(state)[0], 502)
        receipt = state.finalize()
        self.assertFalse(receipt["valid"])
        self.assertIn(
            "encoded-upstream-response-refused", {row["code"] for row in receipt["reasons"]}
        )
        self.assertEqual(connection.requests[0][3]["Accept-Encoding"], "identity")
        self.assertNotIn(WORKER_CREDENTIAL.encode(), artifacts)

    def test_evidence_store_is_dirfd_anchored_and_refuses_path_swaps(self):
        state, connection, evidence = self.state()
        receipt_info = (evidence / "relay.json").stat()
        self.assertTrue(stat.S_ISREG(receipt_info.st_mode))
        self.assertEqual(stat.S_IMODE(receipt_info.st_mode), 0o600)
        moved = evidence.with_name(evidence.name + "-moved")
        evidence.rename(moved)
        evidence.mkdir(mode=0o700)
        (evidence / "requests").mkdir(mode=0o700)
        with self.assertRaisesRegex(relay.RelayError, "evidence-root-replaced"):
            self.valid_request(state)
        self.assertEqual(connection.requests, [])
        self.assertEqual(list((evidence / "requests").iterdir()), [])

        state, connection, evidence = self.state()
        original_requests = evidence / "requests-original"
        (evidence / "requests").rename(original_requests)
        redirected = self.root / "redirected-requests"
        redirected.mkdir()
        (evidence / "requests").symlink_to(redirected, target_is_directory=True)
        with self.assertRaisesRegex(relay.RelayError, "evidence-requests-replaced"):
            self.valid_request(state)
        self.assertEqual(connection.requests, [])
        self.assertEqual(list(redirected.iterdir()), [])

        state, connection, evidence = self.state()
        target = self.root / "redirected-relay.json"
        target.write_bytes(b"unchanged")
        (evidence / "relay.json").unlink()
        (evidence / "relay.json").symlink_to(target)
        with self.assertRaisesRegex(relay.RelayError, "relay-receipt-replaced"):
            self.valid_request(state)
        self.assertEqual(connection.requests, [])
        self.assertEqual(target.read_bytes(), b"unchanged")

    def test_routes_models_sizes_retries_and_credential_echo_fail_closed(self):
        cases = (
            ("GET", "/v1/responses", request_body(), "unexpected-method"),
            ("POST", "/v1/chat/completions", request_body(), "unexpected-route"),
            ("POST", "/v1/responses", request_body(model="other"), "unexpected-model"),
            ("POST", "/v1/responses", request_body(suffix={"unknown": True}), "unexpected-request-body-field"),
            ("POST", "/v1/responses", b"{", "invalid-request-json"),
        )
        for method, path, body, reason in cases:
            with self.subTest(reason=reason):
                state, connection, evidence = self.state()
                status, _headers, _returned = state.handle(method, path, "HTTP/1.1", [], body)
                self.assertGreaterEqual(status, 400)
                receipt = state.finalize()
                self.assertFalse(receipt["valid"])
                self.assertIn(reason, {row["code"] for row in receipt["reasons"]})
                self.assertEqual(connection.requests, [])
                self.assertIsNone(receipt["score"])
                self.assertEqual(len(receipt["requests"]), 1)
                self.assertIsNone(receipt["requests"][0]["request_body_sha256"])
                self.assertIsNone(receipt["requests"][0]["request_body_path"])
                self.assertEqual(list((evidence / "requests").iterdir()), [])
                self.assertEqual(
                    receipt["accounting"]["budgeted_request_bytes"], len(body)
                )

        state, connection, _evidence = self.state()
        self.assertEqual(self.valid_request(state)[0], 200)
        self.assertEqual(self.valid_request(state)[0], 409)
        receipt = state.finalize()
        self.assertEqual(receipt["accounting"]["retry_refusals"], 1)
        self.assertEqual(len(connection.requests), 1)
        self.assertIn("retry-refused", {row["code"] for row in receipt["reasons"]})

        reflected = FakeConnection(FakeResponse(PROVIDER_CREDENTIAL))
        state, _connection, evidence = self.state(connection=reflected)
        self.assertEqual(self.valid_request(state)[0], 502)
        self.assertFalse(state.finalize()["valid"])
        artifacts = b"".join(path.read_bytes() for path in evidence.rglob("*") if path.is_file())
        self.assertNotIn(PROVIDER_CREDENTIAL, artifacts)

    def test_all_budgets_and_worker_controlled_receipt_fields_fail_closed(self):
        policy = relay.RelayPolicy(
            MODEL, max_request_bytes=64, max_response_bytes=64, max_requests=1,
            max_total_bytes=128,
        )
        state, connection, evidence = self.state(policy=policy)
        oversized = b"x" * 65
        self.assertEqual(
            state.handle("POST", "/v1/responses", "HTTP/1.1", [], oversized)[0], 413
        )
        receipt = state.finalize()
        self.assertIsNone(receipt["requests"][0]["request_body_path"])
        self.assertEqual(connection.requests, [])

        state, connection, evidence = self.state()
        hostile_target = "/" + PROVIDER_CREDENTIAL.decode()
        self.assertEqual(
            state.handle(
                PROVIDER_CREDENTIAL.decode(), hostile_target, "HTTP/hostile",
                [(PROVIDER_CREDENTIAL.decode(), PROVIDER_CREDENTIAL.decode())], request_body(),
            )[0],
            405,
        )
        receipt = state.finalize()
        row = receipt["requests"][0]
        self.assertEqual((row["method"], row["target"], row["http_version"]), (
            "unexpected", "unexpected", "unexpected"
        ))
        self.assertIsNone(row["target_bytes"])
        self.assertIsNone(row["target_sha256"])
        artifacts = b"".join(path.read_bytes() for path in evidence.rglob("*") if path.is_file())
        self.assertNotIn(PROVIDER_CREDENTIAL, artifacts)
        self.assertNotIn(
            hashlib.sha256(hostile_target.encode()).hexdigest().encode(), artifacts
        )

        state, connection, _evidence = self.state(
            policy=relay.RelayPolicy(MODEL, max_requests=1)
        )
        self.assertEqual(self.valid_request(state)[0], 200)
        self.assertEqual(
            self.valid_request(state, request_body(instructions="different second body"))[0], 429
        )
        self.assertEqual(len(connection.requests), 1)

        too_large_response = FakeConnection(FakeResponse(b"x" * 65))
        state, _connection, _evidence = self.state(
            policy=relay.RelayPolicy(MODEL, max_response_bytes=64),
            connection=too_large_response,
        )
        self.assertEqual(self.valid_request(state)[0], 502)
        self.assertIn(
            "response-body-budget-exceeded",
            {row["code"] for row in state.finalize()["reasons"]},
        )

        total_body = request_body()
        total_response = completed_sse()
        state, _connection, _evidence = self.state(policy=relay.RelayPolicy(
            MODEL,
            max_request_bytes=len(total_body),
            max_response_bytes=len(total_response),
            max_total_bytes=len(total_body) + len(total_response) - 1,
        ))
        self.assertEqual(self.valid_request(state)[0], 502)
        self.assertIn(
            "total-byte-budget-exceeded", {row["code"] for row in state.finalize()["reasons"]}
        )

        state, connection, evidence = self.state()
        credential_body = request_body(instructions=PROVIDER_CREDENTIAL.decode())
        self.assertEqual(self.valid_request(state, credential_body)[0], 400)
        receipt = state.finalize()
        self.assertIsNone(receipt["requests"][0]["request_body_bytes"])
        self.assertIsNone(receipt["requests"][0]["request_body_sha256"])
        self.assertIsNone(receipt["requests"][0]["request_body_path"])
        self.assertEqual(connection.requests, [])
        artifacts = b"".join(path.read_bytes() for path in evidence.rglob("*") if path.is_file())
        self.assertNotIn(PROVIDER_CREDENTIAL, artifacts)
        self.assertNotIn(
            hashlib.sha256(credential_body).hexdigest().encode(), artifacts
        )

    def test_rejected_flood_and_restart_are_hard_bounded_without_upstream(self):
        policy = relay.RelayPolicy(
            MODEL,
            max_request_bytes=3000,
            max_requests=1,
            max_total_bytes=4096,
            max_receipt_bytes=8192,
        )
        state, connection, evidence = self.state(policy=policy)
        statuses: list[int] = []
        barrier = threading.Barrier(20)

        def rejected_get() -> None:
            barrier.wait()
            statuses.append(
                state.handle(
                    "GET", "/v1/responses", "HTTP/1.1", [], b"x" * 3000
                )[0]
            )

        workers = [threading.Thread(target=rejected_get) for _ in range(20)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(timeout=5)
            self.assertFalse(worker.is_alive())
        self.assertEqual(statuses.count(405), 1)
        self.assertEqual(statuses.count(409), 19)

        receipt = state.finalize()
        files = [path for path in evidence.rglob("*") if path.is_file()]
        evidence_bytes = sum(path.stat().st_size for path in files)
        accounting = receipt["accounting"]
        self.assertEqual(connection.requests, [])
        self.assertEqual(accounting["inbound_requests"], 1)
        self.assertEqual(accounting["inbound_body_bytes"], 3000)
        self.assertEqual(accounting["rejected_request_bytes"], 3000)
        self.assertEqual(accounting["budgeted_request_bytes"], 3000)
        self.assertEqual(accounting["retained_request_artifacts"], 0)
        self.assertEqual(accounting["retained_request_artifact_bytes"], 0)
        self.assertEqual(accounting["retained_evidence_bytes"], evidence_bytes)
        self.assertLessEqual(
            evidence_bytes, policy.max_total_bytes + policy.max_receipt_bytes
        )
        self.assertEqual(len(receipt["requests"]), 1)
        self.assertLessEqual(len(receipt["reasons"]), 4)
        self.assertTrue(receipt["listener"]["poisoned"])
        self.assertEqual(list((evidence / "requests").iterdir()), [])
        frozen_receipt = (evidence / "relay.json").read_bytes()
        self.assertEqual(
            state.handle("GET", "/after-finalize", "HTTP/1.1", [], b"ignored")[0],
            409,
        )
        self.assertEqual((evidence / "relay.json").read_bytes(), frozen_receipt)
        self.assertEqual(len(state.requests), 1)

        auth_read, auth_write = os.pipe()
        os.write(auth_write, PROVIDER_CREDENTIAL)
        os.close(auth_write)
        with self.assertRaises(relay.RelayError):
            relay.RelayState.create(
                policy,
                evidence,
                boundary.ContextExpectation("executable"),
                lambda: FakeConnection(),
                auth_fd=auth_read,
            )

        state, connection, evidence = self.state(
            policy=relay.RelayPolicy(MODEL, max_requests=1)
        )
        self.assertEqual(self.valid_request(state)[0], 200)
        before = state.snapshot()
        self.assertEqual(
            [self.valid_request(state, request_body(instructions=str(index)))[0]
             for index in range(20)],
            [429] * 20,
        )
        after = state.finalize()
        self.assertEqual(connection.requests.__len__(), 1)
        self.assertEqual(len(after["requests"]), 1)
        self.assertEqual(
            after["accounting"]["retained_request_artifacts"], 1
        )
        self.assertEqual(
            before["accounting"]["budgeted_request_bytes"],
            after["accounting"]["budgeted_request_bytes"],
        )

    def test_nested_request_policy_allows_only_bounded_client_tools_and_safe_include(self):
        hosted = (
            "web_search", "web_search_preview", "file_search", "computer",
            "computer_use_preview", "code_interpreter", "image_generation", "mcp",
            "mcp_list_tools",
        )
        for tool_type in hosted:
            with self.subTest(tool_type=tool_type):
                state, connection, _evidence = self.state()
                status = self.valid_request(
                    state, request_body(suffix={"tools": [{"type": tool_type}]})
                )[0]
                self.assertEqual(status, 422)
                self.assertEqual(connection.requests, [])
                self.assertIn(
                    "hosted-response-tool-refused",
                    {row["code"] for row in state.finalize()["reasons"]},
                )

        state, connection, _evidence = self.state()
        self.assertEqual(
            self.valid_request(
                state, request_body(suffix={"tools": [{"type": "future_hosted_tool"}]})
            )[0],
            422,
        )
        self.assertEqual(connection.requests, [])
        self.assertIn(
            "unexpected-response-tool-type",
            {row["code"] for row in state.finalize()["reasons"]},
        )

        state, connection, _evidence = self.state()
        unsafe_include = ["reasoning.encrypted_content", "web_search_call.action.sources"]
        self.assertEqual(
            self.valid_request(state, request_body(suffix={"include": unsafe_include}))[0], 422
        )
        self.assertEqual(connection.requests, [])
        self.assertIn(
            "unsafe-response-include", {row["code"] for row in state.finalize()["reasons"]}
        )

        state, connection, _evidence = self.state()
        self.assertEqual(
            self.valid_request(
                state,
                request_body(suffix={"tool_choice": {"type": "web_search"}}),
            )[0],
            422,
        )
        self.assertEqual(connection.requests, [])
        self.assertIn(
            "hosted-response-tool-refused",
            {row["code"] for row in state.finalize()["reasons"]},
        )

        missing_cap = json.loads(request_body())
        del missing_cap["max_output_tokens"]
        state, connection, _evidence = self.state()
        self.assertEqual(
            self.valid_request(
                state, json.dumps(missing_cap, separators=(",", ":")).encode("ascii")
            )[0],
            200,
        )
        forwarded = json.loads(connection.requests[0][2])
        self.assertEqual(forwarded["max_output_tokens"], state.policy.max_output_tokens)
        receipt = state.finalize()
        self.assertTrue(receipt["valid"])
        self.assertEqual(
            receipt["requests"][0]["provider_body_transformations"],
            [
                "client-metadata-stripped",
                "prompt-cache-key-replaced",
                "host-output-token-cap-injected",
            ],
        )

        metadata = {
            "root_turn_id": "root-1",
            "session_id": "session-1",
            "thread_id": "thread-1",
            "turn_id": "turn-1",
            "x-codex-installation-id": "install-1",
            "x-codex-turn-metadata": "{}",
            "x-codex-window-id": "window-1",
        }
        state, connection, evidence = self.state()
        raw = request_body(suffix={"client_metadata": metadata})
        self.assertEqual(self.valid_request(state, raw)[0], 200)
        forwarded = json.loads(connection.requests[0][2])
        self.assertNotIn("client_metadata", forwarded)
        receipt = state.finalize()
        self.assertTrue(receipt["valid"])
        row = receipt["requests"][0]
        self.assertEqual(row["provider_body_transformations"], [
            "client-metadata-stripped",
            "prompt-cache-key-replaced",
        ])
        self.assertEqual((evidence / row["request_body_path"]).read_bytes(), raw)

        state, connection, _evidence = self.state()
        self.assertEqual(
            self.valid_request(
                state,
                request_body(suffix={"client_metadata": {"unexpected": "value"}}),
            )[0],
            422,
        )
        self.assertEqual(connection.requests, [])
        self.assertIn(
            "invalid-client-metadata",
            {row["code"] for row in state.finalize()["reasons"]},
        )

        state, connection, _evidence = self.state(
            policy=relay.RelayPolicy(MODEL, max_requests=4, max_tools=7)
        )
        self.assertEqual(
            self.valid_request(state)[0],
            422,
        )
        self.assertEqual(connection.requests, [])
        self.assertIn(
            "tool-budget-exceeded",
            {row["code"] for row in state.finalize()["reasons"]},
        )

        for tool, code in (
            ({"type": "local_shell"}, "unexpected-response-tool-type"),
            ({
                "type": "function",
                "name": "unknown_client_tool",
                "parameters": {"type": "object"},
            }, "unexpected-client-tool-name"),
        ):
            with self.subTest(tool=tool):
                state, connection, _evidence = self.state()
                tools = client_tools()
                tools[0] = tool
                self.assertEqual(
                    self.valid_request(state, request_body(suffix={"tools": tools}))[0],
                    422,
                )
                self.assertEqual(connection.requests, [])
                self.assertIn(code, {row["code"] for row in state.finalize()["reasons"]})

        removed_fields = {
            "instructions": "host instructions",
            "metadata": {"worker": "value"},
            "prompt_cache_retention": "24h",
            "safety_identifier": "worker-identity",
            "service_tier": "priority",
            "truncation": "auto",
        }
        for field, value in removed_fields.items():
            with self.subTest(removed_field=field):
                state, connection, _evidence = self.state()
                self.assertEqual(
                    self.valid_request(
                        state, request_body(suffix={field: value})
                    )[0],
                    400,
                )
                self.assertEqual(connection.requests, [])
                self.assertIn(
                    "unexpected-request-body-field",
                    {row["code"] for row in state.finalize()["reasons"]},
                )

        controlled = (
            ({"reasoning": {"effort": "medium"}}, "invalid-response-reasoning"),
            ({"reasoning": {"effort": "high", "summary": "auto"}},
             "invalid-response-reasoning"),
            ({"text": {"verbosity": "medium"}}, "invalid-response-text"),
            ({"parallel_tool_calls": False}, "invalid-parallel-tool-policy"),
            ({"tool_choice": "none"}, "invalid-tool-choice"),
            ({"prompt_cache_key": "worker-cache-key"}, "invalid-prompt-cache-key"),
            ({"prompt_cache_key": "a" * 257}, "invalid-prompt-cache-key"),
        )
        for suffix, code in controlled:
            with self.subTest(controlled=suffix):
                state, connection, _evidence = self.state()
                self.assertEqual(
                    self.valid_request(state, request_body(suffix=suffix))[0], 422
                )
                self.assertEqual(connection.requests, [])
                self.assertIn(code, {row["code"] for row in state.finalize()["reasons"]})

        required_fields = set(json.loads(request_body())) - {
            "max_output_tokens", "previous_response_id"
        }
        for field in required_fields:
            with self.subTest(missing_field=field):
                value = json.loads(request_body())
                del value[field]
                state, connection, _evidence = self.state()
                self.assertEqual(
                    self.valid_request(
                        state, json.dumps(value, separators=(",", ":")).encode("ascii")
                    )[0],
                    400,
                )
                self.assertEqual(connection.requests, [])
                self.assertIn(
                    "missing-request-body-field",
                    {row["code"] for row in state.finalize()["reasons"]},
                )

        pool = ConnectionPool([FakeResponse(completed_sse("resp_cache_one"))])
        state, _pool, _evidence = self.state(connection_factory=pool)
        self.assertEqual(self.valid_request(state)[0], 200)
        provider_keys = [
            json.loads(connection.requests[0][2])["prompt_cache_key"]
            for connection in pool.connections
        ]
        self.assertEqual(len(provider_keys), 1)
        self.assertNotIn(PROMPT_CACHE_KEY, provider_keys)
        self.assertTrue(state.finalize()["valid"])

    def test_checked_installed_codex_compatibility_receipt_is_source_bound(self):
        receipt_path = LIB.parent / "qualification/installed-codex-compatibility.json"
        receipt = json.loads(receipt_path.read_bytes())
        self.assertEqual(receipt["schema"], "scourge.installed-codex-compatibility")
        self.assertEqual(receipt["status"], "settled")
        self.assertTrue(receipt["valid"])
        self.assertIsNone(receipt["score"])
        self.assertEqual(receipt["codex"]["version"], "codex-cli 0.172.0")
        self.assertEqual(
            receipt["codex"]["sha256"],
            "ad83b94c093f0cdd8176a6bc8005a461bdf23a759863e157d40f562b8a9d664d",
        )
        capabilities = receipt["codex"]["capabilities"]
        self.assertEqual(
            capabilities["model"],
            {
                "shell_type": "unified_exec",
                "slug": "gpt-5.5",
                "supported_in_api": True,
                "tool_mode": None,
                "tool_mode_field_present": False,
                "visibility": "list",
            },
        )
        self.assertEqual(
            capabilities["features"],
            {
                "code_mode": {
                    "default_enabled": False,
                    "stage": "under development",
                },
                "code_mode_host": {"default_enabled": True, "stage": "stable"},
                "shell_snapshot": {"default_enabled": True, "stage": "stable"},
            },
        )
        sources = {
            "native_codex_boundary.py": LIB / "native_codex_boundary.py",
            "responses_relay.py": LIB / "responses_relay.py",
            "native-codex-supervisor.rs": (
                LIB.parent / "fixtures/native-codex-supervisor.rs"
            ),
            "qualification_driver.py": (
                LIB.parent / "qualify-installed-codex-compatibility.py"
            ),
        }
        self.assertEqual(
            receipt["sources"],
            {
                name: hashlib.sha256(path.read_bytes()).hexdigest()
                for name, path in sources.items()
            },
        )
        expected_tools = [
            "exec_command",
            "write_stdin",
            "request_user_input",
            "apply_patch",
            "view_image",
            "get_goal",
            "create_goal",
            "update_goal",
        ]
        expected_mounts = {
            "/workspace": True,
            "/runtime": True,
            "/gateway": False,
            "/opt/scourge-bin/codex": False,
            "/opt/scourge-bin/native-codex-supervisor": False,
        }
        expected_fields = [
            "client_metadata",
            "include",
            "input",
            "model",
            "parallel_tool_calls",
            "prompt_cache_key",
            "reasoning",
            "store",
            "stream",
            "text",
            "tool_choice",
            "tools",
        ]
        expected_transformations = [
            "client-metadata-stripped",
            "prompt-cache-key-replaced",
            "host-output-token-cap-injected",
        ]
        self.assertEqual(
            receipt["runtime"]["image_id"], boundary.PRODUCTION_IMAGE_ID
        )
        self.assertEqual(receipt["runtime"]["image"], "docker.io/library/debian:bookworm-slim")
        supervisor_build = receipt["runtime"]["supervisor"]
        self.assertTrue(supervisor_build["static_musl"])
        self.assertTrue(supervisor_build["reproducible_two_builds"])
        self.assertTrue(supervisor_build["path_independent_two_builds"])
        self.assertEqual(
            supervisor_build["source_argument"],
            "evals/scripts/fixtures/native-codex-supervisor.rs",
        )
        self.assertEqual(
            supervisor_build["working_directory"], "isolated-build-root"
        )
        self.assertEqual(
            supervisor_build["timeout_helper_test"]["test"],
            "tests::timeout_tracks_direct_child_sigkill_and_group_quiescence",
        )
        self.assertTrue(supervisor_build["timeout_helper_test"]["passed"])
        self.assertEqual(
            supervisor_build["timeout_helper_test"]["source_helper"],
            "wait_child_with_limits",
        )
        self.assertEqual(
            supervisor_build["timeout_helper_test"]["production_timeout_seconds"],
            900,
        )
        self.assertFalse(
            supervisor_build["timeout_helper_test"]["exact_900_seconds_executed"]
        )
        self.assertIn(
            "production 900-second timeout helper exercised at 40 ms; "
            "exact 900-second wall clock not run",
            receipt["limits"],
        )
        self.assertEqual(
            supervisor_build["source_sha256"],
            receipt["sources"]["native-codex-supervisor.rs"],
        )
        for mode, block_count in (("executable", 0), ("managed", 1)):
            row = receipt["modes"][mode]
            self.assertTrue(row["valid"])
            self.assertFalse(row["codex_argv"]["code_mode_enabled"])
            self.assertFalse(row["codex_argv"]["code_mode_host_enabled"])
            self.assertFalse(row["codex_argv"]["shell_snapshot_enabled"])
            self.assertTrue(row["effective_environment"]["valid"])
            self.assertEqual(row["effective_environment"]["unexpected_names"], [])
            self.assertEqual(
                row["effective_environment"]["credential_like_names"], []
            )
            self.assertTrue(row["production_collector_parity"]["valid"])
            self.assertEqual(
                row["production_collector_parity"]["podman_executable"],
                "/usr/bin/podman",
            )
            self.assertEqual(
                row["production_collector_parity"]["oci_runtime"],
                "/usr/bin/crun",
            )
            self.assertTrue(row["production_collector_parity"]["auto_remove"])
            self.assertTrue(row["production_collector_parity"]["interactive"])
            self.assertTrue(row["production_collector_parity"]["unsetenv_all"])
            self.assertEqual(
                row["production_collector_parity"]["hostname"],
                boundary.WORKER_HOSTNAME,
            )
            self.assertEqual(
                row["production_collector_parity"]["entrypoint"],
                boundary.SUPERVISOR_CONTAINER_PATH,
            )
            self.assertTrue(
                row["production_collector_parity"]["supervised_codex"]["valid"]
            )
            self.assertEqual(row["process_lineage"]["pre_request_codex_children"], 0)
            self.assertEqual(row["process_lineage"]["expected_tool_roots"], 1)
            self.assertEqual(row["process_lineage"]["unexpected_descendants"], 0)
            self.assertTrue(row["process_lineage"]["codex_child_of_supervisor"])
            self.assertTrue(row["process_lineage"]["valid"])
            self.assertEqual(row["container"]["mount_access"], expected_mounts)
            self.assertTrue(row["container"]["removed"])
            self.assertEqual(row["worker"]["self_sha256"], supervisor_build["binary_sha256"])
            self.assertEqual(row["worker"]["codex_sha256"], receipt["codex"]["sha256"])
            self.assertTrue(row["worker"]["prompt"]["write_complete"])
            self.assertFalse(row["worker"]["prompt"]["write_timed_out"])
            self.assertFalse(row["worker"]["fatal_route_failure"])
            self.assertEqual(
                row["worker"]["teardown"],
                {
                    "routes_inactive": True,
                    "process_group_quiescent": True,
                    "sigkill_escalated": False,
                    "complete": True,
                },
            )
            self.assertEqual(row["worker"]["routes"]["model"]["sessions"], 2)
            self.assertEqual(row["worker"]["routes"]["model"]["refused"], 0)
            self.assertEqual(row["worker"]["routes"]["model"]["active"], 0)
            self.assertEqual(row["worker"]["routes"]["proxy"]["sessions"], 1)
            self.assertEqual(row["worker"]["routes"]["proxy"]["refused"], 0)
            self.assertEqual(row["worker"]["routes"]["proxy"]["active"], 0)
            self.assertEqual(len(row["fake_proxy_attempts"]), 1)
            self.assertTrue(row["fake_proxy_attempts"][0]["payload_exact"])
            self.assertEqual(len(row["requests"]), 2)
            self.assertTrue(all(
                request["top_level_fields"] == expected_fields
                and request["reasoning"] == {"effort": "high"}
                and request["text"] == {"verbosity": "low"}
                and request["prompt_cache_key_bytes"] == 36
                for request in row["requests"]
            ))
            self.assertEqual(
                [tool["name"] for tool in row["requests"][0]["tools"]],
                expected_tools,
            )
            self.assertIsNone(row["requests"][0]["max_output_tokens"])
            self.assertEqual(
                row["requests"][0]["include"], ["reasoning.encrypted_content"]
            )
            self.assertEqual(row["requests"][1]["function_call_output_count"], 1)
            self.assertTrue(row["requests"][1]["offline_tool_call_id_present"])
            self.assertTrue(row["requests"][1]["offline_tool_output_marker_present"])
            self.assertTrue(row["tool_roundtrip"]["valid"])
            self.assertEqual(
                row["relay"]["first_request_context"]["intact_managed_block_count"],
                block_count,
            )
            self.assertTrue(row["relay"]["accounting"]["reconciled"])
            self.assertEqual(row["relay"]["accounting"]["accepted_requests"], 2)
            self.assertEqual(
                [terminal["tool_call_count"] for terminal in row["relay"]["terminals"]],
                [1, 0],
            )
            self.assertTrue(all(
                request["provider_body_transformations"] == expected_transformations
                for request in row["relay"]["requests"]
            ))
            self.assertTrue(all(
                attempt["client_metadata_present"] is False
                and attempt["max_output_tokens"] == 32768
                and attempt["prompt_cache_key_host_scoped"] is True
                for attempt in row["fake_upstream_attempts"]
            ))
            self.assertEqual(len({
                attempt["prompt_cache_key_sha256"]
                for attempt in row["fake_upstream_attempts"]
            }), 2)
        probes = receipt["supervisor_probes"]
        self.assertEqual(
            set(probes),
            {
                "dead_model",
                "dead_proxy",
                "broken_stdin",
                "stubborn_group",
                "direct_term_ignore",
                "signal_escape",
                "sigkill",
            },
        )
        self.assertTrue(all(row["valid"] for row in probes.values()))
        self.assertGreaterEqual(probes["dead_model"]["target_route_refusals"], 1)
        self.assertGreaterEqual(probes["dead_proxy"]["target_route_refusals"], 1)
        self.assertFalse(probes["broken_stdin"]["prompt_write_complete"])
        self.assertFalse(probes["stubborn_group"]["prompt_write_complete"])
        self.assertTrue(probes["stubborn_group"]["process_group_quiescent"])
        self.assertTrue(probes["stubborn_group"]["sigkill_escalated"])
        self.assertTrue(probes["stubborn_group"]["teardown_complete"])
        self.assertEqual(probes["direct_term_ignore"]["codex_signal"], 9)
        self.assertFalse(probes["direct_term_ignore"]["codex_timed_out"])
        self.assertEqual(probes["direct_term_ignore"]["interrupted_by_signal"], 15)
        self.assertTrue(probes["direct_term_ignore"]["sigkill_escalated"])
        self.assertTrue(probes["direct_term_ignore"]["process_group_quiescent"])
        self.assertTrue(probes["direct_term_ignore"]["routes_inactive"])
        self.assertTrue(probes["direct_term_ignore"]["teardown_complete"])
        self.assertEqual(probes["signal_escape"]["interrupted_by_signal"], 15)
        self.assertFalse(probes["sigkill"]["receipt_present"])
        self.assertTrue(all(row["container_removed"] for row in probes.values()))
        self.assertTrue(all(row["escaped_child_absent"] for row in probes.values()))
        encoded = receipt_path.read_bytes()
        self.assertNotIn(PROVIDER_CREDENTIAL, encoded)
        self.assertNotIn(b"offline-installed-codex-provider-canary", encoded)
        self.assertNotIn(os.fspath(LIB.parent.parent.parent).encode(), encoded)
        self.assertNotIn(b"Use exec_command to write exactly", encoded)

    def test_previous_response_ids_are_always_refused(self):
        for response_id in ("resp_foreign", "resp_one", None):
            with self.subTest(first_response_id=response_id):
                state, connection, _evidence = self.state()
                self.assertEqual(self.valid_request(
                    state,
                    request_body(suffix={"previous_response_id": response_id}),
                )[0], 422)
                self.assertEqual(connection.requests, [])
                self.assertIn(
                    "previous-response-id-refused",
                    {row["code"] for row in state.finalize()["reasons"]},
                )

        for response_id, instructions in (
            ("resp_one", "INJECTED replacement prompt"),
            ("resp_any_other", "prepared task"),
        ):
            with self.subTest(response_id=response_id, instructions=instructions):
                pool = ConnectionPool([FakeResponse(completed_sse("resp_one"))])
                state, _pool, _evidence = self.state(connection_factory=pool)
                self.assertEqual(self.valid_request(state)[0], 200)
                self.assertEqual(self.valid_request(
                    state,
                    request_body(
                        instructions=instructions,
                        suffix={"previous_response_id": response_id},
                    ),
                )[0], 422)
                self.assertEqual(len(pool.connections), 1)
                self.assertIn(
                    "previous-response-id-refused",
                    {row["code"] for row in state.finalize()["reasons"]},
                )

        pool = ConnectionPool([FakeResponse(completed_sse("resp_standalone"))])
        state, _pool, _evidence = self.state(connection_factory=pool)
        self.assertEqual(self.valid_request(state)[0], 200)
        self.assertEqual(self.valid_request(
            state, request_body(instructions="independent second request")
        )[0], 409)
        self.assertEqual(len(pool.connections), 1)
        self.assertIn(
            "unbound-followup-request",
            {row["code"] for row in state.finalize()["reasons"]},
        )

    def test_unresolved_tool_chain_and_reused_item_ids_never_settle(self):
        pool = ConnectionPool([FakeResponse(tool_sse())])
        state, _pool, _evidence = self.state(connection_factory=pool)
        self.assertEqual(self.valid_request(state)[0], 200)
        receipt = state.finalize()
        self.assertFalse(receipt["valid"])
        self.assertFalse(receipt["accounting"]["reconciled"])
        self.assertIn(
            "unresolved-tool-call-chain",
            {row["code"] for row in receipt["reasons"]},
        )
        self.assertEqual(receipt["terminals"][-1]["tool_call_count"], 1)

        duplicate_input = json.loads(request_body())
        duplicate_input["input"] = [
            {"id": "msg_repeat", "type": "message"},
            {"id": "msg_repeat", "type": "message"},
        ]
        state, connection, _evidence = self.state()
        self.assertEqual(self.valid_request(
            state, json.dumps(duplicate_input, separators=(",", ":")).encode("ascii")
        )[0], 409)
        self.assertEqual(connection.requests, [])
        self.assertIn(
            "nonunique-item-id", {row["code"] for row in state.finalize()["reasons"]}
        )

        first_input = json.loads(request_body())
        first_input["input"][0]["id"] = "fc_tool"
        pool = ConnectionPool([FakeResponse(tool_sse(item_id="fc_tool"))])
        state, _pool, _evidence = self.state(connection_factory=pool)
        self.assertEqual(self.valid_request(
            state, json.dumps(first_input, separators=(",", ":")).encode("ascii")
        )[0], 502)
        receipt = state.finalize()
        self.assertFalse(receipt["valid"])
        self.assertIn(
            "nonunique-item-id", {row["code"] for row in receipt["reasons"]}
        )

    def test_provider_item_and_call_ids_are_unique_for_the_entire_session(self):
        def followup(first_item):
            value = json.loads(request_body())
            value["input"] = [
                *value["input"],
                first_item,
                {
                    "type": "function_call_output",
                    "id": f"out_{first_item['id']}",
                    "call_id": first_item["call_id"],
                    "output": "done",
                },
            ]
            return json.dumps(value, separators=(",", ":")).encode("ascii")

        first = {
            "id": "fc_shared", "type": "function_call", "status": "completed",
            "name": "exec_command", "call_id": "call_first", "arguments": "{}",
        }
        pool = ConnectionPool([
            FakeResponse(tool_sse(item_id=first["id"], call_id=first["call_id"])),
            FakeResponse(tool_sse(
                response_id="resp_second", item_id=first["id"], call_id="call_second"
            )),
        ])
        state, _pool, _evidence = self.state(connection_factory=pool)
        self.assertEqual(self.valid_request(state)[0], 200)
        self.assertEqual(self.valid_request(state, followup(first))[0], 502)
        receipt = state.finalize()
        self.assertFalse(receipt["valid"])
        self.assertIn("nonunique-item-id", {row["code"] for row in receipt["reasons"]})

        first = dict(first, id="fc_first", call_id="call_shared")
        pool = ConnectionPool([
            FakeResponse(tool_sse(item_id=first["id"], call_id=first["call_id"])),
            FakeResponse(tool_sse(
                response_id="resp_second", item_id="fc_second",
                call_id=first["call_id"],
            )),
        ])
        state, _pool, _evidence = self.state(connection_factory=pool)
        self.assertEqual(self.valid_request(state)[0], 200)
        self.assertEqual(self.valid_request(state, followup(first))[0], 502)
        receipt = state.finalize()
        self.assertFalse(receipt["valid"])
        self.assertIn("nonunique-call-id", {row["code"] for row in receipt["reasons"]})

    def test_incomplete_and_sse_divergent_output_items_never_settle(self):
        in_progress_message = {
            "id": "msg_incomplete", "type": "message", "status": "in_progress",
            "role": "assistant", "content": [],
        }
        terminal = {
            "type": "response.completed",
            "response": {
                "id": "resp_incomplete", "status": "completed",
                "output": [in_progress_message],
                "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
            },
        }
        done = {"type": "response.output_item.done", "output_index": 0,
                "item": in_progress_message}
        body = (
            b"event: response.output_item.done\ndata: "
            + json.dumps(done).encode("ascii") + b"\n\n"
            + b"event: response.completed\ndata: "
            + json.dumps(terminal).encode("ascii") + b"\n\n"
        )
        for response in (
            FakeResponse(tool_sse(status="in_progress")),
            FakeResponse(body),
        ):
            with self.subTest(body=response.body):
                state, _connection, _evidence = self.state(
                    connection=FakeConnection(response)
                )
                self.assertEqual(self.valid_request(state)[0], 502)
                receipt = state.finalize()
                self.assertFalse(receipt["valid"])
                self.assertIn(
                    "upstream-terminal-failure",
                    {row["code"] for row in receipt["reasons"]},
                )

        completed_item = {
            "id": "fc_done", "type": "function_call", "status": "completed",
            "name": "exec_command", "call_id": "call_done", "arguments": "{}",
        }
        done = {"type": "response.output_item.done", "output_index": 0,
                "item": completed_item}
        for terminal_output in ([], [dict(completed_item, arguments='{"changed":true}')],
                                [completed_item, dict(completed_item, id="fc_extra")]):
            terminal = {
                "type": "response.completed",
                "response": {
                    "id": "resp_divergent", "status": "completed",
                    "output": terminal_output,
                    "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
                },
            }
            body = (
                b"event: response.output_item.done\ndata: "
                + json.dumps(done).encode("ascii") + b"\n\n"
                + b"event: response.completed\ndata: "
                + json.dumps(terminal).encode("ascii") + b"\n\n"
            )
            with self.subTest(terminal_output=terminal_output):
                state, _connection, _evidence = self.state(
                    connection=FakeConnection(FakeResponse(body))
                )
                self.assertEqual(self.valid_request(state)[0], 502)
                self.assertFalse(state.finalize()["valid"])

    def test_sse_stream_is_closed_reconciled_and_never_partially_forwarded(self):
        valid = incremental_message_sse(streamed="SAFE")
        state, _connection, _evidence = self.state(
            connection=FakeConnection(FakeResponse(valid))
        )
        status, _headers, returned = self.valid_request(state)
        self.assertEqual(status, 200)
        self.assertEqual(returned, valid)
        self.assertTrue(state.finalize()["valid"])

        injected = incremental_message_sse(streamed="INJECTED", terminal="SAFE")
        malformed = [
            injected,
            valid.replace(
                b"event: response.output_text.delta",
                b"event: response.unknown.delta",
                1,
            ).replace(
                b'"type": "response.output_text.delta"',
                b'"type": "response.unknown.delta"',
                1,
            ),
            valid.replace(b"\n\n", b"\n", 1),
            valid[:-1],
            valid.replace(b"\n", b"\r", 1),
            valid.replace(
                b'data: {"type": "response.created"',
                b"data: [DONE]\n\ndata: {\"type\": \"response.created\"",
                1,
            ),
            valid.replace(b"SAFE", b"\xffAFE", 1),
        ]
        # A duplicate/reordered client-visible event is also refused.
        records = valid.split(b"\n\n")[:-1]
        malformed.extend([
            b"\n\n".join([*records[:4], records[3], *records[4:]]) + b"\n\n",
            b"\n\n".join([records[0], records[2], records[1], *records[3:]])
            + b"\n\n",
        ])
        for body in malformed:
            with self.subTest(body_sha256=hashlib.sha256(body).hexdigest()):
                state, _connection, _evidence = self.state(
                    connection=FakeConnection(FakeResponse(body))
                )
                request = json.loads(request_body())
                request["input"][0]["id"] = "msg_uncommitted_request"
                status, headers, returned = self.valid_request(
                    state,
                    json.dumps(request, separators=(",", ":")).encode("ascii"),
                )
                self.assertEqual(status, 502)
                self.assertEqual(headers["Content-Type"], "application/json")
                self.assertEqual(
                    returned,
                    b'{"error":{"code":"invalid-upstream-response"}}\n',
                )
                self.assertEqual(state.accepted_item_ids, set())
                self.assertEqual(state.accepted_call_ids, set())
                self.assertEqual(state.pending_tool_calls, {})
                self.assertEqual(state.pending_tool_items, [])
                self.assertFalse(state.finalize()["valid"])

        sequenced_records = []
        for sequence, record in enumerate(records):
            event_line, data_line = record.split(b"\n")
            event = json.loads(data_line[6:])
            event["sequence_number"] = sequence + (1 if sequence == 3 else 0)
            sequenced_records.append(
                event_line + b"\n" + b"data: " + json.dumps(event).encode("ascii")
            )
        state, _connection, _evidence = self.state(connection=FakeConnection(
            FakeResponse(b"\n\n".join(sequenced_records) + b"\n\n")
        ))
        self.assertEqual(self.valid_request(state)[0], 502)
        self.assertFalse(state.finalize()["valid"])

    def test_sse_typed_fields_fail_closed_without_committing_state(self):
        invalid_values = (None, False, True, -1, 1 << 63, 0.5, [], {})

        def compact(item):
            terminal = {
                "type": "response.completed",
                "response": {
                    "id": "resp_compact", "status": "completed",
                    "output": [item],
                    "usage": {"input_tokens": 1, "output_tokens": 1,
                              "total_tokens": 2},
                },
            }
            return encode_sse([
                {"type": "response.output_item.done", "output_index": 0,
                 "item": item}, terminal,
            ])

        message = {
            "id": "msg_typed", "type": "message", "status": "completed",
            "role": "assistant", "content": [{
                "type": "output_text", "text": "SAFE", "annotations": [],
                "logprobs": [],
            }],
        }
        function = {
            "id": "fc_typed", "type": "function_call", "status": "completed",
            "name": "exec_command", "call_id": "call_typed", "arguments": "{}",
        }
        custom = {
            "id": "ctc_typed", "type": "custom_tool_call",
            "status": "completed", "name": "apply_patch",
            "call_id": "call_custom_typed", "input": "patch",
        }

        cases = []
        for value in invalid_values:
            for template, key in (
                (message, "id"), (message, "status"), (message, "role"),
                (function, "id"), (function, "name"), (function, "call_id"),
                (function, "arguments"), (custom, "id"), (custom, "name"),
                (custom, "call_id"), (custom, "input"),
            ):
                cases.append((f"compact-{template['type']}-{key}-{type(value).__name__}",
                              compact(dict(template, **{key: value}))))
            changed = json.loads(json.dumps(message))
            changed["content"][0]["text"] = value
            cases.append((f"compact-message-text-{type(value).__name__}",
                          compact(changed)))

        for source_name, source in (
            ("message", incremental_message_sse()),
            ("function", incremental_tool_sse("function_call")),
            ("custom", incremental_tool_sse("custom_tool_call")),
        ):
            original = decode_sse(source)
            for value in invalid_values:
                # Presence is distinct from absence: null/bool/float/container
                # sequence numbers are never treated as an omitted sequence.
                changed = json.loads(json.dumps(original))
                for event in changed:
                    event["sequence_number"] = value
                cases.append((f"{source_name}-sequence-{type(value).__name__}",
                              encode_sse(changed)))

                for field in ("output_index", "item_id"):
                    changed = json.loads(json.dumps(original))
                    target = next(event for event in changed if field in event)
                    target[field] = value
                    cases.append((f"{source_name}-{field}-{type(value).__name__}",
                                  encode_sse(changed)))

                if source_name == "message":
                    changed = json.loads(json.dumps(original))
                    target = next(event for event in changed
                                  if "content_index" in event)
                    target["content_index"] = value
                    cases.append((f"message-content-index-{type(value).__name__}",
                                  encode_sse(changed)))

                changed = json.loads(json.dumps(original))
                terminal = changed[-1]["response"]
                terminal["created_at"] = value
                cases.append((f"{source_name}-created-at-{type(value).__name__}",
                              encode_sse(changed)))
                for token in ("input_tokens", "output_tokens", "total_tokens"):
                    changed = json.loads(json.dumps(original))
                    changed[-1]["response"]["usage"][token] = value
                    cases.append((f"{source_name}-{token}-{type(value).__name__}",
                                  encode_sse(changed)))

        for name, body in cases:
            with self.subTest(name=name):
                state, _connection, _evidence = self.state(
                    connection=FakeConnection(FakeResponse(body))
                )
                before = {
                    "accepted_requests": state.accepted_requests,
                    "upstream_attempts": state.upstream_attempts,
                    "inbound_requests": state.inbound_requests,
                    "response_bytes": state.response_bytes,
                    "accepted_input": state.accepted_input,
                    "accepted_item_ids": set(state.accepted_item_ids),
                    "accepted_call_ids": set(state.accepted_call_ids),
                    "pending_tool_calls": dict(state.pending_tool_calls),
                    "pending_tool_items": list(state.pending_tool_items),
                    "requests": list(state.requests),
                    "terminals": list(state.terminals),
                    "retained_request_artifacts": state.store.accounting()[
                        "retained_request_artifacts"
                    ],
                }
                status, headers, returned = self.valid_request(state)
                self.assertEqual(status, 502)
                self.assertEqual(headers["Content-Type"], "application/json")
                self.assertEqual(
                    returned,
                    b'{"error":{"code":"invalid-upstream-response"}}\n',
                )
                after = {
                    **{key: getattr(state, key) for key in (
                        "accepted_requests", "upstream_attempts",
                        "inbound_requests", "response_bytes", "accepted_input",
                    )},
                    "accepted_item_ids": set(state.accepted_item_ids),
                    "accepted_call_ids": set(state.accepted_call_ids),
                    "pending_tool_calls": dict(state.pending_tool_calls),
                    "pending_tool_items": list(state.pending_tool_items),
                    "requests": list(state.requests),
                    "terminals": list(state.terminals),
                    "retained_request_artifacts": state.store.accounting()[
                        "retained_request_artifacts"
                    ],
                }
                self.assertEqual(after, before)
                self.assertTrue(state.poisoned)

        for body in (
            incremental_message_sse(), incremental_tool_sse("function_call"),
            incremental_tool_sse("custom_tool_call"),
        ):
            state, _connection, _evidence = self.state(
                connection=FakeConnection(FakeResponse(body))
            )
            status, _headers, returned = self.valid_request(state)
            self.assertEqual(status, 200)
            self.assertEqual(returned, body)

    def test_invalid_second_response_preserves_prior_pending_transition(self):
        first_item = {
            "id": "fc_first_atomic", "type": "function_call",
            "status": "completed", "name": "exec_command",
            "call_id": "call_first_atomic", "arguments": "{}",
        }
        malformed = decode_sse(completed_sse("resp_second_atomic"))
        malformed[0]["sequence_number"] = None
        pool = ConnectionPool([
            FakeResponse(tool_sse(
                item_id=first_item["id"], call_id=first_item["call_id"]
            )),
            FakeResponse(encode_sse(malformed)),
        ])
        state, _pool, _evidence = self.state(connection_factory=pool)
        self.assertEqual(self.valid_request(state)[0], 200)
        followup = json.loads(request_body())
        followup["input"] = [
            *followup["input"], first_item,
            {"type": "function_call_output", "id": "out_first_atomic",
             "call_id": first_item["call_id"], "output": "done"},
        ]
        body = json.dumps(followup, separators=(",", ":")).encode("ascii")
        before = {
            "accepted_requests": state.accepted_requests,
            "upstream_attempts": state.upstream_attempts,
            "inbound_requests": state.inbound_requests,
            "response_bytes": state.response_bytes,
            "accepted_input": json.loads(json.dumps(state.accepted_input)),
            "accepted_item_ids": set(state.accepted_item_ids),
            "accepted_call_ids": set(state.accepted_call_ids),
            "pending_tool_calls": dict(state.pending_tool_calls),
            "pending_tool_items": json.loads(json.dumps(state.pending_tool_items)),
            "requests": json.loads(json.dumps(state.requests)),
            "terminals": json.loads(json.dumps(state.terminals)),
            "store": state.store.accounting()["retained_request_artifacts"],
        }
        status, _headers, returned = self.valid_request(state, body)
        self.assertEqual(status, 502)
        self.assertEqual(
            returned, b'{"error":{"code":"invalid-upstream-response"}}\n'
        )
        after = {
            "accepted_requests": state.accepted_requests,
            "upstream_attempts": state.upstream_attempts,
            "inbound_requests": state.inbound_requests,
            "response_bytes": state.response_bytes,
            "accepted_input": state.accepted_input,
            "accepted_item_ids": set(state.accepted_item_ids),
            "accepted_call_ids": set(state.accepted_call_ids),
            "pending_tool_calls": dict(state.pending_tool_calls),
            "pending_tool_items": state.pending_tool_items,
            "requests": state.requests,
            "terminals": state.terminals,
            "store": state.store.accounting()["retained_request_artifacts"],
        }
        self.assertEqual(after, before)
        self.assertTrue(state.poisoned)

    def test_output_items_require_the_exact_completed_allowlisted_schema(self):
        valid_message = {
            "id": "msg_completed", "type": "message", "status": "completed",
            "role": "assistant", "content": [{
                "type": "output_text", "text": "done", "annotations": [],
                "logprobs": [],
            }],
        }
        valid_call = {
            "id": "fc_completed", "type": "function_call",
            "status": "completed", "name": "exec_command",
            "call_id": "call_completed", "arguments": "{}",
        }

        def sse(item):
            done = {"type": "response.output_item.done", "output_index": 0,
                    "item": item}
            terminal = {
                "type": "response.completed",
                "response": {
                    "id": "resp_schema", "status": "completed", "output": [item],
                    "usage": {"input_tokens": 1, "output_tokens": 1,
                              "total_tokens": 2},
                },
            }
            return (
                b"event: response.output_item.done\ndata: "
                + json.dumps(done).encode("ascii") + b"\n\n"
                + b"event: response.completed\ndata: "
                + json.dumps(terminal).encode("ascii") + b"\n\n"
            )

        malformed = [
            {key: value for key, value in valid_message.items() if key != "id"},
            {key: value for key, value in valid_message.items() if key != "status"},
            dict(valid_message, status="in_progress"),
            dict(valid_message, content=[]),
            dict(valid_message, role="user"),
            dict(valid_message, unexpected=True),
            dict(valid_message, content=[{
                "type": "input_text", "text": "wrong", "annotations": [],
                "logprobs": [],
            }]),
            dict(valid_message, content=[{
                "type": "output_text", "text": "wrong annotation",
                "annotations": [{"type": "unknown"}], "logprobs": [],
            }]),
            {"id": "unknown_completed", "type": "reasoning",
             "status": "completed", "summary": []},
            {key: value for key, value in valid_call.items() if key != "call_id"},
            {key: value for key, value in valid_call.items() if key != "status"},
            dict(valid_call, arguments="not-json"),
            dict(valid_call, extra="laundered"),
        ]
        for item in malformed:
            with self.subTest(item=item):
                state, _connection, _evidence = self.state(
                    connection=FakeConnection(FakeResponse(sse(item)))
                )
                status, _headers, returned = self.valid_request(state)
                self.assertEqual(status, 502)
                self.assertEqual(
                    returned,
                    b'{"error":{"code":"invalid-upstream-response"}}\n',
                )
                receipt = state.finalize()
                self.assertFalse(receipt["valid"])
                self.assertIn(
                    "upstream-terminal-failure",
                    {row["code"] for row in receipt["reasons"]},
                )

        state, _connection, _evidence = self.state(
            connection=FakeConnection(FakeResponse(sse(valid_message)))
        )
        self.assertEqual(self.valid_request(state)[0], 200)
        self.assertTrue(state.finalize()["valid"])

    def test_context_receipt_proves_zero_or_one_intact_block_and_no_host_context(self):
        executable = boundary.inspect_first_request_context(
            request_body(instructions="no guide"),
            boundary.ContextExpectation(
                "executable", forbidden_fragments=(("host-checkout", "/host/project/context"),)
            ),
        )
        self.assertTrue(executable["valid"])
        self.assertEqual(executable["managed_start_count"], 0)

        expectation = boundary.ContextExpectation(
            "managed",
            MANAGED_BLOCK,
            (("host-checkout", "/host/project/context"),),
        )
        managed = boundary.inspect_first_request_context(
            request_body(instructions=f"prefix\n{MANAGED_BLOCK}suffix"), expectation
        )
        self.assertTrue(managed["valid"])
        self.assertEqual(managed["intact_managed_block_count"], 1)
        duplicate = boundary.inspect_first_request_context(
            request_body(instructions=MANAGED_BLOCK + MANAGED_BLOCK), expectation
        )
        self.assertFalse(duplicate["valid"])
        leaked = boundary.inspect_first_request_context(
            request_body(instructions=MANAGED_BLOCK + "/host/project/context"), expectation
        )
        self.assertFalse(leaked["valid"])
        self.assertEqual(leaked["forbidden_context_matches"], ["host-checkout"])
        key_leak = boundary.inspect_first_request_context(
            request_body(
                instructions=MANAGED_BLOCK,
                suffix={"metadata": {"/host/project/context": "hidden in a JSON key"}},
            ),
            expectation,
        )
        self.assertFalse(key_leak["valid"])
        self.assertEqual(key_leak["forbidden_context_matches"], ["host-checkout"])

    def test_rejected_request_cannot_prime_first_accepted_context(self):
        expectation = boundary.ContextExpectation("managed", MANAGED_BLOCK)
        state, connection, _evidence = self.state(context=expectation)
        priming = request_body(instructions=MANAGED_BLOCK)
        self.assertEqual(
            state.handle("POST", "/v1/not-responses", "HTTP/1.1", [], priming)[0], 404
        )
        self.assertIsNone(state.first_request_context)
        missing = request_body(instructions="managed block omitted")
        self.assertEqual(
            state.handle("POST", "/v1/responses", "HTTP/1.1", [], missing)[0], 409
        )
        receipt = state.finalize()
        self.assertIsNone(receipt["first_request_context"])
        self.assertEqual(connection.requests, [])
        self.assertEqual(receipt["listener"]["closed_reason"], "unexpected-route")
        self.assertTrue(receipt["listener"]["poisoned"])
        self.assertEqual(len(receipt["requests"]), 1)

    def test_http_parser_rejects_ambiguous_framing_and_oversize(self):
        policy = relay.RelayPolicy(MODEL, max_request_bytes=64)
        body = b"{}"
        valid = (
            b"POST /v1/responses HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Authorization: hostile\r\n"
            b"Content-Length: 2\r\n\r\n{}"
        )
        parsed = relay.parse_http_request(BytesIO(valid), policy)
        self.assertEqual(parsed[:3], ("POST", "/v1/responses", "HTTP/1.1"))
        self.assertEqual(parsed[-2], body)
        self.assertEqual(parsed[-1], len(valid))
        for raw, code in (
            (
                b"POST /v1/responses HTTP/1.1\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}",
                "duplicate-request-header",
            ),
            (
                b"POST /v1/responses HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n",
                "transfer-encoding-refused",
            ),
            (
                b"POST /v1/responses HTTP/1.1\r\nContent-Length: 65\r\n\r\n",
                "request-body-budget-exceeded",
            ),
        ):
            with self.subTest(code=code), self.assertRaisesRegex(relay.RelayError, code):
                relay.parse_http_request(BytesIO(raw), policy)

        truncated = (
            b"POST /v1/responses HTTP/1.1\r\nContent-Length: 2\r\n\r\n{"
        )
        with self.assertRaisesRegex(relay.RelayError, "truncated-request-body") as caught:
            relay.parse_http_request(BytesIO(truncated), policy)
        self.assertEqual(caught.exception.received_bytes, len(truncated))
        self.assertEqual(caught.exception.body_bytes, 1)
        state, connection, evidence = self.state(policy=policy)
        state.record_transport_refusal(
            caught.exception.code,
            received_bytes=caught.exception.received_bytes,
            body_bytes=caught.exception.body_bytes,
        )
        receipt = state.finalize()
        self.assertEqual(connection.requests, [])
        self.assertEqual(receipt["accounting"]["transport_refusal_bytes"], len(truncated))
        self.assertEqual(receipt["accounting"]["rejected_request_bytes"], 1)
        self.assertEqual(list((evidence / "requests").iterdir()), [])

    def test_fake_codex_process_and_canary_scan_are_offline_and_secret_free(self):
        worker = self.root / "worker"
        artifacts = self.root / "worker-artifacts"
        worker.mkdir()
        artifacts.mkdir()
        config = worker / "config.toml"
        config.write_text(boundary.codex_provider_config(MODEL, "low"), encoding="utf-8")
        output = worker / "request.json"
        stub = worker / "fake-codex.py"
        template = worker / "request-template.json"
        template.write_bytes(request_body(instructions="offline stub"))
        stub.write_text(
            "import json, pathlib, sys\n"
            "config = pathlib.Path(sys.argv[1]).read_text()\n"
            "assert 'requires_openai_auth = false' in config\n"
            "body = json.loads(pathlib.Path(sys.argv[4]).read_text())\n"
            "assert body['model'] == sys.argv[3]\n"
            "pathlib.Path(sys.argv[2]).write_text(json.dumps(body, separators=(',', ':')))\n",
            encoding="utf-8",
        )
        environment = boundary.worker_environment()
        command = [
            sys.executable, "-I", str(stub), str(config), str(output), MODEL, str(template)
        ]
        completed = subprocess.run(command, env=environment, check=False, capture_output=True)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        state, _connection, evidence = self.state()
        self.assertEqual(self.valid_request(state, output.read_bytes(), [])[0], 200)
        self.assertTrue(state.finalize()["valid"])
        scan = boundary.credential_canary_evidence(
            PROVIDER_CREDENTIAL,
            worker_environment_values=environment,
            worker_proc_blobs=(b"\x00".join(arg.encode() for arg in command),),
            worker_roots=(worker,),
            artifact_roots=(artifacts, evidence),
        )
        self.assertTrue(all(scan[area]["absent"] for area in ("env", "proc", "files", "artifacts")))
        (artifacts / "leak").write_bytes(PROVIDER_CREDENTIAL)
        scan = boundary.credential_canary_evidence(
            PROVIDER_CREDENTIAL,
            worker_environment_values=environment,
            worker_proc_blobs=(),
            worker_roots=(worker,),
            artifact_roots=(artifacts,),
        )
        self.assertFalse(scan["artifacts"]["absent"])

    def test_boundary_settlement_requires_every_probe_and_null_scores_failures(self):
        state, _connection, evidence = self.state()
        self.assertEqual(self.valid_request(state)[0], 200)
        relay_receipt = state.finalize()
        absence = boundary.credential_canary_evidence(
            PROVIDER_CREDENTIAL,
            worker_environment_values=boundary.worker_environment(),
            worker_proc_blobs=(b"fake-codex\x00--json",),
            worker_roots=(evidence,),
            artifact_roots=(evidence,),
        )
        expected_environment = boundary.worker_environment()
        environment_blob = b"\0".join(
            f"{name}={value}".encode("ascii")
            for name, value in sorted(expected_environment.items())
        ) + b"\0"
        environment_evidence = boundary.effective_worker_environment_evidence(
            environment_blob,
            {
                "Config": {
                    "Env": [
                        f"{name}={value}"
                        for name, value in sorted(expected_environment.items())
                    ],
                    "Hostname": boundary.WORKER_HOSTNAME,
                }
            },
        )
        probes = {
            "schema": boundary.PROBE_SCHEMA,
            "schema_version": boundary.SCHEMA_VERSION,
            "credential_canary_absence": absence,
            "environment": environment_evidence,
            "protected_paths": {
                name: {
                    operation: {
                        "attempted": True,
                        "refused": True,
                        "errno": 2,
                        "error": "No such file or directory",
                        "path": boundary.PROTECTED_WORKER_PATHS[name],
                    }
                    for operation in ("read", "write")
                }
                for name in boundary.REQUIRED_PROTECTED_PATHS
            },
            "direct_egress": {
                "attempted": True,
                "destination": "192.0.2.1:443",
                "connected": False,
                "errno": 101,
                "error": "Network is unreachable",
            },
            "mounts": {
                "container_id": "c" * 64,
                "allowlist": {
                    "attempted": True,
                    "expected_destinations": [
                        "/gateway", "/opt/adapter/forward.js", "/opt/scourge-bin/codex",
                        "/runtime", "/workspace",
                    ],
                    "observed_destinations": [
                        "/gateway", "/opt/adapter/forward.js", "/opt/scourge-bin/codex",
                        "/runtime", "/workspace",
                    ],
                    "exact": True,
                },
                "write_probes": {
                    "workspace": {
                        "attempted": True, "succeeded": True, "bytes_written": 1,
                        "cleaned": True, "path": "/workspace",
                    },
                    "runtime": {
                        "attempted": True, "succeeded": True, "bytes_written": 1,
                        "cleaned": True, "path": "/runtime",
                    },
                    "binaries": [
                        {
                            "attempted": True, "refused": True, "errno": 30,
                            "error": "Read-only file system", "path": "/opt/scourge-bin/codex",
                        },
                        {
                            "attempted": True, "refused": True, "errno": 30,
                            "error": "Read-only file system", "path": "/opt/adapter/forward.js",
                        },
                    ],
                    "gateway": {
                        "attempted": True, "refused": True, "errno": 30,
                        "error": "Read-only file system", "path": "/gateway",
                    },
                    "rootfs": {
                        "attempted": True, "refused": True, "errno": 30,
                        "error": "Read-only file system", "path": "/",
                    },
                },
            },
            "gateway": {
                "container_id": "c" * 64,
                "inspect": {
                    "attempted": True,
                    "expected_sockets": ["model.sock"],
                    "observed_sockets": ["model.sock"],
                    "exact": True,
                    "modes": {"model.sock": 0o600},
                },
                "proxy": None,
            },
            "isolation": {
                "container_id": "c" * 64,
                "podman_info": {
                    "attempted": True, "exit_code": 0, "rootless": True, "remote": False,
                },
                "launch": {
                    "attempted": True,
                    "argv_sha256": "d" * 64,
                    "required_flags_present": sorted(boundary.REQUIRED_PODMAN_FLAGS),
                    "required_flags_complete": True,
                    "launch_shape_valid": True,
                    "podman_executable": "/usr/bin/podman",
                    "oci_runtime": "/usr/bin/crun",
                    "auto_remove": False,
                    "interactive": False,
                    "unsetenv_all": True,
                    "hostname": boundary.WORKER_HOSTNAME,
                    "environment_names": sorted(boundary.worker_environment()),
                    "proxy_port": None,
                    "credential_environment_names": [],
                },
                "inspect": {
                    "attempted": True,
                    "exit_code": 0,
                    "network_mode": "none",
                    "read_only_rootfs": True,
                    "cap_add": [],
                    "cap_drop": ["cap_chown", "cap_setuid"],
                    "security_opt": ["no-new-privileges"],
                    "pids_limit": 128,
                    "userns_mode": "private",
                },
                "worker": {"cap_eff": "0000000000000000", "no_new_privs": 1},
            },
            "teardown": {
                "worker": {"attempted": True, "stopped": True, "exit_code": 0},
                "forwarder": {"attempted": True, "stopped": True, "exit_code": 0},
                "container": {
                    "container_id": "c" * 64,
                    "remove_attempted": True,
                    "exists_probe_exit_code": 1,
                    "removed": True,
                },
            },
        }
        settled = boundary.settle_boundary(relay_receipt, probes)
        self.assertTrue(settled["valid"])
        self.assertIsNone(settled["score"])
        two_socket = json.loads(json.dumps(probes))
        exchange = {
            "request_bytes": 28,
            "request_sha256": "a" * 64,
            "response_bytes": 26,
            "response_sha256": "b" * 64,
        }
        two_socket["gateway"] = {
            "container_id": "c" * 64,
            "inspect": {
                "attempted": True,
                "expected_sockets": ["model.sock", "proxy.sock"],
                "observed_sockets": ["model.sock", "proxy.sock"],
                "exact": True,
                "modes": {"model.sock": 0o600, "proxy.sock": 0o600},
            },
            "proxy": {
                "attempted": True,
                "port": 19080,
                "connected": True,
                "worker": exchange,
                "host": {"attempts": 1, **exchange},
                "reconciled": True,
            },
        }
        two_socket["isolation"]["launch"]["environment_names"] = sorted(
            boundary.worker_environment(proxy_port=19080)
        )
        two_socket["isolation"]["launch"]["proxy_port"] = 19080
        self.assertTrue(boundary.settle_boundary(relay_receipt, two_socket)["valid"])
        probes["direct_egress"]["connected"] = True
        invalid = boundary.settle_boundary(relay_receipt, probes)
        self.assertEqual(invalid["status"], "unsettled")
        self.assertFalse(invalid["valid"])
        self.assertFalse(invalid["settled"])
        self.assertIsNone(invalid["score"])
        self.assertIn("direct-egress-available", {row["code"] for row in invalid["reasons"]})
        probes["direct_egress"]["connected"] = False
        probes["protected_paths"]["ground_truth"]["write"]["refused"] = False
        invalid = boundary.settle_boundary(relay_receipt, probes)
        self.assertIn(
            "protected-path-visible-ground_truth", {row["code"] for row in invalid["reasons"]}
        )


if __name__ == "__main__":
    unittest.main()
