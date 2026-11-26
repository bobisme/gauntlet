#!/usr/bin/env python3
"""Host-owned, credential-bearing relay for one pinned Responses origin.

The worker connects through a read-only Unix socket exposed on its loopback by
the existing worker forwarder.  This relay parses HTTP itself, discards every
worker header value, validates a bounded Responses JSON body, and makes exactly
one fixed-origin TLS attempt for each accepted request.  It never redirects or
retries.  Provider authentication is read only from inherited descriptor 3.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import hashlib
import http.client
import json
import math
import os
from pathlib import Path
import re
import signal
import socket
import ssl
import stat
import sys
import threading
from typing import BinaryIO, Callable, Iterable, Mapping, Sequence

from native_codex_boundary import (
    ContextExpectation,
    SCHEMA_VERSION,
    inspect_first_request_context,
    read_provider_credential,
    strict_json,
)


RELAY_SCHEMA = "scourge.responses-relay"
UPSTREAM_HOST = "api.openai.com"
UPSTREAM_PORT = 443
UPSTREAM_PATH = "/v1/responses"
WORKER_PATH = "/v1/responses"
MAX_HEADER_BYTES = 16 << 10
MAX_HEADER_COUNT = 32
_HEADER_NAME = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")
_TOOL_NAME = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
_RESPONSE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}\Z")
_SENSITIVE_HEADERS = frozenset({
    "api-key",
    "authorization",
    "cookie",
    "openai-api-key",
    "openai-organization",
    "openai-project",
    "proxy-authorization",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
})
_PROVEN_BODY_FIELDS = frozenset({
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
})
_ALLOWED_BODY_FIELDS = _PROVEN_BODY_FIELDS | frozenset({
    "max_output_tokens",
    "previous_response_id",
})
_CLIENT_TOOL_TYPES = frozenset({"function", "custom"})
_CLIENT_TOOL_NAMES = {
    "exec_command": "function",
    "write_stdin": "function",
    "request_user_input": "function",
    "apply_patch": "custom",
    "view_image": "function",
    "get_goal": "function",
    "create_goal": "function",
    "update_goal": "function",
}
_HOSTED_TOOL_TYPES = frozenset({
    "code_interpreter",
    "computer",
    "computer_use_preview",
    "file_search",
    "image_generation",
    "mcp",
    "mcp_list_tools",
    "web_search",
    "web_search_preview",
})
_PROMPT_CACHE_KEY = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z"
)
_CLIENT_METADATA_FIELDS = frozenset({
    "root_turn_id",
    "session_id",
    "thread_id",
    "turn_id",
    "x-codex-installation-id",
    "x-codex-turn-metadata",
    "x-codex-window-id",
})


class RelayError(ValueError):
    def __init__(
        self,
        code: str,
        status: int = 400,
        *,
        received_bytes: int = 0,
        body_bytes: int = 0,
    ):
        super().__init__(code)
        self.code = code
        self.status = status
        self.received_bytes = received_bytes
        self.body_bytes = body_bytes


@dataclass(frozen=True)
class RelayPolicy:
    model: str
    max_request_bytes: int = 2 << 20
    max_response_bytes: int = 16 << 20
    max_requests: int = 64
    max_total_bytes: int = 64 << 20
    max_output_tokens: int = 32768
    max_tools: int = 64
    max_receipt_bytes: int = 1 << 20
    timeout_seconds: float = 180.0

    def __post_init__(self) -> None:
        if not isinstance(self.model, str) or not self.model or len(self.model) > 256:
            raise RelayError("invalid-model-policy")
        for value in (
            self.max_request_bytes,
            self.max_response_bytes,
            self.max_requests,
            self.max_total_bytes,
            self.max_output_tokens,
            self.max_tools,
            self.max_receipt_bytes,
        ):
            if type(value) is not int or value < 1:
                raise RelayError("invalid-relay-budget")
        if self.max_total_bytes < self.max_request_bytes:
            raise RelayError("invalid-relay-budget")
        if (
            self.max_request_bytes > 8 << 20
            or self.max_response_bytes > 32 << 20
            or self.max_requests > 64
            or self.max_total_bytes > 64 << 20
            or self.max_tools > 64
            or self.max_receipt_bytes > 8 << 20
        ):
            raise RelayError("invalid-relay-budget")
        if not isinstance(self.timeout_seconds, (int, float)) or self.timeout_seconds <= 0:
            raise RelayError("invalid-relay-timeout")


def _json_bytes(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def _bounded_json(value: object, depth: int = 0) -> bool:
    """Bound nested client tool schemas independently of the wire byte cap."""

    if depth > 32:
        return False
    if value is None or type(value) is bool or type(value) is int:
        return True
    if type(value) is float:
        return math.isfinite(value)
    if isinstance(value, str):
        return len(value) <= 65536
    if isinstance(value, list):
        return len(value) <= 256 and all(_bounded_json(item, depth + 1) for item in value)
    if isinstance(value, dict):
        return (
            len(value) <= 256
            and all(isinstance(key, str) and len(key) <= 256 for key in value)
            and all(_bounded_json(item, depth + 1) for item in value.values())
        )
    return False


def _valid_tool_name(value: object) -> bool:
    return isinstance(value, str) and bool(_TOOL_NAME.fullmatch(value))


def _validate_client_tool(value: object) -> str | None:
    if not isinstance(value, dict) or not isinstance(value.get("type"), str):
        return "invalid-client-tool"
    tool_type = value["type"]
    if tool_type in _HOSTED_TOOL_TYPES:
        return "hosted-response-tool-refused"
    if tool_type not in _CLIENT_TOOL_TYPES:
        return "unexpected-response-tool-type"
    if not _valid_tool_name(value.get("name")):
        return "invalid-client-tool"
    if _CLIENT_TOOL_NAMES.get(value["name"]) != tool_type:
        return "unexpected-client-tool-name"
    description = value.get("description")
    if description is not None and (
        not isinstance(description, str) or len(description) > 8192
    ):
        return "invalid-client-tool"
    if tool_type == "function":
        if not {"type", "name", "parameters"} <= set(value) <= {
            "type", "name", "description", "parameters", "strict"
        }:
            return "invalid-client-tool"
        if not isinstance(value["parameters"], dict) or not _bounded_json(value["parameters"]):
            return "invalid-client-tool"
        if "strict" in value and type(value["strict"]) is not bool:
            return "invalid-client-tool"
        return None
    if not {"type", "name"} <= set(value) <= {"type", "name", "description", "format"}:
        return "invalid-client-tool"
    format_value = value.get("format")
    if format_value is None:
        return None
    if not isinstance(format_value, dict) or not isinstance(format_value.get("type"), str):
        return "invalid-client-tool"
    if format_value["type"] == "text":
        return None if set(format_value) == {"type"} else "invalid-client-tool"
    if format_value["type"] == "grammar" and set(format_value) == {
        "type", "syntax", "definition"
    }:
        return None if (
            format_value["syntax"] in {"lark", "regex"}
            and isinstance(format_value["definition"], str)
            and len(format_value["definition"]) <= 65536
        ) else "invalid-client-tool"
    return "invalid-client-tool"


def _validate_tool_choice(value: object, tools: Mapping[str, str]) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return None if value in {"auto", "none", "required"} else "invalid-tool-choice"
    if not isinstance(value, dict) or not isinstance(value.get("type"), str):
        return "invalid-tool-choice"
    tool_type = value["type"]
    if tool_type in _HOSTED_TOOL_TYPES:
        return "hosted-response-tool-refused"
    if tool_type not in {"function", "custom"} or set(value) != {"type", "name"}:
        return "invalid-tool-choice"
    name = value.get("name")
    return None if _valid_tool_name(name) and tools.get(name) == tool_type else (
        "invalid-tool-choice"
    )


def _safe_response_id(value: object) -> str | None:
    return value if isinstance(value, str) and _RESPONSE_ID.fullmatch(value) else None


def _response_tool_chain(response: Mapping[str, object]) -> dict[str, str] | None:
    output = response.get("output", [])
    if not isinstance(output, list):
        return None
    chain: dict[str, str] = {}
    for item in output:
        if not isinstance(item, dict):
            return None
        item_type = item.get("type")
        if item_type not in {"function_call", "custom_tool_call"}:
            if isinstance(item_type, str) and item_type.endswith("_call"):
                return None
            continue
        call_id = _safe_response_id(item.get("call_id"))
        name = item.get("name")
        expected_type = "function" if item_type == "function_call" else "custom"
        if (
            call_id is None
            or call_id in chain
            or not isinstance(name, str)
            or _CLIENT_TOOL_NAMES.get(name) != expected_type
            or not _bounded_json(item)
        ):
            return None
        chain[call_id] = hashlib.sha256(_json_bytes(item)).hexdigest()
    return chain


def _request_binds_tool_chain(
    input_items: object,
    expected: Mapping[str, str],
    *,
    previous_response_id_present: bool,
) -> bool:
    if not isinstance(input_items, list) or not expected:
        return False
    call_items: dict[str, str] = {}
    output_ids: set[str] = set()
    for item in input_items:
        if not isinstance(item, dict):
            continue
        item_type = item.get("type")
        call_id = _safe_response_id(item.get("call_id"))
        if item_type in {"function_call", "custom_tool_call"} and call_id is not None:
            if call_id in call_items:
                return False
            call_items[call_id] = hashlib.sha256(_json_bytes(item)).hexdigest()
        elif item_type in {"function_call_output", "custom_tool_call_output"}:
            if call_id is None or call_id in output_ids:
                return False
            output_ids.add(call_id)
    expected_ids = set(expected)
    if output_ids != expected_ids:
        return False
    return previous_response_id_present or call_items == dict(expected)


class EvidenceStore:
    """Dirfd-anchored atomic storage for request bodies and receipts."""

    _REQUEST_NAME = re.compile(r"request-[0-9]{6}\.body\Z")
    _DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC

    def __init__(
        self,
        root: os.PathLike[str] | str,
        credential: bytes,
        *,
        max_request_artifact_bytes: int,
        max_request_artifacts: int,
        max_receipt_bytes: int,
    ):
        self.root = Path(root)
        if not self.root.is_absolute() or "\0" in os.fspath(self.root):
            raise RelayError("unsafe-evidence-root")
        try:
            os.mkdir(self.root, 0o700)
        except FileExistsError:
            pass
        try:
            self._root_fd = os.open(self.root, self._DIRECTORY_FLAGS)
        except OSError as error:
            raise RelayError("unsafe-evidence-root") from error
        self._root_identity = self._directory_identity(
            os.fstat(self._root_fd), "unsafe-evidence-root"
        )
        try:
            resolved_root = self.root.resolve(strict=True)
        except OSError as error:
            os.close(self._root_fd)
            raise RelayError("unsafe-evidence-root") from error
        if resolved_root != self.root:
            os.close(self._root_fd)
            raise RelayError("unsafe-evidence-root")
        try:
            os.mkdir("requests", 0o700, dir_fd=self._root_fd)
        except FileExistsError:
            pass
        try:
            self._requests_fd = os.open(
                "requests", self._DIRECTORY_FLAGS, dir_fd=self._root_fd
            )
        except OSError as error:
            os.close(self._root_fd)
            raise RelayError("unsafe-evidence-requests") from error
        self._requests_identity = self._directory_identity(
            os.fstat(self._requests_fd), "unsafe-evidence-requests"
        )
        self.requests = self.root / "requests"
        self.credential = credential
        self.max_request_artifact_bytes = max_request_artifact_bytes
        self.max_request_artifacts = max_request_artifacts
        self.max_receipt_bytes = max_receipt_bytes
        self._request_artifact_bytes = 0
        self._receipt_bytes = 0
        self._relay_identity: tuple[int, int] | None = None
        self._request_identities: dict[str, tuple[int, int]] = {}
        self._revalidate()

    @staticmethod
    def _identity(info: os.stat_result) -> tuple[int, int]:
        return info.st_dev, info.st_ino

    @classmethod
    def _directory_identity(
        cls, info: os.stat_result, code: str
    ) -> tuple[int, int]:
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            raise RelayError(code)
        return cls._identity(info)

    @classmethod
    def _regular_identity(
        cls, info: os.stat_result, code: str
    ) -> tuple[int, int]:
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            raise RelayError(code)
        return cls._identity(info)

    def _revalidate(self) -> None:
        root_info = os.fstat(self._root_fd)
        if self._directory_identity(root_info, "unsafe-evidence-root") != self._root_identity:
            raise RelayError("evidence-root-replaced")
        try:
            root_path_info = os.stat(self.root, follow_symlinks=False)
        except OSError as error:
            raise RelayError("evidence-root-replaced") from error
        if self._identity(root_path_info) != self._root_identity:
            raise RelayError("evidence-root-replaced")

        requests_info = os.fstat(self._requests_fd)
        if (
            self._directory_identity(requests_info, "unsafe-evidence-requests")
            != self._requests_identity
        ):
            raise RelayError("evidence-requests-replaced")
        try:
            requests_entry = os.stat(
                "requests", dir_fd=self._root_fd, follow_symlinks=False
            )
        except OSError as error:
            raise RelayError("evidence-requests-replaced") from error
        if self._identity(requests_entry) != self._requests_identity:
            raise RelayError("evidence-requests-replaced")

        root_entries = set(os.listdir(self._root_fd))
        expected_root = {"requests"}
        if self._relay_identity is not None:
            expected_root.add("relay.json")
            try:
                relay_info = os.stat(
                    "relay.json", dir_fd=self._root_fd, follow_symlinks=False
                )
                relay_identity = self._regular_identity(
                    relay_info, "relay-receipt-replaced"
                )
            except (OSError, RelayError) as error:
                raise RelayError("relay-receipt-replaced") from error
            if relay_identity != self._relay_identity:
                raise RelayError("relay-receipt-replaced")
        if root_entries != expected_root:
            raise RelayError("unexpected-evidence-root-entry")

        request_entries = set(os.listdir(self._requests_fd))
        if request_entries != set(self._request_identities):
            raise RelayError("unexpected-evidence-request-entry")
        for name, expected in self._request_identities.items():
            try:
                info = os.stat(name, dir_fd=self._requests_fd, follow_symlinks=False)
                identity = self._regular_identity(info, "request-artifact-replaced")
            except (OSError, RelayError) as error:
                raise RelayError("request-artifact-replaced") from error
            if identity != expected:
                raise RelayError("request-artifact-replaced")

    def _atomic(
        self,
        directory_fd: int,
        name: str,
        data: bytes,
        *,
        replace: bool,
    ) -> tuple[int, int]:
        if self.credential in data:
            raise RelayError("credential-in-artifact")
        self._revalidate()
        if not replace:
            try:
                os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise RelayError("evidence-artifact-already-exists")
        temporary = f".{name}.{os.getpid()}.{os.urandom(8).hex()}.tmp"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
        fd = os.open(temporary, flags, 0o600, dir_fd=directory_fd)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb", closefd=False) as writer:
                writer.write(data)
                writer.flush()
                os.fsync(writer.fileno())
            self._regular_identity(os.fstat(fd), "unsafe-temporary-artifact")
            os.close(fd)
            fd = -1
            os.replace(
                temporary,
                name,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
            )
            info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            identity = self._regular_identity(info, "unsafe-evidence-artifact")
            os.fsync(directory_fd)
            return identity
        finally:
            if fd >= 0:
                os.close(fd)
            try:
                os.unlink(temporary, dir_fd=directory_fd)
            except FileNotFoundError:
                pass

    def request_body(self, sequence: int, body: bytes) -> str | None:
        if self.credential in body:
            return None
        if (
            len(self._request_identities) >= self.max_request_artifacts
            or self._request_artifact_bytes + len(body)
            > self.max_request_artifact_bytes
        ):
            raise RelayError("evidence-request-budget-exceeded")
        name = f"request-{sequence:06d}.body"
        if not self._REQUEST_NAME.fullmatch(name):
            raise RelayError("invalid-request-artifact-name")
        identity = self._atomic(self._requests_fd, name, body, replace=False)
        self._request_identities[name] = identity
        self._request_artifact_bytes += len(body)
        self._revalidate()
        return f"requests/{name}"

    def publish(self, receipt: Mapping[str, object]) -> None:
        value = dict(receipt)
        source_accounting = value.get("accounting")
        if not isinstance(source_accounting, Mapping):
            raise RelayError("invalid-relay-receipt")
        accounting = dict(source_accounting)
        value["accounting"] = accounting
        receipt_bytes = self._receipt_bytes
        for _ in range(16):
            accounting.update({
                "retained_request_artifact_bytes": self._request_artifact_bytes,
                "retained_receipt_bytes": receipt_bytes,
                "retained_evidence_bytes": self._request_artifact_bytes + receipt_bytes,
                "retained_request_artifacts": len(self._request_identities),
            })
            data = _json_bytes(value) + b"\n"
            if len(data) == receipt_bytes:
                break
            receipt_bytes = len(data)
        else:
            raise RelayError("receipt-accounting-did-not-converge")
        if (
            receipt_bytes > self.max_receipt_bytes
            or self._request_artifact_bytes + receipt_bytes
            > self.max_request_artifact_bytes + self.max_receipt_bytes
        ):
            raise RelayError("evidence-receipt-budget-exceeded")
        identity = self._atomic(
            self._root_fd,
            "relay.json",
            data,
            replace=True,
        )
        self._relay_identity = identity
        self._receipt_bytes = receipt_bytes
        self._revalidate()

    def accounting(self) -> dict[str, int]:
        return {
            "retained_request_artifact_bytes": self._request_artifact_bytes,
            "retained_receipt_bytes": self._receipt_bytes,
            "retained_evidence_bytes": self._request_artifact_bytes + self._receipt_bytes,
            "retained_request_artifacts": len(self._request_identities),
        }

    def _read_regular(self, directory_fd: int, name: str) -> bytes:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory_fd)
        try:
            self._regular_identity(os.fstat(fd), "unsafe-evidence-artifact")
            chunks = []
            while chunk := os.read(fd, 1 << 20):
                chunks.append(chunk)
            return b"".join(chunks)
        finally:
            os.close(fd)

    def credential_absent(self) -> bool:
        try:
            self._revalidate()
            if self._relay_identity is not None and self.credential in self._read_regular(
                self._root_fd, "relay.json"
            ):
                return False
            for name in sorted(self._request_identities):
                if self.credential in self._read_regular(self._requests_fd, name):
                    return False
            self._revalidate()
            return True
        except (OSError, RelayError):
            return False


@dataclass
class RelayState:
    policy: RelayPolicy
    credential: bytes
    store: EvidenceStore
    context: ContextExpectation
    connection_factory: Callable[[], object]
    inbound_requests: int = 0
    accepted_requests: int = 0
    upstream_attempts: int = 0
    inbound_wire_bytes: int = 0
    inbound_body_bytes: int = 0
    request_bytes: int = 0
    provider_request_bytes: int = 0
    budgeted_request_bytes: int = 0
    rejected_request_bytes: int = 0
    transport_refusal_bytes: int = 0
    response_bytes: int = 0
    retry_refusals: int = 0
    requests: list[dict[str, object]] = field(default_factory=list)
    terminals: list[dict[str, object]] = field(default_factory=list)
    reasons: list[dict[str, object]] = field(default_factory=list)
    seen_digests: set[str] = field(default_factory=set)
    first_request_context: dict[str, object] | None = None
    last_completed_response_id: str | None = None
    pending_tool_calls: dict[str, str] = field(default_factory=dict, repr=False)
    provider_cache_scope: str = field(
        default_factory=lambda: os.urandom(16).hex(), repr=False
    )
    poisoned: bool = False
    listener_closed_reason: str | None = None
    finalized: bool = False
    _admission_lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    @classmethod
    def create(
        cls,
        policy: RelayPolicy,
        evidence_root: os.PathLike[str] | str,
        context: ContextExpectation,
        connection_factory: Callable[[], object] | None = None,
        *,
        auth_fd: int = 3,
    ) -> "RelayState":
        credential = read_provider_credential(auth_fd)
        store = EvidenceStore(
            evidence_root,
            credential,
            max_request_artifact_bytes=policy.max_total_bytes,
            max_request_artifacts=policy.max_requests,
            max_receipt_bytes=policy.max_receipt_bytes,
        )
        if connection_factory is None:
            tls = ssl.create_default_context()
            tls.minimum_version = ssl.TLSVersion.TLSv1_2

            def fixed_connection() -> http.client.HTTPSConnection:
                return http.client.HTTPSConnection(
                    UPSTREAM_HOST,
                    UPSTREAM_PORT,
                    timeout=policy.timeout_seconds,
                    context=tls,
                )

            connection_factory = fixed_connection
        state = cls(policy, credential, store, context, connection_factory)
        state._publish()
        return state

    def _reason(self, code: str, sequence: int | None = None) -> None:
        row: dict[str, object] = {"code": code}
        if sequence is not None:
            row["request_sequence"] = sequence
        if row not in self.reasons:
            self.reasons.append(row)

    def _publish(self) -> None:
        self.store.publish(self.snapshot())

    def _refuse(
        self,
        record: dict[str, object],
        code: str,
        status: int,
        *,
        body_bytes: int,
    ) -> tuple[int, dict[str, str], bytes]:
        sequence = int(record["sequence"])
        record["accepted"] = False
        record["refusal"] = code
        self.rejected_request_bytes += body_bytes
        self.poisoned = True
        self.listener_closed_reason = code
        self._reason(code, sequence)
        self._publish()
        payload = _json_bytes({"error": {"code": code}}) + b"\n"
        return status, {"Content-Type": "application/json", "Connection": "close"}, payload

    def record_transport_refusal(
        self,
        code: str,
        *,
        received_bytes: int = 0,
        body_bytes: int = 0,
    ) -> None:
        if self.finalized or self.poisoned or self.listener_closed_reason is not None:
            return
        if (
            type(received_bytes) is not int
            or type(body_bytes) is not int
            or not 0 <= body_bytes <= received_bytes
            or received_bytes > MAX_HEADER_BYTES + self.policy.max_request_bytes
        ):
            code = "invalid-transport-accounting"
            received_bytes = 0
            body_bytes = 0
        self.inbound_requests += 1
        sequence = self.inbound_requests
        self.inbound_wire_bytes += received_bytes
        self.inbound_body_bytes += body_bytes
        self.transport_refusal_bytes += received_bytes
        proposed_budget = self.budgeted_request_bytes + body_bytes
        if proposed_budget + self.response_bytes <= self.policy.max_total_bytes:
            self.budgeted_request_bytes = proposed_budget
        else:
            self.budgeted_request_bytes = self.policy.max_total_bytes + 1
            self._reason("total-byte-budget-exceeded", sequence)
        if len(self.requests) < self.policy.max_requests:
            self.requests.append({
                "sequence": sequence,
                "accepted": False,
                "refusal": code,
                "transport_bytes": received_bytes,
                "request_body_bytes": None,
                "request_body_sha256": None,
                "request_body_path": None,
                "provider_body_bytes": None,
                "provider_body_sha256": None,
                "provider_body_transformations": [],
                "stripped_worker_headers": [],
            })
        else:
            self._reason("request-budget-exceeded", sequence)
        self.rejected_request_bytes += body_bytes
        self.poisoned = True
        self.listener_closed_reason = code
        self._reason(code, sequence)
        self._publish()

    def handle(
        self,
        method: str,
        target: str,
        version: str,
        headers: Sequence[tuple[str, str]],
        body: bytes,
        wire_bytes: int | None = None,
    ) -> tuple[int, dict[str, str], bytes]:
        with self._admission_lock:
            return self._handle_unlocked(
                method, target, version, headers, body, wire_bytes
            )

    def _handle_unlocked(
        self,
        method: str,
        target: str,
        version: str,
        headers: Sequence[tuple[str, str]],
        body: bytes,
        wire_bytes: int | None = None,
    ) -> tuple[int, dict[str, str], bytes]:
        if self.finalized:
            code, status = "relay-finalized", 409
            return status, {"Content-Type": "application/json", "Connection": "close"}, (
                _json_bytes({"error": {"code": code}}) + b"\n"
            )
        if self.poisoned:
            code, status = "relay-poisoned", 409
            return status, {"Content-Type": "application/json", "Connection": "close"}, (
                _json_bytes({"error": {"code": code}}) + b"\n"
            )
        if self.listener_closed_reason is not None:
            code, status = "request-budget-exceeded", 429
            return status, {"Content-Type": "application/json", "Connection": "close"}, (
                _json_bytes({"error": {"code": code}}) + b"\n"
            )

        if wire_bytes is None:
            wire_bytes = len(body)
        if (
            type(wire_bytes) is not int
            or wire_bytes < len(body)
            or wire_bytes > MAX_HEADER_BYTES + len(body)
        ):
            self.record_transport_refusal("invalid-transport-accounting")
            code = "invalid-transport-accounting"
            return 400, {"Content-Type": "application/json", "Connection": "close"}, (
                _json_bytes({"error": {"code": code}}) + b"\n"
            )

        credential_in_body = self.credential in body
        # Do not preserve a credential-bearing body's exact length indirectly
        # through aggregate counters. Charge the full per-request ceiling,
        # which is conservative, bounded, and non-disclosing.
        accounted_body_bytes = (
            self.policy.max_request_bytes if credential_in_body else len(body)
        )
        accounted_wire_bytes = (
            MAX_HEADER_BYTES + self.policy.max_request_bytes
            if credential_in_body
            else wire_bytes
        )

        self.inbound_requests += 1
        sequence = self.inbound_requests
        self.inbound_wire_bytes += accounted_wire_bytes
        self.inbound_body_bytes += accounted_body_bytes
        if sequence > self.policy.max_requests:
            self.rejected_request_bytes += accounted_body_bytes
            self.poisoned = True
            self.listener_closed_reason = "request-budget-exceeded"
            self._reason("request-budget-exceeded", sequence)
            self._publish()
            code = "request-budget-exceeded"
            return 429, {"Content-Type": "application/json", "Connection": "close"}, (
                _json_bytes({"error": {"code": code}}) + b"\n"
            )
        if (
            self.budgeted_request_bytes + self.response_bytes + accounted_body_bytes
            > self.policy.max_total_bytes
        ):
            self.budgeted_request_bytes = self.policy.max_total_bytes + 1
            self.rejected_request_bytes += accounted_body_bytes
            self.poisoned = True
            self.listener_closed_reason = "total-byte-budget-exceeded"
            self._reason("total-byte-budget-exceeded", sequence)
            self._publish()
            code = "total-byte-budget-exceeded"
            return 413, {"Content-Type": "application/json", "Connection": "close"}, (
                _json_bytes({"error": {"code": code}}) + b"\n"
            )
        self.budgeted_request_bytes += accounted_body_bytes
        header_names = [
            name.lower()
            for name, _value in headers[:MAX_HEADER_COUNT]
            if isinstance(name, str)
        ]
        stripped = sorted(set(header_names) & _SENSITIVE_HEADERS)
        expected_target = target == WORKER_PATH
        record: dict[str, object] = {
            "sequence": sequence,
            "method": method if method == "POST" else "unexpected",
            "target": WORKER_PATH if expected_target else "unexpected",
            # An unexpected target is fully worker-controlled and can itself
            # contain a low-entropy secret. Retain neither its size nor a
            # brute-forceable digest. The accepted route is a fixed constant.
            "target_bytes": len(WORKER_PATH) if expected_target else None,
            "target_sha256": (
                hashlib.sha256(WORKER_PATH.encode("ascii")).hexdigest()
                if expected_target else None
            ),
            "http_version": version if version == "HTTP/1.1" else "unexpected",
            "accepted": False,
            # Provider authentication in a body is not evidence: even its
            # length or digest could disclose a small credential candidate.
            "transport_bytes": None if credential_in_body else wire_bytes,
            "request_body_bytes": None if credential_in_body else len(body),
            "request_body_sha256": None,
            "request_body_path": None,
            "provider_body_bytes": None,
            "provider_body_sha256": None,
            "provider_body_transformations": [],
            "stripped_worker_headers": stripped,
            "ignored_worker_header_count": min(len(headers), MAX_HEADER_COUNT) - len(stripped),
        }
        self.requests.append(record)
        if credential_in_body:
            return self._refuse(
                record,
                "provider-credential-in-request-body",
                400,
                body_bytes=accounted_body_bytes,
            )
        if method != "POST":
            return self._refuse(record, "unexpected-method", 405, body_bytes=len(body))
        if target != WORKER_PATH:
            return self._refuse(record, "unexpected-route", 404, body_bytes=len(body))
        if version != "HTTP/1.1":
            return self._refuse(
                record, "unexpected-http-version", 505, body_bytes=len(body)
            )
        if len(body) > self.policy.max_request_bytes:
            return self._refuse(
                record, "request-body-budget-exceeded", 413, body_bytes=len(body)
            )
        digest = hashlib.sha256(body).hexdigest()
        if digest in self.seen_digests:
            self.retry_refusals += 1
            return self._refuse(record, "retry-refused", 409, body_bytes=len(body))
        try:
            value = strict_json(body)
        except (UnicodeDecodeError, ValueError, RecursionError):
            return self._refuse(record, "invalid-request-json", 400, body_bytes=len(body))
        validation = self._validate_body(value)
        if validation is not None:
            code, status = validation
            return self._refuse(record, code, status, body_bytes=len(body))
        provider_body, transformations = self._provider_body(value, body)
        if len(provider_body) > self.policy.max_request_bytes:
            return self._refuse(
                record, "provider-body-budget-exceeded", 413, body_bytes=len(body)
            )
        charged_bytes = max(len(body), len(provider_body))
        additional_charge = charged_bytes - len(body)
        if (
            self.budgeted_request_bytes + self.response_bytes + additional_charge
            > self.policy.max_total_bytes
        ):
            return self._refuse(
                record, "total-byte-budget-exceeded", 413, body_bytes=len(body)
            )
        if self.accepted_requests == 0:
            # Context evidence belongs to the first request that would actually
            # reach the provider. A rejected route/body cannot prime it. Refuse
            # the run if anything arrived before that candidate, even though
            # every earlier refusal already invalidates settlement.
            if sequence != 1:
                return self._refuse(
                    record, "first-accepted-request-primed", 409, body_bytes=len(body)
                )
            candidate_context = inspect_first_request_context(body, self.context)
            if candidate_context.get("valid") is not True:
                self.first_request_context = candidate_context
                return self._refuse(
                    record, "first-request-context-mismatch", 422, body_bytes=len(body)
                )
            self.first_request_context = candidate_context
        if self.first_request_context is None or self.first_request_context.get("valid") is not True:
            return self._refuse(
                record, "first-request-context-mismatch", 422, body_bytes=len(body)
            )

        try:
            path = self.store.request_body(sequence, body)
        except RelayError:
            return self._refuse(
                record, "evidence-request-budget-exceeded", 500, body_bytes=len(body)
            )
        if path is None:
            return self._refuse(
                record, "provider-credential-in-request-body", 400, body_bytes=len(body)
            )
        self.seen_digests.add(digest)
        self.accepted_requests += 1
        self.request_bytes += len(body)
        self.provider_request_bytes += len(provider_body)
        self.budgeted_request_bytes += additional_charge
        # The next chain link may only use an ID produced by this exact
        # attempt. Clear the prior link before dispatch so a failed terminal
        # cannot leave an older completed response eligible for reuse.
        self.last_completed_response_id = None
        self.pending_tool_calls = {}
        record["accepted"] = True
        record["request_body_sha256"] = digest
        record["request_body_path"] = path
        record["provider_body_bytes"] = len(provider_body)
        record["provider_body_sha256"] = hashlib.sha256(provider_body).hexdigest()
        record["provider_body_transformations"] = transformations
        record["upstream_attempt"] = self.accepted_requests
        self.upstream_attempts += 1
        connection = None
        try:
            connection = self.connection_factory()
            # No incoming header or origin is used here. http.client adds the
            # fixed Host header and performs no redirect or automatic retry.
            connection.request(
                "POST",
                UPSTREAM_PATH,
                body=provider_body,
                headers={
                    "Authorization": f"Bearer {self.credential.decode('ascii')}",
                    "Content-Type": "application/json",
                    "Accept": "text/event-stream, application/json",
                    "Accept-Encoding": "identity",
                    "Connection": "close",
                    "User-Agent": "scourge-native-codex-relay/1",
                },
            )
            response = connection.getresponse()
            upstream_status = int(response.status)
            response_headers = list(response.getheaders())
            response_body = self._read_response(response)
        except (OSError, TimeoutError, http.client.HTTPException, ssl.SSLError):
            self._reason("upstream-transport-failure", sequence)
            self.poisoned = True
            self.listener_closed_reason = "upstream-transport-failure"
            record["upstream_status"] = None
            self._publish()
            return 502, {"Content-Type": "application/json", "Connection": "close"}, (
                b'{"error":{"code":"upstream-transport-failure"}}\n'
            )
        finally:
            try:
                if connection is not None:
                    connection.close()
            except Exception:
                pass

        record["upstream_status"] = upstream_status
        if response_body is None:
            self._reason("response-body-budget-exceeded", sequence)
            self.poisoned = True
            self.listener_closed_reason = "response-body-budget-exceeded"
            self._publish()
            return 502, {"Content-Type": "application/json", "Connection": "close"}, (
                b'{"error":{"code":"response-body-budget-exceeded"}}\n'
            )
        if self.credential in response_body:
            self._reason("provider-credential-in-response", sequence)
            self.poisoned = True
            self.listener_closed_reason = "provider-credential-in-response"
            self._publish()
            return 502, {"Content-Type": "application/json", "Connection": "close"}, (
                b'{"error":{"code":"provider-credential-in-response"}}\n'
            )
        if (
            self.budgeted_request_bytes + self.response_bytes + len(response_body)
            > self.policy.max_total_bytes
        ):
            self._reason("total-byte-budget-exceeded", sequence)
            self.poisoned = True
            self.listener_closed_reason = "total-byte-budget-exceeded"
            self._publish()
            return 502, {"Content-Type": "application/json", "Connection": "close"}, (
                b'{"error":{"code":"total-byte-budget-exceeded"}}\n'
            )
        self.response_bytes += len(response_body)
        content_type = _single_content_type(response_headers)
        content_encoding = _single_content_encoding(response_headers)
        if content_encoding not in (None, "identity"):
            self._reason("encoded-upstream-response-refused", sequence)
            self.poisoned = True
            self.listener_closed_reason = "encoded-upstream-response-refused"
            self._publish()
            return 502, {"Content-Type": "application/json", "Connection": "close"}, (
                b'{"error":{"code":"encoded-upstream-response-refused"}}\n'
            )
        terminal = _terminal_receipt(content_type, response_body)
        chain = terminal.pop("_tool_call_chain", {})
        if not isinstance(chain, dict):
            chain = {}
        terminal.update({
            "request_sequence": sequence,
            "upstream_status": upstream_status,
            "response_bytes": len(response_body),
            "response_sha256": hashlib.sha256(response_body).hexdigest(),
        })
        self.terminals.append(terminal)
        if upstream_status != 200:
            self._reason("unexpected-upstream-status", sequence)
            self.poisoned = True
            self.listener_closed_reason = "unexpected-upstream-status"
        if terminal.get("completed") is not True:
            terminal_reason = str(terminal.get("reason", "invalid-upstream-terminal"))
            self._reason(terminal_reason, sequence)
            self.poisoned = True
            self.listener_closed_reason = terminal_reason
        elif upstream_status == 200:
            response_id = terminal.get("response_id")
            assert isinstance(response_id, str)
            self.last_completed_response_id = response_id
            self.pending_tool_calls = chain
            terminal["tool_call_count"] = len(chain)
            terminal["tool_call_item_sha256"] = sorted(chain.values())
            if self.accepted_requests >= self.policy.max_requests:
                self.listener_closed_reason = "request-budget-exhausted"
        self._publish()
        return upstream_status, {
            "Content-Type": content_type or "application/octet-stream",
            "Content-Length": str(len(response_body)),
            "Connection": "close",
        }, response_body

    def _validate_body(self, value: object) -> tuple[str, int] | None:
        if not isinstance(value, dict):
            return "request-body-not-object", 400
        fields = set(value)
        if fields - _ALLOWED_BODY_FIELDS:
            return "unexpected-request-body-field", 400
        if not _PROVEN_BODY_FIELDS <= fields:
            return "missing-request-body-field", 400
        if value.get("model") != self.policy.model:
            return "unexpected-model", 422
        if value.get("stream") is not True:
            return "nonstreaming-request-refused", 422
        if value["store"] is not False:
            return "stored-response-refused", 422
        if (
            not isinstance(value.get("input"), list)
            or not value["input"]
            or not _bounded_json(value["input"])
        ):
            return "invalid-response-input", 400
        if "max_output_tokens" in value:
            output = value["max_output_tokens"]
            if type(output) is not int or output < 1 or output > self.policy.max_output_tokens:
                return "output-token-budget-exceeded", 422
        client_metadata = value.get("client_metadata")
        if "client_metadata" in value and (
            not isinstance(client_metadata, dict)
            or set(client_metadata) != _CLIENT_METADATA_FIELDS
            or any(
                not isinstance(item, str) or len(item.encode("utf-8")) > 16384
                for item in client_metadata.values()
            )
        ):
            return "invalid-client-metadata", 422
        include = value.get("include")
        if include != ["reasoning.encrypted_content"]:
            return "unsafe-response-include", 422
        if value.get("reasoning") != {"effort": "high"}:
            return "invalid-response-reasoning", 422
        if value.get("text") != {"verbosity": "low"}:
            return "invalid-response-text", 422
        if value.get("parallel_tool_calls") is not True:
            return "invalid-parallel-tool-policy", 422
        prompt_cache_key = value.get("prompt_cache_key")
        if not isinstance(prompt_cache_key, str) or not _PROMPT_CACHE_KEY.fullmatch(
            prompt_cache_key
        ):
            return "invalid-prompt-cache-key", 422
        tools = value.get("tools")
        tool_names: dict[str, str] = {}
        if "tools" in value:
            if not isinstance(tools, list):
                return "invalid-client-tools", 400
            if len(tools) > self.policy.max_tools:
                return "tool-budget-exceeded", 422
            for tool in tools:
                tool_error = _validate_client_tool(tool)
                if tool_error is not None:
                    return tool_error, 422
                tool_type = tool["type"]
                name = tool["name"]
                if name in tool_names:
                    return "duplicate-client-tool-name", 422
                tool_names[name] = tool_type
            if tool_names != _CLIENT_TOOL_NAMES:
                return "unexpected-client-tool-set", 422
        choice_error = (
            _validate_tool_choice(value["tool_choice"], tool_names)
            if "tool_choice" in value and value["tool_choice"] is not None
            else ("invalid-tool-choice" if "tool_choice" in value else None)
        )
        if choice_error is not None:
            return choice_error, 422
        if value["tool_choice"] != "auto":
            return "invalid-tool-choice", 422
        previous_response_id_present = "previous_response_id" in value
        if previous_response_id_present:
            if self.accepted_requests == 0:
                return "previous-response-id-on-first-request", 422
            previous_response_id = _safe_response_id(value["previous_response_id"])
            if (
                previous_response_id is None
                or self.last_completed_response_id is None
                or previous_response_id != self.last_completed_response_id
            ):
                return "previous-response-id-mismatch", 409
        if self.accepted_requests > 0:
            if self.pending_tool_calls:
                if not _request_binds_tool_chain(
                    value["input"],
                    self.pending_tool_calls,
                    previous_response_id_present=previous_response_id_present,
                ):
                    return "followup-tool-chain-mismatch", 409
            elif not previous_response_id_present:
                return "unbound-followup-request", 409
        return None

    def _provider_body(
        self, value: Mapping[str, object], raw: bytes
    ) -> tuple[bytes, list[str]]:
        """Apply only host-owned compatibility transforms after validation."""

        transformations: list[str] = []
        provider_value = dict(value)
        if "client_metadata" in provider_value:
            del provider_value["client_metadata"]
            transformations.append("client-metadata-stripped")
        provider_value["prompt_cache_key"] = (
            f"scourge-{self.provider_cache_scope}-{self.accepted_requests + 1:06d}"
        )
        transformations.append("prompt-cache-key-replaced")
        if "max_output_tokens" not in provider_value:
            provider_value["max_output_tokens"] = self.policy.max_output_tokens
            transformations.append("host-output-token-cap-injected")
        if not transformations:
            return raw, transformations
        return _json_bytes(provider_value), transformations

    def _read_response(self, response: object) -> bytes | None:
        chunks: list[bytes] = []
        size = 0
        while True:
            chunk = response.read(min(65536, self.policy.max_response_bytes + 1 - size))
            if not chunk:
                return b"".join(chunks)
            chunks.append(chunk)
            size += len(chunk)
            if size > self.policy.max_response_bytes:
                return None

    def snapshot(self) -> dict[str, object]:
        reconciled = (
            self.accepted_requests > 0
            and self.accepted_requests == self.upstream_attempts == len(self.terminals)
            and all(row.get("completed") is True for row in self.terminals)
        )
        valid = self.finalized and not self.reasons and reconciled
        return {
            "schema": RELAY_SCHEMA,
            "schema_version": SCHEMA_VERSION,
            "status": "settled" if valid else ("unsettled" if self.finalized else "pending"),
            "settled": valid,
            "valid": valid,
            "score": None,
            "auth": {
                "source": "inherited-descriptor-3",
                "worker_header_values_forwarded": False,
                "credential_recorded": False,
            },
            "upstream": {
                "origin": f"https://{UPSTREAM_HOST}:{UPSTREAM_PORT}",
                "path": UPSTREAM_PATH,
                "redirects": False,
                "retries": False,
            },
            "policy": {
                "model": self.policy.model,
                "max_request_bytes": self.policy.max_request_bytes,
                "max_response_bytes": self.policy.max_response_bytes,
                "max_requests": self.policy.max_requests,
                "max_total_bytes": self.policy.max_total_bytes,
                "max_receipt_bytes": self.policy.max_receipt_bytes,
                "max_retained_evidence_bytes": (
                    self.policy.max_total_bytes + self.policy.max_receipt_bytes
                ),
                "max_output_tokens": self.policy.max_output_tokens,
                "missing_output_token_cap": "inject-host-ceiling",
                "client_metadata": "validate-exact-and-strip",
                "prompt_cache_key": "validate-uuid-and-replace-per-attempt",
                "request_shape": "installed-codex-0.172-gpt-5.5",
                "max_tools": self.policy.max_tools,
            },
            "accounting": {
                "inbound_requests": self.inbound_requests,
                "inbound_wire_bytes": self.inbound_wire_bytes,
                "inbound_body_bytes": self.inbound_body_bytes,
                "credential_body_accounting": "full-request-ceiling",
                "accepted_requests": self.accepted_requests,
                "upstream_attempts": self.upstream_attempts,
                "terminal_receipts": len(self.terminals),
                "request_bytes": self.request_bytes,
                "provider_request_bytes": self.provider_request_bytes,
                "budgeted_request_bytes": self.budgeted_request_bytes,
                "rejected_request_bytes": self.rejected_request_bytes,
                "transport_refusal_bytes": self.transport_refusal_bytes,
                "response_bytes": self.response_bytes,
                "total_bytes": self.budgeted_request_bytes + self.response_bytes,
                "retry_refusals": self.retry_refusals,
                "reconciled": reconciled,
                **self.store.accounting(),
            },
            "listener": {
                "accepting": not (
                    self.finalized
                    or self.poisoned
                    or self.listener_closed_reason is not None
                ),
                "poisoned": self.poisoned,
                "closed_reason": self.listener_closed_reason,
            },
            "requests": self.requests,
            "terminals": self.terminals,
            "first_request_context": self.first_request_context,
            "reasons": self.reasons,
        }

    def finalize(self) -> dict[str, object]:
        if self.finalized:
            return self.snapshot()
        self.finalized = True
        if self.accepted_requests == 0:
            self._reason("no-accepted-model-request")
        if self.accepted_requests != self.upstream_attempts or self.accepted_requests != len(self.terminals):
            self._reason("request-terminal-accounting-mismatch")
        if self.first_request_context is None or self.first_request_context.get("valid") is not True:
            self._reason("first-request-context-mismatch")
        if not self.store.credential_absent():
            self._reason("provider-credential-in-artifact")
        self._publish()
        return self.snapshot()


def _single_content_type(headers: Sequence[tuple[str, str]]) -> str | None:
    values = [value.split(";", 1)[0].strip().lower() for name, value in headers if name.lower() == "content-type"]
    return values[0] if len(values) == 1 else None


def _single_content_encoding(headers: Sequence[tuple[str, str]]) -> str | None:
    values = [value.strip().lower() for name, value in headers if name.lower() == "content-encoding"]
    # Duplicate Content-Encoding is ambiguous even when both values say
    # identity. Represent that ambiguity as a non-identity sentinel.
    return values[0] if len(values) == 1 else (None if not values else "ambiguous")


def _terminal_receipt(content_type: str | None, body: bytes) -> dict[str, object]:
    try:
        if content_type == "text/event-stream":
            events = _sse_events(body)
            terminals = [event for event in events if event.get("type") in {
                "response.completed", "response.failed", "response.incomplete"
            }]
            if len(terminals) != 1 or events[-1] is not terminals[0]:
                return {"completed": False, "reason": "invalid-upstream-terminal"}
            event = terminals[0]
            response = event.get("response")
            if not isinstance(response, dict):
                return {"completed": False, "reason": "invalid-upstream-terminal"}
            kind = event["type"]
            usage = _usage(response.get("usage"))
            response_id = _safe_response_id(response.get("id"))
            tool_chain = _response_tool_chain(response)
            completed = (
                kind == "response.completed"
                and response.get("status") == "completed"
                and response_id is not None
                and usage is not None
                and tool_chain is not None
            )
            return {
                "completed": completed,
                "event_type": kind,
                "response_id": response_id,
                "usage": usage,
                "reason": None if completed else "upstream-terminal-failure",
                "_tool_call_chain": tool_chain or {},
            }
        if content_type == "application/json":
            value = strict_json(body)
            if not isinstance(value, dict):
                raise ValueError("response is not an object")
            usage = _usage(value.get("usage"))
            response_id = _safe_response_id(value.get("id"))
            tool_chain = _response_tool_chain(value)
            completed = (
                value.get("status") == "completed"
                and response_id is not None
                and usage is not None
                and tool_chain is not None
            )
            return {
                "completed": completed,
                "event_type": "response.completed" if completed else "response.failed",
                "response_id": response_id,
                "usage": usage,
                "reason": None if completed else "upstream-terminal-failure",
                "_tool_call_chain": tool_chain or {},
            }
    except (UnicodeDecodeError, ValueError, RecursionError):
        pass
    return {"completed": False, "reason": "invalid-upstream-terminal"}


def _usage(value: object) -> dict[str, int] | None:
    if not isinstance(value, dict):
        return None
    result: dict[str, int] = {}
    for key in ("input_tokens", "output_tokens", "total_tokens"):
        number = value.get(key)
        if type(number) is int and number >= 0:
            result[key] = number
    required = {"input_tokens", "output_tokens", "total_tokens"}
    return result if set(result) == required else None


def _sse_events(body: bytes) -> list[dict[str, object]]:
    if not body.endswith((b"\n\n", b"\r\n\r\n")):
        raise ValueError("torn SSE stream")
    events: list[dict[str, object]] = []
    data: list[bytes] = []
    event_name: str | None = None
    for raw_line in body.replace(b"\r\n", b"\n").split(b"\n"):
        if raw_line == b"":
            if data:
                value = strict_json(b"\n".join(data))
                if not isinstance(value, dict):
                    raise ValueError("SSE data is not an object")
                if event_name is not None and value.get("type") != event_name:
                    raise ValueError("SSE type disagreement")
                events.append(value)
            data, event_name = [], None
            continue
        if raw_line.startswith(b":"):
            continue
        field, separator, value = raw_line.partition(b":")
        if not separator:
            raise ValueError("malformed SSE field")
        value = value[1:] if value.startswith(b" ") else value
        if field == b"event":
            event_name = value.decode("ascii")
        elif field == b"data":
            data.append(value)
        elif field == b"retry":
            raise ValueError("SSE retry directive refused")
        elif field != b"id":
            raise ValueError("unknown SSE field")
    if not events:
        raise ValueError("empty SSE stream")
    return events


def parse_http_request(
    reader: BinaryIO,
    policy: RelayPolicy,
) -> tuple[str, str, str, list[tuple[str, str]], bytes, int]:
    """Parse one unambiguous bounded HTTP/1.1 request from the worker."""

    received = 0
    body_received = 0

    def fail(code: str, status: int = 400) -> None:
        raise RelayError(
            code,
            status,
            received_bytes=received,
            body_bytes=body_received,
        )

    line = reader.readline(4097)
    received += len(line)
    if len(line) > 4096:
        fail("request-line-too-large", 431)
    if not line.endswith(b"\r\n"):
        fail("malformed-request-line")
    try:
        method, target, version = line[:-2].decode("ascii").split(" ")
    except (UnicodeDecodeError, ValueError) as error:
        try:
            fail("malformed-request-line")
        except RelayError as refusal:
            raise refusal from error
    headers: list[tuple[str, str]] = []
    names: set[str] = set()
    for _ in range(MAX_HEADER_COUNT + 1):
        line = reader.readline(MAX_HEADER_BYTES + 1)
        received += len(line)
        if received > MAX_HEADER_BYTES:
            fail("request-headers-too-large", 431)
        if line == b"\r\n":
            break
        if not line.endswith(b"\r\n") or line.startswith((b" ", b"\t")):
            fail("malformed-request-header")
        name, separator, value = line[:-2].partition(b":")
        if not separator or not _HEADER_NAME.fullmatch(name):
            fail("malformed-request-header")
        lowered = name.decode("ascii").lower()
        if lowered in names:
            fail("duplicate-request-header")
        names.add(lowered)
        value = value.strip(b" \t")
        if any(byte < 0x20 and byte != 0x09 for byte in value) or 0x7F in value:
            fail("malformed-request-header")
        headers.append((name.decode("ascii"), value.decode("latin1")))
    else:
        fail("too-many-request-headers", 431)
    table = {name.lower(): value for name, value in headers}
    if "transfer-encoding" in table:
        fail("transfer-encoding-refused")
    if "expect" in table or "upgrade" in table:
        fail("request-upgrade-refused")
    length_value = table.get("content-length")
    if length_value is None or not length_value.isascii() or not length_value.isdecimal():
        fail("invalid-content-length", 411)
    length = int(length_value)
    if length > policy.max_request_bytes:
        fail("request-body-budget-exceeded", 413)
    body = bytearray()
    while len(body) < length:
        chunk = reader.read(length - len(body))
        if not chunk:
            fail("truncated-request-body")
        body.extend(chunk)
        body_received += len(chunk)
        received += len(chunk)
    return method, target, version, headers, bytes(body), received


def _write_response(connection: socket.socket, status: int, headers: Mapping[str, str], body: bytes) -> None:
    phrases = {
        200: "OK", 400: "Bad Request", 404: "Not Found", 405: "Method Not Allowed",
        409: "Conflict", 411: "Length Required", 413: "Content Too Large",
        422: "Unprocessable Content", 429: "Too Many Requests", 431: "Request Header Fields Too Large",
        500: "Internal Server Error", 502: "Bad Gateway", 505: "HTTP Version Not Supported",
    }
    safe = dict(headers)
    safe["Content-Length"] = str(len(body))
    safe["Connection"] = "close"
    head = [f"HTTP/1.1 {status} {phrases.get(status, 'Error')}\r\n"]
    head.extend(f"{name}: {value}\r\n" for name, value in safe.items())
    connection.sendall("".join(head).encode("ascii") + b"\r\n" + body)


def serve_unix(state: RelayState, socket_path: os.PathLike[str] | str, stop: threading.Event) -> None:
    path = Path(socket_path)
    if not path.is_absolute() or path.exists() or path.parent.resolve(strict=True) != path.parent:
        raise RelayError("unsafe-relay-socket-path")
    parent = path.parent.stat()
    if parent.st_uid != os.geteuid() or stat.S_IMODE(parent.st_mode) != 0o700:
        raise RelayError("unsafe-relay-socket-parent")
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        server.bind(os.fspath(path))
        os.chmod(path, 0o600)
        identity = path.lstat()
        server.listen(8)
        server.settimeout(0.2)
        while not stop.is_set() and not (
            state.finalized or state.poisoned or state.listener_closed_reason is not None
        ):
            try:
                connection, _address = server.accept()
            except socket.timeout:
                continue
            with connection:
                connection.settimeout(state.policy.timeout_seconds)
                try:
                    with connection.makefile("rb") as reader:
                        request = parse_http_request(reader, state.policy)
                    result = state.handle(*request)
                except RelayError as error:
                    state.record_transport_refusal(
                        error.code,
                        received_bytes=error.received_bytes,
                        body_bytes=error.body_bytes,
                    )
                    payload = _json_bytes({"error": {"code": error.code}}) + b"\n"
                    result = error.status, {"Content-Type": "application/json"}, payload
                except (OSError, TimeoutError):
                    state.record_transport_refusal("worker-transport-failure")
                    break
                try:
                    _write_response(connection, *result)
                except OSError:
                    sequence = state.inbound_requests or None
                    state._reason("worker-response-delivery-failure", sequence)
                    state.poisoned = True
                    state.listener_closed_reason = "worker-response-delivery-failure"
                    state._publish()
                    break
    finally:
        server.close()
        try:
            current = path.lstat()
            if stat.S_ISSOCK(current.st_mode) and (current.st_dev, current.st_ino) == (identity.st_dev, identity.st_ino):
                path.unlink()
        except (FileNotFoundError, UnboundLocalError):
            pass


def _arguments(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket", required=True)
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--mode", choices=("executable", "managed"), required=True)
    parser.add_argument("--managed-block-file")
    parser.add_argument("--forbid-context", action="append", default=[], metavar="LABEL=TEXT")
    parser.add_argument("--max-request-bytes", type=int, default=2 << 20)
    parser.add_argument("--max-response-bytes", type=int, default=16 << 20)
    parser.add_argument("--max-requests", type=int, default=64)
    parser.add_argument("--max-total-bytes", type=int, default=64 << 20)
    parser.add_argument("--max-receipt-bytes", type=int, default=1 << 20)
    parser.add_argument("--max-output-tokens", type=int, default=32768)
    parser.add_argument("--max-tools", type=int, default=64)
    return parser.parse_args(argv)


def main(argv: Sequence[str] = sys.argv[1:]) -> int:
    args = _arguments(argv)
    if (args.mode == "managed") != bool(args.managed_block_file):
        raise SystemExit("managed mode requires --managed-block-file and executable mode forbids it")
    block = Path(args.managed_block_file).read_text(encoding="utf-8") if args.managed_block_file else None
    forbidden: list[tuple[str, str]] = []
    for value in args.forbid_context:
        label, separator, text = value.partition("=")
        if not separator:
            raise SystemExit("--forbid-context requires LABEL=TEXT")
        forbidden.append((label, text))
    expectation = ContextExpectation(args.mode, block, tuple(forbidden))
    policy = RelayPolicy(
        args.model,
        max_request_bytes=args.max_request_bytes,
        max_response_bytes=args.max_response_bytes,
        max_requests=args.max_requests,
        max_total_bytes=args.max_total_bytes,
        max_receipt_bytes=args.max_receipt_bytes,
        max_output_tokens=args.max_output_tokens,
        max_tools=args.max_tools,
    )
    state = RelayState.create(policy, args.evidence, expectation)
    stop = threading.Event()
    for number in (signal.SIGINT, signal.SIGTERM):
        signal.signal(number, lambda _number, _frame: stop.set())
    try:
        serve_unix(state, args.socket, stop)
    finally:
        receipt = state.finalize()
    sys.stdout.buffer.write(_json_bytes(receipt) + b"\n")
    return 0 if receipt["valid"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
