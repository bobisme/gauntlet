"""Credential-free native Codex worker-boundary helpers.

This module deliberately contains no provider client. The worker receives an
auth-free custom Codex provider on loopback; the host relay is the only process
that receives provider authentication. These helpers keep launch policy,
context evidence, credential-canary checks, and final boundary settlement
independently testable without starting a model or contacting a network.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
from typing import Iterable, Mapping, Sequence


SCHEMA_VERSION = 1
BOUNDARY_SCHEMA = "scourge.native-codex-boundary"
PROBE_SCHEMA = "scourge.native-codex-probes"
ENVIRONMENT_SCHEMA = "scourge.native-codex-effective-environment"
PROVIDER_NAME = "scourge_responses_relay"
PROVIDER_BASE_URL = "http://127.0.0.1:18080/v1"
WORKER_HOSTNAME = "scourge-worker"
PRODUCTION_IMAGE_ID = "43f84a0b210f98845ef003912981774c95efe439eaa4b1cb62cf803fd46fc82a"
CODEX_CONTAINER_PATH = "/opt/scourge-bin/codex"
SUPERVISOR_CONTAINER_PATH = "/opt/scourge-bin/native-codex-supervisor"
MANAGED_START = "<!-- scourge:managed-start -->"
MANAGED_END = "<!-- scourge:managed-end -->"
REQUIRED_PROTECTED_PATHS = (
    "fixture_source",
    "ground_truth",
    "admin_secret",
    "hidden_canaries",
    "grading_state",
)
PROTECTED_WORKER_PATHS = {
    "fixture_source": "/referee/fixture-source",
    "ground_truth": "/referee/ground-truth.json",
    "admin_secret": "/referee/admin-secret",
    "hidden_canaries": "/referee/hidden-canaries",
    "grading_state": "/referee/grading-state",
}
SAFE_ENVIRONMENT_KEYS = frozenset({
    "CODEX_HOME",
    "HOME",
    "HOSTNAME",
    "LANG",
    "M0_PROXY_PORT",
    "NO_COLOR",
    "PATH",
    "TERM",
    "TMPDIR",
    "XDG_CACHE_HOME",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_RUNTIME_DIR",
    "XDG_STATE_HOME",
})
_CREDENTIAL_NAME = re.compile(
    r"(?:^|_)(?:api_?key|auth|bearer|credential|password|secret|token)(?:_|$)", re.I
)
_ENVIRONMENT_NAME = re.compile(r"[A-Z][A-Z0-9_]{0,63}\Z")
_SAFE_NAME = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}\Z")
_HEX_IMAGE = re.compile(r"[0-9a-f]{64}\Z")
_CAPABILITY = re.compile(r"cap_[a-z0-9_]+\Z")
REQUIRED_PODMAN_FLAGS = frozenset({
    "--remote=false",
    "--pull=never",
    "--network=none",
    "--read-only",
    "--http-proxy=false",
    "--cap-drop=all",
    "--security-opt=no-new-privileges",
    "--pids-limit=128",
    "--userns=keep-id",
    "--unsetenv-all",
    f"--hostname={WORKER_HOSTNAME}",
})


class BoundaryError(ValueError):
    """A launch or evidence value would weaken the qualified boundary."""

    def __init__(self, code: str, detail: str | None = None):
        super().__init__(detail or code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class PinnedExecutable:
    """One exact read-only executable admitted to the worker."""

    source: Path
    destination: str
    sha256: str


@dataclass(frozen=True)
class SupervisedCodex:
    """The complete compiled-supervisor/Codex production entrypoint."""

    supervisor: PinnedExecutable
    codex: PinnedExecutable
    codex_argv: tuple[str, ...]


def _json_bytes(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def _unique_object(pairs: Iterable[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def strict_json(raw: bytes) -> object:
    """Decode one strict UTF-8 JSON value, rejecting duplicates and NaN."""

    def reject_constant(_value: str) -> object:
        raise ValueError("non-finite JSON number")

    return json.loads(
        raw.decode("utf-8"), object_pairs_hook=_unique_object, parse_constant=reject_constant
    )


def read_provider_credential(fd: int = 3, *, maximum: int = 8192) -> bytes:
    """Read and close the inherited provider-auth descriptor only."""

    if type(fd) is not int or fd < 0 or type(maximum) is not int or maximum < 1:
        raise BoundaryError("invalid-auth-descriptor")
    try:
        descriptor_type = os.fstat(fd).st_mode
    except OSError as error:
        raise BoundaryError("invalid-auth-descriptor") from error
    if stat.S_ISREG(descriptor_type) or stat.S_ISDIR(descriptor_type):
        os.close(fd)
        raise BoundaryError("auth-file-descriptor-refused")
    chunks: list[bytes] = []
    size = 0
    try:
        while True:
            chunk = os.read(fd, min(4096, maximum + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > maximum:
                raise BoundaryError("provider-auth-too-large")
    finally:
        os.close(fd)
    credential = b"".join(chunks)
    if not credential:
        raise BoundaryError("missing-provider-auth")
    if any(byte < 0x21 or byte > 0x7E for byte in credential):
        raise BoundaryError("invalid-provider-auth")
    return credential


def _toml_string(value: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise BoundaryError("invalid-config-string")
    # JSON strings are TOML basic strings for these admitted values and avoid
    # handwritten quote escaping.
    return json.dumps(value, ensure_ascii=True)


def codex_provider_config(model: str, reasoning_effort: str) -> str:
    """Return the complete auth-free custom-provider config used in-worker."""

    if reasoning_effort not in {"low", "medium", "high", "xhigh"}:
        raise BoundaryError("invalid-reasoning-effort")
    model_value = _toml_string(model)
    return (
        f"model = {model_value}\n"
        f"model_provider = {_toml_string(PROVIDER_NAME)}\n"
        f"model_reasoning_effort = {_toml_string(reasoning_effort)}\n"
        "web_search = \"disabled\"\n"
        "mcp_servers = {}\n"
        f"[model_providers.{PROVIDER_NAME}]\n"
        "name = \"Scourge host Responses relay\"\n"
        f"base_url = {_toml_string(PROVIDER_BASE_URL)}\n"
        "wire_api = \"responses\"\n"
        "requires_openai_auth = false\n"
    )


def codex_exec_argv(
    codex: str,
    model: str,
    reasoning_effort: str,
    mode: str,
    *,
    project: str = "/workspace",
    final_message: str = "/runtime/artifacts/final-message.txt",
) -> list[str]:
    """Build the native Codex command without a key-injection launcher."""

    if mode not in {"executable", "managed"}:
        raise BoundaryError("invalid-context-mode")
    for path in (codex, project, final_message):
        if not isinstance(path, str) or not path.startswith("/") or "\n" in path:
            raise BoundaryError("invalid-container-path")
    codex_provider_config(model, reasoning_effort)
    provider_override = (
        f'model_providers.{PROVIDER_NAME}={{ name="Scourge host Responses relay", '
        f'base_url="{PROVIDER_BASE_URL}", wire_api="responses", '
        "requires_openai_auth=false }"
    )
    # The inline provider is deliberate: --ignore-user-config prevents an
    # image- or operator-owned provider from winning over prepared policy.
    argv = [
        codex,
        "--no-daemon",
        "--ask-for-approval",
        "never",
        "exec",
        "--json",
        "--ephemeral",
        "--ignore-user-config",
        "--ignore-rules",
        "--strict-config",
        "--skip-git-repo-check",
        "--sandbox",
        "danger-full-access",
        "--cd",
        project,
        "--add-dir",
        "/runtime",
        "--model",
        model,
        "--disable",
        "hooks",
        "--disable",
        "apps",
        "--disable",
        "plugins",
        "--disable",
        "multi_agent",
        "--disable",
        "multi_agent_v2",
        "--disable",
        "code_mode",
        "--disable",
        "code_mode_host",
        "--disable",
        "shell_snapshot",
        "-c",
        f'model_provider="{PROVIDER_NAME}"',
        "-c",
        provider_override,
        "-c",
        "mcp_servers={}",
        "-c",
        'web_search="disabled"',
        "-c",
        f'model_reasoning_effort="{reasoning_effort}"',
        "-c",
        f"project_doc_max_bytes={0 if mode == 'executable' else 65536}",
        "--output-last-message",
        final_message,
        "-",
    ]
    assert "codex-launch.py" not in argv
    return argv


def worker_environment(*, proxy_port: int | None = None) -> dict[str, str]:
    """Return the complete allowlisted environment for the Podman worker."""

    if proxy_port is not None and (
        type(proxy_port) is not int or not 1 <= proxy_port <= 65535 or proxy_port == 18080
    ):
        raise BoundaryError("invalid-proxy-port")
    environment = {
        "CODEX_HOME": "/runtime/codex-home",
        "HOME": "/runtime/home",
        "HOSTNAME": WORKER_HOSTNAME,
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
        environment["M0_PROXY_PORT"] = str(proxy_port)
    return environment


def effective_worker_environment_evidence(
    proc_environ: bytes,
    inspection: Mapping[str, object],
    *,
    proxy_port: int | None = None,
) -> dict[str, object]:
    """Attest actual worker and Podman-inspect environments without values."""

    expected = worker_environment(proxy_port=proxy_port)
    expected_rows = [f"{name}={expected[name]}" for name in sorted(expected)]
    expected_bytes = b"\0".join(row.encode("utf-8") for row in expected_rows) + b"\0"
    observed: dict[str, bytes] = {}
    malformed = False
    if (
        not isinstance(proc_environ, bytes)
        or len(proc_environ) > 65536
        or not proc_environ.endswith(b"\0")
    ):
        malformed = True
    else:
        for row in proc_environ[:-1].split(b"\0"):
            name_bytes, separator, value = row.partition(b"=")
            try:
                name = name_bytes.decode("ascii")
            except UnicodeDecodeError:
                malformed = True
                continue
            if (
                not separator
                or _ENVIRONMENT_NAME.fullmatch(name) is None
                or name in observed
            ):
                malformed = True
                continue
            observed[name] = value
    expected_encoded = {
        name: value.encode("utf-8") for name, value in expected.items()
    }
    observed_names = set(observed)
    expected_names = set(expected)
    unexpected = sorted(observed_names - expected_names)
    missing = sorted(expected_names - observed_names)
    mismatched = sorted(
        name
        for name in observed_names & expected_names
        if observed[name] != expected_encoded[name]
    )
    credential_like = sorted(name for name in observed_names if _CREDENTIAL_NAME.search(name))
    proc_exact = not malformed and not unexpected and not missing and not mismatched

    config = inspection.get("Config") if isinstance(inspection, Mapping) else None
    inspect_rows = config.get("Env") if isinstance(config, Mapping) else None
    inspect_hostname = config.get("Hostname") if isinstance(config, Mapping) else None
    inspect_values: dict[str, str] = {}
    inspect_malformed = not isinstance(inspect_rows, list)
    if isinstance(inspect_rows, list):
        for row in inspect_rows:
            if not isinstance(row, str):
                inspect_malformed = True
                continue
            name, separator, value = row.partition("=")
            if (
                not separator
                or _ENVIRONMENT_NAME.fullmatch(name) is None
                or name in inspect_values
            ):
                inspect_malformed = True
                continue
            inspect_values[name] = value
    inspect_env_exact = not inspect_malformed and inspect_values == expected
    inspect_hostname_exact = inspect_hostname == WORKER_HOSTNAME
    valid = bool(
        proc_exact
        and inspect_env_exact
        and inspect_hostname_exact
        and not credential_like
    )
    return {
        "schema": ENVIRONMENT_SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "attempted": True,
        "source": "/proc/self/environ+podman-inspect",
        "expected_names": sorted(expected_names),
        "observed_names": sorted(observed_names),
        "unexpected_names": unexpected,
        "missing_names": missing,
        "value_mismatch_names": mismatched,
        "credential_like_names": credential_like,
        "proc_bytes": len(proc_environ) if isinstance(proc_environ, bytes) else None,
        "proc_exact": proc_exact,
        "inspect_env_exact": inspect_env_exact,
        "inspect_hostname_exact": inspect_hostname_exact,
        "expected_sha256": hashlib.sha256(expected_bytes).hexdigest(),
        "observed_sha256": hashlib.sha256(expected_bytes).hexdigest() if proc_exact else None,
        "valid": valid,
    }


@dataclass(frozen=True)
class ReadOnlyMount:
    source: Path
    destination: str


def _canonical(path: os.PathLike[str] | str, *, kind: str) -> Path:
    candidate = Path(path)
    if not candidate.is_absolute() or "\n" in os.fspath(candidate):
        raise BoundaryError("noncanonical-host-path", kind)
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as error:
        raise BoundaryError("missing-host-path", kind) from error
    if resolved != candidate:
        raise BoundaryError("noncanonical-host-path", kind)
    if kind == "directory" and not candidate.is_dir():
        raise BoundaryError("wrong-host-path-kind", kind)
    if kind == "file" and not candidate.is_file():
        raise BoundaryError("wrong-host-path-kind", kind)
    return resolved


def _canonical_protected(path: os.PathLike[str] | str) -> Path:
    candidate = Path(path)
    if not candidate.is_absolute() or "\n" in os.fspath(candidate):
        raise BoundaryError("noncanonical-host-path", "protected")
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as error:
        raise BoundaryError("missing-host-path", "protected") from error
    if resolved != candidate:
        raise BoundaryError("noncanonical-host-path", "protected")
    return resolved


def _overlaps(left: Path, right: Path) -> bool:
    return left == right or left in right.parents or right in left.parents


def _pinned_executable(value: PinnedExecutable, destination: str) -> Path:
    if not isinstance(value, PinnedExecutable) or value.destination != destination:
        raise BoundaryError("invalid-pinned-executable")
    source = _canonical(value.source, kind="file")
    if (
        not os.access(source, os.X_OK)
        or not _HEX_IMAGE.fullmatch(value.sha256)
        or hashlib.sha256(source.read_bytes()).hexdigest() != value.sha256
    ):
        raise BoundaryError("pinned-executable-mismatch")
    return source


def _supervised_command(value: SupervisedCodex) -> tuple[list[tuple[Path, str]], str, list[str]]:
    supervisor = _pinned_executable(value.supervisor, SUPERVISOR_CONTAINER_PATH)
    codex = _pinned_executable(value.codex, CODEX_CONTAINER_PATH)
    command = list(value.codex_argv)
    if (
        not command
        or command[0] != CODEX_CONTAINER_PATH
        or command.count(CODEX_CONTAINER_PATH) != 1
        or command[-1] != "-"
        or command.count("-") != 1
        or any(
            reserved in command
            for reserved in ("--self-sha256", "--codex-sha256", "--")
        )
        or any(not isinstance(argument, str) or "\x00" in argument for argument in command)
        or command.count("--no-daemon") != 1
        or command.count("--ask-for-approval") != 1
        or command[command.index("--ask-for-approval") + 1] != "never"
        or command.count("--ignore-user-config") != 1
        or command.count("--ignore-rules") != 1
        or command.count("--sandbox") != 1
        or command[command.index("--sandbox") + 1] != "danger-full-access"
        or any(
            sum(
                command[index:index + 2] == ["--disable", feature]
                for index in range(len(command) - 1)
            ) != 1
            for feature in ("code_mode", "code_mode_host", "shell_snapshot")
        )
    ):
        raise BoundaryError("invalid-supervised-codex-command")
    return (
        [
            (supervisor, SUPERVISOR_CONTAINER_PATH),
            (codex, CODEX_CONTAINER_PATH),
        ],
        SUPERVISOR_CONTAINER_PATH,
        [
            "--self-sha256",
            value.supervisor.sha256,
            "--codex-sha256",
            value.codex.sha256,
            "--",
            *command,
        ],
    )


def build_podman_argv(
    *,
    podman_executable: os.PathLike[str] | str,
    oci_runtime: os.PathLike[str] | str,
    auto_remove: bool,
    interactive: bool,
    image_id: str,
    name: str,
    cidfile: os.PathLike[str] | str,
    workspace: os.PathLike[str] | str,
    runtime: os.PathLike[str] | str,
    gateway: os.PathLike[str] | str,
    readonly_mounts: Sequence[ReadOnlyMount],
    protected_roots: Sequence[os.PathLike[str] | str],
    entrypoint: str | None = None,
    command: Sequence[str] = (),
    supervised_codex: SupervisedCodex | None = None,
    proxy_port: int | None = None,
    environment: Mapping[str, str] | None = None,
) -> list[str]:
    """Build one exact networkless rootless Podman worker invocation."""

    podman_path = _canonical(podman_executable, kind="file")
    runtime_path = _canonical(oci_runtime, kind="file")
    if (
        not os.access(podman_path, os.X_OK)
        or not os.access(runtime_path, os.X_OK)
        or type(auto_remove) is not bool
        or type(interactive) is not bool
    ):
        raise BoundaryError("invalid-container-runtime")
    if not _HEX_IMAGE.fullmatch(image_id):
        raise BoundaryError("invalid-image-id")
    supervised_rows: list[tuple[Path, str]] = []
    if supervised_codex is not None:
        if entrypoint is not None or command or image_id != PRODUCTION_IMAGE_ID:
            raise BoundaryError("invalid-supervised-worker-shape")
        supervised_rows, entrypoint, command = _supervised_command(supervised_codex)
    if not _SAFE_NAME.fullmatch(name):
        raise BoundaryError("invalid-container-name")
    cidfile_path = Path(cidfile)
    if not cidfile_path.is_absolute() or "\n" in os.fspath(cidfile_path):
        raise BoundaryError("invalid-cidfile")
    cid_parent = _canonical(cidfile_path.parent, kind="directory")
    if cidfile_path.exists():
        raise BoundaryError("cidfile-exists")
    writable = [
        (_canonical(workspace, kind="directory"), "/workspace"),
        (_canonical(runtime, kind="directory"), "/runtime"),
    ]
    gateway_path = _canonical(gateway, kind="directory")
    gateway_entries = sorted(gateway_path.iterdir())
    gateway_info = gateway_path.stat()
    expected_socket_names = {"model.sock"}
    if proxy_port is not None:
        # Validate the port before using it to select the two-socket topology.
        worker_environment(proxy_port=proxy_port)
        expected_socket_names.add("proxy.sock")
    if (
        {entry.name for entry in gateway_entries} != expected_socket_names
        or any(
            not stat.S_ISSOCK(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600
            for info in (entry.lstat() for entry in gateway_entries)
        )
        or gateway_info.st_uid != os.geteuid()
        or stat.S_IMODE(gateway_info.st_mode) != 0o700
    ):
        raise BoundaryError("gateway-socket-set-not-exact")
    protected = [_canonical_protected(path) for path in protected_roots]
    sources = [path for path, _destination in writable] + [gateway_path]
    ro_rows: list[tuple[Path, str]] = []
    destinations = {PurePosixPath("/workspace"), PurePosixPath("/runtime"), PurePosixPath("/gateway")}
    for source, destination in supervised_rows:
        destination_path = PurePosixPath(destination)
        if destination_path in destinations:
            raise BoundaryError("duplicate-readonly-destination")
        destinations.add(destination_path)
        sources.append(source)
        ro_rows.append((source, destination))
    for mount in readonly_mounts:
        kind = "file" if mount.source.is_file() else "directory"
        source = _canonical(mount.source, kind=kind)
        destination = mount.destination
        destination_path = PurePosixPath(destination) if isinstance(destination, str) else None
        if (
            not isinstance(destination, str)
            or not destination.startswith("/opt/")
            or ".." in PurePosixPath(destination).parts
            or "\n" in destination
            or destination_path is None
            or any(
                destination_path == current
                or destination_path in current.parents
                or current in destination_path.parents
                for current in destinations
            )
        ):
            raise BoundaryError("invalid-readonly-destination")
        destinations.add(destination_path)
        sources.append(source)
        ro_rows.append((source, destination))
    for source in sources:
        if any(_overlaps(source, root) for root in protected):
            raise BoundaryError("protected-root-mounted")
    if _overlaps(writable[0][0], writable[1][0]):
        raise BoundaryError("overlapping-writable-mounts")
    if any(cid_parent == root or root in cid_parent.parents for root in protected):
        raise BoundaryError("protected-cidfile-parent")
    if not isinstance(entrypoint, str) or not entrypoint.startswith("/") or "\n" in entrypoint:
        raise BoundaryError("invalid-entrypoint")
    if not command or any(not isinstance(arg, str) or "\x00" in arg for arg in command):
        raise BoundaryError("invalid-worker-command")
    expected_environment = worker_environment(proxy_port=proxy_port)
    env = dict(expected_environment if environment is None else environment)
    if env != expected_environment or set(env) - SAFE_ENVIRONMENT_KEYS:
        raise BoundaryError("unexpected-worker-environment")
    for key, value in env.items():
        if _CREDENTIAL_NAME.search(key) or not isinstance(value, str) or "\x00" in value or "\n" in value:
            raise BoundaryError("unsafe-worker-environment")

    argv = [
        os.fspath(podman_path),
        "--remote=false",
        f"--runtime={runtime_path}",
        "run",
    ]
    if auto_remove:
        argv.append("--rm")
    argv.append("--unsetenv-all")
    if interactive:
        argv.append("--interactive")
    argv.extend([
        "--pull=never",
        "--network=none",
        "--read-only",
        "--http-proxy=false",
        "--cap-drop=all",
        "--security-opt=no-new-privileges",
        "--pids-limit=128",
        "--userns=keep-id",
        f"--hostname={WORKER_HOSTNAME}",
        "--name",
        name,
        "--cidfile",
        os.fspath(cidfile_path),
        "--mount",
        f"type=bind,src={writable[0][0]},dst=/workspace",
        "--mount",
        f"type=bind,src={writable[1][0]},dst=/runtime",
        "--mount",
        f"type=bind,src={gateway_path},dst=/gateway,ro=true",
    ])
    for source, destination in ro_rows:
        argv.extend(("--mount", f"type=bind,src={source},dst={destination},ro=true"))
    for key in sorted(env):
        argv.extend(("--env", f"{key}={env[key]}"))
    argv.extend(("--entrypoint", entrypoint, image_id, *command))
    return argv


def podman_manifest(argv: Sequence[str]) -> dict[str, object]:
    """Return a secret-free, independently checkable launch summary."""

    entrypoint_option_positions = [
        index for index, value in enumerate(argv[:-2]) if value == "--entrypoint"
    ]
    image_candidate = (
        entrypoint_option_positions[0] + 2
        if len(entrypoint_option_positions) == 1
        else None
    )
    image_position = (
        image_candidate
        if image_candidate is not None
        and image_candidate < len(argv)
        and _HEX_IMAGE.fullmatch(argv[image_candidate])
        else None
    )
    options = list(argv[:image_position]) if image_position is not None else list(argv)
    command = list(argv[image_position + 1:]) if image_position is not None else []
    values = set(options)
    mounts = [
        options[index + 1]
        for index, value in enumerate(options[:-1])
        if value == "--mount"
    ]
    environments = [
        options[index + 1].split("=", 1)[0]
        for index, value in enumerate(options[:-1])
        if value == "--env"
    ]
    runtime_words = [value for value in options if value.startswith("--runtime=")]
    hostname_words = [value for value in options if value.startswith("--hostname=")]
    entrypoints = [
        options[index + 1]
        for index, value in enumerate(options[:-1])
        if value == "--entrypoint"
    ]
    entrypoint = entrypoints[0] if len(entrypoints) == 1 else None
    mount_destinations = [
        row.split(",dst=", 1)[1].split(",", 1)[0]
        for row in mounts
        if ",dst=" in row
    ]
    supervisor_digest = command[1] if len(command) > 1 else None
    codex_digest = command[3] if len(command) > 3 else None
    supervised_contract_valid = bool(
        entrypoint == SUPERVISOR_CONTAINER_PATH
        and len(command) >= 7
        and command[0] == "--self-sha256"
        and command.count("--self-sha256") == 1
        and isinstance(supervisor_digest, str)
        and _HEX_IMAGE.fullmatch(supervisor_digest)
        and command[2] == "--codex-sha256"
        and command.count("--codex-sha256") == 1
        and isinstance(codex_digest, str)
        and _HEX_IMAGE.fullmatch(codex_digest)
        and command[4:6] == ["--", CODEX_CONTAINER_PATH]
        and command.count("--") == 1
        and command.count(CODEX_CONTAINER_PATH) == 1
        and command[-1] == "-"
        and mount_destinations.count(SUPERVISOR_CONTAINER_PATH) == 1
        and mount_destinations.count(CODEX_CONTAINER_PATH) == 1
        and all(
            row.endswith(",ro=true")
            for row in mounts
            if any(f"dst={destination}" in row for destination in (
                SUPERVISOR_CONTAINER_PATH, CODEX_CONTAINER_PATH
            ))
        )
    )
    controlled = (
        "--rm",
        "--interactive",
        "--unsetenv-all",
        "--remote=false",
        "run",
    )
    launch_shape_valid = bool(
        image_position is not None
        and len(argv) >= 5
        and options[1:2] == ["--remote=false"]
        and len(runtime_words) == 1
        and options[2:3] == runtime_words
        and options[3:4] == ["run"]
        and options.count("--unsetenv-all") == 1
        and len(hostname_words) == 1
        and hostname_words[0] == f"--hostname={WORKER_HOSTNAME}"
        and options.count("--rm") <= 1
        and options.count("--interactive") <= 1
        and len(entrypoints) == 1
        and (entrypoint != SUPERVISOR_CONTAINER_PATH or supervised_contract_valid)
        and not any(value in command for value in controlled)
        and not any(value.startswith(("--runtime=", "--hostname=")) for value in command)
    )
    return {
        "podman_executable": argv[0] if argv else None,
        "oci_runtime": next(
            (value.split("=", 1)[1] for value in runtime_words),
            None,
        ),
        "auto_remove": options.count("--rm") == 1,
        "interactive": options.count("--interactive") == 1,
        "unsetenv_all": options.count("--unsetenv-all") == 1,
        "hostname": next(
            (value.split("=", 1)[1] for value in hostname_words),
            None,
        ),
        "image_position": image_position,
        "entrypoint": entrypoint,
        "supervised_codex": {
            "present": entrypoint == SUPERVISOR_CONTAINER_PATH,
            "valid": supervised_contract_valid,
            "supervisor_path": SUPERVISOR_CONTAINER_PATH
            if entrypoint == SUPERVISOR_CONTAINER_PATH else None,
            "supervisor_sha256": supervisor_digest
            if supervised_contract_valid else None,
            "codex_path": CODEX_CONTAINER_PATH
            if supervised_contract_valid else None,
            "codex_sha256": codex_digest if supervised_contract_valid else None,
            "codex_argv_sha256": hashlib.sha256(
                b"\0".join(value.encode() for value in command[5:])
            ).hexdigest() if supervised_contract_valid else None,
            "prompt_transport": "bounded-container-stdin"
            if supervised_contract_valid else None,
        },
        "launch_shape_valid": launch_shape_valid,
        "argv_sha256": hashlib.sha256(b"\0".join(value.encode() for value in argv)).hexdigest(),
        "required_flags_present": sorted(REQUIRED_PODMAN_FLAGS & values),
        "required_flags_complete": REQUIRED_PODMAN_FLAGS <= values and launch_shape_valid,
        "mounts": mounts,
        "environment_names": environments,
        "credential_environment_names": sorted(
            name for name in environments if _CREDENTIAL_NAME.search(name)
        ),
    }


@dataclass(frozen=True)
class ContextExpectation:
    mode: str
    managed_block: str | None = None
    forbidden_fragments: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        if self.mode not in {"executable", "managed"}:
            raise BoundaryError("invalid-context-mode")
        if self.mode == "managed":
            if (
                not self.managed_block
                or self.managed_block.count(MANAGED_START) != 1
                or self.managed_block.count(MANAGED_END) != 1
                or self.managed_block.index(MANAGED_START) >= self.managed_block.index(MANAGED_END)
            ):
                raise BoundaryError("invalid-managed-block")
        elif self.managed_block is not None:
            raise BoundaryError("unexpected-managed-block")
        labels: set[str] = set()
        for label, fragment in self.forbidden_fragments:
            if not _SAFE_NAME.fullmatch(label) or not fragment or label in labels:
                raise BoundaryError("invalid-forbidden-context")
            labels.add(label)


def _strings(value: object) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)
    elif isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from _strings(item)


def inspect_first_request_context(raw: bytes, expectation: ContextExpectation) -> dict[str, object]:
    """Prove the assigned guide cell from the relay's byte-exact first body."""

    reasons: list[dict[str, object]] = []
    try:
        value = strict_json(raw)
        texts = list(_strings(value))
    except (UnicodeDecodeError, ValueError, RecursionError) as error:
        texts = []
        reasons.append({"code": "invalid-first-request-json", "detail": type(error).__name__})
    starts = sum(text.count(MANAGED_START) for text in texts)
    ends = sum(text.count(MANAGED_END) for text in texts)
    intact = 0
    managed_sha256 = None
    if expectation.managed_block is not None:
        managed_sha256 = hashlib.sha256(expectation.managed_block.encode("utf-8")).hexdigest()
        intact = sum(text.count(expectation.managed_block) for text in texts)
    if expectation.mode == "executable":
        if starts or ends:
            reasons.append({"code": "managed-block-in-executable-cell"})
    elif (starts, ends, intact) != (1, 1, 1):
        reasons.append({"code": "managed-block-count-mismatch"})
    # Include object keys and a fail-closed concatenation so a fragment cannot
    # be hidden by moving it into a key or splitting it across JSON strings.
    joined_text = "".join(texts)
    forbidden = sorted(
        label
        for label, fragment in expectation.forbidden_fragments
        if fragment in joined_text
    )
    if forbidden:
        reasons.append({"code": "host-context-visible", "labels": forbidden})
    return {
        "mode": expectation.mode,
        "request_body_bytes": len(raw),
        "request_body_sha256": hashlib.sha256(raw).hexdigest(),
        "managed_start_count": starts,
        "managed_end_count": ends,
        "intact_managed_block_count": intact,
        "managed_block_sha256": managed_sha256,
        "forbidden_context_matches": forbidden,
        "valid": not reasons,
        "reasons": reasons,
    }


def _scan_file(path: Path, needle: bytes, maximum: int) -> tuple[bool, int, str | None]:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        return False, 0, "unsafe-entry"
    scanned = 0
    overlap = b""
    with path.open("rb") as reader:
        while chunk := reader.read(1 << 20):
            scanned += len(chunk)
            if scanned > maximum:
                return False, scanned, "scan-budget-exceeded"
            combined = overlap + chunk
            if needle in combined:
                return True, scanned, None
            overlap = combined[-max(0, len(needle) - 1):]
    return False, scanned, None


def _scan_roots(roots: Sequence[os.PathLike[str] | str], needle: bytes, maximum: int) -> dict[str, object]:
    matches: list[str] = []
    issues: list[dict[str, str]] = []
    scanned = 0
    entries = 0
    for root_value in roots:
        root = Path(root_value)
        try:
            root = root.resolve(strict=True)
        except OSError:
            issues.append({"path": os.fspath(root), "code": "missing-scan-root"})
            continue
        candidates = [root] if root.is_file() else sorted(
            path for path in root.rglob("*") if path.is_file() or path.is_symlink()
        )
        for path in candidates:
            entries += 1
            found, count, issue = _scan_file(path, needle, maximum - scanned)
            scanned += count
            label = os.fspath(path.relative_to(root)) if path != root else root.name
            if found:
                matches.append(label)
            if issue:
                issues.append({"path": label, "code": issue})
            if scanned > maximum:
                break
        if scanned > maximum:
            break
    return {
        "absent": not matches and not issues,
        "bytes_scanned": scanned,
        "entries_scanned": entries,
        "matches": matches,
        "issues": issues,
    }


def credential_canary_evidence(
    credential: bytes,
    *,
    worker_environment_values: Mapping[str, str],
    worker_proc_blobs: Sequence[bytes],
    worker_roots: Sequence[os.PathLike[str] | str],
    artifact_roots: Sequence[os.PathLike[str] | str],
    maximum_file_bytes: int = 64 << 20,
) -> dict[str, object]:
    """Check the provider canary without retaining it or a digest of it."""

    if not credential:
        raise BoundaryError("missing-provider-auth")
    env_blob = b"\x00".join(
        f"{key}={value}".encode("utf-8", errors="surrogateescape")
        for key, value in sorted(worker_environment_values.items())
    )
    proc_blob = b"\x00".join(worker_proc_blobs)
    files = _scan_roots(worker_roots, credential, maximum_file_bytes)
    artifacts = _scan_roots(artifact_roots, credential, maximum_file_bytes)
    return {
        "env": {
            "absent": credential not in env_blob,
            "bytes_scanned": len(env_blob),
            "entries_scanned": len(worker_environment_values),
        },
        "proc": {
            "absent": credential not in proc_blob,
            "bytes_scanned": len(proc_blob),
            "entries_scanned": len(worker_proc_blobs),
        },
        "files": files,
        "artifacts": artifacts,
    }


def _exact_object(value: object, keys: set[str]) -> bool:
    return isinstance(value, dict) and set(value) == keys


def _refusal_probe(value: object, *, path: str | None = None) -> bool:
    keys = {"attempted", "refused", "errno", "error"}
    if path is not None:
        keys.add("path")
    return (
        _exact_object(value, keys)
        and value["attempted"] is True
        and value["refused"] is True
        and type(value["errno"]) is int
        and value["errno"] != 0
        and isinstance(value["error"], str)
        and bool(value["error"])
        and (path is None or value["path"] == path)
    )


def _write_probe(value: object, path: str) -> bool:
    return (
        _exact_object(value, {"attempted", "succeeded", "bytes_written", "cleaned", "path"})
        and value["attempted"] is True
        and value["succeeded"] is True
        and type(value["bytes_written"]) is int
        and value["bytes_written"] > 0
        and value["cleaned"] is True
        and value["path"] == path
    )


def settle_boundary(relay: Mapping[str, object], probes: Mapping[str, object]) -> dict[str, object]:
    """Combine typed relay/host/worker receipts with trial-capture semantics."""

    reasons: list[dict[str, object]] = []

    def require(value: object, code: str) -> None:
        if value is not True:
            reasons.append({"code": code})

    require(relay.get("settled"), "relay-unsettled")
    require(relay.get("valid"), "relay-invalid")
    accounting = relay.get("accounting")
    require(
        isinstance(accounting, dict) and accounting.get("reconciled") is True,
        "request-terminal-mismatch",
    )
    context = relay.get("first_request_context")
    require(
        isinstance(context, dict) and context.get("valid") is True,
        "context-evidence-mismatch",
    )
    require(
        probes.get("schema") == PROBE_SCHEMA and probes.get("schema_version") == SCHEMA_VERSION,
        "invalid-probe-receipt",
    )
    environment = probes.get("environment")
    require(
        isinstance(environment, dict)
        and environment.get("schema") == ENVIRONMENT_SCHEMA
        and environment.get("schema_version") == SCHEMA_VERSION
        and environment.get("attempted") is True
        and environment.get("proc_exact") is True
        and environment.get("inspect_env_exact") is True
        and environment.get("inspect_hostname_exact") is True
        and environment.get("credential_like_names") == []
        and environment.get("valid") is True,
        "worker-environment-mismatch",
    )

    credential = probes.get("credential_canary_absence")
    if not isinstance(credential, dict) or set(credential) != {"env", "proc", "files", "artifacts"}:
        reasons.append({"code": "missing-credential-canary-evidence"})
    else:
        for area in ("env", "proc"):
            row = credential.get(area)
            require(
                _exact_object(row, {"absent", "bytes_scanned", "entries_scanned"})
                and row["absent"] is True
                and type(row["bytes_scanned"]) is int
                and row["bytes_scanned"] > 0
                and type(row["entries_scanned"]) is int
                and row["entries_scanned"] > 0,
                f"credential-canary-visible-{area}",
            )
        for area in ("files", "artifacts"):
            row = credential.get(area)
            require(
                _exact_object(
                    row, {"absent", "bytes_scanned", "entries_scanned", "matches", "issues"}
                )
                and row["absent"] is True
                and type(row["bytes_scanned"]) is int
                and row["bytes_scanned"] > 0
                and type(row["entries_scanned"]) is int
                and row["entries_scanned"] > 0
                and row["matches"] == []
                and row["issues"] == [],
                f"credential-canary-visible-{area}",
            )

    protected = probes.get("protected_paths")
    if not isinstance(protected, dict) or set(protected) != set(REQUIRED_PROTECTED_PATHS):
        reasons.append({"code": "missing-protected-path-evidence"})
    else:
        for label in REQUIRED_PROTECTED_PATHS:
            row = protected[label]
            expected_path = PROTECTED_WORKER_PATHS[label]
            valid = (
                _exact_object(row, {"read", "write"})
                and _refusal_probe(row["read"], path=expected_path)
                and _refusal_probe(row["write"], path=expected_path)
            )
            require(valid, f"protected-path-visible-{label}")

    egress = probes.get("direct_egress")
    require(
        _exact_object(egress, {"attempted", "destination", "connected", "errno", "error"})
        and egress["attempted"] is True
        and egress["destination"] == "192.0.2.1:443"
        and egress["connected"] is False
        and type(egress["errno"]) is int
        and egress["errno"] != 0
        and isinstance(egress["error"], str)
        and bool(egress["error"]),
        "direct-egress-available",
    )

    mounts = probes.get("mounts")
    mount_container_id = None
    if not _exact_object(mounts, {"container_id", "allowlist", "write_probes"}):
        reasons.append({"code": "missing-mount-evidence"})
    else:
        mount_container_id = mounts["container_id"]
        require(
            isinstance(mount_container_id, str) and bool(_HEX_IMAGE.fullmatch(mount_container_id)),
            "invalid-mount-container-identity",
        )
        allowlist = mounts["allowlist"]
        require(
            _exact_object(
                allowlist,
                {"attempted", "expected_destinations", "observed_destinations", "exact"},
            )
            and allowlist["attempted"] is True
            and allowlist["exact"] is True
            and isinstance(allowlist["expected_destinations"], list)
            and allowlist["expected_destinations"] == allowlist["observed_destinations"]
            and len(set(allowlist["expected_destinations"])) == len(allowlist["expected_destinations"])
            and {"/workspace", "/runtime", "/gateway"} <= set(allowlist["expected_destinations"]),
            "mount-allowlist-mismatch",
        )
        writes = mounts["write_probes"]
        writes_valid = isinstance(writes, dict) and set(writes) == {
            "workspace", "runtime", "binaries", "gateway", "rootfs"
        }
        require(writes_valid, "missing-mount-write-probes")
        if writes_valid:
            require(_write_probe(writes["workspace"], "/workspace"), "mount-check-failed-workspace")
            require(_write_probe(writes["runtime"], "/runtime"), "mount-check-failed-runtime")
            binaries = writes["binaries"]
            require(
                isinstance(binaries, list)
                and len(binaries) >= 2
                and len({row.get("path") for row in binaries if isinstance(row, dict)}) == len(binaries)
                and all(
                    isinstance(row, dict)
                    and isinstance(row.get("path"), str)
                    and row["path"].startswith("/opt/")
                    and _refusal_probe(row, path=row["path"])
                    for row in binaries
                ),
                "mount-check-failed-binaries",
            )
            require(
                _refusal_probe(writes["gateway"], path="/gateway"),
                "mount-check-failed-gateway",
            )
            require(
                _refusal_probe(writes["rootfs"], path="/"),
                "mount-check-failed-rootfs",
            )

    gateway = probes.get("gateway")
    gateway_proxy_port = None
    gateway_valid = _exact_object(gateway, {"container_id", "inspect", "proxy"})
    if gateway_valid:
        gateway_inspect = gateway["inspect"]
        expected_sockets = gateway_inspect.get("expected_sockets") if isinstance(
            gateway_inspect, dict
        ) else None
        allowed_sockets = (["model.sock"], ["model.sock", "proxy.sock"])
        gateway_valid = (
            gateway["container_id"] == mount_container_id
            and _exact_object(
                gateway_inspect,
                {"attempted", "expected_sockets", "observed_sockets", "exact", "modes"},
            )
            and gateway_inspect["attempted"] is True
            and expected_sockets in allowed_sockets
            and gateway_inspect["observed_sockets"] == expected_sockets
            and gateway_inspect["exact"] is True
            and gateway_inspect["modes"] == {
                name: 0o600 for name in expected_sockets
            }
        )
        proxy = gateway["proxy"]
        if gateway_valid and expected_sockets == ["model.sock"]:
            gateway_valid = proxy is None
        elif gateway_valid:
            gateway_valid = (
                _exact_object(
                    proxy,
                    {
                        "attempted",
                        "port",
                        "connected",
                        "worker",
                        "host",
                        "reconciled",
                    },
                )
                and proxy["attempted"] is True
                and type(proxy["port"]) is int
                and 1 <= proxy["port"] <= 65535
                and proxy["port"] != 18080
                and proxy["connected"] is True
                and _exact_object(
                    proxy["worker"],
                    {"request_bytes", "request_sha256", "response_bytes", "response_sha256"},
                )
                and _exact_object(
                    proxy["host"],
                    {
                        "attempts",
                        "request_bytes",
                        "request_sha256",
                        "response_bytes",
                        "response_sha256",
                    },
                )
                and proxy["host"]["attempts"] == 1
                and proxy["worker"] == {
                    key: proxy["host"][key]
                    for key in (
                        "request_bytes", "request_sha256", "response_bytes", "response_sha256"
                    )
                }
                and type(proxy["worker"]["request_bytes"]) is int
                and proxy["worker"]["request_bytes"] > 0
                and type(proxy["worker"]["response_bytes"]) is int
                and proxy["worker"]["response_bytes"] > 0
                and all(
                    isinstance(proxy["worker"][field], str)
                    and bool(_HEX_IMAGE.fullmatch(proxy["worker"][field]))
                    for field in ("request_sha256", "response_sha256")
                )
                and proxy["reconciled"] is True
            )
            if gateway_valid:
                gateway_proxy_port = proxy["port"]
    require(gateway_valid, "gateway-topology-mismatch")

    isolation = probes.get("isolation")
    isolation_valid = _exact_object(
        isolation, {"container_id", "podman_info", "launch", "inspect", "worker"}
    )
    if isolation_valid:
        podman_info = isolation["podman_info"]
        launch = isolation["launch"]
        inspected = isolation["inspect"]
        worker_security = isolation["worker"]
        observed_caps = inspected.get("cap_drop") if isinstance(inspected, dict) else None
        isolation_valid = (
            isolation["container_id"] == mount_container_id
            and _exact_object(
                podman_info, {"attempted", "exit_code", "rootless", "remote"}
            )
            and podman_info["attempted"] is True
            and podman_info["exit_code"] == 0
            and podman_info["rootless"] is True
            and podman_info["remote"] is False
            and _exact_object(
                launch,
                {
                    "attempted",
                    "argv_sha256",
                    "required_flags_present",
                    "required_flags_complete",
                    "launch_shape_valid",
                    "podman_executable",
                    "oci_runtime",
                    "auto_remove",
                    "interactive",
                    "unsetenv_all",
                    "hostname",
                    "environment_names",
                    "proxy_port",
                    "credential_environment_names",
                },
            )
            and launch["attempted"] is True
            and isinstance(launch["argv_sha256"], str)
            and bool(_HEX_IMAGE.fullmatch(launch["argv_sha256"]))
            and launch["required_flags_present"] == sorted(REQUIRED_PODMAN_FLAGS)
            and launch["required_flags_complete"] is True
            and launch["launch_shape_valid"] is True
            and launch["podman_executable"] == "/usr/bin/podman"
            and launch["oci_runtime"] == "/usr/bin/crun"
            and launch["auto_remove"] is False
            and launch["interactive"] is False
            and launch["unsetenv_all"] is True
            and launch["hostname"] == WORKER_HOSTNAME
            and launch["environment_names"] == sorted(
                worker_environment(proxy_port=gateway_proxy_port)
            )
            and launch["proxy_port"] == gateway_proxy_port
            and launch["credential_environment_names"] == []
            and _exact_object(
                inspected,
                {
                    "attempted",
                    "exit_code",
                    "network_mode",
                    "read_only_rootfs",
                    "cap_add",
                    "cap_drop",
                    "security_opt",
                    "pids_limit",
                    "userns_mode",
                },
            )
            and inspected["attempted"] is True
            and inspected["exit_code"] == 0
            and inspected["network_mode"] == "none"
            and inspected["read_only_rootfs"] is True
            and inspected["cap_add"] == []
            and isinstance(observed_caps, list)
            and bool(observed_caps)
            and observed_caps == sorted(set(observed_caps))
            and all(isinstance(value, str) and _CAPABILITY.fullmatch(value) for value in observed_caps)
            and inspected["security_opt"] == ["no-new-privileges"]
            and inspected["pids_limit"] == 128
            and inspected["userns_mode"] in {"private", "keep-id"}
            and _exact_object(worker_security, {"cap_eff", "no_new_privs"})
            and isinstance(worker_security["cap_eff"], str)
            and bool(re.fullmatch(r"[0-9A-Fa-f]{16}", worker_security["cap_eff"]))
            and int(worker_security["cap_eff"], 16) == 0
            and worker_security["no_new_privs"] == 1
        )
    require(isolation_valid, "container-isolation-mismatch")

    teardown = probes.get("teardown")
    if not _exact_object(teardown, {"worker", "forwarder", "container"}):
        reasons.append({"code": "missing-teardown-evidence"})
    else:
        for field in ("worker", "forwarder"):
            row = teardown[field]
            require(
                _exact_object(row, {"attempted", "stopped", "exit_code"})
                and row["attempted"] is True
                and row["stopped"] is True
                and type(row["exit_code"]) is int
                and (
                    row["exit_code"] == 0
                    if field == "worker"
                    else row["exit_code"] in (0, 143)
                ),
                f"teardown-check-failed-{field}",
            )
        container = teardown["container"]
        require(
            _exact_object(
                container,
                {"container_id", "remove_attempted", "exists_probe_exit_code", "removed"},
            )
            and isinstance(container["container_id"], str)
            and bool(_HEX_IMAGE.fullmatch(container["container_id"]))
            and container["container_id"] == mount_container_id
            and container["remove_attempted"] is True
            and container["exists_probe_exit_code"] == 1
            and container["removed"] is True,
            "teardown-check-failed-container",
        )

    return {
        "schema": BOUNDARY_SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "status": "unsettled" if reasons else "settled",
        "settled": not reasons,
        "valid": not reasons,
        "score": None,
        "relay": dict(relay),
        "probes": dict(probes),
        "reasons": reasons,
    }
