#!/usr/bin/env python3
"""Drive one unscored real-application smoke session on the pinned public target.

This runner is deliberately narrow. It:

* verifies the pinned upstream checkout byte for byte (a patched tree is refused),
* builds and runs a disposable loopback-only container from that checkout,
* proves the target's declared cross-account read and write behaviour referee-side,
* resets the target from one pristine database copy before each arm,
* launches one fresh Pi/Orca worker process per arm in a private workspace, home and
  Rite store, captures the full JSON event stream, and
* tears the container down and verifies it is gone.

It never reads a credential value, never reuses a worker process, never reruns an
assigned arm, and never grades an arm. See evals/realapp/README.md.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

REALAPP = Path(__file__).resolve().parent
REPO = REALAPP.parents[1]
TARGET_LOCK = json.loads((REALAPP / "target.lock.json").read_text())
MATERIALS_LOCK = json.loads((REALAPP / "materials.lock.json").read_text())
FROZEN_ASSIGNMENT = REALAPP / "frozen-assignment.json"
MATERIALS = REALAPP / "materials"
SCRATCH_BASE = Path(os.environ.get("REALAPP_SCRATCH", "/tmp/scourge-realapp/sessions"))

IMAGE_TAG = str(TARGET_LOCK["container"]["built_reference"])
MODEL_ROW = {"provider": "orcacyber", "model": "orca/orcacyber-flash-1.0", "thinking": "low"}
BASE_PATH = "/home/bob/.bun/bin:/home/bob/.local/share/mise/installs/python/latest/bin:/usr/local/bin:/usr/bin:/bin"
# Referee-side helpers (rite, python) run with the operator's PATH; the worker
# still receives only BASE_PATH in its own environment allowlist.
HELPER_PATH = os.environ.get("PATH", BASE_PATH)
ACCOUNT_LIST = [
    ("name1", "pass1"),
    ("name2", "pass2"),
    ("admin", "pass1"),
    ("alice", "alice-smoke-pw"),
    ("bob", "bob-smoke-pw"),
    ("carol", "carol-smoke-pw"),
]
# Referee material an arm must not need: the repository, the plan, the frozen locks
# and the referee's own evidence. The worker's own workspace and scratch prefix are
# normalized out first, because their paths contain the project name.
REFEREE_PATH_TOKENS = (
    "/home/bob/src/scourge",
    "notes/plan",
    "evals/realapp",
    "evals/m0-baseline",
    "target.lock.json",
    "frozen-assignment.json",
    "pristine.db",
    "seed-proof",
)


def die(message: str, code: int = 1) -> "NoReturn":
    print(f"FATAL: {message}", file=sys.stderr)
    sys.exit(code)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def write_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=False) + "\n")


def load_frozen_assignment(path: Path = FROZEN_ASSIGNMENT) -> tuple[bytes, dict, str]:
    if not path.is_file():
        die("run `freeze` before the first arm")
    payload = path.read_bytes()
    try:
        assignment = json.loads(payload)
    except json.JSONDecodeError as error:
        die(f"frozen assignment is invalid JSON: {error}")
    return payload, assignment, sha256_bytes(payload)


def snapshot_frozen_assignment(records: Path, payload: bytes) -> dict[str, str]:
    """Preserve the exact assignment bytes used by one committed session."""
    relative = Path("referee/frozen-assignment.json")
    destination = records / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(payload)
    return {"path": str(relative), "sha256": sha256_bytes(payload)}


def run(argv, *, cwd=None, env=None, timeout=120, check=True) -> subprocess.CompletedProcess:
    result = subprocess.run(argv, cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout)
    if check and result.returncode != 0:
        raise RuntimeError(f"command failed ({result.returncode}): {argv}\n{result.stderr.strip()}")
    return result


def podman(*args, **kwargs) -> subprocess.CompletedProcess:
    return run(["podman", "--remote=false", *args], **kwargs)


def container_exists(name: str) -> bool:
    return podman("container", "exists", name, check=False).returncode == 0


def remove_container(name: str) -> None:
    if container_exists(name):
        podman("rm", "--force", name, check=False, timeout=60)
    deadline = time.time() + 20
    while container_exists(name):
        if time.time() > deadline:
            raise RuntimeError(f"container {name} survived removal")
        time.sleep(0.5)


# ---------------------------------------------------------------------------
# native HTTP without an external dependency


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect)


def http(url: str, method: str = "GET", body=None, token=None, timeout=5) -> dict:
    data = None
    headers = {"Accept": "application/json"}
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with OPENER.open(request, timeout=timeout) as response:
            raw = response.read()
            status = response.status
    except urllib.error.HTTPError as error:
        raw = error.read()
        status = error.code
    try:
        parsed = json.loads(raw.decode())
    except (UnicodeDecodeError, json.JSONDecodeError):
        parsed = raw.decode(errors="replace")
    return {"status": status, "body": parsed}


# ---------------------------------------------------------------------------
# pins


def verify_source_tree(source_dir: Path) -> dict:
    upstream = TARGET_LOCK["upstream"]
    if not (source_dir / ".git").exists():
        die(f"source directory {source_dir} is not a git checkout of the pinned commit")
    head = run(["git", "-C", str(source_dir), "rev-parse", "HEAD"]).stdout.strip()
    tree = run(["git", "-C", str(source_dir), "rev-parse", "HEAD^{tree}"]).stdout.strip()
    if head != upstream["commit"] or tree != upstream["tree"]:
        die(f"source checkout is not the pinned revision ({head} {tree})")
    dirty = run(["git", "-C", str(source_dir), "status", "--porcelain", "--untracked-files=all"]).stdout.strip()
    if dirty:
        die("source checkout has local modifications; a patched tree is not a real-application target")
    manifest = upstream["file_manifest"]
    seen = {}
    for path in sorted(source_dir.rglob("*")):
        if not path.is_file():
            continue
        rel = str(path.relative_to(source_dir))
        if rel.split("/")[0] == ".git":
            continue
        seen[rel] = sha256_file(path)
    if set(seen) != set(manifest):
        missing = sorted(set(manifest) - set(seen))
        extra = sorted(set(seen) - set(manifest))
        die(f"source file set differs from the pin (missing={missing} extra={extra})")
    mismatched = [name for name, digest in manifest.items() if seen[name] != digest]
    if mismatched:
        die(f"source files differ from the pin: {mismatched}")
    return {"commit": head, "tree": tree, "files": len(manifest), "clean": True}


def verify_materials() -> dict:
    digests = {}
    for rel, expected in MATERIALS_LOCK["files"].items():
        path = REALAPP / rel
        actual = sha256_file(path)
        if actual != expected:
            die(f"frozen input {rel} does not match materials.lock.json")
        digests[rel] = actual
    for rel, record in MATERIALS_LOCK["copied_from_m0_baseline"].items():
        if digests[f"materials/{rel}"] != record["sha256"]:
            die(f"{rel} is not byte-identical to the frozen M0.4 material")
    return digests


def pi_binary() -> Path:
    found = shutil.which("pi")
    if not found:
        die("the Pi CLI is not on PATH; the frozen assignment needs it")
    return Path(found)


def pi_version(binary: Path) -> str:
    return run([str(binary), "--version"]).stdout.strip()


def model_available(binary: Path) -> str:
    listing = run([str(binary), "--list-models", "orca"], check=False)
    for line in listing.stdout.splitlines():
        if MODEL_ROW["model"] in line:
            return line.strip()
    die(f"model {MODEL_ROW['model']} is not configured for the Pi CLI")
    raise AssertionError


def free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def image_id() -> str:
    result = podman("image", "inspect", "--format", "{{.Id}}", IMAGE_TAG, check=False)
    if result.returncode != 0:
        return ""
    return result.stdout.strip()


def expected_image_labels() -> dict[str, str]:
    """Return immutable build-input attestations carried by the local image.

    Podman image IDs include build timestamps, so they are useful observations but
    not reproducibility keys.  These labels bind the image to the inputs that the
    harness can reproduce and independently verify.
    """
    manifest = TARGET_LOCK["upstream"]["file_manifest"]
    manifest_digest = sha256_bytes(json.dumps(
        manifest, sort_keys=True, separators=(",", ":"),
    ).encode())
    return {
        "org.scourge.realapp.source-commit": TARGET_LOCK["upstream"]["commit"],
        "org.scourge.realapp.source-tree": TARGET_LOCK["upstream"]["tree"],
        "org.scourge.realapp.source-manifest-sha256": manifest_digest,
        "org.scourge.realapp.target-lock-sha256": sha256_file(REALAPP / "target.lock.json"),
        "org.scourge.realapp.containerfile-sha256": sha256_file(
            REALAPP / "container/Containerfile"
        ),
    }


def image_labels() -> dict[str, str]:
    result = podman("image", "inspect", IMAGE_TAG, check=False)
    if result.returncode != 0:
        return {}
    try:
        record = json.loads(result.stdout)[0]
    except (IndexError, json.JSONDecodeError, TypeError):
        die("the local target image has unreadable inspection metadata")
    labels = record.get("Labels") or record.get("Config", {}).get("Labels") or {}
    return {str(key): str(value) for key, value in labels.items()}


def verify_image_labels() -> dict[str, str]:
    observed = image_labels()
    expected = expected_image_labels()
    mismatches = {
        key: {"expected": value, "observed": observed.get(key)}
        for key, value in expected.items()
        if observed.get(key) != value
    }
    if mismatches:
        die(f"the local image is not bound to the pinned build inputs: {mismatches}")
    return {key: observed[key] for key in expected}


# ---------------------------------------------------------------------------
# target lifecycle


def stage_and_build(source_dir: Path, stage_dir: Path) -> str:
    verify_source_tree(source_dir)
    stage_dir.mkdir(parents=True)
    shutil.copytree(source_dir, stage_dir, dirs_exist_ok=True,
                    ignore=shutil.ignore_patterns(".git"))
    manifest = TARGET_LOCK["upstream"]["file_manifest"]
    for rel, expected in manifest.items():
        if sha256_file(stage_dir / rel) != expected:
            die(f"staged context file {rel} differs from the pin")
    containerfile = REALAPP / "container/Containerfile"
    if sha256_file(containerfile) != MATERIALS_LOCK["files"]["container/Containerfile"]:
        die("Containerfile does not match the frozen digest")
    shutil.copy2(containerfile, stage_dir / "Containerfile")
    digest = TARGET_LOCK["container"]["base_image_digest"]
    if digest not in containerfile.read_text():
        die("Containerfile does not pin the frozen base image digest")
    label_args = [item for key, value in expected_image_labels().items()
                  for item in ("--label", f"{key}={value}")]
    result = podman("build", "--pull=never", *label_args,
                    "-f", str(stage_dir / "Containerfile"),
                    "-t", IMAGE_TAG, str(stage_dir), timeout=900, check=False)
    (stage_dir / "build.log").write_text(result.stdout + result.stderr)
    if result.returncode != 0:
        die("image build failed; see the staged build log")
    built = image_id()
    if not built:
        die("built image is missing after a successful build")
    return built


def start_target(state_dir: Path, name: str, port: int) -> None:
    state_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(state_dir, 0o777)
    podman("run", "-d", "--rm", "--name", name, "--pull=never", "--read-only",
           "--tmpfs", "/tmp", "--pids-limit=128", "--cap-drop=all",
           "--security-opt=no-new-privileges", "--http-proxy=false",
           "-p", f"127.0.0.1:{port}:5000",
           "--mount", f"type=bind,src={state_dir},dst=/vampi/database,rw",
           IMAGE_TAG)


def wait_ready(url: str, name: str, timeout: float = 90) -> dict:
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        if not container_exists(name):
            logs = podman("logs", name, check=False).stderr[-2000:]
            raise RuntimeError(f"target container {name} exited before readiness: {logs}")
        try:
            reply = http(f"{url}/", timeout=2)
        except (urllib.error.URLError, TimeoutError, ConnectionError) as error:
            last = str(error)
            time.sleep(0.5)
            continue
        if reply["status"] == 200 and isinstance(reply["body"], dict):
            return reply
        last = reply
        time.sleep(0.5)
    raise RuntimeError(f"target did not become ready: {last}")


def stop_and_verify(name: str) -> dict:
    existed = container_exists(name)
    remove_container(name)
    return {"container": name, "existed_before_stop": existed, "absent_after_stop": not container_exists(name)}


def reset_state(pristine: Path, state_dir: Path) -> dict:
    state_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(state_dir, 0o777)
    target = state_dir / "database.db"
    shutil.copyfile(pristine, target)
    os.chmod(target, 0o666)
    return {"database_sha256": sha256_file(target), "pristine_sha256": sha256_file(pristine),
            "equal": sha256_file(target) == sha256_file(pristine)}


def referee_state(url: str) -> dict:
    home = http(f"{url}/")
    users = http(f"{url}/users/v1")
    books = http(f"{url}/books/v1")
    return {"home": home, "users": users, "books": books}


def login(url: str, username: str, password: str) -> dict:
    return http(f"{url}/users/v1/login", "POST", {"username": username, "password": password})


def token_for(url: str, username: str, password: str) -> str:
    reply = login(url, username, password)
    if reply["status"] != 200 or not isinstance(reply["body"], dict) or "auth_token" not in reply["body"]:
        raise RuntimeError(f"login failed for the referee account {username}: {reply['status']} {reply['body']}")
    return reply["body"]["auth_token"]


def seed_pristine(scratch: Path, port: int, name: str) -> dict:
    state_dir = scratch / "target/seed-database"
    if any(state_dir.glob("*")):
        die("seed state directory is not empty")
    start_target(state_dir, name, port)
    url = f"http://127.0.0.1:{port}"
    wait_ready(url, name)
    steps = []
    reply = http(f"{url}/createdb")
    steps.append({"op": "createdb", "status": reply["status"], "body": reply["body"]})
    if reply["status"] != 200:
        die("target database initializer failed")
    for username, password in ACCOUNT_LIST[3:]:
        reply = http(f"{url}/users/v1/register", "POST",
                     {"username": username, "password": password, "email": f"{username}@example.test"})
        steps.append({"op": "register", "account": username, "status": reply["status"], "body": reply["body"]})
        if reply["status"] != 200:
            die(f"could not register the test account {username}")
    before = referee_state(url)
    stop_and_verify(name)
    pristine = scratch / "target/pristine.db"
    shutil.copyfile(state_dir / "database.db", pristine)
    os.chmod(pristine, 0o444)
    return {"seeding_steps": steps, "pristine_sha256": sha256_file(pristine),
            "seeded_state": before}


def referee_proof(scratch: Path, port: int, name: str, pristine: Path) -> dict:
    state_dir = scratch / "target/proof-database"
    reset_state(pristine, state_dir)
    start_target(state_dir, name, port)
    url = f"http://127.0.0.1:{port}"
    wait_ready(url, name)
    proofs = {}
    try:
        alice = token_for(url, "alice", "alice-smoke-pw")
        bob = token_for(url, "bob", "bob-smoke-pw")
        carol = token_for(url, "carol", "carol-smoke-pw")
        proofs["identity"] = {
            "alice": http(f"{url}/me", token=alice)["body"],
            "bob": http(f"{url}/me", token=bob)["body"],
            "carol": http(f"{url}/me", token=carol)["body"],
        }
        title = f"referee-proof-{os.urandom(4).hex()}"
        secret = f"CANARY-{os.urandom(16).hex()}"
        created = http(f"{url}/books/v1", "POST", {"book_title": title, "secret": secret}, token=alice)
        owner = http(f"{url}/books/v1/{title}", token=alice)
        other = http(f"{url}/books/v1/{title}", token=bob)
        anonymous = http(f"{url}/books/v1/{title}")
        missing = http(f"{url}/books/v1/referee-missing-{os.urandom(4).hex()}", token=bob)
        proofs["read_oracle_class"] = {
            "create_status": created["status"],
            "owner_read": {"status": owner["status"], "secret_present": secret in json.dumps(owner["body"])},
            "other_read": {"status": other["status"], "secret_present": secret in json.dumps(other["body"])},
            "anonymous_read": {"status": anonymous["status"], "secret_present": secret in json.dumps(anonymous["body"])},
            "missing_read": {"status": missing["status"], "body": missing["body"]},
            "expected_finding_observed": (
                owner["status"] == 200 and other["status"] == 200
                and secret in json.dumps(other["body"]) and anonymous["status"] == 401
            ),
        }
        new_password = f"proof-{os.urandom(6).hex()}"
        changed = http(f"{url}/users/v1/alice/password", "PUT", {"password": new_password}, token=carol)
        old_login = login(url, "alice", "alice-smoke-pw")
        new_login = login(url, "alice", new_password)
        proofs["state_change_oracle_class"] = {
            "write_status": changed["status"],
            "old_credential_login_succeeds": "auth_token" in json.dumps(old_login["body"]),
            "new_credential_login_succeeds": "auth_token" in json.dumps(new_login["body"]),
            "expected_secondary_flaw_observed": (
                changed["status"] == 204
                and "auth_token" not in json.dumps(old_login["body"])
                and "auth_token" in json.dumps(new_login["body"])
            ),
        }
    finally:
        proofs["teardown"] = stop_and_verify(name)
    proofs["protocol"] = "referee-side loopback HTTP against a fresh reset of the pristine database"
    proofs["not_a_graded_run"] = True
    return proofs


# ---------------------------------------------------------------------------
# worker boundary


def host_rite_stores() -> list[Path]:
    default = Path(os.environ.get("XDG_DATA_HOME", str(Path.home() / ".local/share"))) / "rite"
    effective = Path(os.environ.get("RITE_DATA_DIR", str(default)))
    return list(dict.fromkeys([default, effective]))


def hook_free(store: Path, artifact: Path) -> dict:
    env = {"PATH": HELPER_PATH, "HOME": str(store.parent), "LANG": "C.UTF-8", "RITE_DATA_DIR": str(store)}
    result = run(["rite", "hooks", "list", "--format", "json"], env=env, timeout=10, check=False)
    artifact.write_text(result.stdout + result.stderr)
    if result.returncode != 0:
        die(f"cannot read the Rite hook inventory in {store}")
    text = result.stdout.strip()
    if not text:
        die("empty Rite hook inventory")
    try:
        document = json.loads(text)
        records = document if isinstance(document, list) else [document]
    except json.JSONDecodeError:
        records = [json.loads(line) for line in text.splitlines() if line.strip()]
    if len(records) != 1 or not isinstance(records[0].get("hooks"), list):
        die("unexpected Rite hook inventory shape")
    active = [hook for hook in records[0]["hooks"] if hook.get("active") is not False]
    if active:
        die(f"{len(active)} active Rite hooks in {store}; a trial must not fire host hooks")
    return {"store": str(store), "active_hooks": 0, "hooks": len(records[0]["hooks"])}


def live_snapshot(scratch: Path, destination: Path) -> None:
    """Reuse the M0 harness observer: shared Rite files plus visible trial processes."""
    env = {"PATH": HELPER_PATH, "HOME": os.environ.get("HOME", "/home/bob"), "LANG": "C.UTF-8"}
    stores = [str(path) for path in host_rite_stores()]
    result = subprocess.run(
        [sys.executable, "-I", str(REPO / "evals/scripts/lib/live-snapshot.py"), str(scratch), *stores],
        env=env, capture_output=True, text=True, timeout=60)
    if result.returncode != 0:
        die("live safety snapshot failed")
    destination.write_text(result.stdout)


def worker_env(home: Path, tmp: Path) -> dict:
    return {
        "HOME": str(home),
        "PATH": BASE_PATH,
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TERM": "dumb",
        "TZ": "UTC",
        "NO_COLOR": "1",
        "TMPDIR": str(tmp),
        "XDG_CONFIG_HOME": str(home / ".config"),
        "XDG_DATA_HOME": str(home / ".local/share"),
        "XDG_CACHE_HOME": str(home / ".cache"),
        "XDG_STATE_HOME": str(home / ".local/state"),
    }


def worker_argv(prompt: str) -> list[str]:
    return [
        str(pi_binary()),
        "--mode", "json",
        "--provider", MODEL_ROW["provider"],
        "--model", MODEL_ROW["model"],
        "--thinking", MODEL_ROW["thinking"],
        "--no-session",
        "--no-context-files",
        "--no-skills",
        "--no-extensions",
        "--no-mcp",
        "--no-prompt-templates",
        "--no-themes",
        "--no-approve",
        "--tools", "read,bash,edit,write",
        prompt,
    ]


# ---------------------------------------------------------------------------
# event parsing


def parse_events(path: Path) -> dict:
    events = []
    for line in path.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            events.append({"type": "unknown-line", "raw": line[:400]})
    assistant = [event["message"] for event in events
                 if event.get("type") == "message_end" and event.get("message", {}).get("role") == "assistant"]
    final = ""
    if assistant and assistant[-1].get("stopReason") == "stop":
        for block in assistant[-1].get("content", []):
            if block.get("type") == "text":
                final += block.get("text", "")
    usage_total = {"input": 0, "output": 0, "cacheRead": 0, "cacheWrite": 0, "reasoning": 0, "total": 0}
    cost_total = 0.0
    usage_available = False
    for message in assistant:
        usage = message.get("usage") or {}
        if usage:
            usage_available = True
        for key in usage_total:
            value = usage.get(key)
            if isinstance(value, (int, float)):
                usage_total[key] += value
        cost = (usage.get("cost") or {}).get("total")
        if isinstance(cost, (int, float)):
            cost_total += cost
    tool_counts: dict[str, int] = {}
    commands = []
    for event in events:
        if event.get("type") == "tool_execution_start":
            name = event.get("toolName", "?")
            tool_counts[name] = tool_counts.get(name, 0) + 1
            args = event.get("args") or {}
            if name == "bash":
                commands.append(str(args.get("command", ""))[:600])
            elif name in ("read", "write", "edit"):
                commands.append(f"{name} {args.get('path', '')}"[:600])
    system_sections = {}
    for event in events:
        if event.get("type") == "message_end" and event.get("message", {}).get("role") == "system":
            sections = event["message"].get("sections") or {}
            system_sections = {name: sha256_bytes(value.encode() if isinstance(value, str) else
                                                   json.dumps(value, sort_keys=True).encode())
                               for name, value in sections.items()}
            break
    observed_model = {}
    for message in assistant:
        observed_model = {"provider": message.get("provider"), "model": message.get("model"),
                          "api": message.get("api"), "thinkingLevel": message.get("thinkingLevel")}
    return {
        "events": len(events),
        "assistant_messages": len(assistant),
        "completed_turns": sum(1 for event in events if event.get("type") == "turn_end"),
        "final_stop_reason": assistant[-1].get("stopReason") if assistant else None,
        "final_message": final,
        "all_assistant_text": [
            "".join(block.get("text", "") for block in message.get("content", []) if block.get("type") == "text")
            for message in assistant
        ],
        "usage": usage_total,
        "usage_available": usage_available,
        "model_cost": cost_total if usage_available else None,
        "tool_calls": sum(tool_counts.values()),
        "tool_counts": tool_counts,
        "tool_commands": commands,
        "observed_model": observed_model,
        "system_prompt_section_sha256": system_sections,
    }


def contamination_audit(commands: list[str], workspace: Path | None = None,
                        scratch: Path | None = None) -> dict:
    """Look for referee paths in the worker's own tool commands.

    The worker's workspace and the session scratch prefix are normalized away: both
    contain the project name, and neither is referee material.
    """
    normalized = []
    for command in commands:
        text = command
        for prefix, label in ((workspace, "<workspace>"), (scratch, "<scratch>")):
            if prefix:
                text = text.replace(str(prefix), label)
        normalized.append(text)
    hits = [text for text in normalized if any(token in text for token in REFEREE_PATH_TOKENS)]
    return {
        "method": "v2-normalized",
        "scanned_tool_commands": len(commands),
        "normalized_prefixes": [str(path) for path in (workspace, scratch) if path],
        "tokens": list(REFEREE_PATH_TOKENS),
        "hits": len(hits),
        "examples": hits[:10],
        "limit": "same-UID host process without filesystem confinement; absence of hits is evidence, not proof",
    }


# ---------------------------------------------------------------------------
# one arm


def render_engagement(url: str, destination: Path) -> dict:
    template = (MATERIALS / "engagement.template.json").read_text()
    replacement = MATERIALS_LOCK["engagement_rendering"]["placeholder"]
    if template.count(replacement) != MATERIALS_LOCK["engagement_rendering"]["occurrences"]:
        die("engagement template placeholder count changed")
    rendered = template.replace(replacement, url)
    destination.write_text(rendered)
    return {"path": destination.name, "sha256": sha256_file(destination), "target_url": url}


def run_arm(arm: str, scratch: Path, records: Path, pristine: Path, port: int, timeout: int,
            session_id: str, frozen_assignment_sha256: str) -> dict:
    url = f"http://127.0.0.1:{port}"
    arm_dir = records / f"arm-{arm}"
    workspace = scratch / f"workspace-{arm}"
    home = scratch / f"home-{arm}"
    tmp = scratch / f"tmp-{arm}"
    rite = scratch / f"rite-{arm}"
    for directory in (arm_dir, workspace, home, tmp, rite):
        directory.mkdir(parents=True, exist_ok=False)
    os.chmod(workspace, 0o700)
    pi_config = Path(os.environ.get("HOME", "/home/bob")) / ".pi"
    (home / ".pi").symlink_to(pi_config)
    if (home / ".pi").resolve() != pi_config.resolve():
        die("worker home does not resolve the configured Pi access path")

    for name in ("task.txt", "report-template.md"):
        shutil.copyfile(MATERIALS / name, workspace / name)
    engagement = render_engagement(url, workspace / "engagement.json")
    if arm == "b":
        shutil.copyfile(MATERIALS / "condition-b/methodology.md", workspace / "methodology.md")
    visible = {path.name: sha256_file(path) for path in sorted(workspace.iterdir()) if path.is_file()}

    state_dir = scratch / f"target/state-{arm}"
    reset = reset_state(pristine, state_dir)
    if not reset["equal"]:
        die("target reset did not restore the pristine database")
    name = f"{session_id}-{arm}"
    start_target(state_dir, name, port)
    try:
        wait_ready(url, name)
        before = referee_state(url)
        write_json(arm_dir / "target-before.json", before)
        before_digest = sha256_bytes(json.dumps(before, sort_keys=True).encode())
        hook_free(rite, arm_dir / "rites-before.txt")
        live_before = arm_dir / "live-before.json"
        live_snapshot(scratch, live_before)

        prompt = (MATERIALS / "task.txt").read_text()
        argv = worker_argv(prompt)
        env = worker_env(home, tmp)
        assignment = {
            "schema_version": 1,
            "session": session_id,
            "arm": arm,
            "assigned_condition": "A" if arm == "a" else "B",
            "target": {"url": url, "port": port, "lock_sha256": sha256_file(REALAPP / "target.lock.json"),
                       "image_id": image_id(), "pristine_sha256": pristine and sha256_file(pristine)},
            "model": MODEL_ROW,
            "runner": {"binary": argv[0], "version": pi_version(Path(argv[0])), "mode": "json"},
            "visible_inputs": visible,
            "prompt_sha256": sha256_bytes(prompt.encode()),
            "budgets": {"agent_seconds": timeout},
            "argv": argv,
            "environment_keys": sorted(env),
            "environment": {key: value for key, value in env.items() if key not in ("HOME", "TMPDIR")},
            "material_lock_sha256": sha256_file(REALAPP / "materials.lock.json"),
            "frozen_assignment_sha256": frozen_assignment_sha256,
            "reset": reset,
            "engagement": engagement,
        }
        write_json(arm_dir / "assignment.json", assignment)
        write_json(arm_dir / "argv.json", {"argv": argv})
        (arm_dir / "prompt.txt").write_text(prompt)

        events_path = arm_dir / "events.jsonl"
        stderr_path = arm_dir / "stderr.log"
        started = time.time()
        timed_out = False
        with events_path.open("wb") as out, stderr_path.open("wb") as err:
            process = subprocess.Popen(argv, cwd=workspace, env=env, stdin=subprocess.DEVNULL,
                                       stdout=out, stderr=err, start_new_session=True)
            try:
                exit_code = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                with contextlib.suppress(ProcessLookupError, PermissionError):
                    os.killpg(process.pid, signal.SIGTERM)
                try:
                    exit_code = process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    with contextlib.suppress(ProcessLookupError, PermissionError):
                        os.killpg(process.pid, signal.SIGKILL)
                    exit_code = process.wait(timeout=15)
            # the worker group must not outlive its arm: terminate any children it left
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.killpg(process.pid, signal.SIGTERM)
        duration = round(time.time() - started, 3)

        hook_free(rite, arm_dir / "rites-after.txt")
        live_after = arm_dir / "live-after.json"
        live_snapshot(scratch, live_after)
        safety = {"snapshots_equal": live_before.read_bytes() == live_after.read_bytes()}
        try:
            safety["trial_processes"] = json.loads(live_after.read_text()).get("trial_processes")
        except json.JSONDecodeError:
            safety["trial_processes"] = None

        after = referee_state(url)
        write_json(arm_dir / "target-after.json", after)
    finally:
        teardown = stop_and_verify(name)

    parsed = parse_events(events_path)
    (arm_dir / "final-message.md").write_text(parsed["final_message"] + "\n")
    (arm_dir / "all-assistant-text.md").write_text(
        "\n\n---\n\n".join(parsed["all_assistant_text"]) + "\n")
    placed = {"task.txt", "report-template.md", "engagement.json", "methodology.md"}
    submitted = {}
    for path in sorted(workspace.rglob("*")):
        if path.is_file() and str(path.relative_to(workspace)) not in placed:
            relative = str(path.relative_to(workspace))
            submitted[relative] = sha256_file(path)
            destination = arm_dir / "submitted" / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, destination)
    write_json(arm_dir / "workspace-after.json",
               {"placed_inputs": visible, "other_files": submitted})

    completed = (not timed_out and exit_code == 0 and parsed["final_stop_reason"] == "stop")
    record = {
        "schema_version": 1,
        "session": session_id,
        "arm": arm,
        "assigned_condition": "A" if arm == "a" else "B",
        "status": "completed" if completed else ("timed_out" if timed_out else "failed"),
        "failed": not completed,
        "failure_reason": None if completed else
                          ("agent wall-clock budget exhausted" if timed_out else
                           f"worker exit {exit_code} stop_reason {parsed['final_stop_reason']}"),
        "rerun": False,
        "target": {"url": url, "port": port, "image_id": image_id(), "reset": reset,
                   "state_sha256_before_arm": before_digest},
        "model": MODEL_ROW,
        "observed_model": parsed["observed_model"],
        "runner": {"binary": argv[0], "version": pi_version(Path(argv[0]))},
        "visible_inputs": visible,
        "prompt_sha256": sha256_bytes(prompt.encode()),
        "budgets": {"agent_seconds": timeout},
        "timing": {"started_unix_seconds": int(started), "elapsed_seconds": duration},
        "exit_code": exit_code,
        "timed_out": timed_out,
        "tools": {"calls": parsed["tool_calls"], "counts": parsed["tool_counts"]},
        "cost": {
            "model_input_tokens": parsed["usage"]["input"],
            "model_output_tokens": parsed["usage"]["output"],
            "model_cache_read_tokens": parsed["usage"]["cacheRead"],
            "model_cache_write_tokens": parsed["usage"]["cacheWrite"],
            "model_reasoning_tokens": parsed["usage"]["reasoning"],
            "model_total_tokens": parsed["usage"]["total"],
            "model_usd": parsed["model_cost"],
            "usage_available": parsed["usage_available"],
            "accounting_source": "Pi JSON event stream message_end usage, summed over assistant messages",
            "target_requests": "not counted server-side; the target publishes no access log",
        },
        "safety": {"live_snapshots_equal": safety["snapshots_equal"],
                   "trial_processes_after": safety["trial_processes"],
                   "host_hooks_active": 0},
        "teardown": teardown,
        "transcript": {"path": f"arm-{arm}/events.jsonl", "sha256": sha256_file(events_path),
                       "stderr_sha256": sha256_file(stderr_path),
                       "events": parsed["events"],
                       "system_prompt_section_sha256": parsed["system_prompt_section_sha256"]},
        "submitted": {"final_message_path": f"arm-{arm}/final-message.md",
                      "files": submitted},
        "contamination_audit": contamination_audit(parsed["tool_commands"], workspace, scratch),
    }
    write_json(arm_dir / "run.json", record)
    return record


# ---------------------------------------------------------------------------
# session and preflight


def freeze(args) -> dict:
    binary = pi_binary()
    verify_materials()
    row = model_available(binary)
    containerfile = REALAPP / "container/Containerfile"
    if TARGET_LOCK["container"]["base_image_digest"] not in containerfile.read_text():
        die("Containerfile does not pin the recorded base image digest")
    built = image_id()
    if not built:
        die("the pinned image is not built; run `build --source-dir DIR` before `freeze`")
    labels = verify_image_labels()
    assignment = {
        "schema_version": 1,
        "kind": "real-application-smoke-frozen-assignment",
        "frozen_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "status": "frozen before the first assigned arm run",
        "scored": False,
        "gating": False,
        "decision_use": "none; this session is unscored, training-contaminated and excluded from every rate and gate",
        "target": {
            "lock": "evals/realapp/target.lock.json",
            "lock_sha256": sha256_file(REALAPP / "target.lock.json"),
            "name": TARGET_LOCK["upstream"]["name"],
            "url": TARGET_LOCK["upstream"]["url"],
            "commit": TARGET_LOCK["upstream"]["commit"],
            "tree": TARGET_LOCK["upstream"]["tree"],
            "environment": TARGET_LOCK["runtime"]["environment"],
            "image": TARGET_LOCK["container"]["built_reference"],
            "image_id": built,
            "build_input_labels": labels,
            "base_image_digest": TARGET_LOCK["container"]["base_image_digest"],
            "listener": TARGET_LOCK["container"]["listener"],
        },
        "instrument": MATERIALS_LOCK["instrument"],
        "model": {**MODEL_ROW, "runner": "Pi CLI", "runner_version": pi_version(binary),
                  "listed": row},
        "budgets": {"agent_seconds": 900, "target_requests": None, "model_usd": None,
                    "note": "one fresh worker process per arm, no retry; a diagnostic rerun would be a new labelled trial"},
        "arms": {
            "A": {"additional_inputs": []},
            "B": {"additional_inputs": ["materials/condition-b/methodology.md"]},
        },
        "visible_inputs": MATERIALS_LOCK["visible_inputs"],
        "materials_lock_sha256": sha256_file(REALAPP / "materials.lock.json"),
        "withheld_from_both_arms": MATERIALS_LOCK["withheld_from_both_arms"],
        "parity": {
            "target": "both arms run against the same port and image, each from a fresh copy of the same pristine database",
            "instrument": "none for both arms",
            "model": "same provider, model id, thinking level, tool allowlist and budgets; all non-cwd system sections are byte-identical",
            "wrapper": "same Pi CLI version, same argv shape, same environment allowlist, same runner-installed defaults",
            "only_assigned_content_difference": "condition B may read materials/condition-b/methodology.md; run-private cwd paths differ by arm",
        },
        "hint_parity": MATERIALS_LOCK["hint_parity"],
        "order": ["A", "B"],
    }
    write_json(FROZEN_ASSIGNMENT, assignment)
    print(json.dumps(assignment, indent=2))
    return assignment


def preflight(args, frozen: dict | None = None) -> dict:
    verify_materials()
    if frozen is None:
        _, frozen, _ = load_frozen_assignment()
    if frozen["target"]["lock_sha256"] != sha256_file(REALAPP / "target.lock.json"):
        die("target lock changed after the assignment was frozen")
    if frozen["materials_lock_sha256"] != sha256_file(REALAPP / "materials.lock.json"):
        die("materials lock changed after the assignment was frozen")
    rootless = podman("info", "--format", "{{.Host.Security.Rootless}}").stdout.strip()
    if rootless != "true":
        die("rootless Podman is required")
    source = verify_source_tree(Path(args.source_dir))
    binary = pi_binary()
    version = pi_version(binary)
    if version != frozen["model"]["runner_version"]:
        die(f"Pi CLI version {version} differs from the frozen {frozen['model']['runner_version']}")
    row = model_available(binary)
    built = image_id()
    if not built:
        die("the pinned image is not built; run `build --source-dir DIR` first")
    labels = verify_image_labels()
    result = {
        "materials": "verified",
        "source": source,
        "pi": {"binary": str(binary), "version": version},
        "model": row,
        "image": {"reference": IMAGE_TAG, "present": True, "id": built,
                  "build_input_labels": labels,
                  "base_image_digest": TARGET_LOCK["container"]["base_image_digest"]},
        "rootless_podman": True,
        "loopback_port": free_loopback_port(),
        "frozen_assignment": str(FROZEN_ASSIGNMENT),
    }
    print(json.dumps(result, indent=2))
    return result


def session(args) -> dict:
    requested_arms = [arm.strip() for arm in (args.arms or "").split(",") if arm.strip()]
    if requested_arms != ["a", "b"]:
        die("a committed smoke session requires exactly `--arms a,b`; use `rehearse` for no-model diagnostics")
    frozen_payload, frozen, frozen_sha256 = load_frozen_assignment()
    pre = preflight(args, frozen)
    if not pre["image"]["present"]:
        die("the pinned image is not built; run `build --source-dir DIR` first")
    session_id = args.session_id or f"m0.4.3-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}"
    if not re.fullmatch(r"[a-z0-9.]+-[0-9]{8}T[0-9]{6}Z", session_id):
        die("session id must look like m0.4.3-YYYYmmddTHHMMSSZ")
    records = REALAPP / "smoke" / session_id
    if records.exists():
        die(f"session directory {records} already exists; sessions are never reused")
    scratch = SCRATCH_BASE / session_id
    if scratch.exists():
        die(f"scratch directory {scratch} already exists; sessions are never reused")
    records.mkdir(parents=True)
    scratch.mkdir(parents=True)
    frozen_record = snapshot_frozen_assignment(records, frozen_payload)
    port = free_loopback_port()
    url = f"http://127.0.0.1:{port}"
    timeline = []

    def step(name: str, detail=None):
        timeline.append({"at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "step": name,
                         "detail": detail})
        print(f"[{name}] {detail if detail is not None else ''}", file=sys.stderr)

    write_json(records / "preflight.json", pre)
    step("session_start", {"session": session_id, "port": port})
    seeded = seed_pristine(scratch, port, f"{session_id}-seed")
    step("seeded", {"pristine_sha256": seeded["pristine_sha256"]})
    write_json(records / "referee/seeding.json", seeded)
    proof = referee_proof(scratch, port, f"{session_id}-proof", scratch / "target/pristine.db")
    write_json(records / "referee/seed-proof.json", proof)
    step("target_proof", {"read_flaw": proof["read_oracle_class"]["expected_finding_observed"],
                          "write_flaw": proof["state_change_oracle_class"]["expected_secondary_flaw_observed"]})
    if not proof["read_oracle_class"]["expected_finding_observed"]:
        die("the pinned target did not exhibit the documented private-object read behaviour")
    write_json(records / "referee/expected.json", {
        "schema_version": 1,
        "target": TARGET_LOCK["upstream"]["name"],
        "referee_only": True,
        "not_visible_to_arms": True,
        "expected_finding": {
            "class": TARGET_LOCK["documents_flaw"]["class"],
            "resource": "books",
            "operation": "read",
            "rule_violated": "a book's declared readers are its owner; another authenticated account can read the secret field",
            "oracle": TARGET_LOCK["documents_flaw"]["oracle_class"],
        },
        "additionally_present": TARGET_LOCK["documents_flaw"]["secondary_upstream_flaw"],
        "grading": "none; the smoke records what each arm submitted and what supported it",
    })
    rendered_path = records / "rendered/engagement.json"
    rendered_path.parent.mkdir(parents=True)
    rendered = render_engagement(url, rendered_path)
    step("engagement_rendered", {"sha256": rendered["sha256"]})

    arms = requested_arms
    results = []
    for arm in arms:
        step(f"arm_{arm}_start")
        record = run_arm(arm, scratch, records, scratch / "target/pristine.db", port,
                         args.timeout, session_id, frozen_sha256)
        results.append(record)
        step(f"arm_{arm}_end", {"status": record["status"], "exit_code": record["exit_code"],
                                "elapsed_seconds": record["timing"]["elapsed_seconds"],
                                "tool_calls": record["tools"]["calls"],
                                "container_absent": record["teardown"]["absent_after_stop"]})
    leftovers = [name for name in (f"{session_id}-seed", f"{session_id}-proof",
                                   *(f"{session_id}-{arm}" for arm in arms)) if container_exists(name)]
    evidence = {
        "schema_version": 1,
        "kind": "real-application-smoke-session",
        "session": session_id,
        "scored": False,
        "gating": False,
        "status": "complete" if arms == ["a", "b"] and len(results) == 2
        and all(not record["failed"] for record in results) else "incomplete",
        "claim": "unscored, training-contaminated, non-gating real-target smoke; no rate and no comparison is inferred",
        "target": {"lock_sha256": sha256_file(REALAPP / "target.lock.json"),
                   "url": url, "port": port, "image_id": image_id(),
                   "pristine_sha256": seeded["pristine_sha256"]},
        "model": frozen["model"],
        "frozen_assignment": frozen_record,
        "frozen_assignment_sha256": frozen_sha256,
        "materials_lock_sha256": frozen["materials_lock_sha256"],
        "rendered_engagement": rendered,
        "arm_order": arms,
        "arms": {record["arm"]: {"status": record["status"], "failed": record["failed"],
                                 "failure_reason": record["failure_reason"],
                                 "elapsed_seconds": record["timing"]["elapsed_seconds"],
                                 "tools": record["tools"]["calls"],
                                 "input_tokens": record["cost"]["model_input_tokens"],
                                 "output_tokens": record["cost"]["model_output_tokens"],
                                 "model_usd": record["cost"]["model_usd"],
                                 "rerun": record["rerun"]} for record in results},
        "resets": {record["arm"]: record["target"]["reset"] for record in results},
        "reset_parity": {
            "state_sha256": {record["arm"]: record["target"]["state_sha256_before_arm"] for record in results},
            "equal": len({record["target"]["state_sha256_before_arm"] for record in results}) <= 1,
        },
        "teardown": {"containers_absent": not leftovers, "checked": [f"{session_id}-{arm}" for arm in arms]
                     + [f"{session_id}-seed", f"{session_id}-proof"], "leftovers": leftovers},
        "scratch": str(scratch),
        "timeline": timeline,
    }
    write_json(records / "session.json", evidence)
    if leftovers:
        die(f"containers survived teardown: {leftovers}")
    print(json.dumps({"session": session_id, "records": str(records), "status": evidence["status"]}, indent=2))
    return evidence


def rehearse(args) -> dict:
    """Exercise seed, target proof, reset replay and teardown without a model call."""
    frozen = json.loads(FROZEN_ASSIGNMENT.read_text())
    pre = preflight(args)
    if not pre["image"]["present"]:
        die("the pinned image is not built; run `build --source-dir DIR` first")
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    scratch = SCRATCH_BASE / f"rehearsal-{stamp}"
    scratch.mkdir(parents=True)
    port = free_loopback_port()
    url = f"http://127.0.0.1:{port}"
    seeded = seed_pristine(scratch, port, f"rehearsal-{stamp}-seed")
    pristine = scratch / "target/pristine.db"
    proof = referee_proof(scratch, port, f"rehearsal-{stamp}-proof", pristine)
    replays = []
    for index in (1, 2):
        state_dir = scratch / f"target/replay-{index}"
        reset = reset_state(pristine, state_dir)
        name = f"rehearsal-{stamp}-replay-{index}"
        start_target(state_dir, name, port)
        try:
            ready = wait_ready(url, name)
            state = referee_state(url)
            replays.append({"index": index, "reset": reset, "ready": ready, "state": state,
                            "state_sha256": sha256_bytes(json.dumps(state, sort_keys=True).encode())})
        finally:
            replays[-1]["teardown"] = stop_and_verify(name)
    leftovers = [name for name in podman("ps", "-a", "--format", "{{.Names}}", check=False).stdout.split()
                 if name.startswith(f"rehearsal-{stamp}")]
    evidence = {
        "schema_version": 1,
        "kind": "real-application-smoke-rehearsal",
        "scored": False,
        "not_an_assigned_arm": True,
        "model_calls": 0,
        "rehearsal": stamp,
        "port": port,
        "preflight": pre,
        "frozen_assignment_sha256": sha256_file(FROZEN_ASSIGNMENT),
        "seeding": {key: value for key, value in seeded.items() if key != "seeded_state"},
        "seed_state_sha256": sha256_bytes(json.dumps(seeded["seeded_state"], sort_keys=True).encode()),
        "proof": proof,
        "replay_state_equal": len({replay["state_sha256"] for replay in replays}) == 1,
        "replays": replays,
        "containers_absent": not leftovers,
        "leftovers": leftovers,
    }
    write_json(scratch / "rehearsal.json", evidence)
    print(json.dumps({"rehearsal": stamp, "evidence": str(scratch / "rehearsal.json"),
                      "replay_state_equal": evidence["replay_state_equal"],
                      "containers_absent": evidence["containers_absent"],
                      "read_flaw_proven": proof["read_oracle_class"]["expected_finding_observed"],
                      "write_flaw_proven": proof["state_change_oracle_class"]["expected_secondary_flaw_observed"],
                      "frozen_assignment": frozen["frozen_at"]}, indent=2))
    if leftovers:
        die(f"containers survived the rehearsal: {leftovers}")
    return evidence


def reaudit(args) -> dict:
    """Recompute only the contamination audit of a committed session from its transcripts.

    The raw event transcripts and their hashes are not touched. This exists because the
    first audit token set matched the worker's own workspace path string, which produced
    false positives; the corrected audit normalizes the worker's prefixes.
    """
    session_dir = REALAPP / "smoke" / args.session
    session = json.loads((session_dir / "session.json").read_text())
    scratch = Path(session["scratch"])
    updated = {}
    for arm in session.get("arms", {}):
        arm_dir = session_dir / f"arm-{arm}"
        record = json.loads((arm_dir / "run.json").read_text())
        parsed = parse_events(arm_dir / "events.jsonl")
        if sha256_file(arm_dir / "events.jsonl") != record["transcript"]["sha256"]:
            die(f"arm-{arm}: transcript changed since the run; refusing to re-audit")
        previous = record.get("contamination_audit")
        record["contamination_audit"] = contamination_audit(parsed["tool_commands"],
                                                            scratch / f"workspace-{arm}", scratch)
        record["contamination_audit"]["recomputed_from_transcript"] = True
        if previous and previous != record["contamination_audit"]:
            record["contamination_audit"]["superseded_audit"] = previous
        write_json(arm_dir / "run.json", record)
        updated[arm] = record["contamination_audit"]["hits"]
    print(json.dumps({"session": args.session, "hits": updated}, indent=2))
    return updated


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    f = sub.add_parser("freeze", help="write the frozen A/B assignment")
    f.set_defaults(func=freeze)
    b = sub.add_parser("build", help="stage the pinned source and build the loopback image")
    b.add_argument("--source-dir", required=True)
    b.set_defaults(func=lambda args: stage_and_build(
        Path(args.source_dir).resolve(),
        SCRATCH_BASE / f"build-context-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}"))
    p = sub.add_parser("preflight", help="verify pins, materials, image and model without running a trial")
    p.add_argument("--source-dir", required=True)
    p.set_defaults(func=preflight)
    a = sub.add_parser("reaudit", help="recompute a session's contamination audit from its transcripts")
    a.add_argument("--session", required=True)
    a.set_defaults(func=reaudit)
    r = sub.add_parser("rehearse", help="seed, prove, replay the reset and tear down without a model call")
    r.add_argument("--source-dir", required=True)
    r.set_defaults(func=rehearse)
    s = sub.add_parser("session", help="seed, prove, run both arms and tear down")
    s.add_argument("--source-dir", required=True)
    s.add_argument("--session-id", default=None)
    s.add_argument("--arms", default="a,b",
                   help="must be exactly a,b for a committed session; use rehearse for diagnostics")
    s.add_argument("--timeout", type=int, default=900)
    s.set_defaults(func=session)
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
