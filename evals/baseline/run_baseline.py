#!/usr/bin/env python3
"""M0.4 baseline runner: condition A/B on the development fixture.

This runner only orchestrates the frozen experiment. It does not decide the
M0 question and it does not adjudicate claims: the decision rule lives in
../m0-decision-rule.md and the failure taxonomy belongs to M0.4.4.

Every session is a fresh Pi process inside the documented rootless worker
boundary (rootless Podman, --network=none, read-only rootfs, all capabilities
dropped, no host loopback). The worker reaches exactly two referee-owned Unix
socket relays: the pinned Teapot proxy listener and a raw CONNECT tunnel to the
pinned model API. The target, ground truth, admin secret, referee receipts and
grading code stay on the host.

Subcommands:
  schedule   write a seeded randomized A/B schedule (refuses to overwrite)
  preflight  verify every pin, build the fixture package and tool bundle
  pilot      one labelled, unscored session used to validate the runner
  run        execute the committed schedule, appending every run to the ledger
  verify     check ledger completeness, cleanup and leak invariants
"""

import argparse
import asyncio
import gzip
import hashlib
import json
import os
from pathlib import Path
import random
import re
import secrets
import shutil
import signal
import subprocess
import sys
import time

sys.dont_write_bytecode = True

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
M0 = ROOT / "evals/m0-baseline"
WORKER = HERE / "worker"
LOCK_PATH = M0 / "materials.lock.json"
MANIFEST_PATH = M0 / "qualification/evidence/manifest.json"
SCHEMAS = M0 / "qualification/evidence/schemas"
SCHEDULE_PATH = HERE / "schedule.json"
LEDGER_PATH = HERE / "evidence/ledger.jsonl"
BASELINE_DIR = HERE / "evidence"
APPROVAL_SOURCE = ROOT / "fixtures/target/example/passes/staging.toml"
COMMON = M0 / "common"
CONDITION_B = M0 / "condition-b/methodology.md"

sys.path.insert(0, str(HERE))
import evidence_paths as ep  # noqa: E402

MODEL_PROVIDER = "orcacyber"
MODEL_ID = "orca/orcacyber-flash-1.0"
MODEL_API = "https://api.orcarouter.ai/v1"
THINKING = "high"
TOOLS = ["bash"]
WALL_SECONDS = 900
MIN_PER_ARM = 5
DEFAULT_RUNS = 10
IMAGE = "docker.io/library/debian:13-slim"
SCORE_AMENDMENT_TYPE = "score_amendment"
SCORE_AMENDMENT_SCHEMA = 1
SCORE_AMENDMENT_OPERATION = "add_missing_score"
SCORE_AMENDMENT_HASH_SCOPE = "exact UTF-8 JSONL record including trailing LF"

INVENTORY_COMMANDS = {
    "version": ("version",),
    "projects_list": ("projects", "list"),
    "projects_show": ("projects", "show"),
    "proxy_status": ("proxy", "status"),
    "pass_show": ("pass", "show"),
    "scope_list": ("scope", "list"),
    "hosts_list": ("hosts", "list"),
    "flows_list": ("flows", "list"),
    "findings_list": ("findings", "list"),
    "leads_list": ("leads", "list"),
    "sessions_list": ("sessions", "list"),
    "rules_list": ("rules", "list"),
    "intercept_status": ("intercept", "status"),
    "intercept_rules_list": ("intercept", "rules", "list"),
    "intercept_queue_list": ("intercept", "queue", "list"),
    "scripts_list": ("scripts", "list"),
    "scripts_approvals": ("scripts", "approvals"),
    "config_list": ("config", "list"),
    "macros_list": ("macros", "list"),
    "jobs_list": ("jobs", "list"),
    "sitemap_show": ("sitemap", "show"),
    "authz_matrix": ("authz", "matrix"),
    "checks_list": ("checks", "list"),
    "commands_list": ("commands", "list"),
}


class Blocked(Exception):
    """A scored run cannot be attempted; record it, never replace it."""


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(path)


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def read_json_regular(path):
    """Read JSON from evidence with the no-follow, nlink==1 guard."""
    return json.loads(ep.read_regular_nofollow(path).decode("utf-8"))


def run(argv, *, env=None, cwd=None, timeout=60, check=True):
    completed = subprocess.run(
        [str(part) for part in argv],
        capture_output=True,
        text=True,
        env=env,
        cwd=cwd,
        timeout=timeout,
        check=False,
    )
    if check and completed.returncode:
        raise Blocked(
            f"command failed ({completed.returncode}): {' '.join(str(x) for x in argv[:4])}: "
            f"{completed.stderr.strip()[:2000]}"
        )
    return completed


def lock():
    return read_json(LOCK_PATH)


def expected_digest():
    manifest = read_json(MANIFEST_PATH)
    value = manifest["attestation"]["semantic_projection_sha256"]
    if not value:
        raise Blocked("qualification manifest has no semantic projection digest")
    return value


def pinned_teapot(path):
    path = Path(path).resolve()
    if not path.is_file():
        raise Blocked(f"pinned Teapot binary is absent: {path}")
    if sha256_file(path) != lock()["teapot"]["binary_sha256"]:
        raise Blocked("Teapot binary does not match materials.lock.json")
    version = run([path, "--version"], timeout=10).stdout.strip()
    if version != lock()["teapot"]["version_stdout"]:
        raise Blocked(f"unexpected Teapot version: {version!r}")
    return path


def preflight_materials():
    result = subprocess.run(
        [sys.executable, "-B", str(M0 / "check-materials.py")],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    if result.returncode:
        raise Blocked(f"materials check failed: {result.stderr.strip()}")
    return result.stdout.strip()


def clean_env(run_root):
    paths = {
        "HOME": run_root / "home",
        "XDG_CONFIG_HOME": run_root / "config",
        "XDG_STATE_HOME": run_root / "state",
        "XDG_DATA_HOME": run_root / "data",
        "XDG_RUNTIME_DIR": run_root / "run",
    }
    for path in paths.values():
        path.mkdir(mode=0o700, exist_ok=True)
    return paths, {
        "PATH": "/usr/bin:/bin",
        "NO_COLOR": "1",
        "TERM": "dumb",
        **{name: str(path) for name, path in paths.items()},
    }


def teapot_json(teapot, project, env, words, rows=None, label=None, timeout=60):
    argv = [teapot, "--project", project, "--json", *words]
    completed = run(argv, env=env, timeout=timeout, check=False)
    if rows is not None:
        rows.append(
            {
                "label": label or " ".join(words),
                "argv": [str(part) for part in argv],
                "exit": completed.returncode,
                "stdout_sha256": sha256_bytes(completed.stdout.encode()),
                "stderr": completed.stderr,
            }
        )
    if completed.returncode:
        raise Blocked(f"teapot {' '.join(words)} failed: {completed.stderr.strip()[:1000]}")
    return json.loads(completed.stdout)


def setup_project(teapot, run_root, rows):
    project = run_root / "workspace"
    project.mkdir(mode=0o700, exist_ok=True)
    approval = run_root / "approval/staging.toml"
    approval.parent.mkdir(mode=0o700, exist_ok=True)
    shutil.copyfile(APPROVAL_SOURCE, approval)
    approval.chmod(0o600)
    _, env = clean_env(run_root)
    teapot_json(teapot, project, env, ("projects", "init"), rows, "setup: projects init")
    teapot_json(teapot, project, env, ("pass", "attach", str(approval)), rows, "setup: pass attach")
    teapot_json(teapot, project, env, ("scope", "add", "127.0.0.1"), rows, "setup: scope add")
    teapot_json(
        teapot,
        project,
        env,
        (
            "proxy",
            "start",
            "--listen",
            "127.0.0.1:0",
            "--detach",
            "--pass",
            str(approval),
            "--no-enforce",
        ),
        rows,
        "setup: proxy start",
    )
    return project, approval, env


def capture_inventory(teapot, project, env, rows, artifacts):
    sys.path.insert(0, str(M0))
    import project_inventory

    raw = {}
    for name, words in INVENTORY_COMMANDS.items():
        raw[name] = teapot_json(teapot, project, env, words, rows, f"capture: {' '.join(words)}")
    projection, digest = project_inventory.project_inventory(raw, SCHEMAS)
    write_json(artifacts / "raw-inventory.json", raw)
    write_json(
        artifacts / "projected.json",
        {
            "schema_version": project_inventory.SCHEMA_VERSION,
            "sha256": digest,
            "projection": projection,
        },
    )
    return raw, projection, digest


def freeze_visible_inputs(workspace, arm, artifacts):
    """Write the frozen common inputs, then add the one assigned B file."""
    files = {}
    for name in ("task.txt", "engagement.json", "report-template.md"):
        source = COMMON / name
        target = workspace / name
        shutil.copyfile(source, target)
        target.chmod(0o644)
        files[name] = sha256_file(source)
    if arm == "B":
        target = workspace / "condition-b/methodology.md"
        target.parent.mkdir(mode=0o755, exist_ok=True)
        shutil.copyfile(CONDITION_B, target)
        target.chmod(0o644)
        files["condition-b/methodology.md"] = sha256_file(CONDITION_B)
    visible = {
        "arm": arm,
        "files": files,
        "instrument_store": ".teapot (Teapot project store; parity governed by projected.json)",
        "workspace_entries": sorted(
            entry.name for entry in workspace.iterdir() if entry.name != ".teapot"
        ),
    }
    write_json(artifacts / "visible-inputs.json", visible)
    return visible


def build_tool_bundle(base):
    """Assemble host binaries for the worker. No credential is copied."""
    tools = base / "_tools"
    if (tools / "READY").is_file():
        return tools
    tools.mkdir(parents=True, exist_ok=True)
    glibc = tools / "glibc"
    lib = tools / "lib"
    glibc.mkdir(exist_ok=True)
    lib.mkdir(exist_ok=True)
    copies = {
        "/usr/lib/libc.so.6": glibc,
        "/usr/lib/libm.so.6": glibc,
        "/usr/lib/libpthread.so.0": glibc,
        "/usr/lib/libdl.so.2": glibc,
        "/usr/lib/librt.so.1": glibc,
        "/usr/lib/libgcc_s.so.1": glibc,
        "/usr/lib/libstdc++.so.6": glibc,
        "/usr/lib/libresolv.so.2": glibc,
        "/usr/lib64/ld-linux-x86-64.so.2": glibc,
    }
    for source, target in copies.items():
        if not Path(source).is_file():
            raise Blocked(f"host library missing for the worker bundle: {source}")
        shutil.copy2(source, target / Path(source).name)
    binaries = ["/usr/bin/curl", "/usr/bin/jq"]
    for source in binaries:
        shutil.copy2(source, lib / Path(source).name)
    deps = run(["ldd", *binaries], timeout=30).stdout
    skip = {"libc.so.6", "ld-linux-x86-64.so.2", "libm.so.6", "libdl.so.2", "libpthread.so.0", "librt.so.1"}
    for line in deps.splitlines():
        if "=>" not in line:
            continue
        path = line.split("=>", 1)[1].strip().split(" ")[0]
        if not path or not Path(path).is_file():
            continue
        if Path(path).name in skip:
            continue
        target = lib / Path(path).name
        if not target.exists():
            shutil.copy2(path, target)
    (tools / "READY").write_text("ok\n", encoding="ascii")
    return tools


def build_fixture_package(base):
    package = base / "_fixture/package"
    if (package / "scourge-fixture").is_file():
        return package
    sys.path.insert(0, str(ROOT / "fixtures/target"))
    import package as package_module

    package.parent.mkdir(parents=True, exist_ok=True)
    registry = Path(os.environ.get("CARGO_HOME", Path.home() / ".cargo")) / "registry"
    if not registry.is_dir():
        raise Blocked("offline Cargo registry cache unavailable")
    cargo_home = base / "_fixture/cargo"
    cargo_home.mkdir(parents=True, exist_ok=True)
    link = cargo_home / "registry"
    if not link.exists():
        link.symlink_to(registry.resolve())
    env = os.environ.copy()
    env.update(
        {
            "CARGO_HOME": str(cargo_home),
            "CARGO_NET_OFFLINE": "true",
            "CARGO_BUILD_JOBS": "2",
        }
    )
    old = os.environ.copy()
    os.environ.update(env)
    try:
        package_module.build_package(package)
    finally:
        os.environ.clear()
        os.environ.update(old)
    if not (package / "scourge-fixture").is_file():
        raise Blocked("fixture package build produced no binary")
    return package


def start_fixture(package, artifacts, port=3000):
    import socket

    if not (1 <= port <= 65535):
        raise Blocked("invalid fixture port")
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        probe.bind(("127.0.0.1", port))
    except OSError as error:
        raise Blocked(f"fixture port {port} is not free: {error}") from error
    finally:
        probe.close()
    binary = package / "scourge-fixture"
    stdout = open(artifacts / "fixture.stdout", "wb")
    stderr = open(artifacts / "fixture.stderr", "wb")
    env = {"PATH": "/usr/bin:/bin", "NO_COLOR": "1", "TERM": "dumb"}
    proc = subprocess.Popen(
        [str(binary), "--listen", f"127.0.0.1:{port}", "--admin-secret-file", "admin-secret"],
        cwd=package,
        stdout=stdout,
        stderr=stderr,
        env=env,
        start_new_session=True,
    )
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise Blocked("fixture exited before it listened")
        probe = subprocess.run(
            [
                "curl",
                "-q",
                "--silent",
                "--show-error",
                "--noproxy",
                "*",
                "--proto",
                "=http",
                "--max-time",
                "2",
                "--output",
                "/dev/null",
                "--write-out",
                "%{http_code}",
                f"http://127.0.0.1:{port}/",
            ],
            capture_output=True,
            text=True,
        )
        if probe.stdout.strip().isdigit():
            return proc, port
        time.sleep(0.2)
    stop_process(proc)
    raise Blocked("fixture did not answer on its loopback port")


def stop_process(proc, grace=10):
    if proc is None or proc.poll() is not None:
        return True
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        return True
    try:
        proc.wait(timeout=grace)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait(timeout=grace)
    return proc.poll() is not None


def referee_observe(package, port, artifacts):
    referee = ROOT / "fixtures/target/referee"
    completed = run(
        [sys.executable, "-B", "observe.py", str(port), str(package)],
        cwd=referee,
        timeout=120,
        check=False,
        env={"PATH": "/usr/bin:/bin", "NO_COLOR": "1", "TERM": "dumb"},
    )
    if completed.returncode:
        raise Blocked(f"referee fixture receipt failed: {completed.stderr.strip()[:2000]}")
    receipt = json.loads(completed.stdout)
    write_json(artifacts / "live-state.json", receipt)
    return receipt


def start_relay(script, socket_path, *args):
    socket_path.parent.mkdir(parents=True, exist_ok=True)
    log = open(socket_path.parent / f"{socket_path.stem}.log", "wb")
    proc = subprocess.Popen(
        [sys.executable, "-B", str(script), str(socket_path), *map(str, args)],
        stdout=log,
        stderr=log,
        start_new_session=True,
    )
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise Blocked(f"relay {socket_path.name} exited early")
        if socket_path.exists():
            return proc
        time.sleep(0.05)
    stop_process(proc)
    raise Blocked(f"relay {socket_path.name} did not create its socket")


def podman_image():
    completed = run(["podman", "--remote=false", "image", "inspect", "--format", "{{.Id}}", IMAGE], timeout=30)
    image_id = completed.stdout.strip()
    if len(image_id) != 64 or any(c not in "0123456789abcdef" for c in image_id):
        raise Blocked("invalid local worker image identity")
    return image_id


def podman_rootless():
    completed = run(
        ["podman", "--remote=false", "info", "--format", "{{.Host.Security.Rootless}}"],
        timeout=30,
    )
    if completed.stdout.strip() != "true":
        raise Blocked("rootless Podman is required")


def container_argv(run_root, project, approval, tools, teapot, image_id, proxy_port, cidfile, name):
    pi_cli = Path(os.path.realpath(shutil.which("pi") or ""))
    if not pi_cli.is_file():
        raise Blocked("the configured Pi CLI is not on PATH")
    pi_pkg = pi_cli.parents[2]
    node_dir = Path(
        run(["node", "-e", "console.log(require('path').dirname(process.execPath))"], timeout=30).stdout.strip()
    ).parent
    auth = Path.home() / ".pi/agent/auth.json"
    if not auth.is_file():
        raise Blocked(f"configured Pi credential file is absent: {auth}")
    mounts = [
        ("src", str(tools / "glibc"), "/opt/glibc", True),
        ("src", str(tools / "lib"), "/opt/worker/lib", True),
        ("src", str(node_dir), "/opt/node", True),
        ("src", str(pi_pkg), "/opt/pi", True),
        ("src", str(teapot), "/opt/worker/teapot", True),
        ("src", str(WORKER), "/opt/adapter", True),
        ("src", str(run_root / "gateway"), "/gateway", True),
        ("src", str(run_root / "workspace"), "/workspace", False),
        ("src", str(run_root / "pi-agent"), "/pi-agent", False),
        ("src", str(auth), "/pi-agent/auth.json", True),
        ("src", str(run_root / "home"), str(run_root / "home"), False),
        ("src", str(run_root / "config"), str(run_root / "config"), False),
        ("src", str(run_root / "state"), str(run_root / "state"), False),
        ("src", str(run_root / "data"), str(run_root / "data"), False),
        ("src", str(run_root / "run"), str(run_root / "run"), False),
        ("src", str(approval), str(approval), True),
        ("src", "/etc/ssl/certs/ca-certificates.crt", "/etc/ssl/certs/ca-certificates.crt", True),
    ]
    argv = [
        "podman",
        "--remote=false",
        "run",
        "--pull=never",
        "--network=none",
        "--read-only",
        "--http-proxy=false",
        "--cap-drop=all",
        "--security-opt=no-new-privileges",
        "--pids-limit=256",
        "--name",
        name,
        "--cidfile",
        str(cidfile),
        "--tmpfs",
        "/tmp:rw,size=256m",
    ]
    for _, source, target, readonly in mounts:
        spec = f"type=bind,src={source},dst={target}"
        if readonly:
            spec += ",ro=true"
        argv += ["--mount", spec]
    env = {
        "HOME": str(run_root / "home"),
        "XDG_CONFIG_HOME": str(run_root / "config"),
        "XDG_STATE_HOME": str(run_root / "state"),
        "XDG_DATA_HOME": str(run_root / "data"),
        "XDG_RUNTIME_DIR": str(run_root / "run"),
        "M0_PROXY_PORT": str(proxy_port),
        "HTTPS_PROXY": "http://127.0.0.1:18080",
        "HTTP_PROXY": "",
        "NO_PROXY": "",
        "PI_CODING_AGENT_DIR": "/pi-agent",
        "PI_OFFLINE": "1",
        "PI_SKIP_VERSION_CHECK": "1",
        "PI_TELEMETRY": "0",
        "NO_COLOR": "1",
        "TERM": "dumb",
    }
    for key, value in env.items():
        argv += ["-e", f"{key}={value}"]
    argv += ["--entrypoint", "/bin/bash", image_id, "/opt/adapter/entry.sh"]
    return argv


def start_model_relay(run_root):
    return start_relay(WORKER / "model-relay.py", run_root / "gateway/model.sock")


def start_proxy_relay(run_root, proxy_port):
    return start_relay(WORKER / "tcp-relay.py", run_root / "gateway/proxy.sock", proxy_port)


def proxy_listener(teapot, project, env):
    status = teapot_json(teapot, project, env, ("proxy", "status"))
    engine = status["proxy"]["engine"]
    listener = engine.get("listener") or ""
    match = re.fullmatch(r"127\.0\.0\.1:(\d+)", listener)
    if not match:
        raise Blocked(f"unexpected Teapot proxy listener: {listener!r}")
    return int(match.group(1))


def assistant_messages(events):
    out = []
    for event in events:
        if event.get("type") == "message_end" and isinstance(event.get("message"), dict):
            if event["message"].get("role") == "assistant":
                out.append(event["message"])
    return out


def parse_transcript(path):
    data = path.read_bytes() if path.is_file() else b""
    events = []
    for line in data.splitlines():
        if not line.strip():
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    messages = assistant_messages(events)
    usage = {"input": 0, "output": 0, "cacheRead": 0, "cacheWrite": 0, "reasoning": 0, "total": 0.0}
    per_turn = []
    for message in messages:
        item = message.get("usage") or {}
        cost = item.get("cost") or {}
        per_turn.append(
            {
                "input": item.get("input"),
                "output": item.get("output"),
                "cacheRead": item.get("cacheRead"),
                "cost_total": cost.get("total"),
            }
        )
        for key in ("input", "output", "cacheRead", "cacheWrite", "reasoning"):
            value = item.get(key)
            if isinstance(value, (int, float)):
                usage[key] += value
        if isinstance(cost.get("total"), (int, float)):
            usage["total"] += cost["total"]
    tool_starts = []
    seen_tools = set()
    for event in events:
        if event.get("type") == "tool_execution_start":
            tool_id = event.get("toolCallId")
            if tool_id not in seen_tools:
                seen_tools.add(tool_id)
                tool_starts.append(event.get("toolName"))
    settled = any(event.get("type") == "agent_settled" for event in events)
    final_text = ""
    for message in reversed(messages):
        parts = []
        content = message.get("content")
        if isinstance(content, list):
            for block in content:
                if isinstance(block, dict) and block.get("type") == "text":
                    parts.append(block.get("text") or "")
        if parts:
            final_text = "".join(parts)
            break
    models = sorted({(m.get("provider"), m.get("model")) for m in messages if m.get("provider")})
    return {
        "bytes": len(data),
        "sha256": sha256_bytes(data),
        "events": len(events),
        "assistant_messages": len(messages),
        "agent_settled": settled,
        "models": [{"provider": p, "model": m} for p, m in models],
        "usage": usage,
        "per_turn": per_turn,
        "tool_calls": len(tool_starts),
        "tool_names": sorted(set(name for name in tool_starts if name)),
        "final_text": final_text,
    }


def write_final_message(artifacts, parsed):
    text = parsed.pop("final_text", "")
    (artifacts / "final-message.txt").write_text(text, encoding="utf-8")
    return text


def instrument_state(teapot, project, env, artifacts, rows):
    state = {}
    for key, words in (
        ("proxy_status", ("proxy", "status")),
        ("flows", ("flows", "list")),
        ("findings", ("findings", "list")),
        ("leads", ("leads", "list")),
        ("sessions", ("sessions", "list")),
        ("authz_matrix", ("authz", "matrix")),
    ):
        state[key] = teapot_json(teapot, project, env, words, rows, f"postrun: {' '.join(words)}")
    write_json(artifacts / "instrument-state.json", state)
    flows = state.get("flows", {}).get("flows", [])
    findings = state.get("findings", {}).get("findings", {})
    leads = state.get("leads", {}).get("leads", {})
    sessions = state.get("sessions", {}).get("sessions", [])
    return {
        "flows": len(flows) if isinstance(flows, list) else None,
        "findings_total": findings.get("total") if isinstance(findings, dict) else None,
        "findings_rows": len(findings.get("rows", [])) if isinstance(findings, dict) else None,
        "leads": leads.get("count") if isinstance(leads, dict) else None,
        "sessions": len(sessions) if isinstance(sessions, list) else None,
        "flow_methods": sorted({f.get("method") for f in flows if isinstance(f, dict)}),
    }


def cleanup_session(teapot, project, env, run_root, container, relays, fixture, artifacts):
    result = {
        "container_removed": False,
        "relays_stopped": False,
        "proxy_stopped": False,
        "proxy_status_verified": False,
        "fixture_stopped": False,
        "errors": [],
    }
    name, cid = container
    if cid:
        subprocess.run(
            ["podman", "--remote=false", "rm", "--force", "--ignore", cid],
            capture_output=True,
            text=True,
            timeout=60,
        )
        probe = subprocess.run(
            ["podman", "--remote=false", "container", "exists", cid],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if probe.returncode != 1:
            result["errors"].append(f"container {cid} still exists")
        else:
            result["container_removed"] = True
    elif name:
        result["errors"].append(f"container ID unavailable; inspect {name}")
    for relay in relays:
        if relay and not stop_process(relay):
            result["errors"].append("relay process remained")
    result["relays_stopped"] = not result["errors"] or all("relay" not in e for e in result["errors"])
    try:
        stopped = teapot_json(teapot, project, env, ("proxy", "stop"))
        if stopped.get("proxy", {}).get("stopped") is not True:
            result["errors"].append("proxy stop did not confirm stopped=true")
        else:
            result["proxy_stopped"] = True
        status = teapot_json(teapot, project, env, ("proxy", "status"))
        if status.get("proxy", {}).get("running") is False:
            result["proxy_status_verified"] = True
        else:
            result["errors"].append("proxy status did not confirm running=false")
    except Exception as error:  # noqa: BLE001 - retained as evidence
        result["errors"].append(f"proxy teardown: {error}")
    if not stop_process(fixture):
        result["errors"].append("fixture process remained")
    else:
        result["fixture_stopped"] = True
    result["success"] = all(
        (
            result["container_removed"],
            result["relays_stopped"],
            result["proxy_stopped"],
            result["proxy_status_verified"],
            result["fixture_stopped"],
        )
    ) and not result["errors"]
    write_json(artifacts / "cleanup.json", result)
    return result


def score_placeholder(parsed, final_text, arm, instrument):
    """Mechanical observations only. Claim adjudication is M0.4.4."""
    heading = re.compile(r"(?im)^\s{0,3}(#{1,6}\s+|\*\*)?\s*(finding|vulnerability|issue)\b")
    sections = len(heading.findall(final_text))
    return {
        "rubric": "m0-baseline-claim-adjudication-v1",
        "status": "pending_adjudication",
        "adjudicated": False,
        "owner": "bn-93a (M0.4.4)",
        "report_present": bool(final_text.strip()),
        "report_chars": len(final_text.strip()),
        "heuristic_finding_headings": sections,
        "instrument_flows": instrument.get("flows"),
        "instrument_findings_total": instrument.get("findings_total"),
        "unsupported_authorization_claims": None,
        "note": (
            "No model grades this run and this runner does not adjudicate prose. "
            "The ledger records the inputs; M0.4.4 applies the frozen claim rubric."
        ),
    }


def infrastructure_score_disposition(reason):
    """Mechanical non-score for a run that never reached scoring inputs."""
    return {
        "rubric": "m0-baseline-claim-adjudication-v1",
        "status": "not_adjudicable_infrastructure_failure",
        "adjudicated": False,
        "owner": "bn-93a (M0.4.4)",
        "report_present": False,
        "report_chars": 0,
        "heuristic_finding_headings": None,
        "instrument_flows": None,
        "instrument_findings_total": None,
        "unsupported_authorization_claims": None,
        "note": (
            f"Run ended before the normal scoring inputs were available: {reason}. "
            "No claim score or unsupported-claim count is inferred; M0.4.4 "
            "(bn-93a) owns claim adjudication."
        ),
    }


def ensure_score_disposition(record):
    """Ensure a scored run has an honest mechanical score disposition."""
    if isinstance(record.get("score"), dict):
        return record["score"]
    reason = record.get("blocked") or f"run status {record.get('status', 'unknown')}"
    record["score"] = infrastructure_score_disposition(reason)
    return record["score"]


def parse_ledger_bytes(data):
    """Partition immutable run rows from typed append-only amendments."""
    runs = []
    amendments = []
    problems = []
    for line_number, raw_line in enumerate(data.splitlines(keepends=True), start=1):
        if not raw_line.strip():
            problems.append(f"ledger line {line_number} is blank")
            continue
        if not raw_line.endswith(b"\n"):
            problems.append(f"ledger line {line_number} lacks a trailing LF")
        try:
            record = json.loads(raw_line)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            problems.append(f"ledger line {line_number} is invalid JSON: {error}")
            continue
        entry = {
            "record": record,
            "line_number": line_number,
            "line_sha256": sha256_bytes(raw_line),
        }
        record_type = record.get("record_type")
        if record_type == SCORE_AMENDMENT_TYPE:
            amendments.append(entry)
        elif record_type in (None, "run"):
            runs.append(entry)
        else:
            problems.append(
                f"ledger line {line_number} has unknown record_type {record_type!r}"
            )
    return runs, amendments, problems


def load_ledger(path=LEDGER_PATH):
    if not path.exists():
        return [], [], []
    return parse_ledger_bytes(path.read_bytes())


def make_score_amendment(run_entry, score):
    """Bind an append-only score disposition to one exact immutable run line."""
    row = run_entry["record"]
    return {
        "record_type": SCORE_AMENDMENT_TYPE,
        "schema_version": SCORE_AMENDMENT_SCHEMA,
        "operation": SCORE_AMENDMENT_OPERATION,
        "target": {
            "schedule_position": row["schedule_position"],
            "assigned_arm": row["assigned_arm"],
            "trial_label": row["trial_label"],
            "source_line_sha256": run_entry["line_sha256"],
            "source_line_sha256_scope": SCORE_AMENDMENT_HASH_SCOPE,
        },
        "score": score,
    }


def score_coverage(run_entries, amendment_entries):
    """Validate exactly one inline or linked score source for every run."""
    problems = []
    run_by_identity = {}
    for entry in run_entries:
        row = entry["record"]
        identity = (
            row.get("schedule_position"),
            row.get("assigned_arm"),
            row.get("trial_label"),
        )
        if identity in run_by_identity:
            problems.append(f"duplicate run identity for score coverage: {identity}")
        else:
            run_by_identity[identity] = entry

    valid_amendments = {}
    for entry in amendment_entries:
        amendment = entry["record"]
        target = amendment.get("target") or {}
        identity = (
            target.get("schedule_position"),
            target.get("assigned_arm"),
            target.get("trial_label"),
        )
        prefix = f"score amendment line {entry['line_number']}"
        valid = True
        if amendment.get("schema_version") != SCORE_AMENDMENT_SCHEMA:
            problems.append(f"{prefix} has unsupported schema_version")
            valid = False
        if amendment.get("operation") != SCORE_AMENDMENT_OPERATION:
            problems.append(f"{prefix} has unsupported operation")
            valid = False
        if target.get("source_line_sha256_scope") != SCORE_AMENDMENT_HASH_SCOPE:
            problems.append(f"{prefix} has the wrong source-line hash scope")
            valid = False
        run_entry = run_by_identity.get(identity)
        if run_entry is None:
            problems.append(f"{prefix} targets no run: {identity}")
            valid = False
        elif target.get("source_line_sha256") != run_entry["line_sha256"]:
            problems.append(f"{prefix} source-line hash mismatch for {identity}")
            valid = False
        score = amendment.get("score")
        if not isinstance(score, dict):
            problems.append(f"{prefix} has no score disposition")
            valid = False
        elif run_entry is not None and score != infrastructure_score_disposition(
            run_entry["record"].get("blocked")
            or f"run status {run_entry['record'].get('status', 'unknown')}"
        ):
            problems.append(f"{prefix} has an invalid score disposition")
            valid = False
        if identity in valid_amendments:
            problems.append(f"duplicate score amendments for {identity}")
            valid = False
        if valid:
            valid_amendments[identity] = entry

    covered = []
    inline = 0
    amended = 0
    missing = []
    for identity, run_entry in run_by_identity.items():
        row = run_entry["record"]
        score = row.get("score")
        inline_score = isinstance(score, dict) and (
            score.get("rubric") == "m0-baseline-claim-adjudication-v1"
            and score.get("status")
            in ("pending_adjudication", "not_adjudicable_infrastructure_failure")
            and score.get("adjudicated") is False
            and score.get("owner") == "bn-93a (M0.4.4)"
            and score.get("unsupported_authorization_claims") is None
        )
        amendment_score = identity in valid_amendments
        label = identity[2]
        if score is not None and not inline_score:
            problems.append(f"{label}: inline score is malformed")
        if inline_score and amendment_score:
            problems.append(f"{label}: inline score conflicts with score amendment")
        elif inline_score:
            inline += 1
            covered.append(label)
        elif amendment_score:
            amended += 1
            covered.append(label)
        else:
            missing.append(label)
            problems.append(f"{label}: missing score or valid score amendment")
    report = {
        "expected": len(run_entries),
        "covered": len(covered),
        "inline": inline,
        "amended": amended,
        "missing": sorted(missing),
        "covered_trials": sorted(covered),
    }
    return report, problems


def record_ledger(record, path=LEDGER_PATH):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def safe_report_files(workspace):
    """Hash intended top-level report files without following links.

    Enumeration skips symlinks, special files and hardlinks. The hash itself
    re-checks the opened descriptor with fstat before reading any byte.
    """
    files, skipped = ep.iter_workspace_files(workspace)
    hashes = {}
    extra = []
    for relative, path in files:
        if "/" in relative:
            continue
        if not relative.lower().endswith((".md", ".txt", ".json")):
            continue
        try:
            hashes[relative] = ep.sha256_regular_nofollow(path)
        except (OSError, ep.PathSafetyError) as error:
            extra.append({"path": relative, "reason": f"report-hash-refused:{type(error).__name__}"})
    if extra:
        skipped = sorted(skipped + extra, key=lambda item: item["path"])
    return hashes, skipped


def execute_session(
    *,
    arm,
    position,
    scored,
    base,
    evidence,
    teapot,
    package,
    image_id,
    tools,
    trial_label=None,
    prompt_override=None,
):
    label = ep.safe_label(trial_label or f"pos-{position:02d}-{arm.lower()}")
    run_root = base / f"{label}-{secrets.token_hex(6)}"
    if run_root.exists():
        raise Blocked(f"run root already exists: {run_root}")
    socket_probe = run_root / "run/teapot" / ("0" * 32) / "control.sock"
    if len(str(socket_probe)) > 107:
        raise Blocked(
            "run-root path is too long for the Teapot control socket "
            f"({len(str(socket_probe))} > 107 bytes); choose a shorter --base"
        )
    for name in ("workspace", "home", "config", "state", "data", "run", "artifacts", "gateway", "pi-agent", "approval"):
        (run_root / name).mkdir(mode=0o700, parents=True)
    artifacts = run_root / "artifacts"
    rows = []
    started = time.time()
    started_ms = time.monotonic()
    container = (None, None)
    relays = []
    fixture = None
    env = None
    project = None
    approval = None
    stdout_path = artifacts / "transcript.jsonl"
    stderr_path = artifacts / "worker.stderr"
    record = {
        "schema_version": 1,
        "scored": scored,
        "trial_label": label,
        "schedule_position": position,
        "assigned_arm": arm,
        "condition_b_visible": arm == "B",
        "model": {"provider": MODEL_PROVIDER, "id": MODEL_ID, "thinking": THINKING, "tools": TOOLS},
        "pins": {
            "materials_lock_sha256": sha256_file(LOCK_PATH),
            "teapot_sha256": sha256_file(teapot),
            "projector_sha256": lock()["files"]["project_inventory.py"],
            "expected_semantic_digest": expected_digest(),
            "fixture_binary_sha256": sha256_file(package / "scourge-fixture"),
            "fixture_catalog_sha256": sha256_file(package / "ground-truth.json"),
            "worker_image_id": image_id,
            "source_commit": run(["git", "-C", ROOT, "rev-parse", "HEAD"], timeout=10).stdout.strip(),
        },
        "budgets": {"wall_seconds": WALL_SECONDS, "fixture_port": 3000, "teapot_requests_ceiling": 1000},
        "runtime": {
            "python": sys.version.split()[0],
            "node": run(["node", "--version"], timeout=30).stdout.strip(),
            "pi": run(["pi", "--version"], timeout=30).stdout.strip(),
        },
        "retries": [],
        "appended_trials": [],
    }
    status = "infrastructure_failure"
    exit_code = None
    timed_out = False
    parsed = {}
    try:
        project, approval, env = setup_project(teapot, run_root, rows)
        raw, projection, digest = capture_inventory(teapot, project, env, rows, artifacts)
        record["parity"] = {
            "prelaunch_eligible": bool(projection.get("prelaunch", {}).get("eligible")),
            "semantic_digest": digest,
            "semantic_digest_matches_frozen": digest == expected_digest(),
            "raw_inventory_sha256": sha256_file(artifacts / "raw-inventory.json"),
            "projected_sha256": sha256_file(artifacts / "projected.json"),
            "project_id": raw["projects_list"]["projects"][0]["id"],
            "inventory_commands": sorted(INVENTORY_COMMANDS),
        }
        write_json(artifacts / "prelaunch.json", {"commands": rows, **record["parity"]})
        if not record["parity"]["prelaunch_eligible"]:
            raise Blocked("prelaunch inventory is not eligible")
        if not record["parity"]["semantic_digest_matches_frozen"]:
            raise Blocked("prelaunch semantic digest differs from the frozen qualification")

        record["visible_inputs"] = freeze_visible_inputs(project, arm, artifacts)
        if prompt_override is not None:
            (project / "task.txt").write_text(prompt_override, encoding="utf-8")
            (project / "QUALIFICATION.md").write_text(
                "Unscored collection qualification. This workspace is not a condition A or B session.\n",
                encoding="utf-8",
            )
            record["qualification"] = True
            record["visible_inputs"]["qualification"] = {
                "task_sha256": sha256_file(project / "task.txt"),
                "marker_sha256": sha256_file(project / "QUALIFICATION.md"),
            }
        proxy_port = proxy_listener(teapot, project, env)
        record["teapot_proxy_port"] = proxy_port

        fixture, port = start_fixture(package, artifacts)
        record["fixture"] = {
            "pid": fixture.pid,
            "port": port,
            "binary_sha256": sha256_file(package / "scourge-fixture"),
        }
        receipt = referee_observe(package, port, artifacts)
        record["fixture_receipt"] = {
            "sha256": sha256_file(artifacts / "live-state.json"),
            "reset_after_checks": receipt.get("reset_after_checks"),
            "referee_target_requests": receipt.get("referee_target_requests"),
            "catalog_sha256": receipt.get("catalog_sha256"),
            "fixture_binary_sha256": receipt.get("fixture_binary_sha256"),
        }
        if not (
            receipt.get("reset_after_checks") is True
            and receipt.get("catalog_sha256") == record["pins"]["fixture_catalog_sha256"]
            and receipt.get("fixture_binary_sha256") == record["pins"]["fixture_binary_sha256"]
        ):
            raise Blocked("referee fixture receipt is invalid")

        relays = [start_model_relay(run_root), start_proxy_relay(run_root, proxy_port)]
        record["relays"] = {
            "model": "CONNECT api.orcarouter.ai:443 only",
            "proxy": f"TCP 127.0.0.1:{proxy_port} only",
            "worker_network": "none",
        }

        for name in ("models.json", "settings.json"):
            shutil.copyfile(WORKER / "pi-agent" / name, run_root / "pi-agent" / name)
        (run_root / "pi-agent").chmod(0o700)
        name = "scourge-m0-" + secrets.token_hex(12)
        cidfile = run_root / "container.cid"
        argv = container_argv(
            run_root, project, approval, tools, teapot, image_id, proxy_port, cidfile, name
        )
        record["container"] = {
            "name": name,
            "image": IMAGE,
            "image_id": image_id,
            "network": "none",
            "rootfs": "read-only",
            "capabilities": "all dropped",
            "no_new_privileges": True,
            "mounts": [item for item in argv if "dst=" in item],
            "argv": argv,
        }
        container_started = time.monotonic()
        with open(stdout_path, "wb") as out, open(stderr_path, "wb") as err:
            proc = subprocess.Popen(argv, stdout=out, stderr=err)
            deadline = time.monotonic() + WALL_SECONDS
            cid = None
            while time.monotonic() < deadline:
                if cidfile.is_file():
                    cid = cidfile.read_text().strip() or None
                container = (name, cid)
                if proc.poll() is not None:
                    break
                time.sleep(0.5)
            if proc.poll() is None:
                timed_out = True
                if cid:
                    subprocess.run(
                        ["podman", "--remote=false", "rm", "--force", "--ignore", cid],
                        capture_output=True,
                        text=True,
                        timeout=60,
                    )
                try:
                    proc.wait(timeout=60)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=30)
            exit_code = proc.returncode
        record["timing"] = {
            "container_started_unix_seconds": int(time.time()),
            "duration_milliseconds": int((time.monotonic() - container_started) * 1000),
            "timed_out": timed_out,
        }
        parsed = parse_transcript(stdout_path)
        final_text = write_final_message(artifacts, parsed)
        instrument = instrument_state(teapot, project, env, artifacts, rows)
        record["instrument"] = instrument
        reported = parsed.get("models", [])
        record["model_reported"] = reported
        if timed_out:
            status = "timeout"
        elif exit_code != 0:
            status = "agent_error"
        elif not parsed.get("assistant_messages"):
            status = "zero_output"
        elif not parsed.get("agent_settled"):
            status = "incomplete"
        else:
            status = "completed"
        if reported and any(
            (row.get("provider") != MODEL_PROVIDER or row.get("model") != MODEL_ID) for row in reported
        ):
            record["model_mismatch"] = reported
        record["score"] = score_placeholder(parsed, final_text, arm, instrument)
    except Blocked as error:
        record["blocked"] = str(error)
        status = "infrastructure_failure"
    except Exception as error:  # noqa: BLE001 - every failure is retained
        record["blocked"] = f"{type(error).__name__}: {error}"
        status = "infrastructure_failure"
    finally:
        try:
            if project is None or env is None:
                cleanup = {
                    "success": True,
                    "container_removed": True,
                    "relays_stopped": True,
                    "proxy_stopped": True,
                    "proxy_status_verified": True,
                    "fixture_stopped": True,
                    "note": "setup stopped before a proxy, relay, container or fixture started",
                    "errors": [],
                }
                write_json(artifacts / "cleanup.json", cleanup)
            else:
                cleanup = cleanup_session(teapot, project, env, run_root, container, relays, fixture, artifacts)
        except Exception as error:  # noqa: BLE001
            cleanup = {"success": False, "errors": [f"cleanup crashed: {error}"]}
            write_json(artifacts / "cleanup.json", cleanup)
        record["cleanup"] = cleanup
        if not cleanup.get("success") and status == "completed":
            status = "cleanup_failure"
        record["status"] = status
        record["exit_code"] = exit_code
        record["timing"] = {
            "started_unix_seconds": int(started),
            "ended_unix_seconds": int(time.time()),
            "elapsed_milliseconds": int((time.monotonic() - started_ms) * 1000),
            **record.get("timing", {}),
        }
        record["transcript"] = {
            "path": str(stdout_path.relative_to(run_root)) if stdout_path.exists() else None,
            "sha256": parsed.get("sha256") if parsed else (sha256_file(stdout_path) if stdout_path.exists() else None),
            "events": parsed.get("events"),
            "assistant_messages": parsed.get("assistant_messages"),
            "agent_settled": parsed.get("agent_settled"),
            "tool_calls": parsed.get("tool_calls"),
            "tool_names": parsed.get("tool_names"),
        }
        record["cost"] = {
            "model_input_tokens": parsed.get("usage", {}).get("input"),
            "model_output_tokens": parsed.get("usage", {}).get("output"),
            "cache_read_tokens": parsed.get("usage", {}).get("cacheRead"),
            "reasoning_tokens": parsed.get("usage", {}).get("reasoning"),
            "model_usd": parsed.get("usage", {}).get("total"),
            "per_turn": parsed.get("per_turn", []),
            "usage_available": bool(parsed.get("assistant_messages")),
        }
        record["final_message_sha256"] = (
            sha256_file(artifacts / "final-message.txt") if (artifacts / "final-message.txt").exists() else None
        )
        record["workspace_after"] = sorted(
            entry.name for entry in (run_root / "workspace").iterdir() if entry.name != ".teapot"
        )
        try:
            report_files, report_skipped = safe_report_files(run_root / "workspace")
        except (OSError, ep.PathSafetyError) as error:
            report_files = {}
            report_skipped = [{"path": ".", "reason": f"report-scan-refused:{type(error).__name__}"}]
        record["report_files"] = report_files
        record["report_files_skipped"] = report_skipped
        record["run_root"] = str(run_root)
        record["evidence_dir"] = str(evidence)
        if scored:
            ensure_score_disposition(record)
        write_json(artifacts / "run.json", record)
        if scored:
            record_ledger(record)
        # Unscored runs are written by copy_evidence, which refuses to
        # overwrite an existing evidence target.
    return record


def copy_evidence(record, evidence):
    evidence = Path(evidence)
    evidence.mkdir(parents=True, exist_ok=True)
    label = ep.safe_label(record["trial_label"])
    target = ep.safe_join(evidence, label)
    if target.is_symlink():
        raise Blocked(f"evidence target is a symlink: {target}")
    if target.exists() and any(target.iterdir()):
        raise Blocked(f"evidence target already has files: {target}")
    target.mkdir(parents=True, exist_ok=True)
    run_root = Path(record["run_root"])
    source = run_root / "artifacts"
    if source.is_symlink() or not source.is_dir():
        raise Blocked(f"artifacts directory is missing or a symlink: {source}")

    copied = {}
    keep = {
        "worker.stderr": "worker.stderr",
        "final-message.txt": "final-message.txt",
        "run.json": "run.json",
        "prelaunch.json": "prelaunch.json",
        "raw-inventory.json": "raw-inventory.json",
        "projected.json": "projected.json",
        "live-state.json": "live-state.json",
        "instrument-state.json": "instrument-state.json",
        "visible-inputs.json": "visible-inputs.json",
        "cleanup.json": "cleanup.json",
        "fixture.stderr": "fixture.stderr",
    }
    transcript = source / "transcript.jsonl"
    if transcript.is_symlink():
        raise Blocked("raw transcript is a symlink")
    if transcript.is_file():
        raw = ep.read_regular_nofollow(transcript)
        compressed = gzip.compress(raw, compresslevel=9, mtime=0)
        (target / "transcript.jsonl.gz").write_bytes(compressed)
        copied["transcript.jsonl.gz"] = ep.sha256_file(target / "transcript.jsonl.gz")
        copied["transcript.jsonl.sha256"] = sha256_bytes(raw)
        copied["transcript.jsonl.bytes"] = len(raw)
        calls = []
        for line in raw.splitlines():
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get("type") == "tool_execution_start":
                calls.append(
                    json.dumps(
                        {"tool": event.get("toolName"), "args": event.get("args")},
                        sort_keys=True,
                    )
                )
        (target / "tool-calls.jsonl").write_text("\n".join(calls) + ("\n" if calls else ""), encoding="utf-8")
        copied["tool-calls.jsonl"] = ep.sha256_file(target / "tool-calls.jsonl")
    for name, out in keep.items():
        try:
            path = ep.safe_join(source, name)
        except ep.PathSafetyError as error:
            raise Blocked(f"unsafe artifact path {name!r}: {error}") from error
        if path.is_symlink() or not path.is_file():
            continue
        destination = ep.safe_join(target, out)
        try:
            ep.copy_regular_nofollow(path, destination)
        except ep.PathSafetyError as error:
            raise Blocked(f"cannot copy artifact {name!r}: {error}") from error
        copied[out] = ep.sha256_file(destination)

    workspace = run_root / "workspace"
    skipped = []
    if workspace.is_symlink():
        skipped = [{"path": ".", "reason": "workspace-is-symlink"}]
    elif workspace.is_dir():
        result = ep.copy_workspace_tree(workspace, target / "workspace")
        for relative, meta in result["files"].items():
            copied[f"workspace/{relative}"] = meta["sha256"]
        skipped = result["skipped"]
    else:
        skipped = [{"path": ".", "reason": "workspace-missing"}]
    skipped_path = target / "workspace-skipped.json"
    write_json(
        skipped_path,
        {
            "schema_version": 1,
            "rule": "regular files only; no symlinks; .teapot excluded; paths relative to workspace",
            "skipped": skipped,
        },
    )
    copied["workspace-skipped.json"] = ep.sha256_file(skipped_path)
    write_json(target / "SHA256SUMS.json", copied)
    return copied


def collect_evidence(record, evidence):
    try:
        return copy_evidence(record, evidence)
    except (Blocked, ep.PathSafetyError, OSError) as error:
        label = ep.safe_label(record["trial_label"])
        try:
            target = ep.safe_join(Path(evidence), label)
        except (ep.PathSafetyError, OSError):
            return None
        try:
            write_json(
                target / "copy-error.json",
                {
                    "schema_version": 1,
                    "trial_label": label,
                    "error": f"{type(error).__name__}: {error}",
                    "note": "the run record remains in the ledger; evidence copy failed safely",
                },
            )
        except OSError:
            pass
        return None


def cmd_schedule(args):
    path = Path(args.path)
    if path.exists():
        raise SystemExit(f"refusing to overwrite an existing schedule: {path}")
    seed = args.seed or secrets.token_hex(16)
    if not re.fullmatch(r"[0-9a-f]{8,128}", seed):
        raise SystemExit("seed must be lowercase hex")
    arms = ["A"] * (args.runs // 2) + ["B"] * (args.runs // 2)
    if args.runs % 2:
        arms.append("A")
    random.Random(seed).shuffle(arms)
    counts = {arm: arms.count(arm) for arm in ("A", "B")}
    if min(counts.values()) < MIN_PER_ARM:
        raise SystemExit(f"schedule has fewer than {MIN_PER_ARM} runs in an arm: {counts}")
    schedule = {
        "schema_version": 1,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "seed": seed,
        "generator": "python3 random.Random(seed).shuffle over balanced A/B arms",
        "runs": [
            {"position": position, "arm": arm} for position, arm in enumerate(arms, start=1)
        ],
        "counts": counts,
        "model": {"provider": MODEL_PROVIDER, "id": MODEL_ID, "thinking": THINKING, "tools": TOOLS},
        "pins": {
            "teapot_sha256": lock()["teapot"]["binary_sha256"],
            "teapot_source_commit": lock()["teapot"]["source_commit"],
            "materials_lock_sha256": sha256_file(LOCK_PATH),
            "projector_sha256": sha256_file(M0 / "project_inventory.py"),
            "expected_semantic_digest": expected_digest(),
            "approval_source_sha256": sha256_file(APPROVAL_SOURCE),
            "model_api": MODEL_API,
        },
        "budgets": {"wall_seconds": WALL_SECONDS},
    }
    write_json(path, schedule)
    print(json.dumps({"schedule": str(path), "seed": seed, "counts": counts}, sort_keys=True))


def load_schedule(path):
    schedule = read_json(path)
    positions = [row["position"] for row in schedule["runs"]]
    if positions != list(range(1, len(positions) + 1)):
        raise Blocked("schedule positions are not contiguous")
    counts = {arm: sum(1 for row in schedule["runs"] if row["arm"] == arm) for arm in ("A", "B")}
    if min(counts.values()) < MIN_PER_ARM:
        raise Blocked(f"schedule has fewer than {MIN_PER_ARM} runs in an arm: {counts}")
    if schedule["pins"]["expected_semantic_digest"] != expected_digest():
        raise Blocked("schedule was frozen against a different parity digest")
    if schedule["pins"]["teapot_sha256"] != lock()["teapot"]["binary_sha256"]:
        raise Blocked("schedule was frozen against a different Teapot")
    return schedule


def cmd_preflight(args):
    base = Path(args.base).resolve()
    base.mkdir(parents=True, exist_ok=True)
    teapot = pinned_teapot(args.teapot)
    message = preflight_materials()
    schedule = load_schedule(SCHEDULE_PATH) if SCHEDULE_PATH.exists() else None
    podman_rootless()
    image_id = podman_image()
    tools = build_tool_bundle(base)
    package = build_fixture_package(base)
    pi_pkg = str(Path(os.path.realpath(shutil.which("pi") or "")).parents[2])
    auth = Path.home() / ".pi/agent/auth.json"
    report = {
        "materials": message,
        "teapot": {"path": str(teapot), "sha256": sha256_file(teapot)},
        "projector_expected_digest": expected_digest(),
        "schedule": {
            "path": str(SCHEDULE_PATH),
            "present": schedule is not None,
            "counts": schedule["counts"] if schedule else None,
            "seed": schedule["seed"] if schedule else None,
        },
        "podman": {
            "version": run(["podman", "--remote=false", "--version"], timeout=30).stdout.strip(),
            "rootless": True,
            "image_id": image_id,
        },
        "fixture": {
            "binary": str(package / "scourge-fixture"),
            "binary_sha256": sha256_file(package / "scourge-fixture"),
            "catalog_sha256": sha256_file(package / "ground-truth.json"),
        },
        "worker": {
            "image": IMAGE,
            "tool_bundle": str(tools),
            "pi_package": pi_pkg,
            "node": run(["node", "--version"], timeout=30).stdout.strip(),
            "auth_present": auth.is_file(),
            "auth_read": False,
        },
    }
    root = Path(args.base).resolve() / "_preflight"
    write_json(root / "preflight.json", report)
    print(json.dumps(report, indent=2, sort_keys=True))


def cmd_pilot(args):
    base = Path(args.base).resolve()
    evidence = Path(args.evidence).resolve()
    base.mkdir(parents=True, exist_ok=True)
    teapot = pinned_teapot(args.teapot)
    preflight_materials()
    podman_rootless()
    image_id = podman_image()
    tools = build_tool_bundle(base)
    package = build_fixture_package(base)
    record = execute_session(
        arm=args.arm,
        position=0,
        scored=False,
        base=base,
        evidence=evidence,
        teapot=teapot,
        package=package,
        image_id=image_id,
        tools=tools,
        trial_label="pilot",
    )
    collect_evidence(record, evidence)
    print(json.dumps({k: record.get(k) for k in ("status", "timing", "cost", "score")}, indent=2, sort_keys=True))


def cmd_run(args):
    schedule = load_schedule(SCHEDULE_PATH)
    base = Path(args.base).resolve()
    evidence = Path(args.evidence).resolve()
    base.mkdir(parents=True, exist_ok=True)
    teapot = pinned_teapot(args.teapot)
    preflight_materials()
    podman_rootless()
    image_id = podman_image()
    tools = build_tool_bundle(base)
    package = build_fixture_package(base)
    done = set()
    run_entries, _, ledger_problems = load_ledger()
    if ledger_problems:
        raise Blocked(f"ledger is invalid: {ledger_problems}")
    for entry in run_entries:
        row = entry["record"]
        if row.get("scored"):
            done.add((row["schedule_position"], row["assigned_arm"]))
    selected = schedule["runs"]
    if args.positions:
        wanted = {int(value) for value in args.positions.split(",")}
        selected = [row for row in selected if row["position"] in wanted]
    for row in selected:
        key = (row["position"], row["arm"])
        if key in done:
            print(f"skip position {row['position']} ({row['arm']}): already in the ledger", file=sys.stderr)
            continue
        print(f"run position {row['position']} arm {row['arm']}", file=sys.stderr)
        record = execute_session(
            arm=row["arm"],
            position=row["position"],
            scored=True,
            base=base,
            evidence=evidence,
            teapot=teapot,
            package=package,
            image_id=image_id,
            tools=tools,
        )
        collect_evidence(record, evidence)
        done.add(key)
        print(
            json.dumps(
                {
                    "position": row["position"],
                    "arm": row["arm"],
                    "status": record["status"],
                    "duration_ms": record.get("timing", {}).get("elapsed_milliseconds"),
                    "usd": record.get("cost", {}).get("model_usd"),
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
    print(json.dumps({"ledger": str(LEDGER_PATH), "runs": len(done)}), file=sys.stderr)


def cmd_qualify(args):
    base = Path(args.base).resolve()
    evidence = Path(args.evidence).resolve()
    base.mkdir(parents=True, exist_ok=True)
    teapot = pinned_teapot(args.teapot)
    preflight_materials()
    podman_rootless()
    image_id = podman_image()
    tools = build_tool_bundle(base)
    package = build_fixture_package(base)
    prompt = (
        "This is an unscored harness qualification, not a security assessment. "
        "In this workspace, run `teapot proxy status --json` to read the proxy listener. "
        "Then send exactly one unauthenticated GET to http://127.0.0.1:3000/app/api/me "
        "through that proxy (for example with `teapot run -- curl -s -o /dev/null -w '%{http_code}' "
        "http://127.0.0.1:3000/app/api/me`). Do not test any other route. "
        "Then reply exactly: QUALIFICATION-OK <http-status>"
    )
    record = execute_session(
        arm="A",
        position=0,
        scored=False,
        base=base,
        evidence=evidence,
        teapot=teapot,
        package=package,
        image_id=image_id,
        tools=tools,
        trial_label=ep.safe_label(args.label),
        prompt_override=prompt,
    )
    collect_evidence(record, evidence)
    transcript = record.get("transcript") or {}
    report = {
        "label": args.label,
        "scored": False,
        "in_ledger": False,
        "status": record.get("status"),
        "agent_settled": transcript.get("agent_settled"),
        "transcript_sha256": transcript.get("sha256"),
        "transcript_events": transcript.get("events"),
        "model_reported": record.get("model_reported"),
        "cleanup": record.get("cleanup"),
        "cost": {key: value for key, value in (record.get("cost") or {}).items() if key != "per_turn"},
        "passed": bool(
            record.get("status") == "completed"
            and transcript.get("agent_settled") is True
            and (record.get("cleanup") or {}).get("success") is True
        ),
    }
    write_json(evidence / f"{args.label}-result.json", report)
    print(json.dumps(report, indent=2, sort_keys=True))
    if not report["passed"]:
        raise SystemExit(1)


def cmd_verify(args):
    schedule = load_schedule(SCHEDULE_PATH)
    expected = {(row["position"], row["arm"]) for row in schedule["runs"]}
    evidence = Path(args.evidence).resolve()
    run_entries, amendment_entries, ledger_problems = load_ledger()
    rows = [entry["record"] for entry in run_entries]
    problems = list(ledger_problems)
    notes = []
    score_report, score_problems = score_coverage(run_entries, amendment_entries)
    problems.extend(score_problems)
    seen = set()
    for row in rows:
        key = (row["schedule_position"], row["assigned_arm"])
        if key in seen:
            problems.append(f"duplicate ledger entry {key}")
        seen.add(key)
    missing = sorted(expected - seen)
    extra = sorted(seen - expected)
    if missing:
        problems.append(f"missing schedule positions: {missing}")
    if extra:
        problems.append(f"ledger entries outside the schedule: {extra}")
    if [row["schedule_position"] for row in rows] != sorted(row["schedule_position"] for row in rows):
        problems.append("ledger rows are not in schedule order")

    valid = []
    status_counts = {}
    for row in rows:
        try:
            label = ep.safe_label(row["trial_label"])
        except ep.PathSafetyError as error:
            problems.append(f"unsafe trial label: {error}")
            continue
        status_counts[row["status"]] = status_counts.get(row["status"], 0) + 1
        try:
            target = ep.safe_join(evidence, label)
        except ep.PathSafetyError as error:
            problems.append(f"{label}: evidence path is unsafe: {error}")
            continue
        if target.is_symlink():
            problems.append(f"{label}: evidence target is a symlink")
            continue
        try:
            run_path = ep.safe_join(target, "run.json")
        except ep.PathSafetyError as error:
            problems.append(f"{label}: unsafe run.json path: {error}")
            run_path = None
        if run_path is None:
            pass
        elif not run_path.is_file():
            problems.append(f"{label}: missing run.json")
        else:
            try:
                if read_json_regular(run_path) != row:
                    problems.append(f"{label}: run.json differs from the ledger row")
            except (OSError, ep.PathSafetyError) as error:
                problems.append(f"{label}: run.json refused: {error}")
        try:
            manifest_path = ep.safe_join(target, "SHA256SUMS.json")
        except ep.PathSafetyError as error:
            problems.append(f"{label}: unsafe SHA256SUMS path: {error}")
            manifest_path = None
        if manifest_path is None:
            pass
        elif not manifest_path.is_file():
            problems.append(f"{label}: missing SHA256SUMS.json")
        else:
            try:
                manifest = read_json_regular(manifest_path)
            except (OSError, ep.PathSafetyError) as error:
                problems.append(f"{label}: SHA256SUMS.json refused: {error}")
                manifest = None
            for name, digest in (manifest or {}).items():
                if name.endswith((".sha256", ".bytes")):
                    continue
                try:
                    path = ep.safe_join(target, name)
                except ep.PathSafetyError as error:
                    problems.append(f"{label}: unsafe manifest path {name!r}: {error}")
                    continue
                if path.is_symlink():
                    problems.append(f"{label}: manifest entry is a symlink: {name}")
                    continue
                if not path.is_file():
                    problems.append(f"{label}: manifest entry missing: {name}")
                    continue
                try:
                    actual = ep.sha256_regular_nofollow(path)
                except (OSError, ep.PathSafetyError) as error:
                    problems.append(f"{label}: manifest entry refused {name!r}: {error}")
                    continue
                if actual != digest:
                    problems.append(f"{label}: manifest hash mismatch: {name}")
        try:
            transcript_path = ep.safe_join(target, "transcript.jsonl.gz")
        except ep.PathSafetyError as error:
            problems.append(f"{label}: unsafe transcript path: {error}")
            transcript_path = None
        if transcript_path is None:
            pass
        elif not transcript_path.is_file():
            problems.append(f"{label}: missing transcript")
        else:
            try:
                raw = gzip.decompress(ep.read_regular_nofollow(transcript_path))
            except (OSError, EOFError) as error:
                problems.append(f"{label}: unreadable transcript: {error}")
            else:
                if sha256_bytes(raw) != row["transcript"]["sha256"]:
                    problems.append(f"{label}: transcript hash mismatch")
                try:
                    manifest = (
                        read_json_regular(manifest_path)
                        if manifest_path is not None and manifest_path.is_file()
                        else {}
                    )
                except (OSError, ep.PathSafetyError) as error:
                    problems.append(f"{label}: transcript manifest refused: {error}")
                    manifest = {}
                if manifest.get("transcript.jsonl.sha256") not in (None, sha256_bytes(raw)):
                    problems.append(f"{label}: manifest transcript digest disagrees with the ledger")
        cleanup = row.get("cleanup") or {}
        if not cleanup.get("success"):
            problems.append(f"{label}: cleanup failure {cleanup.get('errors')}")
        try:
            supplement_root = ep.safe_join(target, "workspace-supplement")
        except ep.PathSafetyError as error:
            problems.append(f"{label}: unsafe supplement path: {error}")
            supplement_root = None
        if supplement_root is not None and supplement_root.exists():
            if supplement_root.is_symlink():
                problems.append(f"{label}: workspace-supplement is a symlink")
            else:
                try:
                    supplement = ep.safe_join(supplement_root, "SUPPLEMENT.json")
                except ep.PathSafetyError as error:
                    problems.append(f"{label}: unsafe supplement manifest: {error}")
                    supplement = None
                if supplement is not None and supplement.is_symlink():
                    problems.append(f"{label}: supplement manifest is a symlink")
                elif supplement is not None and supplement.is_file():
                    try:
                        entry = read_json_regular(supplement)
                    except (OSError, ep.PathSafetyError) as error:
                        problems.append(f"{label}: supplement manifest refused: {error}")
                        entry = {}
                    for name, meta in entry.get("files", {}).items():
                        try:
                            path = ep.safe_join(supplement_root, name)
                        except ep.PathSafetyError as error:
                            problems.append(
                                f"{label}: unsafe supplementary path {name!r}: {error}"
                            )
                            continue
                        if path.is_symlink():
                            problems.append(f"{label}: supplementary entry is a symlink: {name}")
                            continue
                        if not path.is_file():
                            problems.append(f"{label}: supplementary evidence missing: {name}")
                            continue
                        try:
                            actual = ep.sha256_regular_nofollow(path)
                        except (OSError, ep.PathSafetyError) as error:
                            problems.append(f"{label}: supplementary evidence refused {name!r}: {error}")
                            continue
                        if actual != meta.get("sha256"):
                            problems.append(f"{label}: supplementary evidence hash mismatch: {name}")
        reported = row.get("model_reported") or []
        model_ok = bool(reported) and all(
            item.get("provider") == MODEL_PROVIDER and item.get("model") == MODEL_ID for item in reported
        )
        if row.get("status") == "completed" and row.get("transcript", {}).get("agent_settled") and model_ok:
            valid.append(label)
        if row.get("status") == "completed" and not model_ok:
            problems.append(f"{label}: completed run does not report the pinned model")

    containers = run(
        ["podman", "--remote=false", "ps", "-a", "--format", "{{.Names}}"],
        timeout=30,
    ).stdout.split()
    leaked = [name for name in containers if name.startswith(("scourge-m0-", "m0-"))]
    if leaked:
        problems.append(f"live worker containers: {leaked}")
    processes = run(["ps", "-eo", "args"], timeout=30).stdout.splitlines()
    roots = [row.get("run_root") for row in rows if row.get("run_root")]
    relay_leaks = [
        line
        for line in processes
        if ("model-relay.py" in line or "tcp-relay.py" in line)
        and any(root in line for root in roots)
    ]
    if relay_leaks:
        problems.append(f"live relays: {len(relay_leaks)}")
    teapot_leaks = [
        line
        for line in processes
        if "teapot" in line and "--project" in line and any(root in line for root in roots)
    ]
    if teapot_leaks:
        problems.append(f"live Teapot engines for retained run roots: {len(teapot_leaks)}")
    fixture_leaks = [
        line
        for line in processes
        if any(root in line for root in roots) and "scourge-fixture" in line
    ]
    if fixture_leaks:
        problems.append(f"live fixture processes: {len(fixture_leaks)}")

    decision = "inconclusive"
    if len(valid) >= len(expected):
        decision = "ready_for_adjudication"
    else:
        notes.append(
            f"preregistered rule needs {len(expected)} valid sessions; "
            f"{len(valid)} completed cleanly, so the decision is inconclusive"
        )
    report = {
        "schedule": {"seed": schedule["seed"], "counts": schedule["counts"], "expected": len(expected)},
        "ledger_entries": len(rows),
        "ledger_records": len(run_entries) + len(amendment_entries),
        "score_amendments": len(amendment_entries),
        "score_coverage": score_report,
        "valid_completed_sessions": valid,
        "status_counts": status_counts,
        "decision_rule": {"status": decision, "valid": len(valid), "required": len(expected)},
        "adjudication": "pending (M0.4.4)",
        "live_worker_containers": leaked,
        "notes": notes,
        "problems": problems,
    }
    try:
        verify_path = ep.safe_join(evidence, "verify.json")
    except ep.PathSafetyError as error:
        problems.append(f"unsafe verify.json path: {error}")
        verify_path = None
    if getattr(args, "no_write", False):
        pass
    elif verify_path is None:
        pass
    else:
        write_json(verify_path, report)
    print(json.dumps(report, indent=2, sort_keys=True))
    if problems:
        raise SystemExit(1)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--base", default=os.environ.get("EVAL_BASE", "/tmp/scourge-evals"))
    parser.add_argument("--evidence", default=str(BASELINE_DIR))
    sub = parser.add_subparsers(dest="command", required=True)

    schedule = sub.add_parser("schedule")
    schedule.add_argument("--path", default=str(SCHEDULE_PATH))
    schedule.add_argument("--seed")
    schedule.add_argument("--runs", type=int, default=DEFAULT_RUNS)
    schedule.set_defaults(func=cmd_schedule)

    preflight = sub.add_parser("preflight")
    preflight.add_argument("--teapot", required=True)
    preflight.set_defaults(func=cmd_preflight)

    pilot = sub.add_parser("pilot")
    pilot.add_argument("--teapot", required=True)
    pilot.add_argument("--arm", choices=("A", "B"), default="A")
    pilot.set_defaults(func=cmd_pilot)

    run_parser = sub.add_parser("run")
    run_parser.add_argument("--teapot", required=True)
    run_parser.add_argument("--positions")
    run_parser.set_defaults(func=cmd_run)

    qualify = sub.add_parser("qualify")
    qualify.add_argument("--teapot", required=True)
    qualify.add_argument("--label", default="qualification-1")
    qualify.set_defaults(func=cmd_qualify)

    verify = sub.add_parser("verify")
    verify.add_argument("--no-write", action="store_true", help="validate without rewriting verify.json")
    verify.set_defaults(func=cmd_verify)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
