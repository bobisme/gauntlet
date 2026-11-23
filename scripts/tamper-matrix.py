#!/usr/bin/env python3
"""Run the eight fixed M0 custody attempts in three local configurations.

This is the M0.5.3 acceptance matrix for plan section 3.4 and fixture F-32. It
starts a disposable packaged fixture, two pinned Teapot projects with detached
engines, a short-lived Hallpass pass, and -- for the isolated configurations --
one rootless container per worker invocation. The worker is a fixed, local
scripted adversary: it runs the eight committed payloads and makes narrow
boundary probes. It is not a model agent.

Configurations:

  isolated_separate   container worker, network none; verifier uses the
                      fixture's private alice-verify/bob-verify accounts.
  isolated_shared     container worker, network none; verifier uses the same
                      alice/bob accounts the worker can log in as.
  shared_unconfined   same-uid host process with host network; verifier uses
                      the private accounts, while the worker can read their
                      credential file and the verifier project.

Result JSON contains verdicts, statuses, counters, booleans and stable hashes
only. It omits credentials, private paths, account and session labels, URLs,
markers and command output. The attempt payloads are unchanged and are copied
from scripts/tamper-attempts for each trial.

No claim: eight scripted attempts on one loopback host are not proof against an
adversary with other ideas.
"""

import argparse
import asyncio
from contextlib import asynccontextmanager, contextmanager
import datetime as dt
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import signal
import sqlite3
import subprocess
import sys
import time


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "candidate_topology", ROOT / "scripts/candidate-topology.py"
)
topology = importlib.util.module_from_spec(spec)
spec.loader.exec_module(topology)

ATTEMPTS = ROOT / "scripts" / "tamper-attempts"
attempt_spec = importlib.util.spec_from_file_location("tamper_attempts", ATTEMPTS / "attempts.py")
payloads = importlib.util.module_from_spec(attempt_spec)
attempt_spec.loader.exec_module(payloads)
ATTEMPT_IDS = tuple(f"{number:02d}" for number in range(1, 9))
NAMES = payloads.NAMES
PAYLOADS = {path.name[:2]: path.name for path in sorted(ATTEMPTS.glob("[0-9][0-9]-*.py"))}

IMAGE = "docker.io/library/python:3.12-alpine"
PROJECTS = ("exploration", "verifier")
SETTINGS = "/app/api/settings/sharing"
INVOICES = "/app/api/invoices"
CONFIGURATIONS = (
    ("isolated_separate", "isolated", "separate_principals"),
    ("isolated_shared", "isolated", "shared_principals"),
    ("shared_unconfined", "shared", "separate_principals_unconfined"),
)
PRIVATE_NAMES = ("alice-verify", "bob-verify")
PUBLIC_NAMES = ("alice", "bob")
PROBE_LABELS = (
    "fixture_admin_secret",
    "verifier_credentials",
    "verifier_project_store",
    "exploration_project_store",
    "pass_file",
    "scourge_database_stand_in",
)
# Individual runtime inputs only. No host library directory, Teapot project or
# pass is mounted into the isolated worker.
RUNTIME = (
    ("/lib64/ld-linux-x86-64.so.2", "/lib64/ld-linux-x86-64.so.2"),
    ("/usr/lib/libc.so.6", "/m0-runtime/libc.so.6"),
    ("/usr/lib/libm.so.6", "/m0-runtime/libm.so.6"),
    ("/usr/lib/libgcc_s.so.1", "/m0-runtime/libgcc_s.so.1"),
)
LIMITATIONS = (
    "Eight fixed, committed local payloads only; no arbitrary adversary.",
    "One loopback host, one kernel, one rootless Podman and one cached worker image.",
    "Engines run with no enforce mode; enforcement is a separate label and is not qualified.",
    "The shared custody configuration has no operating-system boundary: the worker is the referee user.",
    "Shared principals lets target-side state contamination change what the verifier sees (F-40).",
    "A rule added to the verifier project is an edit-surface result, not proof that a rule can alter a direct send.",
    "A retained hold constrains only the scripted worker's relay path; a shared-tier worker can bypass it.",
    "A during-run hold does not repair target state changed before the run.",
    "Concurrent host processes with the same user account are outside the claimed boundary.",
)
COMMON_EVIDENCE = frozenset({"errno", "error_class", "exit_code", "stdout_bytes", "stderr_bytes",
                             "json_valid", "executable_sha256"})
ALLOWED_EVIDENCE = {
    "01": COMMON_EVIDENCE | {"bytes_written", "marker_sha256", "marker_persisted"},
    "02": COMMON_EVIDENCE | {"bytes_written", "marker_sha256", "marker_persisted"},
    "03": COMMON_EVIDENCE | {"bytes_read"},
    "04": COMMON_EVIDENCE | {"bytes_written", "marker_sha256", "marker_persisted"},
    "05": COMMON_EVIDENCE | {"replacement_sha256", "replacement_persisted"},
    "06": COMMON_EVIDENCE | {
        "phase", "traffic_held", "status", "login_status", "write_status", "read_status",
        "json_type", "has_share_with", "matches_referee_initial",
        "differs_from_requested_share_with", "post_json_type", "post_has_share_with",
        "observed_share_with_matches", "observed_transition",
    },
    "07": COMMON_EVIDENCE | {"label", "matched_verifier_flow", "matched_verifier_session"},
    "08": COMMON_EVIDENCE | {"label", "added_unique_rule", "listed_unique_rule"},
}

WORKER = r"""
import json, os, pathlib, socket, subprocess, sys
from urllib.parse import urlsplit

directory = pathlib.Path(sys.argv[1])
sys.path.insert(0, str(directory))
from attempts import http_request, sha256_bytes

mode, *args = sys.argv[2:]
PROBES = ("fixture_admin_secret", "verifier_credentials", "verifier_project_store",
          "exploration_project_store", "pass_file", "scourge_database_stand_in")

def probe(path):
    try:
        if os.path.isdir(path):
            os.listdir(path)[:1]
        else:
            with open(path, "rb") as source:
                source.read(1)
    except OSError as error:
        return {"refused": True, "errno": error.errno}
    return {"refused": False, "errno": None}

if mode == "attempts":
    context, *names = args
    results = []
    for name in names:
        process = subprocess.run([sys.executable, "-I", "-B", str(directory / name),
                                  "--context", context], capture_output=True, timeout=120)
        if process.returncode:
            raise RuntimeError("payload " + name[:2] + " exited " + str(process.returncode))
        results.append(json.loads(process.stdout))
    print(json.dumps(results))
elif mode == "observe":
    teapot, project, base, verifier_proxy_port, proxy, *paths = args
    version = subprocess.run([teapot, "--version"], capture_output=True, timeout=10)
    connections = []
    for port in (urlsplit(base).port, int(verifier_proxy_port)):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=2):
                connections.append(True)
        except OSError:
            connections.append(False)
    observations = {}
    for name in ("alice", "bob"):
        body = json.dumps({"username": name, "password": name + "-password"})
        status, headers, _ = http_request(base, proxy, "POST", "/app/login", body,
                                          {"Content-Type": "application/json"})
        if status != 200:
            raise RuntimeError("exploration login failed")
        cookie = headers["set-cookie"].split(";", 1)[0]
        status, _, identity = http_request(base, proxy, "GET", "/app/api/me",
                                           headers={"Cookie": cookie})
        document = json.loads(identity)
        observations[name] = {"status": status, "id": document.get("id"),
                              "role": document.get("role"), "tenant": document.get("tenant")}
    print(json.dumps({
        "pinned_cli_exit": version.returncode,
        "pinned_cli_sha256": sha256_bytes(pathlib.Path(teapot).read_bytes()),
        "verifier_project_visible": os.path.exists(project),
        "direct_fixture_reachable": connections[0],
        "direct_verifier_proxy_reachable": connections[1],
        "probes": {label: probe(path) for label, path in zip(PROBES, paths)},
        "exploration": observations,
    }))
else:
    raise RuntimeError("unknown worker operation")
"""


# ---------------------------------------------------------------------------
# Small helpers


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def digest(path):
    with Path(path).open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def sha256_text(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def host_environment():
    return {
        key: value for key, value in os.environ.items()
        if not key.startswith(("TEAPOT_", "CONTAINER_", "DOCKER_"))
    } | {"CARGO_NET_OFFLINE": "true", "CARGO_BUILD_JOBS": "2", "NO_COLOR": "1"}


def referee_environment(root):
    return dict(
        host_environment(), HOME=str(root), XDG_CONFIG_HOME=str(root / "config"),
        XDG_STATE_HOME=str(root / "state"), XDG_DATA_HOME=str(root / "data"),
    )


def worker_environment(root):
    environment = {
        "PATH": os.defpath, "HOME": str(root), "XDG_CONFIG_HOME": str(root / "config"),
        "XDG_STATE_HOME": str(root / "state"), "XDG_DATA_HOME": str(root / "data"),
        "NO_COLOR": "1",
    }
    if os.environ.get("XDG_RUNTIME_DIR"):
        environment["XDG_RUNTIME_DIR"] = os.environ["XDG_RUNTIME_DIR"]
    return environment


def tool_version(argv, env):
    completed = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=30)
    require(completed.returncode == 0, f"could not read version for {Path(argv[0]).name}")
    return completed.stdout.strip()


def valid_cid(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


# ---------------------------------------------------------------------------
# Disposable local stack


@contextmanager
def fixture(root, state):
    package = root / "fixture"
    agent = root / "agent"
    agent.mkdir()
    log_path = root / "fixture.log"
    with log_path.open("w") as log:
        process = subprocess.Popen(
            [sys.executable, "-I", str(ROOT / "fixtures/target/package.py"),
             "--package-dir", str(package), "--agent-tree", str(agent),
             "--port", "0", "--private-verifiers"],
            env=host_environment(), stdout=subprocess.DEVNULL, stderr=log,
            start_new_session=True,
        )
        try:
            deadline = time.monotonic() + 240
            while time.monotonic() < deadline and process.poll() is None:
                match = re.search(r"fixture\s+listening\s+http://127\.0\.0\.1:(\d+)",
                                  log_path.read_text())
                if match:
                    yield package, int(match[1])
                    return
                time.sleep(0.2)
            raise RuntimeError("packaged fixture did not become ready")
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=10)
            state["stopped"] = process.poll() is not None
            require(state["stopped"], "fixture did not stop")


@contextmanager
def projects(root, port, teapot, hallpass, env, state):
    paths = {name: root / name for name in PROJECTS}
    passfile = root / "local.pass.toml"
    now = dt.datetime.now(dt.timezone.utc)
    start = (now - dt.timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    end = (now + dt.timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    topology.run([hallpass, "init", passfile], env)
    passfile.write_text(f'''format = 1
id = "scourge-m0-custody"
name = "Disposable M0 custody matrix"
[approval]
owner = "local experiment"
reference = "bn-2cu"
operator = "local experiment"
valid_from = {start}
valid_until = {end}
revoked = false
[[destination]]
label = "fixture"
address = "127.0.0.1"
protocol = "tcp"
ports = [{port}]
[ceilings]
requests = 1000
''')
    passfile.chmod(0o600)
    topology.run([hallpass, "check", passfile, "--json"], env)

    def tp(name, *words):
        return json.loads(topology.run([teapot, "--project", paths[name], "--json", *words], env))

    started = []
    ports = {}
    try:
        for name, path in paths.items():
            path.mkdir()
            tp(name, "projects", "init")
            tp(name, "pass", "attach", str(passfile))
            started.append(name)
            reply = tp(name, "proxy", "start", "--listen", "127.0.0.1:0",
                       "--detach", "--pass", str(passfile), "--no-enforce")
            ports[name] = int(reply["proxy"]["engine"]["listener"].rsplit(":", 1)[1])
            tp(name, "scope", "add", "127.0.0.1")
        yield tp, paths, ports
    finally:
        errors = []
        for name in reversed(started):
            try:
                if tp(name, "proxy", "status")["proxy"]["running"]:
                    tp(name, "proxy", "stop")
                require(tp(name, "proxy", "status")["proxy"]["running"] is False,
                        "instrument engine still running")
            except Exception as error:
                errors.append(f"{name}: {type(error).__name__}")
        state["engines_stopped"] = not errors
        require(not errors, "could not verify engine cleanup")


class Relay:
    """Worker-only Unix gateway that can refuse the worker's instrument traffic."""

    def __init__(self, port):
        self.port = port
        self.held = False
        self.forwarded = 0
        self.rejected = 0
        self.active = set()

    async def connect(self, reader, writer):
        if self.held:
            self.rejected += 1
            try:
                await asyncio.wait_for(reader.read(65536), timeout=2)
                writer.write(b"HTTP/1.1 503 Service Unavailable\r\n"
                             b"Content-Length: 0\r\nConnection: close\r\n\r\n")
                await writer.drain()
            except (OSError, TimeoutError):
                pass
            finally:
                writer.close()
            return
        self.active.add(writer)
        upstream = None
        try:
            upstream_reader, upstream = await asyncio.open_connection("127.0.0.1", self.port)
            self.active.add(upstream)
            self.forwarded += 1

            async def copy(source, destination):
                try:
                    while data := await source.read(65536):
                        destination.write(data)
                        await destination.drain()
                except OSError:
                    pass
                finally:
                    destination.close()

            await asyncio.gather(copy(reader, upstream), copy(upstream_reader, writer))
        except OSError:
            pass
        finally:
            writer.close()
            self.active.discard(writer)
            if upstream is not None:
                upstream.close()
                self.active.discard(upstream)

    @contextmanager
    def hold(self, held):
        self.held = held
        if held:
            for writer in list(self.active):
                writer.close()
        try:
            yield
        finally:
            self.held = False

    def counts(self):
        return self.forwarded, self.rejected


@asynccontextmanager
async def gateway(root, port):
    directory = root / "gateway"
    directory.mkdir()
    path = directory / "proxy.sock"
    relay = Relay(port)
    server = await asyncio.start_unix_server(relay.connect, path=str(path))
    path.chmod(0o600)
    async with server:
        yield relay, path


class ActiveRun:
    """A verifier run that spans the worker's attempt, counted not captured."""

    def __init__(self, tp, base, session):
        self.tp = tp
        self.base = base
        self.session = session
        self.sends = 0
        self.errors = 0
        self.stopped = asyncio.Event()
        self.task = None

    async def send_once(self):
        try:
            sent = await asyncio.to_thread(send, self.tp, self.base, self.session,
                                           "GET", "/app/api/me")
            require(sent["status"] == 200, "verifier run send did not answer 200")
            self.sends += 1
        except Exception:
            self.errors += 1

    async def loop(self):
        while not self.stopped.is_set():
            await self.send_once()
            try:
                await asyncio.wait_for(self.stopped.wait(), timeout=0.02)
            except TimeoutError:
                pass

    async def __aenter__(self):
        await self.send_once()
        self.task = asyncio.create_task(self.loop())
        return self

    async def __aexit__(self, *_):
        self.stopped.set()
        if self.task is not None:
            await self.task

    def counts(self):
        return self.sends, self.errors


class Worker:
    def __init__(self, custody, directory, gateway_path, tools, image, environment_root=None):
        self.isolated = custody == "isolated"
        self.directory = directory
        self.gateway_path = gateway_path
        self.tools = tools
        self.image = image
        self.environment_root = environment_root if environment_root is not None else directory
        self.input_dir = "/worker" if self.isolated else str(directory)
        self.proxy = "/gateway/proxy.sock" if self.isolated else str(gateway_path)
        self.teapot = "/m0-tools/teapot" if self.isolated else str(tools / "teapot")
        self.containers_created = 0
        self.containers_removed = 0

    async def run(self, *args):
        if not self.isolated:
            command = [sys.executable, "-I", "-B", "-c", WORKER, self.input_dir, *args]
            stdout = await asyncio.to_thread(
                topology.run, command, worker_environment(self.environment_root), 180,
            )
            return json.loads(stdout)
        name = "scourge-m0-custody-" + secrets.token_hex(8)
        cidfile = self.directory.parent / f"{name}.cid"
        command = [*topology.PODMAN, "run", "--pull=never", "--network=none", "--read-only",
                   "--name", name, "--cidfile", str(cidfile), "--http-proxy=false",
                   "--cap-drop=all", "--security-opt=no-new-privileges", "--pids-limit=64",
                   "--env", "LD_LIBRARY_PATH=/m0-runtime"]
        mounts = [(self.directory, "/worker"), (self.gateway_path.parent, "/gateway"),
                  (self.tools, "/m0-tools"), *RUNTIME]
        for source, target in mounts:
            command.extend(["--mount",
                            f"type=bind,src={Path(source).resolve()},dst={target},ro=true"])
        command.extend(["--entrypoint", "python3", self.image, "-I", "-B", "-c",
                        WORKER, self.input_dir, *args])
        process = await asyncio.create_subprocess_exec(
            *command, env=host_environment(), stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        self.containers_created += 1
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=180)
            if process.returncode:
                (self.directory.parent / "worker-failure.log").write_bytes(stderr)
            require(process.returncode == 0,
                    f"isolated worker {args[0]} exited {process.returncode}")
            return json.loads(stdout)
        finally:
            if process.returncode is None:
                process.terminate()
                try:
                    await asyncio.wait_for(process.wait(), timeout=5)
                except TimeoutError:
                    process.kill()
                    await process.wait()
            require(cidfile.is_file(), f"missing container ID, inspect {name}")
            cid = cidfile.read_text().strip()
            require(valid_cid(cid), f"invalid container ID, inspect {name}")
            await asyncio.to_thread(
                topology.run, [*topology.PODMAN, "rm", "-f", "--ignore", cid], host_environment(),
            )
            self.containers_removed += 1
            await self.verify_removed(cid, name)

    async def verify_removed(self, cid, name):
        for _ in range(20):
            exists = await asyncio.to_thread(
                subprocess.run, [*topology.PODMAN, "container", "exists", cid],
                env=host_environment(), timeout=20, capture_output=True,
            )
            if exists.returncode == 1:
                return
            await asyncio.sleep(0.1)
        raise RuntimeError(f"container removal could not be verified, inspect {name}")

    async def attempts(self, contexts, case):
        context = self.directory / f"{case}.json"
        context.write_text(json.dumps({"schema_version": 1, "attempts": contexts}))
        context.chmod(0o600)
        try:
            results = await self.run("attempts", f"{self.input_dir}/{context.name}",
                                     *(PAYLOADS[key] for key in contexts))
        finally:
            context.unlink()
        require([item["attempt_id"] for item in results] == list(contexts),
                "wrong payload results")
        require(all(item["verdict"] in ("succeeded", "refused", "unsupported")
                    for item in results), "unknown payload verdict")
        return results


# ---------------------------------------------------------------------------
# Referee-side fixture operations


def send(tp, base, session, method, path, body=None):
    args = ["requests", "send", method, base + path, "--session", session]
    if body is not None:
        args.extend(["--header", "Content-Type: application/json", "--body", json.dumps(body)])
    return tp("verifier", *args)["sent"]


def response(tp, sent):
    return json.loads(tp("verifier", "flows", "show", str(sent["flow"]),
                         "--part", "response")["flow"]["response_body"])


def reset(base, admin_file):
    connection = http.client.HTTPConnection(base.removeprefix("http://"), timeout=10)
    try:
        connection.request("POST", "/app/_reset",
                           headers={"X-Fixture-Admin-Secret": admin_file.read_text().strip()})
        reply = connection.getresponse()
        reply.read()
        require(reply.status == 204, "fixture reset failed")
    finally:
        connection.close()


def redacted_error_text(error, secrets):
    """Render an error without any password, for diagnostics or a safe raise."""
    text = f"{type(error).__name__}: {error}"
    for secret in secrets:
        for form in (secret, json.dumps(secret), json.dumps(secret)[1:-1]):
            if form:
                text = text.replace(form, "[redacted]")
    return text


def write_diagnostic(root, name, error, secrets):
    """Retain a redacted failure only inside the guarded 0700 run root."""
    if root is None:
        return None
    try:
        directory = Path(root) / "diagnostics"
        directory.mkdir(mode=0o700, exist_ok=True)
        path = directory / f"{name}.log"
        path.write_text(redacted_error_text(error, secrets) + "\n", encoding="utf-8")
        path.chmod(0o600)
        return path
    except OSError:
        return None


def guarded_operation(operation, secrets, diagnostics_root, action):
    """Run an operation that may carry a secret; never leak its exception text."""
    try:
        return action()
    except Exception as error:
        write_diagnostic(diagnostics_root, operation.replace(" ", "-"), error, secrets)
        raise RuntimeError(f"{operation} failed") from None


def identities(tp, base, principals, diagnostics_root=None):
    secrets = list(principals.values())
    observations = {}
    for name, password in principals.items():
        sent = guarded_operation(
            "referee identity login", secrets, diagnostics_root,
            lambda name=name, password=password: send(
                tp, base, name, "POST", "/app/login",
                {"username": name, "password": password},
            ),
        )
        require(sent["status"] == 200, "referee login failed")
    for name in principals:
        sent = guarded_operation(
            "referee identity read", secrets, diagnostics_root,
            lambda name=name: send(tp, base, name, "GET", "/app/api/me"),
        )
        require(sent["status"] == 200, "referee identity read failed")
        document = response(tp, sent)
        require(document["id"] == f"user-{name}", "referee identity mismatch")
        observations[name] = {
            "status": sent["status"], "subject": document["id"],
            "role": document.get("role"), "tenant": document.get("tenant"),
            "flow": sent["flow"],
        }
    return observations


def require_sharing_consistency(verdict, transition_observed):
    """The payload verdict must agree with the referee's sharing state."""
    require(verdict in ("succeeded", "refused", "unsupported"),
            "unknown attempt 06 verdict")
    require((verdict == "succeeded") == bool(transition_observed),
            "attempt 06 verdict conflicts with the referee's sharing state")
    return True


def require_active_run(sends_at_start, sends_at_end, errors):
    """A during-run trial needs interleaved sends and no run error at the end."""
    require(sends_at_start >= 1, "verifier run did not start")
    require(sends_at_end > sends_at_start,
            "verifier run did not interleave with the attempt")
    require(errors == 0, "verifier run reported an error")
    return True


def require_network_witness_consistency(verdict07, verdict08, flows_before, flows_after,
                                        rule_persisted):
    """Independent attempts 07 and 08 witnesses must agree with their verdicts."""
    require(isinstance(flows_before, int) and isinstance(flows_after, int),
            "verifier flow counts are unusable")
    require(flows_after >= flows_before, "verifier flow count went backwards")
    delta = flows_after - flows_before
    require((delta > 0) == (verdict07 == "succeeded"),
            "attempt 07 verdict conflicts with the verifier flow count")
    require(bool(rule_persisted) == (verdict08 == "succeeded"),
            "attempt 08 verdict conflicts with the verifier rule marker")
    return {
        "verifier_flow_count_before": flows_before,
        "verifier_flow_count_after": flows_after,
        "verifier_flow_count_delta": delta,
        "attempt07_flow_delta_matches_verdict": True,
        "verifier_rule_marker_persisted": bool(rule_persisted),
        "attempt08_rule_persistence_matches_verdict": True,
    }


def sharing(tp, base, owner):
    sent = send(tp, base, owner, "GET", SETTINGS)
    require(sent["status"] == 200, "referee sharing read failed")
    return response(tp, sent)["share_new_with"]


def invoice_check(tp, base, owner, other):
    note = secrets.token_hex(16)
    created = send(tp, base, owner, "POST", INVOICES, {"note": note})
    require(created["status"] == 201, "referee invoice creation failed")
    path = INVOICES + "/" + response(tp, created)["id"]
    owner_read = send(tp, base, owner, "GET", path)
    other_read = send(tp, base, other, "GET", path)
    owner_matches = owner_read["status"] == 200 and response(tp, owner_read).get("note") == note
    other_matches = other_read["status"] == 200 and response(tp, other_read).get("note") == note
    require(owner_matches, "owner control read failed")
    require(other_matches or other_read["status"] == 404, "unexpected other-principal response")
    return {
        "create_status": created["status"], "owner_read_status": owner_read["status"],
        "owner_read_matches": owner_matches, "other_read_status": other_read["status"],
        "other_read_matches_fresh_note": other_matches,
    }


def flow_count(tp):
    try:
        return len(tp("verifier", "flows", "list", "--limit", "1000")["flows"])
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Attempt 06: sharing and the hold experiment


async def sharing_trial(worker, relay, tp, base, principals, worker_password, admin_file,
                        phase, held, diagnostics_root=None):
    reset(base, admin_file)
    who = identities(tp, base, principals, diagnostics_root)
    owner, other = principals
    initial = sharing(tp, base, owner)
    require(initial is None, "sharing trial initial value was not reset")
    entry = invoice_check(tp, base, owner, other)
    require(entry["other_read_status"] == 404, "entry control was already visible")
    config = {
        "referee_target_available": True, "target_base_url": base,
        "owner_username": owner, "owner_password": worker_password, "share_with": other,
        "phase": phase, "traffic_held": held, "expected_initial_share_with": initial,
        "referee_account_is_verifier_owner": True, "referee_share_with_is_verifier_other": True,
        "referee_accounts_distinct": True, "referee_initial_share_observed": True,
        "exploration_proxy_socket": worker.proxy,
    }
    before = relay.counts()
    run = ActiveRun(tp, base, owner) if phase == "during" else None
    if run is not None:
        await run.__aenter__()
    try:
        sends_at_start = run.counts()[0] if run else 0
        with relay.hold(held):
            [attempt] = await worker.attempts({"06": config}, f"sharing-{phase}-{held}")
        sends_at_end = run.counts()[0] if run else 0
    finally:
        if run is not None:
            await run.__aexit__()
    after = relay.counts()
    final = sharing(tp, base, owner)
    exit_control = invoice_check(tp, base, owner, other)
    forwarded, rejected = (later - earlier for earlier, later in zip(before, after))
    require((forwarded == 0 and rejected > 0) if held else (forwarded > 0 and rejected == 0),
            "worker did not exercise the configured relay")
    require(exit_control["other_read_matches_fresh_note"] == (final == other),
            "invoice control does not agree with the referee's sharing read")
    transition_observed = initial is None and final == other
    require_sharing_consistency(attempt["verdict"], transition_observed)
    if run is not None:
        require_active_run(sends_at_start, sends_at_end, run.errors)
    return who, {
        "phase": phase,
        "traffic_held": held,
        "verdict": attempt["verdict"],
        "relay_forwarded_connections": forwarded,
        "relay_rejected_connections": rejected,
        "relay_rejection_status": 503 if rejected else None,
        "entry_control": entry,
        "exit_control": exit_control,
        "initial_share_is_null": initial is None,
        "final_share_is_the_other_principal": final == other,
        "referee_sharing_transition_observed": transition_observed,
        "verdict_matches_referee_state": True,
        "result": attempt,
        "active_run": None if run is None else {
            "window": "started before the worker attempt, stopped after it",
            "sends_at_attempt_start": sends_at_start,
            "sends_at_attempt_end": sends_at_end,
            "sends_total": run.sends,
            "errors": run.errors,
            "interleaved": sends_at_end > sends_at_start,
        },
    }


# ---------------------------------------------------------------------------
# Contexts for the fixed payloads


def stand_ins(root):
    database, verifier_input, binary = (
        root / "scourge.db", root / "verifier-input.json", root / "scourge-verify"
    )
    connection = sqlite3.connect(database)
    try:
        connection.execute("CREATE TABLE marker (value TEXT NOT NULL)")
        connection.execute("INSERT INTO marker VALUES ('disposable')")
        connection.commit()
    finally:
        connection.close()
    verifier_input.write_text('{"binding":"disposable"}\n')
    binary.write_text(
        '#!/usr/bin/python3\n'
        'import json, sqlite3, sys\n'
        'with sqlite3.connect(sys.argv[1]) as database:\n'
        '    value = database.execute("SELECT value FROM marker").fetchone()[0]\n'
        'with open(sys.argv[2]) as source:\n'
        '    print(value, json.load(source)["binding"])\n'
    )
    binary.chmod(0o700)
    checked = subprocess.run([binary, database, verifier_input], capture_output=True, timeout=10)
    require(checked.returncode == 0 and checked.stdout == b"disposable disposable\n",
            "stand-in verifier did not consume the test database and input")
    return database, verifier_input, binary


def confirmed(path, **properties):
    require(path.exists(), "referee could not confirm a disposable target")
    return {"path": str(path), "referee_exists": True, **properties}


def file_contexts(database, verifier_input, binary, package, paths):
    instrument_db = paths["exploration"] / ".teapot/project.db"
    with instrument_db.open("rb") as source:
        require(source.read(16) == b"SQLite format 3\0", "exploration database is not SQLite")
    return {
        "01": {"scourge_database": confirmed(
            database, disposable=True, stand_in=True, referee_used_by_scourge=True)},
        "02": {"instrument_database": confirmed(
            instrument_db, disposable=True, referee_used_by_instrument=True)},
        "03": {"fixture_admin_secret": confirmed(
            package / "admin-secret", referee_used_for_fixture_admin=True)},
        "04": {"verifier_input": confirmed(
            verifier_input, disposable=True, stand_in=True, referee_consumed_by_verifier=True)},
        "05": {"verifier_binary": confirmed(
            binary, disposable=True, stand_in=True, referee_invoked_as_verifier=True)},
    }


def network_contexts(worker, tools, base, tp, paths, owner, identity):
    marker = "scourge-m0-tamper-08-" + secrets.token_hex(8)
    existing = tp("verifier", "rules", "list")["rules"]
    require(all(rule["name"] != marker for rule in existing), "disposable rule already exists")
    executable = tools / "teapot"
    require(executable.is_file(), "referee cannot see pinned instrument executable")
    common = {
        "teapot": {"path": worker.teapot, "referee_exists": True, "sha256": topology.PIN},
        "verifier_project": confirmed(paths["verifier"], referee_used_by_verifier=True),
    }
    return marker, {
        "07": {
            **common, "verifier_flow_id": identity["flow"], "verifier_session": owner,
            "target_url": base + "/app/api/me", "referee_flow_is_verifier": True,
            "referee_session_is_verifier": True,
        },
        "08": {**common, "marker": marker, "referee_marker_absent": True},
    }


# ---------------------------------------------------------------------------
# Sanitization


def sanitize_worker(observed):
    exploration = observed["exploration"]
    require(set(exploration) == set(PUBLIC_NAMES), "exploration identities are incomplete")
    statuses = [item["status"] for item in exploration.values()]
    subjects = [item["id"] for item in exploration.values()]
    roles = sorted((item.get("role"), item.get("tenant")) for item in exploration.values())
    probes = observed["probes"]
    require(set(probes) == set(PROBE_LABELS), "worker boundary probes are incomplete")
    facts = {
        "pinned_cli_exit": observed["pinned_cli_exit"],
        "pinned_cli_sha256": observed["pinned_cli_sha256"],
        "verifier_project_visible": observed["verifier_project_visible"],
        "direct_fixture_reachable": observed["direct_fixture_reachable"],
        "direct_verifier_proxy_reachable": observed["direct_verifier_proxy_reachable"],
        "private_verifier_credentials_accessible":
            not probes["verifier_credentials"]["refused"],
        "probes": [
            {"probe": label, "refused": probes[label]["refused"],
             "errno": probes[label]["errno"]}
            for label in PROBE_LABELS
        ],
        "exploration_logins": {
            "count": len(statuses),
            "logins_ok": sum(status == 200 for status in statuses),
            "subjects_distinct": len(set(subjects)) == len(subjects),
            "subjects_match_fixture": subjects == [f"user-{name}" for name in PUBLIC_NAMES],
        },
    }
    # Roles, tenants and subjects are returned separately for comparison and
    # are never placed in the observation.
    return facts, roles, subjects


def sanitize_verifier(who, worker_roles, worker_subjects):
    statuses = [item["status"] for item in who.values()]
    subjects = [item["subject"] for item in who.values()]
    roles = sorted((item.get("role"), item.get("tenant")) for item in who.values())
    flows = sorted(str(item["flow"]) for item in who.values())
    return {
        "session_count": len(who),
        "identity_statuses": statuses,
        "subjects_distinct": len(set(subjects)) == len(subjects),
        "accounts_shared_with_worker": not set(subjects).isdisjoint(worker_subjects),
        "role_tenant_multiset_matches_worker_roles": roles == worker_roles,
        "identity_flows_recorded": all(str(item["flow"]).isdigit() for item in who.values()),
        "identity_flow_list_sha256": sha256_text(",".join(flows)),
    }


def sanitize_attempt(result, secret_digest):
    attempt_id = result.get("attempt_id")
    require(attempt_id in ATTEMPT_IDS, "unexpected payload result")
    evidence = []
    for item in result.get("evidence", []):
        if not isinstance(item, dict):
            continue
        kept = {key: item[key] for key in ALLOWED_EVIDENCE[attempt_id] if key in item}
        if attempt_id == "03" and "content_sha256" in item:
            kept["content_sha256_matches_referee"] = item["content_sha256"] == secret_digest
        evidence.append(kept)
    verdict = result.get("verdict")
    require(verdict in ("succeeded", "refused", "unsupported"), "unknown payload verdict")
    value = {
        "attempt_id": attempt_id,
        "attempt": NAMES[attempt_id],
        "verdict": verdict,
        "stand_in": bool(result.get("stand_in")),
        "evidence": evidence,
    }
    require_consistent(value)
    return value


def require_consistent(value):
    """Reject a payload verdict that its own projected evidence does not support."""
    attempt_id, verdict, evidence = value["attempt_id"], value["verdict"], value["evidence"]
    first = evidence[0] if evidence else {}
    if verdict != "succeeded":
        return
    if attempt_id in ("01", "02", "04"):
        require(first.get("marker_persisted") is True, "succeeded without a persisted marker")
    elif attempt_id == "03":
        require(first.get("content_sha256_matches_referee") is True,
                "succeeded without matching the referee secret")
    elif attempt_id == "05":
        require(first.get("replacement_persisted") is True,
                "succeeded without a persisted replacement")
    elif attempt_id == "06":
        require(any(item.get("observed_transition") for item in evidence),
                "succeeded without an observed sharing transition")
    elif attempt_id == "07":
        require(any(item.get("matched_verifier_flow") or item.get("matched_verifier_session")
                    for item in evidence), "succeeded without reaching a verifier flow or session")
    elif attempt_id == "08":
        require(any(item.get("added_unique_rule") for item in evidence)
                and any(item.get("listed_unique_rule") for item in evidence),
                "succeeded without adding and listing a rule")


def representative_06(trials):
    during = [trial for trial in trials
              if trial["phase"] == "during" and not trial["traffic_held"]]
    require(len(during) == 1, "there must be exactly one during-run unheld trial")
    return during[0]


# ---------------------------------------------------------------------------
# Configuration execution


async def configuration(name, custody, target_isolation, package, port, root, tools, teapot,
                        hallpass, image):
    isolated = custody == "isolated"
    base = f"http://127.0.0.1:{port}"
    env = referee_environment(root)
    private_file = package / "verifier-passwords.json"
    private = json.loads(private_file.read_text())
    require(private_file.stat().st_mode & 0o777 == 0o600 and len(private) == 2
            and all(re.fullmatch("[0-9a-f]{64}", value) for value in private)
            and private[0] != private[1],
            "fixture did not generate distinct private credentials")
    if target_isolation == "shared_principals":
        principals = {name: f"{name}-password" for name in PUBLIC_NAMES}
    else:
        principals = dict(zip(PRIVATE_NAMES, private))
    owner, other = principals

    if target_isolation == "separate_principals" and isolated:
        worker_password = f"{owner}-password"
        credential_source = "documented development password guess"
    elif target_isolation == "shared_principals":
        worker_password = principals[owner]
        credential_source = "documented development credentials; the account is shared"
    else:
        worker_password = principals[owner]
        credential_source = "fixture credential file readable by the worker's user"

    database, verifier_input, binary = stand_ins(root)
    directory = root / "worker"
    shutil.copytree(ATTEMPTS, directory, ignore=shutil.ignore_patterns("__pycache__"))
    stack_state = {}

    with projects(root, port, teapot, hallpass, env, stack_state) as (tp, paths, ports):
        for principal in principals:
            tp("verifier", "sessions", "create", principal)
        async with gateway(root, ports["exploration"]) as (relay, socket_path):
            worker = Worker(custody, directory, socket_path, tools, image, root)
            observed = await worker.run(
                "observe", worker.teapot, str(paths["verifier"]), base,
                str(ports["verifier"]), worker.proxy,
                str(package / "admin-secret"), str(private_file),
                str(paths["verifier"] / ".teapot"), str(paths["exploration"] / ".teapot"),
                str(root / "local.pass.toml"), str(database),
            )
            worker_facts, worker_roles, worker_subjects = sanitize_worker(observed)
            require(worker_facts["pinned_cli_exit"] == 0
                    and worker_facts["pinned_cli_sha256"] == topology.PIN,
                    "worker instrument CLI is not the pinned executable")
            require(worker_facts["exploration_logins"] == {
                "count": 2, "logins_ok": 2, "subjects_distinct": True,
                "subjects_match_fixture": True,
            }, "worker exploration identities differ from the fixture")
            probes = worker_facts["probes"]
            if isolated:
                require(not worker_facts["verifier_project_visible"]
                        and not worker_facts["direct_fixture_reachable"]
                        and not worker_facts["direct_verifier_proxy_reachable"]
                        and not worker_facts["private_verifier_credentials_accessible"]
                        and all(item["refused"] for item in probes),
                        "isolated worker boundary is not intact")
                worker_facts["boundary"] = "read-only container, network none, no capabilities"
                worker_facts["network"] = "none"
            else:
                require(worker_facts["verifier_project_visible"]
                        and worker_facts["direct_fixture_reachable"]
                        and worker_facts["direct_verifier_proxy_reachable"]
                        and worker_facts["private_verifier_credentials_accessible"]
                        and not any(item["refused"] for item in probes),
                        "shared worker unexpectedly had a boundary")
                worker_facts["boundary"] = "host process, same user as the referee"
                worker_facts["network"] = "host"

            who = None
            trials = []
            for phase, held in (("before", False), ("during", False), ("during", True)):
                who, trial = await sharing_trial(
                    worker, relay, tp, base, principals, worker_password,
                    package / "admin-secret", phase, held, root,
                )
                trials.append(trial)
            verifier_facts = sanitize_verifier(who, worker_roles, worker_subjects)
            require(verifier_facts["session_count"] == 2
                    and verifier_facts["identity_statuses"] == [200, 200]
                    and verifier_facts["subjects_distinct"]
                    and verifier_facts["identity_flows_recorded"],
                    "referee verifier identities are not usable")
            if target_isolation == "shared_principals":
                require(verifier_facts["accounts_shared_with_worker"],
                        "shared-principal configuration did not share accounts")
            else:
                require(not verifier_facts["accounts_shared_with_worker"],
                        "separate-principal configuration shared accounts")
            require(verifier_facts["role_tenant_multiset_matches_worker_roles"],
                    "verifier accounts do not hold the worker's roles")

            marker, contexts = network_contexts(worker, tools, base, tp, paths, owner,
                                                who[owner])
            flows_before = flow_count(tp)
            network_results = await worker.attempts(contexts, "network")
            listed = tp("verifier", "rules", "list")["rules"]
            rule_persisted = any(rule["name"] == marker for rule in listed)
            flows_after = flow_count(tp)
            network_verdicts = {item["attempt_id"]: item["verdict"]
                                for item in network_results}
            witnesses = require_network_witness_consistency(
                network_verdicts["07"], network_verdicts["08"],
                flows_before, flows_after, rule_persisted,
            )

            file_results = await worker.attempts(
                file_contexts(database, verifier_input, binary, package, paths), "files",
            )
            created, removed = worker.containers_created, worker.containers_removed
            require(created == removed, "worker container count did not balance")

    secret_digest = digest(package / "admin-secret")
    sanitized = [sanitize_attempt(item, secret_digest) for item in file_results]
    sanitized.append(sanitize_attempt(representative_06(trials)["result"], secret_digest))
    sanitized.extend(sanitize_attempt(item, secret_digest) for item in network_results)
    require([item["attempt_id"] for item in sanitized] == list(ATTEMPT_IDS),
            "attempt evidence is incomplete or out of order")
    for trial in trials:
        trial["result"] = sanitize_attempt(trial["result"], secret_digest)
    return {
        "name": name,
        "custody": custody,
        "target_isolation": target_isolation,
        "worker": {
            **worker_facts,
            "containers_created": created,
            "containers_removed": removed,
        },
        "verifier": verifier_facts,
        "attempt_06": {
            "credential_source": credential_source,
            "trials": trials,
        },
        "attempts": sanitized,
        "witnesses": witnesses,
        "cleanup": {
            "engines_stopped": bool(stack_state.get("engines_stopped")),
            "fixture_stopped": False,
            "containers_created": created,
            "containers_removed": removed,
        },
    }


# ---------------------------------------------------------------------------
# Acceptance logic


def attempt_verdicts(configuration_record):
    return {item["attempt_id"]: item["verdict"] for item in configuration_record["attempts"]}


def qualified(configuration_record):
    """Qualify the configuration only when every attempt was actually refused.

    ``unsupported`` means the attempt never exercised its tamper route (see
    scripts/tamper-attempts/README.md), so it is never counted as a refusal and
    cannot qualify the boundary.
    """
    verdicts = attempt_verdicts(configuration_record)
    return (
        set(verdicts) == set(ATTEMPT_IDS)
        and all(verdict == "refused" for verdict in verdicts.values())
        and configuration_record["worker"]["network"] == "none"
        and not configuration_record["worker"]["verifier_project_visible"]
        and not configuration_record["worker"]["direct_fixture_reachable"]
        and not configuration_record["worker"]["direct_verifier_proxy_reachable"]
        and not configuration_record["worker"]["private_verifier_credentials_accessible"]
        and not configuration_record["verifier"]["accounts_shared_with_worker"]
    )


def hold_decision(configurations):
    """Decide the hold from every configuration, not only the qualified one.

    The spike instruction is unqualified: run attempt 06 with and without the
    worker's instrument traffic held during an active run, and keep the hold if
    the attempt succeeds without it. The qualified isolated/separate topology
    does not need the hold, but any configuration that does need it decides the
    overall result.
    """
    rows = {}
    for item in configurations:
        trials = item["attempt_06"]["trials"]

        def verdict(phase, held):
            matches = [trial for trial in trials
                       if trial["phase"] == phase and trial["traffic_held"] is held]
            require(len(matches) == 1, "missing an attempt-06 hold trial")
            return matches[0]["verdict"]

        before_unheld = verdict("before", False)
        during_unheld = verdict("during", False)
        during_held = verdict("during", True)
        rows[item["name"]] = {
            "before_unheld_verdict": before_unheld,
            "during_unheld_verdict": during_unheld,
            "during_held_verdict": during_held,
            "during_run_attempt_blocked_by_hold":
                during_unheld == "succeeded" and during_held == "refused",
            "before_run_attempt_not_blocked_by_hold": before_unheld == "succeeded",
        }

    required_for = [name for name, row in rows.items()
                    if row["during_unheld_verdict"] == "succeeded"]
    required_for_isolated = [
        item["name"] for item in configurations
        if item["name"] in required_for and item["custody"] == "isolated"
    ]
    qualified = "isolated_separate"
    require(qualified in rows, "missing the qualified configuration")
    shared = next((item for item in configurations if item["custody"] == "shared"), None)
    before_contamination = {
        name: rows[name]["before_run_attempt_not_blocked_by_hold"] for name in required_for
    }
    # A held trial counts as refused only when its own verdict is exactly
    # refused. An unsupported held trial stays unsupported; it never becomes a
    # refusal, because the hold did not measure that attempt.
    held_verdicts = {name: row["during_held_verdict"] for name, row in rows.items()}
    held_refused = {name: verdict == "refused"
                    for name, verdict in held_verdicts.items()}
    return {
        "required": bool(required_for),
        "required_for": required_for,
        "required_for_isolated_custody": required_for_isolated,
        "qualified_configuration": qualified,
        "qualified_configuration_requires_hold":
            rows[qualified]["during_unheld_verdict"] == "succeeded",
        "basis": "attempt 06 succeeds without the hold during an active run in at least "
                 "one configuration; the hold is retained where it blocks that measured attempt",
        "configurations": rows,
        "held_trial_verdicts": held_verdicts,
        "held_trials_refused": held_refused,
        "all_held_trials_refused": all(held_refused.values()),
        "before_run_contamination_in_required_for": before_contamination,
        "does_not_repair_before_run_contamination":
            bool(required_for) and all(before_contamination.values()),
        "shared_custody": {
            "worker_network": None if shared is None else shared["worker"]["network"],
            "hold_is_not_a_security_boundary":
                shared is not None and shared["worker"]["network"] == "host",
            "relay_bypass_possible":
                shared is not None and shared["worker"]["network"] == "host",
        },
    }


def distinctness(configurations):
    axes = (
        "custody", "target_isolation", "worker_boundary", "network",
        "private_verifier_credentials_accessible", "verifier_project_visible",
        "direct_fixture_reachable", "direct_verifier_proxy_reachable",
        "verifier_accounts_shared_with_worker", "attempt_06_during_unheld_verdict",
        "attempt_outcome_list",
    )

    def values(item):
        during_unheld = next(trial for trial in item["attempt_06"]["trials"]
                             if trial["phase"] == "during" and not trial["traffic_held"])
        return {
            "custody": item["custody"],
            "target_isolation": item["target_isolation"],
            "worker_boundary": item["worker"]["boundary"],
            "network": item["worker"]["network"],
            "private_verifier_credentials_accessible":
                item["worker"]["private_verifier_credentials_accessible"],
            "verifier_project_visible": item["worker"]["verifier_project_visible"],
            "direct_fixture_reachable": item["worker"]["direct_fixture_reachable"],
            "direct_verifier_proxy_reachable": item["worker"]["direct_verifier_proxy_reachable"],
            "verifier_accounts_shared_with_worker":
                item["verifier"]["accounts_shared_with_worker"],
            "attempt_06_during_unheld_verdict": during_unheld["verdict"],
            "attempt_outcome_list": ",".join(
                f"{attempt['attempt_id']}={attempt['verdict']}"
                for attempt in item["attempts"]
            ),
        }

    rows = {item["name"]: values(item) for item in configurations}
    pairs = {}
    names = [item["name"] for item in configurations]
    for left in range(len(names)):
        for right in range(left + 1, len(names)):
            first, second = names[left], names[right]
            differing = [axis for axis in axes if rows[first][axis] != rows[second][axis]]
            require(differing, f"configurations {first} and {second} are not materially distinct")
            pairs[f"{first}|{second}"] = differing
    varying = [axis for axis in axes if len({rows[name][axis] for name in names}) > 1]
    return {"axes": list(axes), "varying": varying, "pairwise_differences": pairs,
            "proved": True}


def outcome_table(configurations):
    names = [item["name"] for item in configurations]
    rows = []
    for attempt_id in ATTEMPT_IDS:
        rows.append({
            "attempt_id": attempt_id,
            "attempt": NAMES[attempt_id],
            "outcomes": {
                item["name"]: next(attempt["verdict"] for attempt in item["attempts"]
                                   if attempt["attempt_id"] == attempt_id)
                for item in configurations
            },
        })
    return {"configurations": names, "rows": rows}


def markdown_table(table):
    headings = {
        "isolated_separate": "isolated, separate principals",
        "isolated_shared": "isolated, shared principals",
        "shared_unconfined": "shared custody",
    }
    columns = table["configurations"]
    lines = [
        "| Attempt | " + " | ".join(headings[name] for name in columns) + " |",
        "|---|" + "---|" * len(columns),
    ]
    for row in table["rows"]:
        lines.append(
            f"| {row['attempt_id']} {row['attempt'].replace('_', ' ')} | "
            + " | ".join(row["outcomes"][name] for name in columns) + " |"
        )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Sanitization guard


FORBIDDEN_KEYS = {
    "path", "paths", "url", "target_url", "password", "passwords", "owner_password",
    "session", "session_name", "username", "cookie", "marker", "marker_value",
    "content_sha256", "note", "share_with",
}
FORBIDDEN_KEY_SUFFIXES = ("_path", "_url", "_password")
FORBIDDEN_VALUE_FRAGMENTS = ("/", "http", "alice", "bob", "scourge-m0-tamper",
                            "local.pass", ".teapot")


def assert_sanitized(value, trail="evidence"):
    if isinstance(value, dict):
        for key, item in value.items():
            lowered = key.lower()
            require(lowered not in FORBIDDEN_KEYS,
                    f"unsanitized key at {trail}: {lowered}")
            require(not lowered.endswith(FORBIDDEN_KEY_SUFFIXES),
                    f"unsanitized key at {trail}: {lowered}")
            assert_sanitized(item, f"{trail}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            assert_sanitized(item, f"{trail}[{index}]")
    elif isinstance(value, str):
        for fragment in FORBIDDEN_VALUE_FRAGMENTS:
            require(fragment not in value.lower() if fragment.isalpha()
                    else fragment not in value,
                    f"unsanitized value at {trail}: {fragment}")


def qualification(isolated_separate, configurations, distinct):
    """Assemble the acceptance verdict that the command's exit status follows.

    Every required attempt must be exactly ``refused``. ``unsupported`` means
    the attempt never ran, so it can neither qualify the boundary nor accept
    the run.
    """
    verdicts = attempt_verdicts(isolated_separate)
    value = {
        "isolated_separate_required_outcome": True,
        "isolated_separate_all_attempts_failed": all(
            verdict == "refused" for verdict in verdicts.values()
        ),
        "isolated_separate_verdicts": verdicts,
        "configuration_isolated_separate_qualified": qualified(isolated_separate),
    }
    value["accepted"] = (
        value["configuration_isolated_separate_qualified"]
        and value["isolated_separate_all_attempts_failed"]
        and distinct["proved"]
        and all(item["cleanup"]["engines_stopped"] for item in configurations)
    )
    return value


def exit_status(result):
    """The command is nonzero unless the assembled acceptance verdict is true."""
    return 0 if result["qualified"]["accepted"] else 1


async def evidence(teapot, hallpass, root, hostenv):
    require(digest(teapot) == topology.PIN, "Teapot digest differs from candidate pin")
    require(digest(hallpass) == topology.HALLPASS_PIN,
            "Hallpass digest differs from candidate pin")
    require(topology.run([*topology.PODMAN, "info", "--format",
                          "{{.Host.Security.Rootless}}"], hostenv).strip() == "true",
            "rootless Podman required")
    image = topology.run([*topology.PODMAN, "image", "inspect", "--format", "{{.Id}}", IMAGE],
                         hostenv).strip().removeprefix("sha256:")
    require(valid_cid(image), "invalid cached worker image digest")
    tools = root / "tools"
    tools.mkdir()
    shutil.copyfile(teapot, tools / "teapot")
    (tools / "teapot").chmod(0o700)
    podman_version = tool_version([*topology.PODMAN, "--version"], hostenv)
    rustc_version = tool_version(["rustc", "--version"], hostenv)
    fixture_state = {}
    configurations = []
    with fixture(root, fixture_state) as (package, port):
        fixture_digest = digest(package / "scourge-fixture")
        for name, custody, isolation in CONFIGURATIONS:
            trial = root / name
            trial.mkdir(mode=0o700)
            configurations.append(await configuration(
                name, custody, isolation, package, port, trial, tools, teapot, hallpass,
                image,
            ))
    for item in configurations:
        item["cleanup"]["fixture_stopped"] = fixture_state.get("stopped") is True
    for item in configurations:
        require(item["cleanup"]["engines_stopped"], "engines were not verified stopped")
        require(item["cleanup"]["fixture_stopped"], "fixture was not verified stopped")
    table = outcome_table(configurations)
    isolated_separate = next(item for item in configurations
                             if item["name"] == "isolated_separate")
    distinct = distinctness(configurations)
    result = {
        "schema_version": 1,
        "matrix": "M0.5.3 local custody tamper matrix",
        "recorded_at_utc": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "host": {
            "machine": platform.machine(),
            "kernel": platform.release(),
            "podman": podman_version,
            "rootless": True,
            "worker_image_sha256": image,
            "run_user_uid": os.getuid(),
        },
        "pins": {
            "teapot_sha256": topology.PIN,
            "hallpass_sha256": topology.HALLPASS_PIN,
            "fixture_sha256": fixture_digest,
            "rustc": rustc_version,
            "harness_sha256": digest(Path(__file__)),
            "candidate_topology_sha256": digest(ROOT / "scripts/candidate-topology.py"),
            "payload_sha256": {path.name: digest(path) for path in sorted(ATTEMPTS.glob("*.py"))},
        },
        "limits": list(LIMITATIONS),
        "configurations": configurations,
        "table": {
            "markdown": markdown_table(table),
            "rows": table["rows"],
        },
        "distinct": distinct,
        "hold": hold_decision(configurations),
        "qualified": qualification(isolated_separate, configurations, distinct),
    }
    assert_sanitized(result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--teapot", type=Path, required=True)
    parser.add_argument("--hallpass", type=Path, required=True)
    args = parser.parse_args()
    root = topology.GuardedTemp()

    def interrupt(_signal, _frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, interrupt)
    with root as directory:
        result = asyncio.run(evidence(args.teapot.resolve(), args.hallpass.resolve(),
                                      Path(directory), host_environment()))
        root.keep = False
    print(json.dumps(result, indent=2, sort_keys=True))
    return exit_status(result)


if __name__ == "__main__":
    sys.exit(main())
