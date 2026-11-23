#!/usr/bin/env python3
"""Exercise the public example against the actual external package on Linux."""

import http.client
import json
import os
from collections import namedtuple
from functools import partial
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import tomllib
from urllib.parse import urlsplit
from uuid import uuid4

from referee.check_catalog import check_catalog


FIXTURE = Path(__file__).resolve().parent


def load_toml(path):
    with path.open("rb") as source:
        return tomllib.load(source)


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def launch_command(package_dir, agent_tree):
    return [sys.executable, str(FIXTURE / "package.py"),
            "--package-dir", str(package_dir), "--agent-tree", str(agent_tree)]


def check_rejected_paths(parent, agent_tree):
    alias = parent / "alias-to-agent"
    alias.symlink_to(agent_tree, target_is_directory=True)
    package = parent / "target"

    def check_rejected(package_dir, tree, message):
        result = subprocess.run(launch_command(package_dir, tree), cwd=parent,
                                capture_output=True, text=True, timeout=10, check=False)
        require(result.returncode == 2 and message in result.stderr,
                "launcher accepted an overlapping or linked checkout or package")
        require(not package_dir.exists(), "invalid launch created a package directory")

    for package_dir, tree in [(agent_tree / "target", agent_tree),
                              (alias / "target", agent_tree), (package, FIXTURE.parents[1])]:
        check_rejected(package_dir, tree, "must be outside the agent tree")

    private_alias = agent_tree / "private-alias"
    for target in (package / "admin-secret", FIXTURE):
        private_alias.symlink_to(target)
        check_rejected(package, agent_tree, "the agent tree links to the checkout or package")
        private_alias.unlink()


def wait_for_listener(process, log, authority):
    expected = f"fixture  listening  http://{authority}"
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        output = log.read_text()
        if expected in output.splitlines():
            return
        require(process.poll() is None, f"fixture exited during startup\n{output}")
        time.sleep(0.1)
    raise RuntimeError("timed out building or starting the fixture")


def check_boundary(process, package_dir, agent_tree, visible, log):
    paths = {"scourge-fixture": 0o700, "ground-truth.json": 0o600, "admin-secret": 0o600}
    require({entry.name for entry in package_dir.iterdir()} == set(paths),
            "the package should contain only the executable, ground truth and secret")
    require(stat.S_IMODE(package_dir.stat().st_mode) == 0o700, "package directory is not private")
    require(set(agent_tree.rglob("*")) == visible, "launcher wrote into the agent tree")
    for name, mode in paths.items():
        path = package_dir / name
        entry = path.lstat()
        require(path.resolve(strict=True).parent == package_dir
                and not path.resolve().is_relative_to(agent_tree)
                and stat.S_ISREG(entry.st_mode) and stat.S_IMODE(entry.st_mode) == mode
                and entry.st_uid == os.geteuid(), f"invalid location, owner or mode for {name}")

    proc_dir = Path(f"/proc/{process.pid}")
    require((proc_dir / "exe").resolve(strict=True) == package_dir / "scourge-fixture",
            "the live executable is not the installed binary")
    require((proc_dir / "cwd").resolve(strict=True) == package_dir,
            "the live fixture did not enter the external package directory")
    secret = (package_dir / "admin-secret").read_text().rstrip("\n")
    require(re.fullmatch(r"[0-9a-f]{64}", secret), "invalid generated administration secret")
    for data in ((proc_dir / "cmdline").read_bytes(), (proc_dir / "environ").read_bytes(),
                 log.read_bytes()):
        require(secret.encode("ascii") not in data, "secret leaked into process metadata or logs")
    return secret


Reply = namedtuple("Reply", ["status", "headers", "body"])


def request_http(authority, request, *, cookie=None, body=None, headers=()):
    conn = http.client.HTTPConnection(authority, timeout=5)
    method, path = request.split(" ", 1)
    try:
        conn.putrequest(method, path)
        for header, value in headers:
            conn.putheader(header, value)
        if cookie:
            conn.putheader("Cookie", cookie)
        if body is not None:
            body = json.dumps(body).encode()
            if not any(name.lower() == "content-type" for name, _ in headers):
                conn.putheader("Content-Type", "application/json")
            conn.putheader("Content-Length", str(len(body)))
        conn.endheaders(body)
        response = conn.getresponse()
        return Reply(response.status, response.headers, response.read())
    finally:
        conn.close()


def send(authority, request, *, status, **options):
    reply = request_http(authority, request, **options)
    require(reply.status == status, f"{request}: expected {status}, got {reply.status}")
    return json.loads(reply.body) if reply.body else None, reply.headers


def login(authority, username):
    _, headers = send(authority, "POST /app/login", status=200,
                      body={"username": username, "password": f"{username}-password"})
    return headers["Set-Cookie"].split(";", 1)[0]


def field_values(fields):
    return {field.removeprefix("/"): uuid4().hex for field in fields}


def check_engagement(authority, engagement, macros):
    owner, other = engagement["principal"].values()
    sessions = {}
    for principal in engagement["principal"].values():
        probe = principal["identity_probe"]
        for user in (principal["session"], principal["verifier_session"]):
            cookie = login(authority, user)
            identity, _ = send(authority, probe["request"], status=200, cookie=cookie)
            require(identity[probe["subject"].removeprefix("/")] == f"user-{user}",
                    "identity probe returned the wrong subject")
            sessions[user] = cookie

    owner_cookie = sessions[owner["session"]]
    cleanup_cookie = login(authority, owner["session"])
    readers = {
        "owner": owner_cookie,
        "group": sessions[owner["verifier_session"]],
        "authenticated": sessions[other["session"]],
        "public": None,
    }
    for name, resource in engagement["property"].items():
        plant = resource["plant"]
        macro = load_toml(macros / (plant["macro"] + ".toml"))
        [step] = macro["steps"]
        [extract] = step["extract"]
        require(step["state_changing"] and extract["from"] == "json_pointer"
                and extract["expr"] == plant["id_from"], f"incorrect plant or extract for {name}")
        request = step["request"]
        url = urlsplit(request["url"])
        require(url.scheme == "http" and url.netloc == authority and not (url.query or url.fragment),
                f"plant macro for {name} is outside the sample pass")
        fields = field_values(plant["fields"])
        template = json.loads(request["body"]["text"])
        require(template.keys() == fields.keys(), f"unbound plant fields for {name}")
        spawned, _ = send(authority, f'{request["method"]} {url.path}', status=201,
                          cookie=owner_cookie, body=fields, headers=request["headers"])
        object_id = spawned[plant["id_from"].removeprefix("/")]

        write = resource.get("write")
        if write:
            fields = field_values(write["fields"])
            send(authority, write["request"].format(id=object_id), status=204,
                 cookie=owner_cookie, body=fields)
        reader = readers[resource["readers"]]
        observed, _ = send(authority, resource["read"].format(id=object_id), status=200, cookie=reader)
        if name == "echo_reports":
            require(fields["note"] in observed["echoes"], "echo request did not return submitted text")
        else:
            require(observed == fields, f"readback did not match the planted or updated fields for {name}")
        send(authority, resource["remove"].format(id=object_id), status=204, cookie=cleanup_cookie)


def main():
    with tempfile.TemporaryDirectory(prefix="scourge-fixture-check-") as tmp:
        parent = Path(tmp).resolve()
        agent_tree = parent / "agent"
        shutil.copytree(FIXTURE / "example", agent_tree)
        macros = agent_tree / "teapot-project" / ".teapot" / "macros"
        shutil.copytree(FIXTURE / "teapot", macros)
        visible = set(agent_tree.rglob("*"))
        engagement = load_toml(agent_tree / "engagement.toml")
        hallpass = load_toml(agent_tree / engagement["engagement"]["pass"])
        [destination] = hallpass["destination"]
        require(destination == {"label": "development-fixture", "address": "127.0.0.1",
                                "protocol": "tcp", "ports": [3000]}, "invalid sample pass scope")
        authority = f'{destination["address"]}:{destination["ports"][0]}'
        check_rejected_paths(parent, agent_tree)

        package_dir = parent / "referee-target"
        log = parent / "startup.log"
        with log.open("w") as output, subprocess.Popen(
            launch_command(package_dir, agent_tree), cwd=parent, stdout=output, stderr=output,
            start_new_session=True,
        ) as process:
            try:
                wait_for_listener(process, log, authority)
                secret = check_boundary(process, package_dir, agent_tree, visible, log)
                truth = json.loads((package_dir / "ground-truth.json").read_text())
                require(truth["schema_version"] == 1 and truth["fixture"] == "scourge-fixture",
                        "unexpected packaged ground truth")
                properties = {case["property"] for kind in ("flaws", "controls", "decoys")
                              for case in truth[kind].values() if "property" in case}
                require(engagement["property"].keys() == properties,
                        "the engagement must declare every resource class in the fixture")
                check_engagement(authority, engagement, macros)
                check_catalog(truth, engagement, partial(request_http, authority),
                              partial(login, authority), secret)
            finally:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGINT)
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid, signal.SIGKILL)
                        process.wait(timeout=5)
        print(f"Validated {len(engagement['property'])} resource classes, identity probes, "
              "the referee catalog and the external package")


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, ValueError) as error:
        sys.exit(f"error: {error}")
