#!/usr/bin/env python3
"""Exercise actual CLI consumers, offline. See docs/hallpass-three-copies.md."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parent.parent
parser = argparse.ArgumentParser()
for name in ("hallpass", "playpen", "teapot"):
    parser.add_argument("--" + name, type=Path, required=True)
args = parser.parse_args()
bins = {name: getattr(args, name).resolve(strict=True) for name in ("hallpass", "playpen", "teapot")}

def sha(path):
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()

with tempfile.TemporaryDirectory(prefix="scourge-pass-contract-") as directory:
    tmp = Path(directory)
    home = tmp / "home"
    home.mkdir()
    project = tmp / "project"
    project.mkdir()
    env = {"HOME": str(home), "XDG_CONFIG_HOME": str(home / "config"),
           "XDG_DATA_HOME": str(home / "data"), "XDG_CACHE_HOME": str(home / "cache"),
           "PATH": "/usr/bin:/bin", "LANG": "C"}
    def run(name, *argv):
        proc = subprocess.run([str(bins[name]), *map(str, argv)], cwd=tmp, env=env,
                              text=True, capture_output=True, timeout=30)
        if proc.returncode:
            raise RuntimeError(f"{name} {argv}: exit {proc.returncode}: {proc.stderr} {proc.stdout}")
        return json.loads(proc.stdout)

    # init creates the file securely; the synthetic text is the filled-in template.
    passfile = tmp / "pass.toml"
    init = subprocess.run([str(bins["hallpass"]), "init", str(passfile)], cwd=tmp,
                          env=env, text=True, capture_output=True, timeout=30, check=True)
    del init
    passfile.write_bytes((root / "fixtures/contracts/hallpass-three-copies.pass.toml").read_bytes())
    passfile.chmod(0o600)
    digest = sha(passfile)
    hall = run("hallpass", "--format", "json", "check", passfile)
    assert hall["result"] == "ok" and hall["digest"] == digest
    play = run("playpen", "plan", "--format", "json", "--pass", passfile, "--", "/bin/true")
    assert play["plan"]["pass"]["digest"] == digest
    assert "192.0.2.10:443/tcp" in play["plan"]["allowed"]
    run("teapot", "projects", "init", "--project", project, "--json")
    attached = run("teapot", "pass", "attach", passfile, "--project", project, "--json")
    assert attached["attached"]["id"] == "scourge-contract"
    shown = run("teapot", "pass", "show", "--project", project, "--json")
    assert shown["pass"]["state"] == "bound" and shown["pass"]["digest"] == digest
    decision = run("teapot", "pass", "check", "192.0.2.10:443", "--project", project, "--json")
    assert decision["check"]["verdict"] == "allowed"
    print(json.dumps({"schema_version": 1, "fixture_digest": digest,
        "binaries": {name: sha(path) for name, path in bins.items()},
        "hallpass": {"result": hall["result"], "digest": hall["digest"]},
        "playpen": {"digest": play["plan"]["pass"]["digest"],
                    "allowed": play["plan"]["allowed"], "coverage": play["plan"]["pass"]["coverage"]},
        "teapot": {"digest": shown["pass"]["digest"], "state": shown["pass"]["state"],
                   "window": shown["pass"]["window"], "check": decision["check"]["verdict"]}}, indent=2))
