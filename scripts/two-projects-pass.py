#!/usr/bin/env python3
"""Observe two Teapot engines sharing one Hallpass ledger, on loopback only."""
import argparse
import datetime as dt
import hashlib
import http.server
import json
import os
import pathlib
import subprocess
import tempfile
import threading

ROOT = pathlib.Path(__file__).resolve().parents[1]
PIN = "6d15d625e10afa768a221f64eb7a2a245a64a7babbe61cf74ce8d4ff33b2f458"

class Handler(http.server.BaseHTTPRequestHandler):
    paths = []
    def do_GET(self):
        self.paths.append(self.path)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")
    def log_message(self, *_args):
        pass

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--teapot", required=True, type=pathlib.Path)
    parser.add_argument("--hallpass", required=True, type=pathlib.Path)
    args = parser.parse_args()
    teapot, hallpass = args.teapot.resolve(), args.hallpass.resolve()
    digest = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
    assert digest(teapot) == PIN == json.loads((ROOT / "fixtures/contracts/manifest.json").read_text())["binary_sha256"]
    print(json.dumps({"teapot_sha256": digest(teapot), "hallpass_sha256": digest(hallpass)}), flush=True)
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with tempfile.TemporaryDirectory(prefix="scourge-two-pass-") as tmp:
            root = pathlib.Path(tmp)
            env = dict(os.environ, HOME=tmp, XDG_CONFIG_HOME=str(root / "config"), XDG_STATE_HOME=str(root / "state"), XDG_DATA_HOME=str(root / "data"), NO_COLOR="1")
            for key in ("TEAPOT_PASS", "TEAPOT_ENFORCED", "TEAPOT_PLAYPEN", "TEAPOT_DETACHED"):
                env.pop(key, None)
            def run(label, argv):
                p = subprocess.run([str(x) for x in argv], capture_output=True, text=True, env=env, timeout=30)
                print(json.dumps({"step": label.replace(tmp, "$TMP"), "argv": [str(x).replace(tmp, "$TMP") for x in argv[1:]], "exit": p.returncode, "stdout": p.stdout.replace(tmp, "$TMP"), "stderr": p.stderr.replace(tmp, "$TMP")}), flush=True)
                if p.returncode:
                    raise RuntimeError(f"{label} failed: {p.returncode}")
                return p.stdout
            passfile = root / "loopback.pass.toml"
            run("init", [hallpass, "init", passfile])
            now = dt.datetime.now(dt.timezone.utc)
            stamp = lambda t: t.strftime("%Y-%m-%dT%H:%M:%SZ")
            passfile.write_text(f"""format = 1
id = "scourge-two-projects"
name = "Scourge loopback experiment"
[approval]
owner = "local experiment"
reference = "bn-2cv"
operator = "local experiment"
valid_from = {stamp(now - dt.timedelta(hours=1))}
valid_until = {stamp(now + dt.timedelta(days=1))}
revoked = false
[[destination]]
label = "local"
address = "127.0.0.1"
protocol = "tcp"
ports = {server.server_port}
[ceilings]
requests = 100
""")
            os.chmod(passfile, 0o600)
            print(json.dumps({"pass_sha256": digest(passfile), "pass_contents": passfile.read_text()}), flush=True)
            run("pass-check", [hallpass, "check", passfile, "--json"])
            projects = [root / "one", root / "two"]
            def tp(i, *words):
                return run(f"{i+1}:" + " ".join(words), [teapot, "--project", projects[i], "--json", *words])
            def snap(label):
                ledger = json.loads(run(label + ":ledger", [hallpass, "ledger", passfile, "--json"]))
                expected = {"before": 0, "after-1": 10, "after-2": 20, "stopped": 20}[label]
                assert ledger["verified"] and ledger["totals"][0]["spent"] == expected
                assert ledger["digest"] == "sha256:" + digest(passfile)
                for i in range(2):
                    show = json.loads(tp(i, "pass", "show"))["pass"]
                    assert show["digest"] == ledger["digest"]
                    status = json.loads(tp(i, "proxy", "status"))["proxy"]
                    if label != "stopped":
                        assert status["engine"]["pass"] == str(passfile)
                        assert status["health"]["requests"]["handed"] == (1 if (label == "after-2" or label == "after-1" and i == 0) else 0)
                    else:
                        assert show["ceilings"][0]["unused"] == 9
            started = []
            try:
                for i, project in enumerate(projects):
                    project.mkdir()
                    tp(i, "projects", "init")
                    tp(i, "pass", "attach", str(passfile))
                    tp(i, "proxy", "start", "--listen", "127.0.0.1:0", "--detach", "--pass", str(passfile), "--no-enforce")
                    started.append(i)
                    tp(i, "scope", "add", "127.0.0.1")
                snap("before")
                for i in range(2):
                    tp(i, "requests", "send", "GET", f"http://127.0.0.1:{server.server_port}/project-{i+1}")
                    snap(f"after-{i+1}")
                assert Handler.paths == ["/project-1", "/project-2"], Handler.paths
                print(json.dumps({"target_paths": Handler.paths}), flush=True)
            finally:
                for i in reversed(started):
                    tp(i, "proxy", "stop")
                if len(started) == 2:
                    snap("stopped")
    finally:
        server.shutdown()
        server.server_close()
        thread.join()

if __name__ == "__main__":
    main()
