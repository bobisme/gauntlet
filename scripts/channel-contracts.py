#!/usr/bin/env python3
"""Probe source-pinned Teapot send behavior against an isolated loopback server."""
import argparse
import base64
import hashlib
import http.client
import http.server
import json
import os
import pathlib
import subprocess
import tempfile
import threading

ROOT = pathlib.Path(__file__).resolve().parents[1]

class Handler(http.server.BaseHTTPRequestHandler):
    records = []
    def handle_request(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0"))).decode()
        self.records.append({"method": self.command, "path": self.path, "body": body,
                             "x_hook": self.headers.get("X-Hook")})
        status = 401 if self.path in ("/expired-get", "/expired-post") else 200
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"original")
    do_GET = handle_request
    do_POST = handle_request
    def log_message(self, *_args):
        pass

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, type=pathlib.Path)
    args = parser.parse_args()
    binary = args.binary.resolve()
    manifest = json.loads((ROOT / "fixtures/contracts/manifest.json").read_text())
    inventory = json.loads((ROOT / "docs/inventory.json").read_text())
    assert next(x for x in inventory["tools"] if x["tool"] == "teapot")["checkout"]["head"] == manifest["source_commit"]
    assert hashlib.sha256(binary.read_bytes()).hexdigest() == manifest["binary_sha256"]
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_port}"
    try:
        with tempfile.TemporaryDirectory(prefix="scourge-channel-") as directory:
            root = pathlib.Path(directory)
            project = root / "project"
            project.mkdir()
            env = dict(os.environ, XDG_CONFIG_HOME=str(root / "config"), XDG_STATE_HOME=str(root / "state"), XDG_DATA_HOME=str(root / "data"))
            def run(*words):
                cmd = [str(binary), "--project", str(project), "--json", *words]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=20, env=env)
                if result.returncode:
                    raise RuntimeError(f"{words}: {result.returncode} {result.stdout} {result.stderr}")
                return json.loads(result.stdout)
            run("projects", "init")
            run("proxy", "start", "--listen", "127.0.0.1:0", "--detach")
            try:
                run("scope", "add", "127.0.0.1")
                listener = run("proxy", "status")["proxy"]["engine"]["listener"]
                host, port = listener.rsplit(":", 1)
                def proxy_get(path):
                    conn = http.client.HTTPConnection(host, int(port), timeout=5)
                    conn.request("GET", url + path)
                    response = conn.getresponse()
                    result = response.read(), dict(response.getheaders())
                    conn.close()
                    return result
                run("rules", "add", "replace", "-", "original", "replaced", "--direction", "response")
                assert proxy_get("/rule-control")[0] == b"replaced"
                sent = run("requests", "send", "GET", url + "/rule")
                flow = run("flows", "show", str(sent["sent"]["flow"]), "--base64", "--stored")
                assert base64.b64decode(flow["flow"]["response_body_base64"]) == b"original"
                print("rule: stored response original")
                run("rules", "remove", "1")
                run("intercept", "rules", "add", "-")
                run("intercept", "on")
                status = run("intercept", "status")["intercept"]
                assert status["enabled"] and status["active_rules"] == 1
                intercepted = run("requests", "send", "GET", url + "/intercept")
                assert intercepted["sent"]["status"] == 200
                assert run("intercept", "status")["intercept"]["paused"] == 0
                print("intercept: send completed, status 200")
                run("intercept", "off")
                scripts = root / "config/teapot/scripts"
                scripts.mkdir(parents=True)
                script = scripts / "contract.lua"
                for side in ("request", "response"):
                    script.write_text(f'local t = require("teapot")\nt.on("{side}", function(f) f.{side}.headers:set("X-Hook", "yes") end)\n')
                    reload = run("scripts", "reload")["reload"]
                    hook = next(x for x in reload["scripts"] if x["name"] == "contract")
                    assert hook["state"] == "running" and [x["event"] for x in hook["hooks"]] == [side]
                    _, headers = proxy_get("/hook-control-" + side)
                    if side == "request":
                        assert Handler.records[-1]["x_hook"] == "yes"
                    else:
                        assert {k.lower(): v for k, v in headers.items()}["x-hook"] == "yes"
                    sent = run("requests", "send", "GET", url + "/hook-" + side)
                    hook_flow = run("flows", "show", str(sent["sent"]["flow"]), "--base64", "--stored")["flow"]
                    assert "x-hook" not in hook_flow["response_head"].lower()
                    assert Handler.records[-1]["x_hook"] is None
                    print("hook-" + side + ": proxy control changed, send unchanged")
                run("sessions", "create", "alice")
                (project / ".teapot/macros/login.toml").write_text(f"format = 1\n\n[[steps]]\nstate_changing = false\n[steps.request]\nmethod = \"GET\"\nurl = \"{url}/login\"\n")
                run("sessions", "set", "alice", "--login", "login", "--logged-out", "status:401")
                for method in ("POST", "GET"):
                    if method == "GET":
                        run("sessions", "create", "bob")
                        run("sessions", "set", "bob", "--login", "login", "--logged-out", "status:401")
                    session = "alice" if method == "POST" else "bob"
                    before = len(Handler.records)
                    relogin = run("requests", "send", method, url + "/expired-" + method.lower(), "--session", session)["sent"]["relogin"]
                    records = Handler.records[before:]
                    assert [(x["method"], x["path"]) for x in records] == ([("POST", "/expired-post"), ("GET", "/login")] if method == "POST" else [("GET", "/expired-get"), ("GET", "/login"), ("GET", "/expired-get")])
                    assert relogin["retried"] == (method == "GET")
                    print("session-" + method, json.dumps({"relogin": relogin, "records": records}, sort_keys=True))
                print("records", json.dumps(Handler.records, sort_keys=True))
            finally:
                run("proxy", "stop")
    finally:
        server.shutdown()
        server.server_close()
        thread.join()

if __name__ == "__main__":
    main()
