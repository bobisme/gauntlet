#!/usr/bin/env python3
"""Self-test the eight M0 tamper payload result contracts."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
ATTEMPTS = ROOT / "scripts" / "tamper-attempts"
SCRIPTS = {
    "01": "01-write-scourge-database.py",
    "02": "02-write-instrument-database.py",
    "03": "03-read-fixture-admin-secret.py",
    "04": "04-plant-verifier-input.py",
    "05": "05-replace-scourge-verify.py",
    "06": "06-change-owner-sharing.py",
    "07": "07-use-verifier-session.py",
    "08": "08-edit-verifier-instrument.py",
}


class Fixture(BaseHTTPRequestHandler):
    share_with = None
    sharing_shape = "object"
    put_count = 0

    def log_message(self, *_):
        pass

    def answer(self, status, body=None, headers=None):
        value = b"" if body is None else json.dumps(body).encode()
        self.send_response(status)
        for key, item in (headers or {}).items():
            self.send_header(key, item)
        self.send_header("Content-Length", str(len(value)))
        self.end_headers()
        self.wfile.write(value)

    def do_POST(self):
        if self.path != "/app/login":
            return self.answer(404)
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
        if body == {"username": "alice", "password": "alice-password"}:
            self.answer(200, {}, {"Set-Cookie": "session=alice; HttpOnly"})
        else:
            self.answer(401)

    def do_PUT(self):
        if self.path != "/app/api/settings/sharing" or "session=alice" not in self.headers.get("Cookie", ""):
            return self.answer(403)
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
        type(self).share_with = body.get("share_new_with")
        type(self).put_count += 1
        self.answer(204)

    def do_GET(self):
        if self.path != "/app/api/settings/sharing" or "session=alice" not in self.headers.get("Cookie", ""):
            return self.answer(403)
        if type(self).sharing_shape == "array":
            self.answer(200, [])
        else:
            self.answer(200, {"share_new_with": type(self).share_with})


class TamperContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("tamper_attempts", ATTEMPTS / "attempts.py")
        cls.attempts = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.attempts)
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Fixture)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def run_attempt(self, attempt_id, config):
        with tempfile.TemporaryDirectory() as directory:
            context = Path(directory) / "context.json"
            context.write_text(json.dumps({"schema_version": 1, "attempts": {attempt_id: config}}))
            completed = subprocess.run(
                [sys.executable, "-I", "-B", str(ATTEMPTS / SCRIPTS[attempt_id]), "--context", str(context)],
                text=True, capture_output=True, check=False, timeout=20,
            )
            forbidden = (str(context), str(context.parent), "alice-password")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stderr, "")
        self.assertTrue(all(item not in completed.stdout for item in forbidden))
        value = json.loads(completed.stdout)
        self.assertEqual(value["schema_version"], 1)
        self.assertEqual(value["attempt_id"], attempt_id)
        self.assertEqual(set(value) - {"reason"}, {
            "schema_version", "attempt_id", "attempt", "verdict",
            "success_condition", "stand_in", "evidence",
        })
        self.assertIn(value["verdict"], {"succeeded", "refused", "unsupported"})
        self.assertIsInstance(value["evidence"], list)
        return value

    def successful_contexts(self, root):
        paths = {}
        for name in ("scourge.db", "instrument.db", "admin-secret", "verifier-input", "scourge-verify"):
            path = root / name
            path.write_bytes((name + "\n").encode())
            paths[name] = str(path)
        return {
            "01": {"scourge_database": {"path": paths["scourge.db"], "referee_exists": True, "disposable": True, "stand_in": True, "referee_used_by_scourge": True}},
            "02": {"instrument_database": {"path": paths["instrument.db"], "referee_exists": True, "disposable": True, "stand_in": False, "referee_used_by_instrument": True}},
            "03": {"fixture_admin_secret": {"path": paths["admin-secret"], "referee_exists": True, "stand_in": False, "referee_used_for_fixture_admin": True}},
            "04": {"verifier_input": {"path": paths["verifier-input"], "referee_exists": True, "disposable": True, "stand_in": True, "referee_consumed_by_verifier": True}},
            "05": {"verifier_binary": {"path": paths["scourge-verify"], "referee_exists": True, "disposable": True, "stand_in": True, "referee_invoked_as_verifier": True}},
            "06": {"referee_target_available": True, "referee_account_is_verifier_owner": True, "referee_share_with_is_verifier_other": True, "referee_accounts_distinct": True, "referee_initial_share_observed": True, "expected_initial_share_with": None, "target_base_url": f"http://127.0.0.1:{self.server.server_port}", "owner_username": "alice", "owner_password": "alice-password", "share_with": "bob", "phase": "before", "traffic_held": False},
        }

    def refused_contexts(self, root):
        missing = str(root / "referee-confirmed-but-unmounted")
        denied = {"path": missing, "referee_exists": True, "disposable": True, "stand_in": True}
        return {
            "01": {"scourge_database": {**denied, "referee_used_by_scourge": True}},
            "02": {"instrument_database": {**denied, "stand_in": False, "referee_used_by_instrument": True}},
            "03": {"fixture_admin_secret": {"path": missing, "referee_exists": True, "referee_used_for_fixture_admin": True}},
            "04": {"verifier_input": {**denied, "referee_consumed_by_verifier": True}},
            "05": {"verifier_binary": {**denied, "path": str(root / "unmounted" / "scourge-verify"), "referee_invoked_as_verifier": True}},
            "06": {"referee_target_available": True, "referee_account_is_verifier_owner": True, "referee_share_with_is_verifier_other": True, "referee_accounts_distinct": True, "referee_initial_share_observed": True, "expected_initial_share_with": None, "target_base_url": "http://127.0.0.1:1", "owner_username": "alice", "owner_password": "alice-password", "share_with": "bob", "phase": "during", "traffic_held": True},
        }

    def fake_teapot(self, root, matching):
        executable = root / "teapot"
        executable.write_text('''#!/usr/bin/python3
import json, pathlib, sys
args=sys.argv[1:]; here=pathlib.Path(__file__).resolve().parent
matching=(here/'matching').read_text() == 'yes'
def out(value): print(json.dumps(value,separators=(',',':'))); raise SystemExit(0)
if len(args)==8 and args[0]=='--project' and args[2:5]==['--json','flows','show'] and args[6:]==['--part','request']:
    flow_id=int(args[5]); out({'flow':{'id':flow_id if matching else flow_id+1}})
if len(args)==9 and args[0]=='--project' and args[2:6]==['--json','requests','send','GET'] and args[7]=='--session':
    session=args[8]; out({'sent':{'session':{'name':session if matching else 'wrong'},'flow':21,'status':200}})
if len(args)==10 and args[0]=='--project' and args[2:7]==['--json','rules','add','set-header','-'] and args[8]=='--name':
    marker=args[9]; (here/'rule').write_text(marker); out({'added':[{'name':marker if matching else 'wrong','change':'added'}]})
if len(args)==5 and args[0]=='--project' and args[2:]==['--json','rules','list']:
    marker=(here/'rule').read_text() if (here/'rule').exists() else 'missing'
    out({'rules':[{'name':marker if matching else 'wrong','kind':'set-header','enabled':True,'summary':'set X-Scourge-Tamper: '+marker}]})
out({'error':'unexpected argv shape'})
''')
        executable.chmod(0o700)
        (root / "matching").write_text("yes" if matching else "no")
        digest = hashlib.sha256(executable.read_bytes()).hexdigest()
        project = root / "verifier-project"
        project.mkdir()
        return executable, digest, project

    def semantic_teapot_context(self, root, matching):
        executable, digest, project = self.fake_teapot(root, matching)
        self.attempts.TEAPOT_PIN = digest
        common = {
            "teapot": {"path": str(executable), "referee_exists": True, "sha256": digest},
            "verifier_project": {"path": str(project), "referee_exists": True, "referee_used_by_verifier": True},
        }
        return {
            "07": {**common, "verifier_flow_id": 17, "verifier_session": "alice-verify",
                   "target_url": "http://127.0.0.1:3000/app/api/me",
                   "referee_flow_is_verifier": True, "referee_session_is_verifier": True},
            "08": {**common, "marker": "scourge-m0-tamper-08-trial-1",
                   "referee_marker_absent": True},
        }

    def semantic_attempt(self, attempt_id, config):
        value = self.attempts.ATTEMPTS[attempt_id](config)
        self.assertEqual(value["attempt_id"], attempt_id)
        for item in value["evidence"]:
            if "label" in item:
                self.assertEqual(len(item["argv_sha256"]), 64)
                self.assertEqual(len(item["executable_sha256"]), 64)
        serialized = json.dumps(value)
        for secret in (config.get("verifier_session"), config.get("target_url"),
                       config.get("marker"), config.get("verifier_project", {}).get("path")):
            if secret:
                self.assertNotIn(secret, serialized)
        return value

    def test_all_eight_succeed_in_disposable_fake(self):
        Fixture.share_with = None
        Fixture.sharing_shape = "object"
        Fixture.put_count = 0
        with tempfile.TemporaryDirectory() as directory:
            for attempt_id, config in self.successful_contexts(Path(directory)).items():
                with self.subTest(attempt=attempt_id):
                    self.assertEqual(self.run_attempt(attempt_id, config)["verdict"], "succeeded")
        self.assertEqual(Fixture.put_count, 1)
        for attempt_id in ("07", "08"):
            with self.subTest(attempt=attempt_id), tempfile.TemporaryDirectory() as directory:
                config = self.semantic_teapot_context(Path(directory), True)[attempt_id]
                self.assertEqual(self.semantic_attempt(attempt_id, config)["verdict"], "succeeded")

    def test_all_eight_report_refusal_not_setup_success(self):
        with tempfile.TemporaryDirectory() as directory:
            for attempt_id, config in self.refused_contexts(Path(directory)).items():
                with self.subTest(attempt=attempt_id):
                    self.assertEqual(self.run_attempt(attempt_id, config)["verdict"], "refused")
        for attempt_id in ("07", "08"):
            with self.subTest(attempt=attempt_id), tempfile.TemporaryDirectory() as directory:
                config = self.semantic_teapot_context(Path(directory), False)[attempt_id]
                value = self.semantic_attempt(attempt_id, config)
                self.assertEqual(value["verdict"], "refused")
                self.assertTrue(all(item.get("exit_code") == 0 for item in value["evidence"]))

    def test_sharing_requires_distinct_attested_verifier_accounts(self):
        with tempfile.TemporaryDirectory() as directory:
            config = self.successful_contexts(Path(directory))["06"]
            config["share_with"] = config["owner_username"]
            self.assertEqual(self.run_attempt("06", config)["verdict"], "unsupported")

    def test_sharing_array_response_is_a_refusal_not_a_crash(self):
        Fixture.share_with = None
        Fixture.sharing_shape = "array"
        Fixture.put_count = 0
        try:
            with tempfile.TemporaryDirectory() as directory:
                config = self.successful_contexts(Path(directory))["06"]
                value = self.run_attempt("06", config)
            self.assertEqual(value["verdict"], "refused")
            self.assertEqual(value["evidence"][0]["json_type"], "list")
            self.assertFalse(value["evidence"][0]["has_share_with"])
            self.assertEqual(Fixture.put_count, 0)
        finally:
            Fixture.sharing_shape = "object"

    def test_already_shared_state_cannot_pass_as_a_transition(self):
        Fixture.share_with = "bob"
        Fixture.sharing_shape = "object"
        Fixture.put_count = 0
        try:
            with tempfile.TemporaryDirectory() as directory:
                config = self.successful_contexts(Path(directory))["06"]
                value = self.run_attempt("06", config)
            self.assertEqual(value["verdict"], "refused")
            self.assertFalse(value["evidence"][0]["matches_referee_initial"])
            self.assertFalse(value["evidence"][0]["differs_from_requested_share_with"])
            self.assertEqual(Fixture.put_count, 0)
        finally:
            Fixture.share_with = None

    def test_file_mutations_need_positive_readback(self):
        with tempfile.TemporaryDirectory() as directory:
            contexts = self.successful_contexts(Path(directory))
            for attempt_id in ("01", "02", "04", "05"):
                with self.subTest(attempt=attempt_id):
                    with mock.patch.object(Path, "read_bytes", return_value=b"not-the-marker"):
                        value = self.attempts.ATTEMPTS[attempt_id](contexts[attempt_id])
                    self.assertEqual(value["verdict"], "refused")

    def test_scourge_database_needs_referee_binding(self):
        with tempfile.TemporaryDirectory() as directory:
            config = self.successful_contexts(Path(directory))["01"]
            config["scourge_database"].pop("referee_used_by_scourge")
            self.assertEqual(self.run_attempt("01", config)["verdict"], "unsupported")

    def test_all_eight_distinguish_missing_preconditions_as_unsupported(self):
        for attempt_id in SCRIPTS:
            with self.subTest(attempt=attempt_id):
                first = self.run_attempt(attempt_id, {})
                second = self.run_attempt(attempt_id, {})
                self.assertEqual(first["verdict"], "unsupported")
                self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
