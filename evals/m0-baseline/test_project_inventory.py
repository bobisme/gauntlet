#!/usr/bin/env python3
"""Regression fixtures for the fail-closed M0 Teapot inventory projector."""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import project_inventory as subject


ROOT = Path(__file__).resolve().parents[2]
EVIDENCE = ROOT / "evals/m0-baseline/qualification/evidence"


def wrapped(key, value, advice=None):
    return {key: value, "advice": advice or []}


def fresh_inventory(tag):
    """Representative raw inventory from a fresh pinned-binary project.

    The two tags model separate runs. Stable state is equal; paths, ids, ports,
    timestamps, storage, WAL, log, fd, task, uptime and performance samples vary.
    """
    run = "a" if tag == "a" else "b"
    project = f"/tmp/scourge-baseline-{run}/project"
    state = f"/tmp/scourge-baseline-{run}/state"
    project_id = "1" * 32 if run == "a" else "2" * 32
    instance = "3" * 32 if run == "a" else "4" * 32
    pid = 41001 if run == "a" else 52002
    port = 31001 if run == "a" else 42002
    started = "2026-11-23T01:00:00Z" if run == "a" else "2026-11-23T02:00:00Z"
    digest = "sha256:" + ("a" * 64 if run == "a" else "b" * 64)
    pass_id = f"baseline-{run}"
    pass_path = f"/tmp/scourge-baseline-{run}/approval.toml"
    engine = {
        "build": "0.1.0",
        "control_socket": f"{state}/teapot/run/{project_id}/control.sock",
        "enforced": False,
        "instance": instance,
        "listener": f"127.0.0.1:{port}",
        "mode": "regular",
        "pass": pass_path,
        "pid": pid,
        "policy_locked": True,
        "project": project,
        "project_id": project_id,
        "started_at": started,
    }
    watch = {
        "checks": 1 if run == "a" else 3,
        "last_check_at": started,
        "last_edit": None,
        "period_ms": 1000,
    }
    gate_pass = {
        "current_digest": digest,
        "destinations": 1,
        "digest": digest,
        "id": pass_id,
        "name": "M0 baseline",
        "operator": "local evaluation",
        "owner": "local evaluation",
        "path": pass_path,
        "reference": "bn-2wv",
        "valid_from": started,
        "valid_until": "2026-11-24T03:00:00Z" if run == "a" else "2026-11-24T04:00:00Z",
        "window": "valid",
    }
    proxy = {
        "engine": engine,
        "health": {
            "at": started,
            "browser": {"listeners": [], "refused_own_traffic": 0},
            "capture": {
                "estimated_store_bytes": 500000 if run == "a" else 600000,
                "flows_not_captured": 0,
                "free_bytes": 1000000 if run == "a" else 900000,
                "gc_bytes_freed": 0,
                "gc_errors": 0,
                "gc_paused": 0,
                "gc_runs": 0,
                "max_store_bytes": 21474836480,
                "min_free_bytes": 1073741824,
                "probe_error": None,
                "reason": None,
                "reason_text": None,
                "resumes": 0,
                "since": started,
                "state": "capturing",
                "store_bytes": 475136 if run == "a" else 512000,
                "warning": None,
                "writer": {
                    "busy_retries": 0,
                    "committed_batches": 1 if run == "a" else 2,
                    "committed_records": 1 if run == "a" else 3,
                    "discarded_records": 0,
                    "full_events": 0,
                    "last_commit_ms": 1 if run == "a" else 3,
                    "max_commit_ms": 1 if run == "a" else 4,
                    "oldest_uncommitted_ms": None,
                    "queue_bytes_limit": 67108864,
                    "queue_records_limit": 10000,
                    "queued_bytes": 0,
                    "queued_records": 0,
                    "refused_late_records": 0,
                    "rejected_records": 0,
                    "state": "running",
                    "wal_bytes": 0 if run == "a" else 16512,
                    "wal_cap_bytes": 67108864,
                    "wal_restart_busy": 0,
                    "wal_restart_expired": 0,
                    "wal_restarts": 0,
                    "wal_warning": None,
                },
            },
            "checks": None,
            "connections": {
                "accept_errors": 0,
                "accepted": 0,
                "active": 0,
                "ended_cancelled": 0,
                "ended_clean": 0,
                "ended_client_gone": 0,
                "ended_error": 0,
                "ended_timeout": 0,
                "over_cap": 0,
                "region_failures": 0,
            },
            "counters": {
                "events_dropped": 0,
                "flows": {"cancelled": 0, "client_gone": 0, "completed": 0, "local_reply": 0, "refused": 0, "timed_out": 0, "upstream_failed": 0},
                "gate_refusals": 0,
                "tls": {"client_failures": 0, "client_handshakes": 0, "upstream_failures": 0, "upstream_handshakes": 0},
                "upstream": {"dial_failures": 0, "dials": 0, "open": 0},
            },
            "findings": {"critical": 0, "high": 0, "info": 0, "low": 0, "medium": 0},
            "gate": {
                "closed": {},
                "failed_path": None,
                "newer_pass_waiting": None,
                "off_pass": 0,
                "pass": gate_pass,
                "questions": 0,
                "refusals": {},
                "refusals_total": 0,
                "settings": {"relay": "allow", "required": False},
                "state": "bound",
                "stop": None,
                "stop_reason": None,
                "watch": watch,
                "window": {"ending": False, "self_stop_at": gate_pass["valid_until"], "self_stop_in_secs": 80000 if run == "a" else 79000, "valid_until": gate_pass["valid_until"]},
            },
            "jobs": {
                "active": [],
                "ended": 0,
                "lanes": {"busiest": [], "evicted": 0, "hosts": 0, "in_flight": 0, "limits": {"concurrency": 4, "max_concurrency": 32, "rate": 10}, "max_hosts": 4096, "waiting": 0},
                "record_failures": 0,
                "started": 0,
            },
            "log": {"file": {"bytes": 500 if run == "a" else 900, "dropped_lines": 0, "max_bytes": 10485760, "path": f"{state}/teapot/logs/{project_id}.log", "rotations": 0, "total_cap": 41943040}, "level": "info", "stderr": False},
            "macro_recording": None,
            "pass_watch": watch,
            "passthrough": {"auto_switch_after": 3, "client_trusts_ca": False, "findings": [], "ignore_hosts": [], "switched": []},
            "pending": {"active_jobs": 0, "hook_latency_p95_us": 4 if run == "a" else 9, "index_backlog": 0, "pass": f"bound (valid until {gate_pass['valid_until']})", "passive_backlog": 0, "playpen_last_drops": None, "sitemap_backlog": 0},
            "policy_lock": {"allow_eval": False, "locked": True, "locked_keys": ["pass.*", "proxy.mode"], "note": "policy lock", "pass": {"digest": digest, "id": pass_id}, "pass_path": pass_path, "reasons": ["pass-flag"], "refused": ["pass detach"]},
            "process": {"open_fds": 25 if run == "a" else 28, "runtime": {"reactor": {"backend": "epoll", "selection_fallback": "FeatureDisabled", "verdict": "ready"}, "workers": 4}, "tasks": {"cancelling": 0, "running": 11 if run == "a" else 12, "total": 11 if run == "a" else 12}},
            "requests": {"blocks": 0, "carried": 0, "counter": "requests", "drawn": 0, "handed": 0, "in_hand": 0, "ledger": 0, "left": 1000, "spent": 0, "total": 1000, "total_at_start": 1000, "unused": 0},
            "script_refusals": {"failed_writes": 0, "pending": 0, "rows": 0, "total": 0},
            "scripts": {
                "disable_after": 20,
                "disabled": 0,
                "generation": 1,
                "scripts": [{"busy": 0, "calls": 0 if run == "a" else 1, "consecutive_failures": 0, "errors": 0, "hooks": [], "last_failure": None, "limits": 0, "log_dropped": 0, "log_lines": 0 if run == "a" else 2, "name": "passive-headers", "p95_us": None if run == "a" else 3, "state": "running", "timeouts": 0}],
                "unattributed": {"busy": 0, "calls": 0, "errors": 0, "limits": 0, "timeouts": 0},
            },
            "scripts_following": [],
            "stop": {"audit_dropped": 0, "audit_pending": 0, "generation": 0, "history": [], "in_flight": 0, "latched": None},
            "uptime_secs": 0 if run == "a" else 1,
        },
        "project": project,
        "running": True,
    }
    pass_show = {
        "ceilings": [{"counter": "requests", "left": 1000, "spent": 0, "total": 1000, "unused": 0}],
        "destinations": [{"label": "development-fixture", "name_rules": "scope", "names": [], "network": "127.0.0.1", "ports": "3000", "protocol": "tcp"}],
        "digest": digest,
        "enforcement": {"code": "not-enforceable", "enforceable": False, "last_drop_list": None, "not_enforceable": ["loopback"], "on": False, "playpen_enforces_names": False, "why": "loopback is not enforceable"},
        "id": pass_id,
        "lock": {"locked": True, "locked_keys": ["pass.*", "proxy.mode"], "note": "policy lock", "reasons": ["pass-flag"], "refused": ["pass detach"]},
        "name": "M0 baseline",
        "names": "scope rules names",
        "newer_pass": None,
        "off_pass": 0,
        "operator": "local evaluation",
        "owner": "local evaluation",
        "pass_file": pass_path,
        "reference": "bn-2wv",
        "refusals": 0,
        "relay": "allow",
        "required": False,
        "source": "flag",
        "state": "bound",
        "stop": None,
        "valid_from": started,
        "valid_until": gate_pass["valid_until"],
        "window": "valid",
    }
    script = {
        "busy": 0,
        "calls": 0 if run == "a" else 2,
        "checks": [{"id": "headers.csp-missing", "kind": "passive", "line": 140, "severity": "low", "state": "enabled"}],
        "commands": [],
        "consecutive_failures": 0,
        "error": None,
        "error_kind": None,
        "error_line": None,
        "errors": 0,
        "file": None,
        "fix": None,
        "generation": 1,
        "hooks": [],
        "last_failure": None,
        "last_refused_send": None,
        "leads": [],
        "limit_hits": 0,
        "name": "passive-headers",
        "note": None,
        "overridden_by": None,
        "p95_us": None if run == "a" else 8,
        "previous_running": False,
        "refused_sends": 0,
        "signatures": [],
        "source": "bundled",
        "state": "running",
        "timeouts": 0,
    }
    check = {"confidence": "firm", "file": None, "id": "authz.idor", "kind": "active", "line": None, "profile": "quick", "reason": None, "replaced_by": None, "replaces": [], "script": None, "severity": "high", "source": "builtin", "state": "enabled", "title": "Another session reads the owner's resource (IDOR)"}
    empty_findings = {"counts": {"critical": 0, "high": 0, "info": 0, "low": 0, "medium": 0}, "failing": None, "grouped": True, "groups": 0, "more": False, "rows": [], "total": 0}
    sitemap = {"backlog": 0, "filter_cut": False, "folded": 0, "follower": "caught_up", "hidden_hosts": 0, "hidden_nodes": 0, "hosts": 0, "map": "current", "more": 0, "nodes": 0, "rows": [], "shown": 0, "view": "all"}
    matrix = {"abbreviations": [], "empty": True, "filter": [], "legend": [], "more": False, "next_cursor": None, "order": "stable", "rows": [], "sessions": [], "sessions_not_shown": 0, "shown": 0, "surprising": 0, "surprising_only": False, "text": "empty"}
    version_engine = engine.copy()
    return {
        "authz_matrix": wrapped("matrix", matrix),
        "checks_list": wrapped("checks", [check]),
        "commands_list": wrapped("commands", []),
        "config_list": wrapped("settings", [{"key": "pass.path", "value": pass_path}, {"key": "scope", "value": [{"host": "127.0.0.1", "path": "/*", "subdomains": False}]}]),
        "findings_list": wrapped("findings", empty_findings),
        "flows_list": wrapped("flows", []),
        "hosts_list": wrapped("hosts", []),
        "intercept_queue_list": wrapped("queue", []),
        "intercept_rules_list": wrapped("rules", []),
        "intercept_status": wrapped("intercept", {"active_rules": 0, "change": None, "enabled": True, "on_timeout": "forward", "paused": 0, "rules": 0, "timeout_secs": None}),
        "jobs_list": wrapped("jobs", []),
        "leads_list": wrapped("leads", {"count": 0, "more": False, "rows": []}),
        "macros_list": wrapped("macros", []),
        "pass_show": wrapped("pass", pass_show),
        "projects_list": wrapped("projects", [{"current": True, "id": project_id, "path": project}]),
        "projects_show": wrapped("project", {"blob_bytes": 0, "blob_files": 0, "config": f"{project}/.teapot/config.toml", "db_bytes": 475136 if run == "a" else 512000, "engine_pid": pid, "exists": True, "flows": 0, "found": "explicit", "id": project_id, "latest_schema": 8, "path": project, "schema_version": 8, "wal_bytes": 0 if run == "a" else 16512}),
        "proxy_status": wrapped("proxy", proxy),
        "rules_list": wrapped("rules", []),
        "scope_list": wrapped("scope", [{"entry": "127.0.0.1", "path": "/*", "subdomains": False}]),
        "scripts_approvals": wrapped("approvals", []),
        "scripts_list": wrapped("scripts", [script]),
        "sessions_list": wrapped("sessions", []),
        "sitemap_show": wrapped("sitemap", sitemap),
        "version": wrapped("version", {"answered_by": "engine", "arch": "x86_64", "commit": None, "engine": version_engine, "os": "linux", "profile": "debug", "protocol": 1, "version": "0.1.0"}),
    }


def committed_inventory(label):
    return json.loads((EVIDENCE / label / "raw-inventory.json").read_text())


def schema_definition(filename, name):
    document = json.loads((ROOT / "fixtures/contracts" / filename).read_text())
    return document["output"]["schema"]["result"]["$defs"][name]


def qualification_schema_definition(filename, name):
    document = json.loads((ROOT / "evals/m0-baseline/qualification/evidence/schemas" / filename).read_text())
    return document["schema"]["result"]["$defs"][name]


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def schema_sample(schema, root):
    if "$ref" in schema:
        return schema_sample(root["$defs"][schema["$ref"].removeprefix("#/$defs/")], root)
    for combinator in ("oneOf", "anyOf"):
        if combinator in schema:
            return schema_sample(schema[combinator][0], root)
    if "const" in schema:
        return schema["const"]
    schema_type = schema.get("type")
    if isinstance(schema_type, list):
        schema_type = next((item for item in schema_type if item != "null"), "null")
    if schema_type == "object":
        return {key: schema_sample(schema["properties"][key], root) for key in schema.get("required", [])}
    if schema_type == "array":
        return []
    if schema_type == "boolean":
        return False
    if schema_type in {"integer", "number"}:
        return schema.get("minimum", 0)
    if schema_type == "null":
        return None
    return ""


class InventoryProjectionTests(unittest.TestCase):
    def test_run_volatile_values_project_equal(self):
        projection_a, digest_a = subject.project_inventory(committed_inventory("run-a"))
        projection_b, digest_b = subject.project_inventory(committed_inventory("run-b"))
        self.assertEqual(projection_a, projection_b)
        self.assertEqual(digest_a, digest_b)
        self.assertTrue(projection_a["prelaunch"]["eligible"], projection_a["prelaunch"]["violations"])

    def test_every_configured_state_invariant_is_eligible_only_at_baseline(self):
        def upstream(inventory):
            inventory["pass_show"]["pass"]["upstream_proxy"] = {
                "addresses": [{"address": "127.0.0.2:8080", "allowed": True, "code": None, "destination": "development-fixture", "message": None}],
                "checked": "destination and scope",
                "credentials": False,
                "not_checked": "none",
                "proxy": "http://127.0.0.2:8080",
                "resolved_by": "literal",
                "usable": True,
            }

        mutations = {
            "approval absent": lambda value: value["pass_show"].__setitem__("pass", None),
            "gate approval absent": lambda value: value["proxy_status"]["proxy"]["health"]["gate"].__setitem__("pass", None),
            "scope changed": lambda value: value["scope_list"]["scope"][0].__setitem__("path", "/app/*"),
            "proxy not running": lambda value: value["proxy_status"]["proxy"].__setitem__("running", False),
            "proxy mode changed": lambda value: value["proxy_status"]["proxy"]["engine"].__setitem__("mode", "upstream:http://127.0.0.2:8080"),
            "policy unlocked": lambda value: value["proxy_status"]["proxy"]["health"]["policy_lock"].__setitem__("locked", False),
            "proxy enforced": lambda value: value["proxy_status"]["proxy"]["engine"].__setitem__("enforced", True),
            "intercept disabled": lambda value: value["intercept_status"]["intercept"].__setitem__("enabled", False),
            "approval enforcement changed": lambda value: value["pass_show"]["pass"]["enforcement"].__setitem__("on", True),
            "approval source changed": lambda value: value["pass_show"]["pass"].__setitem__("source", "config"),
            "approval destination changed": lambda value: value["pass_show"]["pass"]["destinations"][0].__setitem__("ports", "3001"),
            "project configuration changed": lambda value: value["config_list"]["settings"].append({"key": "proxy.mode", "value": "regular"}),
            "upstream proxy configured": upstream,
            "project config outside project": lambda value: value["projects_show"]["project"].__setitem__("config", "/tmp/wrong/config.toml"),
            "proxy listener not loopback": lambda value: value["proxy_status"]["proxy"]["engine"].__setitem__("listener", "0.0.0.0:12345"),
            "version listener not loopback": lambda value: value["version"]["version"]["engine"].__setitem__("listener", "0.0.0.0:12345"),
            "log dropped lines": lambda value: value["proxy_status"]["proxy"]["health"]["log"]["file"].__setitem__("dropped_lines", 1),
            "unattributed script error": lambda value: value["proxy_status"]["proxy"]["health"]["scripts"]["unattributed"].__setitem__("errors", 1),
            "runtime script dropped log": lambda value: value["proxy_status"]["proxy"]["health"]["scripts"]["scripts"][0].__setitem__("log_dropped", 1),
            "gate current digest differs": lambda value: value["proxy_status"]["proxy"]["health"]["gate"]["pass"].__setitem__("current_digest", "sha256:" + "0" * 64),
            "gate watch applied edit": lambda value: value["proxy_status"]["proxy"]["health"]["gate"]["watch"].__setitem__("last_edit", {"at": "2026-11-22T00:00:00Z", "digest": "sha256:" + "0" * 64, "outcome": "applied", "changes": ["destination changed"]}),
            "pass watch applied edit": lambda value: value["proxy_status"]["proxy"]["health"]["pass_watch"].__setitem__("last_edit", {"at": "2026-11-22T00:00:00Z", "digest": "sha256:" + "0" * 64, "outcome": "applied", "changes": ["destination changed"]}),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                changed = committed_inventory("run-a")
                mutate(changed)
                try:
                    projection, _ = subject.project_inventory(changed)
                except subject.ProjectionError:
                    continue
                self.assertFalse(projection["prelaunch"]["eligible"], projection["prelaunch"])

    def test_meaningful_host_pin_projects_unequal(self):
        baseline = committed_inventory("run-a")
        changed = committed_inventory("run-b")
        changed["hosts_list"]["hosts"] = [{"name": "fixture.local", "addresses": ["127.0.0.2"]}]
        _, baseline_digest = subject.project_inventory(baseline)
        changed_projection, changed_digest = subject.project_inventory(changed)
        self.assertNotEqual(baseline_digest, changed_digest)
        self.assertEqual(changed_projection["state"]["hosts"][0]["name"], "fixture.local")
        self.assertFalse(changed_projection["prelaunch"]["eligible"])

    def test_unknown_proxy_field_fails_closed(self):
        changed = fresh_inventory("a")
        changed["proxy_status"]["proxy"]["health"]["new_telemetry"] = 1
        with self.assertRaisesRegex(subject.ProjectionError, "unknown or missing fields"):
            subject.project_inventory(changed)

    def test_unknown_nested_fields_fail_closed(self):
        cases = {}

        browser = fresh_inventory("a")
        browser["proxy_status"]["proxy"]["health"]["browser"]["listeners"] = [{
            "listener": "127.0.0.1:4000",
            "refuse_own_traffic": True,
            "refused_own_traffic": 0,
            "connections": {key: 0 for key in subject.CONNECTION_FIELDS},
            "new_field": 1,
        }]
        cases["browser listener"] = browser

        stop = fresh_inventory("a")
        stop["proxy_status"]["proxy"]["health"]["stop"]["history"] = [{
            "reason": "operator",
            "message": "stopped",
            "at": "2026-11-23T00:00:00Z",
            "generation": 1,
            "job": None,
            "cancelled": [],
            "pass": None,
            "new_field": 1,
        }]
        cases["stop history"] = stop

        origin = fresh_inventory("a")
        origin["checks_list"]["checks"][0]["replaces"] = [{
            "source": "builtin", "script": None, "file": None, "line": None, "new_field": 1
        }]
        cases["check replacement origin"] = origin

        hook = fresh_inventory("a")
        hook["scripts_list"]["scripts"][0]["hooks"] = [{
            "event": "request", "text": "request", "filter": None, "line": 1, "new_field": 1
        }]
        cases["script hook"] = hook

        upstream = fresh_inventory("a")
        upstream["pass_show"]["pass"]["upstream_proxy"] = {
            "addresses": [{"address": "127.0.0.2:8080", "allowed": True, "new_field": 1}],
            "checked": "destination and scope",
            "credentials": False,
            "not_checked": "none",
            "proxy": "http://127.0.0.2:8080",
            "resolved_by": "literal",
            "usable": True,
        }
        cases["upstream address verdict"] = upstream

        advice = fresh_inventory("a")
        advice["version"]["advice"] = [{"level": "info", "type": "next", "message": "next", "new_field": 1}]
        cases["advice"] = advice

        project_config = committed_inventory("run-a")
        project_config["projects_show"]["project"]["config"] = {"path": "/tmp/config.toml"}
        cases["project config type"] = project_config

        script_failure = committed_inventory("run-a")
        script_failure["scripts_list"]["scripts"][0]["last_failure"] = {"message": "failure"}
        cases["script last failure type"] = script_failure

        gate_path = committed_inventory("run-a")
        gate_path["proxy_status"]["proxy"]["health"]["gate"]["pass"]["path"] = {"path": "wrong"}
        cases["gate pass path type"] = gate_path

        pass_stop = committed_inventory("run-a")
        pass_stop["pass_show"]["pass"]["stop"] = {"reason": "wrong"}
        cases["pass stop type"] = pass_stop

        watch_edit = committed_inventory("run-a")
        watch_edit["proxy_status"]["proxy"]["health"]["gate"]["watch"]["last_edit"] = {
            "at": "2026-11-22T00:00:00Z", "digest": None, "outcome": "applied", "changes": [], "unknown_field": 1
        }
        cases["watch edit"] = watch_edit

        for label, changed in cases.items():
            with self.subTest(label=label):
                with self.assertRaises(subject.ProjectionError):
                    subject.project_inventory(changed)

    def test_wildcard_matches_only_ascii_index_in_actual_list(self):
        pattern = "/proxy/health/scripts/scripts/*/calls"
        document = {"proxy": {"health": {"scripts": {"scripts": [{"calls": 0}]}}}}
        self.assertTrue(subject.pointer_matches(pattern, "/proxy/health/scripts/scripts/0/calls", document))
        self.assertFalse(subject.pointer_matches(pattern, "/proxy/health/scripts/scripts/item/calls", document))
        self.assertFalse(subject.pointer_matches(pattern, "/proxy/health/scripts/scripts/0/nested/calls", document))
        self.assertFalse(subject.pointer_matches(pattern, "/proxy/health/scripts/scripts/²/calls", document))
        dict_document = {"proxy": {"health": {"scripts": {"scripts": {"0": {"calls": 0}}}}}}
        self.assertFalse(subject.pointer_matches(pattern, "/proxy/health/scripts/scripts/0/calls", dict_document))

    def test_all_projected_commands_have_pinned_schemas(self):
        schema_dir = EVIDENCE / "schemas"
        self.assertEqual({path.name for path in schema_dir.glob("*.json")}, set(subject.SCHEMA_FILES.values()))
        self.assertEqual(len(subject.SCHEMA_FILES), 24)
        for command, filename in subject.SCHEMA_FILES.items():
            document = json.loads((schema_dir / filename).read_text())
            self.assertEqual(document["schema"]["command"], command.replace("_", " "))

    def test_previously_omitted_schema_nested_rows_reject_unknown_fields(self):
        definitions = {
            "authz-matrix.json": ("MatrixRow", "MatrixCell"),
            "findings-list.json": ("FindingListRow",),
            "flows-list.json": ("FlowRow",),
            "intercept-queue-list.json": ("PausedRow",),
            "intercept-rules-list.json": ("InterceptRuleRow",),
            "jobs-list.json": ("JobListed",),
            "leads-list.json": ("LeadListRow",),
            "rules-list.json": ("RuleRow",),
            "sitemap-show.json": ("SitemapRow",),
        }
        for filename, names in definitions.items():
            root = json.loads((EVIDENCE / "schemas" / filename).read_text())["schema"]["result"]
            for name in names:
                with self.subTest(filename=filename, definition=name):
                    row = schema_sample(root["$defs"][name], root)
                    row["unknown_field"] = 1
                    with self.assertRaisesRegex(subject.ProjectionError, "unknown"):
                        subject.validate_schema(row, root["$defs"][name], root, f"/{name}")

    def test_qualification_rejects_forged_ids_digests_and_cleanup(self):
        checker = load_module("m0_check_materials", ROOT / "evals/m0-baseline/check-materials.py")
        manifest = json.loads((EVIDENCE / "manifest.json").read_text())
        lock = json.loads((ROOT / "evals/m0-baseline/materials.lock.json").read_text())
        forged_id = copy.deepcopy(manifest)
        forged_id["runs"][0]["project_id"] = "0" * 32
        with self.assertRaises(SystemExit):
            checker.validate_qualification(lock, manifest_override=forged_id)
        forged_digest = copy.deepcopy(manifest)
        forged_digest["attestation"]["semantic_projection_sha256"] = "0" * 64
        with self.assertRaises(SystemExit):
            checker.validate_qualification(lock, manifest_override=forged_digest)
        with self.assertRaises(SystemExit):
            checker.validate_cleanup_record({"success": False}, "hostile")

    def test_capture_fails_on_proxy_stop_or_root_cleanup_failure(self):
        capture = load_module("m0_capture", ROOT / "evals/m0-baseline/qualification/capture_fresh_pair.py")

        class Recorder:
            def __init__(self, stop_error=None):
                self.rows = []
                self.stop_error = stop_error

            def teapot_json(self, _label, _project, words):
                if self.stop_error and words == ("proxy", "stop"):
                    raise self.stop_error
                if words == ("proxy", "stop"):
                    return {"proxy": {"stopped": True}}
                if words == ("proxy", "status"):
                    return {"proxy": {"running": False}}
                return {}

        with tempfile.TemporaryDirectory() as base_text:
            base = Path(base_text)
            run_root = base / "run-stop"
            run_root.mkdir()
            with self.assertRaisesRegex(RuntimeError, "cleanup failed"):
                capture.cleanup_run(Recorder(RuntimeError("stop failed")), run_root / "project", run_root, True, base / "evidence", "run-a")
            self.assertFalse(run_root.exists())

            run_root = base / "run-remove"
            run_root.mkdir()
            with mock.patch.object(capture.shutil, "rmtree", side_effect=OSError("remove failed")):
                with self.assertRaisesRegex(RuntimeError, "cleanup failed"):
                    capture.cleanup_run(Recorder(), run_root / "project", run_root, True, base / "evidence", "run-b")

    def test_capture_cleans_proxy_when_start_launches_then_response_fails(self):
        capture = load_module("m0_capture_start_failure", ROOT / "evals/m0-baseline/qualification/capture_fresh_pair.py")

        class FailingStartRecorder:
            instances = []

            def __init__(self, _teapot, _env):
                self.rows = []
                self.calls = []
                self.project = None
                self.__class__.instances.append(self)

            def teapot_json(self, label, project, words):
                self.calls.append((label, words))
                self.project = Path(project)
                if words[:2] == ("proxy", "start"):
                    raise RuntimeError("start response failed after launch")
                if words == ("proxy", "stop"):
                    return {"proxy": {"stopped": True}}
                if words == ("proxy", "status"):
                    return {"proxy": {"running": False}}
                return {}

        with tempfile.TemporaryDirectory() as base_text:
            output = Path(base_text) / "evidence"
            with mock.patch.object(capture, "Recorder", FailingStartRecorder):
                with self.assertRaisesRegex(RuntimeError, "start response failed after launch"):
                    capture.capture_run("run-a", Path("/pinned/teapot"), output)
            recorder = FailingStartRecorder.instances[-1]
            self.assertIn(("cleanup: proxy stop", ("proxy", "stop")), recorder.calls)
            self.assertIn(("cleanup: proxy status", ("proxy", "status")), recorder.calls)
            self.assertFalse(recorder.project.parent.exists())
            cleanup = json.loads((output / "run-a/cleanup.json").read_text())
            self.assertTrue(cleanup["success"])

    def test_schema_backed_selector_fields(self):
        self.assertEqual(subject.RULE_FIELDS | subject.RULE_OPTIONAL_FIELDS, set(schema_definition("schema-rules-list.json", "RuleRow")["properties"]))
        self.assertEqual(subject.SCRIPT_FIELDS, set(schema_definition("schema-scripts-list.json", "ScriptRow")["properties"]))
        self.assertEqual(subject.CONFIG_FIELDS, set(schema_definition("schema-config-list.json", "Setting")["properties"]))
        self.assertEqual(subject.ENGINE_FIELDS, set(schema_definition("schema-version.json", "EngineInfo")["properties"]))
        self.assertEqual(subject.VERSION_FIELDS, set(schema_definition("schema-version.json", "VersionInfo")["properties"]))
        self.assertEqual(subject.PASS_FIELDS | subject.PASS_OPTIONAL_FIELDS, set(schema_definition("schema-pass-show.json", "PassReport")["properties"]))
        self.assertEqual(subject.CEILING_FIELDS, set(schema_definition("schema-pass-show.json", "CeilingInfo")["properties"]))
        self.assertEqual(subject.DESTINATION_FIELDS, set(schema_definition("schema-pass-show.json", "DestinationInfo")["properties"]))
        self.assertEqual(subject.ENFORCEMENT_FIELDS, set(schema_definition("schema-pass-show.json", "EnforcementInfo")["properties"]))
        self.assertEqual(subject.LOCK_FIELDS, set(schema_definition("schema-pass-show.json", "LockReport")["properties"]))
        self.assertEqual(subject.UPSTREAM_PROXY_FIELDS, set(schema_definition("schema-pass-show.json", "UpstreamProxyInfo")["properties"]))
        self.assertEqual(subject.ADDRESS_VERDICT_FIELDS | subject.ADDRESS_VERDICT_OPTIONAL_FIELDS, set(schema_definition("schema-pass-show.json", "AddressVerdict")["properties"]))
        self.assertEqual(subject.INTERCEPT_FIELDS, set(schema_definition("schema-intercept-status.json", "InterceptStatus")["properties"]))
        self.assertEqual(subject.SCRIPT_CHECK_FIELDS | subject.SCRIPT_CHECK_OPTIONAL_FIELDS, set(schema_definition("schema-scripts-list.json", "ScriptCheckRow")["properties"]))
        self.assertEqual(subject.SCRIPT_LEAD_FIELDS | subject.SCRIPT_LEAD_OPTIONAL_FIELDS, set(schema_definition("schema-scripts-list.json", "ScriptLeadRow")["properties"]))
        self.assertEqual(subject.SCRIPT_HOOK_FIELDS | subject.SCRIPT_HOOK_OPTIONAL_FIELDS, set(schema_definition("schema-scripts-list.json", "HookRow")["properties"]))
        self.assertEqual(subject.CHECK_FIELDS | subject.CHECK_OPTIONAL_FIELDS, set(qualification_schema_definition("checks-list.json", "CheckRow")["properties"]))
        self.assertEqual(subject.CHECK_ORIGIN_FIELDS, set(qualification_schema_definition("checks-list.json", "CheckOrigin")["properties"]))
        self.assertEqual(subject.CHECK_HEALTH_FIELDS, set(qualification_schema_definition("checks-list.json", "CheckHealthView")["properties"]))
        self.assertEqual(subject.SCRIPT_COMMAND_FIELDS, set(qualification_schema_definition("commands-list.json", "ScriptCommand")["properties"]))
        self.assertEqual(subject.SCRIPT_ARG_FIELDS, set(qualification_schema_definition("commands-list.json", "ScriptArg")["properties"]))
        self.assertEqual(subject.HOST_FIELDS, set(qualification_schema_definition("hosts-list.json", "Pin")["properties"]))
        self.assertEqual(subject.SCOPE_FIELDS, set(qualification_schema_definition("scope-list.json", "ScopeRow")["properties"]))
        self.assertEqual(subject.PROJECT_LIST_FIELDS | subject.PROJECT_LIST_OPTIONAL_FIELDS, set(qualification_schema_definition("projects-list.json", "ProjectEntry")["properties"]))
        self.assertEqual(subject.PROJECT_SHOW_FIELDS, set(qualification_schema_definition("projects-show.json", "ProjectInfo")["properties"]))
        self.assertEqual(subject.SCRIPT_APPROVAL_FIELDS, set(qualification_schema_definition("scripts-approvals.json", "ApprovalRow")["properties"]))

    def test_committed_real_fresh_pair_reprojects_equal(self):
        evidence = ROOT / "evals/m0-baseline/qualification/evidence"
        manifest = json.loads((evidence / "manifest.json").read_text())
        self.assertTrue(manifest["attestation"]["fresh_roots_and_project_ids_unique"])
        self.assertTrue(manifest["attestation"]["raw_inventory_hashes_distinct"])
        self.assertTrue(manifest["attestation"]["semantic_projections_equal"])
        self.assertTrue(manifest["attestation"]["both_prelaunch_eligible"])
        self.assertEqual(manifest["attestation"]["assessment_agents_started"], 0)
        self.assertEqual(manifest["attestation"]["target_requests_sent"], 0)
        digests = []
        roots = []
        project_ids = []
        for run in manifest["runs"]:
            raw_path = evidence / run["raw_inventory"]
            projected_path = evidence / run["projected"]
            creation_path = evidence / run["creation_evidence"]
            self.assertEqual(sha256(raw_path), run["raw_inventory_sha256"])
            self.assertEqual(sha256(projected_path), run["projected_sha256"])
            self.assertEqual(sha256(creation_path), run["creation_evidence_sha256"])
            raw = json.loads(raw_path.read_text())
            expected = json.loads(projected_path.read_text())
            projection, digest = subject.project_inventory(raw)
            self.assertEqual(projection, expected["projection"])
            self.assertEqual(digest, expected["sha256"])
            self.assertTrue(projection["prelaunch"]["eligible"], projection["prelaunch"]["violations"])
            creation = json.loads(creation_path.read_text())
            self.assertTrue(all(creation["before_setup"].values()))
            self.assertTrue(all(creation["fresh_environment_directories_empty"].values()))
            roots.append(run["run_root"])
            project_ids.append(run["project_id"])
            digests.append(digest)
        self.assertEqual(len(set(roots)), 2)
        self.assertEqual(len(set(project_ids)), 2)
        self.assertEqual(len(set(digests)), 1)

    def test_pinned_proxy_capture_matches_shape(self):
        capture = json.loads((ROOT / "fixtures/contracts/describe-status.json").read_text())
        subject.validate_proxy_shape(capture["output"]["proxy"])


if __name__ == "__main__":
    unittest.main()
