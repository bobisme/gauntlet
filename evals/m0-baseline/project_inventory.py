#!/usr/bin/env python3
"""Project a raw prelaunch Teapot inventory into stable M0 parity state.

The projector is deliberately fail-closed. Every command envelope and every
selected row has an exact key contract. A wildcard in an excluded JSON pointer
matches exactly one array element; it never matches an object key recursively.
"""

import argparse
import hashlib
import json
from pathlib import Path


SCHEMA_VERSION = 1
EXPECTED_SCRIPTS_SHA256 = "ecb4ea664b41f290fd01252d4c841bf11148c2f0e35ed39900a38880d418d801"
EXPECTED_CHECKS_SHA256 = "dbb9285fc10a27734ccf56c78226e80679223ba839649642f6ee50fa6f34b5fc"
EXPECTED_MATRIX_LEGEND_SHA256 = "c1cefdb9737a818bbac4c6c248cadf4be48a4b0bdb24078ce4c3df3a061e86d6"
COMMANDS = {
    "authz_matrix",
    "checks_list",
    "commands_list",
    "config_list",
    "findings_list",
    "flows_list",
    "hosts_list",
    "intercept_queue_list",
    "intercept_rules_list",
    "intercept_status",
    "jobs_list",
    "leads_list",
    "macros_list",
    "pass_show",
    "projects_list",
    "projects_show",
    "proxy_status",
    "rules_list",
    "scope_list",
    "scripts_approvals",
    "scripts_list",
    "sessions_list",
    "sitemap_show",
    "version",
}
SCHEMA_DIR = Path(__file__).resolve().parent / "qualification/evidence/schemas"
SCHEMA_FILES = {name: f"{name.replace('_', '-')}.json" for name in COMMANDS}
ADVICE_FIELDS = {"level", "type", "message"}
ADVICE_OPTIONAL_FIELDS = {"command"}
ENGINE_FIELDS = {"build", "control_socket", "enforced", "instance", "listener", "mode", "pass", "pid", "policy_locked", "project", "project_id", "started_at"}
VERSION_FIELDS = {"answered_by", "arch", "commit", "engine", "os", "profile", "protocol", "version"}
PROJECT_LIST_FIELDS = {"current", "id", "path"}
PROJECT_LIST_OPTIONAL_FIELDS = {"problem"}
PROJECT_SHOW_FIELDS = {"blob_bytes", "blob_files", "config", "db_bytes", "engine_pid", "exists", "flows", "found", "id", "latest_schema", "path", "schema_version", "wal_bytes"}
RULE_FIELDS = {"n", "name", "kind", "filter", "direction", "enabled", "status", "summary"}
RULE_OPTIONAL_FIELDS = {"matched"}
LEAD_FIELDS = {"id", "rank", "weight", "rule", "source", "state", "title", "host", "method", "path", "seen", "tested", "last_seen"}
LEAD_OPTIONAL_FIELDS = {"finding", "follow_up", "point"}
SCOPE_FIELDS = {"entry", "path", "subdomains"}
HOST_FIELDS = {"addresses", "name"}
CONFIG_FIELDS = {"key", "value"}
SCRIPT_FIELDS = {"busy", "calls", "checks", "commands", "consecutive_failures", "error", "error_kind", "error_line", "errors", "file", "fix", "generation", "hooks", "last_failure", "last_refused_send", "leads", "limit_hits", "name", "note", "overridden_by", "p95_us", "previous_running", "refused_sends", "signatures", "source", "state", "timeouts"}
SCRIPT_CHECK_FIELDS = {"id", "kind", "severity", "state"}
SCRIPT_CHECK_OPTIONAL_FIELDS = {"line"}
SCRIPT_LEAD_FIELDS = {"id", "weight", "state"}
SCRIPT_LEAD_OPTIONAL_FIELDS = {"line"}
SCRIPT_HOOK_FIELDS = {"event", "text"}
SCRIPT_HOOK_OPTIONAL_FIELDS = {"filter", "line"}
CHECK_FIELDS = {"confidence", "file", "id", "kind", "line", "profile", "reason", "replaced_by", "replaces", "script", "severity", "source", "state", "title"}
CHECK_OPTIONAL_FIELDS = {"health"}
CHECK_ORIGIN_FIELDS = {"source", "script", "file", "line"}
CHECK_HEALTH_FIELDS = {"state", "calls", "failures", "consecutive_failures", "quarantines", "last_failure"}
PASS_FIELDS = {"ceilings", "destinations", "digest", "enforcement", "id", "lock", "name", "names", "newer_pass", "off_pass", "operator", "owner", "pass_file", "reference", "refusals", "relay", "required", "source", "state", "stop", "valid_from", "valid_until", "window"}
PASS_OPTIONAL_FIELDS = {"upstream_proxy"}
CEILING_FIELDS = {"counter", "left", "spent", "total", "unused"}
DESTINATION_FIELDS = {"label", "name_rules", "names", "network", "ports", "protocol"}
ENFORCEMENT_FIELDS = {"code", "enforceable", "last_drop_list", "not_enforceable", "on", "playpen_enforces_names", "why"}
LOCK_FIELDS = {"locked", "locked_keys", "note", "reasons", "refused"}
UPSTREAM_PROXY_FIELDS = {"addresses", "checked", "credentials", "not_checked", "proxy", "resolved_by", "usable"}
ADDRESS_VERDICT_FIELDS = {"address", "allowed"}
ADDRESS_VERDICT_OPTIONAL_FIELDS = {"code", "destination", "message"}
INTERCEPT_FIELDS = {"active_rules", "change", "enabled", "on_timeout", "paused", "rules", "timeout_secs"}
CONNECTION_FIELDS = {"accept_errors", "accepted", "active", "ended_cancelled", "ended_clean", "ended_client_gone", "ended_error", "ended_timeout", "over_cap", "region_failures"}
BROWSER_LISTENER_FIELDS = {"listener", "refuse_own_traffic", "refused_own_traffic", "connections"}
STOP_RECORD_FIELDS = {"reason", "message", "at", "generation", "job", "cancelled", "pass"}
CANCELLED_FIELDS = {"id", "work", "sent_before_stop"}
WORK_FIELDS = {"kind", "label", "job"}
LATCHED_STOP_FIELDS = {"reason", "message", "at", "resumable", "fix"}
SCRIPT_APPROVAL_FIELDS = {"name", "state", "digest", "path"}
INTERCEPT_RULE_FIELDS = {"n", "name", "filter", "direction", "enabled"}
PAUSED_ROW_FIELDS = {"id", "flow", "direction", "rule", "held_at", "waited_secs", "method", "destination", "target", "status"}
ACTIVE_JOB_FIELDS = {"id", "kind", "started_at", "counters", "in_flight", "budget", "ending", "lane", "waiting", "hosts_stopped", "listeners"}
JOB_COUNTER_FIELDS = {"sent", "refused", "blocked", "errors", "units", "own_traffic_refused"}
JOB_BUDGET_FIELDS = {"max_requests", "max_time", "max_refused"}
JOB_LANE_FIELDS = {"rate", "concurrency"}
JOB_WAITING_FIELDS = {"waiting", "hosts"}
JOB_LISTENER_FIELDS = {"address", "connections_open"}
HOST_LANE_FIELDS = {"host", "in_flight", "waiting"}
PASSTHROUGH_FINDING_FIELDS = {"code", "host", "message", "fix", "then", "at", "rejected_in_a_row"}
HEALTH_HOOK_FIELDS = {"hook", "calls", "errors", "limits", "timeouts", "busy"}
HEALTH_FAILURE_FIELDS = {"hook", "kind", "line", "message"}
EDIT_REPORT_FIELDS = {"at", "digest", "outcome", "changes"}
SCRIPT_COMMAND_FIELDS = {"name", "summary", "script", "line", "mutates", "level", "level_declared", "args"}
SCRIPT_ARG_FIELDS = {"name", "type", "required", "positional", "help"}
MACRO_RECORDING_FIELDS = {"name", "started_at", "after_flow", "session"}
WAITING_PASS_FIELDS = {"digest", "changes"}
MATRIX_LEGEND_FIELDS = {"mark", "meaning"}
PROXY_EXCLUDED_POINTERS = [
    "/proxy/project",
    "/proxy/engine/control_socket",
    "/proxy/engine/instance",
    "/proxy/engine/pid",
    "/proxy/engine/project",
    "/proxy/engine/project_id",
    "/proxy/engine/started_at",
    "/proxy/health/at",
    "/proxy/health/capture/estimated_store_bytes",
    "/proxy/health/capture/free_bytes",
    "/proxy/health/capture/max_store_bytes",
    "/proxy/health/capture/min_free_bytes",
    "/proxy/health/capture/since",
    "/proxy/health/capture/store_bytes",
    "/proxy/health/capture/writer/last_commit_ms",
    "/proxy/health/capture/writer/max_commit_ms",
    "/proxy/health/capture/writer/oldest_uncommitted_ms",
    "/proxy/health/capture/writer/committed_batches",
    "/proxy/health/capture/writer/committed_records",
    "/proxy/health/capture/writer/wal_bytes",
    "/proxy/health/checks/checks/*/calls",
    "/proxy/health/checks/checks/*/last_failure",
    "/proxy/health/checks/checks/*/p95_us",
    "/proxy/health/gate/window/self_stop_at",
    "/proxy/health/gate/window/self_stop_in_secs",
    "/proxy/health/gate/window/valid_until",
    "/proxy/health/gate/watch/checks",
    "/proxy/health/gate/watch/last_check_at",
    "/proxy/health/log/file/bytes",
    "/proxy/health/log/file/path",
    "/proxy/health/pass_watch/checks",
    "/proxy/health/pass_watch/last_check_at",
    "/proxy/health/process/open_fds",
    "/proxy/health/process/runtime",
    "/proxy/health/process/tasks",
    "/proxy/health/pending/hook_latency_p95_us",
    "/proxy/health/scripts/scripts/*/calls",
    "/proxy/health/scripts/scripts/*/log_lines",
    "/proxy/health/scripts/scripts/*/p95_us",
    "/proxy/health/uptime_secs",
]
APPROVAL_NORMALIZED_POINTERS = [
    "/proxy/engine/pass",
    "/proxy/health/gate/pass/current_digest",
    "/proxy/health/gate/pass/digest",
    "/proxy/health/gate/pass/id",
    "/proxy/health/gate/pass/path",
    "/proxy/health/gate/pass/valid_from",
    "/proxy/health/gate/pass/valid_until",
    "/proxy/health/policy_lock/pass/digest",
    "/proxy/health/policy_lock/pass/id",
    "/proxy/health/policy_lock/pass_path",
    "/proxy/health/pending/pass",
    "/pass_show/pass/digest",
    "/pass_show/pass/id",
    "/pass_show/pass/pass_file",
    "/pass_show/pass/valid_from",
    "/pass_show/pass/valid_until",
    "/config_list/settings/*/value when key=pass.path",
]


class ProjectionError(ValueError):
    pass


def fail(path, message):
    raise ProjectionError(f"{path}: {message}")


def canonical_sha256(value):
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return hashlib.sha256(encoded).hexdigest()


def exact_dict(value, keys, path):
    if not isinstance(value, dict):
        fail(path, "expected object")
    actual = set(value)
    expected = set(keys)
    if actual != expected:
        fail(path, f"unknown or missing fields: expected {sorted(expected)}, got {sorted(actual)}")
    return value


def exact_dict_optional(value, required, optional, path):
    if not isinstance(value, dict):
        fail(path, "expected object")
    actual = set(value)
    required = set(required)
    allowed = required | set(optional)
    if not required <= actual or not actual <= allowed:
        fail(path, f"unknown or missing fields: required {sorted(required)}, allowed {sorted(allowed)}, got {sorted(actual)}")
    return value


def list_value(value, path):
    if not isinstance(value, list):
        fail(path, "expected array")
    return value


def scalar_list(value, path, scalar_type=str):
    rows = list_value(value, path)
    for index, row in enumerate(rows):
        if not isinstance(row, scalar_type):
            fail(f"{path}/{index}", f"expected {scalar_type.__name__}")
    return rows


def typed(value, expected, path):
    if not isinstance(value, expected) or (expected is int and isinstance(value, bool)):
        fail(path, f"expected {expected.__name__}")
    return value


def optional_typed(value, expected, path):
    if value is not None:
        typed(value, expected, path)
    return value


def schema_type_matches(value, expected):
    return {
        "array": isinstance(value, list),
        "boolean": isinstance(value, bool),
        "integer": isinstance(value, int) and not isinstance(value, bool),
        "null": value is None,
        "number": isinstance(value, (int, float)) and not isinstance(value, bool),
        "object": isinstance(value, dict),
        "string": isinstance(value, str),
    }.get(expected, False)


def validate_schema(value, schema, root, path):
    """Validate the pinned command-schema subset and reject undeclared fields."""
    if "$ref" in schema:
        prefix = "#/$defs/"
        reference = schema["$ref"]
        if not reference.startswith(prefix):
            fail(path, f"unsupported schema reference {reference!r}")
        name = reference[len(prefix):].replace("~1", "/").replace("~0", "~")
        if name not in root.get("$defs", {}):
            fail(path, f"missing schema definition {name!r}")
        validate_schema(value, root["$defs"][name], root, path)
        return
    for combinator in ("oneOf", "anyOf"):
        if combinator in schema:
            matches = 0
            for candidate in schema[combinator]:
                try:
                    validate_schema(value, candidate, root, path)
                except ProjectionError:
                    continue
                matches += 1
            if not matches or (combinator == "oneOf" and matches != 1):
                fail(path, f"does not match {combinator} schema")
            return
    if "const" in schema and value != schema["const"]:
        fail(path, f"expected constant {schema['const']!r}")
    if "enum" in schema and value not in schema["enum"]:
        fail(path, f"expected one of {schema['enum']!r}")
    expected = schema.get("type")
    if expected is not None:
        types = [expected] if isinstance(expected, str) else expected
        if not any(schema_type_matches(value, item) for item in types):
            fail(path, f"expected schema type {types!r}")
    if value is not None and "minimum" in schema and value < schema["minimum"]:
        fail(path, f"below schema minimum {schema['minimum']!r}")
    if value is not None and "maximum" in schema and value > schema["maximum"]:
        fail(path, f"above schema maximum {schema['maximum']!r}")
    if value is not None and "format" in schema:
        ranges = {
            "uint8": (0, 2**8 - 1),
            "uint16": (0, 2**16 - 1),
            "uint32": (0, 2**32 - 1),
            "uint64": (0, 2**64 - 1),
            "int64": (-(2**63), 2**63 - 1),
        }
        format_name = schema["format"]
        if format_name in ranges:
            low, high = ranges[format_name]
            if not schema_type_matches(value, "integer") or not low <= value <= high:
                fail(path, f"expected {format_name}")
        elif format_name == "double" and not schema_type_matches(value, "number"):
            fail(path, "expected double")
        elif format_name not in ranges and format_name != "double":
            fail(path, f"unsupported schema format {format_name!r}")
    if isinstance(value, dict) and "properties" in schema:
        properties = schema["properties"]
        required = set(schema.get("required", []))
        missing = required - set(value)
        unknown = set(value) - set(properties)
        if missing or unknown:
            fail(path, f"schema fields missing={sorted(missing)}, unknown={sorted(unknown)}")
        for key, child in value.items():
            validate_schema(child, properties[key], root, f"{path}/{key}")
    elif isinstance(value, dict):
        additional = schema.get("additionalProperties")
        if isinstance(additional, dict):
            for key, child in value.items():
                validate_schema(child, additional, root, f"{path}/{key}")
        elif additional is False and value:
            fail(path, "object fields are forbidden by schema")
    if isinstance(value, list) and "items" in schema:
        for index, child in enumerate(value):
            validate_schema(child, schema["items"], root, f"{path}/{index}")


def validate_inventory_schemas(inventory, schema_dir=SCHEMA_DIR):
    schema_dir = Path(schema_dir)
    expected_files = set(SCHEMA_FILES.values())
    actual_files = {path.name for path in schema_dir.glob("*.json")}
    if actual_files != expected_files:
        fail("/schemas", f"expected {sorted(expected_files)}, got {sorted(actual_files)}")
    for command, filename in SCHEMA_FILES.items():
        try:
            document = json.loads((schema_dir / filename).read_text(encoding="utf-8"))
            command_schema = document["schema"]
            if command_schema["command"] != command.replace("_", " "):
                fail(f"/schemas/{filename}", "command does not match inventory key")
            result_schema = command_schema["result"]
        except (OSError, json.JSONDecodeError, KeyError, TypeError) as error:
            fail(f"/schemas/{filename}", f"invalid captured schema: {error}")
        validate_schema(inventory[command], result_schema, result_schema, f"/{command}")


def validate_advice(value, path):
    for index, row in enumerate(list_value(value, path)):
        exact_dict_optional(row, ADVICE_FIELDS, ADVICE_OPTIONAL_FIELDS, f"{path}/{index}")


def envelope(inventory, command, payload):
    row = exact_dict(inventory[command], {payload, "advice"}, f"/{command}")
    validate_advice(row["advice"], f"/{command}/advice")
    return row[payload]


def pointer_tokens(pointer):
    if not pointer.startswith("/"):
        raise ValueError(f"not a JSON pointer: {pointer}")
    return tuple(part.replace("~1", "/").replace("~0", "~") for part in pointer[1:].split("/"))


def pointer_matches(pattern, path, document=None):
    """Match `*` only to an ASCII index whose parent in `document` is a list."""
    pattern_tokens = pointer_tokens(pattern)
    path_tokens = pointer_tokens(path)
    if len(pattern_tokens) != len(path_tokens):
        return False
    node = document
    for expected, actual in zip(pattern_tokens, path_tokens):
        if expected == "*":
            if not actual or any(character not in "0123456789" for character in actual):
                return False
            if document is None or not isinstance(node, list):
                return False
            index = int(actual)
            if index >= len(node):
                return False
            node = node[index]
        elif expected != actual:
            return False
        elif document is not None:
            if isinstance(node, dict) and actual in node:
                node = node[actual]
            elif isinstance(node, list) and actual and all(c in "0123456789" for c in actual) and int(actual) < len(node):
                node = node[int(actual)]
            else:
                return False
    return True


def excluded(path, document):
    return any(pointer_matches(pattern, path, document) for pattern in PROXY_EXCLUDED_POINTERS)


def drop_proxy_fields(value, path="/proxy", document=None):
    if document is None:
        document = {"proxy": value}
    if excluded(path, document):
        return None, True
    if isinstance(value, dict):
        result = {}
        for key, child in value.items():
            projected, dropped = drop_proxy_fields(child, f"{path}/{key}", document)
            if not dropped:
                result[key] = projected
        return result, False
    if isinstance(value, list):
        result = []
        for index, child in enumerate(value):
            projected, dropped = drop_proxy_fields(child, f"{path}/{index}", document)
            if not dropped:
                result.append(projected)
        return result, False
    return value, False


def project_engine(engine, path):
    exact_dict(engine, ENGINE_FIELDS, path)


def validate_connections(value, path):
    exact_dict(value, CONNECTION_FIELDS, path)


def validate_check_origin(value, path):
    exact_dict(value, CHECK_ORIGIN_FIELDS, path)


def validate_check_health(value, path):
    exact_dict(value, CHECK_HEALTH_FIELDS, path)


def project_watch(watch, path):
    if watch is None:
        return
    exact_dict(watch, {"checks", "last_check_at", "last_edit", "period_ms"}, path)
    typed(watch["checks"], int, f"{path}/checks")
    optional_typed(watch["last_check_at"], str, f"{path}/last_check_at")
    typed(watch["period_ms"], int, f"{path}/period_ms")
    if watch["last_edit"] is not None:
        edit = exact_dict(watch["last_edit"], EDIT_REPORT_FIELDS, f"{path}/last_edit")
        typed(edit["at"], str, f"{path}/last_edit/at")
        optional_typed(edit["digest"], str, f"{path}/last_edit/digest")
        typed(edit["outcome"], str, f"{path}/last_edit/outcome")
        scalar_list(edit["changes"], f"{path}/last_edit/changes")


def project_health_script(row, path):
    exact_dict_optional(
        row,
        {"busy", "calls", "consecutive_failures", "errors", "hooks", "last_failure", "limits", "log_dropped", "log_lines", "name", "p95_us", "state", "timeouts"},
        {"reason"},
        path,
    )
    for index, hook in enumerate(list_value(row["hooks"], f"{path}/hooks")):
        exact_dict(hook, HEALTH_HOOK_FIELDS, f"{path}/hooks/{index}")
    if row["last_failure"] is not None:
        failure = exact_dict(row["last_failure"], HEALTH_FAILURE_FIELDS, f"{path}/last_failure")
        for key in HEALTH_FAILURE_FIELDS:
            typed(failure[key], str, f"{path}/last_failure/{key}")


def validate_proxy_shape(proxy):
    exact_dict(proxy, {"engine", "health", "project", "running"}, "/proxy")
    project_engine(proxy["engine"], "/proxy/engine")
    h = exact_dict(
        proxy["health"],
        {"at", "browser", "capture", "checks", "connections", "counters", "findings", "gate", "jobs", "log", "macro_recording", "pass_watch", "passthrough", "pending", "policy_lock", "process", "requests", "script_refusals", "scripts", "scripts_following", "stop", "uptime_secs"},
        "/proxy/health",
    )
    browser = exact_dict(h["browser"], {"listeners", "refused_own_traffic"}, "/proxy/health/browser")
    for index, row in enumerate(list_value(browser["listeners"], "/proxy/health/browser/listeners")):
        path = f"/proxy/health/browser/listeners/{index}"
        exact_dict(row, BROWSER_LISTENER_FIELDS, path)
        validate_connections(row["connections"], f"{path}/connections")
    capture = exact_dict(
        h["capture"],
        {"estimated_store_bytes", "flows_not_captured", "free_bytes", "gc_bytes_freed", "gc_errors", "gc_paused", "gc_runs", "max_store_bytes", "min_free_bytes", "probe_error", "reason", "reason_text", "resumes", "since", "state", "store_bytes", "warning", "writer"},
        "/proxy/health/capture",
    )
    exact_dict(
        capture["writer"],
        {"busy_retries", "committed_batches", "committed_records", "discarded_records", "full_events", "last_commit_ms", "max_commit_ms", "oldest_uncommitted_ms", "queue_bytes_limit", "queue_records_limit", "queued_bytes", "queued_records", "refused_late_records", "rejected_records", "state", "wal_bytes", "wal_cap_bytes", "wal_restart_busy", "wal_restart_expired", "wal_restarts", "wal_warning"},
        "/proxy/health/capture/writer",
    )
    if h["checks"] is not None:
        checks = exact_dict(h["checks"], {"checks", "quarantine_after", "quarantined"}, "/proxy/health/checks")
        for index, row in enumerate(list_value(checks["checks"], "/proxy/health/checks/checks")):
            exact_dict_optional(row, {"calls", "consecutive_failures", "failures", "id", "last_failure", "quarantines", "state", "timeouts"}, {"p95_us", "reason"}, f"/proxy/health/checks/checks/{index}")
    validate_connections(h["connections"], "/proxy/health/connections")
    counters = exact_dict(h["counters"], {"events_dropped", "flows", "gate_refusals", "tls", "upstream"}, "/proxy/health/counters")
    exact_dict(counters["flows"], {"cancelled", "client_gone", "completed", "local_reply", "refused", "timed_out", "upstream_failed"}, "/proxy/health/counters/flows")
    exact_dict(counters["tls"], {"client_failures", "client_handshakes", "upstream_failures", "upstream_handshakes"}, "/proxy/health/counters/tls")
    exact_dict(counters["upstream"], {"dial_failures", "dials", "open"}, "/proxy/health/counters/upstream")
    exact_dict(h["findings"], {"critical", "high", "info", "low", "medium"}, "/proxy/health/findings")
    gate = exact_dict(h["gate"], {"closed", "failed_path", "newer_pass_waiting", "off_pass", "pass", "questions", "refusals", "refusals_total", "settings", "state", "stop", "stop_reason", "watch", "window"}, "/proxy/health/gate")
    exact_dict(gate["closed"], set(), "/proxy/health/gate/closed")
    exact_dict(gate["refusals"], set(), "/proxy/health/gate/refusals")
    exact_dict(gate["settings"], {"relay", "required"}, "/proxy/health/gate/settings")
    if gate["newer_pass_waiting"] is not None:
        waiting = exact_dict(gate["newer_pass_waiting"], WAITING_PASS_FIELDS, "/proxy/health/gate/newer_pass_waiting")
        scalar_list(waiting["changes"], "/proxy/health/gate/newer_pass_waiting/changes")
    if gate["stop"] is not None:
        fail("/proxy/health/gate/stop", "prelaunch gate must not be stopped")
    project_watch(gate["watch"], "/proxy/health/gate/watch")
    if gate["window"] is not None:
        exact_dict(gate["window"], {"ending", "self_stop_at", "self_stop_in_secs", "valid_until"}, "/proxy/health/gate/window")
    if gate["pass"] is not None:
        gate_pass = exact_dict(gate["pass"], {"current_digest", "destinations", "digest", "id", "name", "operator", "owner", "path", "reference", "valid_from", "valid_until", "window"}, "/proxy/health/gate/pass")
        for key in ("current_digest", "digest", "id", "name", "operator", "owner", "path", "reference", "valid_from", "valid_until", "window"):
            optional_typed(gate_pass[key], str, f"/proxy/health/gate/pass/{key}")
        typed(gate_pass["destinations"], int, "/proxy/health/gate/pass/destinations")
    jobs = exact_dict(h["jobs"], {"active", "ended", "lanes", "record_failures", "started"}, "/proxy/health/jobs")
    for index, row in enumerate(list_value(jobs["active"], "/proxy/health/jobs/active")):
        path = f"/proxy/health/jobs/active/{index}"
        exact_dict(row, ACTIVE_JOB_FIELDS, path)
        exact_dict(row["counters"], JOB_COUNTER_FIELDS, f"{path}/counters")
        exact_dict(row["budget"], JOB_BUDGET_FIELDS, f"{path}/budget")
        exact_dict(row["lane"], JOB_LANE_FIELDS, f"{path}/lane")
        waiting = exact_dict(row["waiting"], JOB_WAITING_FIELDS, f"{path}/waiting")
        scalar_list(waiting["hosts"], f"{path}/waiting/hosts")
        for listener_index, listener in enumerate(list_value(row["listeners"], f"{path}/listeners")):
            exact_dict(listener, JOB_LISTENER_FIELDS, f"{path}/listeners/{listener_index}")
    lanes = exact_dict(jobs["lanes"], {"busiest", "evicted", "hosts", "in_flight", "limits", "max_hosts", "waiting"}, "/proxy/health/jobs/lanes")
    for index, row in enumerate(list_value(lanes["busiest"], "/proxy/health/jobs/lanes/busiest")):
        exact_dict(row, HOST_LANE_FIELDS, f"/proxy/health/jobs/lanes/busiest/{index}")
    exact_dict(lanes["limits"], {"concurrency", "max_concurrency", "rate"}, "/proxy/health/jobs/lanes/limits")
    log = exact_dict(h["log"], {"file", "level", "stderr"}, "/proxy/health/log")
    exact_dict(log["file"], {"bytes", "dropped_lines", "max_bytes", "path", "rotations", "total_cap"}, "/proxy/health/log/file")
    project_watch(h["pass_watch"], "/proxy/health/pass_watch")
    if h["macro_recording"] is not None:
        exact_dict(h["macro_recording"], MACRO_RECORDING_FIELDS, "/proxy/health/macro_recording")
    passthrough = exact_dict(h["passthrough"], {"auto_switch_after", "client_trusts_ca", "findings", "ignore_hosts", "switched"}, "/proxy/health/passthrough")
    for index, row in enumerate(list_value(passthrough["findings"], "/proxy/health/passthrough/findings")):
        exact_dict(row, PASSTHROUGH_FINDING_FIELDS, f"/proxy/health/passthrough/findings/{index}")
    for key in ("ignore_hosts", "switched"):
        scalar_list(passthrough[key], f"/proxy/health/passthrough/{key}")
    exact_dict(h["pending"], {"active_jobs", "hook_latency_p95_us", "index_backlog", "pass", "passive_backlog", "playpen_last_drops", "sitemap_backlog"}, "/proxy/health/pending")
    policy = exact_dict(h["policy_lock"], {"allow_eval", "locked", "locked_keys", "note", "pass", "pass_path", "reasons", "refused"}, "/proxy/health/policy_lock")
    for key in ("locked_keys", "reasons", "refused"):
        scalar_list(policy[key], f"/proxy/health/policy_lock/{key}")
    if policy["pass"] is not None:
        exact_dict(policy["pass"], {"digest", "id"}, "/proxy/health/policy_lock/pass")
    process = exact_dict(h["process"], {"open_fds", "runtime", "tasks"}, "/proxy/health/process")
    runtime = exact_dict(process["runtime"], {"reactor", "workers"}, "/proxy/health/process/runtime")
    exact_dict(runtime["reactor"], {"backend", "selection_fallback", "verdict"}, "/proxy/health/process/runtime/reactor")
    exact_dict(process["tasks"], {"cancelling", "running", "total"}, "/proxy/health/process/tasks")
    if h["requests"] is not None:
        exact_dict(h["requests"], {"blocks", "carried", "counter", "drawn", "handed", "in_hand", "ledger", "left", "spent", "total", "total_at_start", "unused"}, "/proxy/health/requests")
    exact_dict(h["script_refusals"], {"failed_writes", "pending", "rows", "total"}, "/proxy/health/script_refusals")
    scripts = exact_dict(h["scripts"], {"disable_after", "disabled", "generation", "scripts", "unattributed"}, "/proxy/health/scripts")
    for index, row in enumerate(list_value(scripts["scripts"], "/proxy/health/scripts/scripts")):
        project_health_script(row, f"/proxy/health/scripts/scripts/{index}")
    exact_dict(scripts["unattributed"], {"busy", "calls", "errors", "limits", "timeouts"}, "/proxy/health/scripts/unattributed")
    scalar_list(h["scripts_following"], "/proxy/health/scripts_following")
    stop = exact_dict(h["stop"], {"audit_dropped", "audit_pending", "generation", "history", "in_flight", "latched"}, "/proxy/health/stop")
    if stop["latched"] is not None:
        exact_dict(stop["latched"], LATCHED_STOP_FIELDS, "/proxy/health/stop/latched")
    for index, row in enumerate(list_value(stop["history"], "/proxy/health/stop/history")):
        path = f"/proxy/health/stop/history/{index}"
        exact_dict(row, STOP_RECORD_FIELDS, path)
        if row["pass"] is not None:
            pair = list_value(row["pass"], f"{path}/pass")
            if len(pair) != 2 or not all(isinstance(item, str) for item in pair):
                fail(f"{path}/pass", "expected [pass id, digest]")
        for cancelled_index, cancelled in enumerate(list_value(row["cancelled"], f"{path}/cancelled")):
            cancelled_path = f"{path}/cancelled/{cancelled_index}"
            exact_dict(cancelled, CANCELLED_FIELDS, cancelled_path)
            exact_dict(cancelled["work"], WORK_FIELDS, f"{cancelled_path}/work")


def normalize_listener(value, path):
    typed(value, str, path)
    host, separator, port = value.rpartition(":")
    if not separator or not host or not port or any(character not in "0123456789" for character in port):
        fail(path, "expected host:ASCII-decimal-port")
    if not 0 <= int(port) <= 65535:
        fail(path, "port is out of range")
    return {"host": host, "port": "<ephemeral>"}


def normalize_proxy(proxy):
    validate_proxy_shape(proxy)
    projected, dropped = drop_proxy_fields(proxy)
    assert not dropped
    projected["engine"]["listener"] = normalize_listener(proxy["engine"]["listener"], "/proxy/engine/listener")
    projected["engine"]["pass"] = projected["engine"]["pass"] is not None
    gate = projected["health"]["gate"]
    if gate["pass"] is not None:
        gate["pass"] = {
            "current_matches_loaded": gate["pass"]["current_digest"] == gate["pass"]["digest"],
            "destinations": gate["pass"]["destinations"],
            "name": gate["pass"]["name"],
            "operator": gate["pass"]["operator"],
            "owner": gate["pass"]["owner"],
            "reference": gate["pass"]["reference"],
            "window": gate["pass"]["window"],
        }
    policy = projected["health"]["policy_lock"]
    policy["pass"] = policy["pass"] is not None
    policy["pass_path"] = policy["pass_path"] is not None
    pending = projected["health"]["pending"]
    if isinstance(pending["pass"], str) and pending["pass"].startswith("bound"):
        pending["pass"] = "bound"
    return projected


def project_version(raw):
    version = envelope(raw, "version", "version")
    exact_dict(version, VERSION_FIELDS, "/version/version")
    if version["engine"] is None:
        fail("/version/version/engine", "running engine must answer prelaunch inventory")
    project_engine(version["engine"], "/version/version/engine")
    return {
        "answered_by": version["answered_by"],
        "arch": version["arch"],
        "commit": version["commit"],
        "engine": {key: version["engine"][key] for key in ("build", "enforced", "mode", "policy_locked")} | {"listener": normalize_listener(version["engine"]["listener"], "/version/version/engine/listener")},
        "os": version["os"],
        "profile": version["profile"],
        "protocol": version["protocol"],
        "version": version["version"],
    }


def project_projects(raw):
    rows = list_value(envelope(raw, "projects_list", "projects"), "/projects_list/projects")
    projected_rows = []
    for index, row in enumerate(rows):
        exact_dict_optional(row, PROJECT_LIST_FIELDS, PROJECT_LIST_OPTIONAL_FIELDS, f"/projects_list/projects/{index}")
        projected_rows.append({"current": row["current"], "problem": row.get("problem")})
    project = envelope(raw, "projects_show", "project")
    exact_dict(project, PROJECT_SHOW_FIELDS, "/projects_show/project")
    return {
        "list": projected_rows,
        "show": {key: project[key] for key in ("blob_files", "exists", "flows", "found", "latest_schema", "schema_version")},
    }


def project_links(raw):
    projects = envelope(raw, "projects_list", "projects")
    shown = envelope(raw, "projects_show", "project")
    proxy = envelope(raw, "proxy_status", "proxy")
    version = envelope(raw, "version", "version")
    settings = envelope(raw, "config_list", "settings")
    report = envelope(raw, "pass_show", "pass")
    project_row = projects[0] if len(projects) == 1 else {}
    config_values = {row.get("key"): row.get("value") for row in settings if isinstance(row, dict)}
    pass_path = config_values.get("pass.path")
    gate_pass = proxy.get("health", {}).get("gate", {}).get("pass") or {}
    policy = proxy.get("health", {}).get("policy_lock", {})
    policy_pass = policy.get("pass") or {}
    report = report or {}
    shown_path = shown.get("path")
    shown_id = shown.get("id")
    return {
        "project": {
            "config_under_project": isinstance(shown_path, str) and shown.get("config") == f"{shown_path}/.teapot/config.toml",
            "list_show_identity": project_row.get("path") == shown_path and project_row.get("id") == shown_id,
            "proxy_identity": proxy.get("project") == shown_path and proxy.get("engine", {}).get("project") == shown_path and proxy.get("engine", {}).get("project_id") == shown_id,
            "version_identity": version.get("engine", {}).get("project") == shown_path and version.get("engine", {}).get("project_id") == shown_id,
        },
        "approval": {
            "paths_equal": isinstance(pass_path, str) and pass_path == proxy.get("engine", {}).get("pass") == gate_pass.get("path") == policy.get("pass_path") == report.get("pass_file"),
            "ids_equal": gate_pass.get("id") is not None and gate_pass.get("id") == policy_pass.get("id") == report.get("id"),
            "digests_equal": gate_pass.get("digest") is not None and gate_pass.get("digest") == gate_pass.get("current_digest") == policy_pass.get("digest") == report.get("digest"),
        },
    }


def project_pass(raw):
    value = envelope(raw, "pass_show", "pass")
    if value is None:
        return None
    exact_dict_optional(value, PASS_FIELDS, PASS_OPTIONAL_FIELDS, "/pass_show/pass")
    for index, row in enumerate(list_value(value["ceilings"], "/pass_show/pass/ceilings")):
        exact_dict(row, CEILING_FIELDS, f"/pass_show/pass/ceilings/{index}")
    for index, row in enumerate(list_value(value["destinations"], "/pass_show/pass/destinations")):
        exact_dict(row, DESTINATION_FIELDS, f"/pass_show/pass/destinations/{index}")
        scalar_list(row["names"], f"/pass_show/pass/destinations/{index}/names")
    enforcement = exact_dict(value["enforcement"], ENFORCEMENT_FIELDS, "/pass_show/pass/enforcement")
    scalar_list(enforcement["not_enforceable"], "/pass_show/pass/enforcement/not_enforceable")
    if enforcement["last_drop_list"] is not None:
        drop_list = exact_dict(enforcement["last_drop_list"], {"packets", "destinations"}, "/pass_show/pass/enforcement/last_drop_list")
        for index, row in enumerate(list_value(drop_list["destinations"], "/pass_show/pass/enforcement/last_drop_list/destinations")):
            exact_dict_optional(row, {"address", "protocol", "packets"}, {"port"}, f"/pass_show/pass/enforcement/last_drop_list/destinations/{index}")
    lock = exact_dict(value["lock"], LOCK_FIELDS, "/pass_show/pass/lock")
    for key in ("locked_keys", "reasons", "refused"):
        scalar_list(lock[key], f"/pass_show/pass/lock/{key}")
    if value["newer_pass"] is not None:
        newer = exact_dict_optional(value["newer_pass"], {"widens", "narrows"}, {"digest"}, "/pass_show/pass/newer_pass")
        scalar_list(newer["widens"], "/pass_show/pass/newer_pass/widens")
        scalar_list(newer["narrows"], "/pass_show/pass/newer_pass/narrows")
    upstream = value.get("upstream_proxy")
    if upstream is not None:
        exact_dict(upstream, UPSTREAM_PROXY_FIELDS, "/pass_show/pass/upstream_proxy")
        addresses = []
        for index, row in enumerate(list_value(upstream["addresses"], "/pass_show/pass/upstream_proxy/addresses")):
            exact_dict_optional(row, ADDRESS_VERDICT_FIELDS, ADDRESS_VERDICT_OPTIONAL_FIELDS, f"/pass_show/pass/upstream_proxy/addresses/{index}")
            addresses.append(row)
        upstream = upstream.copy()
        upstream["addresses"] = sorted(addresses, key=lambda row: row["address"])
    return {key: value[key] for key in ("ceilings", "destinations", "enforcement", "lock", "name", "newer_pass", "off_pass", "operator", "owner", "reference", "refusals", "relay", "required", "source", "state", "stop", "window")} | {"upstream_proxy": upstream}


def project_rows(raw, command, payload, required, optional=(), sort_key=None):
    rows = list_value(envelope(raw, command, payload), f"/{command}/{payload}")
    projected = []
    for index, row in enumerate(rows):
        exact_dict_optional(row, required, optional, f"/{command}/{payload}/{index}")
        projected.append(row)
    if sort_key:
        projected.sort(key=sort_key)
    return projected


def require_empty(rows, path):
    if rows:
        fail(path, "prelaunch state must be empty")
    return []


def project_simple(raw):
    scope = project_rows(raw, "scope_list", "scope", SCOPE_FIELDS, sort_key=lambda row: (row["entry"], row["path"], row["subdomains"]))
    hosts = project_rows(raw, "hosts_list", "hosts", HOST_FIELDS, sort_key=lambda row: (row["name"], tuple(row["addresses"])))
    for index, row in enumerate(hosts):
        scalar_list(row["addresses"], f"/hosts_list/hosts/{index}/addresses")
    flows = require_empty(list_value(envelope(raw, "flows_list", "flows"), "/flows_list/flows"), "/flows_list/flows")
    findings = envelope(raw, "findings_list", "findings")
    exact_dict(findings, {"counts", "failing", "grouped", "groups", "more", "rows", "total"}, "/findings_list/findings")
    exact_dict(findings["counts"], {"critical", "high", "info", "low", "medium"}, "/findings_list/findings/counts")
    require_empty(list_value(findings["rows"], "/findings_list/findings/rows"), "/findings_list/findings/rows")
    leads = envelope(raw, "leads_list", "leads")
    exact_dict(leads, {"count", "more", "rows"}, "/leads_list/leads")
    lead_rows = []
    for index, row in enumerate(list_value(leads["rows"], "/leads_list/leads/rows")):
        exact_dict_optional(row, LEAD_FIELDS, LEAD_OPTIONAL_FIELDS, f"/leads_list/leads/rows/{index}")
        lead_rows.append(row)
    lead_rows.sort(key=lambda row: row["id"])
    sessions = require_empty(list_value(envelope(raw, "sessions_list", "sessions"), "/sessions_list/sessions"), "/sessions_list/sessions")
    rules = project_rows(raw, "rules_list", "rules", RULE_FIELDS, RULE_OPTIONAL_FIELDS, sort_key=lambda row: (row["n"], row["name"]))
    intercept = envelope(raw, "intercept_status", "intercept")
    exact_dict(intercept, INTERCEPT_FIELDS, "/intercept_status/intercept")
    intercept_rules = list_value(envelope(raw, "intercept_rules_list", "rules"), "/intercept_rules_list/rules")
    for index, row in enumerate(intercept_rules):
        exact_dict(row, INTERCEPT_RULE_FIELDS, f"/intercept_rules_list/rules/{index}")
    require_empty(intercept_rules, "/intercept_rules_list/rules")
    queue = list_value(envelope(raw, "intercept_queue_list", "queue"), "/intercept_queue_list/queue")
    for index, row in enumerate(queue):
        exact_dict(row, PAUSED_ROW_FIELDS, f"/intercept_queue_list/queue/{index}")
    require_empty(queue, "/intercept_queue_list/queue")
    approvals = list_value(envelope(raw, "scripts_approvals", "approvals"), "/scripts_approvals/approvals")
    for index, row in enumerate(approvals):
        exact_dict(row, SCRIPT_APPROVAL_FIELDS, f"/scripts_approvals/approvals/{index}")
    require_empty(approvals, "/scripts_approvals/approvals")
    settings = project_rows(raw, "config_list", "settings", CONFIG_FIELDS, sort_key=lambda row: row["key"])
    for index, row in enumerate(settings):
        if row["key"] == "pass.path" and row["value"] is not None:
            row = row.copy()
            row["value"] = "<run-private-pass>"
            settings[index] = row
    macros = require_empty(list_value(envelope(raw, "macros_list", "macros"), "/macros_list/macros"), "/macros_list/macros")
    jobs = require_empty(list_value(envelope(raw, "jobs_list", "jobs"), "/jobs_list/jobs"), "/jobs_list/jobs")
    sitemap = envelope(raw, "sitemap_show", "sitemap")
    exact_dict(sitemap, {"backlog", "filter_cut", "folded", "follower", "hidden_hosts", "hidden_nodes", "hosts", "map", "more", "nodes", "rows", "shown", "view"}, "/sitemap_show/sitemap")
    require_empty(list_value(sitemap["rows"], "/sitemap_show/sitemap/rows"), "/sitemap_show/sitemap/rows")
    matrix = envelope(raw, "authz_matrix", "matrix")
    exact_dict(matrix, {"abbreviations", "empty", "filter", "legend", "more", "next_cursor", "order", "rows", "sessions", "sessions_not_shown", "shown", "surprising", "surprising_only", "text"}, "/authz_matrix/matrix")
    require_empty(list_value(matrix["rows"], "/authz_matrix/matrix/rows"), "/authz_matrix/matrix/rows")
    for key in ("abbreviations", "filter", "sessions"):
        require_empty(list_value(matrix[key], f"/authz_matrix/matrix/{key}"), f"/authz_matrix/matrix/{key}")
    for index, row in enumerate(list_value(matrix["legend"], "/authz_matrix/matrix/legend")):
        exact_dict(row, MATRIX_LEGEND_FIELDS, f"/authz_matrix/matrix/legend/{index}")
    commands = list_value(envelope(raw, "commands_list", "commands"), "/commands_list/commands")
    for index, row in enumerate(commands):
        path = f"/commands_list/commands/{index}"
        exact_dict(row, SCRIPT_COMMAND_FIELDS, path)
        for arg_index, arg in enumerate(list_value(row["args"], f"{path}/args")):
            exact_dict(arg, SCRIPT_ARG_FIELDS, f"{path}/args/{arg_index}")
    require_empty(commands, "/commands_list/commands")
    return {
        "scope": scope,
        "hosts": hosts,
        "flows": flows,
        "findings": findings,
        "leads": {"count": leads["count"], "more": leads["more"], "rows": lead_rows},
        "sessions": sessions,
        "rules": rules,
        "intercept": intercept,
        "intercept_rules": intercept_rules,
        "intercept_queue": queue,
        "script_approvals": approvals,
        "config": settings,
        "macros": macros,
        "jobs": jobs,
        "sitemap": {key: sitemap[key] for key in ("backlog", "filter_cut", "folded", "hidden_hosts", "hidden_nodes", "hosts", "more", "nodes", "rows", "shown")},
        "authz_matrix": {key: matrix[key] for key in ("abbreviations", "empty", "filter", "legend", "more", "next_cursor", "rows", "sessions", "sessions_not_shown", "shown", "surprising", "surprising_only")},
        "commands": commands,
    }


def project_scripts(raw):
    rows = list_value(envelope(raw, "scripts_list", "scripts"), "/scripts_list/scripts")
    projected = []
    for index, row in enumerate(rows):
        path = f"/scripts_list/scripts/{index}"
        exact_dict(row, SCRIPT_FIELDS, path)
        checks = []
        for child_index, child in enumerate(list_value(row["checks"], f"{path}/checks")):
            exact_dict_optional(child, SCRIPT_CHECK_FIELDS, SCRIPT_CHECK_OPTIONAL_FIELDS, f"{path}/checks/{child_index}")
            checks.append(child)
        checks.sort(key=lambda child: child["id"])
        leads = []
        for child_index, child in enumerate(list_value(row["leads"], f"{path}/leads")):
            exact_dict_optional(child, SCRIPT_LEAD_FIELDS, SCRIPT_LEAD_OPTIONAL_FIELDS, f"{path}/leads/{child_index}")
            leads.append(child)
        leads.sort(key=lambda child: child["id"])
        hooks = []
        for child_index, child in enumerate(list_value(row["hooks"], f"{path}/hooks")):
            exact_dict_optional(child, SCRIPT_HOOK_FIELDS, SCRIPT_HOOK_OPTIONAL_FIELDS, f"{path}/hooks/{child_index}")
            hooks.append(child)
        commands = scalar_list(row["commands"], f"{path}/commands")
        signatures = scalar_list(row["signatures"], f"{path}/signatures")
        projected.append({key: row[key] for key in ("consecutive_failures", "error", "error_kind", "error_line", "errors", "file", "fix", "generation", "last_failure", "last_refused_send", "limit_hits", "name", "note", "overridden_by", "previous_running", "refused_sends", "source", "state", "timeouts")} | {"checks": checks, "commands": commands, "hooks": hooks, "leads": leads, "signatures": signatures})
    projected.sort(key=lambda row: (row["name"], row["source"], row["file"] or ""))
    return projected


def project_checks(raw):
    rows = list_value(envelope(raw, "checks_list", "checks"), "/checks_list/checks")
    projected = []
    for index, row in enumerate(rows):
        path = f"/checks_list/checks/{index}"
        exact_dict_optional(row, CHECK_FIELDS, CHECK_OPTIONAL_FIELDS, path)
        if row["replaced_by"] is not None:
            validate_check_origin(row["replaced_by"], f"{path}/replaced_by")
        for child_index, origin in enumerate(list_value(row["replaces"], f"{path}/replaces")):
            validate_check_origin(origin, f"{path}/replaces/{child_index}")
        if row.get("health") is not None:
            validate_check_health(row["health"], f"{path}/health")
        projected.append(row)
    projected.sort(key=lambda row: (row["id"], row["source"], row["script"] or "", row["line"] if row["line"] is not None else -1))
    return projected


def eligibility(projection):
    state = projection["state"]
    proxy = projection["proxy"]
    health = proxy["health"]
    pass_report = projection["pass"]
    violations = []

    def expect(actual, expected, label):
        if actual != expected:
            violations.append(f"{label}: expected {expected!r}, got {actual!r}")

    version = projection["version"]
    expect(version["version"], "0.1.0", "Teapot version")
    expect(version["protocol"], 1, "Teapot protocol")
    expect(version["answered_by"], "engine", "version responder")
    expect(version["engine"], {"build": "0.1.0", "enforced": False, "listener": {"host": "127.0.0.1", "port": "<ephemeral>"}, "mode": "regular", "policy_locked": True}, "version engine")

    expect(projection["links"], {"project": {"config_under_project": True, "list_show_identity": True, "proxy_identity": True, "version_identity": True}, "approval": {"paths_equal": True, "ids_equal": True, "digests_equal": True}}, "raw project and approval links")

    expect(projection["projects"]["list"], [{"current": True, "problem": None}], "project registry")
    project = projection["projects"]["show"]
    expect(project["exists"], True, "project existence")
    expect(project["found"], "explicit", "project selection")
    expect(project["flows"], 0, "project flow count")
    expect(project["blob_files"], 0, "project blob count")
    expect(project["schema_version"], project["latest_schema"], "project schema")

    expect(proxy["running"], True, "proxy running")
    expect(proxy["engine"]["build"], "0.1.0", "proxy build")
    expect(proxy["engine"]["mode"], "regular", "proxy mode")
    expect(proxy["engine"]["enforced"], False, "proxy enforcement")
    expect(proxy["engine"]["policy_locked"], True, "proxy policy lock")
    expect(proxy["engine"]["listener"], {"host": "127.0.0.1", "port": "<ephemeral>"}, "proxy listener")
    expect(proxy["engine"]["pass"], True, "proxy attached approval")

    capture = health["capture"]
    expect(capture["state"], "capturing", "capture state")
    for key in ("flows_not_captured", "gc_bytes_freed", "gc_errors", "gc_paused", "gc_runs", "resumes"):
        expect(capture[key], 0, f"capture {key}")
    for key in ("probe_error", "reason", "reason_text", "warning"):
        expect(capture[key], None, f"capture {key}")
    writer = capture["writer"]
    expect(writer["state"], "running", "capture writer state")
    for key in ("busy_retries", "discarded_records", "full_events", "queued_bytes", "queued_records", "refused_late_records", "rejected_records", "wal_restart_busy", "wal_restart_expired", "wal_restarts"):
        expect(writer[key], 0, f"capture writer {key}")
    expect(writer["wal_warning"], None, "capture writer WAL warning")

    expect(health["browser"], {"listeners": [], "refused_own_traffic": 0}, "browser listener state")
    expect(health["checks"], None, "check runtime state")
    for key, value in health["connections"].items():
        expect(value, 0, f"connection {key}")
    for group in ("flows", "tls", "upstream"):
        for key, value in health["counters"][group].items():
            expect(value, 0, f"proxy {group} {key}")
    expect(health["counters"]["events_dropped"], 0, "proxy events dropped")
    expect(health["counters"]["gate_refusals"], 0, "proxy gate refusals")
    for key, value in health["findings"].items():
        expect(value, 0, f"proxy findings {key}")

    gate = health["gate"]
    expect(gate["state"], "bound", "gate state")
    expect(gate["settings"], {"relay": "allow", "required": False}, "gate settings")
    expect(gate["closed"], {}, "gate closed reasons")
    expect(gate["failed_path"], None, "gate failed path")
    expect(gate["newer_pass_waiting"], None, "gate newer approval")
    expect(gate["off_pass"], 0, "gate off-pass count")
    expect(gate["questions"], 0, "gate questions")
    expect(gate["refusals"], {}, "gate refusal reasons")
    expect(gate["refusals_total"], 0, "gate refusal total")
    expect(gate["stop"], None, "gate stop")
    expect(gate["stop_reason"], None, "gate stop reason")
    if gate["pass"] is None:
        violations.append("gate approval is absent")
    else:
        expect(gate["pass"]["destinations"], 1, "gate approval destinations")
        expect(gate["pass"]["current_matches_loaded"], True, "gate current approval digest")
        expect(gate["pass"]["window"], "valid", "gate approval window")
    expect(gate["window"]["ending"], False, "gate approval ending")
    expect(gate["watch"]["last_edit"], None, "gate approval edit")
    expect(health["pass_watch"]["last_edit"], None, "pass watcher edit")

    jobs = health["jobs"]
    expect(jobs["active"], [], "active jobs")
    for key in ("ended", "record_failures", "started"):
        expect(jobs[key], 0, f"jobs {key}")
    for key in ("busiest",):
        expect(jobs["lanes"][key], [], f"job lanes {key}")
    for key in ("evicted", "hosts", "in_flight", "waiting"):
        expect(jobs["lanes"][key], 0, f"job lanes {key}")
    expect(health["macro_recording"], None, "macro recording")
    expect(health["log"]["level"], "info", "log level")
    expect(health["log"]["stderr"], False, "log stderr")
    expect(health["log"]["file"]["dropped_lines"], 0, "log dropped lines")
    expect(health["log"]["file"]["rotations"], 0, "log rotations")
    expect(health["passthrough"]["findings"], [], "passthrough findings")
    expect(health["passthrough"]["switched"], [], "passthrough switches")
    expect(health["passthrough"]["ignore_hosts"], [], "passthrough ignore hosts")
    expect(health["passthrough"]["client_trusts_ca"], False, "passthrough client trust")
    expect(health["passthrough"]["auto_switch_after"], 3, "passthrough switch threshold")
    for key in ("active_jobs", "index_backlog", "passive_backlog", "sitemap_backlog"):
        expect(health["pending"][key], 0, f"pending {key}")
    expect(health["pending"]["pass"], "bound", "pending approval")
    expect(health["pending"]["playpen_last_drops"], None, "playpen drops")

    policy = health["policy_lock"]
    expect(policy["allow_eval"], False, "policy eval")
    expect(policy["locked"], True, "policy lock")
    expect(policy["locked_keys"], ["pass.*", "proxy.mode"], "policy locked keys")
    expect(policy["pass"], True, "policy approval")
    expect(policy["pass_path"], True, "policy approval path")
    requests = health["requests"]
    if requests is None:
        violations.append("request ceiling is absent")
    else:
        for key in ("blocks", "carried", "drawn", "handed", "in_hand", "ledger", "spent", "unused"):
            expect(requests[key], 0, f"requests {key}")
        expect(requests["counter"], "requests", "request counter")
        expect(requests["total"], 1000, "request ceiling total")
        expect(requests["total_at_start"], 1000, "request ceiling start total")
        expect(requests["left"], 1000, "request ceiling left")
    for key, value in health["script_refusals"].items():
        expect(value, 0, f"script refusals {key}")
    expect(health["scripts"]["disabled"], 0, "disabled scripts")
    for key, value in health["scripts"]["unattributed"].items():
        expect(value, 0, f"unattributed script {key}")
    for row in health["scripts"]["scripts"]:
        expect(row["state"], "running", f"runtime script {row['name']} state")
        for key in ("busy", "consecutive_failures", "errors", "limits", "log_dropped", "timeouts"):
            expect(row[key], 0, f"runtime script {row['name']} {key}")
        expect(row["hooks"], [], f"runtime script {row['name']} hooks")
        expect(row["last_failure"], None, f"runtime script {row['name']} last failure")
    expect(health["scripts_following"], [], "followed scripts")
    stop = health["stop"]
    expect(stop, {"audit_dropped": 0, "audit_pending": 0, "generation": 0, "history": [], "in_flight": 0, "latched": None}, "stop state")

    if pass_report is None:
        violations.append("attached approval report is absent")
    else:
        expect(pass_report["destinations"], [{"label": "development-fixture", "name_rules": "scope", "names": [], "network": "127.0.0.1", "ports": "3000", "protocol": "tcp"}], "approval destination")
        expect(pass_report["ceilings"], [{"counter": "requests", "left": 1000, "spent": 0, "total": 1000, "unused": 0}], "approval ceiling")
        expect(pass_report["state"], "bound", "approval state")
        expect(pass_report["window"], "valid", "approval window")
        expect(pass_report["stop"], None, "approval stop")
        expect(pass_report["newer_pass"], None, "approval edits")
        expect(pass_report["off_pass"], 0, "approval off-pass count")
        expect(pass_report["refusals"], 0, "approval refusals")
        expect(pass_report["relay"], "allow", "approval relay")
        expect(pass_report["required"], False, "approval required")
        expect(pass_report["source"], "flag", "approval source")
        expect(pass_report["upstream_proxy"], None, "upstream proxy")
        expect(pass_report["enforcement"]["on"], False, "approval enforcement")
        expect(pass_report["enforcement"]["enforceable"], False, "approval enforceability")
        expect(pass_report["enforcement"]["code"], "not-enforceable", "approval enforcement code")
        expect(pass_report["enforcement"]["last_drop_list"], None, "approval drop list")
        expect(pass_report["lock"]["locked"], True, "approval lock")
        expect(pass_report["lock"]["locked_keys"], ["pass.*", "proxy.mode"], "approval locked keys")

    expect(state["scope"], [{"entry": "127.0.0.1", "path": "/*", "subdomains": False}], "fixture scope")
    expect(state["config"], [{"key": "pass.path", "value": "<run-private-pass>"}, {"key": "scope", "value": [{"host": "127.0.0.1", "path": "/*", "subdomains": False}]}], "project configuration")
    expect(state["intercept"], {"active_rules": 0, "change": None, "enabled": True, "on_timeout": "forward", "paused": 0, "rules": 0, "timeout_secs": None}, "intercept state")
    for name in ("hosts", "rules", "intercept_rules", "intercept_queue", "script_approvals"):
        if state[name]:
            violations.append(f"{name} is not empty")
    if state["leads"]["rows"] or state["leads"]["count"] != 0:
        violations.append("leads is not empty")
    expect(state["findings"]["total"], 0, "finding total")
    expect(state["findings"]["groups"], 0, "finding groups")
    expect(state["findings"]["failing"], None, "finding query failure")
    expect(state["findings"]["grouped"], True, "finding grouping")
    expect(state["findings"]["more"], False, "finding pagination")
    for key, value in state["findings"]["counts"].items():
        expect(value, 0, f"finding count {key}")
    expect(state["sitemap"], {"backlog": 0, "filter_cut": False, "folded": 0, "hidden_hosts": 0, "hidden_nodes": 0, "hosts": 0, "more": 0, "nodes": 0, "rows": [], "shown": 0}, "sitemap state")
    matrix_without_legend = {key: value for key, value in state["authz_matrix"].items() if key != "legend"}
    expect(matrix_without_legend, {"abbreviations": [], "empty": True, "filter": [], "more": False, "next_cursor": None, "rows": [], "sessions": [], "sessions_not_shown": 0, "shown": 0, "surprising": 0, "surprising_only": False}, "authorization matrix")
    expect(canonical_sha256(state["authz_matrix"]["legend"]), EXPECTED_MATRIX_LEGEND_SHA256, "authorization matrix legend")
    expect(state["commands"], [], "script commands")

    for row in projection["scripts"]:
        if row["source"] != "bundled" or row["file"] is not None:
            violations.append(f"non-bundled script {row['name']}")
        expect(row["state"], "running", f"script {row['name']} state")
        expect(row["previous_running"], False, f"script {row['name']} previous revision")
        for key in ("consecutive_failures", "errors", "limit_hits", "refused_sends", "timeouts"):
            expect(row[key], 0, f"script {row['name']} {key}")
        for key in ("error", "error_kind", "error_line", "fix", "last_failure", "last_refused_send", "note", "overridden_by"):
            expect(row[key], None, f"script {row['name']} {key}")
        expect(row["commands"], [], f"script {row['name']} commands")
        expect(row["hooks"], [], f"script {row['name']} hooks")
        expect(row["signatures"], [], f"script {row['name']} signatures")
    for row in projection["checks"]:
        if row["source"] not in {"builtin", "bundled"}:
            violations.append(f"non-native check {row['id']}")
        expect(row["state"], "enabled", f"check {row['id']} state")
        expect(row["replaced_by"], None, f"check {row['id']} replacement")
        expect(row["replaces"], [], f"check {row['id']} replaced origins")
        expect(row.get("health"), None, f"check {row['id']} health")
    expect(canonical_sha256(projection["scripts"]), EXPECTED_SCRIPTS_SHA256, "pinned built-in script set")
    expect(canonical_sha256(projection["checks"]), EXPECTED_CHECKS_SHA256, "pinned native check set")
    return {"eligible": not violations, "violations": violations}


def project_inventory(inventory, schema_dir=SCHEMA_DIR):
    exact_dict(inventory, COMMANDS, "")
    validate_inventory_schemas(inventory, schema_dir)
    proxy = envelope(inventory, "proxy_status", "proxy")
    projection = {
        "schema_version": SCHEMA_VERSION,
        "version": project_version(inventory),
        "projects": project_projects(inventory),
        "links": project_links(inventory),
        "proxy": normalize_proxy(proxy),
        "pass": project_pass(inventory),
        "state": project_simple(inventory),
        "scripts": project_scripts(inventory),
        "checks": project_checks(inventory),
    }
    projection["prelaunch"] = eligibility(projection)
    return projection, canonical_sha256(projection)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inventory", type=Path)
    args = parser.parse_args()
    try:
        projection, digest = project_inventory(json.loads(args.inventory.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError, ProjectionError) as error:
        parser.exit(1, f"error: inventory projection: {error}\n")
    print(json.dumps({"schema_version": SCHEMA_VERSION, "sha256": digest, "projection": projection}, sort_keys=True, separators=(",", ":"), ensure_ascii=False))


if __name__ == "__main__":
    main()
