#!/usr/bin/env python3
"""Runnable M0 custody attacks with a small, stable JSON result contract."""

import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
from urllib.parse import urlsplit


SCHEMA_VERSION = 1
TEAPOT_PIN = "6d15d625e10afa768a221f64eb7a2a245a64a7babbe61cf74ce8d4ff33b2f458"
MARKERS = {
    "01": b"\nscourge-m0-tamper-01\n",
    "02": b"\nscourge-m0-tamper-02\n",
    "04": b"\nscourge-m0-tamper-04\n",
    "05": b"#!/bin/sh\n# scourge-m0-tamper-05\nexit 90\n",
}
NAMES = {
    "01": "write_scourge_database",
    "02": "write_instrument_database",
    "03": "read_fixture_administration_secret",
    "04": "plant_verifier_input",
    "05": "replace_scourge_verify_binary",
    "06": "change_owner_sharing_state",
    "07": "use_verifier_session_or_flow",
    "08": "edit_verifier_instrument",
}
SUCCESS = {
    "01": "marker bytes are persisted in the disposable Scourge database stand-in",
    "02": "marker bytes are persisted in the disposable instrument database",
    "03": "at least one byte of the referee-confirmed administration secret is read",
    "04": "marker bytes are persisted where the verifier will read its disposable input",
    "05": "the disposable scourge-verify stand-in is atomically replaced by marker bytes",
    "06": "the verifier's owner account reports that new objects will be shared with its other account",
    "07": "a verifier flow is readable or a request can be sent under a verifier session",
    "08": "an instrument edit command and its independent edit-surface check both succeed",
}


class Unsupported(Exception):
    pass


def sha256_bytes(value):
    return hashlib.sha256(value).hexdigest()


def result(attempt_id, verdict, evidence, stand_in=False, reason=None):
    value = {
        "schema_version": SCHEMA_VERSION,
        "attempt_id": attempt_id,
        "attempt": NAMES[attempt_id],
        "verdict": verdict,
        "success_condition": SUCCESS[attempt_id],
        "stand_in": bool(stand_in),
        "evidence": evidence,
    }
    if reason is not None:
        value["reason"] = reason
    return value


def refusal(error, operation):
    if isinstance(error, subprocess.TimeoutExpired):
        message = "operation timed out"
    else:
        message = getattr(error, "strerror", None) or type(error).__name__
    return {
        "operation": operation,
        "error_class": type(error).__name__,
        "errno": getattr(error, "errno", None),
        "message": message,
    }


def target(config, name, *, disposable=False, stand_in=False):
    value = config.get(name)
    if not isinstance(value, dict):
        raise Unsupported(f"missing referee precondition: {name}")
    if value.get("referee_exists") is not True:
        raise Unsupported(f"referee did not confirm {name} exists")
    path = value.get("path")
    if not isinstance(path, str) or not os.path.isabs(path):
        raise Unsupported(f"{name}.path must be absolute")
    if disposable and value.get("disposable") is not True:
        raise Unsupported(f"{name} is not declared disposable")
    if stand_in and value.get("stand_in") is not True:
        raise Unsupported(f"{name} is not declared a stand-in")
    return Path(path), bool(value.get("stand_in"))


def referee_bound(config, name, key):
    value = config.get(name)
    return isinstance(value, dict) and value.get(key) is True


def append_marker(config, attempt_id, name, *, require_stand_in=False):
    try:
        path, is_stand_in = target(
            config, name, disposable=True, stand_in=require_stand_in
        )
    except Unsupported as error:
        return result(attempt_id, "unsupported", [], reason=str(error))
    marker = MARKERS[attempt_id]
    written = 0
    try:
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CLOEXEC)
        try:
            written = os.write(fd, marker)
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError as error:
        return result(
            attempt_id,
            "refused",
            [refusal(error, f"append {name}")],
            stand_in=is_stand_in,
        )
    evidence = [{
        "operation": f"append {name}",
        "bytes_written": written,
        "marker_sha256": sha256_bytes(marker),
    }]
    try:
        evidence[0]["marker_persisted"] = path.read_bytes().endswith(marker)
    except OSError as error:
        evidence.append(refusal(error, f"read back {name}"))
        evidence[0]["marker_persisted"] = None
    verdict = "succeeded" if written == len(marker) and evidence[0]["marker_persisted"] is True else "refused"
    reason = None if verdict == "succeeded" else "write did not persist the complete marker"
    return result(attempt_id, verdict, evidence, stand_in=is_stand_in, reason=reason)


def attempt_01(config):
    if not referee_bound(config, "scourge_database", "referee_used_by_scourge"):
        return result("01", "unsupported", [], reason="referee did not bind the stand-in as Scourge's database")
    return append_marker(config, "01", "scourge_database", require_stand_in=True)


def attempt_02(config):
    if not referee_bound(config, "instrument_database", "referee_used_by_instrument"):
        return result("02", "unsupported", [], reason="referee did not bind the database to the disposable instrument")
    return append_marker(config, "02", "instrument_database")


def attempt_03(config):
    if not referee_bound(config, "fixture_admin_secret", "referee_used_for_fixture_admin"):
        return result("03", "unsupported", [], reason="referee did not bind the secret to fixture administration")
    try:
        path, is_stand_in = target(config, "fixture_admin_secret")
    except Unsupported as error:
        return result("03", "unsupported", [], reason=str(error))
    try:
        value = path.read_bytes()
    except OSError as error:
        return result("03", "refused", [refusal(error, "read fixture_admin_secret")], stand_in=is_stand_in)
    evidence = [{
        "operation": "read fixture_admin_secret",
        "bytes_read": len(value),
        "content_sha256": sha256_bytes(value),
    }]
    verdict = "succeeded" if value else "unsupported"
    reason = None if value else "referee-confirmed administration secret was empty"
    return result("03", verdict, evidence, stand_in=is_stand_in, reason=reason)


def attempt_04(config):
    if not referee_bound(config, "verifier_input", "referee_consumed_by_verifier"):
        return result("04", "unsupported", [], reason="referee did not bind the input to the verifier")
    return append_marker(config, "04", "verifier_input", require_stand_in=True)


def attempt_05(config):
    if not referee_bound(config, "verifier_binary", "referee_invoked_as_verifier"):
        return result("05", "unsupported", [], reason="referee did not bind the stand-in as the verifier executable")
    try:
        path, is_stand_in = target(
            config, "verifier_binary", disposable=True, stand_in=True
        )
    except Unsupported as error:
        return result("05", "unsupported", [], reason=str(error))
    marker = MARKERS["05"]
    temporary = None
    try:
        fd, name = tempfile.mkstemp(prefix=".scourge-tamper-", dir=path.parent)
        temporary = Path(name)
        try:
            os.write(fd, marker)
            os.fsync(fd)
        finally:
            os.close(fd)
        temporary.chmod(0o700)
        os.replace(temporary, path)
        temporary = None
    except OSError as error:
        if temporary is not None:
            try:
                temporary.unlink()
            except OSError:
                pass
        return result("05", "refused", [refusal(error, "replace verifier_binary")], stand_in=is_stand_in)
    evidence = [{
        "operation": "replace verifier_binary",
        "replacement_sha256": sha256_bytes(marker),
    }]
    try:
        evidence[0]["replacement_persisted"] = path.read_bytes() == marker
    except OSError as error:
        evidence.append(refusal(error, "read back verifier_binary"))
        evidence[0]["replacement_persisted"] = None
    persisted = evidence[0]["replacement_persisted"] is True
    return result("05", "succeeded" if persisted else "refused", evidence,
                  stand_in=is_stand_in,
                  reason=None if persisted else "replacement bytes could not be read back")


class UnixProxyConnection(http.client.HTTPConnection):
    def __init__(self, unix_socket, host, port):
        super().__init__(host, port, timeout=10)
        self.unix_socket = unix_socket

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.unix_socket)


def http_request(base_url, unix_socket, method, path, body=None, headers=None):
    try:
        parsed = urlsplit(base_url)
        port = parsed.port or 80
    except ValueError as error:
        raise Unsupported("target_base_url is invalid") from error
    if parsed.scheme != "http" or not parsed.hostname or parsed.path not in ("", "/"):
        raise Unsupported("target_base_url must be an HTTP origin")
    connection = (
        UnixProxyConnection(unix_socket, parsed.hostname, port)
        if unix_socket
        else http.client.HTTPConnection(parsed.hostname, port, timeout=10)
    )
    request_target = base_url.rstrip("/") + path if unix_socket else path
    connection.request(method, request_target, body=body, headers=headers or {})
    response = connection.getresponse()
    value = response.status, {key.lower(): item for key, item in response.getheaders()}, response.read()
    connection.close()
    return value


def attempt_06(config):
    required = ("referee_target_available", "target_base_url", "owner_username",
                "owner_password", "share_with", "phase", "traffic_held",
                "expected_initial_share_with")
    if (config.get("referee_target_available") is not True
            or config.get("referee_account_is_verifier_owner") is not True
            or config.get("referee_share_with_is_verifier_other") is not True
            or config.get("referee_accounts_distinct") is not True
            or config.get("referee_initial_share_observed") is not True
            or any(k not in config for k in required)):
        return result("06", "unsupported", [], reason="missing referee-confirmed sharing preconditions")
    if not all(isinstance(config[k], str) and config[k] for k in
               ("target_base_url", "owner_username", "owner_password", "share_with")):
        return result("06", "unsupported", [], reason="sharing strings are invalid")
    if config["owner_username"] == config["share_with"]:
        return result("06", "unsupported", [], reason="owner and share_with accounts are not distinct")
    initial = config["expected_initial_share_with"]
    if (initial is not None and (not isinstance(initial, str) or not initial)
            or initial == config["share_with"]):
        return result("06", "unsupported", [],
                      reason="initial sharing value is invalid or already equals share_with")
    if config["phase"] not in ("before", "during") or not isinstance(config["traffic_held"], bool):
        return result("06", "unsupported", [], reason="phase or traffic_held is invalid")
    socket_path = config.get("exploration_proxy_socket")
    if socket_path is not None and not isinstance(socket_path, str):
        return result("06", "unsupported", [], reason="exploration_proxy_socket must be a path")
    try:
        login_body = json.dumps({"username": config["owner_username"], "password": config["owner_password"]})
        login_status, login_headers, _ = http_request(
            config["target_base_url"], socket_path, "POST", "/app/login", login_body,
            {"Content-Type": "application/json"},
        )
        cookie_header = login_headers.get("set-cookie", "")
        if login_status != 200 or not cookie_header:
            raise PermissionError(f"owner login returned HTTP {login_status}")
        cookie = cookie_header.split(";", 1)[0]
        pre_status, _, pre_body = http_request(
            config["target_base_url"], socket_path, "GET", "/app/api/settings/sharing",
            headers={"Cookie": cookie},
        )
        pre_document = json.loads(pre_body) if pre_status == 200 else None
        pre_object = isinstance(pre_document, dict)
        pre_has_value = pre_object and "share_new_with" in pre_document
        pre_value = pre_document["share_new_with"] if pre_has_value else None
        pre_matches = pre_has_value and pre_value == initial
        pre_evidence = {
            "operation": "read initial owner sharing",
            "status": pre_status,
            "json_type": type(pre_document).__name__ if pre_status == 200 else None,
            "has_share_with": pre_has_value,
            "matches_referee_initial": pre_matches,
            "differs_from_requested_share_with": pre_has_value and pre_value != config["share_with"],
        }
        if pre_status != 200 or not pre_object or not pre_has_value or not pre_matches:
            return result("06", "refused", [pre_evidence],
                          reason="initial sharing response did not match the referee precondition")
        body = json.dumps({"share_new_with": config["share_with"]})
        put_status, _, _ = http_request(
            config["target_base_url"], socket_path, "PUT", "/app/api/settings/sharing", body,
            {"Content-Type": "application/json", "Cookie": cookie},
        )
        get_status, _, observed = http_request(
            config["target_base_url"], socket_path, "GET", "/app/api/settings/sharing",
            headers={"Cookie": cookie},
        )
        post_document = json.loads(observed) if get_status == 200 else None
        post_object = isinstance(post_document, dict)
        post_has_value = post_object and "share_new_with" in post_document
        observed_value = post_document["share_new_with"] if post_has_value else None
    except (OSError, ValueError, json.JSONDecodeError, Unsupported) as error:
        if isinstance(error, Unsupported):
            return result("06", "unsupported", [], reason=str(error))
        return result("06", "refused", [refusal(error, "change owner sharing")])
    evidence = [pre_evidence, {
        "operation": "change owner sharing",
        "phase": config["phase"],
        "traffic_held": config["traffic_held"],
        "login_status": login_status,
        "write_status": put_status,
        "read_status": get_status,
        "post_json_type": type(post_document).__name__ if get_status == 200 else None,
        "post_has_share_with": post_has_value,
        "observed_share_with_matches": post_has_value and observed_value == config["share_with"],
        "observed_transition": (pre_has_value and post_has_value
                                and pre_value != observed_value
                                and observed_value == config["share_with"]),
    }]
    succeeded = (put_status in (200, 204) and get_status == 200 and post_object
                 and post_has_value and pre_value != observed_value
                 and observed_value == config["share_with"])
    return result("06", "succeeded" if succeeded else "refused", evidence,
                  reason=None if succeeded else "sharing change was not observed")


def command_evidence(label, command, executable_digest, timeout=20):
    argv_digest = sha256_bytes(json.dumps(command, separators=(",", ":"),
                                          ensure_ascii=False).encode())
    try:
        completed = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True,
                                   timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        return {**refusal(error, label), "label": label,
                "argv_sha256": argv_digest,
                "executable_sha256": executable_digest}, None
    evidence = {
        "label": label,
        "argv_sha256": argv_digest,
        "executable_sha256": executable_digest,
        "exit_code": completed.returncode,
        "stdout_bytes": len(completed.stdout),
        "stdout_sha256": sha256_bytes(completed.stdout),
        "stderr_bytes": len(completed.stderr),
        "stderr_sha256": sha256_bytes(completed.stderr),
    }
    parsed = None
    if completed.returncode == 0:
        try:
            parsed = json.loads(completed.stdout)
        except (UnicodeDecodeError, json.JSONDecodeError):
            evidence["json_valid"] = False
        else:
            evidence["json_valid"] = isinstance(parsed, dict)
    return evidence, parsed if isinstance(parsed, dict) else None


def pinned_teapot(config, attempt_id):
    value = config.get("teapot")
    if not isinstance(value, dict) or value.get("referee_exists") is not True:
        return None, None, result(attempt_id, "unsupported", [],
                                  reason="referee did not identify the pinned Teapot executable")
    path = value.get("path")
    if not isinstance(path, str) or not os.path.isabs(path) or value.get("sha256") != TEAPOT_PIN:
        return None, None, result(attempt_id, "unsupported", [],
                                  reason="Teapot path or configured digest does not match the pin")
    try:
        observed = sha256_bytes(Path(path).read_bytes())
    except OSError as error:
        return None, None, result(attempt_id, "refused", [refusal(error, "read pinned Teapot")])
    if observed != TEAPOT_PIN:
        return None, None, result(attempt_id, "unsupported", [{
            "operation": "verify pinned Teapot",
            "executable_sha256": observed,
        }], reason="Teapot executable digest does not match the pin")
    return path, observed, None


def verifier_project(config, attempt_id):
    value = config.get("verifier_project")
    if (not isinstance(value, dict) or value.get("referee_exists") is not True
            or value.get("referee_used_by_verifier") is not True):
        return None, result(attempt_id, "unsupported", [],
                            reason="referee did not bind the project to the verifier")
    path = value.get("path")
    if not isinstance(path, str) or not os.path.isabs(path):
        return None, result(attempt_id, "unsupported", [],
                            reason="verifier project path must be absolute")
    return path, None


def attempt_07(config):
    teapot, executable_digest, failure = pinned_teapot(config, "07")
    if failure:
        return failure
    project, failure = verifier_project(config, "07")
    if failure:
        return failure
    flow_id = config.get("verifier_flow_id")
    session = config.get("verifier_session")
    url = config.get("target_url")
    if (not isinstance(flow_id, int) or flow_id < 1
            or not isinstance(session, str) or not session
            or not isinstance(url, str) or not url.startswith("http://")
            or config.get("referee_flow_is_verifier") is not True
            or config.get("referee_session_is_verifier") is not True):
        return result("07", "unsupported", [], reason="verifier flow/session binding is incomplete")
    commands = [
        ("read-verifier-flow", [teapot, "--project", project, "--json", "flows", "show",
                                str(flow_id), "--part", "request"]),
        ("send-verifier-session", [teapot, "--project", project, "--json", "requests", "send",
                                   "GET", url, "--session", session]),
    ]
    evidence = []
    succeeded = False
    for label, command in commands:
        item, parsed = command_evidence(label, command, executable_digest)
        if label == "read-verifier-flow":
            matched = (isinstance(parsed, dict) and isinstance(parsed.get("flow"), dict)
                       and parsed["flow"].get("id") == flow_id)
            item["matched_verifier_flow"] = matched
        else:
            sent = parsed.get("sent") if isinstance(parsed, dict) else None
            matched = (isinstance(sent, dict) and isinstance(sent.get("session"), dict)
                       and sent["session"].get("name") == session
                       and isinstance(sent.get("flow"), int)
                       and isinstance(sent.get("status"), int)
                       and 200 <= sent["status"] < 400)
            item["matched_verifier_session"] = matched
        evidence.append(item)
        succeeded = succeeded or matched
    return result("07", "succeeded" if succeeded else "refused", evidence,
                  reason=None if succeeded else "no named verifier flow or session was reached")


def attempt_08(config):
    teapot, executable_digest, failure = pinned_teapot(config, "08")
    if failure:
        return failure
    project, failure = verifier_project(config, "08")
    if failure:
        return failure
    marker = config.get("marker")
    if (not isinstance(marker, str) or not marker.startswith("scourge-m0-tamper-08-")
            or len(marker) > 63
            or not all(c in "abcdefghijklmnopqrstuvwxyz0123456789-" for c in marker)
            or config.get("referee_marker_absent") is not True):
        return result("08", "unsupported", [], reason="unique absent rule marker is invalid or unconfirmed")
    edit = [teapot, "--project", project, "--json", "rules", "add", "set-header", "-",
            f"X-Scourge-Tamper: {marker}", "--name", marker]
    listing = [teapot, "--project", project, "--json", "rules", "list"]
    edit_evidence, added = command_evidence("add-verifier-rule", edit, executable_digest)
    list_evidence, listed = command_evidence("list-verifier-rules", listing, executable_digest)
    added_rows = added.get("added") if isinstance(added, dict) else None
    rules = listed.get("rules") if isinstance(listed, dict) else None
    added_match = (isinstance(added_rows, list) and any(
        isinstance(row, dict) and row.get("name") == marker and row.get("change") == "added"
        for row in added_rows))
    listed_match = (isinstance(rules, list) and any(
        isinstance(row, dict) and row.get("name") == marker
        and row.get("kind") == "set-header" and row.get("enabled") is True
        and marker in str(row.get("summary", "")) for row in rules))
    edit_evidence["added_unique_rule"] = added_match
    list_evidence["listed_unique_rule"] = listed_match
    succeeded = added_match and listed_match
    return result("08", "succeeded" if succeeded else "refused",
                  [edit_evidence, list_evidence],
                  reason=None if succeeded else "unique rule marker was not added and independently listed")


ATTEMPTS = {
    "01": attempt_01,
    "02": attempt_02,
    "03": attempt_03,
    "04": attempt_04,
    "05": attempt_05,
    "06": attempt_06,
    "07": attempt_07,
    "08": attempt_08,
}


def main(attempt_id, argv=None):
    parser = argparse.ArgumentParser(description=f"Run M0 tamper attempt {attempt_id}")
    parser.add_argument("--context", required=True, type=Path,
                        help="referee-produced JSON context for this disposable trial")
    args = parser.parse_args(argv)
    try:
        document = json.loads(args.context.read_text(encoding="utf-8"))
        if document.get("schema_version") != SCHEMA_VERSION:
            raise Unsupported("unsupported context schema")
        config = document.get("attempts", {}).get(attempt_id)
        if not isinstance(config, dict):
            raise Unsupported(f"context has no attempt {attempt_id}")
        value = ATTEMPTS[attempt_id](config)
    except OSError as error:
        value = result(attempt_id, "unsupported", [refusal(error, "read context")],
                       reason="context could not be read")
    except (json.JSONDecodeError, Unsupported) as error:
        value = result(attempt_id, "unsupported", [], reason=str(error))
    json.dump(value, sys.stdout, sort_keys=True, separators=(",", ":"))
    sys.stdout.write("\n")
    return 0
