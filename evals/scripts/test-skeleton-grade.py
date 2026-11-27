#!/usr/bin/env python3
"""Synthetic process and referee receipts for the offline four-cell rubric."""

from base64 import b64encode
import copy
import gzip
from itertools import groupby
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import tomllib
import unittest
from unittest.mock import patch
from uuid import NAMESPACE_URL, UUID, uuid5
import zlib

sys.path.insert(0, str(Path(__file__).resolve().parent / "lib"))
import skeleton_grade as rubric


ORACLE = {"id": rubric.ORACLE_ID, "version": rubric.ORACLE_VERSION,
          "digest": rubric.native_digest(rubric.oracle_contract())}
TEST_MONITOR_KEY = bytes(range(32))
INVESTIGATION_IDENTITY = rubric.investigation_identity()
ROLES, IDENTITY_STEPS = rubric.oracle_roles(rubric.oracle_contract())
COOKIES = {"owner": "01234567-0123-4123-8123-0123456789ab",
           "other": "89abcdef-0123-4123-8123-0123456789ab"}
EXPLORATION_COOKIES = {"owner": "12345678-0123-4123-8123-0123456789ab",
                       "other": "9abcdef0-0123-4123-8123-0123456789ab"}
SUBJECTS = {"owner": "fixture-account-831", "other": "fixture-account-257"}
PINS = {"model": "scripted", "model_settings_sha256": "a" * 64, "harness_sha256": "b" * 64,
        "fixture_sha256": "c" * 64, "scourge_sha256": "d" * 64, "oracle": ORACLE,
        "teapot_sha256": rubric.HISTORICAL_TEAPOT_SHA256,
        "investigation_sha256": INVESTIGATION_IDENTITY["binary_sha256"],
        "investigation_exec_path": "/qualified/bin/investigation",
        "operation_registry": rubric.registry_pin(),
        "process_monitor_sha256": "e" * 64, "process_monitor_key_sha256": rubric.digest(TEST_MONITOR_KEY)}
PROPERTIES = {"positive": "private_reports", "public": "catalog", "login": "login_reports",
              "same_subject": "invoices", "f37": "cached_reports"}
ENGAGEMENT = "fixture"
DEFINED = json.loads((Path(__file__).resolve().parents[2]
                      / "fixtures/contracts/scourge-v1/verification-record.json").read_text())
FIXTURES = Path(__file__).resolve().parents[1] / "skeleton"
GUIDE = (Path(__file__).resolve().parents[2] /
         "crates/scourge-core/src/workspace/managed-guide.md").read_bytes()
SCREEN = b"Record security leads and verify findings with independent controls.\nA lead is an observation.\nNext  scourge list leads\n"
FLOW_TEMPLATE = json.loads((Path(__file__).resolve().parents[2] /
                            "fuzz/corpus/teapot_output/flows-show.json").read_text())
DECLARATION_TOML = (Path(__file__).resolve().parents[2] /
                    "fixtures/target/schema-examples/engagement.toml").read_bytes()
DECLARATION = tomllib.loads(DECLARATION_TOML.decode())
ORIGIN = "http://fixture.invalid:37279"
TARGET = {"origin": ORIGIN, "addresses": [], "tls_identity": None,
          "deployment_marker": None, "strength": "operator_asserted"}
PASS_TEMPLATE = json.loads((rubric.REPOSITORY / "fuzz/corpus/teapot_output/units-left.json").read_bytes())
VERSION_TEMPLATE = json.loads((rubric.REPOSITORY / "fuzz/corpus/teapot_output/describe.json").read_bytes())
DRY_RUN_TEMPLATE = json.loads((rubric.REPOSITORY / "fuzz/corpus/teapot_output/dry-run.json").read_bytes())
SESSION_TEMPLATE = json.loads((rubric.REPOSITORY / "fuzz/corpus/teapot_output/session-show.json").read_bytes())
PROXY_TEMPLATE = json.loads((rubric.REPOSITORY / "fuzz/corpus/teapot_output/describe-status.json").read_bytes())
SEND_TEMPLATE = json.loads((rubric.REPOSITORY / "fuzz/corpus/teapot_output/send.json").read_bytes())
PASS_FILE = "/qualified/fixture/operator-pass.toml"
ACTIVE_RULE = {"n": 1, "name": "edit", "kind": "block", "filter": "in:scope", "direction": "request",
               "enabled": True, "status": "running", "summary": "block"}


def evidence_id(kind, key):
    return f"{kind}_{uuid5(NAMESPACE_URL, f'scourge-skeleton-fixture/{kind}/{key}')}"


def case_evidence_ids(location):
    attempt = location.split("/")[0]
    return {"case": evidence_id("case", attempt), "handle": evidence_id("handle", location),
            "run": evidence_id("run", location), "manifest": evidence_id("art", f"{attempt}/manifest"),
            "experiment": evidence_id("art", f"{location}/experiment"),
            "publication": evidence_id("art", f"{location}/publication")}


def case_request_key(location):
    return f"rk_{uuid5(NAMESPACE_URL, f'scourge-skeleton-fixture/request/{location}').hex}"


def case_publication_key(location):
    intent = f"P-{uuid5(NAMESPACE_URL, f'scourge-skeleton-fixture/publication/{location}').hex}"
    return rubric.investigation_command_key("verification-publication", intent)


def fixture_capture_attachment(handle, run, key, position, ref, content):
    return {"role": "original-output", "availability": "staged", "digest": f'sha256:{ref["digest"]}',
            "size_bytes": len(content), "receipt": {"handle": handle, "run_id": run,
            "key": key, "position": position, "result": "accepted", "accepted_at": "2026-11-23T16:00:00Z",
            "request_digest": f'sha256:{rubric.native_digest([handle, key, ref["digest"]])}'}}


class Fixture:
    def __init__(self, root, declaration_source=DECLARATION_TOML, prompts=None, historical_cases=None, *,
                 clone_supplied_workspace=False, clone_supplied_lead=False):
        self.root = root
        self.evidence = rubric.Evidence(root, TEST_MONITOR_KEY)
        self.instrument_children = {}
        self.historical_cases = historical_cases or {}
        self.history = {}
        self.clone_supplied_lead = clone_supplied_lead
        self.declaration = tomllib.loads(declaration_source.decode())
        guide = (
            b"<!-- scourge:managed-start -->\n"
            + f"<!-- scourge:managed-sha256 {rubric.digest(GUIDE)} -->\n".encode()
            + GUIDE + b"<!-- scourge:managed-end -->\n"
        )
        self.manifest_source = self.write("frozen/engagement-source.toml", declaration_source)
        visible = {"engagement.toml": self.manifest_source["sha256"]}
        workspace_files = {}
        for cell in rubric.CELLS:
            workspace_cell = "executable/supplied" if clone_supplied_workspace and cell == "managed/supplied" else cell
            workspace_id = UUID(int=uuid5(NAMESPACE_URL, workspace_cell).int, version=4)
            base = f'frozen/{cell.replace("/", "-")}'
            workspace_files[cell] = {
                "scourge.toml": self.write(f"{base}/scourge.toml",
                                           f'version = 1\nworkspace_id = "{workspace_id}"\n'.encode()),
                ".scourge/demo-owner": self.write(f"{base}/.scourge/demo-owner", [str(workspace_id)]),
                ".scourge/state.sqlite3": self.write(f"{base}/.scourge/state.sqlite3", workspace_id.bytes),
            }
        self.pass_artifact = self.write("frozen/pass.toml", (
            b'format = 1\nid = "pass.development-fixture"\n'
            b'name = "Synthetic owned fixture"\n[ceilings]\nrequests = 2000\n'
        ))
        self.manifest = self.write("frozen/manifest.json", {
            "revision": 1, "source_digest": self.manifest_source["sha256"],
            "pass_digest": self.pass_artifact["sha256"], "declaration": self.declaration,
        })
        self.frozen = {
            "schema": rubric.ASSIGNMENT, "pins": PINS,
            "prompts": {name: self.write(f"frozen/{name}.txt", (prompts or {}).get(
                name, (FIXTURES / f"{name}.txt").read_bytes()))
                        for name in ("supplied", "discovery", "concept")},
            "managed_block": self.write("frozen/managed.md", guide),
            "cases": {key: {"property": {"id": prop, "digest": rubric.digest(
                                rubric.canonical(self.declaration["property"][prop]))},
                            "exposure": "unauthenticated" if key not in rubric.INVALID else None}
                      for key, prop in PROPERTIES.items()},
            "cells": {
                cell: {**self.provision(cell.replace("/", "-"), PROPERTIES),
                       "supplied_lead": self.native_id("L", cell.replace("/", "-"), 1)
                       if cell.endswith("/supplied") else None,
                       "workspace_config": workspace_files[cell]["scourge.toml"],
                       "visible": {**visible, **{name: ref["sha256"] for name, ref in workspace_files[cell].items()},
                                   **({"AGENTS.md": rubric.digest(guide)} if cell.startswith("managed") else {})}}
                for cell in rubric.CELLS},
            "f37": {**self.provision("scripted-f37", ("f37",)), "supplied_lead": "L-9"},
        }
        for cell, assignment in self.frozen["cells"].items():
            if not cell.endswith("/discovery"):
                continue
            inputs = {"engagement.toml": self.manifest_source, **workspace_files[cell]}
            if cell.startswith("managed"):
                inputs["AGENTS.md"] = self.frozen["managed_block"]
            assignment["discovery_review"] = self.write(f'frozen/{assignment["attempt_id"]}-review.json', {
                "schema": rubric.DISCOVERY_REVIEW, "source": "fixture-referee", "attempt_id": assignment["attempt_id"],
                "manifest_sha256": self.manifest["sha256"], "prompt_sha256": self.frozen["prompts"]["discovery"]["sha256"],
                "visible_inputs": inputs, "hints": [],
            })
        self.ledger = {"schema": rubric.LEDGER, "attempts": [self.trial(cell) for cell in rubric.CELLS],
                       "scripted_f37": self.scripted_f37()}

    def provision(self, prefix, cases):
        reset_id = f"reset-{prefix}"
        ids = case_evidence_ids(f"{prefix}/preparation")
        manifest_capture = self.write(f"frozen/preparation/{prefix}/manifest-capture.json", {
            "result": "record_shown", "id": ids["run"], "historical": False,
            "record": {"header": {"id": ids["run"], "case_id": ids["case"], "revision": 2}, "body": {
                "producer": rubric.INVESTIGATION_ACTOR,
                "capture": {"handle": ids["handle"], "protocol": rubric.INVESTIGATION_PROTOCOL,
                            "metadata": {"scourge_investigation": INVESTIGATION_IDENTITY}},
                "capture_finalization": {"finalization": "finalized",
                    "manifest": {"digest": f'sha256:{rubric.digest(reset_id.encode())}'}, "artifacts": [
                        {"key": "engagement", "position": 1, "retention": {"state": "retained",
                         "artifact_ref": {"id": ids["manifest"], "revision": 1},
                         "digest": f'sha256:{self.manifest["sha256"]}',
                         "size_bytes": len(self.evidence.read(self.manifest))}},
                    ]},
            }},
        })
        access = {}
        for case in cases:
            path = f"frozen/preparation/{prefix}/{case}"
            prop_id = PROPERTIES[case]
            bindings = {}
            for role, principal in (("owner", "alice"), ("other", "bob")):
                declared = self.declaration["principal"][principal]
                for field, cookies in (("session", EXPLORATION_COOKIES), ("verifier_session", COOKIES)):
                    reference = declared[field]
                    native = reference.removeprefix("session.").replace(".", "_")
                    subject = SUBJECTS["owner"] if case == "same_subject" and field == "verifier_session" else SUBJECTS[role]
                    probe = copy.deepcopy(FLOW_TEMPLATE)
                    original = probe["flow"]
                    original.update(id=len(bindings) + 1, url=ORIGIN + rubric.IDENTITY_PATH, request_head=(
                        f"GET {rubric.IDENTITY_PATH} HTTP/1.1\nCookie: scourge_session={cookies[role]}"
                    ))
                    payload = rubric.canonical({"id": subject})
                    original["response_body_base64"] = b64encode(payload).decode()
                    original["response_body_info"].update(captured=len(payload), shown=len(payload), observed=len(payload))
                    bindings[reference] = {
                        "native_session": native, "identity_probe": declared["identity_probe"],
                        "credential_sha256": rubric.digest(cookies[role].encode()),
                        "subject_sha256": rubric.digest(subject.encode()),
                        "original": self.write(f"{path}/{native}.json", probe),
                    }
            access[case] = self.write(f"{path}/access.json", {
                "schema": rubric.PREPARED_ACCESS, "source": "fixture-referee", "qualified": True,
                "attempt_id": prefix, "reset_id": reset_id, "case": case, "engagement": ENGAGEMENT,
                "property": {"id": prop_id, "digest": rubric.native_digest(self.declaration["property"][prop_id])},
                "manifest_sha256": self.manifest["sha256"], "environment_kind": "simulated",
                "instrument": DEFINED["instrument"], "target": TARGET, "bindings": bindings,
                "pass_file": PASS_FILE,
            })
        return {
            "attempt_id": prefix, "reset_id": reset_id, "session_access": access,
            "teapot_exec_path": self.teapot_exec_path(prefix),
            "manifest": self.manifest, "manifest_source": self.manifest_source,
            "pass_artifact": self.pass_artifact, "manifest_history": [], "manifest_capture": manifest_capture,
        }

    def write(self, path, value):
        data = value if isinstance(value, bytes) else rubric.canonical(value)
        location = self.root / path
        location.parent.mkdir(parents=True, exist_ok=True)
        location.write_bytes(data)
        return {"path": path, "sha256": rubric.digest(data)}

    def copy(self, path, source):
        return self.write(path, self.evidence.read(source))

    def retain(self, prefix):
        (self.root / prefix).mkdir(mode=0o700)
        self.write(f"{prefix}/retained/raw/worker.stderr", b"")
        raw = self.raw_transcript(prefix, [])
        return {"attempt_id": prefix, "raw": raw, "capture": self.capture(prefix, raw)}

    def raw_transcript(self, prefix, items):
        events = [{"type": "thread.started", "thread_id": prefix},
                  *({"type": "item.completed", "item": item} for item in items),
                  {"type": "turn.completed"}]
        return self.write(f"{prefix}/retained/raw/transcript.jsonl",
                          b"".join(rubric.canonical(event) + b"\n" for event in events))

    def capture(self, prefix, raw):
        data = self.evidence.read(raw)
        retained = self.root / prefix / "retained"
        (retained / "artifacts").mkdir(exist_ok=True)
        inventory = []
        for path in sorted(retained.rglob("*")):
            entry = {"path": path.relative_to(retained).as_posix()}
            if path.is_dir():
                entry.update(type="directory", bytes=0, sha256=None)
            else:
                contents = path.read_bytes()
                entry.update(type="file", bytes=len(contents), sha256=rubric.digest(contents))
            inventory.append(entry)
        inventory_hash = rubric.digest(rubric.canonical(inventory))
        def identity(path):
            info = path.stat()
            return {"device": info.st_dev, "inode": info.st_ino, "owner_uid": info.st_uid,
                    "mode": info.st_mode & 0o777}

        return self.write(f"{prefix}/capture.json", {
            "schema": "scourge.trial-capture", "schema_version": 1, "trial_id": prefix,
            "status": "settled", "settled": True, "valid": True, "score": None,
            "preflight": {"schema": "scourge.trial-capture-preflight", "schema_version": 1,
                          "run_root": str(self.root), "checkout": str(FIXTURES.parents[1]),
                          "exclude_roots": [],
                          "root_identity": identity(self.root), "passed": True, "reasons": [],
                          "capacity": {"minimum_bytes": 1, "available_bytes": 10_000_000,
                                       "minimum_inodes": 1, "available_inodes": 10_000},
                          "write_probe": {"bytes_written": 26, "flushed": True, "file_synced": True,
                                          "unlinked": True, "directory_synced": True}},
            "trial_identity": identity(self.root / prefix),
            "reasons": [], "terminal_event_type": "turn.completed",
            "process": {"exit_code": 0, "worker_stopped": True, "interrupted": False},
            "checks": {"safety_ok": True, "boundary_ok": True},
            "events": {"issues": [], "valid_prefix_sha256": raw["sha256"], "valid_prefix_bytes": len(data),
                       "valid_prefix_events": len(data.splitlines()), "terminal_line": len(data.splitlines())},
            "inventory": {"complete": True, "verified": True, "source": inventory, "retained": inventory,
                          "source_sha256": inventory_hash, "retained_sha256": inventory_hash},
        })

    def sync_capture(self, entry, *, native=False, items=None, children=None):
        """Settle test inputs after deliberate changes to captured observations."""
        prefix = entry["attempt_id"]
        referee = self.evidence.json(entry["referee"])
        if native:
            monitor = self.evidence.json(referee["events"])
            if items is None:
                items = [
                    {"id": row["native_item"], "type": "command_execution",
                     "command": shlex.join(["/usr/bin/bash", "-lc", shlex.join(row["argv"])]),
                     "aggregated_output": self.evidence.read(row["stdout"]).decode(),
                     "status": "completed", "exit_code": row["exit_code"]}
                    for row in monitor["calls"]
                ]
            monitor["commands"] = [
                {"native_item": item["id"], "command": item["command"],
                 "output_sha256": rubric.digest(item["aggregated_output"].encode()),
                 "tree_closed": True, "lost_events": 0, "exit_code": item["exit_code"],
                 "executions": [
                     {**{key: call[key] for key in ("process_id", "argv", "binary_sha256", "exec_path", "exit_code")},
                      "approved_child_processes": [proc["process_id"] for proc in self.instrument_children.get(
                          (prefix, item["id"]), []) if proc.get("parent_process_id") == call["process_id"]],
                      "stdout_bytes": len(self.evidence.read(call["stdout"])),
                      "stdout_sha256": call["stdout"]["sha256"], "stdout_offset": call["output_offset"]}
                     for call in monitor["calls"] if call["native_item"] == item["id"]
                 ] + self.instrument_children.get((prefix, item["id"]), []) + (children or {}).get(item["id"], [])}
                for item in items if item["type"] == "command_execution"
            ]
            referee["events"] = self.write(referee["events"]["path"], monitor)
        if items is not None:
            entry["raw"] = self.raw_transcript(prefix, items)
            for key in ("events", "case_index", "useful"):
                if key in referee:
                    self.change(referee, [key], lambda row: row.update(raw_sha256=entry["raw"]["sha256"]))
        if native:
            track = entry.get("cell", "scripted/supplied").split("/")[1]
            prompt = self.evidence.read(self.frozen["prompts"][track])
            trace = {
                "schema": rubric.HOST_TRACE, "attempt_id": prefix,
                "assignment_sha256": referee["assignment_sha256"],
                "session_id": monitor["session_id"], "raw_sha256": entry["raw"]["sha256"],
                "monitor_sha256": PINS["process_monitor_sha256"],
                "prompt_sha256": rubric.digest(prompt), "prompt_size_bytes": len(prompt),
                "drained": True, "lost_events": 0, "commands": monitor["commands"],
                "elapsed_milliseconds": monitor["elapsed_milliseconds"],
            }
            referee["host_trace"] = self.write(f"{prefix}/retained/artifacts/host-trace.json", {
                "trace": trace, "hmac_sha256": rubric.host_trace_mac(trace, TEST_MONITOR_KEY),
            })
        entry["capture"] = self.capture(prefix, entry["raw"])
        entry["referee"] = self.write(entry["referee"]["path"], {
            **referee, "capture_sha256": entry["capture"]["sha256"], "raw_sha256": entry["raw"]["sha256"],
        })

    def review(self, entry, **fields):
        return self.write(f'{entry["attempt_id"]}/referee.json', {
            "schema": rubric.REVIEW, "source": "referee", "capture_sha256": entry["capture"]["sha256"],
            "raw_sha256": entry["raw"]["sha256"],
            "assignment_sha256": rubric.digest(rubric.canonical(self.frozen)), **fields,
        })

    def native_id(self, kind, prefix, number):
        if kind == "L" and number == 1:
            if self.clone_supplied_lead and prefix in {"executable-supplied", "managed-supplied"}:
                return f"L-{UUID(int=uuid5(NAMESPACE_URL, 'executable-supplied').int, version=4).hex}"
            if prefix == "managed-supplied":
                return f"L-{uuid5(NAMESPACE_URL, prefix).hex}"
        return f"{kind}-{number}" if kind == "L" or prefix == "executable-supplied" else f"{kind}-{prefix}-{number}"

    @staticmethod
    def teapot_exec_path(prefix):
        return f"/qualified/prepared/{prefix}/teapot"

    def write_case(self, prefix, case, number, lead_index):
        spec = self.frozen["cases"][case]
        is_invalid = case in rubric.INVALID
        result, exposure = ("invalid", None) if is_invalid else ("true", spec["exposure"])
        lead, run, rid = (self.native_id(kind, prefix, lead_index) for kind in ("L", "R", "V"))
        location = f"{prefix}/retained/artifacts/{case}"
        manifest = self.copy(f"{location}/manifest.json", self.manifest)
        prop = self.declaration["property"][spec["property"]["id"]]
        record = copy.deepcopy(DEFINED)
        values = {"owner": "alice", "other": "bob", "read": prop["read"],
                  "plant": prop["plant"]["operation"], "remove": prop["remove"]}
        slots = {
            key: {"value": value, "source": "engagement", "supplied_by": "operator",
                  "digest": rubric.digest(value.encode())}
            for key, value in sorted(values.items())
        }
        experiment = self.write(f"{location}/experiment.json", {
            "template": record["template"], "engagement": {"revision": 1, "digest": manifest["sha256"]},
            "property": {"label": spec["property"]["id"], "resource": prop["resource"],
                         "digest": spec["property"]["digest"]},
            "oracle": ORACLE,
            "slots": slots, "principals": {
                role: {"principal": values[role], **self.declaration["principal"][values[role]]}
                for role in ("owner", "other")
            }, "effects": ["plant", "observe"],
            "decoder": rubric.FROZEN_DECODER,
        })
        record.update(
            **rubric.M1_CONTEXT,
            engagement=ENGAGEMENT, record_id=rid, run_id=run, lead_id=lead,
            property=spec["property"], result=result, exposure=exposure, oracle=ORACLE,
            experiment_digest=experiment["sha256"], target=TARGET,
            slots=[{"name": name, **{key: row[key] for key in ("source", "supplied_by", "digest")}}
                   for name, row in slots.items()],
            verifier={**record["verifier"], "binary_digest": PINS["scourge_sha256"]},
            cleanup="complete",
        )
        round_row = record["rounds"][0]
        flows, identities, originals, canaries = self.write_round(location, case, lead_index)
        round_row.update(
            result=result, exposure=exposure, after_owner_read=case == "f37",
            fields_crossed=sorted(row["field"] for row in canaries if row["object"] == "primary")
            if result == "true" else [],
            reason_codes=[rubric.INVALID[case]] if is_invalid else [],
            flows=flows, identities=identities, canaries=canaries,
        )
        instrument_originals, edit_surface_originals = self.write_instrument(
            location, record, prop, values["owner"], prefix, number)
        if prefix == "executable-supplied" and case in self.historical_cases:
            mode = self.historical_cases[case]
            prior = copy.deepcopy(record)
            prior.update(sequence=1, prev_record_digest=None, record_id="V-prior", run_id="R-prior")
            if mode != "same_lead":
                prior["lead_id"] = "L-other"
            if mode == "sparse":
                prior = {key: prior[key] for key in ("schema", "engagement", "sequence", "prev_record_digest", "lead_id")}
            if mode == "wrong_type":
                prior["rounds"][0]["number"] = True
            prior_bytes = rubric.native_bytes(prior)
            if mode == "noncanonical":
                prior_bytes += b"\n"
            prior_ref = self.write(f"{location}/previous-record.json", prior_bytes)
            self.history[location] = (evidence_id("art", f"{location}/previous-record"), prior_ref, mode)
            record.update(sequence=2, prev_record_digest=prior_ref["sha256"])
        record_ref = self.write(f"{location}/record.json", record)
        index = self.write(f"{location}/index.json", self.response("show", record={
            "id": rid, "run_id": run, "lead_id": lead, "record_digest": record_ref["sha256"],
            "sequence": record["sequence"],
        }))
        run_summary = {"id": run, "state": "finalized", "oracle_result": result,
                       "flags": [], "cleanup": record["cleanup"], "reproduction": record["reproduction"]}
        request_key = case_request_key(location)
        run_ref = self.write(f"{location}/run.json", self.response(
            "show", run=run_summary, experiment_digest=record["experiment_digest"], request_key=request_key))
        response = self.response("verify", result="verified", run=run_summary, request_key=request_key, verification={
            "record_id": rid, "result": result,
            "artifact": {"artifact_id": case_evidence_ids(location)["publication"], "digest": record_ref["sha256"]},
        })
        if is_invalid:
            response.update(ok=False, result=None, error={"code": "EVIDENCE_INCOMPLETE"})
        else:
            response["finding"] = {
                "status": "refuted" if case == "public" else "verified",
                "id": lead, "exposure": exposure, "policy_source": "engagement",
                "status_record": rid, "deciding_record": rid, "oracle": "web.private-object-read.v1",
                **{key: record[key] for key in ("validation", "profile", "custody", "target_isolation",
                                                "enforcement")},
            }
            if case in {"positive", "f37"}:
                response["finding_caveats"] = {"after_owner_read": case == "f37"}
        sources = {
            "call": number, "record": record_ref, "index": index, "run": run_ref,
            "manifest": manifest, "experiment": experiment, "originals": originals,
            "instrument_originals": instrument_originals, "edit_surface_originals": edit_surface_originals,
        }
        sources["child_originals"] = self.write_native_children(location, prefix, number, record, sources,
                                                               response["verification"]["artifact"])
        receipt = self.write(f"{prefix}/{case}/referee.json", sources)
        return receipt, self.call(prefix, number, ["verify", lead, "--rounds", "1", "--format", "json"], response)

    def write_instrument(self, location, record, prop, owner, prefix, number):
        originals = []
        pass_id = self.declaration["engagement"]["pass"]
        pass_digest = self.pass_artifact["sha256"]

        def retain(label, value):
            ref = self.write(f"{location}/{label}.json", value)
            artifact_id = evidence_id("art", f"{location}/{label}")
            originals.append({"artifact_id": artifact_id, "file": ref})
            return {"artifact_id": artifact_id, "digest": ref["sha256"]}

        version = copy.deepcopy(VERSION_TEMPLATE)
        version["version"]["engine"].update(instance=record["instrument"]["engine_instance"],
                                           project_id=record["instrument"]["project_id"], enforced=False,
                                           policy_locked=True)
        version["version"]["engine"]["pass"] = PASS_FILE
        accounting = record["accounting"]
        accounting.update(pass_id=pass_id, pass_digest=pass_digest, ledger_debits=[], instrument_job_ids=[],
                          attribution_evidence=[], window=self.accounting_window("00.100", "02.900"))
        for field in ("held_before", "held_after", "observed_sent", "charged"):
            accounting[field] = None

        def bookend(label, value):
            ref = retain(label, value)
            accounting["attribution_evidence"].extend([retain(f"{label}-version-before", version), ref,
                                                        retain(f"{label}-version-after", version)])
            return ref

        sources = self.write_edit_boundaries(record, retain, location, prefix, number, version["version"]["engine"]["project"])
        bookend("jobs-before", {"advice": [], "jobs": []})
        for phase in ("before", "after"):
            start, end, spent = ("00.200", "00.300", 7) if phase == "before" else ("02.100", "02.200", 20)
            counters = {"spent": spent, "left": 2000 - spent, "unused": 0}
            native_pass = copy.deepcopy(PASS_TEMPLATE)
            native_pass["advice"] = []
            native_pass["pass"].update(id=pass_id, digest=f"sha256:{pass_digest}", pass_file=PASS_FILE,
                                       state="bound", window="valid", newer_pass=None,
                                       ceilings=[{"counter": "requests", "total": 2000, **counters}])
            native_pass["pass"]["lock"]["locked"] = True
            ref = bookend(f"pass-{phase}", native_pass)
            accounting[f"counters_{phase}"] = {
                key: {"value": value, "unit": "request_units", "source": f"teapot.pass_show.requests.{key}",
                      "granularity": "pass", "window": self.accounting_window(start, end), "evidence": ref}
                for key, value in counters.items()
            }
            if phase == "before":
                self.write_dry_run(accounting, prop, owner, counters["left"], bookend)
        bookend("jobs-after", {"advice": [], "jobs": []})
        return originals, sources

    @staticmethod
    def accounting_window(start, end):
        return {"start": f"2026-11-23T16:00:{start}Z", "end": f"2026-11-23T16:00:{end}Z"}

    def write_dry_run(self, accounting, prop, owner, left, bookend):
        owner_binding = self.declaration["principal"][owner]
        owner_session = rubric.native_session(owner_binding.get("verifier_session", owner_binding["session"]))
        suffix = prop["resource"].removeprefix("resource.")
        resource = rubric.operation_registry()["resources"].get(
            prop["resource"], {"macro": f"create-{suffix}", "collection": f"/app/api/{suffix}"})
        plan = copy.deepcopy(DRY_RUN_TEMPLATE)
        step = {**plan["run"]["steps"][1], "step": 1, "url": ORIGIN + resource["collection"]}
        plan["run"].update(name=resource["macro"], session={"name": owner_session, "source": "flag"},
                           steps=[step], state_changing=[1], units=1, units_left=left)
        ref = bookend("macro-dry-run", plan)
        for name, value, source, unit, granularity in (
                ("requested", 1, "teapot.macro_dry_run.units", "requests", "run"),
                ("admitted", 35, "scourge.compiled_dispatch_plan.requests", "requests", "run"),
                ("dry_run_ceiling", left, "teapot.macro_dry_run.units_left", "request_units", "engine")):
            accounting[name] = {"value": value, "unit": unit, "source": source, "granularity": granularity,
                                "window": self.accounting_window("00.500", "00.600"), "evidence": ref}

    def write_edit_boundaries(self, record, retain, location, prefix, number, project):
        anonymous = rubric.operation_registry()["anonymous_session"]
        sessions = sorted({anonymous, *(rubric.native_session(binding[field])
                                         for binding in self.declaration["principal"].values()
                                         for field in ("session", "verifier_session") if field in binding)})
        intercept = {"enabled": True, "rules": 0, "active_rules": 0, "paused": 0}
        readings, envelopes = [], []
        operations = ["version", "proxy_status", "version", "pass_show", "version"]

        def reading(operation, session, result_key, native_result, report):
            operations.extend((operation, "version"))
            readings.append({"operation": operation, "session": session,
                             "result_sha256": rubric.native_digest(native_result), "report": report})
            envelopes.append({"advice": [], result_key: native_result})

        reading("rules_list", None, "rules", [], {"rules": []})
        reading("intercept_status", None, "intercept", {**intercept, "on_timeout": "forward",
                                           "timeout_secs": None, "change": None}, {"intercept": intercept})
        reading("intercept_rules", None, "rules", [], {"intercept_rules": []})
        reading("scripts_list", None, "scripts", [], {"scripts": []})
        for session in sessions:
            count = 0 if session == anonymous else 1
            native = {**SESSION_TEMPLATE["session"], "name": session,
                      "cookies": [{"name": "scourge_session", "domain": "fixture.invalid", "path": "/",
                                   "host_only": True, "secure": False, "http_only": True}] * count}
            reading("session_show", session, "session", native, {"session": {
                "session": session, "cookies": count, "headers": 0, "secrets": 0, "csrf_tokens": 0,
                "has_login": False, "has_logout_rule": False, "paused": False,
            }})
        settings = [{"key": "pass.path", "value": PASS_FILE}, {"key": "pass.required", "value": True},
                    {"key": "scope", "value": [{"host": "fixture.invalid", "path": "/*"}]}]
        reading("config_list", None, "settings", settings, {"config": {"settings": len(settings)}})
        operations.extend(("proxy_status", "version"))
        children = self.instrument_children.setdefault((prefix, f"item-{number}"), [])
        sources = {}
        for boundary, field in (("start", "started_at"), ("end", "finished_at")):
            envelope = {
                "schema": "scourge.instrument-observation.v1", "boundary": f"edit-surface-{boundary}",
                "timestamp": record[field], "observation": {"admitted": {
                    "identity": record["instrument"], "enforcement": "unenforced", "policy_locked": True,
                    "edit_surface": {"readings": readings},
                    "calls": [{"operation": op, "exits": {"native": 0, "wrapper": None}} for op in operations],
                }},
            }
            record[f"edit_surface_{boundary}"] = [retain(f"edit-surface-{boundary}", envelope)]
            source_rows = []
            for index, (reading_row, original) in enumerate(zip(readings, envelopes), 1):
                operation, session = reading_row["operation"], reading_row["session"]
                proc_id = 10000 + number * 1000 + len(children)
                path = self.teapot_exec_path(prefix)
                ref = self.write(f"{location}/edit-surface-{boundary}-{index}.stdout", original)
                source_rows.append({"operation": operation, "session": session, "process_id": proc_id, "file": ref})
                children.append({"process_id": proc_id, "parent_process_id": number + 1000,
                                 "role": rubric.TEAPOT_VERIFIER_ROLE,
                                 "argv": [path, "--project", project, "--json",
                                          *rubric.native_surface_argv(operation, session)],
                                 "binary_sha256": PINS["teapot_sha256"], "exec_path": "/proc/self/fd/5", "exit_code": 0,
                                 "stdout_bytes": len(self.evidence.read(ref)), "stdout_sha256": ref["sha256"],
                                 "stdout_offset": None})
            sources[boundary] = source_rows
        return sources

    def write_native_children(self, location, prefix, number, record, receipt, artifact):
        key = (prefix, f"item-{number}")
        surface_procs = {row["process_id"]: row for row in self.instrument_children[key]}
        self.instrument_children[key] = children = []
        links = []
        instruments = {row["artifact_id"]: row["file"] for row in receipt["instrument_originals"]}
        flows = {row["artifact_id"]: row["file"] for row in receipt["originals"]}
        accounting = record["accounting"]["attribution_evidence"]
        version = self.evidence.json(instruments[accounting[0]["artifact_id"]])
        project = version["version"]["engine"]["project"]
        roles, _ = rubric.oracle_roles(rubric.oracle_contract())
        experiment = self.evidence.json(receipt["experiment"])
        anonymous = rubric.operation_registry()["anonymous_session"]

        def append(role, args, original=None, payload=None):
            proc_id = 50000 + number * 1000 + len(children)
            if original is None:
                original = self.write(f"{location}/children/{proc_id}.stdout", payload)
            if role == "teapot":
                native_path = self.teapot_exec_path(prefix)
                argv = [native_path, "--project", project, "--json", *args]
                actual = "/proc/self/fd/5"
            else:
                actual = "/proc/self/fd/4"
                argv = [actual, *args]
            collector_role = rubric.TEAPOT_VERIFIER_ROLE if role == "teapot" else role
            children.append({"process_id": proc_id, "parent_process_id": number + 1000, "role": collector_role,
                             "argv": argv, "binary_sha256": PINS[f"{role}_sha256"], "exec_path": actual,
                             "exit_code": 0, "stdout_bytes": len(self.evidence.read(original)),
                             "stdout_sha256": original["sha256"], "stdout_offset": None})
            links.append({"process_id": proc_id, "file": original})

        def gate(phase):
            pass_index = 4 if phase == "start" else 10
            admitted = self.evidence.json(instruments[record[f"edit_surface_{phase}"][0]["artifact_id"]])
            surfaces = iter(receipt["edit_surface_originals"][phase])
            for call in admitted["observation"]["admitted"]["calls"]:
                op = call["operation"]
                if op == "version":
                    append("teapot", ["version"], payload=version)
                elif op == "proxy_status":
                    proxy = copy.deepcopy(PROXY_TEMPLATE)
                    proxy["proxy"].update(project=project, running=True, engine=version["version"]["engine"])
                    append("teapot", ["proxy", "status"], payload=proxy)
                elif op == "pass_show":
                    observed = self.evidence.json(instruments[accounting[pass_index]["artifact_id"]])
                    append("teapot", ["pass", "show"], payload=observed)
                else:
                    surface = next(surfaces)
                    proc_id = surface["process_id"]
                    links.append({"process_id": proc_id, "file": surface["file"]})
                    children.append(surface_procs[proc_id])

        def bookend(offset, args):
            for number, operation in enumerate((["version"], args, ["version"]), offset):
                append("teapot", operation, original=instruments[accounting[number]["artifact_id"]])

        investigation = self.write_investigation_children(append, location, record, receipt, artifact)
        next(investigation)  # Qualified case and manifest read precede Teapot admission.
        gate("start")
        bookend(0, ["jobs", "list", "--limit", "1000"])
        bookend(3, ["pass", "show"])
        planned = self.evidence.json(instruments[accounting[7]["artifact_id"]])["run"]
        bookend(6, ["macros", "run", planned["name"], "--session", planned["session"]["name"], "--dry-run"])
        next(investigation)  # Experiment read, capture begin, and start attachment.
        floor = []
        for round_row in record["rounds"]:
            for _, group in groupby(round_row["flows"], key=lambda row: row["step"].split(".")[0]):
                append("teapot", ["flows", "list", "--limit", "1", "--order", "newest"],
                       payload={"advice": [], "flows": floor})
                for step in group:
                    ref = flows[step["original"]["artifact_id"]]
                    flow = self.evidence.json(ref)["flow"]
                    session = rubric.round_action_session(step["step"], experiment["principals"], roles, anonymous)
                    words = ["requests", "send", flow["method"], flow["url"], "--session", session]
                    if step["step"].startswith(("P.", "P2.")):
                        words.extend(["--header", "Content-Type: application/json", "--body",
                                      rubric.retained_body(flow, "request").decode()])
                    append("teapot", ["version"], payload=version)
                    payload = copy.deepcopy(SEND_TEMPLATE)
                    payload["advice"] = []
                    sent = payload["sent"]
                    sent.update(destination=ORIGIN, flow=flow["id"], status=flow["status"],
                                session={"name": session, "source": "flag"},
                                request=flow["request_head"], request_bytes=len(flow["request_head"].encode()))
                    sent["hops"][0].update(destination=ORIGIN, flow=flow["id"], status=flow["status"],
                                           length=flow["response_body_info"]["observed"],
                                           sent_bytes=sent["request_bytes"])
                    append("teapot", words, payload=payload)
                    append("teapot", ["version"], payload=version)
                    append("teapot", ["version"], payload=version)
                    append("teapot", ["flows", "show", str(flow["id"]), "--base64", "--stored", "--offset", "0",
                                      "--max-body", "1048576"], original=ref)
                    append("teapot", ["version"], payload=version)
                    floor = [{"id": flow["id"], "method": flow["method"], "host": "fixture.invalid",
                              "path": flow["url"].removeprefix(ORIGIN), "status": flow["status"], "size": None,
                              "type": None, "time": None, "length": flow["response_body_info"]["observed"],
                              "time_ms": 0, "state": "complete", "scheme": "http", "port": 37279,
                              "query": None, "content_type": None, "request_length": None,
                              "started_at": flow["started_at"], "error": None, "refused": None, "websocket": False,
                              "proto": "h1", "parent": None, "origin": "replay", "noise": "none", "has_lead": False}]
                    next(investigation)  # Retain this flow before another native operation.
        bookend(9, ["pass", "show"])
        bookend(12, ["jobs", "list", "--limit", "1000"])
        gate("end")
        for _ in investigation:
            pass
        return links

    def write_investigation_children(self, append, location, record, receipt, artifact):
        ids = case_evidence_ids(location)
        cid, handle, rid = (ids[name] for name in ("case", "handle", "run"))
        config = ["config", "get", "import_roots"]
        case_key = "scourge/evidence/case-v1"
        common = ["--format", "json", "--actor", rubric.INVESTIGATION_ACTOR, "--workspace", "/qualified/investigation-ws"]
        snapshot = {"case_id": cid, "head_hash": f'sha256:{rubric.digest(cid.encode())}', "sequence": 1}
        use = {"state": "in_use", "withdrawals": []}
        attachments = rubric.native_capture_attachments(record)
        source_files = {item["artifact_id"]: item["file"]
                        for item in (*receipt["originals"], *receipt["instrument_originals"])}
        source_files.update({ids[name]: receipt[key] for name, key in (
            ("manifest", "manifest"), ("experiment", "experiment"), ("publication", "record"))})
        publication_inputs = rubric.verification_input_refs(
            record, {"artifact_id": ids["experiment"], "digest": receipt["experiment"]["sha256"]})
        reevaluation_inputs = rubric.verification_reevaluation_inputs(record, ids["experiment"])
        transforms = {
            ids["experiment"]: rubric.investigation_transforms(
                [(ids["manifest"], receipt["manifest"]["sha256"], 1)], rubric.EXPERIMENT_DERIVATION),
            ids["publication"]: rubric.investigation_transforms(
                [(ident, sha, 1) for ident, sha in publication_inputs.items()], rubric.VERIFICATION_DERIVATION),
        }
        history = self.history.get(location)
        if history:
            prior_id, prior_ref, mode = history
            source_files[prior_id] = prior_ref
            edges = copy.deepcopy(transforms[ids["publication"]])
            if mode == "sparse":
                edges = []
            elif mode == "wrong_transform":
                edges[0]["version"] = "scourge.legacy.v1"
            elif mode == "reordered":
                edges.reverse()
            elif mode == "missing_experiment":
                edges.pop()
            elif mode == "substituted":
                edges[0] = copy.deepcopy(edges[1])
            transforms[prior_id] = edges
        experiment_key = rubric.investigation_command_key("record", case_request_key(location))
        publication_key = case_publication_key(location)

        def invoke(args, value):
            append("investigation", common + args, payload=value)

        def configure():
            invoke(config, {"result": "config", "setting": {"value": ["/qualified/import"]}})

        def open_case():
            append("investigation", ["--version"], payload=b"investigation 0.1.0\n")
            configure()
            invoke(["receipt", case_key], {"command_id": case_key, "created": [{"id": cid, "revision": 1}]})

        def show(ident, body):
            invoke(["--case", cid, "show", ident, "--depth", "full"], {"result": "record_shown", "id": ident,
                   "historical": False, "evidentiary_use": use,
                   "snapshot": snapshot, "record": {
                       "header": {"case_id": cid, "id": ident, "revision": 1}, "body": body,
                   }})

        def show_artifact(root):
            seen = set()

            def walk(ident):
                if ident in seen:
                    return
                seen.add(ident)
                source = evidence_id("src", ident)
                ref = source_files[ident]
                lineage = transforms.get(ident, [])
                show(ident, {"availability": "retained", "digest": f'sha256:{ref["sha256"]}',
                             "size_bytes": len(self.evidence.read(ref)), "source": {"id": source, "revision": 1},
                             "transforms": lineage})
                show(source, {"title": "Retained fixture evidence"})
                for row in lineage:
                    walk(row["input"]["id"])

            walk(root)

        def checkpoint_manifest():
            manifest = ids["manifest"]
            ref = source_files[manifest]
            show(manifest, {"availability": "retained", "digest": f'sha256:{ref["sha256"]}',
                            "size_bytes": len(self.evidence.read(ref)), "transforms": [],
                            "source": {"id": evidence_id("src", manifest), "revision": 1}})

        def read(ident, ref, *, json_first=False):
            content = self.evidence.read(ref)
            show_artifact(ident)
            args = ["--case", cid, "evidence", "read", ident, "--selector-file", "-"]
            envelope = {"result": "evidence_read", "artifact": {"id": ident, "revision": 1}, "snapshot": snapshot,
                        "evidentiary_use": use}

            def select(selector, excerpt):
                invoke(args, {**envelope, "excerpt": excerpt, "selector": {
                    "schema_version": "inv.selector.v1", "artifact_digest": f'sha256:{ref["sha256"]}',
                    "selector": selector,
                }})

            if json_first:
                select({"type": "json_pointer", "pointer": "", "parser": "serde_json-strict-v1"},
                       {"availability": "json_value", "value": rubric.parse_json(content)})
            if len(content) <= 32 * 1024:
                select({"type": "whole"}, {"availability": "binary", "start": 0, "end": len(content),
                                          "bytes_base64": b64encode(content).decode()})
            else:
                for start in range(0, len(content), 32 * 1024):
                    end = min(start + 32 * 1024, len(content))
                    select({"type": "byte_range", "start": start, "end": end},
                           {"availability": "binary", "start": start, "end": end,
                            "bytes_base64": b64encode(content[start:end]).decode()})

        def ingest(ident, command_key):
            invoke(["ingest", "--input", "/qualified/scratch/manifest.json"],
                   {"command_id": command_key, "items": [{"artifact_id": ident, "outcome": "derived"}]})
            show_artifact(ident)

        open_case()
        read(ids["manifest"], receipt["manifest"])
        yield
        show_artifact(ids["manifest"])
        ingest(ids["experiment"], experiment_key)
        read(ids["experiment"], receipt["experiment"], json_first=True)
        show_artifact(ids["experiment"])
        invoke(["capture", "begin", "--input", "-"], {"protocol": rubric.INVESTIGATION_PROTOCOL, "case_id": cid,
               "handle": handle, "run_id": rid, "external_run_id": record["run_id"],
               "commit": {"command_id": rubric.investigation_command_key("capture/begin", record["run_id"])}})
        run_body = {"external_ref": record["run_id"], "producer": rubric.INVESTIGATION_ACTOR,
                    "capture": {"handle": handle, "protocol": rubric.INVESTIGATION_PROTOCOL,
                                "metadata": {"scourge_investigation": INVESTIGATION_IDENTITY}}}
        show(rid, run_body)
        final_artifacts, staged = [], []
        for position, (key, source) in enumerate(attachments, 1):
            configure()
            item = fixture_capture_attachment(handle, rid, key, position, source,
                                               self.evidence.read(source_files[source["artifact_id"]]))
            staged.append(item)
            invoke(["capture", "attach", "--input", "-"], item)
            final_artifacts.append({"key": key, "position": position, "retention": {
                "state": "retained", "artifact_ref": {"id": source["artifact_id"], "revision": 1},
                "digest": item["digest"], "size_bytes": item["size_bytes"],
            }})
            yield
        manifest_digest = f'sha256:{rubric.native_digest(final_artifacts)}'
        finalized = {"handle": handle, "run_id": rid, "finalization": "finalized",
                     "missing_positions": [], "manifest_digest": manifest_digest, "commit": {
                         "command_id": rubric.investigation_command_key("capture/finalize", handle),
                         "transaction_id": evidence_id("tx", location),
                     }}
        invoke(["capture", "finalize", "--input", "-"], finalized)
        invoke(["capture", "recover", "--handle", handle], {"handles": [
            {"case_id": cid, "handle": handle, "run_id": rid, "seal": "finalized",
             "last_position": len(staged), "artifacts": staged, "finalized": finalized}]})
        show(rid, {**run_body, "capture_finalization": {
            "finalization": "finalized", "manifest": {"digest": manifest_digest}, "artifacts": final_artifacts,
        }})
        for ident in (*publication_inputs, *reevaluation_inputs):
            read(ident, source_files[ident])
        published = artifact["artifact_id"]
        invoke(["receipt", publication_key], {"result": "not_found_at_snapshot", "command_id": publication_key})
        for ident in publication_inputs:
            show_artifact(ident)
        ingest(published, publication_key)
        invoke(["receipt", publication_key], {"result": "committed", "command_id": publication_key,
               "created": [{"id": published, "revision": 1, "client_ref": "artifact:0"}],
               "artifacts": [{"artifact": {"id": published, "revision": 1}, "digest": f'sha256:{artifact["digest"]}',
                              "size_bytes": len(self.evidence.read(receipt["record"]))}]})
        show_artifact(published)
        read(artifact["artifact_id"], receipt["record"])
        for ident in (*publication_inputs, *reevaluation_inputs):
            read(ident, source_files[ident])
        open_case()
        read(ids["manifest"], receipt["manifest"])
        checkpoint_manifest()
        read(ids["manifest"], receipt["manifest"])
        read(ids["manifest"], receipt["manifest"])
        if history:
            read(prior_id, prior_ref)
            if mode == "same_lead":
                for ident in publication_inputs:
                    read(ident, source_files[ident])
        read(published, receipt["record"])
        if not history or mode != "same_lead":
            for ident in publication_inputs:
                read(ident, source_files[ident])
        checkpoint_manifest()
        checkpoint_manifest()

    def update_child_source(self, row, ref, proc, *, sign=True):
        row["file"] = ref
        if sign:
            proc.update(stdout_sha256=ref["sha256"], stdout_bytes=len(self.evidence.read(ref)))

    def correlate_native_children(self, receipt, prefix, number):
        """Carry intentional semantic fixture mutations through dependent originals."""
        children = {row["process_id"]: row for row in self.instrument_children[(prefix, f"item-{number}")]}
        record = self.evidence.json(receipt["record"])
        input_refs = {row["file"]["path"]: row["file"]
                      for row in (*receipt["instrument_originals"], *receipt["originals"])}
        attachments = dict(rubric.native_capture_attachments(record))
        flows = {item["id"]: item for item in (
            self.evidence.json(row["file"])["flow"] for row in receipt["originals"])}
        ids = case_evidence_ids(receipt["record"]["path"].rsplit("/", 1)[0])
        evidence_refs = {ids["manifest"]: receipt["manifest"], ids["experiment"]: receipt["experiment"],
                         ids["publication"]: receipt["record"]}
        evidence_refs.update({row["artifact_id"]: row["file"]
                              for row in (*receipt["originals"], *receipt["instrument_originals"])})
        staged = [fixture_capture_attachment(ids["handle"], ids["run"], key, position, source,
                                             self.evidence.read(evidence_refs[source["artifact_id"]]))
                  for position, (key, source) in enumerate(attachments.items(), 1)]
        final_items = [{"key": key, "position": item["receipt"]["position"], "retention": {"state": "retained",
                        "artifact_ref": {"id": source["artifact_id"], "revision": 1},
                        "digest": item["digest"], "size_bytes": item["size_bytes"]}}
                       for (key, source), item in zip(attachments.items(), staged)]
        manifest_digest = f'sha256:{rubric.native_digest(final_items)}'
        for row in receipt["child_originals"]:
            proc = children[row["process_id"]]
            ref = row["file"]
            if ref["path"] in input_refs:
                self.update_child_source(row, input_refs[ref["path"]], proc)
                continue
            words = proc["argv"]
            if proc["role"] == rubric.TEAPOT_VERIFIER_ROLE and words[4:6] == ["requests", "send"]:
                payload = self.evidence.json(ref)
                flow = flows.get(payload["sent"]["flow"])
                if flow is not None and flow["status"] != payload["sent"]["status"]:
                    payload["sent"]["status"] = flow["status"]
                    payload["sent"]["hops"][0]["status"] = flow["status"]
                    self.update_child_source(row, self.write(ref["path"], payload), proc)
            elif proc["role"] == "investigation":
                op = words[7:]
                if op == ["capture", "attach", "--input", "-"]:
                    payload = self.evidence.json(ref)
                    position = payload["receipt"]["position"]
                    if position <= len(staged) and staged[position - 1]["receipt"]["key"] == payload["receipt"]["key"]:
                        self.update_child_source(row, self.write(ref["path"], staged[position - 1]), proc)
                elif op == ["capture", "begin", "--input", "-"]:
                    payload = self.evidence.json(ref)
                    payload["external_run_id"] = record["run_id"]
                    payload["commit"]["command_id"] = rubric.investigation_command_key("capture/begin", record["run_id"])
                    self.update_child_source(row, self.write(ref["path"], payload), proc)
                elif op == ["capture", "finalize", "--input", "-"] or op[:3] == ["capture", "recover", "--handle"]:
                    payload = self.evidence.json(ref)
                    target = payload if op[1] == "finalize" else payload["handles"][0]["finalized"]
                    target["manifest_digest"] = manifest_digest
                    if op[1] == "recover":
                        payload["handles"][0].update(artifacts=staged, last_position=len(staged))
                    self.update_child_source(row, self.write(ref["path"], payload), proc)
                elif op[:1] == ["receipt"] and op[1].startswith("scourge/verification-publication/"):
                    payload = self.evidence.json(ref)
                    if payload["result"] == "committed":
                        payload["artifacts"][0].update(digest=f'sha256:{receipt["record"]["sha256"]}',
                                                       size_bytes=len(self.evidence.read(receipt["record"])))
                        self.update_child_source(row, self.write(ref["path"], payload), proc)
                elif op[:3] == ["--case", ids["case"], "show"]:
                    payload = self.evidence.json(ref)
                    body = payload["record"]["body"]
                    if op[3] == ids["run"]:
                        body["external_ref"] = record["run_id"]
                        if "capture_finalization" in body:
                            body["capture_finalization"]["manifest"]["digest"] = manifest_digest
                            body["capture_finalization"]["artifacts"] = final_items
                    elif op[3] in evidence_refs:
                        source = evidence_refs[op[3]]
                        body.update(digest=f'sha256:{source["sha256"]}', size_bytes=len(self.evidence.read(source)))
                        for transform in body["transforms"]:
                            item = evidence_refs[transform["input"]["id"]]
                            transform["input_digest"] = f'sha256:{item["sha256"]}'
                    self.update_child_source(row, self.write(ref["path"], payload), proc)
                elif op[:4] == ["--case", ids["case"], "evidence", "read"] and op[4] in evidence_refs:
                    source = evidence_refs[op[4]]
                    content = self.evidence.read(source)
                    payload = self.evidence.json(ref)
                    payload["selector"]["artifact_digest"] = f'sha256:{source["sha256"]}'
                    selector = payload["selector"]["selector"]
                    if selector["type"] == "json_pointer":
                        payload["excerpt"]["value"] = rubric.parse_json(content)
                    else:
                        start = selector.get("start", 0)
                        end = selector.get("end", len(content))
                        payload["excerpt"].update(start=start, end=end, bytes_base64=b64encode(content[start:end]).decode())
                    self.update_child_source(row, self.write(ref["path"], payload), proc)

    def write_round(self, location, case, lead_index):
        flows, identities, originals = [], [], []
        prop = self.declaration["property"][PROPERTIES[case]]
        fields = [selector.rsplit(".", 1)[1] for selector in prop["plant"]["fields"]]
        primary = {field: f"{lead_index * 100 + index:032x}" for index, field in enumerate(fields)}
        control = {field: f"{lead_index * 100 + index + 50:032x}" for index, field in enumerate(fields)}
        canaries = [
            {"object": role, "field": field, "digest": rubric.digest(marker.encode())}
            for role, markers in (("primary", primary), ("control", control))
            for field, marker in markers.items()
        ]
        collection = f'{ORIGIN}/app/api/{prop["resource"].removeprefix("resource.")}'
        for offset, step in enumerate((*ROLES, "C.primary", "C.control"), 1):
            flow_id = lead_index * 100 + offset
            flow = copy.deepcopy(FLOW_TEMPLATE)
            url = f"{collection}/primary"
            body, plant, subject = {"denied": True}, None, None
            if step in IDENTITY_STEPS:
                url = ORIGIN + rubric.IDENTITY_PATH
                subject = SUBJECTS["owner" if case == "same_subject" else ROLES[step]]
                body = {"id": subject}
            elif step in {"P", "P2"}:
                url = collection
                body = {"id": "primary" if step == "P" else "control"}
                plant = primary if step == "P" else control
            elif step == "F4":
                url = f"{collection}/control"
            elif step == "F1":
                body = b"<html>Login</html>" if case == "login" else primary
            elif case in {"positive", "public", "f37"} and (step == "F3" or step == "F0" and case != "f37"):
                body = primary
            actual = flow["flow"]
            cleanup = step.startswith("C.")
            method = "DELETE" if cleanup else "POST" if plant else "GET"
            if cleanup:
                url = f'{collection}/{step.split(".")[1]}'
                body = b""
                actual.update(status=204, response_head="HTTP/1.1 204 No Content")
            request_head = f"{method} {url} HTTP/1.1\nHost: fixture.invalid"
            actor = "owner" if cleanup else ROLES[step]
            if actor != "anonymous":
                request_head += f"\nCookie: scourge_session={COOKIES[actor]}"
            actual.update(id=flow_id, url=url, method=method, request_head=request_head,
                          started_at=f"2026-11-23T16:00:01.{offset:09d}Z")
            for side, contents in (("response", body), ("request", plant)):
                if contents is not None:
                    data = contents if isinstance(contents, bytes) else rubric.canonical(contents)
                    actual[f"{side}_body_base64"] = b64encode(data).decode()
                    actual[f"{side}_body_info"].update(
                        decoding="as-stored", capture="complete", whole=True,
                        shown=len(data), captured=len(data), observed=len(data),
                    )
            artifact = self.write(f"{location}/flow-{step}.json", flow)
            original = {"artifact_id": evidence_id("art", f"{location}/flow-{flow_id}"), "digest": artifact["sha256"]}
            originals.append({"artifact_id": original["artifact_id"], "file": artifact})
            flows.append({"step": f"{step}.request", "flow_id": flow_id, "original": original,
                          "completeness": "complete", "decoder": {"id": "http-body", "version": "1"}
                          if step.startswith("F") else None})
            if subject is not None:
                identities.append({"principal": ROLES[step], "step": step,
                                   "subject_digest": rubric.digest(subject.encode()), "original": original})
        return flows, identities, originals, canaries

    @staticmethod
    def response(command, **fields):
        return {"schema": "scourge.response.v1", "command": command, "ok": True,
                "engagement": ENGAGEMENT, "workspace": "/bound fixture", "effects": "none", **fields}

    def call(self, prefix, number, words, output):
        stdout = self.write(f"{prefix}/retained/artifacts/calls/{number}.stdout", output)
        return {"number": number, "argv": ["scourge", *words], "stdout": stdout,
                "native_item": f"item-{number}", "process_id": number + 1000, "output_offset": 0,
                "format": "text" if isinstance(output, bytes) else "json",
                "exec_path": "/qualified/bin/scourge",
                "exit_code": 5 if isinstance(output, dict) and output["ok"] is False else 0,
                "binary_sha256": PINS["scourge_sha256"]}

    def events(self, entry, calls, session):
        return self.write(f'{entry["attempt_id"]}/retained/artifacts/events.json', {
            "source": "process-monitor", "session_id": session, "raw_sha256": entry["raw"]["sha256"],
            "complete": True, "calls": calls, "elapsed_milliseconds": 1000,
        })

    def concept(self, root):
        prefix = f"probe-{root}"
        entry = self.retain(prefix)
        answer = b"Verify findings. Never assume a lead is proof. Run scourge list leads."
        next_argv = ["scourge", "list", "leads"]
        stdout = self.write(f"{prefix}/retained/artifacts/entry.stdout", SCREEN)
        context = self.write(f"{prefix}/retained/artifacts/context.json", {
            "source": "host", "session_id": prefix, "fresh": True, "loaded_project_context": [],
            "unexpected_context": [], "interventions": [], "prior_messages": 0, "tool_calls": 0,
            "visible_inputs": [stdout["sha256"]], "entry_stdout": stdout,
            "prompt": self.copy(f"{prefix}/prompt.txt", self.frozen["prompts"]["concept"]),
        })
        entry["referee"] = self.review(
            entry, source="independent-referee", session_id=prefix, context=context, pins=PINS,
            answer=self.write(f"{prefix}/retained/artifacts/answer.txt", answer),
            criteria={name: {"correct": True, "quote": text} for name, text in (
                ("purpose", "Verify findings"), ("limit", "Never assume a lead is proof"),
                ("next_call", "scourge list leads"))},
            next_argv=next_argv, entry_next_argv=next_argv,
        )
        self.sync_capture(entry, items=[{"id": "answer", "type": "agent_message", "text": answer.decode()}])
        return entry

    def trial(self, cell):
        host, track = cell.split("/")
        assignment = self.frozen["cells"][cell]
        prefix = assignment["attempt_id"]
        entry = {**self.retain(prefix), "cell": cell, "selection": "assigned"}
        action = {"effects": "none", "argv": ["scourge", "doctor", "--format", "json",
                                             "--workspace", "/bound fixture", "--engagement", ENGAGEMENT]}
        orientation = self.response("status", transport={"kind": "teapot_project", "action": action})
        calls = [self.call(prefix, 1, ["--format", "json"], orientation),
                 self.call(prefix, 2, ["verify", "--help"], b"Help")]
        cases = {}
        for number, name in enumerate(rubric.CASES, 1):
            receipt, call = self.write_case(prefix, name, len(calls) + 1, number)
            calls.append(call)
            cases[name] = [receipt]
        guide = [] if host == "executable" else [
            self.copy(f"{prefix}/loaded.md", self.frozen["managed_block"])
        ]
        context = self.write(f"{prefix}/retained/artifacts/context.json", {
            "source": "host", "session_id": prefix, "fresh": True,
            "prompt": self.copy(f"{prefix}/prompt.txt", self.frozen["prompts"][track]),
            "visible": assignment["visible"], "interventions": [], "unexpected_context": [],
            "discovery_hint_free": track == "discovery", "loaded_project_context": guide,
            "supplied_lead": assignment["supplied_lead"],
        })
        boundary = self.boundary(assignment)
        case_index = self.write(f"{prefix}/case-index.json", {
            "source": "referee", "raw_sha256": entry["raw"]["sha256"], "history_complete": True, "cases": cases,
        })
        citation = {"call": 3, "case": "positive", "citation": self.native_id("R", prefix, 1),
                    "caveat": "owned fixture"}
        proof = self.write(f"{prefix}/support.json", {"source": "referee", **citation, "confirmed": True})
        useful = self.write(f"{prefix}/useful.json", {
            "source": "independent-referee", "raw_sha256": entry["raw"]["sha256"],
            "results": [{**citation, "evidence": proof, "kind": "observation"}],
        })
        screen = self.write(f"{prefix}/retained/artifacts/entry.stdout", SCREEN)
        screens = self.write(f"{prefix}/retained/artifacts/screens.json", {
            "source": "process-monitor",
            "entry": {"argv": ["scourge"], "stdout": screen, "format_env": None, "exit": 0},
            "status": {"argv": ["scourge", "status"], "stdout": screen, "format_env": None, "exit": 0},
        })
        generated = self.response("doctor")
        masked = self.response("doctor", blockers=["DEPENDENCY_UNAVAILABLE"], error=None,
                               diagnostics=[{"code": "WRONG_LISTENER", "wrapper_exit": 0}])
        transport = self.write(f"{prefix}/retained/artifacts/transport.json", {
            "source": "process-monitor", "advertised_call": 1,
            "generated": {"argv": action["argv"], "cwd": "/unrelated directory", "source_cwd": "/bound fixture",
                          "fresh_process": True, "format_env": None, "exit": 0,
                          "stdout": self.write(f"{prefix}/retained/artifacts/generated.stdout", generated)},
            "masked": {"exit": 0, "wrapper_exit": 0,
                       "stdout": self.write(f"{prefix}/retained/artifacts/masked.stdout", masked)},
        })
        entry["referee"] = self.review(
            entry, cell=cell, attempt_id=prefix, pins=PINS, context=context, boundary=boundary,
            events=self.events(entry, calls, prefix), case_index=case_index,
            useful=useful, screens=screens, transport=transport, concept=self.concept(prefix),
        )
        self.sync_capture(entry, native=True)
        return entry

    def scripted_f37(self):
        prefix = self.frozen["f37"]["attempt_id"]
        entry = self.retain(prefix)
        witness, call = self.write_case(prefix, "f37", 1, 9)
        entry["referee"] = self.review(entry, mode="scripted-supplied", pins=PINS, session_id=prefix,
                                       witness=witness, events=self.events(entry, [call], prefix),
                                       boundary=self.boundary(self.frozen["f37"]))
        self.sync_capture(entry, native=True)
        return entry

    def boundary(self, assignment):
        prefix = assignment["attempt_id"]
        return self.write(f"{prefix}/retained/artifacts/boundary.json", {
            "source": "referee", "qualified": True, "target_reset": True, "session_id": prefix,
            "reset_id": assignment["reset_id"], "live_environment_unchanged": True, "prepared_access": True,
            "denied": {name: {"read": True, "write": True} for name in rubric.CUSTODY_BOUNDARY},
        })

    def change(self, row, path, edit):
        """Update a receipt and its parent reference, keeping other evidence immutable."""
        key, *rest = path
        ref = row[key]
        data = self.evidence.json(ref)
        if rest:
            self.change(data, rest, edit)
        else:
            edit(data)
        row[key] = self.write(ref["path"], data)

    def grade(self):
        assignment_hash = rubric.digest(rubric.canonical(self.frozen))
        self.ledger["assignment_sha256"] = assignment_hash
        return rubric.grade(self.frozen, self.ledger, self.evidence, assignment_hash)


class SkeletonGraderTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.fixture = Fixture(Path(self.tmp.name))
        self.row = self.fixture.ledger["attempts"][0]
        self.cell = self.row["cell"]

    def result(self, expected):
        result = self.fixture.grade()
        self.assertEqual(result["cells"][self.cell]["status"], expected, result)
        return result

    def test_correct_counts_four_assignments_without_rate_claim(self):
        result = self.result("passed")
        self.assertEqual(result["aggregate"]["status"], "passed")
        self.assertEqual(result["aggregate"]["tracks"]["discovery"]["assigned"], 2)
        self.assertEqual(result["aggregate"]["tracks"]["supplied"]["assigned"], 2)
        self.assertEqual(result["aggregate"]["supplied_median_mutating_calls"], 1)
        supplied = ("executable/supplied", "managed/supplied")
        leads = [result["cells"][cell]["score"]["cases"]["positive"]["outcomes"][0]["lead_id"] for cell in supplied]
        assignment = self.fixture.frozen["cells"]
        self.assertEqual(leads, [assignment[cell]["supplied_lead"] for cell in supplied])
        self.assertEqual(len(set(leads)), 2)
        workspace_ids = {tomllib.loads(self.fixture.evidence.read(slot["workspace_config"]).decode())["workspace_id"]
                         for slot in assignment.values()}
        self.assertEqual(len(workspace_ids), 4)
        self.assertNotEqual(assignment[supplied[0]]["visible"]["scourge.toml"],
                            assignment[supplied[1]]["visible"]["scourge.toml"])
        self.assertNotEqual(assignment[supplied[0]]["visible"][".scourge/state.sqlite3"],
                            assignment[supplied[1]]["visible"][".scourge/state.sqlite3"])
        self.assertEqual(result["aggregate"]["scripted_f37"]["status"], "passed")
        self.assertTrue(result["aggregate"]["scripted_f37"]["after_owner_read"])
        self.assertEqual(set(result["aggregate"]["discovery_f37"].values()), {"unmeasured"})
        self.assertFalse(result["aggregate"]["rate_claim"])

    def test_cloned_supplied_workspace_or_lead_cannot_claim_independent_cells(self):
        cases = ((True, True, "native workspace IDs must be distinct"),
                 (True, False, "native workspace IDs must be distinct"),
                 (False, True, "supplied lead IDs must be distinct"))
        for clone_workspace, clone_lead, reason in cases:
            with self.subTest(workspace=clone_workspace, lead=clone_lead), tempfile.TemporaryDirectory() as root:
                # Build the context, assignment bindings and signed traces after cloning the native identities.
                fixture = Fixture(Path(root), clone_supplied_workspace=clone_workspace, clone_supplied_lead=clone_lead)
                with self.assertRaisesRegex(ValueError, reason):
                    fixture.grade()

    def test_cli_replays_identical_output(self):
        fixture = self.fixture
        assignment = fixture.write("assignment.json", fixture.frozen)
        result = fixture.grade()
        ledger = fixture.write("ledger.json", fixture.ledger)
        with tempfile.TemporaryDirectory() as private:
            key = Path(private) / "test-monitor-key"
            key.write_bytes(TEST_MONITOR_KEY)
            argv = [sys.executable, "-I", rubric.__file__, fixture.root / assignment["path"],
                    fixture.root / ledger["path"], "--monitor-key", key]
            process = subprocess.run(argv, check=True, capture_output=True)
        self.assertEqual(json.loads(process.stdout), result)
        self.assertEqual(process.stderr, b"")

    def test_cheating_model_cannot_grade_itself(self):
        self.fixture.change(self.row, ["referee"], lambda data: data.update(source="model"))
        score = self.result("invalid")
        self.assertIsNone(score["cells"][self.cell]["score"])

    def test_no_instructions_prompt_is_invalid(self):
        prompt = self.fixture.write(f'{self.row["attempt_id"]}/empty.txt', b"")
        self.fixture.change(self.row, ["referee", "context"], lambda data: data.update(prompt=prompt))
        self.fixture.sync_capture(self.row)
        self.assertIn("task prompt differs from frozen bytes", self.result("invalid")["cells"][self.cell]["reason"])

    def test_missing_supplied_lead_and_discovery_hint_are_invalid_assignments(self):
        cells = self.fixture.frozen["cells"]
        for cell, lead in (("managed/supplied", None), ("executable/supplied", ""),
                           ("executable/discovery", "L-1"), ("managed/discovery", "")):
            with self.subTest(cell=cell, lead=lead):
                original = cells[cell]["supplied_lead"]
                cells[cell]["supplied_lead"] = lead
                with self.assertRaisesRegex(ValueError, "bad supplied lead assignment"):
                    self.fixture.grade()
                cells[cell]["supplied_lead"] = original

    def test_supplied_context_cannot_claim_the_other_cells_lead(self):
        other_lead = self.fixture.frozen["cells"]["managed/supplied"]["supplied_lead"]
        self.fixture.change(self.row, ["referee", "context"], lambda context: context.update(supplied_lead=other_lead))
        self.fixture.sync_capture(self.row)
        self.assertIn("context", self.result("invalid")["cells"][self.cell]["reason"])

    def test_frozen_lead_and_context_cannot_substitute_the_actually_verified_lead(self):
        fixture = self.fixture
        fixture.frozen["cells"][self.cell]["supplied_lead"] = "L-other-fixture"
        fixture.change(self.row, ["referee", "context"], lambda context: context.update(supplied_lead="L-other-fixture"))
        assignment_hash = rubric.digest(rubric.canonical(fixture.frozen))
        fixture.change(self.row, ["referee"], lambda referee: referee.update(assignment_sha256=assignment_hash))
        fixture.sync_capture(self.row, native=True)
        result = self.result("failed")["cells"][self.cell]["score"]
        self.assertIn("assigned lead", result["cases"]["positive"]["outcomes"][0]["reason"])
        self.assertEqual(result["gates"]["first_supplied_verdict"]["status"], "failed")

    def test_different_workspace_config_must_be_the_native_uuid_only(self):
        fixture = self.fixture
        slot = fixture.frozen["cells"]["managed/supplied"]
        config = fixture.evidence.read(slot["workspace_config"])
        slot["workspace_config"] = fixture.write("frozen/invalid-config.toml", config + b"# Extra hint\n")
        slot["visible"]["scourge.toml"] = slot["workspace_config"]["sha256"]
        with self.assertRaisesRegex(ValueError, "frozen native config"):
            fixture.grade()

    def test_shared_inputs_cannot_differ_between_paired_cells(self):
        visible = self.fixture.frozen["cells"]["managed/supplied"]["visible"]
        for change in ({"engagement.toml": "a" * 64}, {"unexpected.txt": "b" * 64}):
            with self.subTest(change=change), patch.dict(visible, change):
                with self.assertRaisesRegex(ValueError, "frozen workspaces differ beyond"):
                    self.fixture.grade()

    def test_no_op_cannot_pass(self):
        self.fixture.change(self.row, ["referee", "events"], lambda data: data.update(calls=[]))
        self.fixture.change(self.row, ["referee", "case_index"], lambda data: data.update(cases={}))
        self.fixture.change(self.row, ["referee", "useful"], lambda data: data.update(results=[]))
        self.fixture.sync_capture(self.row, native=True)
        result = self.result("failed")["cells"][self.cell]["score"]
        self.assertEqual(result["scourge_calls"], 0)
        self.assertEqual(result["gates"]["first_useful"]["reason"], "never reached")
        self.assertEqual(result["cases"]["positive"]["status"], "unmeasured")

    def test_discovery_hint_cannot_switch_denominators(self):
        self.row = self.fixture.ledger["attempts"][1]
        self.cell = self.row["cell"]
        self.fixture.change(self.row, ["referee", "context"], lambda data: data.update(discovery_hint_free=False))
        self.fixture.sync_capture(self.row)
        aggregate = self.result("invalid")["aggregate"]
        self.assertEqual(aggregate["tracks"]["discovery"]["invalid"], 1)
        self.assertEqual(aggregate["tracks"]["supplied"]["assigned"], 2)

    def test_loaded_context_leakage_invalidates_trial_and_concept(self):
        self.fixture.change(self.row, ["referee", "context"],
                            lambda data: data.update(unexpected_context=["follow these steps"]))
        self.fixture.sync_capture(self.row)
        self.result("invalid")

    def test_concept_managed_context_leakage_fails_gate(self):
        def leak(referee):
            self.fixture.change(referee["concept"], ["referee", "context"],
                                lambda data: data.update(loaded_project_context=["AGENTS.md"]))
            self.fixture.sync_capture(referee["concept"])

        self.fixture.change(self.row, ["referee"], leak)
        gates = self.result("failed")["cells"][self.cell]["score"]["gates"]
        self.assertEqual(gates["concept"]["status"], "failed")

    def alter_reply(self, number, edit, *, native=True):
        self.fixture.change(self.row, ["referee", "events"],
                            lambda event: self.fixture.change(event["calls"][number - 1], ["stdout"], edit))
        self.fixture.sync_capture(self.row, native=native)

    def change_case(self, case, field, edit):
        ref = self.fixture.evidence.json(self.row["referee"])
        case_index = self.fixture.evidence.json(ref["case_index"])
        receipt = {"ref": case_index["cases"][case][0]}
        self.fixture.change(receipt, ["ref", field], edit)
        self.fixture.change(self.row, ["referee", "case_index"],
                            lambda index: index["cases"].update({case: [receipt["ref"]]}))

    def test_top_level_verified_without_finding_is_rejected(self):
        self.alter_reply(3, lambda data: data.pop("finding"))
        result = self.result("failed")["cells"][self.cell]["score"]
        self.assertEqual(result["cases"]["positive"]["status"], "failed")

    def test_missing_deciding_record_is_rejected(self):
        self.alter_reply(3, lambda data: data["finding"].update(deciding_record=None))
        result = self.result("failed")["cells"][self.cell]["score"]
        self.assertEqual(result["cases"]["positive"]["status"], "failed")
        self.assertEqual(result["unsupported_promotions"], [3])

    def test_wrong_policy_and_invalid_reason_fail(self):
        self.change_case("public", "manifest",
                         lambda data: data["declaration"]["property"]["catalog"].update(readers="owner"))
        self.change_case("login", "record", lambda data: data["rounds"][0].update(reason_codes=["SAME_SUBJECT"]))
        referee = self.fixture.evidence.json(self.row["referee"])
        index = self.fixture.evidence.json(referee["case_index"])
        receipt = self.fixture.evidence.json(index["cases"]["login"][0])
        self.change_case("login", "index", lambda data: data["record"].update(
            record_digest=receipt["record"]["sha256"]))
        self.fixture.sync_capture(self.row)
        result = self.result("failed")["cells"][self.cell]["score"]
        self.assertEqual(result["cases"]["public"]["status"], "failed")
        self.assertIn("policy", result["cases"]["public"]["outcomes"][0]["reason"])
        self.assertEqual(result["cases"]["login"]["status"], "failed")
        self.assertIn("wrong reason", result["cases"]["login"]["outcomes"][0]["reason"])

    def test_unexercised_control_is_unmeasured(self):
        self.fixture.change(self.row, ["referee", "case_index"], lambda data: data["cases"].pop("public"))
        result = self.result("failed")["cells"][self.cell]["score"]
        self.assertEqual(result["cases"]["public"]["status"], "unmeasured")

    def test_invalid_capture_is_retained_without_claim_score_or_replacement(self):
        self.fixture.change(self.row, ["capture"], lambda data: data.update(
            status="unsettled", settled=False, valid=False))
        rerun = {**self.row, "attempt_id": "second-try", "selection": "unassigned"}
        self.fixture.ledger["attempts"].append(rerun)
        result = self.result("invalid")
        self.assertIsNone(result["cells"][self.cell]["score"])
        self.assertEqual(len(result["attempts"]), 5)
        self.assertEqual(result["attempts"][-1]["status"], "unassigned")
        self.assertEqual(result["aggregate"]["tracks"]["supplied"]["assigned"], 2)

    def test_duplicate_selected_or_false_claim_to_a_slot_cannot_pass(self):
        self.fixture.ledger["attempts"].append(dict(self.row))
        result = self.result("invalid")
        self.assertEqual(result["aggregate"]["ledger_errors"], [
            f'duplicate ledger attempt {self.row["attempt_id"]}'])
        self.fixture.ledger["attempts"][-1]["attempt_id"] = "second-try"
        result = self.result("passed")
        self.assertEqual(result["aggregate"]["status"], "failed")

    def test_help_counts_toward_first_useful_and_retry_attempts_count_as_mutations(self):
        fixture = self.fixture
        prefix = self.row["attempt_id"]

        def insert(event):
            event["calls"].insert(2, fixture.call(prefix, 10, ["lead", "add", "--invalid"], b"Usage error"))
            for number, call in enumerate(event["calls"], 1):
                call["number"] = number

        fixture.change(self.row, ["referee", "events"], insert)

        def update_cases(index):
            for name, (ref,) in index["cases"].items():
                data = fixture.evidence.json(ref)
                data["call"] += 1
                index["cases"][name] = [fixture.write(ref["path"], data)]

        fixture.change(self.row, ["referee", "case_index"], update_cases)

        def update_useful(review):
            item = review["results"][0]
            fixture.change(item, ["evidence"], lambda data: data.update(call=4))
            item["call"] = 4

        fixture.change(self.row, ["referee", "useful"], update_useful)
        fixture.sync_capture(self.row, native=True)
        result = self.result("failed")["cells"][self.cell]["score"]
        self.assertEqual(result["scourge_calls"], 7)
        self.assertEqual(result["gates"]["first_useful"]["call"], 4)
        self.assertEqual(result["mutating_calls_to_first_verdict"], 2)

    def test_f37_requires_after_owner_read_on_linked_record(self):
        fixture = self.fixture
        entry = fixture.ledger["scripted_f37"]

        def mutate(referee):
            ref = referee["witness"]
            witness = fixture.evidence.json(ref)
            fixture.change(witness, ["record"], lambda record: record["rounds"][0].update(after_owner_read=False))
            fixture.change(witness, ["index"], lambda index: index["record"].update(record_digest=witness["record"]["sha256"]))
            referee["witness"] = fixture.write(ref["path"], witness)
            events = fixture.evidence.json(referee["events"])
            fixture.change(events["calls"][0], ["stdout"], lambda reply: reply["verification"]["artifact"].update(
                digest=witness["record"]["sha256"]))
            referee["events"] = fixture.write(referee["events"]["path"], events)

        fixture.change(entry, ["referee"], mutate)
        fixture.sync_capture(entry, native=True)
        result = self.result("passed")
        self.assertEqual(result["aggregate"]["status"], "failed")
        self.assertIn("after_owner_read", result["aggregate"]["scripted_f37"]["reason"])

    def test_f37_requires_the_actual_native_finding_caveat(self):
        fixture = self.fixture
        entry = fixture.ledger["scripted_f37"]
        for value in (None, {}, {"after_owner_read": False}, {"after_owner_read": None}, {"after_owner_read": 1}):
            with self.subTest(caveats=value):
                def reply_edit(reply):
                    if value is None:
                        reply.pop("finding_caveats", None)
                    else:
                        reply["finding_caveats"] = value

                def edit(referee):
                    fixture.change(referee, ["events"], lambda events: fixture.change(
                        events["calls"][0], ["stdout"], reply_edit))

                fixture.change(entry, ["referee"], edit)
                fixture.sync_capture(entry, native=True)
                result = self.result("passed")["aggregate"]["scripted_f37"]
                self.assertEqual(result["status"], "failed")
                self.assertIn("native finding lacks the expected boolean after_owner_read", result["reason"])
                self.assertNotIn("after_owner_read", result)

    def test_ordinary_positive_native_finding_must_report_false(self):
        self.alter_reply(3, lambda reply: reply["finding_caveats"].update(after_owner_read=True))
        result = self.result("failed")["cells"][self.cell]["score"]["cases"]["positive"]
        self.assertIn("native finding lacks the expected boolean after_owner_read", result["outcomes"][0]["reason"])

    def test_native_verify_argv_round_count_matches_retained_record(self):
        fixture = self.fixture
        self.assertEqual(rubric.verification_rounds(["scourge", "verify", "L-1"], "L-1"), 2)
        self.assertEqual(rubric.verification_rounds(
            ["scourge", "--workspace", "/fixture", "verify", "--rounds=2", "--", "L-1"], "L-1"), 2)
        for args in (["--rounds", "1", "--rounds=1"], ["--rounds", "wrong"], ["--rounds=0"],
                     ["--", "--rounds=1"], ["--workspace", "--rounds"], ["--workspace=--rounds"]):
            with self.subTest(args=args), self.assertRaisesRegex(ValueError, "verify argv"):
                rubric.verification_rounds(["scourge", "verify", "L-1", *args], "L-1")

        def default_rounds(events):
            events["calls"][2]["argv"][3:5] = []

        fixture.change(self.row, ["referee", "events"], default_rounds)
        fixture.sync_capture(self.row, native=True)
        result = self.result("failed")["cells"][self.cell]["score"]["cases"]["positive"]
        self.assertIn("retained round count or outcomes disagree with actual verify argv", result["outcomes"][0]["reason"])

    def test_typed_masked_failure_is_required(self):
        def mutate(transport):
            self.fixture.change(transport["masked"], ["stdout"], lambda data: data.update(diagnostics=[]))

        self.fixture.change(self.row, ["referee", "transport"], mutate)
        self.fixture.sync_capture(self.row)
        result = self.result("failed")["cells"][self.cell]["score"]
        self.assertEqual(result["gates"]["transport"]["status"], "failed")

    def test_generated_action_argv_is_compared_without_rewriting(self):
        def mutate(transport):
            transport["generated"]["argv"][0] = "/different/scourge"

        self.fixture.change(self.row, ["referee", "transport"], mutate)
        self.fixture.sync_capture(self.row)
        result = self.result("failed")["cells"][self.cell]["score"]
        self.assertEqual(result["gates"]["transport"]["status"], "failed")

    def test_default_status_counts_actual_utf8_bytes(self):
        ref = self.fixture.write(f'{self.row["attempt_id"]}/retained/artifacts/big-status.stdout',
                                 ("é" * 1025).encode())
        self.fixture.change(self.row, ["referee", "screens"], lambda data: data["status"].update(stdout=ref))
        self.fixture.sync_capture(self.row)
        result = self.result("failed")["cells"][self.cell]["score"]
        self.assertEqual(result["gates"]["screens"]["status"], "failed")

    def test_unretained_artifact_cannot_be_substituted_with_link(self):
        raw = self.fixture.root / self.row["raw"]["path"]
        original = raw.with_name("copy.jsonl")
        raw.rename(original)
        os.link(original, raw)
        self.result("invalid")

    def test_missing_retained_flow_cannot_support_native_badge(self):
        prefix = self.row["attempt_id"]
        (self.fixture.root / prefix / "retained/artifacts/positive/flow-F3.json").unlink()
        self.fixture.sync_capture(self.row)
        result = self.result("failed")["cells"][self.cell]["score"]
        self.assertEqual(result["unsupported_promotions"], [3])

    def test_settled_command_free_native_stream_cannot_support_projected_calls(self):
        self.fixture.sync_capture(self.row, items=[])
        score = self.result("invalid")["cells"][self.cell]
        self.assertIn("does not bind this assignment and capture", score["reason"])
        self.assertIsNone(score["score"])

    def test_projected_badge_cannot_replace_native_stdout(self):
        self.alter_reply(3, lambda data: data["finding"].update(policy_source="operator"), native=False)
        score = self.result("invalid")["cells"][self.cell]
        self.assertIn("output differs", score["reason"])

    def test_concept_coordinated_argv_forgery_does_not_override_screen(self):
        unrelated = ["scourge", "verify", "UNRELATED"]

        def mutate(referee):
            self.fixture.change(referee["concept"], ["referee"], lambda proof: proof.update(
                next_argv=unrelated, entry_next_argv=unrelated))

        self.fixture.change(self.row, ["referee"], mutate)
        concept = self.result("failed")["cells"][self.cell]["score"]["gates"]["concept"]
        self.assertIn("captured screen or native answer", concept["reason"])

    def test_concept_forged_answer_fails_even_when_criteria_match_it(self):
        def mutate(referee):
            entry = referee["concept"]
            new_answer = self.fixture.write(
                f'{entry["attempt_id"]}/retained/artifacts/new-answer.txt',
                b"Verify findings. Never assume a lead is proof. Run scourge list leads. Added later.")
            self.fixture.change(entry, ["referee"], lambda proof: proof.update(answer=new_answer))
            self.fixture.sync_capture(entry)

        self.fixture.change(self.row, ["referee"], mutate)
        concept = self.result("failed")["cells"][self.cell]["score"]["gates"]["concept"]
        self.assertIn("native entry-only transcript", concept["reason"])

    def test_phantom_directory_cannot_pass_with_matching_inventory_hashes(self):
        def mutate(capture):
            inventory = capture["inventory"]
            rows = inventory["source"]
            rows.append({"path": "artifacts/phantom", "type": "directory", "bytes": 0, "sha256": None})
            rows.sort(key=lambda row: row["path"])
            inventory.update(retained=rows, source_sha256=rubric.digest(rubric.canonical(rows)),
                             retained_sha256=rubric.digest(rubric.canonical(rows)))

        self.fixture.change(self.row, ["capture"], mutate)
        score = self.result("invalid")["cells"][self.cell]
        self.assertIn("actual file tree", score["reason"])

    def test_boolean_preflight_is_not_a_capacity_and_path_receipt(self):
        self.fixture.change(self.row, ["capture"], lambda data: data.update(preflight={"passed": True}))
        self.assertIsNone(self.result("invalid")["cells"][self.cell]["score"])

    def test_complete_round_requires_every_oracle_step(self):
        self.change_case("positive", "record", lambda record: record["rounds"][0]["flows"].pop(7))
        self.rebind_case("positive", 3)
        result = self.result("failed")["cells"][self.cell]["score"]
        self.assertIn("chronological step groups", result["cases"]["positive"]["outcomes"][0]["reason"])

    def test_record_and_badge_cannot_substitute_an_admission_projection(self):
        def project(referee):
            index = self.fixture.evidence.json(referee["case_index"])
            ref = {"case": index["cases"]["positive"][0]}
            asserted = self.fixture.write(f'{self.row["attempt_id"]}/admitted.json', {"admitted": True})
            self.fixture.change(ref, ["case"], lambda case: case.update(manifest=asserted))
            self.fixture.change(referee, ["case_index"], lambda receipts: receipts["cases"].update(
                positive=[ref["case"]]))

        self.fixture.change(self.row, ["referee"], project)
        result = self.result("failed")["cells"][self.cell]["score"]
        self.assertIn("frozen manifest", result["cases"]["positive"]["outcomes"][0]["reason"])

    def change_flow(self, entry, case, step, number, edit):
        """Mutate an original and rebuild its soundness links to expose semantic errors."""
        fixture = self.fixture
        ref = fixture.evidence.json(entry["referee"])
        index = fixture.evidence.json(ref["case_index"]) if "case_index" in ref else None
        receipt = {"case": index["cases"][case][0] if index else ref["witness"]}

        def change_sources(sources):
            originals = [item for item in sources["originals"] if item["file"]["path"].endswith(f"/flow-{step}.json")]
            self.assertEqual(len(originals), 1)
            original = originals[0]
            fixture.change(original, ["file"], lambda envelope: edit(envelope["flow"]))
            native_id = fixture.evidence.json(original["file"])["flow"]["id"]

            def change_record(record):
                for row in record["rounds"]:
                    for item in [*row["flows"], *row["identities"]]:
                        if item["original"]["artifact_id"] == original["artifact_id"]:
                            item["original"]["digest"] = original["file"]["sha256"]
                            if "flow_id" in item:
                                item["flow_id"] = native_id

            fixture.change(sources, ["record"], change_record)
            fixture.change(sources, ["index"], lambda reply: reply["record"].update(
                record_digest=sources["record"]["sha256"]))
            fixture.correlate_native_children(sources, entry["attempt_id"], number)

        fixture.change(receipt, ["case"], change_sources)
        sha = fixture.evidence.json(receipt["case"])["record"]["sha256"]

        def change_referee(referee):
            if index:
                fixture.change(referee, ["case_index"], lambda review: review["cases"].update(
                    {case: [receipt["case"]]}))
            else:
                referee["witness"] = receipt["case"]
            fixture.change(referee, ["events"], lambda events: fixture.change(
                events["calls"][number - 1], ["stdout"],
                lambda reply: reply["verification"]["artifact"].update(digest=sha)))

        fixture.change(entry, ["referee"], change_referee)
        fixture.sync_capture(entry, native=True)

    def test_f37_rejects_owner_authenticated_cache_read(self):
        entry = self.fixture.ledger["scripted_f37"]
        self.change_flow(entry, "f37", "F3", 1, lambda flow: flow.update(
            request_head=f'{flow["request_head"]}\nCookie: scourge_session={COOKIES["owner"]}'))
        gate = self.result("passed")["aggregate"]["scripted_f37"]
        self.assertEqual(gate["status"], "failed")
        self.assertIn("F3 used the wrong fixture session", gate["reason"])

    def test_owner_credential_cannot_stand_in_for_other(self):
        self.change_flow(self.row, "positive", "F2", 3, lambda flow: flow.update(
            request_head=flow["request_head"].replace(COOKIES["other"], COOKIES["owner"])))
        gate = self.result("failed")["cells"][self.cell]["score"]["cases"]["positive"]
        self.assertIn("F2 used the wrong fixture session", gate["outcomes"][0]["reason"])

    def test_missing_or_duplicate_authenticated_cookie_cannot_pass(self):
        self.change_flow(self.row, "positive", "I1", 3, lambda flow: flow.update(
            request_head=flow["request_head"].split("\nCookie:")[0]))
        self.change_flow(self.row, "public", "I2", 4, lambda flow: flow.update(
            request_head=f'{flow["request_head"]}\nCookie: scourge_session={COOKIES["other"]}'))
        cases = self.result("failed")["cells"][self.cell]["score"]["cases"]
        self.assertIn("lack distinct fixture session", cases["positive"]["outcomes"][0]["reason"])
        self.assertIn("ambiguous fixture session", cases["public"]["outcomes"][0]["reason"])

    def test_native_bodies_allow_empty_denial_and_dechunked_compression(self):
        def response(flow, data, headers):
            flow["response_head"] += headers
            flow["response_body_base64"] = b64encode(data).decode()
            flow["response_body_info"].update(captured=len(data), shown=len(data), observed=len(data))

        entry = self.fixture.ledger["scripted_f37"]

        def deny(flow):
            flow.update(status=401, response_head="HTTP/1.1 401 Unauthorized")
            response(flow, b"", "\nContent-Length: 0")

        self.change_flow(entry, "f37", "F0", 1, deny)

        def compress(flow):
            primary = rubric.retained_body(flow, "response")
            response(flow, gzip.compress(primary, mtime=0),
                     "\nTransfer-Encoding: chunked\nContent-Encoding: gzip")

        self.change_flow(entry, "f37", "F3", 1, compress)
        gate = self.result("passed")["aggregate"]["scripted_f37"]
        self.assertEqual(gate["status"], "passed")
        self.assertTrue(gate["after_owner_read"])

    def test_native_decoder_bounds_and_framing(self):
        payload = b'{"note":"plain response"}'
        options = {"limits": {"max_decoded_bytes": 1_048_576, "max_expansion_ratio": 100}}
        flow = copy.deepcopy(FLOW_TEMPLATE["flow"])
        flow["response_head"] += "\nContent-Encoding: deflate"
        for window in (15, -15):
            compressor = zlib.compressobj(wbits=window)
            coded = compressor.compress(payload) + compressor.flush()
            flow["response_body_base64"] = b64encode(coded).decode()
            flow["response_body_info"].update(captured=len(coded), shown=len(coded), observed=len(coded))
            self.assertEqual(rubric.decoded_response(flow, options), payload)
        with self.assertRaisesRegex(ValueError, "oversized"):
            rubric.decoded_response(flow, {"limits": {"max_decoded_bytes": 2, "max_expansion_ratio": 100}})
        chunked = b"4\r\ntest\r\n0\r\n\r\n"
        flow["response_head"] = "HTTP/1.1 200 OK\nTransfer-Encoding: chunked"
        flow["response_body_base64"] = b64encode(chunked).decode()
        flow["response_body_info"].update(captured=len(chunked), shown=len(chunked), observed=len(chunked))
        self.assertEqual(rubric.decoded_response(flow, options), chunked)
        flow.update(response_head="HTTP/1.1 401 Unauthorized\nContent-Length: 0", status=401)
        flow.pop("response_body_base64")
        flow["response_body_info"].update(capture="none", captured=0, shown=0, observed=0, whole=False)
        with self.assertRaisesRegex(ValueError, "body bytes are absent"):
            rubric.decoded_response(flow, options)

    def test_codex_shell_wrapper_discovery_and_compound_processes(self):
        fixture = self.fixture
        referee = fixture.evidence.json(self.row["referee"])
        calls = fixture.evidence.json(referee["events"])["calls"]
        separate = [json.loads(line)["item"] for line in fixture.evidence.read(self.row["raw"]).splitlines()
                    if json.loads(line)["type"] == "item.completed"]
        orient = calls[0]
        status = fixture.evidence.read(orient["stdout"]).decode()
        discovery = "/usr/bin/bash -lc 'command -v scourge'"
        compound = "/usr/bin/bash -lc \"cd '/bound fixture' && scourge --format json && scourge verify --help\""
        extras = [
            {"id": "native-discovery", "type": "command_execution", "command": discovery,
             "aggregated_output": "/usr/local/bin/scourge\n", "status": "completed", "exit_code": 0},
            {"id": orient["native_item"], "type": "command_execution", "command": compound,
             "aggregated_output": status + "Help", "status": "completed", "exit_code": 0},
        ]

        def combine(events):
            events["calls"][1].update(native_item=orient["native_item"], output_offset=len(status.encode()))

        fixture.change(self.row, ["referee", "events"], combine)
        recorded = [json.loads(line)["item"] for line in
                    (FIXTURES / "codex-0.172-command-items.jsonl").read_bytes().splitlines()]
        self.assertEqual([item["aggregated_output"] for item in recorded],
                         ["/usr/bin/sh\n", "first\nsecond\n"])
        fixture.sync_capture(self.row, native=True, items=[*recorded, *extras, *separate[2:]])
        score = self.result("passed")["cells"][self.cell]["score"]
        self.assertEqual(score["scourge_calls"], 6)
        self.assertEqual(score["gates"]["first_useful"]["call"], 3)
        # Removing the help row without removing its observed process fails.
        fixture.change(self.row, ["referee", "events"], lambda events: events["calls"].pop(1))
        fixture.sync_capture(self.row)
        self.assertIn("do not account", self.result("invalid")["cells"][self.cell]["reason"])

    def test_shell_expansion_and_malformed_items_defer_to_authenticated_exec_trace(self):
        for source in ('scourge show "$id"', "scourge '", "command -v scourge"):
            shell_command = shlex.join(["/usr/bin/bash", "-lc", source])
            with self.subTest(source=source):
                self.assertIsNone(rubric.direct_scourge_argv({"command": shell_command}))
        literal = "/usr/bin/bash -lc 'scourge show L-1'"
        self.assertEqual(rubric.direct_scourge_argv({"command": literal}), ["scourge", "show", "L-1"])

    def test_pipe_and_redirect_keep_authenticated_process_output(self):
        fixture = self.fixture
        items = [event["item"] for line in fixture.evidence.read(self.row["raw"]).splitlines()
                 if (event := json.loads(line))["type"] == "item.completed"]
        items[1].update(command="/usr/bin/bash -lc 'scourge verify --help > help.txt'", aggregated_output="")
        items[2].update(command="/usr/bin/bash -lc 'scourge verify L-1 --format json | jq .run.id'",
                        aggregated_output='"R-1"\n')

        def mark_transformed(events):
            for row in events["calls"][1:3]:
                row["output_offset"] = None
            events["calls"][2]["format"] = "text"  # The process stdout is still a native JSON response.

        fixture.change(self.row, ["referee", "events"], mark_transformed)
        fixture.sync_capture(self.row, native=True, items=items)
        score = self.result("passed")["cells"][self.cell]["score"]
        self.assertEqual(score["scourge_calls"], 6)
        self.assertEqual(score["mutating_calls_to_first_verdict"], 1)

        fixture.change(self.row, ["referee", "events"], lambda events: events["calls"][2].update(output_offset=0))
        fixture.sync_capture(self.row, native=True, items=items)
        self.assertIn("direct process output differs", self.result("invalid")["cells"][self.cell]["reason"])

    def test_concept_accepts_rendered_context_abbreviation(self):
        fixture = self.fixture
        screen = SCREEN.replace(b"scourge list leads\n",
                                b"scourge list leads (use the selected workspace and engagement)\n")
        prefix = self.row["attempt_id"]
        source = fixture.write(f"{prefix}/retained/artifacts/abbreviated-entry.stdout", screen)
        fixture.change(self.row, ["referee", "screens"], lambda info: info["entry"].update(stdout=source))

        def update_concept(referee):
            entry = referee["concept"]
            abbreviated = fixture.write(f'{entry["attempt_id"]}/retained/artifacts/abbreviated.stdout', screen)
            fixture.change(entry, ["referee", "context"], lambda info: info.update(
                entry_stdout=abbreviated, visible_inputs=[abbreviated["sha256"]]))
            fixture.sync_capture(entry)

        fixture.change(self.row, ["referee"], update_concept)
        fixture.sync_capture(self.row)
        self.assertEqual(self.result("passed")["cells"][self.cell]["score"]["gates"]["concept"]["status"], "passed")

    def test_unsigned_empty_compound_trace_cannot_hide_mutation(self):
        fixture = self.fixture
        command = '/usr/bin/bash -lc "true && scourge lead add sneaky"'
        item = {"id": "unattributed", "type": "command_execution", "command": command,
                "aggregated_output": "", "status": "completed", "exit_code": 0}
        items = [event["item"] for line in fixture.evidence.read(self.row["raw"]).splitlines()
                 if (event := json.loads(line))["type"] == "item.completed"]
        items.insert(2, item)
        fixture.change(self.row, ["referee", "events"], lambda events: events["commands"].insert(2, {
            "native_item": item["id"], "command": command, "output_sha256": rubric.digest(b""),
            "tree_closed": True, "lost_events": 0, "exit_code": 0, "executions": [],
        }))
        # Rebuild both raw hashes and the inventory, leaving the independent
        # host signature unchanged.
        fixture.sync_capture(self.row, items=items)
        score = self.result("invalid")["cells"][self.cell]
        self.assertIn("does not bind this assignment and capture", score["reason"])
        self.assertIsNone(score["score"])

    def test_trace_reference_and_private_key_are_required(self):
        fixture = self.fixture
        fixture.change(self.row, ["referee"], lambda referee: referee.pop("host_trace"))
        score = self.result("invalid")["cells"][self.cell]
        self.assertIn("missing authenticated host process trace", score["reason"])
        fixture.evidence = rubric.Evidence(fixture.root, b"\xff" * 32)
        score = self.result("invalid")["cells"][self.cell]
        self.assertIn("missing or incorrect frozen host trace key", score["reason"])

    def test_modified_or_signer_reported_incomplete_host_trace_fails(self):
        fixture = self.fixture

        def change_trace(envelope):
            envelope["trace"]["commands"][1]["executions"].clear()

        fixture.change(self.row, ["referee", "host_trace"], change_trace)
        fixture.sync_capture(self.row)
        self.assertIn("authentication", self.result("invalid")["cells"][self.cell]["reason"])

        def incomplete_trace(envelope):
            envelope["trace"]["commands"][1]["lost_events"] = 1
            envelope["hmac_sha256"] = rubric.host_trace_mac(envelope["trace"], TEST_MONITOR_KEY)

        fixture.change(self.row, ["referee", "host_trace"], incomplete_trace)
        fixture.sync_capture(self.row)
        self.assertIn("complete host tree settlement", self.result("invalid")["cells"][self.cell]["reason"])

    def test_valid_host_signature_requires_exact_launch_prompt_digest_and_size(self):
        fixture = self.fixture
        trace_ref = fixture.evidence.json(self.row["referee"])["host_trace"]
        original = fixture.evidence.json(trace_ref)
        cases = ({"prompt_sha256": rubric.digest(b"unexpected instruction")},
                 {"prompt_size_bytes": original["trace"]["prompt_size_bytes"] + 1},
                 {"prompt_size_bytes": True}, {"prompt_sha256": None})
        for changes in cases:
            with self.subTest(changes=changes):
                def alter(envelope):
                    envelope["trace"] = {**original["trace"], **changes}
                    envelope["hmac_sha256"] = rubric.host_trace_mac(envelope["trace"], TEST_MONITOR_KEY)

                fixture.change(self.row, ["referee", "host_trace"], alter)
                fixture.sync_capture(self.row)
                score = self.result("invalid")["cells"][self.cell]
                self.assertIn("launch stdin differs", score["reason"])
                self.assertIsNone(score["score"])

    def test_valid_signature_does_not_allow_an_omitted_command(self):
        fixture = self.fixture

        def omit(envelope):
            envelope["trace"]["commands"].pop(1)
            envelope["hmac_sha256"] = rubric.host_trace_mac(envelope["trace"], TEST_MONITOR_KEY)

        fixture.change(self.row, ["referee", "host_trace"], omit)
        fixture.sync_capture(self.row)
        self.assertIn("does not cover every native command", self.result("invalid")["cells"][self.cell]["reason"])

    def change_native_experiment(self, case, number, edit, record_edit=None):
        self.change_case(case, "experiment", edit)
        ref = self.fixture.evidence.json(self.row["referee"])
        cases = self.fixture.evidence.json(ref["case_index"])["cases"]
        experiment = self.fixture.evidence.json(cases[case][0])["experiment"]["sha256"]

        def bind_record(record):
            record["experiment_digest"] = experiment
            if record_edit is not None:
                record_edit(record)

        self.change_case(case, "record", bind_record)
        self.change_case(case, "run", lambda reply: reply.update(experiment_digest=experiment))
        self.rebind_case(case, number)

    def test_native_experiment_requires_slots_principals_and_effects(self):
        cases = [("positive", 3, "slots"), ("public", 4, "principals"), ("login", 5, "effects")]
        for case, number, field in cases:
            self.change_native_experiment(case, number, lambda experiment: experiment.pop(field))
        graded = self.result("failed")["cells"][self.cell]["score"]["cases"]
        for case, _, _ in cases:
            self.assertIn("canonical native FrozenExperiment", graded[case]["outcomes"][0]["reason"])

    def test_relinked_native_experiment_rejects_mutated_bindings(self):
        wrong_operation = "operation.wrong"
        wrong_digest = rubric.digest(wrong_operation.encode())

        def change_slot(record):
            next(slot for slot in record["slots"] if slot["name"] == "read")["digest"] = wrong_digest

        self.change_native_experiment("positive", 3, lambda exp: exp["slots"]["read"].update(
            value=wrong_operation, digest=wrong_digest), change_slot)
        self.change_native_experiment("public", 4, lambda exp: exp["principals"]["other"].update(
            session=exp["principals"]["owner"]["session"]))
        self.change_native_experiment("login", 5, lambda exp: exp["effects"].append("mutate"))
        scored = self.result("failed")["cells"][self.cell]["score"]["cases"]
        for case, reason in (("positive", "operation slot"), ("public", "principal does not match"),
                             ("login", "effects do not match")):
            self.assertIn(reason, scored[case]["outcomes"][0]["reason"])

    def test_coherent_whole_role_swap_fails_frozen_session_binding(self):
        for step in (*ROLES, "C.primary", "C.control"):
            role = "owner" if step.startswith("C.") else ROLES[step]
            if role == "anonymous":
                continue
            opposite = "other" if role == "owner" else "owner"
            self.change_flow(
                self.row, "positive", step, 3,
                lambda flow: self.swap_flow_role(flow, step, role, opposite),
            )

        def swap_record(record):
            for identity in record["rounds"][0]["identities"]:
                replacement = "other" if identity["principal"] == "owner" else "owner"
                identity["subject_digest"] = rubric.digest(SUBJECTS[replacement].encode())

        self.change_case("positive", "record", swap_record)
        self.rebind_case("positive", 3)
        result = self.result("failed")["cells"][self.cell]["score"]["cases"]["positive"]
        self.assertIn("I1 used the wrong fixture session", result["outcomes"][0]["reason"])

    @staticmethod
    def swap_flow_role(flow, step, role, opposite):
        flow["request_head"] = flow["request_head"].replace(COOKIES[role], COOKIES[opposite])
        if step in IDENTITY_STEPS:
            payload = rubric.canonical({"id": SUBJECTS[opposite]})
            flow["response_body_base64"] = b64encode(payload).decode()
            flow["response_body_info"].update(captured=len(payload), shown=len(payload), observed=len(payload))

    def test_prepared_session_probe_and_reset_do_not_transfer_to_another_case(self):
        fixture = self.fixture
        slot = fixture.frozen["cells"][self.cell]
        receipt = fixture.evidence.json(slot["session_access"]["positive"])
        other_case = {**slot, "session_access": {**slot["session_access"],
                                               "positive": slot["session_access"]["public"]}}
        record = {**DEFINED, **rubric.M1_CONTEXT, "engagement": ENGAGEMENT, "target": TARGET,
                  "property": receipt["property"]}
        with self.assertRaisesRegex(ValueError, "does not bind"):
            rubric.prepared_access(fixture.evidence, other_case, "positive", record, {}, DECLARATION)
        fixture.change(self.row, ["referee", "boundary"], lambda boundary: boundary.update(reset_id="another-reset"))
        fixture.sync_capture(self.row)
        self.assertIn("prepared access", self.result("invalid")["cells"][self.cell]["reason"])

    def test_coordinated_decoder_limit_drift_fails_exact_compiled_binding(self):
        self.change_native_experiment("positive", 3, lambda experiment: experiment["decoder"]["limits"].update(
            max_expansion_ratio=101))
        result = self.result("failed")["cells"][self.cell]["score"]["cases"]["positive"]
        self.assertIn("exact compiled template binding", result["outcomes"][0]["reason"])

    def test_compiled_decoder_limits_match_native_source(self):
        template = Path(rubric.REPOSITORY / "crates/scourge-core/src/template/mod.rs").read_text()
        for constant, name in (("DEFAULT_MAX_DECODED_BYTES", "max_decoded_bytes"),
                               ("DEFAULT_MAX_EXPANSION_RATIO", "max_expansion_ratio")):
            literal = template.split(f"pub const {constant}: u64 = ", 1)[1].split(";", 1)[0]
            self.assertEqual(rubric.FROZEN_DECODER["limits"][name], int(literal.replace("_", "")))

    def test_native_manifest_refuses_omitted_unknown_and_noncanonical_shapes(self):
        manifest = self.fixture.evidence.json(self.fixture.manifest)
        for candidate in (
            {key: value for key, value in manifest.items() if key != "pass_digest"},
            {**manifest, "unknown": True},
            {**manifest, "parent": None},
            {**manifest, "revision": 2},
            {**manifest, "declaration": {**manifest["declaration"], "unknown": "inert"}},
        ):
            with self.subTest(candidate=candidate.keys()), self.assertRaises(ValueError):
                rubric.qualified_manifest(rubric.native_bytes(candidate))
        with self.assertRaisesRegex(ValueError, "canonical"):
            rubric.qualified_manifest(rubric.native_bytes(manifest) + b"\n")

    def test_manifest_must_bind_independent_source_pass_and_native_ancestry(self):
        fixture = self.fixture
        assignment = fixture.frozen["cells"][self.cell]
        wrong = fixture.write("frozen/unadmitted-pass.bin", b"different pass bytes")
        with self.assertRaisesRegex(ValueError, "source/pass digests"):
            rubric.check_manifest_admission(fixture.evidence, {**assignment, "pass_artifact": wrong})
        with self.assertRaisesRegex(ValueError, "source/pass digests"):
            rubric.check_manifest_admission(fixture.evidence, {**assignment, "manifest_source": wrong})
        current = fixture.evidence.json(fixture.manifest)
        child = fixture.write("frozen/manifest-v2.json", {**current, "revision": 2, "parent": "7" * 64})
        with self.assertRaisesRegex(ValueError, "ancestry"):
            rubric.check_manifest_admission(fixture.evidence, {
                **assignment, "manifest": child, "manifest_history": [fixture.manifest],
            })

    def test_fixture_manifest_requires_the_prepared_capture_original(self):
        fixture = self.fixture
        assignment = fixture.frozen["cells"][self.cell]
        original = assignment["manifest_capture"]
        ids = case_evidence_ids(f'{self.row["attempt_id"]}/preparation')
        self.assertEqual(rubric.prepared_manifest_capture(fixture.evidence, assignment),
                         (ids["case"], ids["manifest"], 1))
        wrong = fixture.evidence.json(original)
        wrong["record"]["body"]["capture_finalization"]["artifacts"][0]["key"] = "not-engagement"
        ref = fixture.write("frozen/wrong-capture.json", wrong)
        with self.assertRaisesRegex(ValueError, "manifest original differs"):
            rubric.check_manifest_admission(fixture.evidence, {**assignment, "manifest_capture": ref})

        def edit(children, receipt):
            proc = next(proc for proc in children if proc["argv"][-4:] == ["show", ids["manifest"], "--depth", "full"])
            link = next(row for row in receipt["child_originals"] if row["process_id"] == proc["process_id"])
            reply = fixture.evidence.json(link["file"])
            unknown = evidence_id("art", "same-manifest-digest-but-different-capture")
            proc["argv"][-3] = reply["id"] = reply["record"]["header"]["id"] = unknown
            fixture.update_child_source(link, fixture.write(link["file"]["path"], reply), proc)

        self.edit_signed_case_children("positive", 3, edit)
        calls = self.result("failed")["cells"][self.cell]["score"]["cases"]
        self.assertIn("preflight manifest read is missing", calls["positive"]["outcomes"][0]["reason"])

    def test_prepared_capture_original_cannot_claim_a_transform(self):
        ident = case_evidence_ids(f'{self.row["attempt_id"]}/preparation')["manifest"]
        self.mutate_investigation_output("positive", 3,
                                         lambda op: op[-4:] == ["show", ident, "--depth", "full"],
                                         lambda reply: reply["record"]["body"].update(transforms=[{}]))
        cases = self.result("failed")["cells"][self.cell]["score"]["cases"]
        self.assertIn("exact native derivation inputs", cases["positive"]["outcomes"][0]["reason"])

    def test_matching_record_and_badge_cannot_overclaim_custody_or_enforcement(self):
        values = {"custody": "isolated", "target_isolation": "separate_principals",
                  "enforcement": "egress_enforced"}
        self.change_case("positive", "record", lambda record: record.update(
            **values, destination_time_enforced=True, request_ceiling_enforced=True))
        self.rebind_case("positive", 3)
        self.alter_reply(3, lambda reply: reply["finding"].update(values))
        self.change_case("public", "record", lambda record: record.update(environment_kind="original"))
        self.rebind_case("public", 4)
        scored = self.result("failed")["cells"][self.cell]["score"]["cases"]
        for case in ("positive", "public"):
            self.assertIn("native M1 custody and enforcement", scored[case]["outcomes"][0]["reason"])

    def test_native_target_and_flow_origin_must_match_prepared_fixture(self):
        self.change_case("positive", "record", lambda record: record["target"].update(
            origin="http://substitute.invalid:37279", addresses=["192.0.2.11"]))
        self.rebind_case("positive", 3)
        self.change_flow(self.row, "public", "F2", 4, lambda flow: flow.update(
            url=flow["url"].replace(ORIGIN, "http://fixture.invalid:37280")))
        scored = self.result("failed")["cells"][self.cell]["score"]["cases"]
        self.assertIn("native target differs", scored["positive"]["outcomes"][0]["reason"])
        self.assertIn("outside the prepared fixture origin", scored["public"]["outcomes"][0]["reason"])

    def test_declared_canary_field_cannot_be_omitted_from_both_plants(self):
        def drop_plant_field(flow):
            body = json.loads(rubric.retained_body(flow, "request"))
            body.pop("detail")
            data = rubric.canonical(body)
            flow["request_body_base64"] = b64encode(data).decode()
            flow["request_body_info"].update(captured=len(data), shown=len(data), observed=len(data))

        for step in ("P", "P2"):
            self.change_flow(self.row, "positive", step, 3, drop_plant_field)

        def drop_record_field(record):
            row = record["rounds"][0]
            row["canaries"] = [canary for canary in row["canaries"] if canary["field"] != "detail"]
            row["fields_crossed"] = ["note"]

        self.change_case("positive", "record", drop_record_field)
        self.rebind_case("positive", 3)
        scored = self.result("failed")["cells"][self.cell]["score"]["cases"]["positive"]
        self.assertIn("cover every native declared field", scored["outcomes"][0]["reason"])

    def test_every_native_fixture_property_resolves_in_the_pinned_registry(self):
        registry = rubric.operation_registry()
        observed = {prop["resource"]: rubric.registered_property(prop) for prop in DECLARATION["property"].values()}
        self.assertEqual(observed, registry["resources"])
        self.assertEqual(rubric.registry_pin()["compiled_digest"],
                         "241a2c9a9cfac4be5ef31d2e9eb9a9bdbfd4e85e87b8e92daca539cc7ac8d289")

    def test_coherent_invented_resource_experiment_does_not_resolve(self):
        source = DECLARATION_TOML
        for namespace in (b"resource", b"operation", b"selector"):
            source = source.replace(namespace + b".catalog", namespace + b".nonexistent")
        with tempfile.TemporaryDirectory() as root:
            result = Fixture(Path(root), declaration_source=source).grade()
        self.assertEqual(result["aggregate"]["status"], "failed")
        for row in result["cells"].values():
            reason = row["score"]["cases"]["public"]["outcomes"][0]["reason"]
            self.assertIn("outside the compiled native operation registry", reason)

    def test_rehashed_bad_id_and_timestamp_fail_independent_chronology(self):
        self.change_flow(self.row, "public", "F1", 4, lambda flow: flow.update(id=208))
        self.change_flow(self.row, "public", "F3", 4, lambda flow: flow.update(id=206))
        self.change_flow(self.row, "positive", "F3", 3, lambda flow: flow.update(
            started_at="2026-11-23T16:00:01.000000004Z"))
        scored = self.result("failed")["cells"][self.cell]["score"]["cases"]
        self.assertIn("timestamps do not establish dispatch order", scored["positive"]["outcomes"][0]["reason"])
        self.assertIn("flow IDs do not advance", scored["public"]["outcomes"][0]["reason"])

    def test_late_cold_retry_cannot_shadow_the_real_f37_cold_read(self):
        fixture = self.fixture
        entry = fixture.ledger["scripted_f37"]
        sources = fixture.evidence.json(fixture.evidence.json(entry["referee"])["witness"])
        originals = {Path(item["file"]["path"]).name: item["file"] for item in sources["originals"]}
        cold = fixture.evidence.json(originals["flow-F0.json"])
        owner = fixture.evidence.json(originals["flow-F1.json"])["flow"]
        cold["flow"].update(id=991, started_at="2026-11-23T16:00:02Z")
        self.change_flow(entry, "f37", "F0", 1, lambda flow: flow.update(
            response_body_base64=owner["response_body_base64"],
            response_body_info=owner["response_body_info"]))
        late = fixture.write(f'{entry["attempt_id"]}/retained/artifacts/f37/late-F0.json', cold)

        def insert(referee):
            def mutate(witness):
                artifact = {"artifact_id": "late-cold-read", "digest": late["sha256"]}
                witness["originals"].append({"artifact_id": artifact["artifact_id"], "file": late})

                def append(record):
                    record["rounds"][0]["flows"].append({
                        "step": "F0.retry", "flow_id": 991, "original": artifact, "completeness": "complete",
                        "decoder": {"id": "http-body", "version": "1"},
                    })

                fixture.change(witness, ["record"], append)
                fixture.change(witness, ["index"], lambda index: index["record"].update(
                    record_digest=witness["record"]["sha256"]))

            fixture.change(referee, ["witness"], mutate)
            sha = fixture.evidence.json(referee["witness"])["record"]["sha256"]
            fixture.change(referee, ["events"], lambda events: fixture.change(
                events["calls"][0], ["stdout"], lambda reply: reply["verification"]["artifact"].update(digest=sha)))

        fixture.change(entry, ["referee"], insert)
        fixture.sync_capture(entry, native=True)
        result = self.result("passed")["aggregate"]["scripted_f37"]
        self.assertEqual(result["status"], "failed")
        self.assertIn("shadowed", result["reason"])

    def test_registered_clean_sessions_and_dispatch_disallow_multi_hop_steps(self):
        for extras in (["login", "retry"], ["login", "login", "retry"], ["redirect"]):
            with self.subTest(extras=extras):
                round_row = {"flows": [{"step": f"{step}.{kind}"} for step in ROLES
                                       for kind in (["request", *extras] if step == "F1" else ["request"])]}
                with self.assertRaisesRegex(ValueError, "relogin, retry or followed redirect"):
                    rubric.chronological_steps(round_row, ROLES)

    def change_instrument_artifact(self, case, number, label, edit):
        fixture = self.fixture

        def change_case_index(index):
            case_ref = index["cases"][case][0]
            receipt = fixture.evidence.json(case_ref)
            entry = next(item for item in receipt["instrument_originals"]
                         if item["file"]["path"].endswith(f"/{label}.json"))
            fixture.change(entry, ["file"], edit)

            def change_record(record):
                artifact_id = entry["artifact_id"]
                sha = entry["file"]["sha256"]
                if label.startswith("edit-surface-"):
                    boundary = label.removeprefix("edit-surface-")
                    record[f"edit_surface_{boundary}"][0]["digest"] = sha
                else:
                    accounting = record["accounting"]
                    for ref in accounting["attribution_evidence"]:
                        if ref["artifact_id"] == artifact_id:
                            ref["digest"] = sha
                    for phase in ("before", "after"):
                        for count in accounting[f"counters_{phase}"].values():
                            if count is not None and count["evidence"]["artifact_id"] == artifact_id:
                                count["evidence"]["digest"] = sha

            fixture.change(receipt, ["record"], change_record)
            index["cases"][case][0] = fixture.write(case_ref["path"], receipt)

        fixture.change(self.row, ["referee", "case_index"], change_case_index)
        self.rebind_case(case, number)

    def change_gate_source(self, case, number, key, edit, *, sign=True):
        fixture = self.fixture

        def change_case_index(index):
            case_ref = index["cases"][case][0]
            receipt = fixture.evidence.json(case_ref)
            row = next(row for row in receipt["edit_surface_originals"]["start"]
                       if (row["operation"], row["session"]) == key)
            fixture.change(row, ["file"], edit)
            children = fixture.instrument_children[(self.row["attempt_id"], f"item-{number}")]
            proc = next(proc for proc in children if proc["process_id"] == row["process_id"])
            child_source = next(source for source in receipt["child_originals"] if source["process_id"] == proc["process_id"])
            fixture.update_child_source(child_source, row["file"], proc, sign=sign)
            index["cases"][case][0] = fixture.write(case_ref["path"], receipt)

        fixture.change(self.row, ["referee", "case_index"], change_case_index)
        fixture.sync_capture(self.row, native=True)

    def test_native_admitted_boundary_rejects_active_rule_and_missing_reads(self):
        def insert_rule(envelope):
            row = envelope["observation"]["admitted"]["edit_surface"]["readings"][0]
            row.update(result_sha256=rubric.native_digest([ACTIVE_RULE]), report={"rules": [[True, "running"]]})

        self.change_gate_source("positive", 3, ("rules_list", None), lambda source: source["rules"].append(ACTIVE_RULE))
        self.change_instrument_artifact("positive", 3, "edit-surface-start", insert_rule)
        self.change_instrument_artifact("public", 4, "edit-surface-end",
                                        lambda envelope: envelope["observation"]["admitted"].update(calls=[]))
        self.change_instrument_artifact("login", 5, "edit-surface-start",
                                        lambda envelope: envelope["observation"]["admitted"]["edit_surface"].update(
                                            readings=[]))
        results = self.result("failed")["cells"][self.cell]["score"]["cases"]
        for case, reason in (("positive", "active or unqualified rule"), ("public", "unconsumed native edit-surface source"),
                             ("login", "edit-surface sources do not cover the admitted boundary")):
            self.assertIn(reason, results[case]["outcomes"][0]["reason"])

    def test_native_edit_surface_rejects_counterfeit_summary_unsigned_and_unknown_sources(self):
        def counterfeit(envelope):
            row = envelope["observation"]["admitted"]["edit_surface"]["readings"][0]
            row.update(result_sha256=rubric.native_digest([ACTIVE_RULE]), report={"rules": []})

        self.change_gate_source("positive", 3, ("rules_list", None), lambda source: source["rules"].append(ACTIVE_RULE))
        self.change_instrument_artifact("positive", 3, "edit-surface-start", counterfeit)
        self.change_gate_source("public", 4, ("rules_list", None), lambda source: source["rules"].append(ACTIVE_RULE),
                                sign=False)
        self.change_gate_source("login", 5, ("rules_list", None), lambda source: source.update(invented=True))
        self.change_instrument_artifact("same_subject", 6, "edit-surface-start", counterfeit)
        results = self.result("failed")["cells"][self.cell]["score"]["cases"]
        for case, reason in (("positive", "report differs from its retained source reduction"),
                             ("public", "native child original differs from authenticated stdout"),
                             ("login", "unknown native edit-surface source shape"),
                             ("same_subject", "result digest differs from retained source")):
            self.assertIn(reason, results[case]["outcomes"][0]["reason"])

    def test_unexpected_or_duplicated_direct_teapot_child_fails(self):
        fixture = self.fixture
        prefix = self.row["attempt_id"]
        for number, unexpected in ((3, True), (4, False)):
            children = fixture.instrument_children[(prefix, f"item-{number}")]
            extra = {**children[0], "process_id": 8000 + number}
            if unexpected:
                extra["argv"] = extra["argv"][:4] + ["rules-status", "list"]
            children.append(extra)
        fixture.sync_capture(self.row, native=True)
        cases = self.result("failed")["cells"][self.cell]["score"]["cases"]
        for case in ("positive", "public"):
            self.assertIn("do not cover the signed verify subprocesses", cases[case]["outcomes"][0]["reason"])

    def test_foreign_child_and_tool_grandchild_cannot_contribute_to_verification(self):
        fixture = self.fixture
        prefix = self.row["attempt_id"]
        children = fixture.instrument_children[(prefix, "item-3")]
        foreign = {**children[0], "process_id": 999888, "exec_path": "/tmp/teapot", "role": "teapot",
                   "binary_sha256": "9" * 64, "argv": ["teapot", *children[0]["argv"][1:]]}
        children.append(foreign)
        children = fixture.instrument_children[(prefix, "item-4")]
        wrapper = {"process_id": 999700, "parent_process_id": 1004, "role": "support",
                   "argv": ["/bin/sh", "-c", "teapot requests send"], "exec_path": "/bin/sh",
                   "binary_sha256": "7" * 64, "exit_code": 0}
        grandchild = {**children[0], "process_id": 999701, "parent_process_id": 999700}
        children.extend([wrapper, grandchild])
        fixture.sync_capture(self.row, native=True)
        cases = self.result("failed")["cells"][self.cell]["score"]["cases"]
        self.assertIn("misclassified or failed direct Scourge verify child", cases["positive"]["outcomes"][0]["reason"])
        self.assertIn("unexpected descendant", cases["public"]["outcomes"][0]["reason"])

    def test_fully_referenced_extra_dispatch_and_evidence_tool_operation_fail(self):
        fixture = self.fixture
        prefix = self.row["attempt_id"]

        def append_signed(case_index, case, number, role, args):
            info = case_index["cases"][case]
            children = fixture.instrument_children[(prefix, f"item-{number}")]
            source = next(proc for proc in children if proc["role"] == role)
            extra = {**source, "process_id": 999000 + number, "argv": args(source["argv"])}
            raw = fixture.write(f"{prefix}/retained/artifacts/extra-{number}.stdout", {"advice": []})
            extra.update(stdout_bytes=len(fixture.evidence.read(raw)), stdout_sha256=raw["sha256"])
            children.append(extra)
            fixture.change(info, [0], lambda receipt: receipt["child_originals"].append(
                {"process_id": extra["process_id"], "file": raw}))

        def edit(index):
            append_signed(index, "positive", 3, rubric.TEAPOT_VERIFIER_ROLE,
                          lambda words: [*words[:4], "requests", "send", "--url", ORIGIN + "/extra"])
            append_signed(index, "public", 4, "investigation",
                          lambda words: [words[0], "--format", "json", "--actor", rubric.INVESTIGATION_ACTOR, "--workspace",
                                         "/qualified/investigation-ws", "capture", "begin", "--input", "-"])

        fixture.change(self.row, ["referee", "case_index"], edit)
        fixture.sync_capture(self.row, native=True)
        cases = self.result("failed")["cells"][self.cell]["score"]["cases"]
        self.assertIn("unexplained Teapot child", cases["positive"]["outcomes"][0]["reason"])
        self.assertIn("inside or after the coherent finding snapshot", cases["public"]["outcomes"][0]["reason"])

    def test_request_reference_executable_cannot_claim_historical_schema_lane(self):
        with self.assertRaisesRegex(ValueError, "schema lane differs from the authenticated Teapot"):
            rubric.check_native_teapot_operations(
                [], {}, {**PINS, "teapot_sha256": rubric.REQUEST_REFERENCE_TEAPOT[1]}, DEFINED, {}, {}, {}, {}, (), "", 1)

    def test_historical_verifier_requires_distinct_signed_role(self):
        fixture = self.fixture
        children = fixture.instrument_children[(self.row["attempt_id"], "item-3")]
        child = next(proc for proc in children if proc["role"] == rubric.TEAPOT_VERIFIER_ROLE)
        for role in ("teapot", rubric.TEAPOT_PREPARATION_ROLE):
            with self.subTest(role=role):
                child["role"] = role
                fixture.sync_capture(self.row, native=True)
                score = self.result("invalid")["cells"][self.cell]
                self.assertIn("wrong preparation or verifier role", score["reason"])

    def test_direct_preparation_exec_cannot_supply_verification_evidence(self):
        fixture = self.fixture
        children = fixture.instrument_children[(self.row["attempt_id"], "item-3")]
        child = next(proc for proc in children if proc["role"] == rubric.TEAPOT_VERIFIER_ROLE)
        child.update(exec_path=child["argv"][0], role=rubric.TEAPOT_PREPARATION_ROLE)
        fixture.sync_capture(self.row, native=True)
        result = self.result("failed")["cells"][self.cell]["score"]["cases"]["positive"]
        self.assertIn("misclassified or failed direct Scourge verify child", result["outcomes"][0]["reason"])

    def test_historical_verifier_requires_its_own_prepared_logical_executable(self):
        fixture = self.fixture
        children = fixture.instrument_children[(self.row["attempt_id"], "item-3")]
        child = next(proc for proc in children if proc["role"] == rubric.TEAPOT_VERIFIER_ROLE)
        child["argv"][0] = fixture.frozen["cells"]["managed/supplied"]["teapot_exec_path"]
        fixture.sync_capture(self.row, native=True)
        result = self.result("failed")["cells"][self.cell]["score"]["cases"]["positive"]
        self.assertIn("invalid authenticated Teapot child executable", result["outcomes"][0]["reason"])

    def test_direct_historical_preparation_requires_the_preparation_role(self):
        fixture = self.fixture
        children = fixture.instrument_children[(self.row["attempt_id"], "item-3")]
        child = next(proc for proc in children if proc["role"] == rubric.TEAPOT_VERIFIER_ROLE)
        for role in ("teapot", rubric.TEAPOT_VERIFIER_ROLE):
            with self.subTest(role=role):
                child.update(exec_path=child["argv"][0], role=role)
                fixture.sync_capture(self.row, native=True)
                score = self.result("invalid")["cells"][self.cell]
                self.assertIn("wrong preparation or verifier role", score["reason"])

    def test_native_accounting_accepts_unavailable_after_counter_values(self):
        def unavailable(data):
            counters = data["pass"]["ceilings"][0]
            counters.update(spent=None, left=None)
            counters.pop("unused")

        self.change_instrument_artifact("positive", 3, "pass-after", unavailable)
        self.change_case("positive", "record", lambda record: record["accounting"].update(
            counters_after={"spent": None, "left": None, "unused": None}))
        self.rebind_case("positive", 3)
        result = self.result("passed")["cells"][self.cell]["score"]["cases"]["positive"]
        self.assertEqual(result["status"], "passed")

    def edit_signed_case_children(self, case, number, edit):
        fixture = self.fixture
        children = fixture.instrument_children[(self.row["attempt_id"], f"item-{number}")]

        def change_case(index):
            fixture.change(index["cases"][case], [0], lambda receipt: edit(children, receipt))

        fixture.change(self.row, ["referee", "case_index"], change_case)
        fixture.sync_capture(self.row, native=True)

    def test_missing_native_investigation_run_binding_fails(self):
        fixture = self.fixture

        def edit(children, receipt):
            removed = {proc["process_id"] for proc in children if proc["role"] == "investigation"
                       and proc["argv"][-4:] == ["show", case_evidence_ids(
                           receipt["record"]["path"].rsplit("/", 1)[0])["run"], "--depth", "full"]}
            self.assertEqual(len(removed), 2)
            children[:] = [proc for proc in children if proc["process_id"] not in removed]
            receipt["child_originals"] = [row for row in receipt["child_originals"] if row["process_id"] not in removed]
            begin = next(proc for proc in children if proc["argv"][-4:] == ["capture", "begin", "--input", "-"])
            row = next(row for row in receipt["child_originals"] if row["process_id"] == begin["process_id"])
            ref = {"file": row["file"]}
            fixture.change(ref, ["file"], lambda reply: reply.pop("external_run_id", None))
            fixture.update_child_source(row, ref["file"], begin)

        self.edit_signed_case_children("positive", 3, edit)
        result = self.result("failed")["cells"][self.cell]["score"]["cases"]["positive"]
        self.assertIn("missing authenticated Investigation run read", result["outcomes"][0]["reason"])

    def test_investigation_capture_must_match_global_host_order(self):
        def edit(children, receipt):
            children.sort(key=lambda proc: proc["role"] != rubric.TEAPOT_VERIFIER_ROLE)
            ordered = {proc["process_id"]: order for order, proc in enumerate(children)}
            receipt["child_originals"].sort(key=lambda row: ordered[row["process_id"]])

        self.edit_signed_case_children("positive", 3, edit)
        result = self.result("failed")["cells"][self.cell]["score"]["cases"]["positive"]
        self.assertIn("manifest read did not establish preflight authority", result["outcomes"][0]["reason"])

    def test_native_investigation_must_read_exact_claim_lineage_bytes(self):
        fixture = self.fixture

        def find_flow_read(children, receipt):
            record = fixture.evidence.json(receipt["record"])
            ident = next(row["original"]["artifact_id"] for row in record["rounds"][0]["flows"]
                         if row["step"] == "F0.request")
            return next(proc for proc in children if proc["argv"][-4:] == ["read", ident, "--selector-file", "-"])

        def drop(children, receipt):
            proc = find_flow_read(children, receipt)
            children.remove(proc)
            receipt["child_originals"] = [row for row in receipt["child_originals"]
                                          if row["process_id"] != proc["process_id"]]

        def forge(children, receipt):
            proc = find_flow_read(children, receipt)
            row = next(row for row in receipt["child_originals"] if row["process_id"] == proc["process_id"])
            ref = {"file": row["file"]}
            fixture.change(ref, ["file"], lambda reply: reply["excerpt"].update(bytes_base64=b64encode(b"other").decode()))
            fixture.update_child_source(row, ref["file"], proc)

        self.edit_signed_case_children("positive", 3, drop)
        self.edit_signed_case_children("public", 4, forge)
        results = self.result("failed")["cells"][self.cell]["score"]["cases"]
        self.assertIn("missing the next exact artifact byte selector", results["positive"]["outcomes"][0]["reason"])
        self.assertIn("read bytes differ from the retained artifact", results["public"]["outcomes"][0]["reason"])

    def mutate_investigation_output(self, case, call, predicate, mutate):
        fixture = self.fixture

        def edit(children, receipt):
            proc = next(proc for proc in children if proc["role"] == "investigation" and predicate(proc["argv"][7:]))
            row = next(row for row in receipt["child_originals"] if row["process_id"] == proc["process_id"])
            ref = {"file": row["file"]}
            fixture.change(ref, ["file"], mutate)
            fixture.update_child_source(row, ref["file"], proc)

        self.edit_signed_case_children(case, call, edit)

    def test_native_lineage_accepts_digestless_source_transform_and_manifest_checkpoint(self):
        fixture = self.fixture

        def check_checkpoints(children, receipt):
            ids = case_evidence_ids(receipt["record"]["path"].rsplit("/", 1)[0])
            indices = [index for index, proc in enumerate(children) if proc["argv"][7:] == [
                "--case", ids["case"], "show", ids["manifest"], "--depth", "full"]]
            # At this point the manifest has already been fully traversed in
            # both native evidence opens. The final checkpoint only checks its head.
            index = indices[-3]
            root = fixture.evidence.json(receipt["child_originals"][index]["file"])
            source = fixture.evidence.json(receipt["child_originals"][index + 1]["file"])
            self.assertTrue(source["id"].startswith("src_"))
            self.assertNotIn("digest", source["record"]["body"])
            self.assertEqual(root["record"]["body"]["source"]["id"], source["id"])
            self.assertEqual(indices[-2:], [len(children) - 2, len(children) - 1])

        self.edit_signed_case_children("positive", 3, check_checkpoints)
        self.result("passed")

    def test_native_lineage_rejects_stale_withdrawn_and_mismatched_input(self):
        def source(op):
            return len(op) == 6 and op[2] == "show" and op[3].startswith("src_")

        self.mutate_investigation_output("positive", 3, source, lambda reply: reply["snapshot"].update(sequence=2))
        self.mutate_investigation_output("public", 4, source, lambda reply: reply.update(historical=True))
        self.mutate_investigation_output("login", 5, source,
                                         lambda reply: reply["evidentiary_use"].update(state="withdrawn", withdrawals=[{}]))
        ids = case_evidence_ids(f'{self.row["attempt_id"]}/retained/artifacts/same_subject')
        self.mutate_investigation_output("same_subject", 6,
                                         lambda op: op[-4:] == ["show", ids["experiment"], "--depth", "full"],
                                         lambda reply: reply["record"]["body"]["transforms"][0].update(
                                             input_digest="sha256:" + "7" * 64))
        results = self.result("failed")["cells"][self.cell]["score"]["cases"]
        for case, reason in (("positive", "lineage crosses snapshots"), ("public", "lineage record is historical"),
                             ("login", "lineage record is historical, withdrawn"),
                             ("same_subject", "exact native derivation inputs")):
            self.assertIn(reason, results[case]["outcomes"][0]["reason"])

    def mutate_case_derivation(self, case, call, target, mutate):
        location = f'{self.row["attempt_id"]}/retained/artifacts/{case}'
        ident = case_evidence_ids(location)[target]
        self.mutate_investigation_output(case, call, lambda op: op[-4:] == ["show", ident, "--depth", "full"],
                                         lambda reply: mutate(reply["record"]["body"]["transforms"]))

    def test_experiment_requires_exact_manifest_derivation_at_every_observation(self):
        self.mutate_case_derivation("positive", 3, "experiment", list.clear)
        self.mutate_case_derivation("public", 4, "experiment", lambda edges: edges[0]["input"].update(
            id=evidence_id("art", "unrelated-manifest")))
        self.mutate_case_derivation("login", 5, "experiment", lambda edges: edges.append(copy.deepcopy(edges[0])))
        self.mutate_case_derivation("same_subject", 6, "experiment", lambda edges: edges[0].update(version="wrong"))
        cases = self.result("failed")["cells"][self.cell]["score"]["cases"]
        for case in PROPERTIES.keys() - {"f37"}:
            self.assertIn("exact native derivation inputs", cases[case]["outcomes"][0]["reason"])

    def test_publication_requires_exact_ordered_record_and_experiment_inputs(self):
        self.mutate_case_derivation("positive", 3, "publication", list.clear)
        self.mutate_case_derivation("public", 4, "publication", lambda edges: edges[0]["input"].update(revision=2))
        self.mutate_case_derivation("login", 5, "publication", lambda edges: edges.append(copy.deepcopy(edges[0])))
        self.mutate_case_derivation("same_subject", 6, "publication", list.reverse)
        cases = self.result("failed")["cells"][self.cell]["score"]["cases"]
        for case in PROPERTIES.keys() - {"f37"}:
            self.assertIn("exact native derivation inputs", cases[case]["outcomes"][0]["reason"])

    def publication_batch(self, children, receipt):
        key = case_publication_key(receipt["record"]["path"].rsplit("/", 1)[0])
        lookup = next(index for index, proc in enumerate(children) if proc["argv"][-2:] == ["receipt", key])
        ingest = next(index for index in range(lookup + 1, len(children))
                      if children[index]["argv"][7:9] == ["ingest", "--input"])
        return lookup, ingest

    def test_publication_rejects_mixed_snapshots_even_with_complete_individual_lineage(self):
        fixture = self.fixture

        def edit(children, receipt):
            lookup, ingest = self.publication_batch(children, receipt)
            record = fixture.evidence.json(receipt["record"])
            ident = next(flow["original"]["artifact_id"] for flow in record["rounds"][0]["flows"]
                         if flow["step"] == "F0.request")
            start = next(index for index in range(lookup + 1, ingest)
                         if children[index]["argv"][-4:] == ["show", ident, "--depth", "full"])
            self.assertTrue(children[start + 1]["argv"][-3].startswith("src_"))
            for proc in children[start:start + 2]:
                row = next(row for row in receipt["child_originals"] if row["process_id"] == proc["process_id"])
                reply = fixture.evidence.json(row["file"])
                reply["snapshot"].update(sequence=reply["snapshot"]["sequence"] + 1, head_hash="sha256:" + "a" * 64)
                fixture.update_child_source(row, fixture.write(row["file"]["path"], reply), proc)

        self.edit_signed_case_children("positive", 3, edit)
        cases = self.result("failed")["cells"][self.cell]["score"]["cases"]
        self.assertIn("different fresh snapshots", cases["positive"]["outcomes"][0]["reason"])

    def test_publication_requires_fresh_complete_input_walks_in_order_without_interposition(self):
        def rewrite(mode):
            def edit(children, receipt):
                lookup, ingest = self.publication_batch(children, receipt)
                first = lookup + 1
                self.assertTrue(children[first + 1]["argv"][-3].startswith("src_"))
                if mode == "stale":
                    children[lookup:first + 2] = [*children[first:first + 2], children[lookup]]
                elif mode == "missing_source":
                    omitted = children.pop(first + 1)["process_id"]
                    receipt["child_originals"] = [row for row in receipt["child_originals"]
                                                  if row["process_id"] != omitted]
                elif mode == "extra_operation":
                    original = children[first]
                    proc = {**original, "process_id": 999813}
                    row = next(row for row in receipt["child_originals"] if row["process_id"] == original["process_id"])
                    content = self.fixture.evidence.read(row["file"])
                    path = f'{self.row["attempt_id"]}/retained/artifacts/extra-publication-show.stdout'
                    ref = self.fixture.write(path, content)
                    children.insert(ingest, proc)
                    receipt["child_originals"].append({"process_id": proc["process_id"], "file": ref})
                else:
                    self.assertTrue(children[first + 3]["argv"][-3].startswith("src_"))
                    children[first:first + 4] = [*children[first + 2:first + 4], *children[first:first + 2]]
                order = {proc["process_id"]: index for index, proc in enumerate(children)}
                receipt["child_originals"].sort(key=lambda row: order[row["process_id"]])
            return edit

        mutations = {"positive": (3, "stale", "post-capture preparation and reevaluation does not immediately precede"),
                     "public": (4, "missing_source", "next authenticated Source or Artifact read"),
                     "login": (5, "extra_operation", "must immediately precede the native ingest"),
                     "same_subject": (6, "reordered", "next fresh ordered input show")}
        for case, (call, mode, _) in mutations.items():
            self.edit_signed_case_children(case, call, rewrite(mode))
        cases = self.result("failed")["cells"][self.cell]["score"]["cases"]
        for case, (_, _, reason) in mutations.items():
            self.assertIn(reason, cases[case]["outcomes"][0]["reason"])

    def test_experiment_ancestor_must_be_observed_at_the_same_snapshot(self):
        fixture = self.fixture

        def edit(children, receipt):
            ids = case_evidence_ids(receipt["record"]["path"].rsplit("/", 1)[0])
            experiment = next(i for i, proc in enumerate(children) if proc["role"] == "investigation"
                              and proc["argv"][-4:] == ["show", ids["experiment"], "--depth", "full"])
            proc = children[experiment + 2]
            self.assertEqual(proc["argv"][-4:], ["show", ids["manifest"], "--depth", "full"])
            row = next(row for row in receipt["child_originals"] if row["process_id"] == proc["process_id"])
            reply = fixture.evidence.json(row["file"])
            reply["snapshot"]["sequence"] += 1
            fixture.update_child_source(row, fixture.write(row["file"]["path"], reply), proc)

        self.edit_signed_case_children("positive", 3, edit)
        cases = self.result("failed")["cells"][self.cell]["score"]["cases"]
        self.assertIn("lineage crosses snapshots", cases["positive"]["outcomes"][0]["reason"])

    def experiment_batch(self, children, receipt):
        ingest = next(index for index, proc in enumerate(children)
                      if proc["role"] == "investigation" and proc["argv"][7:9] == ["ingest", "--input"])
        ids = case_evidence_ids(receipt["record"]["path"].rsplit("/", 1)[0])
        self.assertEqual(children[ingest - 2]["argv"][-4:], ["show", ids["manifest"], "--depth", "full"])
        self.assertTrue(children[ingest - 1]["argv"][-3].startswith("src_"))
        return ingest - 2, ingest

    def test_experiment_requires_the_fresh_ordered_walk_adjacent_to_ingest(self):
        fixture = self.fixture

        def rewrite(mode):
            def edit(children, receipt):
                start, ingest = self.experiment_batch(children, receipt)
                root, source = children[start:ingest]
                if mode == "missing":
                    del children[start:ingest]
                    omitted = {root["process_id"], source["process_id"]}
                    receipt["child_originals"] = [row for row in receipt["child_originals"]
                                                  if row["process_id"] not in omitted]
                elif mode == "stale":
                    previous = children[start - 1]
                    self.assertEqual(previous["role"], rubric.TEAPOT_VERIFIER_ROLE)
                    children[start - 1:ingest] = [root, source, previous]
                elif mode == "reordered":
                    children[start:ingest] = [source, root]
                else:
                    proc = {**root, "process_id": 999814}
                    row = next(row for row in receipt["child_originals"] if row["process_id"] == root["process_id"])
                    path = f'{self.row["attempt_id"]}/retained/artifacts/interposed-experiment-show.stdout'
                    ref = fixture.write(path, fixture.evidence.read(row["file"]))
                    children.insert(ingest, proc)
                    receipt["child_originals"].append({"process_id": proc["process_id"], "file": ref})
                order = {proc["process_id"]: index for index, proc in enumerate(children)}
                receipt["child_originals"].sort(key=lambda row: order[row["process_id"]])
            return edit

        mutations = {"positive": (3, "missing", "next fresh ordered input show"),
                     "public": (4, "stale", "unexplained Investigation child operation"),
                     "login": (5, "reordered", "next fresh ordered input show"),
                     "same_subject": (6, "interposed", "must immediately precede the native ingest")}
        for case, (call, mode, _) in mutations.items():
            self.edit_signed_case_children(case, call, rewrite(mode))
        cases = self.result("failed")["cells"][self.cell]["score"]["cases"]
        for case, (_, _, reason) in mutations.items():
            self.assertIn(reason, cases[case]["outcomes"][0]["reason"])

    def edit_fresh_experiment_output(self, case, call, offset, mutate):
        fixture = self.fixture

        def edit(children, receipt):
            start, _ = self.experiment_batch(children, receipt)
            proc = children[start + offset]
            row = next(row for row in receipt["child_originals"] if row["process_id"] == proc["process_id"])
            reply = fixture.evidence.json(row["file"])
            mutate(reply)
            fixture.update_child_source(row, fixture.write(row["file"]["path"], reply), proc)

        self.edit_signed_case_children(case, call, edit)

    def test_experiment_fresh_walk_checks_current_snapshot_digest_and_revision(self):
        self.edit_fresh_experiment_output("positive", 3, 0, lambda reply: reply["evidentiary_use"].update(
            state="withdrawn", withdrawals=[{}]))
        self.edit_fresh_experiment_output("public", 4, 0, lambda reply: reply["record"]["body"].update(
            digest="sha256:" + "7" * 64))
        self.edit_fresh_experiment_output("login", 5, 1, lambda reply: reply["snapshot"].update(
            sequence=reply["snapshot"]["sequence"] + 1, head_hash="sha256:" + "7" * 64))
        self.edit_fresh_experiment_output("same_subject", 6, 0, lambda reply: reply["record"]["header"].update(
            revision=2))
        cases = self.result("failed")["cells"][self.cell]["score"]["cases"]
        for case, reason in (("positive", "historical, withdrawn"), ("public", "input differs from the retained original"),
                             ("login", "lineage crosses snapshots"), ("same_subject", "prepared manifest")):
            self.assertIn(reason, cases[case]["outcomes"][0]["reason"])

    def test_experiment_fresh_snapshot_may_follow_the_separate_admission_read(self):
        def later(reply):
            reply["snapshot"].update(sequence=reply["snapshot"]["sequence"] + 1, head_hash="sha256:" + "7" * 64)

        self.edit_fresh_experiment_output("positive", 3, 0, later)
        self.edit_fresh_experiment_output("positive", 3, 1, later)
        self.result("passed")

    def test_execution_boundary_requires_fresh_experiment_describe_before_capture(self):
        fixture = self.fixture

        def mutation(mode):
            def edit(children, receipt):
                ids = case_evidence_ids(receipt["record"]["path"].rsplit("/", 1)[0])
                capture = next(i for i, p in enumerate(children) if p["argv"][-4:] ==
                               ["capture", "begin", "--input", "-"])
                root_args = ["show", ids["experiment"], "--depth", "full"]
                start = max(i for i in range(capture) if children[i]["argv"][-4:] == root_args)
                if mode == "missing":
                    removed = {proc["process_id"] for proc in children[start:capture]}
                    del children[start:capture]
                    receipt["child_originals"] = [row for row in receipt["child_originals"]
                                                  if row["process_id"] not in removed]
                elif mode == "stale":
                    children[start - 1:capture] = [*children[start:capture], children[start - 1]]
                else:
                    proc = children[start + (mode == "mixed")]
                    row = next(row for row in receipt["child_originals"] if row["process_id"] == proc["process_id"])
                    reply = fixture.evidence.json(row["file"])
                    if mode == "mixed":
                        reply["snapshot"]["sequence"] += 1
                    else:
                        reply["record"]["header"]["revision"] += 1
                    fixture.update_child_source(row, fixture.write(row["file"]["path"], reply), proc)
                order = {proc["process_id"]: i for i, proc in enumerate(children)}
                receipt["child_originals"].sort(key=lambda row: order[row["process_id"]])
            return edit

        mutations = {"positive": (3, "missing", "execution-boundary describe is missing"),
                     "public": (4, "stale", "missing the next exact artifact byte selector"),
                     "login": (5, "mixed", "lineage crosses snapshots"),
                     "same_subject": (6, "changed", "Experiment revision changed")}
        for case, (call, mode, _) in mutations.items():
            self.edit_signed_case_children(case, call, mutation(mode))
        cases = self.result("failed")["cells"][self.cell]["score"]["cases"]
        for case, (_, _, reason) in mutations.items():
            self.assertIn(reason, cases[case]["outcomes"][0]["reason"])

    def test_publication_preparation_and_commit_require_independent_reevaluation_reads(self):
        fixture = self.fixture

        def mutate(mode):
            def edit(children, receipt):
                lookup, _ = self.publication_batch(children, receipt)
                record = fixture.evidence.json(receipt["record"])
                ids = case_evidence_ids(receipt["record"]["path"].rsplit("/", 1)[0])
                flow = next(row["original"]["artifact_id"] for row in record["rounds"][0]["flows"]
                            if row["step"] == "F0.request")
                selector = lambda ident: ["read", ident, "--selector-file", "-"]
                if mode == "post_commit":
                    after_receipt = next(i for i, proc in enumerate(children[lookup + 1:], lookup + 1)
                                         if proc["argv"][-2:] == children[lookup]["argv"][-2:])
                    selector_pos = next(i for i in range(after_receipt + 1, len(children))
                                        if children[i]["argv"][-4:] == selector(flow))
                else:
                    selector_pos = max(i for i in range(lookup) if children[i]["argv"][-4:] ==
                                       selector(ids["experiment"] if mode == "experiment" else flow))
                proc = children[selector_pos]
                link = next(row for row in receipt["child_originals"] if row["process_id"] == proc["process_id"])
                if mode == "reuse":
                    reply = fixture.evidence.json(link["file"])
                    reply["snapshot"]["sequence"] += 1
                    fixture.update_child_source(link, fixture.write(link["file"]["path"], reply), proc)
                else:
                    children.pop(selector_pos)
                    receipt["child_originals"].remove(link)
            return edit

        for case, call, mode in (("positive", 3, "flow"), ("public", 4, "experiment"),
                                 ("login", 5, "post_commit"), ("same_subject", 6, "reuse")):
            self.edit_signed_case_children(case, call, mutate(mode))
        cases = self.result("failed")["cells"][self.cell]["score"]["cases"]
        for case in ("positive", "public", "login"):
            self.assertIn("missing the next exact artifact byte selector", cases[case]["outcomes"][0]["reason"])
        self.assertIn("selector is outside", cases["same_subject"]["outcomes"][0]["reason"])

    def test_coherent_badge_requires_current_record_and_fresh_inputs_at_the_named_snapshot(self):
        fixture = self.fixture

        def mutate(mode):
            def edit(children, receipt):
                record = fixture.evidence.json(receipt["record"])
                ids = case_evidence_ids(receipt["record"]["path"].rsplit("/", 1)[0])
                flow = next(row["original"]["artifact_id"] for row in record["rounds"][0]["flows"]
                            if row["step"] == "F0.request")
                target = ids["publication"] if mode == "record" else flow
                end = max(i for i, proc in enumerate(children) if proc["argv"][-4:] ==
                          ["read", target, "--selector-file", "-"])
                start = max(i for i in range(end) if children[i]["argv"][-4:] == ["show", target, "--depth", "full"])
                if mode in {"record", "input"}:
                    removed = {proc["process_id"] for proc in children[start:end + 1]}
                    del children[start:end + 1]
                    receipt["child_originals"] = [row for row in receipt["child_originals"]
                                                  if row["process_id"] not in removed]
                    return
                procs = children[start:end + 1] if mode == "mixed" else [children[end]]
                for proc in procs:
                    row = next(row for row in receipt["child_originals"] if row["process_id"] == proc["process_id"])
                    reply = fixture.evidence.json(row["file"])
                    reply["snapshot"]["sequence"] += 1
                    fixture.update_child_source(row, fixture.write(row["file"]["path"], reply), proc)
            return edit

        for case, call, mode in (("positive", 3, "record"), ("public", 4, "input"),
                                 ("login", 5, "mixed"), ("same_subject", 6, "selector")):
            self.edit_signed_case_children(case, call, mutate(mode))
        cases = self.result("failed")["cells"][self.cell]["score"]["cases"]
        self.assertIn("coherent finding is missing", cases["positive"]["outcomes"][0]["reason"])
        self.assertIn("coherent finding is missing", cases["public"]["outcomes"][0]["reason"])
        self.assertIn("coherent finding reads use different snapshots", cases["login"]["outcomes"][0]["reason"])
        self.assertIn("selector is outside", cases["same_subject"]["outcomes"][0]["reason"])

    def test_coherent_history_requires_canonical_verification_v1_records(self):
        root = Path(self.tmp.name) / "malformed-history"
        root.mkdir(mode=0o700)
        fixture = Fixture(root, historical_cases={
            "positive": "sparse", "public": "wrong_type", "login": "noncanonical", "same_subject": "other_lead",
        })
        cell = fixture.grade()["cells"][self.cell]
        self.assertEqual(cell["status"], "failed")
        cases = cell["score"]["cases"]
        for name in ("positive", "public", "login"):
            self.assertIn("not canonical native VerificationV1", cases[name]["outcomes"][0]["reason"])
        self.assertEqual(cases["same_subject"]["status"], "passed")

    def test_coherent_history_binds_each_prior_derivation_to_its_ordered_inputs(self):
        root = Path(self.tmp.name) / "wrong-history"
        root.mkdir(mode=0o700)
        fixture = Fixture(root, historical_cases={
            "positive": "wrong_transform", "public": "reordered", "login": "missing_experiment",
            "same_subject": "substituted",
        })
        cell = fixture.grade()["cells"][self.cell]
        self.assertEqual(cell["status"], "failed")
        cases = cell["score"]["cases"]
        for name, reason in (("positive", "unsupported derivation"), ("public", "exact ordered record inputs"),
                             ("login", "one Experiment"), ("same_subject", "exact ordered record inputs")):
            self.assertIn(reason, cases[name]["outcomes"][0]["reason"])

    def test_coherent_history_accepts_same_and_other_lead_reads_in_native_order(self):
        root = Path(self.tmp.name) / "valid-history"
        root.mkdir(mode=0o700)
        fixture = Fixture(root, historical_cases={
            "positive": "same_lead", "public": "other_lead",
        })
        result = fixture.grade()
        self.assertEqual(result["aggregate"]["status"], "passed", result["cells"][self.cell])

    def test_native_ingests_must_use_the_exact_authenticated_command_id(self):
        def ingest(op):
            return op[:2] == ["ingest", "--input"]

        self.mutate_investigation_output("positive", 3, ingest, lambda reply: reply.pop("command_id"))
        other_location = f'{self.row["attempt_id"]}/retained/artifacts/positive'
        other_key = rubric.investigation_command_key("record", case_request_key(other_location))
        self.mutate_investigation_output("public", 4, ingest, lambda reply: reply.update(command_id=other_key))

        def unbound_publication(children, receipt):
            fixture = self.fixture
            proc = [proc for proc in children if proc["role"] == "investigation" and ingest(proc["argv"][7:])][-1]
            row = next(row for row in receipt["child_originals"] if row["process_id"] == proc["process_id"])
            reply = fixture.evidence.json(row["file"])
            reply["command_id"] = rubric.investigation_command_key("verification-publication", "P-wrong")
            fixture.update_child_source(row, fixture.write(row["file"]["path"], reply), proc)

        self.edit_signed_case_children("login", 5, unbound_publication)
        self.mutate_investigation_output("same_subject", 6,
                                         lambda op: op[:1] == ["receipt"] and "/verification-publication/" in op[1],
                                         lambda reply: reply.update(result="committed"))
        cases = self.result("failed")["cells"][self.cell]["score"]["cases"]
        reasons = {case: cases[case]["outcomes"][0]["reason"] for case in rubric.CASES}
        for case in ("positive", "public"):
            self.assertIn("native request command ID", reasons[case])
        self.assertIn("native receipt command ID", reasons["login"])
        self.assertIn("native pre-ingest receipt lookup", reasons["same_subject"])

    def test_publication_receipt_must_bind_the_ingested_artifact(self):
        fixture = self.fixture

        def edit(children, receipt):
            proc = [proc for proc in children if proc["role"] == "investigation" and proc["argv"][7:8] == ["receipt"]
                    and "/verification-publication/" in proc["argv"][8]][-1]
            row = next(row for row in receipt["child_originals"] if row["process_id"] == proc["process_id"])
            reply = fixture.evidence.json(row["file"])
            reply["artifacts"][0]["size_bytes"] += 1
            fixture.update_child_source(row, fixture.write(row["file"]["path"], reply), proc)

        self.edit_signed_case_children("positive", 3, edit)
        cases = self.result("failed")["cells"][self.cell]["score"]["cases"]
        self.assertIn("receipt does not bind the retained artifact bytes", cases["positive"]["outcomes"][0]["reason"])

    def test_publication_command_id_cannot_be_reused_for_another_record(self):
        fixture = self.fixture
        reused = case_publication_key(f'{self.row["attempt_id"]}/retained/artifacts/positive')

        def edit(children, receipt):
            location = receipt["record"]["path"].rsplit("/", 1)[0]
            old = case_publication_key(location)
            links = {row["process_id"]: row for row in receipt["child_originals"]}
            for proc in children:
                if proc["argv"][-2:] == ["receipt", old]:
                    proc["argv"][-1] = reused
                elif proc["argv"][7:9] != ["ingest", "--input"]:
                    continue
                row = links[proc["process_id"]]
                reply = fixture.evidence.json(row["file"])
                if reply.get("command_id") == old:
                    reply["command_id"] = reused
                    fixture.update_child_source(row, fixture.write(row["file"]["path"], reply), proc)

        self.edit_signed_case_children("public", 4, edit)
        conflicts = self.result("failed")["cells"][self.cell]["score"]["identity_conflicts"]
        self.assertTrue(any("publication_command_id" in reason for reason in conflicts), conflicts)

    def test_unrelated_digestless_source_cannot_replace_the_required_lineage_read(self):
        fixture = self.fixture

        def edit(children, receipt):
            proc = next(proc for proc in children if proc["role"] == "investigation"
                        and proc["argv"][-4:-3] == ["show"] and proc["argv"][-3].startswith("src_"))
            row = next(row for row in receipt["child_originals"] if row["process_id"] == proc["process_id"])
            output = fixture.evidence.json(row["file"])
            other = evidence_id("src", "unrelated")
            proc["argv"][-3] = other
            output["id"] = output["record"]["header"]["id"] = other
            fixture.update_child_source(row, fixture.write(row["file"]["path"], output), proc)

        self.edit_signed_case_children("positive", 3, edit)
        result = self.result("failed")["cells"][self.cell]["score"]["cases"]["positive"]
        self.assertIn("missing its next authenticated Source or Artifact read", result["outcomes"][0]["reason"])

    def test_native_capture_requires_qualified_ids_and_commit_keys(self):
        def begin(op):
            return op == ["capture", "begin", "--input", "-"]

        self.mutate_investigation_output("positive", 3, begin, lambda reply: reply.update(handle="handle_fixture"))
        self.mutate_investigation_output("public", 4, begin, lambda reply: reply.pop("commit"))
        self.mutate_investigation_output("login", 5, lambda op: op == ["capture", "finalize", "--input", "-"],
                                         lambda reply: reply["commit"].pop("transaction_id"))
        self.mutate_investigation_output("same_subject", 6, lambda op: op[:3] == ["capture", "recover", "--handle"],
                                         lambda reply: reply["handles"][0]["finalized"]["commit"].update(
                                             transaction_id="foreign-transaction"))
        results = self.result("failed")["cells"][self.cell]["score"]["cases"]
        for case, reason in (("positive", "capture begin identity or commit"), ("public", "capture begin identity or commit"),
                             ("login", "finalization lacks its native manifest or commit"),
                             ("same_subject", "recovery does not identify the finalized capture")):
            self.assertIn(reason, results[case]["outcomes"][0]["reason"])

    def test_native_capture_requires_size_request_time_and_qualified_run_identity(self):
        def attach(op):
            return op == ["capture", "attach", "--input", "-"]

        self.mutate_investigation_output("positive", 3, attach, lambda reply: reply.pop("size_bytes"))
        self.mutate_investigation_output("public", 4, attach, lambda reply: reply["receipt"].pop("request_digest"))
        self.mutate_investigation_output("login", 5, attach, lambda reply: reply["receipt"].pop("accepted_at"))
        self.mutate_investigation_output("same_subject", 6,
                                         lambda op: len(op) == 6 and op[2] == "show" and op[3].startswith("run_"),
                                         lambda reply: reply["record"]["body"]["capture"].pop("metadata"))
        results = self.result("failed")["cells"][self.cell]["score"]["cases"]
        for case in ("positive", "public", "login"):
            self.assertIn("attachment is missing native size, request digest, time", results[case]["outcomes"][0]["reason"])
        self.assertIn("run read is for another capture", results["same_subject"]["outcomes"][0]["reason"])

    def test_native_capture_recovery_and_final_manifest_reconcile_attachment_receipts(self):
        self.mutate_investigation_output("positive", 3, lambda op: op[:3] == ["capture", "recover", "--handle"],
                                         lambda reply: reply["handles"][0].pop("last_position"))
        self.mutate_investigation_output("public", 4, lambda op: op[:3] == ["capture", "recover", "--handle"],
                                         lambda reply: reply["handles"][0].pop("artifacts"))
        self.mutate_investigation_output("login", 5, lambda op: op[:3] == ["capture", "recover", "--handle"],
                                         lambda reply: reply["handles"][0]["artifacts"][0]["receipt"].update(
                                             request_digest="sha256:" + "7" * 64))
        fixture = self.fixture

        def omit_size(children, receipt):
            runs = [proc for proc in children if proc["role"] == "investigation" and len(proc["argv"][7:]) == 6
                    and proc["argv"][9] == "show" and proc["argv"][10].startswith("run_")]
            proc = runs[-1]
            row = next(row for row in receipt["child_originals"] if row["process_id"] == proc["process_id"])
            ref = {"file": row["file"]}
            fixture.change(ref, ["file"], lambda reply: reply["record"]["body"]["capture_finalization"][
                "artifacts"][0]["retention"].pop("size_bytes"))
            fixture.update_child_source(row, ref["file"], proc)

        self.edit_signed_case_children("same_subject", 6, omit_size)
        results = self.result("failed")["cells"][self.cell]["score"]["cases"]
        for case, reason in (("positive", "recovery does not identify the finalized capture"),
                             ("public", "recovery does not identify the finalized capture"),
                             ("login", "recovered attachments differ from the original native receipts"),
                             ("same_subject", "final run read does not seal the exact native source inventory")):
            self.assertIn(reason, results[case]["outcomes"][0]["reason"])

    def test_teapot_native_send_requires_full_schema_and_successful_hop(self):
        fixture = self.fixture

        def edit(children, receipt):
            proc = next(proc for proc in children if proc["argv"][4:6] == ["requests", "send"])
            row = next(row for row in receipt["child_originals"] if row["process_id"] == proc["process_id"])
            ref = {"file": row["file"]}
            def strip_hop(reply):
                hop = reply["sent"]["hops"][0]
                reply["sent"]["hops"] = [{"flow": hop["flow"]}]
            fixture.change(ref, ["file"], strip_hop)
            fixture.update_child_source(row, ref["file"], proc)

        self.edit_signed_case_children("positive", 3, edit)
        result = self.result("failed")["cells"][self.cell]["score"]["cases"]["positive"]
        self.assertIn("unknown native Teapot stdout shape for requests-send", result["outcomes"][0]["reason"])

    def test_cleanup_cannot_disappear_from_registered_round(self):
        def drop_cleanup(record):
            row = record["rounds"][0]
            row["flows"] = [flow for flow in row["flows"] if not flow["step"].startswith("C.")]

        self.change_case("positive", "record", drop_cleanup)
        self.rebind_case("positive", 3)
        result = self.result("failed")["cells"][self.cell]["score"]["cases"]["positive"]
        self.assertIn("lacks established cleanup evidence for both planted objects", result["outcomes"][0]["reason"])

    def test_cleanup_failure_with_authenticated_delete_outcome_can_be_partial(self):
        self.change_flow(self.row, "positive", "C.primary", 3, lambda flow: flow.update(
            status=404, response_head="HTTP/1.1 404 Not Found"))
        self.change_case("positive", "record", lambda record: record.update(cleanup="partial"))
        self.change_case("positive", "run", lambda read: read["run"].update(cleanup="partial"))
        self.rebind_case("positive", 3)
        self.alter_reply(3, lambda reply: reply["run"].update(cleanup="partial"))
        result = self.result("passed")["cells"][self.cell]["score"]["cases"]["positive"]
        self.assertEqual(result["status"], "passed")

    def test_native_scripts_reduce_empty_and_require_matching_generation(self):
        self.assertEqual(rubric.reduce_native_edit_surface("scripts_list", None, []), {"scripts": []})
        scripts = json.loads((rubric.REPOSITORY / "fuzz/corpus/teapot_output/scripts-list.json").read_bytes())["scripts"]
        self.assertEqual(len(rubric.reduce_native_edit_surface("scripts_list", None, scripts)["scripts"]), len(scripts))
        scripts[-1]["generation"] += 1
        with self.assertRaisesRegex(ValueError, "unqualified script"):
            rubric.reduce_native_edit_surface("scripts_list", None, scripts)

    def test_edit_surface_rejects_session_relogin_and_active_intercept_or_script(self):
        fixture = self.fixture
        referee = fixture.evidence.json(self.row["referee"])
        ref = fixture.evidence.json(referee["case_index"])["cases"]["positive"][0]
        receipt = fixture.evidence.json(ref)
        boundary = next(source["file"] for source in receipt["instrument_originals"]
                        if source["file"]["path"].endswith("/edit-surface-start.json"))
        scripts = json.loads((rubric.REPOSITORY / "fuzz/corpus/teapot_output/scripts-list.json").read_bytes())
        active = {**scripts["scripts"][0], "state": "running",
                  "hooks": [{"event": "request", "line": 1, "text": "request (line 1)"}]}
        for operation, result_key, edit, reason in (
            ("intercept_status", "intercept", lambda result: result.update(paused=1),
             "active or inconsistent interception"),
            ("scripts_list", "scripts", lambda result: result.append(active), "editing or unqualified script"),
            ("session_show", "session", lambda result: result.update(login="login-workflow"),
             "unqualified session behavior"),
        ):
            with self.subTest(operation=operation):
                gate = fixture.evidence.json(boundary)["observation"]["admitted"]
                readings = gate["edit_surface"]["readings"]
                row = next(item for item in readings if item["operation"] == operation)
                sources = {(item["operation"], item["session"]): fixture.evidence.json(item["file"])
                           for item in receipt["edit_surface_originals"]["start"]}
                original = sources[(operation, row["session"])][result_key]
                edit(original)
                row.update(result_sha256=rubric.native_digest(original),
                           report=rubric.reduce_native_edit_surface(operation, row["session"], original))
                sessions = [item["session"] for item in readings if item["operation"] == "session_show"]
                with self.assertRaisesRegex(ValueError, reason):
                    rubric.check_native_edit_surface(gate, sessions, "scourge_anonymous", sources)

    def test_accounting_requires_chronological_distinct_samples_and_native_continuity(self):
        self.change_instrument_artifact("positive", 3, "pass-after",
                                        lambda envelope: envelope["pass"]["ceilings"][0].update(spent=6, left=1994))

        def set_after_counter_values(record, spent, left):
            record["accounting"]["counters_after"]["spent"]["value"] = spent
            record["accounting"]["counters_after"]["left"]["value"] = left

        self.change_case("positive", "record", lambda record: set_after_counter_values(record, 6, 1994))
        self.rebind_case("positive", 3)
        self.change_case("public", "record", lambda record: record["accounting"].update(counters_before=None))
        self.rebind_case("public", 4)

        def false_time(record):
            for count in record["accounting"]["counters_after"].values():
                count["window"] = self.fixture.accounting_window("00.800", "00.850")

        self.change_case("login", "record", false_time)
        self.rebind_case("login", 5)
        self.change_instrument_artifact("same_subject", 6, "pass-after",
                                        lambda envelope: envelope["pass"]["ceilings"][0].update(spent=7, left=1993))
        self.change_case("same_subject", "record", lambda record: set_after_counter_values(record, 7, 1993))
        self.rebind_case("same_subject", 6)
        results = self.result("failed")["cells"][self.cell]["score"]["cases"]
        for case, reason in (("positive", "pass counters are discontinuous"), ("public", "lacks before/after counters"),
                             ("login", "samples do not bookend the retained traffic")):
            self.assertIn(reason, results[case]["outcomes"][0]["reason"])
        self.assertEqual(results["same_subject"]["status"], "passed")

    def test_native_accounting_cannot_substitute_the_admitted_pass(self):
        self.change_case("positive", "record", lambda record: record["accounting"].update(
            pass_id="pass.substitute", pass_digest="1" * 64))
        self.rebind_case("positive", 3)
        result = self.result("failed")["cells"][self.cell]["score"]["cases"]["positive"]
        self.assertIn("native accounting pass does not match", result["outcomes"][0]["reason"])

    def test_native_pass_observation_cannot_name_another_protected_file(self):
        fixture = self.fixture

        def instrument_substitution(root):
            case = root["cases"]["public"][0]
            info = fixture.evidence.json(case)
            native_pass = next(item for item in info["instrument_originals"] if item["file"]["path"].endswith("/pass-after.json"))
            fixture.change(native_pass, ["file"], lambda envelope: envelope["pass"].update(
                pass_file="/substitute/pass.toml"))
            fixture.change(info, ["record"], lambda record: next(
                item for item in record["accounting"]["attribution_evidence"]
                if item["artifact_id"] == native_pass["artifact_id"]).update(digest=native_pass["file"]["sha256"]))
            root["cases"]["public"][0] = fixture.write(case["path"], info)

        fixture.change(self.row, ["referee", "case_index"], instrument_substitution)
        self.rebind_case("public", 4)
        result = self.result("failed")["cells"][self.cell]["score"]["cases"]["public"]
        self.assertIn("native instrument pass report differs", result["outcomes"][0]["reason"])

    def test_coherently_reused_native_run_id_cannot_serve_two_cases(self):
        self.change_case("public", "record", lambda record: record.update(run_id="R-1"))
        self.change_case("public", "index", lambda index: index["record"].update(run_id="R-1"))
        self.change_case("public", "run", lambda run: run["run"].update(id="R-1"))
        self.rebind_case("public", 4)
        self.alter_reply(4, lambda reply: reply["run"].update(id="R-1"))
        score = self.result("failed")["cells"][self.cell]["score"]
        self.assertIn("run R-1 identifies multiple native cases or records", score["identity_conflicts"])

    def inject_concept_lifecycle(self, event):
        fixture = self.fixture

        def change_concept(referee):
            entry = referee["concept"]
            events = fixture.evidence.read(entry["raw"]).splitlines(keepends=True)
            events.insert(-1, rubric.canonical(event) + b"\n")
            entry["raw"] = fixture.write(entry["raw"]["path"], b"".join(events))
            fixture.sync_capture(entry)

        fixture.change(self.row, ["referee"], change_concept)
        return self.result("failed")["cells"][self.cell]["score"]["gates"]["concept"]["reason"]

    def test_concept_started_only_tool_overrides_claim_of_zero_tool_calls(self):
        reason = self.inject_concept_lifecycle({
            "type": "item.started", "item": {"id": "hidden", "type": "command_execution",
                                              "command": "scourge --help", "status": "in_progress"},
        })
        self.assertIn("native tool item", reason)

    def test_concept_unpaired_update_is_incomplete(self):
        reason = self.inject_concept_lifecycle({
            "type": "item.updated", "item": {"id": "pending", "type": "reasoning", "text": "pending"},
        })
        self.assertIn("unfinished native item", reason)

    def test_incompatible_engagement_authority_and_unsafe_objective_are_refused(self):
        for source, reason in (
            (DECLARATION_TOML.replace(b'required_custody = "shared"', b'required_custody = "isolated"')
             .replace(b'required_enforcement = "none"', b'required_enforcement = "egress"'), "requirements do not match M1"),
            (DECLARATION_TOML.replace(b"Assess access to the development fixture resources",
                                     b"GET https://example.invalid/private"), "unsafe objective"),
        ):
            with tempfile.TemporaryDirectory() as root, self.assertRaisesRegex(ValueError, reason):
                Fixture(Path(root), declaration_source=source).grade()

    def test_rehashed_coached_discovery_is_still_rejected(self):
        prompts = {"discovery": b"Use scourge verify L-1. The flaw is private_reports; owner alice, other bob."}
        with tempfile.TemporaryDirectory() as root, self.assertRaisesRegex(ValueError, "checked-in prompt"):
            Fixture(Path(root), prompts=prompts).grade()

    def test_discovery_review_must_cover_actual_visible_bytes(self):
        fixture = self.fixture
        slot = fixture.frozen["cells"]["executable/discovery"]
        wrong = fixture.write("frozen/substitute.txt", b"Different workspace bytes")
        fixture.change(slot, ["discovery_review"], lambda review: review["visible_inputs"].update({
            "engagement.toml": wrong,
        }))
        with self.assertRaisesRegex(ValueError, "exact visible workspace bytes"):
            fixture.grade()

    def test_exec_path_catches_spoofed_argv_zero(self):
        fixture = self.fixture
        events = [json.loads(line)["item"] for line in fixture.evidence.read(self.row["raw"]).splitlines()
                  if json.loads(line)["type"] == "item.completed"]
        child = {"process_id": 2900, "argv": ["scourge", "--help"], "exec_path": "/usr/bin/printf",
                 "binary_sha256": "7" * 64, "exit_code": 0}
        fixture.sync_capture(self.row, native=True, items=events, children={events[1]["id"]: [child]})
        self.assertIn("without the pinned executable", self.result("invalid")["cells"][self.cell]["reason"])

    def test_successful_shell_does_not_mask_failing_scourge_child(self):
        fixture = self.fixture
        events = [json.loads(line)["item"] for line in fixture.evidence.read(self.row["raw"]).splitlines()
                  if json.loads(line)["type"] == "item.completed"]
        item = events[2]
        item["command"] = "/usr/bin/bash -lc 'scourge verify L-1 --format json || true'"
        fixture.change(self.row, ["referee", "events"], lambda observations: observations["calls"][2].update(exit_code=5))
        fixture.sync_capture(self.row, native=True, items=events)
        result = self.result("failed")["cells"][self.cell]["score"]["cases"]["positive"]
        self.assertIn("native Scourge child exit", result["outcomes"][0]["reason"])

    def rebind_case(self, case, number):
        """Make a changed native record internally consistent to reach deeper checks."""
        ref = self.fixture.evidence.json(self.row["referee"])
        cases = self.fixture.evidence.json(ref["case_index"])["cases"]
        sha = self.fixture.evidence.json(cases[case][0])["record"]["sha256"]
        self.change_case(case, "index", lambda data: data["record"].update(record_digest=sha))
        def correlate(index):
            self.fixture.change(index["cases"][case], [0],
                                lambda receipt: self.fixture.correlate_native_children(
                                    receipt, self.row["attempt_id"], number))

        self.fixture.change(self.row, ["referee", "case_index"], correlate)
        self.alter_reply(number, lambda reply: reply["verification"]["artifact"].update(digest=sha))


if __name__ == "__main__":
    unittest.main()
