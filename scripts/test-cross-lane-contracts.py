#!/usr/bin/env python3
"""Validate the frozen M0 contract examples without binaries or network."""
import copy
import hashlib
import json
import re
import unittest
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures/contracts"
EXAMPLES = FIXTURES / "scourge-v1"


def decode_json(data):
    def unique(pairs):
        result = dict(pairs)
        if len(result) != len(pairs):
            raise ValueError("duplicate JSON member")
        return result

    def invalid_constant(token):
        raise ValueError(f"invalid JSON token {token}")

    return json.loads(data.decode("utf-8"), object_pairs_hook=unique, parse_constant=invalid_constant)


def read_json(path):
    return decode_json(path.read_bytes())


WIRE = read_json(ROOT / "docs/contracts/scourge-v1.json")
SHAPES = WIRE["shapes"]
ENUMS = WIRE["enums"]
EXITS = WIRE["error_exits"]
OPTIONAL_FIELDS = {
    shape: set(fields) for shape, fields in WIRE.get("optional_fields", {}).items()
}
PATTERNS = {
    "request_key": r"rk_[A-Za-z0-9_-]+",
    "sha256": r"[0-9a-f]{64}",
    "nonce": r"[0-9a-f]{32}",
    "git_commit": r"[0-9a-f]{40}",
    "kebab_case": r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*",
    "reason_code": r"[A-Z][A-Z0-9_]*",
    "probability": r"(?:0(?:\.[0-9]+)?|1(?:\.0+)?)",
    "timestamp": r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z",
    "absolute_path": r"/[^\x00]*",
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def validate(value, kind, path="$"):
    if kind.endswith("?"):
        if value is not None:
            validate(value, kind[:-1], path)
    elif kind.endswith("[]"):
        require(isinstance(value, list), path)
        for index, item in enumerate(value):
            validate(item, kind[:-2], f"{path}[{index}]")
    elif kind in SHAPES:
        shape = SHAPES[kind]
        optional = OPTIONAL_FIELDS.get(kind, set())
        require(isinstance(value, dict), path)
        required = shape.keys() - optional
        require(required <= value.keys(), f"{path} missing {required - value.keys()}")
        if kind not in WIRE["extensible_shapes"]:
            require(value.keys() <= shape.keys(), f"{path} extra {value.keys() - shape.keys()}")
        for key, child in shape.items():
            if key in value:
                validate(value[key], child, f"{path}.{key}")
    elif kind in ENUMS:
        require(type(value) is str and value in ENUMS[kind], path)
    elif kind == "error_code":
        require(type(value) is str and value in EXITS, path)
    elif kind.startswith("="):
        require(value == kind[1:], path)
    elif kind in PATTERNS:
        require(type(value) is str and re.fullmatch(PATTERNS[kind], value), path)
        if kind == "timestamp":
            datetime.fromisoformat(value)
    elif kind == "string":
        require(type(value) is str and value and "\0" not in value, path)
    elif kind == "boolean":
        require(type(value) is bool, path)
    elif kind == "integer":
        require(type(value) is int, path)
    elif kind == "uint":
        require(type(value) is int and 0 <= value < 2**64, path)
    elif kind == "object":
        require(isinstance(value, dict), path)
    else:
        raise RuntimeError(f"unknown wire type {kind}")


def validate_action(action, response):
    argv = action["argv"]
    require(argv, "empty argv")
    if argv[0] != "scourge":
        require(Path(argv[0]).is_absolute(), "unresolved executable")
        require("--json" in argv[1:], "native format required")
        return
    expected = ["scourge", "--format", "json"]
    if response["workspace"] is not None:
        expected += ["--workspace", response["workspace"]]
    if response["engagement"] is not None:
        expected += ["--engagement", response["engagement"]]
    require(argv[:len(expected)] == expected and len(argv) > len(expected), "incomplete Scourge argv")


def validate_response(response, status):
    validate(response, "scourge.response.v1")
    error = response["error"]
    if response["ok"]:
        require(error is None and response["result"] is not None and status == 0, "successful response")
    else:
        require(error is not None and response["result"] is None, "error response")
        require(status == EXITS[error["code"]], "error exit")
    actions = response["next"]
    if response["transport"] is not None:
        actions = [*actions, response["transport"]["action"]]
    for action in actions:
        validate_action(action, response)


def validate_accounting(accounting):
    validate(accounting, "scourge.accounting.v1")
    require((accounting["pass_id"] is None) == (accounting["pass_digest"] is None), "pass identity")
    if accounting["attribution"] != "unestablished":
        require(accounting["attribution_evidence"], "attribution requires evidence")
    for field, unit in (("observed_sent", "requests"), ("charged", "request_units")):
        count = accounting[field]
        if count is not None:
            require(count["granularity"] == "run" and count["unit"] == unit, f"{field} requires run-scoped {unit}")


def validate_record(record):
    validate(record, "scourge.verification.v1")
    require(record["sequence"] >= 1, "record sequence")
    require((record["sequence"] == 1) == (record["prev_record_digest"] is None), "predecessor")
    require((record["kind"] == "retest") == (record["retest"] is not None), "retest fields")
    retest = record["retest"]
    phases = {"verify"}
    if retest is not None:
        phases = {"retest_candidate"}
        if retest["mode"] == "paired":
            phases.add("paired_baseline")
        require((retest["mode"] == "paired") == (retest["paired_baseline_target"] is not None), "paired baseline identity")
    for observation in [record, *record["rounds"]]:
        require((observation["result"] == "true") == (observation["exposure"] is not None), "exposure")
    for number, round_record in enumerate(record["rounds"], start=1):
        require(round_record["number"] == number, "round order")
        require(round_record["phase"] in phases, "round phase")
        if round_record["result"] == "invalid":
            require(round_record["reason_codes"], "invalid reason")
        for flow in round_record["flows"]:
            if flow["completeness"] == "complete":
                require(flow["original"] is not None and flow["flow_id"] is not None, "original flow")
    if record["target_isolation"] in {"separate_principals", "clean_instance"}:
        require(record["custody"] == "isolated", "custody proof")
    require((record["enforcement"] == "egress_enforced") == record["destination_time_enforced"], "egress enforcement")
    validate_accounting(record["accounting"])


def request_outcome(entries, scope, key, incoming):
    """Model keyed replay after CLI defaults have been applied."""
    entry = entries.get((scope, key))
    if entry is None:
        return ("OBJECT_NOT_FOUND", None)
    stored, run_id, has_step_intent = entry
    validate_request(incoming)
    # JSON comparison distinguishes booleans from integers.
    if json.dumps(stored, sort_keys=True) != json.dumps(incoming, sort_keys=True):
        return ("IDEMPOTENCY_KEY_REUSED", None)
    return ("existing" if has_step_intent else "reopen_same_run", run_id)


def validate_request(request):
    validate(request, "scourge.request-input.v1")
    if request["command"] in {"verify", "retest"}:
        arguments = request["arguments"]
        validate(arguments, request["command"] + "_arguments")
        require(arguments["rounds"] is None or arguments["rounds"] > 0, "positive rounds")


class PublicationModel:
    """Model the required order. Production implements finish atomically."""

    def __init__(self, engagement):
        self.head = {"engagement": engagement, "sequence": 0, "record_digest": None}
        self.intents = {}
        self.candidates = {}
        self.linked = {}

    def declare(self, intent):
        validate(intent, "scourge.publication-intent.v1")
        require(intent["state"] == "pending" and intent["artifact_id"] is None, "pending intent")
        require(intent["expected_head"] == self.head and intent["engagement"] == self.head["engagement"], "head moved")
        require(intent["intent_id"] not in self.intents, "duplicate intent")
        self.intents[intent["intent_id"]] = copy.deepcopy(intent)

    def store(self, intent_id, artifact_id, data):
        require(intent_id in self.intents, "write ahead")
        require(self.intents[intent_id]["state"] == "pending", "intent not pending")
        if intent_id in self.candidates:
            require((artifact_id, data) == self.candidates[intent_id], "changed store retry")
        self.candidates[intent_id] = (artifact_id, data)

    def finish(self, intent_id):
        require(intent_id in self.intents, "missing intent")
        intent = self.intents[intent_id]
        if intent["state"] == "complete":
            return intent["artifact_id"]
        require(intent["state"] == "pending", "intent not pending")
        require(intent_id in self.candidates, "artifact unavailable")
        artifact_id, data = self.candidates[intent_id]
        require(hashlib.sha256(data).hexdigest() == intent["record_digest"], "artifact digest")
        record = decode_json(data)
        validate_record(record)
        require(record["engagement"] == intent["engagement"], "engagement")
        require(record["record_id"] == intent["record_id"] and record["run_id"] == intent["run_id"], "record identity")
        require(record["prev_record_digest"] == intent["expected_head"]["record_digest"], "predecessor mismatch")
        require(record["sequence"] == intent["expected_head"]["sequence"] + 1, "sequence mismatch")
        require(self.head == intent["expected_head"], "head moved")
        require(record["run_id"] not in self.linked, "run already linked")
        self.linked[record["run_id"]] = artifact_id
        self.head = {"engagement": record["engagement"], "sequence": record["sequence"], "record_digest": intent["record_digest"]}
        intent.update(state="complete", artifact_id=artifact_id)
        return artifact_id


class CrossLaneContracts(unittest.TestCase):
    def test_exit_registry_matches_adr(self):
        adr = (ROOT / "docs/adr/cross-lane-contracts.md").read_text()
        rows = re.findall(r"^\| ([0-8]) \|[^\n]*?\| ([^\n]+) \|$", adr, re.M)
        self.assertEqual([int(code) for code, _ in rows], [0, 2, 3, 4, 5, 6, 7, 8])
        documented = [
            (name, int(code)) for code, row in rows for name in re.findall(r"`([A-Z_]+)`", row)
        ]
        self.assertEqual(len(documented), len(EXITS))
        self.assertEqual(dict(documented), EXITS)
        representatives = [
            "SLOT_CONFLICT", "OBJECT_NOT_FOUND", "IDEMPOTENCY_KEY_REUSED",
            "ORACLE_UNAVAILABLE", "INTEGRITY_FAILURE", "DEPENDENCY_UNAVAILABLE", "ACCOUNTING_UNESTABLISHED",
        ]
        self.assertEqual([EXITS[code] for code in representatives], list(range(2, 9)))

    def test_response_examples_and_required_fields(self):
        for case in read_json(EXAMPLES / "responses.json"):
            response = case["response"]
            with self.subTest(command=response["command"], status=case["exit"]):
                validate_response(response, case["exit"])
                for key in SHAPES["scourge.response.v1"]:
                    if key in OPTIONAL_FIELDS["scourge.response.v1"]:
                        continue
                    truncated = response.copy()
                    del truncated[key]
                    with self.assertRaises(ValueError):
                        validate_response(truncated, case["exit"])

        response = read_json(EXAMPLES / "responses.json")[0]["response"]
        omitted = response.copy()
        del omitted["finding_caveats"]
        validate_response(omitted, 0)
        validate_response(dict(response, finding_caveats=None), 0)

    def test_next_argv_preserves_whitespace_and_binding(self):
        response = read_json(EXAMPLES / "responses.json")[0]["response"]
        argv = response["next"][0]["argv"]
        index = argv.index("--workspace") + 1
        argv[index:index + 1] = argv[index].split()
        with self.assertRaisesRegex(ValueError, "incomplete Scourge argv"):
            validate_response(response, 0)

    def test_masked_failures_keep_typed_diagnostics(self):
        responses = [case["response"] for case in read_json(EXAMPLES / "responses.json")]
        ready = next(response for response in responses if response["result"] == "ready")
        blocked = next(response for response in responses if response["result"] == "blocked")
        failure = next(response for response in responses if response["error"] and response["error"]["code"] == "DEPENDENCY_UNAVAILABLE")
        self.assertEqual(ready["transport"], blocked["transport"])
        self.assertEqual(blocked["blockers"], ["DEPENDENCY_UNAVAILABLE"])
        self.assertEqual(blocked["diagnostics"][0]["code"], "WRONG_LISTENER")
        self.assertEqual(blocked["diagnostics"][0]["wrapper_exit"], 0)
        self.assertEqual(blocked["diagnostics"][0]["native_exit"], 0)
        event = read_json(EXAMPLES / "stderr-event.json")
        validate(event, "scourge.diagnostic.v1")
        for field in ("engagement", "workspace", "request_key"):
            self.assertEqual(event[field], failure[field])
        self.assertEqual(event["run_id"], failure["run"]["id"])
        self.assertEqual(event["diagnostic"], failure["diagnostics"][0])
        self.assertEqual(event["diagnostic"]["code"], "TOOL_UNAVAILABLE")
        self.assertIsNone(event["diagnostic"]["native_exit"])
        self.assertEqual(event["diagnostic"]["wrapper_exit"], 0)

    def test_request_recovery_scope_conflict_and_retry(self):
        original = read_json(EXAMPLES / "request-input.json")
        validate_request(original)
        key = "rk_example_01"
        scope = ("/work/orders", "orders-api")
        reordered = dict(original, arguments=dict(reversed(list(original["arguments"].items()))))
        store = {(scope, key): (original, "R-1", False)}
        self.assertEqual(request_outcome(store, scope, key, reordered), ("reopen_same_run", "R-1"))
        store[(scope, key)] = (original, "R-1", True)
        self.assertEqual(request_outcome(store, scope, key, reordered), ("existing", "R-1"))
        changed = dict(original, arguments=dict(original["arguments"], rounds=3))
        self.assertEqual(request_outcome(store, scope, key, changed), ("IDEMPOTENCY_KEY_REUSED", None))
        cross_scope = request_outcome(store, ("/work/orders", "different"), key, original)
        self.assertEqual(cross_scope, request_outcome(store, scope, "rk_unknown", original))
        self.assertEqual(cross_scope, ("OBJECT_NOT_FOUND", None))
        self.assertEqual(len(store), 1)

    def test_record_fields_and_independent_dimensions(self):
        record = read_json(EXAMPLES / "verification-record.json")
        validate_record(record)
        self.assertEqual((record["result"], record["effects"], record["cleanup"]), ("invalid", "observed", "unknown"))
        for key in SHAPES["scourge.verification.v1"]:
            changed = record.copy()
            del changed[key]
            with self.assertRaises(ValueError):
                validate_record(changed)
        for key, invalid in [("kind", "retest"), ("custody", "trusted"), ("target_isolation", "clean_instance"), ("result", True)]:
            with self.subTest(field=key), self.assertRaises(ValueError):
                validate_record(dict(record, **{key: invalid}))
        retest = {
            "mode": "paired", "baseline_record": "V-baseline", "baseline_digest": "1" * 64,
            "property_result": "no_violation_within_tested_scope", "functional_result": "regression_observed",
            "paired_baseline_target": record["target"], "intermittent_sampling": None,
        }
        retest_record = dict(record, kind="retest", retest=retest,
                             rounds=[dict(record["rounds"][0], phase="retest_candidate")])
        validate_record(retest_record)
        with self.assertRaises(ValueError):
            validate_record(dict(retest_record, retest=dict(retest, functional_result="fixed")))

    def test_accounting_refuses_pass_delta_as_charge(self):
        accounting = read_json(EXAMPLES / "verification-record.json")["accounting"]
        validate_accounting(accounting)
        for key in SHAPES["scourge.accounting.v1"]:
            changed = accounting.copy()
            del changed[key]
            with self.assertRaises(ValueError):
                validate_accounting(changed)
        self.assertIsNone(accounting["counters_before"])
        self.assertEqual(accounting["ledger_debits"][0]["amount"]["granularity"], "block")
        self.assertEqual(accounting["observed_sent"]["value"], 1)
        self.assertIsNone(accounting["charged"])
        self.assertEqual(ENUMS["attribution"], ["exclusive", "shared", "unestablished"])
        with self.assertRaisesRegex(ValueError, "run-scoped"):
            validate_accounting(dict(accounting, charged=accounting["counters_after"]["spent"]))
        for attribution in ("exclusive", "shared"):
            with self.assertRaisesRegex(ValueError, "requires evidence"):
                validate_accounting(dict(accounting, attribution=attribution))

    def test_publication_requires_prior_intent_and_exact_bytes(self):
        intent = read_json(EXAMPLES / "publication-intent.json")
        chain = PublicationModel(intent["engagement"])
        data = (EXAMPLES / "verification-record.json").read_bytes()
        with self.assertRaisesRegex(ValueError, "write ahead"):
            chain.store("P-1", "artifact-one", data)
        chain.declare(intent)
        with self.assertRaisesRegex(ValueError, "artifact unavailable"):
            chain.finish("P-1")
        chain.store("P-1", "artifact-one", data + b" ")
        with self.assertRaisesRegex(ValueError, "artifact digest"):
            chain.finish("P-1")
        with self.assertRaisesRegex(ValueError, "changed store retry"):
            chain.store("P-1", "artifact-two", data)
        self.assertEqual(chain.head, intent["expected_head"])
        self.assertFalse(chain.linked)

    def test_publication_recovery_rebuilds_stale_head_without_duplicate_links(self):
        intent = read_json(EXAMPLES / "publication-intent.json")
        record = read_json(EXAMPLES / "verification-record.json")
        chain = PublicationModel(intent["engagement"])
        chain.declare(intent)
        next_record = dict(record, run_id="R-2", record_id="V-2")

        def stage(intent_id, candidate):
            data = json.dumps(candidate).encode()
            chain.declare(dict(intent, intent_id=intent_id, expected_head=chain.head,
                               record_id=candidate["record_id"], run_id=candidate["run_id"],
                               record_digest=hashlib.sha256(data).hexdigest()))
            chain.store(intent_id, "artifact-" + intent_id, data)

        stage("P-2", next_record)
        data = (EXAMPLES / "verification-record.json").read_bytes()
        chain.store("P-1", "artifact-P-1", data)
        chain.store("P-1", "artifact-P-1", data)
        self.assertEqual(chain.finish("P-1"), "artifact-P-1")
        with self.assertRaisesRegex(ValueError, "head moved"):
            chain.finish("P-2")
        self.assertNotIn("R-2", chain.linked)
        chain.intents["P-2"]["state"] = "superseded"
        rebuilt = dict(next_record, record_id="V-4", sequence=2, prev_record_digest=chain.head["record_digest"])
        stage("P-3", dict(rebuilt, record_id="V-3", prev_record_digest="f" * 64))
        with self.assertRaisesRegex(ValueError, "predecessor mismatch"):
            chain.finish("P-3")
        stage("P-4", rebuilt)
        self.assertEqual(chain.finish("P-4"), "artifact-P-4")
        self.assertEqual(chain.finish("P-1"), "artifact-P-1")
        stage("P-5", dict(rebuilt, record_id="V-5", sequence=3, prev_record_digest=chain.head["record_digest"]))
        with self.assertRaisesRegex(ValueError, "run already linked"):
            chain.finish("P-5")
        self.assertEqual(chain.head["sequence"], 2)
        self.assertEqual(chain.linked, {"R-1": "artifact-P-1", "R-2": "artifact-P-4"})

    def test_argv_pins_match_inventory_schema_and_captures(self):
        registry = read_json(ROOT / "docs/contracts/teapot-argv-v1.json")
        manifest = read_json(FIXTURES / "manifest.json")
        inventory = read_json(ROOT / "docs/inventory.json")
        tool = next(tool for tool in inventory["tools"] if tool["tool"] == "teapot")
        self.assertEqual(registry["schema"], "scourge.teapot-argv.v1")
        for field in ("source_commit", "binary_sha256", "historical_inventory_binary_sha256"):
            self.assertEqual(registry[field], manifest[field])
        self.assertEqual(registry["source_commit"], tool["checkout"]["head"])
        self.assertEqual(registry["historical_inventory_binary_sha256"], tool["installed"]["sha256"])
        operations = registry["operations"]
        self.assertEqual(len({row["name"] for row in operations}), len(operations))
        coverage = {row["operation"] for row in operations if row["capture"] is not None}
        self.assertEqual(coverage, {"describe", "check_session", "send", "read_flow", "dry_run",
                                    "units_left", "list_jobs", "cancel", "edit_surface"})
        schema_only = {row["name"]: row["argv"][4:] for row in operations if row["capture"] is None}
        self.assertEqual(schema_only, {
            "macro_replay": ["--yes", "flows", "replay", "--macro", "{macro}", "--step", "{step}",
                             "--session", "{session}", "--set", "{edit}"],
            "send_dry_run": ["requests", "send", "{method}", "{url}", "--session", "{session}", "--dry-run"],
        })
        for pin in operations:
            with self.subTest(pin=pin["name"]):
                self.check_pin(pin)

    def check_pin(self, pin):
        schema = read_json(FIXTURES / pin["schema_fixture"])["output"]["schema"]
        argv = pin["argv"]
        self.assertEqual(argv[:4], ["{executable}", "--project", "{project}", "--json"])
        command = schema["command"].split()
        start = 5 if argv[4] == "--yes" else 4
        self.assertEqual(argv[start:start + len(command)], command)
        self.assertIn(pin["result_key"], schema["result"]["properties"])
        arguments = schema["arguments"]
        if "$ref" in arguments:
            arguments = arguments["$defs"][arguments["$ref"].rsplit("/", 1)[1]]
        properties = arguments.get("properties", {})
        for flag in argv[start + len(command):]:
            if flag.startswith("--"):
                self.assertIn(flag[2:].replace("-", "_"), properties)
        for option in pin["optional"]:
            for flag in option["argv"]:
                if flag.startswith("--"):
                    prop = properties[flag[2:].replace("-", "_")]
                    self.assertEqual(option["repeatable"], prop["type"] == "array")

        capture = pin["capture"]
        if capture is None:
            return
        recorded = read_json(FIXTURES / capture["fixture"])
        actual = recorded["argv"]
        expected = argv[1:]
        for change in capture["variant"]:
            tail = change["replace_tail"]
            self.assertEqual(expected[-len(tail):], tail)
            expected = expected[:-len(tail)] + change["with"]
        self.assertEqual(len(actual), len(expected))
        for observed, pinned in zip(actual, expected, strict=True):
            if pinned == "{project}":
                self.assertTrue(Path(observed).is_absolute())
            elif pinned == "{url}":
                self.assertRegex(observed, r"^http://127\.0\.0\.1:[0-9]+/probe$")
            elif pinned == "{flow_id}":
                self.assertEqual(int(observed), recorded["output"]["flow"]["id"])
            else:
                self.assertEqual(observed, capture["substitutions"].get(pinned, pinned))
        self.assertEqual(recorded["exit_code"], 0)
        self.assertIn(pin["result_key"], recorded["output"])


if __name__ == "__main__":
    unittest.main()
