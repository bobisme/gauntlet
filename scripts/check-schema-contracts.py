#!/usr/bin/env python3
"""Offline checks for the versioned engagement, policy rule and claim template contracts.

The checker reads local files only. It parses them strictly, evaluates the small
enumerated subset of JSON Schema keywords the checked-in contracts use, and then
applies the reference, provenance and scope rules that a schema cannot state.
It sends no target traffic and starts no registered operation.
"""

from copy import deepcopy
from datetime import datetime
import hashlib
import json
import math
from pathlib import Path
import re
import tomllib
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "schemas"
EXAMPLES = ROOT / "fixtures" / "target" / "schema-examples"
FIXTURE_ENGAGEMENT = ROOT / "fixtures" / "target" / "example" / "engagement.toml"

CONTRACTS = {
    "engagement": ("engagement.v1.schema.json", "scourge.engagement.v1"),
    "policy-rule": ("policy-rule.v1.schema.json", "scourge.policy-rule.v1"),
    "claim-template": ("claim-template.v1.schema.json", "scourge.claim-template.v1"),
}
TYPES = {
    "array": (list,),
    "integer": (int,),
    "number": (int, float),
    "object": (dict,),
    "string": (str,),
}
KEYWORDS = {
    "$defs", "$id", "$ref", "$schema", "additionalProperties", "anyOf", "const",
    "description", "enum", "exclusiveMaximum", "exclusiveMinimum", "format", "if", "items",
    "maxLength", "minItems", "minProperties", "minimum", "oneOf", "pattern", "properties",
    "propertyNames", "required", "then", "title", "type", "uniqueItems",
}
SCOPE_BY_CLASS = {
    "private-object-read": "object_read",
    "state-change": "state_change",
    "collection-disclosure": "collection_disclosure",
    "existence": "existence",
}
FORBIDDEN = (
    (re.compile(r"\b(?:GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS|TRACE|CONNECT)\s+\S"),
     "request line"),
    (re.compile(r"^(?:curl|wget|bash|zsh|sh|python[0-9.]*|nc|ncat|ssh|scp|sudo|env|perl|ruby|node)\b"),
     "command"),
    (re.compile(r"^#!"), "script header"),
    (re.compile(r"(?:`|\$\()"), "command substitution"),
    (re.compile(r"[\x00-\x08\x0b-\x1f\x7f]"), "control character"),
    (re.compile(r"(?:;|&&|\|\|)\s*(?:curl|wget|bash|sh|nc|python[0-9.]*|rm|cat|echo|id|whoami)\b"),
     "command separator"),
    (re.compile(r"(?:password|passwd|secret|token|api[_-]?key|authorization|cookie)\s*[:=]", re.I),
     "credential"),
    (re.compile(r"://"), "network target"),
)


class Invalid(ValueError):
    pass


def json_document(text):
    def members(pairs):
        result = {}
        for name, value in pairs:
            if name in result:
                raise Invalid("duplicate JSON member")
            result[name] = value
        return result

    def finite_number(token):
        number = float(token)
        if not math.isfinite(number):
            raise Invalid("non-finite JSON number")
        return number

    return json.loads(text, object_pairs_hook=members, parse_constant=finite_number,
                      parse_float=finite_number)


def check_shape(schema, value, root, path="$"):
    """Evaluate the assertion keywords these specific checked-in schemas use."""
    unknown = schema.keys() - KEYWORDS
    if unknown:
        raise AssertionError(f"unsupported schema keywords: {sorted(unknown)}")

    if "$ref" in schema:
        reference = schema["$ref"]
        if not reference.startswith("#/$defs/"):
            raise AssertionError("expected a local definition reference")
        check_shape(root["$defs"][reference.removeprefix("#/$defs/")], value, root, path)

    kind = schema.get("type")
    if kind and type(value) not in TYPES[kind]:
        raise Invalid(f"{path}: expected {kind}")
    if isinstance(value, float) and not math.isfinite(value):
        raise Invalid(f"{path}: non-finite number")
    if "const" in schema and value != schema["const"]:
        raise Invalid(f"{path}: unexpected constant")
    if "enum" in schema and value not in schema["enum"]:
        raise Invalid(f"{path}: unknown value")

    if "if" in schema:
        try:
            check_shape(schema["if"], value, root, path)
        except Invalid:
            pass
        else:
            check_shape(schema["then"], value, root, path)

    for keyword, lower, upper in (("anyOf", 1, math.inf), ("oneOf", 1, 1)):
        if keyword not in schema:
            continue
        successes = 0
        reasons = []
        for option in schema[keyword]:
            try:
                check_shape(option, value, root, path)
            except Invalid as issue:
                reasons.append(str(issue))
            else:
                successes += 1
        if not lower <= successes <= upper:
            raise Invalid(f"{path}: {keyword} matched {successes} choices ({', '.join(reasons)})")

    if isinstance(value, dict):
        for key in schema.get("required", ()):
            if key not in value:
                raise Invalid(f"{path}.{key}: missing required field")
        if len(value) < schema.get("minProperties", 0):
            raise Invalid(f"{path}: too few entries")
        properties = schema.get("properties", {})
        for key, item in value.items():
            if "propertyNames" in schema:
                check_shape(schema["propertyNames"], key, root, f"{path} (entry name)")
            child = properties.get(key, schema.get("additionalProperties", {}))
            if child is False:
                raise Invalid(f"{path}: unknown field")
            check_shape(child, item, root, f"{path}.{key}")

    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0):
            raise Invalid(f"{path}: too few entries")
        if schema.get("uniqueItems") and any(item in value[:index] for index, item in enumerate(value)):
            raise Invalid(f"{path}: duplicate entry")
        if "items" in schema:
            for index, item in enumerate(value):
                check_shape(schema["items"], item, root, f"{path}[{index}]")

    if isinstance(value, str):
        if "pattern" in schema and not re.search(schema["pattern"], value):
            raise Invalid(f"{path}: invalid spelling")
        if len(value) > schema.get("maxLength", math.inf):
            raise Invalid(f"{path}: text too long")
        if schema.get("format") == "date-time":
            try:
                datetime.fromisoformat(value)
            except ValueError as issue:
                raise Invalid(f"{path}: invalid date-time") from issue

    if type(value) in (int, float):
        if not (value >= schema.get("minimum", -math.inf)
                and schema.get("exclusiveMinimum", -math.inf) < value
                and value < schema.get("exclusiveMaximum", math.inf)):
            raise Invalid(f"{path}: number out of range")


def walk_strings(value, path):
    if isinstance(value, dict):
        for key, item in value.items():
            yield f"{path}.{key} (name)", key
            yield from walk_strings(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from walk_strings(item, f"{path}[{index}]")
    elif isinstance(value, str):
        yield path, value


def scan_forbidden(document):
    """Reject executable-shaped or secret-shaped text anywhere in a contract instance."""
    for path, text in walk_strings(document, "$"):
        for pattern, label in FORBIDDEN:
            if pattern.search(text):
                raise Invalid(f"{path}: forbidden {label}")


def engagement_links(document):
    sessions = {}
    for name, principal in document["principal"].items():
        for field in ("session", "verifier_session"):
            if field not in principal:
                continue
            label = principal[field]
            if label in sessions:
                raise Invalid(f"principal.{name}.{field}: session label already used by {sessions[label]}")
            sessions[label] = f"{name}.{field}"
    for name, property_record in document["property"].items():
        if "writers" in property_record and "write" not in property_record:
            raise Invalid(f"property.{name}.writers: a write rule requires a write operation")


def policy_links(document, engagement):
    name = document["property"]
    if name not in engagement["property"]:
        raise Invalid(f"property: {name} is not declared in the engagement")
    declared = engagement["property"][name]
    for field in ("readers", "writers"):
        if field not in document:
            continue
        if field not in declared:
            raise Invalid(f"{field}: the engagement declares no {field} rule for {name}")
        if document[field] != declared[field]:
            raise Invalid(f"{field}: differs from the engagement revision for {name}")
    version = document.get("target_version")
    declared_version = engagement["engagement"].get("target_version")
    if version is not None and version != declared_version:
        raise Invalid("target_version: the rule names a version the engagement does not declare")
    source = document["source"]
    citation = source.get("citation")
    if citation is not None:
        selector = citation["selector"]
        if selector["end"] <= selector["start"]:
            raise Invalid("source.citation.selector: byte range must be nonempty and forward")
    if source["kind"] == "inferred":
        return
    if engagement["engagement"]["required_custody"] == "shared":
        if source["admission"]["identity"] != "attributed":
            raise Invalid("source.admission.identity: shared custody records an attributed statement")


def claim_links(document, engagement):
    claim_class = document["claim_class"]
    _, _, kind = claim_class.partition("/")
    expected = SCOPE_BY_CLASS.get(kind)
    if expected is None:
        raise Invalid(f"claim_class: unregistered claim class {claim_class}")
    if document["oracle"]["scope"] != expected:
        raise Invalid(f"oracle.scope: {document['oracle']['scope']} does not measure {claim_class}")

    slots = document["slots"]
    for name, slot in slots.items():
        if slot["kind"] == "property" and "lead" in slot["supplied_by"]:
            raise Invalid(f"slots.{name}: a property slot may not be supplied by a lead")

    steps = {}
    used = set()
    for step in document["recipe"]:
        if step["id"] in steps:
            raise Invalid("recipe: duplicate step ID")
        steps[step["id"]] = step
        used.update(step["slots"])
    if used != set(slots):
        raise Invalid("recipe: slot bindings must cover exactly the declared slots")

    for name, control in document["controls"].items():
        step = steps.get(control["step"])
        if step is None:
            raise Invalid(f"controls.{name}: unknown recipe step")
        if name not in step["controls"]:
            raise Invalid(f"controls.{name}: the step does not declare this control")
    for step in document["recipe"]:
        for name in step["controls"]:
            if name not in document["controls"]:
                raise Invalid(f"recipe.{step['id']}: unknown control")
            if document["controls"][name]["step"] != step["id"]:
                raise Invalid(f"recipe.{step['id']}: the control names another step")

    cleanup = document["cleanup"]["step"]
    if cleanup not in steps:
        raise Invalid("cleanup.step: unknown recipe step")
    if steps[cleanup]["effect"] != "plant":
        raise Invalid("cleanup.step: cleanup removes run-created state, which is the plant effect class")

    dimensions = set()
    for name, variant in document["retest_variants"].items():
        if variant["step"] not in steps:
            raise Invalid(f"retest_variants.{name}: unknown recipe step")
        dimensions.add(variant["result_dimension"])
    if dimensions != {"security_property", "legitimate_path"}:
        raise Invalid("retest_variants: both result dimensions are required")

    allowed = set(engagement["engagement"]["allow_effects"])
    for step in document["recipe"]:
        if step["effect"] != "none" and step["effect"] not in allowed:
            raise Invalid(f"recipe.{step['id']}: the engagement does not allow the {step['effect']} effect")


def check_contract(name, document, engagement=None):
    schema = Contracts.schemas[name]
    check_shape(schema, document, schema)
    scan_forbidden(document)
    if name == "engagement":
        engagement_links(document)
    elif name == "policy-rule":
        policy_links(document, engagement)
    else:
        claim_links(document, engagement)


def mutate(document, path, value):
    result = deepcopy(document)
    segment = result
    for key in path[:-1]:
        segment = segment[key]
    if value is MISSING:
        del segment[path[-1]]
    else:
        segment[path[-1]] = value
    return result


class _Missing:
    def __repr__(self):
        return "MISSING"


MISSING = _Missing()


class Contracts(unittest.TestCase):
    schemas = {}
    engagement = {}
    policy = {}
    template = {}
    fixture = {}

    @classmethod
    def setUpClass(cls):
        for name, (filename, version) in CONTRACTS.items():
            path = SCHEMAS / filename
            schema = json_document(path.read_text(encoding="utf-8"))
            if schema["$id"] != f"https://scourge.invalid/schemas/{filename}":
                raise AssertionError(f"unexpected schema ID in {filename}")
            if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
                raise AssertionError(f"unexpected JSON Schema dialect in {filename}")
            cls.schemas[name] = schema
            if version.split(".")[-1] != "v1":
                raise AssertionError(f"unexpected contract version {version}")
        cls.engagement = tomllib.loads((EXAMPLES / "engagement.toml").read_text(encoding="utf-8"))
        cls.policy = json_document((EXAMPLES / "policy-rule-orders.json").read_text(encoding="utf-8"))
        cls.template = json_document(
            (EXAMPLES / "claim-template-private-object-read.json").read_text(encoding="utf-8")
        )
        cls.fixture = tomllib.loads(FIXTURE_ENGAGEMENT.read_text(encoding="utf-8"))

    @classmethod
    def check(cls, name, document):
        check_contract(name, deepcopy(document),
                       cls.engagement if name != "engagement" else None)

    @classmethod
    def source_def(cls, kind):
        return cls.schemas["policy-rule"]["$defs"][f"source_{kind}"]

    def test_development_fixture_engagement(self):
        self.check("engagement", self.engagement)
        self.assertEqual(self.engagement["schema_version"], "scourge.engagement.v1")
        self.assertEqual(self.engagement["principal"].keys(), self.fixture["principal"].keys())
        self.assertEqual(self.engagement["property"].keys(), self.fixture["property"].keys())
        self.assertEqual(len(self.engagement["property"]), 12)
        for name, record in self.engagement["property"].items():
            original = self.fixture["property"][name]
            for field in ("readers", "writers", "policy"):
                self.assertEqual(record.get(field), original.get(field))
            for field in ("resource", "read", "plant", "remove", "policy"):
                self.assertIn(field, record)
            self.assertIn("operation.", record["read"])
            self.assertEqual(record["plant"]["fields"],
                             [f"selector.{name.replace('_', '-')}.{field.strip('/')}"
                              for field in original["plant"]["fields"]])
            self.assertEqual("write" in record, "write" in original)
            self.assertEqual("writers" in record, "writers" in original)
            if "write" in original:
                self.assertEqual(record["write"]["fields"],
                                 [f"selector.{name.replace('_', '-')}.{field.strip('/')}"
                                  for field in original["write"]["fields"]])
        for name, record in self.engagement["principal"].items():
            self.assertIn("session", record)
            self.assertIn("verifier_session", record)
            self.assertEqual(record["identity_probe"]["operation"], "operation.identity.probe")

    def test_engagement_optional_fields(self):
        optional = deepcopy(self.engagement)
        del optional["engagement"]["max_verify_runs"]
        del optional["engagement"]["retest_miss_threshold"]
        del optional["principal"]["alice"]["verifier_session"]
        del optional["principal"]["bob"]["groups"]
        del optional["property"]["orders"]["readers"]
        del optional["property"]["orders"]["writers"]
        del optional["property"]["orders"]["write"]
        self.check("engagement", optional)

    def test_engagement_rejections(self):
        cases = (
            (("schema_version",), "scourge.engagement.v2", "unexpected constant"),
            (("engagement",), MISSING, "missing required field"),
            (("engagement", "pass"), "passes/staging.toml", "invalid spelling"),
            (("engagement", "pass"), "pass", "invalid spelling"),
            (("engagement", "target_version"), MISSING, "missing required field"),
            (("engagement", "target_version"), "fixture-v1", "invalid spelling"),
            (("engagement", "allow_effects"), [], "too few entries"),
            (("engagement", "allow_effects"), ["observe", "delete"], "unknown value"),
            (("engagement", "max_verify_runs"), True, "expected integer"),
            (("engagement", "max_verify_runs"), 0, "number out of range"),
            (("engagement", "retest_miss_threshold"), float("nan"), "non-finite number"),
            (("engagement", "instrument", "project"), "teapot-project", "invalid spelling"),
            (("principal", "bob", "session"), "session.alice", "session label already used"),
            (("principal", "alice", "verifier_session"), "alice-verify", "invalid spelling"),
            (("principal", "alice", "identity_probe"), {"operation": "GET /app/api/me"},
             "missing required field"),
            (("principal", "alice", "identity_probe", "operation"), "operation", "invalid spelling"),
            (("principal", "alice", "identity_probe", "subject"), "/id", "invalid spelling"),
            (("principal", "alice", "password"), "placeholder", "unknown field"),
            (("principal", "alice", "groups"), ["tenant-a"], "invalid spelling"),
            (("property", "orders", "read"), "GET /app/api/orders/{id}", "invalid spelling"),
            (("property", "orders", "read"), "orders.read", "invalid spelling"),
            (("property", "orders", "policy"), "  ", "invalid spelling"),
            (("property", "orders", "policy"), MISSING, "missing required field"),
            (("property", "orders", "plant"), MISSING, "missing required field"),
            (("property", "orders", "plant", "fields"), [], "too few entries"),
            (("property", "orders", "plant", "id_from"), "/id", "invalid spelling"),
            (("property", "orders", "resource"), "orders", "invalid spelling"),
            (("property", "orders", "write"), MISSING, "missing required field"),
            (("property", "orders", "readers"), "", "unknown value"),
            (("property", "orders", "actor"), "alice", "unknown field"),
        )
        for path, value, expected in cases:
            with self.subTest(path=path, value=value), self.assertRaisesRegex(Invalid, expected):
                self.check("engagement", mutate(self.engagement, path, value))

    def test_policy_rule_example(self):
        self.check("policy-rule", self.policy)
        digest = hashlib.sha256((EXAMPLES / "engagement.toml").read_bytes()).hexdigest()
        self.assertEqual(self.policy["source"]["kind"], "engagement")
        self.assertEqual(self.policy["source"]["revision"]["sha256"], digest)
        self.assertEqual(self.policy["property"], "orders")
        self.assertEqual(self.policy["target_version"],
                         self.engagement["engagement"]["target_version"])

    def test_policy_rule_sources(self):
        artifact = {"artifact_id": "artifact.sample", "sha256": "a" * 64}
        citation = {**artifact, "selector": {"type": "byte_range", "start": 0, "end": 10}}
        admission = {"actor": "operator.sample", "identity": "attributed",
                     "recorded_at": "2026-11-23T00:00:00Z"}
        engagement = {"kind": "engagement", "revision": artifact, "admission": admission}
        document = {"kind": "document", "citation": citation, "admission": admission}
        operator = {"kind": "operator", "statement": artifact, "admission": admission}
        inferred = {"kind": "inferred", "citation": citation}
        base = {key: self.policy[key] for key in ("schema_version", "property", "readers")}
        for source in (engagement, document, operator, inferred, {"kind": "inferred"}):
            with self.subTest(kind=source["kind"]):
                instance = {**base, "target_version": "version.fixture.v1", "source": source}
                self.check("policy-rule", instance)

        # Each source is validated against its own branch, so a failure names the defect.
        for kind, source, expected in (
            ("engagement", {"kind": "engagement", "revision": artifact},
             "admission: missing required field"),
            ("engagement", {**engagement, "note": "extra"}, "unknown field"),
            ("document", {"kind": "document", "citation": artifact, "admission": admission},
             "selector: missing required field"),
            ("document", {**document, "citation": {**citation, "sha256": "abc"}},
             "invalid spelling"),
            ("document", {**document, "citation": {**citation, "artifact_id": "doc"}},
             "invalid spelling"),
            ("operator", {"kind": "operator", "admission": admission},
             "statement: missing required field"),
            ("operator", {**operator, "admission": {**admission, "recorded_at": "2026-02-31T00:00:00Z"}},
             "invalid date-time"),
            ("operator", {**operator, "admission": {**admission, "actor": "sample"}},
             "invalid spelling"),
            ("operator", {**operator, "admission": {**admission, "identity": "signed"}},
             "unknown value"),
            ("inferred", {"kind": "inferred", "admission": admission}, "unknown field"),
            ("inferred", {"kind": "inferred", "citation": {**citation, "selector":
                                                           {"type": "range", "start": 0, "end": 10}}},
             "unexpected constant"),
        ):
            with self.subTest(kind=kind, source=source), self.assertRaisesRegex(Invalid, expected):
                check_shape(self.source_def(kind), deepcopy(source), self.schemas["policy-rule"])

        for source, version, expected in (
            (engagement, MISSING, "target_version: missing required field"),
            ({**inferred, "admission": admission}, "version.fixture.v1", "oneOf matched 0"),
            ({"kind": "operator", "admission": admission}, "version.fixture.v1", "oneOf matched 0"),
            ({"kind": "agent"}, "version.fixture.v1", "oneOf matched 0"),
            (inferred, "version.other.v1",
             "target_version: the rule names a version the engagement does not declare"),
            ({**operator, "admission": {**admission, "identity": "authenticated"}},
             "version.fixture.v1", "shared custody records an attributed statement"),
            ({**inferred, "citation": {**citation, "selector":
                                       {"type": "byte_range", "start": 10, "end": 5}}},
             "version.fixture.v1", "byte range must be nonempty and forward"),
            ({**inferred, "citation": {**citation, "selector":
                                       {"type": "byte_range", "start": 5, "end": 5}}},
             "version.fixture.v1", "byte range must be nonempty and forward"),
            ({**document, "citation": {**citation, "selector":
                                       {"type": "byte_range", "start": 10, "end": 5}}},
             "version.fixture.v1", "byte range must be nonempty and forward"),
            ({**document, "citation": {**citation, "selector":
                                       {"type": "byte_range", "start": 5, "end": 5}}},
             "version.fixture.v1", "byte range must be nonempty and forward"),
        ):
            with self.subTest(source=source, expected=expected):
                instance = {**base, "source": source}
                if version is not MISSING:
                    instance["target_version"] = version
                with self.assertRaisesRegex(Invalid, expected):
                    self.check("policy-rule", instance)

        for path, value, expected in (
            (("property",), "orderz", "not declared in the engagement"),
            (("property",), "Orders", "invalid spelling"),
            (("property",), "invoices", "declares no writers rule"),
            (("readers",), "group", "differs from the engagement revision"),
            (("source",), MISSING, "missing required field"),
            (("policy",), "GET /app/api/orders/{id}", "forbidden request line"),
        ):
            with self.subTest(path=path), self.assertRaisesRegex(Invalid, expected):
                self.check("policy-rule", mutate(self.policy, path, value))

    def test_claim_template_example(self):
        self.check("claim-template", self.template)
        self.assertEqual(self.template["claim_class"], "web-authz/private-object-read")
        self.assertEqual(self.template["oracle"],
                         {"id": "oracle.web.private-object-read.v1", "scope": "object_read"})
        used = {slot for step in self.template["recipe"] for slot in step["slots"]}
        self.assertEqual(used, set(self.template["slots"]))
        self.assertEqual({step["effect"] for step in self.template["recipe"]},
                         {"none", "observe", "plant"})
        self.assertEqual({variant["result_dimension"]
                          for variant in self.template["retest_variants"].values()},
                         {"security_property", "legitimate_path"})
        for step in self.template["recipe"]:
            self.assertTrue(step["operation"].startswith("operation."))
            for control in step["controls"]:
                self.assertEqual(self.template["controls"][control]["step"], step["id"])

    def test_claim_scope_binding(self):
        for claim_class, oracle_id, scope, expected in (
            ("web-authz/collection-disclosure", "oracle.web.private-object-read.v1",
             "object_read", "claim_class: unexpected constant"),
            ("web-authz/existence", "oracle.web.private-object-read.v1",
             "object_read", "claim_class: unexpected constant"),
            ("web-authz/private-object-read", "oracle.web.private-object-read.v1",
             "existence", r"oracle\.scope: unexpected constant"),
            ("web-authz/collection-disclosure", "oracle.web.collection-disclosure.v1",
             "object_read", "does not measure web-authz/collection-disclosure"),
            ("web-authz/existence", "oracle.web.existence.v1",
             "object_read", "does not measure web-authz/existence"),
            ("web-authz/private-object-read", "oracle.web.object-read.v2",
             "collection_disclosure", "does not measure web-authz/private-object-read"),
            ("web-authz/state-change", "oracle.web.state-change.v1",
             "object_read", "does not measure web-authz/state-change"),
            ("web-authz/idor", "oracle.web.unknown.v1",
             "object_read", "unregistered claim class"),
        ):
            with self.subTest(claim_class=claim_class), self.assertRaisesRegex(Invalid, expected):
                template = deepcopy(self.template)
                template["claim_class"] = claim_class
                template["oracle"] = {"id": oracle_id, "scope": scope}
                self.check("claim-template", template)

    def test_claim_template_rejections(self):
        recipe = self.template["recipe"]
        cases = (
            (("slots", "read", "supplied_by"), ["lead", "operator"],
             "a property slot may not be supplied by a lead"),
            (("slots", "read", "kind"), "artifact", None),
            (("slots", "read", "supplied_by"), [], "too few entries"),
            (("recipe",), [recipe[0], recipe[0]], "duplicate step ID"),
            (("recipe", 0, "operation"), "send", "invalid spelling"),
            (("recipe", 0, "operation"), "operation", "invalid spelling"),
            (("recipe", 0, "effect"), "mutate", "does not allow the mutate effect"),
            (("recipe", 0, "effect"), MISSING, "missing required field"),
            (("recipe", 1, "controls"), ["control.missing"], "unknown control"),
            (("recipe", 1, "controls"), ["control.distinct_subject"], "names another step"),
            (("recipe", 0, "slots"), ["owner", "missing"], "must cover exactly"),
            (("controls", "control.distinct_subject", "step"), "probe.other.first",
             "does not declare this control"),
            (("controls", "control.missing",), {
                "step": "missing.step", "rules_out": "Something", "reason_code": "X_CODE"},
             "unknown recipe step"),
            (("controls", "control.distinct_subject", "rules_out"), "  ", "invalid spelling"),
            (("controls", "control.distinct_subject", "reason_code"), "same_subject",
             "invalid spelling"),
            (("controls",), {}, "too few entries"),
            (("cleanup", "step"), "missing", "unknown recipe step"),
            (("cleanup", "step"), "read.other.first",
             "cleanup removes run-created state, which is the plant effect class"),
            (("cleanup",), MISSING, "missing required field"),
            (("retest_variants", "legitimate_path"), MISSING, "both result dimensions"),
            (("retest_variants", "security_property", "step"), "missing", "unknown recipe step"),
            (("oracle", "id"), "web.private-object-read.v1", "invalid spelling"),
            (("oracle", "scope"), "collection_disclosure", "unexpected constant"),
            (("template_version",), 0, "number out of range"),
            (("claim_class",), "web-authz", "unexpected constant"),
            (("schema_version",), "scourge.claim-template.v2", "unexpected constant"),
        )
        for path, value, expected in cases:
            with self.subTest(path=path, value=value):
                template = mutate(self.template, path, value)
                if expected is None:
                    self.check("claim-template", template)
                else:
                    with self.assertRaisesRegex(Invalid, expected):
                        self.check("claim-template", template)

    def test_forbidden_content(self):
        for text, expected in (
            ("Order owners may read GET /app/api/orders/{id}", "forbidden request line"),
            ("curl -s https://127.0.0.1:3000/app", "forbidden command"),
            ("See https://example.test/orders", "forbidden network target"),
            ("password = hunter2", "forbidden credential"),
            ("Run $(id) first", "forbidden command substitution"),
            ("x; rm -rf /", "forbidden command separator"),
            ("#!/bin/sh", "forbidden script header"),
        ):
            with self.subTest(text=text), self.assertRaisesRegex(Invalid, expected):
                scan_forbidden({"prose": text})
        with self.assertRaisesRegex(Invalid, "forbidden control character"):
            scan_forbidden({"prose": "line\u0000break"})

    def test_strict_documents(self):
        for text, expected in ((r'{"x":1,"\u0078":2}', "duplicate JSON member"),
                               ('{"x":Infinity}', "non-finite JSON number"),
                               ('{"x":1e500}', "non-finite JSON number")):
            with self.subTest(text=text), self.assertRaisesRegex(Invalid, expected):
                json_document(text)
        with self.assertRaises(tomllib.TOMLDecodeError):
            tomllib.loads('field = "first"\nfield = "second"\n')

    def test_schemas_are_strict_and_versioned(self):
        def walk(schema, path, root):
            if not isinstance(schema, dict):
                return
            unknown = schema.keys() - KEYWORDS
            self.assertFalse(unknown, f"{path}: unsupported keywords {sorted(unknown)}")
            if "$ref" in schema:
                name = schema["$ref"].removeprefix("#/$defs/")
                self.assertIn(name, root["$defs"], path)
            if schema.get("type") == "object":
                self.assertIn("additionalProperties", schema, path)
                if "properties" in schema:
                    self.assertIs(schema["additionalProperties"], False, path)
            for keyword in ("additionalProperties", "propertyNames", "items", "if", "then"):
                if keyword in schema:
                    walk(schema[keyword], f"{path}.{keyword}", root)
            for keyword in ("properties", "$defs"):
                for name, child in schema.get(keyword, {}).items():
                    walk(child, f"{path}.{keyword}.{name}", root)
            for keyword in ("anyOf", "oneOf"):
                for index, child in enumerate(schema.get(keyword, ())):
                    walk(child, f"{path}.{keyword}[{index}]", root)

        for name, (filename, version) in CONTRACTS.items():
            with self.subTest(name=name):
                schema = self.schemas[name]
                self.assertEqual(schema["properties"]["schema_version"]["const"], version)
                walk(schema, filename, schema)

if __name__ == "__main__":
    unittest.main()
