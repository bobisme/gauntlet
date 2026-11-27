#!/usr/bin/env python3
"""Grade the four frozen Scourge skeleton assignments from offline referee evidence."""

import argparse
from base64 import b64decode
from collections import deque
from datetime import datetime, timezone
from functools import lru_cache
from hashlib import sha256
import hmac
from itertools import groupby
from ipaddress import ip_address
import json
from pathlib import Path, PurePosixPath
import re
import shlex
from statistics import median
import tomllib
from urllib.parse import urlsplit
import zlib


ASSIGNMENT = "scourge.skeleton-assignment.v1"
LEDGER = "scourge.skeleton-ledger.v1"
RUBRIC = "scourge.skeleton-rubric.v1"
REVIEW = "scourge.skeleton-referee.v1"
HOST_TRACE = "scourge.skeleton-host-process-trace.v1"
PREPARED_ACCESS = "scourge.skeleton-prepared-session-access.v1"
DISCOVERY_REVIEW = "scourge.skeleton-discovery-input-review.v1"
CELLS = tuple(f"{host}/{track}" for host in ("executable", "managed")
              for track in ("supplied", "discovery"))
CASES = ("positive", "public", "login", "same_subject")
INVALID = {"login": "OBSERVER_INVALID", "same_subject": "SAME_SUBJECT"}
ORACLE_ID = "web.private-object-read"
ORACLE_VERSION = "1"
ORACLE_KEY = f"{ORACLE_ID}.v{ORACLE_VERSION}"
REPOSITORY = Path(__file__).resolve().parents[3]
MATERIALS = REPOSITORY / "evals/skeleton"
ORACLE_CONTRACT = REPOSITORY / "docs/contracts/oracle-specifications.v1.json"
CLAIM_TEMPLATE = REPOSITORY / "fixtures/target/schema-examples/claim-template-private-object-read.json"
WIRE_CONTRACT = REPOSITORY / "docs/contracts/scourge-v1.json"
REGISTRY_CONTRACT = MATERIALS / "native-fixture-registry.v1.json"
OPERATIONS_SOURCE = REPOSITORY / "crates/scourge-core/src/operations.rs"
DECLARATION_SOURCE = REPOSITORY / "crates/scourge-core/src/declaration.rs"
NATIVE_REGISTRY_DIGEST = "241a2c9a9cfac4be5ef31d2e9eb9a9bdbfd4e85e87b8e92daca539cc7ac8d289"
SESSION_COOKIE = "scourge_session"
IDENTITY_PATH = "/app/api/me"
IDENTITY_PROBE = {"operation": "operation.identity.probe", "subject": "selector.identity.subject"}
FROZEN_DECODER = {
    "identity": {"id": "http-body", "version": "1"},
    "limits": {"max_decoded_bytes": 1_048_576, "max_expansion_ratio": 100},
}
M1_CONTEXT = {
    "custody": "shared", "target_isolation": "separate_principals_unconfined",
    "enforcement": "unenforced", "environment_kind": "simulated",
    "destination_time_enforced": False, "request_ceiling_enforced": False,
}
CUSTODY_BOUNDARY = {"fixture_source", "ground_truth", "admin_secret", "hidden_canaries",
                    "grading_state", "prepared_session_bindings"}
DIGEST = re.compile(r"[0-9a-f]{64}")
LOCAL_ID = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}")
MAX_SCREEN_BYTES = 2048
MAX_FIRST_CALLS = 3
MAX_MEDIAN_MUTATIONS = 6
MAX_NATIVE_COUNT = (1 << 53) - 1
DEFAULT_VERIFY_ROUNDS = 2
REQUEST_REFERENCE_TEAPOT = (
    "6e66dca22026db00cfadb4e07a6950165b160c14",
    "c03bd1dfb40cdcbba7ab97b5f5ab16cb00a8f5ed33c7c59c6ab59a980326abae",
)
HISTORICAL_TEAPOT_SHA256 = "6d15d625e10afa768a221f64eb7a2a245a64a7babbe61cf74ce8d4ff33b2f458"
TEAPOT_PREPARATION_ROLE = "teapot-preparation"
TEAPOT_VERIFIER_ROLE = "teapot-verifier"
BOUND_EXEC = re.compile(r"/proc/self/fd/[0-9]+")
WORKSPACE_CONFIG = "scourge.toml"
WORKSPACE_LOCAL_FILES = {WORKSPACE_CONFIG, ".scourge/demo-owner", ".scourge/state.sqlite3"}
NATIVE_WORKSPACE_CONFIG = re.compile(
    rb'version = 1\nworkspace_id = "(?P<workspace_id>[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}'
    rb'-[89ab][0-9a-f]{3}-[0-9a-f]{12})"\n'
)
INVESTIGATION_ACTOR = "agent:scourge"
INVESTIGATION_PROTOCOL = "inv.capture.v1"
EXPERIMENT_DERIVATION = ("freeze registered verifier experiment", "scourge.preflight.v1")
VERIFICATION_DERIVATION = ("evaluate compiled oracle and build verification record", "scourge.verification.v1")
FORBIDDEN_PROSE = re.compile(
    r"\b(?:GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS|TRACE|CONNECT)\s+\S"
    r"|^(?:curl|wget|bash|zsh|sh|python[0-9.]*|nc|ncat|ssh|scp|sudo|env|perl|ruby|node)\b"
    r"|^#!|`|\$\("
    r"|(?:;|&&|\|\|)\s*(?:curl|wget|bash|sh|nc|python[0-9.]*|rm|cat|echo|id|whoami)\b"
    r"|(?i:password|passwd|secret|token|api[_-]?key|authorization|cookie)\s*[:=]"
    r"|://"
)


def need(condition, reason):
    if not condition:
        raise ValueError(reason)


def digest(data):
    return sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def host_trace_mac(trace, key):
    payload = HOST_TRACE.encode() + b"\0" + canonical(trace)
    return hmac.digest(key, payload, "sha256").hex()


def native_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def native_digest(value):
    return digest(native_bytes(value))


def oracle_contract():
    return parse_json(ORACLE_CONTRACT.read_bytes())["oracles"][ORACLE_KEY]


def operation_registry():
    return parse_json(REGISTRY_CONTRACT.read_bytes())


def compiled_registry_digest(registry):
    """Reproduce the native operations.rs registry_digest serialization."""
    identity = registry["identity"]
    dispatch = ", ".join(
        f'DispatchSpec {{ flow: "{row["flow"]}", principal: {row["principal"].title()}, actions: {row["actions"]} }}'
        for row in registry["dispatches"]
    )
    values = [
        registry["id"],
        f'anonymous={registry["anonymous_session"]}',
        "identity=" + "|".join(identity[key] for key in ("operation", "subject", "path", "json_field")),
        f'object-id={registry["object_id_field"]}',
        f"dispatch=[{dispatch}]",
    ]
    for resource, spec in registry["resources"].items():
        prefix = "selector." + resource.removeprefix("resource.") + "."
        need(all(name.startswith(prefix) for name in spec["fields"]), "registry selectors do not scope to their resource")
        fields = ",".join(f'{name.removeprefix(prefix)}={field}' for name, field in spec["fields"].items())
        values.append("|".join([resource, *(spec[key] for key in ("read", "plant", "remove", "id_from",
                                                                  "collection", "macro")), fields]))
    return digest("\n".join(values).encode())


def registry_pin():
    data = REGISTRY_CONTRACT.read_bytes()
    contract = parse_json(data)
    need(digest(OPERATIONS_SOURCE.read_bytes()) == contract["source_sha256"]
         and digest(DECLARATION_SOURCE.read_bytes()) == contract["declaration_source_sha256"]
         and compiled_registry_digest(contract) == contract["compiled_sha256"] == NATIVE_REGISTRY_DIGEST,
         "frozen fixture registry or declaration grammar differs from native source")
    return {"id": contract["id"], "digest": digest(data), "compiled_digest": contract["compiled_sha256"]}


def registered_property(prop):
    spec = operation_registry()["resources"].get(prop["resource"])
    need(spec is not None, "property is outside the compiled native operation registry")
    plant = prop["plant"]
    need(prop["read"] == spec["read"] and plant["operation"] == spec["plant"]
         and prop["remove"] == spec["remove"] and plant["id_from"] == spec["id_from"]
         and plant["fields"] == list(spec["fields"]), "property operations or ordered selectors differ from the native registry")
    return spec


def oracle_roles(contract):
    # Cleanup has a separately recorded outcome and does not decide exposure.
    steps = {flow["id"]: flow["principal"] for flow in contract["flows"] if flow["id"] != "C"}
    identities = [flow["id"] for flow in contract["flows"] if flow["action"] == "identity_probe"]
    need(tuple(steps) == tuple(step for step in contract["required_flows"] if step != "C"),
         "frozen oracle step order differs")
    return steps, identities


def parse_json(data):
    def no_duplicates(pairs):
        obj = dict(pairs)
        need(len(obj) == len(pairs), "duplicate JSON key")
        return obj

    def reject_constant(value):
        raise ValueError(f"invalid JSON constant: {value}")

    return json.loads(data.decode("utf-8"), object_pairs_hook=no_duplicates,
                      parse_constant=reject_constant)


class Evidence:
    def __init__(self, root, monitor_key=None):
        self.root = root.resolve(strict=True)
        self.monitor_key = monitor_key

    def read(self, ref, prefix=None):
        need(ref.keys() == {"path", "sha256"} and DIGEST.fullmatch(ref["sha256"]),
             "bad artifact reference")
        name = ref["path"]
        path = PurePosixPath(name)
        need(path.parts and not path.is_absolute() and ".." not in path.parts
             and path.as_posix() == name and (prefix is None or path.parts[0] == prefix),
             "artifact outside its evidence directory")
        current = self.root
        for part in path.parts:
            current /= part
            need(not current.is_symlink(), "symlink in artifact path")
        need(current.is_file() and current.stat().st_nlink == 1, "artifact is not a private regular file")
        data = current.read_bytes()
        need(digest(data) == ref["sha256"], "artifact digest mismatch")
        return data

    def json(self, ref, prefix=None):
        return parse_json(self.read(ref, prefix))

    def retained(self, ref, prefix):
        need(ref["path"].startswith(f"{prefix}/retained/artifacts/"),
             "source artifact is outside the settled inventory")
        return self.read(ref, prefix)


def argv(value):
    return isinstance(value, list) and bool(value) and all(
        isinstance(word, str) and "\0" not in word for word in value
    ) and bool(value[0])


def invocation(words):
    """Recognize the M1 CLI verb and attempted effect from the actual argv."""
    args = []
    skip = False
    for word in words[1:]:
        if "--" in args:
            args.append(word)
        elif skip:
            skip = False
        elif word in {"--workspace", "--engagement", "--format"}:
            skip = True
        elif word == "--json" or word.startswith(("--workspace=", "--engagement=", "--format=")):
            continue
        else:
            args.append(word)
    options = args[:args.index("--")] if "--" in args else args
    if not args:
        return "status", False
    if args[0] == "help" or "-h" in options or "--help" in options:
        return "help", False
    verb = args[0]
    if verb in {"lead", "run", "engagement"} and len(args) > 1:
        verb = " ".join(args[:2])
    mutating = (
        verb in {"init", "demo", "engagement add", "run reconcile",
                 "lead add", "lead set", "lead withdraw", "lead defer", "lead duplicate"}
        or verb == "verify" and "--plan" not in options
    )
    return verb, mutating


def verification_rounds(words, lead):
    """Bind the native live verify request to its one lead and round count."""
    remainder = iter(words[1:])
    positional = []
    rounds = None
    for word in remainder:
        flag, equal, inline = word.partition("=")
        if word == "--":
            positional.extend(remainder)
            break
        if word == "--json":
            continue
        if flag in {"--workspace", "--engagement", "--format", "--rounds"}:
            value = inline if equal else next(remainder, "")
            need(value and not value.startswith("--"), "verify argv has a missing or hidden option value")
            if flag == "--rounds":
                need(positional[:1] == ["verify"] and rounds is None and re.fullmatch(r"\+?[0-9]+", value),
                     "verify argv has duplicate, misplaced or malformed --rounds")
                rounds = int(value)
                need(0 < rounds <= MAX_NATIVE_COUNT, "verify argv --rounds is outside the supported range")
            continue
        need(not word.startswith("-"), "verify argv has an unexpected or hidden option")
        positional.append(word)
    need(positional == ["verify", lead], "verify argv does not name the exact lead and supported live options")
    return DEFAULT_VERIFY_ROUNDS if rounds is None else rounds


def require_shape(value, required, optional=()):
    need(isinstance(value, dict) and set(required) <= value.keys() <= {*required, *optional},
         "malformed native engagement declaration shape")


def nonempty_string(value):
    return isinstance(value, str) and bool(value.strip())


def safe_prose(value):
    return (isinstance(value, str) and 0 < len(value) <= 4096 and value == value.strip()
            and not value.startswith("\ufeff") and not value.endswith("\ufeff")
            and not any(ord(char) < 32 or ord(char) == 127 for char in value)
            and not FORBIDDEN_PROSE.search(value))


def registered(value, kind):
    return isinstance(value, str) and re.fullmatch(rf"{kind}(?:\.[a-z0-9][a-z0-9-]{{0,31}}){{1,6}}", value)


def qualified_manifest(data):
    manifest = parse_json(data)
    base = {"revision", "source_digest", "pass_digest", "declaration"}
    need(isinstance(manifest, dict) and base <= manifest.keys() <= base | {"parent"}
         and data == native_bytes(manifest), "not a canonical native engagement manifest")
    revision = manifest["revision"]
    need(type(revision) is int and 0 < revision < 2**64
         and DIGEST.fullmatch(manifest["source_digest"]) and DIGEST.fullmatch(manifest["pass_digest"])
         and (revision == 1 and "parent" not in manifest
              or revision > 1 and DIGEST.fullmatch(manifest.get("parent") or "")
              and manifest["parent"] != digest(data)),
         "invalid native engagement manifest revision, parent or source/pass pin")
    declaration = manifest["declaration"]
    require_shape(declaration, {"schema_version", "engagement", "principal", "property"})
    need(declaration["schema_version"] == "scourge.engagement.v1", "wrong native engagement declaration schema")
    settings = declaration["engagement"]
    need(isinstance(declaration["principal"], dict) and isinstance(declaration["property"], dict),
         "native principals and properties must be maps")
    require_shape(settings, {"objective", "pass", "instrument", "target_version", "required_custody",
                             "required_enforcement", "allow_effects", "audience"},
                  {"max_verify_runs", "retest_miss_threshold"})
    require_shape(settings["instrument"], {"kind", "project"})
    effects = settings["allow_effects"]
    need(safe_prose(settings["objective"]), "unsafe objective in native engagement declaration")
    need(registered(settings["pass"], "pass")
         and registered(settings["target_version"], "version")
         and settings["instrument"]["kind"] == "teapot" and registered(settings["instrument"]["project"], "project")
         and settings["required_custody"] in {"shared", "isolated"}
         and settings["required_enforcement"] in {"none", "egress"} and settings["audience"] in {"internal", "third_party"}
         and isinstance(effects, list) and len(effects) == len(set(effects)) > 0
         and set(effects) <= {"observe", "plant", "mutate"}
         and ("max_verify_runs" not in settings
              or type(settings["max_verify_runs"]) is int and 0 < settings["max_verify_runs"] < 2**53)
         and ("retest_miss_threshold" not in settings
              or type(settings["retest_miss_threshold"]) in {int, float} and 0 < settings["retest_miss_threshold"] < 1),
         "invalid native engagement settings")
    sessions = set()
    for name, principal in declaration["principal"].items():
        require_shape(principal, {"session", "identity_probe"}, {"verifier_session", "groups"})
        require_shape(principal["identity_probe"], {"operation", "subject"})
        need(re.fullmatch("[a-z][a-z0-9_]{0,63}", name) and not FORBIDDEN_PROSE.search(name)
             and registered(principal["identity_probe"]["operation"], "operation")
             and registered(principal["identity_probe"]["subject"], "selector"), "invalid declared identity probe")
        if "groups" in principal:
            groups = principal["groups"]
            need(isinstance(groups, list) and len(groups) == len(set(groups)) > 0
                 and all(registered(group, "group") for group in groups), "invalid declared principal groups")
        for field in ("session", "verifier_session"):
            if field in principal:
                reference = principal[field]
                need(registered(reference, "session") and reference not in sessions,
                     "invalid or duplicate declared session reference")
                sessions.add(reference)
    for name, prop in declaration["property"].items():
        require_shape(prop, {"resource", "read", "plant", "remove", "policy"}, {"write", "readers", "writers"})
        need(re.fullmatch("[a-z][a-z0-9_]{0,63}", name) and not FORBIDDEN_PROSE.search(name)
             and all(registered(prop[key], kind) for key, kind in (("resource", "resource"),
                     ("read", "operation"), ("remove", "operation")))
             and safe_prose(prop["policy"]) and ("writers" not in prop or "write" in prop),
             "invalid declared property")
        for field in ("readers", "writers"):
            if field in prop:
                need(prop[field] in {"owner", "group", "authenticated", "public"}, "invalid declared audience")
        for field in ("plant", "write"):
            if field in prop:
                operation = prop[field]
                required = {"operation", "fields", "id_from"} if field == "plant" else {"operation", "fields"}
                require_shape(operation, required)
                selectors = operation["fields"]
                need(registered(operation["operation"], "operation")
                     and (field != "plant" or registered(operation["id_from"], "selector"))
                     and isinstance(selectors, list) and len(selectors) == len(set(selectors)) > 0
                     and all(registered(selector, "selector") for selector in selectors),
                     "invalid declared property operation")
    need(declaration["principal"] and declaration["property"], "empty native engagement declaration")
    return manifest


def check_manifest_admission(evidence, assignment):
    manifest = qualified_manifest(evidence.read(assignment["manifest"]))
    source = assignment["manifest_source"]
    pass_artifact = assignment["pass_artifact"]
    need(source["sha256"] == manifest["source_digest"] and pass_artifact["sha256"] == manifest["pass_digest"]
         and evidence.read(pass_artifact), "native manifest source/pass digests differ from protected admission")
    data = evidence.read(source)
    declaration = parse_json(data) if data.lstrip().startswith(b"{") else tomllib.loads(data.decode())
    need(declaration == manifest["declaration"], "admitted declaration bytes differ from the manifest")
    settings = declaration["engagement"]
    need(settings["required_custody"] == "shared" and settings["required_enforcement"] == "none"
         and settings["audience"] == "internal" and {"plant", "observe"} <= set(settings["allow_effects"]),
         "admitted engagement requirements do not match M1 custody, enforcement, audience and effects")
    history = assignment["manifest_history"]
    need(isinstance(history, list) and len(history) == manifest["revision"] - 1,
         "frozen manifest history does not fill the native revisions")
    previous = None
    for revision, ref in enumerate([*history, assignment["manifest"]], 1):
        current = qualified_manifest(evidence.read(ref))
        need(current["revision"] == revision and current.get("parent") == previous,
             "frozen manifest ancestry does not match the native parent digest")
        previous = ref["sha256"]
    prepared_manifest_capture(evidence, assignment)


def check_discovery_review(evidence, assignment, frozen):
    review = evidence.json(assignment["discovery_review"])
    need(review["schema"] == DISCOVERY_REVIEW and review["source"] == "fixture-referee"
         and review["attempt_id"] == assignment["attempt_id"]
         and review["manifest_sha256"] == assignment["manifest"]["sha256"]
         and review["prompt_sha256"] == frozen["prompts"]["discovery"]["sha256"]
         and review["hints"] == [], "discovery lacks independent review of case-specific hints")
    inputs = review["visible_inputs"]
    hashes = {path: digest(evidence.read(ref)) for path, ref in inputs.items()}
    need(hashes == assignment["visible"], "discovery review differs from the exact visible workspace bytes")


def check_assignment(frozen, evidence):
    need(frozen["schema"] == ASSIGNMENT and set(frozen["cells"]) == set(CELLS),
         "expected exactly the four frozen cells")
    attempts = [row["attempt_id"] for row in frozen["cells"].values()]
    need(len(set(attempts)) == len(CELLS) and all(LOCAL_ID.fullmatch(key) for key in attempts),
         "frozen attempt IDs must be distinct")
    pins = frozen["pins"]
    for key in ("model_settings_sha256", "harness_sha256", "fixture_sha256", "scourge_sha256", "teapot_sha256",
                "investigation_sha256",
                "process_monitor_sha256", "process_monitor_key_sha256"):
        need(DIGEST.fullmatch(pins[key]), f"bad {key} pin")
    investigation_path = Path(pins["investigation_exec_path"])
    need(investigation_path.is_absolute() and investigation_path.as_posix() == pins["investigation_exec_path"]
         and ".." not in investigation_path.parts, "missing or invalid frozen Investigation executable")
    need(len({pins[f"{tool}_sha256"] for tool in ("scourge", "teapot", "investigation")}) == 3,
         "frozen native executables must have distinct identities")
    need(pins["teapot_sha256"] == HISTORICAL_TEAPOT_SHA256,
         "frozen Teapot executable differs from the historical verifier pin")
    need(pins["investigation_sha256"] == investigation_identity()["binary_sha256"],
         "frozen Investigation executable differs from the native qualified identity")
    need(isinstance(pins["model"], str) and pins["model"].strip(), "missing model pin")
    oracle = pins["oracle"]
    need(oracle == {"id": ORACLE_ID, "version": ORACLE_VERSION, "digest": native_digest(oracle_contract())},
         "oracle pin does not match the frozen contract")
    need(pins["operation_registry"] == registry_pin(), "operation registry pin differs from the native contract")
    need(set(frozen["prompts"]) == {"supplied", "discovery", "concept"}, "bad frozen prompt set")
    prompts = {key: evidence.read(ref) for key, ref in frozen["prompts"].items()}
    for key, data in prompts.items():
        need(data == (MATERIALS / f"{key}.txt").read_bytes(), f"frozen {key} prompt differs from the checked-in prompt")
    guide = evidence.read(frozen["managed_block"])
    start, marker, body = guide.split(b"\n", 2)
    end = b"<!-- scourge:managed-end -->\n"
    need(start == b"<!-- scourge:managed-start -->" and body.endswith(end)
         and body[:-len(end)] == (REPOSITORY / "crates/scourge-core/src/workspace/managed-guide.md").read_bytes()
         and marker == f"<!-- scourge:managed-sha256 {digest(body[:-len(end)])} -->".encode(),
         "managed guide block has the wrong bytes or body digest")
    need(set(frozen["cases"]) == {*CASES, "f37"}, "bad frozen case set")
    for case, spec in frozen["cases"].items():
        need(spec["property"]["id"] and DIGEST.fullmatch(spec["property"]["digest"]), "bad property pin")
        if case not in INVALID:
            need(spec["exposure"] in {"unauthenticated", "cross_principal"}, "bad exposure")
    need(frozen["cases"]["f37"]["exposure"] == "unauthenticated", "wrong F-37 exposure")
    workspace_ids = set()
    for track in ("supplied", "discovery"):
        executable = frozen["cells"][f"executable/{track}"]
        managed = frozen["cells"][f"managed/{track}"]
        for slot in (executable, managed):
            lead = slot["supplied_lead"]
            need(isinstance(lead, str) and re.fullmatch(r"L-[A-Za-z0-9_-]+", lead)
                 if track == "supplied" else lead is None, "bad supplied lead assignment")
            config = slot["workspace_config"]
            native_config = NATIVE_WORKSPACE_CONFIG.fullmatch(evidence.read(config))
            need(slot["visible"].get(WORKSPACE_CONFIG) == config["sha256"] and native_config,
                 "visible workspace configuration is not the frozen native config")
            workspace_id = native_config["workspace_id"]
            need(workspace_id not in workspace_ids, "frozen native workspace IDs must be distinct")
            workspace_ids.add(workspace_id)
        if track == "supplied":
            need(executable["supplied_lead"] != managed["supplied_lead"], "frozen supplied lead IDs must be distinct")
        executable_files, managed_files = executable["visible"], managed["visible"]
        need("AGENTS.md" not in executable_files and managed_files.keys() == executable_files.keys() | {"AGENTS.md"}
             and managed_files["AGENTS.md"] == digest(guide)
             and all(managed_files[path] == sha for path, sha in executable_files.items()
                     if path not in WORKSPACE_LOCAL_FILES),
             "frozen workspaces differ beyond native workspace state and the managed guide")
        for path, sha in (*executable_files.items(), *managed_files.items()):
            pure = PurePosixPath(path)
            need(pure.parts and pure.as_posix() == path and not pure.is_absolute()
                 and ".." not in pure.parts and DIGEST.fullmatch(sha), "bad visible file inventory")
    need(frozen["f37"]["supplied_lead"] and LOCAL_ID.fullmatch(frozen["f37"]["attempt_id"])
         and frozen["f37"]["attempt_id"] not in attempts, "bad scripted F-37 assignment")
    reset_ids = set()
    for name, row in (*frozen["cells"].items(), ("f37", frozen["f37"])):
        teapot_path = Path(row["teapot_exec_path"])
        need(teapot_path.is_absolute() and teapot_path.as_posix() == row["teapot_exec_path"]
             and teapot_path.name == "teapot" and ".." not in teapot_path.parts,
             "missing or invalid frozen prepared Teapot executable path")
        check_manifest_admission(evidence, row)
        reset_id = row["reset_id"]
        need(LOCAL_ID.fullmatch(reset_id) and reset_id not in reset_ids, "missing or reused prepared fixture reset ID")
        reset_ids.add(reset_id)
        expected = {"f37"} if name == "f37" else {*CASES, "f37"}
        need(set(row["session_access"]) == expected, "missing frozen per-case session access pins")
        if name.endswith("/discovery"):
            check_discovery_review(evidence, row, frozen)


def check_preflight(receipt, evidence, attempt_id):
    preflight = receipt["preflight"]
    run_root = Path(preflight["run_root"])
    checkout = Path(preflight["checkout"])
    need(preflight["schema"] == "scourge.trial-capture-preflight"
         and type(preflight["schema_version"]) is int and preflight["schema_version"] == 1
         and preflight["reasons"] == [] and run_root.is_absolute() and checkout.is_absolute()
         and run_root.as_posix() == preflight["run_root"] and checkout.as_posix() == preflight["checkout"]
         and ".." not in (*run_root.parts, *checkout.parts) and isinstance(preflight["exclude_roots"], list)
         and not run_root.is_relative_to(checkout) and not checkout.is_relative_to(run_root),
         "missing typed external capture preflight")
    probe = preflight["write_probe"]
    need(type(probe["bytes_written"]) is int and probe["bytes_written"] == len(b"scourge capture preflight\n")
         and all(probe[field] is True for field in ("flushed", "file_synced", "unlinked", "directory_synced")),
         "incomplete filesystem write probe")
    for group, identity in (
        ("root", preflight["root_identity"]), ("trial", receipt["trial_identity"])
    ):
        need(all(type(identity[field]) is int and identity[field] >= 0
                 for field in ("device", "inode", "owner_uid"))
             and identity["inode"] > 0 and identity["mode"] == 0o700, f"invalid {group} directory identity")
    need(preflight["root_identity"]["owner_uid"] == receipt["trial_identity"]["owner_uid"]
         and receipt["trial_id"] == attempt_id, "preflight and trial identity differ")
    for unit in ("bytes", "inodes"):
        floor, available = (preflight["capacity"][f"{key}_{unit}"] for key in ("minimum", "available"))
        need(type(floor) is int and type(available) is int and available >= floor > 0,
             "invalid run-root capacity measurement")
    # Artifacts may be replayed from a copy. A receipt at its original location
    # must still match the directory identities observed by preflight.
    if evidence.root == run_root:
        for path, identity in ((evidence.root, preflight["root_identity"]),
                               (evidence.root / attempt_id, receipt["trial_identity"])):
            info = path.stat()
            need((info.st_dev, info.st_ino, info.st_uid, info.st_mode & 0o777) ==
                 (identity["device"], identity["inode"], identity["owner_uid"], identity["mode"]),
                 "preflight directory identity changed")


def check_inventory(evidence, attempt_id, rows):
    root = evidence.root / attempt_id / "retained"
    names = {}
    for path in root.rglob("*"):
        need(not path.is_symlink(), "symlink in retained inventory")
        names[path.relative_to(root).as_posix()] = "directory" if path.is_dir() else "file"
    expected = {row["path"]: row["type"] for row in rows}
    need(names == expected and {"raw", "raw/transcript.jsonl", "raw/worker.stderr", "artifacts"} <= names.keys(),
         "retained inventory differs from the actual file tree")
    for row in rows:
        if row["type"] == "file":
            retained = evidence.read({"path": f'{attempt_id}/retained/{row["path"]}',
                                      "sha256": row["sha256"]}, attempt_id)
            need(len(retained) == row["bytes"], "retained artifact byte count differs")
        else:
            need(row["type"] == "directory" and row["bytes"] == 0 and row["sha256"] is None,
                 "invalid retained inventory entry")


def check_capture(evidence, entry):
    attempt_id = entry["attempt_id"]
    need(entry["capture"]["path"] == f"{attempt_id}/capture.json", "capture receipt is misplaced")
    capture = evidence.json(entry["capture"], attempt_id)
    need(capture["schema"] == "scourge.trial-capture" and type(capture["schema_version"]) is int
         and capture["schema_version"] == 1,
         "unsupported capture receipt")
    need(capture["trial_id"] == attempt_id, "capture trial ID mismatch")
    need(capture["status"] == "settled" and capture["settled"] is True
         and capture["valid"] is True and capture["score"] is None
         and capture["reasons"] == [] and capture["preflight"]["passed"] is True,
         "invalid or unsettled capture")
    process = capture["process"]
    checks = capture["checks"]
    need(process["worker_stopped"] is True and process["interrupted"] is False
         and type(process["exit_code"]) is int and process["exit_code"] == 0
         and checks["safety_ok"] is True and checks["boundary_ok"] is True,
         "capture is missing successful process, safety or boundary settlement")
    check_preflight(capture, evidence, attempt_id)
    inv = capture["inventory"]
    rows = inv["retained"]
    need(inv["complete"] is True and inv["verified"] is True and inv["source"] == rows
         and inv["retained_sha256"] == inv["source_sha256"] == digest(canonical(rows)),
         "unverified capture inventory")
    names = [row["path"] for row in rows]
    need(names == sorted(set(names)), "duplicate or unordered retained inventory")
    raw = entry["raw"]
    expected_path = f"{attempt_id}/retained/raw/transcript.jsonl"
    need(raw["path"] == expected_path, "raw transcript is outside its canonical location")
    matches = [row for row in rows if row["path"] == "raw/transcript.jsonl"]
    data = evidence.read(raw, attempt_id)
    need(matches == [{"path": "raw/transcript.jsonl", "type": "file", "bytes": len(data),
                      "sha256": raw["sha256"]}] and data, "raw transcript is not in the retained inventory")
    summary = capture["events"]
    terminal = capture["terminal_event_type"]
    lines = data.split(b"\n")
    event_lines = [(number, line) for number, line in enumerate(lines, 1) if line.strip(b" \t\r")]
    need(event_lines and event_lines[-1][0] < len(lines) and summary["issues"] == []
         and summary["valid_prefix_sha256"] == raw["sha256"]
         and summary["valid_prefix_bytes"] == len(data)
         and summary["valid_prefix_events"] == len(event_lines)
         and summary["terminal_line"] == event_lines[-1][0], "unsettled event stream")
    native = [parse_json(line) for _, line in event_lines]
    kinds = [event["type"] for event in native]
    need(all(isinstance(kind, str) and kind.strip() for kind in kinds)
         and kinds[-1] == terminal and kinds.count(terminal) == 1, "missing or misplaced terminal event")
    check_inventory(evidence, attempt_id, rows)
    return evidence.json(entry["referee"], attempt_id), native


def check_trial(evidence, frozen, cell, entry, referee, assignment_digest, native):
    attempt_id = entry["attempt_id"]
    host, track = cell.split("/")
    assignment = frozen["cells"][cell]
    need(referee["schema"] == REVIEW and referee["source"] == "referee"
         and referee["assignment_sha256"] == assignment_digest
         and referee["capture_sha256"] == entry["capture"]["sha256"]
         and referee["raw_sha256"] == entry["raw"]["sha256"]
         and (referee["cell"], referee["attempt_id"], referee["pins"])
         == (cell, attempt_id, frozen["pins"]), "referee attestation does not bind the assignment and capture")
    context = parse_json(evidence.retained(referee["context"], attempt_id))
    need(context["prompt"]["sha256"] == frozen["prompts"][track]["sha256"],
         "task prompt differs from frozen bytes")
    prompt = evidence.read(context["prompt"], attempt_id)
    need(context["source"] == "host" and LOCAL_ID.fullmatch(context["session_id"])
         and [event["thread_id"] for event in native if event["type"] == "thread.started"]
         == [context["session_id"]]
         and context["fresh"] is True and context["visible"] == assignment["visible"]
         and context["interventions"] == [] and context["unexpected_context"] == []
         and context["supplied_lead"] == assignment["supplied_lead"],
         "cold-start context, workspace inventory or interventions differ from the assignment")
    if track == "discovery":
        need(context["discovery_hint_free"] is True, "discovery input singles out a case")
    loaded = context["loaded_project_context"]
    if host == "managed":
        need(len(loaded) == 1 and loaded[0]["sha256"] == frozen["managed_block"]["sha256"],
             "exact managed guide was not loaded")
        evidence.read(loaded[0], attempt_id)
    else:
        need(loaded == [], "executable session loaded project instructions")
    check_boundary(evidence, referee["boundary"], assignment, context["session_id"])
    return context["session_id"], prompt


def check_boundary(evidence, ref, assignment, session_id):
    boundary = parse_json(evidence.retained(ref, assignment["attempt_id"]))
    need(boundary["qualified"] is True and boundary["target_reset"] is True
         and boundary["live_environment_unchanged"] is True
         and boundary["source"] == "referee" and boundary["session_id"] == session_id
         and boundary["reset_id"] == assignment["reset_id"]
         and boundary["prepared_access"] is True, "unqualified boundary, reset or prepared access")
    need(set(boundary["denied"]) == CUSTODY_BOUNDARY and all(
        row == {"read": True, "write": True} for row in boundary["denied"].values()
    ), "referee materials remained reachable")


def command_items(native):
    items = [event["item"] for event in native if event["type"] == "item.completed"
             and event["item"]["type"] == "command_execution"]
    need(len({item["id"] for item in items}) == len(items), "duplicate native command item")
    return items


def direct_scourge_argv(item):
    """Cross-check simple command lines independently of process attribution."""
    try:
        words = shlex.split(item["command"])
        source = item["command"]
        if len(words) == 3 and Path(words[0]).name in {"bash", "sh"} and words[1] in {"-c", "-lc"}:
            source = words[2]
            if any(marker in source for marker in ("$", "`", "\\", "\n", "*", "?", "[", "~", "!")):
                return None
        lexer = shlex.shlex(source, posix=True, punctuation_chars=True)
        lexer.whitespace_split = True
        words = list(lexer)
    except ValueError:
        return None  # The authenticated trace remains authoritative for malformed shell text.
    if any(word and set(word) <= set(";&|<>()") for word in words):
        return None
    if words[:2] == ["command", "--"]:
        words = words[2:]
    elif words[:1] == ["command"] and len(words) > 1 and not words[1].startswith("-"):
        words = words[1:]
    return words if words and Path(words[0]).name == "scourge" else None


def check_host_trace(evidence, entry, referee, session_id, pins, native, assignment_digest, prompt):
    key = evidence.monitor_key
    need(isinstance(key, bytes) and len(key) == 32 and hmac.compare_digest(
        digest(key), pins["process_monitor_key_sha256"]), "missing or incorrect frozen host trace key")
    need("host_trace" in referee, "missing authenticated host process trace")
    envelope = parse_json(evidence.retained(referee["host_trace"], entry["attempt_id"]))
    trace = envelope["trace"]
    mac = envelope["hmac_sha256"]
    need(isinstance(mac, str) and DIGEST.fullmatch(mac)
         and hmac.compare_digest(mac, host_trace_mac(trace, key)), "invalid host process trace authentication")
    need(trace["schema"] == HOST_TRACE and trace["attempt_id"] == entry["attempt_id"]
         and trace["assignment_sha256"] == assignment_digest and trace["session_id"] == session_id
         and trace["raw_sha256"] == entry["raw"]["sha256"]
         and trace["monitor_sha256"] == pins["process_monitor_sha256"],
         "authenticated host process trace does not bind this assignment and capture")
    prompt_sha256 = trace.get("prompt_sha256")
    prompt_size = trace.get("prompt_size_bytes")
    need(isinstance(prompt_sha256, str) and DIGEST.fullmatch(prompt_sha256)
         and type(prompt_size) is int and prompt_size > 0
         and (prompt is None or (prompt_sha256, prompt_size) == (digest(prompt), len(prompt))),
         "authenticated launch stdin differs from the frozen and observed prompt")
    need(trace["drained"] is True and type(trace["lost_events"]) is int and trace["lost_events"] == 0,
         "authenticated host process trace is incomplete")
    items = command_items(native)
    commands = trace["commands"]
    need([row["native_item"] for row in commands] == [item["id"] for item in items],
         "authenticated trace does not cover every native command item")
    for row, item in zip(commands, items):
        need(row["tree_closed"] is True and type(row["lost_events"]) is int and row["lost_events"] == 0
             and type(row["exit_code"]) is int and row["exit_code"] == item["exit_code"],
             "native command lacks complete host tree settlement")
    elapsed = trace["elapsed_milliseconds"]
    need(type(elapsed) is int and elapsed >= 0, "missing authenticated process timing")
    return items, commands, elapsed


def load_calls(evidence, entry, referee, session_id, pins, native, assignment_digest, prompt=None):
    prefix = entry["attempt_id"]
    events = parse_json(evidence.retained(referee["events"], prefix))
    need(events["source"] == "process-monitor" and events["session_id"] == session_id
         and events["raw_sha256"] == entry["raw"]["sha256"] and events["complete"] is True,
         "incomplete or unrelated process accounting")
    items, commands, elapsed = check_host_trace(
        evidence, entry, referee, session_id, pins, native, assignment_digest, prompt)
    need(events["commands"] == commands and events["elapsed_milliseconds"] == elapsed,
         "process projection differs from the authenticated host trace")
    calls = []
    native_items = {item["id"]: item for item in items}
    attributed = []
    executions = {}
    command_execs = {}
    for command in commands:
        item = native_items[command["native_item"]]
        output = item["aggregated_output"].encode()
        need(command["command"] == item["command"] and command["output_sha256"] == digest(output)
             and type(item["exit_code"]) is int and item["status"] in {"completed", "failed"},
             "process monitor does not match the native command item")
        processes = command["executions"]
        need(isinstance(processes, list), "missing retained exec records")
        command_execs[item["id"]] = processes
        process_ids = [proc["process_id"] for proc in processes]
        need(all(type(pid) is int and pid > 0 for pid in process_ids)
             and len(process_ids) == len(set(process_ids)), "invalid process attribution")
        for proc in processes:
            words = proc["argv"]
            binary = proc["binary_sha256"]
            path = Path(proc["exec_path"])
            need(argv(words) and DIGEST.fullmatch(binary) and path.is_absolute()
                 and path.as_posix() == proc["exec_path"] and ".." not in path.parts
                 and type(proc["exit_code"]) is int and -255 <= proc["exit_code"] <= 255,
                 "invalid retained executable path, argv or process exit")
            role = proc.get("role")
            if binary == HISTORICAL_TEAPOT_SHA256 or role in {TEAPOT_PREPARATION_ROLE, TEAPOT_VERIFIER_ROLE}:
                # The collector identifies staged preparation by direct exec and the bound verifier by fd exec.
                bound = BOUND_EXEC.fullmatch(proc["exec_path"])
                expected_role = TEAPOT_VERIFIER_ROLE if bound else TEAPOT_PREPARATION_ROLE
                need(binary == HISTORICAL_TEAPOT_SHA256 and role == expected_role
                     and (bound or proc["exec_path"] == words[0]),
                     "authenticated historical Teapot executable has the wrong preparation or verifier role")
            pinned = binary == pins["scourge_sha256"]
            need(pinned or all(name != "scourge" for name in (Path(words[0]).name, path.name)),
                 "argv or path claims Scourge without the pinned executable")
            if pinned:
                key = (item["id"], proc["process_id"])
                attributed.append(key)
                executions[key] = proc
    need([(row["native_item"], row["process_id"]) for row in events["calls"]] == attributed,
         "process receipts do not account for the native Scourge calls in order")
    by_item = {}
    spans = {}
    for number, row in enumerate(events["calls"], 1):
        item = native_items[row["native_item"]]
        proc = executions[(item["id"], row["process_id"])]
        need(type(row["number"]) is int and row["number"] == number and argv(row["argv"])
             and row["binary_sha256"] == pins["scourge_sha256"]
             and proc["argv"] == row["argv"],
             "bad invocation order, argv or binary")
        data = evidence.retained(row["stdout"], prefix)
        need(type(proc["stdout_bytes"]) is int and proc["stdout_bytes"] == len(data)
             and proc["stdout_sha256"] == digest(data), "process output differs from authenticated stdout")
        # A pipe, redirect, or interleaved command can lack a trustworthy
        # contiguous span in the native aggregated output. The host still
        # attests the exact retained per-process bytes above.
        start = proc["stdout_offset"]
        if start is not None:
            output = item["aggregated_output"].encode()
            need(type(start) is int and 0 <= start <= len(output), "invalid authenticated native stdout offset")
            end = start + len(data)
            need(end <= len(output) and output[start:end] == data,
                 "direct process output differs from its authenticated native span")
            if end > start:
                spans.setdefault(item["id"], []).append((start, end))
        by_item.setdefault(item["id"], []).append(row["argv"])
        response = None
        if data.lstrip().startswith(b"{"):
            try:
                parsed = parse_json(data)
            except ValueError:
                pass  # A malformed response still consumes a call.
            else:
                if isinstance(parsed, dict) and parsed.get("schema") == "scourge.response.v1":
                    response = parsed
        verb, mutating = invocation(row["argv"])
        calls.append({**row, "format": "json" if response is not None else row["format"], "verb": verb,
                      "mutating": mutating, "reply": response, "bytes": len(data),
                      "exit_code": proc["exit_code"], "exec_path": proc["exec_path"],
                      "execution": proc, "command_execs": command_execs[item["id"]]})
    for ranges in spans.values():
        ordered = sorted(ranges)
        need(all(left[1] <= right[0] for left, right in zip(ordered, ordered[1:])),
             "authenticated native stdout spans overlap")
    for item in items:
        direct = direct_scourge_argv(item)
        if direct is not None:
            need(by_item.get(item["id"]) == [direct], "direct native Scourge invocation is missing or differs")
    return calls, elapsed


def retained_body(flow, side):
    info = flow[f"{side}_body_info"]
    need(info["decoding"] == "as-stored" and isinstance(flow[f"{side}_head"], str),
         "missing native body capture shape")
    encoded = flow.get(f"{side}_body_base64")
    if (side == "response" and info["capture"] == "none" and encoded is None
            and info["captured"] == info["shown"] == 0 and info["whole"] is False):
        status = flow["status"]
        if flow["method"] == "HEAD" or status in (204, 304) or type(status) is int and 100 <= status < 200:
            return b""
    need(isinstance(encoded, str), "native complete body bytes are absent")
    body = b64decode(encoded, validate=True)
    need(info["capture"] == "complete" and info["whole"] is True and info["decoding"] == "as-stored"
         and info["shown"] == info["captured"] == len(body)
         and (info["observed"] is None or info["observed"] >= len(body)), "incomplete retained flow body")
    return body


def http_headers(head):
    lines = [line.removesuffix("\r") for line in head.split("\n")]
    while lines and not lines[-1]:
        lines.pop()
    need(lines and lines[0] and not any(line.startswith((" ", "\t")) for line in lines[1:]),
         "missing or ambiguous native HTTP head")
    headers = {}
    for line in lines[1:]:
        name, separator, value = line.partition(":")
        need(separator and re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name),
             "invalid native HTTP header")
        headers.setdefault(name.lower(), []).append(value.strip())
    return headers


def session_digest(flow):
    """Identify the development fixture's authentication without exposing its cookie."""
    headers = http_headers(flow["request_head"])
    need("authorization" not in headers, "unqualified fixture authentication mechanism")
    sessions = []
    for header in headers.get("cookie", []):
        for item in header.split(";"):
            name, _, value = item.strip().partition("=")
            if name == SESSION_COOKIE:
                need(re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", value),
                     "malformed or redacted fixture session credential")
                sessions.append(value)
    need(len(sessions) <= 1, "ambiguous fixture session credential")
    return digest(sessions[0].encode()) if sessions else None


def decompress(body, coding, maximum):
    payload = bytearray()
    header = body[:2]
    zlib_header = (len(header) == 2 and header[0] & 15 == 8 and header[0] >> 4 <= 7
                   and int.from_bytes(header, "big") % 31 == 0)
    mode = 31 if coding == "gzip" else 15 if zlib_header else -15
    remaining = body
    while remaining:
        stream = zlib.decompressobj(mode)
        try:
            payload.extend(stream.decompress(remaining, maximum - len(payload) + 1))
        except zlib.error as error:
            raise ValueError("invalid retained compressed body") from error
        need(len(payload) <= maximum and stream.eof and not stream.unconsumed_tail,
             "truncated or oversized retained compressed body")
        remaining = stream.unused_data
        if coding != "gzip":
            need(not remaining, "trailing retained deflate bytes")
    need(body, "empty retained compressed stream")
    return bytes(payload)


def json_string_payload(body):
    value = parse_json(body)
    document = next(iter(value.values())) if isinstance(value, dict) and len(value) == 1 else value
    return document.encode() if isinstance(document, str) else None


def decoded_response(flow, decoder):
    limits = decoder["limits"]
    maximum, ratio = limits["max_decoded_bytes"], limits["max_expansion_ratio"]
    need(type(maximum) is int and maximum >= 0 and type(ratio) is int and ratio >= 0,
         "unqualified HTTP decoder bounds")
    maximum = min(maximum, 16 * 1_048_576)
    ratio = min(ratio, 10_000)
    body = retained_body(flow, "response")
    initial = len(body)
    headers = http_headers(flow["response_head"])

    def header(name):
        values = headers.get(name, [""])
        need(len(values) == 1, "ambiguous retained HTTP coding")
        return values[0].lower()

    # The native verification-record reader receives body bytes after Teapot
    # removes transfer coding. Replay content coding only, even when the
    # retained response head still contains Transfer-Encoding: chunked.
    coding = header("content-encoding")
    if coding in {"gzip", "deflate"}:
        limit = min(maximum, len(body) * ratio)
        body = decompress(body, coding, limit)
    else:
        need(coding in {"", "identity"}, "unsupported retained content coding")
    media = header("content-type").split(";", 1)[0].strip()
    if media == "application/json" or media.endswith("+json"):
        try:
            inner = json_string_payload(body)
            if inner is not None:
                # The native record adapter selects this stage only when the
                # string itself carries JSON. The decoding stage accepts text.
                parse_json(inner)
                body = inner
        except (ValueError, UnicodeError):
            pass  # An ordinary payload is neither a JSON wrapper nor a second decoding step.
    need(len(body) <= maximum and (not initial or len(body) <= initial * ratio),
         "decoded body exceeds its frozen bounds")
    return body


def linked_artifacts(reads, evidence, prefix):
    """Decode immutable instrument originals and bind them to each native round."""
    known = {}
    for item in reads:
        artifact, ref = item["artifact_id"], item["file"]
        need(artifact not in known, "duplicate retained evidence identity")
        value = parse_json(evidence.retained(ref, prefix))
        known[artifact] = (ref["sha256"], value)
    return known


def target_origin(url):
    parts = urlsplit(url)
    need(parts.scheme in {"http", "https"} and parts.hostname and parts.username is None
         and parts.password is None and not parts.fragment and parts.port != 0, "invalid native fixture URL")
    return f"{parts.scheme}://{parts.netloc}"


def request_matches_target(flow, origin):
    url = flow["url"]
    if target_origin(url) != origin:
        return False
    parts = urlsplit(url)
    path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    request = flow["request_head"].splitlines()[0].split()
    return (len(request) == 3 and request[0] == flow["method"]
            and request[1] in {url, path} and re.fullmatch(r"HTTP/[0-9]+(?:\.[0-9]+)?", request[2]))


def subject_digest_for(flow, field):
    subject = parse_json(retained_body(flow, "response"))[field]
    need(isinstance(subject, str) and subject, "native identity probe lacks a subject")
    return digest(subject.encode())


def native_session(reference):
    return reference.removeprefix("session.").replace(".", "_")


def prepared_access(evidence, assignment, case, record, experiment, declaration):
    access = evidence.json(assignment["session_access"][case])
    need(access["schema"] == PREPARED_ACCESS and access["source"] == "fixture-referee" and access["qualified"] is True
         and access["attempt_id"] == assignment["attempt_id"] and access["reset_id"] == assignment["reset_id"]
         and access["case"] == case and access["property"] == record["property"]
         and access["engagement"] == record["engagement"] and access["manifest_sha256"] == assignment["manifest"]["sha256"]
         and access["environment_kind"] == record["environment_kind"] and access["instrument"] == record["instrument"],
         "protected session access does not bind the assigned case, environment or reset")
    target = access["target"]
    need(target == record["target"]
         and set(target) == {"origin", "addresses", "tls_identity", "deployment_marker", "strength"}
         and target["origin"] == target_origin(target["origin"]) and isinstance(target["addresses"], list),
         "native target differs from the protected prepared fixture")
    for address in target["addresses"]:
        ip_address(address)
    declared = {
        principal[field]: principal["identity_probe"]
        for principal in declaration["principal"].values()
        for field in ("session", "verifier_session") if field in principal
    }
    bindings = access["bindings"]
    need(set(bindings) == set(declared), "protected access does not cover all declared native sessions")
    registry = operation_registry()
    identity = registry["identity"]
    probe = {key: identity[key] for key in ("operation", "subject")}
    probe_url = target["origin"] + identity["path"]
    credentials = set()
    probe_ids = set()
    for reference, binding in bindings.items():
        need(binding["native_session"] == native_session(reference)
             and binding["native_session"] != registry["anonymous_session"]
             and binding["identity_probe"] == declared[reference] == probe,
             "protected session reference or identity probe differs from the declaration")
        envelope = evidence.json(binding["original"])
        flow = envelope["flow"]
        need(flow["method"] == "GET" and flow["url"] == probe_url and flow["status"] == 200
             and request_matches_target(flow, target["origin"])
             and type(flow["id"]) is int and flow["id"] > 0 and flow["id"] not in probe_ids
             and flow["origin"] == "replay" and flow["state"] == "complete" and flow.get("selector") is None
             and flow.get("request_sent_head") is None and flow.get("response_sent_head") is None
             and not any(advice["type"] == "head-cut" for advice in envelope["advice"]),
             "unqualified native original for a protected identity probe")
        credential = session_digest(flow)
        need(credential and credential == binding["credential_sha256"] and credential not in credentials
             and subject_digest_for(flow, identity["json_field"]) == binding["subject_sha256"],
             "protected identity original does not corroborate the distinct session binding")
        credentials.add(credential)
        probe_ids.add(flow["id"])
    roles = {role: bindings[value["verifier_session"] or value["session"]]
             for role, value in experiment["principals"].items()}
    need(Path(access["pass_file"]).is_absolute(), "protected fixture does not bind the native pass file")
    return target["origin"], probe_url, roles, access["pass_file"]


def native_timestamp(value):
    match = re.fullmatch(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})", value)
    need(match is not None, "invalid native chronological timestamp")
    seconds, fraction, offset = match.groups()
    return (datetime.fromisoformat(seconds + offset).astimezone(timezone.utc),
            int((fraction or "").ljust(9, "0")))


def chronological_steps(round_row, roles):
    names = []
    for item in round_row["flows"]:
        parts = item["step"].split(".")
        group, kind = ".".join(parts[:-1]), parts[-1]
        need(group in roles or group in {"C.primary", "C.control"}, "unknown native round step")
        names.append((group, kind))
    groups = [(group, [kind for _, kind in entries]) for group, entries in groupby(names, key=lambda row: row[0])]
    ordered = [group for group, _ in groups]
    cleanup = ["C.primary", "C.control"]
    need(ordered == [*roles, *(group for group in cleanup if group in ordered)],
         "native chronological step groups are missing, reordered or shadowed")
    # The registered live dispatcher uses SendOptions::default() without
    # redirect following. Both admitted gates disallow session relogin.
    need(all(kinds == ["request"] for _, kinds in groups),
         "registered M1 dispatch has a repeated flow, relogin, retry or followed redirect")


def replay_round(round_row, known, case, decoder, roles, identity_steps, access, resource_spec):
    origin, probe_url, prepared_roles, _ = access
    need(round_row["phase"] == "verify", "wrong round phase")
    chronological_steps(round_row, roles)
    selected = {}
    role_requests = []
    used_ids = set()
    cleanup = []
    previous_id = 0
    previous_start = None
    for item in round_row["flows"]:
        if item["completeness"] != "complete":
            continue
        original = item["original"]
        expected_digest, envelope = known[original["artifact_id"]]
        flow = envelope["flow"]
        need(expected_digest == original["digest"]
             and type(item["flow_id"]) is int and item["flow_id"] == flow["id"] > 0
             and item["flow_id"] not in used_ids and flow["origin"] == "replay"
             and flow["state"] == "complete" and flow.get("selector") is None
             and not any(advice["type"] == "head-cut" for advice in envelope["advice"])
             and flow.get("request_sent_head") is None and flow.get("response_sent_head") is None,
             "retained original is unlinked, reused or inadmissible")
        need(request_matches_target(flow, origin), "retained request is outside the prepared fixture origin or URL")
        started = native_timestamp(flow["started_at"])
        need(item["flow_id"] > previous_id and (previous_start is None or started >= previous_start),
             "retained native flow IDs or timestamps do not establish dispatch order")
        previous_id, previous_start = item["flow_id"], started
        used_ids.add(item["flow_id"])
        contract, *segments = item["step"].split(".")
        if contract in roles and segments == ["request"]:
            selected[contract] = (item, flow)
            role_requests.append((contract, flow))
        if contract == "C":
            cleanup.append((segments[0], flow))
    need(tuple(selected) == tuple(roles), "retained round lacks complete ordered oracle steps")
    credentials = {step: session_digest(flow) for step, (_, flow) in selected.items()}
    role_credentials = {role: binding["credential_sha256"] for role, binding in prepared_roles.items()}
    role_credentials["anonymous"] = None
    need(credentials["I1"] and credentials["I2"] and credentials["I1"] != credentials["I2"],
         "identity probes lack distinct fixture session credentials")
    for step, flow in role_requests:
        need(session_digest(flow) == role_credentials[roles[step]], f"{step} used the wrong fixture session")
    for _, flow in cleanup:
        need(flow["method"] == "DELETE" and session_digest(flow) == role_credentials["owner"],
             "cleanup request did not use the owner session")
    for step, (_, flow) in selected.items():
        need(flow["method"] == ("POST" if step in {"P", "P2"} else "GET")
             and isinstance(flow["url"], str), "wrong oracle step request")
    identity_rows = {row["step"]: row for row in round_row["identities"]}
    need(len(round_row["identities"]) == len(identity_steps) and set(identity_rows) == set(identity_steps),
         "round lacks its four identity measurements")
    registry = operation_registry()
    subjects = {}
    for step in identity_steps:
        principal = roles[step]
        flow_reference, flow = selected[step]
        subject = subject_digest_for(flow, registry["identity"]["json_field"])
        identity = identity_rows[step]
        need(flow["url"] == probe_url and identity["subject_digest"] == subject == prepared_roles[principal]["subject_sha256"]
             and identity["principal"] == principal and identity["original"] == flow_reference["original"],
             "identity does not match its protected probe and retained step")
        subjects[step] = subject
    need(subjects["I1"] == subjects["I3"] and subjects["I2"] == subjects["I4"],
         "observed identity drift")
    need((subjects["I1"] == subjects["I2"]) == (case == "same_subject"),
         "native subjects do not establish the assigned case")

    objects, canaries = {}, {}
    declared_fields = set(resource_spec["fields"].values())
    collection = origin + resource_spec["collection"]
    for role, step in (("primary", "P"), ("control", "P2")):
        _, flow = selected[step]
        need(flow["url"] == collection, "plant request is outside the admitted fixture collection")
        object_id = parse_json(retained_body(flow, "response"))[registry["object_id_field"]]
        need(isinstance(object_id, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,256}", object_id),
             "invalid planted object")
        objects[role] = (flow["url"].rstrip("/") + "/" + object_id)
        request = parse_json(retained_body(flow, "request"))
        fields = [row for row in round_row["canaries"] if row["object"] == role]
        need({row["field"] for row in fields} == declared_fields and set(request) == declared_fields,
             "plant canaries do not cover every native declared field")
        canaries[role] = {}
        for row in fields:
            value = request[row["field"]]
            need(isinstance(value, str) and re.fullmatch("[0-9a-f]{32}", value)
                 and row["digest"] == digest(value.encode()) and row["field"] not in canaries[role],
                 "planted canary does not match the retained request")
            canaries[role][row["field"]] = value.encode()
    need(len(set((*canaries["primary"].values(), *canaries["control"].values()))) ==
         len(round_row["canaries"]) and objects["primary"] != objects["control"]
         and selected["P"][1]["url"] == selected["P2"][1]["url"], "invalid plant/control separation")
    need([role for role, _ in cleanup] == ["primary", "control"]
         and all(flow["url"] == objects[role] and type(flow["status"]) is int for role, flow in cleanup),
         "retained round lacks established cleanup evidence for both planted objects")
    hits = {}
    for step in ("F0", "F1", "F2", "F3", "F4"):
        row, flow = selected[step]
        need(flow["url"] == objects["control" if step == "F4" else "primary"]
             and row["decoder"] == decoder["identity"], "read step lacks its object or pinned decoder")
        body = decoded_response(flow, decoder)
        hits[step] = {field for field, marker in canaries["primary"].items() if marker in body}
    need(not hits["F4"], "primary canary leaked into the negative control")
    if case == "login":
        need(not hits["F1"], "native owner response does not establish OBSERVER_INVALID")
    else:
        need(hits["F1"], "owner observation is missing its primary canary")
    if case not in INVALID:
        crossed = hits["F0"] | hits["F2"] | hits["F3"]
        exposure = "unauthenticated" if hits["F0"] or hits["F3"] else "cross_principal"
        after = not hits["F0"] and bool(hits["F3"])
        need(crossed and round_row["fields_crossed"] == sorted(crossed)
             and round_row["exposure"] == exposure, "native bodies do not establish recorded exposure")
        need(round_row["after_owner_read"] is after, "retained bodies disagree with after_owner_read")
    else:
        need(round_row["exposure"] is None and round_row["after_owner_read"] is False
             and round_row["fields_crossed"] == [], "invalid round asserts an exposure")
    return [flow["status"] for _, flow in cleanup]


def check_experiment_bindings(experiment, record, declaration, prop):
    template = parse_json(CLAIM_TEMPLATE.read_bytes())
    slots = experiment["slots"]
    declarations = template["slots"]
    principals = experiment["principals"]
    principal_roles = {name for name, slot in declarations.items() if slot["kind"] == "principal"}
    need(experiment["template"] == {"id": template["claim_class"], "version": str(template["template_version"])}
         and set(slots) == set(declarations) and set(principals) == principal_roles,
         "native experiment has incomplete or unknown slot and principal bindings")
    recorded_slots = []
    for name, binding in sorted(slots.items()):
        need(set(binding) == {"value", "source", "supplied_by", "digest"},
             "invalid native slot binding shape")
        value = binding["value"]
        source = binding["source"]
        expected_supplier = record["lead_id"] if source == "lead" else "operator"
        channel = "operator" if source == "engagement" else source
        need(isinstance(value, str) and value and binding["digest"] == digest(value.encode())
             and source in {"engagement", "lead"} and channel in declarations[name]["supplied_by"]
             and binding["supplied_by"] == expected_supplier,
             "native slot value, source or supplier is invalid")
        if name not in principal_roles:
            expected_value = prop["plant"]["operation"] if name == "plant" else prop[name]
            need(value == expected_value, "native operation slot does not match the admitted property")
        recorded_slots.append({"name": name, **{key: binding[key] for key in ("source", "supplied_by", "digest")}})
    need(record["slots"] == recorded_slots, "native verification record does not bind the same slots")
    labels, sessions = set(), set()
    for role, bound in principals.items():
        label = slots[role]["value"]
        admitted = declaration["principal"][label]
        expected = {key: admitted.get(key) for key in ("session", "verifier_session", "groups", "identity_probe")}
        need(bound == {"principal": label, **expected} and isinstance(bound["session"], str),
             "native principal does not match the admitted binding")
        need(label not in labels, "native experiment reused a declared principal")
        labels.add(label)
        for session in (bound["session"], bound["verifier_session"]):
            if session is not None:
                need(isinstance(session, str) and session and session not in sessions,
                     "native experiment reused or lacks a valid instrument session")
                sessions.add(session)
    expected_effects = list(dict.fromkeys(step["effect"] for step in template["recipe"] if step["effect"] != "none"))
    need(experiment["effects"] == expected_effects
         and set(expected_effects) <= set(declaration["engagement"]["allow_effects"]),
         "native experiment effects do not match the admitted frozen recipe")


def admitted_property(receipt, record, manifest_pin, evidence, prefix):
    manifest_ref = receipt["manifest"]
    experiment_ref = receipt["experiment"]
    need(manifest_ref["sha256"] == manifest_pin["sha256"]
         and experiment_ref["sha256"] == record["experiment_digest"],
         "policy is outside the frozen manifest or native experiment")
    manifest = qualified_manifest(evidence.retained(manifest_ref, prefix))
    data = evidence.retained(experiment_ref, prefix)
    experiment = parse_json(data)
    need(set(experiment) == {"template", "engagement", "property", "slots", "principals", "oracle", "decoder",
                             "effects"} and data == native_bytes(experiment),
         "retained experiment is not the canonical native FrozenExperiment shape")
    need(experiment["engagement"] == {"revision": record["engagement_revision"],
                                      "digest": manifest_ref["sha256"]}
         and manifest["revision"] == record["engagement_revision"]
         and experiment["oracle"] == record["oracle"] and experiment["template"] == record["template"],
         "native experiment does not link the admitted engagement or oracle")
    property_id = record["property"]["id"]
    declaration = manifest["declaration"]
    prop = declaration["property"][property_id]
    resource_spec = registered_property(prop)
    need(experiment["property"] == {"label": property_id, "resource": prop["resource"],
                                    "digest": record["property"]["digest"]}
         and native_digest(prop) == record["property"]["digest"],
         "property is not the canonical declaration admitted for the native experiment")
    check_experiment_bindings(experiment, record, declaration, prop)
    decoder = experiment["decoder"]
    need(decoder == FROZEN_DECODER and all(type(value) is int for value in decoder["limits"].values()),
         "native decoder differs from the exact compiled template binding")
    return prop, declaration, experiment, resource_spec


def native_count(value):
    return type(value) is int and 0 <= value <= MAX_NATIVE_COUNT


def gate_surfaces(sessions):
    return [("rules_list", None), ("intercept_status", None), ("intercept_rules", None), ("scripts_list", None),
            *(("session_show", session) for session in sessions), ("config_list", None)]


def native_surface_argv(operation, session):
    commands = {"rules_list": ["rules", "list"], "intercept_status": ["intercept", "status"],
                "intercept_rules": ["intercept", "rules", "list"], "scripts_list": ["scripts", "list"],
                "session_show": ["sessions", "show", session], "config_list": ["config", "list"]}
    return commands[operation]


def read_native_children(evidence, prefix, receipts, call, pins):
    parent = call["process_id"]
    signed = call["command_execs"]
    children = [proc for proc in signed if proc.get("parent_process_id") == parent]
    child_ids = [proc["process_id"] for proc in children]
    approved = call["execution"].get("approved_child_processes")
    need(isinstance(approved, list) and all(type(pid) is int for pid in approved)
         and sorted(approved) == sorted(child_ids) and parent not in child_ids,
         "authenticated native child topology differs from collector approval")
    need(not any(proc.get("parent_process_id") in child_ids for proc in signed),
         "authenticated verify child launched an unexpected descendant")
    result = {"teapot": [], "investigation": []}
    tools = {pins["teapot_sha256"]: ("teapot", TEAPOT_VERIFIER_ROLE),
             pins["investigation_sha256"]: ("investigation", "investigation")}
    scourge_pids = {proc["process_id"] for proc in signed if proc["binary_sha256"] == pins["scourge_sha256"]}
    need(all(proc.get("parent_process_id") in scourge_pids for proc in signed
             if proc.get("role") in {"teapot", TEAPOT_VERIFIER_ROLE, "investigation"}
             or proc["binary_sha256"] in tools),
         "authenticated native tool has no direct pinned Scourge parent")
    for proc in children:
        role, expected_role = tools.get(proc["binary_sha256"], (None, None))
        need(role is not None and proc["role"] == expected_role and proc["exit_code"] == 0,
             "unexplained, misclassified or failed direct Scourge verify child")
        path = pins[f"{role}_exec_path"]
        fd = BOUND_EXEC.fullmatch(proc["exec_path"])
        if role == "teapot":
            need(fd and proc["argv"][0] == path,
                 "invalid authenticated Teapot child executable")
        else:
            need(fd and proc["argv"][0] in {path, proc["exec_path"]},
                 "invalid authenticated Investigation child executable")
    need(isinstance(receipts, list) and [row["process_id"] for row in receipts] == child_ids
         and len({row["file"]["path"] for row in receipts}) == len(receipts),
         "native child originals do not cover the signed verify subprocesses in order")
    for position, (proc, row) in enumerate(zip(children, receipts)):
        ref = row["file"]
        raw = evidence.retained(ref, prefix)
        need(set(row) == {"process_id", "file"} and type(row["process_id"]) is int
             and type(proc["stdout_bytes"]) is int and proc["stdout_bytes"] == len(raw)
             and proc["stdout_sha256"] == ref["sha256"], "native child original differs from authenticated stdout")
        role, _ = tools[proc["binary_sha256"]]
        result[role].append(({**proc, "trace_position": position}, ref, raw))
    return result


def record_gate(record, originals, boundary):
    return originals[record[f"edit_surface_{boundary}"][0]["artifact_id"]][1]["observation"]["admitted"]


def round_action_session(step, principals, roles, anonymous):
    role = "owner" if step.startswith("C.") else roles[step.split(".")[0]]
    if role == "anonymous":
        return anonymous
    binding = principals[role]
    return native_session(binding["verifier_session"] or binding["session"])


def check_native_flow_floor(envelope):
    """Validate the single-page summary emitted by Teapot's flows-list command."""
    texts = ("method", "host", "path", "size", "type", "time", "scheme", "query", "content_type", "error", "refused")
    numbers = ("status", "length", "time_ms", "port", "request_length", "parent")
    required = {*texts, *numbers, "id", "state", "started_at", "websocket", "proto", "origin", "noise", "has_lead"}
    rows = envelope["flows"]
    native_schema = teapot_surface_schema("", "version")
    need(set(envelope) == {"flows", "advice"}
         and matches_native_schema(envelope["advice"], native_schema["properties"]["advice"], native_schema)
         and isinstance(rows, list) and len(rows) <= 1, "native flow floor has an unknown result shape")
    for row in rows:
        need(required <= row.keys() <= required | {"in_scope"}
             and native_count(row["id"]) and row["id"] > 0
             and all(type(row[key]) in {str, type(None)} for key in texts)
             and all(row[key] is None or native_count(row[key]) for key in numbers)
             and all(type(row[key]) is bool for key in ("websocket", "has_lead"))
             and ("in_scope" not in row or type(row["in_scope"]) is bool)
             and row["state"] in {"live", "complete", "error", "passthrough", "malformed", "interrupted", "intercepted"}
             and row["proto"] in {None, "h1", "h2", "ws"}
             and isinstance(row["origin"], str) and row["noise"] in {"none", "static", "telemetry", "browser"},
             "native flow floor has an unknown row shape")
        native_timestamp(row["started_at"])


def check_teapot_operation_envelope(words, envelope, referenced):
    operation = tuple(words[:2])
    if operation == ("flows", "list"):
        check_native_flow_floor(envelope)
        return
    commands = {("version",): "version", ("proxy", "status"): "proxy-status", ("pass", "show"): "pass-show",
                ("jobs", "list"): "jobs-list", ("macros", "run"): "macros-run",
                ("requests", "send"): "requests-send", ("flows", "show"): "flows-show"}
    command = commands.get(operation)
    if command:
        lane = "request-reference-" if referenced and command in {"version", "proxy-status", "pass-show"} else ""
        schema = teapot_surface_schema(lane, command)
        need(matches_native_schema(envelope, schema, schema), f"unknown native Teapot stdout shape for {command}")
    # Edit-surface families are validated by the stricter gate reducer.


def check_native_teapot_operations(children, receipt, pins, record, originals, known, experiment, resource_spec,
                                   bound_pass, pass_file, expected_rounds):
    instrument = record["instrument"]
    identity = (instrument["commit"], instrument["binary_digest"])
    referenced = pins["teapot_sha256"] == REQUEST_REFERENCE_TEAPOT[1]
    need((identity == REQUEST_REFERENCE_TEAPOT if referenced
          else identity[1] is None and identity[0] in {None, "6238d5a78a6514466d54ad16dd5737f43c1d4961"}),
         "native instrument schema lane differs from the authenticated Teapot executable")
    accounting_refs = record["accounting"]["attribution_evidence"]
    version = originals[accounting_refs[0]["artifact_id"]][1]["version"]
    project = version["engine"]["project"]
    prefix = [pins["teapot_exec_path"], "--project", project, "--json"]
    reads = iter(children)
    last_position = None

    def consume(words, sha=None, referenced_send=False):
        nonlocal last_position
        item = next(reads, None)
        need(item is not None, f"missing authenticated Teapot operation {' '.join(words[:2])}")
        proc, source, raw = item
        last_position = proc["trace_position"]
        expected = prefix + words
        actual = proc["argv"]
        if referenced_send:
            need(actual[:-2] == expected and actual[-2] == "--ref"
                 and re.fullmatch(r"scourge:[a-f0-9]{64}", actual[-1]) and actual[-1] not in send_refs,
                 "authenticated native dispatch has a wrong or reused reference or argv")
            send_refs.add(actual[-1])
        else:
            need(actual == expected, f"unexpected Teapot child in expected {' '.join(words[:2])} operation")
        need(sha is None or source["sha256"] == sha, "native Teapot child differs from its linked original")
        reply = parse_json(raw)
        check_teapot_operation_envelope(words, reply, referenced)
        if words == ["version"]:
            need(reply["version"] == version, "authenticated Teapot version differs from bound instrument")
        return proc, source, reply

    def gate(boundary):
        outlined = record_gate(record, originals, boundary)
        surface_rows = receipt["edit_surface_originals"][boundary]
        readings = iter(zip(outlined["edit_surface"]["readings"], surface_rows))
        need(len(surface_rows) == len(outlined["edit_surface"]["readings"]),
             "native edit-surface sources do not cover the admitted boundary")
        observed = {}
        for entry in outlined["calls"]:
            op = entry["operation"]
            if op == "version":
                consume(["version"])
            elif op == "proxy_status":
                result = consume(["proxy", "status"])[2]["proxy"]
                need(result["project"] == project and result["running"] is True
                     and result["engine"] == version["engine"], "authenticated proxy status has the wrong instrument")
            elif op == "pass_show":
                sample = consume(["pass", "show"])[2]["pass"]
                check_pass_sample(sample, bound_pass, pass_file, outlined["policy_locked"])
            else:
                row, link = next(readings, (None, None))
                need(row is not None and row["operation"] == op, "unexpected native edit-surface subprocess order")
                session = row["session"]
                proc, source, envelope = consume(native_surface_argv(op, session))
                need(link == {"operation": op, "session": session, "process_id": proc["process_id"], "file": source}
                     and (op, session) not in observed, "native edit-surface original differs from its authenticated Teapot child")
                observed[(op, session)] = envelope
        need(next(readings, None) is None, "unconsumed native edit-surface source")
        return observed

    def accounting(ops, refs):
        for words, ref in zip(ops, refs):
            consume(words, ref["digest"])

    def bookends(words):
        return [call for op in words for call in (["version"], op, ["version"])]

    need(set(receipt["edit_surface_originals"]) == {"start", "end"} and len(accounting_refs) == 15,
         "native instrument sources do not include exactly two gates and the accounting operations")
    surfaces = {"start": gate("start")}
    registry = operation_registry()
    roles, _ = oracle_roles(oracle_contract())
    anonymous = registry["anonymous_session"]
    principals = experiment["principals"]
    owner = round_action_session("P.request", principals, roles, anonymous)
    jobs = ["jobs", "list", "--limit", "1000"]
    pass_read = ["pass", "show"]
    plan = ["macros", "run", resource_spec["macro"], "--session", owner, "--dry-run"]
    accounting(bookends([jobs, pass_read, plan]), accounting_refs[:9])
    admitted = last_position
    send_refs = set()
    flow_readbacks = {}
    dispatched = 0
    last_flow = 0
    for round_row in record["rounds"]:
        grouped = groupby(round_row["flows"], key=lambda flow: flow["step"].split(".")[0])
        for _, steps in grouped:
            floor = consume(["flows", "list", "--limit", "1", "--order", "newest"])[2]["flows"]
            need(isinstance(floor, list) and len(floor) <= 1
                 and (not floor and last_flow == 0 or floor and type(floor[0]["id"]) is int
                      and floor[0]["id"] >= max(1, last_flow)), "native flow floor is missing or discontinuous")
            for row in steps:
                flow_id = row["flow_id"]
                sha, envelope = known[row["original"]["artifact_id"]]
                flow = envelope["flow"]
                need(row["completeness"] == "complete" and (not floor or flow_id > floor[0]["id"]),
                     "native dispatch lacks a complete flow above its authenticated floor")
                session = round_action_session(row["step"], principals, roles, anonymous)
                words = ["requests", "send", flow["method"], flow["url"], "--session", session]
                if row["step"].split(".")[0] in {"P", "P2"}:
                    words += ["--header", "Content-Type: application/json",
                              "--body", retained_body(flow, "request").decode("utf-8")]
                consume(["version"])
                sent = consume(words, referenced_send=referenced)[2]["sent"]
                origin = target_origin(flow["url"])
                need(sent["dry_run"] is False and sent["flow"] == flow_id and sent["status"] == flow["status"]
                     and sent["session"]["name"] == session and sent["relogin"] is None and sent["csrf"] is None
                     and sent["destination"] == origin and sent["would_refuse"] is None and sent["withheld"] is None
                     and len(sent["hops"]) == 1 and sent["hops"][0]["flow"] == flow_id
                     and sent["hops"][0]["status"] == flow["status"] and sent["hops"][0]["destination"] == origin
                     and sent["hops"][0]["outcome"] == sent["hops"][0]["state"] == "complete"
                     and sent["hops"][0]["sent_bytes"] > 0,
                     "authenticated Teapot send does not identify the registered retained flow")
                consume(["version"])
                consume(["version"])
                consume(["flows", "show", str(flow_id), "--base64", "--stored", "--offset", "0", "--max-body",
                         "1048576"], sha)
                consume(["version"])
                flow_readbacks[row["original"]["artifact_id"]] = last_position
                last_flow = flow_id
                dispatched += 1
    expected_dispatches = expected_rounds * sum(row["actions"] for row in registry["dispatches"])
    need(0 < dispatched <= expected_dispatches <= record["accounting"]["admitted"]["value"],
         "authenticated Teapot dispatches exceed the admitted registered budget")
    accounting(bookends([pass_read, jobs]), accounting_refs[9:])
    surfaces["end"] = gate("end")
    need(next(reads, None) is None, "unexplained Teapot child after the expected native verify operations")
    positions = [proc["trace_position"] for proc, _, _ in children]
    next_operation = dict(zip(positions, positions[1:]))
    return surfaces, {"first": positions[0], "admitted": admitted, "finished": last_position,
                      "start_attach_before": next_operation[admitted],
                      "flow_attachments": {ident: (readback, next_operation[readback])
                                           for ident, readback in flow_readbacks.items()}}


def native_capture_attachments(record):
    entries = [("edit-surface-start", record["edit_surface_start"][0])]
    dispatches = [row["flow"] for row in operation_registry()["dispatches"]]
    for round_row in record["rounds"]:
        number = round_row["number"]
        for flow in round_row["flows"]:
            contract = flow["step"].split(".")[0]
            position = (number - 1) * len(dispatches) + dispatches.index(contract) + 1
            entries.append((f'r{number}-s{position}-request-{flow["flow_id"]}', flow["original"]))
    entries.append(("edit-surface-end", record["edit_surface_end"][0]))
    entries.extend((f"accounting-{offset}", ref)
                   for offset, ref in enumerate(record["accounting"]["attribution_evidence"]))
    return entries


def native_investigation_excerpt(output, content, offset):
    selector = output["selector"]["selector"]
    excerpt = output["excerpt"]
    if selector == {"type": "json_pointer", "pointer": "", "parser": "serde_json-strict-v1"}:
        need(excerpt["availability"] == "json_value" and native_bytes(excerpt["value"]) == native_bytes(parse_json(content)),
             "Investigation JSON selector returned a different artifact")
        return offset, False, True
    actual, end = native_investigation_byte_excerpt(output, len(content), offset)
    need(actual == content[offset:end], "Investigation read bytes differ from the retained artifact")
    complete = end == len(content)
    return 0 if complete else end, complete, False


def native_investigation_byte_excerpt(output, size, offset):
    selector = output["selector"]["selector"]
    excerpt = output["excerpt"]
    if size <= 32 * 1024:
        need(offset == 0 and selector == {"type": "whole"}, "Investigation read did not select the native whole artifact")
        end = size
    else:
        end = min(offset + 32 * 1024, size)
        need(selector == {"type": "byte_range", "start": offset, "end": end}
             and type(selector["start"]) is int and type(selector["end"]) is int,
             "Investigation read did not select the native ordered byte range")
    if excerpt["availability"] == "text":
        actual = excerpt["text"].encode("utf-8")
    else:
        need(excerpt["availability"] == "binary", "Investigation read did not return exact bytes")
        actual = b64decode(excerpt["bytes_base64"], validate=True)
    need(type(excerpt["start"]) is int and type(excerpt["end"]) is int
         and (excerpt["start"], excerpt["end"]) == (offset, end) and len(actual) == end - offset,
         "Investigation read bytes differ from the retained artifact")
    return actual, end


def investigation_id(value, kind):
    return isinstance(value, str) and bool(re.fullmatch(
        rf"{kind}_[a-f0-9]{{8}}(?:-[a-f0-9]{{4}}){{3}}-[a-f0-9]{{12}}", value))


def investigation_digest(value):
    return isinstance(value, str) and bool(re.fullmatch(r"sha256:[a-f0-9]{64}", value))


@lru_cache
def investigation_identity():
    qualification = REPOSITORY / "fixtures/contracts/evidence/investigation-conformance.json"
    value = parse_json(qualification.read_bytes())["investigation"]
    return {key: value[key] for key in ("version", "source_commit", "binary_sha256")}


def investigation_command_key(operation, binding):
    return f"scourge/{operation}/{digest(binding.encode())}"


def native_capture_attachment(value, handle, run_id):
    receipt = value.get("receipt", {})
    need(value.get("role") == "original-output" and value.get("availability") == "staged"
         and investigation_digest(value.get("digest")) and native_count(value.get("size_bytes"))
         and receipt.get("handle") == handle and receipt.get("run_id") == run_id
         and receipt.get("result") in {"accepted", "already_accepted"}
         and nonempty_string(receipt.get("key")) and native_count(receipt.get("position")) and receipt["position"] > 0
         and investigation_digest(receipt.get("request_digest")) and nonempty_string(receipt.get("accepted_at")),
         "Investigation attachment is missing native size, request digest, time or receipt identity")
    native_timestamp(receipt["accepted_at"])
    return (receipt["key"], receipt["position"], value["digest"], value["size_bytes"],
            receipt["request_digest"], receipt["accepted_at"])


def investigation_record(output, ident, case_id):
    header = output["record"]["header"]
    need(output["result"] == "record_shown" and output["id"] == header["id"] == ident
         and header["case_id"] == case_id and native_count(header["revision"]) and header["revision"] > 0,
         "unbound Investigation record read")
    return header, output["record"]["body"]


def current_investigation_record(output, ident, case_id):
    header, body = investigation_record(output, ident, case_id)
    snapshot = output["snapshot"]
    use = output["evidentiary_use"]
    need(output["historical"] is False and isinstance(body, dict)
         and investigation_digest(snapshot["head_hash"]) and native_count(snapshot["sequence"])
         and use["state"] == "in_use" and use["withdrawals"] == [],
         "Investigation lineage record is historical, withdrawn or unqualified")
    return header, body


def prepared_manifest_capture(evidence, assignment):
    """Bind the manifest to the native show bytes supplied by the trusted referee."""
    output = parse_json(evidence.read(assignment["manifest_capture"]))
    ident = output["id"]
    case_id = output["record"]["header"]["case_id"]
    need(investigation_id(ident, "run") and investigation_id(case_id, "case") and output["historical"] is False,
         "invalid trusted-referee preparation manifest capture identity")
    _, body = investigation_record(output, ident, case_id)
    capture = body["capture"]
    final = body["capture_finalization"]
    need(body["producer"] == INVESTIGATION_ACTOR and capture["protocol"] == INVESTIGATION_PROTOCOL
         and investigation_id(capture["handle"], "handle")
         and capture["metadata"]["scourge_investigation"] == investigation_identity()
         and final["finalization"] == "finalized" and investigation_digest(final["manifest"]["digest"])
         and isinstance(final["artifacts"], list) and len(final["artifacts"]) == 1,
         "trusted-referee preparation capture does not describe one sealed manifest original")
    item = final["artifacts"][0]
    retained = item["retention"]
    ref = retained["artifact_ref"]
    manifest = assignment["manifest"]
    need(item["key"] == "engagement" and native_count(item["position"]) and item["position"] == 1
         and retained["state"] == "retained" and investigation_id(ref["id"], "art")
         and native_count(ref["revision"]) and ref["revision"] == 1
         and retained["digest"] == f'sha256:{manifest["sha256"]}' and native_count(retained["size_bytes"])
         and retained["size_bytes"] == len(evidence.read(manifest)),
         "trusted-referee preparation manifest original differs from the frozen bytes or identity")
    return case_id, ref["id"], ref["revision"]


def investigation_lineage_edges(body, required_transforms=None):
    source = body["source"]
    need(investigation_id(source["id"], "src") and native_count(source["revision"]) and source["revision"] > 0,
         "Investigation artifact has an unqualified Source reference")
    edges = [(source["id"], source["revision"], None)]
    transforms = body["transforms"]
    need(isinstance(transforms, list) and len(transforms) < 1024, "unqualified Investigation transform inventory")
    if required_transforms is not None:
        need(native_bytes(transforms) == native_bytes(required_transforms),
             "Investigation Artifact differs from its exact native derivation inputs")
    for transform in transforms:
        target = transform["input"]
        sha = transform["input_digest"]
        need(investigation_id(target["id"], "art") and native_count(target["revision"]) and target["revision"] > 0
             and investigation_digest(sha) and isinstance(transform["transformation"], str)
             and isinstance(transform["version"], str), "unqualified Investigation transform reference")
        edges.append((target["id"], target["revision"], sha))
    return edges


def read_investigation_lineage(children, root, ident, case_id, command_prefix, inventory, required_transforms):
    """Replay the native depth-first current Artifact/Source snapshot walk."""
    header, root_body = current_investigation_record(root, ident, case_id)
    head = root["snapshot"]
    root_edges = investigation_lineage_edges(root_body, required_transforms.get(ident))

    def show_args(node):
        return [*command_prefix, "--case", case_id, "show", node, "--depth", "full"]

    active = {ident}
    visited = {ident: (header["revision"], root_body["digest"])}
    edge_count = len(root_edges)

    def visit(node, minimum_revision, expected_digest):
        nonlocal edge_count
        need(node not in active, "Investigation lineage contains a cycle")
        if node in visited:
            revision, sha = visited[node]
            need(revision >= minimum_revision and sha == expected_digest,
                 "Investigation lineage reference disagrees with its earlier observation")
            return
        need(len(visited) < 256 and children and children[0][0]["argv"][1:] == show_args(node),
             "Investigation lineage is missing its next authenticated Source or Artifact read")
        _, _, raw = children.popleft()
        reply = parse_json(raw)
        ancestor, body = current_investigation_record(reply, node, case_id)
        need(reply["snapshot"] == head and ancestor["revision"] >= minimum_revision,
             "Investigation lineage crosses snapshots or uses an older revision")
        if investigation_id(node, "src"):
            need(expected_digest is None, "Investigation Source cannot prove an Artifact digest")
            visited[node] = (ancestor["revision"], None)
            return
        sha = body["digest"]
        need(investigation_digest(sha) and sha == expected_digest
             and (node not in inventory or sha == f"sha256:{inventory[node]}"),
             "Investigation transform input digest differs from its authenticated Artifact")
        edges = investigation_lineage_edges(body, required_transforms.get(node))
        edge_count += len(edges)
        need(edge_count <= 1024, "Investigation lineage exceeds the native edge bound")
        visited[node] = (ancestor["revision"], sha)
        active.add(node)
        for edge in edges:
            visit(*edge)
        active.remove(node)

    for edge in root_edges:
        visit(*edge)


def investigation_transforms(inputs, derivation):
    transformation, version = derivation
    return [{"input": {"id": ident, "revision": revision}, "input_digest": f"sha256:{sha}",
             "transformation": transformation, "version": version} for ident, sha, revision in inputs]


def verification_input_refs(record, experiment):
    """Collect the canonical native VerificationV1::lineage_inputs order."""
    refs = {}

    def add(value):
        ident, sha = value["artifact_id"], value["digest"]
        need(set(value) == {"artifact_id", "digest"} and investigation_id(ident, "art")
             and DIGEST.fullmatch(sha) and refs.get(ident, sha) == sha
             and (sha != experiment["digest"] or value == experiment),
             "verification record has conflicting native derivation inputs")
        refs[ident] = sha

    def collect(value):
        if isinstance(value, dict) and "artifact_id" in value:
            add(value)
        elif isinstance(value, dict):
            for key in sorted(value):
                collect(value[key])
        elif isinstance(value, list):
            for child in value:
                collect(child)

    collect(record)
    add(experiment)
    return refs


@lru_cache
def scourge_wire_contract():
    return parse_json(WIRE_CONTRACT.read_bytes())


def matches_verification_wire(value, rule, field=None):
    """Check the registered shapes and Rust scalar rules reachable from VerificationV1."""
    if rule.endswith("?"):
        return value is None or matches_verification_wire(value, rule[:-1], field)
    if rule.endswith("[]"):
        return isinstance(value, list) and all(matches_verification_wire(item, rule[:-2], field) for item in value)
    if rule.startswith("="):
        return value == rule[1:]
    registry = scourge_wire_contract()
    if rule in registry["shapes"]:
        fields = registry["shapes"][rule]
        return (isinstance(value, dict) and value.keys() == fields.keys()
                and all(matches_verification_wire(value[name], spec, name) for name, spec in fields.items()))
    if rule in registry["enums"]:
        return value in registry["enums"][rule]
    if rule == "boolean":
        return type(value) is bool
    if rule == "uint":
        return type(value) is int and 0 <= value < 1 << 64
    if not isinstance(value, str):
        return False
    if rule == "string":
        opaque_ids = {"run_id": "R-", "lead_id": "L-", "record_id": "V-", "baseline_record": "V-"}
        prefix = opaque_ids.get(field)
        return bool(value and "\0" not in value) if prefix is None else bool(re.fullmatch(prefix + r"[A-Za-z0-9_-]+", value))
    if rule == "timestamp":
        if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-5][0-9](?:\.[0-9]{1,9})?Z", value):
            return False
        try:
            native_timestamp(value)
        except ValueError:
            return False
        return True
    patterns = {"sha256": r"[a-f0-9]{64}", "git_commit": r"[a-f0-9]{40}", "nonce": r"[a-f0-9]{32}",
                "reason_code": r"[A-Z][A-Z0-9_]{1,63}", "probability": r"(?:0(?:\.[0-9]+)?|1(?:\.0+)?)"}
    return rule in patterns and bool(re.fullmatch(patterns[rule], value))


def qualified_verification_record(content):
    record = parse_json(content)
    need(matches_verification_wire(record, "scourge.verification.v1") and native_bytes(record) == content,
         "Investigation record is not canonical native VerificationV1")
    return record


def verification_lineage_refs(record, transforms):
    observed = []
    experiments = []
    for row in transforms:
        need((row["transformation"], row["version"]) == VERIFICATION_DERIVATION,
             "Investigation verification record has unsupported derivation")
        ident = row["input"]["id"]
        sha = row["input_digest"].removeprefix("sha256:")
        observed.append((ident, sha))
        if sha == record["experiment_digest"]:
            experiments.append({"artifact_id": ident, "digest": sha})
    need(len(experiments) == 1, "Investigation verification record does not derive from one Experiment")
    expected = verification_input_refs(record, experiments[0])
    need(observed == list(expected.items()), "Investigation verification lineage differs from its exact ordered record inputs")
    return expected


def verification_reevaluation_inputs(record, experiment_id):
    """Follow observations_from_record's last request/retry in the frozen oracle order."""
    required = (*oracle_roles(oracle_contract())[0], "C")
    inputs = [experiment_id]
    for round_row in record["rounds"]:
        selected = {}
        for flow in round_row["flows"]:
            step = flow["step"].split(".")
            if step[0] in required and step[-1] in {"request", "retry"}:
                selected[step[0]] = flow["original"]
        inputs.extend(selected[step]["artifact_id"] for step in required if selected.get(step))
    return inputs


def investigation_selector(output, ident, sha, header, snapshot):
    selector = output["selector"]
    need(output["result"] == "evidence_read" and output["artifact"]["id"] == ident
         and type(output["artifact"]["revision"]) is int and output["artifact"]["revision"] == header
         and output["snapshot"] == snapshot and selector["artifact_digest"] == f"sha256:{sha}"
         and selector["schema_version"] == "inv.selector.v1"
         and output["evidentiary_use"]["state"] == "in_use" and output["evidentiary_use"]["withdrawals"] == [],
         "Investigation selector is outside the admitted evidence graph or read snapshot")
    return selector["selector"]


def read_native_investigation_artifact(children, ident, case_id, command_prefix, source_bytes, inventory,
                                       required_transforms, missing):
    show = [*command_prefix, "--case", case_id, "show", ident, "--depth", "full"]
    need(children and children[0][0]["argv"][1:] == show, missing)
    _, _, raw = children.popleft()
    reply = parse_json(raw)
    header, body = current_investigation_record(reply, ident, case_id)
    sha = inventory[ident]
    need(body["digest"] == f"sha256:{sha}" and body["availability"] == "retained"
         and native_count(body["size_bytes"]) and body["size_bytes"] <= 64 * 1024 * 1024
         and (sha not in source_bytes or body["size_bytes"] == len(source_bytes[sha])),
         "Investigation input differs from the retained original")
    read_investigation_lineage(children, reply, ident, case_id, command_prefix, inventory, required_transforms)
    return header["revision"], reply["snapshot"], body


def read_fresh_derivation_inputs(children, prior_position, case_id, command_prefix, inputs,
                                 source_bytes, inventory, required_transforms, kind):
    """Replay the uninterrupted native record_in input walks before the ingest."""
    remaining = len(children)
    snapshot = None
    checked = []
    for ident, sha in inputs.items():
        need(inventory[ident] == sha, "Investigation derivation input differs from the frozen inventory")
        revision, head, _ = read_native_investigation_artifact(
            children, ident, case_id, command_prefix, source_bytes, inventory, required_transforms,
            f"Investigation {kind} is missing its next fresh ordered input show")
        need(snapshot is None or head == snapshot, f"Investigation {kind} inputs use different fresh snapshots")
        snapshot = head
        checked.append((ident, sha, revision))
    next_position = prior_position + (remaining - len(children)) + 1
    need(children and children[0][0]["trace_position"] == next_position
         and children[0][0]["argv"][1:-1] == [*command_prefix, "ingest", "--input"],
         f"Investigation {kind} input walks must immediately precede the native ingest")
    return checked


def read_investigation_artifact_bytes(children, ident, revision, snapshot, case_id, command_prefix, sha, size, json_data=None):
    args = [*command_prefix, "--case", case_id, "evidence", "read", ident, "--selector-file", "-"]
    offset = 0
    recovered = []
    json_first = json_data is not None
    while True:
        need(children and children[0][0]["argv"][1:] == args,
             "Investigation phase is missing the next exact artifact byte selector")
        _, _, raw = children.popleft()
        reply = parse_json(raw)
        selector = investigation_selector(reply, ident, sha, revision, snapshot)
        if json_first:
            _, _, json_read = native_investigation_excerpt(reply, json_data, offset)
            need(json_read, "Investigation artifact selectors are out of native read order")
            json_first = False
            continue
        need(selector["type"] in {"whole", "byte_range"}, "Investigation artifact selectors are out of native read order")
        actual, offset = native_investigation_byte_excerpt(reply, size, offset)
        recovered.append(actual)
        if offset == size:
            content = b"".join(recovered)
            need(digest(content) == sha, "Investigation read bytes differ from the retained artifact")
            return content


def check_publication_receipt(output, artifact, size):
    created = [row for row in output["created"] if row.get("client_ref") == "artifact:0"]
    need(len(created) == 1 and created[0]["id"] == artifact["artifact_id"]
         and native_count(created[0]["revision"]) and created[0]["revision"] > 0,
         "Investigation publication receipt lacks its native artifact identity")
    revision = created[0]["revision"]
    matches = [row for row in output["artifacts"] if row["artifact"]["id"] == artifact["artifact_id"]
               and row["artifact"]["revision"] == revision]
    need(len(matches) == 1 and native_count(matches[0]["artifact"]["revision"])
         and matches[0]["digest"] == f'sha256:{artifact["digest"]}'
         and native_count(matches[0]["size_bytes"]) and matches[0]["size_bytes"] == size,
         "Investigation publication receipt does not bind the retained artifact bytes")
    return revision


def check_coherent_finding_reads(children, position, case_id, command_prefix, manifest, manifest_history,
                                 record, artifact, inputs, source_bytes, inventory, transforms):
    """Replay the native coherent badge capture under one evidence checkpoint."""
    remaining = len(children)
    manifest_id, manifest_revision = manifest
    inventory = inventory.copy()
    captured = {}

    def checkpoint():
        args = [*command_prefix, "--case", case_id, "show", manifest_id, "--depth", "full"]
        need(children and children[0][0]["argv"][1:] == args,
             "Investigation coherent finding is missing its native manifest checkpoint")
        proc, _, raw = children.popleft()
        reply = parse_json(raw)
        header, body = current_investigation_record(reply, manifest_id, case_id)
        need(header["revision"] == manifest_revision and body["digest"] == f"sha256:{inventory[manifest_id]}",
             "Investigation coherent checkpoint differs from the prepared manifest")
        return reply["snapshot"], proc["trace_position"]

    def read(ident, head=None):
        revision, observed, body = read_native_investigation_artifact(
            children, ident, case_id, command_prefix, source_bytes, inventory, transforms,
            "Investigation coherent finding is missing its next fresh ordered artifact observation")
        need(head is None or observed == head, "Investigation coherent finding reads use different snapshots")
        need(ident != manifest_id or revision == manifest_revision,
             "Investigation coherent finding changed the prepared manifest revision")
        content = read_investigation_artifact_bytes(children, ident, revision, observed, case_id, command_prefix,
                                                    inventory[ident], body["size_bytes"])
        return content, body

    def historical_id(sha=None):
        need(children, "Investigation coherent finding history is incomplete")
        argv = children[0][0]["argv"][1:]
        need(argv[:-3] == [*command_prefix, "--case", case_id, "show"] and argv[-2:] == ["--depth", "full"]
             and investigation_id(argv[-3], "art"), "Investigation coherent finding history is missing an Artifact")
        ident = argv[-3]
        body = parse_json(children[0][2])["record"]["body"]
        observed = body["digest"]
        need(investigation_digest(observed) and (sha is None or observed == f"sha256:{sha}")
             and ident not in inventory, "Investigation coherent finding history reuses or changes an Artifact")
        inventory[ident] = observed.removeprefix("sha256:")
        return ident

    def read_inputs(refs, head):
        for ident, sha in refs.items():
            need(inventory.setdefault(ident, sha) == sha and captured.get(ident, sha) == sha,
                 "Investigation coherent finding changed an original Artifact identity")
            if ident not in captured:
                read(ident, head)
                captured[ident] = sha

    read(manifest_id)  # open_verifier_evidence also rechecks the manifest.
    head, _ = checkpoint()
    read(manifest_id, head)  # read_qualified rechecks the pin inside the named snapshot.
    for manifest_sha in manifest_history:
        read(historical_id(manifest_sha), head)
    read(manifest_id, head)  # capture_linked reads the current indexed manifest again.
    need(native_count(record["sequence"]) and record["sequence"] > 0, "invalid coherent verification sequence")
    predecessor = None
    for sequence in range(1, record["sequence"]):
        ident = historical_id()
        content, body = read(ident, head)
        prior = qualified_verification_record(content)
        refs = verification_lineage_refs(prior, body["transforms"])
        need(prior["engagement"] == record["engagement"]
             and prior["sequence"] == sequence and prior["prev_record_digest"] == predecessor,
             "Investigation coherent finding history differs from the indexed record chain")
        predecessor = inventory[ident]
        if prior["lead_id"] == record["lead_id"]:
            read_inputs(refs, head)
    need(predecessor == record["prev_record_digest"], "Investigation coherent finding predecessor differs")
    content, _ = read(artifact["artifact_id"], head)
    qualified_verification_record(content)
    read_inputs(inputs, head)
    after, _ = checkpoint()
    final, end_position = checkpoint()
    need(after == final == head, "Investigation coherent finding changed its named snapshot")
    need(not children and end_position == position + remaining,
         "unexplained Investigation operation inside or after the coherent finding snapshot")


def check_native_investigation_operations(children, record, receipt, artifact, teapot_order, evidence, prefix,
                                          request_key, prepared_manifest, manifest_history):
    """Reconcile durable native capture operations and the evidence they reference."""
    expected = native_capture_attachments(record)
    inventory = {ref["artifact_id"]: ref["digest"] for _, ref in expected}
    capture_ids = set(inventory)
    inventory[artifact["artifact_id"]] = artifact["digest"]
    manifest_case, manifest_id, manifest_revision = prepared_manifest
    need(manifest_id not in inventory, "protected preparation manifest identity was reused by native verification")
    inventory[manifest_id] = receipt["manifest"]["sha256"]
    expected_ingests = [receipt["experiment"]["sha256"], artifact["digest"]]
    sources = {ref["sha256"]: ref for ref in (
        receipt["record"], receipt["manifest"], receipt["experiment"],
        *(item["file"] for item in (*receipt["originals"], *receipt["instrument_originals"])))}
    source_bytes = {sha: evidence.retained(ref, prefix) for sha, ref in sources.items()}
    need(all(investigation_id(ident, "art") for ident in inventory),
         "native retained Evidence has a noncanonical Investigation Artifact identity")
    identity = investigation_identity()
    qualified_version = f'investigation {identity["version"]}\n'.encode()
    case_key = "scourge/evidence/case-v1"
    workspace = case_id = handle = run_id = None
    configs, attachments, ingested, versions, opened, recovered, finalized = 0, 0, 0, 0, 0, 0, False
    config_pending = False
    expect_run_show = None
    run_reads = []
    begin_position = None
    manifest_digest = None
    transaction_id = None
    staged_receipts = []
    manifest_opens = set()
    experiment_inputs = None
    experiment_id = None
    verification_inputs = reevaluation_inputs = None
    publication_key = publication_revision = None
    publication_inputs = None
    required_transforms = {ident: [] for ident in (*capture_ids, manifest_id)}
    read_bytes = set()
    read_json = set()
    ingest_refs = {}
    children = deque(children)

    def consume_phase(position, reads, phase, next_operation):
        remaining = len(children)
        revisions = []
        command_prefix = ["--format", "json", "--actor", INVESTIGATION_ACTOR, "--workspace", workspace]
        for ident, mode in reads:
            revision, head, body = read_native_investigation_artifact(
                children, ident, case_id, command_prefix, source_bytes, inventory, required_transforms,
                f"Investigation {phase} is missing its next fresh ordered artifact observation")
            revisions.append(revision)
            if mode != "describe":
                sha = inventory[ident]
                read_investigation_artifact_bytes(children, ident, revision, head, case_id, command_prefix, sha,
                                                  body["size_bytes"], source_bytes[sha] if mode == "json" else None)
                read_bytes.add(ident)
                if mode == "json":
                    read_json.add(ident)
        next_position = position + (remaining - len(children)) + 1
        if next_operation is None:
            need(next_position == teapot_order["first"], "Investigation manifest read did not establish preflight authority")
        else:
            expected = next_operation if next_operation == ["--version"] else [*command_prefix, *next_operation]
            need(children and children[0][0]["trace_position"] == next_position
                 and children[0][0]["argv"][1:][:len(expected)] == expected,
                 f"Investigation {phase} does not immediately precede its next native operation")
        return revisions

    while children:
        if (experiment_inputs is None and 1 in manifest_opens
                and children[0][0]["trace_position"] > teapot_order["admitted"]):
            command_prefix = ["--format", "json", "--actor", INVESTIGATION_ACTOR, "--workspace", workspace]
            experiment_inputs = read_fresh_derivation_inputs(
                children, teapot_order["admitted"], case_id, command_prefix, {manifest_id: inventory[manifest_id]},
                source_bytes, inventory, required_transforms, "experiment")
            need(experiment_inputs[0][2] == manifest_revision,
                 "Investigation experiment input revision differs from the prepared manifest")
        proc, _, raw = children.popleft()
        position = proc["trace_position"]
        args = proc["argv"][1:]
        if args == ["--version"]:
            need(raw == qualified_version and versions < 2 and expect_run_show is None and not config_pending,
                 "unexpected Investigation version operation")
            versions += 1
            continue
        need(args[:5] == ["--format", "json", "--actor", INVESTIGATION_ACTOR, "--workspace"] and len(args) > 6
             and Path(args[5]).is_absolute() and ".." not in Path(args[5]).parts
             and (workspace is None or args[5] == workspace), "unbound Investigation workspace or argv")
        workspace = args[5]
        op = args[6:]
        output = parse_json(raw)
        if expect_run_show is not None:
            need(op == ["--case", case_id, "show", run_id, "--depth", "full"],
                 "missing authenticated Investigation run read after capture begin or recovery")
        if config_pending:
            need(op in (["receipt", case_key], ["capture", "attach", "--input", "-"]),
                 "Investigation configuration check has no corresponding caller operation")
            config_pending = False
        if op == ["config", "get", "import_roots"]:
            config_pending = True
            configs += 1
            roots = output["setting"]["value"]
            need(output["result"] == "config" and isinstance(roots, list) and len(roots) == 1
                 and Path(roots[0]).is_absolute(), "invalid Investigation configuration observation")
        elif op == ["receipt", case_key]:
            created = output["created"]
            need(output["command_id"] == case_key and len(created) == 1
                 and type(created[0]["revision"]) is int and created[0]["revision"] == 1
                 and investigation_id(created[0]["id"], "case")
                 and created[0]["id"] == manifest_case
                 and (case_id is None or case_id == created[0]["id"]) and opened < versions,
                 "Investigation case receipts are missing, duplicated or unrelated")
            case_id = created[0]["id"]
            opened += 1
            if opened == 1:
                revisions = consume_phase(position, [(manifest_id, "bytes")], "preflight manifest read", None)
                need(revisions == [manifest_revision], "Investigation preflight manifest revision differs from the preparation")
            else:
                need(publication_revision is not None, "Investigation coherent finding precedes publication")
                check_coherent_finding_reads(children, position, case_id, args[:6], (manifest_id, manifest_revision),
                                             manifest_history, record, artifact, verification_inputs, source_bytes,
                                             inventory, required_transforms)
            manifest_opens.add(opened)
        elif op == ["capture", "begin", "--input", "-"]:
            need(handle is None and ingested == 1 and output["case_id"] == case_id
                 and output["protocol"] == INVESTIGATION_PROTOCOL
                 and ("external_run_id" not in output or output["external_run_id"] == record["run_id"])
                 and set(ingest_refs) <= read_bytes & read_json
                 and teapot_order["admitted"] < position < teapot_order["start_attach_before"],
                 "Investigation capture did not begin once for the admitted run")
            handle, run_id = output["handle"], output["run_id"]
            need(investigation_id(handle, "handle") and investigation_id(run_id, "run")
                 and output.get("commit", {}).get("command_id") == investigation_command_key("capture/begin", record["run_id"]),
                 "invalid native Investigation capture begin identity or commit")
            begin_position = position
            expect_run_show = "open"
        elif op == ["capture", "attach", "--input", "-"]:
            need(run_reads == ["open"] and not finalized and attachments < len(expected),
                 "unexplained Investigation capture attachment")
            key, target = expected[attachments]
            staged = native_capture_attachment(output, handle, run_id)
            need(staged[:4] == (key, attachments + 1, f'sha256:{target["digest"]}',
                                  len(source_bytes[target["digest"]])),
                 "Investigation attachment does not identify the expected retained original")
            staged_receipts.append(staged)
            if key == "edit-surface-start":
                need(begin_position < position < teapot_order["start_attach_before"],
                     "Investigation start attachment does not precede the first native dispatch")
            elif target["artifact_id"] in teapot_order["flow_attachments"]:
                after, before = teapot_order["flow_attachments"][target["artifact_id"]]
                need(after < position < before, "Investigation flow attachment is outside its native dispatch boundary")
            else:
                need(teapot_order["finished"] < position, "Investigation end attachment predates the final Teapot gate")
            attachments += 1
        elif op == ["capture", "finalize", "--input", "-"]:
            need(handle is not None and not finalized and attachments == len(expected)
                 and output["handle"] == handle and output["run_id"] == run_id
                 and output["finalization"] == "finalized" and output.get("missing_positions", []) == []
                 and teapot_order["finished"] < position,
                 "Investigation capture is not the one complete native acquisition")
            manifest_digest = output["manifest_digest"]
            commit = output.get("commit", {})
            transaction_id = commit.get("transaction_id")
            need(investigation_digest(manifest_digest)
                 and commit.get("command_id") == investigation_command_key("capture/finalize", handle)
                 and nonempty_string(transaction_id), "Investigation finalization lacks its native manifest or commit")
            finalized = True
        elif op == ["capture", "recover", "--handle", handle]:
            handles = output["handles"]
            need(finalized and recovered == 0 and isinstance(handles, list) and len(handles) == 1,
                 "Investigation recovery lacks one finalized capture")
            recovered_capture = handles[0]
            returned = recovered_capture.get("artifacts")
            final = recovered_capture.get("finalized", {})
            need(recovered_capture["seal"] == "finalized" and recovered_capture.get("case_id") == case_id
                 and recovered_capture["handle"] == handle and recovered_capture["run_id"] == run_id
                 and native_count(recovered_capture.get("last_position"))
                 and recovered_capture["last_position"] == len(staged_receipts)
                 and isinstance(returned, list) and len(returned) == len(staged_receipts)
                 and final.get("handle") == handle and final.get("run_id") == run_id
                 and final.get("finalization") == "finalized" and final.get("manifest_digest") == manifest_digest
                 and final.get("missing_positions", []) == []
                 and final.get("commit", {}).get("transaction_id") == transaction_id,
                 "Investigation recovery does not identify the finalized capture")
            need([native_capture_attachment(value, handle, run_id) for value in returned] == staged_receipts,
                 "Investigation recovered attachments differ from the original native receipts")
            recovered += 1
            expect_run_show = "finalized"
        elif len(op) == 3 and op[:2] == ["ingest", "--input"]:
            entries = output["items"]
            need(Path(op[2]).is_absolute() and ingested < 2
                 and (ingested == 0 and 1 in manifest_opens and teapot_order["admitted"] < position
                      or ingested == 1 and run_reads == ["open", "finalized"] and capture_ids <= read_bytes)
                 and len(entries) == 1 and entries[0]["outcome"] == "derived",
                 "unexplained Investigation ingestion operation")
            ident = entries[0]["artifact_id"]
            sha = expected_ingests[ingested]
            need(investigation_id(ident, "art") and ident not in ingest_refs and (ident not in inventory or inventory[ident] == sha)
                 and (ingested == 0 or ident == artifact["artifact_id"]),
                 "Investigation ingestion does not identify the expected artifact")
            if ingested == 0:
                need(experiment_inputs is not None and output.get("command_id") == investigation_command_key("record", request_key),
                     "Investigation experiment ingest does not match the native request command ID")
                experiment_id = ident
                required_transforms[ident] = investigation_transforms(experiment_inputs, EXPERIMENT_DERIVATION)
            else:
                need(publication_key is not None and output.get("command_id") == publication_key,
                     "Investigation publication ingest does not match the native receipt command ID")
                required_transforms[ident] = investigation_transforms(publication_inputs, VERIFICATION_DERIVATION)
            ingest_refs[ident] = sha
            inventory[ident] = sha
            ingested += 1
            if ingested == 1:
                verification_inputs = verification_input_refs(record, {"artifact_id": ident, "digest": sha})
                reevaluation_inputs = verification_reevaluation_inputs(record, ident)
                revisions = consume_phase(position, [(ident, "describe"), (ident, "json"), (ident, "describe")],
                                          "experiment publication and execution-boundary describe", ["capture", "begin"])
                need(len(set(revisions)) == 1, "Investigation Experiment revision changed before execution")
            else:
                consume_phase(position, [(ident, "describe")], "publication ingest describe", ["receipt", publication_key])
        elif len(op) == 2 and op[0] == "receipt":
            need(re.fullmatch(r"scourge/verification-publication/[a-f0-9]{64}", op[1]) and output["command_id"] == op[1]
                 and finalized and opened == 1 and run_reads == ["open", "finalized"],
                 "unexplained Investigation receipt operation")
            if publication_key is None:
                need(ingested == 1 and output["result"] == "not_found_at_snapshot",
                     "Investigation publication lacks its native pre-ingest receipt lookup")
                publication_key = op[1]
                need(set(verification_inputs) <= read_bytes
                     and all(inventory[item] == sha for item, sha in verification_inputs.items()),
                     "Investigation publication lacks authenticated input bytes")
                publication_inputs = read_fresh_derivation_inputs(
                    children, position, case_id, args[:6], verification_inputs, source_bytes, inventory, required_transforms,
                    "publication")
            else:
                need(ingested == 2 and publication_revision is None and op[1] == publication_key
                     and output["result"] in {"committed", "already_committed"},
                     "Investigation publication receipt does not match its native ingest command ID")
                publication_revision = check_publication_receipt(output, artifact, len(source_bytes[artifact["digest"]]))
                published_id = artifact["artifact_id"]
                revisions = consume_phase(position, [(published_id, "describe"), (published_id, "bytes"),
                                                      *((item, "bytes") for item in verification_inputs),
                                                      *((item, "bytes") for item in reevaluation_inputs)],
                                          "committed publication read-back and reevaluation", ["--version"])
                need(revisions[:2] == [publication_revision, publication_revision],
                     "Investigation publication revision differs from its committed receipt")
        elif op == ["--case", case_id, "show", run_id, "--depth", "full"]:
            _, body = investigation_record(output, run_id, case_id)
            if expect_run_show is not None:
                need(expect_run_show is not None and body["external_ref"] == record["run_id"]
                     and body["producer"] == INVESTIGATION_ACTOR and body["capture"]["handle"] == handle
                     and body["capture"]["protocol"] == INVESTIGATION_PROTOCOL
                     and body["capture"].get("metadata", {}).get("scourge_investigation") == identity,
                     "Investigation run read is for another capture")
                if expect_run_show == "finalized":
                    final = body["capture_finalization"]
                    need(final["finalization"] == "finalized" and final["manifest"]["digest"] == manifest_digest
                         and [(row["key"], row["position"], row["retention"]["artifact_ref"]["id"],
                               row["retention"]["digest"], row["retention"].get("size_bytes"))
                              for row in final["artifacts"]] ==
                         [(key, index, ref["artifact_id"], f'sha256:{ref["digest"]}', len(source_bytes[ref["digest"]]))
                          for index, (key, ref) in enumerate(expected, 1)]
                         and all(row["retention"]["state"] == "retained" and type(row["position"]) is int
                                 and type(row["retention"]["size_bytes"]) is int
                                 and type(row["retention"]["artifact_ref"]["revision"]) is int
                                 and row["retention"]["artifact_ref"]["revision"] == 1 for row in final["artifacts"]),
                         "Investigation final run read does not seal the exact native source inventory")
                    consume_phase(position, [(item, "bytes") for item in (*verification_inputs, *reevaluation_inputs)],
                                  "post-capture preparation and reevaluation", ["receipt"])
                run_reads.append(expect_run_show)
                expect_run_show = None
            else:
                raise ValueError("unexplained Investigation Run observation")
        else:
            raise ValueError("unexplained Investigation child operation")
    need(versions == opened == 2 and configs == len(expected) + opened and attachments == len(expected)
         and ingested == 2 and publication_revision is not None and finalized and recovered == 1 and not config_pending
         and run_reads == ["open", "finalized"] and expect_run_show is None
         and manifest_opens == {1, 2} and set(inventory) <= read_bytes,
         "authenticated Investigation child operations do not cover the native verification lifecycle")
    return experiment_id, publication_key


@lru_cache
def teapot_surface_schema(lane, command):
    path = REPOSITORY / "fixtures/contracts" / f"schema-{lane}{command}.json"
    return parse_json(path.read_bytes())["output"]["schema"]["result"]


def matches_native_schema(value, schema, root, depth=0):
    """Apply the strict subset from teapot/schema.rs to frozen native schemas."""
    if depth > 128:
        return False
    if type(schema) is bool:
        return schema
    kinds = {"array": list, "boolean": bool, "integer": int, "null": type(None),
             "number": (int, float), "object": dict, "string": str}

    def check(item, rule):
        return matches_native_schema(item, rule, root, depth + 1)

    for key, rule in schema.items():
        if key in {"$defs", "default", "description", "format"}:
            continue
        if key == "type":
            types = rule if isinstance(rule, list) else [rule]
            if not any(type(value) in (kinds[name] if isinstance(kinds[name], tuple) else (kinds[name],))
                       and (name != "integer" or -(1 << 63) <= value < (1 << 64)) for name in types):
                return False
        elif key == "$ref":
            if not rule.startswith("#/$defs/") or not check(value, root["$defs"][rule.removeprefix("#/$defs/")]):
                return False
        elif key == "const":
            if type(value) is not type(rule) or value != rule:
                return False
        elif key in {"anyOf", "oneOf"}:
            count = sum(check(value, choice) for choice in rule)
            if not count or key == "oneOf" and count != 1:
                return False
        elif key == "minimum":
            if type(value) in {int, float} and value < rule:
                return False
        elif key == "maximum":
            if type(value) in {int, float} and value > rule:
                return False
        elif key == "items":
            if isinstance(value, list) and not all(check(item, rule) for item in value):
                return False
        elif key == "required":
            if isinstance(value, dict) and not set(rule) <= value.keys():
                return False
        elif key in {"properties", "additionalProperties"}:
            if isinstance(value, dict):
                props = schema.get("properties", {})
                fallback = schema.get("additionalProperties", False)
                if not all(check(item, props.get(name, fallback)) for name, item in value.items()):
                    return False
        else:
            return False
    return True


def native_surface_result(operation, envelope, instrument):
    commands = {"rules_list": ("rules-list", "rules"), "intercept_status": ("intercept-status", "intercept"),
                "intercept_rules": ("intercept-rules-list", "rules"), "scripts_list": ("scripts-list", "scripts"),
                "session_show": ("sessions-show", "session"), "config_list": ("config-list", "settings")}
    command, key = commands[operation]
    identity = (instrument["commit"], instrument["binary_digest"])
    historical = identity[1] is None and identity[0] in {None, "6238d5a78a6514466d54ad16dd5737f43c1d4961"}
    need(historical or identity == REQUEST_REFERENCE_TEAPOT, "unknown native verifier gate schema lane")
    lane = "" if historical else "request-reference-"
    schema = teapot_surface_schema(lane, command)
    need(matches_native_schema(envelope, schema, schema), f"unknown native edit-surface source shape for {operation}")
    return envelope[key]


def check_native_numbered_rows(rows):
    need(all(row["n"] == number and nonempty_string(row["name"]) for number, row in enumerate(rows, 1))
         and len({row["name"] for row in rows}) == len(rows), "invalid native edit-surface row numbering or names")


def reduce_native_script(script, generation):
    state = script["state"]
    source = script["source"]
    previous = script["previous_running"]
    hooks = {hook["event"] for hook in script["hooks"]}
    editing = {"request_headers", "request", "response_headers", "response", "websocket_message"}
    need(0 < script["generation"] == generation
         and source in {"bundled", "user", "project"}
         and hooks <= editing | {"flow_error", "tls_connect", "start", "stop"}
         and (not previous or state in {"error", "disabled"})
         and (state in {"running", "disabled"} or state == "error" and (previous or not hooks)
              or state == "untrusted" and source == "project" and not hooks or state == "overridden" and not hooks),
         "native instrument boundary has an unqualified script")
    return [state, (state == "running" or previous) and bool(hooks & editing)]


def reduce_native_session(result, session):
    paused = result["state"] == "paused"
    need(result["name"] == session and result["state"] in {"active", "paused"}
         and result["sends"] in {"cookies-only", "headers-to-origins"}
         and (result["sends"] == "cookies-only") == (not result["origins"])
         and paused == (result["paused_reason"] is not None) and (paused or not result["paused_evidence"])
         and result["values"] is None, "native instrument boundary has unqualified session behavior")
    return {"session": session, "cookies": len(result["cookies"]), "headers": len(result["headers"]),
            "secrets": len(result["secrets"]), "csrf_tokens": result["csrf_tokens"], "paused": paused,
            "has_login": result["login"] is not None, "has_logout_rule": result["logged_out"] is not None}


def reduce_native_edit_surface(operation, session, result):
    if operation == "rules_list":
        check_native_numbered_rows(result)
        return {"rules": [[row["enabled"], row["status"]] for row in result]}
    if operation == "intercept_status":
        need(result["change"] is None, "native instrument boundary reports a mutating intercept read")
        return {"intercept": {key: result[key] for key in ("enabled", "rules", "active_rules", "paused")}}
    if operation == "intercept_rules":
        check_native_numbered_rows(result)
        return {"intercept_rules": [row["enabled"] for row in result]}
    if operation == "scripts_list":
        generation = result[0]["generation"] if result else None
        return {"scripts": [reduce_native_script(script, generation) for script in result]}
    if operation == "session_show":
        return {"session": reduce_native_session(result, session)}
    return {"config": {"settings": len(result)}}


def check_native_config(settings, rules, intercept, intercept_rules, sessions):
    """Apply the admitted config allowlist and reconcile it with the native reads."""
    names = [row["key"] for row in settings]
    need(len(set(names)) == len(names), "native edit-surface configuration repeats a key")
    configured = dict((row["key"], row["value"]) for row in settings)
    rules_by_name = {row["name"] for row in rules}
    for key, value in configured.items():
        allowed = False
        if key == "scope":
            allowed = isinstance(value, list) and all(
                isinstance(row, dict) and set(row) <= {"host", "path", "subdomains", "scheme", "port"}
                and nonempty_string(row.get("host")) and (row.get("path") is None or nonempty_string(row["path"]))
                and type(row.get("subdomains")) in {type(None), bool}
                and (row.get("scheme") is None or row["scheme"] in {"http", "https"} and row.get("port") is not None)
                and (row.get("port") is None or type(row["port"]) is int and 0 < row["port"] <= 65535)
                for row in value)
        elif key == "pass.path":
            allowed = nonempty_string(value)
        elif key in {"pass.required", "pass.enforce", "intercept.enabled"}:
            allowed = type(value) is bool
        elif key == "pass.relay":
            allowed = value in {"allow", "block"}
        elif key == "proxy.mode":
            allowed = value == "regular"
        elif key == "rules":
            allowed = isinstance(value, list) and len(value) == len(rules) and all(
                isinstance(row, dict) and row.get("enabled") is False and row.get("name") in rules_by_name
                for row in value)
        elif key == "intercept.rules":
            allowed = isinstance(value, list) and len(value) == len(intercept_rules) and all(
                isinstance(row, dict) and row.get("name") == observed["name"]
                and row.get("enabled", True) is observed["enabled"] for row, observed in zip(value, intercept_rules))
        elif key == "intercept.timeout-secs":
            allowed = type(value) is int and 0 <= value < 1 << 64
        elif key == "intercept.on-timeout":
            allowed = value in {"forward", "drop"}
        elif key == "sessions.default":
            allowed = isinstance(value, str) and bool(re.fullmatch(r"[A-Za-z0-9_-]+", value))
        elif key.startswith("sessions."):
            session, _, setting = key.removeprefix("sessions.").rpartition(".")
            allowed = bool(re.fullmatch(r"[A-Za-z0-9_-]+", session)) and (
                setting == "headers" and isinstance(value, list) and all(isinstance(item, str) for item in value)
                or setting in {"login", "logged-out"} and session not in sessions and nonempty_string(value))
        need(allowed, "native instrument boundary has editable or unqualified configuration")
    need((len(configured.get("rules", [])), len(configured.get("intercept.rules", [])),
          configured.get("intercept.enabled", True), configured.get("intercept.timeout-secs"),
          configured.get("intercept.on-timeout", "forward")) ==
         (len(rules), len(intercept_rules), intercept["enabled"], intercept["timeout_secs"], intercept["on_timeout"]),
         "native configuration and edit-surface readings disagree")


def check_native_edit_surface(admitted, sessions, anonymous, originals):
    expected = gate_surfaces(sessions)
    readings = admitted["edit_surface"]["readings"]
    need([(row["operation"], row["session"]) for row in readings] == expected,
         "native instrument boundary lacks all ordered edit-surface and session reads")
    operations = ["version"]
    for operation in ("proxy_status", "pass_show", *(operation for operation, _ in expected), "proxy_status"):
        operations.extend((operation, "version"))
    calls = admitted["calls"]
    need([call["operation"] for call in calls] == operations
         and all(set(call) == {"operation", "exits"} and set(call["exits"]) == {"native", "wrapper"}
                 and type(call["exits"]["native"]) is int and call["exits"]["native"] == 0
                 and (call["exits"]["wrapper"] is None
                      or type(call["exits"]["wrapper"]) is int and call["exits"]["wrapper"] == 0)
                 for call in calls),
         "native instrument boundary lacks successful version-bookended reads")
    need(list(originals) == expected, "native instrument boundary lacks matching ordered edit-surface source originals")
    reports, native_results = {}, {}
    for row in readings:
        operation, session = row["operation"], row["session"]
        key = (operation, session)
        result = native_surface_result(operation, originals[key], admitted["identity"])
        need(set(row) == {"operation", "session", "result_sha256", "report"}
             and row["result_sha256"] == native_digest(result),
             "native edit-surface result digest differs from retained source")
        derived = reduce_native_edit_surface(operation, session, result)
        need(native_bytes(derived) == native_bytes(row["report"]),
             "native edit-surface report differs from its retained source reduction")
        reports[key] = derived
        native_results[key] = result

    rules = reports[("rules_list", None)]["rules"]
    need(all(enabled is False and status == "off" for enabled, status in rules),
         "native instrument boundary has an active or unqualified rule")
    intercept = reports[("intercept_status", None)]["intercept"]
    intercept_rules = reports[("intercept_rules", None)]["intercept_rules"]
    need(intercept["rules"] == len(intercept_rules) and intercept["active_rules"] == intercept["paused"] == 0
         and not (intercept["enabled"] and any(intercept_rules)),
         "native instrument boundary has active or inconsistent interception")
    scripts = reports[("scripts_list", None)]["scripts"]
    need(len(scripts) < 1000 and all(edits is False for _, edits in scripts),
         "native instrument boundary has an editing or unqualified script")
    for session in sessions:
        report = reports[("session_show", session)]["session"]
        need(report["csrf_tokens"] == 0
             and all(report[key] is False for key in ("has_login", "has_logout_rule", "paused"))
             and (report["cookies"] > 0 if session != anonymous
                  else report["cookies"] == report["headers"] == report["secrets"] == 0),
             "native instrument boundary has unqualified session behavior")
    check_native_config(native_results[("config_list", None)], native_results[("rules_list", None)],
                        native_results[("intercept_status", None)], native_results[("intercept_rules", None)],
                        sessions)


def native_window(window):
    need(set(window) == {"start", "end"}, "native accounting window lacks its endpoints")
    start, end = (native_timestamp(window[label]) for label in ("start", "end"))
    need(start <= end, "native accounting window is reversed")
    return start, end


def check_native_count(count, value, source, unit, granularity, ref, window):
    need(isinstance(count, dict) and native_count(count["value"])
         and count == {"value": value, "source": source, "unit": unit, "granularity": granularity,
                       "evidence": ref, "window": window},
         f"native accounting count differs from retained evidence for {source}")


def check_pass_sample(sample, bound_pass, pass_file, locked):
    pass_id, pass_digest, total = bound_pass
    need(sample["id"] == pass_id and sample["digest"] == f"sha256:{pass_digest}"
         and sample["pass_file"] == pass_file and sample["state"] == "bound"
         and sample["window"] == "valid" and sample["newer_pass"] is None
         and sample["enforcement"]["on"] is False and sample["lock"]["locked"] is locked,
         "native instrument pass report differs from protected pass admission")
    ceilings = [row for row in sample["ceilings"] if row["counter"] == "requests"]
    need(len(ceilings) <= 1, "native pass sample repeats its requests ceiling")
    if not ceilings:
        return None
    counters = ceilings[0]
    need(native_count(counters["total"]) and counters["total"] == total
         and all(counters.get(key) is None or native_count(counters[key]) and counters[key] <= total
                 for key in ("spent", "left", "unused")),
         "native pass sample counters differ from the protected requests ceiling")
    return counters


def check_native_instrument(record, originals, bound_pass, pass_file, experiment, resource_spec, flow_times,
                            expected_rounds, surfaces):
    seen = {}

    def read(ref):
        artifact = ref["artifact_id"]
        observed_digest, envelope = originals[artifact]
        need(artifact not in seen and ref["digest"] == observed_digest,
             "retained instrument artifact was reused or differs from its native reference")
        seen[artifact] = observed_digest
        return envelope

    instrument = record["instrument"]
    registry = operation_registry()
    anonymous = registry["anonymous_session"]
    sessions = sorted({anonymous, *(native_session(binding[field])
                                    for binding in experiment["principals"].values()
                                    for field in ("session", "verifier_session") if binding[field] is not None)})
    locks = []
    gate_times = []
    for boundary, time in (("start", "started_at"), ("end", "finished_at")):
        refs = record[f"edit_surface_{boundary}"]
        need(len(refs) == 1, "record lacks a single native instrument boundary observation")
        observed = read(refs[0])
        admitted = observed["observation"]["admitted"]
        need(observed["schema"] == "scourge.instrument-observation.v1"
             and observed["boundary"] == f"edit-surface-{boundary}" and observed["timestamp"] == record[time]
             and admitted["identity"] == instrument and admitted["enforcement"] == record["enforcement"]
             and type(admitted["policy_locked"]) is bool, "retained instrument boundary does not support the native record")
        check_native_edit_surface(admitted, sessions, anonymous, surfaces[boundary])
        locks.append(admitted["policy_locked"])
        gate_times.append(native_timestamp(observed["timestamp"]))
    locked = locks[0]
    need(locked is locks[1] and gate_times[0] < gate_times[1],
         "native instrument boundaries differ in policy lock or are not chronological")

    accounting = record["accounting"]
    pass_id, pass_digest, total = bound_pass
    need(accounting["schema"] == "scourge.accounting.v1" and accounting["pass_id"] == pass_id
         and accounting["pass_digest"] == pass_digest and native_count(total) and total > 0,
         "native accounting pass does not match the protected admitted pass")
    need(accounting["attribution"] == "unestablished" and accounting["instrument_job_ids"] == []
         and accounting["ledger_debits"] == []
         and all(accounting[key] is None for key in ("held_before", "held_after", "observed_sent", "charged")),
         "native M1 accounting includes unsupported per-run attribution")
    native_reads = ("jobs", "pass", "run", "pass", "jobs")
    operations = [operation for kind in native_reads for operation in ("version", kind, "version")]
    refs = accounting["attribution_evidence"]
    need(len(refs) == len(operations), "native accounting lacks complete ordered pre/post evidence")
    samples = []
    first_version = None
    for ref, operation in zip(refs, operations):
        envelope = read(ref)
        need(set(envelope) == {"advice", operation} and isinstance(envelope["advice"], list),
             "native accounting reply does not match its ordered operation")
        reply = envelope[operation]
        if operation == "version":
            engine = reply["engine"]
            need(reply["answered_by"] == "engine" and engine["instance"] == instrument["engine_instance"]
                 and engine["project_id"] == instrument["project_id"] and engine["enforced"] is False
                 and engine["policy_locked"] is locked and engine["pass"] == pass_file
                 and reply["version"] == engine["build"] == instrument["version"]
                 and reply["commit"] == instrument["commit"] and reply["protocol"] == instrument["protocol"]
                 and (first_version is None or reply == first_version),
                 "native accounting engine differs from the protected instrument")
            first_version = reply
        elif operation == "jobs":
            need(isinstance(reply, list) and len(reply) <= 1000
                 and all(native_count(job["id"]) for job in reply)
                 and len({job["id"] for job in reply}) == len(reply), "invalid native accounting jobs sample")
        else:
            samples.append((ref, reply))

    ((pre_ref, pre), (plan_ref, plan), (post_ref, post)) = samples
    before = check_pass_sample(pre, bound_pass, pass_file, locked)
    after = check_pass_sample(post, bound_pass, pass_file, locked)
    need(before is not None and native_count(before.get("spent")) and native_count(before.get("left")),
         "native admission lacks its readable before-counters")
    need(after is None or (after.get("spent") is None or before["spent"] <= after["spent"])
         and (after.get("left") is None or before["left"] >= after["left"]),
         "native before/after pass counters are discontinuous")

    sample_times = []
    for phase, ref, native in (("before", pre_ref, before), ("after", post_ref, after)):
        counters = accounting[f"counters_{phase}"]
        if native is None:
            need(counters is None, "record adds counters absent from the native pass sample")
            sample_times.append(None)
            continue
        need(isinstance(counters, dict) and set(counters) == {"spent", "left", "unused"},
             "native pass accounting lacks before/after counters")
        window = next((count["window"] for count in counters.values() if count is not None), None)
        for counter in ("spent", "left", "unused"):
            value = native.get(counter)
            if value is None:
                need(counters[counter] is None, "accounting supplies a counter absent from native pass evidence")
            else:
                check_native_count(counters[counter], value, f"teapot.pass_show.requests.{counter}",
                                   "request_units", "pass", ref, window)
        sample_times.append(native_window(window) if window is not None else None)

    owner = experiment["principals"]["owner"]
    owner_session = native_session(owner["verifier_session"] or owner["session"])
    need(plan["dry_run"] is True and plan["job"] is None and plan["outcome"] == "planned"
         and plan["name"] == resource_spec["macro"] and plan["session"]["name"] == owner_session
         and type(plan["units"]) is int and plan["units"] == 1
         and native_count(plan["units_left"]) and plan["units_left"] >= plan["units"]
         and isinstance(plan["steps"], list) and bool(plan["steps"])
         and all(step["outcome"] in {"planned", "not-run"} and step["flow"] is None and step["status"] is None
                 for step in plan["steps"]), "native macro dry-run does not support the registered admission")
    # The native admission reserves a conservative per-action budget for
    # authenticated work even when these clean sessions do not relogin.
    required = expected_rounds * sum(row["actions"] * (1 if row["principal"] == "anonymous" else 3)
                                    for row in registry["dispatches"])
    need(required <= before["left"], "native pass has insufficient units for the compiled dispatch bound")
    need(isinstance(accounting["admitted"], dict), "native accounting lacks the registered admission count")
    plan_window = accounting["admitted"]["window"]
    for name, value, source, unit, granularity in (
            ("requested", plan["units"], "teapot.macro_dry_run.units", "requests", "run"),
            ("admitted", required, "scourge.compiled_dispatch_plan.requests", "requests", "run"),
            ("dry_run_ceiling", plan["units_left"], "teapot.macro_dry_run.units_left", "request_units", "engine")):
        check_native_count(accounting[name], value, source, unit, granularity, plan_ref, plan_window)
    plan_start, plan_end = native_window(plan_window)
    run_start, run_end = native_window(accounting["window"])
    (pre_start, pre_end), post = sample_times
    need(flow_times and gate_times[0] <= run_start <= pre_start <= pre_end <= plan_start <= plan_end
         <= min(flow_times) <= max(flow_times) <= run_end <= gate_times[1]
         and (post is None or max(flow_times) <= post[0] <= post[1] <= run_end),
         "native pass and dry-run samples do not bookend the retained traffic")
    need(seen.keys() == originals.keys(), "case includes unlinked native instrument evidence")
    return seen


def check_case(case, spec, evidence, prefix, receipt, call, pins, assignment, supplied=None):
    pins = {**pins, "teapot_exec_path": assignment["teapot_exec_path"]}
    reply = call["reply"] or {}
    verification = reply.get("verification") or {}
    record_ref = receipt["record"]
    record = parse_json(evidence.retained(record_ref, prefix))
    index = parse_json(evidence.retained(receipt["index"], prefix))
    run_read = parse_json(evidence.retained(receipt["run"], prefix))
    record_id, run_id, lead_id = record["record_id"], record["run_id"], record["lead_id"]
    run = reply.get("run") or {}
    need(call["verb"] == "verify" and call["mutating"] and lead_id in call["argv"][1:]
         and (supplied is None or lead_id == supplied) and call["format"] == "json",
         "record is not linked to its actual verification call or assigned lead")
    expected_rounds = verification_rounds(call["argv"], lead_id)
    need(record["schema"] == "scourge.verification.v1" and record["kind"] == "verify"
         and record["oracle"] == pins["oracle"] and record["property"] == spec["property"]
         and record["validation"] == "deterministic" and
         record["profile"] == "runtime-controlled.v1"
         and record["verifier"]["binary_digest"] == pins["scourge_sha256"],
         "record has the wrong schema, verifier, oracle, or property")
    need(all(type(record[field]) is type(expected) and record[field] == expected
             for field, expected in M1_CONTEXT.items()), "record does not carry the native M1 custody and enforcement context")
    expected = "invalid" if case in INVALID else "true"
    if reply["ok"] is True:
        expected_exit = 0
    else:
        need(reply["ok"] is False, "invalid native response status")
        expected_exit = parse_json(WIRE_CONTRACT.read_bytes())["error_exits"][reply["error"]["code"]]
    need(call["exit_code"] == expected_exit, "native Scourge child exit does not support its response")
    need(record["result"] == verification.get("result") == run.get("oracle_result") == expected
         and run["state"] == "finalized" and run["id"] == run_id
         and verification.get("record_id") == record_id
         and reply["command"] == "verify"
         and reply["engagement"] == record["engagement"], "verification result or linked run differs")
    details = index["record"]
    need(index["schema"] == "scourge.response.v1" and index["ok"] is True
         and index["command"] == "show" and index["engagement"] == record["engagement"]
         and (details["id"], details["run_id"], details["lead_id"], details["record_digest"],
              details["sequence"]) == (record_id, run_id, lead_id, record_ref["sha256"], record["sequence"]),
         "record index does not link the retained original")
    need(run_read["schema"] == "scourge.response.v1" and run_read["ok"] is True
         and run_read["command"] == "show" and run_read["engagement"] == record["engagement"]
         and run_read["run"] == run and run_read["experiment_digest"] == record["experiment_digest"]
         and DIGEST.fullmatch(record["experiment_digest"]), "run read-back mismatch")
    request_key = reply.get("request_key")
    need(isinstance(request_key, str) and len(request_key) <= 128 and re.fullmatch(r"rk_[A-Za-z0-9_-]+", request_key)
         and run_read.get("request_key") == request_key, "native run read-back has a different request key")
    known = linked_artifacts(receipt["originals"], evidence, prefix)
    rounds = [row for row in record["rounds"] if row["result"] == expected]
    need(rounds, "missing qualifying retained round")
    need(len(rounds) == len(record["rounds"]) == expected_rounds
         and all(type(row["number"]) is int for row in rounds)
         and [row["number"] for row in rounds] == list(range(1, len(rounds) + 1)),
         "retained round count or outcomes disagree with actual verify argv")
    prop, declaration, experiment, resource_spec = admitted_property(receipt, record, assignment["manifest"], evidence, prefix)
    access = prepared_access(evidence, assignment, case, record, experiment, declaration)
    roles, identity_steps = oracle_roles(oracle_contract())
    dispatches = operation_registry()["dispatches"]
    need(list(roles.items()) == [(row["flow"], row["principal"]) for row in dispatches if row["flow"] != "C"],
         "native fixture dispatch registry disagrees with the pinned oracle")
    chronology = [flow["flow_id"] for row in rounds for flow in row["flows"] if flow["flow_id"]]
    need(chronology == sorted(set(chronology)), "retained native flow IDs do not advance in dispatch order")
    cleanup_statuses = [status for round_row in rounds for status in replay_round(
        round_row, known, case, experiment["decoder"], roles, identity_steps, access, resource_spec)]
    complete = cleanup_statuses.count(204)
    unresolved = any(200 <= status < 300 and status != 204 for status in cleanup_statuses)
    cleanup = ("complete" if complete == len(cleanup_statuses) else "partial" if complete else
               "unknown" if unresolved else "failed")
    need(record["cleanup"] == run["cleanup"] == cleanup, "native cleanup aggregate disagrees with retained outcomes")
    flow_times = [native_timestamp(known[flow["original"]["artifact_id"]][1]["flow"]["started_at"])
                  for row in rounds for flow in row["flows"] if flow["completeness"] == "complete"]
    protected_pass = evidence.read(assignment["pass_artifact"])
    pass_declaration = tomllib.loads(protected_pass.decode())
    pass_id = pass_declaration["id"]
    need(nonempty_string(pass_id), "protected native pass lacks its ID")
    bound_pass = (pass_id, digest(protected_pass), pass_declaration["ceilings"]["requests"])
    instrument = linked_artifacts(receipt["instrument_originals"], evidence, prefix)
    native_children = read_native_children(evidence, prefix, receipt["child_originals"], call, pins)
    surfaces, teapot_order = check_native_teapot_operations(
        native_children["teapot"], receipt, pins, record, instrument, known,
        experiment, resource_spec, bound_pass, access[-1], expected_rounds)
    instrument_ids = check_native_instrument(record, instrument, bound_pass, access[-1],
                                             experiment, resource_spec, flow_times, expected_rounds, surfaces)
    need(not set(known) & instrument_ids.keys(), "a native flow identity was reused as instrument evidence")
    finding = reply.get("finding") or {}
    finding_after_owner_read = None
    if case in INVALID:
        need(finding.get("status") != "verified" and record["exposure"] is None
             and any(INVALID[case] in row["reason_codes"]
                     and (any(item["original"] for item in row["identities"])
                          or any(flow["completeness"] == "complete" for flow in row["flows"]))
                     for row in rounds),
             "invalid control has the wrong reason or was promoted")
    else:
        expected_status = "refuted" if case == "public" else "verified"
        need(reply["ok"] is True and finding.get("status") == expected_status
             and (case == "public" or experiment["slots"]["owner"]["source"] == "engagement")
             and (finding["status_record"], finding["deciding_record"]) == (record_id, record_id)
             and finding["id"] == lead_id and finding["validation"] == record["validation"]
             and finding["profile"] == record["profile"]
             and finding["oracle"] == f'{pins["oracle"]["id"]}.v{pins["oracle"]["version"]}'
             and finding["exposure"] == record["exposure"] == spec["exposure"],
             "finding badge lacks the expected status, basis, or deciding record")
        for field in ("custody", "target_isolation", "enforcement"):
            need(finding[field] == record[field], "finding custody or enforcement differs")
        artifact = verification["artifact"]
        need(artifact["digest"] == record_ref["sha256"] and artifact["artifact_id"],
             "publication artifact does not match the retained record")
        need(finding["policy_source"] == "engagement" and record["policy_rule"] is None
             and prop["readers"] == ("public" if case == "public" else "owner"),
             "admitted engagement policy does not support the badge")
        true_rounds = [row for row in rounds if row["exposure"] == spec["exposure"]
                       and row["canaries"] and row["fields_crossed"] and row["flows"]
                       and all(flow["completeness"] == "complete" for flow in row["flows"])]
        need(true_rounds, "missing complete retained witnessing round")
        if case in {"positive", "f37"}:
            expected_after = case == "f37"
            need(any(row["after_owner_read"] is True for row in true_rounds) is expected_after,
                 "linked witnessing round has the wrong after_owner_read")
            caveats = reply.get("finding_caveats")
            need(isinstance(caveats, dict) and caveats.get("after_owner_read") is expected_after,
                 "native finding lacks the expected boolean after_owner_read caveat")
            finding_after_owner_read = caveats["after_owner_read"]
    artifact_ids = sorted({*known, *instrument_ids})
    artifact = verification.get("artifact")
    if artifact is not None:
        need(artifact["digest"] == record_ref["sha256"] and artifact["artifact_id"] not in artifact_ids,
             "native publication artifact conflicts with retained evidence")
        artifact_ids.append(artifact["artifact_id"])
    need(artifact is not None, "native verification lacks its publication artifact")
    experiment_id, publication_key = check_native_investigation_operations(
        native_children["investigation"], record, receipt, artifact, teapot_order, evidence, prefix, request_key,
        prepared_manifest_capture(evidence, assignment), [ref["sha256"] for ref in assignment["manifest_history"]])
    result = {"status": "passed", "call": call["number"], "lead_id": lead_id,
              "record_id": record_id, "run_id": run_id, "record_sha256": record_ref["sha256"],
              "artifact_ids": [*artifact_ids, experiment_id], "request_key": request_key,
              "publication_command_id": publication_key}
    if finding_after_owner_read is not None:
        result["after_owner_read"] = finding_after_owner_read
    return result


def optional_gate(check):
    try:
        return {"status": "passed", **(check() or {})}
    except (ValueError, KeyError, TypeError, AttributeError, IndexError, OSError) as error:
        return {"status": "failed", "reason": str(error)}


def cases_for(evidence, entry, referee, frozen, calls, assignment):
    prefix = entry["attempt_id"]
    inventory = evidence.json(referee["case_index"], prefix)
    need(inventory["source"] == "referee" and inventory["raw_sha256"] == entry["raw"]["sha256"]
         and inventory["history_complete"] is True, "incomplete case and promotion history")
    rows = {}
    claim_index = inventory["cases"]
    need(set(claim_index) <= {*CASES, "f37"}, "unknown case receipt")
    for case in (*CASES, "f37"):
        receipt_refs = claim_index.get(case, [])
        if not receipt_refs:
            rows[case] = {"status": "unmeasured"}
            continue

        def replay(ref):
            receipt = evidence.json(ref, prefix)
            number = receipt["call"]
            need(type(number) is int and 1 <= number <= len(calls), "unknown verification call")
            target = assignment["supplied_lead"] if case == "positive" else None
            return check_case(case, frozen["cases"][case], evidence, prefix, receipt,
                              calls[number - 1], frozen["pins"], assignment, target)

        attempts = [optional_gate(lambda ref=ref: replay(ref)) for ref in receipt_refs]
        rows[case] = {"status": "passed" if all(item["status"] == "passed" for item in attempts)
                      else "failed", "outcomes": attempts}
    accepted = {
        (row["lead_id"], row["record_id"])
        for case in ("positive", "f37")
        for row in rows[case].get("outcomes", []) if row["status"] == "passed"
    }
    unsupported = []
    for call in calls:
        response = call["reply"] or {}
        findings = [response.get("finding") or {}, *response.get("findings", [])]
        for finding in findings:
            if finding.get("status") == "verified" and (
                finding.get("id"), finding.get("deciding_record")
            ) not in accepted:
                unsupported.append(call["number"])
    return rows, sorted(set(unsupported))


def first_useful(evidence, entry, referee, frozen, calls, case_rows):
    prefix = entry["attempt_id"]
    judgments = evidence.json(referee["useful"], prefix)
    need(judgments["source"] == "independent-referee"
         and judgments["raw_sha256"] == entry["raw"]["sha256"], "useful-result review did not come from the referee")
    if not judgments["results"]:
        return {"status": "failed", "call": None, "reason": "never reached"}

    def supported(item):
        number = item["call"]
        need(type(number) is int and 1 <= number <= len(calls) and item["case"] in frozen["cases"],
             "citation does not identify an actual call and fixture case")
        call = calls[number - 1]
        reply = call["reply"] or {}
        proof = evidence.json(item["evidence"], prefix)
        need(proof["source"] == "referee" and proof["case"] == item["case"]
             and proof["call"] == number and proof["citation"] == item["citation"]
             and proof["caveat"] == item["caveat"] and proof["confirmed"] is True
             and isinstance(item["citation"], str) and item["citation"].strip()
             and isinstance(item["caveat"], str) and item["caveat"].strip(),
             "citation or caveat lacks independent support")
        if item["kind"] == "blocker":
            need(item["citation"] in [
                *reply.get("blockers", []), (reply.get("error") or {}).get("code")
            ], "confirmed blocker is absent from the original response")
        else:
            lead = reply.get("lead") or {}
            need(item["kind"] == "observation" and (
                any(row["status"] == "passed" and row["call"] == number
                    and item["citation"] in (row["record_id"], row["run_id"], row["lead_id"])
                    for row in case_rows[item["case"]].get("outcomes", []))
                or (lead.get("id") == item["citation"]
                    and proof.get("property") == frozen["cases"][item["case"]]["property"]
                    and evidence.read(proof["case_evidence"], prefix))
            ), "reference is absent from the original observation or qualifying outcome")
        return number

    measurements = [optional_gate(lambda item=item: {"call": supported(item)})
                    for item in judgments["results"]]
    numbers = [item["call"] for item in measurements if item["status"] == "passed"]
    number = min(numbers) if numbers else None
    return {"status": "passed" if number is not None and number <= MAX_FIRST_CALLS else "failed",
            "call": number, "judgments": measurements}


def screens(evidence, entry, referee):
    prefix = entry["attempt_id"]
    receipt = parse_json(evidence.retained(referee["screens"], prefix))
    need(receipt["source"] == "process-monitor", "entry sizes lack process observations")
    sizes = {}
    for name, args in (("entry", []), ("status", ["status"])):
        measurement = receipt[name]
        need(argv(measurement["argv"]) and Path(measurement["argv"][0]).name == "scourge"
             and measurement["argv"][1:] == args and measurement["format_env"] is None,
             "wrong entry or default status invocation")
        sizes[name] = len(evidence.retained(measurement["stdout"], prefix))
        need(0 < sizes[name] <= MAX_SCREEN_BYTES and measurement["exit"] == 0,
             f"{name} output is empty, failed, or exceeded {MAX_SCREEN_BYTES} bytes")
    return {"bytes": sizes}


def check_concept(evidence, frozen, entry, referee, assignment_digest):
    probe = referee["concept"]
    concept, native = check_capture(evidence, probe)
    prefix = probe["attempt_id"]
    need(concept["schema"] == REVIEW and concept["source"] == "independent-referee"
         and concept["assignment_sha256"] == assignment_digest and concept["pins"] == frozen["pins"]
         and concept["capture_sha256"] == probe["capture"]["sha256"]
         and concept["raw_sha256"] == probe["raw"]["sha256"], "concept review does not bind its capture")
    context = parse_json(evidence.retained(concept["context"], prefix))
    need(context["source"] == "host" and context["fresh"] is True
         and context["loaded_project_context"] == [] and context["unexpected_context"] == []
         and context["interventions"] == [] and context["prior_messages"] == 0 and context["tool_calls"] == 0
         and concept["session_id"] == context["session_id"] and LOCAL_ID.fullmatch(context["session_id"])
         and [event["thread_id"] for event in native if event["type"] == "thread.started"]
         == [context["session_id"]],
         "concept answer did not come from a fresh entry-only session")
    need(context["prompt"]["sha256"] == frozen["prompts"]["concept"]["sha256"],
         "concept prompt differs from frozen bytes")
    evidence.read(context["prompt"], prefix)
    entry_screen = evidence.retained(context["entry_stdout"], prefix)
    entry_receipt = parse_json(evidence.retained(referee["screens"], entry["attempt_id"]))["entry"]
    need(0 < len(entry_screen) <= MAX_SCREEN_BYTES and context["visible_inputs"] ==
         [context["entry_stdout"]["sha256"]]
         and context["entry_stdout"]["sha256"] == entry_receipt["stdout"]["sha256"],
         "concept worker did not see exactly the captured entry screen")
    items = []
    pending = set()
    completed = set()
    for event in native:
        kind = event["type"]
        if not kind.startswith("item."):
            continue
        item = event["item"]
        need(item["type"] in {"agent_message", "reasoning"}, "entry-only concept transcript includes a native tool item")
        item_key = (item["id"], item["type"])
        need(item_key not in completed, "entry-only concept transcript repeats a completed item")
        if kind in {"item.started", "item.updated"}:
            pending.add(item_key)
        elif kind == "item.completed":
            pending.discard(item_key)
            completed.add(item_key)
            items.append(item)
        else:
            raise ValueError("entry-only concept transcript contains an unknown item lifecycle")
    need(not pending, "entry-only concept transcript contains an unfinished native item")
    messages = [item for item in items if item["type"] == "agent_message"]
    answer = evidence.retained(concept["answer"], prefix).decode("utf-8")
    need(all(item["type"] in {"agent_message", "reasoning"} for item in items)
         and len(messages) == 1 and messages[0]["text"] == answer,
         "concept answer differs from native entry-only transcript")
    need(len(answer.strip()) > 0 and set(concept["criteria"]) == {"purpose", "limit", "next_call"},
         "concept evidence is incomplete")
    for item in concept["criteria"].values():
        need(item["correct"] is True and item["quote"].strip() and item["quote"] in answer,
             "concept answer did not cover every criterion")
    qualifier = " (use the selected workspace and engagement)"
    suggestions = [shlex.split(line.partition("  ")[2].removesuffix(qualifier))
                   for line in entry_screen.decode("utf-8").splitlines()
                   if line.startswith("Next  ")]
    need(argv(concept["next_argv"]) and suggestions == [concept["next_argv"]]
         and concept["entry_next_argv"] == concept["next_argv"]
         and shlex.split(concept["criteria"]["next_call"]["quote"]) == concept["next_argv"],
         "concept next call differs from the captured screen or native answer")
    return {"attempt_id": prefix, "session_id": concept["session_id"]}


def check_transport(evidence, entry, referee, calls):
    prefix = entry["attempt_id"]
    data = parse_json(evidence.retained(referee["transport"], prefix))
    need(data["source"] == "process-monitor", "transport witness is not a process receipt")
    number = data["advertised_call"]
    need(type(number) is int and 1 <= number <= len(calls), "missing orientation invocation")
    call = calls[number - 1]
    advertised = call["reply"]
    need(call["verb"] in {"status", "brief", "tldr", "onboard"} and advertised["effects"] == "none",
         "advertised action did not come from read-only orientation")
    action = advertised["transport"]["action"]
    executed = data["generated"]
    origin = Path(executed["source_cwd"])
    cwd = Path(executed["cwd"])
    workspace = Path(advertised["workspace"])
    need(action["effects"] == "none" and argv(action["argv"]) and executed["argv"] == action["argv"]
         and executed["fresh_process"] is True and executed["format_env"] is None
         and workspace.is_absolute() and cwd.is_absolute() and origin.is_absolute()
         and cwd != origin and not cwd.is_relative_to(workspace),
         "generated argv was changed or ran in the wrong process context")
    reply = parse_json(evidence.retained(executed["stdout"], prefix))
    need(reply["schema"] == "scourge.response.v1" and reply["ok"] is True and executed["exit"] == 0
         and reply["workspace"] == advertised["workspace"] and reply["engagement"] == advertised["engagement"]
         and reply["effects"] == "none" and reply["command"] == invocation(action["argv"])[0],
         "generated action did not return the expected structured response")
    masked = data["masked"]
    failure = parse_json(evidence.retained(masked["stdout"], prefix))
    need(failure["schema"] == "scourge.response.v1"
         and failure["workspace"] == advertised["workspace"] and failure["engagement"] == advertised["engagement"]
         and masked["wrapper_exit"] == 0, "masked-failure wrapper or response identity differs")
    diagnostics = [item for item in failure["diagnostics"]
                   if item["wrapper_exit"] == 0 and item["code"] in {"WRONG_LISTENER", "TOOL_UNAVAILABLE"}]
    need(diagnostics and (
        failure["ok"] is True and masked["exit"] == 0 and failure.get("error") is None
        and "DEPENDENCY_UNAVAILABLE" in failure["blockers"]
        or failure["ok"] is False and masked["exit"] == 7
        and failure["error"]["code"] == "DEPENDENCY_UNAVAILABLE"
    ), "masked failure did not preserve its typed diagnostic and blocker")


def mutations_to_verdict(calls, supplied):
    attempts = 0
    for call in calls:
        attempts += call["mutating"]
        reply = call["reply"] or {}
        verification = reply.get("verification") or {}
        if (call["verb"] == "verify" and supplied in call["argv"][1:]
                and verification.get("record_id") and verification.get("result") in {"true", "false", "invalid", "error"}):
            return attempts, call["number"]
    return None, None


def grade_cell(evidence, frozen, cell, entry, assignment_digest):
    referee, native = check_capture(evidence, entry)
    session, prompt = check_trial(evidence, frozen, cell, entry, referee, assignment_digest, native)
    calls, elapsed = load_calls(evidence, entry, referee, session, frozen["pins"], native, assignment_digest, prompt)
    assignment = frozen["cells"][cell]
    supplied = assignment["supplied_lead"]
    cases, unsupported = cases_for(evidence, entry, referee, frozen, calls, assignment)
    gates = {
        "first_useful": first_useful(evidence, entry, referee, frozen, calls, cases),
        "screens": optional_gate(lambda: screens(evidence, entry, referee)),
        "concept": optional_gate(lambda: check_concept(evidence, frozen, entry, referee, assignment_digest)),
        "transport": optional_gate(lambda: check_transport(evidence, entry, referee, calls)),
    }
    attempts, first_verdict = mutations_to_verdict(calls, supplied) if supplied else (None, None)
    if supplied:
        first_positive = next((row for row in cases["positive"].get("outcomes", [])
                               if row["status"] == "passed" and row["call"] == first_verdict), None)
        gates["first_supplied_verdict"] = {"status": "passed" if first_positive else "failed"}
    passed = (all(cases[key]["status"] == "passed" for key in CASES)
              and cases["f37"]["status"] != "failed" and not unsupported
              and all(row["status"] == "passed" for row in gates.values()) and bool(calls))
    return {
        "status": "passed" if passed else "failed",
        "session_id": session,
        "score": {"cases": cases, "unsupported_promotions": unsupported, "gates": gates,
                  "scourge_calls": len(calls), "elapsed_milliseconds": elapsed,
                  "mutating_calls_to_first_verdict": attempts,
                  "first_verdict_call": first_verdict},
    }


def grade_scripted_f37(evidence, frozen, entry, assignment_digest):
    needed = frozen["f37"]
    need(entry["attempt_id"] == needed["attempt_id"], "wrong scripted F-37 assignment")
    prefix = entry["attempt_id"]
    referee, native = check_capture(evidence, entry)
    need(referee["schema"] == REVIEW and referee["source"] == "referee"
         and referee["assignment_sha256"] == assignment_digest
         and referee["mode"] == "scripted-supplied" and referee["pins"] == frozen["pins"]
         and referee["capture_sha256"] == entry["capture"]["sha256"]
         and referee["raw_sha256"] == entry["raw"]["sha256"], "unbound scripted F-37 witness")
    session = referee["session_id"]
    need(LOCAL_ID.fullmatch(session), "bad scripted session identity")
    check_boundary(evidence, referee["boundary"], needed, session)
    calls, _ = load_calls(evidence, entry, referee, session, frozen["pins"], native, assignment_digest)
    receipt = evidence.json(referee["witness"], prefix)
    number = receipt["call"]
    need(type(number) is int and 1 <= number <= len(calls), "missing scripted F-37 verify invocation")
    return {**check_case("f37", frozen["cases"]["f37"], evidence, prefix, receipt,
                         calls[number - 1], frozen["pins"], needed, needed["supplied_lead"]),
            "session_id": session, "attempt_id": prefix}


def check_evidence_identities(cells, scripted):
    found = {}
    conflicts = {}
    outcomes = [
        (cell, case, outcome)
        for cell, entry in cells.items() if entry["score"]
        for case, case_result in entry["score"]["cases"].items()
        for outcome in case_result.get("outcomes", []) if outcome["status"] == "passed"
    ]
    if scripted["status"] == "passed":
        outcomes.append(("scripted_f37", "f37", scripted))
    for cell, case, outcome in outcomes:
        lead, record, run = (outcome[field] for field in ("lead_id", "record_id", "run_id"))
        basis = (cell, case, lead, record, run, outcome["record_sha256"])
        # A lead may have several records in one workspace, all for the same fixture case.
        identities = [
            (("lead", cell, lead), (cell, case)),
            (("record", record), basis),
            (("run", run), basis),
            (("request_key", outcome["request_key"]), basis),
            (("publication_command_id", outcome["publication_command_id"]), basis),
            *((("artifact", artifact), basis) for artifact in outcome["artifact_ids"]),
        ]
        for key, identity in identities:
            prior = found.setdefault(key, identity)
            if prior != identity:
                for owner in (cell, prior[0]):
                    conflicts.setdefault(owner, set()).add(f"{key[0]} {key[-1]} identifies multiple native cases or records")
    for cell, reasons in conflicts.items():
        if cell == "scripted_f37":
            scripted.update(status="failed", reason="; ".join(sorted(reasons)))
        else:
            cells[cell]["status"] = "failed"
            cells[cell]["score"]["identity_conflicts"] = sorted(reasons)


def retained_attempt(entry, result, evidence):
    summary = {field: entry.get(field) for field in
               ("attempt_id", "cell", "selection", "capture", "raw", "referee")}
    summary["status"] = result or "unassigned"
    try:
        capture = evidence.json(entry["capture"], entry["attempt_id"])
        need(capture["schema"] == "scourge.trial-capture" and capture["trial_id"] == entry["attempt_id"],
             "capture provenance mismatch")
        summary["capture_status"] = capture["status"]
        summary["capture_valid"] = capture["valid"]
        events = capture.get("events") or {}
        summary["usage"] = {key: events.get(key) for key in
                            ("model_input_tokens", "model_output_tokens", "provider_reported_model")}
    except (ValueError, KeyError, TypeError, AttributeError, OSError) as error:
        summary["capture_error"] = str(error)
    return summary


def grade(frozen, ledger, evidence, assignment_digest):
    check_assignment(frozen, evidence)
    need(ledger["schema"] == LEDGER and ledger["assignment_sha256"] == assignment_digest,
         "ledger does not bind the frozen assignment bytes")
    rows = ledger["attempts"]
    attempt_ids = [entry["attempt_id"] for entry in rows]
    need(all(LOCAL_ID.fullmatch(key) for key in attempt_ids), "bad ledger attempt identity")
    reservations = {row["attempt_id"]: cell for cell, row in frozen["cells"].items()}
    ledger_errors = []
    seen = {}
    for entry in rows:
        attempt_id = entry["attempt_id"]
        if attempt_id in seen:
            ledger_errors.append(f"duplicate ledger attempt {attempt_id}")
        seen.setdefault(attempt_id, []).append(entry)
        if entry["cell"] not in CELLS:
            ledger_errors.append(f"unknown cell for attempt {attempt_id}")
        if attempt_id in reservations and entry["cell"] != reservations[attempt_id]:
            ledger_errors.append(f"frozen attempt {attempt_id} assigned to the wrong cell")
        if attempt_id not in reservations and entry["selection"] != "unassigned":
            ledger_errors.append(f"unassigned attempt {attempt_id} claims a denominator slot")

    cells = {}
    identities = {}
    for cell in CELLS:
        attempt_id = frozen["cells"][cell]["attempt_id"]
        selected = seen.get(attempt_id, [])
        result = {"status": "unmeasured", "score": None}
        if selected:
            result = {"status": "invalid", "score": None}
            try:
                need(len(selected) == 1 and selected[0]["cell"] == cell
                     and selected[0]["selection"] == "assigned", "wrong or duplicate ledger assignment")
                result = grade_cell(evidence, frozen, cell, selected[0], assignment_digest)
            except (ValueError, KeyError, TypeError, AttributeError, IndexError, OSError) as error:
                result["reason"] = str(error)
        cells[cell] = {"attempt_id": attempt_id, **result}
        if result.get("session_id"):
            identities.setdefault(result["session_id"], []).append(cell)
        concept = ((result["score"] or {}).get("gates") or {}).get("concept")
        if concept and concept["status"] == "passed":
            identities.setdefault(concept["session_id"], []).append(cell)
            if concept["attempt_id"] in seen or concept["attempt_id"] == frozen["f37"]["attempt_id"]:
                cells[cell].update(status="invalid", score=None, reason="concept reused a ledger attempt")

    scripted = ledger["scripted_f37"]
    f37 = optional_gate(lambda: grade_scripted_f37(evidence, frozen, scripted, assignment_digest)) if scripted else {
        "status": "unmeasured"
    }
    if f37["status"] == "passed":
        identities.setdefault(f37["session_id"], []).append("scripted_f37")
        if f37["attempt_id"] in seen:
            f37 = {"status": "failed", "reason": "scripted F-37 reused a ledger attempt"}
    for matching in identities.values():
        if len(matching) > 1:
            for cell in matching:
                if cell == "scripted_f37":
                    f37 = {"status": "failed", "reason": "scripted F-37 reused a session"}
                else:
                    cells[cell].update(status="invalid", score=None, reason="trial or concept reused a session")
    check_evidence_identities(cells, f37)

    tracks = {}
    for track in ("supplied", "discovery"):
        group = [cells[cell] for cell in CELLS if cell.endswith(f"/{track}")]
        tracks[track] = {"assigned": len(group),
                         **{status: sum(row["status"] == status for row in group)
                            for status in ("passed", "failed", "invalid", "unmeasured")}}
    mutations = [
        cells[cell]["score"]["mutating_calls_to_first_verdict"] if cells[cell]["score"] else None
        for cell in CELLS if cell.endswith("/supplied")
    ]
    median_mutations = median(mutations) if None not in mutations else None
    discovery_f37 = {
        cell: row["score"]["cases"]["f37"]["status"] if row["score"] else "unmeasured"
        for cell, row in cells.items() if cell.endswith("/discovery")
    }
    passed = (not ledger_errors and all(row["status"] == "passed" for row in cells.values())
              and f37["status"] == "passed" and median_mutations is not None
              and median_mutations <= MAX_MEDIAN_MUTATIONS)
    return {
        "schema": RUBRIC, "assignment_sha256": assignment_digest, "cells": cells,
        "attempts": [
            retained_attempt(row, cells[reservations[row["attempt_id"]]]["status"]
                             if row["attempt_id"] in reservations else None, evidence)
            for row in rows
        ],
        "aggregate": {
            "status": "passed" if passed else "failed", "tracks": tracks, "ledger_errors": ledger_errors,
            "supplied_median_mutating_calls": median_mutations, "scripted_f37": f37,
            "discovery_f37": discovery_f37, "rate_claim": False,
        },
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("assignment", type=Path)
    parser.add_argument("ledger", type=Path)
    parser.add_argument("--artifact-root", type=Path)
    parser.add_argument("--monitor-key", type=Path, help="private 32-byte host trace replay key")
    args = parser.parse_args()
    try:
        assignment = args.assignment.read_bytes()
        artifact_root = (args.artifact_root or args.ledger.parent).resolve(strict=True)
        monitor_key = None
        if args.monitor_key:
            key_path = args.monitor_key.resolve(strict=True)
            need(not key_path.is_relative_to(artifact_root), "monitor key must stay outside the artifact root")
            monitor_key = key_path.read_bytes()
        score = grade(parse_json(assignment), parse_json(args.ledger.read_bytes()),
                      Evidence(artifact_root, monitor_key), digest(assignment))
    except (ValueError, KeyError, TypeError, AttributeError, IndexError, OSError) as error:
        parser.exit(2, f"Invalid skeleton input: {error}\n")
    print(json.dumps(score, indent=2, sort_keys=True))
    return int(score["aggregate"]["status"] != "passed")


if __name__ == "__main__":
    raise SystemExit(main())
