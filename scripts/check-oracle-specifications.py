#!/usr/bin/env python3
"""Validate the frozen v1 oracle registry against its ADR and M0 evidence."""

from __future__ import annotations

import json
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "docs/contracts/oracle-specifications.v1.json"
ADR = ROOT / "docs/adr/oracle-specifications.md"
PLAN = ROOT / "notes/plan.md"
TRUTH = ROOT / "fixtures/target/referee/ground-truth.json"
BASELINE = ROOT / "docs/adr/baseline-taxonomy-decision.md"

EXPECTED = {
    "web.private-object-read.v1": {
        "prefix": "POR",
        "flows": ["I1", "I2", "P", "P2", "F0", "F1", "F2", "F3", "F4", "I3", "I4", "C"],
        "invalid": {
            "SAME_SUBJECT",
            "OBSERVER_INVALID",
            "CANARY_NOT_SPECIFIC",
            "SESSION_DRIFT",
            "EVIDENCE_INCOMPLETE",
        },
        "failures": {
            "I1": "SAME_SUBJECT", "I2": "SAME_SUBJECT", "P": None, "P2": None,
            "F0": None, "F1": "OBSERVER_INVALID", "F2": None, "F3": None,
            "F4": "CANARY_NOT_SPECIFIC", "I3": "SESSION_DRIFT",
            "I4": "SESSION_DRIFT", "C": None,
        },
        "predicate": {
            "true": "setup is valid; the primary canary is present in F1 and absent from F4; and that same canary is present in at least one of F0, F2, or F3",
            "false": "setup is valid and the primary canary is absent from F0, F2, and F3",
            "exposure": {
                "unauthenticated": "the primary canary is present in F0 or F3",
                "cross_principal": "the primary canary is absent from F0 and F3 and present in F2",
                "after_owner_read": "F0 lacks the primary canary and F3 contains it",
            },
            "invalid_precedence": [
                "SAME_SUBJECT", "OBSERVER_INVALID", "CANARY_NOT_SPECIFIC",
                "SESSION_DRIFT", "EVIDENCE_INCOMPLETE",
            ],
            "error": "an instrument or oracle crash",
        },
        "checks": 12,
    },
    "web.forbidden-state-change.v1": {
        "prefix": "FSC",
        "flows": ["I1", "I2", "P", "W2", "R2", "W1", "R1", "W3", "R3", "I3", "I4", "C"],
        "invalid": {
            "SAME_SUBJECT",
            "OBSERVER_INVALID",
            "OWNER_VIEW_LOST",
            "SESSION_DRIFT",
            "EVIDENCE_INCOMPLETE",
        },
        "failures": {
            "I1": "SAME_SUBJECT", "I2": "SAME_SUBJECT", "P": None,
            "W2": "OBSERVER_INVALID", "R2": "OBSERVER_INVALID", "W1": None,
            "R1": "OWNER_VIEW_LOST", "W3": None, "R3": None,
            "I3": "SESSION_DRIFT", "I4": "SESSION_DRIFT", "C": None,
        },
        "predicate": {
            "true": "setup is valid; R2 contains V2; and R1 contains V1 or R3 contains V3",
            "false": "setup is valid; R2 contains V2; R1 still contains V2; and R3 does not contain V3",
            "exposure": {
                "cross_principal": "R1 contains V1",
                "unauthenticated": "R3 contains V3",
            },
            "invalid_precedence": [
                "SAME_SUBJECT", "OBSERVER_INVALID", "OWNER_VIEW_LOST",
                "SESSION_DRIFT", "EVIDENCE_INCOMPLETE",
            ],
            "error": "an instrument or oracle crash",
        },
        "checks": 11,
    },
}
CHECK_KINDS = {"identity", "control", "correlation", "completeness", "scope"}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def resolve_truth(truth: dict, reference: str) -> object:
    value: object = truth
    for part in reference.removeprefix("development:").split("."):
        require(isinstance(value, dict) and part in value, f"unknown development fixture {reference}")
        value = value[part]
    return value


def validate(contract: dict, adr: str, plan: str, truth: dict, baseline: str) -> tuple[int, int]:
    require(contract.get("schema_version") == "scourge.oracle-specifications.v1", "wrong schema version")
    require(contract.get("status") == "frozen", "oracle registry is not frozen")
    require(contract.get("result_domain") == ["true", "false", "invalid", "error"], "wrong result domain")
    qualification = contract.get("qualification", {})
    require(qualification.get("required_kill_rate") == 1.0, "mutation kill rate is not 100%")
    require(qualification.get("implementation_status") == "contract_only", "implementation status must stay explicit")
    require("M0-ADD-03" in baseline, "baseline scope disposition is missing")

    plan_fixtures = set(re.findall(r"^\| (F-[0-9]{2}) \|", plan, re.MULTILINE))
    require(len(plan_fixtures) == 53, f"expected 53 plan fixtures, found {len(plan_fixtures)}")
    oracles = contract.get("oracles")
    require(isinstance(oracles, dict) and set(oracles) == set(EXPECTED), "unexpected oracle registry keys")

    total_checks = 0
    for oracle_id, expected in EXPECTED.items():
        oracle = oracles[oracle_id]
        required_flows = oracle.get("required_flows")
        require(required_flows == expected["flows"], f"{oracle_id}: wrong required flow order")
        flows = oracle.get("flows")
        require(isinstance(flows, list), f"{oracle_id}: flows are not a list")
        flow_ids = [flow.get("id") for flow in flows]
        require(flow_ids == required_flows, f"{oracle_id}: flow records do not match required order")
        require(len(flow_ids) == len(set(flow_ids)), f"{oracle_id}: duplicate flow id")

        invalid = oracle.get("invalid_reasons")
        require(isinstance(invalid, dict) and set(invalid) == expected["invalid"],
                f"{oracle_id}: wrong invalid reason set")
        predicate = oracle.get("predicate")
        require(predicate == expected["predicate"], f"{oracle_id}: frozen predicate drift")
        require(predicate["invalid_precedence"] == list(invalid),
                f"{oracle_id}: invalid precedence and reason order differ")
        for flow in flows:
            failure = flow.get("failure_code")
            require(failure is None or failure in invalid, f"{oracle_id}: unknown flow failure code {failure}")
            require(failure == expected["failures"][flow["id"]],
                    f"{oracle_id}: wrong failure code for {flow['id']}")
            for field in ("principal", "action", "control"):
                require(isinstance(flow.get(field), str) and flow[field], f"{oracle_id}: empty flow {field}")

        checks = oracle.get("numbered_checks")
        require(isinstance(checks, list) and len(checks) == expected["checks"],
                f"{oracle_id}: wrong numbered check count")
        expected_ids = [f'{expected["prefix"]}-{index:02d}' for index in range(1, len(checks) + 1)]
        check_ids = [check.get("id") for check in checks]
        require(check_ids == expected_ids, f"{oracle_id}: checks are not contiguous and ordered")
        require(len(check_ids) == len(set(check_ids)), f"{oracle_id}: duplicate check id")
        kinds = {check.get("kind") for check in checks}
        require(kinds == CHECK_KINDS, f"{oracle_id}: missing mutation check kind {sorted(CHECK_KINDS - kinds)}")
        for check in checks:
            require(isinstance(check.get("check"), str) and check["check"], f"{check['id']}: empty check")
            killed_by = check.get("killed_by")
            require(isinstance(killed_by, list) and killed_by, f"{check['id']}: no killing fixture")
            for reference in killed_by:
                if re.fullmatch(r"F-[0-9]{2}", reference):
                    require(reference in plan_fixtures, f"{check['id']}: unknown plan fixture {reference}")
                elif reference.startswith("development:"):
                    resolve_truth(truth, reference)
                else:
                    require(reference == "M0-ADD-03" and reference in baseline,
                            f"{check['id']}: unknown evidence reference {reference}")
            require(adr.count(f"| {check['id']} |") == 1, f"{check['id']}: absent or duplicated in ADR")
        total_checks += len(checks)

        misses = oracle.get("known_misses")
        require(isinstance(misses, list) and len(misses) >= 4 and all(misses),
                f"{oracle_id}: known misses are incomplete")
        require(adr.count(f"## `{oracle_id}`") == 1, f"{oracle_id}: missing ADR section")

    private = oracles["web.private-object-read.v1"]
    boundary = private.get("scope_boundary", {})
    require(boundary.get("unsupported_claim_classes") == [
        "collection_disclosure", "object_existence_or_status"
    ], "object-read scope boundary does not name both excluded claim classes")
    require(boundary.get("dispatch_result") == "ORACLE_UNAVAILABLE"
            and boundary.get("dispatch_timing") == "before target traffic",
            "unsupported classes are not refused before traffic")
    notes = " ".join(boundary.get("notes", []))
    require("CANARY_NOT_SPECIFIC" in notes and "OBSERVER_INVALID" in notes,
            "scope boundary does not preserve both M0 distinctions")
    private_misses = " ".join(private["known_misses"])
    require("cross-account or tenant-wide state that reaches across accounts" in private_misses
            and "separate verifier principals close the account-level route" in private_misses,
            "object-read known misses reverse the account-level isolation guarantee")

    private_truth = truth["decoys"]
    require(private_truth["same_subject"]["expected"]["reason"] == "SAME_SUBJECT", "fixture drift: same subject")
    require(private_truth["login_page"]["expected"]["reason"] == "OBSERVER_INVALID", "fixture drift: login page")
    require(private_truth["canary_echo"]["expected"]["reason"] == "CANARY_NOT_SPECIFIC", "fixture drift: echo")
    require(private_truth["session_expiry"]["expected"]["reason"] == "SESSION_DRIFT", "fixture drift: session")
    require(truth["flaws"]["shared_private_cache"]["expected"]["qualification"] == "after_owner_read",
            "fixture drift: cache qualification")
    require(truth["flaws"]["cross_user_order_patch"]["operation"] == "write"
            and truth["flaws"]["cross_user_order_patch"]["expected"]["oracle"] == "true",
            "fixture drift: forbidden state change")

    state_misses = " ".join(oracles["web.forbidden-state-change.v1"]["known_misses"])
    require(all(term in state_misses for term in ("canary string", "delete", "cancel", "approve")),
            "state-change known misses do not preserve the class boundary")
    require("contract_only" in adr and "100%" in adr, "ADR overstates qualification or omits mutation gate")
    return len(oracles), total_checks


def load_inputs() -> tuple[dict, str, str, dict, str]:
    return (
        json.loads(CONTRACT.read_text(encoding="utf-8")),
        ADR.read_text(encoding="utf-8"),
        PLAN.read_text(encoding="utf-8"),
        json.loads(TRUTH.read_text(encoding="utf-8")),
        BASELINE.read_text(encoding="utf-8"),
    )


def main() -> int:
    try:
        oracles, checks = validate(*load_inputs())
    except (OSError, json.JSONDecodeError, ValueError) as error:
        print(f"oracle specifications: {error}", file=sys.stderr)
        return 1
    print(f"oracle specifications: {oracles} frozen oracles, {checks} numbered mutation checks")
    return 0


if __name__ == "__main__":
    sys.exit(main())
