#!/usr/bin/env python3
"""M0.7-to-M1 contract and live tracker reconciliation gate."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import tomllib


ROOT = Path(__file__).resolve().parents[1]
TRACKER_ACCEPTANCE_MARKER = "# M0.7 frozen-contract acceptance"

EXPECTED_BONES = {
    "bn-10s", "bn-14c", "bn-14o", "bn-1aw", "bn-1ca", "bn-1j8",
    "bn-1qi", "bn-1st", "bn-1wj", "bn-1wp", "bn-1y5", "bn-1zv",
    "bn-20h", "bn-20l", "bn-20u", "bn-23g", "bn-23h", "bn-24d",
    "bn-24s", "bn-24v", "bn-25j", "bn-264", "bn-26a", "bn-26c",
    "bn-27k", "bn-27p", "bn-28q", "bn-2a3", "bn-2ai", "bn-2c6",
    "bn-2dq", "bn-2e6", "bn-2el", "bn-2f7", "bn-2ij", "bn-2kf",
    "bn-2s7", "bn-2w2", "bn-360", "bn-36n", "bn-3bh", "bn-3dv",
    "bn-3gx", "bn-3jd", "bn-3lg", "bn-3s5", "bn-dip", "bn-f1x",
    "bn-g2i", "bn-ijh", "bn-iv7", "bn-jcq", "bn-r3b", "bn-tnk",
    "bn-xwe",
}

EXPECTED_ACCEPTANCE_BONES = {
    "bn-10s", "bn-14o", "bn-1aw", "bn-1j8", "bn-1qi", "bn-1st",
    "bn-1wj", "bn-1wp", "bn-20h", "bn-20l", "bn-20u", "bn-23g",
    "bn-23h", "bn-24d", "bn-24s", "bn-24v", "bn-25j", "bn-264",
    "bn-26a", "bn-26c", "bn-27k", "bn-28q", "bn-2a3", "bn-2ai",
    "bn-2c6", "bn-2e6", "bn-2el", "bn-2f7", "bn-2ij", "bn-2s7",
    "bn-2w2", "bn-360", "bn-36n", "bn-3bh", "bn-3gx", "bn-3jd",
    "bn-3lg", "bn-3s5", "bn-dip", "bn-g2i", "bn-ijh", "bn-iv7",
    "bn-jcq", "bn-r3b", "bn-tnk", "bn-xwe",
}

REQUIRED_ROUTES = {
    "bn-1aw": {"scourge.response.v1", "M0-ADD-01"},
    "bn-24v": {"scourge.response.v1", "M0-ADD-01"},
    "bn-360": {"M0-ADD-01", "M0-ADD-02", "M0-ADD-04"},
    "bn-36n": {"scourge.oracle-specifications.v1", "M0-ADD-03"},
    "bn-20l": {"scourge.oracle-specifications.v1", "M0-ADD-03"},
    "bn-23g": {"scourge.response.v1", "M0-ADD-03"},
    "bn-tnk": {"scourge.claim-template.v1"},
    "bn-1wp": {"scourge.engagement.v1", "scourge.policy-rule.v1"},
    "bn-2f7": {"scourge.verification.v1", "scourge.publication-intent.v1"},
}

EXPECTED_ERROR_EXITS = {
    "USAGE_ERROR": 2,
    "SCHEMA_INVALID": 2,
    "SLOT_CONFLICT": 2,
    "WORKSPACE_UNBOUND": 3,
    "ENGAGEMENT_REQUIRED": 3,
    "OBJECT_NOT_FOUND": 3,
    "INPUT_REQUIRED": 3,
    "INPUT_AMBIGUOUS": 3,
    "CONFLICTING_RUN": 4,
    "REVISION_CONFLICT": 4,
    "IDEMPOTENCY_KEY_REUSED": 4,
    "SLOTS_INCOMPLETE": 5,
    "IDENTITY_UNESTABLISHED": 5,
    "EVIDENCE_INCOMPLETE": 5,
    "ORACLE_UNAVAILABLE": 5,
    "CAPABILITY_UNAVAILABLE": 5,
    "INTEGRITY_FAILURE": 6,
    "DEPENDENCY_UNAVAILABLE": 7,
    "EFFECT_UNKNOWN": 7,
    "AUTHORITY_REQUIRED": 8,
    "SCOPE_REFUSED": 8,
    "BUDGET_REFUSED": 8,
    "ENFORCEMENT_UNAVAILABLE": 8,
    "CUSTODY_UNAVAILABLE": 8,
    "METHOD_REFUSED": 8,
    "INSTRUMENT_EDITS_ACTIVE": 8,
    "ACCOUNTING_UNESTABLISHED": 8,
}


def section(text: str, start: str, end: str) -> str:
    after = text.split(start, 1)[1]
    return after.split(end, 1)[0]


def default_workspace_root(repo_root: Path = ROOT) -> Path:
    """Return the Maw default workspace, not an ephemeral workspace snapshot."""
    resolved = repo_root.resolve()
    workspaces = resolved.parent
    maw = workspaces.parent
    if workspaces.name == "workspaces" and maw.name == ".maw":
        return maw.parent
    return resolved


def _bn_json(tracker_root: Path, *arguments: str) -> dict:
    result = subprocess.run(
        ["bn", *arguments],
        cwd=tracker_root,
        text=True,
        capture_output=True,
    )
    assert result.returncode == 0, (
        f"bn {' '.join(arguments)} failed in {tracker_root}: "
        f"{result.stderr.strip() or result.stdout.strip()}"
    )
    return json.loads(result.stdout)


def load_live_tracker(recut: dict, repo_root: Path = ROOT) -> dict:
    """Read the current default-workspace Bones projection without writing it."""
    tracker_root = default_workspace_root(repo_root)
    assert (tracker_root / ".bones/config.toml").is_file(), (
        f"live tracker not found at {tracker_root}"
    )
    listing = _bn_json(
        tracker_root,
        "list",
        "--all-states",
        "--limit",
        "0",
        "--format",
        "json",
    )
    m1_ids = {
        item["id"]
        for item in listing["items"]
        if "m1" in item.get("labels", [])
    }
    bones = {
        bone_id: _bn_json(tracker_root, "show", bone_id, "--json")
        for bone_id in recut["keep_bones"]
    }
    return {
        "tracker_root": str(tracker_root),
        "m1_ids": m1_ids,
        "bones": bones,
    }


def tracker_acceptance_body(description: str, marker: str) -> str:
    assert description.count(marker) == 1, (
        f"expected exactly one {marker!r} section"
    )
    return description.split(marker, 1)[1].strip()


def validate_tracker(recut: dict, live: dict) -> None:
    """Validate all live M1 states, dependency anchors and acceptance edits."""
    keep = set(recut["keep_bones"])
    routes = set(recut["acceptance_routes"])
    tracker = recut["tracker_projection"]
    expected = tracker["bones"]
    marker = tracker["acceptance_marker"]

    assert tracker["source"] == "default-workspace local bn projection"
    assert marker == TRACKER_ACCEPTANCE_MARKER
    assert set(expected) == keep, "tracker projection must cover all 55 KEEP bones"
    assert {
        bone_id
        for bone_id, projection in expected.items()
        if "acceptance_sha256" in projection
    } == routes, "acceptance hashes must cover exactly the 46 edited bones"
    assert set(live["bones"]) == keep, "live projection is missing a KEEP bone"
    assert set(live["m1_ids"]) == keep, (
        "live M1 set differs from the 55-bone disposition: "
        f"missing={sorted(keep - set(live['m1_ids']))}, "
        f"extra={sorted(set(live['m1_ids']) - keep)}"
    )

    for bone_id in sorted(keep):
        bone = live["bones"][bone_id]
        projection = expected[bone_id]
        assert bone["id"] == bone_id
        state = bone.get("state")
        assert state in ("open", "doing", "done"), (
            f"KEEP bone {bone_id} has invalid lifecycle state {state!r}"
        )
        assert "m1" in bone.get("labels", []), f"{bone_id} lost its m1 label"
        assert bone.get("parent_id") == projection["parent_id"], (
            f"{bone_id} parent changed: {bone.get('parent_id')!r} != "
            f"{projection['parent_id']!r}"
        )
        assert set(bone.get("depends_on", [])) == set(projection["depends_on"]), (
            f"{bone_id} dependency anchors changed: "
            f"{sorted(bone.get('depends_on', []))} != "
            f"{sorted(projection['depends_on'])}"
        )

        description = bone["description"]
        if bone_id in routes:
            body = tracker_acceptance_body(description, marker)
            actual_digest = hashlib.sha256(body.encode()).hexdigest()
            assert actual_digest == projection["acceptance_sha256"], (
                f"{bone_id} frozen-contract acceptance changed: "
                f"{actual_digest} != {projection['acceptance_sha256']}"
            )
        else:
            assert marker not in description, (
                f"{bone_id} has an unmanifested frozen-contract acceptance edit"
            )

    boundary = tracker_acceptance_body(
        live["bones"]["bn-23g"]["description"], marker
    )
    for required in (
        "collection-disclosure",
        "object-existence/status",
        "stay leads",
        "`verify --plan` is read-only",
        "`ORACLE_UNAVAILABLE` plus supported classes",
        "`verify` returns exit 5 before target traffic",
        "neither promotions nor negative object-read findings",
    ):
        assert required in boundary, f"bn-23g lost acceptance boundary: {required}"


def main() -> None:
    recut = json.loads((ROOT / "docs/contracts/m1-recut.v1.json").read_text())
    assert recut["schema"] == "scourge.m1-recut.v1"
    assert recut["base_plan_revision"] == 5
    assert recut["result_plan_revision"] == 6
    result = recut["m0_result"]
    assert result == {
        "assigned_sessions": 10,
        "valid_sessions": 6,
        "invalid_sessions": 4,
        "taxonomy_adjudicable": True,
        "unsupported_claims": 2,
        "preregistered_threshold": 2,
        "failed_prerequisite": "ten-valid-sessions",
        "outcome": "inconclusive",
        "branch": "none",
        "m1_scope": "verifier-led-shared-custody-retained",
    }

    keep = recut["keep_bones"]
    assert len(keep) == len(set(keep)) == 55
    assert set(keep) == EXPECTED_BONES
    assert recut["cut_bones"] == []
    assert recut["split_bones"] == []
    assert recut["counts"] == {
        "obligations_kept": 11,
        "invariants_kept": 51,
        "fixtures_kept": 53,
        "acceptance_additions": 4,
        "m1_bones_reviewed": 55,
        "m1_bones_with_contract_acceptance_edits": 46,
        "m1_bones_cut": 0,
        "m1_bones_split": 0,
    }
    assert recut["contracts"] == {
        "engagement": "scourge.engagement.v1",
        "policy_rule": "scourge.policy-rule.v1",
        "claim_template": "scourge.claim-template.v1",
        "response": "scourge.response.v1",
        "request_input": "scourge.request-input.v1",
        "verification": "scourge.verification.v1",
        "publication_intent": "scourge.publication-intent.v1",
        "accounting": "scourge.accounting.v1",
        "teapot_argv": "scourge.teapot-argv.v1",
        "oracle_registry": "scourge.oracle-specifications.v1",
    }

    routes = {key: set(value) for key, value in recut["acceptance_routes"].items()}
    assert set(routes) == EXPECTED_ACCEPTANCE_BONES
    for bone, required in REQUIRED_ROUTES.items():
        assert required <= routes[bone], (bone, required - routes[bone])
    assert set(recut["later_routes"]["bn-wog"]) == {"M0-ADD-02", "M0-ADD-03"}

    live_tracker = load_live_tracker(recut)
    validate_tracker(recut, live_tracker)

    contract_files = {
        "scourge.engagement.v1": ROOT / "schemas/engagement.v1.schema.json",
        "scourge.policy-rule.v1": ROOT / "schemas/policy-rule.v1.schema.json",
        "scourge.claim-template.v1": ROOT / "schemas/claim-template.v1.schema.json",
        "scourge.contract-registry.v1": ROOT / "docs/contracts/scourge-v1.json",
        "scourge.teapot-argv.v1": ROOT / "docs/contracts/teapot-argv-v1.json",
        "scourge.oracle-specifications.v1": ROOT / "docs/contracts/oracle-specifications.v1.json",
    }
    for schema, path in contract_files.items():
        document = json.loads(path.read_text())
        declared = {
            document.get("schema"),
            document.get("schema_version"),
            document.get("properties", {})
            .get("schema_version", {})
            .get("const"),
        }
        assert schema in declared, (schema, path)

    registry = json.loads((ROOT / "docs/contracts/scourge-v1.json").read_text())
    assert registry["error_exits"] == EXPECTED_ERROR_EXITS
    assert set(recut["contracts"].values()) - {
        "scourge.engagement.v1",
        "scourge.policy-rule.v1",
        "scourge.claim-template.v1",
        "scourge.teapot-argv.v1",
        "scourge.oracle-specifications.v1",
    } <= set(registry["shapes"])

    engagement_example = tomllib.loads(
        (ROOT / "fixtures/target/schema-examples/engagement.toml").read_text()
    )
    assert engagement_example["schema_version"] == "scourge.engagement.v1"
    assert engagement_example["engagement"]["target_version"].startswith("version.")

    template_example = json.loads(
        (ROOT / "fixtures/target/schema-examples/claim-template-private-object-read.json").read_text()
    )
    assert template_example["schema_version"] == "scourge.claim-template.v1"
    for slot in ("read", "plant", "remove"):
        assert template_example["slots"][slot] == {
            "kind": "property",
            "supplied_by": ["operator"],
        }

    oracle_registry = json.loads(
        (ROOT / "docs/contracts/oracle-specifications.v1.json").read_text()
    )
    object_read = oracle_registry["oracles"]["web.private-object-read.v1"]
    assert object_read["scope_boundary"] == {
        "unsupported_claim_classes": [
            "collection_disclosure",
            "object_existence_or_status",
        ],
        "dispatch_result": "ORACLE_UNAVAILABLE",
        "dispatch_timing": "before target traffic",
        "notes": [
            "CANARY_NOT_SPECIFIC rejects an object-read interpretation of the echo collection but does not refute the separately supported collection-disclosure proposition.",
            "OBSERVER_INVALID rejects an object-content read interpretation of the login-page response but does not adjudicate the separate existence/status proposition.",
        ],
    }
    assert oracle_registry["oracles"]["web.forbidden-state-change.v1"]["ships"] == "M2"

    plan = (ROOT / "notes/plan.md").read_text()
    assert "**Revision:** 6 — 2026-11-23" in plan
    assert "The taxonomy\nwas adjudicable for the six valid submissions" in plan
    assert "inconclusive** solely because the\npreregistered ten-valid-session prerequisite failed" in plan
    assert "prerequisite failed; no branch applies" in plan
    assert "taxonomy\ninadjudicable" not in plan
    recut_adr = (ROOT / "docs/adr/m1-contract-recut.md").read_text()
    assert "taxonomy\nwas adjudicable for the six valid submissions" in recut_adr
    assert "No branch applied solely\nbecause the preregistered ten-valid-session prerequisite failed" in recut_adr
    engagement = section(plan, "### 4.6 The engagement file", "## 5.")
    for forbidden in ("request = \"GET", "macro =", "DELETE /app", "PATCH /app"):
        assert forbidden not in engagement
    for required in (
        'schema_version = "scourge.engagement.v1"',
        'target_version = "version.fixture.v1"',
        'operation = "operation.orders.create"',
    ):
        assert required in engagement
    templates = section(plan, "### 6.2 Templates and slots", "### 6.3")
    assert "property slots are operator-only" in templates.lower()
    assert "cannot supply or replace the operations" in templates
    errors = section(plan, "### 8.5 Errors and exit codes", "### 8.6")
    assert all(code in errors for code in registry["error_exits"])
    responses = section(plan, "### 8.4 Responses", "### 8.5")
    response_example = json.loads(responses.split("```json", 1)[1].split("```", 1)[0])
    assert set(response_example) == set(registry["shapes"]["scourge.response.v1"])
    assert set(response_example["finding"]) == set(registry["shapes"]["finding"])
    assert set(response_example["run"]) == set(registry["shapes"]["run"])
    packages = section(plan, "### 12.2 Work packages", "### 12.3")
    assert all(marker in packages for marker in ("M0-ADD-01", "M0-ADD-02", "M0-ADD-03", "M0-ADD-04"))
    assert "ORACLE_UNAVAILABLE" in packages
    assert "M1.10 and M1.11 run beside M1 and M2. Neither is on M1's exit." in plan

    readme = (ROOT / "README.md").read_text()
    assert "M0 is in closeout" in readme
    assert "no M1 implementation claim" in readme

    print(
        "M1 re-cut: 55 live KEEP, 0 CUT, 0 SPLIT; "
        "46 acceptance edits and M0-ADD-01..04 verified from "
        f"{live_tracker['tracker_root']}"
    )


if __name__ == "__main__":
    main()
