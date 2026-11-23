#!/usr/bin/env python3
"""Validate the frozen M0 condition materials and their A/B parity."""

import hashlib
import json
from pathlib import Path

import project_inventory as projector


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
LOCK = HERE / "materials.lock.json"
COMMON = {
    "common/engagement.json",
    "common/report-template.md",
    "common/task.txt",
}
RESOURCES = {
    "orders",
    "invoices",
    "tenant_notes",
    "bulletins",
    "catalog",
    "private_reports",
    "cached_reports",
    "login_reports",
    "stale_reports",
    "forbidden_reports",
    "echo_reports",
    "expiring_reports",
}
INVENTORY_COMMANDS = [
    "version",
    "projects list",
    "projects show",
    "proxy status",
    "pass show",
    "scope list",
    "hosts list",
    "flows list",
    "findings list",
    "leads list",
    "sessions list",
    "rules list",
    "intercept status",
    "intercept rules list",
    "intercept queue list",
    "scripts list",
    "scripts approvals",
    "config list",
    "macros list",
    "jobs list",
    "sitemap show",
    "authz matrix",
    "checks list",
    "commands list",
]
PROXY_VOLATILE_POINTERS = projector.PROXY_EXCLUDED_POINTERS


def require(condition, message):
    if not condition:
        raise SystemExit(f"m0 baseline materials: {message}")


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def visible_sets_are_exact(visible):
    arm_a = set(visible["condition_a"]["files"])
    arm_b = set(visible["condition_b"]["files"])
    return arm_a == COMMON and arm_b == COMMON | {"condition-b/methodology.md"}


def validate_cleanup_record(cleanup, label):
    require(
        cleanup == {
            "errors": [],
            "proxy_stop_attempted": True,
            "proxy_stopped": True,
            "proxy_status_verified": True,
            "run_root_removal_attempted": True,
            "run_root_removed": True,
            "success": True,
        },
        f"qualification cleanup did not succeed: {label}",
    )


def validate_qualification(lock, manifest_override=None, evidence_override=None):
    evidence = evidence_override or HERE / "qualification/evidence"
    manifest = manifest_override or json.loads((evidence / "manifest.json").read_text(encoding="utf-8"))
    require(manifest["schema_version"] == 1, "unsupported qualification evidence schema")
    capture_script = ROOT / manifest["capture_script"]
    require(sha256(capture_script) == manifest["capture_script_sha256"], "qualification capture script changed")
    require(manifest["teapot"]["sha256"] == lock["teapot"]["binary_sha256"], "qualification used another Teapot binary")
    require(manifest["teapot"]["version_stdout"] == lock["teapot"]["version_stdout"], "qualification used another Teapot version")
    approval_source = ROOT / manifest["approval_source"]
    require(sha256(approval_source) == manifest["approval_source_sha256"], "qualification approval source changed")
    require(manifest["inventory_commands"] == INVENTORY_COMMANDS, "qualification inventory command set differs")
    expected_schemas = {f"schemas/{filename}" for filename in projector.SCHEMA_FILES.values()}
    require(set(manifest["schema_files"]) == expected_schemas, "qualification must capture all 24 projected command schemas")
    for name, expected in manifest["schema_files"].items():
        require(sha256(evidence / name) == expected, f"qualification schema hash changed: {name}")
    for name, expected in manifest["supporting_files"].items():
        require(sha256(evidence / name) == expected, f"qualification supporting-file hash changed: {name}")
    roots = []
    project_ids = []
    raw_hashes = []
    projection_digests = []
    require([run["label"] for run in manifest["runs"]] == ["run-a", "run-b"], "qualification run set changed")
    cleanup_success = []
    for run in manifest["runs"]:
        raw_path = evidence / run["raw_inventory"]
        projected_path = evidence / run["projected"]
        creation_path = evidence / run["creation_evidence"]
        require(sha256(raw_path) == run["raw_inventory_sha256"], f"raw inventory hash changed: {run['label']}")
        require(sha256(projected_path) == run["projected_sha256"], f"projection evidence hash changed: {run['label']}")
        require(sha256(creation_path) == run["creation_evidence_sha256"], f"creation evidence hash changed: {run['label']}")
        raw = json.loads(raw_path.read_text(encoding="utf-8"))
        projection, digest = projector.project_inventory(raw)
        committed = json.loads(projected_path.read_text(encoding="utf-8"))
        require(projection == committed["projection"], f"projection replay changed: {run['label']}")
        require(digest == committed["sha256"] == run["semantic_projection_sha256"], f"projection digest changed: {run['label']}")
        require(projection["prelaunch"]["eligible"], f"qualification run is not eligible: {run['label']}")
        require(run["eligible"] == projection["prelaunch"]["eligible"], f"declared eligibility differs: {run['label']}")
        creation = json.loads(creation_path.read_text(encoding="utf-8"))
        require(all(creation["before_setup"].values()), f"qualification path was reused: {run['label']}")
        require(all(creation["fresh_environment_directories_empty"].values()), f"qualification environment was not empty: {run['label']}")
        project_row = raw["projects_list"]["projects"][0]
        project_show = raw["projects_show"]["project"]
        require(run["project_id"] == project_row["id"] == project_show["id"] == creation["after_setup"]["project_id"], f"qualification project id differs from raw evidence: {run['label']}")
        require(run["project"] == project_row["path"] == project_show["path"] == creation["project"], f"qualification project path differs from raw evidence: {run['label']}")
        require(run["run_root"] == creation["run_root"], f"qualification run root differs from creation evidence: {run['label']}")
        require(run["approval"] == creation["approval"], f"qualification approval path differs from creation evidence: {run['label']}")
        require(creation["raw_inventory_sha256"] == run["raw_inventory_sha256"], f"creation raw hash differs: {run['label']}")
        require(creation["projected_sha256"] == run["projected_sha256"], f"creation projection hash differs: {run['label']}")
        require(creation["semantic_projection_sha256"] == digest, f"creation semantic digest differs: {run['label']}")
        cleanup = json.loads((evidence / run["label"] / "cleanup.json").read_text(encoding="utf-8"))
        validate_cleanup_record(cleanup, run["label"])
        cleanup_success.append(cleanup["success"])
        roots.append(run["run_root"])
        project_ids.append(run["project_id"])
        raw_hashes.append(run["raw_inventory_sha256"])
        projection_digests.append(digest)
    require(len(set(roots)) == len(roots) == 2, "qualification run roots were reused")
    require(len(set(project_ids)) == len(project_ids) == 2, "qualification project IDs were reused")
    require(len(set(raw_hashes)) == 2, "qualification raw inventories did not retain run volatility")
    require(len(set(projection_digests)) == 1, "qualification semantic projections differ")
    attestation = manifest["attestation"]
    require(attestation["fresh_roots_and_project_ids_unique"], "qualification uniqueness attestation failed")
    require(attestation["raw_inventory_hashes_distinct"], "qualification raw evidence attestation failed")
    require(attestation["semantic_projections_equal"], "qualification projection attestation failed")
    require(attestation["both_prelaunch_eligible"], "qualification eligibility attestation failed")
    require(attestation["semantic_projection_sha256"] == projection_digests[0], "qualification declared semantic digest differs")
    require(attestation["fresh_roots_and_project_ids_unique"] == (len(set(roots)) == len(set(project_ids)) == 2), "qualification uniqueness attestation differs from evidence")
    require(attestation["raw_inventory_hashes_distinct"] == (len(set(raw_hashes)) == 2), "qualification raw hash attestation differs from evidence")
    require(attestation["semantic_projections_equal"] == (len(set(projection_digests)) == 1), "qualification projection attestation differs from evidence")
    require(attestation["both_prelaunch_eligible"] == all(run["eligible"] for run in manifest["runs"]), "qualification eligibility attestation differs from evidence")
    require(attestation["all_cleanup_succeeded"] == all(cleanup_success), "qualification cleanup attestation differs from evidence")
    require(attestation["assessment_agents_started"] == 0, "qualification started an assessment agent")
    require(attestation["target_requests_sent"] == 0, "qualification sent target traffic")


def main():
    lock = json.loads(LOCK.read_text(encoding="utf-8"))
    require(lock["schema_version"] == 1, "unsupported lock schema")
    require(lock["status"] == "frozen before first scored M0.4 baseline run", "lock is not frozen")

    expected_files = set(lock["files"])
    actual_files = {
        str(path.relative_to(HERE))
        for path in HERE.rglob("*")
        if path.is_file() and path.name not in {"materials.lock.json", "check-materials.py"}
    }
    require(actual_files == expected_files, f"unlocked material files: expected {sorted(expected_files)}, got {sorted(actual_files)}")
    for name, expected in lock["files"].items():
        require(sha256(HERE / name) == expected, f"hash mismatch for {name}")

    visible = lock["visible_inputs"]
    require(visible_sets_are_exact(visible), "condition A must be common files and condition B must add only methodology prose")
    mutated_visible = json.loads(json.dumps(visible))
    mutated_visible["condition_b"]["files"].append("condition-b/unlocked-extra.txt")
    require(not visible_sets_are_exact(mutated_visible), "visible-input regression failed to reject an extra B file")
    require(
        visible["condition_a"]["native_instrument_docs"]
        == visible["condition_b"]["native_instrument_docs"],
        "native instrument documentation differs between arms",
    )

    task = (HERE / "common/task.txt").read_text(encoding="utf-8").lower()
    require("assess cross-user access" in task and "report" in task and "evidence" in task, "task objective changed")
    require("teapot" not in task and "scourge" not in task, "task names a tool")

    engagement = json.loads((HERE / "common/engagement.json").read_text(encoding="utf-8"))
    require(engagement["schema_version"] == 1, "unsupported engagement schema")
    require(
        [account["username"] for account in engagement["accounts"]] == ["alice", "bob", "admin"],
        "exploration account pool changed or became a named pair",
    )
    require(
        all("verify" not in account["username"] for account in engagement["accounts"]),
        "verifier account exposed",
    )
    resources = engagement["resources"]
    require({resource["name"] for resource in resources} == RESOURCES, "resource declarations are incomplete")
    require(len(resources) == len(RESOURCES), "resource declaration is duplicated")
    require(all(resource.get("readers") for resource in resources), "resource policy is missing")
    require(
        all(not ({"expected", "finding", "flaw", "decoy", "control"} & set(resource)) for resource in resources),
        "resource declaration carries a case-specific hint",
    )

    contract_path = ROOT / lock["teapot"]["contract_manifest"]
    require(sha256(contract_path) == lock["teapot"]["contract_manifest_sha256"], "Teapot contract manifest changed")
    contract = json.loads(contract_path.read_text(encoding="utf-8"))
    require(contract["source_commit"] == lock["teapot"]["source_commit"], "Teapot source pin differs")
    require(contract["binary_sha256"] == lock["teapot"]["binary_sha256"], "Teapot binary pin differs")

    runtime = lock["runtime_instrument_contract"]
    require(runtime["lifecycle"].startswith("fresh run-private project"), "fresh Teapot lifecycle is not required")
    require(runtime["inventory_commands"] == INVENTORY_COMMANDS, "initial Teapot inventory is incomplete")
    require(
        {"flows", "findings", "leads", "sessions", "user rules", "intercept rules", "user and project scripts"}
        <= set(runtime["empty"]),
        "initial visible Teapot state is not constrained",
    )
    require("host pins are empty" in runtime["configured"], "initial host pins are not constrained")
    require("equal semantic-projection SHA-256 before launch" in runtime["comparison"], "semantic cross-arm state equality is not required")
    projection = runtime["semantic_projection"]
    require(projection["version"] == 1, "semantic projection version changed")
    require(
        projection["proxy_status_excluded_json_pointers"] == PROXY_VOLATILE_POINTERS,
        "proxy telemetry exclusion list changed",
    )
    require(
        projection["approval_normalized_json_pointers"] == projector.APPROVAL_NORMALIZED_POINTERS,
        "approval normalization list changed",
    )
    require(projection["version"] == projector.SCHEMA_VERSION, "projector code and lock versions differ")
    require(projection["implementation"] == "evals/m0-baseline/project_inventory.py", "projector implementation path changed")
    require(
        projection["pinned_identity_sha256"]
        == {
            "scripts": projector.EXPECTED_SCRIPTS_SHA256,
            "checks": projector.EXPECTED_CHECKS_SHA256,
            "authorization_matrix_legend": projector.EXPECTED_MATRIX_LEGEND_SHA256,
        },
        "pinned native identity digests differ from projector code",
    )
    require(projection["unknown_field_policy"].startswith("fail projection"), "unknown telemetry can be silently ignored")
    require(projection["global_excluded_json_pointers"] == ["/advice"], "global projection exclusion changed")
    require(
        set(projection["selected_by_command"])
        == {
            "version",
            "projects list, projects show",
            "proxy status",
            "pass show",
            "scope list",
            "hosts list",
            "flows, findings, leads, sessions, intercept queue, macros, jobs, sitemap, authz matrix",
            "rules list, intercept status, intercept rules list",
            "scripts list, scripts approvals, checks list, commands list",
            "config list",
        },
        "per-command semantic projection is incomplete",
    )
    included = " ".join(projection["include"])
    for required in ("rule", "script", "check", "scope", "host pins", "pass", "meaningful"):
        require(required in included, f"semantic projection omits {required}")

    validate_qualification(lock)

    print("m0 baseline materials: frozen hashes and A/B parity verified")


if __name__ == "__main__":
    main()
