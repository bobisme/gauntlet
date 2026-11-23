#!/usr/bin/env python3
"""Static and record gate for the M0.4.3 real-application smoke.

Runs without the network, Podman or a model. It verifies:

1. the frozen visible inputs are byte-identical to the M0.4 materials,
2. the engagement template declares every class and names no flaw,
3. the target pin and Containerfile are consistent and contain no source mutation,
4. the frozen A/B assignment matches the locks and the recorded arm inputs,
5. each committed smoke session is internally consistent and proven torn down.

A failure exits 1 so `just check` stops.
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
import sys
from pathlib import Path

REALAPP = Path(__file__).resolve().parent
REPO = REALAPP.parents[1]
M0_LOCK = json.loads((REPO / "evals/m0-baseline/materials.lock.json").read_text())
TARGET_LOCK = json.loads((REALAPP / "target.lock.json").read_text())
MATERIALS_LOCK = json.loads((REALAPP / "materials.lock.json").read_text())
FROZEN = REALAPP / "frozen-assignment.json"
FAILURES: list[str] = []
CHECKS = 0


def check(condition: bool, message: str) -> None:
    global CHECKS
    CHECKS += 1
    if not condition:
        FAILURES.append(message)


def sha256_file(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def load_session_frozen_assignment(session_dir: Path, session: dict) -> dict:
    """Load and authenticate a session's immutable assignment snapshot."""
    metadata = session.get("frozen_assignment")
    if not isinstance(metadata, dict):
        raise ValueError("session has no frozen-assignment snapshot metadata")
    if metadata.get("path") != "referee/frozen-assignment.json":
        raise ValueError("session frozen-assignment path is not the canonical relative path")
    snapshot = session_dir / metadata["path"]
    if not snapshot.is_file():
        raise ValueError("session frozen-assignment snapshot is missing")
    digest = sha256_file(snapshot)
    if metadata.get("sha256") != digest or session.get("frozen_assignment_sha256") != digest:
        raise ValueError("session frozen-assignment snapshot digest does not match its record")
    return json.loads(snapshot.read_text())


def main() -> int:
    # 1. frozen inputs
    for rel, record in MATERIALS_LOCK["copied_from_m0_baseline"].items():
        path = REALAPP / "materials" / rel
        check(path.is_file(), f"missing frozen input {rel}")
        if path.is_file():
            check(sha256_file(path) == record["sha256"], f"{rel} differs from its recorded digest")
            source = REPO / record["source"]
            check(source.is_file() and sha256_file(source) == record["sha256"],
                  f"{rel} is not byte-identical to {record['source']}")
        expected_key = rel.replace("condition-b/", "")
        if expected_key in M0_LOCK["files"]:
            check(record["sha256"] == M0_LOCK["files"][expected_key],
                  f"{rel} does not match the committed M0.4 materials lock")
    for rel, digest in MATERIALS_LOCK["files"].items():
        path = REALAPP / rel
        check(path.is_file() and sha256_file(path) == digest, f"{rel} differs from materials.lock.json")

    # 2. engagement template content
    template = json.loads((REALAPP / "materials/engagement.template.json").read_text())
    placeholder = MATERIALS_LOCK["engagement_rendering"]["placeholder"]
    raw_template = (REALAPP / "materials/engagement.template.json").read_text()
    check(raw_template.count(placeholder) == MATERIALS_LOCK["engagement_rendering"]["occurrences"],
          "engagement template placeholder count changed")
    names = {resource["name"] for resource in template["resources"]}
    check({"books", "users", "user_password", "user_email", "user_debug"} <= names,
          "the engagement no longer declares every resource class")
    for resource in template["resources"]:
        check(bool(resource.get("fields")) and bool(resource.get("operations")),
              f"resource {resource.get('name')} lost its declared fields or operations")
        check(any(key in resource for key in ("readers", "writers")),
              f"resource {resource.get('name')} lost its policy rule")
    accounts = {account["username"] for account in template["accounts"]}
    check({"alice", "bob", "carol"} <= accounts, "the engagement lost an explicit test account")
    check(MATERIALS_LOCK["instrument"]["name"] == "none",
          "the instrument declaration changed; the runner does not configure one")
    for path in sorted((REALAPP / "materials").rglob("*")):
        if not path.is_file():
            continue
        text = path.read_text(errors="replace").lower()
        for token in ("vulnerab", "bola", "broken object", "flaw", "expected finding", "exploit"):
            check(token not in text, f"visible input {path.name} names a flaw ({token})")

    # 3. target pin and image recipe
    containerfile = (REALAPP / "container/Containerfile").read_text()
    check(TARGET_LOCK["container"]["base_image_digest"] in containerfile,
          "Containerfile does not pin the recorded base image digest")
    check(re.search(r"^ENV .*vulnerable=1", containerfile, re.M) is not None,
          "Containerfile does not select the upstream documented vulnerable mode")
    check("tokentimetolive=3600" in containerfile,
          "Containerfile does not record the configured token lifetime")
    for forbidden in ("patch", "sed -i", "git apply", "books.py"):
        check(forbidden not in containerfile, f"Containerfile contains a source mutation step ({forbidden})")
    check(not list(REALAPP.rglob("*.patch")) and not list(REALAPP.rglob("*.diff")),
          "a patch or diff artifact is present; the target must be the unmodified upstream revision")
    manifest = TARGET_LOCK["upstream"]["file_manifest"]
    check(len(manifest) == 22, "the upstream file manifest is incomplete")
    check(set(manifest) >= {"api_views/books.py", "api_views/users.py", "requirements.txt", "app.py"},
          "the upstream manifest lost a file the target depends on")
    check(TARGET_LOCK["documents_flaw"]["no_local_mutation"].startswith("The exercised flaw is upstream"),
          "the target lock does not assert that the flaw is upstream")
    check(TARGET_LOCK["runtime"]["environment"] == {"vulnerable": "1", "tokentimetolive": "3600"},
          "the runtime environment changed")

    # 4. frozen assignment
    check(FROZEN.is_file(), "frozen-assignment.json is missing; run `run_smoke.py freeze`")
    if FROZEN.is_file():
        frozen = json.loads(FROZEN.read_text())
        check(frozen["scored"] is False and frozen["gating"] is False,
              "the frozen assignment claims a score or a gate")
        check(frozen["target"]["lock_sha256"] == sha256_file(REALAPP / "target.lock.json"),
              "the frozen assignment predates the current target lock")
        check(frozen["materials_lock_sha256"] == sha256_file(REALAPP / "materials.lock.json"),
              "the frozen assignment predates the current materials lock")
        check(frozen["model"]["model"] == "orca/orcacyber-flash-1.0",
              "the frozen model changed")
        check(frozen["instrument"]["name"] == "none", "the frozen instrument changed")
        check(frozen["arms"]["A"]["additional_inputs"] == []
              and frozen["arms"]["B"]["additional_inputs"] == ["materials/condition-b/methodology.md"],
              "the only assigned difference is not the condition-B guidance file")
        check(frozen["order"] == ["A", "B"], "the frozen arm order is not A then B")
        check(bool(frozen["target"].get("image_id")),
              "the frozen assignment does not identify the locally built image")

    # 5. runner source parses
    runner = REALAPP / "run_smoke.py"
    ast.parse(runner.read_text())
    source = runner.read_text()
    for required in ("start_new_session=True", "container_exists", "pristine.db", "no-session",
                     "methodology.md", "contamination_audit", "expected_image_labels",
                     "verify_image_labels", 'requested_arms != ["a", "b"]'):
        check(required in source, f"runner lost {required}")

    # 6. committed smoke sessions
    smoke = REALAPP / "smoke"
    sessions = sorted(path for path in smoke.iterdir() if path.is_dir()) if smoke.is_dir() else []
    for session_dir in sessions:
        session_file = session_dir / "session.json"
        check(session_file.is_file(), f"{session_dir.name}: session.json missing")
        if not session_file.is_file():
            continue
        session = json.loads(session_file.read_text())
        try:
            session_frozen = load_session_frozen_assignment(session_dir, session)
        except (ValueError, json.JSONDecodeError) as error:
            check(False, f"{session_dir.name}: {error}")
            session_frozen = None
        check(session["scored"] is False and session["gating"] is False,
              f"{session_dir.name}: session claims a score or a gate")
        if session_frozen is not None:
            check(session["target"]["lock_sha256"] == session_frozen["target"]["lock_sha256"],
                  f"{session_dir.name}: session target differs from its frozen assignment")
            check(session["materials_lock_sha256"] == session_frozen["materials_lock_sha256"],
                  f"{session_dir.name}: session materials differ from its frozen assignment")
        check(session["teardown"]["containers_absent"] is True,
              f"{session_dir.name}: teardown did not prove the container is gone")
        check(session["rendered_engagement"]["sha256"], f"{session_dir.name}: no rendered engagement hash")
        rendered = session_dir / "rendered/engagement.json"
        check(rendered.is_file() and sha256_file(rendered) == session["rendered_engagement"]["sha256"],
              f"{session_dir.name}: rendered engagement is missing or changed")
        check(rendered.is_file() and placeholder not in rendered.read_text(),
              f"{session_dir.name}: rendered engagement still contains the placeholder")
        check((session_dir / "README.md").is_file(),
              f"{session_dir.name}: session README missing")
        check((session_dir / "referee/seed-proof.json").is_file(),
              f"{session_dir.name}: no referee seed proof")
        claim_review = session_dir / "referee/claim-review.json"
        check(claim_review.is_file(), f"{session_dir.name}: no referee claim review")
        if claim_review.is_file():
            review = json.loads(claim_review.read_text())
            check(review["graded"] is False, f"{session_dir.name}: claim review claims a grade")
            check(set(review["arms"]) == {"a", "b"},
                  f"{session_dir.name}: claim review does not cover exactly both arms")
            for arm, data in review["arms"].items():
                check(data["every_claim_traceable_to_a_tool_result"] is True,
                      f"{session_dir.name}/arm-{arm}: a submitted claim has no transcript evidence")
                check(data["claim_count"] == sum(
                    1 for claim in data["claims"] if claim["support_reading"] == "supported"),
                      f"{session_dir.name}/arm-{arm}: claim count disagrees with the claim list")
        if (session_dir / "referee/seed-proof.json").is_file():
            proof = json.loads((session_dir / "referee/seed-proof.json").read_text())
            check(proof["read_oracle_class"]["expected_finding_observed"] is True,
                  f"{session_dir.name}: the seeded read behaviour was not proven")
        arms = session.get("arms", {})
        check(set(arms) == {"a", "b"},
              f"{session_dir.name}: a committed session must contain exactly arms a and b")
        check(session.get("arm_order") == ["a", "b"],
              f"{session_dir.name}: committed arm order must be a then b")
        if session.get("status") == "complete":
            check(all(arm.get("status") == "completed" and not arm.get("failed")
                      for arm in arms.values()),
                  f"{session_dir.name}: complete status does not describe two completed arms")
        inputs = {}
        system_sections = {}
        for arm in arms:
            arm_dir = session_dir / f"arm-{arm}"
            run_file = arm_dir / "run.json"
            check(run_file.is_file(), f"{session_dir.name}/arm-{arm}: run.json missing")
            if not run_file.is_file():
                continue
            record = json.loads(run_file.read_text())
            assignment_file = arm_dir / "assignment.json"
            check(assignment_file.is_file(), f"{session_dir.name}/arm-{arm}: assignment missing")
            if assignment_file.is_file():
                arm_assignment = json.loads(assignment_file.read_text())
                check(arm_assignment["frozen_assignment_sha256"]
                      == session["frozen_assignment_sha256"],
                      f"{session_dir.name}/arm-{arm}: assignment snapshot digest differs")
            events = arm_dir / "events.jsonl"
            check(events.is_file() and sha256_file(events) == record["transcript"]["sha256"],
                  f"{session_dir.name}/arm-{arm}: transcript hash mismatch")
            check((arm_dir / "final-message.md").is_file(),
                  f"{session_dir.name}/arm-{arm}: final message not retained")
            check(record["rerun"] is False, f"{session_dir.name}/arm-{arm}: marked as a rerun")
            audit = record.get("contamination_audit") or {}
            check(audit.get("method") == "v2-normalized",
                  f"{session_dir.name}/arm-{arm}: contamination audit is not the normalized method")
            check(isinstance(audit.get("hits"), int),
                  f"{session_dir.name}/arm-{arm}: contamination audit has no hit count")
            for name in record["submitted"]["files"]:
                check((arm_dir / "submitted" / name).is_file(),
                      f"{session_dir.name}/arm-{arm}: submitted file {name} was not retained")
            check(record["model"]["model"] == session["model"]["model"],
                  f"{session_dir.name}/arm-{arm}: model differs from the session")
            check(record["target"]["reset"]["equal"] is True,
                  f"{session_dir.name}/arm-{arm}: target reset was not equal to the pristine database")
            check(record["teardown"]["absent_after_stop"] is True,
                  f"{session_dir.name}/arm-{arm}: container survived the arm")
            check(record["status"] in ("completed", "failed", "timed_out"),
                  f"{session_dir.name}/arm-{arm}: unknown status")
            if record["status"] != "completed":
                check(bool(record["failure_reason"]),
                      f"{session_dir.name}/arm-{arm}: a failed arm has no retained reason")
            else:
                check(record["transcript"]["events"] > 0,
                      f"{session_dir.name}/arm-{arm}: completed arm has an empty transcript")
            inputs[arm] = record["visible_inputs"]
            system_sections[arm] = record["transcript"]["system_prompt_section_sha256"]
        if set(inputs) == {"a", "b"}:
            shared = {"task.txt", "report-template.md", "engagement.json"}
            for arm in ("a", "b"):
                check(shared <= set(inputs[arm]), f"{session_dir.name}/arm-{arm}: shared input missing")
                check(inputs[arm]["engagement.json"] == session["rendered_engagement"]["sha256"],
                      f"{session_dir.name}/arm-{arm}: engagement bytes differ from the rendered copy")
            check("methodology.md" not in inputs["a"],
                  f"{session_dir.name}: condition A received the condition-B guidance")
            check("methodology.md" in inputs["b"],
                  f"{session_dir.name}: condition B did not receive its assigned guidance")
            check(session["reset_parity"]["equal"] is True,
                  f"{session_dir.name}: target state before the arms was not identical")
            check(inputs["a"]["task.txt"] == inputs["b"]["task.txt"]
                  and inputs["a"]["report-template.md"] == inputs["b"]["report-template.md"],
                  f"{session_dir.name}: common inputs differ between arms")
            shared_sections = set(system_sections["a"]) - {"cwd"}
            check(shared_sections == set(system_sections["b"]) - {"cwd"}
                  and all(system_sections["a"][name] == system_sections["b"][name]
                          for name in shared_sections),
                  f"{session_dir.name}: a non-cwd system section differs between arms")

        corrections_file = session_dir / "referee/review-corrections.json"
        check(corrections_file.is_file(), f"{session_dir.name}: referee corrections missing")
        if corrections_file.is_file():
            corrections = json.loads(corrections_file.read_text())
            check(corrections.get("raw_records_modified") is False,
                  f"{session_dir.name}: corrections do not preserve raw records")
            correction_ids = {item.get("id") for item in corrections.get("corrections", [])}
            check(correction_ids >= {"system-section-parity", "arm-a-mutation-cleanup"},
                  f"{session_dir.name}: required referee corrections are absent")
            before = json.loads((session_dir / "arm-a/target-before.json").read_text())
            after = json.loads((session_dir / "arm-a/target-after.json").read_text())
            before_books = before["books"]["body"]["Books"]
            after_books = after["books"]["body"]["Books"]
            check(len(after_books) > len(before_books),
                  f"{session_dir.name}: Arm A correction lacks the recorded persistent books")

    if FAILURES:
        for failure in FAILURES:
            print(f"FAIL: {failure}", file=sys.stderr)
        print(f"{len(FAILURES)} of {CHECKS} checks failed", file=sys.stderr)
        return 1
    print(f"real-application smoke gate: {CHECKS} checks passed "
          f"({len(sessions)} committed session(s))")
    return 0


if __name__ == "__main__":
    sys.exit(main())
