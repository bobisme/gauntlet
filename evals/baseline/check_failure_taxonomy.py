#!/usr/bin/env python3
"""Verify the M0.4.4 taxonomy against immutable baseline evidence."""

from __future__ import annotations

from collections import Counter
from decimal import Decimal
import gzip
import hashlib
import json
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[2]
TAXONOMY_PATH = ROOT / "evals/baseline/failure-taxonomy.json"
SUMMARY_PATH = ROOT / "evals/baseline/evidence/summary.json"
GROUND_TRUTH_PATH = ROOT / "fixtures/target/referee/ground-truth.json"


def load_json(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def fail(message: str) -> None:
    raise AssertionError(message)


def expect(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def text_lines(relative_path: str) -> list[str]:
    return (ROOT / relative_path).read_text(encoding="utf-8").splitlines()


def text_range(relative_path: str, start: int, end: int) -> str:
    lines = text_lines(relative_path)
    expect(1 <= start <= end <= len(lines), f"unsafe line range for {relative_path}")
    return "\n".join(lines[start - 1 : end])


def gzip_line(relative_path: str, line_number: int) -> bytes:
    with gzip.open(ROOT / relative_path, "rb") as handle:
        for current, line in enumerate(handle, 1):
            if current == line_number:
                return line
    fail(f"missing decompressed line {line_number} in {relative_path}")


def gzip_digest(relative_path: str) -> str:
    digest = hashlib.sha256()
    with gzip.open(ROOT / relative_path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def file_digest(relative_path: str) -> str:
    digest = hashlib.sha256()
    with (ROOT / relative_path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def gzip_settled_submission(relative_path: str) -> tuple[int, dict, int, dict]:
    last_number = 0
    last_event: dict = {}
    submission_line = 0
    submission_event: dict = {}
    with gzip.open(ROOT / relative_path, "rb") as handle:
        for last_number, line in enumerate(handle, 1):
            last_event = json.loads(line)
            if (
                last_event.get("type") == "message_end"
                and (last_event.get("message") or {}).get("role") == "assistant"
            ):
                submission_line = last_number
                submission_event = last_event
    expect(submission_line > 0, f"no assistant submission in {relative_path}")
    return last_number, last_event, submission_line, submission_event


def result_text(event: dict) -> str:
    content = ((event.get("result") or {}).get("content") or [])
    if isinstance(content, str):
        return content
    return "\n".join(
        item.get("text", "") if isinstance(item, dict) else str(item)
        for item in content
    )


def decimal(value: object) -> Decimal:
    return Decimal(str(value))


def decimal_close(left: object, right: object, tolerance: str = "0.000000000000001") -> bool:
    return abs(decimal(left) - decimal(right)) <= Decimal(tolerance)


def arm_dict(counter: Counter[str]) -> dict[str, int]:
    return {arm: counter[arm] for arm in ("A", "B")}


def verify_trials(taxonomy: dict, summary: dict) -> None:
    positions = {row["position"]: row for row in summary["positions"]}
    trials = taxonomy["trials"]
    expect([row["position"] for row in trials] == list(range(1, 11)), "trial order")
    expect(set(positions) == set(range(1, 11)), "summary positions")

    token_fields = {
        "input": "input_tokens",
        "output": "output_tokens",
        "cache_read": "cache_read_tokens",
        "reasoning": "reasoning_tokens",
    }
    for trial in trials:
        position = trial["position"]
        source = positions[position]
        for target_key, source_key in (
            ("arm", "arm"),
            ("status", "status"),
            ("valid", "valid"),
            ("duration_milliseconds", "duration_milliseconds"),
            ("bash_calls", "tool_calls"),
        ):
            expect(
                trial[target_key] == source[source_key],
                f"position {position} {target_key} differs from summary",
            )
        expect(
            decimal(trial["model_usd"]) == decimal(source["model_usd"]),
            f"position {position} cost differs from summary",
        )
        for target_key, source_key in token_fields.items():
            expect(
                trial["provider_tokens"][target_key] == source[source_key],
                f"position {position} token field {target_key}",
            )

        calls_path = ROOT / f"evals/baseline/evidence/pos-{position:02d}-{trial['arm'].lower()}/tool-calls.jsonl"
        calls = [json.loads(line) for line in calls_path.read_text(encoding="utf-8").splitlines()]
        expect(len(calls) == trial["bash_calls"], f"position {position} tool-call count")
        expect(all(call.get("tool") == "bash" for call in calls), f"position {position} non-Bash tool")

    def sum_field(rows: list[dict], field: str) -> int:
        return sum(row[field] for row in rows)

    all_aggregate = taxonomy["aggregates"]["all"]
    expect(all_aggregate["trials"] == len(trials), "all trial count")
    expect(all_aggregate["valid"] == sum(row["valid"] for row in trials), "all valid count")
    expect(all_aggregate["bash_calls"] == sum_field(trials, "bash_calls"), "all Bash calls")
    expect(
        all_aggregate["duration_milliseconds"] == sum_field(trials, "duration_milliseconds"),
        "all duration",
    )
    total_cost = sum(decimal(row["model_usd"]) for row in trials)
    expect(decimal_close(all_aggregate["model_usd"], total_cost), "all cost")
    expect(
        decimal_close(
            all_aggregate["mean_model_usd_per_assigned_trial"], total_cost / len(trials)
        ),
        "all mean cost",
    )
    for key in token_fields:
        expect(
            all_aggregate["provider_tokens"][key]
            == sum(row["provider_tokens"][key] for row in trials),
            f"all {key} tokens",
        )

    valid = [row for row in trials if row["valid"]]
    valid_aggregate = taxonomy["aggregates"]["valid_only"]
    valid_cost = sum(decimal(row["model_usd"]) for row in valid)
    expect(valid_aggregate["trials"] == len(valid), "valid trial count")
    expect(decimal_close(valid_aggregate["model_usd"], valid_cost), "valid cost")
    expect(
        decimal_close(
            valid_aggregate["mean_model_usd_per_valid_trial"], valid_cost / len(valid)
        ),
        "valid mean cost",
    )

    for arm in ("A", "B"):
        rows = [row for row in trials if row["arm"] == arm]
        aggregate = taxonomy["aggregates"]["by_arm"][arm]
        cost = sum(decimal(row["model_usd"]) for row in rows)
        expect(aggregate["trials"] == len(rows), f"arm {arm} trials")
        expect(aggregate["valid"] == sum(row["valid"] for row in rows), f"arm {arm} valid")
        expect(decimal_close(aggregate["model_usd"], cost), f"arm {arm} cost")
        expect(
            decimal_close(
                aggregate["mean_model_usd_per_assigned_trial"], cost / len(rows)
            ),
            f"arm {arm} mean cost",
        )
        expect(aggregate["bash_calls"] == sum_field(rows, "bash_calls"), f"arm {arm} calls")
        expect(
            aggregate["duration_milliseconds"] == sum_field(rows, "duration_milliseconds"),
            f"arm {arm} duration",
        )
        for key in token_fields:
            expect(
                aggregate["provider_tokens"][key]
                == sum(row["provider_tokens"][key] for row in rows),
                f"arm {arm} {key} tokens",
            )

    expect(all_aggregate["model_usd"] == summary["totals"]["model_usd"], "summary total cost")
    expect(all_aggregate["bash_calls"] == summary["totals"]["tool_calls"], "summary total calls")


def verify_claims(taxonomy: dict, summary: dict) -> None:
    positions = {row["position"]: row for row in summary["positions"]}
    valid_positions = {position for position, row in positions.items() if row["valid"]}
    classifications = (
        ("supported_absent_from_key_claim_groups", "SUPPORTED_ABSENT_FROM_KEY"),
        ("unresolved_claim_groups", "UNRESOLVED_COUNTED_UNSUPPORTED"),
    )
    all_groups = [group for key, _ in classifications for group in taxonomy[key]]
    ids = [group["id"] for group in all_groups]
    expect(len(ids) == len(set(ids)), "duplicate claim group id")

    claim_tuples: set[tuple[int, str, str, str]] = set()
    checked_submissions: set[int] = set()
    settled_submissions: dict[int, tuple[int, dict, int, dict]] = {}
    cause_counts: Counter[str] = Counter()
    cause_rows: Counter[str] = Counter()
    cause_arm_counts: dict[str, Counter[str]] = {}
    for key, expected_status in classifications:
        for group in taxonomy[key]:
            position = group["position"]
            expect(position in valid_positions, f"claim from invalid position {position}")
            source = positions[position]
            arm = source["arm"]
            label = f"pos-{position:02d}-{arm.lower()}"
            evidence_prefix = f"evals/baseline/evidence/{label}"
            expect(group["arm"] == arm, f"{group['id']} arm/position binding")
            expect(group["trial_label"] == label, f"{group['id']} trial-label binding")
            expect(group["status"] == expected_status, f"{group['id']} classification")
            expect(
                group["claim_instances"] == len(group["actors_or_audiences"]),
                f"{group['id']} actor count",
            )
            expect(
                len(set(group["actors_or_audiences"])) == group["claim_instances"],
                f"{group['id']} actors unique",
            )
            for actor in group["actors_or_audiences"]:
                claim_tuple = (
                    position,
                    group["resource_class"],
                    group["operation"],
                    actor,
                )
                expect(claim_tuple not in claim_tuples, f"duplicate claim tuple {claim_tuple}")
                claim_tuples.add(claim_tuple)

            transcript = group["transcript"]
            canonical_transcript = f"{evidence_prefix}/transcript.jsonl.gz"
            expect(transcript["path"] == canonical_transcript, f"{group['id']} transcript path")
            expect(transcript["sha256"] == source["transcript_sha256"], f"{group['id']} summary digest")
            if position not in settled_submissions:
                settled_submissions[position] = gzip_settled_submission(canonical_transcript)
            last_number, last_event, submission_line, submission_event = settled_submissions[position]
            expect(
                transcript["decompressed_line"] == submission_line,
                f"{group['id']} canonical settled submission line",
            )
            line = gzip_line(canonical_transcript, transcript["decompressed_line"])
            parsed = json.loads(line)
            expect(parsed.get("type") == "message_end", f"{group['id']} transcript event")
            expect((parsed.get("message") or {}).get("role") == "assistant", f"{group['id']} assistant submission")
            expect(parsed == submission_event, f"{group['id']} canonical settled submission text")
            expect(transcript["marker"].encode() in line, f"{group['id']} transcript marker")
            final_message_path = f"{evidence_prefix}/final-message.txt"
            final_message = (ROOT / final_message_path).read_text(encoding="utf-8")
            submitted_text = "".join(
                item.get("text", "")
                for item in (parsed.get("message") or {}).get("content", [])
                if item.get("type") == "text"
            )
            expect(submitted_text == final_message, f"{group['id']} settled final message text")

            report = group["report"]
            canonical_report = f"{evidence_prefix}/workspace/report.md"
            expect(report["path"] == canonical_report, f"{group['id']} report path")
            expect(
                report["marker"] in text_range(canonical_report, report["line_start"], report["line_end"]),
                f"{group['id']} report marker",
            )
            actor_evidence = report["actor_evidence"]
            expect(
                set(actor_evidence) == set(group["actors_or_audiences"]),
                f"{group['id']} actor evidence coverage",
            )
            for actor, evidence in actor_evidence.items():
                expect(
                    evidence["marker"]
                    in text_range(canonical_report, evidence["line_start"], evidence["line_end"]),
                    f"{group['id']} report evidence for {actor}",
                )

            truth = group["ground_truth"]
            expect(
                truth["marker"]
                in text_range(
                    taxonomy["basis"]["ground_truth"], truth["line_start"], truth["line_end"]
                ),
                f"{group['id']} ground-truth marker",
            )

            cause = group["cause"]
            cause_counts[cause] += group["claim_instances"]
            cause_rows[cause] += 1
            cause_arm_counts.setdefault(cause, Counter())[arm] += group["claim_instances"]

            if position in checked_submissions:
                continue
            run = load_json(ROOT / f"{evidence_prefix}/run.json")
            expect(run["schedule_position"] == position, f"{label} run position")
            expect(run["trial_label"] == label, f"{label} run label")
            expect(run["assigned_arm"] == arm, f"{label} run arm")
            expect(run["status"] == "completed" and run["exit_code"] == 0, f"{label} completion")
            expect(run["transcript"]["agent_settled"] is True, f"{label} settled run")
            expect(run["transcript"]["sha256"] == transcript["sha256"], f"{label} run digest")
            expect(gzip_digest(canonical_transcript) == transcript["sha256"], f"{label} transcript digest")
            expect(last_event.get("type") == "agent_settled", f"{label} final settled event")
            expect(last_number == run["transcript"]["events"], f"{label} transcript event count")
            expect(file_digest(final_message_path) == run["final_message_sha256"], f"{label} final digest")
            expect("report.md" in run["report_files"], f"{label} settled report")
            expect(file_digest(canonical_report) == run["report_files"]["report.md"], f"{label} report digest")
            checked_submissions.add(position)

    declared_causes = {row["cause"]: row for row in taxonomy["adjudication_counts"]}
    expect(set(declared_causes) == set(cause_counts), "adjudication cause set")
    for cause, count in cause_counts.items():
        row = declared_causes[cause]
        expect(row["claim_instances"] == count, f"{cause} count")
        expect(row["affected_report_rows"] == cause_rows[cause], f"{cause} rows")
        expect(arm_dict(cause_arm_counts[cause]) == row["by_arm"], f"{cause} arm counts")

    supported = taxonomy["supported_absent_from_key_claim_groups"]
    unresolved = taxonomy["unresolved_claim_groups"]
    counting = taxonomy["counting"]
    expect(
        sum(group["claim_instances"] for group in supported)
        == counting["supported_absent_from_key_claim_instances"] == 19,
        "supported-absent-from-key total",
    )
    expect(len(supported) == counting["supported_absent_from_key_report_rows"] == 5, "supported rows")
    unsupported_arm_counts: Counter[str] = Counter()
    for group in unresolved:
        unsupported_arm_counts[group["arm"]] += group["claim_instances"]
    unresolved_total = sum(group["claim_instances"] for group in unresolved)
    expect(unresolved_total == counting["unresolved_claim_instances"] == 2, "unresolved total")
    expect(
        unresolved_total == counting["unsupported_conservative_claim_instances"],
        "conservative unsupported total",
    )
    expect(len(unresolved) == counting["unsupported_report_rows"] == 1, "unsupported rows")
    expect(arm_dict(unsupported_arm_counts) == counting["unsupported_claims_by_arm"], "unsupported arm counts")

    rule = (ROOT / taxonomy["basis"]["decision_rule"]).read_text(encoding="utf-8")
    match = re.search(r"threshold is \*\*(\d+) unsupported authorization claims total\*\*", rule)
    expect(match is not None, "decision-rule threshold text")
    expect(int(match.group(1)) == counting["threshold"], "decision-rule threshold")
    expect(counting["outcome"] == "inconclusive", "decision outcome")
    expect(counting["validity_requirement_met"] is False, "validity requirement")
    expect(counting["taxonomy_adjudicable"] is True, "taxonomy adjudicability")
    expect(counting["all_preregistered_requirements_met"] is False, "combined requirements")
    expect(counting["threshold_branch_applied"] is False, "threshold branch")
    expect(len(valid_positions) == taxonomy["basis"]["valid_sessions"] == 6, "valid session basis")


def verify_misses(taxonomy: dict) -> None:
    ground_truth = load_json(GROUND_TRUTH_PATH)
    declared = taxonomy["missed_discoveries"]
    rows = declared["by_flaw"]
    expect({row["flaw"] for row in rows} == set(ground_truth["flaws"]), "missed-discovery flaw set")
    expect(declared["opportunities"] == taxonomy["basis"]["valid_sessions"] * len(rows), "miss opportunities")
    expect(declared["total"] == sum(row["misses"] for row in rows), "miss total")
    arm_total = sum(declared["by_arm"].values())
    expect(arm_total == declared["total"], "miss arm count")
    for row in rows:
        if "evidence" not in row:
            continue
        evidence = row["evidence"]
        expect(
            evidence["marker"]
            in text_range(evidence["path"], evidence["line_start"], evidence["line_end"]),
            f"miss evidence {row['flaw']}",
        )


def verify_friction_and_loss(taxonomy: dict) -> None:
    trials = {row["position"]: row for row in taxonomy["trials"]}
    friction = taxonomy["setup_friction"]
    nonzero = friction["nonzero_bash"]
    declared_nonzero: set[tuple[int, int, int]] = set()
    all_event_ids: set[str] = set()
    arm_counts: Counter[str] = Counter()
    for event in nonzero["events"]:
        position = event["position"]
        trial = trials[position]
        expect(event["event_id"] not in all_event_ids, f"duplicate friction id {event['event_id']}")
        all_event_ids.add(event["event_id"])
        expect(event["arm"] == trial["arm"], f"friction arm at position {position}")
        path = f"evals/baseline/evidence/pos-{position:02d}-{trial['arm'].lower()}/transcript.jsonl.gz"
        parsed = json.loads(gzip_line(path, event["transcript_line"]))
        expect(parsed.get("type") == "tool_execution_end", f"friction event at position {position}")
        result = parsed.get("result") or {}
        structured = result.get("structuredContent") or {}
        expect(structured.get("exit_code") == event["exit_code"], f"friction exit at position {position}")
        key = (position, event["transcript_line"], event["exit_code"])
        expect(key not in declared_nonzero, f"duplicate nonzero friction event {key}")
        declared_nonzero.add(key)
        arm_counts[event["arm"]] += 1
    actual_nonzero: set[tuple[int, int, int]] = set()
    for position, trial in trials.items():
        path = ROOT / f"evals/baseline/evidence/pos-{position:02d}-{trial['arm'].lower()}/transcript.jsonl.gz"
        with gzip.open(path, "rb") as handle:
            for line_number, line in enumerate(handle, 1):
                try:
                    parsed = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if parsed.get("type") != "tool_execution_end":
                    continue
                exit_code = (((parsed.get("result") or {}).get("structuredContent") or {}).get("exit_code"))
                if isinstance(exit_code, int) and exit_code != 0:
                    actual_nonzero.add((position, line_number, exit_code))
    expect(declared_nonzero == actual_nonzero, "nonzero friction inventory is not exhaustive")
    expect(len(declared_nonzero) == nonzero["count"] == 11, "nonzero friction total")
    expect(arm_dict(arm_counts) == nonzero["by_arm"], "nonzero friction arm counts")

    expected_masked = {
        (1, 617), (1, 769), (1, 979),
        (2, 292), (2, 392), (2, 910), (2, 5548),
        (3, 513), (3, 22986), (3, 29516),
        (4, 198), (4, 303), (4, 1027), (4, 7062),
        (5, 282),
        (6, 291), (6, 294), (6, 16192),
        (7, 205), (7, 343), (7, 6652), (7, 28944),
        (8, 296), (8, 632),
        (9, 340), (9, 1063), (9, 30103),
        (10, 200), (10, 293), (10, 1094), (10, 16849),
    }
    masked = friction["masked_exit_zero"]
    masked_keys: set[tuple[int, int]] = set()
    masked_arm_counts: Counter[str] = Counter()
    for event in masked["events"]:
        position = event["position"]
        trial = trials[position]
        expect(event["event_id"] not in all_event_ids, f"duplicate friction id {event['event_id']}")
        all_event_ids.add(event["event_id"])
        expect(event["arm"] == trial["arm"], f"masked friction arm at position {position}")
        key = (position, event["transcript_line"])
        expect(key not in masked_keys, f"duplicate masked friction event {key}")
        masked_keys.add(key)
        path = f"evals/baseline/evidence/pos-{position:02d}-{trial['arm'].lower()}/transcript.jsonl.gz"
        parsed = json.loads(gzip_line(path, event["transcript_line"]))
        expect(parsed.get("type") == "tool_execution_end", f"masked event {key}")
        exit_code = (((parsed.get("result") or {}).get("structuredContent") or {}).get("exit_code"))
        expect(exit_code == 0, f"masked friction outer exit at {key}")
        output = result_text(parsed)
        for marker in event["output_markers"]:
            expect(marker in output, f"masked friction marker {key}: {marker}")
        if "corroborating_line" in event:
            corroborating = json.loads(gzip_line(path, event["corroborating_line"]))
            expect(event["corroborating_marker"] in result_text(corroborating), f"corroboration at {key}")
        masked_arm_counts[event["arm"]] += 1
    expect(masked_keys == expected_masked, "masked exit-zero inventory differs from adjudicated set")
    expect(len(masked_keys) == masked["count"] == 31, "masked exit-zero total")
    expect(arm_dict(masked_arm_counts) == masked["by_arm"], "masked exit-zero arm counts")

    expected_transport = {(3, 1125), (6, 1125), (9, 780), (9, 927), (10, 945)}
    transport = friction["related_transport_exit_zero"]
    transport_keys: set[tuple[int, int]] = set()
    transport_arm_counts: Counter[str] = Counter()
    for event in transport["events"]:
        position = event["position"]
        trial = trials[position]
        expect(event["event_id"] not in all_event_ids, f"duplicate friction id {event['event_id']}")
        all_event_ids.add(event["event_id"])
        expect(event["arm"] == trial["arm"], f"transport friction arm at position {position}")
        key = (position, event["transcript_line"])
        expect(key not in transport_keys, f"duplicate transport friction event {key}")
        transport_keys.add(key)
        path = f"evals/baseline/evidence/pos-{position:02d}-{trial['arm'].lower()}/transcript.jsonl.gz"
        parsed = json.loads(gzip_line(path, event["transcript_line"]))
        exit_code = (((parsed.get("result") or {}).get("structuredContent") or {}).get("exit_code"))
        expect(parsed.get("type") == "tool_execution_end" and exit_code == 0, f"transport event {key}")
        expect(event["output_marker"] in result_text(parsed), f"transport marker {key}")
        transport_arm_counts[event["arm"]] += 1
    expect(transport_keys == expected_transport, "transport friction inventory")
    expect(len(transport_keys) == transport["count"] == 5, "transport friction total")
    expect(arm_dict(transport_arm_counts) == transport["by_arm"], "transport friction arm counts")

    excluded = friction["excluded_exit_zero_probes"]
    expect(
        excluded["silent_duplicate_probes_without_legible_curl_status"]
        == ["pos05:169", "pos06:183", "pos07:1046", "pos08:162", "pos09:451"],
        "excluded silent probes",
    )
    expect(excluded["re_read_not_origin_event"] == ["pos04:5837"], "excluded re-read")

    tails = taxonomy["evidence_loss"]["truncated_jsonl_tails"]
    expect(tails["count"] == len(tails["positions"]), "truncated-tail count")
    tail_arm_counts = Counter(trials[position]["arm"] for position in tails["positions"])
    expect(arm_dict(tail_arm_counts) == tails["by_arm"], "truncated-tail arm counts")
    for position in tails["positions"]:
        trial = trials[position]
        path = f"evals/baseline/evidence/pos-{position:02d}-{trial['arm'].lower()}/transcript.jsonl.gz"
        expected_last = tails["last_decompressed_lines"][str(position)]
        last_number = 0
        last_line = b""
        with gzip.open(ROOT / path, "rb") as handle:
            for last_number, last_line in enumerate(handle, 1):
                pass
        expect(last_number == expected_last, f"position {position} last transcript line")
        try:
            json.loads(last_line)
        except json.JSONDecodeError:
            pass
        else:
            fail(f"position {position} tail is not truncated JSON")

    recovered = taxonomy["evidence_loss"]["nested_workspace_omission_recovered"]
    manifest = load_json(ROOT / recovered["manifest"])
    runs = {row["schedule_position"]: row for row in manifest["runs"]}
    expect(recovered["count"] == len(recovered["positions"]), "recovered-position count")
    recovered_arm_counts = Counter(trials[position]["arm"] for position in recovered["positions"])
    expect(arm_dict(recovered_arm_counts) == recovered["by_arm"], "recovered arm counts")
    for position in recovered["positions"]:
        nested = sum("/" in name for name in runs[position]["files"])
        expect(nested == recovered["recovered_nested_files"][str(position)], f"position {position} nested files")

    unsettled = taxonomy["evidence_loss"]["sessions_without_settled_submission"]
    expect(unsettled["positions"] == tails["positions"], "unsettled positions")
    expect(unsettled["count"] == tails["count"], "unsettled count")
    for position in unsettled["positions"]:
        expect(trials[position]["valid"] is False, f"unsettled position {position} marked valid")


def verify_run_failures(taxonomy: dict) -> None:
    trials = {row["position"]: row for row in taxonomy["trials"]}
    covered: set[int] = set()
    for failure in taxonomy["run_failures"]:
        expect(failure["count"] == len(failure["positions"]), f"{failure['cause']} count")
        arm_counts = Counter(trials[position]["arm"] for position in failure["positions"])
        expect(arm_dict(arm_counts) == failure["by_arm"], f"{failure['cause']} arm counts")
        for position in failure["positions"]:
            expect(position not in covered, f"position {position} in two run-failure causes")
            covered.add(position)
            expect(trials[position]["status"] == failure["classification"], f"position {position} failure class")
    expect(covered == {position for position, row in trials.items() if not row["valid"]}, "run failure coverage")


def verify_teapot_treatment(taxonomy: dict) -> None:
    treatment = taxonomy["teapot_finding_treatment"]
    native_commands = 0
    for trial in taxonomy["trials"]:
        position = trial["position"]
        path = ROOT / f"evals/baseline/evidence/pos-{position:02d}-{trial['arm'].lower()}/tool-calls.jsonl"
        for line in path.read_text(encoding="utf-8").splitlines():
            command = (json.loads(line).get("args") or {}).get("command", "")
            if re.search(r"(?:teapot\s+findings\b|findings\s+repro\b)", command):
                native_commands += 1
    expect(native_commands == treatment["native_finding_or_repro_commands"] == 0, "Teapot finding commands")
    expect(treatment["relied_on_or_submitted_claim_instances"] == 0, "Teapot relied-on claims")


def main() -> None:
    taxonomy = load_json(TAXONOMY_PATH)
    summary = load_json(SUMMARY_PATH)
    expect(taxonomy["schema_version"] == 1, "taxonomy schema")
    expect(taxonomy["basis"]["assigned_sessions"] == 10, "assigned session count")
    expect(taxonomy["basis"]["invalid_sessions"] == 4, "invalid session count")
    verify_trials(taxonomy, summary)
    verify_claims(taxonomy, summary)
    verify_misses(taxonomy)
    verify_friction_and_loss(taxonomy)
    verify_run_failures(taxonomy)
    verify_teapot_treatment(taxonomy)
    for trial in taxonomy["trials"]:
        label = f"pos-{trial['position']:02d}-{trial['arm'].lower()}"
        expect((ROOT / f"evals/baseline/evidence/{label}/final-message.txt").is_file(), f"{label} final message")
    print("failure taxonomy: ok")


if __name__ == "__main__":
    main()
