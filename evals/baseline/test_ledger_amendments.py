#!/usr/bin/env python3
"""Focused tests for append-only baseline score amendments."""

import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import run_baseline as baseline  # noqa: E402


IMMUTABLE_TEN_LINE_SHA256 = "702f955b8a4dd96712eae7c41c1f3db4aa5fd58def2200b0ad50eccbc868bc6e"


def jsonl(record):
    return (json.dumps(record, sort_keys=True) + "\n").encode("utf-8")


def run_record(position=5, arm="B", label="pos-05-b", score=None):
    row = {
        "scored": True,
        "schedule_position": position,
        "assigned_arm": arm,
        "trial_label": label,
        "status": "infrastructure_failure",
        "blocked": "OSError: [Errno 122] Disk quota exceeded",
    }
    if score is not None:
        row["score"] = score
    return row


def entry_for(row):
    raw = jsonl(row)
    return {
        "record": row,
        "line_number": 1,
        "line_sha256": hashlib.sha256(raw).hexdigest(),
    }


def valid_amendment(run_entry):
    score = baseline.infrastructure_score_disposition(
        "OSError: [Errno 122] Disk quota exceeded"
    )
    record = baseline.make_score_amendment(run_entry, score)
    return {"record": record, "line_number": 2, "line_sha256": "a" * 64}


class ScoreAmendmentTests(unittest.TestCase):
    def test_committed_ledger_preserves_original_ten_line_prefix(self):
        lines = baseline.LEDGER_PATH.read_bytes().splitlines(keepends=True)
        self.assertGreaterEqual(len(lines), 10)
        self.assertEqual(
            hashlib.sha256(b"".join(lines[:10])).hexdigest(),
            IMMUTABLE_TEN_LINE_SHA256,
        )

    def test_valid_amendment_completes_score_coverage(self):
        row = run_record()
        run_entry = entry_for(row)
        report, problems = baseline.score_coverage(
            [run_entry], [valid_amendment(run_entry)]
        )
        self.assertEqual(problems, [])
        self.assertEqual(report["covered"], 1)
        self.assertEqual(report["amended"], 1)
        self.assertEqual(report["inline"], 0)

    def test_tampered_source_hash_is_rejected(self):
        run_entry = entry_for(run_record())
        amendment = valid_amendment(run_entry)
        amendment["record"]["target"]["source_line_sha256"] = "0" * 64
        report, problems = baseline.score_coverage([run_entry], [amendment])
        self.assertEqual(report["covered"], 0)
        self.assertTrue(any("source-line hash mismatch" in item for item in problems))
        self.assertTrue(any("missing score" in item for item in problems))

        tampered_score = valid_amendment(run_entry)
        tampered_score["record"]["score"]["note"] = "invented claim score"
        report, problems = baseline.score_coverage([run_entry], [tampered_score])
        self.assertEqual(report["covered"], 0)
        self.assertTrue(any("invalid score disposition" in item for item in problems))

    def test_duplicate_orphan_and_inline_conflict_are_rejected(self):
        missing_entry = entry_for(run_record())
        amendment = valid_amendment(missing_entry)
        duplicate = copy.deepcopy(amendment)
        duplicate["line_number"] = 3
        _, duplicate_problems = baseline.score_coverage(
            [missing_entry], [amendment, duplicate]
        )
        self.assertTrue(
            any("duplicate score amendments" in item for item in duplicate_problems)
        )

        orphan = copy.deepcopy(amendment)
        orphan["record"]["target"]["trial_label"] = "pos-99-a"
        _, orphan_problems = baseline.score_coverage([missing_entry], [orphan])
        self.assertTrue(any("targets no run" in item for item in orphan_problems))

        inline_row = run_record(
            score=baseline.infrastructure_score_disposition("inline fallback")
        )
        inline_entry = entry_for(inline_row)
        conflict = valid_amendment(inline_entry)
        _, conflict_problems = baseline.score_coverage([inline_entry], [conflict])
        self.assertTrue(
            any("inline score conflicts" in item for item in conflict_problems)
        )

    def test_future_failure_fallback_is_mechanical_and_non_adjudicating(self):
        record = {
            "status": "infrastructure_failure",
            "blocked": "fixture failed before launch",
        }
        score = baseline.ensure_score_disposition(record)
        self.assertIs(score, record["score"])
        self.assertEqual(score["status"], "not_adjudicable_infrastructure_failure")
        self.assertIs(score["adjudicated"], False)
        self.assertIs(score["report_present"], False)
        self.assertIsNone(score["unsupported_authorization_claims"])
        self.assertIn("No claim score", score["note"])

    def test_parse_partitions_run_and_amendment_records(self):
        row = run_record()
        run_entry = entry_for(row)
        amendment = baseline.make_score_amendment(
            run_entry,
            baseline.infrastructure_score_disposition("historical failure"),
        )
        runs, amendments, problems = baseline.parse_ledger_bytes(
            jsonl(row) + jsonl(amendment)
        )
        self.assertEqual(problems, [])
        self.assertEqual(len(runs), 1)
        self.assertEqual(len(amendments), 1)
        self.assertEqual(runs[0]["line_sha256"], run_entry["line_sha256"])


if __name__ == "__main__":
    unittest.main()
