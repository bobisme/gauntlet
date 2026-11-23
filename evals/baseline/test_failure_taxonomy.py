#!/usr/bin/env python3
"""Negative self-tests for the M0.4.4 taxonomy checker."""

from __future__ import annotations

from copy import deepcopy
import unittest

import check_failure_taxonomy as checker


class FailureTaxonomyNegativeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.taxonomy = checker.load_json(checker.TAXONOMY_PATH)
        self.summary = checker.load_json(checker.SUMMARY_PATH)

    def test_pos03_claim_cannot_be_relabelled_as_pos06_evidence(self) -> None:
        altered = deepcopy(self.taxonomy)
        source, target = altered["supported_absent_from_key_claim_groups"][:2]
        source["position"] = target["position"]
        source["trial_label"] = target["trial_label"]
        source["arm"] = target["arm"]
        source["transcript"] = deepcopy(target["transcript"])
        source["report"] = deepcopy(target["report"])
        source["ground_truth"] = deepcopy(target["ground_truth"])
        with self.assertRaisesRegex(AssertionError, "duplicate claim tuple"):
            checker.verify_claims(altered, self.summary)

    def test_duplicate_masked_friction_line_is_rejected(self) -> None:
        altered = deepcopy(self.taxonomy)
        events = altered["setup_friction"]["masked_exit_zero"]["events"]
        events[1]["position"] = events[0]["position"]
        events[1]["arm"] = events[0]["arm"]
        events[1]["transcript_line"] = events[0]["transcript_line"]
        with self.assertRaisesRegex(AssertionError, "duplicate masked friction event"):
            checker.verify_friction_and_loss(altered)

    def test_pos09_login_citation_must_be_settled_final_submission(self) -> None:
        altered = deepcopy(self.taxonomy)
        login = altered["unresolved_claim_groups"][0]
        self.assertEqual(login["position"], 9)
        self.assertEqual(login["transcript"]["decompressed_line"], 33316)
        login["transcript"]["decompressed_line"] = 2009
        with self.assertRaisesRegex(AssertionError, "canonical settled submission line"):
            checker.verify_claims(altered, self.summary)


if __name__ == "__main__":
    unittest.main()
