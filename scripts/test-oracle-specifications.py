#!/usr/bin/env python3
"""Negative regression tests for the frozen oracle contract checker."""

from copy import deepcopy
import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / "scripts/check-oracle-specifications.py"
SPEC = importlib.util.spec_from_file_location("oracle_checker", CHECKER)
checker = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(checker)


class OracleSpecificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.inputs = checker.load_inputs()

    def validate(self, contract=None, adr=None, plan=None, truth=None, baseline=None):
        original = self.inputs
        return checker.validate(
            deepcopy(original[0] if contract is None else contract),
            original[1] if adr is None else adr,
            original[2] if plan is None else plan,
            deepcopy(original[3] if truth is None else truth),
            original[4] if baseline is None else baseline,
        )

    def mutate(self):
        return deepcopy(self.inputs[0])

    def test_canonical_contract_passes(self):
        self.assertEqual(self.validate(), (2, 23))

    def test_missing_flow_fails(self):
        contract = self.mutate()
        contract["oracles"]["web.private-object-read.v1"]["flows"].pop(4)
        with self.assertRaisesRegex(ValueError, "flow records"):
            self.validate(contract=contract)

    def test_unknown_invalid_reason_fails(self):
        contract = self.mutate()
        contract["oracles"]["web.forbidden-state-change.v1"]["invalid_reasons"]["STATUS_DENIED"] = "bad"
        with self.assertRaisesRegex(ValueError, "invalid reason"):
            self.validate(contract=contract)

    def test_valid_but_wrong_flow_failure_code_fails(self):
        contract = self.mutate()
        flow = contract["oracles"]["web.forbidden-state-change.v1"]["flows"][8]
        flow["failure_code"] = "OWNER_VIEW_LOST"
        with self.assertRaisesRegex(ValueError, "wrong failure code for R3"):
            self.validate(contract=contract)

    def test_every_frozen_predicate_semantic_drift_fails(self):
        for oracle_id in (
            "web.private-object-read.v1",
            "web.forbidden-state-change.v1",
        ):
            for field in ("true", "false", "exposure", "error"):
                with self.subTest(oracle=oracle_id, field=field):
                    contract = self.mutate()
                    predicate = contract["oracles"][oracle_id]["predicate"]
                    if field == "true":
                        predicate[field] = "always true"
                    elif field == "false":
                        predicate[field] = "always false"
                    elif field == "exposure":
                        first = next(iter(predicate[field]))
                        predicate[field][first] = "any response status"
                    else:
                        predicate[field] = "return false after a crash"
                    with self.assertRaisesRegex(ValueError, "frozen predicate drift"):
                        self.validate(contract=contract)

    def test_invalid_precedence_drift_fails_for_both_oracles(self):
        for oracle_id in (
            "web.private-object-read.v1",
            "web.forbidden-state-change.v1",
        ):
            with self.subTest(oracle=oracle_id):
                contract = self.mutate()
                precedence = contract["oracles"][oracle_id]["predicate"]["invalid_precedence"]
                precedence[0], precedence[1] = precedence[1], precedence[0]
                with self.assertRaisesRegex(ValueError, "frozen predicate drift"):
                    self.validate(contract=contract)

    def test_non_contiguous_check_ids_fail(self):
        contract = self.mutate()
        contract["oracles"]["web.private-object-read.v1"]["numbered_checks"][3]["id"] = "POR-99"
        with self.assertRaisesRegex(ValueError, "not contiguous"):
            self.validate(contract=contract)

    def test_check_without_killing_fixture_fails(self):
        contract = self.mutate()
        contract["oracles"]["web.private-object-read.v1"]["numbered_checks"][0]["killed_by"] = []
        with self.assertRaisesRegex(ValueError, "no killing fixture"):
            self.validate(contract=contract)

    def test_unknown_development_fixture_fails(self):
        contract = self.mutate()
        contract["oracles"]["web.private-object-read.v1"]["numbered_checks"][0]["killed_by"] = [
            "development:decoys.not_real"
        ]
        with self.assertRaisesRegex(ValueError, "unknown development fixture"):
            self.validate(contract=contract)

    def test_missing_scope_class_fails(self):
        contract = self.mutate()
        contract["oracles"]["web.private-object-read.v1"]["scope_boundary"][
            "unsupported_claim_classes"
        ].pop()
        with self.assertRaisesRegex(ValueError, "excluded claim classes"):
            self.validate(contract=contract)

    def test_account_level_known_miss_reversal_fails(self):
        contract = self.mutate()
        misses = contract["oracles"]["web.private-object-read.v1"]["known_misses"]
        misses[3] = "account- or tenant-wide state that separate verifier principals do not isolate"
        with self.assertRaisesRegex(ValueError, "account-level isolation guarantee"):
            self.validate(contract=contract)

    def test_scope_dispatch_after_traffic_fails(self):
        contract = self.mutate()
        contract["oracles"]["web.private-object-read.v1"]["scope_boundary"][
            "dispatch_timing"
        ] = "after traffic"
        with self.assertRaisesRegex(ValueError, "before traffic"):
            self.validate(contract=contract)

    def test_missing_adr_check_fails(self):
        adr = self.inputs[1].replace("| POR-08 |", "| POR-X8 |")
        with self.assertRaisesRegex(ValueError, "POR-08: absent"):
            self.validate(adr=adr)

    def test_state_change_known_miss_drift_fails(self):
        contract = self.mutate()
        contract["oracles"]["web.forbidden-state-change.v1"]["known_misses"][-1] = (
            "destructive actions are supported"
        )
        with self.assertRaisesRegex(ValueError, "known misses"):
            self.validate(contract=contract)

    def test_fixture_reason_drift_fails(self):
        truth = deepcopy(self.inputs[3])
        truth["decoys"]["canary_echo"]["expected"]["reason"] = "OBSERVER_INVALID"
        with self.assertRaisesRegex(ValueError, "fixture drift: echo"):
            self.validate(truth=truth)


if __name__ == "__main__":
    unittest.main()
