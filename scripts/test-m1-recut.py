#!/usr/bin/env python3
"""Regression tests for the live M1 tracker reconciliation gate."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
CHECKER_PATH = ROOT / "scripts/check-m1-recut.py"
SPEC = importlib.util.spec_from_file_location("check_m1_recut", CHECKER_PATH)
assert SPEC is not None and SPEC.loader is not None
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


class TrackerReconciliationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.recut = json.loads(
            (ROOT / "docs/contracts/m1-recut.v1.json").read_text()
        )
        cls.live = CHECKER.load_live_tracker(cls.recut)

    def test_live_projection_matches_manifest(self) -> None:
        CHECKER.validate_tracker(self.recut, self.live)
        self.assertEqual(
            Path(self.live["tracker_root"]),
            CHECKER.default_workspace_root(ROOT),
        )

    def test_keep_bone_accepts_each_lifecycle_state(self) -> None:
        for state in ("open", "doing", "done"):
            with self.subTest(state=state):
                mutated = copy.deepcopy(self.live)
                mutated["bones"]["bn-10s"]["state"] = state
                CHECKER.validate_tracker(self.recut, mutated)

    def test_invalid_keep_bone_lifecycle_state_is_rejected(self) -> None:
        mutated = copy.deepcopy(self.live)
        mutated["bones"]["bn-10s"]["state"] = "invalid"
        with self.assertRaisesRegex(AssertionError, "invalid lifecycle state 'invalid'"):
            CHECKER.validate_tracker(self.recut, mutated)

    def test_missing_keep_bone_is_rejected(self) -> None:
        mutated = copy.deepcopy(self.live)
        del mutated["bones"]["bn-14c"]
        with self.assertRaisesRegex(AssertionError, "missing a KEEP bone"):
            CHECKER.validate_tracker(self.recut, mutated)

    def test_dependency_drift_is_rejected(self) -> None:
        mutated = copy.deepcopy(self.live)
        mutated["bones"]["bn-360"]["depends_on"].remove("bn-ijh")
        with self.assertRaisesRegex(AssertionError, "dependency anchors changed"):
            CHECKER.validate_tracker(self.recut, mutated)

    def test_every_edited_acceptance_body_is_guarded(self) -> None:
        edited = self.recut["acceptance_routes"]
        self.assertEqual(len(edited), 46)
        for bone_id in sorted(edited):
            with self.subTest(bone_id=bone_id):
                mutated = copy.deepcopy(self.live)
                mutated["bones"][bone_id]["description"] += "\nregression"
                with self.assertRaisesRegex(
                    AssertionError, "frozen-contract acceptance changed"
                ):
                    CHECKER.validate_tracker(self.recut, mutated)

    def test_bn23g_boundary_survives_coordinated_hash_change(self) -> None:
        recut = copy.deepcopy(self.recut)
        mutated = copy.deepcopy(self.live)
        marker = recut["tracker_projection"]["acceptance_marker"]
        description = mutated["bones"]["bn-23g"]["description"]
        description = description.replace(
            "`ORACLE_UNAVAILABLE` plus supported classes",
            "an ordinary unsupported result",
        )
        mutated["bones"]["bn-23g"]["description"] = description
        body = CHECKER.tracker_acceptance_body(description, marker)
        recut["tracker_projection"]["bones"]["bn-23g"][
            "acceptance_sha256"
        ] = hashlib.sha256(body.encode()).hexdigest()
        with self.assertRaisesRegex(AssertionError, "bn-23g lost acceptance boundary"):
            CHECKER.validate_tracker(recut, mutated)


if __name__ == "__main__":
    unittest.main()
