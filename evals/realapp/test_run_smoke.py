#!/usr/bin/env python3
"""Focused offline tests for real-application smoke orchestration guards."""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

import check_materials
import run_smoke


class ImageBindingTests(unittest.TestCase):
    def test_expected_labels_bind_every_reproducible_input(self) -> None:
        labels = run_smoke.expected_image_labels()
        self.assertEqual(
            labels["org.scourge.realapp.source-commit"],
            run_smoke.TARGET_LOCK["upstream"]["commit"],
        )
        self.assertEqual(
            labels["org.scourge.realapp.source-tree"],
            run_smoke.TARGET_LOCK["upstream"]["tree"],
        )
        self.assertEqual(len(labels["org.scourge.realapp.source-manifest-sha256"]), 64)
        self.assertEqual(len(labels["org.scourge.realapp.target-lock-sha256"]), 64)
        self.assertEqual(len(labels["org.scourge.realapp.containerfile-sha256"]), 64)

    def test_label_mismatch_is_rejected_without_using_image_id(self) -> None:
        observed = run_smoke.expected_image_labels()
        observed["org.scourge.realapp.source-tree"] = "wrong-tree"
        with mock.patch.object(run_smoke, "image_labels", return_value=observed):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                run_smoke.verify_image_labels()


class SessionShapeTests(unittest.TestCase):
    def test_single_arm_is_rejected_before_preflight_or_target_traffic(self) -> None:
        args = types.SimpleNamespace(arms="a", source_dir="unused", session_id=None, timeout=1)
        with mock.patch.object(
            run_smoke, "preflight", side_effect=AssertionError("preflight must not run")
        ):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                run_smoke.session(args)


class AssignmentSnapshotTests(unittest.TestCase):
    def test_successor_global_assignment_does_not_invalidate_committed_session(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            records = root / "smoke/session-one"
            old_assignment = {"schema_version": 1, "frozen_at": "first"}
            old_payload = (json.dumps(old_assignment, indent=2) + "\n").encode()
            metadata = run_smoke.snapshot_frozen_assignment(records, old_payload)
            session = {
                "frozen_assignment": metadata,
                "frozen_assignment_sha256": metadata["sha256"],
            }

            global_assignment = root / "frozen-assignment.json"
            global_assignment.write_text(json.dumps({"schema_version": 1, "frozen_at": "second"}))

            loaded = check_materials.load_session_frozen_assignment(records, session)
            self.assertEqual(loaded, old_assignment)
            self.assertNotEqual(run_smoke.sha256_file(global_assignment), metadata["sha256"])


if __name__ == "__main__":
    unittest.main()
