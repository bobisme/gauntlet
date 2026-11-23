#!/usr/bin/env python3
"""Regression tests for the frozen Investigation conformance checker."""

from __future__ import annotations

import copy
import importlib.util
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "check_investigation_conformance", ROOT / "scripts/check-investigation-conformance.py"
)
assert SPEC is not None and SPEC.loader is not None
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


class ConformanceRecordTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.record = json.loads(
            (ROOT / "fixtures/contracts/evidence/investigation-conformance.json").read_text()
        )
        cls.cases = CHECK.case_names()
        cls.inputs = CHECK.input_bytes()
        cls.adr = (ROOT / "docs/adr/evidence-contract.md").read_text()
        cls.dependencies = (ROOT / "docs/dependencies.md").read_text()

    def validate(self, record=None, inputs=None, adr=None, dependencies=None) -> None:
        CHECK.validate_record(
            self.record if record is None else record,
            self.cases,
            self.inputs if inputs is None else inputs,
            self.adr if adr is None else adr,
            self.dependencies if dependencies is None else dependencies,
        )

    def test_record_matches_live_case_inventory(self) -> None:
        self.validate()

    def test_source_pin_drift_fails(self) -> None:
        record = copy.deepcopy(self.record)
        record["investigation"]["source_commit"] = "0" * 40
        with self.assertRaisesRegex(ValueError, "source pin"):
            self.validate(record=record)

        record = copy.deepcopy(self.record)
        record["investigation"]["source_archive"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "source archive identity"):
            self.validate(record=record)

    def test_case_or_result_drift_fails(self) -> None:
        record = copy.deepcopy(self.record)
        record["result"]["cases"].pop()
        with self.assertRaisesRegex(ValueError, "case inventory"):
            self.validate(record=record)
        record = copy.deepcopy(self.record)
        record["result"]["passed"] = 11
        with self.assertRaisesRegex(ValueError, "passing result"):
            self.validate(record=record)

    def test_fixture_and_driver_byte_drift_fail(self) -> None:
        for path in (
            "fixtures/contracts/evidence/run.py",
            "fixtures/contracts/evidence/driver.py",
        ):
            with self.subTest(path=path):
                inputs = dict(self.inputs)
                inputs[path] += b"\n# semantic drift\n"
                with self.assertRaisesRegex(ValueError, f"execution input digest {path}"):
                    self.validate(inputs=inputs)

    def test_semantic_adapter_drift_fails_even_when_old_tokens_remain(self) -> None:
        path = "fixtures/contracts/evidence/investigation.py"
        adapter = self.inputs[path].decode()
        mutations = {
            "strict inventory disabled": adapter.replace(
                '"strict_artifact_inventory": request.complete,',
                '"strict_artifact_inventory": False,  # request.complete',
            ),
            "binary decoding discarded": adapter.replace(
                'data = base64.b64decode(excerpt["bytes_base64"], validate=True)',
                'data = b""  # base64.b64decode(excerpt["bytes_base64"], validate=True)',
            ),
            "strict JSON request removed": adapter.replace(
                'request["validate_as"] = "strict_json"',
                'request["validate_as"] = "strict_json"\n            request.pop("validate_as")',
            ),
            "strict JSON rejection remapped": adapter.replace(
                'raise Rejected("invalid_json") from error',
                'raise Rejected("conflict") from error  # invalid_json',
            ),
        }
        for name, mutated in mutations.items():
            with self.subTest(name=name):
                self.assertNotEqual(mutated, adapter)
                inputs = dict(self.inputs)
                inputs[path] = mutated.encode()
                with self.assertRaisesRegex(ValueError, f"execution input digest {path}"):
                    self.validate(inputs=inputs)

    def test_recorded_execution_input_digest_drift_fails(self) -> None:
        record = copy.deepcopy(self.record)
        record["execution"]["input_sha256"]["fixtures/contracts/evidence/run.py"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "recorded execution input digests"):
            self.validate(record=record)

    def test_unsupported_power_loss_capability_fails(self) -> None:
        record = copy.deepcopy(self.record)
        record["unsupported_capabilities"].remove("power-loss durability")
        record["qualified_capabilities"].append("power-loss durability")
        with self.assertRaisesRegex(ValueError, "qualified capabilities"):
            self.validate(record=record)

        record = copy.deepcopy(self.record)
        record["unsupported_capabilities"].remove("power-loss durability")
        with self.assertRaisesRegex(ValueError, "unsupported capabilities"):
            self.validate(record=record)

    def test_empty_limits_or_requalification_triggers_fail(self) -> None:
        for field, message in (
            ("limits", "qualification limits"),
            ("requalify_on", "requalification triggers"),
        ):
            with self.subTest(field=field):
                record = copy.deepcopy(self.record)
                record[field] = []
                with self.assertRaisesRegex(ValueError, message):
                    self.validate(record=record)

    def test_unrelated_build_or_execution_argv_fail(self) -> None:
        record = copy.deepcopy(self.record)
        record["investigation"]["build"]["argv"] = ["true"]
        with self.assertRaisesRegex(ValueError, "build identity"):
            self.validate(record=record)

        record = copy.deepcopy(self.record)
        record["execution"]["argv"] = ["true"]
        with self.assertRaisesRegex(ValueError, "execution argv"):
            self.validate(record=record)

    def test_documented_pin_and_digest_drift_fail(self) -> None:
        with self.assertRaisesRegex(ValueError, "ADR missing"):
            self.validate(adr=self.adr.replace(CHECK.BINARY_SHA256, "f" * 64))
        with self.assertRaisesRegex(ValueError, "dependency pin"):
            self.validate(dependencies=self.dependencies.replace(CHECK.PIN, "0" * 40))


if __name__ == "__main__":
    unittest.main()
