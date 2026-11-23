#!/usr/bin/env python3
"""Validate the frozen M0.6 Investigation conformance record without running it."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import re
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "fixtures/contracts/evidence"
PIN = "6a0c5ed843d0f4870910d3a926298890290c916e"
SOURCE_ARCHIVE_SHA256 = "12efb99c978e10f634f43b039ddc5391de5dbfeb44bcd4703952fb1aae0415df"
BINARY_SHA256 = "c368ab4d8e0511524674692b039c4f248cee2b5676d143a23f5ab9025a31d4fc"
BUILD_ARGV = [
    "cargo",
    "build",
    "--release",
    "--locked",
    "--offline",
    "-p",
    "investigation-cli",
    "--bin",
    "investigation",
]
EXECUTION_ARGV = [
    "python3",
    "-B",
    "fixtures/contracts/evidence/run.py",
    "--adapter",
    "fixtures/contracts/evidence/investigation.py",
]
INPUT_SHA256 = {
    "fixtures/contracts/evidence/run.py": (
        "2d2e8e4363465ccea3227241911d026248c2d65a23fa806bf767fe655a61dc52"
    ),
    "fixtures/contracts/evidence/driver.py": (
        "c2ddb7d23df9f5e316020c72b2017357bc3535084541968a3f064d8cd3eda03a"
    ),
    "fixtures/contracts/evidence/investigation.py": (
        "bb6ae6e425ebae23a39ab9117d55dabac709f4f44d4aaa012a0c114a75562a33"
    ),
}
QUALIFIED_CAPABILITIES = [
    "capture lifecycle and acknowledged-prefix recovery",
    "strict complete artifact inventory",
    "byte-exact text and binary whole or byte-range reads",
    "strict structured JSON reads and derivative writes",
    "exact retained bytes and SHA-256 digests",
    "ordered multi-input lineage",
    "same-key replay and changed-request conflict",
]
UNSUPPORTED_CAPABILITIES = [
    "power-loss durability",
    "retention",
    "export",
    "retraction",
    "concurrent writers",
]
LIMITS = [
    "local filesystem only",
    "no power-loss qualification",
    "no retention, export or retraction qualification",
    "no concurrent-writer qualification",
]
REQUALIFY_ON = [
    "Investigation source pin or version change",
    "capture, ingest or selector protocol change",
    "strict JSON validation change",
    "retention or lineage behavior change",
]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def case_names(root: Path = ROOT) -> list[str]:
    evidence = root / "fixtures/contracts/evidence"
    sys.path.insert(0, str(evidence))
    try:
        spec = importlib.util.spec_from_file_location("scourge_evidence_cases", evidence / "run.py")
        require(spec is not None and spec.loader is not None, "cannot load evidence cases")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return unittest.defaultTestLoader.getTestCaseNames(module.EvidenceCases)
    finally:
        sys.path.pop(0)


def input_bytes(root: Path = ROOT) -> dict[str, bytes]:
    return {path: (root / path).read_bytes() for path in INPUT_SHA256}


def validate_record(
    record: dict,
    expected_cases: list[str],
    inputs: dict[str, bytes],
    adr: str,
    dependencies: str,
) -> None:
    require(
        set(record)
        == {
            "schema_version",
            "observed_on",
            "investigation",
            "execution",
            "result",
            "qualified_capabilities",
            "unsupported_capabilities",
            "limits",
            "requalify_on",
        },
        "record fields",
    )
    require(record.get("schema_version") == "scourge.investigation-conformance.v1", "schema")
    require(record.get("observed_on") == "2026-11-23", "observation date")
    investigation = record.get("investigation", {})
    require(
        set(investigation)
        == {
            "version",
            "source_commit",
            "source_archive",
            "binary_sha256",
            "build",
            "public_interface",
            "protocols",
        },
        "investigation fields",
    )
    require(investigation.get("version") == "0.1.0", "version")
    require(investigation.get("source_commit") == PIN, "source pin")
    require(
        investigation.get("source_archive")
        == {"format": "git archive tar", "sha256": SOURCE_ARCHIVE_SHA256},
        "source archive identity",
    )
    digest = investigation.get("binary_sha256")
    require(digest == BINARY_SHA256 and re.fullmatch(r"[0-9a-f]{64}", digest), "binary digest")
    require(
        investigation.get("build")
        == {"argv": BUILD_ARGV, "cargo": "1.100.0", "rustc": "1.100.0"},
        "build identity",
    )
    require(investigation.get("public_interface") == "versioned JSON CLI", "public interface")
    require(
        investigation.get("protocols") == ["inv.capture.v1", "inv.ingest.v1", "inv.selector.v1"],
        "protocols",
    )
    execution = record.get("execution", {})
    require(
        set(execution)
        == {
            "argv",
            "binary_environment",
            "input_sha256",
            "network_used",
            "target_traffic",
        },
        "execution fields",
    )
    require(execution.get("argv") == EXECUTION_ARGV, "execution argv")
    require(execution.get("binary_environment") == "SCOURGE_INVESTIGATION_BIN", "binary environment")
    recorded_inputs = execution.get("input_sha256")
    require(recorded_inputs == INPUT_SHA256, "recorded execution input digests")
    require(set(inputs) == set(INPUT_SHA256), "execution input set")
    for path, expected_digest in recorded_inputs.items():
        actual_digest = hashlib.sha256(inputs[path]).hexdigest()
        require(actual_digest == expected_digest, f"execution input digest {path}")
    require(execution.get("network_used") is False, "network boundary")
    require(execution.get("target_traffic") is False, "target boundary")
    result = record.get("result", {})
    require(set(result) == {"assigned", "passed", "failed", "cases"}, "result fields")
    require(result.get("assigned") == 12, "assigned count")
    require(result.get("passed") == 12 and result.get("failed") == 0, "passing result")
    require(result.get("cases") == expected_cases, "case inventory")
    require(record.get("qualified_capabilities") == QUALIFIED_CAPABILITIES, "qualified capabilities")
    require(
        record.get("unsupported_capabilities") == UNSUPPORTED_CAPABILITIES,
        "unsupported capabilities",
    )
    require(record.get("limits") == LIMITS and bool(LIMITS), "qualification limits")
    require(record.get("requalify_on") == REQUALIFY_ON and bool(REQUALIFY_ON), "requalification triggers")
    for token in (PIN, SOURCE_ARCHIVE_SHA256, BINARY_SHA256, "passed all 12"):
        require(token in adr, f"ADR missing {token}")
    require(PIN in dependencies, "dependency pin")


def validate(root: Path = ROOT) -> None:
    record = json.loads((root / "fixtures/contracts/evidence/investigation-conformance.json").read_text())
    validate_record(
        record,
        case_names(root),
        input_bytes(root),
        (root / "docs/adr/evidence-contract.md").read_text(),
        (root / "docs/dependencies.md").read_text(),
    )


if __name__ == "__main__":
    validate()
    print("Investigation conformance: 12/12 at 6a0c5ed843d0, frozen record verified")
