"""Run the evidence cases through one explicitly selected adapter."""

import argparse
import hashlib
import importlib.util
import itertools
import sys
import tempfile
import unittest
from pathlib import Path

from driver import (
    Artifact,
    Attachment,
    ByteRange,
    Capture,
    DriverFactory,
    Finalization,
    Lineage,
    Read,
    Rejected,
)


ORIGINAL = b"prefix:text:suffix\r\n"
BINARY = b"prefix:\x00\xff\x08:suffix\r\n"
INVALID_JSON = {
    "duplicate-top": b'{"value":1,"value":2}',
    "duplicate-nested": br'{"items":[{"name":1,"\u006eame":2}]}',
    "nonfinite-token": b'{"value":NaN}',
    "nonfinite-exponent": b'{"value":1e999}',
    "unsafe-integer": b'{"value":9007199254740992}',
    "invalid-utf8": b'{"value":"\xff"}',
}
JSON_KINDS = ("manifest", "experiment", "verification")


class EvidenceCases(unittest.TestCase):
    driver_factory: DriverFactory

    def setUp(self):
        self.scratch = self.temporary_workspace()
        self.driver = self.open_driver(self.scratch)

    def temporary_workspace(self):
        scratch = self.enterContext(tempfile.TemporaryDirectory(prefix="scourge-evidence-"))
        return Path(scratch)

    def open_driver(self, scratch):
        driver = self.driver_factory(scratch)
        self.addCleanup(driver.close)
        return driver

    def restart_driver(self):
        interrupted = self.driver
        interrupted.interrupt()
        self.driver = self.open_driver(self.scratch)
        self.assertIsNot(self.driver, interrupted, "driver factory reused the interrupted session")

    def assert_artifact(self, artifact, data, *, capture_id=None, lineage=()):
        self.assertIsInstance(artifact, Artifact)
        self.assertTrue(artifact.id)
        self.assertEqual(artifact.sha256, hashlib.sha256(data).hexdigest())
        self.assertEqual(artifact.capture_id, capture_id)
        self.assertEqual(artifact.lineage, lineage)
        self.assertEqual(self.driver.read(artifact.id), Read(artifact, data))

    def assert_capture(
        self, captured, capture_id, receipts, *, position, seal, missing_positions=()
    ):
        self.assertIsInstance(captured, Capture)
        self.assertTrue(capture_id)
        self.assertEqual(captured.id, capture_id)
        self.assertEqual(captured.accepted_position, position)
        self.assertEqual(captured.seal, seal)
        self.assertEqual(captured.missing_positions, missing_positions)
        self.assertEqual(captured.attachments, receipts)
        self.assertEqual(len(captured.artifacts), 0 if seal == "open" else len(receipts))

    def assert_attachment(self, receipt, position, key, data):
        self.assertIsInstance(receipt, Attachment)
        self.assertEqual(receipt.position, position)
        self.assertEqual(receipt.key, key)
        self.assertEqual(receipt.sha256, hashlib.sha256(data).hexdigest())
        self.assertRegex(receipt.request_digest, r"^[0-9a-f]{64}$")
        self.assertTrue(receipt.accepted_at)

    def assert_rejected(self, reason, operation, *args, **kwargs):
        with self.assertRaises(Rejected) as raised:
            operation(*args, **kwargs)
        self.assertEqual(raised.exception.reason, reason)

    def captured_original(self):
        capture_id = self.driver.open("source-run")
        self.driver.attach(capture_id, "source-item", ORIGINAL, position=1)
        capture = self.driver.finalize(capture_id, Finalization(1, ("source-item",), complete=True))
        return capture_id, capture.artifacts[0]

    def test_capture(self):
        """Scourge plan §9.2, Capture. Investigation plan §11.3, positions and seal."""
        capture_id = self.driver.open("capture-run")
        log_data = b"fixture log\n"
        self.assert_rejected(
            "conflict", self.driver.attach, capture_id, "log", log_data, position=2
        )
        main = self.driver.attach(capture_id, "body", ORIGINAL, position=1)
        log = self.driver.attach(capture_id, "log", log_data, position=2)
        self.assert_rejected(
            "conflict",
            self.driver.finalize,
            capture_id,
            Finalization(1, ("body",), complete=True),
        )
        request = Finalization(2, ("body", "log"), complete=True)
        sealed = self.driver.finalize(capture_id, request)
        self.assert_capture(sealed, capture_id, (main, log), position=2, seal="complete")
        original, log_artifact = sealed.artifacts
        self.assertNotEqual(original.id, log_artifact.id)
        self.assert_attachment(main, 1, "body", ORIGINAL)
        self.assert_attachment(log, 2, "log", log_data)
        self.assert_artifact(original, ORIGINAL, capture_id=capture_id)
        self.assert_artifact(log_artifact, log_data, capture_id=capture_id)
        self.assert_rejected("closed", self.driver.attach, capture_id, "late", b"late", position=3)
        self.assertEqual(self.driver.finalize(capture_id, request), sealed)

    def test_complete_inventory_mismatch(self):
        """Scourge plan §9.2, a mismatched inventory must leave a capture open."""
        capture_id = self.driver.open("inventory-run")
        body = self.driver.attach(capture_id, "body", ORIGINAL, position=1)
        log = self.driver.attach(capture_id, "log", b"log\n", position=2)
        self.assert_rejected(
            "conflict",
            self.driver.finalize,
            capture_id,
            Finalization(2, ("body", "other"), complete=True),
        )
        self.assert_capture(
            self.driver.recover(capture_id), capture_id, (body, log), position=2, seal="open"
        )

    def test_read_by_id_and_selected_part(self):
        """Scourge plan §9.2, Read. Investigation plan §5.4, byte_range."""
        capture_id, original = self.captured_original()
        self.assert_artifact(original, ORIGINAL, capture_id=capture_id)
        self.assertEqual(
            self.driver.read(original.id, part=ByteRange(7, 11)),
            Read(original, b"text"),
        )

        lineage = (Lineage(original.id, original.sha256, "fixture-manifest/v1"),)
        data = b'{"manifest":"fixture"}'
        derived = self.driver.record("manifest", "manifest", data, lineage=lineage)
        self.assert_artifact(derived, data, lineage=lineage)
        self.assertEqual(
            self.driver.read(derived.id, part=ByteRange(13, 20)),
            Read(derived, b"fixture"),
        )
        for invalid in (
            ByteRange(-1, 3),
            ByteRange(7, 6),
            ByteRange(7, 7),
            ByteRange(7, len(ORIGINAL) + 1),
        ):
            with self.subTest(part=invalid):
                self.assert_rejected("invalid_range", self.driver.read, original.id, part=invalid)

    def test_read_binary_by_id_and_selected_part(self):
        """Scourge plan §9.2, byte-exact whole and partial reads of arbitrary bytes."""
        capture_id = self.driver.open("binary-run")
        self.driver.attach(capture_id, "body", BINARY, position=1)
        sealed = self.driver.finalize(capture_id, Finalization(1, ("body",), complete=True))
        original = sealed.artifacts[0]
        for part, expected in ((None, BINARY), (ByteRange(7, 10), b"\x00\xff\x08")):
            with self.subTest(part=part):
                self.assertEqual(original.sha256, hashlib.sha256(BINARY).hexdigest())
                self.assertEqual(original.capture_id, capture_id)
                self.assertEqual(self.driver.read(original.id, part=part), Read(original, expected))

    def test_record_derived_artifacts(self):
        """Scourge plan §9.2, Record. Investigation plan §11.4, lineage."""
        capture_id, original = self.captured_original()
        lineage = (Lineage(original.id, original.sha256, "fixture-manifest/v1"),)
        manifest_bytes = b'{ "fixture": "manifest" }\n'
        manifest = self.driver.record("manifest", "manifest", manifest_bytes, lineage=lineage)
        self.assert_artifact(manifest, manifest_bytes, lineage=lineage)

        lineage = (Lineage(manifest.id, manifest.sha256, "fixture-experiment/v2"),)
        experiment_bytes = b'{ "fixture": "experiment" }\n'
        experiment = self.driver.record(
            "experiment", "experiment", experiment_bytes, lineage=lineage
        )
        self.assert_artifact(experiment, experiment_bytes, lineage=lineage)

        lineage = (
            Lineage(experiment.id, experiment.sha256, "fixture-verification/v1"),
            Lineage(original.id, original.sha256, "fixture-verification/v1"),
        )
        verification_bytes = b'{ "fixture": "verification" }\n'
        verification = self.driver.record(
            "verification", "verification", verification_bytes, lineage=lineage
        )
        self.assert_artifact(verification, verification_bytes, lineage=lineage)
        self.assertEqual(len({original.id, manifest.id, experiment.id, verification.id}), 4)
        self.assert_rejected(
            "conflict",
            self.driver.record,
            "verification",
            "verification",
            verification_bytes,
            lineage=lineage[:1],
        )
        self.assert_artifact(verification, verification_bytes, lineage=lineage)
        self.assert_artifact(original, ORIGINAL, capture_id=capture_id)

    def test_reject_invalid_lineage(self):
        """Scourge plan §9.2 and INV-27. Investigation plan §11.4, source identity."""
        capture_id, original = self.captured_original()
        foreign = self.open_driver(self.temporary_workspace())
        foreign_capture = foreign.open("independent-run")
        foreign_bytes = b"artifact retained only in the independent store"
        foreign.attach(foreign_capture, "foreign", foreign_bytes, position=1)
        sealed = foreign.finalize(foreign_capture, Finalization(1, ("foreign",), complete=True))
        foreign_artifact = sealed.artifacts[0]
        self.assertEqual(foreign.read(foreign_artifact.id), Read(foreign_artifact, foreign_bytes))
        self.assert_rejected("missing", self.driver.read, foreign_artifact.id)

        transform = "fixture-manifest/v1"
        valid = Lineage(original.id, original.sha256, transform)
        data = b'{"manifest":"check source binding"}'
        for reason, invalid in (
            ("missing", Lineage(foreign_artifact.id, foreign_artifact.sha256, transform)),
            ("digest_mismatch", Lineage(original.id, foreign_artifact.sha256, transform)),
        ):
            with self.subTest(reason=reason):
                key = f"bad-lineage/{reason}"
                self.assert_rejected(
                    reason, self.driver.record, key, "manifest", data, lineage=(invalid,)
                )
                # A rejected derivation leaves the same record key available.
                artifact = self.driver.record(key, "manifest", data, lineage=(valid,))
                self.assert_artifact(artifact, data, lineage=(valid,))
        self.assert_artifact(original, ORIGINAL, capture_id=capture_id)

    def test_same_id_retry(self):
        """Scourge plan §7.5 and §9.2. Investigation plan §11.3, item receipts."""
        capture_id = self.driver.open("retry-run")
        receipt = self.driver.attach(capture_id, "body", ORIGINAL, position=1)

        self.restart_driver()
        self.assertEqual(self.driver.open("retry-run"), capture_id)
        self.assertEqual(self.driver.attach(capture_id, "body", ORIGINAL, position=1), receipt)
        self.assert_rejected(
            "conflict", self.driver.attach, capture_id, "body", ORIGINAL, position=2
        )
        request = Finalization(1, ("body",), complete=True)
        sealed = self.driver.finalize(capture_id, request)
        self.assert_capture(sealed, capture_id, (receipt,), position=1, seal="complete")

        artifact = sealed.artifacts[0]
        lineage = (Lineage(artifact.id, artifact.sha256, "fixture-manifest/v1"),)
        data = b'{"result":"retained"}'
        derived = self.driver.record("receipt", "manifest", data, lineage=lineage)

        self.restart_driver()
        self.assertEqual(self.driver.finalize(capture_id, request), sealed)
        self.assert_rejected(
            "conflict",
            self.driver.finalize,
            capture_id,
            Finalization(1, ("body",), complete=False),
        )
        self.assertEqual(self.driver.finalize(capture_id, request), sealed)
        self.assertEqual(self.driver.attach(capture_id, "body", ORIGINAL, position=1), receipt)
        self.assert_attachment(receipt, 1, "body", ORIGINAL)
        self.assert_artifact(artifact, ORIGINAL, capture_id=capture_id)
        self.assertEqual(self.driver.record("receipt", "manifest", data, lineage=lineage), derived)
        self.assert_rejected(
            "conflict", self.driver.record, "receipt", "experiment", data, lineage=lineage
        )
        self.assert_rejected(
            "conflict",
            self.driver.record,
            "receipt",
            "manifest",
            b'{"result":"replaced"}',
            lineage=lineage,
        )
        self.assertEqual(self.driver.record("receipt", "manifest", data, lineage=lineage), derived)
        self.assert_artifact(derived, data, lineage=lineage)

    def test_recover_interrupted_capture(self):
        """Scourge plan §7.5 and §9.2. Investigation plan §11.3, capture recovery."""
        capture_id = self.driver.open("interrupted-run")
        body = self.driver.attach(capture_id, "body", ORIGINAL, position=1)
        prefix = b"acknowledged partial log\n"
        log = self.driver.attach(capture_id, "log-prefix", prefix, position=2)

        self.restart_driver()
        recovered = self.driver.recover(capture_id)
        self.assert_capture(recovered, capture_id, (body, log), position=2, seal="open")

        inventory = ("body", "log-prefix", "log-trailer")
        self.assert_rejected(
            "conflict",
            self.driver.finalize,
            capture_id,
            Finalization(3, inventory, complete=True),
        )
        request = Finalization(3, inventory, complete=False)
        sealed = self.driver.finalize(capture_id, request)
        self.assert_capture(
            sealed, capture_id, (body, log), position=2, seal="partial", missing_positions=(3,)
        )
        self.assert_attachment(body, 1, "body", ORIGINAL)
        self.assert_attachment(log, 2, "log-prefix", prefix)
        self.assert_artifact(sealed.artifacts[0], ORIGINAL, capture_id=capture_id)
        self.assert_artifact(sealed.artifacts[1], prefix, capture_id=capture_id)
        self.assertEqual(self.driver.attach(capture_id, "log-prefix", prefix, position=2), log)
        self.assert_rejected(
            "closed",
            self.driver.attach,
            capture_id,
            "log-trailer",
            b"late log trailer\n",
            position=3,
        )
        self.assertEqual(self.driver.finalize(capture_id, request), sealed)

    def test_immutable_original_and_redaction(self):
        """Scourge plan §9.2, §10.1 and INV-27."""
        capture_id = self.driver.open("redaction-run")
        original_data = b"sample-marker=fixture-only\n"
        redacted_data = b"sample-marker=[redacted]\n"
        receipt = self.driver.attach(capture_id, "body", original_data, position=1)
        self.assert_rejected(
            "conflict", self.driver.attach, capture_id, "body", redacted_data, position=1
        )
        sealed = self.driver.finalize(capture_id, Finalization(1, ("body",), complete=True))
        self.assert_capture(sealed, capture_id, (receipt,), position=1, seal="complete")
        self.assert_attachment(receipt, 1, "body", original_data)

        original = sealed.artifacts[0]
        lineage = (Lineage(original.id, original.sha256, "fixture-redaction/v1"),)
        redacted = self.driver.record("redacted", "redaction", redacted_data, lineage=lineage)
        self.assertNotEqual(redacted.id, original.id)
        self.assertNotEqual(redacted.sha256, original.sha256)
        self.assert_artifact(redacted, redacted_data, lineage=lineage)
        self.assert_artifact(original, original_data, capture_id=capture_id)

    def test_reject_invalid_structured_reads(self):
        """Scourge plan §4.3 and INV-44, strict JSON inspection after raw capture."""
        capture_id = self.driver.open("json-source")
        for position, (label, data) in enumerate(INVALID_JSON.items(), start=1):
            receipt = self.driver.attach(capture_id, label, data, position=position)
            self.assert_attachment(receipt, position, label, data)
        sealed = self.driver.finalize(
            capture_id, Finalization(len(INVALID_JSON), tuple(INVALID_JSON), complete=True)
        )
        for artifact, (label, data) in zip(sealed.artifacts, INVALID_JSON.items(), strict=True):
            with self.subTest(document=label, operation="raw"):
                self.assert_artifact(artifact, data, capture_id=capture_id)
            for kind in JSON_KINDS:
                with self.subTest(kind=kind, document=label, operation="structured"):
                    self.assert_rejected(
                        "invalid_json", self.driver.read, artifact.id, structured_as=kind
                    )

    def test_reject_invalid_structured_records(self):
        """Scourge plan §4.3 and INV-44, refuse malformed structured writes."""
        _, source = self.captured_original()
        lineage = (Lineage(source.id, source.sha256, "fixture-json/v1"),)
        valid = b'{"value":1}'
        for kind in JSON_KINDS:
            for label, data in INVALID_JSON.items():
                with self.subTest(kind=kind, document=label):
                    key = f"{kind}/{label}"
                    self.assert_rejected(
                        "invalid_json", self.driver.record, key, kind, data, lineage=lineage
                    )
                    artifact = self.driver.record(key, kind, valid, lineage=lineage)
                    self.assert_artifact(artifact, valid, lineage=lineage)

    def test_structured_exact_bytes(self):
        """Scourge plan §4.3 and INV-44, valid JSON spellings retain distinct bytes."""
        _, source = self.captured_original()
        lineage = (Lineage(source.id, source.sha256, "fixture-json/v1"),)
        compact = b'{"decimal":"18.70","counter":"9007199254740992","unit":"ms"}'
        spaced = b'{ "unit": "ms", "counter": "9007199254740992", "decimal": "18.70" }\n'
        for kind in JSON_KINDS:
            with self.subTest(kind=kind, document="exact-bytes"):
                first = self.driver.record(f"{kind}/compact", kind, compact, lineage=lineage)
                second = self.driver.record(f"{kind}/spaced", kind, spaced, lineage=lineage)
                self.assert_artifact(first, compact, lineage=lineage)
                self.assert_artifact(second, spaced, lineage=lineage)
                self.assertNotEqual(first.sha256, second.sha256)
                self.assertEqual(self.driver.read(first.id, structured_as=kind), Read(first, compact))
                self.assertEqual(self.driver.read(second.id, structured_as=kind), Read(second, spaced))


def adapter_factory(path: Path) -> DriverFactory:
    session_ids = itertools.count()

    def open_driver(scratch: Path):
        name = f"evidence_adapter_{next(session_ids)}"
        spec = importlib.util.spec_from_file_location(name, path)
        if spec is None or spec.loader is None:
            raise ValueError(f"expected a Python adapter file at {path}")
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
        return module.open_driver(scratch)

    return open_driver


def main() -> int:
    loader = unittest.TestLoader()
    parser = argparse.ArgumentParser(description=__doc__)
    adapter = parser.add_mutually_exclusive_group(required=True)
    adapter.add_argument("--self-test", action="store_true", help="use the in-memory fixture double")
    adapter.add_argument("--adapter", type=Path, metavar="FILE", help="load one driver adapter")
    parser.add_argument("--case", choices=loader.getTestCaseNames(EvidenceCases), action="append")
    args = parser.parse_args()

    if args.self_test:
        from reference import make_factory

        print("Fixture self-test only. Passing proves nothing about Investigation.", flush=True)
        factory = make_factory()
    else:
        factory = adapter_factory(args.adapter.resolve())

    class SelectedCases(EvidenceCases):
        driver_factory = staticmethod(factory)

    names = args.case or loader.getTestCaseNames(SelectedCases)
    suite = unittest.TestSuite(SelectedCases(name) for name in names)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
