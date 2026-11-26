"""Offline acceptance for M0-ADD-02 capture and evidence retention."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

LIB = Path(__file__).resolve().parent / "lib"
sys.path.insert(0, str(LIB))
import trial_capture as capture  # noqa: E402


PROGRESS = b'{"type":"progress","model":"scripted","usage":{"input_tokens":13,"output_tokens":5}}\n'
TERMINAL = b'{"type":"turn.completed","usage":{"input_tokens":21,"output_tokens":8}}\n'
TRUNCATED = b'{"type":"turn.completed","usage":'
STDERR = b"synthetic diagnostic\n\xff"
NESTED = b"nested bytes\x00\xff\n"


class CaptureSettlementTest(unittest.TestCase):
    def setUp(self):
        scratch = self.enterContext(tempfile.TemporaryDirectory(prefix="scourge-capture-"))
        self.base = Path(scratch).resolve()
        self.checkout = self.base / "checkout"
        self.run_root = self.base / "runs"
        self.source = self.base / "worker"
        self.checkout.mkdir(mode=0o700)
        self.run_root.mkdir(mode=0o700)
        self.source.mkdir(mode=0o700)
        (self.source / "capture").mkdir()
        (self.source / "capture/native.jsonl").write_bytes(PROGRESS + TERMINAL)
        (self.source / "capture/raw.stderr").write_bytes(STDERR)
        (self.source / "work/output/session/nested").mkdir(parents=True)
        (self.source / "work/output/session/nested/data.bin").write_bytes(NESTED)
        (self.source / "work/output/session/empty-dir").mkdir()
        (self.source / "work/output/zero").touch()
        self.trial = self.run_root / "trial"
        self.retained = self.trial / "retained"

    def prepare(self, **overrides):
        receipt = capture.pending(self.run_root, self.checkout, 1, 1, "trial", **overrides)
        self.assertEqual(receipt["status"], "pending")
        self.assertFalse(receipt["settled"])
        self.assertFalse(receipt["valid"])
        self.assertIsNone(receipt["score"])
        self.assertEqual(self.read_receipt(), receipt)
        return receipt

    def settle(self, source=None, **overrides):
        options = {
            "events": "capture/native.jsonl", "stderr": "capture/raw.stderr",
            "artifacts": "work/output", "exit_code": 0, "worker_stopped": True,
            "safety_ok": True, "boundary_ok": True,
        }
        options.update(overrides)
        receipt = capture.settle(self.run_root, "trial", source or self.source, **options)
        self.assertEqual(self.read_receipt(), receipt)
        return receipt

    def read_receipt(self):
        return json.loads((self.trial / "capture.json").read_bytes())

    def event_bytes(self, data):
        (self.source / "capture/native.jsonl").write_bytes(data)

    def assert_unsettled(self, receipt, *codes):
        self.assertEqual(receipt["status"], "unsettled")
        self.assertFalse(receipt["settled"])
        self.assertFalse(receipt["valid"])
        self.assertIsNone(receipt["score"])
        self.assertLessEqual(set(codes), {reason["code"] for reason in receipt["reasons"]})

    def assert_exact_retention(self, receipt, stream):
        inventory = receipt["inventory"]
        self.assertTrue(inventory["complete"])
        self.assertTrue(inventory["verified"])
        rows = inventory["source"]
        self.assertEqual(rows, inventory["retained"])
        self.assertEqual([row["path"] for row in rows], sorted(row["path"] for row in rows))
        self.assertEqual(rows, [
            {"path": "artifacts", "type": "directory", "bytes": 0, "sha256": None},
            {"path": "artifacts/session", "type": "directory", "bytes": 0, "sha256": None},
            {"path": "artifacts/session/empty-dir", "type": "directory", "bytes": 0, "sha256": None},
            {"path": "artifacts/session/nested", "type": "directory", "bytes": 0, "sha256": None},
            self.file_row("artifacts/session/nested/data.bin", NESTED),
            self.file_row("artifacts/zero", b""),
            {"path": "raw", "type": "directory", "bytes": 0, "sha256": None},
            self.file_row("raw/transcript.jsonl", stream),
            self.file_row("raw/worker.stderr", STDERR),
        ])
        digest = hashlib.sha256(json.dumps(
            rows, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")).hexdigest()
        self.assertEqual(inventory["source_sha256"], digest)
        self.assertEqual(inventory["retained_sha256"], digest)
        for path, data in (
            ("artifacts/session/nested/data.bin", NESTED),
            ("raw/transcript.jsonl", stream),
            ("raw/worker.stderr", STDERR),
        ):
            self.assertEqual((self.retained / path).read_bytes(), data)
        self.assertTrue((self.retained / "artifacts/session/empty-dir").is_dir())
        self.assertTrue((self.retained / "artifacts/zero").is_file())

    @staticmethod
    def file_row(path, data):
        return {"path": path, "type": "file", "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}

    def test_correct_capture_settles_with_verified_inventory(self):
        pending = self.prepare()
        preflight = pending["preflight"]
        self.assertEqual(preflight["schema_version"], 1)
        self.assertGreater(preflight["write_probe"]["bytes_written"], 0)
        for check in ("flushed", "file_synced", "unlinked", "directory_synced"):
            self.assertTrue(preflight["write_probe"][check])
        self.assertGreaterEqual(preflight["capacity"]["available_bytes"], 1)
        self.assertGreaterEqual(preflight["capacity"]["available_inodes"], 1)
        self.assertEqual(list(self.run_root.iterdir()), [self.trial])
        receipt = self.settle()
        self.assertEqual(receipt["schema_version"], 1)
        self.assertEqual(receipt["status"], "settled")
        self.assertTrue(receipt["settled"])
        self.assertTrue(receipt["valid"])
        self.assertIsNone(receipt["score"])
        self.assertEqual(receipt["events"]["terminal_line"], 2)
        self.assertEqual(receipt["events"]["model_input_tokens"], 21)
        self.assertEqual(receipt["events"]["valid_prefix_events"], 2)
        self.assert_exact_retention(receipt, PROGRESS + TERMINAL)
        with self.assertRaisesRegex(capture.CaptureError, "already-finalized"):
            self.settle()
        self.assertEqual(self.read_receipt(), receipt)

    def test_torn_terminal_keeps_raw_nested_evidence_and_valid_prefix(self):
        self.prepare()
        stream = PROGRESS + TRUNCATED
        self.event_bytes(stream)
        receipt = self.settle()
        self.assert_unsettled(receipt, "torn-event", "missing-terminal-event")
        self.assert_exact_retention(receipt, stream)
        events = receipt["events"]
        self.assertEqual(events["valid_prefix_events"], 1)
        self.assertEqual(events["valid_prefix_bytes"], len(PROGRESS))
        self.assertEqual(events["valid_prefix_sha256"], hashlib.sha256(PROGRESS).hexdigest())
        self.assertEqual(events["usage"], [{"input_tokens": 13, "output_tokens": 5}])
        self.assertEqual(events["model_input_tokens"], 13)
        self.assertIsNone(events["terminal_line"])

    def test_capacity_refuses_pending_before_trial_creation(self):
        receipt = capture.pending(self.run_root, self.checkout, 1 << 90, 1 << 90, "trial")
        self.assertFalse(receipt["passed"])
        self.assertEqual(
            {row["code"] for row in receipt["reasons"]}, {"insufficient-bytes", "insufficient-inodes"}
        )
        self.assertTrue(receipt["write_probe"]["unlinked"])
        self.assertEqual(receipt["capacity"]["minimum_bytes"], 1 << 90)
        self.assertIsInstance(receipt["capacity"]["available_inodes"], int)
        self.assertEqual(list(self.run_root.iterdir()), [])

    def test_preflight_requires_private_canonical_external_root(self):
        link = self.base / "run-link"
        link.symlink_to(self.run_root, target_is_directory=True)
        self.assertFalse(capture.preflight(link, self.checkout, 1, 1)["passed"])
        self.assertFalse(capture.preflight(f"{self.run_root}/../runs", self.checkout, 1, 1)["passed"])
        self.assertFalse(capture.preflight(self.checkout, self.checkout, 1, 1)["passed"])
        self.assertFalse(capture.preflight(self.run_root, self.checkout, 1, 1,
                                           exclude_roots=[self.run_root / "nested"])["passed"])
        with mock.patch.dict(os.environ, {"HOME": str(self.run_root)}):
            self.assertFalse(capture.preflight(self.run_root, self.checkout, 1, 1)["passed"])
        self.run_root.chmod(0o750)
        self.assertFalse(capture.preflight(self.run_root, self.checkout, 1, 1)["passed"])

    def test_probe_fsync_failure_leaves_no_probe_or_trial(self):
        with mock.patch.object(capture.os, "fsync", side_effect=OSError(5, "test sync failure")):
            failed = capture.pending(self.run_root, self.checkout, 1, 1, "trial")
        self.assertFalse(failed["passed"])
        self.assertTrue(failed["write_probe"]["flushed"])
        self.assertTrue(failed["write_probe"]["unlinked"])
        self.assertFalse(failed["write_probe"]["file_synced"])
        self.assertEqual(list(self.run_root.iterdir()), [])

    def test_interruption_retains_after_stop_but_never_settles(self):
        self.prepare()
        receipt = self.settle(interrupted=True, exit_code=130, safety_ok=False, boundary_ok=False)
        self.assert_unsettled(receipt, "interrupted", "nonzero-command",
                              "safety-check-failed", "boundary-check-failed")
        self.assert_exact_retention(receipt, PROGRESS + TERMINAL)

    def test_unstopped_worker_is_never_read(self):
        self.prepare()
        with mock.patch.object(capture, "_collect", side_effect=AssertionError("worker still running")):
            receipt = self.settle(worker_stopped=False)
        self.assert_unsettled(receipt, "worker-not-stopped")
        self.assertFalse(self.retained.exists())

    def test_malformed_event_and_missing_terminal_remain_unsettled(self):
        self.prepare()
        stream = PROGRESS + b'{"type":3}\n' + TERMINAL
        self.event_bytes(stream)
        receipt = self.settle()
        self.assert_unsettled(receipt, "malformed-event", "missing-terminal-event")
        self.assert_exact_retention(receipt, stream)
        self.assertEqual(receipt["events"]["valid_prefix_events"], 1)

    def test_stream_and_command_receipts_are_both_required(self):
        self.prepare()
        self.event_bytes(PROGRESS)
        receipt = self.settle(exit_code=None)
        self.assert_unsettled(receipt, "missing-terminal-event", "missing-command-receipt")
        self.assert_exact_retention(receipt, PROGRESS)

    def test_event_prefix_refuses_trailing_events_and_torn_json_objects(self):
        for tail, code in (
            (b'{"type":"unexpected"}\n', "post-terminal-event"),
            (b'{"type":"turn.completed"}\n', "post-terminal-event"),
            (b'{"type":"following"', "torn-event"),
            (b'garbage\n', "malformed-event"),
            (b'{"type":"one","type":"two"}\n', "malformed-event"),
            (b'{"type":"following","data":NaN}\n', "malformed-event"),
        ):
            with self.subTest(tail=tail):
                summary = capture._event_prefix(iter((PROGRESS, TERMINAL, tail)), "turn.completed")
                self.assertEqual(summary["valid_prefix_events"], 2)
                self.assertEqual(summary["issues"], [{"code": code, "line": 3}])
        summary = capture._event_prefix(iter((PROGRESS, TERMINAL.rstrip())), "turn.completed")
        self.assertEqual(summary["valid_prefix_events"], 1)
        self.assertEqual(summary["issues"], [{"code": "torn-event", "line": 2},
                                              {"code": "missing-terminal-event"}])

    def test_missing_input_preserves_other_stream_and_nested_artifacts(self):
        self.prepare()
        (self.source / "capture/raw.stderr").unlink()
        receipt = self.settle()
        self.assert_unsettled(receipt, "inventory-incomplete")
        self.assertFalse(receipt["inventory"]["verified"])
        self.assertEqual((self.retained / "artifacts/session/nested/data.bin").read_bytes(), NESTED)
        self.assertEqual((self.retained / "raw/transcript.jsonl").read_bytes(), PROGRESS + TERMINAL)

    def test_rejects_symlinks_hardlink_and_fifo_without_reading_targets(self):
        self.prepare()
        outside = self.base / "outside"
        outside.mkdir()
        (outside / "secret").write_bytes(b"unrelated")
        nested = self.source / "work/output/session/nested"
        (nested / "file-link").symlink_to(outside / "secret")
        (nested / "directory-link").symlink_to(outside, target_is_directory=True)
        os.link(outside / "secret", nested / "external-hardlink")
        os.mkfifo(nested / "pipe")
        receipt = self.settle()
        self.assert_unsettled(receipt, "inventory-incomplete")
        issues = {row["path"]: row["code"] for row in receipt["inventory"]["issues"]}
        self.assertEqual(issues, {
            "artifacts/session/nested/directory-link": "symlink",
            "artifacts/session/nested/external-hardlink": "hardlink",
            "artifacts/session/nested/file-link": "symlink",
            "artifacts/session/nested/pipe": "special-file",
        })
        self.assertEqual(list((self.retained / "artifacts/session/nested").iterdir()),
                         [self.retained / "artifacts/session/nested/data.bin"])

    def test_relative_path_escape_does_not_prevent_retaining_safe_inputs(self):
        self.prepare()
        receipt = self.settle(events="../checkout")
        self.assert_unsettled(receipt, "inventory-incomplete", "event-capture-unavailable")
        self.assertTrue(any(issue["code"] == "unsafe-relative-path"
                            for issue in receipt["inventory"]["issues"]))
        self.assertEqual((self.retained / "raw/worker.stderr").read_bytes(), STDERR)

    def test_source_overlap_refuses_before_creating_retention_tree(self):
        self.prepare()
        receipt = self.settle(self.run_root)
        self.assert_unsettled(receipt, "inventory-incomplete")
        self.assertEqual(receipt["inventory"]["issues"], [{
            "phase": "collection", "code": "overlapping-source",
            "detail": "source and trial directories must be disjoint",
        }])
        self.assertFalse(self.retained.exists())

    def test_entry_swapped_for_symlink_after_lstat_is_refused(self):
        self.prepare()
        actual_open = os.open
        artifact = self.source / "work/output/session/nested/data.bin"
        unrelated = self.base / "unrelated"
        unrelated.write_bytes(b"must not follow")
        replaced = False

        def swap_on_pin(path, flags, *args, **kwargs):
            nonlocal replaced
            if path == "data.bin" and flags == capture.PIN_FLAGS and not replaced:
                artifact.unlink()
                artifact.symlink_to(unrelated)
                replaced = True
            return actual_open(path, flags, *args, **kwargs)

        with mock.patch.object(capture.os, "open", side_effect=swap_on_pin):
            receipt = self.settle()
        self.assertTrue(replaced)
        self.assert_unsettled(receipt, "inventory-incomplete")
        self.assertTrue(any(issue["code"] == "path-changed" for issue in receipt["inventory"]["issues"]))
        self.assertFalse((self.retained / "artifacts/session/nested/data.bin").exists())

    def test_source_modified_after_copy_is_refused(self):
        self.prepare()
        file_row = capture._file_row

        def mutate_prior_file(parent_fd, name, before, path, destination_fd, destination_name, mount_id):
            if path == "artifacts/zero" and destination_fd is not None:
                (self.source / "work/output/session/nested/data.bin").write_bytes(b"later write")
            return file_row(parent_fd, name, before, path, destination_fd, destination_name, mount_id)

        with mock.patch.object(capture, "_file_row", side_effect=mutate_prior_file):
            receipt = self.settle()
        self.assert_unsettled(receipt, "inventory-incomplete")
        self.assertTrue(any(issue["code"] == "path-changed" for issue in receipt["inventory"]["issues"]))
        self.assertEqual((self.retained / "artifacts/session/nested/data.bin").read_bytes(), NESTED)

    def test_destination_digest_mismatch_is_invalid_even_if_complete(self):
        self.prepare()
        file_row = capture._file_row

        def corrupt_copy(parent_fd, name, before, path, destination_fd, destination_name, mount_id):
            row = file_row(parent_fd, name, before, path, destination_fd, destination_name, mount_id)
            if path.endswith("/data.bin") and destination_fd is not None:
                fd = os.open(destination_name, os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW, dir_fd=destination_fd)
                with os.fdopen(fd, "wb") as writer:
                    writer.write(b"x" * len(NESTED))
            return row

        with mock.patch.object(capture, "_file_row", side_effect=corrupt_copy):
            receipt = self.settle()
        self.assert_unsettled(receipt, "inventory-mismatch")
        self.assertTrue(receipt["inventory"]["complete"])
        self.assertFalse(receipt["inventory"]["verified"])
        self.assertNotEqual(receipt["inventory"]["source_sha256"], receipt["inventory"]["retained_sha256"])

    def test_cli_publishes_pending_then_returns_two_for_invalid_capture(self):
        command = [sys.executable, "-B", str(LIB / "trial_capture.py")]
        begin = subprocess.run(
            command + ["pending", "--run-root", str(self.run_root), "--checkout", str(self.checkout),
                       "--min-bytes", "1", "--min-inodes", "1", "--trial-id", "trial",
                       "--terminal-event", "scripted.finished"],
            check=True, capture_output=True, text=True,
        )
        self.assertEqual(json.loads(begin.stdout)["status"], "pending")
        end = subprocess.run(
            command + ["settle", "--run-root", str(self.run_root), "--trial-id", "trial",
                       "--source-root", str(self.source), "--events", "capture/native.jsonl",
                       "--stderr", "capture/raw.stderr", "--artifacts", "work/output",
                       "--exit-code", "0", "--worker-stopped", "--safety-ok", "--boundary-ok"],
            check=False, capture_output=True, text=True,
        )
        self.assertEqual(end.returncode, 2)
        receipt = json.loads(end.stdout)
        self.assert_unsettled(receipt, "missing-terminal-event")
        self.assertEqual(receipt, self.read_receipt())


if __name__ == "__main__":
    unittest.main()
