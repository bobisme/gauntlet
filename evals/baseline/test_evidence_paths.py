#!/usr/bin/env python3
"""Focused tests for evidence collection path safety."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import evidence_paths as ep  # noqa: E402
import run_baseline  # noqa: E402


class WorkspaceCopyTests(unittest.TestCase):
    def test_nested_files_retained_and_hashed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workspace = root / "workspace"
            (workspace / "nested/deep").mkdir(parents=True)
            (workspace / "top.txt").write_text("top\n", encoding="utf-8")
            (workspace / "nested/deep/file.txt").write_text("nested\n", encoding="utf-8")
            (workspace / ".teapot").mkdir()
            (workspace / ".teapot/project.db").write_text("instrument\n", encoding="utf-8")
            destination = root / "evidence/workspace"
            result = ep.copy_workspace_tree(workspace, destination)
            self.assertEqual(
                sorted(result["files"]),
                ["nested/deep/file.txt", "top.txt"],
            )
            self.assertEqual((destination / "nested/deep/file.txt").read_text(), "nested\n")
            self.assertEqual(
                result["files"]["nested/deep/file.txt"]["sha256"],
                ep.sha256_file(destination / "nested/deep/file.txt"),
            )
            self.assertFalse((destination / ".teapot").exists())
            self.assertIn(
                {"path": ".teapot", "reason": "excluded-instrument-store"},
                result["skipped"],
            )

    def test_escaping_symlinks_are_skipped_not_read(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            outside = root / "outside"
            outside.mkdir()
            secret = outside / "secret.txt"
            secret.write_text("ESCAPE-SECRET\n", encoding="utf-8")
            workspace = root / "workspace"
            (workspace / "nested").mkdir(parents=True)
            (workspace / "nested/ok.txt").write_text("ok\n", encoding="utf-8")
            os.symlink(secret, workspace / "leak.txt")
            os.symlink(outside, workspace / "dirlink")
            os.symlink(secret, workspace / "nested/inner-link.txt")
            os.symlink(workspace / "nested/ok.txt", workspace / "inside-link.txt")
            destination = root / "evidence/workspace"
            result = ep.copy_workspace_tree(workspace, destination)
            self.assertEqual(sorted(result["files"]), ["nested/ok.txt"])
            self.assertFalse((destination / "leak.txt").exists())
            self.assertFalse((destination / "dirlink").exists())
            self.assertFalse((destination / "nested/inner-link.txt").exists())
            self.assertFalse((destination / "inside-link.txt").exists())
            reasons = {item["path"]: item["reason"] for item in result["skipped"]}
            self.assertEqual(reasons["leak.txt"], "symlink-file")
            self.assertEqual(reasons["dirlink"], "symlink-directory")
            self.assertEqual(reasons["nested/inner-link.txt"], "symlink-file")
            self.assertEqual(reasons["inside-link.txt"], "symlink-file")
            for path in destination.rglob("*"):
                if path.is_file():
                    self.assertNotIn(b"ESCAPE-SECRET", path.read_bytes())

    def test_hardlink_is_skipped_and_not_copied(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            outside = root / "outside.txt"
            outside.write_text("OUTSIDE-HARDLINK\n", encoding="utf-8")
            workspace = root / "workspace"
            workspace.mkdir()
            (workspace / "normal.txt").write_text("normal\n", encoding="utf-8")
            os.link(outside, workspace / "leak.md")
            files, skipped = ep.iter_workspace_files(workspace)
            self.assertEqual([relative for relative, _ in files], ["normal.txt"])
            self.assertIn({"path": "leak.md", "reason": "hardlink"}, skipped)
            destination = root / "evidence/workspace"
            result = ep.copy_workspace_tree(workspace, destination)
            self.assertEqual(sorted(result["files"]), ["normal.txt"])
            self.assertFalse((destination / "leak.md").exists())
            self.assertIn({"path": "leak.md", "reason": "hardlink"}, result["skipped"])

    def test_safe_report_files_excludes_symlinks_and_hardlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            outside = root / "outside.txt"
            outside.write_text("REPORT-ESCAPE\n", encoding="utf-8")
            workspace = root / "workspace"
            (workspace / "nested").mkdir(parents=True)
            (workspace / "report.md").write_text("report\n", encoding="utf-8")
            (workspace / "notes.txt").write_text("notes\n", encoding="utf-8")
            (workspace / "data.json").write_text("{\"ok\": true}\n", encoding="utf-8")
            (workspace / "nested/inner.md").write_text("nested\n", encoding="utf-8")
            (workspace / "ignore.bin").write_text("bin\n", encoding="utf-8")
            os.symlink(outside, workspace / "link.md")
            os.symlink(workspace / "report.md", workspace / "alias.md")
            os.link(outside, workspace / "hard.txt")
            hashes, skipped = run_baseline.safe_report_files(workspace)
            self.assertEqual(sorted(hashes), ["data.json", "notes.txt", "report.md"])
            self.assertNotIn("link.md", hashes)
            self.assertNotIn("alias.md", hashes)
            self.assertNotIn("hard.txt", hashes)
            reasons = {item["path"]: item["reason"] for item in skipped}
            self.assertEqual(reasons["link.md"], "symlink-file")
            self.assertEqual(reasons["alias.md"], "symlink-file")
            self.assertEqual(reasons["hard.txt"], "hardlink")
            self.assertEqual(
                hashes["report.md"],
                ep.sha256_file(workspace / "report.md"),
            )

    def test_open_time_guard_refuses_hardlink_and_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            outside = root / "outside.txt"
            outside.write_text("GUARD-SECRET\n", encoding="utf-8")
            workspace = root / "workspace"
            workspace.mkdir()
            os.link(outside, workspace / "hard.txt")
            os.symlink(outside, workspace / "link.txt")
            for path in (workspace / "hard.txt", workspace / "link.txt"):
                with self.assertRaises(ep.PathSafetyError):
                    ep.read_regular_nofollow(path)
                with self.assertRaises(ep.PathSafetyError):
                    ep.sha256_regular_nofollow(path)
                destination = root / "copy.txt"
                with self.assertRaises(ep.PathSafetyError):
                    ep.copy_regular_nofollow(path, destination)
                self.assertFalse(destination.exists())

    def test_safe_join_rejects_traversal_and_escaping_links(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "root"
            outside = Path(directory) / "outside"
            root.mkdir()
            outside.mkdir()
            for bad in ("../x", "/absolute", "a/../../b", "", ".", "a/../b"):
                with self.assertRaises(ep.PathSafetyError, msg=bad):
                    ep.safe_join(root, bad)
            os.symlink(outside, root / "link")
            with self.assertRaises(ep.PathSafetyError):
                ep.safe_join(root, "link/escape.txt")
            inside = root / "inside"
            inside.mkdir()
            os.symlink(inside, root / "inside-link")
            with self.assertRaises(ep.PathSafetyError):
                ep.safe_join(root, "inside-link/nested.txt")
            self.assertTrue(str(ep.safe_join(root, "ok/nested.txt")).startswith(str(root)))

    def test_copy_evidence_retains_nested_workspace_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run_root = root / "run"
            (run_root / "artifacts").mkdir(parents=True)
            (run_root / "artifacts/run.json").write_text("{}\n", encoding="utf-8")
            (run_root / "workspace/nested/deep").mkdir(parents=True)
            (run_root / "workspace/nested/deep/report.md").write_text("report\n", encoding="utf-8")
            (run_root / "workspace/top.txt").write_text("top\n", encoding="utf-8")
            outside = root / "outside.txt"
            outside.write_text("ESCAPE\n", encoding="utf-8")
            os.symlink(outside, run_root / "workspace/leak.txt")
            os.link(outside, run_root / "workspace/hard.md")
            evidence = root / "evidence"
            copied = run_baseline.copy_evidence(
                {"run_root": str(run_root), "trial_label": "test-1"}, evidence
            )
            target = evidence / "test-1"
            self.assertTrue((target / "workspace/nested/deep/report.md").is_file())
            self.assertIn("workspace/nested/deep/report.md", copied)
            self.assertIn("workspace/top.txt", copied)
            self.assertNotIn("workspace/leak.txt", copied)
            self.assertNotIn("workspace/hard.md", copied)
            self.assertFalse((target / "workspace/hard.md").exists())
            manifest = json.loads((target / "SHA256SUMS.json").read_text())
            self.assertEqual(
                manifest["workspace/nested/deep/report.md"],
                ep.sha256_file(target / "workspace/nested/deep/report.md"),
            )
            skipped = json.loads((target / "workspace-skipped.json").read_text())
            reasons = {item["path"]: item["reason"] for item in skipped["skipped"]}
            self.assertEqual(reasons["leak.txt"], "symlink-file")
            self.assertEqual(reasons["hard.md"], "hardlink")
            self.assertNotIn(
                b"ESCAPE",
                (target / "workspace/top.txt").read_bytes()
                + (target / "workspace/nested/deep/report.md").read_bytes(),
            )
            with self.assertRaises(run_baseline.Blocked):
                run_baseline.copy_evidence(
                    {"run_root": str(run_root), "trial_label": "test-1"}, evidence
                )

    def test_supplement_script_uses_safe_walker(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run_root = root / "run"
            (run_root / "workspace/nested").mkdir(parents=True)
            (run_root / "workspace/nested/file.txt").write_text("nested\n", encoding="utf-8")
            outside = root / "outside.txt"
            outside.write_text("ESCAPE-SECRET\n", encoding="utf-8")
            os.symlink(outside, run_root / "workspace/leak.txt")
            ledger = root / "ledger.jsonl"
            ledger.write_text(
                json.dumps(
                    {
                        "trial_label": "test-1",
                        "schedule_position": 1,
                        "assigned_arm": "A",
                        "run_root": str(run_root),
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            evidence = root / "evidence"
            command = [
                sys.executable,
                "-B",
                str(HERE / "supplement_evidence.py"),
                "--ledger",
                str(ledger),
                "--evidence",
                str(evidence),
            ]
            completed = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            target = evidence / "test-1/workspace-supplement"
            self.assertTrue((target / "nested/file.txt").is_file())
            entry = json.loads((target / "SUPPLEMENT.json").read_text())
            self.assertIn("nested/file.txt", entry["files"])
            self.assertEqual(entry["files"]["nested/file.txt"]["sha256"], ep.sha256_file(target / "nested/file.txt"))
            self.assertEqual(entry["skipped"][0]["reason"], "symlink-file")
            self.assertNotIn(b"ESCAPE-SECRET", (target / "nested/file.txt").read_bytes())
            again = subprocess.run(command, capture_output=True, text=True)
            self.assertNotEqual(again.returncode, 0)


if __name__ == "__main__":
    unittest.main()
