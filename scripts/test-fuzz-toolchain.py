#!/usr/bin/env python3
"""Regression tests for the recorded cargo-fuzz driver pin.

The review reproduced a fake driver that reports `cargo-fuzz 99.0.0` and still
launched a target: `just fuzz-parsers <target> <seconds>` printed the version and
compiled. These tests put such a shim first on PATH and require a refusal before
the target is compiled or launched.
"""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
CHECKER_PATH = ROOT / "scripts" / "check-fuzz-toolchain.py"
SPEC = importlib.util.spec_from_file_location("check_fuzz_toolchain", CHECKER_PATH)
assert SPEC is not None and SPEC.loader is not None
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)

PINNED = "cargo-fuzz 0.13.1"


class FakeCargo:
    """A cargo shim that reports a chosen version and logs every call."""

    def __init__(self, root: Path, version: str | None, status: int = 0, stdout: str = ""):
        self.root = root
        self.log = root / "cargo-calls.log"
        self.real = shutil.which("cargo")
        assert self.real is not None
        self.path = root / "cargo"
        self.path.write_text(
            "#!/usr/bin/env bash\n"
            f'printf "%s\\n" "$*" >> "{self.log}"\n'
            'if [[ "${1-}" == "fuzz" && "${2-}" == "--version" ]]; then\n'
            f'  printf "%s" "{version or ""}"\n'
            f'  printf "%s" "{stdout}"\n'
            f"  exit {status}\n"
            "fi\n"
            f'exec "{self.real}" "$@"\n'
        )
        self.path.chmod(self.path.stat().st_mode | stat.S_IXUSR)

    def environment(self) -> dict[str, str]:
        environment = dict(os.environ)
        environment["PATH"] = f"{self.root}{os.pathsep}{environment.get('PATH', '')}"
        return environment

    def calls(self) -> list[str]:
        if not self.log.exists():
            return []
        return self.log.read_text().splitlines()


class ToolchainPinTest(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory(prefix="scourge-fuzz-pin.")
        self.root = Path(self.directory.name)
        self.addCleanup(self.directory.cleanup)

    def test_recorded_driver_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory(prefix="scourge-fuzz-ok.") as directory:
            shim = FakeCargo(Path(directory), f"{PINNED}\n")
            self.assertEqual(CHECKER.read_version(str(shim.path)), PINNED)
            self.assertEqual(CHECKER.require_pinned(PINNED), PINNED)
            completed = subprocess.run(
                [sys.executable, "-B", str(CHECKER_PATH), "--cargo", str(shim.path)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(completed.stdout.strip(), PINNED)
            # Only version probes, never a run.
            self.assertEqual(set(shim.calls()), {"fuzz --version"})

    def test_a_newer_driver_is_refused(self) -> None:
        with tempfile.TemporaryDirectory(prefix="scourge-fuzz-bad.") as directory:
            shim = FakeCargo(Path(directory), "cargo-fuzz 99.0.0\n")
            self.assertEqual(CHECKER.read_version(str(shim.path)), "cargo-fuzz 99.0.0")
            with self.assertRaisesRegex(CHECKER.ToolchainPinError, "99.0.0"):
                CHECKER.require_pinned(CHECKER.read_version(str(shim.path)))
            completed = subprocess.run(
                [sys.executable, "-B", str(CHECKER_PATH), "--cargo", str(shim.path)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 1)
            self.assertIn(PINNED, completed.stderr)
            self.assertIn("99.0.0", completed.stderr)
            self.assertEqual(completed.stdout, "")
            # The refusal happens before any other cargo call.
            self.assertEqual(set(shim.calls()), {"fuzz --version"})

    def test_a_missing_driver_is_refused(self) -> None:
        missing = self.root / "missing-cargo"
        with self.assertRaisesRegex(CHECKER.ToolchainPinError, "not installed"):
            CHECKER.read_version(str(missing))
        completed = subprocess.run(
            [sys.executable, "-B", str(CHECKER_PATH), "--cargo", str(missing)],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 1)
        self.assertIn("cargo-fuzz pin:", completed.stderr)

    def test_a_failing_version_probe_is_refused(self) -> None:
        with tempfile.TemporaryDirectory(prefix="scourge-fuzz-fail.") as directory:
            shim = FakeCargo(Path(directory), "", status=3, stdout="")
            with self.assertRaisesRegex(CHECKER.ToolchainPinError, "exited 3"):
                CHECKER.read_version(str(shim.path))

    def test_unknown_arguments_are_refused(self) -> None:
        self.assertEqual(CHECKER.main(["check-fuzz-toolchain.py", "--bogus"]), 2)
        self.assertEqual(CHECKER.main(["check-fuzz-toolchain.py", "--cargo"]), 2)

    def test_the_just_recipe_refuses_before_launch(self) -> None:
        # The exact reproduction from the review: a fake driver first on PATH.
        just = shutil.which("just")
        if just is None:
            self.skipTest("just is not installed")
        with tempfile.TemporaryDirectory(prefix="scourge-fuzz-just.") as directory:
            shim = FakeCargo(Path(directory), "cargo-fuzz 99.0.0\n")
            completed = subprocess.run(
                [just, "fuzz-parsers", "canonical_json", "1"],
                cwd=ROOT,
                env=shim.environment(),
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(completed.returncode, 0, completed.stdout)
            self.assertIn("cargo-fuzz pin:", completed.stderr)
            self.assertIn("99.0.0", completed.stderr)
            self.assertIn(PINNED, completed.stderr)
            # Nothing compiled and no target was launched: the only cargo call
            # is the version probe, so the nightly toolchain and `fuzz run`
            # never ran.
            self.assertEqual(shim.calls(), ["fuzz --version"])


if __name__ == "__main__":
    unittest.main()
