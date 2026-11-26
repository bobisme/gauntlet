#!/usr/bin/env python3
"""Check the M1 entry points and their retained acceptance inventory."""

import copy
import hashlib
import importlib.util
import io
import json
import re
import runpy
import shlex
import stat
import subprocess
import sys
import tempfile
import unittest
from collections import Counter
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs/m1-checks.md"
EXAMPLE = ROOT / "fixtures/target/example/private-object-read-workflow.sh"
SCRIPT = ROOT / "scripts/m1-qualification.py"
GUIDE_CHECK = ROOT / "scripts/check-oracle-guide-example.sh"
QUALIFICATION_ARGUMENTS = {
    "instrument-contract-check": ["teapot", "investigation"],
    "m1-qualification-check": ["oracle_teapot", "recovery_teapot", "investigation"],
    "oracle-fixture-check": ["teapot", "investigation"],
    "recovery-fixture-check": ["teapot", "investigation"],
    "demo-check": ["teapot", "investigation"],
    "fixture-check": [],
    "evidence-bridge-check": [],
}
QUALIFICATION_SUBRECIPES = {
    "evidence-bridge-check": [
        "_evidence-capture-check", "_evidence-publication-check", "_evidence-read-check",
    ],
    "recovery-fixture-check": ["_recovery-native-check", "_recovery-dispatch-check"],
    "demo-check": ["_demo-process-check", "_demo-orphan-check"],
}


def validate_registration(recipes):
    check = [shlex.split(line[0]) for line in recipes["check"]["body"]]
    test = [shlex.split(line[0]) for line in recipes["test"]["body"]]
    for required in (
        "schema-check", "cross-lane-check", "oracle-spec-check", "m1-recut-check",
        "investigation-conformance-check", "fuzz-tooling-check", "test",
    ):
        if ["just", required] not in check:
            raise ValueError(f"just check is missing {required}")
    for flag in ("--all-targets", "--doc"):
        if not any(
            line[:2] == ["cargo", "test"] and {flag, "--workspace", "--locked"} <= set(line)
            for line in test
        ):
            raise ValueError(f"just test is missing the workspace {flag} suite")
    if ["just", "oracle-guide-example-check"] not in test:
        raise ValueError("just test is missing oracle-guide-example-check")
    for name, arguments in QUALIFICATION_ARGUMENTS.items():
        recipe = recipes.get(name, {})
        if [parameter["name"] for parameter in recipe.get("parameters", [])] != arguments:
            raise ValueError(f"unexpected parameters for {name}")
        if not recipe.get("body") and not recipe.get("dependencies"):
            raise ValueError(f"missing runner {name}")
        if any(line[:2] == ["just", name] for line in check + test):
            raise ValueError(f"native runner {name} is in the fast suite")
    if not any(
        shlex.split(line[0])[-4:] == ["$1", "$3", "--recovery-teapot", "$2"]
        and "scripts/m1-qualification.py" in line[0]
        for line in recipes["m1-qualification-check"]["body"]
    ):
        raise ValueError("m1-qualification-check must supply distinct instrument arguments")
    for name, children in QUALIFICATION_SUBRECIPES.items():
        actual = [dependency["recipe"] for dependency in recipes[name]["dependencies"]]
        if actual != children or any(not recipes[child]["body"] for child in children):
            raise ValueError(f"{name} must run every native subcommand")


def table_keys(text, heading):
    section = text.split(f"## {heading}\n", 1)[1].split("\n## ", 1)[0]
    return [
        key.strip()
        for row in re.findall(r"^\| ([^|]+) \| (?!-)", section, re.M)[1:]
        for key in row.split(",")
    ]


def validate_inventory(disposition, inventory):
    for heading in ("Proof obligations", "Invariants", "Fixtures"):
        expected = Counter(table_keys(disposition, heading))
        actual = Counter(table_keys(inventory, f"Retained {heading.lower()}"))
        if actual != expected:
            missing = ", ".join((expected - actual).elements())
            extra = ", ".join((actual - expected).elements())
            raise ValueError(f"{heading} inventory differs. Missing [{missing}]. Extra [{extra}].")


class GateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        dumped = subprocess.check_output(
            ["just", "--dump", "--dump-format", "json"], cwd=ROOT, text=True
        )
        cls.recipes = json.loads(dumped)["recipes"]
        cls.disposition = (ROOT / "docs/adr/baseline-taxonomy-decision.md").read_text()
        cls.inventory = DOC.read_text()
        spec = importlib.util.spec_from_file_location("m1_qualification", SCRIPT)
        cls.qualification = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.qualification)

    def test_registered_routes_and_missing_guide_gate(self):
        validate_registration(self.recipes)
        changed = copy.deepcopy(self.recipes)
        changed["test"]["body"].remove(["just oracle-guide-example-check"])
        with self.assertRaisesRegex(ValueError, "missing oracle-guide-example-check"):
            validate_registration(changed)

    def test_documented_coverage_and_missing_retained_case(self):
        validate_inventory(self.disposition, self.inventory)
        with self.assertRaisesRegex(ValueError, "Missing \\[F-42\\]"):
            validate_inventory(self.disposition, self.inventory.replace(", F-42 |", " |"))

    def test_shell_example_rejects_stale_argv(self):
        subprocess.run(["bash", GUIDE_CHECK, EXAMPLE], cwd=ROOT, check=True)
        source = EXAMPLE.read_text()
        for old, new in (("--depth full", "--depth summary"), (
            'verify "$lead_id" --plan', 'verify "$lead_id" --preview',
        )):
            with self.subTest(old=old), tempfile.TemporaryDirectory() as directory:
                changed = Path(directory) / "example.sh"
                self.assertIn(old, source)
                changed.write_text(source.replace(old, new))
                result = subprocess.run(
                    ["bash", GUIDE_CHECK, changed], cwd=ROOT, capture_output=True, text=True
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("unexpected argv", result.stderr)

    def test_unavailable_and_wrong_binaries_stop_before_any_lane(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing"
            result = subprocess.run(
                [sys.executable, "-B", SCRIPT, sys.executable, missing,
                 "--recovery-teapot", sys.executable],
                cwd=ROOT, capture_output=True, text=True,
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertIn("no lane was run", result.stderr)
        self.assertRegex(result.stderr, r"oracle Teapot .*expected")
        self.assertRegex(result.stderr, r"request-reference Teapot .*expected")
        self.assertRegex(result.stderr, r"Investigation .*missing")

    def test_admitted_snapshots_execute_the_original_bytes_after_source_replacement(self):
        qualification = self.qualification
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            contracts = root / "contracts"
            (contracts / "evidence").mkdir(parents=True)
            snapshots = root / "snapshots"
            snapshots.mkdir(mode=0o700)
            expected = (
                ("oracle Teapot", "manifest.json", None),
                ("Investigation", "evidence/investigation-conformance.json", "investigation"),
                ("request-reference Teapot", "request-reference-manifest.json", None),
            )
            paths = []
            for index, (role, name, key) in enumerate(expected):
                source = root / f"instrument {index}"
                source.write_text(f"#!/bin/sh\nprintf '%s\\n' '{role}'\n")
                source.chmod(0o700)
                paths.append(source)
                authority = {
                    "binary_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                    "source_commit": "synthetic-source",
                }
                (contracts / name).write_text(json.dumps({key: authority} if key else authority))
            with (
                mock.patch.object(qualification, "CONTRACTS", contracts),
                mock.patch.object(qualification.shutil, "which", return_value="/available"),
            ):
                admitted = qualification.preflight(*paths, snapshots)
            for source, (role, _, _) in zip(paths, expected):
                # Give the same input pathname a different inode after admission.
                replacement = source.with_suffix(".new")
                replacement.write_text("#!/bin/sh\nexit 23\n")
                replacement.chmod(0o700)
                replacement.replace(source)
                self.assertEqual(subprocess.run([source], check=False).returncode, 23)
                snapshot = admitted[role]
                self.assertEqual(stat.S_IMODE(snapshot.stat().st_mode), 0o500)
                self.assertEqual(stat.S_IMODE(snapshot.parent.stat().st_mode), 0o700)
                self.assertEqual(subprocess.check_output([snapshot], text=True), f"{role}\n")

    def test_admission_refuses_nonexecutable_and_nonregular_sources(self):
        qualification = self.qualification
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "without-execute"
            source.write_bytes(b"body")
            source.chmod(0o600)
            for path in (source, root):
                with self.subTest(path=path.name):
                    with self.assertRaisesRegex(ValueError, "executable regular file"):
                        qualification.admit_binary(path, {}, root / "snapshot")

    def witnessed_lane(self, stdout, expected=(), marker=None):
        output = io.StringIO()
        argv = [sys.executable, "-c", "import sys; print(sys.argv[1])", "\n".join(stdout)]
        with redirect_stdout(output), redirect_stderr(output):
            success = self.qualification.run_lane("witness", argv, {}, expected, marker)
        return success, output.getvalue()

    def test_libtest_requires_full_summary_and_exact_passing_test_ids(self):
        summary = "test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 3 filtered out; finished in 0.01s"
        first, second = "test suite::one ... ok", "test suite::two ... ok"
        expected = ("suite::one", "suite::two")
        self.assertTrue(self.witnessed_lane([second, first, summary], expected)[0])
        for description, stdout, diagnostic in (
            ("missing", [first, second], "expected 1 test summaries"),
            ("extra", [first, second, summary, "test result: MALFORMED"], "saw 2"),
            ("malformed suffix", [first, second, summary + " malformed"], "no failures or skips"),
            ("malformed missing fields", [first, second, summary.split("0 measured;")[0]], "no failures or skips"),
            ("lower count", [first, second, summary.replace("2 passed", "1 passed")], "no failures or skips"),
            ("ignored", [first, second, summary.replace("0 ignored", "1 ignored")], "no failures or skips"),
            ("nonzero failures", [first, second, summary.replace("0 failed", "1 failed")], "no failures or skips"),
            ("failed status", [first, second, summary.replace("ok.", "FAILED.")], "no failures or skips"),
            ("wrong name with enough passes", [first, "test suite::other ... ok", summary], "expected passing tests"),
            ("required test filtered out", [first, summary], "expected passing tests"),
            ("invalid case result", [first, second.replace("ok", "ignored"), summary], "expected passing tests"),
            ("malformed extra row", [first, second, "  test extra ...MALFORMED", summary], "expected passing tests"),
            ("test follows summary", [first, summary, second], "expected passing tests"),
        ):
            with self.subTest(description=description):
                success, output = self.witnessed_lane(stdout, expected)
                self.assertFalse(success)
                self.assertIn(diagnostic, output)

    def test_custom_read_requires_one_exact_marker_without_a_libtest_summary(self):
        marker = self.qualification.READ_PROJECTION
        _, receipt = marker
        self.assertTrue(self.witnessed_lane([receipt], marker=marker)[0])
        for description, stdout in (
            ("empty", []),
            ("duplicate", [receipt, receipt]),
            ("malformed", [receipt + " unexpected suffix"]),
            ("malformed duplicate", [receipt, receipt + " unexpected suffix"]),
            ("unexpected summary", [receipt, "test result: MALFORMED"]),
        ):
            with self.subTest(description=description):
                self.assertFalse(self.witnessed_lane(stdout, marker=marker)[0])

    def test_actual_non_libtest_lanes_refuse_a_noop_and_require_exact_terminal_evidence(self):
        qualification = self.qualification
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            admitted = {
                "oracle Teapot": root / "oracle",
                "request-reference Teapot": root / "reference",
                "Investigation": root / "investigation",
            }
            with (
                mock.patch.object(qualification, "run_lane", return_value=True) as planned,
                redirect_stdout(io.StringIO()),
            ):
                self.assertTrue(qualification.qualify(admitted, root))
        expected_lanes = {
            "Teapot capture contract", "Investigation public interface",
            "Investigation read projection", "packaged fixture", "first oracle",
        }
        observed = {call.args[0]: call.args for call in planned.call_args_list}
        self.assertEqual({name for name, lane in observed.items() if not lane[3]}, expected_lanes)
        for name in sorted(expected_lanes):
            with self.subTest(lane=name):
                _, _, _, tests, marker = observed[name]
                output = io.StringIO()
                with redirect_stdout(output), redirect_stderr(output):
                    self.assertFalse(qualification.run_lane(name, ("/bin/true",), {}, tests, marker))
                self.assertIn("expected exactly one terminal", output.getvalue())
                prefix, receipt = marker
                self.assertTrue(self.witnessed_lane([receipt], marker=marker)[0])
                for bad in (
                    [prefix],
                    [receipt + " malformed"],
                    [receipt, receipt],
                    [prefix + " malformed", receipt],
                    [receipt, "unexpected trailing output"],
                ):
                    self.assertFalse(self.witnessed_lane(bad, marker=marker)[0])

    def test_investigation_receipt_requires_all_frozen_cases_to_pass(self):
        fixture = ROOT / "fixtures/contracts/evidence"
        with mock.patch.object(sys, "path", [str(fixture), *sys.path]):
            wrapper = runpy.run_path(str(fixture / "check-live.py"))
        qualify = wrapper["qualify"]
        receipt = wrapper["SUCCESS"]
        expected = json.loads((fixture / "investigation-conformance.json").read_text())["result"]["cases"]

        def pass_case(_):
            pass

        def fail_case(case):
            case.fail("synthetic failure")

        def error_case(_):
            raise RuntimeError("synthetic error")

        for replacement, wanted in (
            (pass_case, 0),
            (unittest.skip("synthetic skip")(pass_case), 1),
            (fail_case, 1),
            (error_case, 1),
            (unittest.expectedFailure(fail_case), 1),
        ):
            with self.subTest(case=replacement):
                cases = dict.fromkeys(expected, pass_case)
                cases[expected[0]] = replacement
                output = io.StringIO()
                with redirect_stdout(output), redirect_stderr(output):
                    self.assertEqual(qualify(type("Cases", (unittest.TestCase,), cases), expected), wanted)
                self.assertEqual(output.getvalue().splitlines().count(receipt), int(wanted == 0))
        output = io.StringIO()
        incomplete = type("Incomplete", (unittest.TestCase,), dict.fromkeys(expected[1:], pass_case))
        with redirect_stdout(output), redirect_stderr(output):
            self.assertEqual(qualify(incomplete, expected), 1)
        self.assertNotIn(receipt, output.getvalue())


if __name__ == "__main__":
    unittest.main()
