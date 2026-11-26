#!/usr/bin/env python3
"""Run the native M1 checks only after admitting every required instrument."""

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = ROOT / "fixtures/contracts"
TEST_SUMMARY = re.compile(
    r"test result: ok\. ([0-9]+) passed; 0 failed; 0 ignored; 0 measured;"
    r" [0-9]+ filtered out; finished in [0-9]+\.[0-9]{2}s"
)
TEST_PASS = re.compile(r"test (\S+) \.\.\. ok")
TEAPOT_CAPTURE = ("checked", "checked 37 contracts")
INVESTIGATION_PUBLIC = (
    "Investigation public-interface:",
    "Investigation public-interface: 12 passed, 0 failed, 0 skipped",
)
READ_PROJECTION = (
    "qualified Investigation read projection",
    "qualified Investigation read projection passed",
)
PACKAGED_FIXTURE = (
    "Validated",
    "Validated 12 resource classes, identity probes, the referee catalog and the external package",
)
FIRST_ORACLE = (
    "{",
    '{"external_target_requests":0,"failed":0,"passed":25,"schema":"scourge.oracle-fixture-qualification.v1"}',
)


def admit_binary(path, authority, snapshot):
    # Open once. O_NONBLOCK lets the type check refuse a FIFO without waiting
    # on a writer. The descriptor also gives us the mode of the bytes we read.
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        mode = os.fstat(fd).st_mode
        if not stat.S_ISREG(mode) or not mode & 0o111:
            raise ValueError(f"{path} must be an executable regular file")
        snapshot.parent.mkdir(mode=0o700)
        digest = hashlib.sha256()
        with snapshot.open("xb") as target:
            while chunk := os.read(fd, 1024 * 1024):
                target.write(chunk)
                digest.update(chunk)
            actual = digest.hexdigest()
            if actual != authority["binary_sha256"]:
                raise ValueError(
                    f"{path} has SHA-256 {actual}, expected {authority['binary_sha256']}"
                    f" for source {authority['source_commit']}"
                )
            target.flush()
            os.fchmod(target.fileno(), 0o500)
            os.fsync(target.fileno())
    finally:
        os.close(fd)
    return snapshot


def preflight(teapot, investigation, recovery, root):
    errors = []
    if platform.system() != "Linux":
        errors.append("native M1 qualification requires Linux")
    for tool in ("cargo", "just"):
        if shutil.which(tool) is None:
            errors.append(f"missing {tool}")
    # The end-to-end demo tests intentionally use a clean, fixed PATH.
    if recovery is not None and shutil.which("jq", path="/usr/bin:/bin") is None:
        errors.append("missing jq in /usr/bin:/bin for demo-check")
    inputs = {
        "oracle Teapot": (teapot, "manifest.json", None, "oracle/teapot"),
        "Investigation": (
            investigation, "evidence/investigation-conformance.json", "investigation",
            "evidence/investigation",
        ),
    }
    if recovery is not None:
        inputs["request-reference Teapot"] = (
            recovery, "request-reference-manifest.json", None, "reference/teapot"
        )
    admitted = {}
    for role, (path, manifest, key, destination) in inputs.items():
        try:
            authority = json.loads((CONTRACTS / manifest).read_text())
            if key is not None:
                authority = authority[key]
            admitted[role] = admit_binary(path, authority, root / destination)
        except (KeyError, OSError, RuntimeError, ValueError) as error:
            errors.append(f"{role} ({manifest}): {error}")
    if errors:
        raise ValueError("\n".join(errors))
    return admitted


def run_lane(name, argv, env, expected_tests=(), required_marker=None):
    if bool(expected_tests) == (required_marker is not None):
        print(f"M1 {name}: specify one type of pass evidence", file=sys.stderr, flush=True)
        return False
    print(f"M1 {name}: running", flush=True)
    summaries = []
    test_rows = []
    markers = []
    last_line = None
    try:
        with subprocess.Popen(
            argv, cwd=ROOT, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        ) as process:
            for line in process.stdout:
                print(line, end="", flush=True)
                line = line.removesuffix("\n")
                content = line.lstrip()
                if content:
                    last_line = line
                if content.startswith("test result:"):
                    summaries.append(line)
                elif content.startswith("test "):
                    test_rows.append(None if summaries else TEST_PASS.fullmatch(line))
                if required_marker is not None and content.startswith(required_marker[0]):
                    markers.append(line)
            exit_code = process.wait()
    except OSError as error:
        print(f"M1 {name}: failed to launch: {error}", file=sys.stderr, flush=True)
        return False
    if exit_code:
        print(f"M1 {name}: failed (exit {exit_code})", file=sys.stderr, flush=True)
        return False
    expected_summaries = int(bool(expected_tests))
    if len(summaries) != expected_summaries:
        print(f"M1 {name}: expected {expected_summaries} test summaries, saw {len(summaries)}",
              file=sys.stderr, flush=True)
        return False
    if expected_tests:
        summary = TEST_SUMMARY.fullmatch(summaries[0])
        if summary is None or summary[1] != str(len(expected_tests)):
            print(f"M1 {name}: expected {len(expected_tests)} passes with no failures or skips, "
                  f"saw {summaries[0]!r}", file=sys.stderr, flush=True)
            return False
    passes = [row[1] for row in test_rows if row is not None]
    if len(passes) != len(test_rows) or sorted(passes) != sorted(expected_tests):
        print(f"M1 {name}: expected passing tests {expected_tests!r}, saw {passes!r}",
              file=sys.stderr, flush=True)
        return False
    if required_marker is not None:
        _, expected_line = required_marker
        if markers != [expected_line] or last_line != expected_line:
            print(f"M1 {name}: expected exactly one terminal {expected_line!r} marker, "
                  f"saw {markers!r} and last line {last_line!r}", file=sys.stderr, flush=True)
            return False
    print(f"M1 {name}: passed", flush=True)
    return True


def qualify(admitted, root):
    teapot = admitted["oracle Teapot"]
    investigation = admitted["Investigation"]
    recovery = admitted.get("request-reference Teapot")
    env = {
        **os.environ,
        "CARGO_NET_OFFLINE": "true",
        "RUST_TEST_THREADS": "1",
        "SCOURGE_INVESTIGATION_BIN": str(investigation),
        "SCOURGE_PINNED_TEAPOT": str(teapot),
    }
    # The existing Teapot capture checker uses Python assertions.
    env.pop("PYTHONOPTIMIZE", None)
    # Keep libtest's case rows intact even if the invoking shell requests live output.
    env.pop("RUST_TEST_NOCAPTURE", None)
    python = (sys.executable, "-B")
    cargo = ("cargo", "test", "--offline", "--locked", "-p", "scourge-core")
    invocation = (*cargo, "--test", "teapot_invocation")
    live_preflight = "pinned_live_preflight_refusal_and_success_never_reach_connected_target"
    # The historical capture driver may consult Teapot's user directories.
    # Keep that replay isolated and its Unix socket path short.
    runtime = root / "r"
    runtime.mkdir(mode=0o700)
    capture_env = {
        **env,
        "HOME": str(root),
        "XDG_CONFIG_HOME": str(root / "config"),
        "XDG_CACHE_HOME": str(root / "cache"),
        "XDG_DATA_HOME": str(root / "data"),
        "XDG_STATE_HOME": str(root / "state"),
        "XDG_RUNTIME_DIR": str(runtime),
    }
    lanes = [
        (
            "Teapot capture contract",
            (*python, "scripts/teapot-contracts.py", "--binary", teapot),
            capture_env,
            (),
            TEAPOT_CAPTURE,
        ),
        (
            "Teapot native adapter",
            (*invocation, "--", "--ignored", "--skip", live_preflight),
            env,
            (
                "pinned_accounting_reads_leave_target_jobs_flows_and_existing_ledger_unchanged",
                "pinned_follow_until_and_literal_at_values_match_the_frozen_replies",
                "pinned_send_macro_replay_and_capture_off_match_the_frozen_variants",
                "pinned_teapot_exercises_each_operation",
                "pinned_verifier_gate_refuses_before_target_traffic",
            ),
        ),
        (
            "Investigation public interface",
            (*python, "fixtures/contracts/evidence/check-live.py"),
            env,
            (),
            INVESTIGATION_PUBLIC,
        ),
        (
            "Investigation native capture",
            ("just", "_evidence-capture-check"),
            env,
            (
                "capture_read_and_retry_are_bound_to_one_immutable_artifact",
                "checkpoint_tracks_evidence_changes_and_is_stable_without_writes",
                "derivatives_preserve_ordered_lineage_and_strict_structured_input",
                "killed_producer_recovers_only_acknowledged_prefix",
                "refuses_unqualified_executable_before_creating_workspace",
                "withdrawal_beyond_native_lineage_scan_refuses_every_use",
                "withdrawal_refuses_direct_and_inherited_evidentiary_use",
            ),
        ),
        (
            "Investigation native publication",
            ("just", "_evidence-publication-check"),
            env,
            (
                "verification::record::tests::legacy_checkpoint_rebuild_refuses_even_with_qualified_investigation_receipt",
                "verification::record::tests::qualified_verifier_publishes_from_a_sealed_acquisition_and_exact_readback",
                "verification::record::tests::recovers_a_historical_cleanup_original_from_the_exact_run_capture",
                "verification::record::tests::verified_pending_intent_is_bound_to_its_case_and_private_receipt",
            ),
        ),
        ("Investigation read projection", ("just", "_evidence-read-check"), env, (), READ_PROJECTION),
    ]
    if recovery is not None:
        round_transport = "rounds::tests::pinned_development_fixture_cross_user_round_reads_and_digests_every_flow"
        lanes += [
            (
                "request-reference preflight",
                (*invocation, live_preflight, "--", "--ignored", "--exact"),
                {**env, "SCOURGE_PINNED_TEAPOT": str(recovery)},
                (live_preflight,),
            ),
            ("packaged fixture", ("just", "fixture-check"), env, (), PACKAGED_FIXTURE),
            (
                "first oracle round transport",
                (*cargo, "--lib", "--", round_transport, "--exact", "--ignored"),
                env,
                (round_transport,),
            ),
            (
                "first oracle", ("just", "oracle-fixture-check", teapot, investigation),
                env, (), FIRST_ORACLE,
            ),
            (
                "lost-response recovery",
                ("just", "_recovery-native-check", recovery, investigation),
                env,
                ("recovery::qualified_lost_response_recovery_on_owned_loopback",),
            ),
            (
                "recovery dispatch classification",
                ("just", "_recovery-dispatch-check"),
                env,
                ("rounds::tests::sent_without_flow_is_unknown_while_typed_refusal_is_no_effect",),
            ),
            (
                "demo and guide",
                ("just", "_demo-process-check", teapot, investigation),
                env,
                (
                    "committed_config_loss_stops_fixture_and_uses_private_fallback_control",
                    "demo_help_usage_and_workspace_collision_are_inert",
                    "demo_refuses_unqualified_executable_without_creating_state_or_executing_it",
                    "qualified_demo_follows_generated_argv_and_stops_owned_fixture",
                    "readme_tutorial_runs_in_a_fresh_directory",
                ),
            ),
            (
                "demo orphan recovery",
                ("just", "_demo-orphan-check"),
                env,
                ("workspace::demo::tests::sigkill_orphan_helper_writes_only_into_the_receipted_abandoned_attempt",),
            ),
        ]
    outcomes = [run_lane(*lane) for lane in lanes]
    passed = sum(outcomes)
    print(f"M1 qualification: {passed} passed, {len(outcomes) - passed} failed")
    return all(outcomes)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("oracle_teapot", type=Path)
    parser.add_argument("investigation", type=Path)
    parser.add_argument("--recovery-teapot", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="sg-m1-", dir="/tmp") as directory:
        root = Path(directory)
        try:
            root.chmod(0o700)
            admitted = preflight(args.oracle_teapot, args.investigation, args.recovery_teapot, root)
        except (OSError, ValueError) as error:
            print(f"M1 qualification unavailable; no lane was run\n{error}", file=sys.stderr)
            return 1
        print("M1 preflight passed for " + ", ".join(admitted), flush=True)
        if args.recovery_teapot is None:
            print("M1 scope: instrument contracts; full fixture qualification uses m1-qualification-check")
        return 0 if qualify(admitted, root) else 1


if __name__ == "__main__":
    sys.exit(main())
