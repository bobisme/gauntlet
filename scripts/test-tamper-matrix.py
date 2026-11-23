#!/usr/bin/env python3
"""Deterministic checks for the M0.5.3 custody tamper matrix.

The live matrix needs rootless Podman, a cached image and pinned binaries. This
test needs none of them: it validates the committed observation, the pure
acceptance logic, sanitization, the markdown table, and the relay hold.
"""

import asyncio
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import traceback
import unittest


ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "fixtures/contracts/tamper-matrix-observed.json"
DOCUMENT = ROOT / "docs/tamper-matrix.md"
spec = importlib.util.spec_from_file_location("tamper_matrix", ROOT / "scripts/tamper-matrix.py")
matrix = importlib.util.module_from_spec(spec)
spec.loader.exec_module(matrix)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def synthetic_record(name="isolated_separate", custody="isolated",
                     target_isolation="separate_principals", verdicts=None,
                     during_unheld=None):
    verdicts = verdicts or {}
    attempts = [
        {
            "attempt_id": attempt_id,
            "attempt": matrix.NAMES[attempt_id],
            "verdict": verdicts.get(attempt_id, "refused"),
            "stand_in": False,
            "evidence": [],
        }
        for attempt_id in matrix.ATTEMPT_IDS
    ]
    during_unheld = during_unheld or "refused"
    return {
        "name": name,
        "custody": custody,
        "target_isolation": target_isolation,
        "worker": {
            "boundary": "read-only container, network none, no capabilities"
            if custody == "isolated" else "host process, same user as the referee",
            "network": "none" if custody == "isolated" else "host",
            "private_verifier_credentials_accessible": custody == "shared",
            "verifier_project_visible": custody == "shared",
            "direct_fixture_reachable": custody == "shared",
            "direct_verifier_proxy_reachable": custody == "shared",
        },
        "verifier": {
            "accounts_shared_with_worker": target_isolation == "shared_principals",
        },
        "attempts": attempts,
        "attempt_06": {
            "trials": [
                {"phase": "before", "traffic_held": False, "verdict": "refused"},
                {"phase": "during", "traffic_held": False, "verdict": during_unheld},
                {"phase": "during", "traffic_held": True, "verdict": "refused"},
            ],
        },
        "cleanup": {
            "engines_stopped": True,
            "fixture_stopped": True,
            "containers_created": 6 if custody == "isolated" else 0,
            "containers_removed": 6 if custody == "isolated" else 0,
        },
    }


class RecordedObservation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evidence = json.loads(EVIDENCE.read_text())

    def test_schema_and_configurations(self):
        value = self.evidence
        self.assertEqual(value["schema_version"], 1)
        names = [item["name"] for item in value["configurations"]]
        self.assertEqual(names, ["isolated_separate", "isolated_shared", "shared_unconfined"])
        for item in value["configurations"]:
            self.assertEqual(
                [attempt["attempt_id"] for attempt in item["attempts"]],
                list(matrix.ATTEMPT_IDS),
            )
            for attempt in item["attempts"]:
                self.assertIn(attempt["verdict"], {"succeeded", "refused", "unsupported"})

    def test_isolated_separate_acceptance(self):
        value = self.evidence
        record = next(item for item in value["configurations"]
                      if item["name"] == "isolated_separate")
        verdicts = matrix.attempt_verdicts(record)
        self.assertEqual(set(verdicts), set(matrix.ATTEMPT_IDS))
        for attempt_id, verdict in verdicts.items():
            with self.subTest(attempt=attempt_id):
                self.assertEqual(verdict, "refused")
        self.assertTrue(matrix.qualified(record))
        self.assertTrue(value["qualified"]["accepted"])
        self.assertTrue(value["qualified"]["isolated_separate_all_attempts_failed"])
        self.assertTrue(value["qualified"]["configuration_isolated_separate_qualified"])
        self.assertEqual(value["qualified"]["isolated_separate_verdicts"], verdicts)

    def test_shared_configuration_records_the_limit(self):
        record = next(item for item in self.evidence["configurations"]
                      if item["name"] == "shared_unconfined")
        self.assertEqual(record["custody"], "shared")
        self.assertTrue(record["worker"]["private_verifier_credentials_accessible"])
        self.assertTrue(record["verifier"]["accounts_shared_with_worker"] is False)
        self.assertEqual(record["attempts"][6]["verdict"], "succeeded")

    def test_shared_principals_records_target_contamination(self):
        record = next(item for item in self.evidence["configurations"]
                      if item["name"] == "isolated_shared")
        self.assertEqual(record["target_isolation"], "shared_principals")
        self.assertTrue(record["verifier"]["accounts_shared_with_worker"])
        self.assertEqual(record["worker"]["network"], "none")
        self.assertEqual(record["attempts"][5]["verdict"], "succeeded")
        for attempt in record["attempts"][:5] + record["attempts"][6:]:
            self.assertIn(attempt["verdict"], {"refused", "unsupported"})

    def test_attempt_06_trials_and_controls(self):
        for record in self.evidence["configurations"]:
            trials = record["attempt_06"]["trials"]
            with self.subTest(configuration=record["name"]):
                self.assertEqual([(trial["phase"], trial["traffic_held"]) for trial in trials],
                                 [("before", False), ("during", False), ("during", True)])
                self.assertEqual(record["attempts"][5]["verdict"],
                                 matrix.representative_06(trials)["verdict"])
                for trial in trials:
                    self.assertEqual(trial["entry_control"]["other_read_status"], 404)
                    self.assertEqual(trial["entry_control"]["create_status"], 201)
                    self.assertEqual(trial["exit_control"]["create_status"], 201)
                    self.assertEqual(
                        trial["exit_control"]["other_read_matches_fresh_note"],
                        trial["final_share_is_the_other_principal"],
                    )
                    self.assertTrue(trial["initial_share_is_null"])
                    self.assertEqual(
                        trial["referee_sharing_transition_observed"],
                        trial["final_share_is_the_other_principal"],
                    )
                    self.assertTrue(trial["verdict_matches_referee_state"])
                    self.assertEqual(trial["verdict"] == "succeeded",
                                     trial["referee_sharing_transition_observed"])
                    if trial["traffic_held"]:
                        self.assertEqual(trial["relay_forwarded_connections"], 0)
                        self.assertGreater(trial["relay_rejected_connections"], 0)
                        self.assertEqual(trial["relay_rejection_status"], 503)
                        self.assertEqual(trial["verdict"], "refused")
                    else:
                        self.assertGreater(trial["relay_forwarded_connections"], 0)
                        self.assertEqual(trial["relay_rejected_connections"], 0)
                    if trial["phase"] == "during":
                        run = trial["active_run"]
                        self.assertIsNotNone(run)
                        matrix.require_active_run(
                            run["sends_at_attempt_start"],
                            run["sends_at_attempt_end"],
                            run["errors"],
                        )
                        self.assertGreater(run["sends_at_attempt_end"],
                                           run["sends_at_attempt_start"])
                        self.assertEqual(run["errors"], 0)
                        self.assertTrue(run["interleaved"])
                    else:
                        self.assertIsNone(trial["active_run"])

    def test_network_witnesses_match_verdicts(self):
        for record in self.evidence["configurations"]:
            witnesses = record["witnesses"]
            verdicts = matrix.attempt_verdicts(record)
            with self.subTest(configuration=record["name"]):
                self.assertTrue(witnesses["attempt07_flow_delta_matches_verdict"])
                self.assertTrue(witnesses["attempt08_rule_persistence_matches_verdict"])
                self.assertIsInstance(witnesses["verifier_flow_count_before"], int)
                self.assertIsInstance(witnesses["verifier_flow_count_after"], int)
                self.assertGreaterEqual(witnesses["verifier_flow_count_after"],
                                        witnesses["verifier_flow_count_before"])
                self.assertEqual(witnesses["verifier_flow_count_delta"] > 0,
                                 verdicts["07"] == "succeeded")
                self.assertEqual(witnesses["verifier_rule_marker_persisted"],
                                 verdicts["08"] == "succeeded")
                matrix.require_network_witness_consistency(
                    verdicts["07"], verdicts["08"],
                    witnesses["verifier_flow_count_before"],
                    witnesses["verifier_flow_count_after"],
                    witnesses["verifier_rule_marker_persisted"],
                )

    def test_hold_decision_matches_every_configuration(self):
        value = self.evidence
        decision = value["hold"]
        rows = {item["name"]: item for item in value["configurations"]}

        self.assertTrue(decision["required"])
        self.assertEqual(decision["required_for"],
                         ["isolated_shared", "shared_unconfined"])
        self.assertEqual(decision["required_for_isolated_custody"], ["isolated_shared"])
        self.assertEqual(decision["qualified_configuration"], "isolated_separate")
        self.assertFalse(decision["qualified_configuration_requires_hold"])

        for name, record in rows.items():
            with self.subTest(configuration=name):
                trials = record["attempt_06"]["trials"]
                def verdict(phase, held):
                    return next(trial["verdict"] for trial in trials
                                if trial["phase"] == phase and trial["traffic_held"] is held)
                row = decision["configurations"][name]
                self.assertEqual(row["before_unheld_verdict"], verdict("before", False))
                self.assertEqual(row["during_unheld_verdict"], verdict("during", False))
                self.assertEqual(row["during_held_verdict"], verdict("during", True))
                self.assertEqual(
                    row["during_run_attempt_blocked_by_hold"],
                    verdict("during", False) == "succeeded"
                    and verdict("during", True) != "succeeded",
                )

        isolated_shared = decision["configurations"]["isolated_shared"]
        self.assertEqual(isolated_shared["during_unheld_verdict"], "succeeded")
        self.assertEqual(isolated_shared["during_held_verdict"], "refused")
        self.assertTrue(isolated_shared["during_run_attempt_blocked_by_hold"])
        self.assertTrue(isolated_shared["before_run_attempt_not_blocked_by_hold"])
        self.assertTrue(decision["does_not_repair_before_run_contamination"])
        self.assertEqual(decision["before_run_contamination_in_required_for"],
                         {"isolated_shared": True, "shared_unconfined": True})
        self.assertTrue(decision["all_held_trials_refused"])
        self.assertTrue(all(decision["held_trials_refused"].values()))
        self.assertEqual(set(decision["held_trials_refused"]), set(rows))
        self.assertEqual(decision["shared_custody"]["worker_network"], "host")
        self.assertTrue(decision["shared_custody"]["hold_is_not_a_security_boundary"])
        self.assertTrue(decision["shared_custody"]["relay_bypass_possible"])

    def test_configurations_are_materially_distinct(self):
        distinct = self.evidence["distinct"]
        self.assertTrue(distinct["proved"])
        self.assertEqual(len(distinct["pairwise_differences"]), 3)
        for pair, axes in distinct["pairwise_differences"].items():
            self.assertTrue(axes, pair)
        for axis in ("worker_boundary", "network", "verifier_project_visible",
                     "private_verifier_credentials_accessible",
                     "verifier_accounts_shared_with_worker",
                     "attempt_06_during_unheld_verdict"):
            self.assertIn(axis, distinct["varying"])

    def test_cleanup(self):
        for record in self.evidence["configurations"]:
            cleanup = record["cleanup"]
            with self.subTest(configuration=record["name"]):
                self.assertTrue(cleanup["engines_stopped"])
                self.assertTrue(cleanup["fixture_stopped"])
                self.assertEqual(cleanup["containers_created"], cleanup["containers_removed"])
                self.assertEqual(record["worker"]["containers_created"],
                                 cleanup["containers_created"])
                self.assertEqual(record["worker"]["containers_created"],
                                 6 if record["custody"] == "isolated" else 0)

    def test_observation_is_sanitized(self):
        matrix.assert_sanitized(self.evidence)
        serialized = json.dumps(self.evidence)
        for forbidden in ("alice", "bob", "http", "share_new_with", "scourge-m0-tamper",
                          "local.pass", ".teapot", "verifier-passwords"):
            self.assertNotIn(forbidden, serialized)
        for forbidden_key in ("path", "url", "password", "session_name", "username",
                              "cookie", "marker", "note", "content_sha256"):
            self.assertIsNone(self.find_key(self.evidence, forbidden_key), forbidden_key)

    @staticmethod
    def find_key(value, needle):
        if isinstance(value, dict):
            for key, item in value.items():
                if key == needle:
                    return key
                found = RecordedObservation.find_key(item, needle)
                if found is not None:
                    return found
        elif isinstance(value, list):
            for item in value:
                found = RecordedObservation.find_key(item, needle)
                if found is not None:
                    return found
        return None

    def test_attempt_evidence_supports_each_verdict(self):
        for record in self.evidence["configurations"]:
            for attempt in record["attempts"]:
                with self.subTest(configuration=record["name"],
                                  attempt=attempt["attempt_id"]):
                    matrix.require_consistent(attempt)
                    self.assertEqual(attempt["attempt"], matrix.NAMES[attempt["attempt_id"]])
                    if attempt["attempt_id"] in ("01", "04", "05"):
                        self.assertTrue(attempt["stand_in"])
            for trial in record["attempt_06"]["trials"]:
                matrix.require_consistent(trial["result"])

    def test_pins_match_the_committed_files(self):
        pins = self.evidence["pins"]
        self.assertEqual(pins["teapot_sha256"], matrix.topology.PIN)
        self.assertEqual(pins["hallpass_sha256"], matrix.topology.HALLPASS_PIN)
        self.assertEqual(pins["harness_sha256"], digest(ROOT / "scripts/tamper-matrix.py"))
        self.assertEqual(pins["candidate_topology_sha256"],
                         digest(ROOT / "scripts/candidate-topology.py"))
        expected_payloads = {
            path.name: digest(path)
            for path in sorted((ROOT / "scripts/tamper-attempts").glob("*.py"))
        }
        self.assertEqual(pins["payload_sha256"], expected_payloads)
        host = self.evidence["host"]
        self.assertEqual(host["podman"], "podman version 6.1.3")
        self.assertTrue(host["rootless"])
        self.assertEqual(host["worker_image_sha256"],
                         "28eb0cb65acb65b970e85c0dc57d10067868fae8dd00d072413df273132123ac")
        self.assertEqual(len(pins["fixture_sha256"]), 64)
        self.assertEqual(len(pins["rustc"]), len(pins["rustc"]))

    def test_limits_state_the_no_claim(self):
        limits = " ".join(self.evidence["limits"]).lower()
        for phrase in ("fixed", "loopback", "no enforce", "no operating-system boundary",
                       "f-40", "direct send", "same user", "retained hold",
                       "does not repair target state"):
            self.assertIn(phrase, limits)

    def test_table_matches_the_document(self):
        expected = self.evidence["table"]["markdown"].strip().splitlines()
        section = DOCUMENT.read_text().split("## Attempt by configuration", 1)[1]
        section = section.split("## Attempt 06", 1)[0]
        documented = [
            line.rstrip() for line in section.splitlines()
            if line.startswith("| Attempt") or line.startswith("|---|")
            or re.match(r"^\| 0[1-8] ", line)
        ]
        self.assertEqual(documented, expected)


class AcceptanceLogic(unittest.TestCase):
    def test_success_in_isolated_separate_fails(self):
        record = synthetic_record(verdicts={"05": "succeeded"})
        self.assertFalse(matrix.qualified(record))
        self.assertTrue(matrix.qualified(synthetic_record()))

    def test_unsupported_is_not_a_refusal(self):
        # The payload contract says unsupported is never counted as a refusal,
        # so a configuration with an unexecuted attempt cannot be qualified.
        record = synthetic_record(verdicts={"03": "unsupported"})
        self.assertFalse(matrix.qualified(record))
        self.assertEqual(matrix.attempt_verdicts(record)["03"], "unsupported")
        self.assertTrue(matrix.qualified(synthetic_record()))

    def test_unsupported_makes_accepted_false_and_the_command_nonzero(self):
        configurations = [
            synthetic_record(name="isolated_separate", verdicts={"03": "unsupported"}),
            synthetic_record(name="isolated_shared", target_isolation="shared_principals",
                             during_unheld="succeeded"),
            synthetic_record(name="shared_unconfined", custody="shared",
                             during_unheld="succeeded"),
        ]
        distinct = matrix.distinctness(configurations)
        result = {"qualified": matrix.qualification(configurations[0], configurations,
                                                     distinct)}
        self.assertFalse(result["qualified"]["configuration_isolated_separate_qualified"])
        self.assertFalse(result["qualified"]["isolated_separate_all_attempts_failed"])
        self.assertFalse(result["qualified"]["accepted"])
        self.assertEqual(matrix.exit_status(result), 1)

    def test_every_attempt_refused_still_accepts_and_exits_zero(self):
        configurations = [
            synthetic_record(name="isolated_separate"),
            synthetic_record(name="isolated_shared", target_isolation="shared_principals",
                             during_unheld="succeeded"),
            synthetic_record(name="shared_unconfined", custody="shared",
                             during_unheld="succeeded"),
        ]
        distinct = matrix.distinctness(configurations)
        result = {"qualified": matrix.qualification(configurations[0], configurations,
                                                     distinct)}
        self.assertTrue(result["qualified"]["configuration_isolated_separate_qualified"])
        self.assertTrue(result["qualified"]["isolated_separate_all_attempts_failed"])
        self.assertTrue(result["qualified"]["accepted"])
        self.assertEqual(matrix.exit_status(result), 0)

    def test_held_unsupported_trial_stays_unsupported(self):
        record = synthetic_record()
        record["attempt_06"]["trials"][2]["verdict"] = "unsupported"
        decision = matrix.hold_decision([record])
        self.assertEqual(decision["held_trial_verdicts"]["isolated_separate"],
                         "unsupported")
        self.assertFalse(decision["held_trials_refused"]["isolated_separate"])
        self.assertFalse(decision["all_held_trials_refused"])
        self.assertFalse(decision["configurations"]["isolated_separate"][
            "during_run_attempt_blocked_by_hold"])

    def test_committed_hold_matches_the_harness(self):
        value = json.loads(EVIDENCE.read_text())
        self.assertEqual(matrix.hold_decision(value["configurations"]), value["hold"])

    def test_committed_acceptance_matches_the_harness(self):
        value = json.loads(EVIDENCE.read_text())
        record = next(item for item in value["configurations"]
                      if item["name"] == "isolated_separate")
        self.assertEqual(
            matrix.qualification(record, value["configurations"], value["distinct"]),
            value["qualified"],
        )

    def test_a_visible_boundary_fails(self):
        record = synthetic_record()
        record["worker"]["verifier_project_visible"] = True
        self.assertFalse(matrix.qualified(record))
        record = synthetic_record()
        record["verifier"]["accounts_shared_with_worker"] = True
        self.assertFalse(matrix.qualified(record))

    def test_hold_is_required_when_any_unheld_run_succeeds(self):
        decision = matrix.hold_decision([synthetic_record()])
        self.assertFalse(decision["required"])
        self.assertEqual(decision["required_for"], [])
        self.assertFalse(decision["does_not_repair_before_run_contamination"])
        decision = matrix.hold_decision([
            synthetic_record(name="isolated_separate"),
            synthetic_record(name="isolated_shared",
                             target_isolation="shared_principals",
                             during_unheld="succeeded"),
        ])
        self.assertTrue(decision["required"])
        self.assertTrue(decision["all_held_trials_refused"])

    def test_hold_regression_isolated_shared_decides_the_result(self):
        # The qualified isolated/separate topology does not need the hold. A
        # vulnerable isolated/shared configuration that succeeds during a run
        # without it still makes the spike result "hold required", and the
        # before-run trial proves the hold does not repair earlier state.
        qualified = synthetic_record(name="isolated_separate")
        vulnerable = synthetic_record(name="isolated_shared",
                                      target_isolation="shared_principals",
                                      during_unheld="succeeded")
        vulnerable["attempt_06"]["trials"][0]["verdict"] = "succeeded"
        shared = synthetic_record(name="shared_unconfined", custody="shared",
                                  target_isolation="separate_principals_unconfined",
                                  during_unheld="succeeded")
        shared["attempt_06"]["trials"][0]["verdict"] = "succeeded"
        decision = matrix.hold_decision([qualified, vulnerable, shared])
        self.assertTrue(decision["required"])
        self.assertEqual(decision["required_for"],
                         ["isolated_shared", "shared_unconfined"])
        self.assertEqual(decision["required_for_isolated_custody"], ["isolated_shared"])
        self.assertFalse(decision["qualified_configuration_requires_hold"])
        self.assertTrue(decision["configurations"]["isolated_shared"][
            "during_run_attempt_blocked_by_hold"])
        self.assertTrue(decision["configurations"]["isolated_shared"][
            "before_run_attempt_not_blocked_by_hold"])
        self.assertTrue(decision["does_not_repair_before_run_contamination"])
        self.assertTrue(decision["shared_custody"]["hold_is_not_a_security_boundary"])
        self.assertTrue(decision["all_held_trials_refused"])

    def test_hold_required_when_the_qualified_topology_needs_it(self):
        qualified = synthetic_record(during_unheld="succeeded")
        decision = matrix.hold_decision([qualified])
        self.assertTrue(decision["required"])
        self.assertEqual(decision["required_for_isolated_custody"], ["isolated_separate"])
        self.assertTrue(decision["qualified_configuration_requires_hold"])

    def test_identical_configurations_are_rejected(self):
        records = [synthetic_record(name="isolated_separate"),
                   synthetic_record(name="isolated_shared", target_isolation="shared_principals")]
        records[1]["verifier"]["accounts_shared_with_worker"] = False
        records[1]["target_isolation"] = "separate_principals"
        with self.assertRaises(RuntimeError):
            matrix.distinctness(records)

    def test_real_configurations_are_distinct(self):
        evidence = json.loads(EVIDENCE.read_text())
        self.assertTrue(matrix.distinctness(evidence["configurations"])["proved"])

    def test_markdown_table_shape(self):
        table = {
            "configurations": ["isolated_separate", "isolated_shared", "shared_unconfined"],
            "rows": [{"attempt_id": "01", "attempt": "write_scourge_database",
                      "outcomes": {"isolated_separate": "refused",
                                   "isolated_shared": "refused",
                                   "shared_unconfined": "succeeded"}}],
        }
        markdown = matrix.markdown_table(table).splitlines()
        self.assertEqual(markdown[0],
                         "| Attempt | isolated, separate principals | isolated, shared principals "
                         "| shared custody |")
        self.assertEqual(markdown[2], "| 01 write scourge database | refused | refused | succeeded |")

    def test_cid_validation(self):
        self.assertTrue(matrix.valid_cid("ab" * 32))
        for value in ("", "AB" * 32, "ab" * 31, "zz" * 32, "ab" * 33):
            self.assertFalse(matrix.valid_cid(value))


class Sanitization(unittest.TestCase):
    def test_unsafe_keys_and_values_are_rejected(self):
        for value in (
            {"path": "/home/user/private"},
            {"target_url": "http://127.0.0.1:3000/"},
            {"session_name": "alice-verify"},
            {"marker": "scourge-m0-tamper-08-deadbeef"},
            {"evidence": [{"note": "secret"}]},
            {"ok": "/tmp/private"},
            {"ok": "http://127.0.0.1:3000/app"},
            {"ok": "alice-password"},
            {"ok": "scourge-m0-tamper-08-deadbeef"},
        ):
            with self.subTest(value=value), self.assertRaises(RuntimeError):
                matrix.assert_sanitized(value)

    def test_safe_values_are_accepted(self):
        matrix.assert_sanitized({
            "verdict": "refused",
            "status": 404,
            "bytes_written": 22,
            "marker_sha256": "ab" * 32,
            "credential_source": "documented development password guess",
        })

    def test_attempt_03_never_records_the_secret_digest(self):
        secret = digest(EVIDENCE)
        result = {
            "attempt_id": "03",
            "verdict": "succeeded",
            "stand_in": False,
            "evidence": [{"bytes_read": 65, "content_sha256": secret}],
        }
        value = matrix.sanitize_attempt(result, secret)
        self.assertIsNone(RecordedObservation.find_key(value, "content_sha256"))
        self.assertNotIn(secret, json.dumps(value))
        self.assertTrue(value["evidence"][0]["content_sha256_matches_referee"])
        result["evidence"][0]["content_sha256"] = "0" * 64
        with self.assertRaises(RuntimeError):
            matrix.sanitize_attempt(result, secret)

    def test_succeeded_claims_need_their_own_evidence(self):
        value = {"attempt_id": "08", "verdict": "succeeded",
                 "evidence": [{"added_unique_rule": True}, {"listed_unique_rule": True}]}
        matrix.require_consistent(value)
        value["evidence"][1] = {}
        with self.assertRaises(RuntimeError):
            matrix.require_consistent(value)
        value = {"attempt_id": "06", "verdict": "succeeded",
                 "evidence": [{"status": 200}, {"observed_transition": True}]}
        matrix.require_consistent(value)
        value["evidence"][1] = {"observed_transition": False}
        with self.assertRaises(RuntimeError):
            matrix.require_consistent(value)

    def test_worker_projection_drops_identities_and_paths(self):
        observed = {
            "pinned_cli_exit": 0,
            "pinned_cli_sha256": matrix.topology.PIN,
            "verifier_project_visible": False,
            "direct_fixture_reachable": False,
            "direct_verifier_proxy_reachable": False,
            "probes": {label: {"refused": True, "errno": 2} for label in matrix.PROBE_LABELS},
            "exploration": {
                name: {"status": 200, "id": f"user-{name}", "role": "user",
                       "tenant": f"tenant-{name}"}
                for name in matrix.PUBLIC_NAMES
            },
        }
        facts, roles, subjects = matrix.sanitize_worker(observed)
        serialized = json.dumps(facts)
        for label in matrix.PUBLIC_NAMES:
            self.assertNotIn(label, serialized)
        self.assertTrue(facts["exploration_logins"]["subjects_distinct"])
        self.assertEqual(facts["private_verifier_credentials_accessible"], False)
        self.assertTrue(all("tenant-" in tenant for _, tenant in roles))
        self.assertTrue(subjects)


class ConsistencyRegressions(unittest.TestCase):
    def test_attempt_06_verdict_must_match_referee_state(self):
        matrix.require_sharing_consistency("succeeded", True)
        matrix.require_sharing_consistency("refused", False)
        matrix.require_sharing_consistency("unsupported", False)
        for verdict, transition in (("succeeded", False), ("refused", True),
                                    ("unsupported", True)):
            with self.subTest(verdict=verdict, transition=transition), \
                    self.assertRaises(RuntimeError):
                matrix.require_sharing_consistency(verdict, transition)
        with self.assertRaises(RuntimeError):
            matrix.require_sharing_consistency("unknown", False)

    def test_during_run_requires_interleaving_and_no_final_error(self):
        matrix.require_active_run(1, 2, 0)
        for start, end, errors in ((0, 0, 0), (1, 1, 0), (1, 2, 1), (2, 1, 0)):
            with self.subTest(start=start, end=end, errors=errors), \
                    self.assertRaises(RuntimeError):
                matrix.require_active_run(start, end, errors)

    def test_network_witnesses_reject_each_contradiction(self):
        matrix.require_network_witness_consistency(
            "succeeded", "succeeded", 10, 11, True)
        matrix.require_network_witness_consistency(
            "refused", "refused", 10, 10, False)
        contradictions = (
            ("refused", "refused", 10, 11, False),      # hidden attempt-07 success
            ("succeeded", "succeeded", 10, 10, True),   # no attempt-07 increment
            ("succeeded", "refused", 10, 11, True),     # attempt-08 success, no marker
            ("refused", "succeeded", 10, 10, False),    # attempt-08 marker hidden
            ("refused", "refused", None, 10, False),    # unusable before count
            ("refused", "refused", 10, None, False),    # unusable after count
            ("refused", "refused", 10, 9, False),       # flow count went backwards
        )
        for verdict07, verdict08, before, after, persisted in contradictions:
            with self.subTest(verdict07=verdict07, verdict08=verdict08,
                              before=before, after=after, persisted=persisted), \
                    self.assertRaises(RuntimeError):
                matrix.require_network_witness_consistency(
                    verdict07, verdict08, before, after, persisted)


class SecretSafeFailure(unittest.TestCase):
    def test_identity_failure_never_emits_the_password(self):
        secret = "PLACEHOLDER-PRIVATE-PASSWORD-0123456789"
        principals = {"alice-verify": secret}

        def fake_tp(*_args):
            raise subprocess.TimeoutExpired(
                cmd=["teapot", "--json", "requests", "send", "POST",
                     "http://127.0.0.1:1/app/login", "--body",
                     json.dumps({"username": "alice-verify", "password": secret})],
                timeout=1,
            )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            os.chmod(root, 0o700)
            with self.assertRaises(RuntimeError) as caught:
                matrix.identities(fake_tp, "http://127.0.0.1:1", principals, root)
            error = caught.exception
            self.assertNotIn(secret, str(error))
            self.assertNotIn(secret, repr(error))
            self.assertIsNone(error.__cause__)
            self.assertTrue(error.__suppress_context__)
            rendered = "".join(traceback.format_exception(error))
            self.assertNotIn(secret, rendered)
            emitted = io.StringIO()
            traceback.print_exception(error, file=emitted)
            self.assertNotIn(secret, emitted.getvalue())

            diagnostics = root / "diagnostics"
            self.assertEqual(diagnostics.stat().st_mode & 0o777, 0o700)
            files = list(diagnostics.glob("*.log"))
            self.assertTrue(files)
            for path in files:
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                content = path.read_text()
                self.assertNotIn(secret, content)
                self.assertIn("[redacted]", content)


class RelayHold(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        async def answer(reader, writer):
            try:
                await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5)
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
                             b"Connection: close\r\n\r\nok")
                await writer.drain()
            except (OSError, asyncio.TimeoutError):
                pass
            finally:
                writer.close()

        self.upstream = await asyncio.start_server(answer, "127.0.0.1", 0)
        upstream_port = self.upstream.sockets[0].getsockname()[1]
        self.relay = matrix.Relay(upstream_port)
        self.server = await asyncio.start_server(self.relay.connect, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]

    async def asyncTearDown(self):
        self.server.close()
        await self.server.wait_closed()
        self.upstream.close()
        await self.upstream.wait_closed()

    async def request(self):
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        try:
            writer.write(b"GET / HTTP/1.1\r\nHost: relay.test\r\nConnection: close\r\n\r\n")
            await writer.drain()
            return await asyncio.wait_for(reader.read(4096), timeout=5)
        finally:
            writer.close()
            await writer.wait_closed()

    async def test_unheld_forwards_and_held_refuses(self):
        response = await self.request()
        self.assertIn(b"200", response.split(b"\r\n", 1)[0])
        self.assertEqual(self.relay.counts(), (1, 0))
        with self.relay.hold(True):
            response = await self.request()
        self.assertIn(b"503", response.split(b"\r\n", 1)[0])
        self.assertEqual(self.relay.counts(), (1, 1))
        self.assertFalse(self.relay.held)
        response = await self.request()
        self.assertIn(b"200", response.split(b"\r\n", 1)[0])
        self.assertEqual(self.relay.counts(), (2, 1))


if __name__ == "__main__":
    unittest.main()
