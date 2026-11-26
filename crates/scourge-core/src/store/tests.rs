use super::*;
use crate::{
    domain::{
        CleanupObjectOutcome, CleanupObjectRole, CleanupOwnership, LeadEventKind, RunCleanup,
    },
    ids::{LeadId, VerificationId},
    request::Invocation,
    wire::{Cleanup, Completeness, Effect, Flow, OracleResult, RunFlag, RunState, VersionedId},
};
use tempfile::TempDir;

fn open() -> (TempDir, Store) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().join("state.sqlite3")).unwrap();
    (dir, store)
}

#[test]
fn cleanup_outcome_is_durable_without_erasing_an_oracle_result() {
    let (_dir, mut store) = open();
    let engagement = "local".parse().unwrap();
    let asset = artifact();
    store
        .append_manifest(&engagement, &asset, &asset.digest)
        .unwrap();
    let mut run = Run::declare(engagement, asset.digest);
    run.state = RunState::Finalized;
    run.oracle_result = Some(OracleResult::True);
    let finalized = store.seed_historical_run_fixture(&run).unwrap();
    let mut forged = run.clone();
    forged.oracle_result = Some(OracleResult::False);
    assert!(matches!(
        store.record_run(&forged, Some(finalized)),
        Err(StoreError::Conflict)
    ));
    forged.oracle_result = run.oracle_result;
    forged.reproduction = Reproduction::Reproduced;
    assert!(matches!(
        store.record_run(&forged, Some(finalized)),
        Err(StoreError::Conflict)
    ));
    assert_eq!(store.revision().unwrap(), finalized);
    assert_eq!(store.recover_run(&run.id).unwrap(), run);
    let plant_digest = Sha256Digest::of(b"plant intent");
    let mut cleanup = RunCleanup {
        round: 1,
        object: CleanupObjectRole::Primary,
        plant_step: 3,
        plant_request_digest: plant_digest,
        object_id: Some("run-object".parse().unwrap()),
        ownership: CleanupOwnership::Established,
        cleanup_step: None,
        cleanup_request_digest: None,
        flow_id_floor: None,
        instrument_reference: None,
        effects: None,
        response_status: None,
        flows: Vec::new(),
        outcome: CleanupObjectOutcome::Owed,
    };
    assert_eq!(
        store.record_cleanup(&run.id, &cleanup).unwrap(),
        Cleanup::Unknown
    );
    cleanup.cleanup_step = Some(12);
    cleanup.cleanup_request_digest = Some(Sha256Digest::of(b"remove intent"));
    cleanup.outcome = CleanupObjectOutcome::InFlight;
    assert!(store.record_cleanup(&run.id, &cleanup).is_err());
    let mut failed_without_step = cleanup.clone();
    failed_without_step.instrument_reference = Some("not-sent".parse().unwrap());
    failed_without_step.effects = Some(Effect::None);
    failed_without_step.outcome = CleanupObjectOutcome::Failed;
    assert!(store.record_cleanup(&run.id, &failed_without_step).is_err());
    assert!(
        store
            .db
            .execute(
                "UPDATE run_cleanup SET cleanup_step='12', cleanup_request_digest=?2,
                 instrument_reference='not-sent', effects='none', outcome='failed'
             WHERE run_id=?1 AND round='1' AND object='primary'",
                params![
                    run.id.as_str(),
                    cleanup.cleanup_request_digest.as_ref().unwrap().as_str()
                ],
            )
            .is_err()
    );
    store
        .record_step(
            &run.id,
            &RunStep {
                number: 12,
                step: "round.1.C".parse().unwrap(),
                request_digest: cleanup.cleanup_request_digest.clone().unwrap(),
                flow_id_floor: None,
                instrument_reference: None,
                effects: Some(Effect::None),
                flows: Vec::new(),
            },
        )
        .unwrap();
    assert_eq!(
        store.record_cleanup(&run.id, &cleanup).unwrap(),
        Cleanup::Unknown
    );
    for outcome in [
        CleanupObjectOutcome::InFlight,
        CleanupObjectOutcome::Unknown,
    ] {
        let mut observed_without_reference = cleanup.clone();
        observed_without_reference.effects = Some(Effect::Observed);
        observed_without_reference.outcome = outcome;
        assert!(
            store
                .record_cleanup(&run.id, &observed_without_reference)
                .is_err()
        );
    }
    assert!(
        store
            .db
            .execute(
                "UPDATE run_cleanup SET effects='observed', instrument_reference=NULL
             WHERE run_id=?1 AND round='1' AND object='primary'",
                [run.id.as_str()],
            )
            .is_err()
    );
    let complete_primary = Flow {
        step: "C.primary.request".parse().unwrap(),
        flow_id: Some(77),
        original: None,
        completeness: Completeness::Complete,
        decoder: None,
    };
    let mut false_complete = cleanup.clone();
    false_complete.instrument_reference = Some("not-sent".parse().unwrap());
    false_complete.effects = Some(Effect::Observed);
    false_complete.response_status = Some(204);
    false_complete.flows = vec![complete_primary.clone()];
    false_complete.outcome = CleanupObjectOutcome::Complete;
    assert!(store.record_cleanup(&run.id, &false_complete).is_err());

    false_complete.instrument_reference = Some("flow:77".parse().unwrap());
    false_complete.flows[0].step = "C.control.request".parse().unwrap();
    assert!(store.record_cleanup(&run.id, &false_complete).is_err());

    false_complete.flows = vec![
        complete_primary.clone(),
        Flow {
            step: "C.primary.retry".parse().unwrap(),
            flow_id: None,
            original: None,
            completeness: Completeness::Missing,
            decoder: None,
        },
    ];
    assert!(store.record_cleanup(&run.id, &false_complete).is_err());

    let complete_primary_array = [complete_primary.clone()];
    let flow_json = json(&complete_primary_array).unwrap();
    let sibling_flow_json = json(&[Flow {
        step: "C.control.request".parse().unwrap(),
        ..complete_primary.clone()
    }])
    .unwrap();
    let sibling_then_terminal_json = json(&[
        Flow {
            step: "C.control.request".parse().unwrap(),
            flow_id: Some(76),
            ..complete_primary.clone()
        },
        complete_primary.clone(),
    ])
    .unwrap();
    let raw_step_flows = vec![
        Flow {
            step: "C.control.request".parse().unwrap(),
            flow_id: Some(76),
            ..complete_primary.clone()
        },
        complete_primary.clone(),
        Flow {
            step: "C.primary.retry".parse().unwrap(),
            flow_id: Some(78),
            ..complete_primary.clone()
        },
    ];
    let raw_step_json = json(&raw_step_flows).unwrap();
    // A raw terminal write cannot bypass the missing durable C-step boundary.
    assert!(
        store
            .db
            .execute(
                "INSERT INTO run_cleanup (
                     run_id, round, object, plant_step, plant_request_digest,
                     object_id, ownership, cleanup_step, cleanup_request_digest,
                     flow_id_floor, instrument_reference, effects, response_status,
                     flow_refs, outcome)
                 VALUES (?1, '2', 'primary', '15', ?2, 'raw-object', 'established',
                         '24', ?3, NULL, 'flow:78', 'observed', '204', ?4, 'complete')",
                params![
                    run.id.as_str(),
                    cleanup.plant_request_digest.as_str(),
                    Sha256Digest::of(b"raw remove intent").as_str(),
                    raw_step_json
                ],
            )
            .is_err()
    );
    let missing_terminal_json = json(&[
        complete_primary,
        Flow {
            step: "C.primary.retry".parse().unwrap(),
            flow_id: None,
            original: None,
            completeness: Completeness::Missing,
            decoder: None,
        },
    ])
    .unwrap();
    for (effects, status, reference, flows, outcome) in [
        (
            None,
            Some("204"),
            Some("flow:77"),
            flow_json.as_str(),
            "complete",
        ),
        (
            Some("observed"),
            None,
            Some("flow:77"),
            flow_json.as_str(),
            "complete",
        ),
        (Some("none"), Some("204"), Some("not-sent"), "[]", "failed"),
        (Some("none"), Some("500"), Some("not-sent"), "[]", "failed"),
    ] {
        assert!(
            store
                .db
                .execute(
                    "UPDATE run_cleanup SET effects=?2, response_status=?3,
                     instrument_reference=?4, flow_refs=?5, outcome=?6
                 WHERE run_id=?1 AND round='1' AND object='primary'",
                    params![run.id.as_str(), effects, status, reference, flows, outcome],
                )
                .is_err()
        );
    }
    for (reference, flows) in [
        ("not-sent", flow_json.as_str()),
        ("flow:77", sibling_flow_json.as_str()),
        ("flow:77", sibling_then_terminal_json.as_str()),
        ("flow:77", missing_terminal_json.as_str()),
    ] {
        assert!(
            store
                .db
                .execute(
                    "UPDATE run_cleanup SET effects='observed', response_status='204',
                     instrument_reference=?2, flow_refs=?3, outcome='complete'
                 WHERE run_id=?1 AND round='1' AND object='primary'",
                    params![run.id.as_str(), reference, flows],
                )
                .is_err()
        );
    }
    cleanup.instrument_reference = Some("not-sent".parse().unwrap());
    cleanup.effects = Some(Effect::None);
    cleanup.outcome = CleanupObjectOutcome::Failed;
    assert_eq!(
        store.record_cleanup(&run.id, &cleanup).unwrap(),
        Cleanup::Failed
    );

    let recovered = store.recover_run(&run.id).unwrap();
    assert_eq!(recovered.oracle_result, Some(OracleResult::True));
    assert_eq!(recovered.cleanup, Cleanup::Failed);
    let entry = entry::read(&store.db, &run.engagement).unwrap();
    let attention = entry.attention.expect("failed cleanup must lead Next");
    assert_eq!(attention.reason, entry::AttentionReason::PendingCleanup);
    assert_eq!(attention.run.as_ref(), Some(&run.id));

    // A later finalization writer may carry a stale aggregate cleanup field.
    // Per-object cleanup remains authoritative and the finding remains true.
    run.cleanup = Cleanup::NotRequired;
    store.record_run(&run, Some(finalized)).unwrap();
    let recovered = store.recover_run(&run.id).unwrap();
    assert_eq!(recovered.oracle_result, Some(OracleResult::True));
    assert_eq!(recovered.cleanup, Cleanup::Failed);

    let mut impossible = cleanup.clone();
    impossible.object = CleanupObjectRole::Control;
    impossible.object_id = Some("other-object".parse().unwrap());
    impossible.instrument_reference = None;
    impossible.effects = None;
    impossible.outcome = CleanupObjectOutcome::Complete;
    assert!(store.record_cleanup(&run.id, &impossible).is_err());

    let mut false_completion = cleanup.clone();
    false_completion.outcome = CleanupObjectOutcome::Complete;
    assert!(store.record_cleanup(&run.id, &false_completion).is_err());

    let mut unknown = cleanup.clone();
    unknown.object = CleanupObjectRole::Control;
    unknown.object_id = Some("unknown-object".parse().unwrap());
    unknown.instrument_reference = Some("sent:no-flow".parse().unwrap());
    unknown.effects = Some(Effect::Unknown);
    unknown.outcome = CleanupObjectOutcome::Unknown;
    let mut queued_as_failed = unknown.clone();
    queued_as_failed.effects = Some(Effect::Observed);
    queued_as_failed.response_status = Some(202);
    queued_as_failed.outcome = CleanupObjectOutcome::Failed;
    assert!(store.record_cleanup(&run.id, &queued_as_failed).is_err());
    store.record_cleanup(&run.id, &unknown).unwrap();
    assert!(
        store
            .db
            .execute(
                "UPDATE run_cleanup SET effects=NULL
                 WHERE run_id=?1 AND round='1' AND object='control'",
                [run.id.as_str()],
            )
            .is_err()
    );
    unknown.effects = None;
    assert!(store.record_cleanup(&run.id, &unknown).is_err());
}

#[test]
fn cleanup_transition_settles_known_noncreation_and_preserves_inflight_evidence() {
    let (_dir, mut store) = open();
    let (run, _) = declared_run(&mut store);
    let mut cleanup = RunCleanup {
        round: 1,
        object: CleanupObjectRole::Primary,
        plant_step: 3,
        plant_request_digest: Sha256Digest::of(b"plant intent"),
        object_id: None,
        ownership: CleanupOwnership::Pending,
        cleanup_step: None,
        cleanup_request_digest: None,
        flow_id_floor: None,
        instrument_reference: None,
        effects: None,
        response_status: None,
        flows: Vec::new(),
        outcome: CleanupObjectOutcome::Owed,
    };
    store.record_cleanup(&run.id, &cleanup).unwrap();
    cleanup.ownership = CleanupOwnership::NotCreated;
    cleanup.outcome = CleanupObjectOutcome::NotRequired;
    assert_eq!(
        store.record_cleanup(&run.id, &cleanup).unwrap(),
        Cleanup::NotRequired
    );

    let mut inflight = RunCleanup {
        round: 2,
        object: CleanupObjectRole::Primary,
        plant_step: 15,
        plant_request_digest: Sha256Digest::of(b"second plant intent"),
        object_id: Some("created-object".parse().unwrap()),
        ownership: CleanupOwnership::Established,
        cleanup_step: None,
        cleanup_request_digest: None,
        flow_id_floor: None,
        instrument_reference: None,
        effects: None,
        response_status: None,
        flows: Vec::new(),
        outcome: CleanupObjectOutcome::Owed,
    };
    store.record_cleanup(&run.id, &inflight).unwrap();
    inflight.cleanup_step = Some(24);
    inflight.cleanup_request_digest = Some(Sha256Digest::of(b"second remove intent"));
    inflight.outcome = CleanupObjectOutcome::InFlight;
    assert!(store.record_cleanup(&run.id, &inflight).is_err());
    store
        .record_step(
            &run.id,
            &RunStep {
                number: 24,
                step: "round.2.C".parse().unwrap(),
                request_digest: inflight.cleanup_request_digest.clone().unwrap(),
                flow_id_floor: None,
                instrument_reference: None,
                effects: None,
                flows: Vec::new(),
            },
        )
        .unwrap();
    store.record_cleanup(&run.id, &inflight).unwrap();
    inflight.instrument_reference = Some("flow:88".parse().unwrap());
    inflight.effects = Some(Effect::Observed);
    inflight.response_status = Some(204);
    store.record_cleanup(&run.id, &inflight).unwrap();
    inflight.effects = Some(Effect::Unknown);
    assert!(store.record_cleanup(&run.id, &inflight).is_err());
    inflight.effects = Some(Effect::None);
    inflight.response_status = None;
    assert!(store.record_cleanup(&run.id, &inflight).is_err());
    for effect in ["unknown", "none"] {
        assert!(
            store
                .db
                .execute(
                    "UPDATE run_cleanup SET effects=?2
                 WHERE run_id=?1 AND round='2' AND object='primary'",
                    params![run.id.as_str(), effect],
                )
                .is_err()
        );
    }
}

#[test]
fn cleanup_sql_identity_and_original_enrichment_are_monotonic() {
    let (dir, mut store) = open();
    let (run, _) = declared_run(&mut store);
    let mut cleanup = RunCleanup {
        round: 1,
        object: CleanupObjectRole::Primary,
        plant_step: 3,
        plant_request_digest: Sha256Digest::of(b"plant intent"),
        object_id: Some("created-object".parse().unwrap()),
        ownership: CleanupOwnership::Established,
        cleanup_step: None,
        cleanup_request_digest: None,
        flow_id_floor: None,
        instrument_reference: None,
        effects: None,
        response_status: None,
        flows: Vec::new(),
        outcome: CleanupObjectOutcome::Owed,
    };
    store.record_cleanup(&run.id, &cleanup).unwrap();
    cleanup.cleanup_step = Some(12);
    cleanup.cleanup_request_digest = Some(Sha256Digest::of(b"remove intent"));
    store.record_cleanup(&run.id, &cleanup).unwrap();
    let mut cleanup_step = RunStep {
        number: 12,
        step: "round.1.C".parse().unwrap(),
        request_digest: cleanup.cleanup_request_digest.clone().unwrap(),
        flow_id_floor: None,
        instrument_reference: None,
        effects: None,
        flows: Vec::new(),
    };
    store.record_step(&run.id, &cleanup_step).unwrap();
    cleanup.outcome = CleanupObjectOutcome::InFlight;
    store.record_cleanup(&run.id, &cleanup).unwrap();
    cleanup.instrument_reference = Some("flow:91".parse().unwrap());
    cleanup.effects = Some(Effect::Observed);
    cleanup.response_status = Some(204);
    cleanup.flows = vec![
        Flow {
            step: "C.primary.request".parse().unwrap(),
            flow_id: Some(90),
            original: None,
            completeness: Completeness::Complete,
            decoder: None,
        },
        Flow {
            step: "C.primary.retry".parse().unwrap(),
            flow_id: Some(91),
            original: None,
            completeness: Completeness::Complete,
            decoder: None,
        },
    ];
    cleanup.outcome = CleanupObjectOutcome::Complete;
    // A terminal cleanup row cannot get ahead of its frozen C-step evidence.
    assert!(store.record_cleanup(&run.id, &cleanup).is_err());
    cleanup_step.flows = cleanup.flows.clone();
    store.record_step(&run.id, &cleanup_step).unwrap();
    let mut omitted = cleanup.clone();
    omitted.instrument_reference = Some("flow:90".parse().unwrap());
    omitted.flows.truncate(1);
    assert!(store.record_cleanup(&run.id, &omitted).is_err());
    assert!(
        store
            .db
            .execute(
                "UPDATE run_cleanup SET instrument_reference='flow:90', effects='observed',
                     response_status='204', flow_refs=?2, outcome='complete'
                 WHERE run_id=?1 AND round='1' AND object='primary'",
                params![run.id.as_str(), json(&omitted.flows).unwrap()],
            )
            .is_err()
    );
    let mut other_round = cleanup.clone();
    other_round.round = 2;
    other_round.plant_step = 15;
    assert!(store.record_cleanup(&run.id, &other_round).is_err());
    assert!(
        store
            .db
            .execute(
                "INSERT INTO run_cleanup (
                     run_id, round, object, plant_step, plant_request_digest,
                     object_id, ownership, cleanup_step, cleanup_request_digest,
                     flow_id_floor, instrument_reference, effects, response_status,
                     flow_refs, outcome)
                 VALUES (?1, '2', 'control', '15', ?2, 'cross-round', 'established',
                         '12', ?3, NULL, NULL, NULL, NULL, '[]', 'owed')",
                params![
                    run.id.as_str(),
                    cleanup.plant_request_digest.as_str(),
                    cleanup.cleanup_request_digest.as_ref().unwrap().as_str()
                ],
            )
            .is_err()
    );
    store.record_cleanup(&run.id, &cleanup).unwrap();

    let mut linked = cleanup.flows.clone();
    for flow in &mut linked {
        flow.original = Some(artifact());
    }
    cleanup_step.flows = linked.clone();
    assert!(store.record_step(&run.id, &cleanup_step).is_err());
    for malformed_original in [
        serde_json::json!({"artifact_id": "a1", "extra": "missing digest"}),
        serde_json::json!({"extra": "missing id", "digest": Sha256Digest::of(b"metadata")}),
    ] {
        let mut malformed_step = serde_json::to_value(&cleanup_step.flows).unwrap();
        malformed_step[0]["original"] = malformed_original;
        assert!(
            store
                .db
                .execute(
                    "UPDATE run_steps SET flow_refs=?3
                     WHERE run_id=?1 AND number=?2",
                    params![run.id.as_str(), "12", malformed_step.to_string()],
                )
                .is_err()
        );
    }
    let mut missing_original = serde_json::to_value(&cleanup.flows).unwrap();
    let first = missing_original[0].as_object_mut().unwrap();
    first.remove("original").unwrap();
    first.insert("extra".into(), serde_json::Value::Null);
    let mut missing_decoder = serde_json::to_value(&cleanup.flows).unwrap();
    let first = missing_decoder[0].as_object_mut().unwrap();
    first.remove("decoder").unwrap();
    first.insert("extra".into(), serde_json::Value::Null);
    let mut nul_digest = serde_json::to_value(&cleanup.flows).unwrap();
    nul_digest[0]["original"] = serde_json::json!({
        "artifact_id": "a1",
        "digest": format!("{}\0x", "a".repeat(64)),
    });
    let mut surrogate = serde_json::to_value(&cleanup.flows).unwrap();
    surrogate[0]["original"] = serde_json::json!({
        "artifact_id": "SURROGATE_MARKER",
        "digest": "a".repeat(64),
    });
    let surrogate = surrogate
        .to_string()
        .replacen("\"SURROGATE_MARKER\"", "\"\\ud800\"", 1);
    for malformed_step in [
        missing_original.to_string(),
        missing_decoder.to_string(),
        nul_digest.to_string(),
        surrogate,
    ] {
        assert!(
            store
                .db
                .execute(
                    "UPDATE run_steps SET flow_refs=?3
                     WHERE run_id=?1 AND number=?2",
                    params![run.id.as_str(), "12", malformed_step],
                )
                .is_err()
        );
    }

    let exact_flow_json = json(&cleanup.flows).unwrap();
    let trailing_comma = format!(
        "{},]",
        exact_flow_json
            .strip_suffix(']')
            .expect("serialized flow list ends in an array close")
    );
    let mut invalid_utf8 = exact_flow_json.as_bytes().to_vec();
    let invalid_at = invalid_utf8
        .windows(b"primary".len())
        .position(|window| window == b"primary")
        .expect("fixture flow contains its role");
    invalid_utf8[invalid_at] = 0xff;
    assert!(
        store
            .db
            .execute(
                "UPDATE run_steps SET flow_refs=?3
                 WHERE run_id=?1 AND number=?2",
                params![run.id.as_str(), "12", trailing_comma],
            )
            .is_err()
    );
    assert!(
        store
            .db
            .execute(
                "UPDATE run_cleanup SET flow_refs=?2
                 WHERE run_id=?1 AND round='1' AND object='primary'",
                params![run.id.as_str(), trailing_comma],
            )
            .is_err()
    );
    assert!(
        store
            .db
            .execute(
                "UPDATE run_steps SET flow_refs=CAST(?3 AS TEXT)
                 WHERE run_id=?1 AND number=?2",
                params![run.id.as_str(), "12", invalid_utf8.as_slice()],
            )
            .is_err()
    );
    assert!(
        store
            .db
            .execute(
                "UPDATE run_cleanup SET flow_refs=CAST(?3 AS TEXT)
                 WHERE run_id=?1 AND round=?2 AND object='primary'",
                params![run.id.as_str(), "1", invalid_utf8.as_slice()],
            )
            .is_err()
    );

    let max_flow = Flow {
        step: "F0.request".parse().unwrap(),
        flow_id: Some(u64::MAX),
        original: None,
        completeness: Completeness::Complete,
        decoder: Some(VersionedId {
            id: "http".parse().unwrap(),
            version: "1".parse().unwrap(),
        }),
    };
    let mut max_step = RunStep {
        number: 2,
        step: "maximum flow".parse().unwrap(),
        request_digest: Sha256Digest::of(b"maximum flow"),
        flow_id_floor: None,
        instrument_reference: None,
        effects: None,
        flows: Vec::new(),
    };
    store.record_step(&run.id, &max_step).unwrap();
    let max_flows = [max_flow.clone()];
    let oversized =
        json(&max_flows)
            .unwrap()
            .replacen("18446744073709551615", "18446744073709551616", 1);
    assert!(
        store
            .db
            .execute(
                "UPDATE run_steps SET flow_refs=?3
                 WHERE run_id=?1 AND number=?2",
                params![run.id.as_str(), "2", oversized],
            )
            .is_err()
    );
    max_step.flows.push(max_flow);
    store.record_step(&run.id, &max_step).unwrap();
    let mut replacement = cleanup.flows.clone();
    replacement[0].flow_id = Some(7);
    assert!(
        store
            .db
            .execute(
                "INSERT OR REPLACE INTO run_steps (
                     run_id, number, step, request_digest, flow_id_floor,
                     instrument_reference, effects, flow_refs)
                 VALUES (?1, '12', 'round.1.C', ?2, NULL, NULL, NULL, ?3)",
                params![
                    run.id.as_str(),
                    cleanup_step.request_digest.as_str(),
                    json(&replacement).unwrap()
                ],
            )
            .is_err()
    );
    assert!(
        store
            .db
            .execute(
                "DELETE FROM run_steps WHERE run_id=?1 AND number='12'",
                [run.id.as_str()],
            )
            .is_err()
    );
    store.link_step_originals(&run.id, &cleanup_step).unwrap();

    let mut mismatched = cleanup.clone();
    mismatched.flows = linked.clone();
    mismatched.flows[0].original.as_mut().unwrap().digest = Sha256Digest::of(b"other artifact");
    assert!(store.link_cleanup_originals(&run.id, &mismatched).is_err());
    let mut omitted_link = cleanup.clone();
    omitted_link.flows = linked[..1].to_vec();
    assert!(
        store
            .link_cleanup_originals(&run.id, &omitted_link)
            .is_err()
    );
    assert!(
        store
            .db
            .execute(
                "UPDATE run_cleanup SET flow_refs=?2
                 WHERE run_id=?1 AND round='1' AND object='primary'",
                params![run.id.as_str(), json(&mismatched.flows).unwrap()],
            )
            .is_err()
    );

    let linked_json = json(&linked).unwrap();
    let mut malformed = serde_json::to_value(&linked).unwrap();
    malformed[0]["original"]["digest"] = serde_json::Value::String("not-a-digest".into());
    assert!(
        store
            .db
            .execute(
                "UPDATE run_cleanup SET flow_refs=?2
                 WHERE run_id=?1 AND round='1' AND object='primary'",
                params![run.id.as_str(), malformed.to_string()],
            )
            .is_err()
    );
    assert_eq!(
        store
            .db
            .execute(
                "UPDATE run_cleanup SET flow_refs=?2
                 WHERE run_id=?1 AND round='1' AND object='primary'",
                params![run.id.as_str(), linked_json],
            )
            .unwrap(),
        1
    );
    assert_eq!(store.recover_cleanup(&run.id).unwrap()[0].flows, linked);
    let mut exact = cleanup.clone();
    exact.flows = linked.clone();
    store.link_cleanup_originals(&run.id, &exact).unwrap();

    let mut rewrites = Vec::new();
    let mut changed = linked.clone();
    changed[0].original.as_mut().unwrap().digest = Sha256Digest::of(b"rewritten");
    rewrites.push(changed);
    let mut deleted = linked.clone();
    deleted[0].original = None;
    rewrites.push(deleted);
    let mut reordered = linked.clone();
    reordered.swap(0, 1);
    rewrites.push(reordered);
    let mut sibling = linked.clone();
    sibling[0].step = "C.control.request".parse().unwrap();
    rewrites.push(sibling);
    for rewrite in rewrites {
        assert!(
            store
                .db
                .execute(
                    "UPDATE run_cleanup SET flow_refs=?2
                 WHERE run_id=?1 AND round='1' AND object='primary'",
                    params![run.id.as_str(), json(&rewrite).unwrap()],
                )
                .is_err()
        );
    }

    assert!(
        store
            .db
            .execute(
                "UPDATE run_cleanup SET round='2'
             WHERE run_id=?1 AND round='1' AND object='primary'",
                [run.id.as_str()],
            )
            .is_err()
    );
    assert!(
        store
            .db
            .execute(
                "UPDATE run_cleanup SET object='control'
             WHERE run_id=?1 AND round='1' AND object='primary'",
                [run.id.as_str()],
            )
            .is_err()
    );

    let (other, _) = declared_run(&mut store);
    assert!(
        store
            .db
            .execute(
                "UPDATE run_cleanup SET run_id=?2
             WHERE run_id=?1 AND round='1' AND object='primary'",
                params![run.id.as_str(), other.id.as_str()],
            )
            .is_err()
    );

    drop(store);
    let store = Store::open(dir.path().join("state.sqlite3")).unwrap();
    let recovered = store.recover_run(&run.id).unwrap();
    assert!(
        recovered
            .steps
            .iter()
            .any(|step| { step.number == 2 && step.flows[0].flow_id == Some(u64::MAX) })
    );
    assert_eq!(store.recover_cleanup(&run.id).unwrap()[0].flows, linked);
}

#[test]
fn cleanup_rows_cannot_be_replaced_or_deleted_across_reopen() {
    let (dir, mut store) = open();
    let (run, _) = declared_run(&mut store);
    let mut cleanup = RunCleanup {
        round: 1,
        object: CleanupObjectRole::Primary,
        plant_step: 3,
        plant_request_digest: Sha256Digest::of(b"plant primary"),
        object_id: Some("primary-object".parse().unwrap()),
        ownership: CleanupOwnership::Established,
        cleanup_step: Some(12),
        cleanup_request_digest: Some(Sha256Digest::of(b"remove primary")),
        flow_id_floor: Some(10),
        instrument_reference: None,
        effects: None,
        response_status: None,
        flows: Vec::new(),
        outcome: CleanupObjectOutcome::Owed,
    };
    store.record_cleanup(&run.id, &cleanup).unwrap();
    let mut step = RunStep {
        number: 12,
        step: "round.1.C".parse().unwrap(),
        request_digest: Sha256Digest::of(b"remove frozen batch"),
        flow_id_floor: Some(10),
        instrument_reference: None,
        effects: None,
        flows: Vec::new(),
    };
    store.record_step(&run.id, &step).unwrap();
    cleanup.outcome = CleanupObjectOutcome::InFlight;
    store.record_cleanup(&run.id, &cleanup).unwrap();
    let retained = Flow {
        step: "C.primary.request".parse().unwrap(),
        flow_id: Some(77),
        original: None,
        completeness: Completeness::Complete,
        decoder: Some(VersionedId {
            id: "http".parse().unwrap(),
            version: "1".parse().unwrap(),
        }),
    };
    step.flows.push(retained.clone());
    store.record_step(&run.id, &step).unwrap();
    cleanup.instrument_reference = Some("flow:77".parse().unwrap());
    cleanup.effects = Some(Effect::Observed);
    cleanup.response_status = Some(202);
    cleanup.flows.push(retained);
    cleanup.outcome = CleanupObjectOutcome::Unknown;
    assert_eq!(
        store.record_cleanup(&run.id, &cleanup).unwrap(),
        Cleanup::Unknown
    );
    assert_eq!(pragma(&store.db, "recursive_triggers").unwrap(), 1);

    assert!(
        store
            .db
            .execute(
                "INSERT OR REPLACE INTO run_cleanup (
                     run_id, round, object, plant_step, plant_request_digest,
                     object_id, ownership, cleanup_step, cleanup_request_digest,
                     flow_id_floor, instrument_reference, effects, response_status,
                     flow_refs, outcome)
                 VALUES (?1, '1', 'primary', '3', ?2, NULL, 'not_created',
                         NULL, NULL, NULL, NULL, NULL, NULL, '[]', 'not_required')",
                params![run.id.as_str(), cleanup.plant_request_digest.as_str()],
            )
            .is_err()
    );
    let cleanup_rowid: i64 = store
        .db
        .query_row(
            "SELECT rowid FROM run_cleanup
             WHERE run_id=?1 AND round='1' AND object='primary'",
            [run.id.as_str()],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        store
            .db
            .execute(
                "INSERT OR REPLACE INTO run_cleanup (
                     rowid, run_id, round, object, plant_step, plant_request_digest,
                     object_id, ownership, cleanup_step, cleanup_request_digest,
                     flow_id_floor, instrument_reference, effects, response_status,
                     flow_refs, outcome)
                 VALUES (?1, ?2, '1', 'control', '9', ?3, NULL, 'not_created',
                         NULL, NULL, NULL, NULL, NULL, NULL, '[]', 'not_required')",
                params![
                    cleanup_rowid,
                    run.id.as_str(),
                    cleanup.plant_request_digest.as_str()
                ],
            )
            .is_err()
    );
    let step_rowid: i64 = store
        .db
        .query_row(
            "SELECT rowid FROM run_steps WHERE run_id=?1 AND number='12'",
            [run.id.as_str()],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        store
            .db
            .execute(
                "INSERT OR REPLACE INTO run_steps (
                     rowid, run_id, number, step, request_digest, flow_id_floor,
                     instrument_reference, effects, flow_refs)
                 VALUES (?1, ?2, '24', 'round.2.C', ?3, NULL, NULL, NULL, '[]')",
                params![step_rowid, run.id.as_str(), step.request_digest.as_str()],
            )
            .is_err()
    );
    assert!(
        store
            .db
            .execute(
                "DELETE FROM run_cleanup
                 WHERE run_id=?1 AND round='1' AND object='primary'",
                [run.id.as_str()],
            )
            .is_err()
    );

    drop(store);
    let mut store = Store::open(dir.path().join("state.sqlite3")).unwrap();
    let recovered = store.recover_cleanup(&run.id).unwrap();
    assert_eq!(recovered, vec![cleanup.clone()]);
    assert_eq!(
        store.record_cleanup(&run.id, &recovered[0]).unwrap(),
        Cleanup::Unknown
    );
    assert_eq!(
        store.recover_run(&run.id).unwrap().cleanup,
        Cleanup::Unknown
    );
}

#[test]
fn cleanup_step_growth_is_scoped_to_the_objects_durable_boundary() {
    let (_dir, mut store) = open();
    let (run, _) = declared_run(&mut store);
    let cleanup_digest = Sha256Digest::of(b"remove one object");
    let mut primary = RunCleanup {
        round: 1,
        object: CleanupObjectRole::Primary,
        plant_step: 3,
        plant_request_digest: Sha256Digest::of(b"plant primary"),
        object_id: Some("primary-object".parse().unwrap()),
        ownership: CleanupOwnership::Established,
        cleanup_step: Some(12),
        cleanup_request_digest: Some(cleanup_digest.clone()),
        flow_id_floor: None,
        instrument_reference: None,
        effects: None,
        response_status: None,
        flows: Vec::new(),
        outcome: CleanupObjectOutcome::Owed,
    };
    let mut control = RunCleanup {
        object: CleanupObjectRole::Control,
        plant_step: 9,
        plant_request_digest: Sha256Digest::of(b"plant control"),
        object_id: Some("control-object".parse().unwrap()),
        cleanup_request_digest: Some(Sha256Digest::of(b"remove other object")),
        ..primary.clone()
    };
    store.record_cleanup(&run.id, &primary).unwrap();
    store.record_cleanup(&run.id, &control).unwrap();
    let mut step = RunStep {
        number: 12,
        step: "round.1.C".parse().unwrap(),
        request_digest: Sha256Digest::of(b"remove frozen batch"),
        flow_id_floor: None,
        instrument_reference: None,
        effects: None,
        flows: Vec::new(),
    };
    store.record_step(&run.id, &step).unwrap();

    primary.outcome = CleanupObjectOutcome::InFlight;
    store.record_cleanup(&run.id, &primary).unwrap();
    let primary_flow = Flow {
        step: "C.primary.request".parse().unwrap(),
        flow_id: Some(70),
        original: None,
        completeness: Completeness::Complete,
        decoder: None,
    };
    step.flows.push(primary_flow.clone());
    store.record_step(&run.id, &step).unwrap();
    primary.instrument_reference = Some("flow:70".parse().unwrap());
    primary.effects = Some(Effect::Observed);
    primary.response_status = Some(204);
    primary.flows.push(primary_flow);
    primary.outcome = CleanupObjectOutcome::Complete;
    store.record_cleanup(&run.id, &primary).unwrap();

    // The still-owed sibling must cross its own in-flight boundary first, but
    // may then extend the open batch after primary has completed.
    control.outcome = CleanupObjectOutcome::InFlight;
    store.record_cleanup(&run.id, &control).unwrap();
    step.flows.push(Flow {
        step: "C.control.request".parse().unwrap(),
        flow_id: Some(71),
        original: None,
        completeness: Completeness::Complete,
        decoder: None,
    });
    store.record_step(&run.id, &step).unwrap();

    let mut late_primary_retry = step.clone();
    late_primary_retry.flows.push(Flow {
        step: "C.primary.retry".parse().unwrap(),
        flow_id: Some(72),
        original: None,
        completeness: Completeness::Complete,
        decoder: None,
    });
    assert!(store.record_step(&run.id, &late_primary_retry).is_err());
    assert!(
        store
            .db
            .execute(
                "UPDATE run_steps SET flow_refs=?3
             WHERE run_id=?1 AND number=?2",
                params![
                    run.id.as_str(),
                    step.number.to_string(),
                    json(&late_primary_retry.flows).unwrap()
                ],
            )
            .is_err()
    );
    let mut unsupported = step.clone();
    unsupported.flows.push(Flow {
        step: "C.primary.other".parse().unwrap(),
        flow_id: Some(73),
        original: None,
        completeness: Completeness::Complete,
        decoder: None,
    });
    assert!(store.record_step(&run.id, &unsupported).is_err());
    assert!(
        store
            .db
            .execute(
                "UPDATE run_steps SET flow_refs=?3
                 WHERE run_id=?1 AND number=?2",
                params![
                    run.id.as_str(),
                    step.number.to_string(),
                    json(&unsupported.flows).unwrap()
                ],
            )
            .is_err()
    );
    let mut inserted_before_control = step.flows.clone();
    inserted_before_control.insert(1, late_primary_retry.flows[2].clone());
    let mut replaced_primary = step.flows.clone();
    replaced_primary[0].flow_id = Some(7);
    let removed_primary = step.flows[1..].to_vec();
    for rewrite in [inserted_before_control, replaced_primary, removed_primary] {
        assert!(
            store
                .db
                .execute(
                    "UPDATE run_steps SET flow_refs=?3
                     WHERE run_id=?1 AND number=?2",
                    params![
                        run.id.as_str(),
                        step.number.to_string(),
                        json(&rewrite).unwrap()
                    ],
                )
                .is_err()
        );
    }
    assert!(
        store
            .db
            .execute(
                "UPDATE run_steps SET step='round.2.C'
                 WHERE run_id=?1 AND number=?2",
                params![run.id.as_str(), step.number.to_string()],
            )
            .is_err()
    );
    assert_eq!(
        store.recover_run(&run.id).unwrap().steps[0].flows,
        step.flows
    );
    let cleanup = store.recover_cleanup(&run.id).unwrap();
    assert_eq!(cleanup[0].outcome, CleanupObjectOutcome::Complete);
    assert_eq!(cleanup[1].outcome, CleanupObjectOutcome::InFlight);
}

#[test]
fn a_flowless_unknown_step_can_bind_its_exact_first_recovered_flow() {
    let (_dir, mut store) = open();
    let (run, _) = declared_run(&mut store);
    let mut step = RunStep {
        number: 1,
        step: "receipt".parse().unwrap(),
        request_digest: artifact().digest,
        flow_id_floor: Some(10),
        instrument_reference: None,
        effects: Some(Effect::Unknown),
        flows: Vec::new(),
    };
    store.record_step(&run.id, &step).unwrap();
    step.effects = Some(Effect::Observed);
    step.flows.push(Flow {
        step: "F0.request".parse().unwrap(),
        flow_id: Some(77),
        original: None,
        completeness: Completeness::Complete,
        decoder: None,
    });
    store.record_step(&run.id, &step).unwrap();
    let mut late = step.clone();
    late.flows.push(Flow {
        flow_id: Some(78),
        ..late.flows[0].clone()
    });
    assert!(store.record_step(&run.id, &late).is_err());

    let (other, _) = declared_run(&mut store);
    let mismatched = RunStep {
        number: 1,
        step: "receipt".parse().unwrap(),
        request_digest: artifact().digest,
        flow_id_floor: Some(10),
        instrument_reference: Some("flow:88".parse().unwrap()),
        effects: Some(Effect::Unknown),
        flows: Vec::new(),
    };
    store.record_step(&other.id, &mismatched).unwrap();
    assert!(
        store
            .db
            .execute(
                "UPDATE run_steps SET effects='observed', flow_refs=?3
                 WHERE run_id=?1 AND number=?2",
                params![other.id.as_str(), "1", json(&step.flows).unwrap()],
            )
            .is_err()
    );
}

#[test]
fn a_flowless_unknown_cleanup_can_bind_only_its_exact_recovered_flow() {
    for (floor, accepted) in [(10, true), (77, false), (78, false)] {
        let (_dir, mut store) = open();
        let (run, _) = declared_run(&mut store);
        let mut cleanup = RunCleanup {
            round: 1,
            object: CleanupObjectRole::Primary,
            plant_step: 3,
            plant_request_digest: Sha256Digest::of(b"plant primary"),
            object_id: Some("primary-object".parse().unwrap()),
            ownership: CleanupOwnership::Established,
            cleanup_step: Some(12),
            cleanup_request_digest: Some(Sha256Digest::of(b"remove primary")),
            flow_id_floor: Some(floor),
            instrument_reference: None,
            effects: None,
            response_status: None,
            flows: Vec::new(),
            outcome: CleanupObjectOutcome::Owed,
        };
        store.record_cleanup(&run.id, &cleanup).unwrap();
        let mut step = RunStep {
            number: 12,
            step: "round.1.C".parse().unwrap(),
            request_digest: Sha256Digest::of(b"remove frozen batch"),
            flow_id_floor: Some(floor),
            instrument_reference: None,
            effects: None,
            flows: Vec::new(),
        };
        store.record_step(&run.id, &step).unwrap();
        cleanup.outcome = CleanupObjectOutcome::InFlight;
        store.record_cleanup(&run.id, &cleanup).unwrap();
        step.instrument_reference = Some("flow:77".parse().unwrap());
        step.effects = Some(Effect::Unknown);
        store.record_step(&run.id, &step).unwrap();
        cleanup.instrument_reference = Some("flow:77".parse().unwrap());
        cleanup.effects = Some(Effect::Unknown);
        cleanup.outcome = CleanupObjectOutcome::Unknown;
        store.record_cleanup(&run.id, &cleanup).unwrap();

        step.effects = Some(Effect::Observed);
        step.flows.push(Flow {
            step: "C.primary.request".parse().unwrap(),
            flow_id: Some(77),
            original: None,
            completeness: Completeness::Complete,
            decoder: None,
        });
        if !accepted {
            assert!(store.record_step(&run.id, &step).is_err(), "floor={floor}");
            assert!(
                store
                    .db
                    .execute(
                        "UPDATE run_steps SET effects='observed', flow_refs=?3
                     WHERE run_id=?1 AND number=?2",
                        params![
                            run.id.as_str(),
                            step.number.to_string(),
                            json(&step.flows).unwrap()
                        ],
                    )
                    .is_err()
            );
            assert_eq!(
                store.recover_cleanup(&run.id).unwrap()[0].outcome,
                CleanupObjectOutcome::Unknown
            );
            continue;
        }
        store.record_step(&run.id, &step).unwrap();
        cleanup.effects = Some(Effect::Observed);
        cleanup.response_status = Some(204);
        cleanup.flows = step.flows.clone();
        cleanup.outcome = CleanupObjectOutcome::Complete;
        assert_eq!(
            store.record_cleanup(&run.id, &cleanup).unwrap(),
            Cleanup::Complete
        );
    }
}

#[test]
fn reopened_inflight_cleanup_requires_a_flow_strictly_above_its_floor() {
    for (floor, accepted) in [(10, true), (77, false), (78, false)] {
        let (dir, mut store) = open();
        let (run, _) = declared_run(&mut store);
        let mut cleanup = RunCleanup {
            round: 1,
            object: CleanupObjectRole::Primary,
            plant_step: 3,
            plant_request_digest: Sha256Digest::of(b"plant primary"),
            object_id: Some("primary-object".parse().unwrap()),
            ownership: CleanupOwnership::Established,
            cleanup_step: Some(12),
            cleanup_request_digest: Some(Sha256Digest::of(b"remove primary")),
            flow_id_floor: Some(floor),
            instrument_reference: None,
            effects: None,
            response_status: None,
            flows: Vec::new(),
            outcome: CleanupObjectOutcome::Owed,
        };
        store.record_cleanup(&run.id, &cleanup).unwrap();
        let mut step = RunStep {
            number: 12,
            step: "round.1.C".parse().unwrap(),
            request_digest: Sha256Digest::of(b"remove frozen batch"),
            flow_id_floor: Some(floor),
            instrument_reference: None,
            effects: None,
            flows: Vec::new(),
        };
        store.record_step(&run.id, &step).unwrap();
        cleanup.outcome = CleanupObjectOutcome::InFlight;
        store.record_cleanup(&run.id, &cleanup).unwrap();
        cleanup.instrument_reference = Some("flow:77".parse().unwrap());
        cleanup.effects = Some(Effect::Observed);
        cleanup.response_status = Some(204);
        store.record_cleanup(&run.id, &cleanup).unwrap();

        drop(store);
        let mut store = Store::open(dir.path().join("state.sqlite3")).unwrap();
        step = store.recover_run(&run.id).unwrap().steps[0].clone();
        step.instrument_reference = Some("flow:77".parse().unwrap());
        step.effects = Some(Effect::Observed);
        step.flows.push(Flow {
            step: "C.primary.request".parse().unwrap(),
            flow_id: Some(77),
            original: None,
            completeness: Completeness::Complete,
            decoder: None,
        });
        if !accepted {
            assert!(store.record_step(&run.id, &step).is_err(), "floor={floor}");
            assert!(
                store
                    .db
                    .execute(
                        "UPDATE run_steps SET instrument_reference='flow:77',
                             effects='observed', flow_refs=?3
                         WHERE run_id=?1 AND number=?2",
                        params![
                            run.id.as_str(),
                            step.number.to_string(),
                            json(&step.flows).unwrap()
                        ],
                    )
                    .is_err()
            );
            assert_eq!(
                store.recover_cleanup(&run.id).unwrap()[0].outcome,
                CleanupObjectOutcome::InFlight
            );
            continue;
        }
        store.record_step(&run.id, &step).unwrap();
        cleanup = store.recover_cleanup(&run.id).unwrap()[0].clone();
        cleanup.flows = step.flows.clone();
        cleanup.outcome = CleanupObjectOutcome::Complete;
        assert_eq!(
            store.record_cleanup(&run.id, &cleanup).unwrap(),
            Cleanup::Complete
        );
    }
}

fn artifact() -> Artifact {
    Artifact {
        artifact_id: "a1".parse().unwrap(),
        digest: Sha256Digest::of(b"metadata"),
    }
}

fn declared_run(s: &mut Store) -> (Run, u64) {
    let engagement = "local".parse().unwrap();
    let asset = artifact();
    s.append_manifest(&engagement, &asset, &asset.digest)
        .unwrap();
    let run = Run::declare(engagement, asset.digest);
    let revision = s.seed_historical_run_fixture(&run).unwrap();
    (run, revision)
}

fn finalize_run(s: &mut Store, run: &Run, revision: u64) -> Run {
    let mut run = run.clone();
    run.state = RunState::Finalized;
    s.record_run(&run, Some(revision)).unwrap();
    run
}

fn publication_candidate(
    s: &Store,
    index: &VerificationIndex,
    predecessor: Option<&Sha256Digest>,
) -> (Artifact, Vec<u8>) {
    let mut record = crate::canonical::parse(include_bytes!(
        "../../../../fixtures/contracts/scourge-v1/verification-record.json"
    ))
    .unwrap();
    let experiment: String =
        s.db.query_row(
            "SELECT experiment_digest FROM runs WHERE id=?",
            [index.run_id.as_str()],
            |row| row.get(0),
        )
        .unwrap();
    let lead_revision: i64 =
        s.db.query_row(
            "SELECT max(revision) FROM lead_revisions WHERE lead_id=?",
            [index.lead_id.as_str()],
            |row| row.get(0),
        )
        .unwrap();
    record["record_id"] = serde_json::json!(index.record_id);
    record["engagement"] = serde_json::json!(index.engagement);
    record["sequence"] = serde_json::json!(index.sequence);
    record["prev_record_digest"] =
        predecessor.map_or(serde_json::Value::Null, |digest| serde_json::json!(digest));
    record["lead_id"] = serde_json::json!(index.lead_id);
    record["lead_revision"] = serde_json::json!(lead_revision);
    record["engagement_revision"] = serde_json::json!(1);
    record["run_id"] = serde_json::json!(index.run_id);
    record["experiment_digest"] = serde_json::json!(experiment);
    let bytes = crate::canonical::to_vec(&record).unwrap();
    (
        Artifact {
            artifact_id: index.record.artifact_id.clone(),
            digest: Sha256Digest::of(&bytes),
        },
        bytes,
    )
}

fn pending_cleanup() -> RunCleanup {
    RunCleanup {
        round: 1,
        object: CleanupObjectRole::Primary,
        plant_step: 3,
        plant_request_digest: Sha256Digest::of(b"plant"),
        object_id: None,
        ownership: CleanupOwnership::Pending,
        cleanup_step: None,
        cleanup_request_digest: None,
        flow_id_floor: None,
        instrument_reference: None,
        effects: None,
        response_status: None,
        flows: Vec::new(),
        outcome: CleanupObjectOutcome::Owed,
    }
}

fn metadata_candidate(
    store: &Store,
    run: &Run,
    lead: &LeadId,
) -> (PublicationIntentV1, Artifact, Vec<u8>) {
    let index = VerificationIndex {
        engagement: run.engagement.clone(),
        sequence: 1,
        record_id: VerificationId::generate(),
        run_id: run.id.clone(),
        lead_id: lead.clone(),
        record: artifact(),
    };
    let (artifact, bytes) = publication_candidate(store, &index, None);
    let intent = PublicationIntentV1 {
        schema: PublicationIntentV1Tag::PublicationIntentV1,
        intent_id: PublicationIntentId::generate(),
        engagement: run.engagement.clone(),
        run_id: run.id.clone(),
        record_id: index.record_id,
        record_digest: artifact.digest.clone(),
        expected_head: store.checkpoint(&run.engagement).unwrap().1,
        state: PublicationState::Pending,
        artifact_id: None,
    };
    (intent, artifact, bytes)
}

#[test]
fn metadata_receipts_cannot_mutate_execution_cleanup_or_publication() {
    use super::request_tests::seed_recoverable_verification;

    for command in ["verify", "other"] {
        let (_dir, mut store) = open();
        let scope = RequestScope::new("metadata".parse().unwrap(), "one".parse().unwrap());
        let (lead, _, _) = seed_recoverable_verification(&mut store, &scope);
        let input = Invocation::new(command, serde_json::json!({"lead_id": lead}))
            .normalize()
            .unwrap();
        let mut run = Run::declare(
            scope.engagement.clone(),
            Sha256Digest::of(b"metadata experiment"),
        );
        let accepted = if command == "verify" {
            let before = audit_state(&store);
            assert!(matches!(
                store.declare_request(&scope, &input, &run),
                Err(StoreError::Conflict)
            ));
            assert_eq!(audit_state(&store), before);
            // The verify replay comes from a receipt created before fencing.
            store
                .declare_metadata_fixture(&scope, &input, &run)
                .unwrap()
        } else {
            store.declare_request(&scope, &input, &run).unwrap()
        };
        let (intent, record, bytes) = metadata_candidate(&store, &run, &lead);
        let source = Artifact {
            artifact_id: "art_callers_experiment".parse().unwrap(),
            digest: run.experiment_digest.clone(),
        };
        let keys = BTreeSet::from(["resource:metadata".to_owned()]);
        let pending = pending_cleanup();
        let mut unknown = pending.clone();
        unknown.ownership = CleanupOwnership::Unknown;
        let mut established = pending.clone();
        established.ownership = CleanupOwnership::Established;
        established.object_id = Some("forged-object".parse().unwrap());
        let mut not_created = pending.clone();
        not_created.ownership = CleanupOwnership::NotCreated;
        not_created.outcome = CleanupObjectOutcome::NotRequired;
        let mut step = RunStep {
            number: 3,
            step: "round.1.P".parse().unwrap(),
            request_digest: pending.plant_request_digest.clone(),
            flow_id_floor: None,
            instrument_reference: None,
            effects: None,
            flows: Vec::new(),
        };
        let mut latest = accepted.receipt;
        for state in [RunState::Declared, RunState::Finalized] {
            if state == RunState::Finalized {
                run.state = state;
                run.flags.push(RunFlag::FailedBeforeStart);
                latest = store.record_run(&run, Some(latest)).unwrap();
            }
            let before = audit_state(&store);
            let mut fabricated = run.clone();
            fabricated.effects = Effect::Unknown;
            fabricated.oracle_result = Some(OracleResult::True);
            fabricated.reproduction = Reproduction::Reproduced;
            fabricated.cleanup = Cleanup::Unknown;
            fabricated.flags.push(RunFlag::ReconciliationRequired);
            let mut bundled = run.clone();
            bundled.steps.push(step.clone());
            let mut aliased = fabricated.clone();
            aliased.id = RunId::generate();
            aliased.state = RunState::Finalized;
            for (operation, refused) in [
                ("claim", store.claim_conflicts(&run.id, &keys).is_err()),
                ("step intent", store.record_step(&run.id, &step).is_err()),
                (
                    "step reconciliation",
                    store.reconcile_recorded_step(&run.id, &step).is_err(),
                ),
                ("rebound receipt", store.record_run(&aliased, None).is_err()),
                (
                    "bundled step",
                    store.record_run(&bundled, Some(latest)).is_err(),
                ),
                (
                    "fabricated summary",
                    store.record_run(&fabricated, Some(latest)).is_err(),
                ),
                (
                    "pending cleanup",
                    store.record_cleanup(&run.id, &pending).is_err(),
                ),
                (
                    "unknown cleanup",
                    store.record_cleanup(&run.id, &unknown).is_err(),
                ),
                (
                    "established cleanup",
                    store.record_cleanup(&run.id, &established).is_err(),
                ),
                (
                    "cleanup reconciliation",
                    store
                        .reconcile_recorded_cleanup(&run.id, &established)
                        .is_err(),
                ),
                (
                    "no cleanup outcome",
                    store.record_cleanup(&run.id, &not_created).is_err(),
                ),
                (
                    "experiment",
                    store.link_experiment(&run.id, &source).is_err(),
                ),
                (
                    "step originals",
                    store.link_step_originals(&run.id, &step).is_err(),
                ),
                (
                    "cleanup originals",
                    store.link_cleanup_originals(&run.id, &established).is_err(),
                ),
                (
                    "standalone staging",
                    store
                        .stage_publication_fixture(&intent, &bytes, std::slice::from_ref(&source))
                        .is_err(),
                ),
                (
                    "acquired staging",
                    store
                        .settle_and_stage_publication_fixture(
                            &accepted,
                            &fabricated,
                            &intent,
                            &bytes,
                            std::slice::from_ref(&source),
                        )
                        .is_err(),
                ),
                (
                    "completion",
                    store
                        .complete_publication_fixture(&intent.intent_id, &record, &bytes)
                        .is_err(),
                ),
            ] {
                assert!(refused, "{command} {state:?}: {operation}");
            }
            step.effects = Some(Effect::Observed);
            assert!(store.record_step(&run.id, &step).is_err());
            step.effects = None;
            assert_eq!(store.record_run(&run, Some(latest)).unwrap(), latest);
            store.release_unstarted_conflicts(&run.id).unwrap();
            let replay = store.declare_request(&scope, &input, &run).unwrap();
            assert_eq!(replay.receipt, accepted.receipt);
            assert_eq!(replay.run, run);
            assert_eq!(audit_state(&store), before);
            assert!(store.recover_cleanup(&run.id).unwrap().is_empty());
            assert!(!store.conflicts_held(&run.id).unwrap());
            assert!(
                store
                    .publication_for_reconciliation(&run.id)
                    .unwrap()
                    .is_none()
            );
            let counts: (i64, i64, i64) = store
                .db
                .query_row(
                    "SELECT (SELECT count(*) FROM publication_intents),
                        (SELECT count(*) FROM publication_candidates),
                        (SELECT count(*) FROM verifications)",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .unwrap();
            assert_eq!(counts, (0, 0, 0));
            assert_eq!(
                store.checkpoint(&scope.engagement).unwrap().1,
                intent.expected_head
            );
            let status = entry::read(&store.db, &scope.engagement).unwrap();
            assert_eq!(status.attention_runs, 0);
            assert!(status.attention.is_none());
        }

        // Re-open a pending candidate retained from before the fallback was
        // fenced. Visibility alone must never grant authority to resume it.
        store
            .db
            .execute(
                "INSERT INTO publication_intents
             (id, engagement_id, run_id, record_id, record_digest, expected_sequence,
              expected_digest, state, artifact_id, candidate_required)
             VALUES (?, ?, ?, ?, ?, 0, NULL, 'pending', NULL, 1)",
                params![
                    intent.intent_id.as_str(),
                    intent.engagement.as_str(),
                    run.id.as_str(),
                    intent.record_id.as_str(),
                    intent.record_digest.as_str()
                ],
            )
            .unwrap();
        store.db.execute(
            "INSERT INTO publication_candidates (intent_id, record_bytes, inputs) VALUES (?, ?, ?)",
            params![intent.intent_id.as_str(), bytes, encode_publication_inputs(std::slice::from_ref(&source)).unwrap()],
        ).unwrap();
        let before = audit_state(&store);
        assert_eq!(store.publication(&run.id).unwrap().as_ref(), Some(&intent));
        assert!(matches!(
            store.publication_for_reconciliation(&run.id),
            Err(StoreError::Conflict)
        ));
        assert!(matches!(
            store.stage_publication_fixture(&intent, &bytes, std::slice::from_ref(&source)),
            Err(StoreError::Conflict)
        ));
        assert!(matches!(
            store.complete_publication_fixture(&intent.intent_id, &record, &bytes),
            Err(StoreError::Conflict)
        ));
        assert_eq!(store.publication(&run.id).unwrap().as_ref(), Some(&intent));
        assert_eq!(
            store.checkpoint(&scope.engagement).unwrap().1,
            intent.expected_head
        );
        assert_eq!(audit_state(&store), before);
    }
}

#[test]
fn fenced_cleanup_can_reserve_before_plant_but_requires_observed_plant_for_authority() {
    use super::request_tests::{
        admit_verification, seed_recoverable_verification, verification_claim, verification_run,
    };
    let (_dir, mut store) = open();
    let scope = RequestScope::new("cleanup".parse().unwrap(), "one".parse().unwrap());
    let (lead, manifest, manifest_artifact) = seed_recoverable_verification(&mut store, &scope);
    let claim = verification_claim(&lead, &manifest);
    let run = verification_run(&scope.engagement, &claim, &manifest);
    let input = Invocation::new("verify", serde_json::json!({"lead_id": lead}))
        .normalize()
        .unwrap();
    admit_verification(
        &mut store,
        &scope,
        &input,
        &run,
        &claim,
        &manifest,
        &manifest_artifact,
    )
    .unwrap();
    let pending = pending_cleanup();
    assert!(matches!(
        store.record_cleanup(&run.id, &pending),
        Err(StoreError::Conflict)
    ));
    store
        .claim_conflicts(&run.id, &BTreeSet::from(["resource:cleanup".to_owned()]))
        .unwrap();
    assert_eq!(
        store.record_cleanup(&run.id, &pending).unwrap(),
        Cleanup::Unknown
    );
    let mut established = pending.clone();
    established.ownership = CleanupOwnership::Established;
    established.object_id = Some("selected-object".parse().unwrap());
    let before = audit_state(&store);
    assert!(matches!(
        store.record_cleanup(&run.id, &established),
        Err(StoreError::Conflict)
    ));
    assert_eq!(audit_state(&store), before);
    let mut plant = RunStep {
        number: 3,
        step: "round.1.P".parse().unwrap(),
        request_digest: pending.plant_request_digest.clone(),
        flow_id_floor: None,
        instrument_reference: None,
        effects: None,
        flows: Vec::new(),
    };
    store.record_step(&run.id, &plant).unwrap();
    assert!(matches!(
        store.record_cleanup(&run.id, &established),
        Err(StoreError::Conflict)
    ));
    plant.effects = Some(Effect::Observed);
    store.record_step(&run.id, &plant).unwrap();
    let mut wrong = established.clone();
    wrong.plant_request_digest = Sha256Digest::of(b"other plant");
    assert!(matches!(
        store.record_cleanup(&run.id, &wrong),
        Err(StoreError::Conflict)
    ));
    assert_eq!(
        store.record_cleanup(&run.id, &established).unwrap(),
        Cleanup::Unknown
    );
    assert_eq!(store.recover_cleanup(&run.id).unwrap(), [established]);
}

#[test]
fn a_linked_unkeyed_import_reserves_its_request_key_against_fresh_acceptance() {
    use super::request_tests::{
        admit_verification, seed_recoverable_verification, verification_claim, verification_run,
    };
    let (_dir, mut store) = open();
    let scope = RequestScope::new("reserved-key".parse().unwrap(), "one".parse().unwrap());
    let (lead, manifest, manifest_artifact) = seed_recoverable_verification(&mut store, &scope);
    let claim = verification_claim(&lead, &manifest);
    let mut imported = verification_run(&scope.engagement, &claim, &manifest);
    imported.state = RunState::Finalized;
    store.seed_historical_run_fixture(&imported).unwrap();
    let (intent, artifact, bytes) = metadata_candidate(&store, &imported, &lead);
    store
        .stage_publication_fixture(&intent, &bytes, std::slice::from_ref(&artifact))
        .unwrap();
    store
        .complete_publication_fixture(&intent.intent_id, &artifact, &bytes)
        .unwrap();
    let before = (
        audit_state(&store),
        store.checkpoint(&scope.engagement).unwrap(),
    );

    let mut alias = verification_run(&scope.engagement, &claim, &manifest);
    alias.request_key = imported.request_key.clone();
    let metadata = Invocation::new("other", serde_json::json!({}))
        .normalize()
        .unwrap();
    assert!(matches!(
        store.declare_request(&scope, &metadata, &alias),
        Err(StoreError::Conflict)
    ));
    let verify = Invocation::new("verify", serde_json::json!({"lead_id": lead}))
        .normalize()
        .unwrap();
    assert!(matches!(
        admit_verification(
            &mut store,
            &scope,
            &verify,
            &alias,
            &claim,
            &manifest,
            &manifest_artifact
        ),
        Err(crate::preflight::PreflightError::Store(
            StoreError::Conflict
        ))
    ));
    assert!(
        store
            .find_request(&scope, &alias.request_key)
            .unwrap()
            .is_none()
    );
    assert_eq!(store.recover_run(&imported.id).unwrap(), imported);
    assert_eq!(
        (
            audit_state(&store),
            store.checkpoint(&scope.engagement).unwrap()
        ),
        before
    );
}

fn publish_test_record(
    store: &mut Store,
    run: &Run,
    lead: &LeadRevision,
    artifact_id: &str,
) -> PublicationReceipt {
    let (intent, index, bytes) = stage_test_record(store, run, lead, artifact_id);
    store
        .complete_publication_fixture(&intent.intent_id, &index.record, &bytes)
        .unwrap()
}

fn stage_test_record(
    store: &mut Store,
    run: &Run,
    lead: &LeadRevision,
    artifact_id: &str,
) -> (PublicationIntentV1, VerificationIndex, Vec<u8>) {
    let head = store.checkpoint(&run.engagement).unwrap().1;
    let mut index = VerificationIndex {
        engagement: run.engagement.clone(),
        sequence: head.sequence + 1,
        record_id: VerificationId::generate(),
        run_id: run.id.clone(),
        lead_id: lead.lead_id.clone(),
        record: Artifact {
            artifact_id: artifact_id.parse().unwrap(),
            digest: Sha256Digest::of(b"placeholder"),
        },
    };
    let (record, bytes) = publication_candidate(store, &index, head.record_digest.as_ref());
    index.record = record;
    let intent = PublicationIntentV1 {
        schema: crate::wire::PublicationIntentV1Tag::PublicationIntentV1,
        intent_id: PublicationIntentId::generate(),
        engagement: run.engagement.clone(),
        run_id: run.id.clone(),
        record_id: index.record_id.clone(),
        record_digest: index.record.digest.clone(),
        expected_head: head,
        state: crate::wire::PublicationState::Pending,
        artifact_id: None,
    };
    store
        .stage_publication_fixture(&intent, &bytes, std::slice::from_ref(&artifact()))
        .unwrap();
    (intent, index, bytes)
}

fn audit_state(s: &Store) -> (u64, i64) {
    (
        s.revision().unwrap(),
        s.db.query_row("SELECT count(*) FROM audit_events", [], |r| r.get(0))
            .unwrap(),
    )
}

struct AcquiredPublication {
    acceptance: RunAcceptance,
    run: Run,
    intent: PublicationIntentV1,
    record: VerificationV1,
    inputs: Vec<Artifact>,
}

impl AcquiredPublication {
    fn stage(&self, store: &mut Store) -> Result<u64> {
        let bytes = crate::wire::to_vec(&self.record).unwrap();
        let mut intent = self.intent.clone();
        intent.record_digest = Sha256Digest::of(&bytes);
        store.settle_and_stage_publication_fixture(
            &self.acceptance,
            &self.run,
            &intent,
            &bytes,
            &self.inputs,
        )
    }
}

fn acquired_publication(store: &mut Store, effect: Effect) -> AcquiredPublication {
    acquired_publication_with_cleanup(store, effect, false)
}

fn acquired_publication_with_cleanup(
    store: &mut Store,
    effect: Effect,
    leave_cleanup_pending: bool,
) -> AcquiredPublication {
    use super::request_tests::{
        admit_verification, verification_claim, verification_lead_revision, verification_run,
    };

    let asset = artifact();
    let engagement = "local".parse().unwrap();
    let draft = crate::engagement::EngagementDraft::parse_toml(include_bytes!(
        "../../../../fixtures/target/schema-examples/engagement.toml"
    ))
    .unwrap();
    let pass_ref = draft.settings().pass_ref.clone();
    let manifest = draft
        .accept(crate::engagement::PassPin {
            reference: &pass_ref,
            digest: &asset.digest,
        })
        .unwrap();
    let manifest_artifact = Artifact {
        artifact_id: "art_manifest".parse().unwrap(),
        digest: manifest.digest().clone(),
    };
    store
        .append_manifest(&engagement, &manifest_artifact, manifest.pass_digest())
        .unwrap();
    let lead_id = LeadId::generate();
    let lead = verification_lead_revision(&lead_id, 1, "acquired publication", &manifest);
    store.append_lead_revision(&engagement, &lead).unwrap();
    let input = Invocation::new(
        "verify",
        serde_json::json!({"lead_id": lead.lead_id, "lead_revision": 1, "rounds": 1}),
    )
    .normalize()
    .unwrap();
    let claim = verification_claim(&lead.lead_id, &manifest);
    let run = verification_run(&engagement, &claim, &manifest);
    let asset = Artifact {
        digest: run.experiment_digest.clone(),
        ..asset
    };
    let scope = RequestScope::new(engagement, "primary".parse().unwrap());
    let acceptance = admit_verification(
        store,
        &scope,
        &input,
        &run,
        &claim,
        &manifest,
        &manifest_artifact,
    )
    .unwrap();
    store
        .claim_conflicts(
            &run.id,
            &BTreeSet::from(["resource:publication".to_owned()]),
        )
        .unwrap();
    store.link_experiment(&run.id, &asset).unwrap();
    let (_, expected_head) = store.checkpoint(&run.engagement).unwrap();
    let index = VerificationIndex {
        engagement: run.engagement.clone(),
        sequence: 1,
        record_id: VerificationId::generate(),
        run_id: run.id.clone(),
        lead_id: lead.lead_id,
        record: asset.clone(),
    };
    let (_, bytes) = publication_candidate(store, &index, None);
    let mut record: VerificationV1 = crate::wire::from_slice(&bytes).unwrap();
    record.lead_revision = acceptance.lead_revision.unwrap();
    record.cleanup = if leave_cleanup_pending {
        let mut cleanup = pending_cleanup();
        cleanup.plant_request_digest = asset.digest.clone();
        store.record_cleanup(&run.id, &cleanup).unwrap()
    } else {
        Cleanup::NotRequired
    };
    let flow = record.rounds[0].flows[0].clone();
    for (index, contract) in crate::rounds::RoundFlow::REQUIRED.into_iter().enumerate() {
        let mut step = RunStep {
            number: index as u64 + 1,
            step: format!("round.1.{}", contract.as_str()).try_into().unwrap(),
            request_digest: asset.digest.clone(),
            flow_id_floor: Some(0),
            instrument_reference: None,
            effects: None,
            flows: Vec::new(),
        };
        store.record_step(&run.id, &step).unwrap();
        if contract == crate::rounds::RoundFlow::F2 {
            step.flows.push(Flow {
                original: None,
                decoder: None,
                ..flow.clone()
            });
            step.effects = Some(effect);
            store.record_step(&run.id, &step).unwrap();
            step.flows[0].original = flow.original.clone();
            store.link_step_originals(&run.id, &step).unwrap();
        } else {
            step.effects = Some(Effect::None);
            store.record_step(&run.id, &step).unwrap();
        }
    }
    let bytes = crate::wire::to_vec(&record).unwrap();
    let run = store.recover_run(&run.id).unwrap();
    let intent = PublicationIntentV1 {
        schema: PublicationIntentV1Tag::PublicationIntentV1,
        intent_id: PublicationIntentId::generate(),
        engagement: run.engagement.clone(),
        run_id: run.id.clone(),
        record_id: record.record_id.clone(),
        record_digest: Sha256Digest::of(&bytes),
        expected_head,
        state: PublicationState::Pending,
        artifact_id: None,
    };
    let inputs = record.lineage_inputs(&asset).unwrap();
    AcquiredPublication {
        acceptance,
        run,
        intent,
        record,
        inputs,
    }
}

#[test]
fn settle_and_stage_publication_recovers_one_intent_and_link() {
    let (dir, mut store) = open();
    let acquisition = acquired_publication(&mut store, Effect::Observed);
    let (run, intent) = (&acquisition.run, &acquisition.intent);
    assert_eq!(run.state, RunState::Declared);
    assert!(store.conflicts_held(&run.id).unwrap());
    let previous = audit_state(&store);
    let staged_revision = acquisition.stage(&mut store).unwrap();
    assert_eq!(staged_revision, previous.0 + 2);
    drop(store);

    let mut reopened = Store::open(dir.path().join("state.sqlite3")).unwrap();
    let settled = reopened.recover_run(&run.id).unwrap();
    assert_eq!(settled.state, RunState::Finalized);
    assert_eq!(settled.oracle_result, Some(acquisition.record.result));
    assert_eq!(settled.reproduction, acquisition.record.reproduction);
    assert_eq!(settled.cleanup, acquisition.record.cleanup);
    assert_eq!(settled.effects, acquisition.record.effects);
    assert_eq!(settled.steps, run.steps);
    assert!(!reopened.conflicts_held(&run.id).unwrap());
    assert!(matches!(
        reopened.record_run(run, Some(acquisition.acceptance.receipt)),
        Err(StoreError::Conflict)
    ));
    assert_eq!(
        reopened.publication(&run.id).unwrap().as_ref(),
        Some(intent)
    );
    assert_eq!(reopened.checkpoint(&run.engagement).unwrap().1.sequence, 0);

    let staged = reopened.staged_publication(intent).unwrap().unwrap();
    assert_eq!(staged.inputs, acquisition.inputs);
    let artifact = Artifact {
        artifact_id: "art_acquired_record".parse().unwrap(),
        digest: intent.record_digest.clone(),
    };
    let linked = reopened
        .complete_publication_fixture(&intent.intent_id, &artifact, &staged.record_bytes)
        .unwrap();
    let after = audit_state(&reopened);
    assert_eq!(acquisition.stage(&mut reopened).unwrap(), staged_revision);
    assert_eq!(
        reopened
            .complete_publication_fixture(&intent.intent_id, &artifact, &staged.record_bytes)
            .unwrap(),
        linked
    );
    assert_eq!(after, (staged_revision + 1, previous.1 + 3));
    assert_eq!(audit_state(&reopened), after);
    assert_eq!(reopened.checkpoint(&run.engagement).unwrap().1.sequence, 1);
}

#[test]
fn pending_publication_keeps_its_snapshot_after_cleanup_advances() {
    let (dir, mut store) = open();
    let acquisition = acquired_publication_with_cleanup(&mut store, Effect::Observed, true);
    let intent = &acquisition.intent;
    let run = &intent.run_id;
    assert_eq!(acquisition.record.cleanup, Cleanup::Unknown);
    let staged_revision = acquisition.stage(&mut store).unwrap();
    let mut cleanup = store.recover_cleanup(run).unwrap().remove(0);
    cleanup.ownership = CleanupOwnership::NotCreated;
    cleanup.outcome = CleanupObjectOutcome::NotRequired;
    assert_eq!(
        store.reconcile_recorded_cleanup(run, &cleanup).unwrap(),
        Cleanup::NotRequired
    );
    drop(store);
    let mut reopened = Store::open(dir.path().join("state.sqlite3")).unwrap();
    assert_eq!(acquisition.stage(&mut reopened).unwrap(), staged_revision);
    assert_eq!(
        reopened
            .publication_for_reconciliation(run)
            .unwrap()
            .as_ref(),
        Some(intent)
    );
    let staged = reopened.staged_publication(intent).unwrap().unwrap();
    let artifact = Artifact {
        artifact_id: "art_snapshot_cleanup".parse().unwrap(),
        digest: intent.record_digest.clone(),
    };
    reopened
        .complete_publication_fixture(&intent.intent_id, &artifact, &staged.record_bytes)
        .unwrap();
    assert_eq!(
        reopened.recover_run(run).unwrap().cleanup,
        Cleanup::NotRequired
    );
    assert_eq!(reopened.recover_cleanup(run).unwrap(), [cleanup]);
    assert_eq!(
        decode_publication_record(intent, &staged.record_bytes)
            .unwrap()
            .cleanup,
        Cleanup::Unknown
    );
}

#[test]
fn only_the_acquired_candidate_may_replace_a_superseded_intent() {
    for (generic, unrelated) in [(false, false), (false, true), (true, false), (true, true)] {
        let (_dir, mut store) = open();
        let mut acquisition = acquired_publication(&mut store, Effect::Observed);
        acquisition.stage(&mut store).unwrap();
        let old = acquisition.intent.clone();
        let old_bytes = crate::wire::to_vec(&acquisition.record).unwrap();
        let artifact = Artifact {
            artifact_id: "art_old_intent".parse().unwrap(),
            digest: old.record_digest.clone(),
        };
        let mut other = Run::declare(old.engagement.clone(), Sha256Digest::of(b"unkeyed head"));
        other.state = RunState::Finalized;
        store.seed_historical_run_fixture(&other).unwrap();
        let (head_intent, head_artifact, head_bytes) =
            metadata_candidate(&store, &other, &acquisition.record.lead_id);
        store
            .stage_publication_fixture(
                &head_intent,
                &head_bytes,
                std::slice::from_ref(&head_artifact),
            )
            .unwrap();
        store
            .complete_publication_fixture(&head_intent.intent_id, &head_artifact, &head_bytes)
            .unwrap();
        assert!(matches!(
            store.complete_publication_fixture(&old.intent_id, &artifact, &old_bytes),
            Err(StoreError::HeadMoved)
        ));

        let head = store.checkpoint(&old.engagement).unwrap().1;
        acquisition.record.record_id = VerificationId::generate();
        acquisition.record.run_nonce = acquisition
            .record
            .record_id
            .as_str()
            .strip_prefix("V-")
            .unwrap()
            .parse()
            .unwrap();
        acquisition.record.sequence = head.sequence + 1;
        acquisition.record.prev_record_digest = head.record_digest.clone();
        acquisition.intent.intent_id = PublicationIntentId::generate();
        acquisition.intent.record_id = acquisition.record.record_id.clone();
        acquisition.intent.expected_head = head.clone();
        if unrelated {
            acquisition
                .record
                .limitations
                .push("unrelated candidate".parse().unwrap());
        }
        let bytes = crate::wire::to_vec(&acquisition.record).unwrap();
        acquisition.intent.record_digest = Sha256Digest::of(&bytes);
        let intent = &acquisition.intent;
        if unrelated && !generic {
            let before = audit_state(&store);
            assert!(matches!(
                acquisition.stage(&mut store),
                Err(StoreError::Conflict)
            ));
            assert!(store.publication(&intent.run_id).unwrap().is_none());
            assert_eq!(audit_state(&store), before);
            continue;
        }
        if generic {
            // The predecessor emitted a generic stage audit even for an
            // acquired rebuild. Direct completion cannot tell this apart
            // from its standalone fallback.
            let tx = store.db.transaction().unwrap();
            tx.execute(
                "INSERT INTO publication_intents (id, engagement_id, run_id, record_id, record_digest,
                 expected_sequence, expected_digest, state, artifact_id, candidate_required)
                 VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', NULL, 1)",
                params![
                    intent.intent_id.as_str(), intent.engagement.as_str(), intent.run_id.as_str(),
                    intent.record_id.as_str(), intent.record_digest.as_str(), integer(head.sequence).unwrap(),
                    head.record_digest.as_ref().map(Sha256Digest::as_str),
                ],
            ).unwrap();
            tx.execute(
                "INSERT INTO publication_candidates (intent_id, record_bytes, inputs) VALUES (?, ?, ?)",
                params![intent.intent_id.as_str(), bytes, encode_publication_inputs(&acquisition.inputs).unwrap()],
            ).unwrap();
            commit(tx, PUBLICATION_INTENT, intent.intent_id.as_str()).unwrap();
        } else {
            acquisition.stage(&mut store).unwrap();
            assert_eq!(
                store
                    .publication_for_reconciliation(&intent.run_id)
                    .unwrap()
                    .as_ref(),
                Some(intent)
            );
        }
        let before = audit_state(&store);
        let artifact = Artifact {
            artifact_id: "art_replacement".parse().unwrap(),
            digest: intent.record_digest.clone(),
        };
        let result = store.complete_publication_fixture(&intent.intent_id, &artifact, &bytes);
        if generic {
            assert!(matches!(result, Err(StoreError::Conflict)));
            assert!(matches!(
                store.publication_for_reconciliation(&intent.run_id),
                Err(StoreError::Conflict)
            ));
            assert_eq!(store.checkpoint(&intent.engagement).unwrap().1, head);
            assert_eq!(audit_state(&store), before);
        } else {
            assert_eq!(result.unwrap().index.sequence, 2);
            assert_eq!(store.checkpoint(&intent.engagement).unwrap().1.sequence, 2);
        }
    }
}

#[test]
fn settle_and_stage_publication_refuses_stale_or_mismatched_material() {
    let (_dir, mut store) = open();
    let mut acquisition = acquired_publication(&mut store, Effect::Observed);
    let before = audit_state(&store);
    let receipt = acquisition.acceptance.receipt;
    acquisition.acceptance.receipt += 1;
    assert!(matches!(
        acquisition.stage(&mut store),
        Err(StoreError::Conflict)
    ));
    acquisition.acceptance.receipt = receipt;
    acquisition.record.lead_revision += 1;
    assert!(matches!(
        acquisition.stage(&mut store),
        Err(StoreError::Conflict)
    ));
    acquisition.record.lead_revision -= 1;
    acquisition.record.record_id = VerificationId::generate();
    assert!(matches!(
        acquisition.stage(&mut store),
        Err(StoreError::Integrity)
    ));
    acquisition.record.record_id = acquisition.intent.record_id.clone();
    assert_eq!(audit_state(&store), before);
    assert_eq!(
        store.recover_run(&acquisition.run.id).unwrap(),
        acquisition.run
    );
    assert!(store.publication(&acquisition.run.id).unwrap().is_none());
    assert!(store.conflicts_held(&acquisition.run.id).unwrap());

    // An intervening metadata CAS invalidates the original receipt even
    // when the current snapshot still has identical fields and steps.
    store.record_run(&acquisition.run, Some(receipt)).unwrap();
    let before = audit_state(&store);
    assert!(matches!(
        acquisition.stage(&mut store),
        Err(StoreError::Conflict)
    ));
    assert_eq!(audit_state(&store), before);
    assert_eq!(
        store.recover_run(&acquisition.run.id).unwrap(),
        acquisition.run
    );
    assert!(store.publication(&acquisition.run.id).unwrap().is_none());
    assert!(store.conflicts_held(&acquisition.run.id).unwrap());
}

#[test]
fn settle_and_stage_publication_refuses_unknown_step_effects() {
    let (_dir, mut store) = open();
    let acquisition = acquired_publication(&mut store, Effect::Unknown);
    let before = audit_state(&store);
    assert!(matches!(
        acquisition.stage(&mut store),
        Err(StoreError::Conflict)
    ));
    assert_eq!(audit_state(&store), before);
    assert_eq!(
        store.recover_run(&acquisition.run.id).unwrap(),
        acquisition.run
    );
    assert!(store.publication(&acquisition.run.id).unwrap().is_none());
    assert!(store.conflicts_held(&acquisition.run.id).unwrap());
}

#[test]
fn settle_and_stage_publication_requires_exact_ordered_record_lineage() {
    let (_dir, mut store) = open();
    let mut acquisition = acquired_publication(&mut store, Effect::Observed);
    let expected = acquisition.inputs.clone();
    assert_eq!(
        expected
            .iter()
            .map(|artifact| artifact.artifact_id.as_str())
            .collect::<Vec<_>>(),
        [
            "pass-after",
            "plan",
            "debit",
            "flow-index",
            "edit-surface-end",
            "edit-surface-start",
            "flow-17",
            "flow-16",
            "a1",
        ]
    );
    let mut extra = expected.clone();
    extra.push(Artifact {
        artifact_id: "unlinked".parse().unwrap(),
        digest: Sha256Digest::of(b"unlinked"),
    });
    let mut missing_edit_surface = expected.clone();
    missing_edit_surface.remove(4);
    let mut duplicate = expected.clone();
    duplicate.push(expected[1].clone());
    let mut swapped_digest = expected.clone();
    swapped_digest[0].digest = expected[1].digest.clone();
    let mut substituted_artifact_id = expected.clone();
    substituted_artifact_id[8].artifact_id = "different-experiment".parse().unwrap();
    let mut reordered = expected.clone();
    reordered.swap(0, 1);

    let before = audit_state(&store);
    let checkpoint = store.checkpoint(&acquisition.run.engagement).unwrap();
    for (reason, wrong) in [
        ("extra input", extra),
        ("omitted edit-surface input", missing_edit_surface),
        ("duplicate input", duplicate),
        ("swapped accounting digest", swapped_digest),
        (
            "substituted experiment artifact identity",
            substituted_artifact_id,
        ),
        ("reordered inputs", reordered),
    ] {
        acquisition.inputs = wrong;
        assert!(
            matches!(
                acquisition.stage(&mut store),
                Err(StoreError::Conflict | StoreError::Integrity)
            ),
            "{reason} must be refused"
        );
        assert_eq!(audit_state(&store), before, "{reason}");
        assert_eq!(
            store.recover_run(&acquisition.run.id).unwrap(),
            acquisition.run,
            "{reason}"
        );
        assert!(
            store.conflicts_held(&acquisition.run.id).unwrap(),
            "{reason}"
        );
        assert!(
            store.publication(&acquisition.run.id).unwrap().is_none(),
            "{reason}"
        );
        assert!(
            matches!(
                store.staged_publication(&acquisition.intent),
                Err(StoreError::SelectorNotFound)
            ),
            "{reason}"
        );
        assert_eq!(
            store.checkpoint(&acquisition.run.engagement).unwrap(),
            checkpoint,
            "{reason}"
        );
    }

    acquisition.inputs = expected;
    assert!(acquisition.stage(&mut store).is_ok());
}

#[test]
fn stale_writer_cannot_overwrite_run_outcomes_or_clear_a_finalized_run() {
    let (dir, mut writer) = open();
    let mut other = Store::open(dir.path().join("state.sqlite3")).unwrap();
    let (original, declared) = declared_run(&mut writer);
    let mut finalized = original.clone();
    finalized.state = RunState::Finalized;
    finalized.flags.push(RunFlag::ReconciliationRequired);
    finalized.effects = Effect::Unknown;
    finalized.cleanup = Cleanup::Failed;
    let latest = writer.record_run(&finalized, Some(declared)).unwrap();
    let before = audit_state(&other);
    for revision in [None, Some(declared)] {
        assert!(matches!(
            other.record_run(&original, revision),
            Err(StoreError::Conflict)
        ));
    }
    // A stale update at the same state is still stale: flags/effects/cleanup
    // can change while the run remains finalized.
    let mut resolved = finalized.clone();
    resolved.cleanup = Cleanup::Complete;
    assert!(matches!(
        other.record_run(&resolved, Some(declared)),
        Err(StoreError::Conflict)
    ));
    assert_eq!(audit_state(&writer), before);
    let stored: (String, String, String, String) = other
        .db
        .query_row(
            "SELECT state,flags,effects,cleanup FROM runs WHERE id=?",
            [original.id.as_str()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .unwrap();
    assert_eq!(
        stored,
        (
            "finalized".into(),
            r#"["reconciliation_required"]"#.into(),
            "unknown".into(),
            "failed".into()
        )
    );
    assert_eq!(
        other.record_run(&resolved, Some(latest)).unwrap(),
        latest + 1
    );
}

#[test]
fn acquired_step_receipts_survive_stale_and_conflicting_writes_through_both_paths() {
    let (_dir, mut s) = open();
    let (run, declared) = declared_run(&mut s);
    let pending = RunStep {
        number: 1,
        step: "receipt".parse().unwrap(),
        request_digest: artifact().digest,
        flow_id_floor: Some(7),
        instrument_reference: None,
        effects: None,
        flows: vec![],
    };
    s.record_step(&run.id, &pending).unwrap();
    let mut prelinked = pending.clone();
    prelinked.flows.push(
        serde_json::from_value(serde_json::json!({
            "step": "receipt", "flow_id": 8, "original": artifact(),
            "completeness": "complete", "decoder": null
        }))
        .unwrap(),
    );
    assert!(s.record_step(&run.id, &prelinked).is_err());
    let mut acquired = pending.clone();
    acquired.instrument_reference = Some("local-receipt".parse().unwrap());
    acquired.effects = Some(Effect::Observed);
    acquired.flows.push(serde_json::from_value(serde_json::json!({
        "step": "receipt", "flow_id": 8, "original": null, "completeness": "complete", "decoder": null
    })).unwrap());
    s.record_step(&run.id, &acquired).unwrap();
    let mut open_non_cleanup = RunStep {
        number: 2,
        step: "receipt.open".parse().unwrap(),
        request_digest: artifact().digest,
        flow_id_floor: Some(7),
        instrument_reference: None,
        effects: None,
        flows: acquired.flows.clone(),
    };
    s.record_step(&run.id, &open_non_cleanup).unwrap();
    open_non_cleanup.flows.push(
        serde_json::from_value(serde_json::json!({
            "step": "receipt", "flow_id": 9, "original": null,
            "completeness": "complete", "decoder": null
        }))
        .unwrap(),
    );
    assert!(s.record_step(&run.id, &open_non_cleanup).is_err());
    let before = audit_state(&s);
    let mut appended_after_settlement = acquired.clone();
    appended_after_settlement.flows.push(
        serde_json::from_value(serde_json::json!({
            "step": "receipt", "flow_id": 9, "original": artifact(),
            "completeness": "complete", "decoder": null
        }))
        .unwrap(),
    );
    assert!(s.record_step(&run.id, &appended_after_settlement).is_err());
    appended_after_settlement.flows[1].original = None;
    assert!(s.record_step(&run.id, &appended_after_settlement).is_err());
    let mut changed_reference = acquired.clone();
    changed_reference.instrument_reference = Some("other".parse().unwrap());
    let mut changed_effect = acquired.clone();
    changed_effect.effects = Some(Effect::None);
    let mut changed_flow = acquired.clone();
    changed_flow.flows[0].flow_id = Some(9);
    for conflict in [pending, changed_reference, changed_effect, changed_flow] {
        assert!(matches!(
            s.record_step(&run.id, &conflict),
            Err(StoreError::Conflict)
        ));
        let mut bundled = run.clone();
        bundled.cleanup = Cleanup::Failed;
        bundled.steps.push(conflict);
        assert!(matches!(
            s.record_run(&bundled, Some(declared)),
            Err(StoreError::Conflict)
        ));
        assert_eq!(audit_state(&s), before);
    }
    let receipt: (String,String,String,String) = s.db.query_row(
        "SELECT instrument_reference,s.effects,flow_refs,cleanup FROM run_steps s JOIN runs r ON r.id=s.run_id
         WHERE run_id=? AND number='1'", [run.id.as_str()],
        |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)),
    ).unwrap();
    assert_eq!(
        receipt,
        (
            "local-receipt".into(),
            "observed".into(),
            json(&acquired.flows).unwrap(),
            "not_required".into()
        )
    );
}

#[test]
fn unknown_effects_can_settle_once_through_either_write_path() {
    for bundled in [false, true] {
        for (outcome, contrary) in [
            (Effect::Observed, Effect::None),
            (Effect::None, Effect::Observed),
        ] {
            let (_dir, mut store) = open();
            let (run, declared) = declared_run(&mut store);
            let mut step = RunStep {
                number: 1,
                step: "receipt".parse().unwrap(),
                request_digest: artifact().digest,
                flow_id_floor: Some(7),
                instrument_reference: Some("bound-receipt".parse().unwrap()),
                effects: Some(Effect::Unknown),
                flows: vec![],
            };
            store.record_step(&run.id, &step).unwrap();
            let write = |store: &mut Store, step: &RunStep, run_revision| {
                if bundled {
                    let mut update = run.clone();
                    update.steps.push(step.clone());
                    store.record_run(&update, Some(run_revision))
                } else {
                    store.record_step(&run.id, step)
                }
            };
            let before = audit_state(&store);
            step.effects = Some(outcome);
            let mut other_receipt = step.clone();
            other_receipt.instrument_reference = Some("other".parse().unwrap());
            assert!(matches!(
                write(&mut store, &other_receipt, declared),
                Err(StoreError::Conflict)
            ));
            assert_eq!(audit_state(&store), before);

            let committed = write(&mut store, &step, declared).unwrap();
            assert_eq!(committed, before.0 + 1);
            let settled = (committed, before.1 + 1);
            assert_eq!(audit_state(&store), settled);
            for invalid in [None, Some(Effect::Unknown), Some(contrary)] {
                step.effects = invalid;
                assert!(matches!(
                    write(&mut store, &step, committed),
                    Err(StoreError::Conflict)
                ));
                assert_eq!(audit_state(&store), settled);
            }
            let (reference, stored, operation): (String, String, String) = store
                .db
                .query_row(
                    "SELECT instrument_reference, effects, operation FROM run_steps, audit_events
                 WHERE run_id=? AND number='1' AND revision=?",
                    params![run.id.as_str(), integer(committed).unwrap()],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .unwrap();
            assert_eq!(reference, "bound-receipt");
            assert_eq!(stored, tag(outcome).unwrap());
            assert_eq!(operation, if bundled { "run.record" } else { "run.step" });
        }
    }
}

#[test]
fn publication_retry_returns_original_receipt_after_reopen_and_later_head_advance() {
    let (dir, mut s) = open();
    let (run, declared) = declared_run(&mut s);
    let run = finalize_run(&mut s, &run, declared);
    let engagement = run.engagement.clone();
    let lead = LeadRevision {
        lead_id: LeadId::generate(),
        revision: 1,
        text: "local".parse().unwrap(),
        class: None,
        property: None,
        slots: Default::default(),
        proposed_policy: None,
        origin: crate::domain::LeadOrigin::Local,
        source_ref: None,
        endpoint: None,
        flow_ids: Vec::new(),
        producer_confidence: None,
    };
    s.append_lead_revision(&engagement, &lead).unwrap();
    let mut first = None;
    for sequence in [1, 2] {
        let run_id = if sequence == 1 {
            run.id.clone()
        } else {
            let next = Run::declare(engagement.clone(), artifact().digest);
            let revision = s.seed_historical_run_fixture(&next).unwrap();
            finalize_run(&mut s, &next, revision).id
        };
        let expected_head = s.checkpoint(&engagement).unwrap().1;
        let mut index = VerificationIndex {
            engagement: engagement.clone(),
            sequence,
            record_id: VerificationId::generate(),
            run_id,
            lead_id: lead.lead_id.clone(),
            record: Artifact {
                artifact_id: format!("a{sequence}").parse().unwrap(),
                digest: Sha256Digest::of(b"placeholder"),
            },
        };
        let (record, bytes) =
            publication_candidate(&s, &index, expected_head.record_digest.as_ref());
        index.record = record;
        let intent: PublicationIntentV1 = serde_json::from_value(serde_json::json!({
            "schema": "scourge.publication-intent.v1", "intent_id": PublicationIntentId::generate(), "engagement": engagement,
            "run_id": index.run_id, "record_id": index.record_id, "record_digest": index.record.digest,
            "expected_head": expected_head, "state": "pending", "artifact_id": null
        })).unwrap();
        s.stage_publication_fixture(&intent, &bytes, std::slice::from_ref(&artifact()))
            .unwrap();
        let receipt = s
            .complete_publication_fixture(&intent.intent_id, &index.record, &bytes)
            .unwrap()
            .revision;
        if sequence == 1 {
            first = Some((intent.intent_id, index, bytes, receipt));
        }
    }
    let latest = s.checkpoint(&engagement).unwrap();
    let before = audit_state(&s);
    drop(s);
    let mut reopened = Store::open(dir.path().join("state.sqlite3")).unwrap();
    let (intent, index, bytes, original) = first.unwrap();
    assert_eq!(
        reopened
            .complete_publication_fixture(&intent, &index.record, &bytes)
            .unwrap()
            .revision,
        original
    );
    assert!(original < latest.0);
    let mut conflict = index;
    conflict.record.artifact_id = "other".parse().unwrap();
    assert!(matches!(
        reopened.complete_publication_fixture(&intent, &conflict.record, &bytes),
        Err(StoreError::Integrity)
    ));
    assert_eq!(latest.1.sequence, 2);
    assert_eq!(reopened.checkpoint(&engagement).unwrap(), latest);
    assert_eq!(audit_state(&reopened), before);
}

#[test]
fn exact_table_and_column_whitelist() {
    let (_dir, store) = open();
    let expected = [
        ("audit_events", "revision operation subject recorded_at"),
        (
            "engagement_revisions",
            "engagement_id revision manifest_artifact_id manifest_digest pass_digest",
        ),
        ("engagement_stops", "engagement_id stopped_revision"),
        ("engagements", "id head_sequence head_digest"),
        (
            "lead_events",
            "id lead_id lead_revision kind actor reason evidence_refs recorded_at",
        ),
        ("lead_imports", "engagement_id source_ref lead_id"),
        (
            "lead_revisions",
            "lead_id revision text class slots proposed_policy property origin source_ref endpoint flow_ids producer_confidence",
        ),
        ("leads", "id engagement_id"),
        ("legacy_keyed_runs", "run_id"),
        (
            "publication_candidates",
            "intent_id record_bytes inputs evidence_case_id",
        ),
        (
            "publication_intents",
            "id engagement_id run_id record_id record_digest expected_sequence expected_digest state artifact_id candidate_required",
        ),
        (
            "recorded_checks",
            "engagement_id stage observed_at code native_exit wrapper_exit run_id",
        ),
        (
            "request_keys",
            "key engagement_id binding command input input_digest run_id receipt_revision lead_id lead_revision engagement_revision",
        ),
        (
            "run_cleanup",
            "run_id round object plant_step plant_request_digest object_id ownership cleanup_step cleanup_request_digest flow_id_floor instrument_reference effects response_status flow_refs outcome",
        ),
        ("run_conflict_sets", "run_id set_digest claim_kind"),
        ("run_conflicts", "conflict_key run_id"),
        (
            "run_pre_dispatch_refusals",
            "receipt_digest reference run_id request_key step_number step request_digest action_index argv_digest instrument_digest target_digest lookup_digest source_commit binary_digest engine_instance project_id reason capture_handle attachment_key attachment_position attachment_request_digest artifact_id artifact_digest authority_original",
        ),
        (
            "run_recovery",
            "run_id request_key input_digest capture_handle trusted_evidence",
        ),
        (
            "run_steps",
            "run_id number step request_digest flow_id_floor instrument_reference effects flow_refs",
        ),
        (
            "runs",
            "id engagement_id request_key experiment_digest state flags effects oracle_result reproduction cleanup experiment_artifact_id",
        ),
        ("store_revision", "singleton revision"),
        ("store_workspace", "singleton workspace_id"),
        (
            "teapot_entry_observations",
            "engagement_id route_digest observation",
        ),
        (
            "verifications",
            "record_id engagement_id sequence run_id lead_id artifact_id record_digest intent_id",
        ),
    ];
    let mut tables = store
        .db
        .prepare(
            "SELECT s.name, group_concat(c.name, ' ' ORDER BY c.cid)
         FROM sqlite_schema s JOIN pragma_table_xinfo(s.name) c
         WHERE s.type IN ('table', 'view') AND s.name NOT GLOB 'sqlite_*'
         GROUP BY s.name ORDER BY s.name",
        )
        .unwrap();
    let actual = tables
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    assert_eq!(actual, expected.map(|(t, c)| (t.to_owned(), c.to_owned())));
}

#[test]
fn every_new_staged_payload_is_typed_immutable_and_required_across_reopen() {
    fn setup(store: &mut Store) -> (Run, LeadRevision) {
        let (run, revision) = declared_run(store);
        let run = finalize_run(store, &run, revision);
        let lead = LeadRevision {
            lead_id: LeadId::generate(),
            revision: 1,
            text: "staging integrity witness".parse().unwrap(),
            class: None,
            property: None,
            slots: Default::default(),
            proposed_policy: None,
            origin: crate::domain::LeadOrigin::Local,
            source_ref: None,
            endpoint: None,
            flow_ids: Vec::new(),
            producer_confidence: None,
        };
        store.append_lead_revision(&run.engagement, &lead).unwrap();
        (run, lead)
    }

    // Completed staging stays immutable and authoritative enough that a raw,
    // non-canonical lineage payload makes the next open fail closed too.
    let (complete_dir, mut complete) = open();
    let complete_path = complete_dir.path().join("state.sqlite3");
    let (run, lead) = setup(&mut complete);
    publish_test_record(&mut complete, &run, &lead, "art_staged_complete");
    assert!(
        complete
            .db
            .execute("UPDATE publication_candidates SET inputs='[]'", [])
            .is_err()
    );
    drop(complete);
    let raw = Connection::open(&complete_path).unwrap();
    raw.execute_batch(
        "DROP TRIGGER publication_candidate_no_update;
         UPDATE publication_candidates SET inputs='[ ]'",
    )
    .unwrap();
    drop(raw);
    assert!(matches!(
        Store::open(&complete_path),
        Err(StoreError::Integrity)
    ));

    // The intent and replay source commit atomically. Simulate a hostile raw
    // partial deletion and prove reopen never admits the required live intent.
    let (pending_dir, mut pending) = open();
    let pending_path = pending_dir.path().join("state.sqlite3");
    let (run, lead) = setup(&mut pending);
    let (intent, _, bytes) = stage_test_record(&mut pending, &run, &lead, "art_staged_pending");
    assert!(pending.staged_publication(&intent).unwrap().is_some());
    let before_replay = audit_state(&pending);
    assert_eq!(
        pending
            .stage_publication_fixture(&intent, &bytes, std::slice::from_ref(&artifact()))
            .unwrap(),
        before_replay.0
    );
    assert_eq!(audit_state(&pending), before_replay);
    let mut changed_bytes = bytes.clone();
    changed_bytes.push(b' ');
    assert!(matches!(
        pending.stage_publication_fixture(
            &intent,
            &changed_bytes,
            std::slice::from_ref(&artifact())
        ),
        Err(StoreError::Conflict)
    ));
    assert_eq!(audit_state(&pending), before_replay);
    drop(pending);
    let raw = Connection::open(&pending_path).unwrap();
    raw.execute_batch(
        "DROP TRIGGER publication_candidate_no_delete;
         DELETE FROM publication_candidates",
    )
    .unwrap();
    drop(raw);
    assert!(matches!(
        Store::open(&pending_path),
        Err(StoreError::Integrity)
    ));
}

#[test]
fn every_connection_verifies_wal_foreign_keys_full_sync_and_recursive_triggers() {
    let (dir, first) = open();
    let second = Store::open(dir.path().join("state.sqlite3")).unwrap();
    for s in [first, second] {
        assert_eq!(pragma(&s.db, "foreign_keys").unwrap(), 1);
        assert_eq!(pragma(&s.db, "synchronous").unwrap(), 2);
        assert_eq!(pragma(&s.db, "recursive_triggers").unwrap(), 1);
        let journal: String =
            s.db.pragma_query_value(None, "journal_mode", |r| r.get(0))
                .unwrap();
        assert_eq!(journal, "wal");
        assert_eq!(s.revision().unwrap(), 1);
    }
    assert!(matches!(
        Store::open(":memory:"),
        Err(StoreError::ConnectionSettings)
    ));
}

#[test]
fn existing_store_opens_for_readers_while_a_writer_holds_the_lock() {
    let (dir, mut store) = open();
    let tx = store
        .db
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    let observer = Store::open(dir.path().join("state.sqlite3")).unwrap();
    assert_eq!(observer.revision().unwrap(), 1);
    tx.rollback().unwrap();
}

#[test]
fn read_during_wal_initialization_does_not_create_sidecars() {
    use std::{fs, sync::mpsc::channel};

    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("root");
    let state = dir.path().join("operator");
    fs::create_dir(&state).unwrap();
    let bound = crate::workspace::init(
        &root,
        &state,
        "one",
        include_bytes!("../../../../fixtures/target/schema-examples/engagement.toml"),
        crate::workspace::Authority::default(),
    )
    .unwrap();
    let path = root.join(".scourge/state.sqlite3");
    let wal = path.with_file_name("state.sqlite3-wal");
    let shm = path.with_file_name("state.sqlite3-shm");
    let (started_tx, started_rx) = channel();
    let (resume_tx, resume_rx) = channel();
    std::thread::scope(|scope| {
        let writer_path = &path;
        let writer = scope.spawn(move || {
            Store::open_with_initialization_hook(writer_path, None, || {
                started_tx.send(()).unwrap();
                let _ = resume_rx.recv_timeout(Duration::from_secs(2));
            })
            .unwrap()
        });
        started_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let bytes = fs::read(&path).unwrap();
        assert!(!wal.exists() && !shm.exists());
        assert!(matches!(
            bound.open_coordination(),
            Err(crate::workspace::WorkspaceError::Coordination(
                StoreError::Busy
            ))
        ));
        assert!(!wal.exists() && !shm.exists());
        assert_eq!(fs::read(&path).unwrap(), bytes);
        resume_tx.send(()).unwrap();
        let writer = writer.join().unwrap();

        let family = || [&path, &wal, &shm].map(|path| fs::read(path).unwrap());
        let before = family();
        bound
            .open_coordination()
            .unwrap()
            .snapshot(|snapshot| {
                let scope = snapshot.scope("one".parse().unwrap())?;
                assert!(scope.leads(1, 0)?.is_empty());
                Ok(())
            })
            .unwrap();
        assert_eq!(family(), before);
        assert_eq!(writer.revision().unwrap(), 3);
    });
}

#[test]
fn foreign_database_is_refused_before_its_journal_mode_changes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("foreign.sqlite3");
    let foreign = Connection::open(&path).unwrap();
    foreign
        .execute_batch("CREATE TABLE existing (id INTEGER)")
        .unwrap();
    assert!(matches!(Store::open(path), Err(StoreError::Schema)));
    let mode: String = foreign
        .pragma_query_value(None, "journal_mode", |r| r.get(0))
        .unwrap();
    assert_eq!(mode, "delete");
}

fn legacy_step(effect: Effect) -> RunStep {
    RunStep {
        number: 1,
        step: "legacy.effect".parse().unwrap(),
        request_digest: Sha256Digest::of(b"legacy request"),
        flow_id_floor: None,
        instrument_reference: Some("legacy-receipt".parse().unwrap()),
        effects: Some(effect),
        flows: Vec::new(),
    }
}

fn migrate_v7_keyed_runs(runs: Vec<Run>) -> (TempDir, Store, Vec<(Run, u64)>) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v7.sqlite3");
    let mut db = Connection::open(&path).unwrap();
    let tx = db.transaction().unwrap();
    for migration in &MIGRATIONS[..7] {
        tx.execute_batch(migration).unwrap();
    }
    tx.pragma_update(None, "application_id", APPLICATION_ID)
        .unwrap();
    tx.pragma_update(None, "user_version", 7).unwrap();
    let input =
        r#"{"arguments":{},"command":"migration-fixture","schema":"scourge.request-input.v1"}"#;
    let mut accepted = Vec::with_capacity(runs.len());
    for run in runs {
        tx.execute(
            "INSERT INTO engagements (id) VALUES (?) ON CONFLICT (id) DO NOTHING",
            [run.engagement.as_str()],
        )
        .unwrap();
        tx.execute(
            "INSERT INTO engagement_revisions
             (engagement_id, revision, manifest_artifact_id, manifest_digest, pass_digest)
             VALUES (?1, 1, 'art_legacy_manifest', ?2, ?3)
             ON CONFLICT (engagement_id, revision) DO NOTHING",
            params![
                run.engagement.as_str(),
                Sha256Digest::of(b"legacy manifest").as_str(),
                Sha256Digest::of(b"legacy pass").as_str()
            ],
        )
        .unwrap();
        create_run(&tx, &run).unwrap();
        let receipt = advance(&tx, "request.accept", run.id.as_str()).unwrap();
        tx.execute(
            "INSERT INTO request_keys
             (key, engagement_id, binding, command, input, input_digest, run_id,
              receipt_revision, lead_id, lead_revision, engagement_revision)
             VALUES (?1, ?2, 'workspace:legacy', 'migration-fixture', ?3, ?4, ?5, ?6, NULL, NULL, 1)",
            params![
                run.request_key.as_str(),
                run.engagement.as_str(),
                input,
                Sha256Digest::of(input.as_bytes()).as_str(),
                run.id.as_str(),
                integer(receipt).unwrap()
            ],
        )
        .unwrap();
        accepted.push((run, receipt));
    }
    commit(tx, "schema.migrate", "7").unwrap();
    drop(db);
    let store = Store::open(path).unwrap();
    (dir, store, accepted)
}

fn migrate_v7_keyed(run: Run) -> (TempDir, Store, Run, u64) {
    let (dir, store, mut accepted) = migrate_v7_keyed_runs(vec![run]);
    let (run, receipt) = accepted.pop().unwrap();
    (dir, store, run, receipt)
}

fn v11_publication_database(
    engagement: &str,
    run: &str,
    lead: &str,
) -> (TempDir, std::path::PathBuf, Connection) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("v11-publication.sqlite3");
    let mut db = Connection::open(&path).unwrap();
    let transaction = db.transaction().unwrap();
    for migration in &MIGRATIONS[..11] {
        transaction.execute_batch(migration).unwrap();
    }
    transaction
        .pragma_update(None, "application_id", APPLICATION_ID)
        .unwrap();
    transaction.pragma_update(None, "user_version", 11).unwrap();
    transaction
        .execute(
            "INSERT INTO engagements (id, head_sequence, head_digest) VALUES (?1, 0, NULL)",
            [engagement],
        )
        .unwrap();
    transaction
        .execute(
            "INSERT INTO leads (id, engagement_id) VALUES (?1, ?2)",
            [lead, engagement],
        )
        .unwrap();
    transaction
        .execute(
            "INSERT INTO lead_revisions (lead_id, revision, text, class, slots, proposed_policy)
             VALUES (?1, 1, 'legacy', NULL, '{}', NULL)",
            [lead],
        )
        .unwrap();
    transaction
        .execute(
            "INSERT INTO runs (id, engagement_id, request_key, experiment_digest, state, flags,
                 effects, oracle_result, reproduction, cleanup)
             VALUES (?1, ?2, 'rk_legacy', ?3, 'finalized', '[]',
                 'none', 'invalid', 'not_attempted', 'unknown')",
            params![
                run,
                engagement,
                Sha256Digest::of(b"legacy experiment").as_str()
            ],
        )
        .unwrap();
    transaction.commit().unwrap();
    (directory, path, db)
}

fn legacy_audit(db: &Connection, revision: u64, operation: &str, subject: &str) {
    db.execute(
        "INSERT INTO audit_events (revision, operation, subject) VALUES (?1, ?2, ?3)",
        params![integer(revision).unwrap(), operation, subject],
    )
    .unwrap();
    db.execute(
        "UPDATE store_revision SET revision=?1",
        [integer(revision).unwrap()],
    )
    .unwrap();
}

#[test]
fn migration_v12_reconstructs_completed_intent_artifact_receipts() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("v11.sqlite3");
    let mut db = Connection::open(&path).unwrap();
    let transaction = db.transaction().unwrap();
    for migration in &MIGRATIONS[..11] {
        transaction.execute_batch(migration).unwrap();
    }
    transaction
        .pragma_update(None, "application_id", APPLICATION_ID)
        .unwrap();
    transaction.pragma_update(None, "user_version", 11).unwrap();
    let digest = Sha256Digest::of(b"legacy exact record bytes");
    let experiment = Sha256Digest::of(b"legacy experiment");
    transaction
        .execute(
            "INSERT INTO engagements (id, head_sequence, head_digest) VALUES ('legacy-publication', 0, NULL)",
            [],
        )
        .unwrap();
    transaction
        .execute(
            "INSERT INTO leads (id, engagement_id) VALUES ('L-legacy', 'legacy-publication')",
            [],
        )
        .unwrap();
    transaction
        .execute(
            "INSERT INTO lead_revisions (lead_id, revision, text, class, slots, proposed_policy)
             VALUES ('L-legacy', 1, 'legacy', NULL, '{}', NULL)",
            [],
        )
        .unwrap();
    transaction
        .execute(
            "INSERT INTO runs (id, engagement_id, request_key, experiment_digest, state, flags,
                 effects, oracle_result, reproduction, cleanup)
             VALUES ('R-legacy', 'legacy-publication', 'rk_legacy', ?1, 'finalized', '[]',
                 'none', 'invalid', 'not_attempted', 'unknown')",
            [experiment.as_str()],
        )
        .unwrap();
    transaction
        .execute(
            "INSERT INTO publication_intents
             (id, engagement_id, run_id, record_id, record_digest,
              expected_sequence, expected_digest, state)
             VALUES ('P-legacy', 'legacy-publication', 'R-legacy', 'V-legacy', ?1, 0, NULL, 'complete')",
            [digest.as_str()],
        )
        .unwrap();
    transaction
        .execute(
            "INSERT INTO verifications
             (record_id, engagement_id, sequence, run_id, lead_id, artifact_id, record_digest, intent_id)
             VALUES ('V-legacy', 'legacy-publication', 1, 'R-legacy', 'L-legacy',
                 'art_legacy', ?1, 'P-legacy')",
            [digest.as_str()],
        )
        .unwrap();
    transaction
        .execute(
            "UPDATE engagements SET head_sequence=1, head_digest=?1 WHERE id='legacy-publication'",
            [digest.as_str()],
        )
        .unwrap();
    transaction
        .execute("UPDATE store_revision SET revision=2", [])
        .unwrap();
    transaction
        .execute(
            "INSERT INTO audit_events (revision, operation, subject)
             VALUES (1, 'publication.intent', 'P-legacy'),
                    (2, 'publication.link', 'V-legacy')",
            [],
        )
        .unwrap();
    transaction.commit().unwrap();
    drop(db);

    // Before migration, the old read-only index remains usable without any
    // publication-candidate table or record bytes.
    let reader = read::ReadStore::open(&path).unwrap();
    let legacy_id: VerificationId = "V-legacy".parse().unwrap();
    let legacy = reader
        .snapshot(|snapshot| {
            snapshot
                .scope("legacy-publication".parse().unwrap())?
                .record(&legacy_id)
        })
        .unwrap();
    assert_eq!(legacy.run.as_str(), "R-legacy");
    assert_eq!(legacy.oracle_id, None);
    assert_eq!(legacy.limitations, None);
    drop(reader);

    let store = Store::open(&path).unwrap();
    let run: RunId = "R-legacy".parse().unwrap();
    let publication = store.publication(&run).unwrap().unwrap();
    assert_eq!(publication.state, PublicationState::Complete);
    assert_eq!(publication.artifact_id.unwrap().as_str(), "art_legacy");
    assert_eq!(
        store
            .checkpoint(&"legacy-publication".parse().unwrap())
            .unwrap()
            .1
            .record_digest,
        Some(digest)
    );
    drop(store);

    // Migration 12 marks these rows candidate_required=0 and must preserve the
    // same index-only fallback rather than inventing staged bytes.
    let reader = read::ReadStore::open(&path).unwrap();
    let legacy = reader
        .snapshot(|snapshot| {
            snapshot
                .scope("legacy-publication".parse().unwrap())?
                .record(&legacy_id)
        })
        .unwrap();
    assert_eq!(legacy.run.as_str(), "R-legacy");
    assert_eq!(legacy.oracle_id, None);
    assert_eq!(legacy.limitations, None);
}

#[test]
fn migration_v12_keeps_latest_audited_pending_intent_after_interruption_and_reopen() {
    let engagement = "legacy-pending-duplicates";
    let run = "R-legacy-pending-duplicates";
    let (_directory, path, mut db) =
        v11_publication_database(engagement, run, "L-legacy-pending-duplicates");
    let old_digest = Sha256Digest::of(b"old pending record");
    let current_digest = Sha256Digest::of(b"current pending record");
    db.execute(
        "INSERT INTO publication_intents
         (id, engagement_id, run_id, record_id, record_digest,
          expected_sequence, expected_digest, state)
         VALUES ('P-legacy-old', ?1, ?2, 'V-legacy-old', ?3, 0, NULL, 'pending'),
                ('P-legacy-current', ?1, ?2, 'V-legacy-current', ?4, 0, NULL, 'pending')",
        params![
            engagement,
            run,
            old_digest.as_str(),
            current_digest.as_str()
        ],
    )
    .unwrap();
    legacy_audit(&db, 1, "publication.intent", "P-legacy-old");
    legacy_audit(&db, 2, "publication.intent", "P-legacy-current");

    // Simulate interruption anywhere before the migration transaction commits.
    // SQLite must restore both the table shape and the legacy rows, after which
    // ordinary open can apply the same migration exactly once.
    let interrupted = db.transaction().unwrap();
    interrupted.execute_batch(MIGRATIONS[11]).unwrap();
    interrupted.rollback().unwrap();
    assert_eq!(pragma(&db, "user_version").unwrap(), 11);
    assert!(
        !exists(
            &db,
            "SELECT 1 FROM pragma_table_info('publication_intents') WHERE name='artifact_id'",
            [],
        )
        .unwrap()
    );
    assert_eq!(
        db.query_row(
            "SELECT COUNT(*) FROM publication_intents WHERE state='pending'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .unwrap(),
        2
    );
    drop(db);

    let store = Store::open(&path).unwrap();
    let run: RunId = run.parse().unwrap();
    let live = store.publication(&run).unwrap().unwrap();
    assert_eq!(live.intent_id.as_str(), "P-legacy-current");
    assert_eq!(live.state, PublicationState::Pending);
    assert_eq!(live.artifact_id, None);
    // Version 11 had no durable byte source or verifier receipt to migrate.
    // The pending entry remains inspectable, and recovery cannot link it.
    assert_eq!(store.staged_publication(&live).unwrap(), None);
    assert!(matches!(
        store.publication_for_reconciliation(&run),
        Err(StoreError::Conflict)
    ));
    assert_eq!(
        store
            .db
            .query_row(
                "SELECT state FROM publication_intents WHERE id='P-legacy-old'",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        "superseded"
    );
    assert!(
        store
            .db
            .query_row(
                "SELECT artifact_id IS NULL FROM publication_intents WHERE id='P-legacy-old'",
                [],
                |row| row.get::<_, bool>(0),
            )
            .unwrap()
    );
    assert_eq!(
        store
            .db
            .query_row(
                "SELECT COUNT(*) FROM audit_events
                 WHERE operation='schema.migrate' AND subject=?1",
                [MIGRATIONS.len().to_string()],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        1
    );
    drop(store);

    let reopened = Store::open(&path).unwrap();
    assert_eq!(
        reopened
            .publication(&run)
            .unwrap()
            .unwrap()
            .intent_id
            .as_str(),
        "P-legacy-current"
    );
    assert_eq!(
        reopened
            .db
            .query_row(
                "SELECT COUNT(*) FROM audit_events
                 WHERE operation='schema.migrate' AND subject=?1",
                [MIGRATIONS.len().to_string()],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        1
    );
}

#[test]
fn migration_v12_prefers_linked_complete_intent_over_later_pending_duplicate() {
    let engagement = "legacy-complete-pending";
    let run = "R-legacy-complete-pending";
    let lead = "L-legacy-complete-pending";
    let (_directory, path, db) = v11_publication_database(engagement, run, lead);
    let linked_digest = Sha256Digest::of(b"linked record");
    let pending_digest = Sha256Digest::of(b"later pending record");
    db.execute(
        "INSERT INTO publication_intents
         (id, engagement_id, run_id, record_id, record_digest,
          expected_sequence, expected_digest, state)
         VALUES ('P-legacy-linked', ?1, ?2, 'V-legacy-linked', ?3, 0, NULL, 'complete'),
                ('P-legacy-after-link', ?1, ?2, 'V-legacy-after-link', ?4, 1, ?3, 'pending')",
        params![
            engagement,
            run,
            linked_digest.as_str(),
            pending_digest.as_str()
        ],
    )
    .unwrap();
    db.execute(
        "INSERT INTO verifications
         (record_id, engagement_id, sequence, run_id, lead_id, artifact_id,
          record_digest, intent_id)
         VALUES ('V-legacy-linked', ?1, 1, ?2, ?3, 'art_legacy_linked', ?4,
                 'P-legacy-linked')",
        params![engagement, run, lead, linked_digest.as_str()],
    )
    .unwrap();
    db.execute(
        "UPDATE engagements SET head_sequence=1, head_digest=?1 WHERE id=?2",
        params![linked_digest.as_str(), engagement],
    )
    .unwrap();
    legacy_audit(&db, 1, "publication.intent", "P-legacy-linked");
    legacy_audit(&db, 2, "publication.link", "V-legacy-linked");
    legacy_audit(&db, 3, "publication.intent", "P-legacy-after-link");
    drop(db);

    let store = Store::open(&path).unwrap();
    let run: RunId = run.parse().unwrap();
    let live = store.publication(&run).unwrap().unwrap();
    assert_eq!(live.intent_id.as_str(), "P-legacy-linked");
    assert_eq!(live.state, PublicationState::Complete);
    assert_eq!(live.artifact_id.unwrap().as_str(), "art_legacy_linked");
    assert_eq!(
        store
            .db
            .query_row(
                "SELECT state FROM publication_intents WHERE id='P-legacy-after-link'",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        "superseded"
    );
    assert_eq!(
        store
            .checkpoint(&engagement.parse().unwrap())
            .unwrap()
            .1
            .record_digest,
        Some(linked_digest)
    );
}

#[test]
fn migration_v12_refuses_to_guess_between_unaudited_pending_duplicates() {
    let engagement = "legacy-unaudited-duplicates";
    let run = "R-legacy-unaudited-duplicates";
    let (_directory, path, db) =
        v11_publication_database(engagement, run, "L-legacy-unaudited-duplicates");
    db.execute(
        "INSERT INTO publication_intents
         (id, engagement_id, run_id, record_id, record_digest,
          expected_sequence, expected_digest, state)
         VALUES ('P-audited', ?1, ?2, 'V-audited', ?3, 0, NULL, 'pending'),
                ('P-unaudited', ?1, ?2, 'V-unaudited', ?4, 0, NULL, 'pending')",
        params![
            engagement,
            run,
            Sha256Digest::of(b"audited").as_str(),
            Sha256Digest::of(b"unaudited").as_str()
        ],
    )
    .unwrap();
    legacy_audit(&db, 1, "publication.intent", "P-audited");
    drop(db);

    let Err(error) = Store::open(&path) else {
        panic!("unaudited duplicate intents must fail migration")
    };
    assert_eq!(error.error_code(), crate::wire::ErrorCode::IntegrityFailure);
    let raw = Connection::open(&path).unwrap();
    assert_eq!(pragma(&raw, "user_version").unwrap(), 11);
    assert!(
        !exists(
            &raw,
            "SELECT 1 FROM pragma_table_info('publication_intents') WHERE name='artifact_id'",
            [],
        )
        .unwrap()
    );
}

#[test]
fn broken_predecessor_head_and_index_are_integrity_failures_on_read() {
    let (directory, mut store) = open();
    let (first, revision) = declared_run(&mut store);
    let first = finalize_run(&mut store, &first, revision);
    let lead = LeadRevision {
        lead_id: LeadId::generate(),
        revision: 1,
        text: "chain witness".parse().unwrap(),
        class: None,
        property: None,
        slots: Default::default(),
        proposed_policy: None,
        origin: crate::domain::LeadOrigin::Local,
        source_ref: None,
        endpoint: None,
        flow_ids: Vec::new(),
        producer_confidence: None,
    };
    store
        .append_lead_revision(&first.engagement, &lead)
        .unwrap();
    publish_test_record(&mut store, &first, &lead, "art_chain_one");
    let second = Run::declare(first.engagement.clone(), first.experiment_digest.clone());
    let revision = store.seed_historical_run_fixture(&second).unwrap();
    let second = finalize_run(&mut store, &second, revision);
    let second_receipt = publish_test_record(&mut store, &second, &lead, "art_chain_two");
    let good_head = store.checkpoint(&first.engagement).unwrap().1;
    drop(store);

    let path = directory.path().join("state.sqlite3");
    let raw = Connection::open(&path).unwrap();
    raw.execute_batch(
        "PRAGMA foreign_keys=OFF;
         DROP TRIGGER publication_intent_transition;
         DROP TRIGGER verification_no_update;",
    )
    .unwrap();
    let bad = Sha256Digest::of(b"tampered chain metadata");
    let predecessor = good_head.record_digest.clone().unwrap();
    let first_digest: String = raw
        .query_row(
            "SELECT record_digest FROM verifications WHERE sequence=1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let assert_broken = || {
        let store = match Store::open(&path) {
            Ok(store) => store,
            Err(error) => {
                assert!(matches!(error, StoreError::Integrity));
                assert_eq!(error.error_code(), crate::wire::ErrorCode::IntegrityFailure);
                return;
            }
        };
        let error = store.checkpoint(&first.engagement).unwrap_err();
        assert!(matches!(error, StoreError::Integrity));
        assert_eq!(error.error_code(), crate::wire::ErrorCode::IntegrityFailure);
        let snapshot = crate::store::entry::read(&store.db, &first.engagement).unwrap();
        assert!(snapshot.broken_chain);
    };

    raw.execute(
        "UPDATE publication_intents SET expected_digest=?1 WHERE id=?2",
        params![bad.as_str(), second_receipt.intent.intent_id.as_str()],
    )
    .unwrap();
    assert_broken();
    raw.execute(
        "UPDATE publication_intents SET expected_digest=?1 WHERE id=?2",
        params![first_digest, second_receipt.intent.intent_id.as_str()],
    )
    .unwrap();

    raw.execute(
        "UPDATE engagements SET head_digest=?1 WHERE id=?2",
        params![bad.as_str(), first.engagement.as_str()],
    )
    .unwrap();
    assert_broken();
    raw.execute(
        "UPDATE engagements SET head_digest=?1 WHERE id=?2",
        params![predecessor.as_str(), first.engagement.as_str()],
    )
    .unwrap();

    raw.execute(
        "UPDATE verifications SET record_digest=?1 WHERE sequence=2",
        [bad.as_str()],
    )
    .unwrap();
    assert_broken();
}

#[test]
fn migration_v10_resumes_an_unstarted_legacy_run_without_a_global_barrier() {
    use super::request_tests::{
        admit_verification, seed_recoverable_verification, verification_claim, verification_run,
    };
    let engagement: EngagementId = "legacy-unstarted".parse().unwrap();
    let run = Run::declare(engagement, Sha256Digest::of(b"legacy experiment"));
    let (_dir, mut store, run, _) = migrate_v7_keyed(run);
    assert!(!store.conflicts_held(&run.id).unwrap());

    let scope = RequestScope::new(
        "new-engagement".parse().unwrap(),
        "workspace:legacy".parse().unwrap(),
    );
    let (lead, manifest, artifact) = seed_recoverable_verification(&mut store, &scope);
    let input = Invocation::new("verify", serde_json::json!({"lead_id": lead.as_str()}))
        .normalize()
        .unwrap();
    let claim = verification_claim(&lead, &manifest);
    let contender = verification_run(&scope.engagement, &claim, &manifest);
    admit_verification(
        &mut store, &scope, &input, &contender, &claim, &manifest, &artifact,
    )
    .unwrap();
    store
        .claim_conflicts(
            &contender.id,
            &BTreeSet::from(["resource:unrelated".to_owned()]),
        )
        .unwrap();
    store.release_unstarted_conflicts(&contender.id).unwrap();

    let keys = BTreeSet::from(["resource:legacy".to_owned()]);
    store.claim_conflicts(&run.id, &keys).unwrap();
    assert_eq!(
        store
            .db
            .query_row(
                "SELECT claim_kind FROM run_conflict_sets WHERE run_id=?",
                [run.id.as_str()],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        "exact"
    );
    store.release_unstarted_conflicts(&run.id).unwrap();
    assert!(!store.conflicts_held(&run.id).unwrap());
    store
        .record_step(&run.id, &legacy_step(Effect::Unknown))
        .unwrap();
    assert!(store.conflicts_held(&run.id).unwrap());
}

#[test]
fn migration_v10_multiple_unstarted_owners_make_ordered_cross_engagement_progress() {
    let first = Run::declare(
        "legacy-first".parse().unwrap(),
        Sha256Digest::of(b"first legacy experiment"),
    );
    let second = Run::declare(
        "legacy-second".parse().unwrap(),
        Sha256Digest::of(b"second legacy experiment"),
    );
    let (_dir, mut store, accepted) = migrate_v7_keyed_runs(vec![first.clone(), second.clone()]);
    let first_receipt = accepted[0].1;
    assert!(
        accepted
            .iter()
            .all(|(run, _)| !store.conflicts_held(&run.id).unwrap())
    );

    // Both safe owners can resume into their now-known exact, disjoint sets;
    // neither migration marker globally blocks the other engagement.
    store
        .claim_conflicts(&first.id, &BTreeSet::from(["resource:first".to_owned()]))
        .unwrap();
    store
        .claim_conflicts(&second.id, &BTreeSet::from(["resource:second".to_owned()]))
        .unwrap();
    store.release_unstarted_conflicts(&first.id).unwrap();

    // A direct legacy start has no exact keys, so it installs one global
    // barrier atomically with the step. It reclaims the other exact owner's
    // crash-safe zero-step claim in that same transaction. The other owner
    // cannot start until the first resolves, but it deterministically makes
    // progress after release.
    let mut first_step = legacy_step(Effect::Unknown);
    store.record_step(&first.id, &first_step).unwrap();
    assert!(!store.conflicts_held(&second.id).unwrap());
    assert!(matches!(
        store.record_step(&second.id, &legacy_step(Effect::Unknown)),
        Err(StoreError::Conflict)
    ));
    first_step.effects = Some(Effect::None);
    store.record_step(&first.id, &first_step).unwrap();
    let mut settled = first;
    settled.state = RunState::Finalized;
    settled.effects = Effect::None;
    settled.cleanup = Cleanup::Complete;
    settled.steps.push(first_step);
    store.record_run(&settled, Some(first_receipt)).unwrap();
    assert!(!store.conflicts_held(&settled.id).unwrap());
    store
        .record_step(&second.id, &legacy_step(Effect::Unknown))
        .unwrap();
}

#[test]
fn migration_v10_direct_start_refuses_after_ordinary_and_stop_amendments() {
    let ordinary = Run::declare(
        "legacy-amended".parse().unwrap(),
        Sha256Digest::of(b"ordinary amended legacy experiment"),
    );
    let stopped = Run::declare(
        "legacy-stopped".parse().unwrap(),
        Sha256Digest::of(b"stopped legacy experiment"),
    );
    let (_dir, mut store, _) = migrate_v7_keyed_runs(vec![ordinary.clone(), stopped.clone()]);

    store
        .append_manifest(
            &ordinary.engagement,
            &Artifact {
                artifact_id: "art_legacy_ordinary_amendment".parse().unwrap(),
                digest: Sha256Digest::of(b"legacy ordinary amendment"),
            },
            &Sha256Digest::of(b"legacy pass"),
        )
        .unwrap();
    store
        .append_stop_manifest(
            &stopped.engagement,
            &Artifact {
                artifact_id: "art_legacy_stop_amendment".parse().unwrap(),
                digest: Sha256Digest::of(b"legacy stop amendment"),
            },
            &Sha256Digest::of(b"legacy pass"),
        )
        .unwrap();

    for run in [&ordinary, &stopped] {
        assert!(matches!(
            store.record_step(&run.id, &legacy_step(Effect::Unknown)),
            Err(StoreError::RevisionConflict)
        ));
        assert!(!store.conflicts_held(&run.id).unwrap());
    }
}

#[test]
fn migration_v10_keeps_started_unknown_reconciliation_and_releases_terminally() {
    let engagement: EngagementId = "legacy-started".parse().unwrap();
    let mut run = Run::declare(engagement.clone(), Sha256Digest::of(b"legacy experiment"));
    run.state = RunState::Running;
    run.effects = Effect::Unknown;
    run.cleanup = Cleanup::Unknown;
    run.steps.push(legacy_step(Effect::Unknown));
    let (_dir, mut store, mut run, receipt) = migrate_v7_keyed(run);
    assert!(store.conflicts_held(&run.id).unwrap());

    run.steps[0].effects = Some(Effect::Observed);
    store.record_step(&run.id, &run.steps[0]).unwrap();
    run.state = RunState::Finalized;
    run.effects = Effect::Observed;
    run.cleanup = Cleanup::Complete;
    store.record_run(&run, Some(receipt)).unwrap();
    assert!(!store.conflicts_held(&run.id).unwrap());

    let manifest = Artifact {
        artifact_id: "art_after_legacy".parse().unwrap(),
        digest: Sha256Digest::of(b"after legacy"),
    };
    store
        .append_manifest(&engagement, &manifest, &manifest.digest)
        .unwrap();
}

#[test]
fn migration_v10_allows_only_existing_resolved_terminal_steps_without_a_claim() {
    let engagement = "legacy-terminal".parse().unwrap();
    let mut run = Run::declare(engagement, Sha256Digest::of(b"legacy experiment"));
    run.state = RunState::Finalized;
    run.effects = Effect::Observed;
    run.cleanup = Cleanup::Complete;
    run.steps.push(legacy_step(Effect::Observed));
    let (_dir, mut store, run, receipt) = migrate_v7_keyed(run);
    assert!(!store.conflicts_held(&run.id).unwrap());
    let terminal_receipt = store.record_run(&run, Some(receipt)).unwrap();

    let mut unexpected = legacy_step(Effect::Observed);
    unexpected.number = 2;
    assert!(matches!(
        store.record_step(&run.id, &unexpected),
        Err(StoreError::Conflict)
    ));
    let mut bundled = run.clone();
    bundled.steps.push(unexpected);
    assert!(matches!(
        store.record_run(&bundled, Some(terminal_receipt)),
        Err(StoreError::Conflict)
    ));
}

#[test]
fn migration_indexes_existing_v1_receipts_and_advances_the_revision_once() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v1.sqlite3");
    let mut db = Connection::open(&path).unwrap();
    let tx = db.transaction().unwrap();
    tx.execute_batch(include_str!("001_initial.sql")).unwrap();
    tx.pragma_update(None, "application_id", APPLICATION_ID)
        .unwrap();
    tx.pragma_update(None, "user_version", 1).unwrap();
    assert_eq!(commit(tx, "schema.migrate", "1").unwrap(), 1);
    drop(db);
    let store = Store::open(&path).unwrap();
    assert_eq!(audit_state(&store), (2, 2));
    assert_eq!(
        pragma(&store.db, "user_version").unwrap() as usize,
        MIGRATIONS.len()
    );
    let original: i64 = store.db.query_row(
        "SELECT revision FROM audit_events INDEXED BY audit_receipts WHERE operation=? AND subject=?",
        ["schema.migrate", "1"], |r| r.get(0),
    ).unwrap();
    assert_eq!(original, 1);
    assert_eq!(audit_state(&Store::open(path).unwrap()), (2, 2));
}

#[test]
fn migration_to_the_request_key_integrity_schema_is_unique_and_audited_once() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v3.sqlite3");
    let mut db = Connection::open(&path).unwrap();
    let tx = db.transaction().unwrap();
    tx.execute_batch(include_str!("001_initial.sql")).unwrap();
    tx.execute_batch(include_str!("002_audit_receipts.sql"))
        .unwrap();
    tx.execute_batch(include_str!("003_request_keys.sql"))
        .unwrap();
    // The lane used to create this unused scope index; a store from it must be
    // migrated without either index being left behind.
    tx.execute_batch("CREATE INDEX request_key_scopes ON request_keys (engagement_id, binding);")
        .unwrap();
    tx.pragma_update(None, "application_id", APPLICATION_ID)
        .unwrap();
    tx.pragma_update(None, "user_version", 3).unwrap();
    assert_eq!(commit(tx, "schema.migrate", "3").unwrap(), 1);
    drop(db);

    let store = Store::open(&path).unwrap();
    assert_eq!(audit_state(&store), (2, 2));
    assert_eq!(
        pragma(&store.db, "user_version").unwrap() as usize,
        MIGRATIONS.len()
    );
    let indexes: Vec<String> = store
        .db
        .prepare("SELECT name FROM sqlite_schema WHERE type='index' ORDER BY name")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert!(indexes.iter().any(|name| name == "request_key_runs"));
    assert!(!indexes.iter().any(|name| name == "request_key_scopes"));
}

#[test]
fn newer_schema_is_refused_without_reinitializing_its_data() {
    let (dir, store) = open();
    store.db.pragma_update(None, "user_version", 2000).unwrap();
    drop(store);
    assert!(matches!(
        Store::open(dir.path().join("state.sqlite3")),
        Err(StoreError::Schema)
    ));
    let db = Connection::open(dir.path().join("state.sqlite3")).unwrap();
    assert_eq!(pragma(&db, "user_version").unwrap(), 2000);
    assert_eq!(
        db.query_row("SELECT COUNT(*) FROM audit_events", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        1
    );
}

#[test]
fn audit_failure_rolls_back_the_data_and_counter() {
    let (_dir, mut store) = open();
    store
        .db
        .execute_batch(
            "CREATE TEMP TRIGGER refuse_audit BEFORE INSERT ON audit_events
        BEGIN SELECT RAISE(ABORT, 'test fault'); END;",
        )
        .unwrap();
    let asset = artifact();
    let id = "local".parse().unwrap();
    assert!(store.append_manifest(&id, &asset, &asset.digest).is_err());
    assert_eq!(store.revision().unwrap(), 1);
    assert_eq!(
        store
            .db
            .query_row("SELECT COUNT(*) FROM engagements", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert!(store.checkpoint(&id).is_err());
}

#[test]
fn every_write_has_one_revision_and_audit_including_an_objection_after_publication() {
    let (dir, mut s) = open();
    let observer = Store::open(dir.path().join("state.sqlite3")).unwrap();
    let id: EngagementId = "local".parse().unwrap();
    let asset = artifact();
    let mut ops = vec!["schema.migrate"];
    macro_rules! commit {
        ($write:expr, $operation:literal) => {{
            ops.push($operation);
            let revision = $write.unwrap();
            assert_eq!(revision as usize, ops.len());
            assert_eq!(observer.revision().unwrap(), revision);
        }};
    }
    commit!(
        s.append_manifest(&id, &asset, &asset.digest),
        "engagement.revision"
    );
    commit!(
        s.append_manifest(&id, &asset, &asset.digest),
        "engagement.revision"
    );
    let mut lead = LeadRevision {
        lead_id: LeadId::generate(),
        revision: 1,
        text: "review".parse().unwrap(),
        class: None,
        property: None,
        slots: Default::default(),
        proposed_policy: None,
        origin: crate::domain::LeadOrigin::Local,
        source_ref: None,
        endpoint: None,
        flow_ids: Vec::new(),
        producer_confidence: None,
    };
    commit!(s.append_lead_revision(&id, &lead), "lead.revision");
    lead.revision = 2;
    lead.text = "updated".parse().unwrap();
    commit!(s.append_lead_revision(&id, &lead), "lead.revision");
    let mut run = Run::declare(id.clone(), asset.digest.clone());
    commit!(s.seed_historical_run_fixture(&run), "run.record");
    let run_revision = s.revision().unwrap();
    let mut step = RunStep {
        number: 1,
        step: "receipt".parse().unwrap(),
        request_digest: asset.digest.clone(),
        flow_id_floor: Some(u64::MAX),
        instrument_reference: None,
        effects: None,
        flows: vec![],
    };
    commit!(s.record_step(&run.id, &step), "run.step");
    step.effects = Some(Effect::None);
    commit!(s.record_step(&run.id, &step), "run.step");
    run.state = RunState::Finalized;
    run.cleanup = Cleanup::Complete;
    commit!(s.record_run(&run, Some(run_revision)), "run.record");
    let expected_head = s.checkpoint(&id).unwrap().1;
    let mut index = VerificationIndex {
        engagement: id.clone(),
        sequence: 1,
        record_id: VerificationId::generate(),
        run_id: run.id.clone(),
        lead_id: lead.lead_id.clone(),
        record: asset.clone(),
    };
    let (record, bytes) = publication_candidate(&s, &index, None);
    index.record = record;
    let intent: PublicationIntentV1 = serde_json::from_value(serde_json::json!({
        "schema": "scourge.publication-intent.v1", "intent_id": "P-one", "engagement": id, "run_id": run.id,
        "record_id": index.record_id, "record_digest": index.record.digest, "expected_head": expected_head,
        "state": "pending", "artifact_id": null
    })).unwrap();
    commit!(
        s.stage_publication_fixture(&intent, &bytes, std::slice::from_ref(&asset)),
        "fixture.publication.intent"
    );
    let mut wrong_bytes = bytes.clone();
    wrong_bytes.push(b' ');
    assert!(
        s.complete_publication_fixture(&intent.intent_id, &index.record, &wrong_bytes)
            .is_err()
    );
    assert_eq!(observer.revision().unwrap() as usize, ops.len());
    ops.push("publication.link");
    let revision = s
        .complete_publication_fixture(&intent.intent_id, &index.record, &bytes)
        .unwrap()
        .revision;
    assert_eq!(revision as usize, ops.len());
    assert_eq!(observer.revision().unwrap(), revision);
    let (before, head) = observer.checkpoint(&id).unwrap();
    assert_eq!(head.sequence, 1);
    assert_eq!(head.record_digest, Some(index.record.digest.clone()));
    let mut event = LeadEvent {
        lead_id: lead.lead_id,
        lead_revision: 2,
        kind: LeadEventKind::Objection,
        actor: "operator".parse().unwrap(),
        reason: "review".parse().unwrap(),
        evidence: vec![asset],
        recorded_at: "2026-11-23T12:00:00Z".parse().unwrap(),
    };
    commit!(s.append_lead_event(&event), "lead.event");
    assert_eq!(observer.checkpoint(&id).unwrap(), (before + 1, head));
    event.kind = LeadEventKind::Deferred;
    commit!(s.append_lead_event(&event), "lead.event");
    let mut rows = observer
        .db
        .prepare("SELECT revision, operation FROM audit_events ORDER BY revision")
        .unwrap();
    let audits = rows
        .query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    assert_eq!(
        audits,
        ops.iter()
            .enumerate()
            .map(|(i, op)| ((i + 1) as i64, op.to_string()))
            .collect::<Vec<_>>()
    );
}
