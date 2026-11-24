use super::*;
use crate::{
    domain::LeadEventKind,
    ids::{LeadId, VerificationId},
    wire::{Cleanup, Effect, RunFlag, RunState},
};
use tempfile::TempDir;

fn open() -> (TempDir, Store) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().join("state.sqlite3")).unwrap();
    (dir, store)
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
    let revision = s.record_run(&run, None).unwrap();
    (run, revision)
}

fn audit_state(s: &Store) -> (u64, i64) {
    (
        s.revision().unwrap(),
        s.db.query_row("SELECT count(*) FROM audit_events", [], |r| r.get(0))
            .unwrap(),
    )
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
    let mut acquired = pending.clone();
    acquired.instrument_reference = Some("local-receipt".parse().unwrap());
    acquired.effects = Some(Effect::Observed);
    acquired.flows.push(serde_json::from_value(serde_json::json!({
        "step": "receipt", "flow_id": 8, "original": artifact(), "completeness": "complete", "decoder": null
    })).unwrap());
    s.record_step(&run.id, &acquired).unwrap();
    let before = audit_state(&s);
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
    let (run, _) = declared_run(&mut s);
    let engagement = run.engagement.clone();
    let lead = LeadRevision {
        lead_id: LeadId::generate(),
        revision: 1,
        text: "local".parse().unwrap(),
        class: None,
        slots: Default::default(),
        proposed_policy: None,
    };
    s.append_lead_revision(&engagement, &lead).unwrap();
    let mut first = None;
    for sequence in [1, 2] {
        let run_id = if sequence == 1 {
            run.id.clone()
        } else {
            let next = Run::declare(engagement.clone(), artifact().digest);
            s.record_run(&next, None).unwrap();
            next.id
        };
        let mut record = artifact();
        record.digest = Sha256Digest::of(&[sequence as u8]);
        let index = VerificationIndex {
            engagement: engagement.clone(),
            sequence,
            record_id: VerificationId::generate(),
            run_id,
            lead_id: lead.lead_id.clone(),
            record,
        };
        let intent: PublicationIntentV1 = serde_json::from_value(serde_json::json!({
            "schema": "scourge.publication-intent.v1", "intent_id": PublicationIntentId::generate(), "engagement": engagement,
            "run_id": index.run_id, "record_id": index.record_id, "record_digest": index.record.digest,
            "expected_head": s.checkpoint(&engagement).unwrap().1, "state": "pending", "artifact_id": null
        })).unwrap();
        s.append_intent(&intent).unwrap();
        let receipt = s.link_record(&intent.intent_id, &index).unwrap();
        if sequence == 1 {
            first = Some((intent.intent_id, index, receipt));
        }
    }
    let latest = s.checkpoint(&engagement).unwrap();
    let before = audit_state(&s);
    drop(s);
    let mut reopened = Store::open(dir.path().join("state.sqlite3")).unwrap();
    let (intent, index, original) = first.unwrap();
    assert_eq!(reopened.link_record(&intent, &index).unwrap(), original);
    assert!(original < latest.0);
    let mut conflict = index;
    conflict.record.artifact_id = "other".parse().unwrap();
    assert!(matches!(
        reopened.link_record(&intent, &conflict),
        Err(StoreError::Conflict)
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
        ("engagements", "id head_sequence head_digest"),
        (
            "lead_events",
            "id lead_id lead_revision kind actor reason evidence_refs recorded_at",
        ),
        (
            "lead_revisions",
            "lead_id revision text class slots proposed_policy",
        ),
        ("leads", "id engagement_id"),
        (
            "publication_intents",
            "id engagement_id run_id record_id record_digest expected_sequence expected_digest state",
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
            "run_steps",
            "run_id number step request_digest flow_id_floor instrument_reference effects flow_refs",
        ),
        (
            "runs",
            "id engagement_id request_key experiment_digest state flags effects oracle_result reproduction cleanup",
        ),
        ("store_revision", "singleton revision"),
        ("store_workspace", "singleton workspace_id"),
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
fn every_connection_verifies_wal_foreign_keys_and_full_sync() {
    let (dir, first) = open();
    let second = Store::open(dir.path().join("state.sqlite3")).unwrap();
    for s in [first, second] {
        assert_eq!(pragma(&s.db, "foreign_keys").unwrap(), 1);
        assert_eq!(pragma(&s.db, "synchronous").unwrap(), 2);
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
        slots: Default::default(),
        proposed_policy: None,
    };
    commit!(s.append_lead_revision(&id, &lead), "lead.revision");
    lead.revision = 2;
    lead.text = "updated".parse().unwrap();
    commit!(s.append_lead_revision(&id, &lead), "lead.revision");
    let mut run = Run::declare(id.clone(), asset.digest.clone());
    commit!(s.record_run(&run, None), "run.record");
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
    let index = VerificationIndex {
        engagement: id.clone(),
        sequence: 1,
        record_id: VerificationId::generate(),
        run_id: run.id.clone(),
        lead_id: lead.lead_id.clone(),
        record: asset.clone(),
    };
    let intent: PublicationIntentV1 = serde_json::from_value(serde_json::json!({
        "schema": "scourge.publication-intent.v1", "intent_id": "P-one", "engagement": id, "run_id": run.id,
        "record_id": index.record_id, "record_digest": asset.digest, "expected_head": s.checkpoint(&id).unwrap().1,
        "state": "pending", "artifact_id": null
    })).unwrap();
    commit!(s.append_intent(&intent), "publication.intent");
    let mut wrong_index = index.clone();
    wrong_index.sequence = 2;
    assert!(s.link_record(&intent.intent_id, &wrong_index).is_err());
    assert_eq!(observer.revision().unwrap() as usize, ops.len());
    commit!(s.link_record(&intent.intent_id, &index), "publication.link");
    let (before, head) = observer.checkpoint(&id).unwrap();
    assert_eq!(head.sequence, 1);
    assert_eq!(head.record_digest, Some(asset.digest.clone()));
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
