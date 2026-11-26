use std::path::Path;

use rusqlite::{Connection, config::DbConfig, params};
use scourge_core::{
    domain::{Run, VerificationIndex},
    ids::WireText,
    wire::PublicationIntentV1,
};
use serde_json::json;

/// Restore a historical run directly in the integration test database.
/// Production declarations deliberately cannot create these legacy rows.
pub fn seed(path: &Path, run: &Run) -> u64 {
    let mut connection = Connection::open(path).unwrap();
    connection
        .set_db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER, false)
        .unwrap();
    let tx = connection.transaction().unwrap();
    let data = serde_json::to_value(run).unwrap();
    tx.execute(
        "INSERT INTO runs (id, engagement_id, request_key, experiment_digest,
         state, flags, effects, oracle_result, reproduction, cleanup)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        params![
            run.id.as_str(),
            run.engagement.as_str(),
            run.request_key.as_str(),
            run.experiment_digest.as_str(),
            data["state"].as_str(),
            data["flags"].to_string(),
            data["effects"].as_str(),
            data["oracle_result"].as_str(),
            data["reproduction"].as_str(),
            data["cleanup"].as_str(),
        ],
    )
    .unwrap();
    for step in &run.steps {
        tx.execute(
            "INSERT INTO run_steps (run_id, number, step, request_digest,
             flow_id_floor, instrument_reference, effects, flow_refs)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            params![
                run.id.as_str(),
                step.number.to_string(),
                step.step.as_str(),
                step.request_digest.as_str(),
                step.flow_id_floor.map(|floor| floor.to_string()),
                step.instrument_reference.as_ref().map(WireText::as_str),
                json!(step.effects).as_str(),
                json!(step.flows).to_string(),
            ],
        )
        .unwrap();
    }
    let revision = append_audit(&tx, "run.record", run.id.as_str());
    tx.commit().unwrap();
    revision
}

fn append_audit(tx: &rusqlite::Transaction<'_>, operation: &str, subject: &str) -> u64 {
    let revision: i64 = tx
        .query_row(
            "UPDATE store_revision SET revision=revision+1 WHERE singleton=1 RETURNING revision",
            [],
            |row| row.get(0),
        )
        .unwrap();
    tx.execute(
        "INSERT INTO audit_events (revision, operation, subject) VALUES (?, ?, ?)",
        params![revision, operation, subject],
    )
    .unwrap();
    u64::try_from(revision).unwrap()
}

/// Restore a completed historical chain entry for the read-only CLI tests.
#[allow(dead_code)] // The workspace process test only needs the run fixture.
pub fn seed_linked_record(
    path: &Path,
    intent: &PublicationIntentV1,
    index: &VerificationIndex,
    record_bytes: Option<&[u8]>,
) {
    let mut connection = Connection::open(path).unwrap();
    connection
        .set_db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER, false)
        .unwrap();
    let tx = connection.transaction().unwrap();
    let sequence = i64::try_from(index.sequence).unwrap();
    tx.execute(
        "INSERT INTO publication_intents (id, engagement_id, run_id, record_id, record_digest,
         expected_sequence, expected_digest, state, artifact_id, candidate_required)
         VALUES (?, ?, ?, ?, ?, ?, ?, 'complete', ?, ?)",
        params![
            intent.intent_id.as_str(),
            intent.engagement.as_str(),
            intent.run_id.as_str(),
            index.record_id.as_str(),
            index.record.digest.as_str(),
            sequence - 1,
            intent
                .expected_head
                .record_digest
                .as_ref()
                .map(|digest| digest.as_str()),
            index.record.artifact_id.as_str(),
            i64::from(record_bytes.is_some()),
        ],
    )
    .unwrap();
    append_audit(&tx, "publication.intent", intent.intent_id.as_str());
    if let Some(record_bytes) = record_bytes {
        let inputs = serde_json::to_string(std::slice::from_ref(&index.record)).unwrap();
        tx.execute(
            "INSERT INTO publication_candidates (intent_id, record_bytes, inputs)
             VALUES (?, ?, ?)",
            params![intent.intent_id.as_str(), record_bytes, inputs],
        )
        .unwrap();
    }
    tx.execute(
        "INSERT INTO verifications (record_id, engagement_id, sequence, run_id, lead_id,
         artifact_id, record_digest, intent_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        params![
            index.record_id.as_str(),
            index.engagement.as_str(),
            sequence,
            index.run_id.as_str(),
            index.lead_id.as_str(),
            index.record.artifact_id.as_str(),
            index.record.digest.as_str(),
            intent.intent_id.as_str(),
        ],
    )
    .unwrap();
    assert_eq!(tx.execute(
        "UPDATE engagements SET head_sequence=?1, head_digest=?2 WHERE id=?3 AND head_sequence+1=?1",
        params![sequence, index.record.digest.as_str(), index.engagement.as_str()],
    ).unwrap(), 1);
    append_audit(&tx, "publication.link", index.record_id.as_str());
    tx.commit().unwrap();
}
