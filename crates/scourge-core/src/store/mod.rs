//! Transactional SQLite metadata for a local coordination store.
//! Evidence content stays in its owning store. All SQL writes enter through
//! a transaction that allocates its revision and appends its audit event.

use std::path::Path;

use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde::Serialize;

use crate::{
    canonical::Sha256Digest,
    domain::{LeadEvent, LeadRevision, Run, RunStep, VerificationIndex},
    ids::{EngagementId, PublicationIntentId, RunId},
    wire::{Artifact, Checkpoint, PublicationIntentV1, PublicationState},
};

const MIGRATIONS: &[&str] = &[
    include_str!("001_initial.sql"),
    include_str!("002_audit_receipts.sql"),
];
const APPLICATION_ID: i64 = i32::from_be_bytes(*b"SCRG") as i64;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("coordination database operation failed")]
    Database(#[from] rusqlite::Error),
    #[error("could not encode coordination metadata")]
    Encoding(#[from] serde_json::Error),
    #[error("coordination database does not support the required connection settings")]
    ConnectionSettings,
    #[error("unrecognized coordination database schema")]
    Schema,
    #[error("coordination metadata conflicts with the stored state")]
    Conflict,
    #[error("coordination counter exceeds the SQLite integer range")]
    CounterRange,
}

pub type Result<T> = std::result::Result<T, StoreError>;

pub struct Store {
    db: Connection,
}

impl Store {
    /// Open or create a local SQLite file. The durability profile applies to
    /// every connection, including connections to an already-migrated file.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let mut db = Connection::open(path)?;
        let current = schema_version(&db)?;
        let journal: String = db.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))?;
        db.pragma_update(None, "foreign_keys", "ON")?;
        db.pragma_update(None, "synchronous", "FULL")?;
        if !journal.eq_ignore_ascii_case("wal")
            || pragma(&db, "foreign_keys")? != 1
            || pragma(&db, "synchronous")? != 2
        {
            return Err(StoreError::ConnectionSettings);
        }
        if current < MIGRATIONS.len() {
            migrate(&mut db)?;
        }
        Ok(Self { db })
    }

    pub fn revision(&self) -> Result<u64> {
        unsigned(self.db.query_row(
            "SELECT revision FROM store_revision WHERE singleton = 1",
            [],
            |r| r.get(0),
        )?)
    }

    /// Return the store revision and the engagement checkpoint from one snapshot.
    pub fn checkpoint(&self, engagement: &EngagementId) -> Result<(u64, Checkpoint)> {
        let (revision, sequence, digest): (_, _, Option<String>) = self.db.query_row(
            "SELECT revision, head_sequence, head_digest FROM store_revision, engagements
             WHERE singleton = 1 AND id = ?",
            [engagement.as_str()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        let record_digest = digest
            .map(Sha256Digest::try_from)
            .transpose()
            .map_err(|_| StoreError::Schema)?;
        Ok((
            unsigned(revision)?,
            Checkpoint {
                engagement: engagement.clone(),
                sequence: unsigned(sequence)?,
                record_digest,
            },
        ))
    }

    fn write(
        &mut self,
        operation: &str,
        subject: &str,
        change: impl FnOnce(&Transaction<'_>) -> Result<()>,
    ) -> Result<u64> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        change(&tx)?;
        commit(tx, operation, subject)
    }

    /// Append an immutable manifest pointer, assigning the next engagement revision.
    pub fn append_manifest(
        &mut self,
        id: &EngagementId,
        manifest: &Artifact,
        pass: &Sha256Digest,
    ) -> Result<u64> {
        self.write("engagement.revision", id.as_str(), |tx| {
            tx.execute("INSERT INTO engagements (id) VALUES (?) ON CONFLICT (id) DO NOTHING", [id.as_str()])?;
            tx.execute(
                "INSERT INTO engagement_revisions SELECT ?1, COALESCE(MAX(revision), 0) + 1, ?2, ?3, ?4
                 FROM engagement_revisions WHERE engagement_id = ?1",
                params![id.as_str(), manifest.artifact_id.as_str(), manifest.digest.as_str(), pass.as_str()],
            )?;
            Ok(())
        })
    }

    /// Revision one creates the lead. Edits append and retain the original metadata.
    pub fn append_lead_revision(
        &mut self,
        engagement: &EngagementId,
        lead: &LeadRevision,
    ) -> Result<u64> {
        self.write("lead.revision", lead.lead_id.as_str(), |tx| {
            if lead.revision == 1 {
                tx.execute("INSERT INTO leads (id, engagement_id) VALUES (?, ?)",
                    params![lead.lead_id.as_str(), engagement.as_str()])?;
            }
            one(tx.execute(
                "INSERT INTO lead_revisions SELECT ?1, ?2, ?3, ?4, ?5, ?6
                 WHERE EXISTS (SELECT 1 FROM leads WHERE id = ?1 AND engagement_id = ?7)
                 AND ?2 = (SELECT COALESCE(MAX(revision), 0) + 1 FROM lead_revisions WHERE lead_id = ?1)",
                params![lead.lead_id.as_str(), integer(lead.revision)?, lead.text.as_str(), lead.class.as_ref().map(|v| v.as_str()),
                    json(&lead.slots)?, lead.proposed_policy.as_ref().map(json).transpose()?, engagement.as_str()],
            )?)
        })
    }

    pub fn append_lead_event(&mut self, event: &LeadEvent) -> Result<u64> {
        self.write("lead.event", event.lead_id.as_str(), |tx| {
            tx.execute(
                "INSERT INTO lead_events (lead_id, lead_revision, kind, actor, reason, evidence_refs, recorded_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?)",
                params![event.lead_id.as_str(), integer(event.lead_revision)?, json(&event.kind)?,
                    event.actor.as_str(), event.reason.as_str(), json(&event.evidence)?, event.recorded_at.as_str()],
            )?;
            Ok(())
        })
    }

    /// Pass `None` to create a run. An update requires the revision returned
    /// when the caller's previous run metadata was recorded. Unrelated writes
    /// and individually recorded steps do not invalidate that receipt.
    pub fn record_run(&mut self, run: &Run, previous_revision: Option<u64>) -> Result<u64> {
        self.write("run.record", run.id.as_str(), |tx| {
            let stored_revision: Option<i64> = tx.query_row(
                "SELECT MAX(revision) FROM audit_events WHERE operation='run.record' AND subject=?",
                [run.id.as_str()], |r| r.get(0),
            )?;
            if stored_revision.map(unsigned).transpose()? != previous_revision {
                return Err(StoreError::Conflict);
            }
            one(tx.execute(
                "INSERT INTO runs (id, engagement_id, request_key, experiment_digest, state, flags, effects,
                                   oracle_result, reproduction, cleanup) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                 ON CONFLICT (id) DO UPDATE SET state=excluded.state, flags=excluded.flags, effects=excluded.effects,
                     oracle_result=excluded.oracle_result, reproduction=excluded.reproduction, cleanup=excluded.cleanup
                 WHERE engagement_id=excluded.engagement_id AND request_key=excluded.request_key
                     AND experiment_digest=excluded.experiment_digest",
                params![run.id.as_str(), run.engagement.as_str(), run.request_key.as_str(), run.experiment_digest.as_str(),
                    tag(run.state)?, json(&run.flags)?, tag(run.effects)?, run.oracle_result.map(tag).transpose()?,
                    tag(run.reproduction)?, tag(run.cleanup)?],
            )?)?;
            for step in &run.steps {
                put_step(tx, &run.id, step)?;
            }
            Ok(())
        })
    }

    pub fn record_step(&mut self, run: &RunId, step: &RunStep) -> Result<u64> {
        self.write("run.step", run.as_str(), |tx| put_step(tx, run, step))
    }

    pub fn append_intent(&mut self, intent: &PublicationIntentV1) -> Result<u64> {
        if intent.engagement != intent.expected_head.engagement
            || intent.state != PublicationState::Pending
            || intent.artifact_id.is_some()
        {
            return Err(StoreError::Conflict);
        }
        self.write("publication.intent", intent.intent_id.as_str(), |tx| {
            tx.execute(
                "INSERT INTO publication_intents
                 (id, engagement_id, run_id, record_id, record_digest, expected_sequence, expected_digest, state)
                 VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')",
                params![intent.intent_id.as_str(), intent.engagement.as_str(), intent.run_id.as_str(),
                    intent.record_id.as_str(), intent.record_digest.as_str(), integer(intent.expected_head.sequence)?,
                    intent.expected_head.record_digest.as_ref().map(|v| v.as_str())],
            )?;
            Ok(())
        })
    }

    /// Index a retained record, advance its checkpoint, and close its matching
    /// intent in one commit. Repeating that exact publication returns the
    /// original commit revision, even after subsequent head advances.
    pub fn link_record(
        &mut self,
        intent: &PublicationIntentId,
        index: &VerificationIndex,
    ) -> Result<u64> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let state: Option<String> = tx
            .query_row(
                "SELECT state FROM publication_intents WHERE id=?",
                [intent.as_str()],
                |r| r.get(0),
            )
            .optional()?;
        match state.as_deref() {
            Some("complete") => {
                let receipt = tx.query_row(
                    "SELECT a.revision FROM verifications v JOIN audit_events a
                         ON a.operation='publication.link' AND a.subject=v.record_id
                     WHERE v.record_id=? AND v.engagement_id=? AND v.sequence=? AND v.run_id=?
                         AND v.lead_id=? AND v.artifact_id=? AND v.record_digest=? AND v.intent_id=?",
                    params![index.record_id.as_str(), index.engagement.as_str(), integer(index.sequence)?, index.run_id.as_str(),
                        index.lead_id.as_str(), index.record.artifact_id.as_str(), index.record.digest.as_str(), intent.as_str()],
                    |r| r.get::<_, i64>(0),
                ).optional()?.ok_or(StoreError::Conflict)?;
                return unsigned(receipt);
            }
            Some("pending") => {}
            _ => return Err(StoreError::Conflict),
        }
        tx.execute(
                "INSERT INTO verifications (record_id, engagement_id, sequence, run_id, lead_id, artifact_id, record_digest, intent_id)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                params![index.record_id.as_str(), index.engagement.as_str(), integer(index.sequence)?, index.run_id.as_str(),
                    index.lead_id.as_str(), index.record.artifact_id.as_str(), index.record.digest.as_str(), intent.as_str()],
            )?;
        one(tx.execute(
                "UPDATE engagements SET head_sequence=?1, head_digest=?2 WHERE id=?3 AND head_sequence+1=?1
                 AND EXISTS (SELECT 1 FROM publication_intents WHERE id=?4 AND state='pending'
                     AND expected_sequence=engagements.head_sequence AND expected_digest IS engagements.head_digest)",
                params![integer(index.sequence)?, index.record.digest.as_str(), index.engagement.as_str(), intent.as_str()],
            )?)?;
        one(tx.execute(
            "UPDATE publication_intents SET state='complete' WHERE id=?",
            [intent.as_str()],
        )?)?;
        commit(tx, "publication.link", index.record_id.as_str())
    }
}

fn put_step(tx: &Transaction<'_>, run: &RunId, step: &RunStep) -> Result<()> {
    one(tx.execute(
        "INSERT INTO run_steps (run_id, number, step, request_digest, flow_id_floor, instrument_reference, effects, flow_refs)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (run_id, number) DO UPDATE SET
             instrument_reference=excluded.instrument_reference, effects=excluded.effects, flow_refs=excluded.flow_refs
         WHERE step=excluded.step AND request_digest=excluded.request_digest AND flow_id_floor IS excluded.flow_id_floor
             AND (instrument_reference IS NULL OR instrument_reference IS excluded.instrument_reference)
             AND (effects IS NULL OR effects IS excluded.effects
                  OR (effects='unknown' AND excluded.effects IN ('observed', 'none')))
             AND (flow_refs='[]' OR flow_refs=excluded.flow_refs)",
        params![run.as_str(), step.number.to_string(), step.step.as_str(), step.request_digest.as_str(), step.flow_id_floor.map(|v| v.to_string()),
            step.instrument_reference.as_ref().map(|v| v.as_str()), step.effects.map(tag).transpose()?, json(&step.flows)?],
    )?)
}

fn one(changed: usize) -> Result<()> {
    if changed == 1 {
        Ok(())
    } else {
        Err(StoreError::Conflict)
    }
}

fn unsigned(value: i64) -> Result<u64> {
    value.try_into().map_err(|_| StoreError::CounterRange)
}

fn integer(value: u64) -> Result<i64> {
    value.try_into().map_err(|_| StoreError::CounterRange)
}

fn json<T: Serialize>(value: &T) -> Result<String> {
    Ok(serde_json::to_string(value)?)
}

fn tag(value: impl Serialize) -> Result<String> {
    match serde_json::to_value(value)? {
        serde_json::Value::String(s) => Ok(s),
        _ => Err(StoreError::Schema),
    }
}

fn pragma(db: &Connection, name: &str) -> Result<i64> {
    Ok(db.pragma_query_value(None, name, |row| row.get(0))?)
}

fn commit(tx: Transaction<'_>, operation: &str, subject: &str) -> Result<u64> {
    let revision = tx.query_row(
        "UPDATE store_revision SET revision=revision+1 WHERE singleton=1 RETURNING revision",
        [],
        |r| r.get::<_, i64>(0),
    )?;
    tx.execute(
        "INSERT INTO audit_events (revision, operation, subject) VALUES (?, ?, ?)",
        params![revision, operation, subject],
    )?;
    let revision = unsigned(revision)?;
    tx.commit()?;
    Ok(revision)
}

fn schema_version(db: &Connection) -> Result<usize> {
    let (version, application, populated): (i64, i64, bool) = db.query_row(
        "SELECT user_version, application_id,
             EXISTS(SELECT 1 FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*')
         FROM pragma_user_version, pragma_application_id",
        [],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;
    let current = usize::try_from(version).map_err(|_| StoreError::Schema)?;
    if current > MIGRATIONS.len()
        || (current == 0 && (application != 0 || populated))
        || (current > 0 && application != APPLICATION_ID)
    {
        return Err(StoreError::Schema);
    }
    Ok(current)
}

fn migrate(db: &mut Connection) -> Result<()> {
    // Another first opener can finish migration before we acquire the write lock.
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let current = schema_version(&tx)?;
    if current == MIGRATIONS.len() {
        return Ok(());
    }
    for sql in &MIGRATIONS[current..] {
        tx.execute_batch(sql)?;
    }
    tx.pragma_update(None, "user_version", MIGRATIONS.len() as u32)?;
    tx.pragma_update(None, "application_id", APPLICATION_ID)?;
    commit(tx, "schema.migrate", &MIGRATIONS.len().to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests;
