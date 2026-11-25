//! Small coordination projection for read-only orientation.

use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use super::{Result, Store, StoreError, integer, json, json_value, unsigned};
use crate::{
    canonical::Sha256Digest,
    ids::{EngagementId, RunId, VerificationId},
    wire::Timestamp,
};

pub(super) const SCHEMA_VERSION: usize = 7;

/// A locally recorded result from an operator-bound Teapot route. Counts are
/// a producer snapshot after subtracting references already recorded as leads.
/// The record contains neither native content nor credential locators.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TeapotObservation {
    pub observed_at: Timestamp,
    pub evidence_digest: Sha256Digest,
    pub unrecorded_findings: Option<u64>,
    pub unrecorded_leads: Option<u64>,
}

/// Identity for a recorded inventory bound to this exact instrument route.
pub fn teapot_route_digest(
    kind: crate::wire::TransportKind,
    endpoint: &str,
    project: &str,
) -> Sha256Digest {
    let material = serde_json::json!([kind, endpoint, project]);
    Sha256Digest::of(material.to_string().as_bytes())
}

impl Store {
    /// Record the outcome of a separately authorized native inventory read.
    /// Orientation consumes this evidence without running the instrument.
    pub fn record_teapot_observation(
        &mut self,
        engagement: &EngagementId,
        route: &Sha256Digest,
        observation: &TeapotObservation,
    ) -> Result<u64> {
        self.write("teapot.observe", engagement.as_str(), |tx| {
            if let Some(previous) = teapot_observation(tx, engagement, route)?
                && instant(&previous.observed_at) > instant(&observation.observed_at)
            {
                return Err(StoreError::Conflict);
            }
            tx.execute(
                "INSERT INTO teapot_entry_observations VALUES (?1, ?2, ?3)
                 ON CONFLICT (engagement_id, route_digest) DO UPDATE SET observation=excluded.observation",
                (engagement.as_str(), route.as_str(), json(observation)?),
            )?;
            Ok(())
        })
    }
}

fn instant(timestamp: &Timestamp) -> OffsetDateTime {
    OffsetDateTime::parse(timestamp.as_str(), &Rfc3339).expect("validated timestamp")
}

pub(super) fn teapot_observation(
    db: &Connection,
    engagement: &EngagementId,
    route: &Sha256Digest,
) -> Result<Option<TeapotObservation>> {
    db.query_row(
        "SELECT CASE WHEN length(observation) <= 512 THEN observation END
         FROM teapot_entry_observations WHERE engagement_id=?1 AND route_digest=?2",
        (engagement.as_str(), route.as_str()),
        |row| row.get::<_, String>(0),
    )
    .optional()?
    .map(|value| json_value(&value))
    .transpose()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttentionReason {
    UnknownEffects,
    PendingCleanup,
    BrokenChain,
}

#[derive(Debug)]
pub struct Attention {
    pub reason: AttentionReason,
    pub run: Option<RunId>,
}

#[derive(Debug, Default)]
pub struct EntrySnapshot {
    pub leads: u64,
    pub runs: u64,
    pub attention_runs: u64,
    pub linked_records: u64,
    pub head_sequence: u64,
    pub broken_chain: bool,
    pub attention: Option<Attention>,
}

/// Read counts and the highest-priority outstanding condition from the same
/// transaction. Only coordination metadata is examined. In particular, a
/// structurally intact index establishes neither evidence nor finding status.
pub(super) fn read(db: &Connection, engagement: &EngagementId) -> Result<EntrySnapshot> {
    let id = engagement.as_str();
    let leads = count(db, "SELECT count(*) FROM leads WHERE engagement_id=?1", id)?;
    let runs = count(db, "SELECT count(*) FROM runs WHERE engagement_id=?1", id)?;
    let linked_records = count(
        db,
        "SELECT count(*) FROM verifications WHERE engagement_id=?1",
        id,
    )?;
    let (head_sequence, broken_chain) = db.query_row(
        "SELECT e.head_sequence,
             e.head_sequence<>?2 OR (e.head_sequence>0 AND NOT EXISTS (
                     SELECT 1 FROM verifications h WHERE h.engagement_id=e.id
                       AND h.sequence=e.head_sequence AND h.record_digest=e.head_digest
             )) OR EXISTS (
             SELECT 1 FROM verifications v
             LEFT JOIN publication_intents i ON i.id=v.intent_id
             LEFT JOIN verifications p ON p.engagement_id=v.engagement_id AND p.sequence=v.sequence-1
             WHERE v.engagement_id=?1 AND (
                 length(v.record_digest)<>64 OR v.record_digest GLOB '*[^0-9a-f]*'
                 OR i.id IS NULL OR i.state<>'complete' OR i.artifact_id IS NULL
                 OR i.artifact_id<>v.artifact_id OR i.engagement_id<>v.engagement_id
                 OR i.run_id<>v.run_id OR i.record_id<>v.record_id OR i.record_digest<>v.record_digest
                 OR i.expected_sequence<>v.sequence-1 OR i.expected_digest IS NOT p.record_digest
                 OR (v.sequence>1 AND p.sequence IS NULL)
             )
         ) FROM engagements e WHERE e.id=?1",
        (id, integer(linked_records)?),
        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, bool>(1)?)),
    )?;

    // The same condition drives both the count and the chosen run. An intent
    // with no recorded outcome is conservatively unresolved even if a process
    // stopped before updating its parent run.
    const ATTENTION: &str = "WITH attention AS (
        SELECT r.id, CASE
            WHEN r.effects='unknown' OR EXISTS (
                SELECT 1 FROM run_steps s WHERE s.run_id=r.id AND (s.effects IS NULL OR s.effects='unknown')
            ) THEN 1
            WHEN r.cleanup IN ('partial', 'failed', 'unknown') THEN 2
        END AS priority
        FROM runs r WHERE r.engagement_id=?1
    )";
    let top_run = db
        .query_row(
            &format!("{ATTENTION} SELECT count(*) OVER (), id, priority FROM attention WHERE priority IS NOT NULL ORDER BY priority, id LIMIT 1"),
            [id],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?, row.get::<_, u8>(2)?)),
        )
        .optional()?;
    let attention_runs = unsigned(top_run.as_ref().map_or(0, |(count, _, _)| *count))?;
    let attention = match top_run {
        Some((_, run, priority)) => Some(Attention {
            reason: match priority {
                1 => AttentionReason::UnknownEffects,
                2 => AttentionReason::PendingCleanup,
                _ => return Err(StoreError::Decode),
            },
            run: Some(run.try_into().map_err(|_| StoreError::Decode)?),
        }),
        None if broken_chain => Some(Attention {
            reason: AttentionReason::BrokenChain,
            run: None,
        }),
        None => None,
    };
    Ok(EntrySnapshot {
        leads,
        runs,
        attention_runs,
        linked_records,
        head_sequence: unsigned(head_sequence)?,
        broken_chain,
        attention,
    })
}

pub(super) fn record_ids(
    db: &Connection,
    engagement: &EngagementId,
    limit: u32,
    offset: u32,
) -> Result<Vec<VerificationId>> {
    let mut query = db.prepare(
        "SELECT record_id FROM verifications WHERE engagement_id=?1 ORDER BY sequence LIMIT ?2 OFFSET ?3",
    )?;
    query
        .query_map((engagement.as_str(), limit, offset), |row| {
            row.get::<_, String>(0)
        })?
        .map(|id| id?.try_into().map_err(|_| StoreError::Decode))
        .collect()
}

fn count(db: &Connection, sql: &str, engagement: &str) -> Result<u64> {
    unsigned(db.query_row(sql, [engagement], |row| row.get(0))?)
}
