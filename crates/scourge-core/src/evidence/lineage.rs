//! Complete current-lineage withdrawal check.
//!
//! The pinned dependency's `evidentiary_use` walks at most 64 current
//! Artifacts and Sources (`MAX_LINEAGE`) and reports no completeness flag, so a
//! withdrawal beyond that scan leaves the state `in_use`. Scourge never
//! treats that bounded answer as complete: it fetches every current record
//! reachable through `transforms[].input` and `source`, verifies each record's
//! revision and digest, and refuses (`LineageUnverified`) when the walk cannot
//! be finished. The bounds below only limit work; they never stand in for
//! completeness.

use std::{
    collections::{HashMap, HashSet},
    time::Instant,
};

use serde_json::Value;

use super::{
    Evidence, EvidenceError, RecordRef, Result, Transform, Withdrawal, digest, field, full_id,
    parse_digest, reported_withdrawal, snapshot,
};
use crate::{canonical::Sha256Digest, ids::ArtifactId};

const MAX_RECORDS: usize = 256;
const MAX_EDGES: usize = 1024;

struct Edge {
    target: RecordRef,
    digest: Option<Sha256Digest>,
}

struct CheckedRecord {
    revision: u64,
    digest: Option<Sha256Digest>,
}

enum Visit {
    Enter(Edge),
    Leave(String),
}

impl Evidence {
    /// Visit every current Artifact and Source reachable from `id`. Each
    /// visited record contributes its own reported withdrawal state even when
    /// its other ancestors lie outside the native 64-record scan. Any record
    /// that cannot be fetched, verified against the same snapshot, or walked
    /// within the bounds refuses the read instead of reporting a use that may
    /// hide a withdrawal.
    pub(super) fn check_lineage(
        &self,
        id: &ArtifactId,
        root: &Value,
        head: &Value,
        deadline: Instant,
    ) -> Result<()> {
        let root_ref: RecordRef = field(&root["record"], "header")?;
        if root_ref.id != id.as_str() || root_ref.revision == 0 {
            return Err(EvidenceError::LineageUnverified);
        }
        let mut visits = vec![Visit::Enter(Edge {
            target: root_ref,
            digest: Some(digest(&root["record"]["body"], "digest")?),
        })];
        let mut checked = HashMap::<String, CheckedRecord>::new();
        let mut active = HashSet::new();
        let mut edge_count = 0;
        let mut withdrawal = None;
        while let Some(visit) = visits.pop() {
            let edge = match visit {
                Visit::Enter(edge) => edge,
                Visit::Leave(id) => {
                    active.remove(&id);
                    continue;
                }
            };
            if edge.target.revision == 0 || active.contains(&edge.target.id) {
                return Err(EvidenceError::LineageUnverified);
            }
            if let Some(record) = checked.get(&edge.target.id) {
                record.verify(&edge)?;
                continue;
            }
            if checked.len() >= MAX_RECORDS {
                return Err(EvidenceError::LineageUnverified);
            }
            if Instant::now() >= deadline {
                return Err(EvidenceError::timeout());
            }
            let fetched;
            let reply = if edge.target.id == id.as_str() {
                root
            } else {
                fetched = self
                    .show_until(&edge.target.id, deadline)
                    .map_err(lineage_error)?;
                &fetched
            };
            if snapshot(reply).map_err(lineage_error)? != *head {
                return Err(EvidenceError::ChangedSnapshot);
            }
            let (record, children) =
                lineage_record(reply, &edge.target.id).map_err(lineage_error)?;
            record.verify(&edge)?;
            match reported_withdrawal(reply).map_err(lineage_error)? {
                Some(Withdrawal::Entire) => {
                    return Err(EvidenceError::Withdrawn {
                        artifact: id.clone(),
                        state: Withdrawal::Entire,
                    });
                }
                Some(Withdrawal::Partial) => withdrawal = Some(Withdrawal::Partial),
                None => {}
            }
            edge_count += children.len();
            if edge_count > MAX_EDGES {
                return Err(EvidenceError::LineageUnverified);
            }
            active.insert(edge.target.id.clone());
            checked.insert(edge.target.id.clone(), record);
            visits.push(Visit::Leave(edge.target.id));
            visits.extend(children.into_iter().rev().map(Visit::Enter));
        }
        match withdrawal {
            Some(state) => Err(EvidenceError::Withdrawn {
                artifact: id.clone(),
                state,
            }),
            None => Ok(()),
        }
    }
}

impl CheckedRecord {
    fn verify(&self, edge: &Edge) -> Result<()> {
        if self.revision < edge.target.revision || self.digest != edge.digest {
            return Err(EvidenceError::LineageUnverified);
        }
        Ok(())
    }
}

fn lineage_record(reply: &Value, id: &str) -> Result<(CheckedRecord, Vec<Edge>)> {
    let header: RecordRef = field(&reply["record"], "header")?;
    if header.id != id || header.revision == 0 || reply["historical"] != false {
        return Err(EvidenceError::LineageUnverified);
    }
    let body = &reply["record"]["body"];
    let mut record = CheckedRecord {
        revision: header.revision,
        digest: None,
    };
    let mut edges = Vec::new();
    if full_id(id, "art_") {
        record.digest = Some(digest(body, "digest")?);
        let source: RecordRef = field(body, "source")?;
        if !full_id(&source.id, "src_") {
            return Err(EvidenceError::LineageUnverified);
        }
        edges.push(Edge {
            target: source,
            digest: None,
        });
        let transforms = body["transforms"]
            .as_array()
            .ok_or(EvidenceError::LineageUnverified)?;
        if transforms.len() >= MAX_EDGES {
            return Err(EvidenceError::LineageUnverified);
        }
        for transform in transforms {
            let transform: Transform = serde_json::from_value(transform.clone())
                .map_err(|_| EvidenceError::LineageUnverified)?;
            if !full_id(&transform.input.id, "art_") {
                return Err(EvidenceError::LineageUnverified);
            }
            edges.push(Edge {
                digest: Some(parse_digest(&transform.input_digest)?),
                target: transform.input,
            });
        }
    } else if !full_id(id, "src_") || !body.is_object() {
        return Err(EvidenceError::LineageUnverified);
    }
    Ok((record, edges))
}

fn lineage_error(error: EvidenceError) -> EvidenceError {
    match error {
        EvidenceError::Missing | EvidenceError::Protocol => EvidenceError::LineageUnverified,
        error => error,
    }
}
