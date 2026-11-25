//! Named, coherent coordination and evidence reads.
use crate::verification::{
    record::{EvidenceSnapshot, RecordError},
    status::{
        Audience, Computed, RegistrySnapshot, StatusComputer, StatusSnapshot, standing_true_records,
    },
};
use crate::{
    canonical::Sha256Digest,
    domain::LeadEvent,
    evidence::{Evidence, EvidenceError},
    ids::{EngagementId, LeadId, VerificationId},
    store::{StoreError, read::ReadStore},
    wire::{Checkpoint, Custody},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotName {
    pub coordination_revision: u64,
    pub chain: Checkpoint,
    pub evidence: serde_json::Value,
    pub registry_version: Sha256Digest,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Freshness {
    Current,
    Historical,
}
#[derive(Debug)]
pub struct StandingRecord {
    pub record_id: VerificationId,
    pub custody: Custody,
}
#[derive(Debug)]
pub struct CoherentRead {
    pub name: SnapshotName,
    pub freshness: Freshness,
    pub computed: Computed,
    pub standing_true: Vec<StandingRecord>,
    pub events: Vec<LeadEvent>,
}
#[derive(Debug, thiserror::Error)]
pub enum ReadError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Evidence(#[from] EvidenceError),
    #[error(transparent)]
    Record(#[from] RecordError),
    #[error("no coherent read could be assembled")]
    NoCoherentRead,
}
pub fn registry_version() -> Sha256Digest {
    let bytes = serde_json::to_vec(&(
        env!("CARGO_PKG_VERSION"),
        crate::verification::registry::ORACLE_SPECIFICATION,
        crate::verification::registry::REVOKED_ORACLES,
        include_str!("registry.rs"),
    ))
    .expect("compiled registry serializes");
    Sha256Digest::of(&bytes)
}
/// Copy coordination rows before opening Evidence. An attempt is complete
/// only if Evidence remained at the same checkpoint throughout collection.
pub fn read(
    store: &ReadStore,
    evidence: &Evidence,
    engagement: &EngagementId,
    lead: &LeadId,
    audience: Audience,
    attempts: usize,
) -> Result<CoherentRead, ReadError> {
    let result = assemble(
        attempts.min(3),
        || {
            let (revision, chain_checkpoint, chain) = store.snapshot(|snapshot| {
                let (revision, checkpoint) = snapshot.checkpoint(engagement)?;
                let chain = snapshot.scope(engagement.clone())?.linked_chain(lead)?;
                Ok((revision, checkpoint, chain))
            })?;
            let Some(anchor) = chain.manifests().first() else {
                return Ok(None);
            };
            let anchor = anchor.artifact().artifact_id.clone();
            let before = evidence.checkpoint_for(&anchor)?;
            // Establish that the two named states actually overlapped.
            // If coordination moved before the first evidence checkpoint,
            // their combination is not a historical snapshot.
            let overlap = store.snapshot(|snapshot| snapshot.checkpoint(engagement))?;
            if overlap != (revision, chain_checkpoint.clone()) {
                return Ok(None);
            }
            let registry = RegistrySnapshot::compiled();
            let version = registry_version();
            let captured = EvidenceSnapshot::capture_linked(evidence, &chain, lead);
            let after = evidence.checkpoint_for(&anchor)?;
            if before != after {
                return Ok(None);
            }
            let captured = match captured {
                Ok(value) => value,
                Err(RecordError::Evidence(EvidenceError::ChangedSnapshot)) => return Ok(None),
                Err(error) => return Err(ReadError::from(error)),
            };
            let standing_true = standing_true_records(&captured, &registry)
                .into_iter()
                .map(|(record_id, custody)| StandingRecord { record_id, custody })
                .collect();
            let events = captured.events().to_vec();
            let snapshot = StatusSnapshot::from_capture(Ok(captured))
                .expect("a successful capture is accepted");
            let computed = StatusComputer::compute(lead, &snapshot, audience, &registry);
            let name = SnapshotName {
                coordination_revision: revision,
                chain: chain_checkpoint,
                evidence: before,
                registry_version: version,
            };
            Ok(Some((name, (anchor, computed, standing_true, events))))
        },
        |name, (anchor, _, _, _)| {
            let (revision, chain) = store.snapshot(|snapshot| snapshot.checkpoint(engagement))?;
            let evidence_head = evidence.checkpoint_for(anchor)?;
            Ok(revision == name.coordination_revision
                && chain == name.chain
                && evidence_head == name.evidence
                && registry_version() == name.registry_version)
        },
    )?;
    let Some((name, (_, computed, standing_true, events), freshness)) = result else {
        return Err(ReadError::NoCoherentRead);
    };
    Ok(CoherentRead {
        name,
        freshness,
        computed,
        standing_true,
        events,
    })
}

/// Keep only complete captures; never invent history from a mixed collection.
pub(crate) fn assemble<N, T, E>(
    attempts: usize,
    mut capture: impl FnMut() -> Result<Option<(N, T)>, E>,
    mut current: impl FnMut(&N, &T) -> Result<bool, E>,
) -> Result<Option<(N, T, Freshness)>, E> {
    let mut historical = None;
    for _ in 0..attempts {
        let Some((name, value)) = capture()? else {
            continue;
        };
        if current(&name, &value)? {
            return Ok(Some((name, value, Freshness::Current)));
        }
        historical = Some((name, value, Freshness::Historical));
    }
    Ok(historical)
}

#[cfg(test)]
mod tests {
    use super::{Freshness, assemble};
    use std::cell::RefCell;

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct Name {
        revision: u64,
        chain: u64,
        evidence: u64,
        registry: u64,
    }
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct Rows {
        objection: bool,
    }

    #[test]
    fn objection_committed_during_collection_is_in_newer_result() {
        let state = RefCell::new((
            Name {
                revision: 1,
                chain: 1,
                evidence: 1,
                registry: 1,
            },
            Rows { objection: false },
        ));
        let once = RefCell::new(true);
        let result = assemble(
            2,
            || -> Result<_, ()> {
                let captured = state.borrow().clone();
                if std::mem::take(&mut *once.borrow_mut()) {
                    let mut live = state.borrow_mut();
                    live.0.revision += 1;
                    live.1.objection = true;
                }
                Ok(Some(captured))
            },
            |name, _| Ok(*name == state.borrow().0),
        )
        .unwrap()
        .unwrap();
        assert_eq!(result.0.revision, 2);
        assert!(result.1.objection);
        assert_eq!(result.2, Freshness::Current);
    }

    #[test]
    fn independent_movement_never_labels_old_rows_current() {
        for component in 0..4 {
            let name = Name {
                revision: 1,
                chain: 1,
                evidence: 1,
                registry: 1,
            };
            let mut newer = name.clone();
            match component {
                0 => newer.revision += 1,
                1 => newer.chain += 1,
                2 => newer.evidence += 1,
                _ => newer.registry += 1,
            }
            let result = assemble(
                1,
                || -> Result<_, ()> { Ok(Some((name.clone(), Rows { objection: false }))) },
                |captured, _| Ok(*captured == newer),
            )
            .unwrap()
            .unwrap();
            assert_eq!(result.0, name);
            assert_eq!(result.2, Freshness::Historical);
        }
    }

    #[test]
    fn mixed_attempt_is_not_historical_and_cannot_replace_complete_one() {
        let mut step = 0;
        let result = assemble(
            2,
            || -> Result<_, ()> {
                step += 1;
                Ok(if step == 1 {
                    Some((1, "complete"))
                } else {
                    None
                })
            },
            |_, _| Ok(false),
        )
        .unwrap()
        .unwrap();
        assert_eq!(result, (1, "complete", Freshness::Historical));
        assert!(
            assemble::<u8, u8, ()>(2, || Ok(None), |_, _| Ok(false))
                .unwrap()
                .is_none()
        );
    }
}
