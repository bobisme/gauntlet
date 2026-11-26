//! Named, coherent coordination and evidence reads.
use crate::verification::{
    record::{EvidenceSnapshot, LinkedEvidenceSnapshot, RecordError, evidence_code},
    status::{
        self, Audience, Computed, RegistrySnapshot, Status, StatusComputer, standing_true_records,
    },
};
use crate::{
    canonical::Sha256Digest,
    domain::{LeadEvent, LeadEventKind},
    evidence::{Evidence, EvidenceError},
    ids::{ArtifactId, EngagementId, LeadId, VerificationId},
    store::{
        StoreError,
        read::{LinkedChain, ReadStore},
    },
    wire::{
        Applicability, Checkpoint, Custody, ErrorCode, FindingStatus, FindingSummary, OracleResult,
    },
    workspace::VerifierEvidence,
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
    pub lead_revision: Option<u64>,
    /// A fully qualified projection, present only for a current coherent read.
    pub finding: Option<FindingSummary>,
    /// The typed caveat for the projected finding's exact status record.
    pub after_owner_read: Option<bool>,
}

impl CoherentRead {
    /// Materiality and resolution are not established by an objection event
    /// alone. Withhold an otherwise undisputed current badge until adjudicated.
    pub fn has_unassessed_objection(&self) -> bool {
        self.freshness == Freshness::Current && unassessed_objection(&self.computed, &self.events)
    }
}

struct Projection {
    computed: Computed,
    standing_true: Vec<StandingRecord>,
    events: Vec<LeadEvent>,
    lead_revision: Option<u64>,
    finding: Option<FindingSummary>,
    after_owner_read: Option<bool>,
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

impl ReadError {
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Store(error) => error.error_code(),
            Self::Evidence(error) => evidence_code(error),
            Self::Record(error) => error.code(),
            Self::NoCoherentRead => ErrorCode::CapabilityUnavailable,
        }
    }
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
    read_with(
        store,
        engagement,
        lead,
        audience,
        attempts,
        |anchor| anchor.map(|id| evidence.checkpoint_for(id)).transpose(),
        |chain, lead| EvidenceSnapshot::capture_linked(evidence, chain, lead),
    )
}

/// Read a finding only when its current indexed manifest and pass are the
/// ones bound by the operator. Recheck retention within the evidence snapshot.
pub fn read_qualified(
    store: &ReadStore,
    qualified: &VerifierEvidence<'_>,
    lead: &LeadId,
    audience: Audience,
    attempts: usize,
) -> Result<CoherentRead, ReadError> {
    let evidence = qualified.evidence();
    let pin = qualified.manifest();
    read_with(
        store,
        qualified.engagement(),
        lead,
        audience,
        attempts,
        |_| {
            evidence
                .checkpoint_for(&pin.artifact.reference.artifact_id)
                .map(Some)
        },
        |chain, lead| {
            if !chain.manifests().last().is_some_and(|index| {
                index.revision() == pin.revision
                    && index.artifact() == &pin.artifact.reference
                    && index.pass_digest() == qualified.pass_digest()
            }) {
                return Err(RecordError::InvalidRecord);
            }
            qualified.check_manifest()?;
            EvidenceSnapshot::capture_linked(evidence, chain, lead)
        },
    )
}

pub(crate) fn read_with(
    store: &ReadStore,
    engagement: &EngagementId,
    lead: &LeadId,
    audience: Audience,
    attempts: usize,
    checkpoint: impl Fn(Option<&ArtifactId>) -> Result<Option<serde_json::Value>, EvidenceError>,
    capture: impl Fn(&LinkedChain, &LeadId) -> Result<LinkedEvidenceSnapshot, RecordError>,
) -> Result<CoherentRead, ReadError> {
    let result = assemble(
        attempts.min(3),
        || {
            let (revision, chain_checkpoint, chain) = store.snapshot(|snapshot| {
                let (revision, checkpoint) = snapshot.checkpoint(engagement)?;
                let chain = snapshot.scope(engagement.clone())?.linked_chain(lead)?;
                Ok((revision, checkpoint, chain))
            })?;
            let anchor = chain
                .manifests()
                .first()
                .map(|index| index.artifact().artifact_id.clone());
            let Some(before) = checkpoint(anchor.as_ref())? else {
                return Ok(None);
            };
            // Establish that the two named states actually overlapped.
            // If coordination moved before the first evidence checkpoint,
            // their combination is not a historical snapshot.
            let overlap = store.snapshot(|snapshot| snapshot.checkpoint(engagement))?;
            if overlap != (revision, chain_checkpoint.clone()) {
                return Ok(None);
            }
            let registry = RegistrySnapshot::compiled();
            let version = registry_version();
            let captured = capture(&chain, lead);
            let after = checkpoint(anchor.as_ref())?;
            if after.as_ref() != Some(&before) {
                return Ok(None);
            }
            let captured = match captured {
                Ok(value) => value,
                Err(RecordError::Evidence(EvidenceError::ChangedSnapshot)) => return Ok(None),
                Err(error) => return Err(ReadError::from(error)),
            };
            let projection = project(lead, &captured, audience, &registry);
            let name = SnapshotName {
                coordination_revision: revision,
                chain: chain_checkpoint,
                evidence: before,
                registry_version: version,
            };
            Ok(Some((name, (anchor, projection))))
        },
        |name, (anchor, _)| {
            let (revision, chain) = store.snapshot(|snapshot| snapshot.checkpoint(engagement))?;
            let evidence_head = checkpoint(anchor.as_ref())?;
            Ok(revision == name.coordination_revision
                && chain == name.chain
                && evidence_head.as_ref() == Some(&name.evidence)
                && registry_version() == name.registry_version)
        },
    )?;
    let Some((name, (_, projection), freshness)) = result else {
        return Err(ReadError::NoCoherentRead);
    };
    Ok(CoherentRead {
        name,
        freshness,
        computed: projection.computed,
        standing_true: projection.standing_true,
        events: projection.events,
        lead_revision: projection.lead_revision,
        finding: if freshness == Freshness::Current {
            projection.finding
        } else {
            None
        },
        after_owner_read: if freshness == Freshness::Current {
            projection.after_owner_read
        } else {
            None
        },
    })
}

fn project(
    lead: &LeadId,
    captured: &LinkedEvidenceSnapshot,
    audience: Audience,
    registry: &RegistrySnapshot,
) -> Projection {
    let (computed, policy_source) =
        StatusComputer::compute_linked(lead, captured, audience, registry);
    let standing_true: Vec<_> = standing_true_records(captured, registry)
        .into_iter()
        .map(|(record_id, custody)| StandingRecord { record_id, custody })
        .collect();
    let projected = (|| {
        if unassessed_objection(&computed, captured.events()) {
            return None;
        }
        let status = match computed.status {
            Status::Verified => FindingStatus::Verified,
            Status::Conditional => FindingStatus::Conditional,
            Status::Disputed => FindingStatus::Disputed,
            Status::Refuted => FindingStatus::Refuted,
            Status::NeedsReview => FindingStatus::NeedsReview,
            Status::Lead { .. } | Status::IntegrityFailure => return None,
        };
        let status_record = computed.status_record.as_ref()?;
        if !computed.qualified
            || (status != FindingStatus::NeedsReview
                && !standing_true
                    .iter()
                    .any(|record| &record.record_id == status_record))
        {
            return None;
        }
        let (_, record) = captured
            .records()
            .iter()
            .find(|(_, record)| &record.record_id == status_record)?;
        let applicability = match computed.applicability {
            status::Applicability::AsObserved => Applicability::AsObserved,
            status::Applicability::StillViolated => Applicability::StillViolated,
            status::Applicability::FixedWithinTestedScope => Applicability::FixedWithinTestedScope,
            status::Applicability::Unestablished => Applicability::Unestablished,
        };
        let after_owner_read = finding_after_owner_read(status, record);
        Some((
            FindingSummary {
                id: lead.clone(),
                status,
                applicability,
                profile: record.profile,
                oracle: format!(
                    "{}.v{}",
                    record.oracle.id.as_str(),
                    record.oracle.version.as_str()
                )
                .parse()
                .expect("qualified oracle ID and version"),
                validation: record.validation,
                exposure: record.exposure,
                custody: record.custody,
                target_isolation: record.target_isolation,
                enforcement: record.enforcement,
                policy_source,
                status_record: computed.status_record.clone(),
                deciding_record: computed.deciding_record.clone(),
            },
            after_owner_read,
        ))
    })();
    let (finding, after_owner_read) = projected
        .map(|(finding, caveat)| (Some(finding), caveat))
        .unwrap_or((None, None));
    Projection {
        computed,
        standing_true,
        events: captured.events().to_vec(),
        lead_revision: captured.bindings().last().map(|binding| binding.revision),
        finding,
        after_owner_read,
    }
}

/// Project the one typed oracle caveat that M1 exposes publicly. The value is
/// meaningful only for a current, qualified positive finding from the exact
/// compiled private-object-read oracle. `false` distinguishes an ordinary
/// positive exposure from the owner-primed cache condition; non-positive and
/// non-current statuses disclose no round note.
fn finding_after_owner_read(
    status: FindingStatus,
    record: &crate::wire::VerificationV1,
) -> Option<bool> {
    if !matches!(status, FindingStatus::Verified | FindingStatus::Conditional)
        || record.result != OracleResult::True
        || record.oracle.id.as_str() != crate::verification::registry::ORACLE_ID
        || record.oracle.version.as_str() != crate::verification::registry::ORACLE_VERSION
        || record.oracle.digest != crate::verification::registry::oracle_digest()
    {
        return None;
    }
    let mut positive = record
        .rounds
        .iter()
        .filter(|round| round.result == OracleResult::True)
        .peekable();
    positive
        .peek()
        .is_some()
        .then(|| positive.any(|round| round.after_owner_read))
}

fn unassessed_objection(computed: &Computed, events: &[LeadEvent]) -> bool {
    matches!(computed.status, Status::Verified | Status::Conditional)
        && events
            .iter()
            .any(|event| event.kind == LeadEventKind::Objection)
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
