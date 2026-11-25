//! Pure status and applicability decisions over a captured, linked snapshot.

use crate::{
    domain::LeadEventKind,
    engagement::ManifestRevision,
    evidence::Evidence,
    ids::{LeadId, VerificationId},
    policy::{Access, Policy, PolicyContext, PolicyDecision},
    store::{StoreError, read::LinkedChain},
    template::FrozenExperiment,
    wire::ErrorCode,
    wire::{
        Custody, Exposure, FunctionalResult, OracleResult, PropertyResult, RecordKind, SlotSource,
        VersionedDigest,
    },
};

use crate::verification::record::{LinkedEvidenceSnapshot, RecordError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Audience {
    Internal,
    ThirdParty,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeadState {
    Open,
    Withdrawn,
    Duplicate,
    Deferred,
    Blocked,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LastOutcome {
    None,
    False,
    Invalid,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    IntegrityFailure,
    Lead { state: LeadState, last: LastOutcome },
    Refuted,
    NeedsReview,
    Disputed,
    Conditional,
    Verified,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Applicability {
    AsObserved,
    StillViolated,
    FixedWithinTestedScope,
    Unestablished,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Computed {
    pub status: Status,
    pub applicability: Applicability,
    pub status_record: Option<VerificationId>,
    pub deciding_record: Option<VerificationId>,
    pub qualified: bool,
}

/// Registry revocations captured for this read; no cached result enters this list.
#[derive(Debug)]
pub struct RegistrySnapshot {
    revoked: Vec<VersionedDigest>,
}
impl RegistrySnapshot {
    pub fn compiled() -> Self {
        Self {
            revoked: crate::verification::registry::REVOKED_ORACLES
                .iter()
                .map(|(id, version, digest)| VersionedDigest {
                    id: (*id).parse().expect("compiled oracle id"),
                    version: (*version).parse().expect("compiled oracle version"),
                    digest: (*digest).parse().expect("compiled oracle digest"),
                })
                .collect(),
        }
    }
    #[cfg(test)]
    pub(crate) fn revoked(oracle: VersionedDigest) -> Self {
        Self {
            revoked: vec![oracle],
        }
    }
}

#[derive(Default, Clone, Copy)]
struct ValidatedFacts {
    refutation: bool,
    objection: bool,
}

/// Failure to capture coordination or retained evidence for a status read.
#[derive(Debug, thiserror::Error)]
pub enum StatusCaptureError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Record(#[from] RecordError),
}

/// Opaque outcome of capturing the stores for one status read.
pub struct StatusSnapshot(Option<LinkedEvidenceSnapshot>);
impl StatusSnapshot {
    /// Classify capture errors once, preserving non-integrity failures for the caller.
    pub fn from_capture(
        result: Result<LinkedEvidenceSnapshot, StatusCaptureError>,
    ) -> Result<Self, StatusCaptureError> {
        match result {
            Ok(snapshot) => Ok(Self(Some(snapshot))),
            Err(error)
                if match &error {
                    StatusCaptureError::Store(error) => {
                        error.error_code() == ErrorCode::IntegrityFailure
                    }
                    StatusCaptureError::Record(error) => {
                        error.code() == ErrorCode::IntegrityFailure
                    }
                } =>
            {
                Ok(Self(None))
            }
            Err(error) => Err(error),
        }
    }

    /// Perform store/evidence capture before the pure calculation.
    pub fn capture(
        evidence: &Evidence,
        chain: Result<LinkedChain, StoreError>,
        lead: &LeadId,
    ) -> Result<Self, StatusCaptureError> {
        Self::from_capture(chain.map_err(StatusCaptureError::Store).and_then(|chain| {
            crate::verification::record::EvidenceSnapshot::capture_linked(evidence, &chain, lead)
                .map_err(StatusCaptureError::Record)
        }))
    }
}

pub struct StatusComputer;
impl StatusComputer {
    pub fn compute(
        lead: &LeadId,
        snapshot: &StatusSnapshot,
        audience: Audience,
        registry: &RegistrySnapshot,
    ) -> Computed {
        let Some(snapshot) = &snapshot.0 else {
            return Computed {
                status: Status::IntegrityFailure,
                applicability: Applicability::Unestablished,
                status_record: None,
                deciding_record: None,
                qualified: true,
            };
        };
        Self::compute_with(
            lead,
            snapshot,
            audience,
            ValidatedFacts::default(),
            &|artifact, record| evidence_standing(snapshot, artifact, record, registry),
        )
    }

    #[cfg(test)]
    pub(crate) fn compute_for_test(
        lead: &LeadId,
        snapshot: &LinkedEvidenceSnapshot,
        audience: Audience,
        _registry: &RegistrySnapshot,
        refutation: bool,
        objection: bool,
        standing: impl Fn(&crate::wire::Artifact, &crate::wire::VerificationV1) -> Option<bool>,
    ) -> Computed {
        Self::compute_with(
            lead,
            snapshot,
            audience,
            ValidatedFacts {
                refutation,
                objection,
            },
            &standing,
        )
    }

    fn compute_with(
        lead: &LeadId,
        snapshot: &LinkedEvidenceSnapshot,
        audience: Audience,
        facts: ValidatedFacts,
        standing: &dyn Fn(&crate::wire::Artifact, &crate::wire::VerificationV1) -> Option<bool>,
    ) -> Computed {
        let integrity = || Computed {
            status: Status::IntegrityFailure,
            applicability: Applicability::Unestablished,
            status_record: None,
            deciding_record: None,
            qualified: true,
        };
        if lead != snapshot.lead() {
            return integrity();
        }
        let records: Vec<_> = snapshot
            .records()
            .iter()
            .filter(|(_, record)| &record.lead_id == lead)
            .collect();
        // An internally inconsistent true summary is broken, even if its
        // claimed rounds would otherwise make it ineligible as S.
        if records.iter().any(|(_, r)| {
            r.kind == RecordKind::Verify
                && r.result == OracleResult::True
                && !true_summary_consistent(r)
        }) {
            return integrity();
        }
        let qualifies = |custody| audience == Audience::Internal || custody == Custody::Isolated;
        let s = records
            .iter()
            .rev()
            .find(|(_, r)| {
                r.kind == RecordKind::Verify
                    && r.result == OracleResult::True
                    && profile_true(r)
                    && qualifies(r.custody)
            })
            .copied();
        let Some((s_artifact, s_record)) = s else {
            let any_true = records.iter().any(|(_, r)| {
                r.kind == RecordKind::Verify && r.result == OracleResult::True && profile_true(r)
            });
            if any_true {
                let mut own =
                    Self::compute_with(lead, snapshot, Audience::Internal, facts, standing);
                own.qualified = false;
                own.applicability = Applicability::Unestablished;
                return own;
            }
            if facts.refutation {
                return Computed {
                    status: Status::Refuted,
                    applicability: Applicability::Unestablished,
                    status_record: None,
                    deciding_record: None,
                    qualified: true,
                };
            }
            let state = snapshot
                .events()
                .iter()
                .rev()
                .find_map(|event| match event.kind {
                    LeadEventKind::Withdrawn => Some(LeadState::Withdrawn),
                    LeadEventKind::Duplicate { .. } => Some(LeadState::Duplicate),
                    LeadEventKind::Deferred => Some(LeadState::Deferred),
                    LeadEventKind::Blocked { .. } => Some(LeadState::Blocked),
                    LeadEventKind::Set { .. } => Some(LeadState::Open),
                    _ => None,
                })
                .unwrap_or(LeadState::Open);
            let last = records
                .iter()
                .rev()
                .find(|(_, r)| r.kind == RecordKind::Verify)
                .map_or(LastOutcome::None, |(_, r)| match r.result {
                    OracleResult::False => LastOutcome::False,
                    OracleResult::Invalid | OracleResult::Error => LastOutcome::Invalid,
                    OracleResult::True => LastOutcome::Invalid,
                });
            return Computed {
                status: Status::Lead { state, last },
                applicability: Applicability::Unestablished,
                status_record: None,
                deciding_record: None,
                qualified: true,
            };
        };
        let s_experiment = match snapshot.experiment(s_artifact, s_record) {
            Ok(value) => value,
            Err(_) => return integrity(),
        };
        let Some(s_manifest) = snapshot
            .manifests()
            .iter()
            .find(|m| m.revision() == s_record.engagement_revision)
        else {
            return integrity();
        };
        if !experiment_matches_manifest(&s_experiment, s_manifest) {
            return integrity();
        }
        let mut d = (s_artifact, s_record);
        for (artifact, record) in &records {
            if record.sequence <= s_record.sequence {
                continue;
            }
            if record.kind == RecordKind::Retest
                && record.retest.as_ref().is_some_and(|r| {
                    r.baseline_record == s_record.record_id
                        && r.baseline_digest == s_artifact.digest
                })
            {
                d = (artifact, record);
            }
            if record.kind == RecordKind::Verify
                && record.result == OracleResult::False
                && record.property.id == s_record.property.id
                && same_record_slots(&record.slots, &s_record.slots)
                && same_lead_bindings(snapshot, record.lead_revision, s_record.lead_revision)
            {
                match snapshot.experiment(artifact, record) {
                    Ok(experiment) if same_bindings(&s_experiment, &experiment) => {
                        let Some(manifest) = snapshot
                            .manifests()
                            .iter()
                            .find(|m| m.revision() == record.engagement_revision)
                        else {
                            return integrity();
                        };
                        if !experiment_matches_manifest(&experiment, manifest) {
                            return integrity();
                        }
                        if manifest_bindings_same(s_manifest, manifest, &s_experiment) {
                            d = (artifact, record);
                        }
                    }
                    Err(_) => return integrity(),
                    _ => {}
                }
            }
        }
        let ids = (
            Some(s_record.record_id.clone()),
            Some(d.1.record_id.clone()),
        );
        let finish = |status, applicability| Computed {
            status,
            applicability,
            status_record: ids.0.clone(),
            deciding_record: ids.1.clone(),
            qualified: true,
        };
        let Some(s_stands) = standing(s_artifact, s_record) else {
            return finish(Status::IntegrityFailure, Applicability::Unestablished);
        };
        let Some(d_stands) = standing(d.0, d.1) else {
            return finish(Status::IntegrityFailure, Applicability::Unestablished);
        };
        let run_manifest = s_manifest;
        let Some(bindings_stand) =
            current_bindings_stand(snapshot, s_record, &s_experiment, run_manifest)
        else {
            return finish(Status::IntegrityFailure, Applicability::Unestablished);
        };
        if !s_stands || !bindings_stand {
            return finish(Status::NeedsReview, Applicability::Unestablished);
        }
        let policy = applicable_policy(
            snapshot.manifests(),
            run_manifest,
            &s_experiment,
            s_record.exposure,
        );
        let Some(exposure) = s_record.exposure else {
            return finish(Status::IntegrityFailure, Applicability::Unestablished);
        };
        let mut applicability = if !d_stands || !qualifies(d.1.custody) {
            Applicability::Unestablished
        } else {
            applicability(d.1, s_record.sequence)
        };
        if snapshot.records().iter().any(|(_, r)| {
            r.sequence > d.1.sequence
                && r.target.origin == d.1.target.origin
                && r.target.deployment_marker != d.1.target.deployment_marker
        }) {
            applicability = Applicability::Unestablished;
        }
        if audience == Audience::ThirdParty
            && records.iter().any(|(_, r)| {
                r.sequence > s_record.sequence
                    && r.kind == RecordKind::Verify
                    && r.result == OracleResult::True
                    && !qualifies(r.custody)
            })
        {
            applicability = Applicability::Unestablished;
        }
        if policy == Some(false)
            && later_allowing(snapshot.manifests(), run_manifest, &s_experiment, exposure)
        {
            applicability = Applicability::Unestablished;
        }
        if policy == Some(true) {
            return finish(Status::Refuted, applicability);
        }
        if facts.objection {
            return finish(Status::Disputed, applicability);
        }
        let owner_from_lead = s_record
            .slots
            .iter()
            .any(|slot| slot.name.as_str() == "owner" && slot.source == SlotSource::Lead);
        if policy.is_none() || owner_from_lead {
            finish(Status::Conditional, applicability)
        } else {
            finish(Status::Verified, applicability)
        }
    }
}

/// The same evidence and current-binding gates used by status computation.
/// The list is audience-independent so each standing custody tier remains visible.
pub(crate) fn standing_true_records(
    snapshot: &LinkedEvidenceSnapshot,
    registry: &RegistrySnapshot,
) -> Vec<(VerificationId, Custody)> {
    snapshot
        .records()
        .iter()
        .filter_map(|(artifact, record)| {
            if &record.lead_id != snapshot.lead()
                || record.kind != RecordKind::Verify
                || record.result != OracleResult::True
                || !true_summary_consistent(record)
                || !profile_true(record)
                || evidence_standing(snapshot, artifact, record, registry) != Some(true)
            {
                return None;
            }
            let experiment = snapshot.experiment(artifact, record).ok()?;
            let manifest = snapshot
                .manifests()
                .iter()
                .find(|m| m.revision() == record.engagement_revision)?;
            if !experiment_matches_manifest(&experiment, manifest)
                || current_bindings_stand(snapshot, record, &experiment, manifest) != Some(true)
            {
                return None;
            }
            Some((record.record_id.clone(), record.custody))
        })
        .collect()
}

fn evidence_standing(
    snapshot: &LinkedEvidenceSnapshot,
    artifact: &crate::wire::Artifact,
    record: &crate::wire::VerificationV1,
    registry: &RegistrySnapshot,
) -> Option<bool> {
    match snapshot.reevaluate(artifact) {
        Ok(_) if !registry.revoked.contains(&record.oracle) => Some(true),
        Ok(_) | Err(RecordError::OracleUnavailable) => Some(false),
        Err(_) => None,
    }
}

fn current_bindings_stand(
    snapshot: &LinkedEvidenceSnapshot,
    record: &crate::wire::VerificationV1,
    experiment: &FrozenExperiment,
    run_manifest: &ManifestRevision,
) -> Option<bool> {
    let current_manifest = snapshot.manifests().last()?;
    let current_binding = snapshot.bindings().last();
    Some(
        current_binding.is_some_and(|binding| {
            same_lead_bindings(snapshot, record.lead_revision, binding.revision)
        }) && manifest_bindings_same(run_manifest, current_manifest, experiment),
    )
}

fn true_summary_consistent(record: &crate::wire::VerificationV1) -> bool {
    let yes = record
        .rounds
        .iter()
        .filter(|round| round.result == OracleResult::True)
        .count();
    yes > 0
        && record
            .rounds
            .iter()
            .all(|round| matches!(round.result, OracleResult::True | OracleResult::False))
        && record.reproduction
            == if yes == record.rounds.len() {
                crate::wire::Reproduction::Reproduced
            } else {
                crate::wire::Reproduction::Intermittent
            }
}
fn profile_true(record: &crate::wire::VerificationV1) -> bool {
    if record.rounds.is_empty()
        || record
            .rounds
            .iter()
            .any(|round| !matches!(round.result, OracleResult::True | OracleResult::False))
    {
        return false;
    }
    let true_count = record
        .rounds
        .iter()
        .filter(|round| round.result == OracleResult::True)
        .count();
    match record.profile {
        crate::wire::Profile::RuntimeControlledV1 => true_count == record.rounds.len(),
        crate::wire::Profile::RuntimeIntermittentV1 => true_count >= 2,
    }
}
fn same_record_slots(a: &[crate::wire::Slot], b: &[crate::wire::Slot]) -> bool {
    a.len() == b.len()
        && a.iter()
            .zip(b)
            .all(|(x, y)| x.name == y.name && x.digest == y.digest)
}
fn same_lead_bindings(snapshot: &LinkedEvidenceSnapshot, a: u64, b: u64) -> bool {
    snapshot
        .bindings()
        .iter()
        .find(|value| value.revision == a)
        .zip(snapshot.bindings().iter().find(|value| value.revision == b))
        .is_some_and(|(x, y)| x.class == y.class && x.property == y.property && x.slots == y.slots)
}
fn same_bindings(a: &FrozenExperiment, b: &FrozenExperiment) -> bool {
    a.property
        .as_ref()
        .zip(b.property.as_ref())
        .is_some_and(|(x, y)| x.label == y.label && x.resource == y.resource)
        && a.slots.len() == b.slots.len()
        && a.slots.iter().all(|(name, slot)| {
            b.slots
                .get(name)
                .is_some_and(|other| slot.value == other.value)
        })
        && a.principals == b.principals
}
fn experiment_matches_manifest(experiment: &FrozenExperiment, manifest: &ManifestRevision) -> bool {
    if experiment.engagement.revision != manifest.revision()
        || &experiment.engagement.digest != manifest.digest()
    {
        return false;
    }
    let Some(property) = &experiment.property else {
        return false;
    };
    let Some(declared) = manifest.properties().get(&property.label) else {
        return false;
    };
    if declared.resource != property.resource
        || crate::canonical::to_vec(declared)
            .ok()
            .is_none_or(|bytes| crate::canonical::Sha256Digest::of(&bytes) != property.digest)
    {
        return false;
    }
    experiment.principals.values().all(|bound| {
        manifest
            .principals()
            .get(&bound.principal)
            .is_some_and(|principal| {
                principal.session == bound.session
                    && principal.verifier_session == bound.verifier_session
                    && principal.groups == bound.groups
                    && principal.identity_probe == bound.identity_probe
            })
    })
}
fn manifest_bindings_same(
    a: &ManifestRevision,
    b: &ManifestRevision,
    experiment: &FrozenExperiment,
) -> bool {
    let Some(property) = &experiment.property else {
        return false;
    };
    let same_property = a
        .properties()
        .get(&property.label)
        .zip(b.properties().get(&property.label))
        .is_some_and(|(x, y)| {
            x.resource == y.resource
                && x.read == y.read
                && x.write == y.write
                && x.plant == y.plant
                && x.remove == y.remove
        });
    same_property
        && experiment.principals.values().all(|bound| {
            a.principals().get(&bound.principal) == b.principals().get(&bound.principal)
        })
}
fn policy_allows(
    manifest: &ManifestRevision,
    experiment: &FrozenExperiment,
    exposure: Exposure,
) -> Option<bool> {
    let property = experiment.property.as_ref()?;
    let owner = &experiment
        .principals
        .iter()
        .find(|(slot, _)| slot.as_str() == "owner")?
        .1
        .principal;
    let actor = match exposure {
        Exposure::Unauthenticated => None,
        Exposure::CrossPrincipal => Some(
            &experiment
                .principals
                .iter()
                .find(|(slot, _)| slot.as_str() == "other")?
                .1
                .principal,
        ),
    };
    match Policy::allows_engagement(
        exposure,
        PolicyContext {
            manifest,
            property: &property.label,
            resource: &property.resource,
            target_version: manifest.target_version(),
            access: Access::Read,
            owner,
            actor,
        },
    ) {
        PolicyDecision::Allowed => Some(true),
        PolicyDecision::Denied => Some(false),
        PolicyDecision::NoRule => None,
    }
}
fn applicable_policy(
    manifests: &[ManifestRevision],
    at_run: &ManifestRevision,
    experiment: &FrozenExperiment,
    exposure: Option<Exposure>,
) -> Option<bool> {
    let exposure = exposure?;
    policy_allows(at_run, experiment, exposure).or_else(|| {
        manifests
            .iter()
            .filter(|m| {
                m.revision() > at_run.revision() && m.target_version() == at_run.target_version()
            })
            .find_map(|m| policy_allows(m, experiment, exposure))
    })
}
fn later_allowing(
    manifests: &[ManifestRevision],
    at_run: &ManifestRevision,
    experiment: &FrozenExperiment,
    exposure: Exposure,
) -> bool {
    manifests
        .iter()
        .filter(|m| m.revision() > at_run.revision())
        .any(|m| policy_allows(m, experiment, exposure) == Some(true))
}
fn applicability(record: &crate::wire::VerificationV1, s_sequence: u64) -> Applicability {
    if record.sequence == s_sequence {
        return Applicability::AsObserved;
    }
    let Some(retest) = &record.retest else {
        return Applicability::Unestablished;
    };
    match (retest.property_result, retest.functional_result) {
        (
            PropertyResult::StillViolated,
            FunctionalResult::PreservedWithinTestedScope | FunctionalResult::NotTested,
        ) => Applicability::StillViolated,
        (
            PropertyResult::NoViolationWithinTestedScope,
            FunctionalResult::PreservedWithinTestedScope,
        ) => Applicability::FixedWithinTestedScope,
        _ => Applicability::Unestablished,
    }
}
