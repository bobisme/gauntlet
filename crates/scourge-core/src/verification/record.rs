//! Verifier-owned evaluation and the unlinked `scourge.verification.v1` record.
//!
//! The public entry point consumes [`ExecutedRounds`], a sealed value that only
//! the compiled live acquisition path can construct. Callers may supply the
//! non-verdict context already admitted by coordination, but no API in this
//! module accepts observations, an oracle result, a verdict, or record bytes
//! (INV-01, INV-03). The record is stored as an Investigation derivative over
//! its retained originals and exact experiment. Publication uses a durable
//! verifier intent before the Investigation write and never accepts record
//! bytes or a verdict from its caller.

use std::collections::BTreeMap;

use crate::{
    canonical::{JsonError, Sha256Digest},
    domain::{CleanupObjectOutcome, CleanupObjectRole, LeadEvent, RunCleanup},
    engagement::ManifestRevision,
    evidence::{
        Evidence, EvidenceError, RecordKind as EvidenceRecordKind, RecordRequest,
        VERIFICATION_TRANSFORMATION as RECORD_TRANSFORMATION,
        VERIFICATION_TRANSFORMATION_VERSION as RECORD_TRANSFORMATION_VERSION,
    },
    ids::{LeadId, PublicationIntentId, RunId, RunNonce, VerificationId, WireText},
    rounds::{AcquiredFlow, AcquiredRound, ExecutedRounds, PlantedCanary, RoundFlow},
    store::{
        PublicationReceipt, Store, StoreError,
        read::{LeadBinding, LinkedChain},
    },
    teapot::decode_retained_flow,
    template::FrozenExperiment,
    wire::{
        self, AccountingV1, Artifact, Canary as RecordCanary, Cleanup, Completeness, Custody,
        DeterministicTag, Effect, Enforcement, EnvironmentKind, ErrorCode, Exposure, Flow,
        Identity, Instrument, OracleResult, PolicyRule, Profile, Property, PublicationIntentV1,
        PublicationIntentV1Tag, PublicationState, RecordKind, Reproduction, Round, RoundPhase,
        Slot, Target, TargetIsolation, Timestamp, VerificationV1, VerificationV1Tag, Verifier,
    },
};

use crate::verification::{
    CleanupDetail, ContentCoding, DecodeLimits, Decoding, Evaluation, FaultCause, FieldName,
    FlowId, ObjectKey, OracleRef, PlantDetail, PlantedCanary as ObservationCanary, SavedFlow,
    SavedObservations, Subject, Verdict, decode as decode_body, evaluate, registry, supervise,
};

const PRIMARY_OBJECT: &str = "primary";
const CONTROL_OBJECT: &str = "control";
const REGISTERED_ID_FIELD: &str = "id";

/// Non-verdict context admitted by coordination or observed around this run.
///
/// The verifier mints `record_id` and `run_nonce`, derives the experiment,
/// oracle, accounting and every round from [`ExecutedRounds`], and fixes the
/// record kind/validation itself. Nothing here can inject a result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerificationContext {
    pub sequence: u64,
    pub prev_record_digest: Option<Sha256Digest>,
    pub lead_id: LeadId,
    pub lead_revision: u64,
    pub policy_rule: Option<PolicyRule>,
    pub profile: Profile,
    pub target: Target,
    pub environment_kind: EnvironmentKind,
    pub custody: Custody,
    pub target_isolation: TargetIsolation,
    pub enforcement: Enforcement,
    pub destination_time_enforced: bool,
    pub request_ceiling_enforced: bool,
    pub edit_surface_start: Vec<Artifact>,
    pub edit_surface_end: Vec<Artifact>,
    pub effects: Effect,
    pub instrument: Instrument,
    pub verifier: Verifier,
    pub started_at: Timestamp,
    pub finished_at: Timestamp,
}

/// Record policy, environment classification and chain position supplied by
/// the verifier coordinator. Publication chooses its own current chain head.
#[derive(Clone, Debug)]
pub struct VerificationRecordOptions {
    pub sequence: u64,
    pub prev_record_digest: Option<Sha256Digest>,
    pub policy_rule: Option<PolicyRule>,
    pub environment_kind: EnvironmentKind,
}

impl VerificationContext {
    pub fn from_execution(
        execution: &ExecutedRounds,
        options: VerificationRecordOptions,
    ) -> Result<Self, RecordError> {
        let (acceptance, acquired) = execution.settlement();
        if acceptance.run.id != *execution.run()
            || acceptance.run.engagement != *execution.engagement()
            || acceptance.run.experiment_digest != *execution.experiment_digest()
            || acquired.id != acceptance.run.id
            || acquired.engagement != acceptance.run.engagement
            || acquired.experiment_digest != acceptance.run.experiment_digest
        {
            return Err(RecordError::ContextMismatch);
        }
        let observed = execution.verification();
        Ok(Self {
            sequence: options.sequence,
            prev_record_digest: options.prev_record_digest,
            lead_id: acceptance
                .lead_id
                .clone()
                .ok_or(RecordError::ContextMismatch)?,
            lead_revision: acceptance
                .lead_revision
                .ok_or(RecordError::ContextMismatch)?,
            policy_rule: options.policy_rule,
            profile: Profile::RuntimeControlledV1,
            target: observed.target.clone(),
            environment_kind: options.environment_kind,
            custody: observed.custody,
            target_isolation: observed.target_isolation,
            enforcement: observed.enforcement,
            destination_time_enforced: observed.enforcement == Enforcement::EgressEnforced,
            // Admission observes accounting and estimates a ceiling; it does
            // not prove an enforced per-run request ceiling.
            request_ceiling_enforced: false,
            edit_surface_start: vec![observed.start.artifact.clone()],
            edit_surface_end: vec![observed.end.artifact.clone()],
            effects: acquired.known_effects(),
            instrument: observed.start.observation.identity.clone(),
            verifier: observed.verifier.clone(),
            started_at: observed.started_at.clone(),
            finished_at: observed.finished_at.clone(),
        })
    }

    fn check_execution(&self, execution: &ExecutedRounds) -> Result<(), RecordError> {
        let expected = Self::from_execution(
            execution,
            VerificationRecordOptions {
                sequence: self.sequence,
                prev_record_digest: self.prev_record_digest.clone(),
                policy_rule: self.policy_rule.clone(),
                environment_kind: self.environment_kind,
            },
        )?;
        if *self != expected {
            return Err(RecordError::ContextMismatch);
        }
        Ok(())
    }
}

/// Frozen command projection for one oracle outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Disposition {
    pub result: OracleResult,
    pub error: Option<ErrorCode>,
    pub exit_code: u8,
}

/// A successfully stored but deliberately unpublished verification record.
#[derive(Clone, Debug)]
pub struct StoredVerification {
    pub artifact: Artifact,
    pub record: VerificationV1,
    pub disposition: Disposition,
}

/// A record durably linked to its engagement chain through its verifier-owned
/// write-ahead intent.
#[derive(Clone, Debug)]
pub struct PublishedVerification {
    pub stored: StoredVerification,
    pub publication: PublicationReceipt,
}

/// Typed failures at the record boundary. No failure can be promoted to a
/// positive or negative oracle result.
#[derive(Debug, thiserror::Error)]
pub enum RecordError {
    #[error("the compiled experiment does not bind the private-object-read oracle")]
    OracleUnavailable,
    #[error("the compiled experiment has no bound property")]
    PropertyUnavailable,
    #[error("an acquired flow is not retained by this run's capture")]
    ForeignRunEvidence,
    #[error("a required retained original is missing")]
    MissingOriginal,
    #[error("a retained original is malformed")]
    MalformedOriginal,
    #[error("a retained original or record digest does not match its reference")]
    DigestMismatch,
    #[error("the retained record is invalid or non-canonical")]
    InvalidRecord,
    #[error("the verification context does not match the sealed execution")]
    ContextMismatch,
    #[error("retained-original oracle re-evaluation disagrees with the stored result")]
    ReevaluationMismatch,
    #[error("the verification record cannot be represented by the frozen schema")]
    Schema,
    #[error("the evidence bridge failed: {0}")]
    Evidence(#[from] EvidenceError),
}

impl RecordError {
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::OracleUnavailable => ErrorCode::OracleUnavailable,
            Self::PropertyUnavailable => ErrorCode::SlotsIncomplete,
            Self::Evidence(error) => evidence_code(error),
            Self::ForeignRunEvidence
            | Self::MissingOriginal
            | Self::MalformedOriginal
            | Self::DigestMismatch
            | Self::InvalidRecord
            | Self::ContextMismatch
            | Self::ReevaluationMismatch
            | Self::Schema => ErrorCode::IntegrityFailure,
        }
    }

    pub const fn exit_code(&self) -> u8 {
        self.code().exit_code()
    }
}

/// Typed failures from the two-store publication state machine.
#[derive(Debug, thiserror::Error)]
pub enum PublicationError {
    #[error(transparent)]
    Record(#[from] RecordError),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("a legacy durable publication intent has no matching evidence receipt")]
    ArtifactPending,
    #[error("the publication checkpoint kept moving while the record was rebuilt")]
    HeadMoved,
    #[error("the run has unresolved effects and cannot be published")]
    EffectsUnknown,
}

impl PublicationError {
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Record(error) => error.code(),
            Self::Store(error) => error.error_code(),
            Self::ArtifactPending => ErrorCode::EvidenceIncomplete,
            Self::HeadMoved => ErrorCode::ConflictingRun,
            Self::EffectsUnknown => ErrorCode::EffectUnknown,
        }
    }

    pub fn exit_code(&self) -> u8 {
        self.code().exit_code()
    }
}

pub(crate) const fn evidence_code(error: &EvidenceError) -> ErrorCode {
    match error {
        EvidenceError::UnqualifiedInvestigation
        | EvidenceError::ImportRoot
        | EvidenceError::BackendOutputTooLarge { .. }
        | EvidenceError::BackendTimeout { .. }
        | EvidenceError::StagingBusy
        | EvidenceError::ScratchUnsafe
        | EvidenceError::Backend
        | EvidenceError::BackendFailed { .. }
        | EvidenceError::Io(_) => ErrorCode::DependencyUnavailable,
        EvidenceError::InvalidInput
        | EvidenceError::InvalidRange
        | EvidenceError::InvalidJson
        | EvidenceError::TooLarge
        | EvidenceError::RequestTooLarge
        | EvidenceError::Refused => ErrorCode::EvidenceIncomplete,
        EvidenceError::Missing
        | EvidenceError::Conflict
        | EvidenceError::CaseRoot
        | EvidenceError::Integrity
        | EvidenceError::ChangedSnapshot
        | EvidenceError::LineageUnverified
        | EvidenceError::Withdrawn { .. }
        | EvidenceError::Protocol => ErrorCode::IntegrityFailure,
    }
}

/// Map a failed instrument call and a panicking oracle to `error` (F-14).
///
/// This helper is also the narrow fault boundary used by orchestration code:
/// target/instrument failures never enter the predicate as fabricated evidence.
pub fn evaluate_instrument<T, E>(
    instrument: Result<T, E>,
    oracle: impl FnOnce(T) -> Evaluation,
) -> Evaluation {
    match instrument {
        Ok(value) => supervise(|| oracle(value)),
        Err(_) => Evaluation::fault(FaultCause::InstrumentUnavailable),
    }
}

/// Build, store, read back and independently re-evaluate one verification
/// record. The returned artifact is not linked to any engagement chain.
pub fn evaluate_and_store(
    evidence: &Evidence,
    execution: &ExecutedRounds,
    context: VerificationContext,
) -> Result<StoredVerification, RecordError> {
    context.check_execution(execution)?;
    let source = LiveEvidence(evidence);
    evaluate_and_store_with(&source, Acquisition::from(execution), context)
}

/// Evaluate and publish one verifier-owned record through the write-ahead
/// state machine. A head race rebuilds from the same sealed execution with a
/// fresh record and intent; no target or instrument handle enters this path.
pub fn evaluate_and_publish(
    evidence: &Evidence,
    store: &mut Store,
    execution: &ExecutedRounds,
    context: VerificationContext,
) -> Result<PublishedVerification, PublicationError> {
    context.check_execution(execution)?;
    if context.effects == Effect::Unknown {
        return Err(PublicationError::EffectsUnknown);
    }
    evaluate_and_publish_with(
        &LiveEvidence(evidence),
        store,
        Acquisition::from(execution),
        context,
    )
}

/// Finish only the live verifier intent for `run` from Investigation's
/// original same-key receipt or its immutable verifier-staged replay source.
/// This local recovery path neither accepts record bytes from its caller nor
/// has any target-traffic capability.
pub fn reconcile_publication(
    evidence: &Evidence,
    store: &mut Store,
    run: &RunId,
) -> Result<PublishedVerification, PublicationError> {
    reconcile_publication_with(&LiveEvidence(evidence), store, run)
}

/// Frozen result/error/exit mapping. Oracle reason codes stay inside rounds;
/// this projection never turns `invalid` or `error` into a verdict.
pub fn disposition(result: OracleResult, reasons: &[crate::wire::ReasonCode]) -> Disposition {
    let error = match result {
        OracleResult::True | OracleResult::False => None,
        OracleResult::Invalid
            if reasons.first().is_some_and(|reason| {
                matches!(reason.as_str(), "SAME_SUBJECT" | "SESSION_DRIFT")
            }) =>
        {
            Some(ErrorCode::IdentityUnestablished)
        }
        OracleResult::Invalid => Some(ErrorCode::EvidenceIncomplete),
        OracleResult::Error => Some(ErrorCode::DependencyUnavailable),
    };
    Disposition {
        result,
        exit_code: error.map_or(0, ErrorCode::exit_code),
        error,
    }
}

#[derive(Clone)]
struct Acquisition<'a> {
    run: &'a RunId,
    engagement: &'a crate::ids::EngagementId,
    experiment: &'a FrozenExperiment,
    experiment_digest: &'a Sha256Digest,
    experiment_artifact: &'a Artifact,
    rounds: &'a [AcquiredRound],
    retained: Vec<Artifact>,
    accounting: &'a AccountingV1,
    cleanup: Cleanup,
    settlement: Option<&'a ExecutedRounds>,
}

impl<'a> From<&'a ExecutedRounds> for Acquisition<'a> {
    fn from(execution: &'a ExecutedRounds) -> Self {
        Self {
            run: execution.run(),
            engagement: execution.engagement(),
            experiment: execution.experiment(),
            experiment_digest: execution.experiment_digest(),
            experiment_artifact: execution.experiment_artifact(),
            rounds: execution.rounds(),
            retained: execution
                .capture()
                .original_artifacts
                .iter()
                .map(|original| original.artifact.clone())
                .collect(),
            accounting: execution.accounting().record(),
            cleanup: execution.cleanup(),
            settlement: Some(execution),
        }
    }
}

trait RecordEvidence {
    fn case_id(&self) -> Option<&str> {
        None
    }

    fn store(&self, key: &str, bytes: &[u8], inputs: &[Artifact]) -> Result<Artifact, RecordError>;
    fn read(&self, artifact: &Artifact) -> Result<EvidenceRead, RecordError>;
    fn recover(&self, key: &str) -> Result<Option<Artifact>, RecordError>;

    fn store_publication(
        &self,
        key: &str,
        bytes: &[u8],
        inputs: &[Artifact],
    ) -> Result<Artifact, RecordError> {
        self.store(key, bytes, inputs)
    }

    fn recover_publication(&self, key: &str) -> Result<Option<Artifact>, RecordError> {
        self.recover(key)
    }
}

struct EvidenceRead {
    bytes: Vec<u8>,
    inputs: Vec<Artifact>,
    record_lineage: bool,
}

/// One item loaded from Investigation at a single evidence snapshot. The
/// loader must preserve the exact artifact identity and verified lineage; the
/// status calculation never opens the evidence store.
#[derive(Clone, Debug)]
struct SnapshotArtifact {
    artifact: Artifact,
    bytes: Vec<u8>,
    inputs: Vec<Artifact>,
    record_lineage: bool,
}

/// Immutable retained material for offline re-evaluation.
#[derive(Clone, Debug, Default)]
pub struct EvidenceSnapshot {
    artifacts: Vec<SnapshotArtifact>,
}

impl EvidenceSnapshot {
    /// Capture a chain returned by the coordination read transaction, then
    /// verify every linked record against its index and predecessor. Originals
    /// for this lead are loaded before the pure status calculation begins.
    pub fn capture_linked(
        evidence: &Evidence,
        chain: &LinkedChain,
        lead: &LeadId,
    ) -> Result<LinkedEvidenceSnapshot, RecordError> {
        capture_linked_with(&LiveEvidence(evidence), chain, lead)
    }
}

/// A chain whose exact published record bytes match the coordination indexes.
/// Fields stay private so an unlinked artifact cannot be supplied as a record.
#[derive(Clone)]
pub struct LinkedEvidenceSnapshot {
    pub(crate) evidence: EvidenceSnapshot,
    pub(crate) records: Vec<(Artifact, VerificationV1)>,
    pub(crate) manifests: Vec<ManifestRevision>,
    pub(crate) lead: LeadId,
    pub(crate) bindings: Vec<LeadBinding>,
    pub(crate) events: Vec<LeadEvent>,
}

impl LinkedEvidenceSnapshot {
    /// Exact records authenticated by the coordination chain, in sequence order.
    pub fn records(&self) -> &[(Artifact, VerificationV1)] {
        &self.records
    }

    /// Validated engagement revision lineage captured at the same store snapshot.
    pub fn manifests(&self) -> &[ManifestRevision] {
        &self.manifests
    }

    pub fn lead(&self) -> &LeadId {
        &self.lead
    }

    pub fn bindings(&self) -> &[LeadBinding] {
        &self.bindings
    }

    pub fn events(&self) -> &[LeadEvent] {
        &self.events
    }

    pub(crate) fn experiment(
        &self,
        artifact: &Artifact,
        record: &VerificationV1,
    ) -> Result<FrozenExperiment, RecordError> {
        if !self
            .records
            .iter()
            .any(|(linked, stored)| linked == artifact && stored == record)
        {
            return Err(RecordError::InvalidRecord);
        }
        let retained = read_record(&self.evidence, artifact)?;
        if &retained.record != record {
            return Err(RecordError::InvalidRecord);
        }
        let reference = experiment_reference(record, &retained.inputs)?;
        let read = self.evidence.read(reference)?;
        FrozenExperiment::from_canonical_bytes(&read.bytes, &record.experiment_digest)
            .map_err(|_| RecordError::InvalidRecord)
    }

    /// Re-evaluate a retained record entirely from this immutable snapshot.
    pub fn reevaluate(&self, artifact: &Artifact) -> Result<VerificationV1, RecordError> {
        if !self.records.iter().any(|(linked, _)| linked == artifact) {
            return Err(RecordError::InvalidRecord);
        }
        snapshot_record(&self.evidence, artifact)
    }
}

fn capture_linked_with(
    source: &impl RecordEvidence,
    chain: &LinkedChain,
    lead: &LeadId,
) -> Result<LinkedEvidenceSnapshot, RecordError> {
    if chain.lead() != lead {
        return Err(RecordError::InvalidRecord);
    }
    for (position, binding) in chain.bindings().iter().enumerate() {
        if binding.revision != u64::try_from(position).map_err(|_| RecordError::InvalidRecord)? + 1
        {
            return Err(RecordError::InvalidRecord);
        }
    }
    let mut snapshot = EvidenceSnapshot::default();
    let mut records = Vec::new();
    let mut manifests = Vec::new();
    let mut manifest_parent = None;
    for (position, index) in chain.manifests().iter().enumerate() {
        let read = source.read(index.artifact())?;
        let manifest =
            ManifestRevision::from_canonical_bytes(&read.bytes, &index.artifact().digest)
                .map_err(|_| RecordError::InvalidRecord)?;
        let revision = u64::try_from(position).map_err(|_| RecordError::InvalidRecord)? + 1;
        if manifest.revision() != index.revision()
            || manifest.revision() != revision
            || manifest.parent_digest() != manifest_parent.as_ref()
            || manifest.pass_digest() != index.pass_digest()
        {
            return Err(RecordError::InvalidRecord);
        }
        manifest_parent = Some(manifest.digest().clone());
        manifests.push(manifest);
    }
    if manifests.is_empty() {
        return Err(RecordError::InvalidRecord);
    }
    let mut predecessor = None;
    for (position, index) in chain.records().iter().enumerate() {
        let retained = read_record(source, &index.record)?;
        let record = retained.record;
        let expected_sequence =
            u64::try_from(position).map_err(|_| RecordError::InvalidRecord)? + 1;
        if index.engagement != *chain.engagement()
            || record.engagement != index.engagement
            || record.sequence != index.sequence
            || record.sequence != expected_sequence
            || record.record_id != index.record_id
            || record.run_id != index.run_id
            || record.lead_id != index.lead_id
            || record.prev_record_digest != predecessor
        {
            return Err(RecordError::InvalidRecord);
        }
        predecessor = Some(index.record.digest.clone());
        snapshot.artifacts.push(SnapshotArtifact {
            artifact: index.record.clone(),
            bytes: retained.bytes,
            inputs: retained.inputs.clone(),
            record_lineage: true,
        });
        if &record.lead_id == lead {
            for input in retained.inputs {
                if snapshot.artifacts.iter().any(|item| item.artifact == input) {
                    continue;
                }
                let read = match source.read(&input) {
                    Ok(read) => read,
                    Err(
                        RecordError::MissingOriginal
                        | RecordError::Evidence(EvidenceError::Missing),
                    ) => continue,
                    Err(error) => return Err(error),
                };
                if Sha256Digest::of(&read.bytes) != input.digest {
                    return Err(RecordError::DigestMismatch);
                }
                snapshot.artifacts.push(SnapshotArtifact {
                    artifact: input,
                    bytes: read.bytes,
                    inputs: read.inputs,
                    record_lineage: read.record_lineage,
                });
            }
        }
        records.push((index.record.clone(), record));
    }
    Ok(LinkedEvidenceSnapshot {
        evidence: snapshot,
        records,
        manifests,
        lead: lead.clone(),
        bindings: chain.bindings().to_vec(),
        events: chain.events().to_vec(),
    })
}

impl RecordEvidence for EvidenceSnapshot {
    fn store(&self, _: &str, _: &[u8], _: &[Artifact]) -> Result<Artifact, RecordError> {
        Err(RecordError::InvalidRecord)
    }

    fn read(&self, artifact: &Artifact) -> Result<EvidenceRead, RecordError> {
        let mut matches = self
            .artifacts
            .iter()
            .filter(|item| item.artifact.artifact_id == artifact.artifact_id);
        let item = matches.next().ok_or(RecordError::MissingOriginal)?;
        if matches.next().is_some()
            || item.artifact != *artifact
            || Sha256Digest::of(&item.bytes) != artifact.digest
        {
            return Err(RecordError::DigestMismatch);
        }
        Ok(EvidenceRead {
            bytes: item.bytes.clone(),
            inputs: item.inputs.clone(),
            record_lineage: item.record_lineage,
        })
    }

    fn recover(&self, _: &str) -> Result<Option<Artifact>, RecordError> {
        Err(RecordError::InvalidRecord)
    }
}

/// Re-evaluate an exact retained record without I/O or cached verdicts.
fn snapshot_record(
    evidence: &EvidenceSnapshot,
    artifact: &Artifact,
) -> Result<VerificationV1, RecordError> {
    let retained = read_record(evidence, artifact)?;
    // Missing originals are integrity failures even when the oracle is unavailable.
    for input in &retained.inputs {
        let _ = evidence.read(input)?;
    }
    // M1 only implements the verify oracle. A schema-shaped retest is not
    // evidence that its functional and property results were evaluated.
    if retained.record.kind != RecordKind::Verify || retained.record.retest.is_some() {
        return Err(RecordError::OracleUnavailable);
    }
    let evaluated = reevaluate_record(evidence, &retained.record, &retained.inputs)?;
    if !reevaluation_matches(&retained.record, &evaluated) {
        return Err(RecordError::ReevaluationMismatch);
    }
    Ok(retained.record)
}

struct LiveEvidence<'a>(&'a Evidence);

fn verification_request<'a>(
    key: &'a str,
    bytes: &'a [u8],
    inputs: &'a [Artifact],
) -> RecordRequest<'a> {
    RecordRequest {
        key,
        kind: EvidenceRecordKind::VerificationRecord,
        bytes,
        inputs,
        transformation: RECORD_TRANSFORMATION,
        version: RECORD_TRANSFORMATION_VERSION,
    }
}

impl RecordEvidence for LiveEvidence<'_> {
    fn case_id(&self) -> Option<&str> {
        Some(self.0.case_id())
    }

    fn store(&self, key: &str, bytes: &[u8], inputs: &[Artifact]) -> Result<Artifact, RecordError> {
        self.0
            .record(verification_request(key, bytes, inputs))
            .map(|artifact| artifact.reference)
            .map_err(Into::into)
    }

    fn store_publication(
        &self,
        key: &str,
        bytes: &[u8],
        inputs: &[Artifact],
    ) -> Result<Artifact, RecordError> {
        self.0
            .record_verification_publication(verification_request(key, bytes, inputs))
            .map(|artifact| artifact.reference)
            .map_err(Into::into)
    }

    fn recover_publication(&self, key: &str) -> Result<Option<Artifact>, RecordError> {
        self.0
            .recover_verification_publication(key)
            .map(|artifact| artifact.map(|artifact| artifact.reference))
            .map_err(Into::into)
    }

    fn read(&self, artifact: &Artifact) -> Result<EvidenceRead, RecordError> {
        // Keep the exact bounded bytes. Each consumer below applies its own
        // strict typed parser and, for records and experiments, canonical-byte
        // equality. Investigation's generic JSON selector has a smaller input
        // ceiling than a qualified 1 MiB Teapot body encoded in its envelope.
        let read = self.0.read(&artifact.artifact_id)?;
        if read.artifact.reference != *artifact {
            return Err(RecordError::DigestMismatch);
        }
        Ok(EvidenceRead {
            bytes: read.bytes,
            inputs: read
                .artifact
                .lineage
                .iter()
                .map(|lineage| lineage.input.clone())
                .collect(),
            record_lineage: read.artifact.lineage.iter().all(|lineage| {
                lineage.transformation == RECORD_TRANSFORMATION
                    && lineage.version == RECORD_TRANSFORMATION_VERSION
            }),
        })
    }

    fn recover(&self, key: &str) -> Result<Option<Artifact>, RecordError> {
        self.0
            .recover_record(key)
            .map(|artifact| artifact.map(|artifact| artifact.reference))
            .map_err(Into::into)
    }
}

/// A candidate derived by this module from the sealed acquisition and
/// re-evaluated against its retained originals before it can be staged.
pub(crate) struct PreparedVerification {
    bytes: Vec<u8>,
    inputs: Vec<Artifact>,
    record: VerificationV1,
    disposition: Disposition,
    evidence_case_id: Option<String>,
}

impl PreparedVerification {
    pub(crate) fn staged_material(&self) -> (&[u8], &[Artifact], Option<&str>) {
        (&self.bytes, &self.inputs, self.evidence_case_id.as_deref())
    }
}

/// Checked in this module against qualified Evidence before the Store may
/// link it. Its constructor and captured bytes never come from consumers.
pub(crate) struct VerifiedPublication {
    intent: PublicationIntentId,
    artifact: Artifact,
    retained: RetainedRecord,
    evidence_case_id: Option<String>,
}

impl VerifiedPublication {
    pub(crate) fn staged_material(
        &self,
    ) -> (
        &PublicationIntentId,
        &Artifact,
        &[u8],
        &[Artifact],
        Option<&str>,
    ) {
        (
            &self.intent,
            &self.artifact,
            &self.retained.bytes,
            &self.retained.inputs,
            self.evidence_case_id.as_deref(),
        )
    }
}

fn evaluate_and_prepare_with(
    evidence: &impl RecordEvidence,
    acquisition: Acquisition<'_>,
    context: VerificationContext,
) -> Result<PreparedVerification, RecordError> {
    let evidence_case_id = evidence.case_id();
    if acquisition
        .settlement
        .is_some_and(|execution| Some(execution.evidence_case_id()) != evidence_case_id)
    {
        return Err(RecordError::ForeignRunEvidence);
    }
    validate_acquisition(&acquisition)?;
    let mut evaluated = Vec::with_capacity(acquisition.rounds.len());
    for round in acquisition.rounds {
        let observations =
            observations_from_acquired(acquisition.run, acquisition.experiment, round)?;
        evaluated.push((round, evaluate(&observations)));
    }
    if evaluated.is_empty() {
        return Err(RecordError::Schema);
    }

    let summary = summarize(evaluated.iter().map(|(_, evaluation)| evaluation));
    let record_id = VerificationId::generate();
    let run_nonce: RunNonce = record_id
        .as_str()
        .strip_prefix("V-")
        .expect("generated verification ID has its prefix")
        .parse()
        .expect("generated UUID token is a 128-bit lowercase nonce");
    let property = acquisition
        .experiment
        .property
        .as_ref()
        .ok_or(RecordError::PropertyUnavailable)?;
    let rounds = evaluated
        .into_iter()
        .map(|(round, evaluation)| record_round(round, evaluation, acquisition.experiment))
        .collect::<Result<Vec<_>, _>>()?;
    let record = VerificationV1 {
        schema: VerificationV1Tag::VerificationV1,
        record_id: record_id.clone(),
        kind: RecordKind::Verify,
        engagement: acquisition.engagement.clone(),
        sequence: context.sequence,
        prev_record_digest: context.prev_record_digest,
        lead_id: context.lead_id,
        lead_revision: context.lead_revision,
        engagement_revision: acquisition.experiment.engagement.revision,
        property: Property {
            id: Some(wire_text(property.label.as_str())?),
            digest: property.digest.clone(),
        },
        policy_rule: context.policy_rule,
        slots: slots(acquisition.experiment)?,
        profile: context.profile,
        template: acquisition.experiment.template.clone(),
        experiment_digest: acquisition.experiment_digest.clone(),
        oracle: acquisition.experiment.oracle.clone(),
        validation: DeterministicTag::Deterministic,
        run_id: acquisition.run.clone(),
        run_nonce,
        rounds,
        result: summary.result,
        exposure: summary.exposure,
        reproduction: summary.reproduction,
        target: context.target,
        environment_kind: context.environment_kind,
        custody: context.custody,
        target_isolation: context.target_isolation,
        enforcement: context.enforcement,
        destination_time_enforced: context.destination_time_enforced,
        request_ceiling_enforced: context.request_ceiling_enforced,
        accounting: acquisition.accounting.clone(),
        edit_surface_start: context.edit_surface_start,
        edit_surface_end: context.edit_surface_end,
        effects: context.effects,
        cleanup: acquisition.cleanup,
        instrument: context.instrument,
        verifier: context.verifier,
        retest: None,
        limitations: registry::KNOWN_MISSES
            .iter()
            .map(|miss| wire_text(miss))
            .collect::<Result<_, _>>()?,
        started_at: context.started_at,
        finished_at: context.finished_at,
    };

    let bytes = wire::to_vec(&record).map_err(|_| RecordError::Schema)?;
    let inputs = record
        .lineage_inputs(acquisition.experiment_artifact)
        .map_err(lineage_error)?;
    // Preparation verifies that the referenced originals remain readable, but
    // does not store the candidate record. Publication can therefore persist
    // its intent before the first record write.
    check_readable_inputs(evidence, &inputs)?;
    let reevaluated = reevaluate_record(evidence, &record, &inputs)?;
    if !reevaluation_matches(&record, &reevaluated) {
        return Err(RecordError::ReevaluationMismatch);
    }
    let reasons = record
        .rounds
        .iter()
        .flat_map(|round| round.reason_codes.iter().cloned())
        .collect::<Vec<_>>();
    Ok(PreparedVerification {
        bytes,
        inputs,
        disposition: disposition(record.result, &reasons),
        evidence_case_id: evidence_case_id.map(str::to_owned),
        record,
    })
}

fn store_prepared(
    evidence: &impl RecordEvidence,
    key: &str,
    prepared: PreparedVerification,
) -> Result<StoredVerification, RecordError> {
    let artifact = evidence.store(key, &prepared.bytes, &prepared.inputs)?;
    if artifact.digest != Sha256Digest::of(&prepared.bytes) {
        return Err(RecordError::DigestMismatch);
    }
    let read_record = read_record(evidence, &artifact)?;
    let reevaluated = reevaluate_record(evidence, &read_record.record, &read_record.inputs)?;
    if evidence.recover(key)?.as_ref() != Some(&artifact)
        || read_record.bytes != prepared.bytes
        || read_record.inputs != prepared.inputs
        || read_record.record != prepared.record
        || !reevaluation_matches(&prepared.record, &reevaluated)
    {
        return Err(RecordError::ReevaluationMismatch);
    }
    Ok(StoredVerification {
        artifact,
        disposition: prepared.disposition,
        record: prepared.record,
    })
}

fn evaluate_and_store_with(
    evidence: &impl RecordEvidence,
    acquisition: Acquisition<'_>,
    context: VerificationContext,
) -> Result<StoredVerification, RecordError> {
    let prepared = evaluate_and_prepare_with(evidence, acquisition, context)?;
    let key = prepared.record.record_id.as_str().to_owned();
    store_prepared(evidence, &key, prepared)
}

const MAX_HEAD_REBUILDS: usize = 8;

fn evaluate_and_publish_with(
    evidence: &impl RecordEvidence,
    store: &mut Store,
    acquisition: Acquisition<'_>,
    mut context: VerificationContext,
) -> Result<PublishedVerification, PublicationError> {
    for _ in 0..MAX_HEAD_REBUILDS {
        let (_, head) = store.checkpoint(acquisition.engagement)?;
        context.sequence = head
            .sequence
            .checked_add(1)
            .ok_or(StoreError::CounterRange)?;
        context.prev_record_digest = head.record_digest.clone();
        let prepared = evaluate_and_prepare_with(evidence, acquisition.clone(), context.clone())?;
        let intent = PublicationIntentV1 {
            schema: PublicationIntentV1Tag::PublicationIntentV1,
            intent_id: PublicationIntentId::generate(),
            engagement: acquisition.engagement.clone(),
            run_id: acquisition.run.clone(),
            record_id: prepared.record.record_id.clone(),
            record_digest: Sha256Digest::of(&prepared.bytes),
            expected_head: head,
            state: PublicationState::Pending,
            artifact_id: None,
        };
        let staged = if let Some(execution) = acquisition.settlement {
            store.settle_and_stage_publication(execution, &intent, &prepared)
        } else {
            #[cfg(test)]
            {
                store.stage_publication_fixture(&intent, &prepared.bytes, &prepared.inputs)
            }
            #[cfg(not(test))]
            {
                Err(StoreError::Conflict)
            }
        };
        match staged {
            Ok(_) => {}
            Err(StoreError::HeadMoved) => continue,
            Err(error) => return Err(error.into()),
        }
        match finish_staged_publication(evidence, store, &intent) {
            Ok(published) => return Ok(published),
            Err(PublicationError::Store(StoreError::HeadMoved)) => continue,
            Err(error) => return Err(error),
        }
    }
    Err(PublicationError::HeadMoved)
}

fn reconcile_publication_with(
    evidence: &impl RecordEvidence,
    store: &mut Store,
    run: &RunId,
) -> Result<PublishedVerification, PublicationError> {
    let intent = store
        .publication_for_reconciliation(run)?
        .ok_or(StoreError::SelectorNotFound)?;
    finish_staged_publication(evidence, store, &intent)
}

fn finish_staged_publication(
    evidence: &impl RecordEvidence,
    store: &mut Store,
    intent: &PublicationIntentV1,
) -> Result<PublishedVerification, PublicationError> {
    let staged = store.staged_publication(intent)?;
    let evidence_case_id = evidence.case_id();
    if staged
        .as_ref()
        .and_then(|staged| staged.evidence_case_id.as_deref())
        .is_some_and(|case_id| Some(case_id) != evidence_case_id)
    {
        return Err(RecordError::ForeignRunEvidence.into());
    }
    let key = intent.intent_id.as_str();
    let artifact = if intent.state == PublicationState::Pending {
        if let Some(artifact) = evidence.recover_publication(key)? {
            artifact
        } else {
            let staged = staged.as_ref().ok_or(PublicationError::ArtifactPending)?;
            let retained = evidence.store_publication(key, &staged.record_bytes, &staged.inputs)?;
            if evidence.recover_publication(key)?.as_ref() != Some(&retained) {
                return Err(RecordError::DigestMismatch.into());
            }
            retained
        }
    } else {
        let retained = if store.uses_verifier_publication_receipt(&intent.intent_id)? {
            evidence.recover_publication(key)?
        } else {
            evidence.recover(key)?
        };
        retained.ok_or(PublicationError::ArtifactPending)?
    };
    let retained = read_record(evidence, &artifact)?;
    if retained.record.record_id != intent.record_id
        || retained.record.run_id != intent.run_id
        || retained.record.engagement != intent.engagement
        || artifact.digest != intent.record_digest
        || staged.as_ref().is_some_and(|staged| {
            retained.bytes != staged.record_bytes || retained.inputs != staged.inputs
        })
    {
        return Err(RecordError::DigestMismatch.into());
    }
    check_readable_inputs(evidence, &retained.inputs)?;
    let reevaluated = reevaluate_record(evidence, &retained.record, &retained.inputs)?;
    if !reevaluation_matches(&retained.record, &reevaluated) {
        return Err(RecordError::ReevaluationMismatch.into());
    }
    let checked = VerifiedPublication {
        intent: intent.intent_id.clone(),
        artifact,
        retained,
        evidence_case_id: evidence_case_id.map(str::to_owned),
    };
    let publication = store.complete_publication(&checked)?;
    let record = checked.retained.record;
    let reasons = record
        .rounds
        .iter()
        .flat_map(|round| round.reason_codes.iter().cloned())
        .collect::<Vec<_>>();
    let stored = StoredVerification {
        artifact: checked.artifact,
        disposition: disposition(record.result, &reasons),
        record,
    };
    Ok(PublishedVerification {
        stored,
        publication,
    })
}

fn check_readable_inputs(
    evidence: &impl RecordEvidence,
    inputs: &[Artifact],
) -> Result<(), RecordError> {
    for input in inputs {
        let retained = evidence.read(input)?;
        if Sha256Digest::of(&retained.bytes) != input.digest {
            return Err(RecordError::DigestMismatch);
        }
    }
    Ok(())
}

fn validate_acquisition(acquisition: &Acquisition<'_>) -> Result<(), RecordError> {
    if acquisition.experiment.oracle.id.as_str() != registry::ORACLE_ID
        || acquisition.experiment.oracle.version.as_str() != registry::ORACLE_VERSION
        || acquisition.experiment.oracle.digest != registry::oracle_digest()
    {
        return Err(RecordError::OracleUnavailable);
    }
    if acquisition.experiment_digest != &acquisition.experiment.freeze().map_err(schema)?.1 {
        return Err(RecordError::DigestMismatch);
    }
    for flow in acquisition.rounds.iter().flat_map(|round| &round.flows) {
        if let Some(original) = &flow.reference.original
            && !acquisition.retained.contains(original)
        {
            return Err(RecordError::ForeignRunEvidence);
        }
    }
    for round in acquisition.rounds {
        validate_round_cleanup(round)?;
    }
    Ok(())
}

fn validate_round_cleanup(round: &AcquiredRound) -> Result<(), RecordError> {
    if round.cleanup.len() != 2 {
        return Err(RecordError::InvalidRecord);
    }
    let mut primary = false;
    let mut control = false;
    let mut acquired = round
        .flows
        .iter()
        .filter(|flow| flow.contract == RoundFlow::C)
        .map(|flow| (&flow.reference, false))
        .collect::<Vec<_>>();
    for cleanup in &round.cleanup {
        if cleanup.round != round.number {
            return Err(RecordError::InvalidRecord);
        }
        let seen = match cleanup.object {
            CleanupObjectRole::Primary => &mut primary,
            CleanupObjectRole::Control => &mut control,
        };
        if *seen {
            return Err(RecordError::InvalidRecord);
        }
        *seen = true;
        validate_cleanup_flows(cleanup, &mut acquired)?;
    }
    if !primary || !control || acquired.iter().any(|(_, used)| !used) {
        return Err(RecordError::InvalidRecord);
    }
    Ok(())
}

fn validate_cleanup_flows(
    cleanup: &RunCleanup,
    acquired: &mut [(&Flow, bool)],
) -> Result<(), RecordError> {
    for flow in &cleanup.flows {
        let Some((_, used)) = acquired
            .iter_mut()
            .find(|(candidate, used)| !*used && **candidate == *flow)
        else {
            return Err(RecordError::ForeignRunEvidence);
        };
        *used = true;
    }
    Ok(())
}

fn schema(_: JsonError) -> RecordError {
    RecordError::Schema
}

fn observations_from_acquired(
    run: &RunId,
    experiment: &FrozenExperiment,
    round: &AcquiredRound,
) -> Result<SavedObservations, RecordError> {
    let limits = DecodeLimits::new(
        experiment.decoder.limits.max_decoded_bytes,
        experiment.decoder.limits.max_expansion_ratio,
    );
    let selected = selected_acquired(&round.flows);
    let acquired_cleanup = cleanup_detail(round)?;
    let mut identities = BTreeMap::new();
    for identity in &round.identities {
        if identities
            .insert(identity.contract, identity.subject_digest.as_ref())
            .is_some()
        {
            return Err(RecordError::InvalidRecord);
        }
    }
    let mut flows = Vec::with_capacity(FlowId::REQUIRED.len());
    for required in FlowId::REQUIRED {
        let contract = round_flow(required);
        let Some((position, flow)) = selected.get(&contract).copied() else {
            if required != FlowId::C {
                flows.push(missing_flow(run, required, flows.len() as u64 + 1));
            }
            continue;
        };
        let plant = match contract {
            RoundFlow::P => Some(plant_detail(&flow.response_body, &round.primary)?),
            RoundFlow::P2 => Some(plant_detail(&flow.response_body, &round.control)?),
            _ => None,
        };
        let subject = identities
            .get(&contract)
            .and_then(|digest| *digest)
            .map(|digest| wire_text(digest.as_str()))
            .transpose()?
            .map(Subject::from);
        let cleanup = (contract == RoundFlow::C).then(|| acquired_cleanup.clone());
        let decoding = decoding_for(flow.response_head.as_deref(), &flow.response_body, limits)?;
        flows.push(SavedFlow {
            flow: required,
            run: run.clone(),
            sequence: position as u64 + 1,
            completeness: flow.reference.completeness,
            decoding,
            decoder: decoding.decoder_name(),
            original: flow.reference.original.clone(),
            body: flow.response_body.clone(),
            subject,
            plant,
            cleanup,
        });
    }
    Ok(SavedObservations {
        schema: wire_text(crate::verification::OBSERVATION_SCHEMA)?,
        oracle: OracleRef {
            id: wire_text(registry::ORACLE_ID)?,
            version: wire_text(registry::ORACLE_VERSION)?,
        },
        run: run.clone(),
        round: round.number,
        limits,
        flows,
    })
}

fn cleanup_detail(round: &AcquiredRound) -> Result<CleanupDetail, RecordError> {
    let mut attempted = false;
    let mut removed = Vec::new();
    for cleanup in &round.cleanup {
        match cleanup.outcome {
            CleanupObjectOutcome::Owed | CleanupObjectOutcome::NotRequired => {}
            CleanupObjectOutcome::InFlight | CleanupObjectOutcome::Failed => attempted = true,
            CleanupObjectOutcome::Unknown => {
                attempted |= cleanup.effects.is_some()
                    || cleanup.instrument_reference.is_some()
                    || !cleanup.flows.is_empty();
            }
            CleanupObjectOutcome::Complete => {
                attempted = true;
                let object = cleanup
                    .object_id
                    .clone()
                    .ok_or(RecordError::InvalidRecord)?;
                removed.push(ObjectKey::from(object));
            }
        }
    }
    Ok(CleanupDetail { attempted, removed })
}

fn selected_acquired(flows: &[AcquiredFlow]) -> BTreeMap<RoundFlow, (usize, &AcquiredFlow)> {
    let mut selected = BTreeMap::new();
    for (position, flow) in flows.iter().enumerate() {
        let role = flow.reference.step.as_str().rsplit('.').next();
        if matches!(role, Some("request" | "retry")) {
            selected.insert(flow.contract, (position, flow));
        }
    }
    selected
}

fn missing_flow(run: &RunId, flow: FlowId, sequence: u64) -> SavedFlow {
    SavedFlow {
        flow,
        run: run.clone(),
        sequence,
        completeness: Completeness::Missing,
        decoding: Decoding::default(),
        decoder: None,
        original: None,
        body: Vec::new(),
        subject: None,
        plant: None,
        cleanup: None,
    }
}

fn plant_detail(body: &[u8], planted: &[PlantedCanary]) -> Result<PlantDetail, RecordError> {
    let document: serde_json::Value = serde_json::from_slice(body).unwrap_or_default();
    let object = document
        .get(REGISTERED_ID_FIELD)
        .and_then(serde_json::Value::as_str)
        .map(wire_text)
        .transpose()?
        .map(ObjectKey::from);
    let canaries = planted
        .iter()
        .map(|planted| {
            Ok(ObservationCanary {
                field: FieldName::from(wire_text(planted.field.as_str())?),
                canary: planted.canary.clone(),
            })
        })
        .collect::<Result<_, RecordError>>()?;
    Ok(PlantDetail { object, canaries })
}

fn record_round(
    acquired: &AcquiredRound,
    evaluation: Evaluation,
    experiment: &FrozenExperiment,
) -> Result<Round, RecordError> {
    let mut canaries = Vec::new();
    for (object, planted) in [
        (PRIMARY_OBJECT, &acquired.primary),
        (CONTROL_OBJECT, &acquired.control),
    ] {
        for value in planted {
            canaries.push(RecordCanary {
                object: wire_text(object)?,
                field: wire_text(value.field.as_str())?,
                digest: Sha256Digest::of(value.canary.as_str().as_bytes()),
            });
        }
    }
    let selected = selected_acquired(&acquired.flows);
    let identities = acquired
        .identities
        .iter()
        .map(|identity| {
            let original = selected
                .get(&identity.contract)
                .and_then(|(_, flow)| flow.reference.original.clone());
            Ok(Identity {
                principal: wire_text(principal(identity.contract))?,
                step: wire_text(identity.contract.as_str())?,
                subject_digest: identity.subject_digest.clone(),
                original,
            })
        })
        .collect::<Result<_, RecordError>>()?;
    let flows = acquired
        .flows
        .iter()
        .map(|flow| Flow {
            step: flow.reference.step.clone(),
            flow_id: flow.reference.flow_id,
            original: flow.reference.original.clone(),
            completeness: flow.reference.completeness,
            decoder: matches!(
                flow.contract,
                RoundFlow::F0 | RoundFlow::F1 | RoundFlow::F2 | RoundFlow::F3 | RoundFlow::F4
            )
            .then(|| experiment.decoder.identity.clone()),
        })
        .collect();
    Ok(Round {
        number: acquired.number,
        phase: RoundPhase::Verify,
        canaries,
        flows,
        identities,
        result: evaluation.result.into(),
        exposure: evaluation.exposure,
        after_owner_read: evaluation.after_owner_read.unwrap_or(false),
        fields_crossed: evaluation
            .fields_crossed
            .iter()
            .map(|field| wire_text(field.as_str()))
            .collect::<Result<_, _>>()?,
        reason_codes: evaluation.reason_codes,
    })
}

fn slots(experiment: &FrozenExperiment) -> Result<Vec<Slot>, RecordError> {
    experiment
        .slots
        .iter()
        .map(|(name, binding)| slot(name.as_str(), binding))
        .collect()
}

fn validate_record_experiment(
    record: &VerificationV1,
    experiment: &FrozenExperiment,
) -> Result<(), RecordError> {
    let property = experiment
        .property
        .as_ref()
        .ok_or(RecordError::PropertyUnavailable)?;
    let expected_property = Property {
        id: Some(wire_text(property.label.as_str())?),
        digest: property.digest.clone(),
    };
    if record.engagement_revision != experiment.engagement.revision
        || record.property != expected_property
        || record.slots != slots(experiment)?
        || record.template != experiment.template
        || record.oracle != experiment.oracle
    {
        return Err(RecordError::DigestMismatch);
    }
    Ok(())
}

fn slot(name: &str, binding: &crate::template::SlotBinding) -> Result<Slot, RecordError> {
    Ok(Slot {
        name: wire_text(name)?,
        source: binding.source,
        supplied_by: binding.supplied_by.clone(),
        digest: binding.digest.clone(),
    })
}

struct Summary {
    result: OracleResult,
    exposure: Option<Exposure>,
    reproduction: Reproduction,
}

fn summarize<'a>(evaluations: impl Iterator<Item = &'a Evaluation>) -> Summary {
    let evaluations = evaluations.collect::<Vec<_>>();
    let true_count = evaluations
        .iter()
        .filter(|evaluation| evaluation.result == Verdict::True)
        .count();
    let result = if evaluations
        .iter()
        .any(|evaluation| evaluation.result == Verdict::Error)
    {
        OracleResult::Error
    } else if evaluations.is_empty()
        || evaluations
            .iter()
            .any(|evaluation| evaluation.result == Verdict::Invalid)
    {
        OracleResult::Invalid
    } else if true_count > 0 {
        OracleResult::True
    } else {
        OracleResult::False
    };
    let exposure = if result == OracleResult::True
        && evaluations
            .iter()
            .any(|evaluation| evaluation.exposure == Some(Exposure::Unauthenticated))
    {
        Some(Exposure::Unauthenticated)
    } else if result == OracleResult::True {
        Some(Exposure::CrossPrincipal)
    } else {
        None
    };
    let reproduction = match result {
        OracleResult::True if true_count == evaluations.len() => Reproduction::Reproduced,
        OracleResult::True => Reproduction::Intermittent,
        OracleResult::False => Reproduction::NotReproduced,
        OracleResult::Invalid | OracleResult::Error => Reproduction::NotAttempted,
    };
    Summary {
        result,
        exposure,
        reproduction,
    }
}

struct RetainedRecord {
    bytes: Vec<u8>,
    record: VerificationV1,
    inputs: Vec<Artifact>,
}

fn read_record(
    evidence: &impl RecordEvidence,
    artifact: &Artifact,
) -> Result<RetainedRecord, RecordError> {
    let read = evidence.read(artifact)?;
    if Sha256Digest::of(&read.bytes) != artifact.digest || !read.record_lineage {
        return Err(RecordError::DigestMismatch);
    }
    let record: VerificationV1 =
        wire::from_slice(&read.bytes).map_err(|_| RecordError::InvalidRecord)?;
    let canonical = wire::to_vec(&record).map_err(|_| RecordError::InvalidRecord)?;
    if canonical != read.bytes {
        return Err(RecordError::InvalidRecord);
    }
    Ok(RetainedRecord {
        bytes: read.bytes,
        record,
        inputs: read.inputs,
    })
}

fn experiment_reference<'a>(
    record: &VerificationV1,
    lineage_inputs: &'a [Artifact],
) -> Result<&'a Artifact, RecordError> {
    let mut matches = lineage_inputs
        .iter()
        .filter(|input| input.digest == record.experiment_digest);
    let reference = matches.next().ok_or(RecordError::MissingOriginal)?;
    if matches.next().is_some() {
        return Err(RecordError::DigestMismatch);
    }
    Ok(reference)
}

fn reevaluate_record(
    evidence: &impl RecordEvidence,
    record: &VerificationV1,
    lineage_inputs: &[Artifact],
) -> Result<Reevaluation, RecordError> {
    if record.oracle.id.as_str() != registry::ORACLE_ID
        || record.oracle.version.as_str() != registry::ORACLE_VERSION
        || record.oracle.digest != registry::oracle_digest()
    {
        return Err(RecordError::OracleUnavailable);
    }
    let experiment_reference = experiment_reference(record, lineage_inputs)?;
    let expected_inputs = record
        .lineage_inputs(experiment_reference)
        .map_err(lineage_error)?;
    if expected_inputs != lineage_inputs {
        return Err(RecordError::DigestMismatch);
    }
    let experiment_read = evidence.read(experiment_reference)?;
    if Sha256Digest::of(&experiment_read.bytes) != record.experiment_digest {
        return Err(RecordError::DigestMismatch);
    }
    let experiment =
        FrozenExperiment::from_canonical_bytes(&experiment_read.bytes, &record.experiment_digest)
            .map_err(|_| RecordError::InvalidRecord)?;
    validate_record_experiment(record, &experiment)?;
    let limits = DecodeLimits::new(
        experiment.decoder.limits.max_decoded_bytes,
        experiment.decoder.limits.max_expansion_ratio,
    );
    let mut evaluations = Vec::with_capacity(record.rounds.len());
    for round in &record.rounds {
        let observations = observations_from_record(evidence, record, round, limits)?;
        evaluations.push(evaluate(&observations));
    }
    let summary = summarize(evaluations.iter());
    Ok(Reevaluation {
        summary,
        rounds: evaluations,
    })
}

struct Reevaluation {
    summary: Summary,
    rounds: Vec<Evaluation>,
}

fn reevaluation_matches(record: &VerificationV1, reevaluated: &Reevaluation) -> bool {
    record.result == reevaluated.summary.result
        && record.exposure == reevaluated.summary.exposure
        && record.reproduction == reevaluated.summary.reproduction
        && record.rounds.len() == reevaluated.rounds.len()
        && record
            .rounds
            .iter()
            .zip(&reevaluated.rounds)
            .all(|(round, evaluation)| {
                round.result == OracleResult::from(evaluation.result)
                    && round.exposure == evaluation.exposure
                    && round.after_owner_read == evaluation.after_owner_read.unwrap_or(false)
                    && round.fields_crossed.len() == evaluation.fields_crossed.len()
                    && round
                        .fields_crossed
                        .iter()
                        .zip(&evaluation.fields_crossed)
                        .all(|(recorded, observed)| recorded.as_str() == observed.as_str())
                    && round.reason_codes == evaluation.reason_codes
            })
}

fn observations_from_record(
    evidence: &impl RecordEvidence,
    record: &VerificationV1,
    round: &Round,
    limits: DecodeLimits,
) -> Result<SavedObservations, RecordError> {
    let selected = selected_record(&round.flows);
    let mut identities = BTreeMap::new();
    for identity in &round.identities {
        if identities
            .insert(identity.step.as_str(), identity)
            .is_some()
        {
            return Err(RecordError::InvalidRecord);
        }
    }
    let mut flows = Vec::with_capacity(FlowId::REQUIRED.len());
    for required in FlowId::REQUIRED {
        let Some((position, flow)) = selected.get(required.as_str()).copied() else {
            if required != FlowId::C {
                flows.push(missing_flow(
                    &record.run_id,
                    required,
                    flows.len() as u64 + 1,
                ));
            }
            continue;
        };
        let Some(reference) = &flow.original else {
            if required != FlowId::C {
                flows.push(missing_flow(&record.run_id, required, position as u64 + 1));
            }
            continue;
        };
        let read = evidence.read(reference)?;
        if Sha256Digest::of(&read.bytes) != reference.digest {
            return Err(RecordError::DigestMismatch);
        }
        let id = flow.flow_id.ok_or(RecordError::MissingOriginal)?;
        let retained =
            decode_retained_flow(&read.bytes, id).map_err(|_| RecordError::MalformedOriginal)?;
        let response = retained.retained_response();
        if response.completeness != flow.completeness {
            return Err(RecordError::DigestMismatch);
        }
        let subject = if required.is_identity() {
            subject_from_body(
                &response.body,
                required,
                reference,
                identities.get(required.as_str()).copied(),
            )?
        } else {
            None
        };
        let plant = match required {
            FlowId::P => Some(plant_from_record(
                &retained,
                &response.body,
                round,
                PRIMARY_OBJECT,
            )?),
            FlowId::P2 => Some(plant_from_record(
                &retained,
                &response.body,
                round,
                CONTROL_OBJECT,
            )?),
            _ => None,
        };
        let cleanup = (required == FlowId::C).then(|| CleanupDetail {
            attempted: true,
            removed: Vec::new(),
        });
        let decoding = decoding_for(
            retained.response.rendered_head.as_deref(),
            &response.body,
            limits,
        )?;
        flows.push(SavedFlow {
            flow: required,
            run: record.run_id.clone(),
            sequence: position as u64 + 1,
            completeness: flow.completeness,
            decoding,
            decoder: decoding.decoder_name(),
            original: Some(reference.clone()),
            body: response.body,
            subject,
            plant,
            cleanup,
        });
    }
    Ok(SavedObservations {
        schema: wire_text(crate::verification::OBSERVATION_SCHEMA)?,
        oracle: OracleRef {
            id: wire_text(registry::ORACLE_ID)?,
            version: wire_text(registry::ORACLE_VERSION)?,
        },
        run: record.run_id.clone(),
        round: round.number,
        limits,
        flows,
    })
}

/// Select the frozen, bounded decoder from the retained response metadata.
///
/// Teapot has already removed HTTP transfer framing before it stores a body,
/// so `Transfer-Encoding` is deliberately not reapplied. Content codings are
/// accepted only from the compiled registry. The JSON-string stage is selected
/// only when an application/json response contains a string which itself is a
/// complete JSON document; ordinary one-field JSON objects are not wrappers.
fn decoding_for(
    response_head: Option<&str>,
    body: &[u8],
    limits: DecodeLimits,
) -> Result<Decoding, RecordError> {
    let content = match single_header(response_head, "content-encoding")? {
        None | Some("") => ContentCoding::Identity,
        Some(value) if value.eq_ignore_ascii_case("identity") => ContentCoding::Identity,
        Some(value) if value.eq_ignore_ascii_case("gzip") => ContentCoding::Gzip,
        Some(value) if value.eq_ignore_ascii_case("deflate") => ContentCoding::Deflate,
        Some(_) => return Err(RecordError::MalformedOriginal),
    };
    let mut decoding = Decoding {
        content,
        ..Decoding::default()
    };
    let json = single_header(response_head, "content-type")?
        .and_then(|value| value.split(';').next())
        .map(str::trim)
        .is_some_and(|value| {
            value.eq_ignore_ascii_case("application/json")
                || value.to_ascii_lowercase().ends_with("+json")
        });
    if json
        && let Ok(decoded) = decode_body(body, decoding, limits)
        && is_json_document_wrapper(&decoded.bytes)
    {
        decoding.json_string_body = true;
    }
    Ok(decoding)
}

fn single_header<'a>(
    response_head: Option<&'a str>,
    name: &str,
) -> Result<Option<&'a str>, RecordError> {
    let Some(head) = response_head else {
        return Ok(None);
    };
    let mut values = head.lines().filter_map(|line| {
        let (candidate, value) = line.trim_end_matches('\r').split_once(':')?;
        candidate
            .trim()
            .eq_ignore_ascii_case(name)
            .then_some(value.trim())
    });
    let first = values.next();
    if values.next().is_some() {
        return Err(RecordError::MalformedOriginal);
    }
    Ok(first)
}

fn is_json_document_wrapper(bytes: &[u8]) -> bool {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(bytes) else {
        return false;
    };
    let document = match &value {
        serde_json::Value::String(document) => Some(document.as_str()),
        serde_json::Value::Object(object) if object.len() == 1 => {
            object.values().next().and_then(serde_json::Value::as_str)
        }
        _ => None,
    };
    document.is_some_and(|document| serde_json::from_str::<serde_json::Value>(document).is_ok())
}

fn selected_record(flows: &[Flow]) -> BTreeMap<&str, (usize, &Flow)> {
    let mut selected = BTreeMap::new();
    for (position, flow) in flows.iter().enumerate() {
        let mut parts = flow.step.as_str().split('.');
        let Some(contract) = parts.next() else {
            continue;
        };
        let role = flow.step.as_str().rsplit('.').next();
        if !FlowId::REQUIRED
            .iter()
            .any(|required| required.as_str() == contract)
        {
            continue;
        }
        if matches!(role, Some("request" | "retry")) {
            selected.insert(contract, (position, flow));
        }
    }
    selected
}

fn subject_from_body(
    body: &[u8],
    flow: FlowId,
    original: &Artifact,
    recorded: Option<&Identity>,
) -> Result<Option<Subject>, RecordError> {
    let recorded = recorded.ok_or(RecordError::InvalidRecord)?;
    if recorded.principal.as_str() != principal(round_flow(flow))
        || recorded.original.as_ref() != Some(original)
    {
        return Err(RecordError::DigestMismatch);
    }
    let subject = serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|value| value.get(REGISTERED_ID_FIELD)?.as_str().map(str::to_owned));
    match (subject, recorded.subject_digest.as_ref()) {
        (None, None) => Ok(None),
        (Some(subject), Some(digest)) if *digest == Sha256Digest::of(subject.as_bytes()) => {
            Ok(Some(Subject::from(wire_text(&subject)?)))
        }
        _ => Err(RecordError::DigestMismatch),
    }
}

fn plant_from_record(
    retained: &crate::teapot::StoredFlow,
    response_body: &[u8],
    round: &Round,
    object: &str,
) -> Result<PlantDetail, RecordError> {
    let response: serde_json::Value = serde_json::from_slice(response_body).unwrap_or_default();
    let object_key = response
        .get(REGISTERED_ID_FIELD)
        .and_then(serde_json::Value::as_str)
        .map(wire_text)
        .transpose()?
        .map(ObjectKey::from);
    let request_body = retained
        .request
        .body
        .as_ref()
        .filter(|body| {
            body.whole && body.capture == crate::teapot::BodyCapture::Complete && !retained.head_cut
        })
        .and_then(|body| body.bytes.as_deref())
        .ok_or(RecordError::MissingOriginal)?;
    let request: serde_json::Value =
        serde_json::from_slice(request_body).map_err(|_| RecordError::MalformedOriginal)?;
    let mut canaries = Vec::new();
    for expected in round
        .canaries
        .iter()
        .filter(|canary| canary.object.as_str() == object)
    {
        let Some(value) = request
            .get(expected.field.as_str())
            .and_then(serde_json::Value::as_str)
        else {
            continue;
        };
        if Sha256Digest::of(value.as_bytes()) != expected.digest {
            return Err(RecordError::DigestMismatch);
        }
        let canary = value
            .to_owned()
            .try_into()
            .map_err(|_| RecordError::InvalidRecord)?;
        canaries.push(ObservationCanary {
            field: FieldName::from(expected.field.clone()),
            canary,
        });
    }
    Ok(PlantDetail {
        object: object_key,
        canaries,
    })
}

fn lineage_error(error: JsonError) -> RecordError {
    match error {
        JsonError::Serialize => RecordError::Schema,
        JsonError::DigestMismatch => RecordError::DigestMismatch,
        _ => RecordError::InvalidRecord,
    }
}

fn round_flow(flow: FlowId) -> RoundFlow {
    match flow {
        FlowId::I1 => RoundFlow::I1,
        FlowId::I2 => RoundFlow::I2,
        FlowId::P => RoundFlow::P,
        FlowId::P2 => RoundFlow::P2,
        FlowId::F0 => RoundFlow::F0,
        FlowId::F1 => RoundFlow::F1,
        FlowId::F2 => RoundFlow::F2,
        FlowId::F3 => RoundFlow::F3,
        FlowId::F4 => RoundFlow::F4,
        FlowId::I3 => RoundFlow::I3,
        FlowId::I4 => RoundFlow::I4,
        FlowId::C => RoundFlow::C,
    }
}

fn principal(flow: RoundFlow) -> &'static str {
    match flow {
        RoundFlow::I1 | RoundFlow::I3 => "owner",
        RoundFlow::I2 | RoundFlow::I4 => "other",
        _ => "none",
    }
}

fn wire_text(value: &str) -> Result<WireText, RecordError> {
    value.to_owned().try_into().map_err(|_| RecordError::Schema)
}

#[cfg(test)]
mod tests;
