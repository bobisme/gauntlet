//! Effectful acquisition for the frozen private-object-read round.
//!
//! The caller supplies no request grammar, observations, or verdict.  Request
//! shapes come from the compiled operation registry after it binds the exact
//! frozen experiment to the retained engagement.  Every step records an
//! intent before the first possible target effect, and every Teapot flow the
//! step reports (including login and retry flows) is read by exact ID and
//! attached to one Investigation capture.

use std::collections::{BTreeMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::{
    canonical::{self, Sha256Digest},
    domain::{CleanupObjectOutcome, CleanupObjectRole, CleanupOwnership, RunCleanup, RunStep},
    engagement::{ManifestRevision, VersionRef},
    evidence::{Capture, CaptureHandle, Completion, Evidence, EvidenceError, Finalized},
    ids::{RunId, SessionName, WireText},
    operations::{
        FieldSpec, IDENTITY_PATH, IDENTITY_SUBJECT_FIELD, REGISTRY_ID, RegisteredOperations,
        RegistryError,
    },
    preflight::{LiveAdmission, Prepared},
    store::{ExecutionStore, RunRecovery, Store, StoreError},
    teapot::{
        BodyWindow, DispatchEvidence, EnforcementStatus, FlowReference, FlowRole, GateRefusal,
        InstrumentObservation, InvocationError, SendOptions, StepFlow, Teapot,
        accounting::{AccountingFailure, AccountingObservation},
        passive::PassiveError,
    },
    template::{FrozenExperiment, Method},
    wire::{
        Artifact, Cleanup, Completeness, Custody, Effect, Enforcement, EnvironmentKind, ErrorCode,
        Flow, OracleResult, Strength, Target, TargetIsolation, Timestamp, Verifier,
    },
};

/// Frozen acquisition order from `scourge.oracle-specifications.v1`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RoundFlow {
    I1,
    I2,
    P,
    P2,
    F0,
    F1,
    F2,
    F3,
    F4,
    I3,
    I4,
    C,
}

impl RoundFlow {
    pub const REQUIRED: [Self; 12] = [
        Self::I1,
        Self::I2,
        Self::P,
        Self::P2,
        Self::F0,
        Self::F1,
        Self::F2,
        Self::F3,
        Self::F4,
        Self::I3,
        Self::I4,
        Self::C,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::I1 => "I1",
            Self::I2 => "I2",
            Self::P => "P",
            Self::P2 => "P2",
            Self::F0 => "F0",
            Self::F1 => "F1",
            Self::F2 => "F2",
            Self::F3 => "F3",
            Self::F4 => "F4",
            Self::I3 => "I3",
            Self::I4 => "I4",
            Self::C => "C",
        }
    }

    pub(crate) fn step_number(self, round: u64) -> Option<u64> {
        let index = Self::REQUIRED.iter().position(|flow| *flow == self)?;
        round
            .checked_sub(1)?
            .checked_mul(Self::REQUIRED.len() as u64)?
            .checked_add(index as u64 + 1)
    }
}

/// A verifier-minted 128-bit value in the frozen lowercase hexadecimal form.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Canary(WireText);

impl Canary {
    pub fn parse(value: &str) -> Result<Self, &'static str> {
        if value.len() != 32
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return Err("canary must be 32 lowercase hexadecimal characters");
        }
        Ok(Self(
            value
                .to_owned()
                .try_into()
                .map_err(|_| "canary must be nonempty")?,
        ))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    pub fn occurs_in(&self, body: &[u8]) -> bool {
        let needle = self.as_str().as_bytes();
        body.windows(needle.len()).any(|window| window == needle)
    }
}

impl TryFrom<String> for Canary {
    type Error = &'static str;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<Canary> for String {
    fn from(value: Canary) -> Self {
        value.0.as_str().to_owned()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlantedCanary {
    pub field: WireText,
    pub canary: Canary,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcquiredFlow {
    pub contract: RoundFlow,
    pub sequence: u64,
    pub reference: Flow,
    /// Exact stored response-body window. Empty is distinct from a missing or
    /// incomplete body through `reference.completeness`.
    pub response_body: Vec<u8>,
    /// Teapot's rendered response head, used only to select a compiled body
    /// decoder. It is not proof of wire bytes and is never passed to an oracle.
    pub response_head: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcquiredIdentity {
    pub contract: RoundFlow,
    pub subject_digest: Option<Sha256Digest>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcquiredRound {
    pub number: u64,
    pub primary: Vec<PlantedCanary>,
    pub control: Vec<PlantedCanary>,
    pub flows: Vec<AcquiredFlow>,
    pub identities: Vec<AcquiredIdentity>,
    /// Exact per-object cleanup authority and outcome for this round.
    pub cleanup: Vec<RunCleanup>,
}

#[derive(Debug)]
pub struct ExecutedRounds {
    acceptance: crate::store::RunAcceptance,
    acquired_run: crate::domain::Run,
    experiment: FrozenExperiment,
    experiment_artifact: Artifact,
    evidence_case_id: String,
    rounds: Vec<AcquiredRound>,
    capture: Finalized,
    accounting: AccountingObservation,
    verification: VerificationMaterial,
    _trusted_acquisition: TrustedAcquisition,
}

/// An unconstructible marker proving [`ExecutedRounds`] came from the live,
/// compiled acquisition path rather than caller-supplied observations.
#[derive(Debug)]
struct TrustedAcquisition;

#[cfg(test)]
pub(crate) struct ExecutedRoundsFixture {
    pub acceptance: crate::store::RunAcceptance,
    pub experiment: FrozenExperiment,
    pub experiment_artifact: Artifact,
    pub rounds: Vec<AcquiredRound>,
    pub capture: Finalized,
    pub accounting: crate::wire::AccountingV1,
    pub evidence_case_id: String,
    pub verification: VerificationMaterial,
}

/// Redacted passive observation and its original in this run's capture.
#[derive(Debug)]
pub struct RetainedInstrumentObservation {
    pub observation: InstrumentObservation,
    pub artifact: Artifact,
}

/// Non-verdict context established by the sealed live acquisition.
#[derive(Debug)]
pub struct VerificationMaterial {
    pub start: RetainedInstrumentObservation,
    pub end: RetainedInstrumentObservation,
    pub started_at: Timestamp,
    pub finished_at: Timestamp,
    pub verifier: Verifier,
    pub target: Target,
    /// Target selector admitted by the operator. It is not a deployment marker.
    pub target_version: VersionRef,
    pub custody: Custody,
    pub target_isolation: TargetIsolation,
    pub environment_kind: EnvironmentKind,
    pub enforcement: Enforcement,
}

impl ExecutedRounds {
    #[cfg(test)]
    pub(crate) fn verification_fixture(fixture: ExecutedRoundsFixture) -> Self {
        let ExecutedRoundsFixture {
            acceptance,
            experiment,
            experiment_artifact,
            rounds,
            capture,
            accounting,
            evidence_case_id,
            verification,
        } = fixture;
        let acquired_run = acceptance.run.clone();
        Self {
            acceptance,
            accounting: AccountingObservation::verification_fixture(&acquired_run, accounting),
            acquired_run,
            experiment,
            experiment_artifact,
            evidence_case_id,
            rounds,
            capture,
            verification,
            _trusted_acquisition: TrustedAcquisition,
        }
    }

    /// The durable run every acquired flow is bound to.
    pub fn run(&self) -> &RunId {
        &self.acquired_run.id
    }

    /// Engagement identity accepted in the same durable run declaration.
    pub fn engagement(&self) -> &crate::ids::EngagementId {
        &self.acquired_run.engagement
    }

    /// The retained, compiled experiment that produced every request.
    pub fn experiment(&self) -> &FrozenExperiment {
        &self.experiment
    }

    /// Digest of the exact canonical experiment bytes accepted for the run.
    pub fn experiment_digest(&self) -> &Sha256Digest {
        &self.acquired_run.experiment_digest
    }

    /// Investigation artifact retaining those exact experiment bytes.
    pub fn experiment_artifact(&self) -> &Artifact {
        &self.experiment_artifact
    }

    pub(crate) fn evidence_case_id(&self) -> &str {
        &self.evidence_case_id
    }

    /// Typed observations acquired by the compiled recipe in this run.
    pub fn rounds(&self) -> &[AcquiredRound] {
        &self.rounds
    }

    /// The complete Investigation capture that retained the flow originals.
    pub fn capture(&self) -> &Finalized {
        &self.capture
    }

    /// Accounting observed around exactly this acquisition window.
    pub fn accounting(&self) -> &AccountingObservation {
        &self.accounting
    }

    /// Passive observations, runtime identity and record qualification for
    /// the exact acquisition window.
    pub fn verification(&self) -> &VerificationMaterial {
        &self.verification
    }

    /// Run-wide cleanup summary recovered after per-object originals were
    /// linked to their exact durable steps.
    pub fn cleanup(&self) -> Cleanup {
        self.acquired_run.cleanup
    }

    /// Original request acceptance and the exact durable acquisition snapshot
    /// that publication must compare before settling this run.
    pub fn settlement(&self) -> (&crate::store::RunAcceptance, &crate::domain::Run) {
        (&self.acceptance, &self.acquired_run)
    }
}

/// An acquisition that could not produce a sealed execution. The selectors
/// locate durable state even when the capture or the instrument failed.
#[derive(Debug, thiserror::Error)]
#[error("{error}")]
pub struct ExecutionFailure {
    #[source]
    pub error: Box<RoundError>,
    pub recovery: RunRecovery,
    pub capture_handle: Option<CaptureHandle>,
    pub effects: Effect,
}

impl ExecutionFailure {
    pub fn code(&self) -> ErrorCode {
        if self.effects == Effect::Unknown {
            ErrorCode::EffectUnknown
        } else {
            self.error.code()
        }
    }

    pub fn result(&self) -> OracleResult {
        match self.code() {
            ErrorCode::IdentityUnestablished | ErrorCode::EvidenceIncomplete => {
                OracleResult::Invalid
            }
            _ => OracleResult::Error,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RoundError {
    #[error("the frozen experiment is not executable by the compiled operation registry")]
    Registry,
    #[error("the target origin is not an absolute HTTP origin")]
    InvalidOrigin,
    #[error("the number of rounds must be positive")]
    InvalidRounds,
    #[error("the execution did not match the exact admitted compiled dispatch plan")]
    AdmissionMismatch,
    #[error("isolated custody is not established for this verifier")]
    CustodyUnavailable,
    #[error("the running verifier executable could not be identified")]
    VerifierUnavailable(#[source] std::io::Error),
    #[error("the bound instrument identity changed during acquisition")]
    InstrumentChanged,
    #[error("the wall clock moved backward during acquisition")]
    ClockDiscontinuity,
    #[error("the run has a durable step with unknown effects")]
    EffectsUnknown,
    #[error(transparent)]
    EndGate(Box<GateRefusal>),
    #[error("the operating system could not mint a canary")]
    Random,
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Evidence(#[from] EvidenceError),
    #[error(transparent)]
    Instrument(#[from] InvocationError),
    #[error(transparent)]
    Passive(#[from] PassiveError),
    #[error(transparent)]
    Accounting(Box<AccountingFailure>),
    #[error("the instrument reported a retained flow at or below the pre-send floor")]
    FlowBeforeFloor,
    #[error("the instrument reported one retained flow more than once in a step")]
    DuplicateFlow,
    #[error("the exact flow read-back did not match the registered request")]
    ReadbackMismatch,
    #[error("the plant response did not establish a new object identity")]
    ObjectNotEstablished,
    #[error("an identity response did not contain the registered subject")]
    IdentityNotEstablished,
    #[error("the evidence capture did not publish every attached original")]
    CaptureMismatch,
    #[error("an internal acquisition value did not fit the frozen wire shape")]
    Wire,
}

impl From<RegistryError> for RoundError {
    fn from(_: RegistryError) -> Self {
        Self::Registry
    }
}

impl RoundError {
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::InvalidOrigin | Self::InvalidRounds => ErrorCode::UsageError,
            Self::Registry
            | Self::AdmissionMismatch
            | Self::InstrumentChanged
            | Self::ReadbackMismatch
            | Self::CaptureMismatch
            | Self::Wire => ErrorCode::IntegrityFailure,
            Self::Store(error) => error.error_code(),
            Self::Instrument(error) => error.code(),
            Self::CustodyUnavailable => ErrorCode::CustodyUnavailable,
            Self::EffectsUnknown => ErrorCode::EffectUnknown,
            Self::EndGate(error) => error.code(),
            Self::Accounting(error) => error.error().code(),
            Self::Passive(_)
            | Self::Random
            | Self::VerifierUnavailable(_)
            | Self::ClockDiscontinuity => ErrorCode::DependencyUnavailable,
            Self::Evidence(error) => error.code(),
            Self::FlowBeforeFloor | Self::DuplicateFlow => ErrorCode::EvidenceIncomplete,
            Self::ObjectNotEstablished | Self::IdentityNotEstablished => {
                ErrorCode::IdentityUnestablished
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TargetOrigin(WireText);

impl serde::Serialize for TargetOrigin {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}
impl<'de> serde::Deserialize<'de> for TargetOrigin {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = <String as serde::Deserialize>::deserialize(deserializer)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}

impl TargetOrigin {
    pub fn parse(value: &str) -> Result<Self, RoundError> {
        let authority = value
            .strip_prefix("http://")
            .or_else(|| value.strip_prefix("https://"))
            .ok_or(RoundError::InvalidOrigin)?;
        if authority.is_empty() || authority.contains(['/', '?', '#', '@']) || value.ends_with('.')
        {
            return Err(RoundError::InvalidOrigin);
        }
        Ok(Self(
            value
                .to_owned()
                .try_into()
                .map_err(|_| RoundError::InvalidOrigin)?,
        ))
    }

    /// Exact already-validated origin used by the compiled request recipe.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    fn join(&self, path: &str) -> Result<WireText, RoundError> {
        format!("{}{path}", self.0.as_str())
            .try_into()
            .map_err(|_| RoundError::Wire)
    }
}

trait Entropy {
    fn fill(&mut self, bytes: &mut [u8; 16]) -> Result<(), RoundError>;
}

struct OsEntropy;

impl Entropy for OsEntropy {
    fn fill(&mut self, bytes: &mut [u8; 16]) -> Result<(), RoundError> {
        rustix::rand::getrandom(bytes.as_mut_slice(), rustix::rand::GetRandomFlags::empty())
            .map(|_| ())
            .map_err(|_| RoundError::Random)
    }
}

struct CanaryMint<E> {
    entropy: E,
    seen: HashSet<Canary>,
}

impl<E: Entropy> CanaryMint<E> {
    fn new(entropy: E) -> Self {
        Self {
            entropy,
            seen: HashSet::new(),
        }
    }

    fn mint(&mut self) -> Result<Canary, RoundError> {
        loop {
            let mut bytes = [0_u8; 16];
            self.entropy.fill(&mut bytes)?;
            let mut text = String::with_capacity(32);
            for byte in bytes {
                use std::fmt::Write as _;
                write!(&mut text, "{byte:02x}").expect("writing to a String cannot fail");
            }
            let canary = Canary::parse(&text).map_err(|_| RoundError::Wire)?;
            if self.seen.insert(canary.clone()) {
                return Ok(canary);
            }
        }
    }
}

#[derive(Clone, Debug, Serialize)]
struct RequestIntent<'a> {
    registry: &'static str,
    registry_digest: &'a Sha256Digest,
    round: u64,
    flow: &'static str,
    actions: &'a [RequestAction],
}

#[derive(Clone, Debug, Serialize)]
struct RequestAction {
    kind: &'static str,
    method: Method,
    url: String,
    session: String,
    headers: Vec<String>,
    body: Option<String>,
    #[serde(skip)]
    cleanup_object: Option<CleanupObjectRole>,
}

impl RequestAction {
    fn send(method: Method, url: WireText, session: SessionName) -> Self {
        Self {
            kind: "send",
            method,
            url: url.as_str().to_owned(),
            session: session.as_str().to_owned(),
            headers: Vec::new(),
            body: None,
            cleanup_object: None,
        }
    }

    fn cleanup(url: WireText, session: SessionName, object: CleanupObjectRole) -> Self {
        let mut action = Self::send(Method::Delete, url, session);
        action.cleanup_object = Some(object);
        action
    }

    fn plant(
        url: WireText,
        session: SessionName,
        canaries: &[PlantedCanary],
    ) -> Result<Self, RoundError> {
        let body = canaries
            .iter()
            .map(|planted| (planted.field.as_str(), planted.canary.as_str()))
            .collect::<BTreeMap<_, _>>();
        Ok(Self {
            kind: "send",
            method: Method::Post,
            url: url.as_str().to_owned(),
            session: session.as_str().to_owned(),
            headers: vec!["Content-Type: application/json".to_owned()],
            body: Some(serde_json::to_string(&body).map_err(|_| RoundError::Wire)?),
            cleanup_object: None,
        })
    }

    fn method(&self) -> Method {
        self.method
    }

    fn url(&self) -> Result<WireText, RoundError> {
        self.url.clone().try_into().map_err(|_| RoundError::Wire)
    }

    fn session(&self) -> Result<SessionName, RoundError> {
        self.session.parse().map_err(|_| RoundError::Wire)
    }
}

#[derive(Debug)]
struct DispatchReceipt {
    dispatch: DispatchEvidence,
    flows: Vec<StepFlow>,
    status: Option<u16>,
}

#[derive(Debug)]
struct ActionExecution {
    reference: WireText,
    effect: Effect,
    status: Option<u16>,
    flows: Vec<AcquiredFlow>,
}

#[derive(Debug)]
struct StepExecution {
    flows: Vec<AcquiredFlow>,
    actions: Vec<ActionExecution>,
}

#[derive(Debug)]
struct Readback {
    id: u64,
    url: Option<String>,
    method: Option<String>,
    status: Option<u16>,
    response_body: Vec<u8>,
    response_head: Option<String>,
    completeness: Completeness,
    original: Vec<u8>,
}

trait RoundIo {
    fn flow_floor(&mut self) -> Result<Option<u64>, RoundError>;
    fn dispatch(&mut self, action: &RequestAction) -> Result<DispatchReceipt, RoundError>;
    fn read_flow(&mut self, id: u64) -> Result<Readback, RoundError>;
    fn attach(&mut self, key: &str, bytes: &[u8]) -> Result<(), RoundError>;
    fn finalize(&mut self, completion: Completion) -> Result<Finalized, RoundError>;
}

struct LiveRoundIo<'a> {
    teapot: &'a Teapot,
    evidence: &'a Evidence,
    capture: Capture,
    position: u64,
    keys: Vec<String>,
}

impl LiveRoundIo<'_> {
    fn new<'a>(teapot: &'a Teapot, evidence: &'a Evidence, capture: Capture) -> LiveRoundIo<'a> {
        LiveRoundIo {
            teapot,
            evidence,
            capture,
            position: 0,
            keys: Vec::new(),
        }
    }
}

impl RoundIo for LiveRoundIo<'_> {
    fn flow_floor(&mut self) -> Result<Option<u64>, RoundError> {
        self.teapot.passive().highest_flow_id().map_err(Into::into)
    }

    fn dispatch(&mut self, action: &RequestAction) -> Result<DispatchReceipt, RoundError> {
        teapot_dispatch(self.teapot, action)
    }

    fn read_flow(&mut self, id: u64) -> Result<Readback, RoundError> {
        teapot_read(self.teapot, id)
    }

    fn attach(&mut self, key: &str, bytes: &[u8]) -> Result<(), RoundError> {
        self.position = self.position.checked_add(1).ok_or(RoundError::Wire)?;
        self.evidence
            .attach(&self.capture, self.position, key, bytes)?;
        self.keys.push(key.to_owned());
        Ok(())
    }

    fn finalize(&mut self, completion: Completion) -> Result<Finalized, RoundError> {
        let keys = self.keys.iter().map(String::as_str).collect::<Vec<_>>();
        self.evidence
            .finalize(
                &self.capture,
                (self.position > 0).then_some(self.position),
                completion,
                &keys,
            )
            .map_err(Into::into)
    }
}

fn teapot_dispatch(teapot: &Teapot, action: &RequestAction) -> Result<DispatchReceipt, RoundError> {
    let session = action.session()?;
    let url = action.url()?;
    let observation = teapot.send(
        action.method(),
        &url,
        &session,
        SendOptions {
            headers: &action.headers,
            body: action.body.as_deref(),
            ..SendOptions::default()
        },
    )?;
    Ok(DispatchReceipt {
        dispatch: observation.value.dispatch(),
        flows: observation.value.flows(),
        status: observation.value.status,
    })
}

fn teapot_read(teapot: &Teapot, id: u64) -> Result<Readback, RoundError> {
    let window = BodyWindow::new(0, 1024 * 1024)?;
    let observation = teapot.read_flow(id, Some(window))?;
    let retained = observation.value.retained_response();
    Ok(Readback {
        id,
        url: observation.value.url,
        method: observation.value.method,
        status: observation.value.status,
        response_body: retained.body,
        response_head: observation.value.response.rendered_head,
        completeness: retained.completeness,
        original: observation.evidence.stdout().to_vec(),
    })
}

#[derive(Debug)]
struct PendingOriginal {
    step: u64,
    flow: usize,
    key: String,
}

#[derive(Default)]
struct AcquisitionState {
    steps: BTreeMap<u64, RunStep>,
    pending: Vec<PendingOriginal>,
    sequence: u64,
}

/// Execute one or more complete frozen rounds after successful preflight.
/// The prepared value keeps all live and durable conflict claims held through
/// the final passive observation. `origin` is the operator-bound request
/// origin. No target request can be supplied by a caller.
pub fn execute_live(
    store: &mut Store,
    prepared: Prepared<LiveAdmission<'_>>,
    manifest: &ManifestRevision,
    teapot: &Teapot,
    evidence: &Evidence,
    origin: &TargetOrigin,
) -> Result<ExecutedRounds, ExecutionFailure> {
    let recovery = prepared.acceptance().recovery();
    with_execution_recovery(store, recovery, |store, capture_handle| {
        execute_live_inner(
            store,
            prepared,
            manifest,
            teapot,
            evidence,
            origin,
            capture_handle,
        )
    })
}

fn with_execution_recovery<T>(
    store: &mut Store,
    recovery: RunRecovery,
    execute: impl FnOnce(&mut Store, &mut Option<CaptureHandle>) -> Result<T, RoundError>,
) -> Result<T, ExecutionFailure> {
    let mut capture_handle = None;
    execute(store, &mut capture_handle).map_err(|error| ExecutionFailure {
        effects: store
            .recover_run(&recovery.run_id)
            .map_or(Effect::Unknown, |run| run.known_effects()),
        error: Box::new(error),
        recovery,
        capture_handle,
    })
}

fn execute_live_inner(
    store: &mut Store,
    prepared: Prepared<LiveAdmission<'_>>,
    manifest: &ManifestRevision,
    teapot: &Teapot,
    evidence: &Evidence,
    origin: &TargetOrigin,
    capture_handle: &mut Option<CaptureHandle>,
) -> Result<ExecutedRounds, RoundError> {
    if manifest.settings().required_custody == Custody::Isolated {
        return Err(RoundError::CustodyUnavailable);
    }
    if !prepared.admission().matches(teapot, evidence)
        || prepared.acceptance().lead_id.is_none()
        || prepared.acceptance().lead_revision.is_none()
    {
        return Err(RoundError::AdmissionMismatch);
    }
    check_target_binding(
        &prepared.admission().target_origin,
        &prepared.admission().target_version,
        origin,
        manifest.target_version(),
    )?;
    prepared
        .validate_live_execution(manifest, teapot)
        .map_err(|_| RoundError::AdmissionMismatch)?;
    let operations = RegisteredOperations::resolve(prepared.experiment(), manifest)?;
    if prepared.execution_plan().registry_digest != operations.registry_digest {
        return Err(RoundError::AdmissionMismatch);
    }
    let round_count = prepared.execution_plan().round_count;
    let Some((requests_per_round, required_requests)) = operations.request_bound(round_count)
    else {
        return Err(RoundError::AdmissionMismatch);
    };
    if requests_per_round != prepared.execution_plan().requests_per_round
        || required_requests != prepared.execution_plan().required_requests
    {
        return Err(RoundError::AdmissionMismatch);
    }
    let run = prepared.acceptance().run.id.clone();
    let experiment = prepared.experiment().clone();
    let experiment_artifact = prepared.artifact().clone();
    let target_origin = prepared.admission().target_origin.clone();
    let target_version = prepared.admission().target_version.clone();
    let custody = prepared.admission().custody;
    let target_isolation = prepared.admission().target_isolation;
    let environment_kind = prepared.admission().environment_kind;
    let sessions = prepared.admission().sessions.clone();
    let requirement = prepared.admission().requirement;
    let started_at = prepared.admission().started_at.clone();
    let verifier = running_verifier().map_err(RoundError::VerifierUnavailable)?;
    let mut writer = store.execution_store(&prepared.authority)?;
    writer.check_run(&run)?;
    if evidence
        .describe(&experiment_artifact.artifact_id)?
        .reference
        != experiment_artifact
    {
        return Err(RoundError::CaptureMismatch);
    }
    let capture = evidence.capture(&run)?;
    *capture_handle = Some(capture.handle.clone());
    let mut io = LiveRoundIo::new(teapot, evidence, capture);
    let start = prepared.admission.instrument;
    let start_digest =
        match attach_gate_observation(&mut io, START_OBSERVATION, &started_at, Ok(&start)) {
            Ok(digest) => digest,
            Err(error) => {
                let _ = io.finalize(Completion::Interrupted);
                return Err(error);
            }
        };
    let mut state = AcquisitionState::default();
    let mut mint = CanaryMint::new(OsEntropy);
    let execution = acquire_rounds(
        &mut writer,
        &run,
        &operations,
        &target_origin,
        round_count,
        &mut mint,
        &mut io,
        &mut state,
    );
    // Both passive boundaries and every counter sample belong to this same
    // capture. Preserve all available evidence even when acquisition fails.
    let accounting = prepared.admission.accounting.finish();
    let end = teapot.verifier_preflight(&sessions, requirement);
    let finished_at = Timestamp::now_utc();
    let end_check = end
        .as_ref()
        .map_err(|_| ())
        .and_then(|end| same_instrument_binding(&start, end).then_some(()).ok_or(()));
    let retained = finish_capture(
        &mut io,
        accounting.as_ref().map_or_else(
            |failure| failure.evidence().artifacts(),
            |sample| sample.evidence().artifacts(),
        ),
        end.as_ref(),
        &finished_at,
        execution.is_ok() && accounting.is_ok() && end_check.is_ok(),
    );
    let linked = retained.and_then(|retained| {
        link_originals(
            &mut writer,
            &run,
            &mut state,
            &retained.capture,
            retained.accounting_keys.len() + 2,
        )?;
        Ok(retained)
    });
    let mut rounds = execution?;
    let end = end.map_err(|error| RoundError::EndGate(Box::new(error)))?;
    end_check.map_err(|()| RoundError::InstrumentChanged)?;
    let mut accounting = accounting.map_err(RoundError::Accounting)?;
    let retained = linked?;
    let capture = retained.capture;
    if !capture.complete || !capture.missing_positions.is_empty() {
        return Err(RoundError::CaptureMismatch);
    }
    retain_accounting_artifacts(&mut accounting, &capture, &retained.accounting_keys)?;
    let verification = verification_material(
        VerificationAuthority {
            origin: target_origin,
            target_version,
            verifier,
            custody,
            target_isolation,
            environment_kind,
        },
        started_at,
        finished_at,
        RetainedInstrumentObservation {
            observation: start,
            artifact: observation_artifact(&capture, START_OBSERVATION, &start_digest)?,
        },
        RetainedInstrumentObservation {
            observation: end,
            artifact: observation_artifact(&capture, END_OBSERVATION, &retained.end_digest)?,
        },
    )?;
    let (acquired_run, trusted_acquisition) = seal_acquisition(&writer, &run, &state, &mut rounds)?;
    Ok(ExecutedRounds {
        acceptance: prepared.acceptance,
        acquired_run,
        experiment,
        experiment_artifact,
        evidence_case_id: evidence.case_id().to_owned(),
        rounds,
        capture,
        accounting,
        verification,
        _trusted_acquisition: trusted_acquisition,
    })
}

fn seal_acquisition(
    store: &Store,
    run: &RunId,
    state: &AcquisitionState,
    rounds: &mut [AcquiredRound],
) -> Result<(crate::domain::Run, TrustedAcquisition), RoundError> {
    refresh_round_originals(rounds, state)?;
    refresh_round_cleanup(store, run, rounds)?;
    let acquired_run = store.recover_run(run)?;
    if acquired_run.steps.iter().ne(state.steps.values()) {
        return Err(RoundError::CaptureMismatch);
    }
    if acquired_run.known_effects() == Effect::Unknown
        && (acquired_run.effects == Effect::Unknown
            || !matches!(acquired_run.cleanup, Cleanup::Partial | Cleanup::Unknown)
            || acquired_run.steps.iter().any(|step| {
                matches!(step.effects, None | Some(Effect::Unknown))
                    && !step.step.as_str().ends_with(".C")
            }))
    {
        return Err(RoundError::EffectsUnknown);
    }
    Ok((acquired_run, TrustedAcquisition))
}

fn check_target_binding(
    bound_origin: &TargetOrigin,
    bound_version: &VersionRef,
    origin: &TargetOrigin,
    version: &VersionRef,
) -> Result<(), RoundError> {
    if bound_origin != origin || bound_version != version {
        return Err(RoundError::AdmissionMismatch);
    }
    Ok(())
}

fn same_instrument_binding(start: &InstrumentObservation, end: &InstrumentObservation) -> bool {
    start.identity == end.identity
        && start.enforcement == end.enforcement
        && start.policy_locked == end.policy_locked
        && matches!(
            (&start.pass, &end.pass),
            (Some(start), Some(end))
                if start.id == end.id
                    && start.digest == end.digest
                    && start.file == end.file
        )
}

const START_OBSERVATION: &str = "edit-surface-start";
const END_OBSERVATION: &str = "edit-surface-end";

fn attach_gate_observation(
    io: &mut impl RoundIo,
    key: &str,
    timestamp: &Timestamp,
    observation: Result<&InstrumentObservation, &GateRefusal>,
) -> Result<Sha256Digest, RoundError> {
    let observation = match observation {
        Ok(admitted) => serde_json::json!({"admitted": admitted}),
        Err(refusal) => serde_json::json!({
            "refused": refusal.reason,
            "calls": refusal.calls,
            "edit_surface": refusal.edit_surface,
            "enforcement": refusal.enforcement,
            "policy_locked": refusal.policy_locked,
        }),
    };
    let bytes = canonical::to_vec(&serde_json::json!({
        "schema": "scourge.instrument-observation.v1",
        "boundary": key,
        "timestamp": timestamp,
        "observation": observation,
    }))
    .map_err(|_| RoundError::Wire)?;
    io.attach(key, &bytes)?;
    Ok(Sha256Digest::of(&bytes))
}

struct CaptureEnd {
    capture: Finalized,
    accounting_keys: Vec<String>,
    end_digest: Sha256Digest,
}

fn finish_capture(
    io: &mut impl RoundIo,
    accounting: &[crate::teapot::accounting::NativeEvidence],
    end: Result<&InstrumentObservation, &GateRefusal>,
    finished_at: &Timestamp,
    complete: bool,
) -> Result<CaptureEnd, RoundError> {
    let end_digest = attach_gate_observation(io, END_OBSERVATION, finished_at, end);
    let accounting_keys = accounting
        .iter()
        .enumerate()
        .map(|(index, sample)| {
            let key = format!("accounting-{index}");
            io.attach(&key, sample.stdout())?;
            Ok(key)
        })
        .collect::<Result<Vec<_>, RoundError>>();
    let completion = if complete && end_digest.is_ok() && accounting_keys.is_ok() {
        Completion::Complete
    } else {
        Completion::Interrupted
    };
    let capture = io.finalize(completion)?;
    let accounting_keys = accounting_keys?;
    let end_digest = end_digest?;
    Ok(CaptureEnd {
        capture,
        accounting_keys,
        end_digest,
    })
}

fn observation_artifact(
    capture: &Finalized,
    key: &str,
    expected: &Sha256Digest,
) -> Result<Artifact, RoundError> {
    let original = capture
        .original_artifacts
        .iter()
        .find(|original| original.attachment.key == key)
        .ok_or(RoundError::CaptureMismatch)?;
    if &original.artifact.digest != expected || &original.attachment.digest != expected {
        return Err(RoundError::CaptureMismatch);
    }
    Ok(original.artifact.clone())
}

struct VerificationAuthority {
    origin: TargetOrigin,
    target_version: VersionRef,
    verifier: Verifier,
    custody: Custody,
    target_isolation: TargetIsolation,
    environment_kind: EnvironmentKind,
}

fn verification_material(
    authority: VerificationAuthority,
    started_at: Timestamp,
    finished_at: Timestamp,
    start: RetainedInstrumentObservation,
    end: RetainedInstrumentObservation,
) -> Result<VerificationMaterial, RoundError> {
    use time::{OffsetDateTime, format_description::well_known::Rfc3339};
    let parse = |timestamp: &Timestamp| {
        OffsetDateTime::parse(timestamp.as_str(), &Rfc3339).map_err(|_| RoundError::Wire)
    };
    if parse(&finished_at)? < parse(&started_at)? {
        return Err(RoundError::ClockDiscontinuity);
    }
    let enforcement = match start.observation.enforcement {
        EnforcementStatus::EgressEnforced => Enforcement::EgressEnforced,
        EnforcementStatus::Unenforced => Enforcement::Unenforced,
    };
    Ok(VerificationMaterial {
        start,
        end,
        started_at,
        finished_at,
        verifier: authority.verifier,
        target: Target {
            origin: authority.origin.0,
            addresses: Vec::new(),
            tls_identity: None,
            deployment_marker: None,
            strength: Strength::OperatorAsserted,
        },
        target_version: authority.target_version,
        custody: authority.custody,
        target_isolation: authority.target_isolation,
        environment_kind: authority.environment_kind,
        enforcement,
    })
}

fn running_verifier() -> std::io::Result<Verifier> {
    #[cfg(target_os = "linux")]
    let executable = std::path::Path::new("/proc/self/exe");
    #[cfg(not(target_os = "linux"))]
    let executable = std::env::current_exe()?;
    Ok(Verifier {
        version: env!("CARGO_PKG_VERSION").parse().expect("package version"),
        commit: None,
        binary_digest: Sha256Digest::of_reader(std::fs::File::open(executable)?)?,
    })
}

fn retain_accounting_artifacts(
    accounting: &mut AccountingObservation,
    capture: &Finalized,
    keys: &[String],
) -> Result<(), RoundError> {
    let originals = capture
        .original_artifacts
        .iter()
        .map(|original| (original.attachment.key.as_str(), original.artifact.clone()))
        .collect::<BTreeMap<_, _>>();
    let mut replacements = Vec::new();
    for (native, key) in accounting.evidence().artifacts().iter().zip(keys) {
        let retained = originals
            .get(key.as_str())
            .ok_or(RoundError::CaptureMismatch)?;
        if retained.digest != native.reference().digest {
            return Err(RoundError::CaptureMismatch);
        }
        replacements.push((
            native.reference().artifact_id.as_str().to_owned(),
            retained.clone(),
        ));
    }
    accounting
        .retain_artifacts(&replacements)
        .map_err(|()| RoundError::CaptureMismatch)
}

fn refresh_round_originals(
    rounds: &mut [AcquiredRound],
    state: &AcquisitionState,
) -> Result<(), RoundError> {
    let mut originals = BTreeMap::new();
    for flow in state.steps.values().flat_map(|step| &step.flows) {
        let Some(id) = flow.flow_id else {
            continue;
        };
        let original = flow.original.clone().ok_or(RoundError::CaptureMismatch)?;
        if originals
            .insert((flow.step.clone(), id), original)
            .is_some()
        {
            return Err(RoundError::CaptureMismatch);
        }
    }
    for flow in rounds.iter_mut().flat_map(|round| &mut round.flows) {
        let Some(id) = flow.reference.flow_id else {
            if flow.reference.original.is_some() {
                return Err(RoundError::CaptureMismatch);
            }
            continue;
        };
        flow.reference.original = Some(
            originals
                .get(&(flow.reference.step.clone(), id))
                .cloned()
                .ok_or(RoundError::CaptureMismatch)?,
        );
    }
    Ok(())
}

fn refresh_round_cleanup(
    store: &Store,
    run: &RunId,
    rounds: &mut [AcquiredRound],
) -> Result<(), RoundError> {
    let linked_cleanup = store.recover_cleanup(run)?;
    for round in rounds {
        round.cleanup = linked_cleanup
            .iter()
            .filter(|cleanup| cleanup.round == round.number)
            .cloned()
            .collect();
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn acquire_rounds<E: Entropy, I: RoundIo>(
    store: &mut ExecutionStore<'_>,
    run: &RunId,
    operations: &RegisteredOperations,
    origin: &TargetOrigin,
    round_count: u64,
    mint: &mut CanaryMint<E>,
    io: &mut I,
    state: &mut AcquisitionState,
) -> Result<Vec<AcquiredRound>, RoundError> {
    let collection = origin.join(operations.collection)?;
    let identity = origin.join(IDENTITY_PATH)?;
    let mut rounds = Vec::new();
    for round in 1..=round_count {
        let primary = plant_canaries(&operations.fields, mint)?;
        let control = plant_canaries(&operations.fields, mint)?;
        let mut acquired = AcquiredRound {
            number: round,
            primary: primary.clone(),
            control: control.clone(),
            flows: Vec::new(),
            identities: Vec::new(),
            cleanup: Vec::new(),
        };

        let i1 = execute_step(
            store,
            run,
            operations,
            round,
            RoundFlow::I1,
            vec![RequestAction::send(
                Method::Get,
                identity.clone(),
                operations.owner_session.clone(),
            )],
            io,
            state,
        )?;
        record_identity(&mut acquired, RoundFlow::I1, &i1.flows);
        acquired.flows.extend(i1.flows);

        let i2 = execute_step(
            store,
            run,
            operations,
            round,
            RoundFlow::I2,
            vec![RequestAction::send(
                Method::Get,
                identity.clone(),
                operations.other_session.clone(),
            )],
            io,
            state,
        )?;
        record_identity(&mut acquired, RoundFlow::I2, &i2.flows);
        acquired.flows.extend(i2.flows);

        let mut primary_id = None;
        let mut control_id = None;
        let acquisition: Result<(), RoundError> = (|| {
            let (id, flows) = plant_object(
                store,
                run,
                operations,
                round,
                RoundFlow::P,
                CleanupObjectRole::Primary,
                RequestAction::plant(
                    collection.clone(),
                    operations.owner_session.clone(),
                    &primary,
                )?,
                io,
                state,
            )?;
            primary_id = Some(id);
            acquired.flows.extend(flows);

            let (id, flows) = plant_object(
                store,
                run,
                operations,
                round,
                RoundFlow::P2,
                CleanupObjectRole::Control,
                RequestAction::plant(
                    collection.clone(),
                    operations.owner_session.clone(),
                    &control,
                )?,
                io,
                state,
            )?;
            control_id = Some(id);
            acquired.flows.extend(flows);

            let primary_url = object_url(
                origin,
                operations.collection,
                primary_id
                    .as_deref()
                    .ok_or(RoundError::ObjectNotEstablished)?,
            )?;
            let control_url = object_url(
                origin,
                operations.collection,
                control_id
                    .as_deref()
                    .ok_or(RoundError::ObjectNotEstablished)?,
            )?;
            for (contract, session, url) in [
                (
                    RoundFlow::F0,
                    operations.anonymous_session.clone(),
                    primary_url.clone(),
                ),
                (
                    RoundFlow::F1,
                    operations.owner_session.clone(),
                    primary_url.clone(),
                ),
                (
                    RoundFlow::F2,
                    operations.other_session.clone(),
                    primary_url.clone(),
                ),
                (
                    RoundFlow::F3,
                    operations.anonymous_session.clone(),
                    primary_url.clone(),
                ),
                (
                    RoundFlow::F4,
                    operations.other_session.clone(),
                    control_url.clone(),
                ),
            ] {
                acquired.flows.extend(
                    execute_step(
                        store,
                        run,
                        operations,
                        round,
                        contract,
                        vec![RequestAction::send(Method::Get, url, session)],
                        io,
                        state,
                    )?
                    .flows,
                );
            }

            let i3 = execute_step(
                store,
                run,
                operations,
                round,
                RoundFlow::I3,
                vec![RequestAction::send(
                    Method::Get,
                    identity.clone(),
                    operations.owner_session.clone(),
                )],
                io,
                state,
            )?;
            record_identity(&mut acquired, RoundFlow::I3, &i3.flows);
            acquired.flows.extend(i3.flows);

            let i4 = execute_step(
                store,
                run,
                operations,
                round,
                RoundFlow::I4,
                vec![RequestAction::send(
                    Method::Get,
                    identity.clone(),
                    operations.other_session.clone(),
                )],
                io,
                state,
            )?;
            record_identity(&mut acquired, RoundFlow::I4, &i4.flows);
            acquired.flows.extend(i4.flows);
            Ok(())
        })();

        let cleanup = cleanup_objects(
            store,
            run,
            operations,
            round,
            origin,
            primary_id.as_deref(),
            control_id.as_deref(),
            io,
            state,
        )?;
        acquired.flows.extend(cleanup.flows);
        acquired.cleanup = store
            .recover_cleanup(run)?
            .into_iter()
            .filter(|cleanup| cleanup.round == round)
            .collect();
        acquisition?;
        rounds.push(acquired);
    }
    Ok(rounds)
}

#[allow(clippy::too_many_arguments)]
fn plant_object<I: RoundIo>(
    store: &mut ExecutionStore<'_>,
    run: &RunId,
    operations: &RegisteredOperations,
    round: u64,
    contract: RoundFlow,
    object: CleanupObjectRole,
    action: RequestAction,
    io: &mut I,
    state: &mut AcquisitionState,
) -> Result<(String, Vec<AcquiredFlow>), RoundError> {
    let actions = vec![action];
    let (plant_step, plant_request_digest) = step_identity(operations, round, contract, &actions)?;
    let mut cleanup = RunCleanup {
        round,
        object,
        plant_step,
        plant_request_digest,
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
    store.record_cleanup(run, &cleanup)?;
    let execution = match execute_step(store, run, operations, round, contract, actions, io, state)
    {
        Ok(execution) => execution,
        Err(error) => {
            if state.steps.contains_key(&plant_step) {
                cleanup.ownership = CleanupOwnership::Unknown;
            } else {
                cleanup.ownership = CleanupOwnership::NotCreated;
                cleanup.outcome = CleanupObjectOutcome::NotRequired;
            }
            store.record_cleanup(run, &cleanup)?;
            return Err(error);
        }
    };
    let action = execution.actions.first().ok_or(RoundError::Wire)?;
    let id = object_id(&execution.flows);
    match id {
        Ok(id)
            if action.effect == Effect::Observed
                && action.status.is_some_and(|status| status == 201)
                && valid_object_id(&id) =>
        {
            cleanup.object_id = Some(id.clone().try_into().map_err(|_| RoundError::Wire)?);
            cleanup.ownership = CleanupOwnership::Established;
            store.record_cleanup(run, &cleanup)?;
            Ok((id, execution.flows))
        }
        _ => {
            if action.effect == Effect::None {
                cleanup.ownership = CleanupOwnership::NotCreated;
                cleanup.outcome = CleanupObjectOutcome::NotRequired;
            } else {
                cleanup.ownership = CleanupOwnership::Unknown;
            }
            store.record_cleanup(run, &cleanup)?;
            Err(RoundError::ObjectNotEstablished)
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn cleanup_objects<I: RoundIo>(
    store: &mut ExecutionStore<'_>,
    run: &RunId,
    operations: &RegisteredOperations,
    round: u64,
    origin: &TargetOrigin,
    primary: Option<&str>,
    control: Option<&str>,
    io: &mut I,
    state: &mut AcquisitionState,
) -> Result<StepExecution, RoundError> {
    // A round with either uncertain plant response sends no DELETE at all.
    // Any sibling whose creation was established remains explicitly owed.
    if primary.is_none() || control.is_none() {
        return Ok(StepExecution {
            flows: Vec::new(),
            actions: Vec::new(),
        });
    }
    let eligible = [
        (CleanupObjectRole::Primary, primary),
        (CleanupObjectRole::Control, control),
    ]
    .into_iter()
    .filter_map(|(object, id)| id.map(|id| (object, id)))
    .collect::<Vec<_>>();
    if eligible.is_empty() {
        return Ok(StepExecution {
            flows: Vec::new(),
            actions: Vec::new(),
        });
    }
    let actions = eligible
        .iter()
        .map(|(object, id)| {
            Ok(RequestAction::cleanup(
                object_url(origin, operations.collection, id)?,
                operations.owner_session.clone(),
                *object,
            ))
        })
        .collect::<Result<Vec<_>, RoundError>>()?;
    let (cleanup_step, _) = step_identity(operations, round, RoundFlow::C, &actions)?;
    // The RunStep below binds the frozen batch and order. Each object also
    // binds its own one-action request so recovery never has to infer which
    // DELETE crossed a dispatch boundary.
    for ((object, _), action) in eligible.iter().zip(&actions) {
        let (_, cleanup_request_digest) = step_identity(
            operations,
            round,
            RoundFlow::C,
            std::slice::from_ref(action),
        )?;
        let mut cleanup = store
            .recover_cleanup(run)?
            .into_iter()
            .find(|item| item.round == round && item.object == *object)
            .ok_or(RoundError::Store(StoreError::SelectorNotFound))?;
        cleanup.cleanup_step = Some(cleanup_step);
        cleanup.cleanup_request_digest = Some(cleanup_request_digest);
        store.record_cleanup(run, &cleanup)?;
    }
    match execute_step(
        store,
        run,
        operations,
        round,
        RoundFlow::C,
        actions,
        io,
        state,
    ) {
        Ok(execution) => Ok(execution),
        Err(RoundError::Passive(_)) if !state.steps.contains_key(&cleanup_step) => {
            Ok(StepExecution {
                flows: Vec::new(),
                actions: Vec::new(),
            })
        }
        Err(error) => Err(error),
    }
}

fn cleanup_record(
    store: &Store,
    run: &RunId,
    round: u64,
    object: CleanupObjectRole,
) -> Result<RunCleanup, RoundError> {
    store
        .recover_cleanup(run)?
        .into_iter()
        .find(|item| item.round == round && item.object == object)
        .ok_or(RoundError::Store(StoreError::SelectorNotFound))
}

fn begin_cleanup_action(
    store: &mut ExecutionStore<'_>,
    run: &RunId,
    round: u64,
    object: CleanupObjectRole,
    floor: Option<u64>,
) -> Result<(), RoundError> {
    let mut cleanup = cleanup_record(store, run, round, object)?;
    cleanup.flow_id_floor = floor;
    cleanup.effects = None;
    cleanup.outcome = CleanupObjectOutcome::InFlight;
    store.record_cleanup(run, &cleanup)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn update_cleanup_action(
    store: &mut ExecutionStore<'_>,
    run: &RunId,
    round: u64,
    object: CleanupObjectRole,
    reference: WireText,
    effect: Effect,
    status: Option<u16>,
    flows: &[AcquiredFlow],
    outcome: CleanupObjectOutcome,
) -> Result<(), RoundError> {
    let mut cleanup = cleanup_record(store, run, round, object)?;
    cleanup.instrument_reference = Some(reference);
    cleanup.effects = Some(effect);
    cleanup.response_status = status;
    cleanup.flows = flows.iter().map(|flow| flow.reference.clone()).collect();
    cleanup.outcome = outcome;
    store.record_cleanup(run, &cleanup)?;
    Ok(())
}

fn cleanup_outcome(
    effect: Effect,
    status: Option<u16>,
    flows: &[AcquiredFlow],
) -> CleanupObjectOutcome {
    match (effect, status) {
        (Effect::Observed, Some(204))
            if terminal_flow(flows)
                .is_some_and(|flow| flow.reference.completeness == Completeness::Complete) =>
        {
            CleanupObjectOutcome::Complete
        }
        (Effect::Observed, Some(204)) => CleanupObjectOutcome::Unknown,
        (Effect::Observed, Some(status)) if (200..300).contains(&status) => {
            CleanupObjectOutcome::Unknown
        }
        (Effect::Observed, None) => CleanupObjectOutcome::Unknown,
        (Effect::Observed | Effect::None, _) => CleanupObjectOutcome::Failed,
        (Effect::Unknown, _) => CleanupObjectOutcome::Unknown,
    }
}

#[allow(clippy::too_many_arguments)]
fn execute_step<I: RoundIo>(
    store: &mut ExecutionStore<'_>,
    run: &RunId,
    operations: &RegisteredOperations,
    round: u64,
    contract: RoundFlow,
    actions: Vec<RequestAction>,
    io: &mut I,
    state: &mut AcquisitionState,
) -> Result<StepExecution, RoundError> {
    let dispatch = operations
        .dispatch_spec(contract.as_str())
        .ok_or(RoundError::AdmissionMismatch)?;
    let expected_session = operations.session(dispatch.principal).as_str();
    let valid_action_count = actions.len() as u64 == dispatch.actions
        || contract == RoundFlow::C && (1..=dispatch.actions).contains(&(actions.len() as u64));
    if !valid_action_count
        || actions
            .iter()
            .any(|action| action.kind != "send" || action.session != expected_session)
        || actions
            .iter()
            .any(|action| (contract == RoundFlow::C) != action.cleanup_object.is_some())
    {
        return Err(RoundError::AdmissionMismatch);
    }
    let (number, request_digest) = step_identity(operations, round, contract, &actions)?;
    let floor = io.flow_floor()?;
    let mut step = RunStep {
        number,
        step: format!("round.{round}.{}", contract.as_str())
            .try_into()
            .map_err(|_| RoundError::Wire)?,
        request_digest,
        flow_id_floor: floor,
        instrument_reference: None,
        effects: None,
        flows: Vec::new(),
    };
    // The durable recovery boundary. No call below this line may reach the
    // target until this transaction commits.
    store.record_step(run, &step)?;
    state.steps.insert(number, step.clone());

    let mut retained = HashSet::new();
    let mut acquired = Vec::new();
    let mut action_executions = Vec::new();
    let mut effect = Effect::None;
    let mut primary_reference = None;
    macro_rules! fail_step {
        ($error:expr, $object:expr) => {{
            return finish_failed_step(
                store,
                run,
                round,
                contract,
                $object,
                state,
                step,
                primary_reference,
                acquired,
                action_executions,
                $error,
            );
        }};
    }
    for action in &actions {
        let object = action.cleanup_object;
        if let Some(object) = object {
            begin_cleanup_action(store, run, round, object, floor)?;
        }
        let action_start = acquired.len();
        let receipt = match io.dispatch(action) {
            Ok(receipt) => receipt,
            Err(error) => fail_step!(error, object),
        };
        let action_effect = combine_effect(Effect::None, receipt.dispatch);
        let action_reference = match dispatch_reference(receipt.dispatch) {
            Ok(reference) => reference,
            Err(error) => fail_step!(error, object),
        };
        effect = combine_effect(effect, receipt.dispatch);
        if primary_reference.is_none() {
            primary_reference = Some(action_reference.clone());
        }
        if let Some(object) = object {
            update_cleanup_action(
                store,
                run,
                round,
                object,
                action_reference.clone(),
                action_effect,
                receipt.status,
                &[],
                CleanupObjectOutcome::InFlight,
            )?;
        }
        let terminal_response = receipt
            .flows
            .iter()
            .rposition(|flow| matches!(flow.role, FlowRole::Request | FlowRole::Retry));
        for (sent_index, sent) in receipt.flows.into_iter().enumerate() {
            let label = if contract == RoundFlow::C {
                let object = match action.cleanup_object {
                    Some(CleanupObjectRole::Primary) => "primary",
                    Some(CleanupObjectRole::Control) => "control",
                    None => fail_step!(RoundError::AdmissionMismatch, object),
                };
                format!("C.{object}.{}", flow_role(sent.role))
            } else {
                format!("{}.{}", contract.as_str(), flow_role(sent.role))
            };
            match sent.reference {
                FlowReference::Missing => {
                    state.sequence = match state.sequence.checked_add(1) {
                        Some(sequence) => sequence,
                        None => fail_step!(RoundError::Wire, object),
                    };
                    let reference = Flow {
                        step: match label.clone().try_into() {
                            Ok(label) => label,
                            Err(_) => fail_step!(RoundError::Wire, object),
                        },
                        flow_id: None,
                        original: None,
                        completeness: Completeness::Missing,
                        decoder: None,
                    };
                    step.flows.push(reference.clone());
                    acquired.push(AcquiredFlow {
                        contract,
                        sequence: state.sequence,
                        reference,
                        response_body: Vec::new(),
                        response_head: None,
                    });
                }
                FlowReference::Retained(id) => {
                    if floor.is_some_and(|floor| id <= floor) {
                        fail_step!(RoundError::FlowBeforeFloor, object);
                    }
                    if !retained.insert(id) {
                        fail_step!(RoundError::DuplicateFlow, object);
                    }
                    let readback = match io.read_flow(id) {
                        Ok(readback) => readback,
                        Err(error) => fail_step!(error, object),
                    };
                    if readback.id != id
                        || matches!(sent.role, FlowRole::Request | FlowRole::Retry)
                            && (readback.url.as_deref() != Some(action.url.as_str())
                                || readback.method.as_deref() != Some(action.method.as_str()))
                        || terminal_response == Some(sent_index)
                            && readback.status != receipt.status
                    {
                        fail_step!(RoundError::ReadbackMismatch, object);
                    }
                    let key = flow_original_key(round, number, flow_role(sent.role), id);
                    if let Err(error) = io.attach(&key, &readback.original) {
                        fail_step!(error, object);
                    }
                    state.sequence = match state.sequence.checked_add(1) {
                        Some(sequence) => sequence,
                        None => fail_step!(RoundError::Wire, object),
                    };
                    let reference = Flow {
                        step: match label.try_into() {
                            Ok(label) => label,
                            Err(_) => fail_step!(RoundError::Wire, object),
                        },
                        flow_id: Some(id),
                        original: None,
                        completeness: readback.completeness,
                        decoder: None,
                    };
                    let flow_index = step.flows.len();
                    step.flows.push(reference.clone());
                    state.pending.push(PendingOriginal {
                        step: number,
                        flow: flow_index,
                        key,
                    });
                    acquired.push(AcquiredFlow {
                        contract,
                        sequence: state.sequence,
                        reference,
                        response_body: readback.response_body,
                        response_head: readback.response_head,
                    });
                }
            }
        }
        let action_execution = ActionExecution {
            reference: action_reference,
            effect: action_effect,
            status: receipt.status,
            flows: acquired[action_start..].to_vec(),
        };
        // Persist this action's exact C flows before its terminal per-object
        // cleanup outcome. Recovery must never observe a completed removal
        // whose dispatch evidence is absent from the frozen batch step.
        if object.is_some() {
            store.record_step(run, &step)?;
            state.steps.insert(number, step.clone());
        }
        if let Some(object) = object {
            update_cleanup_action(
                store,
                run,
                round,
                object,
                action_execution.reference.clone(),
                action_execution.effect,
                action_execution.status,
                &action_execution.flows,
                cleanup_outcome(
                    action_execution.effect,
                    action_execution.status,
                    &action_execution.flows,
                ),
            )?;
        }
        action_executions.push(action_execution);
    }
    step.instrument_reference = primary_reference;
    step.effects = Some(effect);
    store.record_step(run, &step)?;
    state.steps.insert(number, step);
    Ok(StepExecution {
        flows: acquired,
        actions: action_executions,
    })
}

fn step_identity(
    operations: &RegisteredOperations,
    round: u64,
    contract: RoundFlow,
    actions: &[RequestAction],
) -> Result<(u64, Sha256Digest), RoundError> {
    let number = contract.step_number(round).ok_or(RoundError::Wire)?;
    let intent = RequestIntent {
        registry: REGISTRY_ID,
        registry_digest: &operations.registry_digest,
        round,
        flow: contract.as_str(),
        actions,
    };
    let request = serde_json::to_vec(&intent).map_err(|_| RoundError::Wire)?;
    Ok((number, Sha256Digest::of(&request)))
}

#[allow(clippy::too_many_arguments)]
fn finish_failed_step(
    store: &mut ExecutionStore<'_>,
    run: &RunId,
    round: u64,
    contract: RoundFlow,
    object: Option<CleanupObjectRole>,
    state: &mut AcquisitionState,
    mut step: RunStep,
    instrument_reference: Option<WireText>,
    acquired: Vec<AcquiredFlow>,
    actions: Vec<ActionExecution>,
    error: RoundError,
) -> Result<StepExecution, RoundError> {
    step.instrument_reference = instrument_reference;
    step.effects = Some(Effect::Unknown);
    store.record_step(run, &step)?;
    state.steps.insert(step.number, step.clone());
    if let Some(object) = object {
        let mut cleanup = cleanup_record(store, run, round, object)?;
        let prefix = match object {
            CleanupObjectRole::Primary => "C.primary.",
            CleanupObjectRole::Control => "C.control.",
        };
        cleanup.flows = step
            .flows
            .iter()
            .filter(|flow| flow.step.as_str().starts_with(prefix))
            .cloned()
            .collect();
        cleanup.effects = Some(match cleanup.effects {
            Some(Effect::Observed) => Effect::Observed,
            _ => Effect::Unknown,
        });
        cleanup.outcome = CleanupObjectOutcome::Unknown;
        store.record_cleanup(run, &cleanup)?;
    }
    if contract == RoundFlow::C {
        Ok(StepExecution {
            flows: acquired,
            actions,
        })
    } else {
        Err(error)
    }
}

fn combine_effect(current: Effect, dispatch: DispatchEvidence) -> Effect {
    match (current, dispatch) {
        (_, DispatchEvidence::NoFlow { .. }) => Effect::Unknown,
        (Effect::Unknown, _) => Effect::Unknown,
        (_, DispatchEvidence::Flow { .. }) => Effect::Observed,
        (effect, DispatchEvidence::NotSent { .. }) => effect,
    }
}

fn dispatch_reference(dispatch: DispatchEvidence) -> Result<WireText, RoundError> {
    let value = match dispatch {
        DispatchEvidence::Flow { flow } => format!("flow:{flow}"),
        DispatchEvidence::NoFlow { .. } => "sent:no-flow".to_owned(),
        DispatchEvidence::NotSent { .. } => "not-sent".to_owned(),
    };
    value.try_into().map_err(|_| RoundError::Wire)
}

pub(crate) fn flow_original_key(round: u64, step: u64, role: &str, id: u64) -> String {
    format!("r{round}-s{step}-{role}-{id}")
}

fn flow_role(role: FlowRole) -> &'static str {
    match role {
        FlowRole::Request => "request",
        FlowRole::Redirect => "redirect",
        FlowRole::Login => "login",
        FlowRole::Retry => "retry",
    }
}

fn plant_canaries<E: Entropy>(
    fields: &[FieldSpec],
    mint: &mut CanaryMint<E>,
) -> Result<Vec<PlantedCanary>, RoundError> {
    fields
        .iter()
        .map(|field| {
            Ok(PlantedCanary {
                field: field
                    .json_name
                    .to_owned()
                    .try_into()
                    .map_err(|_| RoundError::Wire)?,
                canary: mint.mint()?,
            })
        })
        .collect()
}

fn object_url(origin: &TargetOrigin, collection: &str, id: &str) -> Result<WireText, RoundError> {
    if !valid_object_id(id) {
        return Err(RoundError::ObjectNotEstablished);
    }
    origin.join(&format!("{collection}/{id}"))
}

fn valid_object_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 256
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn terminal_flow(flows: &[AcquiredFlow]) -> Option<&AcquiredFlow> {
    flows.last().filter(|flow| {
        matches!(
            flow.reference.step.as_str().rsplit('.').next(),
            Some("request" | "retry")
        )
    })
}

fn complete_body(flows: &[AcquiredFlow]) -> Option<&[u8]> {
    terminal_flow(flows)
        .filter(|flow| flow.reference.completeness == Completeness::Complete)
        .map(|flow| flow.response_body.as_slice())
}

fn object_id(flows: &[AcquiredFlow]) -> Result<String, RoundError> {
    struct ObjectIdReply {
        id: String,
    }

    impl<'de> Deserialize<'de> for ObjectIdReply {
        fn deserialize<D>(decoder: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Fields {
                id: String,
            }

            let Fields { id } = crate::wire::deserialize_object(decoder)?;
            Ok(Self { id })
        }
    }

    let body = complete_body(flows).ok_or(RoundError::ObjectNotEstablished)?;
    crate::wire::from_slice::<ObjectIdReply>(body)
        .ok()
        .map(|reply| reply.id)
        .ok_or(RoundError::ObjectNotEstablished)
}

fn record_identity(round: &mut AcquiredRound, contract: RoundFlow, flows: &[AcquiredFlow]) {
    let subject_digest = complete_body(flows)
        .and_then(|body| serde_json::from_slice::<serde_json::Value>(body).ok())
        .and_then(|value| {
            value
                .get(IDENTITY_SUBJECT_FIELD)
                .and_then(|id| id.as_str())
                .map(|subject| Sha256Digest::of(subject.as_bytes()))
        });
    round.identities.push(AcquiredIdentity {
        contract,
        subject_digest,
    });
}

fn link_originals(
    store: &mut ExecutionStore<'_>,
    run: &RunId,
    state: &mut AcquisitionState,
    finalized: &Finalized,
    additional_originals: usize,
) -> Result<(), RoundError> {
    let originals = finalized
        .original_artifacts
        .iter()
        .map(|original| (original.attachment.key.as_str(), original.artifact.clone()))
        .collect::<BTreeMap<_, _>>();
    if originals.len()
        != state
            .pending
            .len()
            .checked_add(additional_originals)
            .ok_or(RoundError::CaptureMismatch)?
    {
        return Err(RoundError::CaptureMismatch);
    }
    for pending in &state.pending {
        let artifact = originals
            .get(pending.key.as_str())
            .ok_or(RoundError::CaptureMismatch)?;
        let step = state
            .steps
            .get_mut(&pending.step)
            .ok_or(RoundError::CaptureMismatch)?;
        step.flows
            .get_mut(pending.flow)
            .ok_or(RoundError::CaptureMismatch)?
            .original = Some(Artifact {
            artifact_id: artifact.artifact_id.clone(),
            digest: artifact.digest.clone(),
        });
    }
    for step in state.steps.values() {
        store.link_step_originals(run, step)?;
    }
    for mut cleanup in store.recover_cleanup(run)? {
        let Some(step_number) = cleanup.cleanup_step else {
            continue;
        };
        if cleanup.flows.is_empty() {
            continue;
        }
        let step = state
            .steps
            .get(&step_number)
            .ok_or(RoundError::CaptureMismatch)?;
        for flow in &mut cleanup.flows {
            let linked = step
                .flows
                .iter()
                .find(|candidate| candidate.step == flow.step && candidate.flow_id == flow.flow_id)
                .ok_or(RoundError::CaptureMismatch)?;
            flow.original = linked.original.clone();
        }
        store.link_cleanup_originals(run, &cleanup)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::{
        collections::{BTreeMap, BTreeSet},
        fs,
        io::{BufRead, BufReader, Write},
        net::TcpListener,
        path::{Path, PathBuf},
        process::{Command, Output, Stdio},
        str::FromStr,
        thread,
    };

    use super::*;
    use crate::{
        domain::Run,
        engagement::{EngagementDraft, PassPin, PassRef},
        evidence::{Attachment, Original},
        ids::{ArtifactId, EngagementId, LeadId},
        teapot::{BoundEngine, Environment, ExecutableKind},
        template::{Claim, ClaimClass, EngagementPin, SlotName, SlotValue, Templates},
        wire::AbsolutePath,
    };

    const ENGAGEMENT: &[u8] =
        include_bytes!("../../../fixtures/target/schema-examples/engagement.toml");

    fn fixture() -> (ManifestRevision, crate::template::FrozenExperiment) {
        let pass: PassRef = "pass.development-fixture".parse().unwrap();
        let digest = Sha256Digest::of(b"fixture pass");
        let manifest = EngagementDraft::parse_toml(ENGAGEMENT)
            .unwrap()
            .accept(PassPin {
                reference: &pass,
                digest: &digest,
            })
            .unwrap();
        let slot = |name: &str, value: &str| SlotValue {
            name: SlotName::from_str(name).unwrap(),
            value: WireText::try_from(value.to_owned()).unwrap(),
        };
        let claim = Claim {
            class: ClaimClass::from_str("web-authz/private-object-read").unwrap(),
            engagement: EngagementPin {
                revision: manifest.revision(),
                digest: manifest.digest().clone(),
            },
            lead: LeadId::from_str("L-rounds").unwrap(),
            property: Some("orders".parse().unwrap()),
            lead_slots: vec![slot("owner", "alice"), slot("other", "bob")],
            overrides: Vec::new(),
        };
        let experiment = Templates::resolve(&claim, &manifest)
            .unwrap()
            .ready()
            .unwrap();
        (manifest, experiment)
    }

    struct CounterEntropy {
        next: u128,
    }

    impl Entropy for CounterEntropy {
        fn fill(&mut self, bytes: &mut [u8; 16]) -> Result<(), RoundError> {
            *bytes = self.next.to_be_bytes();
            self.next = self.next.checked_add(1).ok_or(RoundError::Random)?;
            Ok(())
        }
    }

    #[test]
    fn deterministic_large_canary_sample_is_unique_lowercase_hex_across_runs() {
        let mut all = BTreeSet::new();
        for base in [0_u128, 50_000] {
            let mut mint = CanaryMint::new(CounterEntropy { next: base });
            for _round in 0..100 {
                for _object in 0..2 {
                    for _field in 0..250 {
                        let canary = mint.mint().unwrap();
                        assert_eq!(canary.as_str().len(), 32);
                        assert!(
                            canary.as_str().bytes().all(|byte| {
                                byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')
                            })
                        );
                        assert!(all.insert(canary.as_str().to_owned()));
                    }
                }
            }
        }
        assert_eq!(all.len(), 100_000);
    }

    #[test]
    fn acquired_round_originals_are_hydrated_from_the_finalized_step_capture() {
        let artifact = Artifact {
            artifact_id: "art_finalized_flow".parse().unwrap(),
            digest: Sha256Digest::of(b"finalized flow"),
        };
        let stored = Flow {
            step: "F2.request".parse().unwrap(),
            flow_id: Some(42),
            original: Some(artifact.clone()),
            completeness: Completeness::Complete,
            decoder: None,
        };
        let mut rounds = vec![AcquiredRound {
            number: 1,
            primary: Vec::new(),
            control: Vec::new(),
            flows: vec![AcquiredFlow {
                contract: RoundFlow::F2,
                sequence: 1,
                reference: Flow {
                    original: None,
                    ..stored.clone()
                },
                response_body: b"finalized flow".to_vec(),
                response_head: None,
            }],
            identities: Vec::new(),
            cleanup: Vec::new(),
        }];
        let state = AcquisitionState {
            steps: BTreeMap::from([(
                1,
                RunStep {
                    number: 1,
                    step: "F2".parse().unwrap(),
                    request_digest: Sha256Digest::of(b"request"),
                    flow_id_floor: Some(41),
                    instrument_reference: None,
                    effects: Some(Effect::Observed),
                    flows: vec![stored.clone()],
                },
            )]),
            pending: Vec::new(),
            sequence: 1,
        };

        refresh_round_originals(&mut rounds, &state).unwrap();
        assert_eq!(rounds[0].flows[0].reference.original, Some(artifact));

        let mut missing = rounds.clone();
        missing[0].flows[0].reference.original = None;
        assert!(refresh_round_originals(&mut missing, &AcquisitionState::default()).is_err());

        let mut duplicate_state = state;
        duplicate_state.steps.insert(
            2,
            RunStep {
                number: 2,
                step: "F2-duplicate".parse().unwrap(),
                request_digest: Sha256Digest::of(b"request duplicate"),
                flow_id_floor: Some(41),
                instrument_reference: None,
                effects: Some(Effect::Observed),
                flows: vec![stored],
            },
        );
        assert!(refresh_round_originals(&mut rounds, &duplicate_state).is_err());
    }

    #[test]
    fn missing_identity_subject_is_retained_for_oracle_session_drift_evaluation() {
        let flow = AcquiredFlow {
            contract: RoundFlow::I3,
            sequence: 1,
            reference: Flow {
                step: "I3.request".parse().unwrap(),
                flow_id: Some(42),
                original: Some(Artifact {
                    artifact_id: "art_missing_identity".parse().unwrap(),
                    digest: Sha256Digest::of(b"missing identity"),
                }),
                completeness: Completeness::Complete,
                decoder: None,
            },
            response_body: br#"{"error":"authentication_required"}"#.to_vec(),
            response_head: None,
        };
        let mut round = AcquiredRound {
            number: 1,
            primary: Vec::new(),
            control: Vec::new(),
            flows: Vec::new(),
            identities: Vec::new(),
            cleanup: Vec::new(),
        };

        record_identity(&mut round, RoundFlow::I3, &[flow]);

        assert_eq!(
            round.identities,
            vec![AcquiredIdentity {
                contract: RoundFlow::I3,
                subject_digest: None,
            }]
        );
    }

    #[derive(Default)]
    struct FakeIo {
        highest: u64,
        floor_calls: usize,
        fail_floor_at: Option<usize>,
        requests: Vec<RequestAction>,
        reads: BTreeMap<u64, Readback>,
        attached: Vec<(String, Vec<u8>)>,
        objects: BTreeMap<String, BTreeMap<String, String>>,
        next_object: u64,
        drop_plant: Option<u64>,
        plant_statuses: Vec<u16>,
        plant_existing: Option<String>,
        plant_response: Option<Vec<u8>>,
        plant_readback_status: Option<u16>,
        delete_statuses: Vec<u16>,
        delete_readback_status: Option<u16>,
        delete_statusless: Option<usize>,
        delete_not_sent: Option<crate::teapot::NotSentReason>,
        delete_native_refusal: Option<&'static str>,
        partial_delete: Option<usize>,
        drop_delete: Option<usize>,
        deletes: usize,
    }

    impl FakeIo {
        fn response(&mut self, action: &RequestAction) -> Vec<u8> {
            if action.method == Method::Post {
                self.next_object += 1;
                if let Some(id) = self.plant_existing.take() {
                    return serde_json::to_vec(&serde_json::json!({"id": id})).unwrap();
                }
                let id = format!("object-{}", self.next_object);
                let fields: BTreeMap<String, String> =
                    serde_json::from_str(action.body.as_deref().unwrap()).unwrap();
                self.objects.insert(id.clone(), fields);
                if let Some(response) = self.plant_response.take() {
                    return response;
                }
                return serde_json::to_vec(&serde_json::json!({"id": id})).unwrap();
            }
            if action.url.ends_with("/app/api/me") {
                let id = if action.session.contains("bob") {
                    "user-bob-verify"
                } else {
                    "user-alice-verify"
                };
                return serde_json::to_vec(&serde_json::json!({"id": id})).unwrap();
            }
            if action.method == Method::Get {
                let id = action.url.rsplit('/').next().unwrap();
                return serde_json::to_vec(self.objects.get(id).unwrap()).unwrap();
            }
            Vec::new()
        }
    }

    impl RoundIo for FakeIo {
        fn flow_floor(&mut self) -> Result<Option<u64>, RoundError> {
            self.floor_calls += 1;
            if self.fail_floor_at == Some(self.floor_calls) {
                return Err(RoundError::Passive(PassiveError::Unavailable));
            }
            Ok((self.highest > 0).then_some(self.highest))
        }

        fn dispatch(&mut self, action: &RequestAction) -> Result<DispatchReceipt, RoundError> {
            if action.method == Method::Delete {
                self.deletes += 1;
                if self.drop_delete == Some(self.deletes) {
                    let object = action.url.rsplit('/').next().unwrap();
                    self.objects.remove(object);
                    self.requests.push(action.clone());
                    return Err(RoundError::ReadbackMismatch);
                }
                if let Some(reason) = self.delete_native_refusal {
                    return Err(RoundError::Instrument(
                        InvocationError::DependencyUnavailable {
                            diagnostic: crate::wire::Diagnostic {
                                code: crate::wire::DiagnosticCode::NativeFailure,
                                message: "native request refusal".parse().unwrap(),
                                native_exit: Some(4),
                                stage: "send".parse().unwrap(),
                                wrapper_exit: None,
                            },
                            native_reason: Some(reason.parse().unwrap()),
                            transport_failure: None,
                        },
                    ));
                }
                if let Some(reason) = self.delete_not_sent {
                    self.requests.push(action.clone());
                    return Ok(DispatchReceipt {
                        dispatch: DispatchEvidence::NotSent { reason },
                        flows: Vec::new(),
                        status: None,
                    });
                }
            }
            self.highest += 1;
            let id = self.highest;
            let response = self.response(action);
            if action.method == Method::Post && self.drop_plant == Some(self.next_object) {
                self.requests.push(action.clone());
                return Ok(DispatchReceipt {
                    dispatch: DispatchEvidence::NoFlow {
                        outcome: crate::teapot::SendOutcome::Unknown,
                    },
                    flows: vec![StepFlow {
                        step: 1,
                        role: FlowRole::Request,
                        reference: FlowReference::Missing,
                    }],
                    status: None,
                });
            }
            let status = if action.method == Method::Delete {
                self.delete_statuses
                    .get(self.deletes - 1)
                    .copied()
                    .unwrap_or(204)
            } else if action.method == Method::Post {
                self.plant_statuses
                    .get(self.next_object as usize - 1)
                    .copied()
                    .unwrap_or(201)
            } else {
                200
            };
            let statusless =
                action.method == Method::Delete && self.delete_statusless == Some(self.deletes);
            if action.method == Method::Delete && status == 204 {
                let object = action.url.rsplit('/').next().unwrap();
                self.objects.remove(object);
            }
            self.reads.insert(
                id,
                Readback {
                    id,
                    url: Some(action.url.clone()),
                    method: Some(action.method.as_str().to_owned()),
                    status: (!statusless).then(|| {
                        if action.method == Method::Post {
                            self.plant_readback_status.unwrap_or(status)
                        } else if action.method == Method::Delete {
                            self.delete_readback_status.unwrap_or(status)
                        } else {
                            status
                        }
                    }),
                    response_body: response,
                    response_head: None,
                    completeness: if action.method == Method::Delete
                        && self.partial_delete == Some(self.deletes)
                    {
                        Completeness::Partial
                    } else {
                        Completeness::Complete
                    },
                    original: format!("exact-flow-{id}\n").into_bytes(),
                },
            );
            self.requests.push(action.clone());
            Ok(DispatchReceipt {
                dispatch: DispatchEvidence::Flow { flow: id },
                flows: vec![StepFlow {
                    step: 1,
                    role: FlowRole::Request,
                    reference: FlowReference::Retained(id),
                }],
                status: (!statusless).then_some(status),
            })
        }

        fn read_flow(&mut self, id: u64) -> Result<Readback, RoundError> {
            self.reads.remove(&id).ok_or(RoundError::ReadbackMismatch)
        }

        fn attach(&mut self, key: &str, bytes: &[u8]) -> Result<(), RoundError> {
            self.attached.push((key.to_owned(), bytes.to_vec()));
            Ok(())
        }

        fn finalize(&mut self, completion: Completion) -> Result<Finalized, RoundError> {
            Ok(finalize_attached(&self.attached, completion))
        }
    }

    fn finalize_attached(attached: &[(String, Vec<u8>)], completion: Completion) -> Finalized {
        let originals = attached
            .iter()
            .enumerate()
            .map(|(index, (key, bytes))| {
                let position = index as u64 + 1;
                let digest = Sha256Digest::of(bytes);
                Original {
                    attachment: Attachment {
                        key: key.clone(),
                        position,
                        digest: digest.clone(),
                        size_bytes: bytes.len(),
                        request_digest: Sha256Digest::of(key.as_bytes()),
                        accepted_at: "2026-11-24T00:00:00Z".to_owned(),
                    },
                    artifact: Artifact {
                        artifact_id: ArtifactId::try_from(format!("art_round_{position}")).unwrap(),
                        digest,
                    },
                }
            })
            .collect();
        Finalized {
            complete: completion == Completion::Complete,
            original_artifacts: originals,
            manifest_digest: Sha256Digest::of(b"manifest"),
            missing_positions: Vec::new(),
            transaction_id: "tx-round".to_owned(),
        }
    }

    fn gate_observation() -> InstrumentObservation {
        InstrumentObservation {
            identity: crate::wire::Instrument {
                name: "teapot".parse().unwrap(),
                version: "0.1.0".parse().unwrap(),
                commit: None,
                binary_digest: None,
                engine_instance: "bound-instance".parse().unwrap(),
                project_id: "bound-project".parse().unwrap(),
                protocol: 1,
            },
            enforcement: EnforcementStatus::Unenforced,
            policy_locked: true,
            edit_surface: crate::teapot::EditSurface::default(),
            calls: Vec::new(),
            pass: None,
        }
    }

    #[test]
    fn ending_instrument_binding_rejects_pass_substitution() {
        let digest = Sha256Digest::of(b"admitted pass");
        let start = InstrumentObservation::verification_fixture(
            "pass-admitted".parse().unwrap(),
            digest.clone(),
            "/tmp/admitted.pass".parse().unwrap(),
        );
        let matching = InstrumentObservation::verification_fixture(
            "pass-admitted".parse().unwrap(),
            digest.clone(),
            "/tmp/admitted.pass".parse().unwrap(),
        );
        assert!(same_instrument_binding(&start, &matching));

        let substituted = InstrumentObservation::verification_fixture(
            "pass-substituted".parse().unwrap(),
            digest,
            "/tmp/admitted.pass".parse().unwrap(),
        );
        assert!(!same_instrument_binding(&start, &substituted));
    }

    #[test]
    fn capture_keeps_both_passive_edges_with_exact_originals() {
        let mut io = FakeIo::default();
        let start = gate_observation();
        let mut end = gate_observation();
        end.edit_surface
            .readings
            .push(crate::teapot::EditSurfaceReading {
                operation: crate::teapot::GateOperation::ConfigList,
                session: None,
                result_sha256: Some(Sha256Digest::of(b"[]")),
                report: Some(crate::teapot::EditSurfaceReport::Config { settings: 0 }),
            });
        let started_at = "2026-11-25T07:00:00Z".parse().unwrap();
        let finished_at = "2026-11-25T07:00:00.5Z".parse().unwrap();
        let start_digest =
            attach_gate_observation(&mut io, START_OBSERVATION, &started_at, Ok(&start)).unwrap();
        io.attach("r1-s1-request-1", b"fake flow").unwrap();
        let retained = finish_capture(&mut io, &[], Ok(&end), &finished_at, true).unwrap();
        assert!(retained.capture.complete);
        assert_eq!(
            io.attached
                .iter()
                .map(|(key, _)| key.as_str())
                .collect::<Vec<_>>(),
            [START_OBSERVATION, "r1-s1-request-1", END_OBSERVATION]
        );
        let start_artifact =
            observation_artifact(&retained.capture, START_OBSERVATION, &start_digest).unwrap();
        let end_artifact =
            observation_artifact(&retained.capture, END_OBSERVATION, &retained.end_digest).unwrap();
        assert_ne!(start_artifact, end_artifact);
        assert!(matches!(
            observation_artifact(&retained.capture, END_OBSERVATION, &start_digest),
            Err(RoundError::CaptureMismatch)
        ));
        let end_bytes = canonical::parse(&io.attached[2].1).unwrap();
        assert_eq!(end_bytes["timestamp"], finished_at.as_str());
        assert_eq!(
            end_bytes["observation"]["admitted"]["identity"]["version"],
            "0.1.0"
        );
        assert_eq!(
            end_bytes["observation"]["admitted"]["edit_surface"]["readings"][0]["operation"],
            "config_list"
        );

        let (manifest, _) = fixture();
        let origin: TargetOrigin = TargetOrigin::parse("https://admitted.invalid").unwrap();
        let verifier = Verifier {
            version: "testing".parse().unwrap(),
            commit: None,
            binary_digest: Sha256Digest::of(b"example verifier"),
        };
        let material = verification_material(
            VerificationAuthority {
                origin: origin.clone(),
                target_version: manifest.target_version().clone(),
                verifier,
                custody: Custody::Shared,
                target_isolation: TargetIsolation::SeparatePrincipalsUnconfined,
                environment_kind: EnvironmentKind::Simulated,
            },
            started_at,
            finished_at,
            RetainedInstrumentObservation {
                observation: start,
                artifact: start_artifact,
            },
            RetainedInstrumentObservation {
                observation: end,
                artifact: end_artifact,
            },
        )
        .unwrap();
        assert_eq!(material.target.origin.as_str(), origin.as_str());
        assert_eq!(&material.target_version, manifest.target_version());
        assert!(material.target.deployment_marker.is_none());
        assert_eq!(material.target.strength, Strength::OperatorAsserted);
        assert!(material.target.addresses.is_empty());
        assert!(material.target.tls_identity.is_none());
        assert_eq!(material.custody, Custody::Shared);
        assert_eq!(
            material.target_isolation,
            TargetIsolation::SeparatePrincipalsUnconfined
        );
        assert_eq!(material.enforcement, Enforcement::Unenforced);
        assert_eq!(material.environment_kind, EnvironmentKind::Simulated);
        assert!(io.requests.is_empty());
    }

    #[test]
    fn runtime_target_binding_refuses_a_late_origin_or_target_selector_change() {
        let (manifest, _) = fixture();
        let bound = TargetOrigin::parse("https://admitted.invalid").unwrap();
        let late = TargetOrigin::parse("https://different.invalid").unwrap();
        let selected = manifest.target_version();
        let other = "version.other".parse().unwrap();
        check_target_binding(&bound, selected, &bound, selected).unwrap();
        for (origin, version) in [(&late, selected), (&bound, &other)] {
            assert!(matches!(
                check_target_binding(&bound, selected, origin, version),
                Err(RoundError::AdmissionMismatch)
            ));
        }
    }

    #[test]
    fn evidence_failures_preserve_dependency_integrity_and_incompleteness_codes() {
        for (error, code) in [
            (
                EvidenceError::Io(std::io::ErrorKind::PermissionDenied),
                ErrorCode::DependencyUnavailable,
            ),
            (EvidenceError::Integrity, ErrorCode::IntegrityFailure),
            (EvidenceError::TooLarge, ErrorCode::EvidenceIncomplete),
        ] {
            assert_eq!(RoundError::Evidence(error).code(), code);
        }
    }

    #[test]
    fn refused_ending_gate_retains_the_passive_observation_and_its_typed_failure() {
        let mut io = FakeIo::default();
        let refusal = GateRefusal {
            reason: crate::teapot::GateRefusalReason::ActiveRule,
            calls: Vec::new(),
            edit_surface: crate::teapot::EditSurface::default(),
            enforcement: Some(EnforcementStatus::Unenforced),
            policy_locked: Some(false),
            invocation: None,
        };
        let timestamp = "2026-11-25T07:00:00Z".parse().unwrap();
        attach_gate_observation(
            &mut io,
            START_OBSERVATION,
            &timestamp,
            Ok(&gate_observation()),
        )
        .unwrap();
        let retained = finish_capture(&mut io, &[], Err(&refusal), &timestamp, false).unwrap();
        assert!(!retained.capture.complete);
        let end =
            observation_artifact(&retained.capture, END_OBSERVATION, &retained.end_digest).unwrap();
        assert_eq!(end.digest, Sha256Digest::of(&io.attached[1].1));
        let bytes = canonical::parse(&io.attached[1].1).unwrap();
        assert_eq!(bytes["observation"]["refused"], "active_rule");
        assert_eq!(
            RoundError::EndGate(Box::new(refusal)).code(),
            ErrorCode::InstrumentEditsActive
        );
        assert!(io.requests.is_empty());
    }

    fn open_run(
        manifest: &ManifestRevision,
        experiment: &crate::template::FrozenExperiment,
    ) -> (tempfile::TempDir, std::path::PathBuf, Store, Run) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.sqlite3");
        let mut store = Store::open(&path).unwrap();
        let engagement = EngagementId::try_from("round-test".to_owned()).unwrap();
        store
            .append_manifest(
                &engagement,
                &Artifact {
                    artifact_id: "art_manifest_rounds".parse().unwrap(),
                    digest: manifest.digest().clone(),
                },
                manifest.pass_digest(),
            )
            .unwrap();
        let run = Run::declare(engagement, experiment.freeze().unwrap().1);
        store.seed_historical_run_fixture(&run).unwrap();
        (dir, path, store, run)
    }

    #[test]
    fn complete_cross_user_round_persists_exact_flow_ids_digests_and_frozen_order() {
        let (manifest, experiment) = fixture();
        let operations = RegisteredOperations::resolve(&experiment, &manifest).unwrap();
        let (_dir, _path, mut store, run) = open_run(&manifest, &experiment);
        let origin = TargetOrigin::parse("http://127.0.0.1:3000").unwrap();
        let mut mint = CanaryMint::new(CounterEntropy { next: 1 });
        let mut io = FakeIo::default();
        let preexisting = BTreeMap::from([
            ("note".to_owned(), "same-name".to_owned()),
            ("detail".to_owned(), "untouched bytes".to_owned()),
        ]);
        io.objects
            .insert("preexisting-object".to_owned(), preexisting.clone());
        let mut state = AcquisitionState::default();
        let mut rounds = acquire_rounds(
            &mut ExecutionStore::fixture(&mut store),
            &run.id,
            &operations,
            &origin,
            1,
            &mut mint,
            &mut io,
            &mut state,
        )
        .unwrap();
        let finalized = io.finalize(Completion::Complete).unwrap();
        link_originals(
            &mut ExecutionStore::fixture(&mut store),
            &run.id,
            &mut state,
            &finalized,
            0,
        )
        .unwrap();
        refresh_round_cleanup(&store, &run.id, &mut rounds).unwrap();

        assert_eq!(rounds.len(), 1);
        assert_eq!(rounds[0].flows.len(), 13, "cleanup sends two removals");
        assert_eq!(rounds[0].identities.len(), 4);
        let crossed = rounds[0]
            .flows
            .iter()
            .find(|flow| flow.contract == RoundFlow::F2)
            .unwrap();
        assert!(rounds[0].primary.iter().all(|planted| {
            crossed
                .response_body
                .windows(32)
                .any(|window| window == planted.canary.as_str().as_bytes())
        }));

        let recovered = store.recover_run(&run.id).unwrap();
        assert_eq!(recovered.steps.len(), 12);
        assert_eq!(
            recovered
                .steps
                .iter()
                .map(|step| step.step.as_str().rsplit('.').next().unwrap())
                .collect::<Vec<_>>(),
            RoundFlow::REQUIRED
                .iter()
                .map(|flow| flow.as_str())
                .collect::<Vec<_>>()
        );
        let mut ids = BTreeSet::new();
        for step in recovered.steps {
            assert_eq!(step.effects, Some(Effect::Observed));
            for flow in step.flows {
                let id = flow.flow_id.unwrap();
                assert!(ids.insert(id));
                let original = flow.original.unwrap();
                assert_eq!(
                    original.digest,
                    Sha256Digest::of(format!("exact-flow-{id}\n").as_bytes())
                );
            }
        }
        assert_eq!(ids.len(), 13);
        assert_eq!(finalized.original_artifacts.len(), 13);
        assert_eq!(
            io.objects.get("preexisting-object"),
            Some(&preexisting),
            "cleanup must preserve an earlier same-name object byte-for-byte"
        );
        assert_eq!(
            store.recover_run(&run.id).unwrap().cleanup,
            Cleanup::Complete
        );
        let cleanup = store.recover_cleanup(&run.id).unwrap();
        assert_eq!(rounds[0].cleanup, cleanup);
        assert_eq!(cleanup.len(), 2);
        assert!(cleanup.iter().all(|item| {
            item.ownership == CleanupOwnership::Established
                && item.outcome == CleanupObjectOutcome::Complete
                && item.object_id.is_some()
                && item.cleanup_request_digest.is_some()
                && item.instrument_reference.is_some()
                && item.flows.iter().all(|flow| flow.original.is_some())
        }));
        assert_ne!(
            cleanup[0].cleanup_request_digest, cleanup[1].cleanup_request_digest,
            "each object binds its own one-action DELETE intent"
        );
    }

    #[test]
    fn cleanup_floor_failure_keeps_round_and_finalizes_existing_originals() {
        let (manifest, experiment) = fixture();
        let operations = RegisteredOperations::resolve(&experiment, &manifest).unwrap();
        let (_dir, _path, mut store, run) = open_run(&manifest, &experiment);
        let origin = TargetOrigin::parse("http://127.0.0.1:3000").unwrap();
        let mut mint = CanaryMint::new(CounterEntropy { next: 40 });
        let mut io = FakeIo {
            fail_floor_at: Some(RoundFlow::REQUIRED.len()),
            ..FakeIo::default()
        };
        let mut state = AcquisitionState::default();
        let mut rounds = acquire_rounds(
            &mut ExecutionStore::fixture(&mut store),
            &run.id,
            &operations,
            &origin,
            1,
            &mut mint,
            &mut io,
            &mut state,
        )
        .unwrap();
        let finalized = io.finalize(Completion::Complete).unwrap();
        link_originals(
            &mut ExecutionStore::fixture(&mut store),
            &run.id,
            &mut state,
            &finalized,
            0,
        )
        .unwrap();
        refresh_round_cleanup(&store, &run.id, &mut rounds).unwrap();

        assert_eq!(rounds.len(), 1);
        assert_eq!(io.deletes, 0);
        assert_eq!(rounds[0].flows.len(), 11);
        assert!(
            rounds[0]
                .cleanup
                .iter()
                .all(|cleanup| cleanup.outcome == CleanupObjectOutcome::Owed)
        );
        assert_eq!(finalized.original_artifacts.len(), 11);
    }

    #[test]
    fn lost_plant_response_leaves_cleanup_owed_and_sends_no_delete() {
        let (manifest, experiment) = fixture();
        let operations = RegisteredOperations::resolve(&experiment, &manifest).unwrap();
        let (_dir, _path, mut store, run) = open_run(&manifest, &experiment);
        let origin = TargetOrigin::parse("http://127.0.0.1:3000").unwrap();
        let mut mint = CanaryMint::new(CounterEntropy { next: 40 });
        let preexisting = BTreeMap::from([
            ("note".to_owned(), "same-name".to_owned()),
            ("detail".to_owned(), "original".to_owned()),
        ]);
        let mut io = FakeIo {
            drop_plant: Some(1),
            ..FakeIo::default()
        };
        io.objects
            .insert("preexisting-object".to_owned(), preexisting.clone());
        let mut state = AcquisitionState::default();

        let recovery = RunRecovery {
            run_id: run.id.clone(),
            request_key: run.request_key.clone(),
        };
        let capture_handle: CaptureHandle = "handle_12345678-1234-4234-8234-123456789abc"
            .parse()
            .unwrap();
        let error = with_execution_recovery(&mut store, recovery.clone(), |store, handle| {
            *handle = Some(capture_handle.clone());
            acquire_rounds(
                &mut ExecutionStore::fixture(store),
                &run.id,
                &operations,
                &origin,
                1,
                &mut mint,
                &mut io,
                &mut state,
            )
        })
        .unwrap_err();
        assert_eq!(error.recovery, recovery);
        assert_eq!(error.capture_handle, Some(capture_handle));
        assert_eq!(error.effects, Effect::Unknown);
        assert_eq!(error.code(), ErrorCode::EffectUnknown);
        assert_eq!(error.result(), OracleResult::Error);
        assert!(matches!(*error.error, RoundError::ObjectNotEstablished));
        assert_eq!(
            io.deletes, 0,
            "an unknown plant receipt grants no delete authority"
        );
        assert_eq!(io.objects.get("preexisting-object"), Some(&preexisting));
        assert_eq!(
            io.objects.len(),
            2,
            "the acted plant remains for reconciliation"
        );
        let cleanup = store.recover_cleanup(&run.id).unwrap();
        assert_eq!(cleanup.len(), 1);
        assert_eq!(cleanup[0].ownership, CleanupOwnership::Unknown);
        assert_eq!(cleanup[0].outcome, CleanupObjectOutcome::Owed);
        assert!(cleanup[0].object_id.is_none());
        assert_eq!(
            store.recover_run(&run.id).unwrap().cleanup,
            Cleanup::Unknown
        );
    }

    #[test]
    fn lost_second_plant_response_abstains_from_all_cleanup() {
        let (manifest, experiment) = fixture();
        let operations = RegisteredOperations::resolve(&experiment, &manifest).unwrap();
        let (_dir, _path, mut store, run) = open_run(&manifest, &experiment);
        let origin = TargetOrigin::parse("http://127.0.0.1:3000").unwrap();
        let mut mint = CanaryMint::new(CounterEntropy { next: 60 });
        let mut io = FakeIo {
            drop_plant: Some(2),
            ..FakeIo::default()
        };
        let mut state = AcquisitionState::default();

        let error = acquire_rounds(
            &mut ExecutionStore::fixture(&mut store),
            &run.id,
            &operations,
            &origin,
            1,
            &mut mint,
            &mut io,
            &mut state,
        )
        .unwrap_err();
        assert!(matches!(error, RoundError::ObjectNotEstablished));
        assert_eq!(
            io.deletes, 0,
            "one uncertain plant aborts the whole C batch"
        );
        assert_eq!(
            io.objects.len(),
            2,
            "neither possibly created object is deleted"
        );
        let cleanup = store.recover_cleanup(&run.id).unwrap();
        assert_eq!(cleanup.len(), 2);
        assert_eq!(cleanup[0].ownership, CleanupOwnership::Established);
        assert_eq!(cleanup[0].outcome, CleanupObjectOutcome::Owed);
        assert_eq!(cleanup[1].ownership, CleanupOwnership::Unknown);
        assert_eq!(cleanup[1].outcome, CleanupObjectOutcome::Owed);
    }

    #[test]
    fn non_created_plant_status_never_grants_delete_authority() {
        let (manifest, experiment) = fixture();
        let operations = RegisteredOperations::resolve(&experiment, &manifest).unwrap();
        let origin = TargetOrigin::parse("http://127.0.0.1:3000").unwrap();
        for status in [200, 202] {
            let (_dir, _path, mut store, run) = open_run(&manifest, &experiment);
            let mut mint = CanaryMint::new(CounterEntropy {
                next: u128::from(status),
            });
            let preexisting = BTreeMap::from([
                ("note".to_owned(), "same-name".to_owned()),
                ("detail".to_owned(), "byte-exact".to_owned()),
            ]);
            let mut io = FakeIo {
                plant_statuses: vec![status],
                plant_existing: (status == 200).then(|| "preexisting-object".to_owned()),
                ..FakeIo::default()
            };
            io.objects
                .insert("preexisting-object".to_owned(), preexisting.clone());
            let mut state = AcquisitionState::default();
            let error = acquire_rounds(
                &mut ExecutionStore::fixture(&mut store),
                &run.id,
                &operations,
                &origin,
                1,
                &mut mint,
                &mut io,
                &mut state,
            )
            .unwrap_err();
            assert!(matches!(error, RoundError::ObjectNotEstablished));
            assert_eq!(io.deletes, 0);
            assert_eq!(io.objects.get("preexisting-object"), Some(&preexisting));
            let cleanup = store.recover_cleanup(&run.id).unwrap();
            assert_eq!(cleanup.len(), 1);
            assert_eq!(cleanup[0].ownership, CleanupOwnership::Unknown);
            assert!(cleanup[0].object_id.is_none());
        }
    }

    #[test]
    fn ambiguous_or_status_contradictory_plant_response_never_grants_authority() {
        let (manifest, experiment) = fixture();
        let operations = RegisteredOperations::resolve(&experiment, &manifest).unwrap();
        let origin = TargetOrigin::parse("http://127.0.0.1:3000").unwrap();
        for mut io in [
            FakeIo {
                plant_response: Some(br#"{"id":"preexisting-object","id":"new-object"}"#.to_vec()),
                ..FakeIo::default()
            },
            FakeIo {
                plant_response: Some(br#"["new-object"]"#.to_vec()),
                ..FakeIo::default()
            },
            FakeIo {
                plant_readback_status: Some(200),
                ..FakeIo::default()
            },
        ] {
            let (_dir, _path, mut store, run) = open_run(&manifest, &experiment);
            let mut mint = CanaryMint::new(CounterEntropy { next: 75 });
            let mut state = AcquisitionState::default();
            assert!(matches!(
                acquire_rounds(
                    &mut ExecutionStore::fixture(&mut store),
                    &run.id,
                    &operations,
                    &origin,
                    1,
                    &mut mint,
                    &mut io,
                    &mut state,
                ),
                Err(RoundError::ObjectNotEstablished | RoundError::ReadbackMismatch)
            ));
            assert_eq!(io.deletes, 0);
            let cleanup = store.recover_cleanup(&run.id).unwrap();
            assert_eq!(cleanup.len(), 1);
            assert_eq!(cleanup[0].ownership, CleanupOwnership::Unknown);
            assert_eq!(cleanup[0].outcome, CleanupObjectOutcome::Owed);
            assert!(cleanup[0].object_id.is_none());
        }
    }

    #[test]
    fn contradictory_cleanup_receipt_and_original_status_remains_unknown() {
        let (manifest, experiment) = fixture();
        let operations = RegisteredOperations::resolve(&experiment, &manifest).unwrap();
        let (_dir, _path, mut store, run) = open_run(&manifest, &experiment);
        let origin = TargetOrigin::parse("http://127.0.0.1:3000").unwrap();
        let mut mint = CanaryMint::new(CounterEntropy { next: 77 });
        let mut io = FakeIo {
            delete_readback_status: Some(202),
            ..FakeIo::default()
        };
        let mut state = AcquisitionState::default();
        let rounds = acquire_rounds(
            &mut ExecutionStore::fixture(&mut store),
            &run.id,
            &operations,
            &origin,
            1,
            &mut mint,
            &mut io,
            &mut state,
        )
        .unwrap();
        assert_eq!(io.deletes, 1);
        assert_eq!(
            rounds[0]
                .cleanup
                .iter()
                .map(|cleanup| cleanup.outcome)
                .collect::<Vec<_>>(),
            [CleanupObjectOutcome::Unknown, CleanupObjectOutcome::Owed]
        );
    }

    #[test]
    fn statusless_observed_cleanup_preserves_the_round_and_exact_evidence() {
        let (manifest, experiment) = fixture();
        let operations = RegisteredOperations::resolve(&experiment, &manifest).unwrap();
        let (_dir, _path, mut store, run) = open_run(&manifest, &experiment);
        let origin = TargetOrigin::parse("http://127.0.0.1:3000").unwrap();
        let mut mint = CanaryMint::new(CounterEntropy { next: 79 });
        let mut io = FakeIo {
            delete_statusless: Some(1),
            ..FakeIo::default()
        };
        let mut state = AcquisitionState::default();
        let mut rounds = acquire_rounds(
            &mut ExecutionStore::fixture(&mut store),
            &run.id,
            &operations,
            &origin,
            1,
            &mut mint,
            &mut io,
            &mut state,
        )
        .unwrap();
        let finalized = io.finalize(Completion::Complete).unwrap();
        link_originals(
            &mut ExecutionStore::fixture(&mut store),
            &run.id,
            &mut state,
            &finalized,
            0,
        )
        .unwrap();
        refresh_round_cleanup(&store, &run.id, &mut rounds).unwrap();
        assert_eq!(rounds.len(), 1);
        assert_eq!(rounds[0].cleanup[0].outcome, CleanupObjectOutcome::Unknown);
        assert_eq!(rounds[0].cleanup[0].effects, Some(Effect::Observed));
        assert_eq!(rounds[0].cleanup[0].response_status, None);
        assert!(
            rounds[0].cleanup[0]
                .flows
                .iter()
                .all(|flow| flow.original.is_some())
        );
        assert_eq!(rounds[0].cleanup[1].outcome, CleanupObjectOutcome::Complete);
        assert_eq!(
            store.recover_run(&run.id).unwrap().cleanup,
            Cleanup::Partial
        );
    }

    #[test]
    fn cleanup_failure_is_per_object_and_does_not_discard_the_round() {
        let (manifest, experiment) = fixture();
        let operations = RegisteredOperations::resolve(&experiment, &manifest).unwrap();
        let (_dir, _path, mut store, run) = open_run(&manifest, &experiment);
        let origin = TargetOrigin::parse("http://127.0.0.1:3000").unwrap();
        let mut mint = CanaryMint::new(CounterEntropy { next: 80 });
        let mut io = FakeIo {
            delete_statuses: vec![500, 204],
            ..FakeIo::default()
        };
        let mut state = AcquisitionState::default();

        let rounds = acquire_rounds(
            &mut ExecutionStore::fixture(&mut store),
            &run.id,
            &operations,
            &origin,
            1,
            &mut mint,
            &mut io,
            &mut state,
        )
        .unwrap();
        assert_eq!(rounds.len(), 1, "cleanup failure is not an oracle failure");
        assert_eq!(
            rounds[0]
                .cleanup
                .iter()
                .map(|item| item.outcome)
                .collect::<Vec<_>>(),
            [CleanupObjectOutcome::Failed, CleanupObjectOutcome::Complete]
        );
        assert_eq!(
            store.recover_run(&run.id).unwrap().cleanup,
            Cleanup::Partial
        );
        assert_eq!(io.objects.len(), 1, "only the failed removal remains");
    }

    #[test]
    fn accepted_cleanup_is_unknown_and_cannot_clear_the_obligation() {
        let (manifest, experiment) = fixture();
        let operations = RegisteredOperations::resolve(&experiment, &manifest).unwrap();
        let (_dir, _path, mut store, run) = open_run(&manifest, &experiment);
        let origin = TargetOrigin::parse("http://127.0.0.1:3000").unwrap();
        let mut mint = CanaryMint::new(CounterEntropy { next: 110 });
        let mut io = FakeIo {
            delete_statuses: vec![202, 204],
            ..FakeIo::default()
        };
        let mut state = AcquisitionState::default();

        let rounds = acquire_rounds(
            &mut ExecutionStore::fixture(&mut store),
            &run.id,
            &operations,
            &origin,
            1,
            &mut mint,
            &mut io,
            &mut state,
        )
        .unwrap();
        assert_eq!(
            rounds[0]
                .cleanup
                .iter()
                .map(|item| (item.outcome, item.response_status))
                .collect::<Vec<_>>(),
            [
                (CleanupObjectOutcome::Unknown, Some(202)),
                (CleanupObjectOutcome::Complete, Some(204)),
            ]
        );
        assert_eq!(
            store.recover_run(&run.id).unwrap().cleanup,
            Cleanup::Partial
        );
        assert_eq!(io.objects.len(), 1);
    }

    #[test]
    fn incomplete_terminal_cleanup_receipt_never_clears_the_obligation() {
        let (manifest, experiment) = fixture();
        let operations = RegisteredOperations::resolve(&experiment, &manifest).unwrap();
        let (_dir, _path, mut store, run) = open_run(&manifest, &experiment);
        let origin = TargetOrigin::parse("http://127.0.0.1:3000").unwrap();
        let mut mint = CanaryMint::new(CounterEntropy { next: 115 });
        let mut io = FakeIo {
            partial_delete: Some(1),
            ..FakeIo::default()
        };
        let mut state = AcquisitionState::default();
        let rounds = acquire_rounds(
            &mut ExecutionStore::fixture(&mut store),
            &run.id,
            &operations,
            &origin,
            1,
            &mut mint,
            &mut io,
            &mut state,
        )
        .unwrap();
        assert_eq!(rounds[0].cleanup[0].response_status, Some(204));
        assert_eq!(rounds[0].cleanup[0].outcome, CleanupObjectOutcome::Unknown);
        assert_eq!(
            store.recover_run(&run.id).unwrap().cleanup,
            Cleanup::Partial
        );
    }

    #[test]
    fn cancelled_or_expired_cleanup_is_typed_failed_and_remains_owed() {
        let (manifest, experiment) = fixture();
        let operations = RegisteredOperations::resolve(&experiment, &manifest).unwrap();
        for reason in [
            crate::teapot::NotSentReason::NotRun,
            crate::teapot::NotSentReason::Refused,
        ] {
            let (_dir, _path, mut store, run) = open_run(&manifest, &experiment);
            let origin = TargetOrigin::parse("http://127.0.0.1:3000").unwrap();
            let mut mint = CanaryMint::new(CounterEntropy { next: 120 });
            let mut io = FakeIo {
                delete_not_sent: Some(reason),
                ..FakeIo::default()
            };
            let mut state = AcquisitionState::default();
            let mut rounds = acquire_rounds(
                &mut ExecutionStore::fixture(&mut store),
                &run.id,
                &operations,
                &origin,
                1,
                &mut mint,
                &mut io,
                &mut state,
            )
            .unwrap();
            let finalized = io.finalize(Completion::Complete).unwrap();
            link_originals(
                &mut ExecutionStore::fixture(&mut store),
                &run.id,
                &mut state,
                &finalized,
                0,
            )
            .unwrap();
            refresh_round_cleanup(&store, &run.id, &mut rounds).unwrap();
            assert!(
                rounds[0]
                    .cleanup
                    .iter()
                    .all(|item| item.outcome == CleanupObjectOutcome::Failed)
            );
            assert_eq!(store.recover_run(&run.id).unwrap().cleanup, Cleanup::Failed);
            assert_eq!(io.objects.len(), 2);
        }
    }

    #[test]
    fn native_exit_four_is_unknown_without_typed_not_sent_evidence() {
        let (manifest, experiment) = fixture();
        let operations = RegisteredOperations::resolve(&experiment, &manifest).unwrap();
        let origin = TargetOrigin::parse("http://127.0.0.1:3000").unwrap();
        for reason in ["pass-expired", "cancel-requested"] {
            let (_dir, _path, mut store, run) = open_run(&manifest, &experiment);
            let mut mint = CanaryMint::new(CounterEntropy { next: 145 });
            let mut io = FakeIo {
                delete_native_refusal: Some(reason),
                ..FakeIo::default()
            };
            let mut state = AcquisitionState::default();
            let rounds = acquire_rounds(
                &mut ExecutionStore::fixture(&mut store),
                &run.id,
                &operations,
                &origin,
                1,
                &mut mint,
                &mut io,
                &mut state,
            )
            .unwrap();
            assert_eq!(
                rounds[0]
                    .cleanup
                    .iter()
                    .map(|cleanup| cleanup.outcome)
                    .collect::<Vec<_>>(),
                [CleanupObjectOutcome::Unknown, CleanupObjectOutcome::Owed]
            );
            assert_eq!(rounds[0].cleanup[0].effects, Some(Effect::Unknown));
            assert_eq!(
                store
                    .recover_run(&run.id)
                    .unwrap()
                    .steps
                    .last()
                    .unwrap()
                    .effects,
                Some(Effect::Unknown)
            );
            assert_eq!(rounds[0].cleanup[0].instrument_reference, None, "{reason}");
        }
    }

    #[test]
    fn each_lost_cleanup_response_preserves_other_objects_exactly() {
        let (manifest, experiment) = fixture();
        let operations = RegisteredOperations::resolve(&experiment, &manifest).unwrap();
        let origin = TargetOrigin::parse("http://127.0.0.1:3000").unwrap();
        for (drop_delete, outcomes, summary) in [
            (
                1,
                [CleanupObjectOutcome::Unknown, CleanupObjectOutcome::Owed],
                Cleanup::Unknown,
            ),
            (
                2,
                [
                    CleanupObjectOutcome::Complete,
                    CleanupObjectOutcome::Unknown,
                ],
                Cleanup::Partial,
            ),
        ] {
            let (_dir, _path, mut store, run) = open_run(&manifest, &experiment);
            let mut mint = CanaryMint::new(CounterEntropy { next: 160 });
            let mut io = FakeIo {
                drop_delete: Some(drop_delete),
                ..FakeIo::default()
            };
            let mut state = AcquisitionState::default();
            let mut rounds = acquire_rounds(
                &mut ExecutionStore::fixture(&mut store),
                &run.id,
                &operations,
                &origin,
                1,
                &mut mint,
                &mut io,
                &mut state,
            )
            .unwrap();
            let finalized = io.finalize(Completion::Complete).unwrap();
            link_originals(
                &mut ExecutionStore::fixture(&mut store),
                &run.id,
                &mut state,
                &finalized,
                0,
            )
            .unwrap();
            let (acquired_run, TrustedAcquisition) =
                seal_acquisition(&store, &run.id, &state, &mut rounds).unwrap();
            assert_eq!(rounds.len(), 1, "lost cleanup reply cannot erase the round");
            assert_eq!(acquired_run.known_effects(), Effect::Unknown);
            assert!(rounds[0].flows.iter().any(|flow| flow.contract == RoundFlow::F2 && flow.reference.original.is_some()));
            assert_eq!(
                io.deletes, drop_delete,
                "an unknown delete stops the batch and is never retried"
            );
            assert_eq!(
                rounds[0]
                    .cleanup
                    .iter()
                    .map(|item| item.outcome)
                    .collect::<Vec<_>>(),
                outcomes
            );
            assert_eq!(acquired_run.cleanup, summary);
            if drop_delete == 2 {
                assert!(
                    rounds[0].cleanup[0]
                        .flows
                        .iter()
                        .all(|flow| flow.original.is_some())
                );
            }
        }
    }

    struct ReloginIo {
        action: Option<RequestAction>,
        reads: BTreeMap<u64, Readback>,
        attached: Vec<(String, Vec<u8>)>,
    }

    impl ReloginIo {
        fn new() -> Self {
            Self {
                action: None,
                reads: BTreeMap::new(),
                attached: Vec::new(),
            }
        }
    }

    impl RoundIo for ReloginIo {
        fn flow_floor(&mut self) -> Result<Option<u64>, RoundError> {
            Ok(Some(7))
        }

        fn dispatch(&mut self, action: &RequestAction) -> Result<DispatchReceipt, RoundError> {
            self.action = Some(action.clone());
            for (id, url, method, body) in [
                (
                    8,
                    action.url.clone(),
                    action.method.as_str().to_owned(),
                    br#"{"id":"logged-out"}"#.to_vec(),
                ),
                (
                    9,
                    "http://127.0.0.1:3000/app/login".to_owned(),
                    "POST".to_owned(),
                    br#"{"ok":true}"#.to_vec(),
                ),
                (
                    10,
                    action.url.clone(),
                    action.method.as_str().to_owned(),
                    br#"{"id":"user-bob-verify"}"#.to_vec(),
                ),
            ] {
                self.reads.insert(
                    id,
                    Readback {
                        id,
                        url: Some(url),
                        method: Some(method),
                        status: Some(if id == 8 { 401 } else { 200 }),
                        response_body: body,
                        response_head: None,
                        completeness: Completeness::Complete,
                        original: format!("exact-relogin-flow-{id}\n").into_bytes(),
                    },
                );
            }
            Ok(DispatchReceipt {
                dispatch: DispatchEvidence::Flow { flow: 10 },
                flows: vec![
                    StepFlow {
                        step: 1,
                        role: FlowRole::Request,
                        reference: FlowReference::Retained(8),
                    },
                    StepFlow {
                        step: 1,
                        role: FlowRole::Login,
                        reference: FlowReference::Retained(9),
                    },
                    StepFlow {
                        step: 1,
                        role: FlowRole::Retry,
                        reference: FlowReference::Retained(10),
                    },
                ],
                status: Some(200),
            })
        }

        fn read_flow(&mut self, id: u64) -> Result<Readback, RoundError> {
            self.reads.remove(&id).ok_or(RoundError::ReadbackMismatch)
        }

        fn attach(&mut self, key: &str, bytes: &[u8]) -> Result<(), RoundError> {
            self.attached.push((key.to_owned(), bytes.to_vec()));
            Ok(())
        }

        fn finalize(&mut self, completion: Completion) -> Result<Finalized, RoundError> {
            Ok(finalize_attached(&self.attached, completion))
        }
    }

    #[test]
    fn login_and_retry_flows_are_read_and_bound_to_the_triggering_step() {
        let (manifest, experiment) = fixture();
        let operations = RegisteredOperations::resolve(&experiment, &manifest).unwrap();
        let (_dir, _path, mut store, run) = open_run(&manifest, &experiment);
        let identity: WireText = "http://127.0.0.1:3000/app/api/me".parse().unwrap();
        let mut io = ReloginIo::new();
        let mut state = AcquisitionState::default();
        let acquired = execute_step(
            &mut ExecutionStore::fixture(&mut store),
            &run.id,
            &operations,
            1,
            RoundFlow::I2,
            vec![RequestAction::send(
                Method::Get,
                identity,
                operations.other_session.clone(),
            )],
            &mut io,
            &mut state,
        )
        .unwrap();
        assert!(io.reads.is_empty());
        assert_eq!(
            acquired
                .flows
                .iter()
                .map(|flow| flow.reference.step.as_str())
                .collect::<Vec<_>>(),
            ["I2.request", "I2.login", "I2.retry"]
        );
        let finalized = io.finalize(Completion::Complete).unwrap();
        link_originals(
            &mut ExecutionStore::fixture(&mut store),
            &run.id,
            &mut state,
            &finalized,
            0,
        )
        .unwrap();
        let recovered = store.recover_run(&run.id).unwrap();
        assert_eq!(recovered.steps[0].flow_id_floor, Some(7));
        assert_eq!(
            recovered.steps[0]
                .flows
                .iter()
                .map(|flow| flow.flow_id.unwrap())
                .collect::<Vec<_>>(),
            [8, 9, 10]
        );
        assert!(
            recovered.steps[0]
                .flows
                .iter()
                .all(|flow| flow.original.is_some())
        );
    }

    #[test]
    fn incomplete_terminal_retry_never_borrows_an_earlier_object_id() {
        let flows = vec![
            AcquiredFlow {
                contract: RoundFlow::P,
                sequence: 1,
                reference: Flow {
                    step: "P.request".parse().unwrap(),
                    flow_id: Some(10),
                    original: None,
                    completeness: Completeness::Complete,
                    decoder: None,
                },
                response_body: br#"{"id":"preexisting-object"}"#.to_vec(),
                response_head: None,
            },
            AcquiredFlow {
                contract: RoundFlow::P,
                sequence: 2,
                reference: Flow {
                    step: "P.retry".parse().unwrap(),
                    flow_id: Some(11),
                    original: None,
                    completeness: Completeness::Partial,
                    decoder: None,
                },
                response_body: br#"{"id":"new-object""#.to_vec(),
                response_head: None,
            },
        ];
        assert!(matches!(
            object_id(&flows),
            Err(RoundError::ObjectNotEstablished)
        ));
        let duplicate = [br#"{"id":"first","id":"second"}"#.as_slice()];
        let duplicate = flows
            .iter()
            .take(1)
            .cloned()
            .map(|mut flow| {
                flow.response_body = duplicate[0].to_vec();
                flow
            })
            .collect::<Vec<_>>();
        assert!(matches!(
            object_id(&duplicate),
            Err(RoundError::ObjectNotEstablished)
        ));
    }

    struct DispatchSink {
        evidence: DispatchEvidence,
        dispatches: usize,
        reads: usize,
        attaches: usize,
    }

    impl RoundIo for DispatchSink {
        fn flow_floor(&mut self) -> Result<Option<u64>, RoundError> {
            Ok(None)
        }

        fn dispatch(&mut self, _: &RequestAction) -> Result<DispatchReceipt, RoundError> {
            self.dispatches += 1;
            let flows = self.evidence.is_no_flow().then_some(StepFlow {
                step: 1,
                role: FlowRole::Request,
                reference: FlowReference::Missing,
            });
            Ok(DispatchReceipt {
                dispatch: self.evidence,
                flows: flows.into_iter().collect(),
                status: None,
            })
        }

        fn read_flow(&mut self, _: u64) -> Result<Readback, RoundError> {
            self.reads += 1;
            unreachable!("a missing flow must never be read by guessed ID")
        }

        fn attach(&mut self, _: &str, _: &[u8]) -> Result<(), RoundError> {
            self.attaches += 1;
            unreachable!("a missing flow has no exact original to attach")
        }

        fn finalize(&mut self, _: Completion) -> Result<Finalized, RoundError> {
            unreachable!()
        }
    }

    #[test]
    fn sent_without_flow_is_unknown_while_typed_refusal_is_no_effect() {
        let (manifest, experiment) = fixture();
        let operations = RegisteredOperations::resolve(&experiment, &manifest).unwrap();
        for (dispatch, expected_effect, expected_flows) in [
            (
                DispatchEvidence::NoFlow {
                    outcome: crate::teapot::SendOutcome::Complete,
                },
                Effect::Unknown,
                1,
            ),
            (
                DispatchEvidence::NotSent {
                    reason: crate::teapot::NotSentReason::Refused,
                },
                Effect::None,
                0,
            ),
        ] {
            let (_dir, _path, mut store, run) = open_run(&manifest, &experiment);
            let identity: WireText = "http://127.0.0.1:3000/app/api/me".parse().unwrap();
            let mut io = DispatchSink {
                evidence: dispatch,
                dispatches: 0,
                reads: 0,
                attaches: 0,
            };
            let mut state = AcquisitionState::default();
            let acquired = execute_step(
                &mut ExecutionStore::fixture(&mut store),
                &run.id,
                &operations,
                1,
                RoundFlow::I1,
                vec![RequestAction::send(
                    Method::Get,
                    identity,
                    operations.owner_session.clone(),
                )],
                &mut io,
                &mut state,
            )
            .unwrap();
            assert_eq!(io.dispatches, 1);
            assert_eq!(io.reads, 0);
            assert_eq!(io.attaches, 0);
            assert_eq!(acquired.flows.len(), expected_flows);
            let recovered = store.recover_run(&run.id).unwrap();
            assert_eq!(recovered.steps[0].effects, Some(expected_effect));
            assert_eq!(recovered.steps[0].flows.len(), expected_flows);
            if expected_flows == 1 {
                assert_eq!(
                    recovered.steps[0].flows[0].completeness,
                    Completeness::Missing
                );
                assert_eq!(recovered.steps[0].flows[0].flow_id, None);
            }
        }
    }

    struct StaleFlowSink {
        reads: usize,
        attaches: usize,
    }

    impl RoundIo for StaleFlowSink {
        fn flow_floor(&mut self) -> Result<Option<u64>, RoundError> {
            Ok(Some(10))
        }

        fn dispatch(&mut self, _: &RequestAction) -> Result<DispatchReceipt, RoundError> {
            Ok(DispatchReceipt {
                dispatch: DispatchEvidence::Flow { flow: 10 },
                flows: vec![StepFlow {
                    step: 1,
                    role: FlowRole::Request,
                    reference: FlowReference::Retained(10),
                }],
                status: Some(200),
            })
        }

        fn read_flow(&mut self, _: u64) -> Result<Readback, RoundError> {
            self.reads += 1;
            unreachable!("a stale flow ID must be rejected before readback")
        }

        fn attach(&mut self, _: &str, _: &[u8]) -> Result<(), RoundError> {
            self.attaches += 1;
            unreachable!("a stale flow ID must never enter Evidence")
        }

        fn finalize(&mut self, _: Completion) -> Result<Finalized, RoundError> {
            unreachable!()
        }
    }

    #[test]
    fn flow_at_the_pre_send_floor_is_typed_failure_with_uncertain_effect() {
        let (manifest, experiment) = fixture();
        let operations = RegisteredOperations::resolve(&experiment, &manifest).unwrap();
        let (_dir, _path, mut store, run) = open_run(&manifest, &experiment);
        let identity: WireText = "http://127.0.0.1:3000/app/api/me".parse().unwrap();
        let mut io = StaleFlowSink {
            reads: 0,
            attaches: 0,
        };
        let mut state = AcquisitionState::default();
        let error = execute_step(
            &mut ExecutionStore::fixture(&mut store),
            &run.id,
            &operations,
            1,
            RoundFlow::I1,
            vec![RequestAction::send(
                Method::Get,
                identity,
                operations.owner_session.clone(),
            )],
            &mut io,
            &mut state,
        )
        .unwrap_err();
        assert!(matches!(error, RoundError::FlowBeforeFloor));
        assert_eq!(error.code(), ErrorCode::EvidenceIncomplete);
        assert_eq!(io.reads, 0);
        assert_eq!(io.attaches, 0);
        let recovered = store.recover_run(&run.id).unwrap();
        assert_eq!(recovered.steps[0].effects, Some(Effect::Unknown));
        assert_eq!(
            recovered.steps[0]
                .instrument_reference
                .as_ref()
                .map(WireText::as_str),
            Some("flow:10")
        );
    }

    #[test]
    fn unregistered_request_binding_is_rejected_before_an_io_can_be_constructed() {
        let (manifest, mut experiment) = fixture();
        let read = experiment
            .slots
            .iter_mut()
            .find(|(slot, _)| slot.as_str() == "read")
            .unwrap()
            .1;
        read.value = "operation.orders.untrusted".parse().unwrap();
        assert!(matches!(
            RegisteredOperations::resolve(&experiment, &manifest),
            Err(RegistryError::Unsupported)
        ));
    }

    #[test]
    fn plant_request_is_complete_compiled_grammar_with_no_macro_execution_surface() {
        let action = RequestAction::plant(
            "http://127.0.0.1:3000/app/api/orders".parse().unwrap(),
            "alice_verify".parse().unwrap(),
            &[
                PlantedCanary {
                    field: "note".parse().unwrap(),
                    canary: Canary::parse("00000000000000000000000000000001").unwrap(),
                },
                PlantedCanary {
                    field: "detail".parse().unwrap(),
                    canary: Canary::parse("00000000000000000000000000000002").unwrap(),
                },
            ],
        )
        .unwrap();
        assert_eq!(action.kind, "send");
        assert_eq!(action.method, Method::Post);
        assert_eq!(action.url, "http://127.0.0.1:3000/app/api/orders");
        assert_eq!(action.session, "alice_verify");
        assert_eq!(action.headers, ["Content-Type: application/json"]);
        assert_eq!(
            action.body.as_deref(),
            Some(
                r#"{"detail":"00000000000000000000000000000002","note":"00000000000000000000000000000001"}"#
            )
        );
    }

    struct WaitBeforeSend {
        path: std::path::PathBuf,
        run: RunId,
    }

    impl RoundIo for WaitBeforeSend {
        fn flow_floor(&mut self) -> Result<Option<u64>, RoundError> {
            Ok(Some(41))
        }

        fn dispatch(&mut self, _: &RequestAction) -> Result<DispatchReceipt, RoundError> {
            let store = Store::open(&self.path).unwrap();
            let recovered = store.recover_run(&self.run).unwrap();
            assert_eq!(recovered.steps.len(), 1);
            assert_eq!(recovered.steps[0].effects, None);
            assert_eq!(recovered.steps[0].flow_id_floor, Some(41));
            println!("round-intent-ready {}", self.run.as_str());
            std::io::stdout().flush().unwrap();
            loop {
                thread::park();
            }
        }

        fn read_flow(&mut self, _: u64) -> Result<Readback, RoundError> {
            unreachable!()
        }

        fn attach(&mut self, _: &str, _: &[u8]) -> Result<(), RoundError> {
            unreachable!()
        }

        fn finalize(&mut self, _: Completion) -> Result<Finalized, RoundError> {
            unreachable!()
        }
    }

    #[test]
    #[ignore = "subprocess helper for the exact round-intent SIGKILL point"]
    fn round_intent_kill_child() {
        let path = std::env::var_os("SCOURGE_ROUNDS_KILL_DB")
            .map(PathBuf::from)
            .expect("child DB path");
        let run: RunId = std::env::var("SCOURGE_ROUNDS_KILL_RUN")
            .expect("child run ID")
            .parse()
            .unwrap();
        let (manifest, experiment) = fixture();
        let operations = RegisteredOperations::resolve(&experiment, &manifest).unwrap();
        let mut store = Store::open(&path).unwrap();
        let identity: WireText = "http://127.0.0.1:3000/app/api/me".parse().unwrap();
        let mut io = WaitBeforeSend {
            path,
            run: run.clone(),
        };
        let mut state = AcquisitionState::default();
        let _ = execute_step(
            &mut ExecutionStore::fixture(&mut store),
            &run,
            &operations,
            1,
            RoundFlow::I1,
            vec![RequestAction::send(
                Method::Get,
                identity,
                operations.owner_session.clone(),
            )],
            &mut io,
            &mut state,
        );
        unreachable!("the parent must kill this process before dispatch")
    }

    #[cfg(unix)]
    #[test]
    fn sigkill_after_intent_before_send_leaves_recovery_visible_intent() {
        let (manifest, experiment) = fixture();
        let (_dir, path, store, run) = open_run(&manifest, &experiment);
        drop(store);
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "rounds::tests::round_intent_kill_child",
                "--ignored",
                "--nocapture",
            ])
            .env("SCOURGE_ROUNDS_KILL_DB", &path)
            .env("SCOURGE_ROUNDS_KILL_RUN", run.id.as_str())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let ready = BufReader::new(child.stdout.take().unwrap())
            .lines()
            .map(|line| line.unwrap())
            .find(|line| line.contains("round-intent-ready"))
            .expect("child persisted the intent and reached the pre-send kill point");
        assert!(ready.contains(run.id.as_str()));
        child.kill().unwrap();
        use std::os::unix::process::ExitStatusExt as _;
        assert_eq!(child.wait().unwrap().signal(), Some(9));

        let store = Store::open(&path).unwrap();
        let recovered = store.recover_run(&run.id).unwrap();
        assert_eq!(recovered.steps.len(), 1);
        assert_eq!(recovered.steps[0].effects, None);
        assert!(recovered.steps[0].flows.is_empty());
    }

    fn absolute(path: &Path) -> AbsolutePath {
        path.to_str().unwrap().parse().unwrap()
    }

    struct DevelopmentTarget {
        origin: TargetOrigin,
        stop: Option<tokio::sync::oneshot::Sender<()>>,
        task: Option<thread::JoinHandle<()>>,
    }

    impl DevelopmentTarget {
        fn start() -> Self {
            let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
            listener.set_nonblocking(true).unwrap();
            let address = listener.local_addr().unwrap();
            let (stop, stopped) = tokio::sync::oneshot::channel();
            let task = thread::spawn(move || {
                let runtime = tokio::runtime::Runtime::new().unwrap();
                runtime.block_on(async move {
                    let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                    let app = scourge_fixture::app_with_verifier_passwords(
                        "rounds-admin".to_owned(),
                        [
                            "rounds-alice-password".to_owned(),
                            "rounds-bob-password".to_owned(),
                        ],
                    );
                    axum::serve(listener, app)
                        .with_graceful_shutdown(async {
                            let _ = stopped.await;
                        })
                        .await
                        .unwrap();
                });
            });
            Self {
                origin: TargetOrigin::parse(&format!("http://{address}")).unwrap(),
                stop: Some(stop),
                task: Some(task),
            }
        }
    }

    impl Drop for DevelopmentTarget {
        fn drop(&mut self) {
            let _ = self.stop.take().unwrap().send(());
            let result = self.task.take().unwrap().join();
            if !thread::panicking() {
                result.unwrap();
            }
        }
    }

    struct PinnedProject {
        binary: PathBuf,
        project: PathBuf,
        environment: Environment,
        _root: tempfile::TempDir,
        started: bool,
    }

    impl PinnedProject {
        fn new() -> Self {
            let binary = fs::canonicalize(
                std::env::var_os("SCOURGE_PINNED_TEAPOT")
                    .expect("set SCOURGE_PINNED_TEAPOT to the frozen executable"),
            )
            .unwrap();
            let contract: serde_json::Value =
                serde_json::from_slice(include_bytes!("../../../fixtures/contracts/manifest.json"))
                    .unwrap();
            assert_eq!(
                Sha256Digest::of(&fs::read(&binary).unwrap()).as_str(),
                contract["binary_sha256"].as_str().unwrap()
            );
            let root = tempfile::tempdir().unwrap();
            let runtime = root.path().join("r");
            fs::create_dir(&runtime).unwrap();
            #[cfg(unix)]
            fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
            let project = root.path().join("project");
            fs::create_dir(&project).unwrap();
            let environment = Environment {
                home: absolute(root.path()),
                config_home: None,
                data_home: None,
                state_home: None,
                cache_home: None,
                runtime_dir: Some(absolute(&runtime)),
            };
            let this = Self {
                binary,
                project: fs::canonicalize(project).unwrap(),
                environment,
                _root: root,
                started: false,
            };
            this.run(&["projects", "init"]);
            this
        }

        fn command(&self, words: &[&str]) -> std::io::Result<Output> {
            let mut command = Command::new(&self.binary);
            command
                .env_clear()
                .env("HOME", self.environment.home.as_str())
                .env(
                    "XDG_RUNTIME_DIR",
                    self.environment.runtime_dir.as_ref().unwrap().as_str(),
                )
                .env("NO_COLOR", "1")
                .env("TERM", "dumb")
                .arg("--project")
                .arg(&self.project)
                .arg("--json")
                .args(words)
                .stdin(Stdio::null())
                .output()
        }

        fn run(&self, words: &[&str]) -> serde_json::Value {
            let output = self.command(words).unwrap();
            assert!(
                output.status.success(),
                "{words:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            serde_json::from_slice(&output.stdout).unwrap()
        }

        fn start(&mut self) -> Teapot {
            let started = self.run(&["proxy", "start", "--listen", "127.0.0.1:0", "--detach"]);
            self.started = true;
            let engine = &started["proxy"]["engine"];
            Teapot::new(
                absolute(&self.binary),
                ExecutableKind::Native,
                absolute(&self.project),
                self.environment.clone(),
                BoundEngine {
                    instance: engine["instance"].as_str().unwrap().parse().unwrap(),
                    project_id: engine["project_id"].as_str().unwrap().parse().unwrap(),
                    enforced: false,
                    policy_locked: false,
                },
            )
        }
    }

    impl Drop for PinnedProject {
        fn drop(&mut self) {
            if self.started {
                let output = self.command(&["proxy", "stop"]);
                if !thread::panicking() {
                    assert!(output.unwrap().status.success());
                }
            }
        }
    }

    struct PinnedIo<'a> {
        teapot: &'a Teapot,
        attached: Vec<(String, Vec<u8>)>,
    }

    impl RoundIo for PinnedIo<'_> {
        fn flow_floor(&mut self) -> Result<Option<u64>, RoundError> {
            self.teapot.passive().highest_flow_id().map_err(Into::into)
        }

        fn dispatch(&mut self, action: &RequestAction) -> Result<DispatchReceipt, RoundError> {
            teapot_dispatch(self.teapot, action)
        }

        fn read_flow(&mut self, id: u64) -> Result<Readback, RoundError> {
            teapot_read(self.teapot, id)
        }

        fn attach(&mut self, key: &str, bytes: &[u8]) -> Result<(), RoundError> {
            self.attached.push((key.to_owned(), bytes.to_vec()));
            Ok(())
        }

        fn finalize(&mut self, completion: Completion) -> Result<Finalized, RoundError> {
            Ok(finalize_attached(&self.attached, completion))
        }
    }

    #[test]
    #[ignore = "requires SCOURGE_PINNED_TEAPOT and a disposable development-fixture listener"]
    fn pinned_development_fixture_cross_user_round_reads_and_digests_every_flow() {
        let target = DevelopmentTarget::start();
        let mut project = PinnedProject::new();
        let macro_dir = project.project.join(".teapot/macros");
        fs::create_dir_all(&macro_dir).unwrap();
        fs::write(
            macro_dir.join("create-order.toml"),
            format!(
                "format = 1\n\n[[steps]]\nstate_changing = true\n[steps.request]\nmethod = \"DELETE\"\nurl = {:?}\n",
                format!("{}/app/api/orders/macro-drift", target.origin.0.as_str())
            ),
        )
        .unwrap();
        let teapot = project.start();
        project.run(&["scope", "add", "127.0.0.1"]);
        for session in ["alice_verify", "bob_verify", "scourge_anonymous"] {
            project.run(&["sessions", "create", session]);
        }
        for (session, username, password) in [
            ("alice_verify", "alice-verify", "rounds-alice-password"),
            ("bob_verify", "bob-verify", "rounds-bob-password"),
        ] {
            let url: WireText = format!("{}/app/login", target.origin.0.as_str())
                .try_into()
                .unwrap();
            let session: SessionName = session.parse().unwrap();
            let body = serde_json::json!({"username": username, "password": password}).to_string();
            let header = "Content-Type: application/json".to_owned();
            let login = teapot
                .send(
                    Method::Post,
                    &url,
                    &session,
                    SendOptions {
                        headers: std::slice::from_ref(&header),
                        body: Some(&body),
                        ..SendOptions::default()
                    },
                )
                .unwrap();
            assert_eq!(login.value.status, Some(200));
        }

        let (manifest, experiment) = fixture();
        let operations = RegisteredOperations::resolve(&experiment, &manifest).unwrap();
        let (_dir, _path, mut store, run) = open_run(&manifest, &experiment);
        let mut mint = CanaryMint::new(CounterEntropy { next: 0x1000 });
        let mut io = PinnedIo {
            teapot: &teapot,
            attached: Vec::new(),
        };
        let mut state = AcquisitionState::default();
        let rounds = acquire_rounds(
            &mut ExecutionStore::fixture(&mut store),
            &run.id,
            &operations,
            &target.origin,
            1,
            &mut mint,
            &mut io,
            &mut state,
        )
        .unwrap();
        let finalized = io.finalize(Completion::Complete).unwrap();
        link_originals(
            &mut ExecutionStore::fixture(&mut store),
            &run.id,
            &mut state,
            &finalized,
            0,
        )
        .unwrap();

        let treatment = rounds[0]
            .flows
            .iter()
            .find(|flow| flow.contract == RoundFlow::F2)
            .unwrap();
        assert!(rounds[0].primary.iter().all(|planted| {
            treatment
                .response_body
                .windows(32)
                .any(|window| window == planted.canary.as_str().as_bytes())
        }));
        let recovered = store.recover_run(&run.id).unwrap();
        let retained = recovered
            .steps
            .iter()
            .flat_map(|step| &step.flows)
            .collect::<Vec<_>>();
        assert_eq!(retained.len(), 13);
        for flow in &retained {
            assert!(flow.flow_id.is_some(), "missing flow id for {flow:?}");
            assert!(flow.original.is_some(), "missing original for {flow:?}");
            assert_eq!(
                flow.completeness,
                Completeness::Complete,
                "incomplete retained flow step={} id={:?}",
                flow.step.as_str(),
                flow.flow_id
            );
        }
        for original in &finalized.original_artifacts {
            let (_, bytes) = io
                .attached
                .iter()
                .find(|(key, _)| key == &original.attachment.key)
                .unwrap();
            assert_eq!(original.artifact.digest, Sha256Digest::of(bytes));
        }
    }
}
