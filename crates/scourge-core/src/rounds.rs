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
    canonical::Sha256Digest,
    domain::{CleanupObjectOutcome, CleanupObjectRole, CleanupOwnership, RunCleanup, RunStep},
    engagement::ManifestRevision,
    evidence::{Capture, Completion, Evidence, EvidenceError, Finalized},
    ids::{RunId, SessionName, WireText},
    operations::{
        FieldSpec, IDENTITY_PATH, IDENTITY_SUBJECT_FIELD, REGISTRY_ID, RegisteredOperations,
        RegistryError,
    },
    preflight::{LiveAdmission, Prepared},
    store::{Store, StoreError},
    teapot::{
        BodyCapture, BodyWindow, DispatchEvidence, FlowReference, FlowRole, InvocationError,
        SendOptions, StepFlow, Teapot,
        accounting::{AccountingFailure, AccountingObservation},
        passive::PassiveError,
    },
    template::Method,
    wire::{Artifact, Cleanup, Completeness, Effect, ErrorCode, Flow},
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
    pub rounds: Vec<AcquiredRound>,
    pub capture: Finalized,
    pub accounting: AccountingObservation,
    pub cleanup: Cleanup,
}

impl ExecutedRounds {
    pub fn cleanup(&self) -> Cleanup {
        self.cleanup
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
            | Self::ReadbackMismatch
            | Self::CaptureMismatch
            | Self::Wire => ErrorCode::IntegrityFailure,
            Self::Store(error) => error.error_code(),
            Self::Instrument(error) => error.code(),
            Self::Passive(_) | Self::Accounting(_) | Self::Random => {
                ErrorCode::DependencyUnavailable
            }
            Self::Evidence(_) | Self::FlowBeforeFloor | Self::DuplicateFlow => {
                ErrorCode::EvidenceIncomplete
            }
            Self::ObjectNotEstablished | Self::IdentityNotEstablished => {
                ErrorCode::IdentityUnestablished
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TargetOrigin(WireText);

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
    let body = observation.value.response.body.as_ref();
    let response_body = body.and_then(|body| body.bytes.clone()).unwrap_or_default();
    let completeness = match body {
        Some(body)
            if body.capture == BodyCapture::None
                && body.captured == 0
                && !observation.value.head_cut
                && (observation.value.method.as_deref() == Some("HEAD")
                    || observation.value.status.is_some_and(|status| {
                        (100..200).contains(&status) || status == 204 || status == 304
                    })) =>
        {
            // These responses are defined to carry no body. Teapot's exact
            // body metadata therefore uses `capture = none`; that is a
            // complete observation of absence, not lost evidence.
            Completeness::Complete
        }
        Some(body)
            if body.whole
                && body.capture == BodyCapture::Complete
                && !observation.value.head_cut =>
        {
            Completeness::Complete
        }
        Some(body) if body.bytes.is_some() => Completeness::Partial,
        _ => Completeness::Missing,
    };
    Ok(Readback {
        id,
        url: observation.value.url,
        method: observation.value.method,
        status: observation.value.status,
        response_body,
        completeness,
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
/// the final counter snapshot. No target request can be supplied by a caller.
pub fn execute_live(
    store: &mut Store,
    prepared: Prepared<LiveAdmission<'_>>,
    manifest: &ManifestRevision,
    teapot: &Teapot,
    evidence: &Evidence,
    origin: &TargetOrigin,
) -> Result<ExecutedRounds, RoundError> {
    let operations = RegisteredOperations::resolve(&prepared.experiment, manifest)?;
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
    let run = prepared.acceptance.run.id.clone();
    let capture = evidence.capture(&run)?;
    let mut io = LiveRoundIo::new(teapot, evidence, capture);
    let mut state = AcquisitionState::default();
    let mut mint = CanaryMint::new(OsEntropy);
    let execution = acquire_rounds(
        store,
        &run,
        &operations,
        origin,
        round_count,
        &mut mint,
        &mut io,
        &mut state,
    );
    let completion = if execution.is_ok() {
        Completion::Complete
    } else {
        Completion::Interrupted
    };
    // Counter observation ends immediately after the last possible target
    // effect. It must still run when later Evidence finalization or local
    // artifact linking fails.
    let accounting = prepared
        .admission
        .accounting
        .finish()
        .map_err(RoundError::Accounting);
    let capture = io.finalize(completion)?;
    link_originals(store, &run, &mut state, &capture)?;
    let cleanup = store.recover_run(&run)?.cleanup;
    let mut rounds = execution?;
    refresh_round_cleanup(store, &run, &mut rounds)?;
    Ok(ExecutedRounds {
        rounds,
        capture,
        accounting: accounting?,
        cleanup,
    })
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
    store: &mut Store,
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
        record_identity(&mut acquired, RoundFlow::I1, &i1.flows)?;
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
        record_identity(&mut acquired, RoundFlow::I2, &i2.flows)?;
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
            record_identity(&mut acquired, RoundFlow::I3, &i3.flows)?;
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
            record_identity(&mut acquired, RoundFlow::I4, &i4.flows)?;
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
    store: &mut Store,
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
            cleanup.ownership = CleanupOwnership::Unknown;
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
    store: &mut Store,
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
    store: &mut Store,
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
    store: &mut Store,
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
    store: &mut Store,
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
                    let key = format!("r{round}-s{number}-{}-{id}", flow_role(sent.role));
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
    let number = (round - 1)
        .checked_mul(RoundFlow::REQUIRED.len() as u64)
        .and_then(|base| {
            RoundFlow::REQUIRED
                .iter()
                .position(|flow| *flow == contract)
                .and_then(|index| base.checked_add(index as u64 + 1))
        })
        .ok_or(RoundError::Wire)?;
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
    store: &mut Store,
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

fn record_identity(
    round: &mut AcquiredRound,
    contract: RoundFlow,
    flows: &[AcquiredFlow],
) -> Result<(), RoundError> {
    let body = complete_body(flows).ok_or(RoundError::IdentityNotEstablished)?;
    let subject = serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|value| {
            value
                .get(IDENTITY_SUBJECT_FIELD)
                .and_then(|id| id.as_str())
                .map(str::to_owned)
        })
        .ok_or(RoundError::IdentityNotEstablished)?;
    round.identities.push(AcquiredIdentity {
        contract,
        subject_digest: Some(Sha256Digest::of(subject.as_bytes())),
    });
    Ok(())
}

fn link_originals(
    store: &mut Store,
    run: &RunId,
    state: &mut AcquisitionState,
    finalized: &Finalized,
) -> Result<(), RoundError> {
    let originals = finalized
        .original_artifacts
        .iter()
        .map(|original| (original.attachment.key.as_str(), original.artifact.clone()))
        .collect::<BTreeMap<_, _>>();
    if originals.len() != state.pending.len() {
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
        store.record_run(&run, None).unwrap();
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
            &mut store,
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
        link_originals(&mut store, &run.id, &mut state, &finalized).unwrap();
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
            &mut store,
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
        link_originals(&mut store, &run.id, &mut state, &finalized).unwrap();
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

        let error = acquire_rounds(
            &mut store,
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
            &mut store,
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
                &mut store,
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
                    &mut store,
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
            &mut store,
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
            &mut store,
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
        link_originals(&mut store, &run.id, &mut state, &finalized).unwrap();
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
            &mut store,
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
            &mut store,
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
            &mut store,
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
                &mut store,
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
            link_originals(&mut store, &run.id, &mut state, &finalized).unwrap();
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
                &mut store,
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
                &mut store,
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
            link_originals(&mut store, &run.id, &mut state, &finalized).unwrap();
            refresh_round_cleanup(&store, &run.id, &mut rounds).unwrap();
            assert_eq!(rounds.len(), 1, "lost cleanup reply cannot erase the round");
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
            assert_eq!(store.recover_run(&run.id).unwrap().cleanup, summary);
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
            &mut store,
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
        link_originals(&mut store, &run.id, &mut state, &finalized).unwrap();
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
                &mut store,
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
            &mut store,
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
            &mut store,
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
            &mut store,
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
        link_originals(&mut store, &run.id, &mut state, &finalized).unwrap();

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
