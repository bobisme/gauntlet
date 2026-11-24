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
    domain::RunStep,
    engagement::ManifestRevision,
    evidence::{Capture, Completion, Evidence, EvidenceError, Finalized},
    ids::{RunId, SessionName, WireText},
    operations::{
        FieldSpec, IDENTITY_PATH, IDENTITY_SUBJECT_FIELD, OBJECT_ID_FIELD, REGISTRY_ID,
        RegisteredOperations, RegistryError,
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
    wire::{Artifact, Completeness, Effect, ErrorCode, Flow},
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
}

#[derive(Debug)]
pub struct ExecutedRounds {
    pub rounds: Vec<AcquiredRound>,
    pub capture: Finalized,
    pub accounting: AccountingObservation,
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
        }
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
}

#[derive(Debug)]
struct Readback {
    id: u64,
    url: Option<String>,
    method: Option<String>,
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
    Ok(ExecutedRounds {
        rounds: execution?,
        capture,
        accounting: accounting?,
    })
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
        record_identity(&mut acquired, RoundFlow::I1, &i1)?;
        acquired.flows.extend(i1);

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
        record_identity(&mut acquired, RoundFlow::I2, &i2)?;
        acquired.flows.extend(i2);

        let p = execute_step(
            store,
            run,
            operations,
            round,
            RoundFlow::P,
            vec![RequestAction::plant(
                collection.clone(),
                operations.owner_session.clone(),
                &primary,
            )?],
            io,
            state,
        )?;
        let primary_id = object_id(&p)?;
        acquired.flows.extend(p);

        let p2 = execute_step(
            store,
            run,
            operations,
            round,
            RoundFlow::P2,
            vec![RequestAction::plant(
                collection.clone(),
                operations.owner_session.clone(),
                &control,
            )?],
            io,
            state,
        )?;
        let control_id = object_id(&p2)?;
        acquired.flows.extend(p2);

        let primary_url = object_url(origin, operations.collection, &primary_id)?;
        let control_url = object_url(origin, operations.collection, &control_id)?;
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
            acquired.flows.extend(execute_step(
                store,
                run,
                operations,
                round,
                contract,
                vec![RequestAction::send(Method::Get, url, session)],
                io,
                state,
            )?);
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
        record_identity(&mut acquired, RoundFlow::I3, &i3)?;
        acquired.flows.extend(i3);

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
        record_identity(&mut acquired, RoundFlow::I4, &i4)?;
        acquired.flows.extend(i4);

        acquired.flows.extend(execute_step(
            store,
            run,
            operations,
            round,
            RoundFlow::C,
            vec![
                RequestAction::send(
                    Method::Delete,
                    primary_url,
                    operations.owner_session.clone(),
                ),
                RequestAction::send(
                    Method::Delete,
                    control_url,
                    operations.owner_session.clone(),
                ),
            ],
            io,
            state,
        )?);
        rounds.push(acquired);
    }
    Ok(rounds)
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
) -> Result<Vec<AcquiredFlow>, RoundError> {
    let dispatch = operations
        .dispatch_spec(contract.as_str())
        .ok_or(RoundError::AdmissionMismatch)?;
    let expected_session = operations.session(dispatch.principal).as_str();
    if actions.len() as u64 != dispatch.actions
        || actions
            .iter()
            .any(|action| action.kind != "send" || action.session != expected_session)
    {
        return Err(RoundError::AdmissionMismatch);
    }
    let number = (round - 1)
        .checked_mul(RoundFlow::REQUIRED.len() as u64)
        .and_then(|base| {
            RoundFlow::REQUIRED
                .iter()
                .position(|flow| *flow == contract)
                .and_then(|index| base.checked_add(index as u64 + 1))
        })
        .ok_or(RoundError::Wire)?;
    let floor = io.flow_floor()?;
    let intent = RequestIntent {
        registry: REGISTRY_ID,
        registry_digest: &operations.registry_digest,
        round,
        flow: contract.as_str(),
        actions: &actions,
    };
    let request = serde_json::to_vec(&intent).map_err(|_| RoundError::Wire)?;
    let mut step = RunStep {
        number,
        step: format!("round.{round}.{}", contract.as_str())
            .try_into()
            .map_err(|_| RoundError::Wire)?,
        request_digest: Sha256Digest::of(&request),
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
    let mut effect = Effect::None;
    let mut primary_reference = None;
    for action in &actions {
        let receipt = match io.dispatch(action) {
            Ok(receipt) => receipt,
            Err(error) => {
                return persist_uncertain(store, run, state, step, primary_reference, error);
            }
        };
        effect = combine_effect(effect, receipt.dispatch);
        if primary_reference.is_none() {
            primary_reference = match dispatch_reference(receipt.dispatch) {
                Ok(reference) => Some(reference),
                Err(error) => {
                    return persist_uncertain(store, run, state, step, primary_reference, error);
                }
            };
        }
        for sent in receipt.flows {
            let label = format!("{}.{}", contract.as_str(), flow_role(sent.role));
            match sent.reference {
                FlowReference::Missing => {
                    state.sequence = match state.sequence.checked_add(1) {
                        Some(sequence) => sequence,
                        None => {
                            return persist_uncertain(
                                store,
                                run,
                                state,
                                step,
                                primary_reference,
                                RoundError::Wire,
                            );
                        }
                    };
                    let reference = Flow {
                        step: match label.clone().try_into() {
                            Ok(label) => label,
                            Err(_) => {
                                return persist_uncertain(
                                    store,
                                    run,
                                    state,
                                    step,
                                    primary_reference,
                                    RoundError::Wire,
                                );
                            }
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
                        return persist_uncertain(
                            store,
                            run,
                            state,
                            step,
                            primary_reference,
                            RoundError::FlowBeforeFloor,
                        );
                    }
                    if !retained.insert(id) {
                        return persist_uncertain(
                            store,
                            run,
                            state,
                            step,
                            primary_reference,
                            RoundError::DuplicateFlow,
                        );
                    }
                    let readback = match io.read_flow(id) {
                        Ok(readback) => readback,
                        Err(error) => {
                            return persist_uncertain(
                                store,
                                run,
                                state,
                                step,
                                primary_reference,
                                error,
                            );
                        }
                    };
                    if readback.id != id
                        || matches!(sent.role, FlowRole::Request | FlowRole::Retry)
                            && (readback.url.as_deref() != Some(action.url.as_str())
                                || readback.method.as_deref() != Some(action.method.as_str()))
                    {
                        return persist_uncertain(
                            store,
                            run,
                            state,
                            step,
                            primary_reference,
                            RoundError::ReadbackMismatch,
                        );
                    }
                    let key = format!("r{round}-s{number}-{}-{id}", flow_role(sent.role));
                    if let Err(error) = io.attach(&key, &readback.original) {
                        return persist_uncertain(
                            store,
                            run,
                            state,
                            step,
                            primary_reference,
                            error,
                        );
                    }
                    state.sequence = match state.sequence.checked_add(1) {
                        Some(sequence) => sequence,
                        None => {
                            return persist_uncertain(
                                store,
                                run,
                                state,
                                step,
                                primary_reference,
                                RoundError::Wire,
                            );
                        }
                    };
                    let reference = Flow {
                        step: match label.try_into() {
                            Ok(label) => label,
                            Err(_) => {
                                return persist_uncertain(
                                    store,
                                    run,
                                    state,
                                    step,
                                    primary_reference,
                                    RoundError::Wire,
                                );
                            }
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
    }
    step.instrument_reference = primary_reference;
    step.effects = Some(effect);
    store.record_step(run, &step)?;
    state.steps.insert(number, step);
    Ok(acquired)
}

fn persist_uncertain<T>(
    store: &mut Store,
    run: &RunId,
    state: &mut AcquisitionState,
    mut step: RunStep,
    instrument_reference: Option<WireText>,
    error: RoundError,
) -> Result<T, RoundError> {
    step.instrument_reference = instrument_reference;
    step.effects = Some(Effect::Unknown);
    store.record_step(run, &step)?;
    state.steps.insert(step.number, step);
    Err(error)
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
    if id.is_empty()
        || id.len() > 256
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(RoundError::ObjectNotEstablished);
    }
    origin.join(&format!("{collection}/{id}"))
}

fn complete_body(flows: &[AcquiredFlow]) -> Option<&[u8]> {
    flows
        .iter()
        .rev()
        .find(|flow| {
            flow.reference.flow_id.is_some()
                && flow.reference.completeness == Completeness::Complete
                && matches!(
                    flow.reference.step.as_str().rsplit('.').next(),
                    Some("request" | "retry")
                )
        })
        .map(|flow| flow.response_body.as_slice())
}

fn object_id(flows: &[AcquiredFlow]) -> Result<String, RoundError> {
    let body = complete_body(flows).ok_or(RoundError::ObjectNotEstablished)?;
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|value| {
            value
                .get(OBJECT_ID_FIELD)
                .and_then(|id| id.as_str())
                .map(str::to_owned)
        })
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
        requests: Vec<RequestAction>,
        reads: BTreeMap<u64, Readback>,
        attached: Vec<(String, Vec<u8>)>,
        objects: BTreeMap<String, BTreeMap<String, String>>,
        next_object: u64,
    }

    impl FakeIo {
        fn response(&mut self, action: &RequestAction) -> Vec<u8> {
            if action.method == Method::Post {
                self.next_object += 1;
                let id = format!("object-{}", self.next_object);
                let fields: BTreeMap<String, String> =
                    serde_json::from_str(action.body.as_deref().unwrap()).unwrap();
                self.objects.insert(id.clone(), fields);
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
            Ok((self.highest > 0).then_some(self.highest))
        }

        fn dispatch(&mut self, action: &RequestAction) -> Result<DispatchReceipt, RoundError> {
            self.highest += 1;
            let id = self.highest;
            let response = self.response(action);
            self.reads.insert(
                id,
                Readback {
                    id,
                    url: Some(action.url.clone()),
                    method: Some(action.method.as_str().to_owned()),
                    response_body: response,
                    completeness: Completeness::Complete,
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
        let finalized = io.finalize(Completion::Complete).unwrap();
        link_originals(&mut store, &run.id, &mut state, &finalized).unwrap();

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
            assert_eq!(acquired.len(), expected_flows);
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
