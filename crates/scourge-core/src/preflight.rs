//! Effect-free verifier preflight and custody of its conflict locks.
//!
//! The coordinator deliberately has no dispatch API. It freezes a registered
//! experiment, durably declares the keyed run, takes all local conflict locks,
//! checks the pinned engagement and instrument, and retains the experiment in
//! Evidence. A caller can only receive [`Prepared`] after every check succeeds;
//! target traffic belongs to the later execution step.

use std::{collections::BTreeSet, fs::File, path::Path};

use rustix::fs::{self as rfs, FileType, Mode, OFlags};

use crate::{
    canonical::{JsonError, Sha256Digest},
    domain::Run,
    engagement::{ManifestRevision, PassRef, PassRefusal, PassState, RequiredEnforcement},
    evidence::{Evidence, EvidenceError, RecordKind, RecordRequest},
    ids::{ArtifactId, SessionName, WireText},
    json_input::MAX_SAFE_INTEGER,
    operations::{
        ANONYMOUS_SESSION, DispatchPrincipal, ROUND_DISPATCHES, RegisteredOperations,
        RegistryError, instrument_session,
    },
    request::NormalizedInput,
    store::{RequestScope, RunAcceptance, Store, StoreError, VerificationPins},
    teapot::{
        GateRefusal, InstrumentObservation, Teapot,
        accounting::{
            AccountingBinding, AccountingCapture, AccountingFailure, AccountingRefusal, MacroPlan,
        },
    },
    template::{Claim, FrozenExperiment, MissingSlots, ResolveError, Templates},
    wire::{AbsolutePath, Artifact, ErrorCode, RunState},
};

const LOCK_DIRECTORY: &str = "run-locks";
const EXPERIMENT_TRANSFORMATION: &str = "freeze registered verifier experiment";
const EXPERIMENT_VERSION: &str = "scourge.preflight.v1";

mod sealed {
    pub trait Sealed {}
}

/// A private local lock namespace. Every instance opened on the same directory
/// contends through kernel `flock`, including independent Scourge processes.
pub struct RunLocks {
    directory: File,
}

#[derive(Debug, thiserror::Error)]
pub enum LockError {
    #[error("the verifier lock namespace is unavailable or unsafe")]
    Unsafe,
    #[error("another run holds a required verifier conflict lock")]
    Busy,
}

impl LockError {
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Unsafe => ErrorCode::IntegrityFailure,
            Self::Busy => ErrorCode::ConflictingRun,
        }
    }
}

impl RunLocks {
    /// Open (and, on first use, create) the private lock directory beneath an
    /// operator-owned parent that is not group/world writable. Symlinks fail
    /// closed.
    pub fn open(root: &Path) -> Result<Self, LockError> {
        let root = File::from(
            rfs::open(
                root,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| LockError::Unsafe)?,
        );
        trusted_parent(&root)?;
        match rfs::mkdirat(&root, LOCK_DIRECTORY, Mode::from_raw_mode(0o700)) {
            Ok(()) | Err(rustix::io::Errno::EXIST) => {}
            Err(_) => return Err(LockError::Unsafe),
        }
        let directory = File::from(
            rfs::openat(
                &root,
                LOCK_DIRECTORY,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| LockError::Unsafe)?,
        );
        private_directory(&directory)?;
        Ok(Self { directory })
    }

    fn acquire(&self, keys: &BTreeSet<String>) -> Result<RunLease, LockError> {
        let mut files = Vec::with_capacity(keys.len());
        for key in keys {
            let name = format!("lock-{}", Sha256Digest::of(key.as_bytes()).as_str());
            let file = File::from(
                rfs::openat(
                    &self.directory,
                    name,
                    OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::from_raw_mode(0o600),
                )
                .map_err(|_| LockError::Unsafe)?,
            );
            private_file(&file)?;
            match rfs::flock(&file, rfs::FlockOperation::NonBlockingLockExclusive) {
                Ok(()) => files.push(file),
                Err(rustix::io::Errno::WOULDBLOCK) => return Err(LockError::Busy),
                Err(_) => return Err(LockError::Unsafe),
            }
        }
        Ok(RunLease { files })
    }
}

fn private_directory(file: &File) -> Result<(), LockError> {
    let stat = rfs::fstat(file).map_err(|_| LockError::Unsafe)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || stat.st_uid != rustix::process::geteuid().as_raw()
        || stat.st_mode & 0o077 != 0
    {
        return Err(LockError::Unsafe);
    }
    Ok(())
}

fn trusted_parent(file: &File) -> Result<(), LockError> {
    let stat = rfs::fstat(file).map_err(|_| LockError::Unsafe)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || stat.st_uid != rustix::process::geteuid().as_raw()
        || stat.st_mode & 0o022 != 0
    {
        return Err(LockError::Unsafe);
    }
    Ok(())
}

fn private_file(file: &File) -> Result<(), LockError> {
    let stat = rfs::fstat(file).map_err(|_| LockError::Unsafe)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_nlink != 1
        || stat.st_uid != rustix::process::geteuid().as_raw()
        || stat.st_mode & 0o077 != 0
    {
        return Err(LockError::Unsafe);
    }
    Ok(())
}

/// Ownership of every pass/session/resource lock for one prepared run.
#[derive(Debug)]
pub struct RunLease {
    files: Vec<File>,
}

impl Drop for RunLease {
    fn drop(&mut self) {
        for file in &self.files {
            let _ = rfs::flock(file, rfs::FlockOperation::Unlock);
        }
    }
}

/// The locally resolved request and revisions, before opening any adapters.
/// A retry reuses the service-minted request key carried by `run`.
pub struct PreflightDeclaration<'a> {
    pub scope: &'a RequestScope,
    pub input: &'a NormalizedInput,
    pub run: &'a Run,
    pub claim: &'a Claim,
    pub lead_revision: u64,
    pub engagement: &'a ManifestRevision,
    pub manifest_artifact: &'a Artifact,
}

impl PreflightDeclaration<'_> {
    fn pins(&self) -> VerificationPins<'_> {
        VerificationPins {
            lead: &self.claim.lead,
            lead_revision: self.lead_revision,
            manifest: self.engagement,
            manifest_artifact: self.manifest_artifact,
        }
    }
}

/// Proof that this exact request passed canonical resolution and the compiled
/// plan checks. Only the preflight module can construct it.
pub(crate) struct ValidatedDeclaration<'a> {
    request: &'a PreflightDeclaration<'a>,
}

impl<'a> ValidatedDeclaration<'a> {
    pub(crate) fn parts(
        self,
    ) -> (
        &'a RequestScope,
        &'a NormalizedInput,
        &'a Run,
        VerificationPins<'a>,
    ) {
        let request = self.request;
        (request.scope, request.input, request.run, request.pins())
    }
}

/// The pass observation made by the bound adapter after local declaration.
pub struct PreflightPass<'a> {
    pub pass_reference: &'a PassRef,
    pub pass_state: PassState<'a>,
    pub pass_file: &'a AbsolutePath,
}

pub struct PreflightRequest<'a> {
    pub declaration: PreflightDeclaration<'a>,
    pub pass: PreflightPass<'a>,
}

/// A durable acceptance. Only a subsequent live preparation can acquire
/// conflicts and open the dependencies.
pub struct DeclaredPreflight<'a> {
    acceptance: RunAcceptance,
    request: PreflightDeclaration<'a>,
    resolved: Option<ResolvedPreflight>,
}

struct ResolvedPreflight {
    experiment: FrozenExperiment,
    bytes: Vec<u8>,
    plan: RegisteredExecutionPlan,
    sessions: Vec<SessionName>,
    keys: BTreeSet<String>,
}

impl std::fmt::Debug for DeclaredPreflight<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DeclaredPreflight")
            .field("acceptance", &self.acceptance)
            .finish_non_exhaustive()
    }
}

impl DeclaredPreflight<'_> {
    pub fn acceptance(&self) -> &RunAcceptance {
        &self.acceptance
    }
}

/// The passive ceiling probe and conservative request bound derived from the
/// exact compiled recipe named by the frozen experiment. Nothing here is
/// caller-selectable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegisteredExecutionPlan {
    pub registry_digest: Sha256Digest,
    pub round_count: u64,
    /// Ordered dispatches in each frozen round.
    pub dispatches: Vec<PlannedDispatch>,
    pub requests_per_round: u64,
    pub required_requests: u64,
    /// Passive dry-run probe only; execution uses compiled direct requests.
    pub macro_name: WireText,
    pub macro_session: SessionName,
    pub expected_macro_requests: u64,
}

/// One compiled dispatch, in execution order within a round.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlannedDispatch {
    pub flow: &'static str,
    pub principal: PlannedPrincipal,
    pub session: SessionName,
    pub actions: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlannedPrincipal {
    Owner,
    Other,
    Anonymous,
}

/// Accepted run and pass pins supplied to the passive adapter check.
pub struct PreflightAccounting<'a> {
    run: &'a Run,
    pass_digest: &'a Sha256Digest,
    pass_file: &'a AbsolutePath,
}

/// The checks whose implementations own the qualified Teapot and Evidence
/// adapters. Test implementations can prove ordering without opening a process
/// or a network path.
pub trait PreflightServices: sealed::Sealed {
    type Admission;

    fn admit(
        &self,
        sessions: &[SessionName],
        plan: &RegisteredExecutionPlan,
        requirement: RequiredEnforcement,
        binding: PreflightAccounting<'_>,
    ) -> Result<Self::Admission, PreflightError>;

    fn record_experiment(
        &self,
        request_key: &str,
        bytes: &[u8],
        manifest: &Artifact,
    ) -> Result<Artifact, PreflightError>;

    fn read_experiment(&self, artifact: &ArtifactId)
    -> Result<(Artifact, Vec<u8>), PreflightError>;
}

/// Production adapter bundle. Its admission retains both the passive gate
/// observation and the before-accounting capture for the execution phase.
pub struct LiveServices<'a> {
    pub teapot: &'a Teapot,
    pub evidence: &'a Evidence,
}

impl sealed::Sealed for LiveServices<'_> {}

/// Production admission is opaque outside this crate. In particular, an
/// external caller cannot replace the accounting capture after preflight.
#[derive(Debug)]
pub struct LiveAdmission<'a> {
    pub(crate) instrument: InstrumentObservation,
    pub(crate) accounting: AccountingCapture<'a>,
    teapot: &'a Teapot,
}

impl LiveAdmission<'_> {
    /// Read-only passive instrument observation retained at admission.
    pub fn instrument(&self) -> &InstrumentObservation {
        &self.instrument
    }

    /// Read-only accounting evidence retained at admission.
    pub fn accounting(&self) -> &AccountingCapture<'_> {
        &self.accounting
    }
}

impl<'a> PreflightServices for LiveServices<'a> {
    type Admission = LiveAdmission<'a>;

    fn admit(
        &self,
        sessions: &[SessionName],
        plan: &RegisteredExecutionPlan,
        requirement: RequiredEnforcement,
        binding: PreflightAccounting<'_>,
    ) -> Result<Self::Admission, PreflightError> {
        let instrument = self
            .teapot
            .verifier_preflight(sessions, requirement)
            .map_err(PreflightError::Gate)?;
        let observed = instrument
            .pass
            .as_ref()
            .ok_or(PreflightError::AccountingPreflight(
                AccountingRefusal::PassUnavailable,
            ))?;
        if &observed.digest != binding.pass_digest || &observed.file != binding.pass_file {
            return Err(PreflightError::AccountingPreflight(
                AccountingRefusal::PassMismatch,
            ));
        }
        let mut accounting = self
            .teapot
            .begin_accounting(
                AccountingBinding {
                    run_id: binding.run.id.clone(),
                    request_key: binding.run.request_key.clone(),
                    pass_id: observed.id.clone(),
                    pass_digest: binding.pass_digest.clone(),
                    pass_file: binding.pass_file.clone(),
                },
                Some(MacroPlan {
                    name: &plan.macro_name,
                    session: &plan.macro_session,
                }),
            )
            .map_err(PreflightError::Accounting)?;
        accounting
            .preflight_registered(plan.required_requests, plan.expected_macro_requests)
            .map_err(PreflightError::AccountingPreflight)?;
        Ok(LiveAdmission {
            instrument,
            accounting,
            teapot: self.teapot,
        })
    }

    fn record_experiment(
        &self,
        request_key: &str,
        bytes: &[u8],
        manifest: &Artifact,
    ) -> Result<Artifact, PreflightError> {
        let input = [manifest.clone()];
        self.evidence
            .record(RecordRequest {
                key: request_key,
                kind: RecordKind::Experiment,
                bytes,
                inputs: &input,
                transformation: EXPERIMENT_TRANSFORMATION,
                version: EXPERIMENT_VERSION,
            })
            .map(|artifact| artifact.reference)
            .map_err(PreflightError::Evidence)
    }

    fn read_experiment(
        &self,
        artifact: &ArtifactId,
    ) -> Result<(Artifact, Vec<u8>), PreflightError> {
        self.evidence
            .read_json(artifact)
            .map(|read| (read.artifact.reference, read.bytes))
            .map_err(PreflightError::Evidence)
    }
}

/// A fully admitted run. Keeping this value alive keeps its deterministic
/// conflict locks alive; dropping it safely releases them on every error path.
/// Authority-bearing fields are private so external callers can inspect but
/// cannot replace an accepted run, experiment, artifact, plan, or admission.
#[derive(Debug)]
pub struct Prepared<A> {
    pub(crate) acceptance: RunAcceptance,
    pub(crate) experiment: FrozenExperiment,
    pub(crate) artifact: Artifact,
    pub(crate) execution_plan: RegisteredExecutionPlan,
    pub(crate) admission: A,
    pub(crate) authority: ExecutionAuthority,
    lease: RunLease,
}

#[derive(Debug)]
pub(crate) struct ExecutionAuthority {
    scope: RequestScope,
    acceptance: RunAcceptance,
}

impl ExecutionAuthority {
    pub(crate) fn identity(&self) -> (&RequestScope, &RunAcceptance) {
        (&self.scope, &self.acceptance)
    }
}

impl<A> Prepared<A> {
    /// Immutable durable acceptance admitted for this execution.
    pub fn acceptance(&self) -> &RunAcceptance {
        &self.acceptance
    }

    /// Immutable frozen experiment admitted for this execution.
    pub fn experiment(&self) -> &FrozenExperiment {
        &self.experiment
    }

    /// Immutable retained experiment artifact admitted for this execution.
    pub fn artifact(&self) -> &Artifact {
        &self.artifact
    }

    /// Immutable service admission retained for this execution.
    pub fn admission(&self) -> &A {
        &self.admission
    }

    /// Immutable exact dispatch budget admitted with this prepared run.
    pub fn execution_plan(&self) -> &RegisteredExecutionPlan {
        &self.execution_plan
    }

    /// Explicitly expose that this value still owns its lock lease without
    /// exposing lock file descriptors or paths.
    pub fn holds_locks(&self) -> bool {
        !self.lease.files.is_empty()
    }

    /// Explicitly abandon a successfully prepared run before its first step.
    /// The store verifies that no step intent exists before releasing durable
    /// ownership; consuming `self` then releases the live-process flocks. A
    /// crash that cannot call this method is recovered by the same predicate
    /// inside the ordered manifest-amendment transaction.
    pub fn abandon(self, store: &mut Store) -> Result<(), StoreError> {
        store.release_unstarted_conflicts(&self.acceptance.run.id)
    }
}

impl Prepared<LiveAdmission<'_>> {
    /// Re-establish every authority-sensitive admission binding immediately
    /// before the first durable execution write or target request.
    pub(crate) fn validate_live_execution(
        &self,
        manifest: &ManifestRevision,
        teapot: &Teapot,
    ) -> Result<(), PreflightError> {
        let (bytes, digest) = self
            .experiment
            .freeze()
            .map_err(PreflightError::Canonical)?;
        if bytes.is_empty()
            || digest != self.acceptance.run.experiment_digest
            || self.artifact.digest != digest
            || self.experiment.engagement.revision != manifest.revision()
            || self.experiment.engagement.digest != *manifest.digest()
            || self.acceptance.engagement_revision != manifest.revision()
        {
            return Err(PreflightError::ExecutionMismatch);
        }
        let plan =
            registered_execution_plan(&self.experiment, manifest, self.execution_plan.round_count)?;
        if plan != self.execution_plan {
            return Err(PreflightError::ExecutionMismatch);
        }
        let (scope, authority_acceptance) = self.authority.identity();
        if authority_acceptance != &self.acceptance
            || scope.engagement != self.acceptance.run.engagement
            || !std::ptr::eq(self.admission.teapot, teapot)
        {
            return Err(PreflightError::ExecutionMismatch);
        }
        let observed = self
            .admission
            .instrument
            .pass
            .as_ref()
            .ok_or(PreflightError::ExecutionMismatch)?;
        let binding = AccountingBinding {
            run_id: self.acceptance.run.id.clone(),
            request_key: self.acceptance.run.request_key.clone(),
            pass_id: observed.id.clone(),
            pass_digest: manifest.pass_digest().clone(),
            pass_file: observed.file.clone(),
        };
        if observed.digest != *manifest.pass_digest()
            || self
                .admission
                .accounting
                .evidence()
                .engine()
                .project_id
                .as_str()
                != manifest.settings().instrument.project.as_str()
            || !self.admission.accounting.matches_registered(
                teapot,
                &binding,
                self.execution_plan.required_requests,
            )
        {
            return Err(PreflightError::ExecutionMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PreflightError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("this request key already crossed the local execution-start boundary")]
    Replay,
    #[error("the declared run does not bind the resolved frozen experiment")]
    ExperimentMismatch,
    #[error("the admitted round count must be positive and fit the compiled request budget")]
    RoundCount,
    #[error(transparent)]
    Resolve(#[from] ResolveError),
    #[error("the registered experiment has unresolved required slots")]
    MissingSlots(MissingSlots),
    #[error(transparent)]
    Pass(#[from] PassRefusal),
    #[error(transparent)]
    Lock(#[from] LockError),
    #[error(transparent)]
    Gate(GateRefusal),
    #[error(transparent)]
    Accounting(Box<AccountingFailure>),
    #[error(transparent)]
    AccountingPreflight(AccountingRefusal),
    #[error(transparent)]
    Evidence(EvidenceError),
    #[error("the retained experiment did not match the exact frozen bytes and digest")]
    EvidenceMismatch,
    #[error("the registered experiment could not be encoded canonically")]
    Canonical(JsonError),
    #[error("a frozen instrument session is not usable by the bound adapter")]
    Session,
    #[error("the live execution does not match the exact admitted authority")]
    ExecutionMismatch,
}

impl PreflightError {
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Store(error) => error.error_code(),
            Self::Replay | Self::Lock(LockError::Busy) => ErrorCode::ConflictingRun,
            Self::ExperimentMismatch | Self::ExecutionMismatch => ErrorCode::IntegrityFailure,
            Self::RoundCount => ErrorCode::UsageError,
            Self::Resolve(error) => error.code(),
            Self::MissingSlots(_) => ErrorCode::SlotsIncomplete,
            Self::Pass(PassRefusal::WrongReference) => ErrorCode::ScopeRefused,
            Self::Pass(PassRefusal::Changed | PassRefusal::Expired | PassRefusal::Revoked) => {
                ErrorCode::AuthorityRequired
            }
            Self::Lock(error) => error.code(),
            Self::Gate(error) => error.code(),
            Self::Accounting(error) => error.error().code(),
            Self::AccountingPreflight(error) => error.code(),
            Self::Evidence(error) => evidence_code(error),
            Self::EvidenceMismatch | Self::Canonical(_) => ErrorCode::IntegrityFailure,
            Self::Session => ErrorCode::ScopeRefused,
        }
    }
}

fn evidence_code(error: &EvidenceError) -> ErrorCode {
    match error {
        EvidenceError::Integrity
        | EvidenceError::ChangedSnapshot
        | EvidenceError::Protocol
        | EvidenceError::LineageUnverified => ErrorCode::IntegrityFailure,
        EvidenceError::UnqualifiedInvestigation
        | EvidenceError::ImportRoot
        | EvidenceError::BackendOutputTooLarge { .. }
        | EvidenceError::BackendTimeout { .. }
        | EvidenceError::StagingBusy
        | EvidenceError::ScratchUnsafe
        | EvidenceError::Backend
        | EvidenceError::BackendFailed { .. }
        | EvidenceError::Io(_) => ErrorCode::DependencyUnavailable,
        _ => ErrorCode::EvidenceIncomplete,
    }
}

/// Reopen the original receipt for exact scoped input, or resolve the
/// experiment and atomically charge a new run against the current allowance.
pub fn declare<'a>(
    store: &mut Store,
    request: PreflightDeclaration<'a>,
) -> Result<DeclaredPreflight<'a>, PreflightError> {
    if let Some(acceptance) =
        store.replay_existing_request(request.scope, &request.run.request_key, request.input)?
    {
        return Ok(DeclaredPreflight {
            acceptance,
            request,
            resolved: None,
        });
    }
    let (validated, resolved) = validate_new_declaration(&request)?;
    let acceptance = store.declare_verification(validated)?;
    // The acceptance may belong to a concurrent identical caller. Cache
    // only a resolution that matches the accepted experiment.
    let resolved =
        (acceptance.run.experiment_digest == request.run.experiment_digest).then_some(resolved);
    Ok(DeclaredPreflight {
        acceptance,
        request,
        resolved,
    })
}

fn validate_new_declaration<'a>(
    request: &'a PreflightDeclaration<'a>,
) -> Result<(ValidatedDeclaration<'a>, ResolvedPreflight), PreflightError> {
    if request.input.command() != "verify" {
        return Err(StoreError::Schema.into());
    }
    let resolved = resolve_preflight(request, &request.run.experiment_digest)?;
    Ok((ValidatedDeclaration { request }, resolved))
}

fn resolve_preflight(
    request: &PreflightDeclaration<'_>,
    expected_digest: &Sha256Digest,
) -> Result<ResolvedPreflight, PreflightError> {
    let experiment = Templates::resolve(request.claim, request.engagement)?
        .ready()
        .map_err(PreflightError::MissingSlots)?;
    let (bytes, digest) = experiment.freeze().map_err(PreflightError::Canonical)?;
    if &digest != expected_digest
        || experiment.engagement.revision != request.engagement.revision()
        || experiment.engagement.digest != *request.engagement.digest()
        || request.manifest_artifact.digest != *request.engagement.digest()
    {
        return Err(PreflightError::ExperimentMismatch);
    }

    let round_count = request
        .input
        .arguments()
        .get("rounds")
        .and_then(serde_json::Value::as_u64)
        .ok_or(PreflightError::RoundCount)?;
    let plan = registered_execution_plan(&experiment, request.engagement, round_count)?;
    let (sessions, keys) = lock_inputs(&experiment, request.engagement)?;
    Ok(ResolvedPreflight {
        experiment,
        bytes,
        plan,
        sessions,
        keys,
    })
}

/// Local conflict ownership for the exact canonical plan.
struct LockedPreflight<'a> {
    acceptance: RunAcceptance,
    request: PreflightDeclaration<'a>,
    resolved: ResolvedPreflight,
    lease: RunLease,
}

/// Acquire the compiled conflict set and fence engagement amendments and stops.
fn lock_declared<'a>(
    store: &mut Store,
    locks: &RunLocks,
    declared: DeclaredPreflight<'a>,
) -> Result<LockedPreflight<'a>, PreflightError> {
    let DeclaredPreflight {
        acceptance,
        request,
        resolved,
    } = declared;
    if acceptance.run.state != RunState::Declared || !acceptance.run.steps.is_empty() {
        return Err(PreflightError::Replay);
    }
    if request.engagement.revision() != acceptance.engagement_revision {
        return Err(StoreError::RevisionConflict.into());
    }
    let resolved = match resolved {
        Some(resolved) => resolved,
        None => resolve_preflight(&request, &acceptance.run.experiment_digest)?,
    };
    let lease = locks.acquire(&resolved.keys)?;
    store.claim_verification_conflicts(
        request.scope,
        &acceptance,
        &request.pins(),
        &resolved.keys,
    )?;
    Ok(LockedPreflight {
        acceptance,
        request,
        resolved,
        lease,
    })
}

/// Acquire local conflict ownership before invoking the adapter opener.
///
/// ```compile_fail
/// use scourge_core::preflight::lock_declared;
/// ```
///
/// ```compile_fail
/// use scourge_core::store::Store;
/// let _ = Store::record_step;
/// ```
pub fn prepare_declared<'s, 'p, S: PreflightServices + 's>(
    store: &mut Store,
    locks: &RunLocks,
    declared: DeclaredPreflight<'_>,
    open: impl FnOnce() -> Result<(&'s S, PreflightPass<'p>), PreflightError>,
) -> Result<Prepared<S::Admission>, PreflightError> {
    let LockedPreflight {
        acceptance,
        request,
        resolved,
        lease,
    } = lock_declared(store, locks, declared)?;
    let ResolvedPreflight {
        experiment,
        bytes,
        plan,
        sessions,
        ..
    } = resolved;
    let engagement = request.engagement;
    let run_id = acceptance.run.id.clone();

    let outcome = (|| {
        let (services, pass) = open()?;
        engagement.check_new_run(pass.pass_reference, pass.pass_state)?;

        let admission = services.admit(
            &sessions,
            &plan,
            engagement.settings().required_enforcement,
            PreflightAccounting {
                run: &acceptance.run,
                pass_digest: engagement.pass_digest(),
                pass_file: pass.pass_file,
            },
        )?;
        let authority = ExecutionAuthority {
            scope: request.scope.clone(),
            acceptance: acceptance.clone(),
        };

        let artifact = services.record_experiment(
            acceptance.run.request_key.as_str(),
            &bytes,
            request.manifest_artifact,
        )?;
        if artifact.digest != acceptance.run.experiment_digest {
            return Err(PreflightError::EvidenceMismatch);
        }
        let (read_reference, read_bytes) = services.read_experiment(&artifact.artifact_id)?;
        if read_reference != artifact
            || read_bytes != bytes
            || Sha256Digest::of(&read_bytes) != artifact.digest
        {
            return Err(PreflightError::EvidenceMismatch);
        }
        store
            .execution_store(&authority)?
            .link_experiment(&acceptance.run.id, &artifact)?;

        Ok(Prepared {
            acceptance,
            experiment,
            artifact,
            execution_plan: plan,
            admission,
            authority,
            lease,
        })
    })();
    if outcome.is_err() {
        store.release_unstarted_conflicts(&run_id)?;
    }
    outcome
}

/// Prepare with adapters and a pass observation that are already available.
/// Use [`declare`] and [`prepare_declared`] to open dependencies after the
/// local declaration and conflict claim.
pub fn prepare<S: PreflightServices>(
    store: &mut Store,
    locks: &RunLocks,
    services: &S,
    request: PreflightRequest<'_>,
) -> Result<Prepared<S::Admission>, PreflightError> {
    let declared = declare(store, request.declaration)?;
    prepare_declared(store, locks, declared, || Ok((services, request.pass)))
}

fn lock_inputs(
    experiment: &FrozenExperiment,
    engagement: &ManifestRevision,
) -> Result<(Vec<SessionName>, BTreeSet<String>), PreflightError> {
    let project = engagement.settings().instrument.project.as_str();
    let mut sessions: BTreeSet<SessionName> = BTreeSet::new();
    for principal in experiment.principals.values() {
        sessions.insert(
            instrument_session(principal.session.as_str()).map_err(registry_preflight_error)?,
        );
        if let Some(session) = &principal.verifier_session {
            sessions
                .insert(instrument_session(session.as_str()).map_err(registry_preflight_error)?);
        }
    }
    sessions.insert(
        ANONYMOUS_SESSION
            .parse()
            .map_err(|_| PreflightError::Session)?,
    );
    let mut keys = BTreeSet::from([format!("pass:{}", engagement.settings().pass_ref.as_str())]);
    for session in &sessions {
        keys.insert(format!("session:{project}:{}", session.as_str()));
    }
    if let Some(property) = &experiment.property {
        keys.insert(format!("resource:{}", property.resource.as_str()));
    }
    Ok((sessions.into_iter().collect(), keys))
}

/// Resolve the same frozen plan and conservative bound used by live admission.
/// This performs no adapter calls or other effects.
pub fn registered_execution_plan(
    experiment: &FrozenExperiment,
    engagement: &ManifestRevision,
    round_count: u64,
) -> Result<RegisteredExecutionPlan, PreflightError> {
    let operations =
        RegisteredOperations::resolve(experiment, engagement).map_err(registry_preflight_error)?;
    if round_count == 0 || round_count > MAX_SAFE_INTEGER {
        return Err(PreflightError::RoundCount);
    }
    let (requests_per_round, required_requests) = operations
        .request_bound(round_count)
        .ok_or(PreflightError::RoundCount)?;
    if requests_per_round > MAX_SAFE_INTEGER || required_requests > MAX_SAFE_INTEGER {
        return Err(PreflightError::RoundCount);
    }
    Ok(RegisteredExecutionPlan {
        registry_digest: operations.registry_digest.clone(),
        round_count,
        dispatches: ROUND_DISPATCHES
            .iter()
            .map(|spec| PlannedDispatch {
                flow: spec.flow,
                principal: match spec.principal {
                    DispatchPrincipal::Owner => PlannedPrincipal::Owner,
                    DispatchPrincipal::Other => PlannedPrincipal::Other,
                    DispatchPrincipal::Anonymous => PlannedPrincipal::Anonymous,
                },
                session: operations.session(spec.principal).clone(),
                actions: spec.actions,
            })
            .collect(),
        requests_per_round,
        required_requests,
        macro_name: operations.macro_name,
        macro_session: operations.owner_session,
        expected_macro_requests: 1,
    })
}

/// Registered session references are namespace-qualified. Teapot's native
/// names omit `session.` and reserve underscore, so underscore is an injective
/// separator for the remaining registered segments (which themselves permit
/// lower alphanumeric and hyphen only).
fn registry_preflight_error(error: RegistryError) -> PreflightError {
    match error {
        RegistryError::Session => PreflightError::Session,
        RegistryError::Unsupported | RegistryError::EngagementMismatch => {
            PreflightError::ExperimentMismatch
        }
    }
}

#[cfg(test)]
mod tests;
