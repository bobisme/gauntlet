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
    request::NormalizedInput,
    store::{RequestScope, RunAcceptance, Store, StoreError},
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
const REGISTERED_PLANT_MACRO: &str = "plant";
const REGISTERED_PLANT_OPERATION: &str = "operation.plant.object";

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

/// Input to steps 1--4 of verifier preflight. `run` carries the service-minted
/// request key; a retry must reopen that key instead of declaring a new run.
pub struct PreflightRequest<'a> {
    pub scope: &'a RequestScope,
    pub input: &'a NormalizedInput,
    pub run: &'a Run,
    pub claim: &'a Claim,
    pub engagement: &'a ManifestRevision,
    pub manifest_artifact: &'a Artifact,
    pub pass_reference: &'a PassRef,
    pub pass_state: PassState<'a>,
    pub pass_file: &'a AbsolutePath,
}

/// The passive ceiling probe and conservative request bound derived from the
/// exact compiled recipe named by the frozen experiment. Nothing here is
/// caller-selectable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegisteredExecutionPlan {
    pub macro_name: WireText,
    pub macro_session: SessionName,
    pub expected_macro_requests: u64,
    pub required_requests: u64,
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
        binding: AccountingBinding,
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

#[derive(Debug)]
pub struct LiveAdmission<'a> {
    pub instrument: InstrumentObservation,
    pub accounting: AccountingCapture<'a>,
}

impl<'a> PreflightServices for LiveServices<'a> {
    type Admission = LiveAdmission<'a>;

    fn admit(
        &self,
        sessions: &[SessionName],
        plan: &RegisteredExecutionPlan,
        requirement: RequiredEnforcement,
        binding: AccountingBinding,
    ) -> Result<Self::Admission, PreflightError> {
        let instrument = self
            .teapot
            .verifier_preflight(sessions, requirement)
            .map_err(PreflightError::Gate)?;
        let accounting = self
            .teapot
            .begin_accounting(
                binding,
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
#[derive(Debug)]
pub struct Prepared<A> {
    pub acceptance: RunAcceptance,
    pub experiment: FrozenExperiment,
    pub artifact: Artifact,
    pub admission: A,
    lease: RunLease,
}

impl<A> Prepared<A> {
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

#[derive(Debug, thiserror::Error)]
pub enum PreflightError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("this request key already crossed the local execution-start boundary")]
    Replay,
    #[error("the declared run does not bind the resolved frozen experiment")]
    ExperimentMismatch,
    #[error(transparent)]
    Resolve(#[from] ResolveError),
    #[error("the registered experiment has unresolved required slots")]
    MissingSlots(MissingSlots),
    #[error("the accepted engagement revision changed before preflight")]
    EngagementRevision,
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
}

impl PreflightError {
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Store(error) => error.error_code(),
            Self::Replay | Self::Lock(LockError::Busy) => ErrorCode::ConflictingRun,
            Self::ExperimentMismatch => ErrorCode::IntegrityFailure,
            Self::Resolve(error) => error.code(),
            Self::MissingSlots(_) => ErrorCode::SlotsIncomplete,
            Self::EngagementRevision => ErrorCode::RevisionConflict,
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

/// Execute verifier preflight steps 1--4. All pure resolution happens before
/// the first adapter call, but the durable run/key commit always precedes the
/// lock and every external process invocation.
pub fn prepare<S: PreflightServices>(
    store: &mut Store,
    locks: &RunLocks,
    services: &S,
    request: PreflightRequest<'_>,
) -> Result<Prepared<S::Admission>, PreflightError> {
    let experiment = Templates::resolve(request.claim, request.engagement)?
        .ready()
        .map_err(PreflightError::MissingSlots)?;
    let (bytes, digest) = experiment.freeze().map_err(PreflightError::Canonical)?;
    if digest != request.run.experiment_digest
        || experiment.engagement.revision != request.engagement.revision()
        || experiment.engagement.digest != *request.engagement.digest()
        || request.manifest_artifact.digest != *request.engagement.digest()
    {
        return Err(PreflightError::ExperimentMismatch);
    }

    // This transaction is the effect boundary: no lock, process, network or
    // Evidence operation occurs before both the run and request key exist.
    let acceptance = store.declare_request(request.scope, request.input, request.run)?;
    if acceptance.run.state != RunState::Declared || !acceptance.run.steps.is_empty() {
        return Err(PreflightError::Replay);
    }

    let plan = registered_execution_plan(&experiment)?;
    let (sessions, keys) = lock_inputs(&experiment, request.engagement)?;
    let lease = locks.acquire(&keys)?;
    store.claim_conflicts(&acceptance.run.id, &keys)?;

    let outcome = (|| {
        if acceptance.engagement_revision != request.engagement.revision() {
            return Err(PreflightError::EngagementRevision);
        }
        request
            .engagement
            .check_new_run(request.pass_reference, request.pass_state)?;

        let pass_id = WireText::try_from(request.pass_reference.as_str().to_owned())
            .map_err(|_| PreflightError::Session)?;
        let admission = services.admit(
            &sessions,
            &plan,
            request.engagement.settings().required_enforcement,
            AccountingBinding {
                run_id: acceptance.run.id.clone(),
                request_key: acceptance.run.request_key.clone(),
                pass_id,
                pass_digest: request.engagement.pass_digest().clone(),
                pass_file: request.pass_file.clone(),
            },
        )?;

        let artifact = services.record_experiment(
            acceptance.run.request_key.as_str(),
            &bytes,
            request.manifest_artifact,
        )?;
        if artifact.digest != digest {
            return Err(PreflightError::EvidenceMismatch);
        }
        let (read_reference, read_bytes) = services.read_experiment(&artifact.artifact_id)?;
        if read_reference != artifact
            || read_bytes != bytes
            || Sha256Digest::of(&read_bytes) != digest
        {
            return Err(PreflightError::EvidenceMismatch);
        }
        store.link_experiment(&acceptance.run.id, &artifact)?;

        Ok(Prepared {
            acceptance,
            experiment,
            artifact,
            admission,
            lease,
        })
    })();
    if outcome.is_err() {
        store.release_unstarted_conflicts(&request.run.id)?;
    }
    outcome
}

fn lock_inputs(
    experiment: &FrozenExperiment,
    engagement: &ManifestRevision,
) -> Result<(Vec<SessionName>, BTreeSet<String>), PreflightError> {
    let project = engagement.settings().instrument.project.as_str();
    let mut sessions: BTreeSet<SessionName> = BTreeSet::new();
    for principal in experiment.principals.values() {
        sessions.insert(instrument_session(principal.session.as_str())?);
        if let Some(session) = &principal.verifier_session {
            sessions.insert(instrument_session(session.as_str())?);
        }
    }
    let mut keys = BTreeSet::from([format!("pass:{}", engagement.settings().pass_ref.as_str())]);
    for session in &sessions {
        keys.insert(format!("session:{project}:{}", session.as_str()));
    }
    if let Some(property) = &experiment.property {
        keys.insert(format!("resource:{}", property.resource.as_str()));
    }
    Ok((sessions.into_iter().collect(), keys))
}

fn registered_execution_plan(
    experiment: &FrozenExperiment,
) -> Result<RegisteredExecutionPlan, PreflightError> {
    let compiled = Templates::registry()
        .iter()
        .find(|compiled| compiled.versioned_id() == experiment.template)
        .ok_or(PreflightError::ExperimentMismatch)?;
    let owner = experiment
        .principals
        .iter()
        .find(|(slot, _)| slot.as_str() == "owner")
        .map(|(_, principal)| principal)
        .ok_or(PreflightError::ExperimentMismatch)?;
    let macro_session = owner
        .verifier_session
        .as_ref()
        .ok_or(PreflightError::Session)?
        .as_str();
    let macro_session = instrument_session(macro_session)?;

    let mut expected_macro_requests = 0_u64;
    let mut required_requests = 0_u64;
    for step in &compiled.template.recipe {
        if step.operation.as_str() == REGISTERED_PLANT_OPERATION {
            expected_macro_requests = expected_macro_requests
                .checked_add(1)
                .ok_or(PreflightError::ExperimentMismatch)?;
        }
        let authenticated = step
            .slots
            .iter()
            .any(|slot| experiment.principals.contains_key(slot));
        // Teapot may add one login and one retry around an authenticated send.
        // Anonymous sends have neither credential behavior.
        required_requests = required_requests
            .checked_add(if authenticated { 3 } else { 1 })
            .ok_or(PreflightError::ExperimentMismatch)?;
    }
    if expected_macro_requests == 0 || required_requests == 0 {
        return Err(PreflightError::ExperimentMismatch);
    }
    Ok(RegisteredExecutionPlan {
        macro_name: WireText::try_from(REGISTERED_PLANT_MACRO.to_owned())
            .map_err(|_| PreflightError::ExperimentMismatch)?,
        macro_session,
        expected_macro_requests,
        required_requests,
    })
}

/// Registered session references are namespace-qualified. Teapot's native
/// names omit `session.` and reserve underscore, so underscore is an injective
/// separator for the remaining registered segments (which themselves permit
/// lower alphanumeric and hyphen only).
fn instrument_session(reference: &str) -> Result<SessionName, PreflightError> {
    let native = reference
        .strip_prefix("session.")
        .ok_or(PreflightError::Session)?
        .replace('.', "_");
    native.parse().map_err(|_| PreflightError::Session)
}

#[cfg(test)]
mod tests;
