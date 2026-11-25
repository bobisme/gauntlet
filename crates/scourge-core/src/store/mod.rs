//! Transactional SQLite metadata for a local coordination store.
//! Evidence content stays in its owning store. All SQL writes enter through
//! a transaction that allocates its revision and appends its audit event.

pub mod checks;
pub mod entry;
pub mod read;
mod recovery;

use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    time::{Duration, Instant},
};

use rusqlite::{
    Connection, FileControl, OpenFlags, OptionalExtension, Transaction, TransactionBehavior,
    functions::FunctionFlags, params, types::ValueRef,
};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;

use crate::{
    canonical::{self, Sha256Digest},
    domain::{
        CleanupObjectOutcome, CleanupObjectRole, CleanupOwnership, LeadEvent, LeadRevision, Run,
        RunCleanup, RunStep, VerificationIndex,
    },
    engagement::ManifestRevision,
    ids::{ArtifactId, EngagementId, LeadId, PublicationIntentId, RequestKey, RunId, WireText},
    preflight::{ExecutionAuthority, ValidatedDeclaration},
    request::NormalizedInput,
    rounds::{ExecutedRounds, RoundFlow},
    template::{Claim, FrozenExperiment},
    verification::record::{PreparedVerification, VerifiedPublication},
    wire::{
        Artifact, Checkpoint, Cleanup, Effect, ErrorCode, Flow, PublicationIntentV1,
        PublicationIntentV1Tag, PublicationState, RecordKind, Reproduction, RoundPhase, RunFlag,
        RunState, SlotSource, VerificationV1,
    },
};

const MIGRATIONS: &[&str] = &[
    include_str!("001_initial.sql"),
    include_str!("002_audit_receipts.sql"),
    include_str!("003_request_keys.sql"),
    include_str!("004_request_key_integrity.sql"),
    include_str!("005_recorded_checks.sql"),
    include_str!("006_workspace_identity.sql"),
    include_str!("007_entry_teapot_observation.sql"),
    include_str!("008_lead_surface.sql"),
    include_str!("009_run_experiment.sql"),
    include_str!("010_run_conflicts.sql"),
    include_str!("011_run_cleanup.sql"),
    include_str!("012_publication.sql"),
    include_str!("013_verification_custody.sql"),
];
const APPLICATION_ID: i64 = i32::from_be_bytes(*b"SCRG") as i64;

/// Wait this long for another writer, then report a typed conflict. Local
/// contention is retryable; it is not evidence that the store is corrupt.
const BUSY_TIMEOUT: Duration = Duration::from_millis(500);
const MAX_PUBLICATION_RECORD_BYTES: usize = 64 * 1024 * 1024;
const MAX_PUBLICATION_INPUT_BYTES: usize = 512 * 1024;
const MAX_PUBLICATION_INPUTS: usize = 256;
const RUN_PUBLICATION_SETTLE: &str = "run.publication.settle";
const PUBLICATION_INTENT: &str = "publication.intent";
const VERIFIED_PUBLICATION_INTENT: &str = "publication.verified.intent";
const FIXTURE_PUBLICATION_INTENT: &str = "fixture.publication.intent";
#[cfg(test)]
pub(crate) const FIXTURE_EVIDENCE_CASE: &str = "case_scourge_test";
const ACQUIRED_PUBLICATION_INTENT: &str = "publication.acquired.intent";
const REQUEST_ACCEPT: &str = "request.accept";
const VERIFY_REQUEST_ACCEPT: &str = "request.verify.accept";

/// Coordinate the short journal-mode initialization window among Scourge
/// connections. SQLite owns transaction locking after WAL setup.
fn initialization_lock(
    path: &Path,
    operation: rustix::fs::FlockOperation,
) -> Result<std::fs::File> {
    use rustix::fs::{self, Mode, OFlags};
    use rustix::io::Errno;

    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let dir = std::fs::File::from(
        fs::open(
            parent,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| StoreError::ConnectionSettings)?,
    );
    let until = Instant::now() + BUSY_TIMEOUT;
    loop {
        match fs::flock(&dir, operation) {
            Ok(()) => return Ok(dir),
            Err(Errno::WOULDBLOCK) if Instant::now() < until => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(Errno::WOULDBLOCK) => return Err(StoreError::Busy),
            Err(_) => return Err(StoreError::ConnectionSettings),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("coordination database operation failed")]
    Database(rusqlite::Error),
    #[error("could not encode coordination metadata")]
    Encoding(#[from] serde_json::Error),
    #[error("stored coordination metadata is not decodable")]
    Decode,
    #[error("coordination database does not support the required connection settings")]
    ConnectionSettings,
    #[error("unrecognized coordination database schema")]
    Schema,
    #[error("coordination metadata conflicts with the stored state")]
    Conflict,
    #[error("the publication checkpoint moved before the record could be linked")]
    HeadMoved,
    #[error("coordination metadata is locked by another writer")]
    Busy,
    #[error("no request key in this scope")]
    RequestNotFound,
    #[error("no such object in this scope")]
    SelectorNotFound,
    #[error("request key was already used for different input")]
    IdempotencyKeyReused,
    #[error("the expected revision does not match the stored revision")]
    RevisionConflict,
    #[error("the engagement's verification run allowance is exhausted")]
    VerifyBudgetRefused,
    #[error("stored coordination metadata failed its integrity check")]
    Integrity,
    #[error("coordination counter exceeds the SQLite integer range")]
    CounterRange,
}

impl From<rusqlite::Error> for StoreError {
    /// Contention is a typed conflict, not corruption: only a database that
    /// refuses to answer for any other reason is an integrity failure.
    fn from(error: rusqlite::Error) -> Self {
        match &error {
            rusqlite::Error::SqliteFailure(code, _)
                if matches!(
                    code.code,
                    rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
                ) =>
            {
                Self::Busy
            }
            _ => Self::Database(error),
        }
    }
}

impl StoreError {
    /// The frozen error code a surface reports. Local conflicts are typed here
    /// rather than as generic database failures, and an absent key and a key in
    /// another scope share one answer, as do an absent and a foreign selector.
    pub fn error_code(&self) -> ErrorCode {
        match self {
            Self::RequestNotFound | Self::SelectorNotFound => ErrorCode::ObjectNotFound,
            Self::IdempotencyKeyReused => ErrorCode::IdempotencyKeyReused,
            Self::RevisionConflict => ErrorCode::RevisionConflict,
            Self::VerifyBudgetRefused => ErrorCode::BudgetRefused,
            Self::Conflict | Self::HeadMoved | Self::Busy => ErrorCode::ConflictingRun,
            Self::Database(_)
            | Self::Encoding(_)
            | Self::Decode
            | Self::ConnectionSettings
            | Self::Schema
            | Self::Integrity
            | Self::CounterRange => ErrorCode::IntegrityFailure,
        }
    }
}

pub type Result<T> = std::result::Result<T, StoreError>;

/// The local identity a request key is scoped to. Workspace callers construct
/// this through [`crate::workspace::BoundWorkspace::request_scope`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestScope {
    pub engagement: EngagementId,
    pub binding: WireText,
}

impl RequestScope {
    pub fn new(engagement: EngagementId, binding: WireText) -> Self {
        Self {
            engagement,
            binding,
        }
    }
}

/// The exact inputs the caller resolved before verifier admission.
pub(crate) struct VerificationPins<'a> {
    pub lead: &'a LeadId,
    pub lead_revision: u64,
    pub manifest: &'a ManifestRevision,
    pub manifest_artifact: &'a Artifact,
    pub claim: &'a Claim,
    pub experiment: &'a FrozenExperiment,
}

/// One durable acceptance of a request key. `receipt` is the store revision
/// that first recorded the key, and it is returned unchanged for every replay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunAcceptance {
    /// The run identity with its current durable state.
    pub run: Run,
    /// The store revision that recorded the key and the run.
    pub receipt: u64,
    /// The lead the first acceptance resolved, if the command names one.
    pub lead_id: Option<LeadId>,
    /// The lead revision the first acceptance resolved. A later lead edit does
    /// not change it: a replay never resolves selectors again.
    pub lead_revision: Option<u64>,
    /// The engagement revision the first acceptance resolved, 0 when none.
    pub engagement_revision: u64,
}

/// Selectors issued by the durable request boundary, usable without a verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunRecovery {
    pub run_id: RunId,
    pub request_key: RequestKey,
}

impl RunAcceptance {
    pub fn recovery(&self) -> RunRecovery {
        RunRecovery {
            run_id: self.run.id.clone(),
            request_key: self.run.request_key.clone(),
        }
    }
}

/// The durable identity returned by a lead mutation. `committed` is false only
/// when a producer import reopens the lead already bound to that exact source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeadAcceptance {
    pub lead_id: LeadId,
    pub revision: u64,
    pub committed: bool,
}

/// One durable publication result. The revision is the original link receipt
/// and is stable across retries, including retries after later head advances.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicationReceipt {
    pub revision: u64,
    pub intent: PublicationIntentV1,
    pub index: VerificationIndex,
}

/// Immutable verifier-owned material retained before the Investigation write.
///
/// It is returned only by exact intent identity so the verifier can retry the
/// original idempotent record operation after a crash. Reconciliation never
/// accepts replacement bytes or inputs from its caller. Coordination retains
/// up to 64 MiB of canonical record bytes per publication: this deliberate
/// storage cost keeps crash recovery independent of untrusted reconstruction.
/// Staging is only a write-retry source, never a verdict or status input; the
/// retained Investigation artifact is still read back and re-evaluated before
/// the chain transaction can link it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagedPublication {
    pub record_bytes: Vec<u8>,
    pub inputs: Vec<Artifact>,
    pub(crate) evidence_case_id: Option<String>,
}

/// One stored request key row, read inside the caller's transaction.
struct StoredRequest {
    engagement: String,
    binding: String,
    command: String,
    input: String,
    input_digest: String,
    run_id: String,
    receipt: u64,
    lead_id: Option<String>,
    lead_revision: Option<u64>,
    engagement_revision: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EngagementTransition {
    Amend,
    Stop,
    Resume,
}

impl StoredRequest {
    fn in_scope(&self, scope: &RequestScope) -> bool {
        self.engagement == scope.engagement.as_str() && self.binding == scope.binding.as_str()
    }

    /// Check the row against itself before any of it is believed. The stored
    /// bytes must hash to the stored digest and must be canonical, the command
    /// column must name the command those bytes carry, and the selector
    /// snapshot must be a snapshot the acceptance could have written.
    fn verify(&self) -> Result<NormalizedInput> {
        if Sha256Digest::of(self.input.as_bytes()).as_str() != self.input_digest {
            return Err(StoreError::Integrity);
        }
        let input = NormalizedInput::read_canonical(self.input.as_bytes())
            .map_err(|_| StoreError::Integrity)?;
        if input.command() != self.command || self.lead_id.is_some() != self.lead_revision.is_some()
        {
            return Err(StoreError::Integrity);
        }
        Ok(input)
    }

    /// Exact equality of the verified stored canonical bytes with the caller's
    /// canonical bytes. Call [`StoredRequest::verify`] first.
    fn matches(&self, input: &NormalizedInput) -> Result<bool> {
        let bytes = input.to_bytes().map_err(|_| StoreError::Schema)?;
        Ok(self.input.as_bytes() == bytes.as_slice())
    }
}

pub struct Store {
    db: Connection,
    #[cfg(test)]
    execution_effects: Option<crate::execution_effects::ExecutionEffects>,
}

/// Run-scoped writes reachable only from successful verifier admission.
pub(crate) struct ExecutionStore<'a> {
    store: &'a mut Store,
    run: Option<RunId>,
}

impl ExecutionStore<'_> {
    #[cfg(test)]
    pub(crate) fn fixture(store: &mut Store) -> ExecutionStore<'_> {
        ExecutionStore { store, run: None }
    }

    pub(crate) fn check_run(&self, run: &RunId) -> Result<()> {
        if self
            .run
            .as_ref()
            .is_some_and(|authorized| authorized != run)
        {
            return Err(StoreError::Conflict);
        }
        Ok(())
    }

    pub(crate) fn record_step(&mut self, run: &RunId, step: &RunStep) -> Result<u64> {
        self.check_run(run)?;
        self.store.record_step_inner(run, step, true)
    }

    pub(crate) fn record_cleanup(&mut self, run: &RunId, cleanup: &RunCleanup) -> Result<Cleanup> {
        self.check_run(run)?;
        self.store.record_cleanup_inner(run, cleanup, true)
    }

    pub(crate) fn link_step_originals(&mut self, run: &RunId, step: &RunStep) -> Result<u64> {
        self.check_run(run)?;
        self.store.link_step_originals(run, step)
    }

    pub(crate) fn link_cleanup_originals(
        &mut self,
        run: &RunId,
        cleanup: &RunCleanup,
    ) -> Result<u64> {
        self.check_run(run)?;
        self.store.link_cleanup_originals(run, cleanup)
    }

    pub(crate) fn link_experiment(&mut self, run: &RunId, artifact: &Artifact) -> Result<u64> {
        self.check_run(run)?;
        self.store.link_experiment(run, artifact)
    }
}

impl std::ops::Deref for ExecutionStore<'_> {
    type Target = Store;

    fn deref(&self) -> &Store {
        self.store
    }
}

impl Store {
    /// Open or create a local SQLite file. The durability profile applies to
    /// every connection, including connections to an already-migrated file.
    /// A blocked writer gives up after [`BUSY_TIMEOUT`] with a typed conflict.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_configured(path.as_ref(), None)
    }

    pub(crate) fn execution_store(
        &mut self,
        authority: &ExecutionAuthority,
    ) -> Result<ExecutionStore<'_>> {
        #[cfg(test)]
        if let Some(effects) = &self.execution_effects {
            effects.store_writer();
        }
        let (scope, approved) = authority.identity();
        let current = self
            .find_request(scope, &approved.run.request_key)?
            .ok_or(StoreError::RequestNotFound)?;
        if current.receipt != approved.receipt
            || current.run.id != approved.run.id
            || current.run.experiment_digest != approved.run.experiment_digest
            || !fenced_owned_run(&self.db, &current.run.id)?
        {
            return Err(StoreError::Conflict);
        }
        Ok(ExecutionStore {
            store: self,
            run: Some(current.run.id),
        })
    }

    /// Refuse a foreign database before configuring or migrating it.
    pub(crate) fn open_workspace(path: &Path, workspace_id: &str) -> Result<Self> {
        // Reading the header on a writable SQLite connection can recover or
        // checkpoint an existing journal. Verify ownership without write
        // authority first, then check again on the connection we will use.
        read::ReadStore::open(path)?.verify_workspace(workspace_id)?;
        Self::open_configured(path, Some(workspace_id))
    }

    fn open_configured(path: &Path, workspace_id: Option<&str>) -> Result<Self> {
        Self::open_with_initialization_hook(path, workspace_id, || {})
    }

    fn open_with_initialization_hook(
        path: &Path,
        workspace_id: Option<&str>,
        after_settings: impl FnOnce(),
    ) -> Result<Self> {
        let _initializing =
            initialization_lock(path, rustix::fs::FlockOperation::NonBlockingLockExclusive)?;
        let mut flags = OpenFlags::default() | OpenFlags::SQLITE_OPEN_NOFOLLOW;
        if workspace_id.is_some() {
            flags.remove(OpenFlags::SQLITE_OPEN_CREATE);
        }
        let mut db = Connection::open_with_flags(path, flags)?;
        db.busy_timeout(BUSY_TIMEOUT)?;
        register_store_functions(&db)?;
        let current = schema_version(&db)?;
        if let Some(id) = workspace_id {
            check_workspace(&db, id)?;
        }
        let journal: String = db.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))?;
        db.pragma_update(None, "foreign_keys", "ON")?;
        db.pragma_update(None, "synchronous", "FULL")?;
        db.pragma_update(None, "recursive_triggers", "ON")?;
        if !journal.eq_ignore_ascii_case("wal")
            || pragma(&db, "foreign_keys")? != 1
            || pragma(&db, "synchronous")? != 2
            || pragma(&db, "recursive_triggers")? != 1
        {
            return Err(StoreError::ConnectionSettings);
        }
        // Keep checkpointed sidecars available to purely read-only clients.
        db.file_control(Some("main"), FileControl::PersistWal(&mut 1))?;
        after_settings();
        if current < MIGRATIONS.len() {
            migrate(&mut db)?;
        }
        // PRAGMA journal_mode changes the header before SQLite opens the
        // sidecars. Take a real read before returning an idle WAL writer.
        let store = Self {
            db,
            #[cfg(test)]
            execution_effects: None,
        };
        store.revision()?;
        validate_publication_staging(&store.db)?;
        Ok(store)
    }

    #[cfg(test)]
    pub(crate) fn observe_execution_effects(
        &mut self,
        effects: crate::execution_effects::ExecutionEffects,
    ) {
        self.execution_effects = Some(effects);
    }

    /// Register binding identities without declaring an evidence manifest or
    /// pinning a pass. Repeating registration does not advance the revision.
    pub(crate) fn register_workspace_engagements<'a>(
        &mut self,
        new_workspace: Option<&str>,
        names: impl Iterator<Item = &'a str>,
    ) -> Result<()> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(id) = new_workspace {
            tx.execute(
                "INSERT INTO store_workspace (singleton, workspace_id) VALUES (1, ?)",
                [id],
            )?;
            advance(&tx, "workspace.register", id)?;
        }
        for name in names {
            if tx.execute(
                "INSERT INTO engagements (id) VALUES (?) ON CONFLICT(id) DO NOTHING",
                [name],
            )? == 1
            {
                advance(&tx, "engagement.register", name)?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn checkpoint_new_file(&self) -> Result<()> {
        let counts: (i64, i64, i64) =
            self.db
                .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?))
                })?;
        if counts != (0, 0, 0) {
            return Err(StoreError::ConnectionSettings);
        }
        // Installation renames a single file. The first authorized writer
        // opens it in WAL mode.
        self.db
            .file_control(Some("main"), FileControl::PersistWal(&mut 0))?;
        let mode: String = self
            .db
            .query_row("PRAGMA journal_mode=DELETE", [], |row| row.get(0))?;
        if !mode.eq_ignore_ascii_case("delete") {
            return Err(StoreError::ConnectionSettings);
        }
        Ok(())
    }

    pub fn revision(&self) -> Result<u64> {
        unsigned(self.db.query_row(
            "SELECT revision FROM store_revision WHERE singleton = 1",
            [],
            |r| r.get(0),
        )?)
    }

    /// Return the store revision and the engagement checkpoint from one snapshot.
    pub fn checkpoint(&self, engagement: &EngagementId) -> Result<(u64, Checkpoint)> {
        let snapshot = self.db.unchecked_transaction()?;
        checkpoint_in(&snapshot, engagement)
    }

    fn write(
        &mut self,
        operation: &str,
        subject: &str,
        change: impl FnOnce(&Transaction<'_>) -> Result<()>,
    ) -> Result<u64> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        change(&tx)?;
        commit(tx, operation, subject)
    }

    /// Append an immutable manifest pointer, assigning the next engagement revision.
    pub fn append_manifest(
        &mut self,
        id: &EngagementId,
        manifest: &Artifact,
        pass: &Sha256Digest,
    ) -> Result<u64> {
        self.append_manifest_inner(id, manifest, pass, EngagementTransition::Amend)
    }

    /// Append an engagement-stop revision while retaining every started or
    /// unknown-effect conflict owner and atomically marking it for
    /// cancellation. A pre-start owner is safe to release: if this transaction
    /// wins before its first step, the later step write observes the missing
    /// claim and fails; if the step wins, this path retains the claim and marks
    /// the now-active run. The caller remains responsible for requesting and
    /// observing instrument cancellation after this local stop transition.
    pub fn append_stop_manifest(
        &mut self,
        id: &EngagementId,
        manifest: &Artifact,
        pass: &Sha256Digest,
    ) -> Result<u64> {
        self.append_manifest_inner(id, manifest, pass, EngagementTransition::Stop)
    }

    /// Explicitly resume admission after a stop revision. Ordinary manifest
    /// amendments intentionally leave the stop fence in place. Resume remains
    /// ordered with conflict ownership: safe zero-step claims are reclaimed,
    /// while any started or unknown owner must first reach its recovery or
    /// terminal transition.
    pub fn append_resume_manifest(
        &mut self,
        id: &EngagementId,
        manifest: &Artifact,
        pass: &Sha256Digest,
    ) -> Result<u64> {
        self.append_manifest_inner(id, manifest, pass, EngagementTransition::Resume)
    }

    fn append_manifest_inner(
        &mut self,
        id: &EngagementId,
        manifest: &Artifact,
        pass: &Sha256Digest,
        transition: EngagementTransition,
    ) -> Result<u64> {
        self.write(
            match transition {
                EngagementTransition::Amend => "engagement.revision",
                EngagementTransition::Stop => "engagement.stop",
                EngagementTransition::Resume => "engagement.resume",
            },
            id.as_str(),
            |tx| {
                // Conflict acquisition and this amendment are both immediate
                // writers. Safely reclaim definitionally unstarted owners in
                // the same transaction. Any step that won first is retained;
                // an ordinary amendment refuses it, while a stop amendment
                // marks it for cancellation without discarding ownership.
                let owners = engagement_conflict_owners(tx, id)?;
                for owner in owners {
                    if conflict_owner_unstarted(tx, &owner)? {
                        release_conflict_rows(tx, &owner)?;
                    } else if transition == EngagementTransition::Stop {
                        mark_cancel_requested(tx, &owner)?;
                    } else {
                        return Err(StoreError::RevisionConflict);
                    }
                }
                tx.execute("INSERT INTO engagements (id) VALUES (?) ON CONFLICT (id) DO NOTHING", [id.as_str()])?;
                tx.execute(
                    "INSERT INTO engagement_revisions SELECT ?1, COALESCE(MAX(revision), 0) + 1, ?2, ?3, ?4
                     FROM engagement_revisions WHERE engagement_id = ?1",
                    params![id.as_str(), manifest.artifact_id.as_str(), manifest.digest.as_str(), pass.as_str()],
                )?;
                let revision: i64 = tx.query_row(
                    "SELECT MAX(revision) FROM engagement_revisions WHERE engagement_id=?",
                    [id.as_str()],
                    |row| row.get(0),
                )?;
                match transition {
                    EngagementTransition::Amend => {}
                    EngagementTransition::Stop => {
                        one(tx.execute(
                            "INSERT INTO engagement_stops (engagement_id, stopped_revision)
                             VALUES (?, ?)
                             ON CONFLICT (engagement_id) DO UPDATE
                             SET stopped_revision=excluded.stopped_revision",
                            params![id.as_str(), revision],
                        )?)?;
                    }
                    EngagementTransition::Resume => {
                        one(tx.execute(
                            "DELETE FROM engagement_stops WHERE engagement_id=?",
                            [id.as_str()],
                        )?)?;
                    }
                }
                Ok(())
            },
        )
    }

    /// Revision one creates the lead. Edits append and retain the original
    /// metadata. The append is a compare-and-set on the caller's observed
    /// revision: a stale or out-of-order edit is a typed revision conflict.
    pub fn append_lead_revision(
        &mut self,
        engagement: &EngagementId,
        lead: &LeadRevision,
    ) -> Result<u64> {
        let expected = lead.revision.checked_sub(1);
        self.compare_and_set_lead_revision(engagement, lead, expected)
    }

    /// Replace a lead revision only if `expected` is still the current one.
    /// `None` requires a lead that does not exist yet. A failed check commits
    /// nothing: no revision advance and no audit event.
    pub fn compare_and_set_lead_revision(
        &mut self,
        engagement: &EngagementId,
        lead: &LeadRevision,
        expected: Option<u64>,
    ) -> Result<u64> {
        self.write("lead.revision", lead.lead_id.as_str(), |tx| {
            let owner: Option<String> = tx
                .query_row(
                    "SELECT engagement_id FROM leads WHERE id=?",
                    [lead.lead_id.as_str()],
                    |r| r.get(0),
                )
                .optional()?;
            let current = unsigned(tx.query_row(
                "SELECT COALESCE(MAX(revision), 0) FROM lead_revisions WHERE lead_id=?",
                [lead.lead_id.as_str()],
                |r| r.get(0),
            )?)?;
            let owned = owner
                .as_deref()
                .is_none_or(|owner| owner == engagement.as_str());
            if current != expected.unwrap_or(0) || !owned || lead.revision != current + 1 {
                return Err(StoreError::RevisionConflict);
            }
            insert_lead_revision(tx, engagement, lead, current)
        })
    }

    /// Create or update a lead and append its attributed event in the same
    /// transaction. This is the only command-facing revision path: observers
    /// can never see a material edit without its history event.
    pub fn compare_and_set_lead_revision_with_event(
        &mut self,
        engagement: &EngagementId,
        lead: &LeadRevision,
        expected: Option<u64>,
        event: &LeadEvent,
    ) -> Result<LeadAcceptance> {
        if event.lead_id != lead.lead_id || event.lead_revision != lead.revision {
            return Err(StoreError::Conflict);
        }
        let lead_id = lead.lead_id.clone();
        let revision = lead.revision;
        self.write("lead.revision", lead.lead_id.as_str(), |tx| {
            let owner: Option<String> = tx
                .query_row(
                    "SELECT engagement_id FROM leads WHERE id=?",
                    [lead.lead_id.as_str()],
                    |r| r.get(0),
                )
                .optional()?;
            let current = unsigned(tx.query_row(
                "SELECT COALESCE(MAX(revision), 0) FROM lead_revisions WHERE lead_id=?",
                [lead.lead_id.as_str()],
                |r| r.get(0),
            )?)?;
            if current != expected.unwrap_or(0)
                || owner
                    .as_deref()
                    .is_some_and(|owner| owner != engagement.as_str())
                || lead.revision != current + 1
            {
                return Err(StoreError::RevisionConflict);
            }
            insert_lead_revision(tx, engagement, lead, current)?;
            insert_lead_event(tx, event)
        })?;
        Ok(LeadAcceptance {
            lead_id,
            revision,
            committed: true,
        })
    }

    /// Import a producer object once per engagement and exact source selector.
    /// A replay returns the original lead without advancing the audit log.
    pub fn create_or_reopen_imported_lead(
        &mut self,
        engagement: &EngagementId,
        lead: &LeadRevision,
        event: &LeadEvent,
    ) -> Result<LeadAcceptance> {
        let Some(source) = lead.source_ref.as_ref() else {
            return Err(StoreError::Conflict);
        };
        if lead.revision != 1 || event.lead_id != lead.lead_id || event.lead_revision != 1 {
            return Err(StoreError::Conflict);
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some((id, revision)) = tx
            .query_row(
                "SELECT i.lead_id, MAX(r.revision)
                 FROM lead_imports i JOIN leads l ON l.id=i.lead_id
                 JOIN lead_revisions r ON r.lead_id=i.lead_id
                 WHERE i.engagement_id=?1 AND i.source_ref=?2
                   AND l.engagement_id=i.engagement_id
                 GROUP BY i.lead_id",
                params![engagement.as_str(), source.as_str()],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()?
        {
            let lead_id = id.parse().map_err(|_| StoreError::Integrity)?;
            return Ok(LeadAcceptance {
                lead_id,
                revision: unsigned(revision)?,
                committed: false,
            });
        }
        insert_lead_revision(&tx, engagement, lead, 0)?;
        tx.execute(
            "INSERT INTO lead_imports (engagement_id, source_ref, lead_id) VALUES (?, ?, ?)",
            params![engagement.as_str(), source.as_str(), lead.lead_id.as_str()],
        )?;
        insert_lead_event(&tx, event)?;
        advance(&tx, "lead.revision", lead.lead_id.as_str())?;
        tx.commit()?;
        Ok(LeadAcceptance {
            lead_id: lead.lead_id.clone(),
            revision: 1,
            committed: true,
        })
    }

    pub fn append_lead_event(&mut self, event: &LeadEvent) -> Result<u64> {
        self.write("lead.event", event.lead_id.as_str(), |tx| {
            insert_lead_event(tx, event)
        })
    }

    /// Update an existing run at its last run metadata revision. Historical
    /// rows that predate receipts accept an absent revision. New runs enter
    /// through request declaration. Unrelated writes and individual steps do
    /// not invalidate the run metadata receipt.
    ///
    /// For a keyed run, execution history comes from durable step writes.
    /// Oracle outcomes and reproduction belong to the publication transaction.
    pub fn record_run(&mut self, run: &Run, previous_revision: Option<u64>) -> Result<u64> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = run_metadata_revision(&tx, &run.id)?.map(|(revision, _)| revision);
        if !exists(&tx, "SELECT 1 FROM runs WHERE id=?1", [run.id.as_str()])?
            || current != previous_revision
            || exists(
                &tx,
                "SELECT 1 FROM runs WHERE request_key=?1 AND id<>?2
                 UNION ALL SELECT 1 FROM request_keys WHERE key=?1 AND run_id<>?2
                 LIMIT 1",
                params![run.request_key.as_str(), run.id.as_str()],
            )?
        {
            return Err(StoreError::Conflict);
        }
        if !validate_run_update(&tx, run)? {
            return current.ok_or(StoreError::Integrity);
        }
        if !run.steps.is_empty()
            && keyed_run_without_conflicts(&tx, &run.id)?
            && !legacy_terminal_update_without_conflicts(&tx, run)?
            && !install_legacy_start_barrier(&tx, &run.id)?
        {
            return Err(StoreError::Conflict);
        }
        insert_run(&tx, run)?;
        if conflicts_resolved(&tx, &run.id)? {
            release_conflict_rows(&tx, &run.id)?;
        }
        commit(tx, "run.record", run.id.as_str())
    }

    #[cfg(test)]
    pub(crate) fn seed_historical_run_fixture(&mut self, run: &Run) -> Result<u64> {
        self.write("run.record", run.id.as_str(), |tx| create_run(tx, run))
    }

    #[cfg(test)]
    pub(crate) fn replace_lead_material_fixture(
        &mut self,
        lead: &LeadId,
        revision: u64,
        class: Option<&str>,
        property: Option<&str>,
        slots: &str,
    ) -> Result<()> {
        one(self.db.execute(
            "UPDATE lead_revisions SET class=?3, property=?4, slots=?5
             WHERE lead_id=?1 AND revision=?2",
            params![lead.as_str(), integer(revision)?, class, property, slots],
        )?)
    }

    /// Durably record a service-minted request key, its normalized input, the
    /// selectors resolved on first acceptance and the declared run in one
    /// transaction. No external effect may precede this commit, so a caller
    /// crosses its first effect boundary only after it returns.
    ///
    /// An issued key in this scope accepts or reopens atomically: the caller
    /// that loses an identical race returns the acceptance the winner
    /// committed, and neither starts another run. The same key with different
    /// input is `IDEMPOTENCY_KEY_REUSED`, and a key held by another scope is
    /// indistinguishable from an absent one. A replay writes nothing.
    ///
    /// The mint path never adopts an existing run row, whatever its state: it
    /// is a strict creation, so a legacy or settled run is neither reset nor
    /// hidden. Execution history is recorded in durable steps. Verified
    /// outcomes are settled by the publication transaction.
    ///
    /// This is a low-level metadata API. A new request must carry a pristine
    /// declared run. Verification keys can be reopened here. A fresh verify
    /// request goes through [`crate::preflight::declare`]. Metadata cannot
    /// acquire conflicts or start a step.
    ///
    /// ```compile_fail
    /// use scourge_core::store::Store;
    /// let _ = Store::declare_verification;
    /// ```
    pub fn declare_request(
        &mut self,
        scope: &RequestScope,
        input: &NormalizedInput,
        run: &Run,
    ) -> Result<RunAcceptance> {
        if input.command() == "verify" {
            return self
                .replay_existing_request(scope, &run.request_key, input)?
                .ok_or(StoreError::Conflict);
        }
        self.declare_request_inner(scope, input, run, None)
    }

    #[cfg(test)]
    pub(crate) fn declare_metadata_fixture(
        &mut self,
        scope: &RequestScope,
        input: &NormalizedInput,
        run: &Run,
    ) -> Result<RunAcceptance> {
        self.declare_request_inner(scope, input, run, None)
    }

    /// Declare a verification against the exact accepted lead, engagement,
    /// manifest artifact and pass. Charge a run only if this transaction
    /// commits a new verification key.
    pub(crate) fn declare_verification(
        &mut self,
        declaration: ValidatedDeclaration<'_>,
        experiment: &FrozenExperiment,
    ) -> Result<RunAcceptance> {
        let (scope, input, run, pins) = declaration.parts(experiment);
        self.declare_request_inner(scope, input, run, Some(&pins))
    }

    fn declare_request_inner(
        &mut self,
        scope: &RequestScope,
        input: &NormalizedInput,
        run: &Run,
        pins: Option<&VerificationPins<'_>>,
    ) -> Result<RunAcceptance> {
        if run.engagement != scope.engagement {
            return Err(StoreError::Conflict);
        }
        let bytes = input.to_bytes().map_err(|_| StoreError::Schema)?;
        let digest = Sha256Digest::of(&bytes);
        let stored_input = String::from_utf8(bytes).map_err(|_| StoreError::Schema)?;

        if let Some(acceptance) = self.replay_existing_request(scope, &run.request_key, input)? {
            return Ok(acceptance);
        }

        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        // Accept-or-reopen: the loser of an identical race sees the acceptance
        // the winner committed and returns it unchanged.
        if let Some(stored) = stored_request(&tx, &run.request_key)? {
            return replay_request(&tx, scope, &run.request_key, &stored, input);
        }
        if run.state != RunState::Declared || !run.flags.is_empty() || !pristine_run_outcome(run) {
            return Err(StoreError::Conflict);
        }
        tx.execute(
            "INSERT INTO engagements (id) VALUES (?) ON CONFLICT (id) DO NOTHING",
            [scope.engagement.as_str()],
        )?;
        ensure_engagement_accepting(&tx, &scope.engagement)?;
        create_run(&tx, run)?;
        let (lead_id, lead_revision, engagement_revision) =
            resolve_selectors(&tx, &scope.engagement, input)?;
        if let Some(pins) = pins {
            check_verification_pins(
                &tx,
                &scope.engagement,
                lead_id.as_ref(),
                lead_revision,
                engagement_revision,
                &run.experiment_digest,
                pins,
            )?;
            if let Some(max_runs) = pins.manifest.settings().max_verify_runs {
                let count: i64 = tx.query_row(
                    "SELECT count(*) FROM request_keys WHERE engagement_id=? AND command='verify'",
                    [scope.engagement.as_str()],
                    |row| row.get(0),
                )?;
                if unsigned(count)? >= max_runs {
                    return Err(StoreError::VerifyBudgetRefused);
                }
            }
        }
        let operation = if pins.is_some() {
            VERIFY_REQUEST_ACCEPT
        } else {
            REQUEST_ACCEPT
        };
        let receipt = advance(&tx, operation, run.id.as_str())?;
        tx.execute(
            "INSERT INTO request_keys (key, engagement_id, binding, command, input, input_digest,
                 run_id, receipt_revision, lead_id, lead_revision, engagement_revision)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            params![
                run.request_key.as_str(),
                scope.engagement.as_str(),
                scope.binding.as_str(),
                input.command(),
                stored_input,
                digest.as_str(),
                run.id.as_str(),
                integer(receipt)?,
                lead_id.as_ref().map(|v| v.as_str()),
                lead_revision.map(integer).transpose()?,
                integer(engagement_revision)?
            ],
        )?;
        tx.commit()?;
        Ok(RunAcceptance {
            run: run.clone(),
            receipt,
            lead_id,
            lead_revision,
            engagement_revision,
        })
    }

    /// Reopen a keyed resubmission from one read snapshot. The stored bytes are
    /// verified as canonical and bound to exactly this key, run and engagement
    /// before the stored input is compared with the caller's. A key that is
    /// absent, invalid for this scope or held by another engagement gets the
    /// same answer, and nothing is created. A replay writes nothing, so it
    /// advances no revision, appends no audit event and crosses no effect
    /// boundary; a stored row that fails its own check is an integrity failure.
    pub fn reopen_request(
        &mut self,
        scope: &RequestScope,
        key: &RequestKey,
        input: &NormalizedInput,
    ) -> Result<RunAcceptance> {
        self.replay_existing_request(scope, key, input)?
            .ok_or(StoreError::RequestNotFound)
    }

    pub(crate) fn replay_existing_request(
        &self,
        scope: &RequestScope,
        key: &RequestKey,
        input: &NormalizedInput,
    ) -> Result<Option<RunAcceptance>> {
        let snapshot = self.db.unchecked_transaction()?;
        stored_request(&snapshot, key)?
            .map(|stored| replay_request(&snapshot, scope, key, &stored, input))
            .transpose()
    }

    /// The `run show --request-key` read path. An unknown key and a key scoped
    /// to another engagement or binding are indistinguishable: both are absent.
    /// The key row and the run it names are read from one snapshot, and a row
    /// that fails its integrity check is reported rather than returned.
    pub fn find_request(
        &self,
        scope: &RequestScope,
        key: &RequestKey,
    ) -> Result<Option<RunAcceptance>> {
        let snapshot = self.db.unchecked_transaction()?;
        let Some(stored) = stored_request(&snapshot, key)?.filter(|stored| stored.in_scope(scope))
        else {
            return Ok(None);
        };
        stored.verify()?;
        acceptance(&snapshot, key, &stored).map(Some)
    }

    /// Atomically claim the complete derived conflict set for an already
    /// accepted run. Kernel flocks serialize live claimants before this call;
    /// these rows preserve ownership after process death. A previous owner is
    /// reclaimable only when it never persisted a step intent, or after its
    /// terminal state establishes that no effect or cleanup remains unknown.
    #[cfg(test)]
    pub(crate) fn claim_conflicts(&mut self, run: &RunId, keys: &BTreeSet<String>) -> Result<u64> {
        self.claim_conflicts_inner(run, keys, |_| Ok(()))
    }

    pub(crate) fn claim_verification_conflicts(
        &mut self,
        scope: &RequestScope,
        accepted: &RunAcceptance,
        pins: &VerificationPins<'_>,
        keys: &BTreeSet<String>,
    ) -> Result<u64> {
        self.claim_conflicts_inner(&accepted.run.id, keys, |tx| {
            let stored = stored_request(tx, &accepted.run.request_key)?
                .filter(|stored| stored.in_scope(scope))
                .ok_or(StoreError::RequestNotFound)?;
            stored.verify()?;
            let actual = acceptance(tx, &accepted.run.request_key, &stored)?;
            if &actual != accepted || stored.command != "verify" {
                return Err(StoreError::Conflict);
            }
            check_verification_pins(
                tx,
                &scope.engagement,
                actual.lead_id.as_ref(),
                actual.lead_revision,
                actual.engagement_revision,
                &actual.run.experiment_digest,
                pins,
            )
        })
    }

    fn claim_conflicts_inner(
        &mut self,
        run: &RunId,
        keys: &BTreeSet<String>,
        check_pins: impl FnOnce(&Transaction<'_>) -> Result<()>,
    ) -> Result<u64> {
        if keys.is_empty() {
            return Err(StoreError::Conflict);
        }
        let set_digest = conflict_set_digest(keys);
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (state, step_count) = accepted_run_admission(&tx, run)?;
        if state != "declared" || step_count != 0 {
            return Err(StoreError::Conflict);
        }
        check_pins(&tx)?;

        let existing: Option<(String, String)> = tx
            .query_row(
                "SELECT set_digest, claim_kind FROM run_conflict_sets WHERE run_id=?",
                [run.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let converting_legacy = match existing {
            Some((existing, kind)) if kind == "exact" => {
                if existing != set_digest.as_str() || conflict_keys(&tx, run)? != *keys {
                    return Err(StoreError::Conflict);
                }
                return tx
                    .query_row(
                        "SELECT revision FROM audit_events
                         WHERE operation='run.conflicts' AND subject=? ORDER BY revision LIMIT 1",
                        [run.as_str()],
                        |row| row.get::<_, i64>(0),
                    )
                    .optional()?
                    .ok_or(StoreError::Integrity)
                    .and_then(unsigned);
            }
            Some((existing, kind)) if kind == "legacy" && existing == "legacy" => {
                if !legacy_keyed_run(&tx, run)? || !conflict_keys(&tx, run)?.is_empty() {
                    return Err(StoreError::Integrity);
                }
                true
            }
            Some(_) => return Err(StoreError::Integrity),
            None => false,
        };

        // Schema-v7 did not retain enough experiment identity to reconstruct
        // exact keys. Until each unresolved legacy owner is explicitly
        // resumed or reconciled, its barrier conservatively conflicts with
        // every new exact admission.
        if legacy_barrier_exists(&tx, run)? {
            return Err(StoreError::Conflict);
        }

        let mut prior = BTreeSet::new();
        let mut owner = tx.prepare("SELECT run_id FROM run_conflicts WHERE conflict_key=?")?;
        for key in keys {
            if let Some(owner) = owner
                .query_row([key], |row| row.get::<_, String>(0))
                .optional()?
            {
                let owner = RunId::try_from(owner).map_err(|_| StoreError::Integrity)?;
                if owner != *run {
                    prior.insert(owner);
                }
            }
        }
        drop(owner);
        for owner in &prior {
            if !conflict_owner_reclaimable(&tx, owner)? {
                return Err(StoreError::Conflict);
            }
        }
        for owner in &prior {
            release_conflict_rows(&tx, owner)?;
        }
        if converting_legacy {
            one(tx.execute(
                "UPDATE run_conflict_sets SET set_digest=?, claim_kind='exact'
                 WHERE run_id=? AND claim_kind='legacy'",
                params![set_digest.as_str(), run.as_str()],
            )?)?;
        } else {
            one(tx.execute(
                "INSERT INTO run_conflict_sets (run_id, set_digest, claim_kind)
                 VALUES (?, ?, 'exact')",
                params![run.as_str(), set_digest.as_str()],
            )?)?;
        }
        for key in keys {
            one(tx.execute(
                "INSERT INTO run_conflicts (conflict_key, run_id) VALUES (?, ?)",
                params![key, run.as_str()],
            )?)?;
        }
        commit(tx, "run.conflicts", run.as_str())
    }

    /// Release a preflight refusal only when the keyed run still has no start
    /// intent. A crash may leave such a claim behind; the next claimant applies
    /// the same predicate while holding the live-process flocks.
    pub fn release_unstarted_conflicts(&mut self, run: &RunId) -> Result<()> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let claimed: Option<String> = tx
            .query_row(
                "SELECT claim_kind FROM run_conflict_sets WHERE run_id=?",
                [run.as_str()],
                |row| row.get(0),
            )
            .optional()?;
        let Some(_kind) = claimed else {
            return Ok(());
        };
        if !conflict_owner_unstarted(&tx, run)? {
            return Err(StoreError::Conflict);
        }
        release_conflict_rows(&tx, run)?;
        commit(tx, "run.conflicts.release", run.as_str())?;
        Ok(())
    }

    /// Whether durable conflict ownership currently names this run.
    pub fn conflicts_held(&self, run: &RunId) -> Result<bool> {
        Ok(self
            .db
            .query_row(
                "SELECT 1 FROM run_conflict_sets WHERE run_id=?",
                [run.as_str()],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .is_some())
    }

    /// Recover the exact durable run and step intents/outcomes after an
    /// interrupted verifier process. Evidence bytes remain in Investigation;
    /// this returns only the local recovery record and immutable references.
    pub fn recover_run(&self, run: &RunId) -> Result<Run> {
        load_run(&self.db, run)
    }

    #[cfg(test)]
    pub(crate) fn record_step(&mut self, run: &RunId, step: &RunStep) -> Result<u64> {
        self.record_step_inner(run, step, true)
    }

    /// Reconcile an existing durable step without opening a new dispatch.
    pub fn reconcile_recorded_step(&mut self, run: &RunId, step: &RunStep) -> Result<u64> {
        self.record_step_inner(run, step, false)
    }

    fn record_step_inner(&mut self, run: &RunId, step: &RunStep, may_start: bool) -> Result<u64> {
        self.write("run.step", run.as_str(), |tx| {
            if !may_start && stored_step(tx, run, step.number)?.is_none() {
                return Err(StoreError::Conflict);
            }
            if keyed_run_without_conflicts(tx, run)? && !install_legacy_start_barrier(tx, run)? {
                return Err(StoreError::Conflict);
            }
            put_step(tx, run, step)
        })
    }

    #[cfg(test)]
    pub(crate) fn record_cleanup(&mut self, run: &RunId, cleanup: &RunCleanup) -> Result<Cleanup> {
        self.record_cleanup_inner(run, cleanup, true)
    }

    /// Reconcile a previously recorded cleanup object and its durable steps.
    pub fn reconcile_recorded_cleanup(
        &mut self,
        run: &RunId,
        cleanup: &RunCleanup,
    ) -> Result<Cleanup> {
        self.record_cleanup_inner(run, cleanup, false)
    }

    fn record_cleanup_inner(
        &mut self,
        run: &RunId,
        cleanup: &RunCleanup,
        may_create: bool,
    ) -> Result<Cleanup> {
        if !cleanup_record_coherent(cleanup) {
            return Err(StoreError::Conflict);
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if !exists(&tx, "SELECT 1 FROM runs WHERE id=?", [run.as_str()])? {
            return Err(StoreError::SelectorNotFound);
        }
        let stored = cleanup_object(&tx, run, cleanup.round, cleanup.object)?;
        if !may_create && stored.is_none() {
            return Err(StoreError::Conflict);
        }
        if !keyed_cleanup_authority(&tx, run, stored.as_ref(), cleanup)?
            || !cleanup_bound_to_step(&tx, run, cleanup)?
        {
            return Err(StoreError::Conflict);
        }
        if let Some(stored) = stored.as_ref()
            && !cleanup_transition(stored, cleanup)
        {
            return Err(StoreError::Conflict);
        }
        put_cleanup(&tx, run, cleanup)?;
        let summary = cleanup_summary(&tx, run)?;
        one(tx.execute(
            "UPDATE runs SET cleanup=?1 WHERE id=?2",
            params![tag(summary)?, run.as_str()],
        )?)?;
        advance(&tx, "run.cleanup", run.as_str())?;
        tx.commit()?;
        Ok(summary)
    }

    /// Recover exact per-object cleanup obligations and outcomes. No target
    /// request is inferred from a plant name, body, or unbound request.
    pub fn recover_cleanup(&self, run: &RunId) -> Result<Vec<RunCleanup>> {
        cleanup_objects(&self.db, run)
    }

    /// Link immutable Investigation originals after the run-wide capture
    /// commits. Only null-to-exact-artifact enrichment is accepted.
    fn link_cleanup_originals(&mut self, run: &RunId, cleanup: &RunCleanup) -> Result<u64> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let stored = cleanup_object(&tx, run, cleanup.round, cleanup.object)?
            .ok_or(StoreError::SelectorNotFound)?;
        if !cleanup_same_except_originals(&stored, cleanup)
            || !original_enrichment(&stored.flows, &cleanup.flows)
            || !keyed_cleanup_authority(&tx, run, Some(&stored), cleanup)?
            || !cleanup_bound_to_step(&tx, run, cleanup)?
        {
            return Err(StoreError::Conflict);
        }
        one(tx.execute(
            "UPDATE run_cleanup SET flow_refs=?1 WHERE run_id=?2 AND round=?3 AND object=?4 AND flow_refs=?5",
            params![
                json(&cleanup.flows)?,
                run.as_str(),
                cleanup.round.to_string(),
                tag(cleanup.object)?,
                json(&stored.flows)?
            ],
        )?)?;
        commit(tx, "run.cleanup.originals", run.as_str())
    }

    /// Publish Evidence artifact references after a capture manifest commits.
    /// The only permitted change is `original: null` to the exact retained
    /// artifact for an otherwise byte-identical flow. This keeps the outcome
    /// durable immediately after dispatch while Investigation still stages the
    /// run-wide capture, then links its immutable originals monotonically.
    fn link_step_originals(&mut self, run: &RunId, step: &RunStep) -> Result<u64> {
        type StoredStep = (
            String,
            String,
            Option<String>,
            Option<String>,
            Option<String>,
            String,
        );
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let stored: Option<StoredStep> = tx
            .query_row(
                "SELECT step, request_digest, flow_id_floor, instrument_reference, effects, flow_refs
                 FROM run_steps WHERE run_id=? AND number=?",
                params![run.as_str(), step.number.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)),
            )
            .optional()?;
        let Some((name, digest, floor, reference, effects, flows)) = stored else {
            return Err(StoreError::SelectorNotFound);
        };
        let stored_flows: Vec<crate::wire::Flow> = json_value(&flows)?;
        if name != step.step.as_str()
            || digest != step.request_digest.as_str()
            || floor != step.flow_id_floor.map(|value| value.to_string())
            || reference.as_deref() != step.instrument_reference.as_ref().map(WireText::as_str)
            || effects.as_deref() != step.effects.map(tag).transpose()?.as_deref()
            || !original_enrichment(&stored_flows, &step.flows)
        {
            return Err(StoreError::Conflict);
        }
        one(tx.execute(
            "UPDATE run_steps SET flow_refs=? WHERE run_id=? AND number=? AND flow_refs=?",
            params![
                json(&step.flows)?,
                run.as_str(),
                step.number.to_string(),
                flows
            ],
        )?)?;
        commit(tx, "run.step.originals", run.as_str())
    }

    /// Link the retained frozen experiment to its already-declared run.
    ///
    /// A new link requires a fenced verification receipt and a conflict claim.
    /// Repeating the exact link returns its original audit revision.
    fn link_experiment(&mut self, run: &RunId, artifact: &Artifact) -> Result<u64> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let stored: Option<(String, Option<String>)> = tx
            .query_row(
                "SELECT r.experiment_digest, r.experiment_artifact_id
                 FROM runs r JOIN request_keys q ON q.run_id=r.id AND q.key=r.request_key
                 WHERE r.id=?",
                [run.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let Some((digest, linked)) = stored else {
            return Err(StoreError::SelectorNotFound);
        };
        if digest != artifact.digest.as_str() {
            return Err(StoreError::Conflict);
        }
        if let Some(linked) = linked {
            if linked != artifact.artifact_id.as_str() {
                return Err(StoreError::Conflict);
            }
            return tx
                .query_row(
                    "SELECT revision FROM audit_events WHERE operation='run.experiment' AND subject=?",
                    [run.as_str()],
                    |row| row.get::<_, i64>(0),
                )
                .optional()?
                .ok_or(StoreError::Integrity)
                .and_then(unsigned);
        }
        if !fenced_owned_run(&tx, run)? {
            return Err(StoreError::Conflict);
        }
        one(tx.execute(
            "UPDATE runs SET experiment_artifact_id=? WHERE id=? AND experiment_artifact_id IS NULL",
            params![artifact.artifact_id.as_str(), run.as_str()],
        )?)?;
        let revision = advance(&tx, "run.experiment", run.as_str())?;
        tx.commit()?;
        Ok(revision)
    }

    #[cfg(test)]
    pub(crate) fn stage_publication_fixture(
        &mut self,
        intent: &PublicationIntentV1,
        record_bytes: &[u8],
        inputs: &[Artifact],
    ) -> Result<u64> {
        self.stage_publication_inner(intent, record_bytes, inputs, None, None)
    }

    /// Settle an exact acquired run and its verifier-evaluated candidate in
    /// one transaction. An exact retry returns the original staging receipt.
    pub(crate) fn settle_and_stage_publication(
        &mut self,
        execution: &ExecutedRounds,
        intent: &PublicationIntentV1,
        evaluated: &PreparedVerification,
    ) -> Result<u64> {
        let (record_bytes, inputs, case_id) = evaluated.staged_material();
        if case_id != Some(execution.evidence_case_id()) {
            return Err(StoreError::Conflict);
        }
        self.stage_publication_inner(
            intent,
            record_bytes,
            inputs,
            Some(execution.settlement()),
            case_id,
        )
    }

    #[cfg(test)]
    fn settle_and_stage_publication_fixture(
        &mut self,
        acceptance: &RunAcceptance,
        acquired: &Run,
        intent: &PublicationIntentV1,
        record_bytes: &[u8],
        inputs: &[Artifact],
    ) -> Result<u64> {
        self.stage_publication_inner(
            intent,
            record_bytes,
            inputs,
            Some((acceptance, acquired)),
            Some(FIXTURE_EVIDENCE_CASE),
        )
    }

    fn stage_publication_inner(
        &mut self,
        intent: &PublicationIntentV1,
        record_bytes: &[u8],
        inputs: &[Artifact],
        acquisition: Option<(&RunAcceptance, &Run)>,
        evidence_case_id: Option<&str>,
    ) -> Result<u64> {
        if intent.engagement != intent.expected_head.engagement
            || intent.state != PublicationState::Pending
            || intent.artifact_id.is_some()
        {
            return Err(StoreError::Conflict);
        }
        let encoded_inputs = encode_publication_inputs(inputs)?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing = publication_by_id(&tx, &intent.intent_id)?;
        if let Some(stored) = &existing {
            if !same_intent_identity(stored, intent) {
                return Err(StoreError::Conflict);
            }
            let staged = publication_candidate_in(&tx, intent)?.ok_or(StoreError::Integrity)?;
            if staged.record_bytes != record_bytes
                || staged.inputs != inputs
                || staged.evidence_case_id.as_deref() != evidence_case_id
            {
                return Err(StoreError::Conflict);
            }
        } else {
            let (_, head) = checkpoint_in(&tx, &intent.engagement)?;
            if head != intent.expected_head {
                return Err(StoreError::HeadMoved);
            }
            if exists(
                &tx,
                "SELECT 1 FROM publication_intents WHERE run_id=? AND state IN ('pending','complete')",
                [intent.run_id.as_str()],
            )? {
                return Err(StoreError::Conflict);
            }
        }
        if let Some(stored) = &existing {
            if stored.state == "pending" {
                require_keyed_publication_settlement(&tx, intent)?;
            }
            return publication_intent_revision(&tx, &intent.intent_id);
        }
        if let Some((acceptance, acquired)) = acquisition {
            let record = decode_publication_record(intent, record_bytes)?;
            let case_id = evidence_case_id.ok_or(StoreError::Integrity)?;
            settle_publication_run(&tx, acceptance, acquired, intent, &record, inputs, case_id)?;
            validate_publication_record_fields(&tx, intent, &record)?;
        } else {
            #[cfg(test)]
            {
                require_unkeyed_publication(&tx, intent)?;
                validate_publication_record(&tx, intent, record_bytes)?;
            }
            #[cfg(not(test))]
            return Err(StoreError::Conflict);
        }
        tx.execute(
            "INSERT INTO publication_intents
             (id, engagement_id, run_id, record_id, record_digest, expected_sequence,
              expected_digest, state, artifact_id, candidate_required)
             VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', NULL, 1)",
            params![
                intent.intent_id.as_str(),
                intent.engagement.as_str(),
                intent.run_id.as_str(),
                intent.record_id.as_str(),
                intent.record_digest.as_str(),
                integer(intent.expected_head.sequence)?,
                intent
                    .expected_head
                    .record_digest
                    .as_ref()
                    .map(|v| v.as_str())
            ],
        )?;
        tx.execute(
            "INSERT INTO publication_candidates (intent_id, record_bytes, inputs, evidence_case_id)
             VALUES (?, ?, ?, ?)",
            params![
                intent.intent_id.as_str(),
                record_bytes,
                encoded_inputs,
                evidence_case_id
            ],
        )?;
        #[cfg(test)]
        let operation = if acquisition.is_some() {
            VERIFIED_PUBLICATION_INTENT
        } else {
            FIXTURE_PUBLICATION_INTENT
        };
        #[cfg(not(test))]
        let operation = VERIFIED_PUBLICATION_INTENT;
        commit(tx, operation, intent.intent_id.as_str())
    }

    /// Load the immutable replay material for an exact verifier intent.
    /// Legacy pre-v12 intents legitimately return `None`; new intents with a
    /// missing or malformed candidate are integrity failures.
    pub fn staged_publication(
        &self,
        intent: &PublicationIntentV1,
    ) -> Result<Option<StagedPublication>> {
        publication_candidate_in(&self.db, intent)
    }

    /// Return the one live publication for a run. Superseded candidates are
    /// deliberately excluded: reconciliation can never revive them.
    ///
    /// Low-level publication writes belong to the verifier.
    ///
    /// ```compile_fail
    /// use scourge_core::store::Store;
    /// let _ = Store::stage_publication;
    /// ```
    /// ```compile_fail
    /// use scourge_core::store::Store;
    /// let _ = Store::settle_and_stage_publication;
    /// ```
    /// ```compile_fail
    /// use scourge_core::store::Store;
    /// let _ = Store::complete_publication;
    /// ```
    /// ```compile_fail
    /// use scourge_core::store::Store;
    /// let _ = Store::complete_legacy_publication_reconciliation;
    /// ```
    pub fn publication(&self, run: &RunId) -> Result<Option<PublicationIntentV1>> {
        publication_in(&self.db, run)
    }

    pub(crate) fn uses_verifier_publication_receipt(
        &self,
        intent: &PublicationIntentId,
    ) -> Result<bool> {
        exists(
            &self.db,
            "SELECT 1 FROM audit_events WHERE subject=?1 AND operation=?2",
            params![intent.as_str(), VERIFIED_PUBLICATION_INTENT],
        )
    }

    /// Check a pending intent's execution authority before reconciliation
    /// accesses Investigation. Complete historical receipts are read-only.
    pub fn publication_for_reconciliation(
        &self,
        run: &RunId,
    ) -> Result<Option<PublicationIntentV1>> {
        let tx = self.db.unchecked_transaction()?;
        let intent = publication_in(&tx, run)?;
        if let Some(pending) = intent
            .as_ref()
            .filter(|intent| intent.state == PublicationState::Pending)
        {
            require_keyed_publication_settlement(&tx, pending)?;
        }
        Ok(intent)
    }

    /// Link a publication whose exact receipt, bytes, ordered lineage and
    /// oracle evaluation were checked by the registered verifier.
    pub(crate) fn complete_publication(
        &mut self,
        verified: &VerifiedPublication,
    ) -> Result<PublicationReceipt> {
        let (intent, artifact, record_bytes, inputs, case_id) = verified.staged_material();
        self.complete_publication_inner(intent, artifact, record_bytes, inputs, case_id)
    }

    #[cfg(test)]
    pub(crate) fn complete_publication_fixture(
        &mut self,
        intent: &PublicationIntentId,
        artifact: &Artifact,
        record_bytes: &[u8],
    ) -> Result<PublicationReceipt> {
        let row = publication_by_id(&self.db, intent)?.ok_or(StoreError::SelectorNotFound)?;
        let staged = publication_candidate_in(&self.db, &decode_publication(row)?)?;
        let inputs = staged
            .as_ref()
            .map_or(&[][..], |staged| staged.inputs.as_slice());
        let case_id = staged
            .as_ref()
            .and_then(|staged| staged.evidence_case_id.as_deref());
        self.complete_publication_inner(intent, artifact, record_bytes, inputs, case_id)
    }

    fn complete_publication_inner(
        &mut self,
        intent: &PublicationIntentId,
        artifact: &Artifact,
        record_bytes: &[u8],
        inputs: &[Artifact],
        evidence_case_id: Option<&str>,
    ) -> Result<PublicationReceipt> {
        if artifact.digest != Sha256Digest::of(record_bytes) {
            return Err(StoreError::Integrity);
        }
        let record: VerificationV1 = crate::canonical::from_canonical_slice(record_bytes)
            .map_err(|_| StoreError::Integrity)?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let stored = publication_by_id(&tx, intent)?.ok_or(StoreError::SelectorNotFound)?;
        let mut publication = decode_publication(stored)?;
        if publication.state == PublicationState::Pending {
            require_keyed_publication_settlement(&tx, &publication)?;
        }
        if publication_candidate_required(&tx, intent)? {
            let staged =
                publication_candidate_in(&tx, &publication)?.ok_or(StoreError::Integrity)?;
            if staged.record_bytes != record_bytes
                || staged.inputs != inputs
                || staged
                    .evidence_case_id
                    .as_deref()
                    .is_some_and(|case_id| Some(case_id) != evidence_case_id)
            {
                return Err(StoreError::Integrity);
            }
        }
        validate_publication_candidate(&tx, &publication, artifact, &record)?;
        let index = verification_index(&record, artifact.clone());
        match publication.state {
            PublicationState::Complete => {
                if publication.artifact_id.as_ref() != Some(&artifact.artifact_id)
                    || !verification_matches(&tx, intent, &index)?
                {
                    return Err(StoreError::Integrity);
                }
                let revision =
                    publication_revision(&tx, "publication.link", record.record_id.as_str())?;
                return Ok(PublicationReceipt {
                    revision,
                    intent: publication,
                    index,
                });
            }
            PublicationState::Superseded => {
                if publication.artifact_id.as_ref() != Some(&artifact.artifact_id) {
                    return Err(StoreError::Integrity);
                }
                return Err(StoreError::HeadMoved);
            }
            PublicationState::Pending => {}
        }
        let (_, head) = checkpoint_in(&tx, &publication.engagement)?;
        if head != publication.expected_head {
            one(tx.execute(
                "UPDATE publication_intents SET state='superseded', artifact_id=? WHERE id=? AND state='pending'",
                params![artifact.artifact_id.as_str(), intent.as_str()],
            )?)?;
            commit(tx, "publication.supersede", intent.as_str())?;
            return Err(StoreError::HeadMoved);
        }
        tx.execute(
            "INSERT INTO verifications (record_id, engagement_id, sequence, run_id, lead_id, artifact_id, record_digest, intent_id)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            params![index.record_id.as_str(), index.engagement.as_str(), integer(index.sequence)?, index.run_id.as_str(),
                index.lead_id.as_str(), index.record.artifact_id.as_str(), index.record.digest.as_str(), intent.as_str()],
        )?;
        one(tx.execute(
            "UPDATE engagements SET head_sequence=?1, head_digest=?2 WHERE id=?3
             AND head_sequence+1=?1 AND head_sequence=?4 AND head_digest IS ?5",
            params![
                integer(index.sequence)?,
                index.record.digest.as_str(),
                index.engagement.as_str(),
                integer(publication.expected_head.sequence)?,
                publication
                    .expected_head
                    .record_digest
                    .as_ref()
                    .map(|v| v.as_str())
            ],
        )?)?;
        one(tx.execute(
            "UPDATE publication_intents SET state='complete', artifact_id=? WHERE id=? AND state='pending'",
            params![artifact.artifact_id.as_str(), intent.as_str()],
        )?)?;
        let revision = commit(tx, "publication.link", index.record_id.as_str())?;
        publication.state = PublicationState::Complete;
        publication.artifact_id = Some(artifact.artifact_id.clone());
        Ok(PublicationReceipt {
            revision,
            intent: publication,
            index,
        })
    }
}

fn publication_in(db: &Connection, run: &RunId) -> Result<Option<PublicationIntentV1>> {
    let mut query = db.prepare(
        "SELECT id, engagement_id, run_id, record_id, record_digest,
                expected_sequence, expected_digest, state, artifact_id
         FROM publication_intents
         WHERE run_id=? AND state IN ('pending','complete') ORDER BY id LIMIT 2",
    )?;
    let rows = query
        .query_map([run.as_str()], publication_row)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    match rows.as_slice() {
        [] => Ok(None),
        [row] => Ok(Some(decode_publication(row.clone())?)),
        _ => Err(StoreError::Integrity),
    }
}

#[derive(Clone)]
struct PublicationRow {
    id: String,
    engagement: String,
    run: String,
    record: String,
    digest: String,
    expected_sequence: i64,
    expected_digest: Option<String>,
    state: String,
    artifact: Option<String>,
}

fn publication_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<PublicationRow> {
    Ok(PublicationRow {
        id: row.get(0)?,
        engagement: row.get(1)?,
        run: row.get(2)?,
        record: row.get(3)?,
        digest: row.get(4)?,
        expected_sequence: row.get(5)?,
        expected_digest: row.get(6)?,
        state: row.get(7)?,
        artifact: row.get(8)?,
    })
}

fn publication_by_id(
    db: &Connection,
    intent: &PublicationIntentId,
) -> Result<Option<PublicationRow>> {
    db.query_row(
        "SELECT id, engagement_id, run_id, record_id, record_digest,
                expected_sequence, expected_digest, state, artifact_id
         FROM publication_intents WHERE id=?",
        [intent.as_str()],
        publication_row,
    )
    .optional()
    .map_err(Into::into)
}

fn decode_publication(row: PublicationRow) -> Result<PublicationIntentV1> {
    let engagement: EngagementId = row.engagement.parse().map_err(|_| StoreError::Integrity)?;
    let expected_digest = row
        .expected_digest
        .map(Sha256Digest::try_from)
        .transpose()
        .map_err(|_| StoreError::Integrity)?;
    let state: PublicationState = tag_value(&row.state).map_err(|_| StoreError::Integrity)?;
    let artifact_id = row
        .artifact
        .map(ArtifactId::try_from)
        .transpose()
        .map_err(|_| StoreError::Integrity)?;
    if (state == PublicationState::Pending && artifact_id.is_some())
        || (state == PublicationState::Complete && artifact_id.is_none())
    {
        return Err(StoreError::Integrity);
    }
    Ok(PublicationIntentV1 {
        schema: PublicationIntentV1Tag::PublicationIntentV1,
        intent_id: row.id.parse().map_err(|_| StoreError::Integrity)?,
        engagement: engagement.clone(),
        run_id: row.run.parse().map_err(|_| StoreError::Integrity)?,
        record_id: row.record.parse().map_err(|_| StoreError::Integrity)?,
        record_digest: row.digest.parse().map_err(|_| StoreError::Integrity)?,
        expected_head: Checkpoint {
            engagement,
            sequence: unsigned(row.expected_sequence).map_err(|_| StoreError::Integrity)?,
            record_digest: expected_digest,
        },
        state,
        artifact_id,
    })
}

fn same_intent_identity(stored: &PublicationRow, candidate: &PublicationIntentV1) -> bool {
    stored.id == candidate.intent_id.as_str()
        && stored.engagement == candidate.engagement.as_str()
        && stored.run == candidate.run_id.as_str()
        && stored.record == candidate.record_id.as_str()
        && stored.digest == candidate.record_digest.as_str()
        && unsigned(stored.expected_sequence)
            .is_ok_and(|sequence| sequence == candidate.expected_head.sequence)
        && stored.expected_digest.as_deref()
            == candidate
                .expected_head
                .record_digest
                .as_ref()
                .map(Sha256Digest::as_str)
}

fn publication_candidate_required(db: &Connection, intent: &PublicationIntentId) -> Result<bool> {
    db.query_row(
        "SELECT candidate_required FROM publication_intents WHERE id=?",
        [intent.as_str()],
        |row| row.get::<_, bool>(0),
    )
    .optional()?
    .ok_or(StoreError::SelectorNotFound)
}

fn publication_candidate_in(
    db: &Connection,
    intent: &PublicationIntentV1,
) -> Result<Option<StagedPublication>> {
    let stored = publication_by_id(db, &intent.intent_id)?.ok_or(StoreError::SelectorNotFound)?;
    if !same_intent_identity(&stored, intent) {
        return Err(StoreError::Integrity);
    }
    let required = publication_candidate_required(db, &intent.intent_id)?;
    let encoded: Option<(Vec<u8>, String, Option<String>)> = db
        .query_row(
            "SELECT record_bytes, inputs, evidence_case_id FROM publication_candidates WHERE intent_id=?",
            [intent.intent_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let Some((record_bytes, encoded_inputs, evidence_case_id)) = encoded else {
        return if required {
            Err(StoreError::Integrity)
        } else {
            Ok(None)
        };
    };
    if !required {
        return Err(StoreError::Integrity);
    }
    let inputs = decode_publication_inputs(&encoded_inputs)?;
    validate_publication_record(db, intent, &record_bytes)?;
    Ok(Some(StagedPublication {
        record_bytes,
        inputs,
        evidence_case_id,
    }))
}

fn encode_publication_inputs(inputs: &[Artifact]) -> Result<String> {
    if inputs.is_empty() || inputs.len() > MAX_PUBLICATION_INPUTS {
        return Err(StoreError::Integrity);
    }
    let mut ids = BTreeSet::new();
    if inputs
        .iter()
        .any(|input| input.artifact_id.as_str().len() > 40 || !ids.insert(&input.artifact_id))
    {
        return Err(StoreError::Integrity);
    }
    let value = serde_json::to_value(inputs)?;
    let bytes = crate::canonical::to_vec(&value).map_err(|_| StoreError::Schema)?;
    if bytes.len() > MAX_PUBLICATION_INPUT_BYTES {
        return Err(StoreError::Integrity);
    }
    String::from_utf8(bytes).map_err(|_| StoreError::Integrity)
}

fn decode_publication_inputs(encoded: &str) -> Result<Vec<Artifact>> {
    if encoded.is_empty() || encoded.len() > MAX_PUBLICATION_INPUT_BYTES {
        return Err(StoreError::Integrity);
    }
    let inputs: Vec<Artifact> = crate::canonical::from_canonical_slice(encoded.as_bytes())
        .map_err(|_| StoreError::Integrity)?;
    if encode_publication_inputs(&inputs)?.as_bytes() != encoded.as_bytes() {
        return Err(StoreError::Integrity);
    }
    Ok(inputs)
}

fn validate_publication_staging(db: &Connection) -> Result<()> {
    if exists(
        db,
        "SELECT 1 FROM publication_intents i
         WHERE i.candidate_required=1
           AND NOT EXISTS (SELECT 1 FROM publication_candidates c WHERE c.intent_id=i.id)
         UNION ALL
         SELECT 1 FROM publication_candidates c
         LEFT JOIN publication_intents i ON i.id=c.intent_id
         WHERE i.id IS NULL OR i.candidate_required<>1
         LIMIT 1",
        [],
    )? {
        return Err(StoreError::Integrity);
    }
    let mut query = db.prepare(
        "SELECT id, engagement_id, run_id, record_id, record_digest,
                expected_sequence, expected_digest, state, artifact_id
         FROM publication_intents
         WHERE candidate_required=1 ORDER BY id",
    )?;
    let pending = query
        .query_map([], publication_row)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(query);
    for row in pending {
        let intent = decode_publication(row)?;
        publication_candidate_in(db, &intent)?.ok_or(StoreError::Integrity)?;
    }
    Ok(())
}

fn publication_revision(db: &Connection, operation: &str, subject: &str) -> Result<u64> {
    let mut query = db.prepare(
        "SELECT revision FROM audit_events WHERE operation=?1 AND subject=?2 ORDER BY revision LIMIT 2",
    )?;
    let rows = query
        .query_map((operation, subject), |row| row.get::<_, i64>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    match rows.as_slice() {
        [revision] => unsigned(*revision),
        _ => Err(StoreError::Integrity),
    }
}

fn checkpoint_in(db: &Connection, engagement: &EngagementId) -> Result<(u64, Checkpoint)> {
    let (revision, sequence, digest): (i64, i64, Option<String>) = db
        .query_row(
            "SELECT revision, head_sequence, head_digest FROM store_revision, engagements
             WHERE singleton=1 AND id=?",
            [engagement.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?
        .ok_or(StoreError::SelectorNotFound)?;
    if !chain_intact(db, engagement)? {
        return Err(StoreError::Integrity);
    }
    Ok((
        unsigned(revision)?,
        Checkpoint {
            engagement: engagement.clone(),
            sequence: unsigned(sequence)?,
            record_digest: digest
                .map(Sha256Digest::try_from)
                .transpose()
                .map_err(|_| StoreError::Integrity)?,
        },
    ))
}

fn chain_intact(db: &Connection, engagement: &EngagementId) -> Result<bool> {
    db.query_row(
        "SELECT e.head_sequence=(SELECT count(*) FROM verifications c WHERE c.engagement_id=e.id)
             AND ((e.head_sequence=0 AND e.head_digest IS NULL) OR EXISTS (
                 SELECT 1 FROM verifications h WHERE h.engagement_id=e.id
                   AND h.sequence=e.head_sequence AND h.record_digest=e.head_digest
             ))
             AND NOT EXISTS (
                 SELECT 1 FROM verifications v
                 LEFT JOIN publication_intents i ON i.id=v.intent_id
                 LEFT JOIN verifications p
                   ON p.engagement_id=v.engagement_id AND p.sequence=v.sequence-1
                 WHERE v.engagement_id=e.id AND (
                     length(v.record_digest)<>64 OR v.record_digest GLOB '*[^0-9a-f]*'
                     OR i.id IS NULL OR i.state<>'complete' OR i.artifact_id IS NULL
                     OR i.artifact_id<>v.artifact_id OR i.engagement_id<>v.engagement_id
                     OR i.run_id<>v.run_id OR i.record_id<>v.record_id
                     OR i.record_digest<>v.record_digest
                     OR i.expected_sequence<>v.sequence-1
                     OR i.expected_digest IS NOT p.record_digest
                     OR (v.sequence>1 AND p.sequence IS NULL)
                 )
             )
         FROM engagements e WHERE e.id=?",
        [engagement.as_str()],
        |row| row.get(0),
    )
    .optional()?
    .ok_or(StoreError::SelectorNotFound)
}

fn validate_publication_candidate(
    db: &Connection,
    intent: &PublicationIntentV1,
    artifact: &Artifact,
    record: &VerificationV1,
) -> Result<()> {
    validate_publication_record_fields(db, intent, record)?;
    if intent.record_digest != artifact.digest {
        return Err(StoreError::Integrity);
    }
    Ok(())
}

fn validate_publication_record(
    db: &Connection,
    intent: &PublicationIntentV1,
    record_bytes: &[u8],
) -> Result<VerificationV1> {
    let record = decode_publication_record(intent, record_bytes)?;
    validate_publication_record_fields(db, intent, &record)?;
    Ok(record)
}

fn decode_publication_record(
    intent: &PublicationIntentV1,
    record_bytes: &[u8],
) -> Result<VerificationV1> {
    if record_bytes.is_empty()
        || record_bytes.len() > MAX_PUBLICATION_RECORD_BYTES
        || Sha256Digest::of(record_bytes) != intent.record_digest
    {
        return Err(StoreError::Integrity);
    }
    crate::canonical::from_canonical_slice(record_bytes).map_err(|_| StoreError::Integrity)
}

fn settle_publication_run(
    tx: &Transaction<'_>,
    original: &RunAcceptance,
    acquired: &Run,
    intent: &PublicationIntentV1,
    record: &VerificationV1,
    inputs: &[Artifact],
    evidence_case_id: &str,
) -> Result<()> {
    if acquired.id != original.run.id
        || acquired.request_key != original.run.request_key
        || acquired.engagement != original.run.engagement
        || acquired.experiment_digest != original.run.experiment_digest
        || acquired.id != record.run_id
        || acquired.engagement != record.engagement
        || acquired.experiment_digest != record.experiment_digest
        || !matches!(acquired.state, RunState::Declared | RunState::Running)
        || !acquired.flags.is_empty()
        || acquired.oracle_result.is_some()
        || acquired.steps.is_empty()
        || acquired.cleanup != record.cleanup
        || record.kind != RecordKind::Verify
        || record.retest.is_some()
    {
        return Err(StoreError::Conflict);
    }
    if !fenced_request_receipt(tx, &acquired.id)? {
        return Err(StoreError::Conflict);
    }
    let stored = stored_request(tx, &acquired.request_key)?.ok_or(StoreError::RequestNotFound)?;
    let input = stored.verify()?;
    let current = acceptance(tx, &acquired.request_key, &stored)?;
    if current.receipt != original.receipt
        || current.lead_id != original.lead_id
        || current.lead_revision != original.lead_revision
        || current.engagement_revision != original.engagement_revision
        || current.run.id != acquired.id
        || current.lead_id.as_ref() != Some(&record.lead_id)
        || current.lead_revision != Some(record.lead_revision)
        || current.engagement_revision != record.engagement_revision
        || input.command() != "verify"
        || input.arguments().get("rounds").and_then(Value::as_u64)
            != u64::try_from(record.rounds.len()).ok()
    {
        return Err(StoreError::Conflict);
    }

    let effects = acquired.known_effects();
    if effects == Effect::Unknown
        || effects != record.effects
        || !publication_flows_match(acquired, record)
    {
        return Err(StoreError::Conflict);
    }
    let experiment = linked_experiment(tx, acquired)?;
    let expected_inputs = record
        .lineage_inputs(&experiment)
        .map_err(|_| StoreError::Integrity)?;
    if inputs != expected_inputs {
        return Err(StoreError::Conflict);
    }

    let mut settled = acquired.clone();
    settled.state = RunState::Finalized;
    settled.effects = effects;
    settled.oracle_result = Some(record.result);
    settled.reproduction = record.reproduction;
    let (revision, operation) =
        run_metadata_revision(tx, &acquired.id)?.ok_or(StoreError::Integrity)?;
    if operation == RUN_PUBLICATION_SETTLE {
        require_rebuilt_settlement(tx, intent, record, inputs, evidence_case_id)?;
        return Ok(());
    }
    if !is_request_acceptance(&operation)
        || revision != original.receipt
        || cleanup_summary(tx, &acquired.id)? != acquired.cleanup
        || current.run != *acquired
        || keyed_run_without_conflicts(tx, &acquired.id)?
    {
        return Err(StoreError::Conflict);
    }
    put_run(tx, &settled)?;
    if conflicts_resolved(tx, &acquired.id)? {
        release_conflict_rows(tx, &acquired.id)?;
    }
    advance(tx, RUN_PUBLICATION_SETTLE, acquired.id.as_str())?;
    Ok(())
}

fn linked_experiment(db: &Connection, run: &Run) -> Result<Artifact> {
    let id: Option<String> = db.query_row(
        "SELECT experiment_artifact_id FROM runs WHERE id=?",
        [run.id.as_str()],
        |row| row.get(0),
    )?;
    Ok(Artifact {
        artifact_id: id
            .ok_or(StoreError::Conflict)?
            .parse()
            .map_err(|_| StoreError::Integrity)?,
        digest: run.experiment_digest.clone(),
    })
}

#[cfg(test)]
fn require_unkeyed_publication(db: &Connection, intent: &PublicationIntentV1) -> Result<()> {
    if keyed_run(db, &intent.run_id)?
        || !exists(
            db,
            "SELECT 1 FROM runs WHERE id=?1 AND engagement_id=?2 AND state='finalized'",
            params![intent.run_id.as_str(), intent.engagement.as_str()],
        )?
    {
        return Err(StoreError::Conflict);
    }
    require_unbound_import_key(db, &intent.run_id)
}

fn require_keyed_publication_settlement(
    db: &Connection,
    intent: &PublicationIntentV1,
) -> Result<()> {
    let run = &intent.run_id;
    if !keyed_run(db, run)? {
        #[cfg(test)]
        if exists(
            db,
            "SELECT 1 FROM audit_events WHERE subject=?1 AND operation=?2",
            params![intent.intent_id.as_str(), FIXTURE_PUBLICATION_INTENT],
        )? {
            return require_unkeyed_publication(db, intent);
        }
        return Err(StoreError::Conflict);
    }

    let (accepted, staged, _) = settled_publication_material(db, intent)?;
    if staged.evidence_case_id.is_none() || !intent_has_settlement(db, intent, accepted.receipt)? {
        return Err(StoreError::Conflict);
    }
    Ok(())
}

fn intent_has_settlement(
    db: &Connection,
    intent: &PublicationIntentV1,
    accepted_revision: u64,
) -> Result<bool> {
    let run = &intent.run_id;
    if !fenced_request_receipt(db, run)? {
        return Ok(false);
    }
    // Only the registered verifier can stage this marker. Older audit
    // operations established acquisition but allowed caller-supplied verdicts.
    exists(
        db,
        "SELECT 1 FROM audit_events stage JOIN audit_events settle
         WHERE stage.subject=?1 AND settle.subject=?2
           AND settle.operation=?3 AND settle.revision>?4
           AND stage.operation=?5 AND settle.revision<stage.revision",
        params![
            intent.intent_id.as_str(),
            run.as_str(),
            RUN_PUBLICATION_SETTLE,
            integer(accepted_revision)?,
            VERIFIED_PUBLICATION_INTENT,
        ],
    )
}

/// The exact candidate is the immutable settlement snapshot. Current run and
/// cleanup rows can evolve after staging; only the immutable acquisition pins
/// and flow identities participate in replay.
fn settled_publication_material(
    db: &Connection,
    intent: &PublicationIntentV1,
) -> Result<(RunAcceptance, StagedPublication, VerificationV1)> {
    let run = &intent.run_id;
    let settled = load_run(db, run)?;
    let stored = stored_request(db, &settled.request_key)?.ok_or(StoreError::Conflict)?;
    let input = stored.verify()?;
    let accepted = acceptance(db, &settled.request_key, &stored)?;
    let staged = publication_candidate_in(db, intent)?.ok_or(StoreError::Conflict)?;
    let record = decode_publication_record(intent, &staged.record_bytes)?;
    validate_publication_record_fields(db, intent, &record)?;
    let experiment = linked_experiment(db, &settled)?;
    if input.command() != "verify"
        || accepted.run.id != *run
        || accepted.lead_id.as_ref() != Some(&record.lead_id)
        || accepted.lead_revision != Some(record.lead_revision)
        || accepted.engagement_revision != record.engagement_revision
        || input.arguments().get("rounds").and_then(Value::as_u64)
            != u64::try_from(record.rounds.len()).ok()
        || record.kind != RecordKind::Verify
        || record.retest.is_some()
        || settled.steps.is_empty()
        || !publication_flows_match(&settled, &record)
        || staged.inputs
            != record
                .lineage_inputs(&experiment)
                .map_err(|_| StoreError::Integrity)?
    {
        return Err(StoreError::Conflict);
    }
    Ok((accepted, staged, record))
}

/// An acquired head rebuild may change only the generated record identity
/// and checkpoint. Find the initial atomic settlement, which remains the
/// source of truth even after one or more checkpoint races.
fn require_rebuilt_settlement(
    db: &Connection,
    intent: &PublicationIntentV1,
    record: &VerificationV1,
    inputs: &[Artifact],
    evidence_case_id: &str,
) -> Result<()> {
    let prior = db
        .query_row(
            "SELECT p.id, p.engagement_id, p.run_id, p.record_id, p.record_digest,
                    p.expected_sequence, p.expected_digest, p.state, p.artifact_id
             FROM publication_intents p
             JOIN audit_events settle ON settle.subject=p.run_id AND settle.operation=?4
             JOIN audit_events stage ON stage.subject=p.id AND stage.revision=settle.revision+1
             JOIN audit_events supersede ON supersede.subject=p.id
               AND supersede.operation='publication.supersede' AND supersede.revision>stage.revision
             WHERE p.run_id=?1 AND p.engagement_id=?2 AND p.state='superseded'
               AND p.expected_sequence < ?3 AND p.artifact_id IS NOT NULL
               AND stage.operation=?5
             ORDER BY stage.revision LIMIT 1",
            params![
                intent.run_id.as_str(),
                intent.engagement.as_str(),
                integer(intent.expected_head.sequence)?,
                RUN_PUBLICATION_SETTLE,
                VERIFIED_PUBLICATION_INTENT,
            ],
            publication_row,
        )
        .optional()?
        .ok_or(StoreError::Conflict)
        .and_then(decode_publication)?;
    let (accepted, staged, mut snapshot) = settled_publication_material(db, &prior)?;
    if !intent_has_settlement(db, &prior, accepted.receipt)?
        || prior.record_id == intent.record_id
        || staged.inputs != inputs
        || staged.evidence_case_id.as_deref() != Some(evidence_case_id)
        || !exists(
            db,
            "SELECT 1 FROM verifications WHERE engagement_id=?1 AND sequence=?2 AND record_digest=?3",
            params![
                intent.engagement.as_str(),
                integer(intent.expected_head.sequence)?,
                intent
                    .expected_head
                    .record_digest
                    .as_ref()
                    .map(Sha256Digest::as_str),
            ],
        )?
    {
        return Err(StoreError::Conflict);
    }
    snapshot.record_id = record.record_id.clone();
    snapshot.run_nonce = record.run_nonce.clone();
    snapshot.sequence = record.sequence;
    snapshot.prev_record_digest = record.prev_record_digest.clone();
    if snapshot != *record {
        return Err(StoreError::Conflict);
    }
    Ok(())
}

fn publication_intent_revision(db: &Connection, intent: &PublicationIntentId) -> Result<u64> {
    db.query_row(
        "SELECT revision FROM audit_events WHERE subject=?1 AND operation IN (?2, ?3, ?4, ?5)
         ORDER BY revision LIMIT 1",
        params![
            intent.as_str(),
            PUBLICATION_INTENT,
            ACQUIRED_PUBLICATION_INTENT,
            VERIFIED_PUBLICATION_INTENT,
            FIXTURE_PUBLICATION_INTENT,
        ],
        |row| row.get::<_, i64>(0),
    )
    .optional()?
    .ok_or(StoreError::Integrity)
    .and_then(unsigned)
}

fn require_unbound_import_key(db: &Connection, run: &RunId) -> Result<()> {
    if exists(
        db,
        "SELECT 1 FROM runs r JOIN request_keys q ON q.key=r.request_key
         WHERE r.id=?1 AND q.run_id<>r.id",
        [run.as_str()],
    )? {
        return Err(StoreError::Conflict);
    }
    Ok(())
}

fn publication_flows_match(acquired: &Run, record: &VerificationV1) -> bool {
    let (step_rounds, remainder) = acquired
        .steps
        .as_chunks::<{ FROZEN_STEPS_PER_ROUND as usize }>();
    remainder.is_empty()
        && step_rounds.len() == record.rounds.len()
        && acquired
            .steps
            .iter()
            .enumerate()
            .all(|(index, step)| step.number == index as u64 + 1)
        && step_rounds
            .iter()
            .zip(&record.rounds)
            .enumerate()
            .all(|(index, (steps, round))| {
                let flows = steps.iter().flat_map(|step| &step.flows);
                round.number == index as u64 + 1
                    && round.phase == RoundPhase::Verify
                    && flows.clone().count() == round.flows.len()
                    && flows.zip(&round.flows).all(|(flow, candidate)| {
                        flow.step == candidate.step
                            && flow.flow_id == candidate.flow_id
                            && flow.original == candidate.original
                            && flow.completeness == candidate.completeness
                            && flow.original.is_some() == flow.flow_id.is_some()
                    })
            })
}

fn validate_publication_record_fields(
    db: &Connection,
    intent: &PublicationIntentV1,
    record: &VerificationV1,
) -> Result<()> {
    let expected_sequence = intent
        .expected_head
        .sequence
        .checked_add(1)
        .ok_or(StoreError::CounterRange)?;
    if intent.record_id != record.record_id
        || intent.engagement != record.engagement
        || intent.run_id != record.run_id
        || record.sequence != expected_sequence
        || record.prev_record_digest != intent.expected_head.record_digest
    {
        return Err(StoreError::Integrity);
    }
    if !exists(
        db,
        "SELECT 1 FROM runs r JOIN leads l
           ON l.engagement_id=r.engagement_id AND l.id=?3
         JOIN lead_revisions lr ON lr.lead_id=l.id AND lr.revision=?4
         WHERE r.id=?1 AND r.engagement_id=?2 AND r.state='finalized'
           AND r.experiment_digest=?5",
        params![
            record.run_id.as_str(),
            record.engagement.as_str(),
            record.lead_id.as_str(),
            integer(record.lead_revision)?,
            record.experiment_digest.as_str()
        ],
    )? {
        return Err(StoreError::Integrity);
    }
    Ok(())
}

fn verification_index(record: &VerificationV1, artifact: Artifact) -> VerificationIndex {
    VerificationIndex {
        engagement: record.engagement.clone(),
        sequence: record.sequence,
        record_id: record.record_id.clone(),
        run_id: record.run_id.clone(),
        lead_id: record.lead_id.clone(),
        record: artifact,
    }
}

fn verification_matches(
    db: &Connection,
    intent: &PublicationIntentId,
    index: &VerificationIndex,
) -> Result<bool> {
    exists(
        db,
        "SELECT 1 FROM verifications WHERE record_id=?1 AND engagement_id=?2
           AND sequence=?3 AND run_id=?4 AND lead_id=?5 AND artifact_id=?6
           AND record_digest=?7 AND intent_id=?8",
        params![
            index.record_id.as_str(),
            index.engagement.as_str(),
            integer(index.sequence)?,
            index.run_id.as_str(),
            index.lead_id.as_str(),
            index.record.artifact_id.as_str(),
            index.record.digest.as_str(),
            intent.as_str()
        ],
    )
}

fn register_store_functions(db: &Connection) -> Result<()> {
    db.create_scalar_function(
        "scourge_flow_refs_valid",
        1,
        FunctionFlags::SQLITE_UTF8
            | FunctionFlags::SQLITE_DETERMINISTIC
            | FunctionFlags::SQLITE_INNOCUOUS,
        |context| {
            Ok(match context.get_raw(0) {
                ValueRef::Text(bytes) => crate::wire::from_slice::<Vec<Flow>>(bytes).is_ok(),
                _ => false,
            })
        },
    )?;
    Ok(())
}

fn insert_lead_revision(
    tx: &Transaction<'_>,
    engagement: &EngagementId,
    lead: &LeadRevision,
    current: u64,
) -> Result<()> {
    if current == 0 {
        tx.execute(
            "INSERT INTO leads (id, engagement_id) VALUES (?, ?)",
            params![lead.lead_id.as_str(), engagement.as_str()],
        )?;
    }
    one(tx.execute(
        "INSERT INTO lead_revisions
         (lead_id, revision, text, class, property, slots, proposed_policy, origin,
          source_ref, endpoint, flow_ids, producer_confidence)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        params![
            lead.lead_id.as_str(),
            integer(lead.revision)?,
            lead.text.as_str(),
            lead.class.as_ref().map(|v| v.as_str()),
            lead.property.as_ref().map(|v| v.as_str()),
            json(&lead.slots)?,
            lead.proposed_policy.as_ref().map(json).transpose()?,
            lead.origin.as_str(),
            lead.source_ref.as_ref().map(|v| v.as_str()),
            lead.endpoint.as_ref().map(|v| v.as_str()),
            json(&lead.flow_ids)?,
            lead.producer_confidence.as_ref().map(|v| v.as_str()),
        ],
    )?)
}

fn insert_lead_event(tx: &Transaction<'_>, event: &LeadEvent) -> Result<()> {
    tx.execute(
        "INSERT INTO lead_events (lead_id, lead_revision, kind, actor, reason, evidence_refs, recorded_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)",
        params![
            event.lead_id.as_str(),
            integer(event.lead_revision)?,
            json(&event.kind)?,
            event.actor.as_str(),
            event.reason.as_str(),
            json(&event.evidence)?,
            event.recorded_at.as_str()
        ],
    )?;
    Ok(())
}

/// Replay a stored acceptance. The stored row is verified, then the caller's
/// canonical bytes must equal it exactly; the run and its receipt are loaded
/// only after both checks pass. A row in another scope is absent here, and
/// nothing about the other scope is revealed.
fn replay_request(
    db: &Connection,
    scope: &RequestScope,
    key: &RequestKey,
    stored: &StoredRequest,
    input: &NormalizedInput,
) -> Result<RunAcceptance> {
    if !stored.in_scope(scope) {
        return Err(StoreError::RequestNotFound);
    }
    stored.verify()?;
    if !stored.matches(input)? {
        return Err(StoreError::IdempotencyKeyReused);
    }
    acceptance(db, key, stored)
}

fn is_request_acceptance(operation: &str) -> bool {
    matches!(operation, REQUEST_ACCEPT | VERIFY_REQUEST_ACCEPT)
}

fn run_metadata_revision(db: &Connection, run: &RunId) -> Result<Option<(u64, String)>> {
    db.query_row(
        "SELECT revision, operation FROM audit_events
         WHERE operation IN ('run.record', ?2, ?3, ?4) AND subject=?1
         ORDER BY revision DESC LIMIT 1",
        params![
            run.as_str(),
            RUN_PUBLICATION_SETTLE,
            REQUEST_ACCEPT,
            VERIFY_REQUEST_ACCEPT
        ],
        |row| Ok((row.get::<_, i64>(0)?, row.get(1)?)),
    )
    .optional()?
    .map(|(revision, operation)| Ok((unsigned(revision)?, operation)))
    .transpose()
}

/// A run names each step once. A repeated number would silently replace the
/// earlier step, so it is refused instead of collapsed.
fn validate_steps(run: &Run) -> Result<()> {
    let mut numbers = BTreeSet::new();
    if run.steps.iter().any(|step| !numbers.insert(step.number)) {
        return Err(StoreError::Conflict);
    }
    Ok(())
}

fn conflict_set_digest(keys: &BTreeSet<String>) -> Sha256Digest {
    let mut bytes = Vec::new();
    for key in keys {
        bytes.extend_from_slice(&(key.len() as u64).to_be_bytes());
        bytes.extend_from_slice(key.as_bytes());
    }
    Sha256Digest::of(&bytes)
}

fn conflict_keys(tx: &Transaction<'_>, run: &RunId) -> Result<BTreeSet<String>> {
    let mut statement =
        tx.prepare("SELECT conflict_key FROM run_conflicts WHERE run_id=? ORDER BY conflict_key")?;
    statement
        .query_map([run.as_str()], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<BTreeSet<_>>>()
        .map_err(StoreError::from)
}

fn engagement_conflict_owners(
    tx: &Transaction<'_>,
    engagement: &EngagementId,
) -> Result<Vec<RunId>> {
    let mut statement = tx.prepare(
        "SELECT c.run_id FROM run_conflict_sets c JOIN runs r ON r.id=c.run_id
         WHERE r.engagement_id=? ORDER BY c.run_id",
    )?;
    statement
        .query_map([engagement.as_str()], |row| row.get::<_, String>(0))?
        .map(|row| RunId::try_from(row?).map_err(|_| StoreError::Integrity))
        .collect()
}

fn ensure_engagement_accepting(db: &Connection, engagement: &EngagementId) -> Result<()> {
    if exists(
        db,
        "SELECT 1 FROM engagement_stops WHERE engagement_id=?",
        [engagement.as_str()],
    )? {
        Err(StoreError::RevisionConflict)
    } else {
        Ok(())
    }
}

fn check_verification_pins(
    db: &Connection,
    engagement: &EngagementId,
    lead: Option<&LeadId>,
    lead_revision: Option<u64>,
    engagement_revision: u64,
    experiment_digest: &Sha256Digest,
    pins: &VerificationPins<'_>,
) -> Result<()> {
    if lead != Some(pins.lead)
        || lead_revision != Some(pins.lead_revision)
        || engagement_revision != pins.manifest.revision()
        || pins.manifest_artifact.digest != *pins.manifest.digest()
        || !exists(
            db,
            "SELECT 1 FROM engagement_revisions
             WHERE engagement_id=?1 AND revision=?2 AND manifest_artifact_id=?3
               AND manifest_digest=?4 AND pass_digest=?5
               AND revision=(SELECT MAX(revision) FROM engagement_revisions WHERE engagement_id=?1)",
            params![
                engagement.as_str(),
                integer(engagement_revision)?,
                pins.manifest_artifact.artifact_id.as_str(),
                pins.manifest.digest().as_str(),
                pins.manifest.pass_digest().as_str(),
            ],
        )?
    {
        return Err(StoreError::RevisionConflict);
    }
    check_verification_material(db, engagement, experiment_digest, pins)
}

/// Bind the accepted selector to the exact persisted claim material and the
/// normalized frozen experiment in the caller's existing write transaction.
fn check_verification_material(
    db: &Connection,
    engagement: &EngagementId,
    experiment_digest: &Sha256Digest,
    pins: &VerificationPins<'_>,
) -> Result<()> {
    if pins.claim.lead != *pins.lead
        || pins.experiment.engagement.revision != pins.manifest.revision()
        || pins.experiment.engagement.digest != *pins.manifest.digest()
        || pins
            .experiment
            .freeze()
            .map_err(|_| StoreError::Integrity)?
            .1
            != *experiment_digest
    {
        return Err(StoreError::RevisionConflict);
    }

    let stored: Option<(Option<String>, Option<String>, String, i64)> = db
        .query_row(
            "SELECT r.class, r.property, r.slots,
                    r.revision=(SELECT MAX(revision) FROM lead_revisions WHERE lead_id=r.lead_id)
             FROM lead_revisions r JOIN leads l ON l.id=r.lead_id
             WHERE l.engagement_id=?1 AND l.id=?2 AND r.revision=?3",
            params![
                engagement.as_str(),
                pins.lead.as_str(),
                integer(pins.lead_revision)?,
            ],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    let Some((class, property, slots, is_current)) = stored else {
        return Err(StoreError::RevisionConflict);
    };
    if is_current != 1
        || class.as_deref() != Some(pins.claim.class.as_str())
        || property.as_deref() != pins.claim.property.as_ref().map(|value| value.as_str())
    {
        return Err(StoreError::RevisionConflict);
    }

    // Stored lead slots are written from a BTreeMap. Requiring their canonical
    // encoding rejects duplicate names and historical malformed/reordered rows
    // before semantic comparison. Claim vector order itself is non-semantic.
    let stored: BTreeMap<String, Value> =
        canonical::from_canonical_slice(slots.as_bytes()).map_err(|_| StoreError::Integrity)?;
    let mut claim = BTreeMap::new();
    for slot in &pins.claim.lead_slots {
        if claim
            .insert(slot.name.as_str(), slot.value.as_str())
            .is_some()
        {
            return Err(StoreError::RevisionConflict);
        }
    }
    if stored.len() != claim.len()
        || stored.iter().any(|(name, value)| {
            value
                .as_str()
                .is_none_or(|value| claim.get(name.as_str()).copied() != Some(value))
        })
    {
        return Err(StoreError::RevisionConflict);
    }

    let frozen_lead = pins
        .experiment
        .slots
        .iter()
        .filter(|(_, binding)| binding.source == SlotSource::Lead)
        .collect::<BTreeMap<_, _>>();
    if frozen_lead.len() != claim.len()
        || claim.iter().any(|(name, value)| {
            frozen_lead
                .iter()
                .find(|(slot, _)| slot.as_str() == *name)
                .is_none_or(|(_, binding)| {
                    binding.value.as_str() != *value
                        || binding.supplied_by.as_str() != pins.lead.as_str()
                        || binding.digest != Sha256Digest::of(value.as_bytes())
                })
        })
    {
        return Err(StoreError::RevisionConflict);
    }

    match (&pins.claim.property, &pins.experiment.property) {
        (None, None) => {}
        (Some(label), Some(binding)) if label == &binding.label => {
            let declared = pins
                .manifest
                .properties()
                .get(label)
                .ok_or(StoreError::RevisionConflict)?;
            let digest =
                Sha256Digest::of(&canonical::to_vec(declared).map_err(|_| StoreError::Integrity)?);
            if binding.resource != declared.resource || binding.digest != digest {
                return Err(StoreError::RevisionConflict);
            }
        }
        _ => return Err(StoreError::RevisionConflict),
    }
    Ok(())
}

/// Read the request acceptance, current engagement head, durable stop fence,
/// and execution-start state from the caller's existing transaction. Both the
/// normal exact-claim path and a migrated run's direct first step use this
/// predicate, so neither can cross an amendment or stop in the opposite writer
/// ordering.
fn accepted_run_admission(tx: &Transaction<'_>, run: &RunId) -> Result<(String, i64)> {
    let accepted: Option<(String, i64, i64, i64, i64)> = tx
        .query_row(
            "SELECT r.state,
                    (SELECT count(*) FROM run_steps s WHERE s.run_id=r.id),
                    q.engagement_revision,
                    COALESCE((SELECT MAX(er.revision) FROM engagement_revisions er
                              WHERE er.engagement_id=r.engagement_id), 0),
                    EXISTS(SELECT 1 FROM engagement_stops es
                           WHERE es.engagement_id=r.engagement_id)
             FROM runs r JOIN request_keys q ON q.run_id=r.id AND q.key=r.request_key
             WHERE r.id=?",
            [run.as_str()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .optional()?;
    let Some((state, step_count, accepted_revision, current_revision, stopped)) = accepted else {
        return Err(StoreError::Conflict);
    };
    if accepted_revision != current_revision || stopped != 0 {
        return Err(StoreError::RevisionConflict);
    }
    ensure_keyed_execution_eligible(tx, run)?;
    Ok((state, step_count))
}

/// A new keyed run needs the fenced preflight receipt before it can claim
/// conflicts or start a step. Pre-conflict migrations retain the old recovery
/// protocol for non-verification operations.
fn ensure_keyed_execution_eligible(tx: &Transaction<'_>, run: &RunId) -> Result<()> {
    if exists(
        tx,
        "SELECT 1 FROM request_keys q
         WHERE q.run_id=?1
           AND NOT EXISTS (
               SELECT 1 FROM audit_events a
               WHERE a.revision=q.receipt_revision AND a.subject=q.run_id AND a.operation=?2
                 AND q.command='verify'
           )
           AND (q.command='verify' OR NOT EXISTS (
               SELECT 1 FROM legacy_keyed_runs l WHERE l.run_id=q.run_id
           ))",
        params![run.as_str(), VERIFY_REQUEST_ACCEPT],
    )? {
        return Err(StoreError::Conflict);
    }
    Ok(())
}

fn keyed_run(db: &Connection, run: &RunId) -> Result<bool> {
    exists(
        db,
        "SELECT 1 FROM request_keys WHERE run_id=?",
        [run.as_str()],
    )
}

fn fenced_request_receipt(db: &Connection, run: &RunId) -> Result<bool> {
    exists(
        db,
        "SELECT 1 FROM request_keys q JOIN audit_events a ON a.revision=q.receipt_revision
         WHERE q.run_id=?1 AND q.command='verify' AND a.subject=q.run_id AND a.operation=?2",
        params![run.as_str(), VERIFY_REQUEST_ACCEPT],
    )
}

fn fenced_owned_run(db: &Connection, run: &RunId) -> Result<bool> {
    Ok(fenced_request_receipt(db, run)?
        && exists(
            db,
            "SELECT 1 FROM run_conflict_sets WHERE run_id=? AND claim_kind='exact'",
            [run.as_str()],
        )?)
}

fn pristine_run_outcome(run: &Run) -> bool {
    run.steps.is_empty()
        && run.effects == Effect::None
        && run.oracle_result.is_none()
        && run.reproduction == Reproduction::NotAttempted
        && run.cleanup == Cleanup::NotRequired
}

/// Return false for an exact metadata replay that needs no write.
fn validate_run_update(tx: &Transaction<'_>, update: &Run) -> Result<bool> {
    let durable = load_run(tx, &update.id)?;
    if !keyed_run(tx, &update.id)? {
        if durable.oracle_result != update.oracle_result
            || durable.reproduction != update.reproduction
        {
            return Err(StoreError::Conflict);
        }
        return Ok(true);
    }
    if &durable == update {
        return fenced_request_receipt(tx, &update.id);
    }
    if durable.steps.is_empty() {
        // A pre-start refusal may close a declaration without creating any
        // dispatch, oracle, reproduction or cleanup state.
        let before_start = !update.flags.is_empty()
            && update
                .flags
                .iter()
                .all(|flag| matches!(flag, RunFlag::Refused | RunFlag::FailedBeforeStart));
        return if durable.state == RunState::Declared
            && pristine_run_outcome(&durable)
            && update.state == RunState::Finalized
            && before_start
            && pristine_run_outcome(update)
        {
            Ok(true)
        } else {
            Err(StoreError::Conflict)
        };
    }

    let effects = if durable
        .steps
        .iter()
        .any(|step| matches!(step.effects, None | Some(Effect::Unknown)))
    {
        Effect::Unknown
    } else if durable
        .steps
        .iter()
        .any(|step| step.effects == Some(Effect::Observed))
    {
        Effect::Observed
    } else {
        Effect::None
    };
    if update.oracle_result != durable.oracle_result
        || update.reproduction != durable.reproduction
        || (update.effects != durable.effects && update.effects != effects)
        || (update.state == RunState::Finalized && update.effects != effects)
        || update
            .steps
            .iter()
            .any(|step| !durable.steps.contains(step))
        || (durable.state == RunState::Finalized && update.state != RunState::Finalized)
        || (update.cleanup != durable.cleanup
            && !legacy_keyed_run(tx, &update.id)?
            && cleanup_objects(tx, &update.id)?.is_empty())
    {
        return Err(StoreError::Conflict);
    }
    Ok(true)
}

fn mark_cancel_requested(tx: &Transaction<'_>, run: &RunId) -> Result<()> {
    let stored: String =
        tx.query_row("SELECT flags FROM runs WHERE id=?", [run.as_str()], |row| {
            row.get(0)
        })?;
    let mut flags: Vec<RunFlag> = json_value(&stored)?;
    if !flags.contains(&RunFlag::CancelRequested) {
        flags.push(RunFlag::CancelRequested);
        one(tx.execute(
            "UPDATE runs SET flags=? WHERE id=?",
            params![json(&flags)?, run.as_str()],
        )?)?;
    }
    Ok(())
}

fn legacy_keyed_run(tx: &Transaction<'_>, run: &RunId) -> Result<bool> {
    exists(
        tx,
        "SELECT 1 FROM legacy_keyed_runs WHERE run_id=?",
        [run.as_str()],
    )
}

fn legacy_barrier_exists(tx: &Transaction<'_>, run: &RunId) -> Result<bool> {
    exists(
        tx,
        "SELECT 1 FROM run_conflict_sets
         WHERE claim_kind='legacy' AND run_id<>? LIMIT 1",
        [run.as_str()],
    )
}

/// A pre-v10 declared/no-step run has no reconstructable exact keys. Its
/// first legacy step therefore installs a global barrier in the same immediate
/// transaction as the step. Multiple safe legacy owners begin with no barrier,
/// so one can always make progress; after one starts, every other admission is
/// conservatively excluded until its terminal transition releases the row.
fn install_legacy_start_barrier(tx: &Transaction<'_>, run: &RunId) -> Result<bool> {
    if !legacy_keyed_run(tx, run)? {
        return Ok(false);
    }
    let (state, step_count) = accepted_run_admission(tx, run)?;
    if state != "declared" || step_count != 0 {
        return Ok(false);
    }

    // A prepared run may have died before it could either start or abandon its
    // exact claim. Reclaim those safe rows in the same immediate transaction
    // as this legacy owner's first step. Any started/unknown owner remains a
    // hard fence; checking every owner before deleting any rows also makes the
    // error path leave the store unchanged.
    let owners = conflict_set_owners(tx)?;
    for owner in &owners {
        if !conflict_owner_unstarted(tx, owner)? {
            return Err(StoreError::Conflict);
        }
    }
    for owner in &owners {
        release_conflict_rows(tx, owner)?;
    }
    one(tx.execute(
        "INSERT INTO run_conflict_sets (run_id, set_digest, claim_kind)
         VALUES (?, 'legacy', 'legacy')",
        [run.as_str()],
    )?)?;
    Ok(true)
}

fn conflict_set_owners(tx: &Transaction<'_>) -> Result<Vec<RunId>> {
    let mut stmt = tx.prepare("SELECT run_id FROM run_conflict_sets ORDER BY run_id")?;
    stmt.query_map([], |row| row.get::<_, String>(0))?
        .map(|row| RunId::try_from(row?).map_err(|_| StoreError::Integrity))
        .collect()
}

fn conflict_owner_unstarted(tx: &Transaction<'_>, run: &RunId) -> Result<bool> {
    tx.query_row(
        "SELECT r.state='declared' AND NOT EXISTS(
             SELECT 1 FROM run_steps s WHERE s.run_id=r.id
         ) FROM runs r WHERE r.id=?",
        [run.as_str()],
        |row| row.get(0),
    )
    .optional()?
    .ok_or(StoreError::Integrity)
}

fn conflicts_resolved(tx: &Transaction<'_>, run: &RunId) -> Result<bool> {
    tx.query_row(
        "SELECT r.state='finalized' AND r.effects<>'unknown'
             AND r.cleanup NOT IN ('partial', 'failed', 'unknown')
             AND NOT EXISTS(SELECT 1 FROM run_steps s
                 WHERE s.run_id=r.id AND (s.effects IS NULL OR s.effects='unknown'))
         FROM runs r WHERE r.id=?",
        [run.as_str()],
        |row| row.get(0),
    )
    .optional()?
    .ok_or(StoreError::Integrity)
}

fn conflict_owner_reclaimable(tx: &Transaction<'_>, run: &RunId) -> Result<bool> {
    Ok(conflict_owner_unstarted(tx, run)? || conflicts_resolved(tx, run)?)
}

fn release_conflict_rows(tx: &Transaction<'_>, run: &RunId) -> Result<()> {
    tx.execute("DELETE FROM run_conflicts WHERE run_id=?", [run.as_str()])?;
    tx.execute(
        "DELETE FROM run_conflict_sets WHERE run_id=?",
        [run.as_str()],
    )?;
    Ok(())
}

fn keyed_run_without_conflicts(tx: &Transaction<'_>, run: &RunId) -> Result<bool> {
    tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM request_keys WHERE run_id=?1)
             AND NOT EXISTS(SELECT 1 FROM run_conflict_sets WHERE run_id=?1)",
        [run.as_str()],
        |row| row.get(0),
    )
    .map_err(StoreError::from)
}

fn legacy_terminal_update_without_conflicts(tx: &Transaction<'_>, run: &Run) -> Result<bool> {
    if !legacy_keyed_run(tx, &run.id)?
        || !conflicts_resolved(tx, &run.id)?
        || run.state != RunState::Finalized
        || run.effects == Effect::Unknown
        || matches!(
            run.cleanup,
            Cleanup::Partial | Cleanup::Failed | Cleanup::Unknown
        )
        || run
            .steps
            .iter()
            .any(|step| step.effects.is_none_or(|effect| effect == Effect::Unknown))
    {
        return Ok(false);
    }
    for step in &run.steps {
        if !exists(
            tx,
            "SELECT 1 FROM run_steps WHERE run_id=?1 AND number=?2",
            params![run.id.as_str(), step.number.to_string()],
        )? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn put_step(tx: &Transaction<'_>, run: &RunId, step: &RunStep) -> Result<()> {
    let stored = stored_step(tx, run, step.number)?;
    if let Some(before) = stored.as_ref()
        && !step_transition(before, step)
    {
        return Err(StoreError::Conflict);
    }
    if !cleanup_step_growth_allowed(tx, run, stored.as_ref(), step)? {
        return Err(StoreError::Conflict);
    }
    if stored.is_none() {
        ensure_keyed_execution_eligible(tx, run)?;
        return insert_step(tx, run, step);
    }
    one(tx.execute(
        "UPDATE run_steps SET instrument_reference=?1, effects=?2, flow_refs=?3
         WHERE run_id=?4 AND number=?5",
        params![
            step.instrument_reference
                .as_ref()
                .map(|value| value.as_str()),
            step.effects.map(tag).transpose()?,
            json(&step.flows)?,
            run.as_str(),
            step.number.to_string()
        ],
    )?)
}

fn stored_step(db: &Connection, run: &RunId, number: u64) -> Result<Option<RunStep>> {
    type StoredStep = (
        String,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        String,
    );
    db.query_row(
        "SELECT step, request_digest, flow_id_floor, instrument_reference, effects, flow_refs
         FROM run_steps WHERE run_id=?1 AND number=?2",
        params![run.as_str(), number.to_string()],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
            ))
        },
    )
    .optional()?
    .map(
        |(step, request_digest, flow_id_floor, instrument_reference, effects, flows): StoredStep| {
            Ok(RunStep {
                number,
                step: step.try_into().map_err(|_| StoreError::Decode)?,
                request_digest: request_digest
                    .try_into()
                    .map_err(|_| StoreError::Decode)?,
                flow_id_floor: flow_id_floor
                    .map(|value| value.parse().map_err(|_| StoreError::Decode))
                    .transpose()?,
                instrument_reference: instrument_reference
                    .map(WireText::try_from)
                    .transpose()
                    .map_err(|_| StoreError::Decode)?,
                effects: effects.map(|value| tag_value(&value)).transpose()?,
                flows: json_value(&flows)?,
            })
        },
    )
    .transpose()
}

fn step_transition(before: &RunStep, after: &RunStep) -> bool {
    let grew = before.flows.len() < after.flows.len();
    let appended_flows_are_fresh = after.flows[before.flows.len().min(after.flows.len())..]
        .iter()
        .all(|flow| {
            flow.flow_id
                .is_none_or(|id| before.flow_id_floor.is_none_or(|floor| id > floor))
        });
    let recovered_first_flow = before.flows.is_empty()
        && before.effects == Some(Effect::Unknown)
        && after.effects == Some(Effect::Observed)
        && after.flows.len() == 1
        && after.flows[0].original.is_none()
        && after.flows[0].flow_id.is_some()
        && before
            .flow_id_floor
            .is_none_or(|floor| after.flows[0].flow_id.is_some_and(|id| id > floor))
        && (after.instrument_reference.is_none()
            || after
                .instrument_reference
                .as_ref()
                .and_then(cleanup_flow_reference)
                == after.flows[0].flow_id);
    before.number == after.number
        && before.step == after.step
        && before.request_digest == after.request_digest
        && before.flow_id_floor == after.flow_id_floor
        && (before.instrument_reference.is_none()
            || before.instrument_reference == after.instrument_reference)
        && (before.effects == after.effects
            || before.effects.is_none()
            || before.effects == Some(Effect::Unknown)
                && matches!(after.effects, Some(Effect::Observed | Effect::None)))
        && before.flows.len() <= after.flows.len()
        && before
            .flows
            .iter()
            .zip(&after.flows)
            .all(|(old, new)| old == new)
        && (!grew || appended_flows_are_fresh)
        && (!grew
            || after.flows[before.flows.len()..]
                .iter()
                .all(|flow| flow.original.is_none())
                && (recovered_first_flow
                    || before.effects.is_none()
                        && (before.flows.is_empty() || frozen_cleanup_step(before))))
}

// The frozen registry has twelve required steps per round and C is last.
const FROZEN_STEPS_PER_ROUND: u64 = 12;

fn frozen_cleanup_step(step: &RunStep) -> bool {
    frozen_cleanup_round(step).is_some()
}

fn frozen_cleanup_round(step: &RunStep) -> Option<u64> {
    step.step
        .as_str()
        .strip_prefix("round.")
        .and_then(|name| name.strip_suffix(".C"))
        .and_then(|round| round.parse::<u64>().ok().map(|value| (round, value)))
        .filter(|(round, value)| {
            *value > 0
                && *round == value.to_string()
                && value.checked_mul(FROZEN_STEPS_PER_ROUND) == Some(step.number)
        })
        .map(|(_, value)| value)
}

fn cleanup_step_growth_allowed(
    db: &Connection,
    run: &RunId,
    before: Option<&RunStep>,
    after: &RunStep,
) -> Result<bool> {
    let Some(round) = frozen_cleanup_round(after) else {
        return Ok(true);
    };
    let prior_len = before.map_or(0, |step| step.flows.len());
    if prior_len >= after.flows.len() {
        return Ok(true);
    }
    let appended = &after.flows[prior_len..];
    for flow in appended {
        let Some(object) = cleanup_flow_role(flow) else {
            return Ok(false);
        };
        let Some(cleanup) = cleanup_object(db, run, round, object)? else {
            return Ok(false);
        };
        if cleanup.cleanup_step != Some(after.number) {
            return Ok(false);
        }
        let allowed = match cleanup.outcome {
            CleanupObjectOutcome::InFlight => flow
                .flow_id
                .is_none_or(|id| cleanup.flow_id_floor.is_none_or(|floor| id > floor)),
            CleanupObjectOutcome::Unknown => {
                before.is_some_and(|step| {
                    step.effects == Some(Effect::Unknown) && after.effects == Some(Effect::Observed)
                }) && cleanup.flows.is_empty()
                    && matches!(cleanup.effects, Some(Effect::Unknown | Effect::Observed))
                    && appended
                        .iter()
                        .filter(|candidate| cleanup_flow_role(candidate) == Some(object))
                        .count()
                        == 1
                    && flow.original.is_none()
                    && flow.flow_id.is_some()
                    && cleanup
                        .flow_id_floor
                        .is_none_or(|floor| flow.flow_id.is_some_and(|id| id > floor))
                    && cleanup
                        .instrument_reference
                        .as_ref()
                        .and_then(cleanup_flow_reference)
                        == flow.flow_id
            }
            CleanupObjectOutcome::Owed
            | CleanupObjectOutcome::NotRequired
            | CleanupObjectOutcome::Complete
            | CleanupObjectOutcome::Failed => false,
        };
        if !allowed {
            return Ok(false);
        }
    }
    Ok(true)
}

fn cleanup_flow_role(flow: &crate::wire::Flow) -> Option<CleanupObjectRole> {
    match flow.step.as_str() {
        "C.primary.request" | "C.primary.redirect" | "C.primary.login" | "C.primary.retry" => {
            Some(CleanupObjectRole::Primary)
        }
        "C.control.request" | "C.control.redirect" | "C.control.login" | "C.control.retry" => {
            Some(CleanupObjectRole::Control)
        }
        _ => None,
    }
}

fn keyed_cleanup_authority(
    db: &Connection,
    run: &RunId,
    before: Option<&RunCleanup>,
    cleanup: &RunCleanup,
) -> Result<bool> {
    if !keyed_run(db, run)? {
        return Ok(true);
    }
    if before.is_none()
        && (!fenced_owned_run(db, run)?
            || !matches!(
                cleanup.outcome,
                CleanupObjectOutcome::Owed | CleanupObjectOutcome::NotRequired
            ))
    {
        return Ok(false);
    }
    let contract = match cleanup.object {
        CleanupObjectRole::Primary => RoundFlow::P,
        CleanupObjectRole::Control => RoundFlow::P2,
    };
    if contract.step_number(cleanup.round) != Some(cleanup.plant_step) {
        return Ok(false);
    }
    let Some(plant) = stored_step(db, run, cleanup.plant_step)? else {
        return Ok(match cleanup.ownership {
            CleanupOwnership::Pending => fenced_owned_run(db, run)?,
            CleanupOwnership::NotCreated => before.is_some_and(|before| {
                before.ownership == CleanupOwnership::Pending
                    && before.outcome == CleanupObjectOutcome::Owed
            }),
            CleanupOwnership::Established if before.is_some() => match cleanup.cleanup_step {
                Some(step) => stored_step(db, run, step)?.is_some(),
                None => false,
            },
            _ => false,
        });
    };
    if plant.step.as_str() != format!("round.{}.{}", cleanup.round, contract.as_str())
        || plant.request_digest != cleanup.plant_request_digest
    {
        return Ok(false);
    }
    Ok(match cleanup.ownership {
        CleanupOwnership::Pending => true,
        CleanupOwnership::Established => plant.effects == Some(Effect::Observed),
        CleanupOwnership::NotCreated => plant.effects == Some(Effect::None),
        CleanupOwnership::Unknown => plant.effects != Some(Effect::None),
    })
}

fn cleanup_bound_to_step(db: &Connection, run: &RunId, cleanup: &RunCleanup) -> Result<bool> {
    let Some(number) = cleanup.cleanup_step else {
        return Ok(true);
    };
    if cleanup.round.checked_mul(FROZEN_STEPS_PER_ROUND) != Some(number) {
        return Ok(false);
    }
    let Some(step) = stored_step(db, run, number)? else {
        return Ok(cleanup.outcome == CleanupObjectOutcome::Owed && cleanup.flows.is_empty());
    };
    if step.step.as_str() != format!("round.{}.C", cleanup.round) {
        return Ok(false);
    }
    let prefix = match cleanup.object {
        CleanupObjectRole::Primary => "C.primary.",
        CleanupObjectRole::Control => "C.control.",
    };
    Ok(cleanup.flows.iter().eq(step
        .flows
        .iter()
        .filter(|flow| flow.step.as_str().starts_with(prefix))))
}

fn cleanup_objects(db: &Connection, run: &RunId) -> Result<Vec<RunCleanup>> {
    let mut query = db.prepare(
        "SELECT round, object, plant_step, plant_request_digest, object_id, ownership,
                cleanup_step, cleanup_request_digest, flow_id_floor, instrument_reference,
                effects, response_status, flow_refs, outcome
         FROM run_cleanup WHERE run_id=?1 ORDER BY CAST(round AS INTEGER), object DESC",
    )?;
    query
        .query_map([run.as_str()], cleanup_row)?
        .map(|row| row?.try_into())
        .collect()
}

fn cleanup_object(
    db: &Connection,
    run: &RunId,
    round: u64,
    object: CleanupObjectRole,
) -> Result<Option<RunCleanup>> {
    db.query_row(
        "SELECT round, object, plant_step, plant_request_digest, object_id, ownership,
                cleanup_step, cleanup_request_digest, flow_id_floor, instrument_reference,
                effects, response_status, flow_refs, outcome
         FROM run_cleanup WHERE run_id=?1 AND round=?2 AND object=?3",
        params![run.as_str(), round.to_string(), tag(object)?],
        cleanup_row,
    )
    .optional()?
    .map(TryInto::try_into)
    .transpose()
}

type CleanupRow = (
    String,
    String,
    String,
    String,
    Option<String>,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    String,
    String,
);

fn cleanup_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<CleanupRow> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
        row.get(8)?,
        row.get(9)?,
        row.get(10)?,
        row.get(11)?,
        row.get(12)?,
        row.get(13)?,
    ))
}

impl TryFrom<CleanupRow> for RunCleanup {
    type Error = StoreError;

    fn try_from(row: CleanupRow) -> Result<Self> {
        Ok(Self {
            round: row.0.parse().map_err(|_| StoreError::Decode)?,
            object: tag_value(&row.1)?,
            plant_step: row.2.parse().map_err(|_| StoreError::Decode)?,
            plant_request_digest: row.3.try_into().map_err(|_| StoreError::Decode)?,
            object_id: row
                .4
                .map(WireText::try_from)
                .transpose()
                .map_err(|_| StoreError::Decode)?,
            ownership: tag_value(&row.5)?,
            cleanup_step: row
                .6
                .map(|value| value.parse().map_err(|_| StoreError::Decode))
                .transpose()?,
            cleanup_request_digest: row
                .7
                .map(Sha256Digest::try_from)
                .transpose()
                .map_err(|_| StoreError::Decode)?,
            flow_id_floor: row
                .8
                .map(|value| value.parse().map_err(|_| StoreError::Decode))
                .transpose()?,
            instrument_reference: row
                .9
                .map(WireText::try_from)
                .transpose()
                .map_err(|_| StoreError::Decode)?,
            effects: row.10.map(|value| tag_value(&value)).transpose()?,
            response_status: row
                .11
                .map(|value| value.parse().map_err(|_| StoreError::Decode))
                .transpose()?,
            flows: json_value(&row.12)?,
            outcome: tag_value(&row.13)?,
        })
    }
}

fn put_cleanup(tx: &Transaction<'_>, run: &RunId, cleanup: &RunCleanup) -> Result<()> {
    let stored = exists(
        tx,
        "SELECT 1 FROM run_cleanup WHERE run_id=?1 AND round=?2 AND object=?3",
        params![
            run.as_str(),
            cleanup.round.to_string(),
            tag(cleanup.object)?
        ],
    )?;
    let values = params![
        run.as_str(),
        cleanup.round.to_string(),
        tag(cleanup.object)?,
        cleanup.plant_step.to_string(),
        cleanup.plant_request_digest.as_str(),
        cleanup.object_id.as_ref().map(WireText::as_str),
        tag(cleanup.ownership)?,
        cleanup.cleanup_step.map(|value| value.to_string()),
        cleanup
            .cleanup_request_digest
            .as_ref()
            .map(Sha256Digest::as_str),
        cleanup.flow_id_floor.map(|value| value.to_string()),
        cleanup.instrument_reference.as_ref().map(WireText::as_str),
        cleanup.effects.map(tag).transpose()?,
        cleanup.response_status.map(|value| value.to_string()),
        json(&cleanup.flows)?,
        tag(cleanup.outcome)?,
    ];
    if stored {
        return one(tx.execute(
            "UPDATE run_cleanup SET object_id=?6, ownership=?7, cleanup_step=?8,
                 cleanup_request_digest=?9, flow_id_floor=?10, instrument_reference=?11,
                 effects=?12, response_status=?13, flow_refs=?14, outcome=?15
             WHERE run_id=?1 AND round=?2 AND object=?3
               AND plant_step=?4 AND plant_request_digest=?5",
            values,
        )?);
    }
    one(tx.execute(
        "INSERT INTO run_cleanup (run_id, round, object, plant_step, plant_request_digest,
             object_id, ownership, cleanup_step, cleanup_request_digest, flow_id_floor,
             instrument_reference, effects, response_status, flow_refs, outcome)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
        values,
    )?)
}

fn cleanup_transition(before: &RunCleanup, after: &RunCleanup) -> bool {
    let ownership = before.ownership == after.ownership
        || matches!(
            (before.ownership, after.ownership),
            (
                CleanupOwnership::Pending | CleanupOwnership::Unknown,
                CleanupOwnership::Established
                    | CleanupOwnership::NotCreated
                    | CleanupOwnership::Unknown
            )
        );
    let outcome = before.outcome == after.outcome
        || matches!(
            (before.outcome, after.outcome),
            (CleanupObjectOutcome::Owed, CleanupObjectOutcome::InFlight)
                | (
                    CleanupObjectOutcome::Owed,
                    CleanupObjectOutcome::NotRequired
                )
                | (
                    CleanupObjectOutcome::InFlight,
                    CleanupObjectOutcome::Complete
                        | CleanupObjectOutcome::Failed
                        | CleanupObjectOutcome::Unknown
                )
                | (
                    CleanupObjectOutcome::Failed | CleanupObjectOutcome::Unknown,
                    CleanupObjectOutcome::Complete
                )
        );
    before.round == after.round
        && before.object == after.object
        && before.plant_step == after.plant_step
        && before.plant_request_digest == after.plant_request_digest
        && (before.object_id.is_none() || before.object_id == after.object_id)
        && ownership
        && (before.cleanup_step.is_none() || before.cleanup_step == after.cleanup_step)
        && (before.cleanup_request_digest.is_none()
            || before.cleanup_request_digest == after.cleanup_request_digest)
        && (before.flow_id_floor.is_none() || before.flow_id_floor == after.flow_id_floor)
        && (before.instrument_reference.is_none()
            || before.instrument_reference == after.instrument_reference)
        && (before.effects == after.effects
            || before.outcome == CleanupObjectOutcome::InFlight && before.effects.is_none()
            || before.effects == Some(Effect::Unknown) && after.effects == Some(Effect::Observed))
        && (before.response_status.is_none() || before.response_status == after.response_status)
        && (before.flows.is_empty() || before.flows == after.flows)
        && outcome
}

fn cleanup_record_coherent(cleanup: &RunCleanup) -> bool {
    let intent = cleanup.cleanup_step.is_some() && cleanup.cleanup_request_digest.is_some();
    if cleanup.cleanup_step.is_some() != cleanup.cleanup_request_digest.is_some()
        || (cleanup.ownership == CleanupOwnership::Established) != cleanup.object_id.is_some()
        || cleanup.ownership != CleanupOwnership::Established && intent
        || cleanup.effects == Some(Effect::Observed) && cleanup.instrument_reference.is_none()
    {
        return false;
    }
    let no_result = cleanup.instrument_reference.is_none()
        && cleanup.effects.is_none()
        && cleanup.response_status.is_none()
        && cleanup.flows.is_empty();
    if !intent
        && (cleanup.flow_id_floor.is_some()
            || cleanup.instrument_reference.is_some()
            || cleanup.effects.is_some()
            || cleanup.response_status.is_some()
            || !cleanup.flows.is_empty())
    {
        return false;
    }
    let prefix = match cleanup.object {
        CleanupObjectRole::Primary => "C.primary.",
        CleanupObjectRole::Control => "C.control.",
    };
    if cleanup
        .flows
        .iter()
        .any(|flow| !flow.step.as_str().starts_with(prefix))
    {
        return false;
    }
    let observed_reference = cleanup.effects != Some(Effect::Observed)
        || cleanup
            .instrument_reference
            .as_ref()
            .and_then(cleanup_flow_reference)
            .is_some();
    if !observed_reference {
        return false;
    }
    match (cleanup.ownership, cleanup.outcome) {
        (CleanupOwnership::Pending | CleanupOwnership::Unknown, CleanupObjectOutcome::Owed) => {
            !intent && no_result
        }
        (CleanupOwnership::NotCreated, CleanupObjectOutcome::NotRequired) => !intent && no_result,
        (CleanupOwnership::Established, CleanupObjectOutcome::Owed) => no_result,
        (CleanupOwnership::Established, CleanupObjectOutcome::InFlight) => intent,
        (CleanupOwnership::Established, CleanupObjectOutcome::Complete) => {
            intent
                && cleanup.instrument_reference.is_some()
                && cleanup.effects == Some(Effect::Observed)
                && cleanup.response_status == Some(204)
                && cleanup.flows.last().is_some_and(|flow| {
                    matches!(
                        flow.step.as_str().rsplit('.').next(),
                        Some("request" | "retry")
                    ) && flow.completeness == crate::wire::Completeness::Complete
                        && flow.flow_id.is_some_and(|flow_id| {
                            cleanup
                                .instrument_reference
                                .as_ref()
                                .and_then(cleanup_flow_reference)
                                == Some(flow_id)
                        })
                })
        }
        (CleanupOwnership::Established, CleanupObjectOutcome::Failed) => {
            intent
                && cleanup.instrument_reference.is_some()
                && match (cleanup.effects, cleanup.response_status) {
                    (Some(Effect::None), None) => true,
                    (Some(Effect::Observed), Some(status)) => !(200..300).contains(&status),
                    _ => false,
                }
        }
        (CleanupOwnership::Established, CleanupObjectOutcome::Unknown) => {
            intent && matches!(cleanup.effects, Some(Effect::Unknown | Effect::Observed))
        }
        _ => false,
    }
}

fn cleanup_flow_reference(reference: &WireText) -> Option<u64> {
    reference.as_str().strip_prefix("flow:")?.parse().ok()
}

fn cleanup_same_except_originals(before: &RunCleanup, after: &RunCleanup) -> bool {
    before.round == after.round
        && before.object == after.object
        && before.plant_step == after.plant_step
        && before.plant_request_digest == after.plant_request_digest
        && before.object_id == after.object_id
        && before.ownership == after.ownership
        && before.cleanup_step == after.cleanup_step
        && before.cleanup_request_digest == after.cleanup_request_digest
        && before.flow_id_floor == after.flow_id_floor
        && before.instrument_reference == after.instrument_reference
        && before.effects == after.effects
        && before.response_status == after.response_status
        && before.outcome == after.outcome
}

fn cleanup_summary(db: &Connection, run: &RunId) -> Result<Cleanup> {
    let objects = cleanup_objects(db, run)?;
    if objects.is_empty()
        || objects
            .iter()
            .all(|object| object.outcome == CleanupObjectOutcome::NotRequired)
    {
        return Ok(Cleanup::NotRequired);
    }
    let complete = objects
        .iter()
        .filter(|object| object.outcome == CleanupObjectOutcome::Complete)
        .count();
    let unresolved = objects.iter().any(|object| {
        matches!(
            object.outcome,
            CleanupObjectOutcome::Owed
                | CleanupObjectOutcome::InFlight
                | CleanupObjectOutcome::Unknown
        )
    });
    let failed = objects
        .iter()
        .any(|object| object.outcome == CleanupObjectOutcome::Failed);
    if complete > 0 && (unresolved || failed) {
        Ok(Cleanup::Partial)
    } else if unresolved {
        Ok(Cleanup::Unknown)
    } else if failed {
        Ok(Cleanup::Failed)
    } else {
        Ok(Cleanup::Complete)
    }
}

fn original_enrichment(stored: &[crate::wire::Flow], linked: &[crate::wire::Flow]) -> bool {
    stored.len() == linked.len()
        && stored.iter().zip(linked).all(|(before, after)| {
            before.step == after.step
                && before.flow_id == after.flow_id
                && before.completeness == after.completeness
                && before.decoder == after.decoder
                && match (&before.original, &after.original) {
                    (None, Some(_)) | (None, None) => true,
                    (Some(before), Some(after)) => before == after,
                    (Some(_), None) => false,
                }
        })
}

fn insert_step(tx: &Transaction<'_>, run: &RunId, step: &RunStep) -> Result<()> {
    one(tx.execute(
        "INSERT INTO run_steps (run_id, number, step, request_digest, flow_id_floor, instrument_reference, effects, flow_refs)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        params![run.as_str(), step.number.to_string(), step.step.as_str(), step.request_digest.as_str(), step.flow_id_floor.map(|v| v.to_string()),
            step.instrument_reference.as_ref().map(|v| v.as_str()), step.effects.map(tag).transpose()?, json(&step.flows)?],
    )?)
}

fn put_run(tx: &Transaction<'_>, run: &Run) -> Result<()> {
    one(tx.execute(
        "INSERT INTO runs (id, engagement_id, request_key, experiment_digest, state, flags, effects,
                           oracle_result, reproduction, cleanup) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT (id) DO UPDATE SET state=excluded.state,
             flags=CASE
                 WHEN EXISTS(SELECT 1 FROM json_each(runs.flags) WHERE value='cancel_requested')
                      AND NOT EXISTS(SELECT 1 FROM json_each(excluded.flags) WHERE value='cancel_requested')
                 THEN json_insert(excluded.flags, '$[#]', 'cancel_requested')
                 ELSE excluded.flags
             END,
             effects=excluded.effects,
             oracle_result=excluded.oracle_result, reproduction=excluded.reproduction,
             cleanup=CASE WHEN EXISTS (SELECT 1 FROM run_cleanup c WHERE c.run_id=runs.id)
                          THEN runs.cleanup ELSE excluded.cleanup END
         WHERE engagement_id=excluded.engagement_id AND request_key=excluded.request_key
             AND experiment_digest=excluded.experiment_digest",
        params![run.id.as_str(), run.engagement.as_str(), run.request_key.as_str(), run.experiment_digest.as_str(),
            tag(run.state)?, json(&run.flags)?, tag(run.effects)?, run.oracle_result.map(tag).transpose()?,
            tag(run.reproduction)?, tag(run.cleanup)?],
    )?)
}

/// Insert or update the run row and every bundled step in one statement set.
fn insert_run(tx: &Transaction<'_>, run: &Run) -> Result<()> {
    validate_steps(run)?;
    put_run(tx, run)?;
    for step in &run.steps {
        put_step(tx, &run.id, step)?;
    }
    Ok(())
}

/// Create a run and its steps strictly. An existing run row is never adopted
/// or rewritten through this path: a run identity that is already stored,
/// whatever its state or schema of origin, is a conflict.
fn create_run(tx: &Transaction<'_>, run: &Run) -> Result<()> {
    let stored: Option<i64> = tx
        .query_row(
            "SELECT 1 FROM runs WHERE id=?1 OR request_key=?2 LIMIT 1",
            params![run.id.as_str(), run.request_key.as_str()],
            |r| r.get(0),
        )
        .optional()?;
    if stored.is_some() {
        return Err(StoreError::Conflict);
    }
    validate_steps(run)?;
    one(tx.execute(
        "INSERT INTO runs (id, engagement_id, request_key, experiment_digest, state, flags, effects,
                           oracle_result, reproduction, cleanup) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        params![run.id.as_str(), run.engagement.as_str(), run.request_key.as_str(), run.experiment_digest.as_str(),
            tag(run.state)?, json(&run.flags)?, tag(run.effects)?, run.oracle_result.map(tag).transpose()?,
            tag(run.reproduction)?, tag(run.cleanup)?],
    )?)?;
    for step in &run.steps {
        insert_step(tx, &run.id, step)?;
    }
    Ok(())
}

fn stored_request(db: &Connection, key: &RequestKey) -> Result<Option<StoredRequest>> {
    type Row = (
        String,
        String,
        String,
        String,
        String,
        String,
        i64,
        Option<String>,
        Option<i64>,
        i64,
    );
    let stored: Option<Row> = db
        .query_row(
            "SELECT engagement_id, binding, command, input, input_digest, run_id, receipt_revision,
                 lead_id, lead_revision, engagement_revision
             FROM request_keys WHERE key=?",
            [key.as_str()],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                    r.get(7)?,
                    r.get(8)?,
                    r.get(9)?,
                ))
            },
        )
        .optional()?;
    stored
        .map(|stored| {
            Ok(StoredRequest {
                engagement: stored.0,
                binding: stored.1,
                command: stored.2,
                input: stored.3,
                input_digest: stored.4,
                run_id: stored.5,
                receipt: unsigned(stored.6)?,
                lead_id: stored.7,
                lead_revision: stored.8.map(unsigned).transpose()?,
                engagement_revision: unsigned(stored.9)?,
            })
        })
        .transpose()
}

/// Load the run a verified key row names and bind it back to that key. The
/// association is exact and one-way: the key names this run, the run names this
/// key, the run belongs to the stored engagement, and the stored receipt is the
/// audit event that accepted the run.
fn acceptance(db: &Connection, key: &RequestKey, stored: &StoredRequest) -> Result<RunAcceptance> {
    let run_id = RunId::try_from(stored.run_id.clone()).map_err(|_| StoreError::Integrity)?;
    let run = load_run(db, &run_id)?;
    if run.request_key != *key || run.engagement.as_str() != stored.engagement {
        return Err(StoreError::Integrity);
    }
    let receipt: Option<i64> = db
        .query_row(
            "SELECT 1 FROM audit_events
             WHERE revision=?1 AND subject=?2
               AND (operation=?3 OR (operation=?4 AND ?5='verify'))",
            params![
                integer(stored.receipt)?,
                stored.run_id.as_str(),
                REQUEST_ACCEPT,
                VERIFY_REQUEST_ACCEPT,
                stored.command,
            ],
            |r| r.get(0),
        )
        .optional()?;
    if receipt.is_none() {
        return Err(StoreError::Integrity);
    }
    Ok(RunAcceptance {
        run,
        receipt: stored.receipt,
        lead_id: stored
            .lead_id
            .as_ref()
            .map(|value| LeadId::try_from(value.clone()).map_err(|_| StoreError::Integrity))
            .transpose()?,
        lead_revision: stored.lead_revision,
        engagement_revision: stored.engagement_revision,
    })
}

/// Load a run with its current durable state and steps. A replay reports what
/// the run is now, not the snapshot taken when the key was accepted.
fn load_run(db: &Connection, id: &RunId) -> Result<Run> {
    let stored = db.query_row(
        "SELECT engagement_id, request_key, experiment_digest, state, flags, effects,
             oracle_result, reproduction, cleanup FROM runs WHERE id=?",
        [id.as_str()],
        |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, Option<String>>(6)?,
                r.get::<_, String>(7)?,
                r.get::<_, String>(8)?,
            ))
        },
    )?;
    let mut steps = db.prepare(
        "SELECT number, step, request_digest, flow_id_floor, instrument_reference, effects, flow_refs
         FROM run_steps WHERE run_id=? ORDER BY CAST(number AS INTEGER)",
    )?;
    let steps = steps
        .query_map([id.as_str()], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, Option<String>>(3)?,
                r.get::<_, Option<String>>(4)?,
                r.get::<_, Option<String>>(5)?,
                r.get::<_, String>(6)?,
            ))
        })?
        .map(|row| {
            let (number, step, digest, floor, reference, effects, flows) = row?;
            Ok(RunStep {
                number: number.parse().map_err(|_| StoreError::Decode)?,
                step: step.try_into().map_err(|_| StoreError::Schema)?,
                request_digest: Sha256Digest::try_from(digest).map_err(|_| StoreError::Schema)?,
                flow_id_floor: floor
                    .map(|value| value.parse().map_err(|_| StoreError::Decode))
                    .transpose()?,
                instrument_reference: reference
                    .map(WireText::try_from)
                    .transpose()
                    .map_err(|_| StoreError::Schema)?,
                effects: effects.map(|value| tag_value(&value)).transpose()?,
                flows: json_value(&flows)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(Run {
        id: id.clone(),
        request_key: RequestKey::try_from(stored.1).map_err(|_| StoreError::Schema)?,
        engagement: EngagementId::try_from(stored.0).map_err(|_| StoreError::Schema)?,
        experiment_digest: Sha256Digest::try_from(stored.2).map_err(|_| StoreError::Schema)?,
        steps,
        state: tag_value(&stored.3)?,
        flags: json_value(&stored.4)?,
        effects: tag_value(&stored.5)?,
        oracle_result: stored.6.map(|value| tag_value(&value)).transpose()?,
        reproduction: tag_value(&stored.7)?,
        cleanup: tag_value(&stored.8)?,
    })
}

/// Snapshot the effective selectors on first acceptance. A null caller
/// selector is resolved once here; a replay never resolves it again.
///
/// An explicit engagement or lead revision must exist in the selected
/// engagement, and a lead or finding selector resolves only there. A foreign
/// object and an absent one get the same answer, so a lookup never reveals
/// another engagement's lead, revision or existence.
fn resolve_selectors(
    db: &Connection,
    engagement: &EngagementId,
    input: &NormalizedInput,
) -> Result<(Option<LeadId>, Option<u64>, u64)> {
    const LEAD_IN_SCOPE: &str = "SELECT 1 FROM lead_revisions r JOIN leads l ON l.id = r.lead_id
         WHERE r.lead_id = ?1 AND l.engagement_id = ?2";
    const LEAD_REVISION_IN_SCOPE: &str =
        "SELECT 1 FROM lead_revisions r JOIN leads l ON l.id = r.lead_id
         WHERE r.lead_id = ?1 AND l.engagement_id = ?2 AND r.revision = ?3";

    let arguments = input.arguments();
    let engagement_revision = match arguments.get("engagement_revision") {
        None | Some(Value::Null) => db
            .query_row(
                "SELECT MAX(revision) FROM engagement_revisions WHERE engagement_id=?",
                [engagement.as_str()],
                |r| r.get::<_, Option<i64>>(0),
            )?
            .map(unsigned)
            .transpose()?
            .unwrap_or(0),
        Some(value) => {
            let revision = value.as_u64().ok_or(StoreError::Schema)?;
            if !exists(
                db,
                "SELECT 1 FROM engagement_revisions WHERE engagement_id=?1 AND revision=?2",
                params![engagement.as_str(), integer(revision)?],
            )? {
                return Err(StoreError::SelectorNotFound);
            }
            revision
        }
    };
    let lead_id = arguments
        .get("lead_id")
        .or_else(|| arguments.get("finding_id"))
        .and_then(Value::as_str)
        .map(|value| LeadId::try_from(value.to_owned()).map_err(|_| StoreError::Schema))
        .transpose()?;
    let lead_revision = match (lead_id.as_ref(), arguments.get("lead_revision")) {
        (Some(lead), explicit) => {
            if !exists(
                db,
                LEAD_IN_SCOPE,
                params![lead.as_str(), engagement.as_str()],
            )? {
                return Err(StoreError::SelectorNotFound);
            }
            match explicit {
                None | Some(Value::Null) => db
                    .query_row(
                        "SELECT MAX(revision) FROM lead_revisions WHERE lead_id=?",
                        [lead.as_str()],
                        |r| r.get::<_, Option<i64>>(0),
                    )?
                    .map(unsigned)
                    .transpose()?,
                Some(value) => {
                    let revision = value.as_u64().ok_or(StoreError::Schema)?;
                    if !exists(
                        db,
                        LEAD_REVISION_IN_SCOPE,
                        params![lead.as_str(), engagement.as_str(), integer(revision)?],
                    )? {
                        return Err(StoreError::SelectorNotFound);
                    }
                    Some(revision)
                }
            }
        }
        (None, _) => None,
    };
    Ok((lead_id, lead_revision, engagement_revision))
}

fn exists(db: &Connection, sql: &str, parameters: impl rusqlite::Params) -> Result<bool> {
    Ok(db
        .query_row(sql, parameters, |r| r.get::<_, i64>(0))
        .optional()?
        .is_some())
}

fn tag_value<T: DeserializeOwned>(value: &str) -> Result<T> {
    serde_json::from_value(Value::String(value.to_owned())).map_err(|_| StoreError::Decode)
}

fn json_value<T: DeserializeOwned>(value: &str) -> Result<T> {
    serde_json::from_str(value).map_err(|_| StoreError::Decode)
}

fn one(changed: usize) -> Result<()> {
    if changed == 1 {
        Ok(())
    } else {
        Err(StoreError::Conflict)
    }
}

fn unsigned(value: i64) -> Result<u64> {
    value.try_into().map_err(|_| StoreError::CounterRange)
}

fn integer(value: u64) -> Result<i64> {
    value.try_into().map_err(|_| StoreError::CounterRange)
}

fn json<T: Serialize>(value: &T) -> Result<String> {
    Ok(serde_json::to_string(value)?)
}

fn tag(value: impl Serialize) -> Result<String> {
    match serde_json::to_value(value)? {
        serde_json::Value::String(s) => Ok(s),
        _ => Err(StoreError::Schema),
    }
}

fn pragma(db: &Connection, name: &str) -> Result<i64> {
    Ok(db.pragma_query_value(None, name, |row| row.get(0))?)
}

fn commit(tx: Transaction<'_>, operation: &str, subject: &str) -> Result<u64> {
    let revision = advance(&tx, operation, subject)?;
    tx.commit()?;
    Ok(revision)
}

/// Allocate the next store revision and append its audit event. Both happen
/// inside the caller's transaction, so a failed write advances neither.
fn advance(tx: &Transaction<'_>, operation: &str, subject: &str) -> Result<u64> {
    let revision = unsigned(tx.query_row(
        "UPDATE store_revision SET revision=revision+1 WHERE singleton=1 RETURNING revision",
        [],
        |r| r.get::<_, i64>(0),
    )?)?;
    tx.execute(
        "INSERT INTO audit_events (revision, operation, subject) VALUES (?, ?, ?)",
        params![integer(revision)?, operation, subject],
    )?;
    Ok(revision)
}

fn schema_version(db: &Connection) -> Result<usize> {
    let (version, application, populated): (i64, i64, bool) = db.query_row(
        "SELECT user_version, application_id,
             EXISTS(SELECT 1 FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*')
         FROM pragma_user_version, pragma_application_id",
        [],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;
    let current = usize::try_from(version).map_err(|_| StoreError::Schema)?;
    if current > MIGRATIONS.len()
        || (current == 0 && (application != 0 || populated))
        || (current > 0 && application != APPLICATION_ID)
    {
        return Err(StoreError::Schema);
    }
    Ok(current)
}

fn check_workspace(db: &Connection, workspace_id: &str) -> Result<()> {
    let stored: Option<String> = db
        .query_row(
            "SELECT workspace_id FROM store_workspace WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    if stored.as_deref() != Some(workspace_id) {
        return Err(StoreError::Integrity);
    }
    let mut moved = 0;
    db.file_control(Some("main"), FileControl::HasMoved(&mut moved))?;
    if moved != 0 {
        return Err(StoreError::Integrity);
    }
    Ok(())
}

fn migrate(db: &mut Connection) -> Result<()> {
    // Another first opener can finish migration before we acquire the write lock.
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let current = schema_version(&tx)?;
    if current == MIGRATIONS.len() {
        return Ok(());
    }
    for sql in &MIGRATIONS[current..] {
        tx.execute_batch(sql)?;
    }
    tx.pragma_update(None, "user_version", MIGRATIONS.len() as u32)?;
    tx.pragma_update(None, "application_id", APPLICATION_ID)?;
    commit(tx, "schema.migrate", &MIGRATIONS.len().to_string())?;
    Ok(())
}

#[cfg(test)]
mod request_tests;
#[cfg(test)]
mod tests;
