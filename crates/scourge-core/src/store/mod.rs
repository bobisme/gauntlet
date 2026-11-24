//! Transactional SQLite metadata for a local coordination store.
//! Evidence content stays in its owning store. All SQL writes enter through
//! a transaction that allocates its revision and appends its audit event.

pub mod checks;
pub mod entry;
pub mod read;

use std::{
    collections::BTreeSet,
    path::Path,
    time::{Duration, Instant},
};

use rusqlite::{
    Connection, FileControl, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params,
};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;

use crate::{
    canonical::Sha256Digest,
    domain::{LeadEvent, LeadRevision, Run, RunStep, VerificationIndex},
    ids::{EngagementId, LeadId, PublicationIntentId, RequestKey, RunId, WireText},
    request::NormalizedInput,
    wire::{
        Artifact, Checkpoint, Cleanup, Effect, ErrorCode, PublicationIntentV1, PublicationState,
        RunFlag, RunState,
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
];
const APPLICATION_ID: i64 = i32::from_be_bytes(*b"SCRG") as i64;

/// Wait this long for another writer, then report a typed conflict. Local
/// contention is retryable; it is not evidence that the store is corrupt.
const BUSY_TIMEOUT: Duration = Duration::from_millis(500);

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
    #[error("coordination metadata is locked by another writer")]
    Busy,
    #[error("no request key in this scope")]
    RequestNotFound,
    #[error("no such object in this scope")]
    SelectorNotFound,
    #[error("request key was already used for different input")]
    IdempotencyKeyReused,
    #[error("lead revision does not match the stored revision")]
    RevisionConflict,
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
            Self::Conflict | Self::Busy => ErrorCode::ConflictingRun,
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

/// The local identity a request key is scoped to. `binding` is the resolved
/// workspace binding name, never a path spelling supplied by the caller.
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

/// The durable identity returned by a lead mutation. `committed` is false only
/// when a producer import reopens the lead already bound to that exact source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeadAcceptance {
    pub lead_id: LeadId,
    pub revision: u64,
    pub committed: bool,
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
    fn verify(&self) -> Result<()> {
        if Sha256Digest::of(self.input.as_bytes()).as_str() != self.input_digest {
            return Err(StoreError::Integrity);
        }
        let input = NormalizedInput::read_canonical(self.input.as_bytes())
            .map_err(|_| StoreError::Integrity)?;
        if input.command() != self.command || self.lead_id.is_some() != self.lead_revision.is_some()
        {
            return Err(StoreError::Integrity);
        }
        Ok(())
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
}

impl Store {
    /// Open or create a local SQLite file. The durability profile applies to
    /// every connection, including connections to an already-migrated file.
    /// A blocked writer gives up after [`BUSY_TIMEOUT`] with a typed conflict.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_configured(path.as_ref(), None)
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
        let current = schema_version(&db)?;
        if let Some(id) = workspace_id {
            check_workspace(&db, id)?;
        }
        let journal: String = db.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))?;
        db.pragma_update(None, "foreign_keys", "ON")?;
        db.pragma_update(None, "synchronous", "FULL")?;
        if !journal.eq_ignore_ascii_case("wal")
            || pragma(&db, "foreign_keys")? != 1
            || pragma(&db, "synchronous")? != 2
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
        let store = Self { db };
        store.revision()?;
        Ok(store)
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
        let (revision, sequence, digest): (_, _, Option<String>) = self.db.query_row(
            "SELECT revision, head_sequence, head_digest FROM store_revision, engagements
             WHERE singleton = 1 AND id = ?",
            [engagement.as_str()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        let record_digest = digest
            .map(Sha256Digest::try_from)
            .transpose()
            .map_err(|_| StoreError::Schema)?;
        Ok((
            unsigned(revision)?,
            Checkpoint {
                engagement: engagement.clone(),
                sequence: unsigned(sequence)?,
                record_digest,
            },
        ))
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

    /// Pass `None` to create a run. An update requires the revision returned
    /// when the caller's previous run metadata was recorded, including the
    /// request acceptance that declared it. Unrelated writes and individually
    /// recorded steps do not invalidate that receipt.
    pub fn record_run(&mut self, run: &Run, previous_revision: Option<u64>) -> Result<u64> {
        self.write("run.record", run.id.as_str(), |tx| {
            let stored_revision: Option<i64> = tx.query_row(
                "SELECT MAX(revision) FROM audit_events
                 WHERE operation IN ('run.record', 'request.accept') AND subject=?",
                [run.id.as_str()],
                |r| r.get(0),
            )?;
            if stored_revision.map(unsigned).transpose()? != previous_revision {
                return Err(StoreError::Conflict);
            }
            if !run.steps.is_empty() && keyed_run_without_conflicts(tx, &run.id)? {
                if legacy_terminal_update_without_conflicts(tx, run)? {
                    // A migrated resolved terminal run may replay only its
                    // already-settled step rows; the helper rejects additions.
                } else if !install_legacy_start_barrier(tx, &run.id)? {
                    return Err(StoreError::Conflict);
                }
            }
            insert_run(tx, run)?;
            if conflicts_resolved(tx, &run.id)? {
                release_conflict_rows(tx, &run.id)?;
            }
            Ok(())
        })
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
    /// hidden. Recording an outcome remains the `record_run` compare-and-set.
    pub fn declare_request(
        &mut self,
        scope: &RequestScope,
        input: &NormalizedInput,
        run: &Run,
    ) -> Result<RunAcceptance> {
        if run.engagement != scope.engagement {
            return Err(StoreError::Conflict);
        }
        let bytes = input.to_bytes().map_err(|_| StoreError::Schema)?;
        let digest = Sha256Digest::of(&bytes);
        let stored_input = String::from_utf8(bytes).map_err(|_| StoreError::Schema)?;

        // A replay reads one snapshot and takes no write lock, so an identical
        // caller neither waits for the minting writer nor reports contention.
        {
            let snapshot = self.db.unchecked_transaction()?;
            if let Some(stored) = stored_request(&snapshot, &run.request_key)? {
                return replay_request(&snapshot, scope, &run.request_key, &stored, input);
            }
        }

        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        // Accept-or-reopen: the loser of an identical race sees the acceptance
        // the winner committed and returns it unchanged.
        if let Some(stored) = stored_request(&tx, &run.request_key)? {
            return replay_request(&tx, scope, &run.request_key, &stored, input);
        }
        tx.execute(
            "INSERT INTO engagements (id) VALUES (?) ON CONFLICT (id) DO NOTHING",
            [scope.engagement.as_str()],
        )?;
        ensure_engagement_accepting(&tx, &scope.engagement)?;
        create_run(&tx, run)?;
        let (lead_id, lead_revision, engagement_revision) =
            resolve_selectors(&tx, &scope.engagement, input)?;
        let receipt = advance(&tx, "request.accept", run.id.as_str())?;
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
        let snapshot = self.db.unchecked_transaction()?;
        let stored = stored_request(&snapshot, key)?
            .filter(|stored| stored.in_scope(scope))
            .ok_or(StoreError::RequestNotFound)?;
        replay_request(&snapshot, scope, key, &stored, input)
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
    pub fn claim_conflicts(&mut self, run: &RunId, keys: &BTreeSet<String>) -> Result<u64> {
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

    pub fn record_step(&mut self, run: &RunId, step: &RunStep) -> Result<u64> {
        self.write("run.step", run.as_str(), |tx| {
            if keyed_run_without_conflicts(tx, run)? && !install_legacy_start_barrier(tx, run)? {
                return Err(StoreError::Conflict);
            }
            put_step(tx, run, step)
        })
    }

    /// Link the retained frozen experiment to its already-declared run.
    ///
    /// The run row and request key necessarily predate this call. Repeating
    /// the same link is read-only and returns the original audit revision;
    /// changing either the artifact or its digest is a conflict.
    pub fn link_experiment(&mut self, run: &RunId, artifact: &Artifact) -> Result<u64> {
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
        one(tx.execute(
            "UPDATE runs SET experiment_artifact_id=? WHERE id=? AND experiment_artifact_id IS NULL",
            params![artifact.artifact_id.as_str(), run.as_str()],
        )?)?;
        let revision = advance(&tx, "run.experiment", run.as_str())?;
        tx.commit()?;
        Ok(revision)
    }

    pub fn append_intent(&mut self, intent: &PublicationIntentV1) -> Result<u64> {
        if intent.engagement != intent.expected_head.engagement
            || intent.state != PublicationState::Pending
            || intent.artifact_id.is_some()
        {
            return Err(StoreError::Conflict);
        }
        self.write("publication.intent", intent.intent_id.as_str(), |tx| {
            tx.execute(
                "INSERT INTO publication_intents
                 (id, engagement_id, run_id, record_id, record_digest, expected_sequence, expected_digest, state)
                 VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')",
                params![intent.intent_id.as_str(), intent.engagement.as_str(), intent.run_id.as_str(),
                    intent.record_id.as_str(), intent.record_digest.as_str(), integer(intent.expected_head.sequence)?,
                    intent.expected_head.record_digest.as_ref().map(|v| v.as_str())],
            )?;
            Ok(())
        })
    }

    /// Index a retained record, advance its checkpoint, and close its matching
    /// intent in one commit. Repeating that exact publication returns the
    /// original commit revision, even after subsequent head advances.
    pub fn link_record(
        &mut self,
        intent: &PublicationIntentId,
        index: &VerificationIndex,
    ) -> Result<u64> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let state: Option<String> = tx
            .query_row(
                "SELECT state FROM publication_intents WHERE id=?",
                [intent.as_str()],
                |r| r.get(0),
            )
            .optional()?;
        match state.as_deref() {
            Some("complete") => {
                let receipt = tx.query_row(
                    "SELECT a.revision FROM verifications v JOIN audit_events a
                         ON a.operation='publication.link' AND a.subject=v.record_id
                     WHERE v.record_id=? AND v.engagement_id=? AND v.sequence=? AND v.run_id=?
                         AND v.lead_id=? AND v.artifact_id=? AND v.record_digest=? AND v.intent_id=?",
                    params![index.record_id.as_str(), index.engagement.as_str(), integer(index.sequence)?, index.run_id.as_str(),
                        index.lead_id.as_str(), index.record.artifact_id.as_str(), index.record.digest.as_str(), intent.as_str()],
                    |r| r.get::<_, i64>(0),
                ).optional()?.ok_or(StoreError::Conflict)?;
                return unsigned(receipt);
            }
            Some("pending") => {}
            _ => return Err(StoreError::Conflict),
        }
        tx.execute(
                "INSERT INTO verifications (record_id, engagement_id, sequence, run_id, lead_id, artifact_id, record_digest, intent_id)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                params![index.record_id.as_str(), index.engagement.as_str(), integer(index.sequence)?, index.run_id.as_str(),
                    index.lead_id.as_str(), index.record.artifact_id.as_str(), index.record.digest.as_str(), intent.as_str()],
            )?;
        one(tx.execute(
                "UPDATE engagements SET head_sequence=?1, head_digest=?2 WHERE id=?3 AND head_sequence+1=?1
                 AND EXISTS (SELECT 1 FROM publication_intents WHERE id=?4 AND state='pending'
                     AND expected_sequence=engagements.head_sequence AND expected_digest IS engagements.head_digest)",
                params![integer(index.sequence)?, index.record.digest.as_str(), index.engagement.as_str(), intent.as_str()],
            )?)?;
        one(tx.execute(
            "UPDATE publication_intents SET state='complete' WHERE id=?",
            [intent.as_str()],
        )?)?;
        commit(tx, "publication.link", index.record_id.as_str())
    }
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
    ensure_engagement_accepting(db, &scope.engagement)?;
    acceptance(db, key, stored)
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
    Ok((state, step_count))
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
    one(tx.execute(
        "INSERT INTO run_steps (run_id, number, step, request_digest, flow_id_floor, instrument_reference, effects, flow_refs)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (run_id, number) DO UPDATE SET
             instrument_reference=excluded.instrument_reference, effects=excluded.effects, flow_refs=excluded.flow_refs
         WHERE step=excluded.step AND request_digest=excluded.request_digest AND flow_id_floor IS excluded.flow_id_floor
             AND (instrument_reference IS NULL OR instrument_reference IS excluded.instrument_reference)
             AND (effects IS NULL OR effects IS excluded.effects
                  OR (effects='unknown' AND excluded.effects IN ('observed', 'none')))
             AND (flow_refs='[]' OR flow_refs=excluded.flow_refs)",
        params![run.as_str(), step.number.to_string(), step.step.as_str(), step.request_digest.as_str(), step.flow_id_floor.map(|v| v.to_string()),
            step.instrument_reference.as_ref().map(|v| v.as_str()), step.effects.map(tag).transpose()?, json(&step.flows)?],
    )?)
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
             oracle_result=excluded.oracle_result, reproduction=excluded.reproduction, cleanup=excluded.cleanup
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
        .query_row("SELECT 1 FROM runs WHERE id=?", [run.id.as_str()], |r| {
            r.get(0)
        })
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
            "SELECT 1 FROM audit_events WHERE revision=? AND operation='request.accept' AND subject=?",
            params![integer(stored.receipt)?, stored.run_id.as_str()],
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
