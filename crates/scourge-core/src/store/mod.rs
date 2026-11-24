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
    wire::{Artifact, Checkpoint, ErrorCode, PublicationIntentV1, PublicationState},
};

const MIGRATIONS: &[&str] = &[
    include_str!("001_initial.sql"),
    include_str!("002_audit_receipts.sql"),
    include_str!("003_request_keys.sql"),
    include_str!("004_request_key_integrity.sql"),
    include_str!("005_recorded_checks.sql"),
    include_str!("006_workspace_identity.sql"),
    include_str!("007_entry_teapot_observation.sql"),
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
        self.write("engagement.revision", id.as_str(), |tx| {
            tx.execute("INSERT INTO engagements (id) VALUES (?) ON CONFLICT (id) DO NOTHING", [id.as_str()])?;
            tx.execute(
                "INSERT INTO engagement_revisions SELECT ?1, COALESCE(MAX(revision), 0) + 1, ?2, ?3, ?4
                 FROM engagement_revisions WHERE engagement_id = ?1",
                params![id.as_str(), manifest.artifact_id.as_str(), manifest.digest.as_str(), pass.as_str()],
            )?;
            Ok(())
        })
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
            if current == 0 {
                tx.execute(
                    "INSERT INTO leads (id, engagement_id) VALUES (?, ?)",
                    params![lead.lead_id.as_str(), engagement.as_str()],
                )?;
            }
            one(tx.execute(
                "INSERT INTO lead_revisions (lead_id, revision, text, class, slots, proposed_policy)
                 VALUES (?, ?, ?, ?, ?, ?)",
                params![lead.lead_id.as_str(), integer(lead.revision)?, lead.text.as_str(),
                    lead.class.as_ref().map(|v| v.as_str()), json(&lead.slots)?,
                    lead.proposed_policy.as_ref().map(json).transpose()?],
            )?)
        })
    }

    pub fn append_lead_event(&mut self, event: &LeadEvent) -> Result<u64> {
        self.write("lead.event", event.lead_id.as_str(), |tx| {
            tx.execute(
                "INSERT INTO lead_events (lead_id, lead_revision, kind, actor, reason, evidence_refs, recorded_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?)",
                params![event.lead_id.as_str(), integer(event.lead_revision)?, json(&event.kind)?,
                    event.actor.as_str(), event.reason.as_str(), json(&event.evidence)?, event.recorded_at.as_str()],
            )?;
            Ok(())
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
            insert_run(tx, run)
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

    pub fn record_step(&mut self, run: &RunId, step: &RunStep) -> Result<u64> {
        self.write("run.step", run.as_str(), |tx| put_step(tx, run, step))
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

/// A run names each step once. A repeated number would silently replace the
/// earlier step, so it is refused instead of collapsed.
fn validate_steps(run: &Run) -> Result<()> {
    let mut numbers = BTreeSet::new();
    if run.steps.iter().any(|step| !numbers.insert(step.number)) {
        return Err(StoreError::Conflict);
    }
    Ok(())
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
         ON CONFLICT (id) DO UPDATE SET state=excluded.state, flags=excluded.flags, effects=excluded.effects,
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
