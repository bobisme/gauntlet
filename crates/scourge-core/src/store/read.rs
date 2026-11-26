//! Read-only inspection of coordination metadata. Recovery can decode the
//! exact stored request identity alongside the run, steps and audit history.

use std::{
    fmt::Write as _,
    fs::{self, File},
    os::unix::{ffi::OsStrExt, fs::FileExt},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use rusqlite::{Connection, OpenFlags, OptionalExtension, Row, config::DbConfig, ffi, params};

use super::checks::{self, CheckView};
use super::{
    BUSY_TIMEOUT, REQUEST_ACCEPT, RequestScope, Result, RunAcceptance, StoreError,
    VERIFY_REQUEST_ACCEPT, acceptance, check_workspace, exists, initialization_lock, json_value,
    run_metadata_revision, schema_version, stored_request, tag, tag_value, unsigned,
};
use crate::{
    canonical::Sha256Digest,
    domain::{LeadEvent, LeadEventKind, LeadOrigin, LeadRevision, VerificationIndex},
    ids::{ArtifactId, EngagementId, LeadId, RequestKey, RunId, VerificationId, WireText},
    request::NormalizedInput,
    verification::registry,
    wire::{Artifact, Completeness, Effect, RunState, RunSummary, Timestamp},
};

const REQUEST_KEYS_SCHEMA_VERSION: usize = 3;
const RUN_EXPERIMENT_SCHEMA_VERSION: usize = 9;

pub struct ReadStore {
    db: Connection,
    path: PathBuf,
}

impl ReadStore {
    /// Open an existing operator-selected database without creating or migrating it.
    /// The Unix VFS may take WAL locks but may not create or write shared
    /// memory. If recovery is required, an authorized writer must do it.
    pub fn open(path: &Path) -> Result<Self> {
        let _opening =
            initialization_lock(path, rustix::fs::FlockOperation::NonBlockingLockShared)?;
        validate_files(path)?;
        let mut uri = String::from("file:");
        for byte in path.as_os_str().as_bytes().iter().copied() {
            if byte.is_ascii_alphanumeric() || b"/._-".contains(&byte) {
                uri.push(char::from(byte));
            } else {
                write!(uri, "%{byte:02X}").expect("write to string");
            }
        }
        uri.push_str("?readonly_shm=1");
        let db = Connection::open_with_flags(
            uri,
            OpenFlags::SQLITE_OPEN_READ_ONLY
                | OpenFlags::SQLITE_OPEN_NOFOLLOW
                | OpenFlags::SQLITE_OPEN_URI,
        )?;
        db.busy_timeout(Duration::ZERO)?;
        db.set_db_config(DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, true)?;
        db.execute_batch(
            "PRAGMA query_only=ON; PRAGMA trusted_schema=OFF; PRAGMA temp_store=MEMORY",
        )?;
        Ok(Self {
            db,
            path: path.to_owned(),
        })
    }

    pub(crate) fn verify_workspace(&self, workspace_id: &str) -> Result<()> {
        self.snapshot(|snapshot| check_workspace(snapshot.db, workspace_id))
    }

    /// Read an accepted run and its recovery metadata in one SQLite snapshot.
    pub fn recover(
        &self,
        scope: &RequestScope,
        selector: RecoverySelector<'_>,
    ) -> Result<RunRecovery> {
        self.snapshot(|snapshot| snapshot.recover(scope, selector))
    }

    /// All lookups in the callback see one deferred SQLite read transaction.
    /// The transaction ends before the response is rendered or written.
    pub fn snapshot<T>(&self, inspect: impl FnOnce(Snapshot<'_>) -> Result<T>) -> Result<T> {
        let deadline = Instant::now() + BUSY_TIMEOUT;
        loop {
            let opening = initialization_lock(
                &self.path,
                rustix::fs::FlockOperation::NonBlockingLockShared,
            )?;
            validate_files(&self.path)?;
            match self.begin_snapshot() {
                Ok((snapshot, schema_version)) => {
                    return inspect(Snapshot {
                        db: &snapshot,
                        schema_version,
                    });
                }
                Err(error) if retryable_snapshot_error(&error) => {
                    drop(opening);
                    if Instant::now() >= deadline {
                        return Err(StoreError::Busy);
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(error) => return Err(error),
            }
        }
    }

    fn begin_snapshot(&self) -> Result<(rusqlite::Transaction<'_>, usize)> {
        let transaction = self.db.unchecked_transaction()?;
        let version = schema_version(&transaction)?;
        if version == 0 {
            return Err(StoreError::Schema);
        }
        Ok((transaction, version))
    }
}

fn retryable_snapshot_error(error: &StoreError) -> bool {
    match error {
        StoreError::Busy => true,
        StoreError::Database(rusqlite::Error::SqliteFailure(error, _)) => matches!(
            error.extended_code,
            ffi::SQLITE_READONLY_RECOVERY
                | ffi::SQLITE_READONLY_CANTLOCK
                | ffi::SQLITE_READONLY_CANTINIT
                | ffi::SQLITE_PROTOCOL
        ),
        _ => false,
    }
}

#[cfg(test)]
#[test]
fn only_documented_contention_is_retryable() {
    let error =
        |code| StoreError::from(rusqlite::Error::SqliteFailure(ffi::Error::new(code), None));
    assert_eq!(ffi::SQLITE_READONLY_RECOVERY, 264);
    for code in [
        ffi::SQLITE_READONLY_RECOVERY,
        ffi::SQLITE_READONLY_CANTINIT,
        ffi::SQLITE_READONLY_CANTLOCK,
        ffi::SQLITE_PROTOCOL,
        ffi::SQLITE_BUSY_RECOVERY,
    ] {
        assert!(retryable_snapshot_error(&error(code)));
    }
    for code in [
        ffi::SQLITE_READONLY,
        ffi::SQLITE_CANTOPEN,
        ffi::SQLITE_CORRUPT,
        ffi::SQLITE_NOTADB,
        ffi::SQLITE_IOERR_SHORT_READ,
    ] {
        assert!(!retryable_snapshot_error(&error(code)));
    }
}

fn read_regular(path: &Path) -> Result<File> {
    use rustix::fs::{Mode, OFlags, open};

    let file = File::from(
        open(
            path,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| StoreError::ConnectionSettings)?,
    );
    if !file.metadata().is_ok_and(|metadata| metadata.is_file()) {
        return Err(StoreError::ConnectionSettings);
    }
    Ok(file)
}

fn sidecar(path: &Path, suffix: &str) -> Result<(PathBuf, Option<fs::Metadata>)> {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    let path = PathBuf::from(name);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(meta) if meta.is_file() => Some(meta),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        _ => return Err(StoreError::ConnectionSettings),
    };
    Ok((path, metadata))
}

fn validate_files(path: &Path) -> Result<()> {
    if !fs::symlink_metadata(path).is_ok_and(|meta| meta.is_file()) {
        return Err(StoreError::ConnectionSettings);
    }
    let (wal_path, wal) = sidecar(path, "-wal")?;
    let (_, shm) = sidecar(path, "-shm")?;
    match (wal, shm) {
        (None, None) => {
            let mut format = [0_u8; 2];
            read_regular(path)?
                .read_exact_at(&mut format, 18)
                .map_err(|_| StoreError::Schema)?;
            // Never interpret the main DB as an immutable snapshot when
            // its WAL header says there might be committed data elsewhere.
            if format.contains(&2) {
                return Err(StoreError::ConnectionSettings);
            }
        }
        (Some(wal), Some(shm)) => {
            const SHM_PAGE: u64 = 32 * 1024;
            if shm.len() < SHM_PAGE || !shm.len().is_multiple_of(SHM_PAGE) {
                return Err(StoreError::Integrity);
            }
            if wal.len() != 0 {
                validate_wal_header(&wal_path)?;
            }
        }
        _ => return Err(StoreError::ConnectionSettings),
    }
    Ok(())
}

fn validate_wal_header(path: &Path) -> Result<()> {
    let mut header = [0_u8; 32];
    read_regular(path)?
        .read_exact_at(&mut header, 0)
        .map_err(|_| StoreError::Integrity)?;
    let word = |index| u32::from_be_bytes(header[index..index + 4].try_into().expect("WAL word"));
    let magic = word(0);
    let page = word(8);
    if !matches!(magic, 0x377f0682 | 0x377f0683)
        || word(4) != 3_007_000
        || !page.is_power_of_two()
        || !(512..=65536).contains(&page)
    {
        return Err(StoreError::Integrity);
    }
    let checksum_word = |bytes: &[u8]| {
        let bytes = bytes.try_into().expect("four checksum bytes");
        if magic & 1 == 0 {
            u32::from_le_bytes(bytes)
        } else {
            u32::from_be_bytes(bytes)
        }
    };
    let mut s0 = 0_u32;
    let mut s1 = 0_u32;
    for pair in header[..24].as_chunks::<8>().0 {
        s0 = s0.wrapping_add(checksum_word(&pair[..4])).wrapping_add(s1);
        s1 = s1.wrapping_add(checksum_word(&pair[4..])).wrapping_add(s0);
    }
    if (s0, s1) != (word(24), word(28)) {
        return Err(StoreError::Integrity);
    }
    Ok(())
}

pub struct Snapshot<'a> {
    db: &'a Connection,
    schema_version: usize,
}

/// Select a durable acceptance by exact run ID or request key.
#[derive(Debug, Clone, Copy)]
pub enum RecoverySelector<'a> {
    Run(&'a RunId),
    RequestKey(&'a RequestKey),
}

/// Local recovery data for one accepted run in one snapshot.
#[derive(Debug, PartialEq, Eq)]
pub struct RunRecovery {
    pub acceptance: RunAcceptance,
    pub input: NormalizedInput,
    pub experiment_artifact_id: Option<ArtifactId>,
    /// Latest revision of the run metadata used for a run compare-and-set.
    pub run_revision: u64,
    /// Store revision visible to this read transaction.
    pub store_revision: u64,
    /// Run-subject audit events in revision order.
    pub audit: Vec<RunAuditEvent>,
}

impl RunRecovery {
    /// An intent without a durable outcome leaves dispatch unresolved even
    /// when the parent run still records no effect.
    pub fn has_unresolved_dispatch(&self) -> bool {
        let run = &self.acceptance.run;
        run.effects == Effect::Unknown
            || run
                .steps
                .iter()
                .any(|step| matches!(step.effects, None | Some(Effect::Unknown)))
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct RunAuditEvent {
    pub revision: u64,
    pub operation: WireText,
    pub recorded_at: Timestamp,
}

impl<'a> Snapshot<'a> {
    /// Resolve the selector inside the engagement and workspace binding
    /// before decoding any stored request. An absent or ambiguous acceptance
    /// yields the same result as a foreign one.
    pub fn recover(
        &self,
        scope: &RequestScope,
        selector: RecoverySelector<'_>,
    ) -> Result<RunRecovery> {
        if self.schema_version < REQUEST_KEYS_SCHEMA_VERSION {
            return Err(StoreError::SelectorNotFound);
        }
        let (selector, value) = match selector {
            RecoverySelector::Run(id) => ("q.run_id", id.as_str()),
            RecoverySelector::RequestKey(key) => ("q.key", key.as_str()),
        };
        // The v3 schema can associate several request keys with one run, even
        // across bindings. Require the unique, reciprocal association.
        let key: String = self.db.query_row(&format!(
            "SELECT q.key FROM request_keys q
             JOIN runs r ON r.id=q.run_id AND r.engagement_id=q.engagement_id AND r.request_key=q.key
             WHERE q.engagement_id=?1 AND q.binding=?2 AND {selector}=?3
                AND NOT EXISTS (SELECT 1 FROM request_keys other WHERE other.run_id=q.run_id AND other.key<>q.key)"
        ), (scope.engagement.as_str(), scope.binding.as_str(), value), |row| row.get(0))
        .optional()?
        .ok_or(StoreError::SelectorNotFound)?;
        let key = key.parse().map_err(|_| StoreError::Integrity)?;
        let stored = stored_request(self.db, &key)?.ok_or(StoreError::Integrity)?;
        let input = stored.verify()?;
        let acceptance = acceptance(self.db, &key, &stored)?;
        let run_id = &acceptance.run.id;
        let (run_revision, _) =
            run_metadata_revision(self.db, run_id)?.ok_or(StoreError::Integrity)?;
        let store_revision = unsigned(self.db.query_row(
            "SELECT revision FROM store_revision WHERE singleton=1",
            [],
            |row| row.get(0),
        )?)?;
        let experiment_artifact_id = if self.schema_version < RUN_EXPERIMENT_SCHEMA_VERSION {
            None
        } else {
            self.db
                .query_row(
                    "SELECT experiment_artifact_id FROM runs WHERE id=?",
                    [run_id.as_str()],
                    |row| row.get::<_, Option<String>>(0),
                )?
                .map(|id| id.parse().map_err(|_| StoreError::Decode))
                .transpose()?
        };
        let mut audit = self.db.prepare(
            "SELECT revision, CASE operation WHEN ?3 THEN ?2 ELSE operation END, recorded_at
             FROM audit_events
             WHERE subject=?1 AND (operation IN (?2, ?3) OR operation GLOB 'run.*')
             ORDER BY revision",
        )?;
        let audit = audit
            .query_map(
                params![run_id.as_str(), REQUEST_ACCEPT, VERIFY_REQUEST_ACCEPT],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )?
            .map(|row| {
                let (revision, operation, recorded_at) = row?;
                Ok(RunAuditEvent {
                    revision: unsigned(revision)?,
                    operation: operation.parse().map_err(|_| StoreError::Decode)?,
                    recorded_at: recorded_at.parse().map_err(|_| StoreError::Decode)?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(RunRecovery {
            acceptance,
            input,
            experiment_artifact_id,
            run_revision,
            store_revision,
            audit,
        })
    }

    /// Capture the revision and chain checkpoint in this read transaction.
    pub fn checkpoint(&self, engagement: &EngagementId) -> Result<(u64, crate::wire::Checkpoint)> {
        super::checkpoint_in(self.db, engagement)
    }

    /// Read only enough engagement IDs to select the sole engagement or report
    /// ambiguous scope. The caller can bound how many choices it displays.
    pub fn engagements(&self, limit: u32) -> Result<Vec<EngagementId>> {
        let mut query = self
            .db
            .prepare("SELECT id FROM engagements ORDER BY id LIMIT ?")?;
        query
            .query_map([limit], |row| row.get::<_, String>(0))?
            .map(|row| row?.parse().map_err(|_| StoreError::Decode))
            .collect()
    }

    pub fn scope(&self, engagement: EngagementId) -> Result<Scope<'a>> {
        if !exists(
            self.db,
            "SELECT 1 FROM engagements WHERE id=?",
            [engagement.as_str()],
        )? {
            return Err(StoreError::SelectorNotFound);
        }
        Ok(Scope {
            db: self.db,
            engagement,
            schema_version: self.schema_version,
        })
    }
}

/// An immutable chain index obtained from one coordination-store read transaction.
/// Its fields are private so callers cannot assert that an unlinked record was published.
#[derive(Debug)]
pub struct LinkedChain {
    engagement: EngagementId,
    records: Vec<VerificationIndex>,
    manifests: Vec<ManifestIndex>,
    lead: LeadId,
    bindings: Vec<LeadBinding>,
    events: Vec<LeadEvent>,
}

/// The binding-bearing fields of one immutable lead revision.
#[derive(Debug, Clone, PartialEq)]
pub struct LeadBinding {
    pub revision: u64,
    pub class: Option<WireText>,
    pub property: Option<WireText>,
    pub slots: std::collections::BTreeMap<WireText, serde_json::Value>,
}

#[derive(Debug)]
pub struct ManifestIndex {
    revision: u64,
    artifact: Artifact,
    pass_digest: Sha256Digest,
}

impl ManifestIndex {
    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn artifact(&self) -> &Artifact {
        &self.artifact
    }
    pub fn pass_digest(&self) -> &Sha256Digest {
        &self.pass_digest
    }
}

impl LinkedChain {
    pub fn engagement(&self) -> &EngagementId {
        &self.engagement
    }
    pub fn records(&self) -> &[VerificationIndex] {
        &self.records
    }
    pub fn manifests(&self) -> &[ManifestIndex] {
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
}

pub struct Scope<'a> {
    db: &'a Connection,
    engagement: EngagementId,
    schema_version: usize,
}

#[derive(Debug)]
pub struct LeadView {
    pub id: LeadId,
    pub revision: u64,
    pub has_records: bool,
}

pub struct LeadDetail {
    pub lead: LeadRevision,
    pub events: Vec<LeadEvent>,
}

pub struct RunView {
    pub run: RunSummary,
    pub effects: Effect,
}

pub struct RunDetail {
    pub view: RunView,
    pub request_key: RequestKey,
    pub experiment_digest: Sha256Digest,
    pub experiment_artifact_id: Option<ArtifactId>,
}

pub struct RecordView {
    pub id: VerificationId,
    pub sequence: u64,
    pub run: RunId,
    pub lead: LeadId,
    pub digest: Sha256Digest,
    pub oracle_id: Option<String>,
    pub oracle_version: Option<String>,
    pub oracle_digest: Option<Sha256Digest>,
    pub limitations: Option<Vec<String>>,
}

pub struct FlowView {
    pub run: RunId,
    pub number: u64,
    pub completeness: Completeness,
}

impl Scope<'_> {
    /// Read a complete, linked chain at this SQLite snapshot.
    pub fn linked_chain(&self, lead: &LeadId) -> Result<LinkedChain> {
        if self.schema_version < 12 || !super::chain_intact(self.db, &self.engagement)? {
            return Err(StoreError::Integrity);
        }
        let mut query = self.db.prepare(
            "SELECT sequence, record_id, run_id, lead_id, artifact_id, record_digest \
             FROM verifications WHERE engagement_id=? ORDER BY sequence",
        )?;
        let records = query
            .query_map([self.engagement.as_str()], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                ))
            })?
            .map(|row| {
                let (sequence, record, run, lead, artifact, digest) = row?;
                Ok(VerificationIndex {
                    engagement: self.engagement.clone(),
                    sequence: unsigned(sequence)?,
                    record_id: record.parse().map_err(|_| StoreError::Decode)?,
                    run_id: run.parse().map_err(|_| StoreError::Decode)?,
                    lead_id: lead.parse().map_err(|_| StoreError::Decode)?,
                    record: Artifact {
                        artifact_id: artifact.parse().map_err(|_| StoreError::Decode)?,
                        digest: digest.parse().map_err(|_| StoreError::Decode)?,
                    },
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let mut query = self.db.prepare(
            "SELECT revision, manifest_artifact_id, manifest_digest, pass_digest \
             FROM engagement_revisions WHERE engagement_id=? ORDER BY revision",
        )?;
        let manifests = query
            .query_map([self.engagement.as_str()], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })?
            .map(|row| {
                let (revision, artifact, digest, pass) = row?;
                Ok(ManifestIndex {
                    revision: unsigned(revision)?,
                    artifact: Artifact {
                        artifact_id: artifact.parse().map_err(|_| StoreError::Decode)?,
                        digest: digest.parse().map_err(|_| StoreError::Decode)?,
                    },
                    pass_digest: pass.parse().map_err(|_| StoreError::Decode)?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let mut query = self.db.prepare("SELECT r.revision, r.class, r.property, r.slots FROM lead_revisions r JOIN leads l ON l.id=r.lead_id WHERE l.engagement_id=? AND l.id=? ORDER BY r.revision")?;
        let bindings = query
            .query_map(params![self.engagement.as_str(), lead.as_str()], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })?
            .map(|row| {
                let (revision, class, property, slots) = row?;
                Ok(LeadBinding {
                    revision: unsigned(revision)?,
                    class: class
                        .map(|x| x.parse())
                        .transpose()
                        .map_err(|_| StoreError::Decode)?,
                    property: property
                        .map(|x| x.parse())
                        .transpose()
                        .map_err(|_| StoreError::Decode)?,
                    slots: json_value(&slots)?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        if bindings.is_empty() {
            return Err(StoreError::SelectorNotFound);
        }
        Ok(LinkedChain {
            engagement: self.engagement.clone(),
            records,
            manifests,
            lead: lead.clone(),
            bindings,
            events: self.lead_detail(lead)?.events,
        })
    }

    pub fn entry_status(&self) -> Result<super::entry::EntrySnapshot> {
        super::entry::read(self.db, &self.engagement)
    }

    pub fn entry_record_ids(&self, limit: u32, offset: u32) -> Result<Vec<VerificationId>> {
        super::entry::record_ids(self.db, &self.engagement, limit, offset)
    }

    pub fn teapot_entry_observation(
        &self,
        route: &Sha256Digest,
    ) -> Result<Option<super::entry::TeapotObservation>> {
        if self.schema_version < super::entry::SCHEMA_VERSION {
            return Ok(None);
        }
        super::entry::teapot_observation(self.db, &self.engagement, route)
    }

    pub fn engagement(&self) -> &EngagementId {
        &self.engagement
    }

    /// Older coordination stores can support normal reads without the
    /// recorded-checks schema. Never migrate them from a reader.
    pub fn recorded_checks(&self) -> Result<Option<Vec<CheckView>>> {
        if self.schema_version < checks::SCHEMA_VERSION {
            return Ok(None);
        }
        checks::load(self.db, &self.engagement).map(Some)
    }

    pub fn lead(&self, id: &LeadId) -> Result<LeadView> {
        let row = self.db.query_row(
            "SELECT l.id, (SELECT MAX(revision) FROM lead_revisions WHERE lead_id=l.id),
                    EXISTS(SELECT 1 FROM verifications WHERE engagement_id=l.engagement_id AND lead_id=l.id)
             FROM leads l WHERE l.engagement_id=?1 AND l.id=?2",
            params![self.engagement.as_str(), id.as_str()],
            lead_row,
        ).optional()?.ok_or(StoreError::SelectorNotFound)?;
        decode_lead(row)
    }

    pub fn leads(&self, limit: u32, offset: u32) -> Result<Vec<LeadView>> {
        let mut query = self.db.prepare(
            "SELECT l.id, (SELECT MAX(revision) FROM lead_revisions WHERE lead_id=l.id),
                    EXISTS(SELECT 1 FROM verifications WHERE engagement_id=l.engagement_id AND lead_id=l.id)
             FROM leads l WHERE l.engagement_id=? ORDER BY l.id LIMIT ? OFFSET ?",
        )?;
        query
            .query_map(params![self.engagement.as_str(), limit, offset], lead_row)?
            .map(|row| decode_lead(row?))
            .collect()
    }

    /// Load the current immutable revision and its complete attributed event
    /// history from this engagement only.
    pub fn lead_detail(&self, id: &LeadId) -> Result<LeadDetail> {
        if self.schema_version < 8 {
            return Err(StoreError::Schema);
        }
        let row = self
            .db
            .query_row(
                "SELECT r.revision, r.text, r.class, r.property, r.slots,
                        r.proposed_policy, r.origin, r.source_ref, r.endpoint,
                        r.flow_ids, r.producer_confidence
                 FROM leads l JOIN lead_revisions r ON r.lead_id=l.id
                 WHERE l.engagement_id=?1 AND l.id=?2
                   AND r.revision=(SELECT MAX(revision) FROM lead_revisions WHERE lead_id=l.id)",
                params![self.engagement.as_str(), id.as_str()],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, Option<String>>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, Option<String>>(7)?,
                        row.get::<_, Option<String>>(8)?,
                        row.get::<_, String>(9)?,
                        row.get::<_, Option<String>>(10)?,
                    ))
                },
            )
            .optional()?
            .ok_or(StoreError::SelectorNotFound)?;
        let lead = LeadRevision {
            lead_id: id.clone(),
            revision: unsigned(row.0)?,
            text: row.1.parse().map_err(|_| StoreError::Decode)?,
            class: row
                .2
                .map(|value| value.parse())
                .transpose()
                .map_err(|_| StoreError::Decode)?,
            property: row
                .3
                .map(|value| value.parse())
                .transpose()
                .map_err(|_| StoreError::Decode)?,
            slots: json_value(&row.4)?,
            proposed_policy: row.5.map(|value| json_value(&value)).transpose()?,
            origin: tag_value::<LeadOrigin>(&row.6)?,
            source_ref: row
                .7
                .map(|value| value.parse())
                .transpose()
                .map_err(|_| StoreError::Decode)?,
            endpoint: row
                .8
                .map(|value| value.parse())
                .transpose()
                .map_err(|_| StoreError::Decode)?,
            flow_ids: json_value(&row.9)?,
            producer_confidence: row
                .10
                .map(|value| value.parse())
                .transpose()
                .map_err(|_| StoreError::Decode)?,
        };
        let mut query = self.db.prepare(
            "SELECT lead_revision, kind, actor, reason, evidence_refs, recorded_at
             FROM lead_events WHERE lead_id=? ORDER BY id",
        )?;
        let events = query
            .query_map([id.as_str()], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                ))
            })?
            .map(|row| {
                let row = row?;
                Ok(LeadEvent {
                    lead_id: id.clone(),
                    lead_revision: unsigned(row.0)?,
                    kind: json_value::<LeadEventKind>(&row.1)?,
                    actor: row.2.parse().map_err(|_| StoreError::Decode)?,
                    reason: row.3.parse().map_err(|_| StoreError::Decode)?,
                    evidence: json_value(&row.4)?,
                    recorded_at: row.5.parse::<Timestamp>().map_err(|_| StoreError::Decode)?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(LeadDetail { lead, events })
    }

    pub fn run(&self, id: &RunId) -> Result<RunDetail> {
        if self.schema_version < RUN_EXPERIMENT_SCHEMA_VERSION {
            let (run, key, digest) = self
                .db
                .query_row(
                    "SELECT id, state, flags, effects, oracle_result, reproduction, cleanup,
                        request_key, experiment_digest
                 FROM runs WHERE engagement_id=? AND id=?",
                    params![self.engagement.as_str(), id.as_str()],
                    |row| {
                        Ok((
                            run_row(row)?,
                            row.get::<_, String>(7)?,
                            row.get::<_, String>(8)?,
                        ))
                    },
                )
                .optional()?
                .ok_or(StoreError::SelectorNotFound)?;
            return Ok(RunDetail {
                view: decode_run(run)?,
                request_key: key.parse().map_err(|_| StoreError::Decode)?,
                experiment_digest: digest.parse().map_err(|_| StoreError::Decode)?,
                experiment_artifact_id: None,
            });
        }
        let (run, key, digest, artifact) = self.db.query_row(
            "SELECT id, state, flags, effects, oracle_result, reproduction, cleanup, request_key,
                    experiment_digest, experiment_artifact_id
             FROM runs WHERE engagement_id=? AND id=?",
            params![self.engagement.as_str(), id.as_str()],
            |row| Ok((run_row(row)?, row.get::<_, String>(7)?, row.get::<_, String>(8)?, row.get::<_, Option<String>>(9)?)),
        ).optional()?.ok_or(StoreError::SelectorNotFound)?;
        Ok(RunDetail {
            view: decode_run(run)?,
            request_key: key.parse().map_err(|_| StoreError::Decode)?,
            experiment_digest: digest.parse().map_err(|_| StoreError::Decode)?,
            experiment_artifact_id: artifact
                .map(|value| value.parse().map_err(|_| StoreError::Decode))
                .transpose()?,
        })
    }

    pub fn runs(&self, state: Option<RunState>, limit: u32, offset: u32) -> Result<Vec<RunView>> {
        let mut query = self.db.prepare(
            "SELECT id, state, flags, effects, oracle_result, reproduction, cleanup
             FROM runs WHERE engagement_id=?1 AND (?2 IS NULL OR state=?2)
             ORDER BY id LIMIT ?3 OFFSET ?4",
        )?;
        query
            .query_map(
                params![
                    self.engagement.as_str(),
                    state.map(tag).transpose()?,
                    limit,
                    offset
                ],
                run_row,
            )?
            .map(|row| decode_run(row?))
            .collect()
    }

    pub fn record(&self, id: &VerificationId) -> Result<RecordView> {
        let (sequence, run, lead, digest, intent): (i64, String, String, String, String) = self
            .db
            .query_row(
                "SELECT sequence, run_id, lead_id, record_digest, intent_id
             FROM verifications WHERE engagement_id=? AND record_id=?",
                params![self.engagement.as_str(), id.as_str()],
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
            .optional()?
            .ok_or(StoreError::SelectorNotFound)?;
        let digest: Sha256Digest = digest.parse().map_err(|_| StoreError::Integrity)?;
        let sequence = unsigned(sequence)?;
        let run: RunId = run.parse().map_err(|_| StoreError::Decode)?;
        let lead: LeadId = lead.parse().map_err(|_| StoreError::Decode)?;

        // Legacy fallback is valid only when the header, physical schema and
        // audit history agree that this database predates staged candidates.
        // PRAGMA user_version and candidate_required are mutable SQLite state;
        // neither alone proves that a missing candidate is historical.
        let candidate_table: bool = self.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema
             WHERE type='table' AND name='publication_candidates')",
            [],
            |row| row.get(0),
        )?;
        let candidate_flag: bool = self.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('publication_intents')
             WHERE name='candidate_required')",
            [],
            |row| row.get(0),
        )?;
        // One migration transaction records the final schema it reached, so a
        // v11 database opened by a v13 build has a durable `13` receipt rather
        // than an intermediate `12` receipt. The first canonical schema receipt
        // at or beyond v12 is the boundary where staged candidates began.
        let mut migration_query = self.db.prepare(
            "SELECT revision, subject FROM audit_events
             WHERE operation='schema.migrate' ORDER BY revision",
        )?;
        let migrations = migration_query
            .query_map([], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut migration_revision = None;
        for (revision, subject) in migrations {
            let version = subject.parse::<u64>().map_err(|_| StoreError::Integrity)?;
            if version.to_string() != subject {
                return Err(StoreError::Integrity);
            }
            if version >= 12 && migration_revision.is_none() {
                migration_revision = Some(revision);
            }
        }

        if candidate_table != candidate_flag {
            return Err(StoreError::Integrity);
        }
        if self.schema_version < 12 {
            // A real pre-v12 database has neither v12 object and no receipt
            // showing that v12 migration ever completed.
            if candidate_table || migration_revision.is_some() {
                return Err(StoreError::Integrity);
            }
            return Ok(index_record(id, sequence, run, lead, digest));
        }
        if !candidate_table || !candidate_flag {
            return Err(StoreError::Integrity);
        }

        let candidate_required: bool = self
            .db
            .query_row(
                "SELECT candidate_required FROM publication_intents WHERE id=?",
                [&intent],
                |row| row.get(0),
            )
            .optional()?
            .ok_or(StoreError::Integrity)?;
        if !candidate_required {
            // A completed pre-v12 publication is a legitimate index-only
            // record. A staged candidate beside an intent that does not
            // require one is inconsistent and must not be treated as legacy.
            let has_candidate: bool = self.db.query_row(
                "SELECT EXISTS(SELECT 1 FROM publication_candidates WHERE intent_id=?)",
                [&intent],
                |row| row.get(0),
            )?;
            if has_candidate {
                return Err(StoreError::Integrity);
            }
            // Migration 12 intentionally leaves old intents without staged
            // bytes. Accept that state only when this intent's durable audit
            // receipt predates the migration receipt.
            let intent_revision: Option<i64> = self
                .db
                .query_row(
                    "SELECT revision FROM audit_events
                     WHERE operation='publication.intent' AND subject=?",
                    [&intent],
                    |row| row.get(0),
                )
                .optional()?;
            let (Some(intent_revision), Some(migration_revision)) =
                (intent_revision, migration_revision)
            else {
                return Err(StoreError::Integrity);
            };
            if intent_revision >= migration_revision {
                return Err(StoreError::Integrity);
            }
            return Ok(index_record(id, sequence, run, lead, digest));
        }

        let record_bytes: Vec<u8> = self
            .db
            .query_row(
                "SELECT record_bytes FROM publication_candidates WHERE intent_id=?",
                [&intent],
                |row| row.get(0),
            )
            .optional()?
            .ok_or(StoreError::Integrity)?;
        let record: crate::wire::VerificationV1 =
            crate::canonical::from_digest(&record_bytes, &digest)
                .map_err(|_| StoreError::Integrity)?;
        if record.record_id != *id
            || record.sequence != sequence
            || record.run_id != run
            || record.lead_id != lead
        {
            return Err(StoreError::Integrity);
        }
        let expected_limitations = registry::KNOWN_MISSES;
        if record.oracle.id.as_str() != registry::ORACLE_ID
            || record.oracle.version.as_str() != registry::ORACLE_VERSION
            || record.oracle.digest != registry::oracle_digest()
            || record.limitations.len() != expected_limitations.len()
            || !expected_limitations.iter().all(|expected| {
                record
                    .limitations
                    .iter()
                    .filter(|actual| actual.as_str() == *expected)
                    .count()
                    == 1
            })
        {
            // The staged record's own digest authenticates its bytes, but it
            // does not establish that those bytes came from this frozen oracle
            // contract. The v1 writer emits the complete registered set for
            // every record; this schema carries no authenticated derivation
            // evidence for accepting a smaller applicable subset.
            return Err(StoreError::Integrity);
        }
        Ok(RecordView {
            id: id.clone(),
            sequence,
            run,
            lead,
            digest,
            oracle_id: Some(record.oracle.id.as_str().to_owned()),
            oracle_version: Some(record.oracle.version.as_str().to_owned()),
            oracle_digest: Some(record.oracle.digest),
            limitations: Some(
                expected_limitations
                    .iter()
                    .map(|limitation| (*limitation).to_owned())
                    .collect(),
            ),
        })
    }

    /// Return only a locally recorded flow reference. In particular, its
    /// original artifact's locator is neither opened nor returned.
    pub fn flow(&self, id: u64) -> Result<FlowView> {
        let (run, number, completeness): (String, String, String) = self
            .db
            .query_row(
                "SELECT r.id, s.number, j.value ->> '$.completeness'
             FROM runs r JOIN run_steps s ON s.run_id=r.id, json_each(s.flow_refs) j
             WHERE r.engagement_id=? AND j.value -> '$.flow_id'=?
             ORDER BY r.id, length(s.number), s.number, j.key LIMIT 1",
                params![self.engagement.as_str(), id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?
            .ok_or(StoreError::SelectorNotFound)?;
        Ok(FlowView {
            run: run.parse().map_err(|_| StoreError::Decode)?,
            number: number.parse().map_err(|_| StoreError::Decode)?,
            completeness: tag_value(&completeness)?,
        })
    }
}

fn lead_row(row: &Row<'_>) -> rusqlite::Result<(String, i64, bool)> {
    Ok((row.get(0)?, row.get(1)?, row.get(2)?))
}

fn index_record(
    id: &VerificationId,
    sequence: u64,
    run: RunId,
    lead: LeadId,
    digest: Sha256Digest,
) -> RecordView {
    RecordView {
        id: id.clone(),
        sequence,
        run,
        lead,
        digest,
        oracle_id: None,
        oracle_version: None,
        oracle_digest: None,
        limitations: None,
    }
}

fn decode_lead((id, revision, has_records): (String, i64, bool)) -> Result<LeadView> {
    Ok(LeadView {
        id: id.parse().map_err(|_| StoreError::Decode)?,
        revision: unsigned(revision)?,
        has_records,
    })
}

struct RunRow {
    id: String,
    state: String,
    flags: String,
    effects: String,
    oracle_result: Option<String>,
    reproduction: String,
    cleanup: String,
}

fn run_row(row: &Row<'_>) -> rusqlite::Result<RunRow> {
    Ok(RunRow {
        id: row.get(0)?,
        state: row.get(1)?,
        flags: row.get(2)?,
        effects: row.get(3)?,
        oracle_result: row.get(4)?,
        reproduction: row.get(5)?,
        cleanup: row.get(6)?,
    })
}

fn decode_run(row: RunRow) -> Result<RunView> {
    Ok(RunView {
        run: RunSummary {
            id: row.id.parse().map_err(|_| StoreError::Decode)?,
            state: tag_value(&row.state)?,
            flags: json_value(&row.flags)?,
            oracle_result: row.oracle_result.as_deref().map(tag_value).transpose()?,
            reproduction: tag_value(&row.reproduction)?,
            cleanup: tag_value(&row.cleanup)?,
        },
        effects: tag_value(&row.effects)?,
    })
}
