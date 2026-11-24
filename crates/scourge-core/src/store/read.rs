//! Local inspection of coordination metadata. A snapshot never opens an
//! evidence store, decodes request arguments, or accepts write operations.

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
    BUSY_TIMEOUT, Result, StoreError, check_workspace, exists, initialization_lock, json_value,
    schema_version, tag, tag_value, unsigned,
};
use crate::{
    canonical::Sha256Digest,
    ids::{EngagementId, LeadId, RequestKey, RunId, VerificationId},
    wire::{Completeness, Effect, RunState, RunSummary},
};

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

impl<'a> Snapshot<'a> {
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

pub struct RunView {
    pub run: RunSummary,
    pub effects: Effect,
}

pub struct RunDetail {
    pub view: RunView,
    pub request_key: RequestKey,
    pub experiment_digest: Sha256Digest,
}

pub struct RecordView {
    pub id: VerificationId,
    pub sequence: u64,
    pub run: RunId,
    pub lead: LeadId,
    pub digest: Sha256Digest,
}

pub struct FlowView {
    pub run: RunId,
    pub number: u64,
    pub completeness: Completeness,
}

impl Scope<'_> {
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

    pub fn run(&self, id: &RunId) -> Result<RunDetail> {
        let (run, key, digest) = self.db.query_row(
            "SELECT id, state, flags, effects, oracle_result, reproduction, cleanup, request_key, experiment_digest
             FROM runs WHERE engagement_id=? AND id=?",
            params![self.engagement.as_str(), id.as_str()],
            |row| Ok((run_row(row)?, row.get::<_, String>(7)?, row.get::<_, String>(8)?)),
        ).optional()?.ok_or(StoreError::SelectorNotFound)?;
        Ok(RunDetail {
            view: decode_run(run)?,
            request_key: key.parse().map_err(|_| StoreError::Decode)?,
            experiment_digest: digest.parse().map_err(|_| StoreError::Decode)?,
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
        let (sequence, run, lead, digest): (i64, String, String, String) = self
            .db
            .query_row(
                "SELECT sequence, run_id, lead_id, record_digest
             FROM verifications WHERE engagement_id=? AND record_id=?",
                params![self.engagement.as_str(), id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?
            .ok_or(StoreError::SelectorNotFound)?;
        Ok(RecordView {
            id: id.clone(),
            sequence: unsigned(sequence)?,
            run: run.parse().map_err(|_| StoreError::Decode)?,
            lead: lead.parse().map_err(|_| StoreError::Decode)?,
            digest: digest.parse().map_err(|_| StoreError::Decode)?,
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
