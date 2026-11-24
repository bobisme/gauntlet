//! Redacted observations written by check producers and displayed by doctor.

use std::time::SystemTime;

use rusqlite::{Connection, OptionalExtension, params};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use super::{Result, Store, StoreError, exists, tag};
use crate::{
    ids::{EngagementId, RequestKey, RunId},
    wire::{Diagnostic, DiagnosticCode, Timestamp},
};

pub(super) const SCHEMA_VERSION: usize = 5;

/// The stages exposed by the bound Teapot diagnostics contract. A check
/// producer records an observation after its authorized operation completes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stage {
    Describe,
    CheckSession,
    DryRun,
    UnitsLeft,
    ListJobs,
}

impl Stage {
    pub const ALL: [Self; 5] = [
        Self::Describe,
        Self::CheckSession,
        Self::DryRun,
        Self::UnitsLeft,
        Self::ListJobs,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Describe => "describe",
            Self::CheckSession => "check_session",
            Self::DryRun => "dry_run",
            Self::UnitsLeft => "units_left",
            Self::ListJobs => "list_jobs",
        }
    }
}

impl std::str::FromStr for Stage {
    type Err = StoreError;

    fn from_str(value: &str) -> Result<Self> {
        Self::ALL
            .into_iter()
            .find(|stage| stage.as_str() == value)
            .ok_or(StoreError::Decode)
    }
}

/// The result of an observed check. A null code means the check passed.
/// The caller supplies the observation timestamp. The store does not retain
/// native messages, probe arguments, or credential references.
pub struct RecordedCheck {
    pub stage: Stage,
    pub observed_at: Timestamp,
    pub code: Option<DiagnosticCode>,
    pub native_exit: Option<i64>,
    pub wrapper_exit: Option<i64>,
    pub run_id: Option<RunId>,
}

impl RecordedCheck {
    fn validate_outcome(&self) -> Result<()> {
        if self.code.is_none()
            && [self.native_exit, self.wrapper_exit]
                .into_iter()
                .flatten()
                .any(|exit| exit != 0)
        {
            return Err(StoreError::Integrity);
        }
        Ok(())
    }

    /// Whole seconds elapsed. A future observation has no established age.
    pub fn age_seconds(&self, now: SystemTime) -> Option<u64> {
        let elapsed = OffsetDateTime::from(now) - instant(&self.observed_at);
        if elapsed.is_negative() {
            None
        } else {
            Some(elapsed.whole_seconds() as u64)
        }
    }

    pub fn diagnostic(&self) -> Option<Diagnostic> {
        self.code.map(|code| {
            crate::response::diagnostic(
                code,
                self.stage.as_str().parse().expect("valid stage"),
                self.native_exit,
                self.wrapper_exit,
            )
        })
    }
}

pub struct CheckView {
    pub check: RecordedCheck,
    pub request_key: Option<RequestKey>,
}

impl Store {
    /// Replace the observation for one check within its engagement and
    /// allocate one audit revision atomically. A delayed observation cannot
    /// displace a newer one. The optional run must be in the selected scope.
    pub fn record_check(
        &mut self,
        engagement: &EngagementId,
        check: &RecordedCheck,
    ) -> Result<u64> {
        check.validate_outcome()?;
        let stage = check.stage.as_str();
        let engagement = engagement.as_str();
        self.write("diagnostic.record", engagement, |tx| {
            if !exists(tx, "SELECT 1 FROM engagements WHERE id=?", [engagement])? {
                return Err(StoreError::SelectorNotFound);
            }
            if let Some(run) = &check.run_id
                && !exists(
                    tx,
                    "SELECT 1 FROM runs WHERE engagement_id=? AND id=?",
                    params![engagement, run.as_str()],
                )?
            {
                return Err(StoreError::SelectorNotFound);
            }
            let previous: Option<String> = tx
                .query_row(
                    "SELECT observed_at FROM recorded_checks WHERE engagement_id=? AND stage=?",
                    params![engagement, stage],
                    |row| row.get(0),
                )
                .optional()?;
            if let Some(previous) = previous {
                let previous = previous.parse().map_err(|_| StoreError::Decode)?;
                if instant(&previous) > instant(&check.observed_at) {
                    return Err(StoreError::Conflict);
                }
            }
            tx.execute(
                "INSERT INTO recorded_checks
                   (engagement_id, stage, observed_at, code, native_exit, wrapper_exit, run_id)
                 VALUES (?, ?, ?, ?, ?, ?, ?)
                 ON CONFLICT (engagement_id, stage) DO UPDATE SET
                   observed_at=excluded.observed_at, code=excluded.code,
                   native_exit=excluded.native_exit, wrapper_exit=excluded.wrapper_exit,
                   run_id=excluded.run_id",
                params![
                    engagement,
                    stage,
                    check.observed_at.as_str(),
                    check.code.map(tag).transpose()?,
                    check.native_exit,
                    check.wrapper_exit,
                    check.run_id.as_ref().map(RunId::as_str),
                ],
            )?;
            Ok(())
        })
    }
}

pub(super) fn load(db: &Connection, engagement: &EngagementId) -> Result<Vec<CheckView>> {
    let mut query = db.prepare(
        "SELECT c.stage, c.observed_at, c.code, c.native_exit, c.wrapper_exit, c.run_id, r.request_key
         FROM recorded_checks c
         LEFT JOIN runs r ON r.engagement_id=c.engagement_id AND r.id=c.run_id
         WHERE c.engagement_id=? ORDER BY c.stage LIMIT ?",
    )?;
    let rows = query.query_map(
        params![engagement.as_str(), Stage::ALL.len() as i64 + 1],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, Option<i64>>(3)?,
                row.get::<_, Option<i64>>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, Option<String>>(6)?,
            ))
        },
    )?;
    rows.map(|row| {
        let (stage, observed_at, code, native_exit, wrapper_exit, run_id, request_key) = row?;
        if run_id.is_some() != request_key.is_some() {
            return Err(StoreError::Integrity);
        }
        let check = RecordedCheck {
            stage: stage.parse()?,
            observed_at: observed_at.try_into().map_err(|_| StoreError::Decode)?,
            code: code
                .map(DiagnosticCode::try_from)
                .transpose()
                .map_err(|_| StoreError::Decode)?,
            native_exit,
            wrapper_exit,
            run_id: run_id
                .map(RunId::try_from)
                .transpose()
                .map_err(|_| StoreError::Decode)?,
        };
        check.validate_outcome()?;
        Ok(CheckView {
            check,
            request_key: request_key
                .map(RequestKey::try_from)
                .transpose()
                .map_err(|_| StoreError::Decode)?,
        })
    })
    .collect()
}

fn instant(timestamp: &Timestamp) -> OffsetDateTime {
    OffsetDateTime::parse(timestamp.as_str(), &Rfc3339).expect("validated UTC timestamp")
}
