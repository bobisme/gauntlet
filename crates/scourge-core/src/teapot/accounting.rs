//! Read-only accounting evidence for an already declared run.
//!
//! The adapter provides both endpoint snapshots. Run orchestration owns the
//! operation between them and custody of the returned artifacts.

use std::fmt;

use serde::Deserialize;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

use crate::{
    canonical::Sha256Digest,
    ids::{RequestKey, RunId, SessionName, WireText},
    json_input::MAX_SAFE_INTEGER,
    wire::{
        AbsolutePath, AccountingV1, AccountingV1Tag, Artifact, Attribution, Count, Counters,
        DiagnosticCode, ErrorCode, Granularity, Timestamp, Unit, Window,
    },
};

use super::{
    BoundEngine, Exits, InvocationError, JOBS_LIST, MACRO_DRY_RUN, MAX_JOBS_LIMIT, NativeReply,
    PASS_SHOW, Spec, Teapot, VERSION, job_page, macro_dry_run_result, macro_dry_run_words,
    request_ceiling,
};

/// The persisted run identities and approved pass pin from trusted state.
#[derive(Clone, Debug)]
pub struct AccountingBinding {
    pub run_id: RunId,
    pub request_key: RequestKey,
    pub pass_id: WireText,
    pub pass_digest: Sha256Digest,
    pub pass_file: AbsolutePath,
}

/// A passive macro plan associated with the declared run.
#[derive(Debug)]
pub struct MacroPlan<'a> {
    pub name: &'a WireText,
    pub session: &'a SessionName,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Before,
    After,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvidenceKind {
    Engine,
    Pass,
    MacroDryRun,
    Jobs,
}

/// An original successful command reply, with independently checkable bytes.
/// Treat stdout as private evidence and redact it at presentation boundaries.
pub struct NativeEvidence {
    reference: Artifact,
    phase: Phase,
    kind: EvidenceKind,
    window: Window,
    exits: Exits,
    stdout: Vec<u8>,
}

impl fmt::Debug for NativeEvidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeEvidence")
            .field("reference", &self.reference)
            .field("phase", &self.phase)
            .field("kind", &self.kind)
            .field("window", &self.window)
            .field("exits", &self.exits)
            .finish_non_exhaustive()
    }
}

impl NativeEvidence {
    pub fn reference(&self) -> &Artifact {
        &self.reference
    }

    pub fn phase(&self) -> Phase {
        self.phase
    }

    pub fn kind(&self) -> EvidenceKind {
        self.kind
    }

    pub fn window(&self) -> &Window {
        &self.window
    }

    pub fn exits(&self) -> Exits {
        self.exits
    }

    pub fn stdout(&self) -> &[u8] {
        &self.stdout
    }
}

/// Run, request, pass and engine context common to one set of artifacts.
#[derive(Debug)]
pub struct Evidence {
    binding: AccountingBinding,
    engine: BoundEngine,
    project: AbsolutePath,
    artifacts: Vec<NativeEvidence>,
}

impl Evidence {
    pub fn binding(&self) -> &AccountingBinding {
        &self.binding
    }

    pub fn engine(&self) -> &BoundEngine {
        &self.engine
    }

    pub fn project(&self) -> &AbsolutePath {
        &self.project
    }

    pub fn artifacts(&self) -> &[NativeEvidence] {
        &self.artifacts
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AccountingRefusal {
    #[error("The accounting observation could not be bound to the approved pass.")]
    PassMismatch,
    #[error("The pass reported that it is unavailable, invalid or changed.")]
    PassUnavailable,
    #[error("The observed request counters changed discontinuously.")]
    CounterDiscontinuity,
    #[error("The observation clock moved backwards.")]
    ClockDiscontinuity,
    #[error("An observed count exceeds the immutable record's integer range.")]
    CountOutOfRange,
    #[error("Teapot did not establish whether the macro fits the request ceiling.")]
    CeilingUnknown,
    #[error("The macro estimate exceeds the observed request ceiling.")]
    CeilingExceeded,
    #[error("Teapot did not establish a run-specific charge.")]
    ExactAttributionUnavailable,
}

impl AccountingRefusal {
    pub fn code(self) -> ErrorCode {
        match self {
            Self::CeilingExceeded => ErrorCode::BudgetRefused,
            _ => ErrorCode::AccountingUnestablished,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AccountingError {
    #[error(transparent)]
    Invocation(#[from] InvocationError),
    #[error(transparent)]
    Refusal(#[from] AccountingRefusal),
}

impl AccountingError {
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Invocation(error) => error.code(),
            Self::Refusal(error) => error.code(),
        }
    }
}

/// Evidence already collected remains available if a later check fails.
#[derive(Debug, thiserror::Error)]
#[error("{error}")]
pub struct AccountingFailure {
    #[source]
    error: AccountingError,
    evidence: Evidence,
}

impl AccountingFailure {
    pub fn error(&self) -> &AccountingError {
        &self.error
    }

    pub fn evidence(&self) -> &Evidence {
        &self.evidence
    }
}

#[derive(Debug)]
pub struct AccountingObservation {
    record: AccountingV1,
    evidence: Evidence,
    within_ceiling: Option<bool>,
}

impl AccountingObservation {
    pub fn record(&self) -> &AccountingV1 {
        &self.record
    }

    pub fn evidence(&self) -> &Evidence {
        &self.evidence
    }

    pub fn within_ceiling(&self) -> Option<bool> {
        self.within_ceiling
    }
}

/// One before snapshot. Consuming it retains the same verified binding for
/// the after snapshot, even if the caller has access to other engines.
#[derive(Debug)]
pub struct AccountingCapture<'a> {
    recorder: Recorder<'a>,
    before: Option<PassCounters>,
    plan: Option<PlanObservation>,
}

impl Teapot {
    /// Capture before evidence. This performs only passive Teapot operations.
    /// Success means that evidence was collected. Call preflight before
    /// relying on the macro ceiling or attempting an exactly accounted run.
    pub fn begin_accounting(
        &self,
        binding: AccountingBinding,
        plan: Option<MacroPlan<'_>>,
    ) -> Result<AccountingCapture<'_>, Box<AccountingFailure>> {
        let mut recorder = Recorder::new(self, binding);
        match recorder.capture_before(plan) {
            Ok((before, plan)) => Ok(AccountingCapture {
                recorder,
                before,
                plan,
            }),
            Err(error) => Err(recorder.failure(error)),
        }
    }
}

impl AccountingCapture<'_> {
    pub fn evidence(&self) -> &Evidence {
        &self.recorder.evidence
    }

    /// Assess this observation for callers that require a known macro
    /// estimate against a known ceiling, or a run-specific charge.
    pub fn preflight(&self, require_exact: bool) -> Result<(), AccountingRefusal> {
        if require_exact {
            return Err(AccountingRefusal::ExactAttributionUnavailable);
        }
        let plan = self
            .plan
            .as_ref()
            .ok_or(AccountingRefusal::CeilingUnknown)?;
        let counters = self.before.as_ref().map(|before| &before.counters);
        match plan.within_ceiling {
            Some(true)
                if counters.is_some_and(|counters| {
                    counters.spent.is_some()
                        && counters
                            .left
                            .as_ref()
                            .is_some_and(|left| left.value >= plan.requested.value)
                }) =>
            {
                Ok(())
            }
            Some(false) => Err(AccountingRefusal::CeilingExceeded),
            _ => Err(AccountingRefusal::CeilingUnknown),
        }
    }

    pub fn finish(mut self) -> Result<AccountingObservation, Box<AccountingFailure>> {
        self.recorder.phase = Phase::After;
        let after = match self.recorder.capture_after(self.before.as_ref()) {
            Ok(after) => after,
            Err(error) => return Err(self.recorder.failure(error)),
        };
        let (requested, dry_run_ceiling, within_ceiling) =
            self.plan.map_or((None, None, None), |plan| {
                (Some(plan.requested), plan.ceiling, plan.within_ceiling)
            });
        let evidence = self.recorder.evidence;
        let record = AccountingV1 {
            schema: AccountingV1Tag::AccountingV1,
            pass_id: Some(evidence.binding.pass_id.clone()),
            pass_digest: Some(evidence.binding.pass_digest.clone()),
            instrument_job_ids: Vec::new(),
            window: window(self.recorder.start, self.recorder.last),
            dry_run_ceiling,
            counters_before: self.before.map(|sample| sample.counters),
            counters_after: after.map(|sample| sample.counters),
            ledger_debits: Vec::new(),
            held_before: None,
            held_after: None,
            requested,
            admitted: None,
            observed_sent: None,
            charged: None,
            attribution: Attribution::Unestablished,
            attribution_evidence: evidence
                .artifacts
                .iter()
                .map(|artifact| artifact.reference.clone())
                .collect(),
        };
        Ok(AccountingObservation {
            record,
            evidence,
            within_ceiling,
        })
    }
}

#[derive(Debug)]
struct PassCounters {
    total: u64,
    counters: Counters,
}

#[derive(Debug)]
struct PlanObservation {
    requested: Count,
    ceiling: Option<Count>,
    within_ceiling: Option<bool>,
}

#[derive(Debug)]
struct Recorder<'a> {
    teapot: &'a Teapot,
    evidence: Evidence,
    phase: Phase,
    start: OffsetDateTime,
    last: OffsetDateTime,
}

impl<'a> Recorder<'a> {
    fn new(teapot: &'a Teapot, binding: AccountingBinding) -> Self {
        let start = OffsetDateTime::now_utc();
        Self {
            teapot,
            evidence: Evidence {
                binding,
                engine: teapot.engine.clone(),
                project: teapot.project.clone(),
                artifacts: Vec::new(),
            },
            phase: Phase::Before,
            start,
            last: start,
        }
    }

    fn failure(self, error: AccountingError) -> Box<AccountingFailure> {
        Box::new(AccountingFailure {
            error,
            evidence: self.evidence,
        })
    }

    fn capture_before(
        &mut self,
        plan: Option<MacroPlan<'_>>,
    ) -> Result<(Option<PassCounters>, Option<PlanObservation>), AccountingError> {
        self.jobs()?;
        let before = self.pass()?;
        let plan = plan.map(|plan| self.plan(plan)).transpose()?;
        Ok((before, plan))
    }

    fn capture_after(
        &mut self,
        before: Option<&PassCounters>,
    ) -> Result<Option<PassCounters>, AccountingError> {
        let after = self.pass()?;
        self.jobs()?;
        check_continuity(before, after.as_ref())?;
        Ok(after)
    }

    fn pass(&mut self) -> Result<Option<PassCounters>, AccountingError> {
        let binding = self.evidence.binding.clone();
        let engine = self.evidence.engine.clone();
        let (sample, index) =
            self.read_live(EvidenceKind::Pass, &PASS_SHOW, &["pass", "show"], |reply| {
                read_pass(reply, &binding, &engine)
            })?;
        sample
            .map(|sample| {
                let evidence = &self.evidence.artifacts[index];
                let count = |value, source| {
                    count(
                        value,
                        Unit::RequestUnits,
                        source,
                        Granularity::Pass,
                        evidence,
                    )
                };
                Ok(PassCounters {
                    total: sample.total,
                    counters: Counters {
                        spent: sample
                            .spent
                            .map(|v| count(v, "teapot.pass_show.requests.spent"))
                            .transpose()?,
                        left: sample
                            .left
                            .map(|v| count(v, "teapot.pass_show.requests.left"))
                            .transpose()?,
                        unused: sample
                            .unused
                            .map(|v| count(v, "teapot.pass_show.requests.unused"))
                            .transpose()?,
                    },
                })
            })
            .transpose()
    }

    fn plan(&mut self, plan: MacroPlan<'_>) -> Result<PlanObservation, AccountingError> {
        let args = macro_dry_run_words(plan.name, plan.session)?;
        let ((result, units_left), index) =
            self.read_live(EvidenceKind::MacroDryRun, &MACRO_DRY_RUN, &args, |reply| {
                Ok(macro_dry_run_result(reply, plan.name, plan.session)?)
            })?;
        let evidence = &self.evidence.artifacts[index];
        let requested = count(
            result.request_count,
            Unit::Requests,
            "teapot.macro_dry_run.units",
            Granularity::RunSummary,
            evidence,
        )?;
        let ceiling = units_left
            .map(|value| {
                count(
                    value,
                    Unit::RequestUnits,
                    "teapot.macro_dry_run.units_left",
                    Granularity::Engine,
                    evidence,
                )
            })
            .transpose()?;
        Ok(PlanObservation {
            requested,
            ceiling,
            within_ceiling: result.within_ceiling,
        })
    }

    fn jobs(&mut self) -> Result<(), AccountingError> {
        let limit = MAX_JOBS_LIMIT.to_string();
        self.read_live(
            EvidenceKind::Jobs,
            &JOBS_LIST,
            &["jobs", "list", "--limit", &limit],
            |reply| {
                job_page(reply, MAX_JOBS_LIMIT, None)?;
                Ok(())
            },
        )?;
        Ok(())
    }

    fn read_live<T>(
        &mut self,
        kind: EvidenceKind,
        spec: &'static Spec,
        words: &[&str],
        check: impl FnOnce(&NativeReply) -> Result<T, AccountingError>,
    ) -> Result<(T, usize), AccountingError> {
        let teapot = self.teapot;
        let pass_file = self.evidence.binding.pass_file.clone();
        let check_engine = |reply: &NativeReply| {
            teapot.check_engine(reply)?;
            if reply.result()["engine"]["pass"].as_str() != Some(pass_file.as_str()) {
                return Err(AccountingRefusal::PassMismatch.into());
            }
            Ok(())
        };
        self.read(EvidenceKind::Engine, &VERSION, &["version"], check_engine)?;
        let observation = self.read(kind, spec, words, check)?;
        self.read(EvidenceKind::Engine, &VERSION, &["version"], check_engine)?;
        Ok(observation)
    }

    fn read<T>(
        &mut self,
        kind: EvidenceKind,
        spec: &'static Spec,
        words: &[&str],
        check: impl FnOnce(&NativeReply) -> Result<T, AccountingError>,
    ) -> Result<(T, usize), AccountingError> {
        let start = OffsetDateTime::now_utc();
        let reply = self.teapot.invoke(spec, words)?;
        let end = OffsetDateTime::now_utc();
        let result = check(&reply);
        let artifact = NativeEvidence {
            reference: Artifact {
                artifact_id: format!("teapot-observation-{}", Uuid::new_v4().simple())
                    .parse()
                    .expect("generated artifact ID"),
                digest: Sha256Digest::of(&reply.stdout),
            },
            phase: self.phase,
            kind,
            window: window(start, end),
            exits: reply.exits(),
            stdout: reply.stdout,
        };
        let index = self.evidence.artifacts.len();
        self.evidence.artifacts.push(artifact);
        if start < self.last || end < start {
            return Err(AccountingRefusal::ClockDiscontinuity.into());
        }
        self.last = end;
        Ok((result?, index))
    }
}

#[derive(Deserialize)]
struct NativeCounters {
    total: u64,
    spent: Option<u64>,
    left: Option<u64>,
    unused: Option<u64>,
}

fn read_pass(
    evidence: &NativeReply,
    binding: &AccountingBinding,
    engine: &BoundEngine,
) -> Result<Option<NativeCounters>, AccountingError> {
    let pass = evidence.result();
    if pass["state"] != "bound" || pass["window"] != "valid" || !pass["newer_pass"].is_null() {
        return Err(AccountingRefusal::PassUnavailable.into());
    }
    if pass["enforcement"]["on"].as_bool() != Some(engine.enforced)
        || pass["lock"]["locked"].as_bool() != Some(engine.policy_locked)
    {
        return Err(evidence.fail(DiagnosticCode::WrongListener).into());
    }
    let digest = pass["digest"]
        .as_str()
        .and_then(|digest| digest.strip_prefix("sha256:"));
    if pass["id"].as_str() != Some(binding.pass_id.as_str())
        || digest != Some(binding.pass_digest.as_str())
        || pass["pass_file"].as_str() != Some(binding.pass_file.as_str())
    {
        return Err(AccountingRefusal::PassMismatch.into());
    }
    request_ceiling(evidence)?
        .map(|counter| {
            NativeCounters::deserialize(counter)
                .map_err(|_| evidence.fail(DiagnosticCode::InvalidNativeOutput).into())
        })
        .transpose()
}

fn check_continuity(
    before: Option<&PassCounters>,
    after: Option<&PassCounters>,
) -> Result<(), AccountingRefusal> {
    let (Some(before), Some(after)) = (before, after) else {
        return Ok(());
    };
    let changes = |a: &Option<Count>, b: &Option<Count>| {
        a.as_ref()
            .zip(b.as_ref())
            .map(|(a, b)| a.value.cmp(&b.value))
    };
    if before.total != after.total
        || changes(&before.counters.spent, &after.counters.spent).is_some_and(|order| order.is_gt())
        || changes(&before.counters.left, &after.counters.left).is_some_and(|order| order.is_lt())
    {
        return Err(AccountingRefusal::CounterDiscontinuity);
    }
    Ok(())
}

fn count(
    value: u64,
    unit: Unit,
    source: &'static str,
    granularity: Granularity,
    evidence: &NativeEvidence,
) -> Result<Count, AccountingError> {
    if value > MAX_SAFE_INTEGER {
        return Err(AccountingRefusal::CountOutOfRange.into());
    }
    Ok(Count {
        value,
        unit,
        source: source.parse().expect("static source"),
        granularity,
        window: evidence.window.clone(),
        evidence: evidence.reference.clone(),
    })
}

fn window(start: OffsetDateTime, end: OffsetDateTime) -> Window {
    fn timestamp(value: OffsetDateTime) -> Timestamp {
        value
            .format(&Rfc3339)
            .expect("system time in RFC 3339 range")
            .parse()
            .expect("UTC RFC 3339 timestamp")
    }
    Window {
        start: timestamp(start),
        end: timestamp(end),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn continuity_uses_ordering_over_full_counter_ranges_without_deltas() {
        let now = OffsetDateTime::now_utc();
        let count = |value| Count {
            value,
            unit: Unit::RequestUnits,
            source: "test".parse().unwrap(),
            granularity: Granularity::Pass,
            window: window(now, now),
            evidence: Artifact {
                artifact_id: "test".parse().unwrap(),
                digest: Sha256Digest::of(b"test"),
            },
        };
        let sample = |spent: Option<u64>, left: Option<u64>| PassCounters {
            total: u64::MAX,
            counters: Counters {
                spent: spent.map(count),
                left: left.map(count),
                unused: None,
            },
        };
        let values = [
            None,
            Some(0),
            Some(1),
            Some(MAX_SAFE_INTEGER),
            Some(u64::MAX),
        ];
        for spent in values {
            for left in values {
                for next_spent in values {
                    for next_left in values {
                        let current = sample(spent, left);
                        let next = sample(next_spent, next_left);
                        let continuous = spent.zip(next_spent).is_none_or(|(a, b)| a <= b)
                            && left.zip(next_left).is_none_or(|(a, b)| a >= b);
                        assert_eq!(
                            check_continuity(Some(&current), Some(&next)).is_ok(),
                            continuous
                        );
                    }
                }
            }
        }
    }
}
