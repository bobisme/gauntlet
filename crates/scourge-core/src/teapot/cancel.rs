use crate::ids::RunId;

use super::{
    BoundEngine, DiagnosticCode, InvocationError, JOB_STOP, Job, Observation, Teapot,
    decode_output, process, process_failure,
};

const STOP_WAIT_SECS: u64 = 10;

/// Job identity recovered from trusted run state.
#[derive(Clone, Debug)]
pub struct OwnedJob {
    run: RunId,
    id: i64,
    engine: BoundEngine,
}

impl OwnedJob {
    /// Reconstitute the exact job and engine previously recorded for this run.
    /// Obtain the association from trusted state, never from a job listing.
    pub fn from_run(run: RunId, id: u64, engine: BoundEngine) -> Result<Self, InvocationError> {
        let id = i64::try_from(id).map_err(|_| InvocationError::InvalidArgument)?;
        if id == 0 {
            return Err(InvocationError::InvalidArgument);
        }
        Ok(Self { run, id, engine })
    }

    pub fn run(&self) -> &RunId {
        &self.run
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CancelAcknowledgment {
    /// Teapot reported that the job reached its stopped state during the call.
    Stopped,
    /// The native reply acknowledged a stop while the job was still ending.
    StopPending,
    /// Teapot reported a terminal state without acknowledging a new stop.
    EndedWithoutStop,
    /// The native reply saw a job ending and reported no new stop.
    EndingWithoutStop,
}

#[derive(Debug, thiserror::Error)]
pub enum CancelError {
    #[error("Scourge did not start the Teapot stop command.")]
    NotRequested(#[source] InvocationError),
    #[error("The Teapot stop request or its outcome could not be confirmed.")]
    Unconfirmed(#[source] InvocationError),
}

#[derive(Debug)]
pub struct Cancellation {
    pub acknowledgment: Observation<CancelAcknowledgment>,
    /// A separate follow-up read. Absence or read failure leaves termination
    /// unconfirmed by this read, even when the stop was acknowledged.
    pub observation: Result<Observation<Option<Job>>, InvocationError>,
}

impl Teapot {
    /// Request stop for a job owned by a run, then observe that exact job.
    pub fn cancel(&self, job: &OwnedJob) -> Result<Cancellation, CancelError> {
        self.check_job_binding(job)
            .map_err(CancelError::NotRequested)?;
        self.verify_engine().map_err(CancelError::NotRequested)?;
        let output = self
            .run(&["jobs", "stop", &job.id.to_string()])
            .map_err(|error| {
                let started = !matches!(&error, process::RunError::Spawn(_));
                let cause = process_failure(&JOB_STOP, self.executable_kind, error);
                if started {
                    CancelError::Unconfirmed(cause)
                } else {
                    CancelError::NotRequested(cause)
                }
            })?;
        // A signal exit has no code: pass it through as absent so the decoder
        // cannot read a stop as acknowledged.
        let evidence = decode_output(
            &JOB_STOP,
            self.executable_kind,
            output.status.code().map(i64::from),
            &output.stdout,
            &output.stderr,
        )
        .map_err(CancelError::Unconfirmed)?;
        self.verify_engine().map_err(CancelError::Unconfirmed)?;
        let value = stop_acknowledgment(evidence.result(), job.id).ok_or_else(|| {
            CancelError::Unconfirmed(evidence.fail(DiagnosticCode::InvalidNativeOutput))
        })?;

        Ok(Cancellation {
            acknowledgment: Observation { value, evidence },
            observation: self.observe_job(job),
        })
    }

    /// Observe the exact job without issuing a stop request. A missing row
    /// supplies no evidence that the job ended.
    pub fn observe_job(&self, job: &OwnedJob) -> Result<Observation<Option<Job>>, InvocationError> {
        self.check_job_binding(job)?;
        // The native store interprets an out-of-range signed cursor as absent.
        // At its maximum representable ID, the first row is already bounded.
        let before = job.id.checked_add(1).map(|id| id as u64);
        let page = self.list_jobs(1, before)?;
        let value = page
            .value
            .into_iter()
            .next()
            .filter(|row| row.id == job.id as u64);
        Ok(Observation {
            value,
            evidence: page.evidence,
        })
    }

    fn check_job_binding(&self, job: &OwnedJob) -> Result<(), InvocationError> {
        if job.engine != self.engine {
            return Err(InvocationError::InvalidArgument);
        }
        Ok(())
    }
}

impl Job {
    pub fn is_terminal(&self) -> bool {
        is_end_state(&self.state) && !self.live && self.ended.is_some()
    }
}

fn is_end_state(state: &str) -> bool {
    matches!(
        state,
        "completed"
            | "stopped"
            | "budget"
            | "refused-limit"
            | "pass-stop"
            | "failed"
            | "interrupted"
    )
}

pub(super) fn stop_acknowledgment(
    stopped: &serde_json::Value,
    id: i64,
) -> Option<CancelAcknowledgment> {
    if stopped["engine_running"] != true || stopped["wait_secs"].as_u64() != Some(STOP_WAIT_SECS) {
        return None;
    }
    let [job] = stopped["jobs"].as_array()?.as_slice() else {
        return None;
    };
    if job["id"].as_i64() != Some(id) {
        return None;
    }
    let state = job["state"].as_str()?;
    let ended = job["ended"].as_bool()?;
    let stopped_now = job["stopped_now"].as_bool()?;
    match (state, ended, stopped_now) {
        ("stopped", true, true) => Some(CancelAcknowledgment::Stopped),
        ("ending", false, true) => Some(CancelAcknowledgment::StopPending),
        ("ending", true, false) => Some(CancelAcknowledgment::EndingWithoutStop),
        (state, true, false) if is_end_state(state) => Some(CancelAcknowledgment::EndedWithoutStop),
        _ => None,
    }
}
