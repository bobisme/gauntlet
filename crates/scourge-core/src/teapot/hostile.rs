//! Pure inspection of captured Teapot replies, for the hostile-input harness.
//!
//! `fuzz/` varies the bytes Teapot printed and nothing else. The parameters a
//! live call takes from operator or run state (session name, follow bound,
//! macro name and step, job ID, body window) are supplied by the caller here,
//! exactly as the adapter takes them from trusted state.
//!
//! Nothing in this module spawns a process, reads the network, writes evidence
//! or changes a verdict. Each function is the adapter's own decoder: the same
//! schema check, then the same trailing shape parser a live call uses, so a
//! malformed or contradictory reply is a typed error and never a pass.
//!
//! The module is compiled only for the `hostile-input` feature the fuzz crate
//! enables; it is not part of the shipped adapter's surface.

use crate::wire::AbsolutePath;

use super::{
    BodyWindow, BoundEngine, CancelAcknowledgment, DiagnosticCode, ExecutableKind, InvocationError,
    Job, MacroReplayReceipt, MacroRun, NativeOutput, SentRequest, StoredFlow, cancel, check_engine,
    flow, job_page, request_ceiling, send,
};

/// The trusted parameters of one action call.
///
/// Each variant belongs to one [`NativeOutput`] action shape; a live call
/// builds it from bound state, and the harness builds it from the parameters the
/// captured seed was recorded with.
#[derive(Clone, Copy, Debug)]
pub enum Trusted<'a> {
    Send {
        session: &'a str,
        follow: Option<u8>,
    },
    MacroRun {
        name: &'a str,
        session: &'a str,
        until: Option<u32>,
    },
    MacroReplay {
        name: &'a str,
        session: &'a str,
        step: u32,
    },
    ReadFlow {
        id: u64,
        window: BodyWindow,
    },
    JobStop {
        id: i64,
    },
}

impl Trusted<'_> {
    /// The action shape these parameters belong to.
    #[must_use]
    pub const fn shape(self) -> NativeOutput {
        match self {
            Self::Send { .. } => NativeOutput::Send,
            Self::MacroRun { .. } => NativeOutput::MacroRun,
            Self::MacroReplay { .. } => NativeOutput::MacroReplay,
            Self::ReadFlow { .. } => NativeOutput::ReadFlow,
            Self::JobStop { .. } => NativeOutput::JobStop,
        }
    }
}

/// The typed shape one action reply parsed into.
///
/// The payloads are boxed so one enum can carry every action's reply without
/// inflating the common case; field access through the box is transparent.
#[derive(Debug)]
pub enum ActionReply {
    /// `requests send`.
    Sent(Box<SentRequest>),
    /// `macros run`.
    Macro(Box<MacroRun>),
    /// `flows replay`.
    Replay(Box<MacroReplayReceipt>),
    /// `flows show`.
    Flow(Box<StoredFlow>),
    /// `jobs stop`.
    Stopped(CancelAcknowledgment),
}

/// Decode one captured argv output and parse the action's typed shape.
///
/// The shape and the trusted parameters must name the same call: a mismatched
/// pair is `InvalidNativeOutput`, never a pass. A missing exit code (a signal)
/// and any non-zero exit are refused before the shape is read, at the same
/// place a live call refuses them.
pub fn action_reply(
    shape: NativeOutput,
    status: Option<i64>,
    stdout: &[u8],
    stderr: &[u8],
    trusted: Trusted<'_>,
) -> Result<ActionReply, InvocationError> {
    let reply = shape.decode(ExecutableKind::Native, status, stdout, stderr)?;
    if trusted.shape() != shape || !shape.is_action() {
        return Err(reply.fail(DiagnosticCode::InvalidNativeOutput));
    }
    let parsed = match trusted {
        Trusted::Send { session, follow } => send::sent_request(&reply, session, follow)
            .map(|sent| ActionReply::Sent(Box::new(sent))),
        Trusted::MacroRun {
            name,
            session,
            until,
        } => send::macro_run(&reply, name, session, until)
            .map(|run| ActionReply::Macro(Box::new(run))),
        Trusted::MacroReplay {
            name,
            session,
            step,
        } => send::macro_replay(&reply, name, session, step)
            .map(|receipt| ActionReply::Replay(Box::new(receipt))),
        Trusted::ReadFlow { id, window } => {
            flow::stored_flow(reply.result(), id, window).map(|mut flow| {
                // The adapter takes this from the envelope's advice, outside the
                // typed flow record.
                flow.head_cut = reply.envelope()["advice"]
                    .as_array()
                    .is_some_and(|advice| advice.iter().any(|item| item["type"] == "head-cut"));
                ActionReply::Flow(Box::new(flow))
            })
        }
        Trusted::JobStop { id } => {
            cancel::stop_acknowledgment(reply.result(), id).map(ActionReply::Stopped)
        }
    };
    parsed.ok_or_else(|| reply.fail(DiagnosticCode::InvalidNativeOutput))
}

/// Decode a `version` reply and whether it came from the bound engine.
///
/// The reply body is untrusted; the project and engine binding are the trusted
/// side a live call compares against.
pub fn version_contract(
    project: &AbsolutePath,
    engine: &BoundEngine,
    status: Option<i64>,
    stdout: &[u8],
    stderr: &[u8],
) -> Result<(), InvocationError> {
    let reply = NativeOutput::Version.decode(ExecutableKind::Native, status, stdout, stderr)?;
    check_engine(project, engine, &reply)
}

/// Decode a `jobs list` reply and parse one bounded page of job rows.
///
/// The page is the trusted request (`limit`, `before`); the rows are untrusted.
pub fn jobs_page(
    limit: u16,
    before: Option<u64>,
    status: Option<i64>,
    stdout: &[u8],
    stderr: &[u8],
) -> Result<Vec<Job>, InvocationError> {
    let reply = NativeOutput::JobsList.decode(ExecutableKind::Native, status, stdout, stderr)?;
    job_page(&reply, limit, before)
}

/// Decode a `pass show` reply and read the request ceiling it reports.
pub fn request_units_left(
    status: Option<i64>,
    stdout: &[u8],
    stderr: &[u8],
) -> Result<Option<u64>, InvocationError> {
    let reply = NativeOutput::PassShow.decode(ExecutableKind::Native, status, stdout, stderr)?;
    Ok(request_ceiling(&reply)?.and_then(|ceiling| ceiling["left"].as_u64()))
}
