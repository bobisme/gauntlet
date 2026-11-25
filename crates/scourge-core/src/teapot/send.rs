//! Effectful Teapot operations: one request under a named session, a declared
//! macro, and a macro-step replay.
//!
//! Teapot's only per-send reference is the flow ID it returns. The ID is
//! nullable: a request can be sent while capture is off or after capture is
//! lost. [`DispatchEvidence`] keeps that absence separate from a step the
//! instrument recorded as not sent, because a missing flow never establishes
//! that a request was not sent (INV-41).
//!
//! A login or retry the instrument adds to a step is bound to that step by
//! [`StepFlow`]. Its flows are returned with the step that caused them; they
//! are never merged into another step. When the instrument retried, the
//! reply's own flow is the retry and `relogin.logged_out_flow` is the send
//! that was answered logged-out, so the original request keeps its own
//! reference.
//!
//! Every decoder also checks the caller's effect bound: a send carries one
//! request plus at most its `--follow` redirects, and a macro run carries the
//! prefix `1..=--until` and nothing else. Native `unknown`, `stopped` and
//! refusals exit through an error envelope, so a successful reply never
//! reports them; a reply that does is rejected rather than read as evidence
//! that nothing was dispatched.

use std::collections::HashSet;

use serde_json::Value;

use super::{
    InvocationError, MACRO_REPLAY, MACRO_RUN, NativeReply, Observation, SEND, Teapot, argument,
};
use crate::{
    ids::{SessionName, WireText},
    template::Method,
    wire::DiagnosticCode,
};

/// Optional values from the frozen `requests send` variant.
#[derive(Clone, Copy, Debug, Default)]
pub struct SendOptions<'a> {
    /// Exact `Name: value` header arguments, in order.
    pub headers: &'a [String],
    /// Exact request body. `None` omits `--body`.
    pub body: Option<&'a str>,
    /// Exact `LOCATION:PATH=VALUE` edits, in order.
    pub edits: &'a [String],
    /// Redirect hops to follow, 0 to 20. `None` omits `--follow`.
    pub follow: Option<u8>,
}

/// Where a sending command's session came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionSource {
    Flag,
    Default,
    None,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionUsed {
    pub name: Option<WireText>,
    pub source: SessionSource,
}

/// The outcome Teapot recorded for a request it sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendOutcome {
    Complete,
    Unknown,
    Stopped,
    Failed,
}

/// The outcome Teapot recorded for a macro step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StepOutcome {
    Complete,
    Unknown,
    Stopped,
    Refused,
    Failed,
    Planned,
    NotRun,
}

/// Why a step is known not to have been sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotSentReason {
    /// A refusal or failure recorded before dispatch.
    Refused,
    /// A dry run planned the step but sent nothing.
    Planned,
    /// A run ended before this step (`--until`, or an earlier step's outcome).
    NotRun,
}

/// What the adapter can say about one step's dispatch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DispatchEvidence {
    /// A retained flow ID is the per-send reference.
    Flow { flow: u64 },
    /// The instrument reported that the request was sent but retained no flow.
    /// Capture may have been off or lost; this establishes neither an effect
    /// nor an absence.
    NoFlow { outcome: SendOutcome },
    /// The instrument recorded that nothing was sent.
    NotSent { reason: NotSentReason },
}

impl DispatchEvidence {
    /// The usable per-send reference, when one exists.
    pub fn flow(self) -> Option<u64> {
        match self {
            Self::Flow { flow } => Some(flow),
            Self::NoFlow { .. } | Self::NotSent { .. } => None,
        }
    }

    /// True for a recorded send, false for a recorded non-send. A missing
    /// flow is still a recorded send: the instrument's step outcome is the
    /// evidence, and it is bound to the reply of this run and step.
    pub fn was_sent(self) -> bool {
        !matches!(self, Self::NotSent { .. })
    }

    pub fn is_not_sent(self) -> bool {
        matches!(self, Self::NotSent { .. })
    }

    pub fn is_no_flow(self) -> bool {
        matches!(self, Self::NoFlow { .. })
    }
}

impl StepOutcome {
    fn dispatch(self, flow: Option<u64>) -> Option<DispatchEvidence> {
        match (self, flow) {
            (Self::Complete, Some(flow)) => Some(DispatchEvidence::Flow { flow }),
            (Self::Unknown, Some(flow)) => Some(DispatchEvidence::Flow { flow }),
            (Self::Stopped, Some(flow)) => Some(DispatchEvidence::Flow { flow }),
            (Self::Failed, Some(flow)) => Some(DispatchEvidence::Flow { flow }),
            (Self::Complete, None) => Some(DispatchEvidence::NoFlow {
                outcome: SendOutcome::Complete,
            }),
            (Self::Unknown, None) => Some(DispatchEvidence::NoFlow {
                outcome: SendOutcome::Unknown,
            }),
            (Self::Stopped, None) => Some(DispatchEvidence::NoFlow {
                outcome: SendOutcome::Stopped,
            }),
            (Self::Failed, None) => Some(DispatchEvidence::NoFlow {
                outcome: SendOutcome::Failed,
            }),
            (Self::Refused, None) => Some(DispatchEvidence::NotSent {
                reason: NotSentReason::Refused,
            }),
            (Self::Planned, None) => Some(DispatchEvidence::NotSent {
                reason: NotSentReason::Planned,
            }),
            (Self::NotRun, None) => Some(DispatchEvidence::NotSent {
                reason: NotSentReason::NotRun,
            }),
            // A flow from a step that was not sent is contradictory.
            (Self::Refused | Self::Planned | Self::NotRun, Some(_)) => None,
        }
    }
}

/// What one flow in a step was for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlowRole {
    /// The step's own request, or its first request with no redirects.
    Request,
    /// A followed redirect in the same send.
    Redirect,
    /// A step of a login macro the instrument ran because of this step.
    Login,
    /// The request after a login, sent again by the instrument.
    Retry,
}

/// The retained per-send reference, or its absence for a send.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlowReference {
    Retained(u64),
    /// The request was sent and no flow was retained (capture off or lost).
    Missing,
}

/// One flow a step sent, bound to that step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StepFlow {
    pub step: u32,
    pub role: FlowRole,
    pub reference: FlowReference,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReloginAction {
    ReLoggedIn,
    LoginShared,
    LoginFailed,
    LoginStopped,
    Paused,
    Reported,
}

/// What the session sender did about a logged-out answer. Names, stable words
/// and flow IDs only; no cookie, token or secret value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReloginUsed {
    pub rule: String,
    pub action: ReloginAction,
    pub ran: bool,
    pub generation: u64,
    pub login: Option<String>,
    pub login_job: Option<u64>,
    pub login_flows: Vec<u64>,
    pub logged_out_flow: Option<u64>,
    pub retried: bool,
    pub retry_flow: Option<u64>,
    pub not_retried: Option<String>,
    pub paused: bool,
    pub reason: Option<String>,
}

impl ReloginUsed {
    /// True when the reply's own send is the instrument's retry, so its flow
    /// and hops describe the second request rather than the one that was
    /// answered logged-out.
    pub fn retried(&self) -> bool {
        self.retried
    }

    /// The send answered logged-out, when the reply's own hop is the retry:
    /// its flow is `logged_out_flow` (`Missing` when capture lost it).
    fn original(&self) -> FlowReference {
        self.logged_out_flow
            .map(FlowReference::Retained)
            .unwrap_or(FlowReference::Missing)
    }

    /// The retry's own send, `Missing` when capture was off or lost for it.
    /// Retried evidence never depends on a flow existing (INV-41).
    fn retry(&self) -> FlowReference {
        self.retry_flow
            .map(FlowReference::Retained)
            .unwrap_or(FlowReference::Missing)
    }

    fn login_references(&self) -> impl Iterator<Item = (FlowRole, FlowReference)> + '_ {
        self.login_flows
            .iter()
            .copied()
            .map(|flow| (FlowRole::Login, FlowReference::Retained(flow)))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VariableBy {
    Extract,
    Compute,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VariableSet {
    pub name: String,
    pub len: u64,
    pub by: VariableBy,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WithheldHeaders {
    pub names: Vec<String>,
    pub reason: String,
}

/// One request in a `requests send` call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SentHop {
    pub destination: String,
    pub elapsed_ms: u64,
    pub flow: Option<u64>,
    pub length: Option<u64>,
    pub location: Option<String>,
    pub outcome: SendOutcome,
    pub sent_bytes: u64,
    pub state: String,
    pub status: Option<u16>,
    pub tags: Vec<String>,
}

/// The exact frozen `requests send` reply, with the per-send reference typed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SentRequest {
    pub flow: Option<u64>,
    pub destination: String,
    /// The request as written to the wire, lossy UTF-8 text. Exact body bytes
    /// are read back with [`Teapot::read_flow`].
    pub request: String,
    pub request_bytes: u64,
    pub hops: Vec<SentHop>,
    pub status: Option<u16>,
    pub session: SessionUsed,
    pub relogin: Option<ReloginUsed>,
    pub withheld: Option<WithheldHeaders>,
}

impl SentRequest {
    /// The dispatch evidence for the send this reply is about: the first hop,
    /// which is the instrument's retry when it retried. A followed redirect's
    /// own flows, and the original request's, are in [`Self::flows`].
    pub fn dispatch(&self) -> DispatchEvidence {
        match self.hops.first() {
            Some(hop) => match hop.flow {
                Some(flow) => DispatchEvidence::Flow { flow },
                None => DispatchEvidence::NoFlow {
                    outcome: hop.outcome,
                },
            },
            // Parsing rejects an empty hop list.
            None => DispatchEvidence::NotSent {
                reason: NotSentReason::Refused,
            },
        }
    }

    /// Every flow this single-step send produced, including redirect hops and
    /// instrument-added login or retry sends. With a retry the hops are the
    /// second send, so the original request's flow comes from the
    /// logged-out answer and the retry is counted once, as [`FlowRole::Retry`].
    pub fn flows(&self) -> Vec<StepFlow> {
        let retried = self.relogin.as_ref().is_some_and(ReloginUsed::retried);
        let mut flows = Vec::new();
        if retried {
            let reference = self
                .relogin
                .as_ref()
                .map(|relogin| relogin.original())
                .unwrap_or(FlowReference::Missing);
            flows.push(StepFlow {
                step: 1,
                role: FlowRole::Request,
                reference,
            });
            if let Some(relogin) = &self.relogin {
                flows.extend(
                    relogin
                        .login_references()
                        .map(|(role, reference)| StepFlow {
                            step: 1,
                            role,
                            reference,
                        }),
                );
            }
        }
        for (index, hop) in self.hops.iter().enumerate() {
            let role = match (retried, index) {
                (true, 0) => FlowRole::Retry,
                (true, _) => FlowRole::Redirect,
                (false, 0) => FlowRole::Request,
                (false, _) => FlowRole::Redirect,
            };
            flows.push(StepFlow {
                step: 1,
                role,
                reference: hop
                    .flow
                    .map(FlowReference::Retained)
                    .unwrap_or(FlowReference::Missing),
            });
        }
        if !retried && let Some(relogin) = &self.relogin {
            flows.extend(
                relogin
                    .login_references()
                    .map(|(role, reference)| StepFlow {
                        step: 1,
                        role,
                        reference,
                    }),
            );
        }
        flows
    }
}

/// One step of a macro run, with its own dispatch evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StepRun {
    pub step: u32,
    pub method: String,
    pub url: String,
    pub state_changing: bool,
    pub outcome: StepOutcome,
    pub flow: Option<u64>,
    pub status: Option<u16>,
    pub class: Option<String>,
    pub reason: Option<String>,
    pub relogin: Option<ReloginUsed>,
    pub csrf_refreshed: Vec<String>,
    pub withheld: Vec<String>,
    pub set: Vec<VariableSet>,
    pub references: Vec<String>,
    pub compute: Option<String>,
}

impl StepRun {
    pub fn dispatch(&self) -> DispatchEvidence {
        self.outcome
            .dispatch(self.flow)
            .expect("parser rejects a flow on a step that was not sent")
    }

    /// Every flow this step produced, including instrument-added login and
    /// retry sends. Each entry keeps this step's number. A retried step keeps
    /// the original request (its logged-out answer's flow), the login, and the
    /// retry separately; the retry is the step's own flow, counted once.
    pub fn flows(&self) -> Vec<StepFlow> {
        let retried = self.relogin.as_ref().is_some_and(ReloginUsed::retried);
        let mut flows = Vec::new();
        if retried {
            flows.push(StepFlow {
                step: self.step,
                role: FlowRole::Request,
                reference: self
                    .relogin
                    .as_ref()
                    .map(|relogin| relogin.original())
                    .unwrap_or(FlowReference::Missing),
            });
        } else if !self.dispatch().is_not_sent() {
            flows.push(StepFlow {
                step: self.step,
                role: FlowRole::Request,
                reference: self
                    .flow
                    .map(FlowReference::Retained)
                    .unwrap_or(FlowReference::Missing),
            });
        }
        if let Some(relogin) = &self.relogin {
            flows.extend(
                relogin
                    .login_references()
                    .map(|(role, reference)| StepFlow {
                        step: self.step,
                        role,
                        reference,
                    }),
            );
            if retried {
                flows.push(StepFlow {
                    step: self.step,
                    role: FlowRole::Retry,
                    reference: relogin.retry(),
                });
            }
        }
        flows
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MacroOutcome {
    Completed,
    Until,
    /// `--dry-run`. The effectful decoders here reject a dry-run reply, so a
    /// live [`MacroRun`] is never `Planned`; the variant names the frozen word.
    Planned,
}

/// The exact frozen `macros run` reply, typed per step.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MacroRun {
    pub job: Option<u64>,
    pub name: String,
    pub outcome: MacroOutcome,
    pub session: SessionUsed,
    pub state_changing: Vec<u32>,
    pub units: u64,
    pub units_left: Option<u64>,
    pub steps: Vec<StepRun>,
    pub variables: Vec<VariableSet>,
}

impl MacroRun {
    pub fn step(&self, step: u32) -> Option<&StepRun> {
        self.steps.iter().find(|run| run.step == step)
    }

    /// All flows the run produced, each bound to its step.
    pub fn flows(&self) -> Vec<StepFlow> {
        self.steps.iter().flat_map(StepRun::flows).collect()
    }
}

/// The exact frozen `flows replay --macro` reply, with preparatory steps and
/// the replayed step kept separate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MacroReplay {
    pub job: Option<u64>,
    pub name: String,
    pub step: u32,
    pub steps_in_macro: u32,
    pub state_changing: Vec<u32>,
    pub units: u64,
    pub units_left: Option<u64>,
    pub preparatory: Vec<StepRun>,
    pub replayed: StepRun,
    pub replaced: Vec<String>,
    pub variables: Vec<VariableSet>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MacroReplayReceipt {
    pub parent: u64,
    pub destination: String,
    pub status: Option<u16>,
    pub time_ms: Option<u64>,
    pub notes: Vec<String>,
    pub relogin: Option<ReloginUsed>,
    pub withheld: Option<WithheldHeaders>,
    pub replay: MacroReplay,
}

impl MacroReplayReceipt {
    /// Flows from the preparatory steps and the replayed step, in run order.
    pub fn flows(&self) -> Vec<StepFlow> {
        self.replay
            .preparatory
            .iter()
            .chain(std::iter::once(&self.replay.replayed))
            .flat_map(StepRun::flows)
            .collect()
    }

    pub fn dispatch(&self) -> DispatchEvidence {
        self.replay.replayed.dispatch()
    }
}

impl Teapot {
    /// Send one request under a named session. This sends target traffic and
    /// spends units, so the caller admits the effect first.
    pub fn send(
        &self,
        method: Method,
        url: &WireText,
        session: &SessionName,
        options: SendOptions<'_>,
    ) -> Result<Observation<SentRequest>, InvocationError> {
        let url = argument(url.as_str())?;
        let session = argument(session.as_str())?;
        if options.follow.is_some_and(|follow| follow > 20) {
            return Err(InvocationError::InvalidArgument);
        }
        let mut words = vec![
            "requests",
            "send",
            method.as_str(),
            url,
            "--session",
            session,
        ];
        let body = options.body.map(body_argument).transpose()?;
        let edits = options
            .edits
            .iter()
            .map(|edit| edit_argument(edit))
            .collect::<Result<Vec<_>, _>>()?;
        for header in options.headers {
            words.extend(["--header", value_argument(header)?]);
        }
        if let Some(body) = &body {
            words.extend(["--body", body.as_str()]);
        }
        for edit in &edits {
            words.extend(["--set", edit.as_str()]);
        }
        let follow = options
            .follow
            .filter(|follow| *follow > 0)
            .map(|v| v.to_string());
        if let Some(follow) = &follow {
            words.extend(["--follow", follow.as_str()]);
        }
        let evidence = self.invoke_live(&SEND, &words)?;
        let value = sent_request(&evidence, session, options.follow)
            .ok_or_else(|| evidence.fail(DiagnosticCode::InvalidNativeOutput))?;
        Ok(Observation { value, evidence })
    }

    /// Run a declared macro for a multi-step plant. `until` bounds the run to
    /// the first N steps and is omitted otherwise.
    pub fn run_macro(
        &self,
        name: &WireText,
        session: &SessionName,
        until: Option<u32>,
    ) -> Result<Observation<MacroRun>, InvocationError> {
        let name = argument(name.as_str())?;
        let session = argument(session.as_str())?;
        if until.is_some_and(|step| step == 0) {
            return Err(InvocationError::InvalidArgument);
        }
        let mut words = vec!["--yes", "macros", "run", name, "--session", session];
        let until_arg = until.map(|step| step.to_string());
        if let Some(until) = &until_arg {
            words.extend(["--until", until.as_str()]);
        }
        let evidence = self.invoke_live(&MACRO_RUN, &words)?;
        let value = macro_run(&evidence, name, session, until)
            .ok_or_else(|| evidence.fail(DiagnosticCode::InvalidNativeOutput))?;
        Ok(Observation { value, evidence })
    }

    /// Replay one step of a declared macro after running the steps before it.
    /// The frozen variant requires at least one `--set` edit; the replay is
    /// schema-qualified by M0.7 and gains runtime qualification only from a
    /// live contract test.
    pub fn replay_macro(
        &self,
        name: &WireText,
        session: &SessionName,
        step: u32,
        edits: &[String],
    ) -> Result<Observation<MacroReplayReceipt>, InvocationError> {
        let name = argument(name.as_str())?;
        let session = argument(session.as_str())?;
        if step == 0 || edits.is_empty() {
            return Err(InvocationError::InvalidArgument);
        }
        let step_arg = step.to_string();
        let mut words = vec![
            "--yes",
            "flows",
            "replay",
            "--macro",
            name,
            "--step",
            step_arg.as_str(),
            "--session",
            session,
        ];
        let edits = edits
            .iter()
            .map(|edit| edit_argument(edit))
            .collect::<Result<Vec<_>, _>>()?;
        for edit in &edits {
            words.extend(["--set", edit.as_str()]);
        }
        let evidence = self.invoke_live(&MACRO_REPLAY, &words)?;
        let value = macro_replay(&evidence, name, session, step)
            .ok_or_else(|| evidence.fail(DiagnosticCode::InvalidNativeOutput))?;
        Ok(Observation { value, evidence })
    }
}

fn value_argument(value: &str) -> Result<&str, InvocationError> {
    // A leading hyphen would be read as another flag by the native parser,
    // and exec cannot carry a NUL: either is a usage error here, never a
    // spawn failure that reads as a missing tool.
    if value.starts_with('-') || value.contains('\0') {
        return Err(InvocationError::InvalidArgument);
    }
    Ok(value)
}

/// Teapot reads a value that begins with `@` as a path source (`@-` is
/// standard input) and `@@x` as the literal text `@x`. Verifier bytes are
/// never a source, so one more `@` keeps them literal (`@x` becomes `@@x`,
/// `@-` becomes `@@-`).
fn literal_argument(value: &str) -> String {
    match value.strip_prefix('@') {
        Some(_) => format!("@{value}"),
        None => value.to_owned(),
    }
}

/// The `--body` of an exact request body: literal, never a file or stdin.
fn body_argument(value: &str) -> Result<String, InvocationError> {
    Ok(literal_argument(value_argument(value)?))
}

/// A `LOCATION:PATH=VALUE` edit. Only the text the frozen parser passes to
/// `resolve` is escaped, so `json:x=@secret` becomes `json:x=@@secret` and
/// Teapot reads the text `@secret`.
///
/// The frozen grammar (`teapot-core` `edit/parse.rs`) resolves:
///
/// - the text after the first `=` for `json`, `json+`, `form`, `query`,
///   `cookie` and `header`;
/// - everything after the colon for `path` and `method`, dropping one leading
///   `=` (`rest.strip_prefix('=').unwrap_or(rest)`), so a no-equals
///   `path:@file` is a source too;
/// - nothing for `json-`, `form-`, `query-` and `cookie-`, which take a name or
///   path and no value.
fn edit_argument(value: &str) -> Result<String, InvocationError> {
    let value = value_argument(value)?;
    let Some((head, rest)) = value.split_once(':') else {
        return Ok(value.to_owned());
    };
    let location = head.trim();
    let source_free = ["json-", "form-", "query-", "cookie-"]
        .iter()
        .any(|removal| location.eq_ignore_ascii_case(removal));
    if source_free {
        return Ok(value.to_owned());
    }
    let escaped = if ["path", "method"]
        .iter()
        .any(|whole| location.eq_ignore_ascii_case(whole))
    {
        match rest.strip_prefix('=') {
            Some(rest) => format!("={}", literal_argument(rest)),
            None => literal_argument(rest),
        }
    } else {
        match rest.split_once('=') {
            Some((target, literal)) => format!("{target}={}", literal_argument(literal)),
            // Not a value this grammar resolves (an unknown location is a
            // usage error, and a value-less form is unchanged).
            None => return Ok(value.to_owned()),
        }
    };
    Ok(format!("{head}:{escaped}"))
}

fn session_used(value: &Value) -> Option<SessionUsed> {
    let name = match &value["name"] {
        Value::Null => None,
        Value::String(name) if !name.is_empty() => Some(name.parse().ok()?),
        _ => return None,
    };
    let source = match value["source"].as_str()? {
        "flag" => SessionSource::Flag,
        "default" => SessionSource::Default,
        "none" => SessionSource::None,
        _ => return None,
    };
    if matches!(source, SessionSource::None) != name.is_none() {
        return None;
    }
    Some(SessionUsed { name, source })
}

fn opted_u64(value: &Value) -> Option<Option<u64>> {
    match value {
        Value::Null => Some(None),
        value => Some(Some(value.as_u64()?)),
    }
}

fn opted_flow(value: &Value) -> Option<Option<u64>> {
    match value {
        Value::Null => Some(None),
        value => value.as_u64().filter(|flow| *flow > 0).map(Some),
    }
}

fn opted_u16(value: &Value) -> Option<Option<u16>> {
    match value {
        Value::Null => Some(None),
        value => Some(Some(u16::try_from(value.as_u64()?).ok()?)),
    }
}

fn opted_string(value: &Value) -> Option<Option<String>> {
    match value {
        Value::Null => Some(None),
        Value::String(text) => Some(Some(text.clone())),
        _ => None,
    }
}

fn strings(value: &Value) -> Option<Vec<String>> {
    value
        .as_array()?
        .iter()
        .map(|item| item.as_str().map(str::to_owned))
        .collect()
}

fn sent_outcome(value: &Value) -> Option<SendOutcome> {
    match value.as_str()? {
        "complete" => Some(SendOutcome::Complete),
        "unknown" => Some(SendOutcome::Unknown),
        "stopped" => Some(SendOutcome::Stopped),
        _ => None,
    }
}

fn step_outcome(value: &Value) -> Option<StepOutcome> {
    match value.as_str()? {
        "complete" => Some(StepOutcome::Complete),
        "unknown" => Some(StepOutcome::Unknown),
        "stopped" => Some(StepOutcome::Stopped),
        "refused" => Some(StepOutcome::Refused),
        "failed" => Some(StepOutcome::Failed),
        "planned" => Some(StepOutcome::Planned),
        "not-run" => Some(StepOutcome::NotRun),
        _ => None,
    }
}

fn relogin(value: &Value) -> Option<ReloginUsed> {
    if value.is_null() {
        return None;
    }
    let action = match value["action"].as_str()? {
        "re-logged-in" => ReloginAction::ReLoggedIn,
        "login-shared" => ReloginAction::LoginShared,
        "login-failed" => ReloginAction::LoginFailed,
        "login-stopped" => ReloginAction::LoginStopped,
        "paused" => ReloginAction::Paused,
        "reported" => ReloginAction::Reported,
        _ => return None,
    };
    let ran = value["ran"].as_bool()?;
    // `ran` says this send ran the login (`teapot-api` `ReloginUsed`). Two
    // action/`ran` pairs the frozen sender cannot write:
    //
    // - `re-logged-in` with `ran=false`: `sessions/login.rs` `run_login`
    //   builds `RELOGGED_IN` only through `base(RELOGGED_IN)`, which sets
    //   `ran=true`; the generation is incremented in the same critical
    //   section as the remembered action, so a send that waited through that
    //   login is answered `login-shared` first (`decided`/`decided_locked`
    //   compare `seen.sent < state.generation` before copying anything).
    // - `login-shared` with `ran=true`: it is the action for a send that
    //   found another send had already logged the session in, so it never
    //   ran one.
    //
    // Every other action goes either way: a session already paused reports
    // `paused` with `ran=false` (`decided`); a login that could not run
    // reports `paused`/`reported` with `ran=true` (`run_login`,
    // `Ended::CannotRun`); and after a retry the sender keeps `ran` from the
    // login that ran and overwrites only the action, so `action=paused` with
    // `ran=true` is the repository-recorded paused-after-retry reply
    // (`fixtures/contracts/channel-observed.txt`, `sessions/sender.rs`).
    if matches!(
        (action, ran),
        (ReloginAction::ReLoggedIn, false) | (ReloginAction::LoginShared, true)
    ) {
        return None;
    }
    let retried = value["retried"].as_bool()?;
    let not_retried = opted_string(&value["not_retried"])?;
    let paused = value["paused"].as_bool()?;
    // `not_retried` answers why the request was not sent again, and the frozen
    // sender writes it only on the paths that return before the retry
    // (`sessions/sender.rs` `after`: `retried` is set only once the retry was
    // sent). A retried send that also says why it was not retried is
    // contradictory.
    if retried && not_retried.is_some() {
        return None;
    }
    // Only a login that allows a retry reaches the retry branch: the jar is
    // new (`re-logged-in`, `login-shared`) or the paused-after-retry path set
    // `paused`. A retry alongside another action is a claim the sender cannot
    // make.
    if retried
        && !matches!(
            action,
            ReloginAction::ReLoggedIn | ReloginAction::LoginShared | ReloginAction::Paused
        )
    {
        return None;
    }
    // A retry answered logged-out again pauses the session: `sessions/sender.rs`
    // assigns `paused`, `action=PAUSED`, the reason, `retried` and
    // `retry_flow` together in that branch, and `action=paused` cannot reach
    // the retry any other way (`allows_retry` is only `re-logged-in` or
    // `login-shared`). A paused-after-retry reply that says the session is
    // not paused is contradictory.
    if retried && action == ReloginAction::Paused && !paused {
        return None;
    }
    let retry_flow = opted_flow(&value["retry_flow"])?;
    // Teapot sets `retried` before it knows whether capture kept the retry's
    // flow, so a retry can have no `retry_flow` (INV-41). A flow without a
    // retry would still be a claim nothing supports.
    if !retried && retry_flow.is_some() {
        return None;
    }
    let logged_out_flow = opted_flow(&value["logged_out_flow"])?;
    let login_flows = value["login_flows"]
        .as_array()?
        .iter()
        .map(|flow| flow.as_u64().filter(|flow| *flow > 0))
        .collect::<Option<Vec<_>>>()?;
    let mut seen = HashSet::new();
    if login_flows.iter().any(|flow| !seen.insert(*flow))
        || retry_flow.is_some_and(|flow| !seen.insert(flow))
    {
        return None;
    }
    Some(ReloginUsed {
        rule: nonempty(value["rule"].as_str()?)?.to_owned(),
        action,
        ran,
        generation: value["generation"].as_u64()?,
        login: opted_string(&value["login"])?,
        login_job: opted_u64(&value["login_job"])?,
        login_flows,
        logged_out_flow,
        retried,
        retry_flow,
        not_retried,
        paused,
        reason: opted_string(&value["reason"])?,
    })
}

fn withheld(value: &Value) -> Option<WithheldHeaders> {
    if value.is_null() {
        return None;
    }
    Some(WithheldHeaders {
        names: strings(&value["names"])?,
        reason: nonempty(value["reason"].as_str()?)?.to_owned(),
    })
}

fn nonempty(value: &str) -> Option<&str> {
    (!value.is_empty()).then_some(value)
}

fn sent_hop(value: &Value) -> Option<SentHop> {
    let flow = opted_flow(&value["flow"])?;
    let outcome = sent_outcome(&value["outcome"])?;
    Some(SentHop {
        destination: nonempty(value["destination"].as_str()?)?.to_owned(),
        elapsed_ms: value["elapsed_ms"].as_u64()?,
        flow,
        length: opted_u64(&value["length"])?,
        location: opted_string(&value["location"])?,
        outcome,
        sent_bytes: value["sent_bytes"].as_u64()?,
        state: nonempty(value["state"].as_str()?)?.to_owned(),
        status: opted_u16(&value["status"])?,
        tags: strings(&value["tags"])?,
    })
}

pub(super) fn sent_request(
    evidence: &NativeReply,
    session: &str,
    follow: Option<u8>,
) -> Option<SentRequest> {
    let sent = evidence.result();
    if sent["dry_run"] != false || !sent["would_refuse"].is_null() {
        return None;
    }
    let session_used = session_used(&sent["session"])?;
    if session_used.source != SessionSource::Flag
        || session_used.name.as_ref().map(WireText::as_str) != Some(session)
    {
        return None;
    }
    let hops = sent["hops"]
        .as_array()?
        .iter()
        .map(sent_hop)
        .collect::<Option<Vec<_>>>()?;
    // One request plus at most the caller's `--follow` redirects. A longer
    // hop list sent traffic past the bound the caller asked for.
    let bound = 1 + usize::from(follow.unwrap_or(0));
    if hops.is_empty() || hops.len() > bound {
        return None;
    }
    // An `unknown` or `stopped` answer, or a stop before a redirect hop,
    // exits as an error envelope: a successful send read every hop whole.
    if hops.iter().any(|hop| hop.outcome != SendOutcome::Complete) {
        return None;
    }
    let flow = opted_flow(&sent["flow"])?;
    // Teapot's `flow` is the first request's flow. A disagreement would make
    // the per-send reference ambiguous.
    if flow != hops[0].flow {
        return None;
    }
    if sent["destination"].as_str() != Some(hops[0].destination.as_str()) {
        return None;
    }
    let status = opted_u16(&sent["status"])?;
    if status != hops.last()?.status {
        return None;
    }
    let mut seen = HashSet::new();
    if hops
        .iter()
        .filter_map(|hop| hop.flow)
        .any(|flow| !seen.insert(flow))
    {
        return None;
    }
    let relogin = relogin(&sent["relogin"]);
    if sent["relogin"].is_null() == relogin.is_some() {
        return None;
    }
    if let Some(relogin) = &relogin {
        let hop_flows: Vec<u64> = hops.iter().filter_map(|hop| hop.flow).collect();
        if relogin.retried {
            // The hops are the instrument's retry, so the reply's flow is the
            // retry's and the logged-out answer's flow is the original
            // request's: they are distinct sends and must not be confused.
            if relogin.retry_flow != flow {
                return None;
            }
            if relogin.logged_out_flow.is_some_and(|original| {
                hop_flows.contains(&original) || relogin.login_flows.contains(&original)
            }) {
                return None;
            }
        } else if let Some(original) = relogin.logged_out_flow {
            // Not retried: the logged-out answer is one of this send's own
            // hops, first request or followed redirect.
            if !hop_flows.contains(&original) {
                return None;
            }
        }
    }
    let withheld = match &sent["withheld"] {
        Value::Null => None,
        value => Some(withheld(value)?),
    };
    Some(SentRequest {
        flow,
        destination: nonempty(sent["destination"].as_str()?)?.to_owned(),
        request: sent["request"].as_str()?.to_owned(),
        request_bytes: sent["request_bytes"].as_u64()?,
        hops,
        status,
        session: session_used,
        relogin,
        withheld,
    })
}

fn variable(value: &Value) -> Option<VariableSet> {
    let by = match value["by"].as_str()? {
        "extract" => VariableBy::Extract,
        "compute" => VariableBy::Compute,
        _ => return None,
    };
    Some(VariableSet {
        name: nonempty(value["name"].as_str()?)?.to_owned(),
        len: value["len"].as_u64()?,
        by,
    })
}

fn variables(value: &Value) -> Option<Vec<VariableSet>> {
    value.as_array()?.iter().map(variable).collect()
}

fn step_run(value: &Value, expected_step: Option<u32>) -> Option<StepRun> {
    let step = u32::try_from(value["step"].as_u64()?).ok()?;
    if step == 0 || expected_step.is_some_and(|expected| expected != step) {
        return None;
    }
    let outcome = step_outcome(&value["outcome"])?;
    let flow = opted_flow(&value["flow"])?;
    // The parser rejects a flow on a step the instrument says was not sent.
    outcome.dispatch(flow)?;
    let relogin = relogin(&value["relogin"]);
    if value["relogin"].is_null() == relogin.is_some() {
        return None;
    }
    let run = StepRun {
        step,
        method: nonempty(value["method"].as_str()?)?.to_owned(),
        url: nonempty(value["url"].as_str()?)?.to_owned(),
        state_changing: value["state_changing"].as_bool()?,
        outcome,
        flow,
        status: opted_u16(&value["status"])?,
        class: opted_string(&value["class"])?,
        reason: opted_string(&value["reason"])?,
        relogin,
        csrf_refreshed: match &value["csrf_refreshed"] {
            Value::Null => Vec::new(),
            value => strings(value)?,
        },
        withheld: match &value["withheld"] {
            Value::Null => Vec::new(),
            value => strings(value)?,
        },
        set: variables(&value["set"])?,
        references: strings(&value["references"])?,
        compute: opted_string(&value["compute"])?,
    };
    // Frozen `StepReport::new` is the only source of a not-run row: an unrun
    // step has no response, no class, no reason, no relogin and none of the
    // `set`, `withheld` or CSRF evidence a send derives. Only declaration
    // metadata (method, url, state-changing, compute, references) survives.
    // Accepting any of it would let `MacroRun::flows` report traffic for a
    // step the same reply calls `NotSent{NotRun}`.
    if outcome == StepOutcome::NotRun
        && (run.status.is_some()
            || run.class.is_some()
            || run.reason.is_some()
            || run.relogin.is_some()
            || !run.set.is_empty()
            || !run.withheld.is_empty()
            || !run.csrf_refreshed.is_empty())
    {
        return None;
    }
    // A retried step's own flow is the retry; the original request is the
    // logged-out answer's flow and must be a different send. Not retried:
    // `logged_out_flow` can be a followed redirect's flow, which a step row
    // does not carry, so it is recorded as reported.
    if let Some(relogin) = &run.relogin
        && relogin.retried
        && (relogin.retry_flow != run.flow
            || relogin
                .logged_out_flow
                .is_some_and(|original| Some(original) == run.flow))
    {
        return None;
    }
    Some(run)
}

fn steps(value: &Value) -> Option<Vec<StepRun>> {
    let mut runs = Vec::new();
    for (index, value) in value.as_array()?.iter().enumerate() {
        let expected = u32::try_from(index + 1).ok()?;
        runs.push(step_run(value, Some(expected))?);
    }
    Some(runs)
}

pub(super) fn macro_run(
    evidence: &NativeReply,
    name: &str,
    session: &str,
    until: Option<u32>,
) -> Option<MacroRun> {
    let run = evidence.result();
    if run["dry_run"] != false {
        return None;
    }
    let session_used = session_used(&run["session"])?;
    if session_used.source != SessionSource::Flag
        || session_used.name.as_ref().map(WireText::as_str) != Some(session)
    {
        return None;
    }
    let outcome = match run["outcome"].as_str()? {
        "completed" => MacroOutcome::Completed,
        "until" => MacroOutcome::Until,
        // `planned` is a dry run, and this call sent for real.
        _ => return None,
    };
    let steps = steps(&run["steps"])?;
    if steps.is_empty() {
        return None;
    }
    // A successful live run sends the prefix `1..=--until` (the whole macro
    // without it) and records the rest as not-run. A refusal, a stop, an
    // unknown answer or a challenge stops the run as an error envelope, so it
    // is never a success, and none of them may read as "nothing was sent".
    let sent = match until {
        None => {
            if outcome != MacroOutcome::Completed {
                return None;
            }
            if steps
                .iter()
                .any(|step| step.outcome != StepOutcome::Complete)
            {
                return None;
            }
            steps.len()
        }
        Some(bound) => {
            let sent = usize::try_from(bound).ok()?;
            // Teapot refuses `--until` past the last step as a usage error.
            if sent == 0 || sent > steps.len() {
                return None;
            }
            for step in &steps {
                if usize::try_from(step.step).ok()? <= sent {
                    if step.outcome != StepOutcome::Complete {
                        return None;
                    }
                } else if step.outcome != StepOutcome::NotRun
                    || step.flow.is_some()
                    || step.status.is_some()
                {
                    return None;
                }
            }
            let expected = if sent < steps.len() {
                MacroOutcome::Until
            } else {
                MacroOutcome::Completed
            };
            if outcome != expected {
                return None;
            }
            sent
        }
    };
    let units = run["units"].as_u64()?;
    if units != u64::try_from(sent).ok()? {
        return None;
    }
    let state_changing = run["state_changing"]
        .as_array()?
        .iter()
        .map(|step| u32::try_from(step.as_u64()?).ok())
        .collect::<Option<Vec<_>>>()?;
    let expected_changing = steps
        .iter()
        .filter(|step| step.state_changing && step.dispatch().was_sent())
        .map(|step| step.step)
        .collect::<Vec<_>>();
    if state_changing != expected_changing {
        return None;
    }
    let run_name = nonempty(run["name"].as_str()?).filter(|value| *value == name)?;
    Some(MacroRun {
        job: opted_u64(&run["job"])?.filter(|job| *job > 0),
        name: run_name.to_owned(),
        outcome,
        session: session_used,
        state_changing,
        units,
        units_left: opted_u64(&run["units_left"])?,
        steps,
        variables: variables(&run["variables"])?,
    })
}

pub(super) fn macro_replay(
    evidence: &NativeReply,
    name: &str,
    session: &str,
    step: u32,
) -> Option<MacroReplayReceipt> {
    let outer = evidence.result();
    if outer["dry_run"] != false || outer["parent"].as_u64()? != 0 {
        return None;
    }
    if !outer["flows"].as_array()?.is_empty() {
        return None;
    }
    let session_used = session_used(&outer["session"])?;
    if session_used.source != SessionSource::Flag
        || session_used.name.as_ref().map(WireText::as_str) != Some(session)
    {
        return None;
    }
    let replay = &outer["macro_replay"];
    if replay.is_null() {
        return None;
    }
    let replay_name = nonempty(replay["name"].as_str()?).filter(|value| *value == name)?;
    let replay_step = u32::try_from(replay["step"].as_u64()?).ok()?;
    let steps_in_macro = u32::try_from(replay["steps_in_macro"].as_u64()?).ok()?;
    if replay_step != step || replay_step > steps_in_macro {
        return None;
    }
    let replayed = step_run(&replay["replayed"], Some(replay_step))?;
    let preparatory = steps(&replay["preparatory"])?;
    if preparatory.iter().any(|run| run.step >= replay_step)
        || preparatory
            .windows(2)
            .any(|pair| pair[0].step >= pair[1].step)
    {
        return None;
    }
    let units = replay["units"].as_u64()?;
    let sent = preparatory
        .iter()
        .chain(std::iter::once(&replayed))
        .filter(|step| step.dispatch().was_sent())
        .count() as u64;
    if units != sent || preparatory.len() != usize::try_from(replay_step - 1).ok()? {
        return None;
    }
    // A successful replay ran and sent the steps before the replayed one and
    // the replayed step itself; a stopped or refused step exits as an error
    // envelope, not as a row this decoder reads as evidence.
    if preparatory
        .iter()
        .chain(std::iter::once(&replayed))
        .any(|step| step.outcome != StepOutcome::Complete)
    {
        return None;
    }
    let state_changing = replay["state_changing"]
        .as_array()?
        .iter()
        .map(|step| u32::try_from(step.as_u64()?).ok())
        .collect::<Option<Vec<_>>>()?;
    let expected_changing = preparatory
        .iter()
        .chain(std::iter::once(&replayed))
        .filter(|step| step.state_changing && step.dispatch().was_sent())
        .map(|step| step.step)
        .collect::<Vec<_>>();
    if state_changing != expected_changing {
        return None;
    }
    let outer_id = opted_flow(&outer["id"])?;
    if outer_id != replayed.flow {
        return None;
    }
    if opted_u16(&outer["status"])? != replayed.status {
        return None;
    }
    let relogin = relogin(&outer["relogin"]);
    if outer["relogin"].is_null() == relogin.is_some() {
        return None;
    }
    let withheld = match &outer["withheld"] {
        Value::Null => None,
        value => Some(withheld(value)?),
    };
    Some(MacroReplayReceipt {
        parent: 0,
        destination: nonempty(outer["destination"].as_str()?)?.to_owned(),
        status: replayed.status,
        time_ms: opted_u64(&outer["time_ms"])?,
        notes: strings(&outer["notes"])?,
        relogin,
        withheld,
        replay: MacroReplay {
            job: opted_u64(&replay["job"])?.filter(|job| *job > 0),
            name: replay_name.to_owned(),
            step: replay_step,
            steps_in_macro,
            state_changing,
            units,
            units_left: opted_u64(&replay["units_left"])?,
            preparatory,
            replayed,
            replaced: strings(&replay["replaced"])?,
            variables: variables(&replay["variables"])?,
        },
    })
}
