//! Structured calls to an operator-bound Teapot project.
//!
//! Create a binding only from trusted operator state. The explicit directory
//! environment also selects Teapot's control socket namespace. Passive probes
//! use version and proxy status. Session checks are a separate, traffic-capable
//! call and require the caller's authorization.

pub mod accounting;
mod process;
mod schema;
#[cfg(all(test, target_os = "linux"))]
mod tests;
mod verifier_gate;

pub use verifier_gate::{
    EditSurface, EditSurfaceReading, EditSurfaceReport, EnforcementStatus, GateCall, GateOperation,
    GateRefusal, GateRefusalReason, InstrumentObservation, RuleStatus, ScriptState, SessionSurface,
};

use std::{
    collections::HashSet,
    fmt,
    process::{Command, Output, Stdio},
    sync::LazyLock,
    time::Duration,
};

use serde::Deserialize;
use serde_json::Value;

use crate::{
    ids::{SessionName, WireText},
    json_input,
    template::Method,
    wire::{self, AbsolutePath, Diagnostic, DiagnosticCode, DiagnosticV1, ErrorCode},
};

/// Limits of the pinned Teapot control protocol and jobs endpoint.
pub const PROTOCOL_VERSION: u64 = 1;
pub const MAX_CLIENT_FRAME_BYTES: usize = 1 << 20;
pub const MAX_SERVER_FRAME_BYTES: usize = 16 << 20;
pub const MAX_JOBS_LIMIT: u16 = 1000;

/// Limits for each local invocation, independent of Teapot's socket limits.
/// Teapot renders its result on one compact JSON line, including a newline.
pub const MAX_SUBPROCESS_STREAM_BYTES: usize = MAX_SERVER_FRAME_BYTES + 1;
pub const SUBPROCESS_DEADLINE: Duration = Duration::from_secs(120);

/// Teapot's directory settings from the operator. An omitted XDG path uses
/// Teapot's normal fallback under `home`, never the invoking process's value.
#[derive(Clone, Debug)]
pub struct Environment {
    pub home: AbsolutePath,
    pub config_home: Option<AbsolutePath>,
    pub data_home: Option<AbsolutePath>,
    pub state_home: Option<AbsolutePath>,
    pub cache_home: Option<AbsolutePath>,
    pub runtime_dir: Option<AbsolutePath>,
}

impl Environment {
    fn apply(&self, command: &mut Command) {
        command.env_clear().env("HOME", self.home.as_str());
        for (name, path) in [
            ("XDG_CONFIG_HOME", &self.config_home),
            ("XDG_DATA_HOME", &self.data_home),
            ("XDG_STATE_HOME", &self.state_home),
            ("XDG_CACHE_HOME", &self.cache_home),
            ("XDG_RUNTIME_DIR", &self.runtime_dir),
        ] {
            if let Some(path) = path {
                command.env(name, path.as_str());
            }
        }
        command.env("NO_COLOR", "1").env("TERM", "dumb");
    }
}

/// Whether the operator's executable is Teapot itself or a trusted wrapper.
/// A wrapper may forward native envelopes unchanged and report a wrapper-only
/// failure as one `scourge.diagnostic.v1` event on stderr.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutableKind {
    Native,
    Wrapper,
}

#[derive(Clone, Debug)]
pub struct BoundEngine {
    pub instance: WireText,
    pub project_id: WireText,
    pub enforced: bool,
    pub policy_locked: bool,
}

#[derive(Clone, Debug)]
pub struct Teapot {
    executable: AbsolutePath,
    executable_kind: ExecutableKind,
    project: AbsolutePath,
    environment: Environment,
    engine: BoundEngine,
}

impl Teapot {
    /// Expects absolute, already resolved operator paths. The caller is
    /// responsible for verifying the provenance of the binding.
    pub fn new(
        executable: AbsolutePath,
        executable_kind: ExecutableKind,
        project: AbsolutePath,
        environment: Environment,
        engine: BoundEngine,
    ) -> Self {
        Self {
            executable,
            executable_kind,
            project,
            environment,
            engine,
        }
    }

    /// Complete passive probe argv for orientation and operator troubleshooting.
    pub fn version_argv(&self) -> Vec<String> {
        self.argv(&["version"])
    }

    pub fn describe(&self) -> Result<Description, InvocationError> {
        let version = self.verify_engine()?;
        let status = self.invoke(&PROXY_STATUS, &["proxy", "status"])?;
        let proxy = status.result();
        if proxy["project"].as_str() != Some(self.project.as_str()) {
            return Err(status.fail(DiagnosticCode::WrongListener));
        }
        if proxy["running"] != true {
            let code = if proxy["engine"].is_object() {
                DiagnosticCode::InvalidNativeOutput
            } else {
                DiagnosticCode::TransportUnavailable
            };
            return Err(status.fail(code));
        }
        self.verify_identity(&status, &proxy["engine"])?;
        Ok(Description { version, status })
    }

    /// Teapot checks a named session and an anonymous control. This may send
    /// two requests and spend units. Use only after admission for this probe.
    pub fn check_session(
        &self,
        session: &SessionName,
        url: &WireText,
    ) -> Result<Observation<SessionState>, InvocationError> {
        let session = argument(session.as_str())?;
        let url = argument(url.as_str())?;
        let evidence = self.invoke_live(
            &SESSION_CHECK,
            &["sessions", "check", session, "--url", url],
        )?;
        let check = evidence.result();
        if check["name"].as_str() != Some(session)
            || check["saved"] != false
            || check["dry_run"] != false
        {
            return Err(evidence.fail(DiagnosticCode::InvalidNativeOutput));
        }
        let value = match check["state"].as_str() {
            Some("logged-in") => SessionState::LoggedIn,
            Some("logged-out") => SessionState::LoggedOut,
            Some("unknown") => SessionState::Unknown,
            _ => return Err(evidence.fail(DiagnosticCode::InvalidNativeOutput)),
        };
        Ok(Observation { value, evidence })
    }

    pub fn dry_run_macro(
        &self,
        name: &WireText,
        session: &SessionName,
    ) -> Result<Observation<DryRun>, InvocationError> {
        let words = macro_dry_run_words(name, session)?;
        let evidence = self.invoke_live(&MACRO_DRY_RUN, &words)?;
        let value = macro_dry_run_result(&evidence, name, session)?.0;
        Ok(Observation { value, evidence })
    }

    pub fn dry_run_request(
        &self,
        method: Method,
        url: &WireText,
        session: &SessionName,
    ) -> Result<Observation<DryRun>, InvocationError> {
        let url = argument(url.as_str())?;
        let session = argument(session.as_str())?;
        let evidence = self.invoke_live(
            &SEND_DRY_RUN,
            &[
                "requests",
                "send",
                method.as_str(),
                url,
                "--session",
                session,
                "--dry-run",
            ],
        )?;
        let sent = evidence.result();
        if sent["dry_run"] != true
            || !sent["flow"].is_null()
            || sent["hops"].as_array().is_none_or(|hops| !hops.is_empty())
            || sent["session"]["name"].as_str() != Some(session)
        {
            return Err(evidence.fail(DiagnosticCode::InvalidNativeOutput));
        }
        let value = DryRun {
            request_count: 1,
            within_ceiling: None,
            scope_would_refuse: Some(!sent["would_refuse"].is_null()),
        };
        Ok(Observation { value, evidence })
    }

    /// Teapot's request ceiling view. An unbound pass or unreadable ledger
    /// leaves the observation absent.
    pub fn units_left(&self) -> Result<Observation<Option<u64>>, InvocationError> {
        let evidence = self.invoke_live(&PASS_SHOW, &["pass", "show"])?;
        let value = request_ceiling(&evidence)?.and_then(|ceiling| ceiling["left"].as_u64());
        Ok(Observation { value, evidence })
    }

    /// One page of job records, retaining native timestamps for the caller's
    /// observation window. `before` is an exclusive job ID cursor.
    pub fn list_jobs(
        &self,
        limit: u16,
        before: Option<u64>,
    ) -> Result<Observation<Vec<Job>>, InvocationError> {
        if !(1..=MAX_JOBS_LIMIT).contains(&limit) {
            return Err(InvocationError::InvalidArgument);
        }
        let limit_arg = limit.to_string();
        let cursor = before.map(|id| id.to_string());
        let mut words = vec!["jobs", "list", "--limit", &limit_arg];
        if let Some(cursor) = &cursor {
            words.extend(["--before", cursor.as_str()]);
        }
        let evidence = self.invoke_live(&JOBS_LIST, &words)?;
        let value = job_page(&evidence, limit, before)?;
        Ok(Observation { value, evidence })
    }

    fn verify_engine(&self) -> Result<NativeReply, InvocationError> {
        let version = self.invoke(&VERSION, &["version"])?;
        self.check_engine(&version)?;
        Ok(version)
    }

    fn check_engine(&self, version: &NativeReply) -> Result<(), InvocationError> {
        let info = version.result();
        if info["answered_by"] == "cli" && info["engine"].is_null() {
            return Err(version.fail(DiagnosticCode::TransportUnavailable));
        }
        if info["answered_by"] != "engine" {
            return Err(version.fail(DiagnosticCode::InvalidNativeOutput));
        }
        self.verify_identity(version, &info["engine"])?;
        if info["protocol"].as_u64() != Some(PROTOCOL_VERSION) {
            return Err(version.fail(DiagnosticCode::NativeFailure));
        }
        Ok(())
    }

    fn verify_identity(&self, reply: &NativeReply, engine: &Value) -> Result<(), InvocationError> {
        if !engine.is_object() {
            return Err(reply.fail(DiagnosticCode::InvalidNativeOutput));
        }
        if engine["project"].as_str() != Some(self.project.as_str())
            || engine["instance"].as_str() != Some(self.engine.instance.as_str())
            || engine["project_id"].as_str() != Some(self.engine.project_id.as_str())
        {
            return Err(reply.fail(DiagnosticCode::WrongListener));
        }
        if engine["enforced"].as_bool() != Some(self.engine.enforced)
            || engine["policy_locked"].as_bool() != Some(self.engine.policy_locked)
        {
            return Err(reply.fail(DiagnosticCode::NativeFailure));
        }
        Ok(())
    }

    fn invoke_live(
        &self,
        spec: &'static Spec,
        words: &[&str],
    ) -> Result<NativeReply, InvocationError> {
        // Native argv has no expected-instance flag. Check both sides of the
        // call to reject an observed restart, without claiming atomic pinning.
        self.verify_engine()?;
        let reply = self.invoke(spec, words)?;
        self.verify_engine()?;
        Ok(reply)
    }

    fn argv(&self, words: &[&str]) -> Vec<String> {
        [
            self.executable.as_str(),
            "--project",
            self.project.as_str(),
            "--json",
        ]
        .into_iter()
        .chain(words.iter().copied())
        .map(str::to_owned)
        .collect()
    }

    fn invoke(&self, spec: &'static Spec, words: &[&str]) -> Result<NativeReply, InvocationError> {
        self.invoke_with_limits(spec, words, process::LIMITS)
    }

    fn invoke_with_limits(
        &self,
        spec: &'static Spec,
        words: &[&str],
        limits: process::Limits,
    ) -> Result<NativeReply, InvocationError> {
        let argv = self.argv(words);
        let mut command = Command::new(&argv[0]);
        command
            .args(&argv[1..])
            .current_dir("/")
            .stdin(Stdio::null());
        self.environment.apply(&mut command);
        let output = process::run(&mut command, limits)
            .map_err(|error| process_failure(spec, self.executable_kind, error))?;
        decode_output(spec, self.executable_kind, output)
    }
}

fn argument(value: &str) -> Result<&str, InvocationError> {
    if value.starts_with('-') {
        return Err(InvocationError::InvalidArgument);
    }
    Ok(value)
}

fn macro_dry_run_words<'a>(
    name: &'a WireText,
    session: &'a SessionName,
) -> Result<[&'a str; 6], InvocationError> {
    Ok([
        "macros",
        "run",
        argument(name.as_str())?,
        "--session",
        argument(session.as_str())?,
        "--dry-run",
    ])
}

fn macro_dry_run_result(
    evidence: &NativeReply,
    name: &WireText,
    session: &SessionName,
) -> Result<(DryRun, Option<u64>), InvocationError> {
    let run = evidence.result();
    let steps_are_passive = run["steps"].as_array().is_some_and(|steps| {
        steps.iter().all(|step| {
            matches!(step["outcome"].as_str(), Some("planned" | "not-run"))
                && step["flow"].is_null()
                && step["status"].is_null()
        })
    });
    if run["dry_run"] != true
        || run["outcome"] != "planned"
        || !run["job"].is_null()
        || run["name"].as_str() != Some(name.as_str())
        || run["session"]["name"].as_str() != Some(session.as_str())
        || !steps_are_passive
    {
        return Err(evidence.fail(DiagnosticCode::InvalidNativeOutput));
    }
    let Some(request_count) = run["units"].as_u64() else {
        return Err(evidence.fail(DiagnosticCode::InvalidNativeOutput));
    };
    let units_left = run["units_left"].as_u64();
    let value = DryRun {
        request_count,
        within_ceiling: units_left.map(|left| request_count <= left),
        scope_would_refuse: None,
    };
    Ok((value, units_left))
}

fn request_ceiling(evidence: &NativeReply) -> Result<Option<&Value>, InvocationError> {
    let mut ceilings = evidence.result()["ceilings"]
        .as_array()
        .ok_or_else(|| evidence.fail(DiagnosticCode::InvalidNativeOutput))?
        .iter()
        .filter(|ceiling| ceiling["counter"] == "requests");
    let requests = ceilings.next();
    if ceilings.next().is_some() {
        return Err(evidence.fail(DiagnosticCode::InvalidNativeOutput));
    }
    Ok(requests)
}

fn job_page(
    evidence: &NativeReply,
    limit: u16,
    before: Option<u64>,
) -> Result<Vec<Job>, InvocationError> {
    let jobs: Vec<Job> = serde_json::from_value(evidence.result().clone())
        .map_err(|_| evidence.fail(DiagnosticCode::InvalidNativeOutput))?;
    let mut ids = HashSet::new();
    if jobs.len() > usize::from(limit)
        || jobs
            .iter()
            .any(|job| before.is_some_and(|cursor| job.id >= cursor) || !ids.insert(job.id))
    {
        return Err(evidence.fail(DiagnosticCode::InvalidNativeOutput));
    }
    Ok(jobs)
}

/// Successful native response with the original JSON retained for evidence.
/// Treat the payload as untrusted data and redact it at presentation boundaries.
pub struct NativeReply {
    envelope: Value,
    spec: &'static Spec,
    exits: Exits,
    stdout: Vec<u8>,
    stderr_empty: bool,
}

impl NativeReply {
    pub fn result(&self) -> &Value {
        &self.envelope[self.spec.result_key]
    }

    pub fn envelope(&self) -> &Value {
        &self.envelope
    }

    pub fn exits(&self) -> Exits {
        self.exits
    }

    fn fail(&self, code: DiagnosticCode) -> InvocationError {
        failure(self.spec, code, self.exits, None)
    }
}

impl fmt::Debug for NativeReply {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeReply")
            .field("stage", &self.spec.stage)
            .field("exits", &self.exits)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub struct Description {
    pub version: NativeReply,
    pub status: NativeReply,
}

#[derive(Debug)]
pub struct Observation<T> {
    pub value: T,
    pub evidence: NativeReply,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionState {
    LoggedIn,
    LoggedOut,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DryRun {
    pub request_count: u64,
    pub within_ceiling: Option<bool>,
    pub scope_would_refuse: Option<bool>,
}

/// Convenience fields from a job. The full record is in the page evidence.
#[derive(Deserialize)]
pub struct Job {
    pub id: u64,
    pub started: String,
    pub ended: Option<String>,
    pub live: bool,
}

impl fmt::Debug for Job {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Job")
            .field("id", &self.id)
            .field("live", &self.live)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Exits {
    pub native: Option<i64>,
    pub wrapper: Option<i64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputStream {
    Stdout,
    Stderr,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportFailure {
    /// The child or a helper holding its pipes outlived the local deadline.
    Timeout,
    /// Capture was discarded because this pipe exceeded its byte limit.
    OutputLimit(OutputStream),
    /// Failed to read or close the subprocess transport cleanly.
    Io,
}

#[derive(Debug, thiserror::Error)]
pub enum InvocationError {
    #[error("Invalid argument for the bound Teapot command.")]
    InvalidArgument,
    #[error("The bound Teapot dependency did not complete the operation.")]
    DependencyUnavailable {
        diagnostic: Diagnostic,
        /// A stable native reason, when the original error envelope supplied one.
        native_reason: Option<wire::KebabCase>,
        /// Local transport failure. For a session check, this does not show
        /// whether the engine dispatched either probe.
        transport_failure: Option<TransportFailure>,
    },
}

impl InvocationError {
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::InvalidArgument => ErrorCode::UsageError,
            Self::DependencyUnavailable { .. } => ErrorCode::DependencyUnavailable,
        }
    }

    pub fn diagnostic(&self) -> Option<&Diagnostic> {
        match self {
            Self::InvalidArgument => None,
            Self::DependencyUnavailable { diagnostic, .. } => Some(diagnostic),
        }
    }
}

struct Spec {
    stage: &'static str,
    result_key: &'static str,
    schema: LazyLock<Value>,
}

macro_rules! spec {
    ($name:ident, $stage:literal, $key:literal, $fixture:literal) => {
        static $name: Spec = Spec {
            stage: $stage,
            result_key: $key,
            schema: LazyLock::new(|| {
                let bytes = include_bytes!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../fixtures/contracts/schema-",
                    $fixture,
                    ".json"
                ));
                json_input::parse(bytes, None).expect("valid embedded Teapot schema")
            }),
        };
    };
}

spec!(VERSION, "describe", "version", "version");
spec!(PROXY_STATUS, "describe", "proxy", "proxy-status");
spec!(SESSION_CHECK, "check_session", "check", "sessions-check");
spec!(MACRO_DRY_RUN, "dry_run", "run", "macros-run");
spec!(SEND_DRY_RUN, "dry_run", "sent", "requests-send");
spec!(PASS_SHOW, "units_left", "pass", "pass-show");
spec!(JOBS_LIST, "list_jobs", "jobs", "jobs-list");
spec!(RULES_LIST, "edit_surface", "rules", "rules-list");
spec!(
    INTERCEPT_STATUS,
    "edit_surface",
    "intercept",
    "intercept-status"
);
spec!(
    INTERCEPT_RULES,
    "edit_surface",
    "rules",
    "intercept-rules-list"
);
spec!(SCRIPTS_LIST, "edit_surface", "scripts", "scripts-list");
spec!(SESSION_SHOW, "edit_surface", "session", "sessions-show");
spec!(CONFIG_LIST, "edit_surface", "settings", "config-list");

fn process_failure(
    spec: &'static Spec,
    kind: ExecutableKind,
    error: process::RunError,
) -> InvocationError {
    use std::io::ErrorKind;
    match error {
        process::RunError::Spawn(reason) => {
            let code = match reason {
                ErrorKind::NotFound | ErrorKind::PermissionDenied | ErrorKind::Unsupported => {
                    DiagnosticCode::ToolUnavailable
                }
                _ => DiagnosticCode::NativeFailure,
            };
            failure(spec, code, process_exits(kind, None), None)
        }
        #[cfg(target_os = "linux")]
        process::RunError::Capture {
            kind: cause,
            status,
        } => {
            let status = status.and_then(|status| status.code()).map(i64::from);
            let exits = process_exits(kind, status);
            let (code, message) = match cause {
                TransportFailure::Timeout => (
                    DiagnosticCode::TransportUnavailable,
                    "The bound Teapot command exceeded its local deadline.",
                ),
                TransportFailure::OutputLimit(OutputStream::Stdout) => (
                    DiagnosticCode::InvalidNativeOutput,
                    "Teapot subprocess stdout exceeded its byte limit.",
                ),
                TransportFailure::OutputLimit(OutputStream::Stderr) => (
                    DiagnosticCode::InvalidNativeOutput,
                    "Teapot subprocess stderr exceeded its byte limit.",
                ),
                TransportFailure::Io => (
                    DiagnosticCode::TransportUnavailable,
                    "Teapot subprocess capture or cleanup failed.",
                ),
            };
            dependency_failure(spec, code, exits, message, None, Some(cause))
        }
    }
}

fn process_exits(kind: ExecutableKind, status: Option<i64>) -> Exits {
    match kind {
        ExecutableKind::Native => Exits {
            native: status,
            wrapper: None,
        },
        ExecutableKind::Wrapper => Exits {
            native: None,
            wrapper: status,
        },
    }
}

fn decode_output(
    spec: &'static Spec,
    kind: ExecutableKind,
    output: Output,
) -> Result<NativeReply, InvocationError> {
    let status = output.status.code().map(i64::from);
    let mut exits = process_exits(kind, status);
    let stdout = json_input::parse(&output.stdout, None).ok();
    let stderr = json_input::parse(&output.stderr, None).ok();
    let contract = &spec.schema["output"]["schema"];

    if kind == ExecutableKind::Wrapper
        && let Ok(event) = wire::from_slice::<DiagnosticV1>(&output.stderr)
    {
        exits.native = event.diagnostic.native_exit;
        return Err(failure(spec, event.diagnostic.code, exits, None));
    }

    // Teapot writes failure envelopes on stderr. Accept a forwarded envelope
    // on either stream, including when an outer wrapper masks the exit.
    if let Some(error) = [stderr.as_ref(), stdout.as_ref()]
        .into_iter()
        .flatten()
        .find(|value| schema::accepts(&contract["error"], value))
    {
        let error = &error["error"];
        if kind == ExecutableKind::Wrapper {
            exits.native = error["code"].as_i64();
        }
        let reason = error["reason"].as_str().unwrap_or_default();
        let code = match reason {
            "wrong-project" | "wrong-engine" => DiagnosticCode::WrongListener,
            "engine-not-running" | "engine-unreachable" | "engine-busy" | "engine-stopping"
            | "connection-lost" | "idle-timeout" => DiagnosticCode::TransportUnavailable,
            "malformed-frame" => DiagnosticCode::InvalidNativeOutput,
            _ => DiagnosticCode::NativeFailure,
        };
        return Err(failure(spec, code, exits, reason.parse().ok()));
    }

    let envelope = stdout.filter(|value| schema::accepts(&contract["result"], value));
    if kind == ExecutableKind::Wrapper && envelope.is_some() {
        exits.native = Some(0);
    }
    if !output.status.success() {
        return Err(failure(spec, DiagnosticCode::NativeFailure, exits, None));
    }
    let envelope =
        envelope.ok_or_else(|| failure(spec, DiagnosticCode::InvalidNativeOutput, exits, None))?;
    Ok(NativeReply {
        envelope,
        spec,
        exits,
        stdout: output.stdout,
        stderr_empty: output.stderr.iter().all(u8::is_ascii_whitespace),
    })
}

fn failure(
    spec: &'static Spec,
    code: DiagnosticCode,
    exits: Exits,
    native_reason: Option<wire::KebabCase>,
) -> InvocationError {
    let message = match code {
        DiagnosticCode::WrongListener => "The peer did not match the configured Teapot engine.",
        DiagnosticCode::ToolUnavailable => "The bound Teapot executable was unavailable.",
        DiagnosticCode::InvalidNativeOutput => "Teapot did not return the expected JSON result.",
        DiagnosticCode::NativeFailure => "The bound Teapot command failed its native checks.",
        DiagnosticCode::TransportUnavailable => "The bound Teapot engine could not be reached.",
    };
    dependency_failure(spec, code, exits, message, native_reason, None)
}

fn dependency_failure(
    spec: &'static Spec,
    code: DiagnosticCode,
    exits: Exits,
    message: &'static str,
    native_reason: Option<wire::KebabCase>,
    transport_failure: Option<TransportFailure>,
) -> InvocationError {
    InvocationError::DependencyUnavailable {
        diagnostic: Diagnostic {
            code,
            message: message.parse().expect("static diagnostic"),
            stage: spec.stage.parse().expect("static stage"),
            native_exit: exits.native,
            wrapper_exit: exits.wrapper,
        },
        native_reason,
        transport_failure,
    }
}
