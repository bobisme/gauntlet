use std::{collections::HashSet, fmt, net::SocketAddr, path::Path};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use super::{
    CONFIG_LIST, Exits, INTERCEPT_RULES, INTERCEPT_STATUS, InvocationError, NativeOutput,
    NativeReply, PASS_SHOW, PROTOCOL_VERSION, PROXY_STATUS, RULES_LIST, SCRIPTS_LIST, SESSION_SHOW,
    Spec, Teapot, VERSION, argument, process,
};
use crate::{
    canonical::Sha256Digest,
    engagement::RequiredEnforcement,
    ids::{SessionName, WireText},
    wire::{AbsolutePath, DiagnosticCode, ErrorCode, Instrument},
};

mod edits;
pub use edits::{EditSurfaceReading, EditSurfaceReport, RuleStatus, ScriptState};
#[cfg(all(test, target_os = "linux"))]
mod tests;

/// The live Teapot verdict about kernel egress enforcement.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementStatus {
    EgressEnforced,
    Unenforced,
}

/// Metadata observed from the native engine for an operator-pinned pass.
#[derive(Debug, PartialEq, Eq)]
pub struct PreviewPass {
    pub id: WireText,
    pub enforcement: EnforcementStatus,
    pub requests_spent: Option<u64>,
    pub requests_left: Option<u64>,
}

impl EnforcementStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EgressEnforced => "egress_enforced",
            Self::Unenforced => "unenforced",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GateOperation {
    Version,
    ProxyStatus,
    PassShow,
    RulesList,
    InterceptStatus,
    InterceptRules,
    ScriptsList,
    SessionShow,
    ConfigList,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct GateCall {
    pub operation: GateOperation,
    pub exits: Exits,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GateRefusalReason {
    EngineUnestablished,
    EnforcementUnestablished,
    EnforcementRequired,
    PassNotEnforceable,
    EditSurfaceUnestablished,
    ActiveRule,
    ActiveIntercept,
    ActiveScriptHook,
    SessionBehavior,
    EditableConfiguration,
}

#[derive(Debug, thiserror::Error)]
#[error("The bound Teapot failed verifier preflight ({reason:?}).")]
pub struct GateRefusal {
    pub reason: GateRefusalReason,
    pub calls: Vec<GateCall>,
    /// Established observations before the refusal, including active edits.
    /// Unavailable reads leave their operation absent from the surface.
    pub edit_surface: EditSurface,
    pub enforcement: Option<EnforcementStatus>,
    pub policy_locked: Option<bool>,
    #[source]
    pub invocation: Option<Box<InvocationError>>,
}

impl GateRefusal {
    pub fn code(&self) -> ErrorCode {
        match self.reason {
            GateRefusalReason::EngineUnestablished
            | GateRefusalReason::EnforcementUnestablished
            | GateRefusalReason::EnforcementRequired
            | GateRefusalReason::PassNotEnforceable => ErrorCode::EnforcementUnavailable,
            _ => ErrorCode::InstrumentEditsActive,
        }
    }
}

/// Passive session metadata. The native command omits credential values.
#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct SessionSurface {
    pub session: SessionName,
    pub cookies: usize,
    pub headers: usize,
    pub secrets: usize,
    pub csrf_tokens: u64,
    pub has_login: bool,
    pub has_logout_rule: bool,
    pub paused: bool,
}

#[derive(Debug, Default, PartialEq, Eq, Serialize)]
pub struct EditSurface {
    pub readings: Vec<EditSurfaceReading>,
}

/// Redacted observation for the verifier's record. Each snapshot is fresh.
/// These passive reads cannot prevent edits between invocations or after
/// the check. Run again at the end to observe the other edge of the run.
#[derive(Debug, Serialize)]
pub struct InstrumentObservation {
    pub identity: Instrument,
    pub enforcement: EnforcementStatus,
    pub policy_locked: bool,
    pub edit_surface: EditSurface,
    pub calls: Vec<GateCall>,
    #[serde(skip)]
    pub(crate) pass: Option<ObservedPass>,
}

#[cfg(test)]
impl InstrumentObservation {
    pub(crate) fn verification_fixture(
        pass_id: WireText,
        digest: Sha256Digest,
        file: crate::wire::AbsolutePath,
    ) -> Self {
        Self {
            identity: Instrument {
                name: "teapot".parse().expect("fixed instrument name"),
                version: "fixture".parse().expect("fixed instrument version"),
                commit: None,
                binary_digest: None,
                engine_instance: "fixture".parse().expect("fixed engine instance"),
                project_id: "fixture".parse().expect("fixed project id"),
                protocol: PROTOCOL_VERSION,
            },
            enforcement: EnforcementStatus::Unenforced,
            policy_locked: false,
            edit_surface: EditSurface::default(),
            calls: Vec::new(),
            pass: Some(ObservedPass {
                id: pass_id,
                digest,
                file,
            }),
        }
    }
}

pub(crate) struct ObservedPass {
    pub id: WireText,
    pub digest: Sha256Digest,
    pub file: AbsolutePath,
}

impl fmt::Debug for ObservedPass {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ObservedPass")
            .finish_non_exhaustive()
    }
}

impl Teapot {
    /// Read the engine's actual enforcement state for the operator-pinned pass.
    /// This is a preview sample and does not admit a verifier operation.
    pub(crate) fn preview_pass(
        &self,
        pass_file: &AbsolutePath,
        pass_digest: &Sha256Digest,
    ) -> Result<PreviewPass, ErrorCode> {
        let mut reads = GateReads {
            teapot: self,
            limits: process::LIMITS,
            schema_lane: None,
            executable_digest: None,
            calls: Vec::new(),
            edit_surface: EditSurface::default(),
            enforcement: None,
            policy_locked: None,
        };
        let failed = |_| ErrorCode::EnforcementUnavailable;
        let version = reads.version(None).map_err(failed)?;
        let engine = &version.result()["engine"];
        let status = reads.proxy_status(engine).map_err(failed)?;
        let pass = reads
            .bound_read(GateOperation::PassShow, None, engine)
            .map_err(failed)?;
        let state = pass.result();
        if state["state"] != "bound"
            || state["pass_file"].as_str() != Some(pass_file.as_str())
            || state["digest"]
                .as_str()
                .and_then(|digest| digest.strip_prefix("sha256:"))
                != Some(pass_digest.as_str())
            || state.get("newer_pass") != Some(&Value::Null)
        {
            return Err(ErrorCode::AccountingUnestablished);
        }
        let enforcement = classify_enforcement(&pass, engine, status.result())
            .map_err(failed)?
            .status;
        let id = state["id"]
            .as_str()
            .and_then(|id| id.parse().ok())
            .ok_or(ErrorCode::AccountingUnestablished)?;
        let counters = super::accounting::read_request_counters(&pass)
            .map_err(|_| ErrorCode::AccountingUnestablished)?;
        Ok(PreviewPass {
            id,
            enforcement,
            requests_spent: counters.as_ref().and_then(|counters| counters.spent),
            requests_left: counters.and_then(|counters| counters.left),
        })
    }

    /// Run before any verifier operation that can reach the target, including
    /// a session check. Supply every session the verifier will use. This can
    /// also take the ending observation for the run record.
    pub fn verifier_preflight(
        &self,
        sessions: &[SessionName],
        requirement: RequiredEnforcement,
    ) -> Result<InstrumentObservation, GateRefusal> {
        self.verifier_preflight_with_limits(sessions, requirement, process::LIMITS)
    }

    /// Admit a verifier effect only after a fresh preflight. The caller can
    /// record the start snapshot in the callback before dispatching and call
    /// `verifier_preflight` again at the end to record the final observation.
    /// The admission and the external dispatch are separate operations.
    pub fn with_verifier_admission<T>(
        &self,
        sessions: &[SessionName],
        requirement: RequiredEnforcement,
        effect: impl FnOnce(InstrumentObservation) -> T,
    ) -> Result<T, GateRefusal> {
        self.verifier_preflight(sessions, requirement).map(effect)
    }

    fn verifier_preflight_with_limits(
        &self,
        sessions: &[SessionName],
        requirement: RequiredEnforcement,
        limits: process::Limits,
    ) -> Result<InstrumentObservation, GateRefusal> {
        let mut reads = GateReads {
            teapot: self,
            limits,
            schema_lane: None,
            executable_digest: None,
            calls: Vec::new(),
            edit_surface: EditSurface::default(),
            enforcement: None,
            policy_locked: None,
        };
        let result = reads.observe(sessions, requirement);
        match result {
            Ok((identity, enforcement)) => Ok(InstrumentObservation {
                identity,
                enforcement: enforcement.status,
                policy_locked: self.engine.policy_locked,
                edit_surface: reads.edit_surface,
                calls: reads.calls,
                pass: enforcement.pass,
            }),
            Err((reason, invocation)) => Err(GateRefusal {
                reason,
                invocation,
                calls: reads.calls,
                edit_surface: reads.edit_surface,
                enforcement: reads.enforcement,
                policy_locked: reads.policy_locked,
            }),
        }
    }
}

type ReadFailure = (GateRefusalReason, Option<Box<InvocationError>>);

struct GateReads<'a> {
    teapot: &'a Teapot,
    limits: process::Limits,
    /// Selected from the executable bytes before parsing the first reply and
    /// never changed during this observation.
    schema_lane: Option<GateSchemaLane>,
    executable_digest: Option<Sha256Digest>,
    calls: Vec<GateCall>,
    edit_surface: EditSurface,
    enforcement: Option<EnforcementStatus>,
    policy_locked: Option<bool>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GateSchemaLane {
    Historical,
    RequestReference,
}

impl GateSchemaLane {
    fn for_digest(digest: &Sha256Digest) -> Self {
        if digest.as_str() == super::REQUEST_REFERENCE_BINARY_SHA256 {
            Self::RequestReference
        } else {
            Self::Historical
        }
    }

    fn accepts(self, operation: GateOperation, envelope: &Value) -> bool {
        match self {
            Self::Historical => operation.output().accepts_strict(envelope),
            Self::RequestReference => operation
                .output()
                .accepts_request_reference_strict(envelope),
        }
    }

    fn accepts_commit(self, commit: &Value) -> bool {
        match self {
            Self::Historical => {
                commit.is_null() || commit == "6238d5a78a6514466d54ad16dd5737f43c1d4961"
            }
            Self::RequestReference => commit == super::REQUEST_REFERENCE_SOURCE,
        }
    }

    fn bookend_matches(self, initial: Option<&Sha256Digest>, observed: &Sha256Digest) -> bool {
        match self {
            Self::Historical => initial.is_none(),
            Self::RequestReference => initial == Some(observed),
        }
    }
}

impl GateOperation {
    /// The frozen output shape this read must satisfy.
    fn output(self) -> NativeOutput {
        match self {
            Self::Version => NativeOutput::Version,
            Self::ProxyStatus => NativeOutput::ProxyStatus,
            Self::PassShow => NativeOutput::PassShow,
            Self::RulesList => NativeOutput::RulesList,
            Self::InterceptStatus => NativeOutput::InterceptStatus,
            Self::InterceptRules => NativeOutput::InterceptRules,
            Self::ScriptsList => NativeOutput::ScriptsList,
            Self::SessionShow => NativeOutput::SessionShow,
            Self::ConfigList => NativeOutput::ConfigList,
        }
    }

    fn spec(self, lane: GateSchemaLane) -> &'static Spec {
        match lane {
            GateSchemaLane::Historical => match self {
                Self::Version => &VERSION,
                Self::ProxyStatus => &PROXY_STATUS,
                Self::PassShow => &PASS_SHOW,
                Self::RulesList => &RULES_LIST,
                Self::InterceptStatus => &INTERCEPT_STATUS,
                Self::InterceptRules => &INTERCEPT_RULES,
                Self::ScriptsList => &SCRIPTS_LIST,
                Self::SessionShow => &SESSION_SHOW,
                Self::ConfigList => &CONFIG_LIST,
            },
            GateSchemaLane::RequestReference => match self {
                Self::Version => &super::REQUEST_REFERENCE_VERSION,
                Self::ProxyStatus => &super::REQUEST_REFERENCE_PROXY_STATUS,
                Self::PassShow => &super::REQUEST_REFERENCE_PASS_SHOW,
                Self::RulesList => &super::REQUEST_REFERENCE_RULES_LIST,
                Self::InterceptStatus => &super::REQUEST_REFERENCE_INTERCEPT_STATUS,
                Self::InterceptRules => &super::REQUEST_REFERENCE_INTERCEPT_RULES,
                Self::ScriptsList => &super::REQUEST_REFERENCE_SCRIPTS_LIST,
                Self::SessionShow => &super::REQUEST_REFERENCE_SESSION_SHOW,
                Self::ConfigList => &super::REQUEST_REFERENCE_CONFIG_LIST,
            },
        }
    }

    fn command(
        self,
        lane: GateSchemaLane,
        session: Option<&SessionName>,
    ) -> (&'static Spec, Vec<&str>) {
        let spec = self.spec(lane);
        match self {
            Self::Version => (spec, vec!["version"]),
            Self::ProxyStatus => (spec, vec!["proxy", "status"]),
            Self::PassShow => (spec, vec!["pass", "show"]),
            Self::RulesList => (spec, vec!["rules", "list"]),
            Self::InterceptStatus => (spec, vec!["intercept", "status"]),
            Self::InterceptRules => (spec, vec!["intercept", "rules", "list"]),
            Self::ScriptsList => (spec, vec!["scripts", "list"]),
            Self::SessionShow => (
                spec,
                vec![
                    "sessions",
                    "show",
                    session.expect("session for show").as_str(),
                ],
            ),
            Self::ConfigList => (spec, vec!["config", "list"]),
        }
    }

    fn unavailable(self) -> GateRefusalReason {
        match self {
            Self::Version | Self::ProxyStatus => GateRefusalReason::EngineUnestablished,
            Self::PassShow => GateRefusalReason::EnforcementUnestablished,
            _ => GateRefusalReason::EditSurfaceUnestablished,
        }
    }
}

impl GateReads<'_> {
    fn select_schema_lane(&mut self) -> Result<(), ReadFailure> {
        if self.schema_lane.is_some() {
            return Ok(());
        }
        let digest = self
            .teapot
            .pin_request_reference_executable()
            .map_err(|error| {
                (
                    GateRefusalReason::EngineUnestablished,
                    Some(Box::new(error)),
                )
            })?;
        let lane = GateSchemaLane::for_digest(&digest);
        self.schema_lane = Some(lane);
        if lane == GateSchemaLane::RequestReference {
            self.executable_digest = Some(digest);
        }
        Ok(())
    }

    fn read(
        &mut self,
        operation: GateOperation,
        session: Option<&SessionName>,
    ) -> Result<NativeReply, ReadFailure> {
        let lane = self
            .schema_lane
            .expect("version selects an immutable schema lane before any read");
        let (spec, words) = operation.command(lane, session);
        let reply = self
            .teapot
            .invoke_with_limits(spec, &words, self.limits)
            .map_err(|error| {
                let mut reason = operation.unavailable();
                if let InvocationError::DependencyUnavailable {
                    diagnostic,
                    native_reason,
                    ..
                } = &error
                {
                    self.calls.push(GateCall {
                        operation,
                        exits: Exits {
                            native: diagnostic.native_exit,
                            wrapper: diagnostic.wrapper_exit,
                        },
                    });
                    if matches!(
                        operation,
                        GateOperation::Version
                            | GateOperation::ProxyStatus
                            | GateOperation::PassShow
                    ) && native_reason
                        .as_ref()
                        .is_some_and(|reason| reason.as_str() == "pass-not-enforceable")
                    {
                        reason = GateRefusalReason::PassNotEnforceable;
                    }
                }
                (reason, Some(Box::new(error)))
            })?;
        self.calls.push(GateCall {
            operation,
            exits: reply.exits(),
        });
        let shape_accepted = self
            .schema_lane
            .expect("version selects an immutable schema lane before any read")
            .accepts(operation, reply.envelope());
        if !reply.stderr_empty || !shape_accepted {
            return Err(invalid(operation, &reply));
        }
        Ok(reply)
    }

    fn version(&mut self, expected: Option<&Value>) -> Result<NativeReply, ReadFailure> {
        let operation = GateOperation::Version;
        self.select_schema_lane()?;
        let reply = self.read(operation, None)?;
        let version = reply.result();
        let engine = &version["engine"];
        let reason = operation.unavailable();
        if version["answered_by"] == "cli" && engine.is_null() {
            return Err((
                reason,
                Some(Box::new(reply.fail(DiagnosticCode::TransportUnavailable))),
            ));
        }
        if version["answered_by"] != "engine"
            || version["protocol"] != PROTOCOL_VERSION
            || version["version"] != "0.1.0"
            || version["version"] != engine["build"]
            || !version.get("commit").is_some_and(|commit| {
                self.schema_lane
                    .expect("selected before the version read")
                    .accepts_commit(commit)
            })
            || (self.schema_lane == Some(GateSchemaLane::RequestReference)
                && !valid_request_reference_version(version))
            || !valid_engine(engine)
        {
            return Err(invalid(operation, &reply));
        }
        self.teapot
            .verify_identity(&reply, engine)
            .map_err(|error| (reason, Some(Box::new(error))))?;
        if expected.is_some_and(|expected| engine != expected) {
            return Err((
                reason,
                Some(Box::new(reply.fail(DiagnosticCode::WrongListener))),
            ));
        }
        Ok(reply)
    }

    fn bound_read(
        &mut self,
        operation: GateOperation,
        session: Option<&SessionName>,
        engine: &Value,
    ) -> Result<NativeReply, ReadFailure> {
        // The previous successful read was already followed by a version
        // check. Repeat it after this one to expose observed engine changes.
        let reply = self.read(operation, session)?;
        self.version(Some(engine))?;
        if let Some(reading) = edits::surface_reading(operation, &reply, session) {
            self.edit_surface.readings.push(reading);
        }
        Ok(reply)
    }

    fn proxy_status(&mut self, engine: &Value) -> Result<NativeReply, ReadFailure> {
        let operation = GateOperation::ProxyStatus;
        let reply = self.bound_read(operation, None, engine)?;
        let proxy = reply.result();
        if proxy["project"].as_str() != Some(self.teapot.project.as_str())
            || proxy["engine"] != *engine
        {
            return Err((
                operation.unavailable(),
                Some(Box::new(reply.fail(DiagnosticCode::WrongListener))),
            ));
        }
        let lock = &proxy["health"]["policy_lock"];
        if proxy["running"] != true
            || lock["locked"] != engine["policy_locked"]
            || lock.get("pass_path") != engine.get("pass")
            || lock["allow_eval"].as_bool().is_none()
            || !proxy["health"]["scripts_following"].is_array()
        {
            return Err(invalid(operation, &reply));
        }
        Ok(reply)
    }

    fn observe(
        &mut self,
        sessions: &[SessionName],
        requirement: RequiredEnforcement,
    ) -> Result<(Instrument, Enforcement), ReadFailure> {
        if sessions
            .iter()
            .any(|session| argument(session.as_str()).is_err())
        {
            return Err((
                GateRefusalReason::EditSurfaceUnestablished,
                Some(Box::new(InvocationError::InvalidArgument)),
            ));
        }
        let version = self.version(None)?;
        let engine = &version.result()["engine"];
        let commit: Option<crate::wire::GitCommit> =
            Deserialize::deserialize(&version.result()["commit"])
                .map_err(|_| invalid(GateOperation::Version, &version))?;
        let binary_digest = self.executable_digest.clone();
        let identity = Instrument {
            name: "teapot".parse().expect("fixed instrument name"),
            version: Deserialize::deserialize(&version.result()["version"])
                .map_err(|_| invalid(GateOperation::Version, &version))?,
            commit,
            binary_digest: binary_digest.clone(),
            engine_instance: self.teapot.engine.instance.clone(),
            project_id: self.teapot.engine.project_id.clone(),
            protocol: PROTOCOL_VERSION,
        };
        let initial_status = self.proxy_status(engine)?;
        self.policy_locked = Some(self.teapot.engine.policy_locked);
        let pass = self.bound_read(GateOperation::PassShow, None, engine)?;
        let enforcement = classify_enforcement(&pass, engine, initial_status.result())?;
        self.enforcement = Some(enforcement.status);
        let enforcement_refusal = enforcement.refusal(requirement);

        let rules = self.bound_read(GateOperation::RulesList, None, engine)?;
        let intercept = self.bound_read(GateOperation::InterceptStatus, None, engine)?;
        let intercept_rules = self.bound_read(GateOperation::InterceptRules, None, engine)?;
        let scripts = self.bound_read(GateOperation::ScriptsList, None, engine)?;
        let mut observed_sessions = Vec::new();
        let mut seen = HashSet::new();
        for session in sessions.iter().filter(|session| seen.insert(*session)) {
            observed_sessions.push((
                session,
                self.bound_read(GateOperation::SessionShow, Some(session), engine)?,
            ));
        }
        let config = self.bound_read(GateOperation::ConfigList, None, engine)?;
        let final_status = self.proxy_status(engine)?;
        if final_status.result()["health"]["policy_lock"]
            != initial_status.result()["health"]["policy_lock"]
            || !same_pass_view(pass.result(), final_status.result())
        {
            return Err(invalid(GateOperation::ProxyStatus, &final_status));
        }
        if let Some(reason) = enforcement_refusal {
            return Err((reason, None));
        }
        if [&initial_status, &final_status].into_iter().any(|status| {
            let health = &status.result()["health"];
            health["policy_lock"]["allow_eval"] == true
                || health["scripts_following"]
                    .as_array()
                    .is_some_and(|rows| !rows.is_empty())
        }) {
            return Err((GateRefusalReason::EditableConfiguration, None));
        }

        edits::classify_edits(
            &rules,
            &intercept,
            &intercept_rules,
            &scripts,
            &observed_sessions,
            &config,
        )?;
        let ending_digest = self.teapot.executable_digest().map_err(|error| {
            (
                GateRefusalReason::EngineUnestablished,
                Some(Box::new(error)),
            )
        })?;
        if !self
            .schema_lane
            .expect("selected by the first version read")
            .bookend_matches(binary_digest.as_ref(), &ending_digest)
        {
            return Err((GateRefusalReason::EngineUnestablished, None));
        }
        Ok((identity, enforcement))
    }
}

fn valid_request_reference_version(version: &Value) -> bool {
    let engine = &version["engine"];
    version.get("asupersync_version").is_some_and(|value| {
        value.is_null() || value.as_str().is_some_and(|value| !value.is_empty())
    }) && version
        .get("features")
        .is_some_and(|features| features["impersonate"].as_bool().is_some())
        && version.get("ftui_version").is_some_and(|value| {
            value.is_null() || value.as_str().is_some_and(|value| !value.is_empty())
        })
        && version
            .get("public_suffix_list_date")
            .is_some_and(|value| value.is_null() || value.as_str().is_some())
        && version
            .get("target")
            .is_some_and(|value| value.is_null() || value.as_str().is_some())
        && engine
            .get("socks5")
            .is_some_and(|value| value.is_null() || value.as_str().is_some())
        && engine
            .get("started_by")
            .and_then(Value::as_str)
            .is_some_and(|value| matches!(value, "cli" | "tui"))
}

fn invalid(operation: GateOperation, reply: &NativeReply) -> ReadFailure {
    (
        operation.unavailable(),
        Some(Box::new(reply.fail(DiagnosticCode::InvalidNativeOutput))),
    )
}

fn valid_engine(engine: &Value) -> bool {
    engine["mode"] == "regular"
        && engine.get("pass").is_some()
        && engine["pid"]
            .as_u64()
            .is_some_and(|pid| (1..=u64::from(u32::MAX)).contains(&pid))
        && engine["listener"]
            .as_str()
            .and_then(|addr| addr.parse::<SocketAddr>().ok())
            .is_some_and(|addr| addr.port() > 0)
        && engine["control_socket"]
            .as_str()
            .is_some_and(|path| Path::new(path).is_absolute())
        && engine["started_at"]
            .as_str()
            .is_some_and(|date| OffsetDateTime::parse(date, &Rfc3339).is_ok())
}

fn classify_enforcement(
    reply: &NativeReply,
    engine: &Value,
    proxy: &Value,
) -> Result<Enforcement, ReadFailure> {
    let pass = reply.result();
    let report = &pass["enforcement"];
    let code = report["code"].as_str().unwrap_or_default();
    let invalid = || invalid(GateOperation::PassShow, reply);
    let on = report["on"] == true;
    let reasons = report["not_enforceable"].as_array().ok_or_else(invalid)?;
    let enforceable = report["enforceable"].as_bool().ok_or_else(invalid)?;
    let lock = &pass["lock"];
    let status_lock = &proxy["health"]["policy_lock"];
    let lock_reasons: Vec<LockReason> =
        Deserialize::deserialize(&status_lock["reasons"]).map_err(|_| invalid())?;
    let mut unique = HashSet::new();
    let pass_lock_reasons = lock["reasons"].as_array().ok_or_else(invalid)?;
    if report["on"] != engine["enforced"]
        || (code == "on") != on
        || report["playpen_enforces_names"] != false
        || enforceable != reasons.is_empty()
        || (code == "not-enforceable") == enforceable
        || reasons
            .iter()
            .any(|reason| reason.as_str().is_none_or(str::is_empty))
        || lock["locked"] != engine["policy_locked"]
        || ["locked_keys", "refused"]
            .iter()
            .any(|key| lock[*key] != status_lock[*key])
        || pass_lock_reasons.len() != lock_reasons.len()
        || lock_reasons.iter().any(|reason| !unique.insert(reason))
        || (lock["locked"] == true) == lock_reasons.is_empty()
        || on != lock_reasons.contains(&LockReason::Enforce)
        || pass.get("pass_file") != engine.get("pass")
        || !matches!(pass["relay"].as_str(), Some("allow" | "block"))
        || !pass["upstream_proxy"].is_null()
        || !same_pass_view(pass, proxy)
    {
        return Err(invalid());
    }
    let observed_pass = match pass["state"].as_str() {
        Some("unbound")
            if pass["pass_file"].is_null()
                && pass.get("digest") == Some(&Value::Null)
                && pass.get("window") == Some(&Value::Null)
                && pass.get("id") == Some(&Value::Null)
                && pass.get("stop") == Some(&Value::Null)
                && code == "no-pass" =>
        {
            None
        }
        Some("bound")
            if pass["window"] == "valid"
                && pass.get("stop") == Some(&Value::Null)
                && matches!(
                    code,
                    "on" | "not-enforceable" | "not-linux" | "playpen-unavailable" | "not-enforced"
                ) =>
        {
            Some(ObservedPass {
                id: pass["id"]
                    .as_str()
                    .filter(|id| !id.is_empty())
                    .and_then(|id| id.parse().ok())
                    .ok_or_else(invalid)?,
                digest: pass["digest"]
                    .as_str()
                    .and_then(|digest| digest.strip_prefix("sha256:"))
                    .and_then(|digest| digest.parse().ok())
                    .ok_or_else(invalid)?,
                file: pass["pass_file"]
                    .as_str()
                    .and_then(|path| path.parse().ok())
                    .ok_or_else(invalid)?,
            })
        }
        _ => return Err(invalid()),
    };

    if on && (observed_pass.is_none() || pass["relay"] != "block" || lock["locked"] != true) {
        return Err(invalid());
    }
    Ok(Enforcement {
        status: if on {
            EnforcementStatus::EgressEnforced
        } else {
            EnforcementStatus::Unenforced
        },
        enforceable,
        pass: observed_pass,
    })
}

struct Enforcement {
    status: EnforcementStatus,
    enforceable: bool,
    pass: Option<ObservedPass>,
}

impl Enforcement {
    fn refusal(&self, requirement: RequiredEnforcement) -> Option<GateRefusalReason> {
        if requirement != RequiredEnforcement::Egress
            || self.status == EnforcementStatus::EgressEnforced
        {
            return None;
        }
        Some(if self.enforceable {
            GateRefusalReason::EnforcementRequired
        } else {
            GateRefusalReason::PassNotEnforceable
        })
    }
}

#[derive(Deserialize, Hash, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum LockReason {
    PassFlag,
    PassEnv,
    AttachedPass,
    Enforce,
    LockPolicyFlag,
}

fn same_pass_view(pass: &Value, proxy: &Value) -> bool {
    let health = &proxy["health"];
    let gate = &health["gate"];
    let lock_pass = &health["policy_lock"]["pass"];
    if gate["state"] != pass["state"]
        || gate["settings"]["relay"] != pass["relay"]
        || gate["settings"]["required"] != pass["required"]
        || ["stop", "stop_reason", "newer_pass_waiting"]
            .iter()
            .any(|key| gate.get(key) != Some(&Value::Null))
        || pass.get("newer_pass") != Some(&Value::Null)
    {
        return false;
    }
    if pass["state"] == "unbound" {
        return gate.get("pass") == Some(&Value::Null)
            && health["policy_lock"].get("pass") == Some(&Value::Null);
    }
    let current = &gate["pass"];
    current["path"] == pass["pass_file"]
        && ["id", "digest", "window"]
            .iter()
            .all(|key| current[*key] == pass[*key])
        && current["current_digest"] == pass["digest"]
        && lock_pass["id"] == pass["id"]
        && lock_pass["digest"] == pass["digest"]
}
