use std::collections::HashSet;

use serde::Deserialize;
use serde_json::Value;

use super::{
    GateOperation, GateRefusalReason, NativeReply, ReadFailure, SessionName, SessionSurface,
    Sha256Digest, invalid,
};

/// One identity-checked edit-surface reply. The digest covers compact JSON of
/// the native result, excluding advice and the surrounding envelope. Retain
/// this evidence inside the verifier's custody boundary.
#[derive(Debug, PartialEq, Eq)]
pub struct EditSurfaceReading {
    pub operation: GateOperation,
    pub session: Option<SessionName>,
    pub result_sha256: Option<Sha256Digest>,
    /// Absent when the reply cannot be reduced to recognized facts.
    pub report: Option<EditSurfaceReport>,
}

/// Decision-relevant facts, with names, filters and other native text omitted.
#[derive(Debug, PartialEq, Eq)]
pub enum EditSurfaceReport {
    Rules(Vec<(bool, RuleStatus)>),
    Intercept {
        enabled: bool,
        rules: u32,
        active_rules: u32,
        paused: u64,
    },
    InterceptRules(Vec<bool>),
    Scripts(Vec<(ScriptState, bool)>),
    Session(SessionSurface),
    Config {
        settings: usize,
    },
}

pub(super) fn surface_reading(
    operation: GateOperation,
    reply: &NativeReply,
    session: Option<&SessionName>,
) -> Option<EditSurfaceReading> {
    use EditSurfaceReport as Report;
    use GateOperation as Op;
    let result = reply.result();
    // Hash the native result only when the passive session view includes
    // the explicit null marker. An unexpected values payload stays private.
    let include_digest = operation != Op::SessionShow || result.get("values") == Some(&Value::Null);
    let report = match operation {
        Op::RulesList => Vec::<Rule>::deserialize(result).ok().map(|rows| {
            Report::Rules(
                rows.into_iter()
                    .map(|rule| (rule.enabled, rule.status))
                    .collect(),
            )
        }),
        Op::InterceptStatus => {
            Intercept::deserialize(result)
                .ok()
                .map(|status| Report::Intercept {
                    enabled: status.enabled,
                    rules: status.rules,
                    active_rules: status.active_rules,
                    paused: status.paused,
                })
        }
        Op::InterceptRules => Vec::<InterceptRule>::deserialize(result).ok().map(|rows| {
            Report::InterceptRules(rows.into_iter().map(|rule| rule.enabled).collect())
        }),
        Op::ScriptsList => Vec::<Script>::deserialize(result).ok().map(|rows| {
            Report::Scripts(
                rows.iter()
                    .map(|script| (script.state, script.edits_flow()))
                    .collect(),
            )
        }),
        Op::SessionShow if include_digest => Session::deserialize(result).ok().and_then(|row| {
            row.surface(session.expect("session for show"))
                .ok()
                .map(Report::Session)
        }),
        Op::SessionShow => None,
        Op::ConfigList => result.as_array().map(|settings| Report::Config {
            settings: settings.len(),
        }),
        _ => return None,
    };
    Some(EditSurfaceReading {
        operation,
        session: session.cloned(),
        result_sha256: include_digest.then(|| {
            Sha256Digest::of(&serde_json::to_vec(result).expect("serializable native JSON"))
        }),
        report,
    })
}

#[derive(Deserialize)]
struct Rule {
    n: u32,
    name: String,
    enabled: bool,
    status: RuleStatus,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RuleStatus {
    Running,
    Off,
    Unapproved,
    Invalid,
}

#[derive(Deserialize)]
struct Intercept {
    enabled: bool,
    rules: u32,
    active_rules: u32,
    paused: u64,
    on_timeout: TimeoutAction,
    #[serde(deserialize_with = "nullable")]
    timeout_secs: Option<u64>,
    change: Value,
}

#[derive(Clone, Copy, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
enum TimeoutAction {
    Forward,
    Drop,
}

#[derive(Deserialize)]
struct InterceptRule {
    n: u32,
    name: String,
    enabled: bool,
}

#[derive(Deserialize)]
struct Script {
    source: ScriptSource,
    state: ScriptState,
    hooks: Vec<Hook>,
    generation: u64,
    previous_running: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
enum ScriptSource {
    Bundled,
    User,
    Project,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ScriptState {
    Running,
    Disabled,
    Error,
    Untrusted,
    Overridden,
}

#[derive(Deserialize)]
struct Hook {
    event: HookEvent,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum HookEvent {
    RequestHeaders,
    Request,
    ResponseHeaders,
    Response,
    WebsocketMessage,
    FlowError,
    TlsConnect,
    Start,
    Stop,
}

impl Script {
    fn consistent(&self) -> bool {
        if self.previous_running
            && !matches!(self.state, ScriptState::Error | ScriptState::Disabled)
        {
            return false;
        }
        match self.state {
            ScriptState::Running | ScriptState::Disabled => true,
            ScriptState::Error => self.previous_running || self.hooks.is_empty(),
            ScriptState::Untrusted => {
                matches!(self.source, ScriptSource::Project) && self.hooks.is_empty()
            }
            ScriptState::Overridden => self.hooks.is_empty(),
        }
    }

    fn edits_flow(&self) -> bool {
        (matches!(self.state, ScriptState::Running) || self.previous_running)
            && self.hooks.iter().any(|hook| {
                matches!(
                    hook.event,
                    HookEvent::RequestHeaders
                        | HookEvent::Request
                        | HookEvent::ResponseHeaders
                        | HookEvent::Response
                        | HookEvent::WebsocketMessage
                )
            })
    }
}

#[derive(Deserialize)]
struct Session {
    name: SessionName,
    state: SessionState,
    sends: SessionSends,
    origins: Vec<String>,
    cookies: Vec<Value>,
    headers: Vec<String>,
    secrets: Vec<String>,
    csrf_tokens: u64,
    #[serde(deserialize_with = "nullable")]
    paused_reason: Option<String>,
    paused_evidence: Vec<u64>,
    #[serde(deserialize_with = "nullable")]
    login: Option<String>,
    #[serde(deserialize_with = "nullable")]
    logged_out: Option<String>,
    values: Value,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
enum SessionState {
    Active,
    Paused,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
enum SessionSends {
    CookiesOnly,
    HeadersToOrigins,
}

fn nullable<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    input: D,
) -> Result<Option<T>, D::Error> {
    Option::deserialize(input)
}

impl Session {
    fn surface(self, expected: &SessionName) -> Result<SessionSurface, GateRefusalReason> {
        let paused = matches!(self.state, SessionState::Paused);
        if &self.name != expected
            || matches!(self.sends, SessionSends::CookiesOnly) != self.origins.is_empty()
            || paused != self.paused_reason.is_some()
            || (!paused && !self.paused_evidence.is_empty())
            || !self.values.is_null()
        {
            return Err(GateRefusalReason::EditSurfaceUnestablished);
        }
        Ok(SessionSurface {
            session: self.name,
            cookies: self.cookies.len(),
            headers: self.headers.len(),
            secrets: self.secrets.len(),
            csrf_tokens: self.csrf_tokens,
            has_login: self.login.is_some(),
            has_logout_rule: self.logged_out.is_some(),
            paused,
        })
    }
}

impl SessionSurface {
    fn edits_flow(&self) -> bool {
        self.paused || self.has_login || self.has_logout_rule || self.csrf_tokens > 0
    }
}

fn decode<T: serde::de::DeserializeOwned>(
    operation: GateOperation,
    reply: &NativeReply,
) -> Result<T, ReadFailure> {
    T::deserialize(reply.result()).map_err(|_| invalid(operation, reply))
}

pub(super) fn classify_edits(
    rules: &NativeReply,
    intercept: &NativeReply,
    intercept_rules: &NativeReply,
    scripts: &NativeReply,
    sessions: &[(&SessionName, NativeReply)],
    config: &NativeReply,
) -> Result<(), ReadFailure> {
    use GateOperation as Op;
    use GateRefusalReason as Reason;
    let rule_rows: Vec<Rule> = decode(Op::RulesList, rules)?;
    if !numbered_rows(rule_rows.iter().map(|rule| (rule.n, rule.name.as_str())))
        || rule_rows
            .iter()
            .any(|rule| rule.enabled == matches!(rule.status, RuleStatus::Off))
    {
        return Err(invalid(Op::RulesList, rules));
    }
    if rule_rows.iter().any(|rule| rule.enabled) {
        return Err((Reason::ActiveRule, None));
    }

    let intercept_status: Intercept = decode(Op::InterceptStatus, intercept)?;
    let intercept_rows: Vec<InterceptRule> = decode(Op::InterceptRules, intercept_rules)?;
    let active_count = intercept_rows
        .iter()
        .filter(|rule| intercept_status.enabled && rule.enabled)
        .count();
    if !numbered_rows(
        intercept_rows
            .iter()
            .map(|rule| (rule.n, rule.name.as_str())),
    ) || !intercept_status.change.is_null()
        || intercept_status.rules as usize != intercept_rows.len()
        || intercept_status.active_rules as usize != active_count
    {
        return Err(invalid(Op::InterceptStatus, intercept));
    }
    if active_count > 0 || intercept_status.paused > 0 {
        return Err((Reason::ActiveIntercept, None));
    }

    let script_rows: Vec<Script> = decode(Op::ScriptsList, scripts)?;
    // The pinned command truncates at 1000 without a continuation token.
    if script_rows.len() >= 1_000
        || script_rows.iter().any(|script| {
            script.generation == 0
                || !script.consistent()
                || script.generation != script_rows[0].generation
        })
    {
        return Err(invalid(Op::ScriptsList, scripts));
    }
    if script_rows.iter().any(Script::edits_flow) {
        return Err((Reason::ActiveScriptHook, None));
    }

    let sessions = sessions
        .iter()
        .map(|(expected, reply)| {
            let session: Session = decode(Op::SessionShow, reply)?;
            session.surface(expected).map_err(|reason| match reason {
                Reason::EditSurfaceUnestablished => invalid(Op::SessionShow, reply),
                _ => (reason, None),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    if sessions.iter().any(SessionSurface::edits_flow) {
        return Err((Reason::SessionBehavior, None));
    }

    let settings = config
        .result()
        .as_array()
        .ok_or_else(|| invalid(Op::ConfigList, config))?;
    check_config(
        settings,
        &rule_rows,
        &intercept_status,
        &intercept_rows,
        &sessions,
    )
    .map_err(|reason| match reason {
        Reason::EditSurfaceUnestablished => invalid(Op::ConfigList, config),
        _ => (reason, None),
    })?;
    Ok(())
}

fn numbered_rows<'a>(rows: impl Iterator<Item = (u32, &'a str)>) -> bool {
    let mut names = HashSet::new();
    rows.enumerate()
        .all(|(i, (n, name))| n as usize == i + 1 && !name.is_empty() && names.insert(name))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ScopeRow {
    host: String,
    path: Option<String>,
    #[serde(rename = "subdomains")]
    _subdomains: Option<bool>,
    scheme: Option<ScopeScheme>,
    port: Option<u16>,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum ScopeScheme {
    Http,
    Https,
}

fn check_config(
    settings: &[Value],
    rules: &[Rule],
    intercept: &Intercept,
    intercept_rules: &[InterceptRule],
    sessions: &[SessionSurface],
) -> Result<(), GateRefusalReason> {
    use GateRefusalReason::{EditSurfaceUnestablished as Unknown, EditableConfiguration};
    let mut keys = HashSet::new();
    let mut configured_rules = 0;
    let mut configured_intercepts = 0;
    let mut intercept_enabled = true;
    let mut intercept_timeout = None;
    let mut on_timeout = TimeoutAction::Forward;

    for setting in settings {
        let key = setting["key"].as_str().ok_or(Unknown)?;
        if !keys.insert(key) {
            return Err(Unknown);
        }
        let value = &setting["value"];
        match key {
            "scope" => {
                let rows: Vec<ScopeRow> = Deserialize::deserialize(value).map_err(|_| Unknown)?;
                if rows.iter().any(|row| {
                    row.host.is_empty()
                        || row.path.as_deref().is_some_and(str::is_empty)
                        || row.port == Some(0)
                        || (row.scheme.is_some() && row.port.is_none())
                }) {
                    return Err(Unknown);
                }
            }
            "pass.path" if value.as_str().is_some_and(|path| !path.is_empty()) => {}
            "pass.required" | "pass.enforce" if value.is_boolean() => {}
            "pass.relay" if matches!(value.as_str(), Some("allow" | "block")) => {}
            "proxy.mode" if value == "regular" => {}
            "rules" => {
                let rows = value.as_array().ok_or(Unknown)?;
                // Every listed rule is off at this point.
                if rows.iter().any(|row| {
                    row["enabled"] != false || !rules.iter().any(|rule| row["name"] == rule.name)
                }) {
                    return Err(EditableConfiguration);
                }
                configured_rules = rows.len();
            }
            "intercept.enabled" => intercept_enabled = value.as_bool().ok_or(Unknown)?,
            "intercept.timeout-secs" => intercept_timeout = Some(value.as_u64().ok_or(Unknown)?),
            "intercept.on-timeout" => {
                on_timeout = Deserialize::deserialize(value).map_err(|_| Unknown)?
            }
            "intercept.rules" => {
                let rows = value.as_array().ok_or(Unknown)?;
                if rows.iter().zip(intercept_rules).any(|(raw, listed)| {
                    raw["name"] != listed.name
                        || raw.get("enabled").map_or(Some(true), Value::as_bool)
                            != Some(listed.enabled)
                }) {
                    return Err(Unknown);
                }
                configured_intercepts = rows.len();
            }
            "sessions.default"
                if value
                    .as_str()
                    .is_some_and(|name| name.parse::<SessionName>().is_ok()) => {}
            _ if valid_session_setting(key, value, sessions)? => {}
            // The frozen config schema permits arbitrary values. Keys outside
            // the qualified profile could change routing or capture.
            _ => return Err(EditableConfiguration),
        }
    }
    if configured_rules != rules.len()
        || configured_intercepts != intercept_rules.len()
        || (intercept_enabled, intercept_timeout, on_timeout)
            != (
                intercept.enabled,
                intercept.timeout_secs,
                intercept.on_timeout,
            )
    {
        return Err(Unknown);
    }
    Ok(())
}

fn valid_session_setting(
    key: &str,
    value: &Value,
    sessions: &[SessionSurface],
) -> Result<bool, GateRefusalReason> {
    let Some((name, setting)) = key
        .strip_prefix("sessions.")
        .and_then(|key| key.rsplit_once('.'))
    else {
        return Ok(false);
    };
    let Ok(name) = name.parse::<SessionName>() else {
        return Ok(false);
    };
    Ok(match setting {
        "headers" => value
            .as_array()
            .is_some_and(|headers| headers.iter().all(Value::is_string)),
        "login" | "logged-out" if value.as_str().is_some_and(|text| !text.is_empty()) => {
            if sessions.iter().any(|session| session.session == name) {
                return Err(GateRefusalReason::SessionBehavior);
            }
            true
        }
        _ => false,
    })
}
