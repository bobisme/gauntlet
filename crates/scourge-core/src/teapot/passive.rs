//! Metadata-only Teapot reads used to turn discovery objects into Scourge
//! leads. These commands are read-only local project-store operations. The
//! returned types deliberately have no field capable of carrying a response
//! body, finding detail, reproduction note, remediation, or producer verdict.

use std::{
    collections::BTreeSet,
    process::{Command, Stdio},
};

use serde_json::Value;

use super::{Environment, ExecutableKind, process};
use crate::{
    ids::WireText,
    json_input,
    wire::{AbsolutePath, ErrorCode},
};

/// A passive lookup may inspect at most this many 1000-row pages across all
/// declared sessions. Exceeding the bound is explicit; it is never reported as
/// an absent flow.
const MAX_FLOW_PAGES: usize = 1024;

#[derive(Clone, Debug)]
pub struct PassiveTeapot {
    executable: AbsolutePath,
    executable_kind: ExecutableKind,
    project: AbsolutePath,
    environment: Environment,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProducerObject {
    Finding,
    Lead,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportHint {
    pub object: ProducerObject,
    pub title: WireText,
    pub endpoint: WireText,
    pub flow_ids: Vec<u64>,
    pub class: Option<WireText>,
    pub producer_confidence: Option<WireText>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FlowHint {
    pub id: u64,
    pub endpoint: WireText,
    pub session: WireText,
}

#[derive(Debug, thiserror::Error)]
pub enum PassiveError {
    #[error("invalid passive Teapot selector")]
    InvalidArgument,
    #[error("the producer object was not found")]
    NotFound,
    #[error("the passive Teapot read was unavailable")]
    Unavailable,
    #[error("Teapot returned invalid passive metadata")]
    InvalidOutput,
    #[error("the flow did not identify exactly one declared session")]
    AmbiguousSession,
    #[error("the passive flow lookup exceeded its page bound")]
    PaginationLimit,
}

impl PassiveError {
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::InvalidArgument => ErrorCode::UsageError,
            Self::NotFound => ErrorCode::ObjectNotFound,
            Self::Unavailable => ErrorCode::DependencyUnavailable,
            Self::InvalidOutput => ErrorCode::IntegrityFailure,
            Self::AmbiguousSession => ErrorCode::InputAmbiguous,
            Self::PaginationLimit => ErrorCode::DependencyUnavailable,
        }
    }
}

impl PassiveTeapot {
    pub fn new(
        executable: AbsolutePath,
        executable_kind: ExecutableKind,
        project: AbsolutePath,
        environment: Environment,
    ) -> Self {
        Self {
            executable,
            executable_kind,
            project,
            environment,
        }
    }

    /// Highest retained flow ID at this instant, or `None` when the project
    /// has no retained flows. This is the verifier's pre-send recovery floor;
    /// it is metadata-only and never reaches the target.
    pub fn highest_flow_id(&self) -> Result<Option<u64>, PassiveError> {
        let envelope = self.read(&["flows", "list", "--limit", "1", "--order", "newest"])?;
        let rows = envelope
            .get("flows")
            .and_then(Value::as_array)
            .ok_or(PassiveError::InvalidOutput)?;
        match rows.as_slice() {
            [] => Ok(None),
            [row] => row
                .as_object()
                .ok_or(PassiveError::InvalidOutput)
                .and_then(|row| integer(row, "id"))
                .and_then(|id| {
                    (id > 0)
                        .then_some(Some(id))
                        .ok_or(PassiveError::InvalidOutput)
                }),
            _ => Err(PassiveError::InvalidOutput),
        }
    }

    pub fn finding(&self, id: u64) -> Result<ImportHint, PassiveError> {
        let id = id.to_string();
        let envelope = self.read(&["findings", "show", &id])?;
        let finding = object_at(&envelope, "finding")?;
        let title = string(finding, "title")?;
        let check = string(finding, "check")?;
        let confidence = string(finding, "confidence")?;
        let endpoint = finding
            .get("endpoint")
            .and_then(Value::as_object)
            .ok_or(PassiveError::InvalidOutput)?;
        let endpoint = endpoint_label(
            string(endpoint, "method")?,
            Some(string(endpoint, "scheme")?),
            string(endpoint, "host")?,
            integer(endpoint, "port")?,
            string(endpoint, "path")?,
        )?;
        let evidence = finding
            .get("evidence")
            .and_then(Value::as_array)
            .ok_or(PassiveError::InvalidOutput)?;
        let mut flow_ids = BTreeSet::new();
        for row in evidence {
            let row = row.as_object().ok_or(PassiveError::InvalidOutput)?;
            match row.get("flow") {
                Some(Value::Null) => {}
                Some(value) => {
                    flow_ids.insert(value.as_u64().ok_or(PassiveError::InvalidOutput)?);
                }
                None => return Err(PassiveError::InvalidOutput),
            }
        }
        if let Some(flow) = finding
            .get("reproduction")
            .and_then(Value::as_object)
            .and_then(|value| value.get("flow"))
            .filter(|value| !value.is_null())
        {
            flow_ids.insert(flow.as_u64().ok_or(PassiveError::InvalidOutput)?);
        }
        Ok(ImportHint {
            object: ProducerObject::Finding,
            title: wire(title)?,
            endpoint,
            flow_ids: flow_ids.into_iter().collect(),
            class: check_mapping(check).as_deref().map(wire).transpose()?,
            producer_confidence: Some(wire(confidence)?),
        })
    }

    pub fn lead(&self, id: u64) -> Result<ImportHint, PassiveError> {
        let id = id.to_string();
        let envelope = self.read(&["leads", "show", &id])?;
        let lead = object_at(&envelope, "lead")?;
        let title = string(lead, "title")?;
        // The rule is read only to validate the pinned response shape. No
        // current Teapot lead rule has a declared Scourge class mapping.
        let _rule = string(lead, "rule")?;
        let endpoint = lead
            .get("endpoint")
            .and_then(Value::as_object)
            .ok_or(PassiveError::InvalidOutput)?;
        let endpoint = endpoint_label(
            string(endpoint, "method")?,
            None,
            string(endpoint, "host")?,
            integer(endpoint, "port")?,
            string(endpoint, "path")?,
        )?;
        let flows = lead
            .get("flows")
            .and_then(Value::as_array)
            .ok_or(PassiveError::InvalidOutput)?;
        let mut flow_ids = BTreeSet::new();
        for flow in flows {
            flow_ids.insert(flow.as_u64().ok_or(PassiveError::InvalidOutput)?);
        }
        Ok(ImportHint {
            object: ProducerObject::Lead,
            title: wire(title)?,
            endpoint,
            flow_ids: flow_ids.into_iter().collect(),
            class: None,
            producer_confidence: None,
        })
    }

    /// Identify a flow's route and session without reading its message or body.
    /// Teapot's list row omits the session, so the exact flow is looked up under
    /// each operator-declared session filter. No target operation is invoked.
    pub fn flow(
        &self,
        id: u64,
        declared_sessions: impl IntoIterator<Item = WireText>,
    ) -> Result<FlowHint, PassiveError> {
        let mut matches = Vec::new();
        let mut pages_read = 0;
        for session in declared_sessions {
            let filter = format!("session:{}", session.as_str());
            let mut after: Option<WireText> = None;
            let mut seen_cursors = BTreeSet::new();
            loop {
                if pages_read == MAX_FLOW_PAGES {
                    return Err(PassiveError::PaginationLimit);
                }
                pages_read += 1;
                let mut words = vec![
                    "flows", "list", &filter, "--limit", "1000", "--order", "oldest",
                ];
                if let Some(cursor) = &after {
                    words.extend(["--after", cursor.as_str()]);
                }
                let envelope = self.read(&words)?;
                let rows = envelope
                    .get("flows")
                    .and_then(Value::as_array)
                    .ok_or(PassiveError::InvalidOutput)?;
                let mut found = false;
                for row in rows {
                    let row = row.as_object().ok_or(PassiveError::InvalidOutput)?;
                    if integer(row, "id")? != id {
                        continue;
                    }
                    let method =
                        optional_string(row, "method")?.ok_or(PassiveError::InvalidOutput)?;
                    let host = optional_string(row, "host")?.ok_or(PassiveError::InvalidOutput)?;
                    let path = optional_string(row, "path")?.ok_or(PassiveError::InvalidOutput)?;
                    let scheme =
                        optional_string(row, "scheme")?.ok_or(PassiveError::InvalidOutput)?;
                    let port = optional_integer(row, "port")?.ok_or(PassiveError::InvalidOutput)?;
                    matches.push(FlowHint {
                        id,
                        endpoint: endpoint_label(method, Some(scheme), host, port, path)?,
                        session: session.clone(),
                    });
                    found = true;
                }
                if found {
                    break;
                }
                let Some(cursor) = next_flow_cursor(&envelope)? else {
                    break;
                };
                if !seen_cursors.insert(cursor.clone()) {
                    return Err(PassiveError::InvalidOutput);
                }
                after = Some(cursor);
            }
        }
        match matches.as_slice() {
            [one] => Ok(one.clone()),
            [] => Err(PassiveError::NotFound),
            _ => Err(PassiveError::AmbiguousSession),
        }
    }

    fn read(&self, words: &[&str]) -> Result<Value, PassiveError> {
        let argv = [
            self.executable.as_str(),
            "--project",
            self.project.as_str(),
            "--json",
        ]
        .into_iter()
        .chain(words.iter().copied())
        .collect::<Vec<_>>();
        let mut command = Command::new(argv[0]);
        command
            .args(&argv[1..])
            .current_dir("/")
            .stdin(Stdio::null());
        self.environment.apply(&mut command);
        let output =
            process::run(&mut command, process::LIMITS).map_err(|_| PassiveError::Unavailable)?;
        let stdout = json_input::parse(&output.stdout, None).ok();
        let stderr = json_input::parse(&output.stderr, None).ok();
        if !output.status.success() {
            let reason = [stderr.as_ref(), stdout.as_ref()]
                .into_iter()
                .flatten()
                .filter_map(|value| value.get("error"))
                .filter_map(|value| value.get("reason"))
                .filter_map(Value::as_str)
                .next();
            return Err(
                if reason.is_some_and(|reason| reason.starts_with("no-such-")) {
                    PassiveError::NotFound
                } else if reason.is_some_and(|reason| reason.starts_with("bad-")) {
                    PassiveError::InvalidArgument
                } else {
                    PassiveError::Unavailable
                },
            );
        }
        if !output.stderr.is_empty() || stdout.as_ref().and_then(Value::as_object).is_none() {
            return Err(PassiveError::InvalidOutput);
        }
        let _ = self.executable_kind;
        Ok(stdout.expect("object checked"))
    }
}

fn next_flow_cursor(value: &Value) -> Result<Option<WireText>, PassiveError> {
    let Some(advice) = value.get("advice") else {
        return Ok(None);
    };
    let advice = advice.as_array().ok_or(PassiveError::InvalidOutput)?;
    let mut next = None;
    for row in advice {
        let row = row.as_object().ok_or(PassiveError::InvalidOutput)?;
        let kind = string(row, "type")?;
        if kind != "next-page" {
            continue;
        }
        let cursor = string(row, "message")?
            .strip_prefix("after ")
            .ok_or(PassiveError::InvalidOutput)?;
        if cursor.is_empty()
            || cursor.len() > 48
            || !cursor.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(PassiveError::InvalidOutput);
        }
        let cursor = wire(cursor)?;
        if next.replace(cursor).is_some() {
            return Err(PassiveError::InvalidOutput);
        }
    }
    Ok(next)
}

fn object_at<'a>(
    value: &'a Value,
    key: &str,
) -> Result<&'a serde_json::Map<String, Value>, PassiveError> {
    value
        .get(key)
        .and_then(Value::as_object)
        .ok_or(PassiveError::InvalidOutput)
}

fn string<'a>(
    object: &'a serde_json::Map<String, Value>,
    key: &str,
) -> Result<&'a str, PassiveError> {
    object
        .get(key)
        .and_then(Value::as_str)
        .ok_or(PassiveError::InvalidOutput)
}

fn optional_string<'a>(
    object: &'a serde_json::Map<String, Value>,
    key: &str,
) -> Result<Option<&'a str>, PassiveError> {
    match object.get(key) {
        Some(Value::Null) => Ok(None),
        Some(value) => value.as_str().map(Some).ok_or(PassiveError::InvalidOutput),
        None => Err(PassiveError::InvalidOutput),
    }
}

fn integer(object: &serde_json::Map<String, Value>, key: &str) -> Result<u64, PassiveError> {
    object
        .get(key)
        .and_then(Value::as_u64)
        .ok_or(PassiveError::InvalidOutput)
}

fn optional_integer(
    object: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<Option<u64>, PassiveError> {
    match object.get(key) {
        Some(Value::Null) => Ok(None),
        Some(value) => value.as_u64().map(Some).ok_or(PassiveError::InvalidOutput),
        None => Err(PassiveError::InvalidOutput),
    }
}

fn endpoint_label(
    method: &str,
    scheme: Option<&str>,
    host: &str,
    port: u64,
    path: &str,
) -> Result<WireText, PassiveError> {
    let value = match scheme {
        Some(scheme) => format!("{method} {scheme}://{host}:{port}{path}"),
        None => format!("{method} {host}:{port}{path}"),
    };
    wire(&value)
}

fn wire(value: &str) -> Result<WireText, PassiveError> {
    value.parse().map_err(|_| PassiveError::InvalidOutput)
}

fn check_mapping(check: &str) -> Option<String> {
    // The pack is the mapping authority. The source pin checker guards the
    // surrounding producer surface; this reader recognizes only its one
    // currently declared non-null mapping.
    const PACK: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../packs/teapot-surface.json"
    ));
    let pack: Value = serde_json::from_str(PACK).expect("valid frozen Teapot surface pack");
    pack.get("checks")?.as_array()?.iter().find_map(|row| {
        (row.get("id").and_then(Value::as_str) == Some(check))
            .then(|| row.get("class").and_then(Value::as_str).map(str::to_owned))
            .flatten()
    })
}
