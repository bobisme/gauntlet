use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::Deserialize;
use serde_json::Value;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use super::{DiagnosticCode, InvocationError, Observation, READ_FLOW, Teapot};
use crate::{json_input, wire::Completeness};

const DEFAULT_BODY_BYTES: u64 = 32 * 1024;
const MAX_BODY_BYTES: u64 = 1024 * 1024;

/// A single window of each stored body, in bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BodyWindow {
    offset: u64,
    size: u64,
}

impl BodyWindow {
    pub fn new(offset: u64, size: u64) -> Result<Self, InvocationError> {
        if !(1..=MAX_BODY_BYTES).contains(&size) {
            return Err(InvocationError::InvalidArgument);
        }
        Ok(Self { offset, size })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum BodyCapture {
    Complete,
    Truncated,
    Interrupted,
    Partial,
    None,
}

pub struct StoredBody {
    /// `None` means Teapot did not supply bytes. An included empty window is `Some([])`.
    pub bytes: Option<Vec<u8>>,
    pub offset: u64,
    pub captured: u64,
    pub observed: Option<u64>,
    pub capture: BodyCapture,
    pub whole: bool,
}

pub struct StoredMessage {
    /// Text rendered by Teapot, which may be escaped, normalized or truncated.
    /// It is not proof of the original wire bytes; use the body window when the
    /// body is what matters.
    pub rendered_head: Option<String>,
    /// Exact stored body bytes for the requested window, when Teapot supplied
    /// them. `capture` and `whole` say how much of the body they are.
    pub body: Option<StoredBody>,
}

pub struct StoredFlow {
    pub id: u64,
    /// Request URL as recorded by Teapot.
    pub url: Option<String>,
    /// `scheme://host:port` derived from the recorded URL. The flow record
    /// carries no separate destination field, so this is the URL's authority.
    pub destination: Option<String>,
    pub method: Option<String>,
    pub status: Option<u16>,
    /// What produced the flow (`proxy`, `replay`, ...).
    pub origin: String,
    /// The flow this one was derived from, when Teapot recorded one.
    pub parent: Option<u64>,
    /// The flow a job sent again because this one's outcome was unknown.
    pub retried_as: Option<u64>,
    /// `retried_as` in words, when present.
    pub sent_again: Option<String>,
    pub tags: Vec<String>,
    pub note: Option<String>,
    /// When the request started, as Teapot recorded it.
    pub started_at: OffsetDateTime,
    /// Request start to response end, in milliseconds.
    pub elapsed_ms: Option<u64>,
    pub state: String,
    pub request: StoredMessage,
    pub response: StoredMessage,
    /// Teapot includes sent forms where its edits changed the stored message.
    pub request_sent: Option<StoredMessage>,
    pub response_sent: Option<StoredMessage>,
    pub head_cut: bool,
}

/// The response bytes and completeness that the verifier may pass to an
/// oracle. This is deliberately smaller than [`StoredFlow`]: status and other
/// target-controlled metadata are not oracle inputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetainedResponse {
    pub body: Vec<u8>,
    pub completeness: Completeness,
}

/// A retained Teapot original was not the exact successful `flows show`
/// response shape admitted during acquisition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("retained flow original is malformed or names another flow")]
pub struct RetainedFlowError;

impl std::fmt::Debug for StoredFlow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoredFlow")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl Teapot {
    /// Read one exact stored ID. This operation sends no request to the target.
    /// The ID identifies a row in the bound project. The caller must establish
    /// any association with a particular run and step independently.
    pub fn read_flow(
        &self,
        id: u64,
        window: Option<BodyWindow>,
    ) -> Result<Observation<StoredFlow>, InvocationError> {
        if id == 0 || i64::try_from(id).is_err() {
            return Err(InvocationError::InvalidArgument);
        }
        let id_arg = id.to_string();
        let mut words = vec!["flows", "show", &id_arg, "--base64", "--stored"];
        let offset_arg;
        let size_arg;
        if let Some(window) = window {
            offset_arg = window.offset.to_string();
            size_arg = window.size.to_string();
            words.extend(["--offset", &offset_arg, "--max-body", &size_arg]);
        }
        let evidence = self.invoke_live(&READ_FLOW, &words)?;
        let window = window.unwrap_or(BodyWindow {
            offset: 0,
            size: DEFAULT_BODY_BYTES,
        });
        let mut value = stored_flow(evidence.result(), id, window)
            .ok_or_else(|| evidence.fail(DiagnosticCode::InvalidNativeOutput))?;
        value.head_cut = evidence.envelope()["advice"]
            .as_array()
            .is_some_and(|advice| advice.iter().any(|item| item["type"] == "head-cut"));
        Ok(Observation { value, evidence })
    }
}

impl StoredFlow {
    /// Reduce a previously validated flow to the status-free observation used
    /// by the oracle. The completeness rule is shared by live acquisition and
    /// retained-original re-evaluation so neither path can promote a partial
    /// body.
    pub fn retained_response(&self) -> RetainedResponse {
        let body = self.response.body.as_ref();
        let bytes = body.and_then(|body| body.bytes.clone()).unwrap_or_default();
        let completeness = match body {
            Some(body)
                if body.capture == BodyCapture::None
                    && body.captured == 0
                    && !self.head_cut
                    && (self.method.as_deref() == Some("HEAD")
                        || self.status.is_some_and(|status| {
                            (100..200).contains(&status) || status == 204 || status == 304
                        })) =>
            {
                Completeness::Complete
            }
            Some(body) if body.whole && body.capture == BodyCapture::Complete && !self.head_cut => {
                Completeness::Complete
            }
            Some(body) if body.bytes.is_some() => Completeness::Partial,
            _ => Completeness::Missing,
        };
        RetainedResponse {
            body: bytes,
            completeness,
        }
    }
}

/// Decode the exact stdout bytes retained for one acquired flow.
///
/// This performs no target I/O. It reapplies the frozen Teapot result schema,
/// exact flow-ID check and body-window checks before returning the same typed
/// observation live acquisition used.
pub fn decode_retained_flow(
    original: &[u8],
    expected_id: u64,
) -> Result<StoredFlow, RetainedFlowError> {
    if expected_id == 0 || i64::try_from(expected_id).is_err() {
        return Err(RetainedFlowError);
    }
    let envelope = json_input::parse(original, None).map_err(|_| RetainedFlowError)?;
    let contract = &READ_FLOW.schema["output"]["schema"]["result"];
    if !super::schema::accepts(contract, &envelope) {
        return Err(RetainedFlowError);
    }
    let mut flow = stored_flow(
        &envelope[READ_FLOW.result_key],
        expected_id,
        BodyWindow {
            offset: 0,
            size: MAX_BODY_BYTES,
        },
    )
    .ok_or(RetainedFlowError)?;
    flow.head_cut = envelope["advice"]
        .as_array()
        .is_some_and(|advice| advice.iter().any(|item| item["type"] == "head-cut"));
    Ok(flow)
}

pub(super) fn stored_flow(flow: &Value, id: u64, window: BodyWindow) -> Option<StoredFlow> {
    if flow["id"].as_u64() != Some(id) || !flow["selector"].is_null() {
        return None;
    }
    let request = message(flow, "request", window)?;
    let response = message(flow, "response", window)?;
    // With the default all-parts view, both body-info structs are emitted
    // even when no response was received or a request carried no body.
    if request.rendered_head.is_none() || request.body.is_none() || response.body.is_none() {
        return None;
    }
    let url = opted_string(&flow["url"])?;
    let destination = url.as_deref().and_then(destination_of);
    Some(StoredFlow {
        id,
        url,
        destination,
        method: opted_string(&flow["method"])?,
        status: opted_u16(&flow["status"])?,
        origin: nonempty(flow["origin"].as_str()?)?.to_owned(),
        parent: opted_u64(&flow["parent"])?,
        retried_as: opted_flow(&flow["retried_as"])?,
        sent_again: opted_string(&flow["sent_again"])?,
        tags: strings(flow["tags"].as_array()?)?,
        note: opted_string(&flow["note"])?,
        started_at: OffsetDateTime::parse(flow["started_at"].as_str()?, &Rfc3339).ok()?,
        elapsed_ms: opted_u64(&flow["time_ms"])?,
        state: nonempty(flow["state"].as_str()?)?.to_owned(),
        request,
        response,
        request_sent: edited_message(message(flow, "request_sent", window)?),
        response_sent: edited_message(message(flow, "response_sent", window)?),
        head_cut: false,
    })
}

fn nonempty(value: &str) -> Option<&str> {
    (!value.is_empty()).then_some(value)
}

fn opted_string(value: &Value) -> Option<Option<String>> {
    match value {
        Value::Null => Some(None),
        Value::String(text) => Some(Some(text.clone())),
        _ => None,
    }
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

fn strings(values: &[Value]) -> Option<Vec<String>> {
    values
        .iter()
        .map(|value| value.as_str().map(str::to_owned))
        .collect()
}

/// Teapot's flow record has a URL but no separate destination. Keep the
/// `scheme://authority` prefix, which is what its send and replay replies call
/// the destination.
fn destination_of(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    if scheme.is_empty()
        || !scheme
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
    {
        return None;
    }
    let authority = rest.split(['/', '?', '#']).next()?;
    if authority.is_empty()
        || authority
            .chars()
            .any(|character| character.is_ascii_control() || character.is_whitespace())
    {
        return None;
    }
    Some(format!("{scheme}://{authority}"))
}

fn edited_message(message: StoredMessage) -> Option<StoredMessage> {
    (message.rendered_head.is_some() || message.body.is_some()).then_some(message)
}

fn message(flow: &Value, side: &str, window: BodyWindow) -> Option<StoredMessage> {
    let encoded = flow[format!("{side}_body_base64")].as_str();
    let info = &flow[format!("{side}_body_info")];
    if !flow[format!("{side}_body")].is_null() || (info.is_null() && encoded.is_some()) {
        return None;
    }
    let body = if info.is_null() {
        None
    } else {
        Some(stored_body(info, encoded, window)?)
    };
    Some(StoredMessage {
        rendered_head: flow[format!("{side}_head")].as_str().map(str::to_owned),
        body,
    })
}

#[derive(Deserialize)]
struct BodyInfo {
    capture: BodyCapture,
    decoding: String,
    captured: u64,
    observed: Option<u64>,
    shown: u64,
    whole: bool,
}

fn stored_body(info: &Value, encoded: Option<&str>, window: BodyWindow) -> Option<StoredBody> {
    let info = BodyInfo::deserialize(info).ok()?;
    let shown = info.captured.saturating_sub(window.offset).min(window.size);
    if info.decoding != "as-stored"
        || info
            .observed
            .is_some_and(|observed| observed < info.captured)
        || (info.capture == BodyCapture::None && (info.captured != 0 || encoded.is_some()))
    {
        return None;
    }
    let bytes = if let Some(encoded) = encoded {
        // Check the padded encoded size before allocating a decoded buffer.
        if info.shown != shown || encoded.len() as u64 != shown.div_ceil(3) * 4 {
            return None;
        }
        let decoded = STANDARD.decode(encoded).ok()?;
        if decoded.len() as u64 != shown {
            return None;
        }
        Some(decoded)
    } else {
        if info.shown != 0 {
            return None;
        }
        None
    };
    let whole = bytes.is_some()
        && window.offset == 0
        && info.shown == info.captured
        && info.capture == BodyCapture::Complete;
    if info.whole != whole {
        return None;
    }
    Some(StoredBody {
        bytes,
        offset: window.offset,
        captured: info.captured,
        observed: info.observed,
        capture: info.capture,
        whole,
    })
}
