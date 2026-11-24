//! Normalized `scourge.request-input.v1`: the exact object a request key binds.
//!
//! Normalization happens before mutable selector resolution, so a replay
//! compares the caller's command and typed input against the stored object
//! without resolving defaults or selectors again. Only the canonical command
//! path and its typed arguments enter the object. Presentation flags, the bound
//! path spelling, actor attribution and the request key are outside equality.
//!
//! Equality is exact equality of the canonical bytes: object member order is
//! irrelevant, array order and string contents are preserved, and every value
//! is decoded against its registered argument shape first.

use serde::Serialize;
use serde_json::{Map, Value, json};

use crate::{
    canonical::{JsonError, Sha256Digest},
    ids::WireText,
    wire::{self, AbsolutePath, RequestInputV1, RetestArguments, VerifyArguments},
};

/// The declared CLI default for `verify --rounds`, applied before comparison.
pub const DEFAULT_VERIFY_ROUNDS: u64 = 2;
/// The declared CLI default for `retest --mode`, applied before comparison.
pub const DEFAULT_RETEST_MODE: &str = "sequential";

const SCHEMA: &str = "scourge.request-input.v1";
const VERIFY: &str = "verify";
const RETEST: &str = "retest";

/// Surface details that never enter the normalized request.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Surface {
    /// `--format`, its hidden `--json` alias or `FORMAT`.
    pub format: Option<WireText>,
    /// The workspace path as spelled after binding.
    pub workspace: Option<AbsolutePath>,
    /// The actor string. Attribution, not authority.
    pub actor: Option<WireText>,
}

/// A command and its typed arguments as supplied, before selector resolution.
#[derive(Clone, Debug)]
pub struct Invocation {
    pub command: String,
    pub arguments: Value,
    pub surface: Surface,
}

impl Invocation {
    pub fn new(command: impl Into<String>, arguments: Value) -> Self {
        Self {
            command: command.into(),
            arguments,
            surface: Surface::default(),
        }
    }

    /// Bind the canonical command path and typed arguments into the object a
    /// request key stores. `self.surface` is deliberately not consulted.
    pub fn normalize(&self) -> Result<NormalizedInput, JsonError> {
        let command = canonical_command(&self.command);
        let arguments = normalized_arguments(&command, &self.arguments)?;
        let bytes = wire::to_vec(&json!({
            "schema": SCHEMA,
            "command": command,
            "arguments": arguments,
        }))?;
        Ok(NormalizedInput {
            input: RequestInputV1::read(&bytes)?,
        })
    }
}

/// The canonical space-separated command path. A bare invocation and the
/// sibling aliases resolve to `status`; internal whitespace is collapsed.
pub fn canonical_command(command: &str) -> String {
    match command.split_whitespace().collect::<Vec<_>>().as_slice() {
        [] => "status".into(),
        ["tldr" | "brief" | "onboard" | "status"] => "status".into(),
        parts => parts.join(" "),
    }
}

/// The normalized request. Two invocations are the same request exactly when
/// their canonical bytes are equal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NormalizedInput {
    input: RequestInputV1,
}

impl NormalizedInput {
    /// The canonical command path, never the alias the caller typed.
    pub fn command(&self) -> &str {
        self.input.command.as_str()
    }

    /// The typed arguments after stable defaults, including explicit nulls.
    pub fn arguments(&self) -> &Map<String, Value> {
        &self.input.arguments
    }

    /// Canonical bytes: sorted members, compact UTF-8, arrays in order.
    pub fn to_bytes(&self) -> Result<Vec<u8>, JsonError> {
        wire::to_vec(&self.input)
    }

    /// SHA-256 over exactly those canonical bytes.
    pub fn digest(&self) -> Result<Sha256Digest, JsonError> {
        Ok(Sha256Digest::of(&self.to_bytes()?))
    }

    /// Read stored bytes back into typed values. This is lenient about byte
    /// spelling, so it is not an authority on what a key binds: use
    /// [`NormalizedInput::read_canonical`] wherever stored bytes are compared
    /// with a caller's request.
    pub fn read(bytes: &[u8]) -> Result<Self, JsonError> {
        Ok(Self {
            input: RequestInputV1::read(bytes)?,
        })
    }

    /// Read the authoritative stored form: the bytes must be canonical and
    /// must still decode to the registered argument shape. Stored bytes that
    /// do not re-encode to themselves are not the object the key accepted.
    pub fn read_canonical(bytes: &[u8]) -> Result<Self, JsonError> {
        let input = RequestInputV1::read(bytes)?;
        if wire::to_vec(&input)? != bytes {
            return Err(JsonError::NonCanonical);
        }
        Ok(Self { input })
    }
}

fn normalized_arguments(command: &str, supplied: &Value) -> Result<Value, JsonError> {
    let Value::Object(supplied) = supplied else {
        return Err(JsonError::InvalidShape);
    };
    let mut arguments = supplied.clone();
    match command {
        VERIFY => {
            arguments.entry("lead_revision").or_insert(Value::Null);
            arguments
                .entry("engagement_revision")
                .or_insert(Value::Null);
            arguments
                .entry("rounds")
                .or_insert(Value::from(DEFAULT_VERIFY_ROUNDS));
            typed::<VerifyArguments>(arguments)
        }
        RETEST => {
            arguments
                .entry("engagement_revision")
                .or_insert(Value::Null);
            arguments
                .entry("mode")
                .or_insert(Value::from(DEFAULT_RETEST_MODE));
            arguments.entry("rounds").or_insert(Value::Null);
            typed::<RetestArguments>(arguments)
        }
        // An unregistered command keeps the base envelope; nothing interprets it.
        _ => Ok(Value::Object(arguments)),
    }
}

/// Decode the registered argument shape, then re-encode it. The result names
/// exactly the registered members, so an omitted flag and its default match.
fn typed<T: serde::de::DeserializeOwned + Serialize>(
    arguments: Map<String, Value>,
) -> Result<Value, JsonError> {
    let decoded: T = wire::from_slice(&wire::to_vec(&Value::Object(arguments))?)?;
    serde_json::to_value(decoded).map_err(|_| JsonError::Serialize)
}
