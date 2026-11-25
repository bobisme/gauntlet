//! Canonical JSON for immutable structured data, and SHA-256 of exact bytes.
//!
//! The byte encoding follows Investigation: recursively sorted object keys,
//! preserved array order, compact UTF-8 JSON, and integers in ±(2^53−1).
//! Scourge encodes SHA-256 as unprefixed lowercase hex. Use [`crate::wire`]
//! for machine envelopes that carry exact counters outside the evidence range.

use std::fmt::Write;

use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{
    ids::{lower_hex, text_type},
    json_input::{self, MAX_SAFE_INTEGER, ParseError},
};

text_type!(Sha256Digest, "SHA-256 digest", |value: &str| lower_hex(
    value, 64
));

impl Sha256Digest {
    /// Hash exact bytes, including any insignificant whitespace in stored JSON.
    pub fn of(bytes: &[u8]) -> Self {
        Self::from_hash(Sha256::digest(bytes).as_ref())
    }

    pub(crate) fn of_reader(reader: impl std::io::Read) -> std::io::Result<Self> {
        use std::io::BufRead;
        let mut reader = std::io::BufReader::new(reader);
        let mut hasher = Sha256::new();
        loop {
            let bytes = reader.fill_buf()?;
            if bytes.is_empty() {
                break;
            }
            hasher.update(bytes);
            let consumed = bytes.len();
            reader.consume(consumed);
        }
        Ok(Self::from_hash(hasher.finalize().as_ref()))
    }

    fn from_hash(bytes: &[u8]) -> Self {
        let mut hex = String::with_capacity(64);
        for byte in bytes {
            write!(hex, "{byte:02x}").expect("formatting to String cannot fail");
        }
        Self(hex)
    }
}

/// Errors use fixed messages so untrusted JSON never appears in summaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum JsonError {
    #[error("malformed JSON or trailing content")]
    Malformed,
    #[error("JSON object contains a duplicate key")]
    DuplicateKey,
    #[error("JSON number exceeds its exact representation")]
    UnsafeNumber,
    #[error("JSON does not match the requested shape")]
    InvalidShape,
    #[error("JSON bytes are not canonical")]
    NonCanonical,
    #[error("SHA-256 does not match stored bytes")]
    DigestMismatch,
    #[error("could not serialize JSON")]
    Serialize,
}

impl From<ParseError> for JsonError {
    fn from(error: ParseError) -> Self {
        match error {
            ParseError::Malformed => Self::Malformed,
            ParseError::DuplicateKey => Self::DuplicateKey,
            ParseError::UnsafeNumber => Self::UnsafeNumber,
        }
    }
}

pub(crate) mod sealed {
    pub trait Sealed {}
}

/// A JSON value or Scourge type that can only contain finite numbers.
/// Values from other sources can enter through [`parse`].
pub trait CanonicalJson: Serialize + sealed::Sealed {}

impl<T: Serialize + sealed::Sealed> CanonicalJson for T {}
impl sealed::Sealed for Value {}

/// Parse one JSON document; reject duplicate member names at every depth.
pub fn parse(bytes: &[u8]) -> Result<Value, JsonError> {
    Ok(json_input::parse(bytes, Some(MAX_SAFE_INTEGER))?)
}

/// Read a manifest, experiment or record, including human-formatted source JSON.
pub fn from_slice<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, JsonError> {
    decode(parse(bytes)?)
}

/// Parse a JSON document whose stored form is required to be canonical.
pub fn from_canonical_slice<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, JsonError> {
    let mut value = parse(bytes)?;
    if encode_value(&mut value)? != bytes {
        return Err(JsonError::NonCanonical);
    }
    decode(value)
}

/// Check an immutable reference before decoding any field in its stored bytes.
pub fn from_digest<T: DeserializeOwned>(
    bytes: &[u8],
    expected: &Sha256Digest,
) -> Result<T, JsonError> {
    if &Sha256Digest::of(bytes) != expected {
        return Err(JsonError::DigestMismatch);
    }
    from_slice(bytes)
}

/// Serialize to canonical JSON. Re-parse to check the evidence integer range
/// and detect repeated keys from flattened extension fields.
///
/// ```compile_fail
/// scourge_core::canonical::to_vec(&f64::NAN);
/// ```
///
/// ```compile_fail
/// #[derive(serde::Serialize)]
/// struct Metadata { values: Vec<Option<f64>> }
/// let values = vec![Some(f64::INFINITY), None, Some(f64::NEG_INFINITY)];
/// scourge_core::canonical::to_vec(&Metadata { values });
/// ```
pub fn to_vec<T: CanonicalJson>(value: &T) -> Result<Vec<u8>, JsonError> {
    encode(value, Some(MAX_SAFE_INTEGER))
}

pub(crate) fn encode<T: CanonicalJson>(
    value: &T,
    max_integer: Option<u64>,
) -> Result<Vec<u8>, JsonError> {
    let bytes = serde_json::to_vec(value).map_err(|_| JsonError::Serialize)?;
    encode_value(&mut json_input::parse(&bytes, max_integer)?)
}

pub(crate) fn decode<T: DeserializeOwned>(value: Value) -> Result<T, JsonError> {
    serde_json::from_value(value).map_err(|_| JsonError::InvalidShape)
}

fn encode_value(value: &mut Value) -> Result<Vec<u8>, JsonError> {
    value.sort_all_objects();
    serde_json::to_vec(value).map_err(|_| JsonError::Serialize)
}
