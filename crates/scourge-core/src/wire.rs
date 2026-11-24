//! Types generated from `docs/contracts/scourge-v1.json`.
//!
//! Use [`from_slice`] for machine input bytes, including nested
//! command arguments and extension objects, so duplicate members are rejected
//! before deserialization. Use [`crate::canonical`] for structured evidence.
//! A versioned reference retains the exact ID and version supplied.

use std::{fmt, marker::PhantomData};

use serde::{
    Deserialize, Deserializer, Serialize,
    de::{MapAccess, Visitor, value::MapAccessDeserializer},
};

use crate::{
    canonical::{self, CanonicalJson, JsonError, Sha256Digest},
    ids::{
        ArtifactId, EngagementId, FindingId, LeadId, PublicationIntentId, RequestKey, RunId,
        RunNonce, VerificationId, WireText, lower_hex, text_type,
    },
    json_input,
};

/// Read one machine document, preserving full-width registry counts.
pub fn from_slice<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, JsonError> {
    canonical::decode(json_input::parse(bytes, None)?)
}

/// Serialize a machine document as compact JSON with sorted object keys.
pub fn to_vec<T: CanonicalJson>(value: &T) -> Result<Vec<u8>, JsonError> {
    canonical::encode(value, None)
}

fn required_nullable<'de, D, T>(decoder: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::deserialize(decoder)
}

/// Deserialize a registered shape with a map-only entry point. Serde's
/// derived struct decoder otherwise also accepts positional sequences.
pub(crate) fn deserialize_object<'de, D, T>(decoder: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct Object<T>(PhantomData<T>);

    impl<'de, T: Deserialize<'de>> Visitor<'de> for Object<T> {
        type Value = T;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a JSON object")
        }

        fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<T, A::Error> {
            T::deserialize(MapAccessDeserializer::new(map))
        }
    }

    decoder.deserialize_map(Object(PhantomData))
}

text_type!(AbsolutePath, "absolute path", |path: &str| path
    .starts_with('/')
    && !path.contains('\0'));
text_type!(GitCommit, "Git commit", |value: &str| lower_hex(value, 40));
text_type!(KebabCase, "kebab-case text", |value: &str| {
    value.starts_with(|character: char| character.is_ascii_lowercase())
        && value.split('-').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        })
});
text_type!(
    /// `^[A-Z][A-Z0-9_]{1,63}$`: an uppercase lead byte and 1 to 63 further
    /// bytes from `[A-Z0-9_]`, so a reason code is 2 to 64 bytes long. The
    /// frozen claim-template schema states the same bound (`$defs/reason_code`),
    /// and every frozen oracle code lies inside it.
    ReasonCode,
    "oracle reason code",
    |value: &str| {
        (2..=64).contains(&value.len())
            && value.starts_with(|character: char| character.is_ascii_uppercase())
            && value
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
    }
);
text_type!(Probability, "probability", |value: &str| {
    let Some((whole, fraction)) = value.split_once('.') else {
        return matches!(value, "0" | "1");
    };
    !fraction.is_empty()
        && match whole {
            "0" => fraction.bytes().all(|byte| byte.is_ascii_digit()),
            "1" => fraction.bytes().all(|byte| byte == b'0'),
            _ => false,
        }
});
text_type!(Timestamp, "UTC timestamp", valid_timestamp);

fn valid_timestamp(value: &str) -> bool {
    let Some(utc) = value.strip_suffix('Z') else {
        return false;
    };
    let (whole, fraction) = utc.split_once('.').unwrap_or((utc, "0"));
    let has_fixed_shape = whole.len() == 19
        && whole
            .bytes()
            .zip(b"0000-00-00T00:00:00")
            .all(|(byte, expected)| {
                if *expected == b'0' {
                    byte.is_ascii_digit()
                } else {
                    byte == *expected
                }
            });
    has_fixed_shape
        && !whole.starts_with("0000-")
        && (1..=9).contains(&fraction.len())
        && fraction.bytes().all(|byte| byte.is_ascii_digit())
        && whole.as_bytes()[17] < b'6'
        && time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
            .is_ok()
}

include!(concat!(env!("OUT_DIR"), "/wire.rs"));

impl RequestInputV1 {
    /// Validate and decode the argument shape for the exact `verify` command.
    pub fn verify_arguments(&self) -> Result<VerifyArguments, JsonError> {
        self.arguments_for("verify")
    }

    /// Validate and decode the argument shape for the exact `retest` command.
    pub fn retest_arguments(&self) -> Result<RetestArguments, JsonError> {
        self.arguments_for("retest")
    }

    fn arguments_for<T: serde::de::DeserializeOwned>(&self, command: &str) -> Result<T, JsonError> {
        if self.command.as_str() != command {
            return Err(JsonError::InvalidShape);
        }
        serde_json::from_value(serde_json::Value::Object(self.arguments.clone()))
            .map_err(|_| JsonError::InvalidShape)
    }

    /// Read a normalized request and check every known argument shape.
    /// An unregistered command can be retained as the base envelope. Neither
    /// argument accessor will interpret it.
    pub fn read(bytes: &[u8]) -> Result<Self, JsonError> {
        let request: Self = from_slice(bytes)?;
        let rounds = match request.command.as_str() {
            "verify" => Some(request.verify_arguments()?.rounds),
            "retest" => request.retest_arguments()?.rounds,
            _ => None,
        };
        if rounds == Some(0) {
            return Err(JsonError::InvalidShape);
        }
        Ok(request)
    }
}
