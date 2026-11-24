//! Typed, saved observations for `web.private-object-read.v1`.
//!
//! The oracle consumes these values only. They are the verifier's own record of
//! one round: the twelve required flows, the canaries each plant wrote, the
//! identities each probe resolved, and the cleanup outcome. There is
//! deliberately no HTTP status field and no policy field anywhere in this
//! module (INV-08); loading a saved observation file that carries one fails at
//! deserialization instead of reaching the predicate.
//!
//! Saved files use [`OBSERVATION_SCHEMA`]. Bodies are hex so fixtures stay
//! readable and byte-exact.

use serde::{Deserialize, Serialize};

use scourge_core::{
    ids::{RunId, WireText},
    wire::{Artifact, Completeness},
};

use crate::decode::{DecodeLimits, Decoding};

/// The saved-observation document this build reads.
pub const OBSERVATION_SCHEMA: &str = "scourge.oracle-observations.v1";

/// One flow of the frozen template, in canonical acquisition order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum FlowId {
    /// Initial owner identity probe.
    #[serde(rename = "I1")]
    I1,
    /// Initial other-principal identity probe.
    #[serde(rename = "I2")]
    I2,
    /// Plant of the primary object, carrying the per-field canaries.
    #[serde(rename = "P")]
    P,
    /// Plant of the distinct control object.
    #[serde(rename = "P2")]
    P2,
    /// Anonymous read of the primary object, before the owner read.
    #[serde(rename = "F0")]
    F0,
    /// Owner read of the primary object.
    #[serde(rename = "F1")]
    F1,
    /// Other-principal read of the primary object.
    #[serde(rename = "F2")]
    F2,
    /// Anonymous read of the primary object, after the owner read.
    #[serde(rename = "F3")]
    F3,
    /// Other-principal read of the control object.
    #[serde(rename = "F4")]
    F4,
    /// Final owner identity probe.
    #[serde(rename = "I3")]
    I3,
    /// Final other-principal identity probe.
    #[serde(rename = "I4")]
    I4,
    /// Cleanup of the run-owned objects.
    #[serde(rename = "C")]
    C,
}

impl FlowId {
    /// The frozen `required_flows` order from `scourge.oracle-specifications.v1`.
    pub const REQUIRED: [Self; 12] = [
        Self::I1,
        Self::I2,
        Self::P,
        Self::P2,
        Self::F0,
        Self::F1,
        Self::F2,
        Self::F3,
        Self::F4,
        Self::I3,
        Self::I4,
        Self::C,
    ];

    /// The frozen flow identifier as written in the contract.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::I1 => "I1",
            Self::I2 => "I2",
            Self::P => "P",
            Self::P2 => "P2",
            Self::F0 => "F0",
            Self::F1 => "F1",
            Self::F2 => "F2",
            Self::F3 => "F3",
            Self::F4 => "F4",
            Self::I3 => "I3",
            Self::I4 => "I4",
            Self::C => "C",
        }
    }

    /// Whether the flow is an identity probe.
    pub const fn is_identity(self) -> bool {
        matches!(self, Self::I1 | Self::I2 | Self::I3 | Self::I4)
    }

    /// Whether the flow plants an object.
    pub const fn is_plant(self) -> bool {
        matches!(self, Self::P | Self::P2)
    }

    /// Whether the flow reads a planted object.
    pub const fn is_read(self) -> bool {
        matches!(self, Self::F0 | Self::F1 | Self::F2 | Self::F3 | Self::F4)
    }
}

/// An opaque, stable subject reference resolved by an identity probe.
///
/// The verifier stores a digest; the oracle only compares values for equality.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Subject(WireText);

impl Subject {
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl From<WireText> for Subject {
    fn from(value: WireText) -> Self {
        Self(value)
    }
}

/// An opaque reference to one target object.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ObjectKey(WireText);

impl ObjectKey {
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl From<WireText> for ObjectKey {
    fn from(value: WireText) -> Self {
        Self(value)
    }
}

/// The declared field name one canary was planted in.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct FieldName(WireText);

impl FieldName {
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl From<WireText> for FieldName {
    fn from(value: WireText) -> Self {
        Self(value)
    }
}

/// A run-minted canary: 128 random bits as 32 lowercase hexadecimal characters.
///
/// The oracle never mints canaries; it only accepts the verifier's planted
/// values and rejects anything that is not in the frozen form.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Canary(WireText);

impl Canary {
    /// Parse the frozen 32-lowercase-hex form.
    pub fn parse(value: &str) -> Result<Self, &'static str> {
        let form = value.len() == 32
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'));
        if !form {
            return Err("canary must be 32 lowercase hexadecimal characters");
        }
        Ok(Self(
            WireText::try_from(value.to_owned()).map_err(|_| "canary must be nonempty")?,
        ))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// Whether the canary occurs in a decoded body.
    ///
    /// The test is a byte-substring test: the canary counts when its frozen
    /// 32-lowercase-hex form appears anywhere in the body. There is no
    /// token-boundary rule, and none is claimed: a longer token that embeds the
    /// canary's bytes (for example `<canary>ff`, or the canary inside a quoted
    /// JSON value) also counts, because any ASCII rendering that preserves the
    /// canary bytes is a disclosure of them. POR-06's "exact" means the exact
    /// current run-minted value rather than a status code or stale content, and
    /// a different or truncated 31-character value does not match.
    pub fn occurs_in(&self, body: &[u8]) -> bool {
        let needle = self.0.as_str().as_bytes();
        body.windows(needle.len()).any(|window| window == needle)
    }
}

impl TryFrom<String> for Canary {
    type Error = &'static str;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<Canary> for String {
    fn from(value: Canary) -> Self {
        value.0.as_str().to_owned()
    }
}

/// One canary the plant wrote into one declared field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlantedCanary {
    pub field: FieldName,
    pub canary: Canary,
}

/// What the plant's own response established (POR-03, POR-11, INV-40).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlantDetail {
    /// The object identity the plant response established, when it did.
    pub object: Option<ObjectKey>,
    pub canaries: Vec<PlantedCanary>,
}

/// What the cleanup flow attempted (recorded separately, never a verdict).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CleanupDetail {
    pub attempted: bool,
    pub removed: Vec<ObjectKey>,
}

/// One saved flow of the round.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedFlow {
    pub flow: FlowId,
    /// The run this observation belongs to (POR-08 run binding).
    pub run: RunId,
    /// Acquisition order inside the round (POR-07).
    pub sequence: u64,
    pub completeness: Completeness,
    pub decoding: Decoding,
    /// The decoder the verifier named for this body (POR-09).
    pub decoder: Option<crate::decode::DecoderName>,
    /// The retained original artifact, when the evidence store has it.
    pub original: Option<Artifact>,
    /// The saved original body, hex in JSON and byte-exact in memory.
    #[serde(with = "hex_bytes")]
    pub body: Vec<u8>,
    /// The subject an identity probe resolved.
    #[serde(default)]
    pub subject: Option<Subject>,
    /// The object and canaries a plant established.
    #[serde(default)]
    pub plant: Option<PlantDetail>,
    /// The removals a cleanup flow attempted.
    #[serde(default)]
    pub cleanup: Option<CleanupDetail>,
}

/// The oracle a saved observation file was produced for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OracleRef {
    pub id: WireText,
    pub version: WireText,
}

/// Every observation one round contributes to `web.private-object-read.v1`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedObservations {
    pub schema: WireText,
    pub oracle: OracleRef,
    /// The run every flow must belong to.
    pub run: RunId,
    pub round: u64,
    /// The frozen decode bounds the run recorded.
    #[serde(default)]
    pub limits: DecodeLimits,
    pub flows: Vec<SavedFlow>,
}

mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer, de::Error as _};

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        let mut hex = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            hex.push(char::from_digit(u32::from(byte >> 4), 16).expect("nibble is a digit"));
            hex.push(char::from_digit(u32::from(byte & 0x0f), 16).expect("nibble is a digit"));
        }
        serializer.serialize_str(&hex)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(deserializer)?;
        if !text.len().is_multiple_of(2) {
            return Err(D::Error::custom("hex body must have an even length"));
        }
        let mut bytes = Vec::with_capacity(text.len() / 2);
        let digits = text.as_bytes();
        for pair in digits.chunks(2) {
            let high = (pair[0] as char)
                .to_digit(16)
                .ok_or_else(|| D::Error::custom("hex body contains a non-hex digit"))?;
            let low = (pair[1] as char)
                .to_digit(16)
                .ok_or_else(|| D::Error::custom("hex body contains a non-hex digit"))?;
            bytes.push(((high << 4) | low) as u8);
        }
        Ok(bytes)
    }
}
