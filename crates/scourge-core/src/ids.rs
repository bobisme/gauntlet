//! Owned identities and opaque references supplied by other tools.

use uuid::Uuid;

/// An identifier or scalar failed its lexical contract.
/// Errors intentionally omit the supplied text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("invalid {0}")]
pub struct InvalidText(pub(crate) &'static str);

macro_rules! text_type {
    ($(#[$meta:meta])* $name:ident, $description:literal, $validate:expr) => {
        $(#[$meta])*
        #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = $crate::ids::InvalidText;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                if $validate(&value) {
                    return Ok(Self(value));
                }
                Err($crate::ids::InvalidText($description))
            }
        }

        impl std::str::FromStr for $name {
            type Err = $crate::ids::InvalidText;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                value.to_owned().try_into()
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(concat!(stringify!($name), "(..)"))
            }
        }
    };
}

pub(crate) use text_type;

fn text(value: &str) -> bool {
    !value.is_empty() && !value.contains('\0')
}

fn token(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

pub(crate) fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

macro_rules! opaque_id {
    ($name:ident, $description:literal, $prefix:literal) => {
        text_type!($name, $description, |value: &str| value
            .strip_prefix($prefix)
            .is_some_and(token));

        impl $name {
            /// Mint an independent random identity without taking any user input.
            pub fn generate() -> Self {
                Self(format!("{}{}", $prefix, Uuid::new_v4().simple()))
            }
        }
    };
}

opaque_id!(LeadId, "lead ID", "L-");
opaque_id!(RunId, "run ID", "R-");
opaque_id!(VerificationId, "verification record ID", "V-");
opaque_id!(PublicationIntentId, "publication intent ID", "P-");
opaque_id!(RequestKey, "request key", "rk_");

text_type!(
    /// An engagement name assigned by the operator.
    EngagementId,
    "engagement ID",
    text
);
text_type!(
    /// An opaque locator supplied by the evidence store.
    ArtifactId,
    "artifact ID",
    text
);
text_type!(
    /// An instrument-owned name used to select a credential binding.
    SessionName,
    "instrument session name",
    text
);
text_type!(RunNonce, "run nonce", |value: &str| lower_hex(value, 32));
text_type!(
    /// A nonempty wire string without NUL.
    WireText,
    "wire string",
    text
);

/// A finding keeps the same identity as its lead.
pub type FindingId = LeadId;
