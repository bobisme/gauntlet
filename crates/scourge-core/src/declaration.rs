//! Strict input and redacted diagnostics for the two operator declarations.

use std::{
    collections::{BTreeMap, HashSet},
    fmt::Write,
    hash::Hash,
    sync::LazyLock,
};

use regex::Regex;
use serde::{Deserialize, Deserializer, de::IntoDeserializer};
use serde_path_to_error::Segment;

use crate::{
    canonical::JsonError,
    ids::text_type,
    json_input::{self, MAX_SAFE_INTEGER, PathSegment},
    toml_input,
    wire::deserialize_object,
};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{stanza}: {issue}")]
pub struct DeclarationError {
    stanza: String,
    issue: DeclarationIssue,
}

impl DeclarationError {
    pub fn stanza(&self) -> &str {
        &self.stanza
    }

    pub fn issue(&self) -> DeclarationIssue {
        self.issue
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DeclarationIssue {
    #[error("malformed document")]
    Malformed,
    #[error("duplicate key")]
    DuplicateKey,
    #[error("number exceeds its canonical representation")]
    UnsafeNumber,
    #[error("invalid or missing field")]
    InvalidShape,
    #[error("target version is required to accept an engagement")]
    MissingTargetVersion,
    #[error("entries must be nonempty and unique")]
    InvalidEntries,
    #[error("number out of range")]
    InvalidNumber,
    #[error("session reference is already used")]
    DuplicateSession,
    #[error("a writers rule requires a write operation")]
    WriteRequired,
    #[error("a rule requires a readers or writers audience")]
    MissingAudience,
    #[error("byte range must be nonempty and forward")]
    InvalidRange,
    #[error("property is not declared")]
    UndeclaredProperty,
    #[error("does not match the bound engagement revision")]
    ScopeMismatch,
    #[error("inferred rules cannot carry operator admission")]
    Unadmitted,
    #[error("operator approval was not established")]
    Unapproved,
    #[error("shared custody requires attributed admission")]
    Unattributed,
    #[error("invalid revision lineage")]
    RevisionLineage,
    #[error(transparent)]
    Canonical(JsonError),
}

pub(crate) fn issue(stanza: &'static str, issue: DeclarationIssue) -> DeclarationError {
    DeclarationError {
        stanza: stanza.into(),
        issue,
    }
}

pub(crate) fn parse_json<'de, T: Deserialize<'de>>(
    input: &[u8],
    root: &'static str,
) -> Result<T, DeclarationError> {
    let value = json_input::parse_located(input, Some(MAX_SAFE_INTEGER)).map_err(|error| {
        let path = error.path.iter().map(|segment| match segment {
            PathSegment::Key(key) => StanzaPart::Key(key),
            PathSegment::Index(index) => StanzaPart::Index(*index),
        });
        DeclarationError {
            stanza: stanza_name(path, root),
            issue: match error.kind {
                json_input::ParseError::Malformed => DeclarationIssue::Malformed,
                json_input::ParseError::DuplicateKey => DeclarationIssue::DuplicateKey,
                json_input::ParseError::UnsafeNumber => DeclarationIssue::UnsafeNumber,
            },
        }
    })?;
    decode(value.into_deserializer(), root)
}

pub(crate) fn parse_toml<T: for<'de> Deserialize<'de>>(
    input: &[u8],
    root: &'static str,
) -> Result<T, DeclarationError> {
    let text = std::str::from_utf8(input).map_err(|_| issue(root, DeclarationIssue::Malformed))?;
    let reader = toml::de::Deserializer::parse(text).map_err(|error| {
        if error.message() != "duplicate key" {
            return issue(root, DeclarationIssue::Malformed);
        }
        let path = error
            .span()
            .and_then(|span| toml_input::key_path(text, span.start));
        let parts = path.iter().flatten().map(|key| StanzaPart::Key(key));
        DeclarationError {
            stanza: stanza_name(parts, root),
            issue: DeclarationIssue::DuplicateKey,
        }
    })?;
    decode(reader, root)
}

pub(crate) fn decode<'de, T: Deserialize<'de>>(
    input: impl Deserializer<'de>,
    root: &'static str,
) -> Result<T, DeclarationError> {
    serde_path_to_error::deserialize::<_, Object<T>>(input)
        .map(|object| object.0)
        .map_err(|error| {
            let path = error.path().iter().map_while(|segment| match segment {
                Segment::Map { key } => Some(StanzaPart::Key(key)),
                Segment::Seq { index } => Some(StanzaPart::Index(*index)),
                Segment::Enum { .. } | Segment::Unknown => None,
            });
            DeclarationError {
                stanza: stanza_name(path, root),
                issue: DeclarationIssue::InvalidShape,
            }
        })
}

enum StanzaPart<'a> {
    Key(&'a str),
    Index(usize),
}

/// The schema-owned field names a rejection may name.
///
/// Only these names may reach a diagnostic. Map entry labels, array contents and
/// enum discriminants are input, including when lexically valid, so the producer
/// renders them as `*` and never copies them.
const STANZA_FIELDS: &[&str] = &[
    "schema_version",
    "engagement",
    "principal",
    "property",
    "objective",
    "pass",
    "instrument",
    "kind",
    "project",
    "target_version",
    "required_custody",
    "required_enforcement",
    "allow_effects",
    "max_verify_runs",
    "retest_miss_threshold",
    "audience",
    "session",
    "verifier_session",
    "groups",
    "identity_probe",
    "operation",
    "subject",
    "resource",
    "read",
    "write",
    "plant",
    "remove",
    "fields",
    "id_from",
    "readers",
    "writers",
    "policy",
    "source",
    "admission",
    "identity",
    "actor",
    "recorded_at",
    "artifact_id",
    "sha256",
    "statement",
    "citation",
    "selector",
    "type",
    "start",
    "end",
    "declaration",
    "revision",
    "parent",
    "source_digest",
    "pass_digest",
    "claim_class",
    "template_version",
    "slots",
    "recipe",
    "effect",
    "controls",
    "oracle",
    "scope",
    "cleanup",
    "evidence_required",
    "retest_variants",
    "result_dimension",
    "rules_out",
    "reason_code",
    "step",
    "id",
];

/// The document roots a rejection may name when it is not located on a field.
const STANZA_ROOTS: &[&str] = &["engagement", "manifest", "policy rule", "claim template"];

/// Schema-owned labels that are not field paths: a rule that requires one of a
/// pair, and the compiled-template registry.
const STANZA_LABELS: &[&str] = &["readers/writers", "registry"];

/// Whether `stanza` is composed only of schema-owned text.
///
/// A stanza is a document root or a registered label, or a dotted field path
/// built from [`STANZA_FIELDS`], `*` for an input-controlled label and `[n]` for
/// an array position. Anything else is not schema-owned: a diagnostic that
/// echoed a supplied key fails this check even when the key looks like an
/// identifier, so a caller can assert redaction instead of trusting it.
pub fn is_schema_stanza(stanza: &str) -> bool {
    if stanza.is_empty() {
        return false;
    }
    if STANZA_ROOTS.contains(&stanza) || STANZA_LABELS.contains(&stanza) {
        return true;
    }
    let mut segments = stanza.split('.');
    let Some(first) = segments.next() else {
        return false;
    };
    // `manifest.revision` and the engagement pointers name the root, then the
    // location inside it; every later segment is a plain field or `*`.
    if !is_stanza_field(first) && !STANZA_ROOTS.contains(&first) {
        return false;
    }
    segments.all(is_stanza_field)
}

fn is_stanza_field(segment: &str) -> bool {
    let mut name = segment;
    let mut indexed = false;
    while let Some(rest) = name.strip_suffix(']') {
        let Some((head, index)) = rest.rsplit_once('[') else {
            return false;
        };
        if index.is_empty() || !index.bytes().all(|byte| byte.is_ascii_digit()) {
            return false;
        }
        name = head;
        indexed = true;
    }
    // A path that starts inside an array has no field name, only positions
    // (`[0]`, `[0][2]`, `[0].revision`): the positions are schema structure too.
    name == "*" || STANZA_FIELDS.contains(&name) || (indexed && name.is_empty())
}

fn stanza_name<'a>(path: impl IntoIterator<Item = StanzaPart<'a>>, root: &str) -> String {
    let mut result = String::new();
    let mut entry_label = false;
    for segment in path {
        match segment {
            StanzaPart::Key(key) => {
                if !result.is_empty() {
                    result.push('.');
                }
                if entry_label || !STANZA_FIELDS.contains(&key) {
                    result.push('*');
                    entry_label = false;
                } else {
                    result.push_str(key);
                    entry_label = root != "policy rule" && matches!(key, "principal" | "property");
                }
            }
            StanzaPart::Index(index) => write!(result, "[{index}]").expect("writing to String"),
        }
    }
    if result.is_empty() {
        return root.into();
    }
    result
}

pub(crate) fn check_safe_integer(value: u64, stanza: &'static str) -> Result<(), DeclarationError> {
    if value > MAX_SAFE_INTEGER {
        return Err(issue(stanza, DeclarationIssue::UnsafeNumber));
    }
    Ok(())
}

/// Use with serde's `default` so omission is accepted but null is rejected.
pub(crate) fn optional<'de, D, T>(input: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(input).map(Some)
}

struct Object<T>(T);

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Object<T> {
    fn deserialize<D: Deserializer<'de>>(input: D) -> Result<Self, D::Error> {
        deserialize_object(input).map(Self)
    }
}

pub(crate) fn optional_object<'de, D, T>(input: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    deserialize_object(input).map(Some)
}

pub(crate) fn objects<'de, D, K, V>(input: D) -> Result<BTreeMap<K, V>, D::Error>
where
    D: Deserializer<'de>,
    K: Deserialize<'de> + Ord,
    V: Deserialize<'de>,
{
    let objects = BTreeMap::<K, Object<V>>::deserialize(input)?;
    Ok(objects
        .into_iter()
        .map(|(key, value)| (key, value.0))
        .collect())
}

// Deriving Deserialize alone also accepts an externally tagged object.
macro_rules! string_enum {
    ($visibility:vis enum $name:ident { $($variant:ident => $value:literal),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
        #[serde(try_from = "String")]
        $visibility enum $name {
            $(#[serde(rename = $value)] $variant),+
        }

        impl TryFrom<String> for $name {
            type Error = &'static str;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                match value.as_str() {
                    $($value => Ok(Self::$variant),)+
                    _ => Err("unknown declaration value"),
                }
            }
        }
    };
}

pub(crate) use string_enum;

pub(crate) fn registered_ref(value: &str, namespace: &str) -> bool {
    let Some(suffix) = value
        .strip_prefix(namespace)
        .and_then(|tail| tail.strip_prefix('.'))
    else {
        return false;
    };
    let mut parts = suffix.split('.');
    let spellings_ok = parts.by_ref().take(6).all(|part| {
        (1..=32).contains(&part.len())
            && part.starts_with(lower_alnum)
            && part
                .chars()
                .all(|character| lower_alnum(character) || character == '-')
    });
    spellings_ok && parts.next().is_none()
}

pub(crate) fn unique_nonempty<T: Eq + Hash>(items: &[T]) -> bool {
    let mut seen = HashSet::with_capacity(items.len());
    !items.is_empty() && items.iter().all(|item| seen.insert(item))
}

fn lower_alnum(character: char) -> bool {
    character.is_ascii_lowercase() || character.is_ascii_digit()
}

macro_rules! reference {
    ($name:ident, $prefix:literal) => {
        text_type!($name, "registered reference", |value: &str| {
            registered_ref(value, $prefix)
        });
    };
}

reference!(OperationRef, "operation");
reference!(ResourceRef, "resource");
reference!(SessionRef, "session");
reference!(SelectorRef, "selector");
reference!(PassRef, "pass");
reference!(GroupRef, "group");
reference!(ProjectRef, "project");
reference!(VersionRef, "version");
reference!(ArtifactRef, "artifact");
reference!(OperatorRef, "operator");

text_type!(Label, "principal or property label", |value: &str| {
    (1..=64).contains(&value.len())
        && value.starts_with(|character: char| character.is_ascii_lowercase())
        && value
            .chars()
            .all(|character| lower_alnum(character) || character == '_')
        && !FORBIDDEN.is_match(value)
});

text_type!(Prose, "declaration prose", safe_prose);

fn safe_prose(value: &str) -> bool {
    fn boundary_space(character: char) -> bool {
        character.is_whitespace() || character == '\u{feff}'
    }

    !value.is_empty()
        && !value.starts_with(boundary_space)
        && !value.ends_with(boundary_space)
        && value.chars().count() <= 4096
        && !value.chars().any(|c| matches!(c, '\x00'..='\x1f' | '\x7f'))
        && !FORBIDDEN.is_match(value)
}

// The frozen ADRs also require the local check to reject executable- or
// credential-shaped text, even in a schema field intended for prose.
static FORBIDDEN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"\b(?:GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS|TRACE|CONNECT)\s+\S",
        r"|^(?:curl|wget|bash|zsh|sh|python[0-9.]*|nc|ncat|ssh|scp|sudo|env|perl|ruby|node)\b",
        r"|^#!|`|\$\(",
        r"|(?:;|&&|\|\|)\s*(?:curl|wget|bash|sh|nc|python[0-9.]*|rm|cat|echo|id|whoami)\b",
        r"|(?i:password|passwd|secret|token|api[_-]?key|authorization|cookie)\s*[:=]",
        r"|://",
    ))
    .expect("fixed contract patterns")
});

#[cfg(test)]
mod tests {
    use super::is_schema_stanza;

    #[test]
    fn schema_owned_stanzas_are_accepted() {
        for stanza in [
            // Document roots and registered labels.
            "engagement",
            "manifest",
            "policy rule",
            "claim template",
            "registry",
            "readers/writers",
            // Fields the producer names directly.
            "principal",
            "property",
            "target_version",
            "template_version",
            "slots",
            "recipe",
            "controls",
            "oracle",
            "cleanup",
            "retest_variants",
            // Located paths, wildcards and array positions.
            "engagement.pass",
            "engagement.*",
            "manifest.revision",
            "source.citation.selector",
            "principal.*.groups",
            "property.*.plant.fields",
            "recipe[0].slots[1]",
            // A path that starts inside an array has positions, not a name.
            "[0]",
            "[0][2]",
            "[0].revision",
            "*",
            "*[0]",
        ] {
            assert!(is_schema_stanza(stanza), "{stanza:?} is schema-owned");
        }
    }

    #[test]
    fn supplied_text_is_never_schema_owned() {
        // An input-controlled key that is lexically a valid identifier, so a
        // shape-only predicate would accept the leak.
        for stanza in [
            "template_extension",
            "engagement.template_extension",
            "template_extension.revision",
            "claim template.template_extension",
            "*_suffix",
            "principal[*].groups",
            "recipe[-1]",
            "recipe[0]x",
            "[]",
            "[a]",
            "[0]x",
            "policy  rule",
            " readers",
            "readers/writers.readers",
            "",
            ".",
            "engagement..pass",
        ] {
            assert!(!is_schema_stanza(stanza), "{stanza:?} is not schema-owned");
        }
    }
}
