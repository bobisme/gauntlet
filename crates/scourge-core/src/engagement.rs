//! Inert engagement declarations and content-addressed revisions.

use std::collections::{BTreeMap, HashSet};

use serde::{Deserialize, Serialize, de::IntoDeserializer};

use crate::{
    DeclarationError, DeclarationIssue as Issue,
    canonical::{self, JsonError, Sha256Digest},
    declaration::{
        self, check_safe_integer, issue, objects, optional, optional_object, string_enum,
        unique_nonempty,
    },
    wire::{ActionEffect, Custody, deserialize_object},
};

pub use crate::declaration::{
    GroupRef, Label, OperationRef, PassRef, ProjectRef, Prose, ResourceRef, SelectorRef,
    SessionRef, VersionRef,
};

string_enum! {
    pub enum AccessAudience {
        Owner => "owner",
        Group => "group",
        Authenticated => "authenticated",
        Public => "public",
    }
}

string_enum! {
    pub enum ReportAudience {
        Internal => "internal",
        ThirdParty => "third_party",
    }
}

string_enum! {
    pub enum RequiredEnforcement {
        None => "none",
        Egress => "egress",
    }
}

string_enum! {
    pub enum InstrumentKind {
        Teapot => "teapot",
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Instrument {
    pub kind: InstrumentKind,
    pub project: ProjectRef,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EngagementSettings {
    pub objective: Prose,
    #[serde(rename = "pass")]
    pub pass_ref: PassRef,
    #[serde(deserialize_with = "deserialize_object")]
    pub instrument: Instrument,
    #[serde(
        default,
        deserialize_with = "optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub target_version: Option<VersionRef>,
    pub required_custody: Custody,
    pub required_enforcement: RequiredEnforcement,
    pub allow_effects: Vec<ActionEffect>,
    #[serde(
        default,
        deserialize_with = "optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub max_verify_runs: Option<u64>,
    #[serde(
        default,
        deserialize_with = "optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub retest_miss_threshold: Option<f64>,
    pub audience: ReportAudience,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityProbe {
    pub operation: OperationRef,
    pub subject: SelectorRef,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Principal {
    pub session: SessionRef,
    #[serde(
        default,
        deserialize_with = "optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub verifier_session: Option<SessionRef>,
    #[serde(
        default,
        deserialize_with = "optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub groups: Option<Vec<GroupRef>>,
    #[serde(deserialize_with = "deserialize_object")]
    pub identity_probe: IdentityProbe,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WriteOperation {
    pub operation: OperationRef,
    pub fields: Vec<SelectorRef>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlantOperation {
    pub operation: OperationRef,
    pub id_from: SelectorRef,
    pub fields: Vec<SelectorRef>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Property {
    pub resource: ResourceRef,
    pub read: OperationRef,
    #[serde(
        default,
        deserialize_with = "optional_object",
        skip_serializing_if = "Option::is_none"
    )]
    pub write: Option<WriteOperation>,
    #[serde(deserialize_with = "deserialize_object")]
    pub plant: PlantOperation,
    pub remove: OperationRef,
    #[serde(
        default,
        deserialize_with = "optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub readers: Option<AccessAudience>,
    #[serde(
        default,
        deserialize_with = "optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub writers: Option<AccessAudience>,
    pub policy: Prose,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Declaration {
    schema_version: SchemaVersion,
    #[serde(deserialize_with = "deserialize_object")]
    engagement: EngagementSettings,
    #[serde(deserialize_with = "objects")]
    principal: BTreeMap<Label, Principal>,
    #[serde(deserialize_with = "objects")]
    property: BTreeMap<Label, Property>,
}

string_enum! {
    enum SchemaVersion {
        V1 => "scourge.engagement.v1",
    }
}

impl Declaration {
    fn validate(&self) -> Result<(), DeclarationError> {
        let settings = &self.engagement;
        if !unique_nonempty(&settings.allow_effects) {
            return Err(issue("engagement.allow_effects", Issue::InvalidEntries));
        }
        if settings.allow_effects.contains(&ActionEffect::None) {
            return Err(issue("engagement.allow_effects", Issue::InvalidShape));
        }
        if let Some(max) = settings.max_verify_runs {
            check_safe_integer(max, "engagement.max_verify_runs")?;
            if max == 0 {
                return Err(issue("engagement.max_verify_runs", Issue::InvalidNumber));
            }
        }
        if settings
            .retest_miss_threshold
            .is_some_and(|value| !(value > 0.0 && value < 1.0))
        {
            return Err(issue(
                "engagement.retest_miss_threshold",
                Issue::InvalidNumber,
            ));
        }
        if self.principal.is_empty() {
            return Err(issue("principal", Issue::InvalidEntries));
        }
        let mut sessions = HashSet::new();
        for principal in self.principal.values() {
            if !sessions.insert(&principal.session) {
                return Err(issue("principal.*.session", Issue::DuplicateSession));
            }
            if principal
                .verifier_session
                .as_ref()
                .is_some_and(|session| !sessions.insert(session))
            {
                return Err(issue(
                    "principal.*.verifier_session",
                    Issue::DuplicateSession,
                ));
            }
            if principal
                .groups
                .as_ref()
                .is_some_and(|groups| !unique_nonempty(groups))
            {
                return Err(issue("principal.*.groups", Issue::InvalidEntries));
            }
        }

        if self.property.is_empty() {
            return Err(issue("property", Issue::InvalidEntries));
        }
        for property in self.property.values() {
            if property.writers.is_some() && property.write.is_none() {
                return Err(issue("property.*.writers", Issue::WriteRequired));
            }
            if property
                .write
                .as_ref()
                .is_some_and(|write| !unique_nonempty(&write.fields))
            {
                return Err(issue("property.*.write.fields", Issue::InvalidEntries));
            }
            if !unique_nonempty(&property.plant.fields) {
                return Err(issue("property.*.plant.fields", Issue::InvalidEntries));
            }
        }
        Ok(())
    }

    fn target_version(&self) -> Result<&VersionRef, DeclarationError> {
        self.engagement
            .target_version
            .as_ref()
            .ok_or_else(|| issue("engagement.target_version", Issue::MissingTargetVersion))
    }
}

/// A well-formed declaration may omit the target version while being edited.
/// Only a complete draft can be accepted as a manifest revision.
#[derive(Clone, Debug, PartialEq)]
pub struct EngagementDraft {
    declaration: Declaration,
    source_digest: Sha256Digest,
}

impl EngagementDraft {
    pub fn parse_toml(input: &[u8]) -> Result<Self, DeclarationError> {
        Self::from_parsed(declaration::parse_toml(input, "engagement")?, input)
    }

    pub fn parse_json(input: &[u8]) -> Result<Self, DeclarationError> {
        Self::from_parsed(declaration::parse_json(input, "engagement")?, input)
    }

    fn from_parsed(declaration: Declaration, input: &[u8]) -> Result<Self, DeclarationError> {
        declaration.validate()?;
        Ok(Self {
            declaration,
            source_digest: Sha256Digest::of(input),
        })
    }

    /// A missing version is the defined partial-draft state.
    pub fn validate(&self) -> Result<(), DeclarationError> {
        self.declaration.target_version().map(|_| ())
    }

    pub fn settings(&self) -> &EngagementSettings {
        &self.declaration.engagement
    }

    pub fn principals(&self) -> &BTreeMap<Label, Principal> {
        &self.declaration.principal
    }

    pub fn properties(&self) -> &BTreeMap<Label, Property> {
        &self.declaration.property
    }

    pub fn accept(self, pass: PassPin<'_>) -> Result<ManifestRevision, DeclarationError> {
        ManifestRevision::freeze(self, pass, 1, None)
    }
}

/// The trusted pass resolver supplies the exact digest for this registered ID.
pub struct PassPin<'a> {
    pub reference: &'a PassRef,
    pub digest: &'a Sha256Digest,
}

/// A fresh verdict from the Hallpass adapter for the referenced pass.
/// A pinned Hallpass `pass-changed` can also mean revocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PassState<'a> {
    Active(&'a Sha256Digest),
    Changed,
    Expired,
    Revoked,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PassRefusal {
    #[error("engagement.pass: observation is for a different pass reference")]
    WrongReference,
    #[error("engagement.pass: pinned pass changed")]
    Changed,
    #[error("engagement.pass: pinned pass expired")]
    Expired,
    #[error("engagement.pass: pinned pass was revoked")]
    Revoked,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestContent {
    revision: u64,
    #[serde(
        default,
        deserialize_with = "optional",
        skip_serializing_if = "Option::is_none"
    )]
    parent: Option<Sha256Digest>,
    source_digest: Sha256Digest,
    pass_digest: Sha256Digest,
    #[serde(deserialize_with = "deserialize_object")]
    declaration: Declaration,
}

impl canonical::sealed::Sealed for ManifestContent {}

// A property declaration is a frozen input to the experiment digest, so its
// exact canonical bytes are hashed when a template binds it.
impl canonical::sealed::Sealed for Property {}

/// Append-only revision value. Persist its canonical bytes as an evidence
/// artifact and retain the digest with the local pointer.
#[derive(Clone, Debug, PartialEq)]
pub struct ManifestRevision {
    content: ManifestContent,
    bytes: Vec<u8>,
    digest: Sha256Digest,
}

impl ManifestRevision {
    fn freeze(
        draft: EngagementDraft,
        pass: PassPin<'_>,
        revision: u64,
        parent: Option<Sha256Digest>,
    ) -> Result<Self, DeclarationError> {
        draft.validate()?;
        if &draft.settings().pass_ref != pass.reference {
            return Err(issue("engagement.pass", Issue::ScopeMismatch));
        }
        let content = ManifestContent {
            revision,
            parent,
            source_digest: draft.source_digest,
            pass_digest: pass.digest.clone(),
            declaration: draft.declaration,
        };
        let bytes = canonical::to_vec(&content)
            .map_err(|error| issue("manifest", Issue::Canonical(error)))?;
        let digest = Sha256Digest::of(&bytes);
        Ok(Self {
            content,
            bytes,
            digest,
        })
    }

    /// Read retained bytes with the trusted digest, then check all local invariants.
    pub fn from_canonical_bytes(
        bytes: &[u8],
        expected: &Sha256Digest,
    ) -> Result<Self, DeclarationError> {
        if &Sha256Digest::of(bytes) != expected {
            return Err(issue(
                "manifest",
                Issue::Canonical(JsonError::DigestMismatch),
            ));
        }
        let value: serde_json::Value = canonical::from_canonical_slice(bytes)
            .map_err(|error| issue("manifest", Issue::Canonical(error)))?;
        let content: ManifestContent = declaration::decode(value.into_deserializer(), "manifest")?;
        if content.revision == 0 || (content.revision == 1) != content.parent.is_none() {
            return Err(issue("manifest.revision", Issue::RevisionLineage));
        }
        content.declaration.validate()?;
        content.declaration.target_version()?;
        Ok(Self {
            content,
            bytes: bytes.to_vec(),
            digest: expected.clone(),
        })
    }

    /// An amendment creates a child revision even when its source bytes match.
    pub fn amend(
        &self,
        draft: EngagementDraft,
        pass: PassPin<'_>,
    ) -> Result<Self, DeclarationError> {
        let revision = self
            .revision()
            .checked_add(1)
            .ok_or_else(|| issue("manifest.revision", Issue::RevisionLineage))?;
        Self::freeze(draft, pass, revision, Some(self.digest.clone()))
    }

    pub fn revision(&self) -> u64 {
        self.content.revision
    }

    pub fn parent_digest(&self) -> Option<&Sha256Digest> {
        self.content.parent.as_ref()
    }

    pub fn digest(&self) -> &Sha256Digest {
        &self.digest
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn source_digest(&self) -> &Sha256Digest {
        &self.content.source_digest
    }

    pub fn pass_digest(&self) -> &Sha256Digest {
        &self.content.pass_digest
    }

    pub fn settings(&self) -> &EngagementSettings {
        &self.content.declaration.engagement
    }

    pub fn target_version(&self) -> &VersionRef {
        self.content
            .declaration
            .target_version()
            .expect("accepted manifest has a target version")
    }

    pub fn principals(&self) -> &BTreeMap<Label, Principal> {
        &self.content.declaration.principal
    }

    pub fn properties(&self) -> &BTreeMap<Label, Property> {
        &self.content.declaration.property
    }

    /// Compare an adapter verdict before dispatching any new run.
    pub fn check_new_run(
        &self,
        reference: &PassRef,
        state: PassState<'_>,
    ) -> Result<(), PassRefusal> {
        if reference != &self.settings().pass_ref {
            return Err(PassRefusal::WrongReference);
        }
        match state {
            PassState::Active(digest) if digest == self.pass_digest() => Ok(()),
            PassState::Active(_) | PassState::Changed => Err(PassRefusal::Changed),
            PassState::Expired => Err(PassRefusal::Expired),
            PassState::Revoked => Err(PassRefusal::Revoked),
        }
    }
}
