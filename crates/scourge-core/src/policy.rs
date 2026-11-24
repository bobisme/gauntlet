//! Operator-admitted expectations, evaluated separately from observations.

use serde::{Deserialize, Deserializer, Serialize, de};

use crate::{
    DeclarationError, DeclarationIssue as Issue,
    canonical::Sha256Digest,
    declaration::{self, issue, optional, optional_object, string_enum},
    engagement::{AccessAudience, Label, ManifestRevision, Prose, ResourceRef, VersionRef},
    wire::{Custody, Exposure, Timestamp, deserialize_object},
};

pub use crate::declaration::{ArtifactRef, OperatorRef};

string_enum! {
    pub enum AdmissionIdentity {
        Attributed => "attributed",
        Authenticated => "authenticated",
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Admission {
    pub actor: OperatorRef,
    #[serde(deserialize_with = "whole_second_utc")]
    pub recorded_at: Timestamp,
    pub identity: AdmissionIdentity,
}

fn whole_second_utc<'de, D: Deserializer<'de>>(input: D) -> Result<Timestamp, D::Error> {
    let timestamp = Timestamp::deserialize(input)?;
    if timestamp.as_str().len() != 20 {
        return Err(de::Error::custom("expected whole-second UTC timestamp"));
    }
    Ok(timestamp)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactReference {
    pub artifact_id: ArtifactRef,
    pub sha256: Sha256Digest,
}

string_enum! {
    enum SelectorKind {
        ByteRange => "byte_range",
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ByteRange {
    #[serde(rename = "type")]
    kind: SelectorKind,
    pub start: u64,
    pub end: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Citation {
    pub artifact_id: ArtifactRef,
    pub sha256: Sha256Digest,
    #[serde(deserialize_with = "deserialize_object")]
    pub selector: ByteRange,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RuleSource {
    Engagement {
        #[serde(deserialize_with = "deserialize_object")]
        revision: ArtifactReference,
        #[serde(deserialize_with = "deserialize_object")]
        admission: Admission,
    },
    Document {
        #[serde(deserialize_with = "deserialize_object")]
        citation: Citation,
        #[serde(deserialize_with = "deserialize_object")]
        admission: Admission,
    },
    Operator {
        #[serde(deserialize_with = "deserialize_object")]
        statement: ArtifactReference,
        #[serde(deserialize_with = "deserialize_object")]
        admission: Admission,
    },
    Inferred {
        #[serde(
            default,
            deserialize_with = "optional_object",
            skip_serializing_if = "Option::is_none"
        )]
        citation: Option<Citation>,
    },
}

impl RuleSource {
    pub fn admission(&self) -> Option<&Admission> {
        match self {
            Self::Engagement { admission, .. }
            | Self::Document { admission, .. }
            | Self::Operator { admission, .. } => Some(admission),
            Self::Inferred { .. } => None,
        }
    }

    fn citation(&self) -> Option<&Citation> {
        match self {
            Self::Document { citation, .. } => Some(citation),
            Self::Inferred { citation } => citation.as_ref(),
            Self::Engagement { .. } | Self::Operator { .. } => None,
        }
    }
}

string_enum! {
    enum SchemaVersion {
        V1 => "scourge.policy-rule.v1",
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Declaration {
    schema_version: SchemaVersion,
    property: Label,
    #[serde(
        default,
        deserialize_with = "optional",
        skip_serializing_if = "Option::is_none"
    )]
    target_version: Option<VersionRef>,
    #[serde(
        default,
        deserialize_with = "optional",
        skip_serializing_if = "Option::is_none"
    )]
    readers: Option<AccessAudience>,
    #[serde(
        default,
        deserialize_with = "optional",
        skip_serializing_if = "Option::is_none"
    )]
    writers: Option<AccessAudience>,
    #[serde(
        default,
        deserialize_with = "optional",
        skip_serializing_if = "Option::is_none"
    )]
    policy: Option<Prose>,
    #[serde(deserialize_with = "deserialize_object")]
    source: RuleSource,
}

/// A rule declaration. Provenance metadata is input until a trusted operator
/// action admits the rule against a particular manifest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct PolicyRule(Declaration);

impl PolicyRule {
    pub fn parse_json(input: &[u8]) -> Result<Self, DeclarationError> {
        let declaration: Declaration = declaration::parse_json(input, "policy rule")?;
        if declaration.readers.is_none() && declaration.writers.is_none() {
            return Err(issue("readers/writers", Issue::MissingAudience));
        }
        if declaration.source.admission().is_some() && declaration.target_version.is_none() {
            return Err(issue("target_version", Issue::MissingTargetVersion));
        }
        if declaration
            .source
            .citation()
            .is_some_and(|citation| citation.selector.end <= citation.selector.start)
        {
            return Err(issue("source.citation.selector", Issue::InvalidRange));
        }
        Ok(Self(declaration))
    }

    pub fn property(&self) -> &Label {
        &self.0.property
    }

    pub fn target_version(&self) -> Option<&VersionRef> {
        self.0.target_version.as_ref()
    }

    pub fn source(&self) -> &RuleSource {
        &self.0.source
    }

    pub fn audience(&self, access: Access) -> Option<AccessAudience> {
        match access {
            Access::Read => self.0.readers,
            Access::Write => self.0.writers,
        }
    }

    pub fn validate_against(&self, manifest: &ManifestRevision) -> Result<(), DeclarationError> {
        self.scoped_resource(manifest).map(|_| ())
    }

    fn scoped_resource<'a>(
        &self,
        manifest: &'a ManifestRevision,
    ) -> Result<&'a ResourceRef, DeclarationError> {
        let rule = &self.0;
        let property = manifest
            .properties()
            .get(&rule.property)
            .ok_or_else(|| issue("property", Issue::UndeclaredProperty))?;
        if rule.readers.is_some() && rule.readers != property.readers {
            return Err(issue("readers", Issue::ScopeMismatch));
        }
        if rule.writers.is_some() && rule.writers != property.writers {
            return Err(issue("writers", Issue::ScopeMismatch));
        }
        if rule
            .target_version
            .as_ref()
            .is_some_and(|version| version != manifest.target_version())
        {
            return Err(issue("target_version", Issue::ScopeMismatch));
        }
        if let RuleSource::Engagement { revision, .. } = &rule.source
            && &revision.sha256 != manifest.source_digest()
        {
            return Err(issue("source.revision.sha256", Issue::ScopeMismatch));
        }
        if manifest.settings().required_custody == Custody::Shared
            && let Some(admission) = rule.source.admission()
            && admission.identity != AdmissionIdentity::Attributed
        {
            return Err(issue("source.admission.identity", Issue::Unattributed));
        }
        Ok(&property.resource)
    }

    /// Record admission for this exact rule and revision. The caller supplies
    /// the trusted operator boundary that confirms the approval independently
    /// of the declaration's claimed source and actor.
    pub fn admit<'a>(
        &'a self,
        manifest: &'a ManifestRevision,
        operator_approved: impl FnOnce(&Self, &ManifestRevision) -> bool,
    ) -> Result<AdmittedPolicyRule<'a>, DeclarationError> {
        let resource = self.scoped_resource(manifest)?;
        if self.0.source.admission().is_none() {
            return Err(issue("source", Issue::Unadmitted));
        }
        if !operator_approved(self, manifest) {
            return Err(issue("source.admission", Issue::Unapproved));
        }
        Ok(AdmittedPolicyRule {
            rule: self,
            manifest,
            resource,
        })
    }
}

/// A rule whose scope was matched at the trusted operator boundary.
#[derive(Debug)]
pub struct AdmittedPolicyRule<'a> {
    rule: &'a PolicyRule,
    manifest: &'a ManifestRevision,
    resource: &'a ResourceRef,
}

impl<'a> AdmittedPolicyRule<'a> {
    pub fn declaration(&self) -> &'a PolicyRule {
        self.rule
    }

    pub fn manifest_digest(&self) -> &'a Sha256Digest {
        self.manifest.digest()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    Read,
    Write,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyDecision {
    Allowed,
    Denied,
    NoRule,
}

/// Scope and established identity labels for the observed access.
/// The authenticated non-owner is present only for a cross-principal exposure.
pub struct PolicyContext<'a> {
    pub manifest: &'a ManifestRevision,
    pub property: &'a Label,
    pub resource: &'a ResourceRef,
    pub target_version: &'a VersionRef,
    pub access: Access,
    pub owner: &'a Label,
    pub actor: Option<&'a Label>,
}

pub struct Policy;

impl Policy {
    pub fn allows(
        rule: Option<&AdmittedPolicyRule<'_>>,
        exposure: Exposure,
        principals: PolicyContext<'_>,
    ) -> PolicyDecision {
        use PolicyDecision::{Allowed, Denied, NoRule};

        let Some(rule) = rule else {
            return NoRule;
        };
        if rule.manifest_digest() != principals.manifest.digest()
            || rule.rule.property() != principals.property
            || rule.resource != principals.resource
            || rule.manifest.target_version() != principals.target_version
        {
            return NoRule;
        }
        let Some(audience) = rule.rule.audience(principals.access) else {
            return NoRule;
        };
        let Some(owner) = principals.manifest.principals().get(principals.owner) else {
            return NoRule;
        };
        let allowed = match (exposure, principals.actor) {
            (Exposure::Unauthenticated, None) => audience == AccessAudience::Public,
            (Exposure::CrossPrincipal, Some(actor)) if actor != principals.owner => {
                let Some(actor) = principals.manifest.principals().get(actor) else {
                    return NoRule;
                };
                match audience {
                    AccessAudience::Owner => false,
                    AccessAudience::Group => {
                        let owner_groups = owner.groups.as_deref().unwrap_or_default();
                        let actor_groups = actor.groups.as_deref().unwrap_or_default();
                        actor_groups
                            .iter()
                            .any(|group| owner_groups.contains(group))
                    }
                    AccessAudience::Authenticated | AccessAudience::Public => true,
                }
            }
            _ => return NoRule,
        };
        if allowed { Allowed } else { Denied }
    }
}
