//! Compiled request grammar for the shipped M1 fixture pack.
//!
//! Engagements and frozen experiments deliberately contain inert registered
//! references, never methods, routes, bodies, or extractors.  This module is
//! the typed half of that contract.  It recognizes only the operation and
//! selector tuples compiled into this build and checks the exact property
//! digest before returning executable request grammar.

use crate::{
    canonical::{self, Sha256Digest},
    engagement::{ManifestRevision, Property},
    ids::{SessionName, WireText},
    template::{BoundPrincipal, FrozenExperiment},
};

pub(crate) const REGISTRY_ID: &str = "scourge.fixture-operations.v1";
pub(crate) const ANONYMOUS_SESSION: &str = "scourge_anonymous";
pub(crate) const IDENTITY_PATH: &str = "/app/api/me";
pub(crate) const IDENTITY_OPERATION: &str = "operation.identity.probe";
pub(crate) const IDENTITY_SELECTOR: &str = "selector.identity.subject";
pub(crate) const IDENTITY_SUBJECT_FIELD: &str = "id";
pub(crate) const OBJECT_ID_FIELD: &str = "id";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FieldSpec {
    pub selector: &'static str,
    pub json_name: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ResourceSpec {
    resource: &'static str,
    read: &'static str,
    plant: &'static str,
    remove: &'static str,
    id_from: &'static str,
    fields: &'static [FieldSpec],
    collection: &'static str,
    macro_name: &'static str,
}

const NOTE: &[FieldSpec] = &[FieldSpec {
    selector: "note",
    json_name: "note",
}];
const NOTE_DETAIL: &[FieldSpec] = &[
    FieldSpec {
        selector: "note",
        json_name: "note",
    },
    FieldSpec {
        selector: "detail",
        json_name: "detail",
    },
];

macro_rules! resource {
    ($name:literal, $path:literal, $macro:literal, $fields:expr) => {
        ResourceSpec {
            resource: concat!("resource.", $name),
            read: concat!("operation.", $name, ".read"),
            plant: concat!("operation.", $name, ".create"),
            remove: concat!("operation.", $name, ".delete"),
            id_from: concat!("selector.", $name, ".response.id"),
            fields: $fields,
            collection: concat!("/app/api/", $path),
            macro_name: $macro,
        }
    };
}

const RESOURCES: &[ResourceSpec] = &[
    resource!("orders", "orders", "create-order", NOTE_DETAIL),
    resource!("invoices", "invoices", "create-invoice", NOTE),
    resource!("tenant-notes", "tenant-notes", "create-tenant-note", NOTE),
    resource!("bulletins", "bulletins", "create-bulletin", NOTE),
    resource!("catalog", "catalog", "create-catalog-entry", NOTE),
    resource!(
        "private-reports",
        "private-reports",
        "create-private-report",
        NOTE_DETAIL
    ),
    resource!(
        "cached-reports",
        "cached-reports",
        "create-cached-report",
        NOTE_DETAIL
    ),
    resource!(
        "login-reports",
        "login-reports",
        "create-login-report",
        NOTE
    ),
    resource!(
        "stale-reports",
        "stale-reports",
        "create-stale-report",
        NOTE
    ),
    resource!(
        "forbidden-reports",
        "forbidden-reports",
        "create-forbidden-report",
        NOTE
    ),
    resource!("echo-reports", "echo-reports", "create-echo-report", NOTE),
    resource!(
        "expiring-reports",
        "expiring-reports",
        "create-expiring-report",
        NOTE
    ),
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DispatchPrincipal {
    Owner,
    Other,
    Anonymous,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DispatchSpec {
    pub flow: &'static str,
    pub principal: DispatchPrincipal,
    pub actions: u64,
}

/// The exact per-round action cardinality used by both admission and execution.
/// An authenticated Teapot send reserves request+login+retry; anonymous sends
/// reserve only their request.
pub(crate) const ROUND_DISPATCHES: &[DispatchSpec] = &[
    DispatchSpec {
        flow: "I1",
        principal: DispatchPrincipal::Owner,
        actions: 1,
    },
    DispatchSpec {
        flow: "I2",
        principal: DispatchPrincipal::Other,
        actions: 1,
    },
    DispatchSpec {
        flow: "P",
        principal: DispatchPrincipal::Owner,
        actions: 1,
    },
    DispatchSpec {
        flow: "P2",
        principal: DispatchPrincipal::Owner,
        actions: 1,
    },
    DispatchSpec {
        flow: "F0",
        principal: DispatchPrincipal::Anonymous,
        actions: 1,
    },
    DispatchSpec {
        flow: "F1",
        principal: DispatchPrincipal::Owner,
        actions: 1,
    },
    DispatchSpec {
        flow: "F2",
        principal: DispatchPrincipal::Other,
        actions: 1,
    },
    DispatchSpec {
        flow: "F3",
        principal: DispatchPrincipal::Anonymous,
        actions: 1,
    },
    DispatchSpec {
        flow: "F4",
        principal: DispatchPrincipal::Other,
        actions: 1,
    },
    DispatchSpec {
        flow: "I3",
        principal: DispatchPrincipal::Owner,
        actions: 1,
    },
    DispatchSpec {
        flow: "I4",
        principal: DispatchPrincipal::Other,
        actions: 1,
    },
    DispatchSpec {
        flow: "C",
        principal: DispatchPrincipal::Owner,
        actions: 2,
    },
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RegisteredOperations {
    pub registry_digest: Sha256Digest,
    pub owner_session: SessionName,
    pub other_session: SessionName,
    pub anonymous_session: SessionName,
    pub collection: &'static str,
    /// Passive Teapot dry-run probe only. Execution never replays this mutable macro.
    pub macro_name: WireText,
    pub fields: Vec<FieldSpec>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum RegistryError {
    #[error("the frozen experiment is not executable by the compiled operation registry")]
    Unsupported,
    #[error("the retained engagement does not match the frozen experiment")]
    EngagementMismatch,
    #[error("the frozen principal session cannot be used by Teapot")]
    Session,
}

impl RegisteredOperations {
    pub fn resolve(
        experiment: &FrozenExperiment,
        manifest: &ManifestRevision,
    ) -> Result<Self, RegistryError> {
        if experiment.engagement.revision != manifest.revision()
            || experiment.engagement.digest != *manifest.digest()
        {
            return Err(RegistryError::EngagementMismatch);
        }
        let binding = experiment
            .property
            .as_ref()
            .ok_or(RegistryError::Unsupported)?;
        let property = manifest
            .properties()
            .get(&binding.label)
            .ok_or(RegistryError::EngagementMismatch)?;
        let property_bytes = canonical::to_vec(property).map_err(|_| RegistryError::Unsupported)?;
        if property.resource != binding.resource
            || Sha256Digest::of(&property_bytes) != binding.digest
        {
            return Err(RegistryError::EngagementMismatch);
        }
        let spec = RESOURCES
            .iter()
            .find(|spec| spec.resource == property.resource.as_str())
            .ok_or(RegistryError::Unsupported)?;
        validate_property(property, spec)?;
        validate_slot(experiment, "read", spec.read)?;
        validate_slot(experiment, "plant", spec.plant)?;
        validate_slot(experiment, "remove", spec.remove)?;
        let owner = principal(experiment, "owner")?;
        let other = principal(experiment, "other")?;
        validate_probe(owner)?;
        validate_probe(other)?;

        Ok(Self {
            registry_digest: registry_digest(),
            owner_session: instrument_session(session(owner))?,
            other_session: instrument_session(session(other))?,
            anonymous_session: ANONYMOUS_SESSION
                .parse()
                .map_err(|_| RegistryError::Session)?,
            collection: spec.collection,
            macro_name: spec
                .macro_name
                .parse()
                .map_err(|_| RegistryError::Unsupported)?,
            fields: spec.fields.to_vec(),
        })
    }

    pub fn dispatch_spec(&self, flow: &str) -> Option<DispatchSpec> {
        ROUND_DISPATCHES
            .iter()
            .copied()
            .find(|spec| spec.flow == flow)
    }

    pub fn session(&self, principal: DispatchPrincipal) -> &SessionName {
        match principal {
            DispatchPrincipal::Owner => &self.owner_session,
            DispatchPrincipal::Other => &self.other_session,
            DispatchPrincipal::Anonymous => &self.anonymous_session,
        }
    }

    pub fn request_bound(&self, round_count: u64) -> Option<(u64, u64)> {
        let per_round = ROUND_DISPATCHES.iter().try_fold(0_u64, |total, spec| {
            let per_action = match spec.principal {
                DispatchPrincipal::Owner | DispatchPrincipal::Other => 3_u64,
                DispatchPrincipal::Anonymous => 1_u64,
            };
            total.checked_add(spec.actions.checked_mul(per_action)?)
        })?;
        per_round
            .checked_mul(round_count)
            .map(|required| (per_round, required))
    }
}

fn validate_property(property: &Property, spec: &ResourceSpec) -> Result<(), RegistryError> {
    let expected_fields = spec
        .fields
        .iter()
        .map(|field| {
            format!(
                "selector.{}.{}",
                resource_suffix(spec.resource),
                field.selector
            )
        })
        .collect::<Vec<_>>();
    if property.read.as_str() != spec.read
        || property.plant.operation.as_str() != spec.plant
        || property.remove.as_str() != spec.remove
        || property.plant.id_from.as_str() != spec.id_from
        || property.plant.fields.len() != expected_fields.len()
        || property
            .plant
            .fields
            .iter()
            .zip(expected_fields)
            .any(|(actual, expected)| actual.as_str() != expected)
    {
        return Err(RegistryError::Unsupported);
    }
    Ok(())
}

fn resource_suffix(resource: &str) -> &str {
    resource
        .strip_prefix("resource.")
        .expect("compiled resource has a prefix")
}

fn validate_slot(
    experiment: &FrozenExperiment,
    name: &str,
    expected: &str,
) -> Result<(), RegistryError> {
    let binding = experiment
        .slots
        .iter()
        .find(|(slot, _)| slot.as_str() == name)
        .map(|(_, binding)| binding)
        .ok_or(RegistryError::Unsupported)?;
    (binding.value.as_str() == expected)
        .then_some(())
        .ok_or(RegistryError::Unsupported)
}

fn principal<'a>(
    experiment: &'a FrozenExperiment,
    name: &str,
) -> Result<&'a BoundPrincipal, RegistryError> {
    experiment
        .principals
        .iter()
        .find(|(slot, _)| slot.as_str() == name)
        .map(|(_, principal)| principal)
        .ok_or(RegistryError::Unsupported)
}

fn validate_probe(principal: &BoundPrincipal) -> Result<(), RegistryError> {
    if principal.identity_probe.operation.as_str() != IDENTITY_OPERATION
        || principal.identity_probe.subject.as_str() != IDENTITY_SELECTOR
    {
        return Err(RegistryError::Unsupported);
    }
    Ok(())
}

fn session(principal: &BoundPrincipal) -> &str {
    principal
        .verifier_session
        .as_ref()
        .unwrap_or(&principal.session)
        .as_str()
}

pub(crate) fn instrument_session(reference: &str) -> Result<SessionName, RegistryError> {
    let native = reference
        .strip_prefix("session.")
        .ok_or(RegistryError::Session)?
        .replace('.', "_");
    native.parse().map_err(|_| RegistryError::Session)
}

fn registry_digest() -> Sha256Digest {
    let declarations = RESOURCES
        .iter()
        .map(|spec| {
            let fields = spec
                .fields
                .iter()
                .map(|field| format!("{}={}", field.selector, field.json_name))
                .collect::<Vec<_>>()
                .join(",");
            format!(
                "{}|{}|{}|{}|{}|{}|{}|{}",
                spec.resource,
                spec.read,
                spec.plant,
                spec.remove,
                spec.id_from,
                spec.collection,
                spec.macro_name,
                fields
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    Sha256Digest::of(
        format!(
            "{REGISTRY_ID}\nanonymous={ANONYMOUS_SESSION}\nidentity={IDENTITY_OPERATION}|{IDENTITY_SELECTOR}|{IDENTITY_PATH}|{IDENTITY_SUBJECT_FIELD}\nobject-id={OBJECT_ID_FIELD}\ndispatch={ROUND_DISPATCHES:?}\n{declarations}"
        )
        .as_bytes(),
    )
}
