//! The frozen out-of-class boundary (POR-12, M0-ADD-03).
//!
//! `web.private-object-read.v1` measures one proposition: a value planted in a
//! declared field of one fresh, run-owned object becomes readable by a
//! forbidden reader. A collection-disclosure echo and an object
//! existence/status difference are different propositions. They must not enter
//! this oracle, must not be promoted and must not become negative object-read
//! findings.
//!
//! [`dispatch`] is the read-only gate. A caller runs it before any target
//! traffic: for an out-of-class class it returns
//! [`Dispatch::OracleUnavailable`] with the supported classes, and the lead
//! stays a lead. This module cannot evaluate observations; that is the point.

use crate::verification::registry::{
    ORACLE_ID, ORACLE_UNAVAILABLE, SUPPORTED_CLAIM_CLASSES, UNSUPPORTED_SCOPE_NAMES,
};

/// A registered claim class from `scourge.claim-template.v1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ClaimClass {
    /// One freshly created object exposes planted field content to a forbidden
    /// reader. This is the only class this oracle measures.
    PrivateObjectRead,
    /// A response discloses other objects or recent values for a collection.
    CollectionDisclosure,
    /// A response discloses whether an object exists or its status, without
    /// protected field content.
    Existence,
    /// A forbidden principal changes a declared field. Ships in M2.
    StateChange,
}

impl ClaimClass {
    /// Every registered claim class.
    pub const REGISTERED: [Self; 4] = [
        Self::PrivateObjectRead,
        Self::CollectionDisclosure,
        Self::Existence,
        Self::StateChange,
    ];

    /// The registered `claim_class` name.
    pub const fn claim_class(self) -> &'static str {
        match self {
            Self::PrivateObjectRead => "web-authz/private-object-read",
            Self::CollectionDisclosure => "web-authz/collection-disclosure",
            Self::Existence => "web-authz/existence",
            Self::StateChange => "web-authz/state-change",
        }
    }

    /// The `oracle.scope` a template must declare for this class.
    pub const fn oracle_scope(self) -> &'static str {
        match self {
            Self::PrivateObjectRead => "object_read",
            Self::CollectionDisclosure => "collection_disclosure",
            Self::Existence => "existence",
            Self::StateChange => "state_change",
        }
    }

    /// Look up a registered claim class by its template name.
    pub fn from_claim_class(value: &str) -> Option<Self> {
        Self::REGISTERED
            .into_iter()
            .find(|class| class.claim_class() == value)
    }
}

/// The read-only answer a `verify --plan` gives for a claim class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Dispatch {
    /// The class is the shipped object-content read; the run may be planned.
    InClass(ClaimClass),
    /// The class is registered but this oracle does not measure it.
    OracleUnavailable {
        claim_class: ClaimClass,
        oracle: &'static str,
        result: &'static str,
        timing: &'static str,
        supported_claim_classes: &'static [ClaimClass],
        unsupported_scope_names: &'static [&'static str],
    },
    /// The class is not registered at all, so no template can match it.
    Unregistered,
}

impl Dispatch {
    /// The registered result code, `ORACLE_UNAVAILABLE`, when refused.
    pub fn result_code(&self) -> Option<&'static str> {
        match self {
            Self::OracleUnavailable { result, .. } => Some(result),
            Self::InClass(_) | Self::Unregistered => None,
        }
    }

    /// The claim classes this build does support, when refused.
    pub fn supported_claim_classes(&self) -> Option<&'static [ClaimClass]> {
        match self {
            Self::OracleUnavailable {
                supported_claim_classes,
                ..
            } => Some(supported_claim_classes),
            Self::InClass(_) | Self::Unregistered => None,
        }
    }
}

/// Decide, without sending anything, whether this oracle can plan a claim class.
pub fn dispatch(claim_class: &str) -> Dispatch {
    dispatch_class(
        claim_class,
        #[cfg(test)]
        true,
    )
}

#[cfg(test)]
pub(crate) fn dispatch_without_scope_check(claim_class: &str) -> Dispatch {
    dispatch_class(claim_class, false)
}

fn dispatch_class(claim_class: &str, #[cfg(test)] enforce_scope: bool) -> Dispatch {
    let Some(class) = ClaimClass::from_claim_class(claim_class) else {
        return Dispatch::Unregistered;
    };
    let in_class = SUPPORTED_CLAIM_CLASSES.contains(&class);
    #[cfg(test)]
    let in_class = in_class
        || (!enforce_scope
            && crate::verification::registry::UNSUPPORTED_CLAIM_CLASSES.contains(&class));
    if in_class {
        return Dispatch::InClass(class);
    }
    Dispatch::OracleUnavailable {
        claim_class: class,
        oracle: ORACLE_ID,
        result: ORACLE_UNAVAILABLE,
        timing: crate::verification::registry::DISPATCH_TIMING,
        supported_claim_classes: &SUPPORTED_CLAIM_CLASSES,
        unsupported_scope_names: &UNSUPPORTED_SCOPE_NAMES,
    }
}
