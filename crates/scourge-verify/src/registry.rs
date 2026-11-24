//! The compiled registration of `web.private-object-read.v1`.
//!
//! The frozen normative contract is
//! [`scourge.oracle-specifications.v1`](../../../docs/contracts/oracle-specifications.v1.json).
//! This module is the code copy of the parts the oracle depends on: the oracle
//! identity, the invalid precedence, the numbered checks, the published known
//! misses and the out-of-class dispatch boundary. Tests compare these constants
//! with the frozen file, so the code cannot drift from the contract without a
//! failing test (INV-09, plan §6.7).

use std::str::FromStr;

use scourge_core::{
    canonical::{self, Sha256Digest},
    wire::ReasonCode,
};

use crate::{
    observations::{FlowId, OBSERVATION_SCHEMA, OracleRef},
    scope::ClaimClass,
};

/// The oracle identity as written in a verification record (`oracle.id`).
pub const ORACLE_ID: &str = "web.private-object-read";

/// The oracle version as written in a verification record (`oracle.version`).
pub const ORACLE_VERSION: &str = "1";

/// The key of this oracle in the frozen contract registry.
pub const ORACLE_CONTRACT_KEY: &str = "web.private-object-read.v1";

/// The frozen contract this build implements.
pub const ORACLE_SPECIFICATION: &str =
    include_str!("../../../docs/contracts/oracle-specifications.v1.json");

/// One of the five frozen `invalid` reason codes, in precedence order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum InvalidReason {
    /// I1 and I2 resolve to the same stable subject.
    SameSubject,
    /// F1 does not contain the primary object canary.
    ObserverInvalid,
    /// F4 contains the primary object canary.
    CanaryNotSpecific,
    /// I3 or I4 differs from its initial subject.
    SessionDrift,
    /// A required flow is missing, incomplete, truncated, over the decode bounds
    /// or otherwise unable to carry a result.
    EvidenceIncomplete,
}

impl InvalidReason {
    /// The frozen `invalid_precedence` order.
    pub const PRECEDENCE: [Self; 5] = [
        Self::SameSubject,
        Self::ObserverInvalid,
        Self::CanaryNotSpecific,
        Self::SessionDrift,
        Self::EvidenceIncomplete,
    ];

    /// The frozen wire code.
    pub const fn code(self) -> &'static str {
        match self {
            Self::SameSubject => "SAME_SUBJECT",
            Self::ObserverInvalid => "OBSERVER_INVALID",
            Self::CanaryNotSpecific => "CANARY_NOT_SPECIFIC",
            Self::SessionDrift => "SESSION_DRIFT",
            Self::EvidenceIncomplete => "EVIDENCE_INCOMPLETE",
        }
    }

    /// The wire reason code carried by a verification record.
    pub fn reason_code(self) -> ReasonCode {
        ReasonCode::from_str(self.code()).expect("frozen reason codes use the registered form")
    }

    /// The position of this code in the frozen precedence order.
    pub fn precedence(self) -> usize {
        Self::PRECEDENCE
            .iter()
            .position(|candidate| *candidate == self)
            .expect("every code is in the precedence list")
    }
}

/// The kind of guarantee a numbered check contributes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckKind {
    Identity,
    Correlation,
    Control,
    Completeness,
    Scope,
}

/// One numbered mutation check (POR-01..POR-12).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NumberedCheck {
    pub id: &'static str,
    pub kind: CheckKind,
}

/// The frozen numbered checks in contract order.
pub const NUMBERED_CHECKS: [NumberedCheck; 12] = [
    NumberedCheck {
        id: "POR-01",
        kind: CheckKind::Identity,
    },
    NumberedCheck {
        id: "POR-02",
        kind: CheckKind::Identity,
    },
    NumberedCheck {
        id: "POR-03",
        kind: CheckKind::Correlation,
    },
    NumberedCheck {
        id: "POR-04",
        kind: CheckKind::Control,
    },
    NumberedCheck {
        id: "POR-05",
        kind: CheckKind::Control,
    },
    NumberedCheck {
        id: "POR-06",
        kind: CheckKind::Correlation,
    },
    NumberedCheck {
        id: "POR-07",
        kind: CheckKind::Control,
    },
    NumberedCheck {
        id: "POR-08",
        kind: CheckKind::Completeness,
    },
    NumberedCheck {
        id: "POR-09",
        kind: CheckKind::Completeness,
    },
    NumberedCheck {
        id: "POR-10",
        kind: CheckKind::Correlation,
    },
    NumberedCheck {
        id: "POR-11",
        kind: CheckKind::Control,
    },
    NumberedCheck {
        id: "POR-12",
        kind: CheckKind::Scope,
    },
];

/// The published known misses, verbatim from the frozen contract.
pub const KNOWN_MISSES: [&str; 7] = [
    "fields that carry no canary, including fields the owner cannot write",
    "exposure delayed past the observation window",
    "the mechanism behind a cross-principal cache exposure",
    "cross-account or tenant-wide state that reaches across accounts; separate verifier principals close the account-level route",
    "objects the verifier cannot create",
    "collection disclosures not specific to the requested object",
    "object existence or status disclosures without protected field content",
];

/// The read-only result a caller must produce before any target traffic for a
/// claim class this oracle does not measure.
pub const ORACLE_UNAVAILABLE: &str = "ORACLE_UNAVAILABLE";

/// The frozen `dispatch_timing` for the out-of-class boundary.
pub const DISPATCH_TIMING: &str = "before target traffic";

/// Claim classes this oracle measures, as registered claim-class names.
pub const SUPPORTED_CLAIM_CLASSES: [ClaimClass; 1] = [ClaimClass::PrivateObjectRead];

/// Claim classes the frozen scope boundary names as unsupported.
pub const UNSUPPORTED_CLAIM_CLASSES: [ClaimClass; 2] =
    [ClaimClass::CollectionDisclosure, ClaimClass::Existence];

/// The frozen scope-boundary names of the unsupported classes.
///
/// The contract spells the existence class `object_existence_or_status`, while
/// the claim-template registry spells the same proposition `existence`.
pub const UNSUPPORTED_SCOPE_NAMES: [&str; 2] =
    ["collection_disclosure", "object_existence_or_status"];

/// Whether a saved observation file names this oracle.
pub fn matches_observation_oracle(oracle: &OracleRef) -> bool {
    oracle.id.as_str() == ORACLE_ID && oracle.version.as_str() == ORACLE_VERSION
}

/// Whether a saved document declares the observation schema this build reads.
pub fn matches_observation_schema(schema: &str) -> bool {
    schema == OBSERVATION_SCHEMA
}

/// The digest of the frozen oracle entry this build implements.
///
/// A verification record names `oracle.digest`; recomputing it from the frozen
/// contract keeps the code and the record pointed at the same bytes.
pub fn oracle_digest() -> Sha256Digest {
    let mut contract =
        canonical::parse(ORACLE_SPECIFICATION.as_bytes()).expect("the frozen contract is JSON");
    let entry = contract
        .get_mut("oracles")
        .and_then(|oracles| oracles.get_mut(ORACLE_CONTRACT_KEY))
        .map(serde_json::Value::take)
        .expect("the frozen contract registers this oracle");
    Sha256Digest::of(&canonical::to_vec(&entry).expect("the frozen oracle entry is canonical"))
}

/// The flows this oracle requires, in frozen order.
pub const REQUIRED_FLOWS: [FlowId; 12] = FlowId::REQUIRED;
