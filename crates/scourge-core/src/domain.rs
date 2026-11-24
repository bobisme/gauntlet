//! Domain values shared by the coordination store, verifier and interface.
//! Published and machine-facing shapes live in [`crate::wire`].

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    canonical::{self, JsonError, Sha256Digest},
    ids::{EngagementId, LeadId, RequestKey, RunId, SessionName, VerificationId, WireText},
    wire::{
        Artifact, Cleanup, Effect, Flow, OracleResult, Reproduction, RunFlag, RunState, SlotSource,
        Timestamp, VersionedDigest, VersionedId,
    },
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lead {
    pub id: LeadId,
    pub engagement: EngagementId,
    pub current_revision: u64,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeadRevision {
    pub lead_id: LeadId,
    pub revision: u64,
    pub text: WireText,
    pub class: Option<WireText>,
    pub slots: BTreeMap<WireText, Value>,
    /// A lead can propose policy. Authority stays with engagement admission.
    pub proposed_policy: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeadEventKind {
    Objection,
    Withdrawn,
    Duplicate { lead_id: LeadId },
    Deferred,
    Refuted,
    Blocked { code: WireText },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeadEvent {
    pub lead_id: LeadId,
    pub lead_revision: u64,
    pub kind: LeadEventKind,
    pub actor: WireText,
    pub reason: WireText,
    pub evidence: Vec<Artifact>,
    pub recorded_at: Timestamp,
}

/// A resolved slot refers to a registry entry by its exact identifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedSlot {
    pub value: WireText,
    pub source: SlotSource,
    pub supplied_by: WireText,
}

/// The session belongs to the bound instrument and is an opaque credential reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrincipalBinding {
    pub session: SessionName,
    pub verifier_session: Option<SessionName>,
    pub groups: Vec<WireText>,
    pub identity_probe: IdentityProbe,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityProbe {
    pub operation: WireText,
    pub subject: WireText,
}

/// Frozen inputs to a test. Per-execution data belongs to the run or its evidence.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Experiment {
    pub template: VersionedId,
    pub slots: BTreeMap<WireText, ResolvedSlot>,
    pub principals: BTreeMap<WireText, PrincipalBinding>,
    pub oracle: VersionedDigest,
    /// The exact resolved limits from the engagement and template.
    pub limits: BTreeMap<WireText, Value>,
}

impl Experiment {
    /// Freeze the test and bind exactly the bytes the evidence store will retain.
    pub fn freeze(&self) -> Result<(Vec<u8>, Sha256Digest), JsonError> {
        let bytes = canonical::to_vec(self)?;
        let digest = Sha256Digest::of(&bytes);
        Ok((bytes, digest))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Run {
    pub id: RunId,
    pub request_key: RequestKey,
    pub engagement: EngagementId,
    pub experiment_digest: Sha256Digest,
    pub steps: Vec<RunStep>,
    pub state: RunState,
    pub flags: Vec<RunFlag>,
    pub effects: Effect,
    pub oracle_result: Option<OracleResult>,
    pub reproduction: Reproduction,
    pub cleanup: Cleanup,
}

impl Run {
    /// Create a new execution identity. The store must load an existing run for
    /// a keyed retry before any code declares or dispatches another run.
    pub fn declare(engagement: EngagementId, experiment_digest: Sha256Digest) -> Self {
        Self {
            id: RunId::generate(),
            request_key: RequestKey::generate(),
            engagement,
            experiment_digest,
            steps: Vec::new(),
            state: RunState::Declared,
            flags: Vec::new(),
            effects: Effect::None,
            oracle_result: None,
            reproduction: Reproduction::NotAttempted,
            cleanup: Cleanup::NotRequired,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunStep {
    pub number: u64,
    pub step: WireText,
    pub request_digest: Sha256Digest,
    pub flow_id_floor: Option<u64>,
    pub instrument_reference: Option<WireText>,
    /// None until an outcome is recorded. Unknown records unresolved dispatch.
    pub effects: Option<Effect>,
    pub flows: Vec<Flow>,
}

/// Local locator for an already-linked verification record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationIndex {
    pub engagement: EngagementId,
    pub sequence: u64,
    pub record_id: VerificationId,
    pub run_id: RunId,
    pub lead_id: LeadId,
    pub record: Artifact,
}

impl canonical::sealed::Sealed for Lead {}
impl canonical::sealed::Sealed for LeadRevision {}
impl canonical::sealed::Sealed for LeadEvent {}
impl canonical::sealed::Sealed for Experiment {}
impl canonical::sealed::Sealed for Run {}
impl canonical::sealed::Sealed for RunStep {}
impl canonical::sealed::Sealed for VerificationIndex {}
