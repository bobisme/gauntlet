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
    /// The operator-declared property selected by the lead, if any.
    pub property: Option<WireText>,
    pub slots: BTreeMap<WireText, Value>,
    /// A lead can propose policy. Authority stays with engagement admission.
    pub proposed_policy: Option<Value>,
    /// Where this unverified claim came from. This is provenance, never evidence.
    pub origin: LeadOrigin,
    /// The exact producer-owned selector used for an import.
    pub source_ref: Option<WireText>,
    /// A bounded endpoint label copied from the producer, never response content.
    pub endpoint: Option<WireText>,
    /// Producer-owned flow identifiers retained only as discovery hints.
    pub flow_ids: Vec<u64>,
    /// A producer's confidence label. Scourge records it as a claim only.
    pub producer_confidence: Option<WireText>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeadOrigin {
    Local,
    Teapot,
}

impl LeadOrigin {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Teapot => "teapot",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeadEventKind {
    Set {
        class_changed: bool,
        slots_changed: bool,
    },
    Objection,
    Withdrawn,
    Duplicate {
        lead_id: LeadId,
    },
    Deferred,
    Refuted,
    Blocked {
        code: WireText,
    },
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

    /// Effects established by durable outcomes, including uncertainty from
    /// any step intent that has no established outcome.
    pub fn known_effects(&self) -> Effect {
        if self.steps.is_empty() || self.effects == Effect::Unknown {
            return self.effects;
        }
        let mut effects = Effect::None;
        for step in &self.steps {
            match step.effects {
                None | Some(Effect::Unknown) => return Effect::Unknown,
                Some(Effect::Observed) if effects == Effect::None => effects = Effect::Observed,
                Some(Effect::None | Effect::Observed) => {}
            }
        }
        effects
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

/// Which freshly planted object in one private-object-read round owns a
/// cleanup obligation. These labels are compiled verifier vocabulary, not a
/// target name supplied by a lead or response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CleanupObjectRole {
    Primary,
    Control,
}

/// What the retained plant response established about creation. Only
/// `Established` carries deletion authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CleanupOwnership {
    Pending,
    Established,
    NotCreated,
    Unknown,
}

/// Exact outcome for one object. `Owed` means no removal was attempted;
/// `InFlight` is the durable boundary immediately before dispatch; `Unknown`
/// means an attempted removal has an unresolved network effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CleanupObjectOutcome {
    Owed,
    InFlight,
    NotRequired,
    Complete,
    Failed,
    Unknown,
}

/// Durable cleanup provenance for one object in one run. The plant binding
/// exists before the plant can be dispatched. Cleanup intent/outcome fields
/// remain empty until an established object is eligible for removal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunCleanup {
    pub round: u64,
    pub object: CleanupObjectRole,
    pub plant_step: u64,
    pub plant_request_digest: Sha256Digest,
    pub object_id: Option<WireText>,
    pub ownership: CleanupOwnership,
    pub cleanup_step: Option<u64>,
    pub cleanup_request_digest: Option<Sha256Digest>,
    pub flow_id_floor: Option<u64>,
    pub instrument_reference: Option<WireText>,
    pub effects: Option<Effect>,
    pub response_status: Option<u16>,
    pub flows: Vec<Flow>,
    pub outcome: CleanupObjectOutcome,
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
impl canonical::sealed::Sealed for RunCleanup {}
impl canonical::sealed::Sealed for VerificationIndex {}
