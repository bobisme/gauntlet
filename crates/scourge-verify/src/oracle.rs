//! The pure `web.private-object-read.v1` predicate.
//!
//! [`evaluate`] consumes the verifier's typed saved observations for one round
//! and returns `true`, `false`, `invalid` with reason codes, or `error`. It
//! performs no I/O, reads no credential, reads no policy rule and never sees an
//! HTTP status (INV-08). Its result is measurement, not authorization: the
//! property's admitted rule decides whether an exposure was allowed.
//!
//! The frozen contract is
//! [`scourge.oracle-specifications.v1`](../../../docs/contracts/oracle-specifications.v1.json)
//! and the explanatory prose is `notes/plan.md` §6.5.
//!
//! The result is `true` when setup is valid - which already requires at least
//! one planted primary canary in F1 and no primary canary in F4 - and at least
//! one planted primary canary is present in F0, F2 or F3. Exposure is
//! `unauthenticated` when a primary canary is present in F0 or F3 and
//! `cross_principal` otherwise. `after_owner_read` is true when no primary
//! canary occurs in F0 and at least one occurs in F3. The result is `false` only
//! when setup is valid and *every* planted primary canary is absent from all
//! three treatment reads. Every frozen invalid reason is `invalid`, never
//! `false`. An instrument or oracle crash is `error`, never `true` and never
//! `false`.
//!
//! Canaries are planted per declared field (POR-10), so every planted primary
//! canary is matched independently and a crossed field is reported by itself. A
//! field whose canary a treatment read contains is reported even when the owner
//! read F1 did not contain that field's canary: dropping it would be a silent
//! false negative and would downgrade `unauthenticated` to `cross_principal`.
//! F1's own gate (POR-04, `OBSERVER_INVALID`) is round-level and unchanged: at
//! least one primary canary must appear in the owner read before any treatment
//! can support a result.

use std::{
    collections::{BTreeMap, BTreeSet},
    panic::{AssertUnwindSafe, catch_unwind},
};

use scourge_core::wire::{Completeness, Exposure, OracleResult, ReasonCode};

use crate::{
    decode::{DecodeError, DecoderName, decode},
    observations::{
        Canary, CleanupDetail, FieldName, FlowId, ObjectKey, PlantedCanary, SavedFlow,
        SavedObservations, Subject,
    },
    registry::{self, InvalidReason},
};

#[cfg(test)]
mod mutation;

#[cfg(test)]
use mutation::{Check, Mutation};

// Compile only the original expression into the library. The unit-test
// build can replace one check at a time while using the same evaluator.
macro_rules! with_check {
    ($mutation:ident, $check:ident, $original:expr, $replacement:expr) => {{
        #[cfg(test)]
        {
            if $mutation.is_some_and(|mutation| mutation.check == Check::$check) {
                $replacement
            } else {
                $original
            }
        }
        #[cfg(not(test))]
        {
            $original
        }
    }};
}

macro_rules! retain_check {
    ($mutation:ident, $check:ident, $condition:expr) => {
        with_check!($mutation, $check, $condition, false)
    };
}

/// One of the four frozen result values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Verdict {
    True,
    False,
    Invalid,
    Error,
}

impl Verdict {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::True => "true",
            Self::False => "false",
            Self::Invalid => "invalid",
            Self::Error => "error",
        }
    }

    /// The wire value a verification record carries.
    pub const fn oracle_result(self) -> OracleResult {
        match self {
            Self::True => OracleResult::True,
            Self::False => OracleResult::False,
            Self::Invalid => OracleResult::Invalid,
            Self::Error => OracleResult::Error,
        }
    }
}

impl From<Verdict> for OracleResult {
    fn from(value: Verdict) -> Self {
        value.oracle_result()
    }
}

/// Why the oracle produced no verdict at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultCause {
    /// The instrument could not be run or its session disappeared.
    InstrumentUnavailable,
    /// The oracle itself failed while evaluating.
    OraclePanic,
    /// The saved observations name an oracle version this build cannot evaluate.
    UnregisteredOracleVersion,
    /// The saved observations declare a document schema this build cannot read.
    UnregisteredObservationSchema,
}

impl FaultCause {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InstrumentUnavailable => "INSTRUMENT_UNAVAILABLE",
            Self::OraclePanic => "ORACLE_PANIC",
            Self::UnregisteredOracleVersion => "UNREGISTERED_ORACLE_VERSION",
            Self::UnregisteredObservationSchema => "UNREGISTERED_OBSERVATION_SCHEMA",
        }
    }
}

/// The specific evidence fault behind `EVIDENCE_INCOMPLETE`.
///
/// The frozen reason-code list stays closed; this detail explains which flow
/// could not carry a result and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IncompleteCause {
    /// A required flow was not saved at all.
    MissingFlow(FlowId),
    /// A flow was saved more than once.
    DuplicateFlow(FlowId),
    /// The flow belongs to another run.
    NotBoundToRun { flow: FlowId },
    /// The flow recorded an incomplete, missing or corrupt acquisition.
    FlowNotComplete {
        flow: FlowId,
        recorded: Completeness,
    },
    /// The flow carries the wrong observation shape for its step.
    FlowShapeMismatch { flow: FlowId },
    /// The original bytes are not retained in the evidence store (INV-27).
    OriginalNotRetained { flow: FlowId },
    /// The named decoder does not match the decoding that was applied.
    DecoderNotNamed {
        flow: FlowId,
        recorded: Option<DecoderName>,
        expected: Option<DecoderName>,
    },
    /// The saved body could not be decoded within the frozen bounds.
    Decode { flow: FlowId, error: DecodeError },
    /// An identity probe saved no stable subject.
    SubjectMissing { flow: FlowId },
    /// Flows were not acquired in the frozen order (POR-07).
    FlowOrder { flow: FlowId, after: FlowId },
    /// The plant response did not establish that this run created the object.
    PlantOwnershipUnestablished { flow: FlowId },
    /// A plant wrote no canary into any declared field.
    PlantCanaryMissing { flow: FlowId },
    /// A plant wrote two canaries into one declared field (POR-10).
    PlantFieldDuplicated { flow: FlowId, field: FieldName },
    /// A plant wrote the same canary into two fields.
    PlantCanaryNotDistinct { flow: FlowId },
    /// The primary and control plants share a canary value (POR-03).
    PlantCanaryNotDistinctAcrossObjects,
    /// The primary and control plants resolved to one object (POR-03).
    PlantObjectsNotDistinct,
    /// The cleanup flow claims removals it also records as not attempted.
    CleanupContradiction { flow: FlowId },
}

/// What cleanup did, recorded separately from the verdict (POR-11).
///
/// Cleanup never changes the result. An unauthorized removal is reported here
/// because the frozen reason-code list has no cleanup code; it is an
/// attribution failure the operator has to see, not evidence about exposure.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CleanupRecord {
    /// Whether the cleanup flow ran.
    pub attempted: bool,
    /// Objects removed with plant-established run ownership.
    pub authorized: Vec<ObjectKey>,
    /// Objects the run attempted to remove without established ownership.
    pub unauthorized: Vec<ObjectKey>,
    /// Run-owned objects the run created and did not remove.
    pub owed: Vec<ObjectKey>,
    /// Plant flows that established no run ownership, so nothing may be
    /// deleted on their behalf (INV-40).
    pub uncertain_plants: Vec<FlowId>,
    /// The cleanup observation claimed removals while also saying no cleanup
    /// was attempted, or supplied duplicate cleanup rows.  This is operator
    /// evidence, not evidence about the exposure predicate.
    pub contradictory: bool,
}

/// The oracle's answer for one round.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evaluation {
    /// `true`, `false`, `invalid` or `error`.
    pub result: Verdict,
    /// Present only for `true`.
    pub exposure: Option<Exposure>,
    /// Derived only when a verdict was produced: `Some(true)` when no primary
    /// canary occurs in F0 and at least one occurs in F3, `Some(false)`
    /// otherwise, `None` for `invalid` and `error`.
    pub after_owner_read: Option<bool>,
    /// Every declared field whose canary crossed, in field order (POR-10).
    pub fields_crossed: Vec<FieldName>,
    /// Frozen reason codes in precedence order; empty for `true`, `false` and
    /// `error`.
    pub reason_codes: Vec<ReasonCode>,
    /// Evidence detail behind `EVIDENCE_INCOMPLETE`.
    pub evidence: Vec<IncompleteCause>,
    /// Cleanup, recorded separately.
    pub cleanup: CleanupRecord,
    /// The named decoders that were actually applied, in name order.
    pub decoders: Vec<DecoderName>,
    /// Present only for `error`.
    pub fault: Option<FaultCause>,
}

impl Evaluation {
    /// A pure `error` outcome. It is never `true` and never `false`.
    pub fn fault(cause: FaultCause) -> Self {
        Self {
            result: Verdict::Error,
            exposure: None,
            after_owner_read: None,
            fields_crossed: Vec::new(),
            reason_codes: Vec::new(),
            evidence: Vec::new(),
            cleanup: CleanupRecord::default(),
            decoders: Vec::new(),
            fault: Some(cause),
        }
    }

    /// Whether the round produced a verdict, as opposed to `invalid`/`error`.
    pub fn is_conclusive(&self) -> bool {
        matches!(self.result, Verdict::True | Verdict::False)
    }

    /// Whether the round measured an exposure.
    pub fn is_true(&self) -> bool {
        self.result == Verdict::True
    }

    /// The first reason code in frozen precedence order, if any.
    pub fn primary_reason(&self) -> Option<&ReasonCode> {
        self.reason_codes.first()
    }
}

/// Evaluate one round of saved observations.
///
/// The signature is the contract's: observations in, result out. There is no
/// status argument and no policy argument (INV-08). A panic inside the oracle
/// is `error`, never a verdict.
///
/// What the predicate cannot see, and does not claim: whether a canary was
/// minted by this run (the verifier's obligation), whether the target really
/// stored the planted value, and any effect outside the twelve recorded flows.
/// Those limits are the published known misses in [`registry::KNOWN_MISSES`].
pub fn evaluate(observations: &SavedObservations) -> Evaluation {
    supervise(|| {
        try_evaluate(
            observations,
            #[cfg(test)]
            None,
        )
    })
}

/// Run the oracle body with the crash guard `evaluate` uses.
///
/// A panic in the instrument or the oracle is `error`; it is never `true` and
/// never `false` (F-14). This is public so a crash path can be exercised
/// without making the oracle able to panic on valid evidence.
pub fn supervise<F: FnOnce() -> Evaluation>(body: F) -> Evaluation {
    match catch_unwind(AssertUnwindSafe(body)) {
        Ok(evaluation) => evaluation,
        Err(_) => Evaluation::fault(FaultCause::OraclePanic),
    }
}

fn try_evaluate(
    observations: &SavedObservations,
    #[cfg(test)] mutation: Option<&Mutation<'_>>,
) -> Evaluation {
    if !registry::matches_observation_oracle(&observations.oracle) {
        return Evaluation::fault(FaultCause::UnregisteredOracleVersion);
    }
    if !registry::matches_observation_schema(observations.schema.as_str()) {
        return Evaluation::fault(FaultCause::UnregisteredObservationSchema);
    }

    let mut causes: Vec<IncompleteCause> = Vec::new();
    let mut cleanup_contradictory = false;
    let mut present: BTreeMap<FlowId, &SavedFlow> = BTreeMap::new();
    for flow in &observations.flows {
        if present.insert(flow.flow, flow).is_some() {
            if flow.flow == FlowId::C {
                cleanup_contradictory = true;
            } else if retain_check!(mutation, FlowCompleteness, true) {
                causes.push(IncompleteCause::DuplicateFlow(flow.flow));
            }
        }
    }
    for flow in FlowId::VERDICT_REQUIRED {
        if retain_check!(mutation, FlowCompleteness, !present.contains_key(&flow)) {
            causes.push(IncompleteCause::MissingFlow(flow));
        }
    }

    let mut bodies: BTreeMap<FlowId, Vec<u8>> = BTreeMap::new();
    let mut subjects: BTreeMap<FlowId, Subject> = BTreeMap::new();
    let mut decoders: BTreeSet<DecoderName> = BTreeSet::new();
    let mut established: BTreeSet<ObjectKey> = BTreeSet::new();

    // Per-flow integrity, in frozen flow order.
    for (&flow, saved) in &present {
        if flow == FlowId::C {
            if saved.run != observations.run
                || saved.completeness != Completeness::Complete
                || !shape_matches(flow, saved)
                || saved.original.is_none()
                || saved.decoder != saved.decoding.decoder_name()
            {
                continue;
            }
            if let Ok(decoded) = decode(&saved.body, saved.decoding, observations.limits) {
                if let Some(name) = decoded.decoder {
                    decoders.insert(name);
                }
                bodies.insert(flow, decoded.bytes);
            }
            continue;
        }
        if retain_check!(mutation, FlowCompleteness, saved.run != observations.run) {
            causes.push(IncompleteCause::NotBoundToRun { flow });
            continue;
        }
        if retain_check!(
            mutation,
            FlowCompleteness,
            saved.completeness != Completeness::Complete
        ) {
            causes.push(IncompleteCause::FlowNotComplete {
                flow,
                recorded: saved.completeness,
            });
            continue;
        }
        if retain_check!(mutation, FlowCompleteness, !shape_matches(flow, saved)) {
            causes.push(IncompleteCause::FlowShapeMismatch { flow });
            continue;
        }
        if retain_check!(mutation, BoundedDecode, saved.original.is_none()) {
            causes.push(IncompleteCause::OriginalNotRetained { flow });
            continue;
        }
        let expected = saved.decoding.decoder_name();
        if retain_check!(mutation, BoundedDecode, saved.decoder != expected) {
            causes.push(IncompleteCause::DecoderNotNamed {
                flow,
                recorded: saved.decoder.clone(),
                expected,
            });
            continue;
        }
        let decoded = with_check!(
            mutation,
            BoundedDecode,
            decode(&saved.body, saved.decoding, observations.limits),
            Ok(crate::DecodedBody {
                bytes: saved.body.clone(),
                decoder: None,
                coded_bytes: saved.body.len() as u64,
                decoded_bytes: saved.body.len() as u64,
            })
        );
        match decoded {
            Ok(decoded) => {
                if let Some(name) = decoded.decoder {
                    decoders.insert(name);
                }
                bodies.insert(flow, decoded.bytes);
            }
            Err(error) => {
                causes.push(IncompleteCause::Decode { flow, error });
                continue;
            }
        }
        if flow.is_identity() {
            match &saved.subject {
                Some(subject) => {
                    subjects.insert(flow, subject.clone());
                }
                None if retain_check!(mutation, FlowCompleteness, true) => {
                    causes.push(IncompleteCause::SubjectMissing { flow });
                }
                None => {}
            }
        }
        if flow.is_plant()
            && let Some(object) = saved.plant.as_ref().and_then(|plant| plant.object.as_ref())
        {
            established.insert(object.clone());
        }
    }

    // POR-03, POR-10: each plant owns a distinct object and carries its own
    // fresh, distinct per-field canaries.
    let mut primary: Vec<&PlantedCanary> = Vec::new();
    let mut control: Vec<&PlantedCanary> = Vec::new();
    for flow in [FlowId::P, FlowId::P2] {
        let Some(saved) = present.get(&flow) else {
            continue;
        };
        if !bodies.contains_key(&flow) {
            continue;
        }
        let Some(plant) = &saved.plant else {
            continue;
        };
        if retain_check!(mutation, FreshPlants, plant.object.is_none()) {
            causes.push(IncompleteCause::PlantOwnershipUnestablished { flow });
            continue;
        }
        if retain_check!(mutation, FreshPlants, plant.canaries.is_empty()) {
            causes.push(IncompleteCause::PlantCanaryMissing { flow });
            continue;
        }
        let mut fields: BTreeSet<FieldName> = BTreeSet::new();
        let mut canaries: BTreeSet<&Canary> = BTreeSet::new();
        let mut distinct = true;
        for planted in &plant.canaries {
            if retain_check!(
                mutation,
                PerFieldCanaries,
                !fields.insert(planted.field.clone())
            ) {
                causes.push(IncompleteCause::PlantFieldDuplicated {
                    flow,
                    field: planted.field.clone(),
                });
                distinct = false;
            }
            if retain_check!(
                mutation,
                PerFieldCanaries,
                !canaries.insert(&planted.canary)
            ) {
                causes.push(IncompleteCause::PlantCanaryNotDistinct { flow });
                distinct = false;
            }
        }
        if distinct {
            match flow {
                FlowId::P => primary.extend(plant.canaries.iter()),
                FlowId::P2 => control.extend(plant.canaries.iter()),
                _ => unreachable!("only plants are inspected here"),
            }
        }
    }
    if retain_check!(
        mutation,
        FreshPlants,
        primary
            .iter()
            .any(|planted| control.iter().any(|other| other.canary == planted.canary))
    ) {
        causes.push(IncompleteCause::PlantCanaryNotDistinctAcrossObjects);
    }
    let plant_object = |flow: FlowId| -> Option<&ObjectKey> {
        present
            .get(&flow)
            .and_then(|saved| saved.plant.as_ref())
            .and_then(|plant| plant.object.as_ref())
    };
    if let (Some(first), Some(second)) = (plant_object(FlowId::P), plant_object(FlowId::P2))
        && retain_check!(mutation, FreshPlants, first == second)
    {
        causes.push(IncompleteCause::PlantObjectsNotDistinct);
    }

    // POR-07: the frozen order is F0 < F1 < F3, so the ordered pair behind the
    // exposure derivation means what that derivation says it means. No other
    // order is frozen: POR-08 freezes presence, completeness and run binding,
    // not the order of unrelated flows, so a control planted first or two
    // unrelated flows that share an acquisition tick stay conclusive.
    let ordered = |before: FlowId, after: FlowId, causes: &mut Vec<IncompleteCause>| {
        let (Some(before_flow), Some(after_flow)) = (present.get(&before), present.get(&after))
        else {
            return;
        };
        if !bodies.contains_key(&before) || !bodies.contains_key(&after) {
            return;
        }
        if after_flow.sequence <= before_flow.sequence {
            causes.push(IncompleteCause::FlowOrder {
                flow: after,
                after: before,
            });
        }
    };
    if retain_check!(mutation, ReadOrder, true) {
        ordered(FlowId::F0, FlowId::F1, &mut causes);
        ordered(FlowId::F1, FlowId::F3, &mut causes);
    }

    // Frozen invalid precedence. A check runs only when its own evidence is
    // usable; otherwise the round falls through to EVIDENCE_INCOMPLETE.
    let mut reasons: Vec<InvalidReason> = Vec::new();
    let owner_first = subjects.get(&FlowId::I1);
    let other_first = subjects.get(&FlowId::I2);

    if let (Some(owner), Some(other)) = (owner_first, other_first)
        && retain_check!(mutation, DistinctSubjects, owner == other)
    {
        reasons.push(InvalidReason::SameSubject);
    }

    // POR-04 is round-level: the owner read must show at least one primary
    // canary before a treatment can support any result.
    let owner_read = bodies.get(&FlowId::F1);
    if !primary.is_empty()
        && let Some(body) = owner_read
        && retain_check!(
            mutation,
            OwnerControl,
            !primary.iter().any(|planted| planted.canary.occurs_in(body))
        )
    {
        reasons.push(InvalidReason::ObserverInvalid);
    }

    if let Some(body) = bodies.get(&FlowId::F4)
        && retain_check!(
            mutation,
            SpecificControl,
            primary.iter().any(|planted| planted.canary.occurs_in(body))
        )
    {
        reasons.push(InvalidReason::CanaryNotSpecific);
    }

    if let (Some(owner), Some(other), Some(owner_last), Some(other_last)) = (
        owner_first,
        other_first,
        subjects.get(&FlowId::I3),
        subjects.get(&FlowId::I4),
    ) && retain_check!(
        mutation,
        StableSubjects,
        owner_last != owner || other_last != other
    ) {
        reasons.push(InvalidReason::SessionDrift);
    }

    cleanup_contradictory |= present
        .get(&FlowId::C)
        .and_then(|saved| saved.cleanup.as_ref())
        .is_some_and(|detail| !detail.attempted && !detail.removed.is_empty());
    if !causes.is_empty() {
        reasons.push(InvalidReason::EvidenceIncomplete);
    }

    let cleanup = cleanup_record(
        &present,
        &bodies,
        &established,
        cleanup_contradictory,
        #[cfg(test)]
        mutation,
    );

    if !reasons.is_empty() {
        reasons.sort_by_key(|reason| reason.precedence());
        reasons.dedup();
        return Evaluation {
            result: Verdict::Invalid,
            exposure: None,
            after_owner_read: None,
            fields_crossed: Vec::new(),
            reason_codes: reasons
                .into_iter()
                .map(InvalidReason::reason_code)
                .collect(),
            evidence: causes,
            cleanup,
            decoders: decoders.into_iter().collect(),
            fault: None,
        };
    }

    // POR-06: only an exact planted primary canary, matched as the frozen
    // 32-hex byte sequence, counts in the treatment reads. POR-10: every planted
    // field is matched independently and reported independently; a treatment
    // canary the owner read did not show is still a crossed field, so `false`
    // requires every primary canary to be absent from F0, F2 and F3.
    let contains_canary = |flow, canary: &Canary| {
        #[cfg(test)]
        if let Some(mutation) = mutation.filter(|mutant| mutant.check == Check::ExactCanary)
            && let Some(status) = mutation.statuses.get(&flow)
        {
            return (200..300).contains(status);
        }
        bodies.get(&flow).is_some_and(|body| canary.occurs_in(body))
    };
    #[cfg(test)]
    if !retain_check!(mutation, PerFieldCanaries, true) {
        primary.truncate(1);
    }
    let mut fields_crossed: BTreeSet<FieldName> = BTreeSet::new();
    let mut unauthenticated = false;
    let mut primary_in_first_read = false;
    let mut primary_in_anonymous_read = false;
    for planted in &primary {
        let in_first_read = contains_canary(FlowId::F0, &planted.canary);
        let in_other_read = contains_canary(FlowId::F2, &planted.canary);
        let in_anonymous_read = contains_canary(FlowId::F3, &planted.canary);
        primary_in_first_read |= in_first_read;
        primary_in_anonymous_read |= in_anonymous_read;
        if in_first_read || in_other_read || in_anonymous_read {
            fields_crossed.insert(planted.field.clone());
            if in_first_read || in_anonymous_read {
                unauthenticated = true;
            }
        }
    }
    // Round-level note, computed over the whole round so that a field exposed in
    // F0 keeps it false for every other field exposed in F3.
    let after_owner_read = !primary_in_first_read && primary_in_anonymous_read;

    if fields_crossed.is_empty() {
        return Evaluation {
            result: Verdict::False,
            exposure: None,
            after_owner_read: Some(false),
            fields_crossed: Vec::new(),
            reason_codes: Vec::new(),
            evidence: causes,
            cleanup,
            decoders: decoders.into_iter().collect(),
            fault: None,
        };
    }

    Evaluation {
        result: Verdict::True,
        exposure: Some(if unauthenticated {
            Exposure::Unauthenticated
        } else {
            Exposure::CrossPrincipal
        }),
        after_owner_read: Some(after_owner_read),
        fields_crossed: fields_crossed.into_iter().collect(),
        reason_codes: Vec::new(),
        evidence: causes,
        cleanup,
        decoders: decoders.into_iter().collect(),
        fault: None,
    }
}

fn shape_matches(flow: FlowId, saved: &SavedFlow) -> bool {
    match flow {
        FlowId::I1 | FlowId::I2 | FlowId::I3 | FlowId::I4 => {
            saved.subject.is_some() && saved.plant.is_none() && saved.cleanup.is_none()
        }
        FlowId::P | FlowId::P2 => {
            saved.plant.is_some() && saved.subject.is_none() && saved.cleanup.is_none()
        }
        FlowId::F0 | FlowId::F1 | FlowId::F2 | FlowId::F3 | FlowId::F4 => {
            saved.subject.is_none() && saved.plant.is_none() && saved.cleanup.is_none()
        }
        FlowId::C => saved.cleanup.is_some() && saved.subject.is_none() && saved.plant.is_none(),
    }
}

fn cleanup_record(
    present: &BTreeMap<FlowId, &SavedFlow>,
    bodies: &BTreeMap<FlowId, Vec<u8>>,
    established: &BTreeSet<ObjectKey>,
    contradictory: bool,
    #[cfg(test)] mutation: Option<&Mutation<'_>>,
) -> CleanupRecord {
    let uncertain_plants: Vec<FlowId> = [FlowId::P, FlowId::P2]
        .into_iter()
        .filter(|flow| {
            let Some(saved) = present.get(flow) else {
                return false;
            };
            let Some(plant) = saved.plant.as_ref() else {
                return false;
            };
            plant.object.is_none() || !bodies.contains_key(flow)
        })
        .collect();

    // POR-11: cleanup authority comes from the plant's own response, and only a
    // complete cleanup flow can report a removal.
    let detail: Option<&CleanupDetail> = present
        .get(&FlowId::C)
        .filter(|_| bodies.contains_key(&FlowId::C))
        .and_then(|saved| saved.cleanup.as_ref());

    let attempted = detail.is_some_and(|cleanup| cleanup.attempted);
    let removed: BTreeSet<ObjectKey> = detail
        .map(|cleanup| cleanup.removed.iter().cloned().collect())
        .unwrap_or_default();
    let (authorized, unauthorized) = with_check!(
        mutation,
        CleanupAuthority,
        (
            removed.intersection(established).cloned().collect(),
            removed.difference(established).cloned().collect(),
        ),
        (removed.iter().cloned().collect(), Vec::new())
    );
    let owed: Vec<ObjectKey> = if attempted {
        established.difference(&removed).cloned().collect()
    } else {
        established.iter().cloned().collect()
    };

    CleanupRecord {
        attempted,
        authorized,
        unauthorized,
        owed,
        uncertain_plants,
        contradictory,
    }
}
