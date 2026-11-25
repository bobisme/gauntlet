//! Deterministic round generator and the independent frozen reference.
//!
//! `Oracle.evaluate` is pure (plan §11.3), so its specification can be checked
//! over generated observations as well as over the hand-written fixtures
//! (M1.5.7). This module supplies three things, and deliberately no fourth:
//!
//! 1. [`generate`] builds one *plan* per case: a documented description of what
//!    a round contains - the declared fields and their fresh per-field
//!    canaries, the two plants, the identity subjects, the acquisition order,
//!    the run binding, the retained originals, the cleanup record, the named
//!    coding of each saved body and, in one case in three, exactly one
//!    deliberate break. [`Plan::observations`] turns a plan into typed
//!    [`SavedObservations`]; the plan is the oracle's input the way a saved
//!    document is, never the oracle's output.
//! 2. [`reference`] is the frozen predicate of
//!    [`scourge.oracle-specifications.v1`](../../../../docs/contracts/oracle-specifications.v1.json)
//!    re-derived from that plan - F1 must show a primary canary, F4 must not,
//!    the treatment reads must be ordered around F1, identities must be
//!    distinct and stable, and so on - together with the frozen invalid
//!    precedence. It computes the expected verdict from the plan, so it stays
//!    independent of `evaluate`'s internals: it never looks at an
//!    [`Evaluation`], never calls the oracle and never re-implements the
//!    bounded decoder.
//! 3. [`status_mutant`] is a deliberately broken, test-only reader that decides
//!    from the HTTP status sidecar. It carries no product code; it exists so
//!    the suite can prove that the first property kills a status-sensitive
//!    oracle (INV-08) without touching the shipped one.
//!
//! ## Case budget
//!
//! [`CASE_BUDGET`] is fixed: [`SEEDS`] x [`CASES_PER_SEED`] = 96 rounds. Every
//! case is a pure function of its `(seed, case)` pair, so a failure is
//! reproducible by calling [`generate`] with the printed numbers. The budget is
//! small on purpose: it runs in the ordinary `just check` suite, adds no
//! dependency and needs no network.
//!
//! ## Minimizing and pinning
//!
//! [`minimize_status_mutant`] is a structural shrinker over the generator's own
//! lattice: it scans [`MUTANT_SHRINK_CASES`] cases of [`MUTANT_SHRINK_SEED`] and
//! returns the failing plan of lowest [`Plan::complexity`]. The seeded case it
//! finds is pinned in [`PINNED_MUTANT_CASE`]; the test fails if the generator
//! drifts away from it, so the regression cannot silently disappear.

use std::collections::{BTreeMap, BTreeSet};

use scourge_core::{
    ids::RunId,
    wire::{Completeness, Exposure},
};

use scourge_verify::{
    Canary, CleanupDetail, ContentCoding, DecodeError, DecodeLimits, DecoderName, Decoding,
    Evaluation, FlowId, IncompleteCause, OBSERVATION_SCHEMA, ORACLE_ID, ORACLE_VERSION, ObjectKey,
    OracleRef, PlantDetail, PlantedCanary, SavedFlow, SavedObservations, TransferCoding, Verdict,
};

use super::{artifact, chunked, escaped_json, field, gzip, object, subject, text, zlib};

/// The deterministic seeds of the ordinary suite. Each one is a fresh draw of
/// the same generator, so the four together cover identities, codings, field
/// counts and defects without a random source anywhere.
pub const SEEDS: [u64; 4] = [0x5343_0001, 0x5343_0002, 0x5343_0003, 0x5343_0004];

/// Rounds generated per seed.
pub const CASES_PER_SEED: u64 = 24;

/// The fixed, documented case budget: 96 typed rounds.
pub const CASE_BUDGET: usize = SEEDS.len() * CASES_PER_SEED as usize;

/// The shrink scan: a fixed seed and a fixed number of cases.
pub const MUTANT_SHRINK_SEED: u64 = 0x5052_0001;
pub const MUTANT_SHRINK_CASES: u64 = 256;

/// The pinned minimized counterexample that kills [`status_mutant`].
///
/// Recorded from [`minimize_status_mutant`]; the test asserts the shrinker still
/// returns exactly this pair.
pub const PINNED_MUTANT_CASE: (u64, u64) = (0x5052_0001, 24);

/// The frozen invalid reason codes in precedence order.
pub const FROZEN_REASONS: [&str; 5] = [
    "SAME_SUBJECT",
    "OBSERVER_INVALID",
    "CANARY_NOT_SPECIFIC",
    "SESSION_DRIFT",
    "EVIDENCE_INCOMPLETE",
];

/// An object this run never created, used to break POR-11.
pub const FOREIGN_OBJECT: &str = "object-not-created-by-this-run";

/// The declared field names the generator plants canaries in (POR-10).
pub const FIELD_NAMES: [&str; 3] = ["label", "note", "body"];

/// The frozen coding stacks and their names in saved evidence. An identity
/// body has no decoder. A name lists the stages in undo order.
pub const DECODING_STACKS: [(Decoding, Option<&str>); 12] = [
    (
        Decoding {
            transfer: TransferCoding::Identity,
            content: ContentCoding::Identity,
            json_string_body: false,
        },
        None,
    ),
    (
        Decoding {
            transfer: TransferCoding::Identity,
            content: ContentCoding::Identity,
            json_string_body: true,
        },
        Some("json_string"),
    ),
    (
        Decoding {
            transfer: TransferCoding::Identity,
            content: ContentCoding::Gzip,
            json_string_body: false,
        },
        Some("gzip"),
    ),
    (
        Decoding {
            transfer: TransferCoding::Identity,
            content: ContentCoding::Gzip,
            json_string_body: true,
        },
        Some("gzip+json_string"),
    ),
    (
        Decoding {
            transfer: TransferCoding::Identity,
            content: ContentCoding::Deflate,
            json_string_body: false,
        },
        Some("deflate"),
    ),
    (
        Decoding {
            transfer: TransferCoding::Identity,
            content: ContentCoding::Deflate,
            json_string_body: true,
        },
        Some("deflate+json_string"),
    ),
    (
        Decoding {
            transfer: TransferCoding::Chunked,
            content: ContentCoding::Identity,
            json_string_body: false,
        },
        Some("chunked"),
    ),
    (
        Decoding {
            transfer: TransferCoding::Chunked,
            content: ContentCoding::Identity,
            json_string_body: true,
        },
        Some("chunked+json_string"),
    ),
    (
        Decoding {
            transfer: TransferCoding::Chunked,
            content: ContentCoding::Gzip,
            json_string_body: false,
        },
        Some("chunked+gzip"),
    ),
    (
        Decoding {
            transfer: TransferCoding::Chunked,
            content: ContentCoding::Gzip,
            json_string_body: true,
        },
        Some("chunked+gzip+json_string"),
    ),
    (
        Decoding {
            transfer: TransferCoding::Chunked,
            content: ContentCoding::Deflate,
            json_string_body: false,
        },
        Some("chunked+deflate"),
    ),
    (
        Decoding {
            transfer: TransferCoding::Chunked,
            content: ContentCoding::Deflate,
            json_string_body: true,
        },
        Some("chunked+deflate+json_string"),
    ),
];

const GZIP: Decoding = Decoding {
    transfer: TransferCoding::Identity,
    content: ContentCoding::Gzip,
    json_string_body: false,
};

/// SplitMix64: a fixed, dependency-free sequence.
///
/// The suite must be reproducible from a seed alone, so it cannot use a system
/// random source and does not need a new crate.
#[derive(Debug)]
pub struct Rng {
    state: u64,
}

impl Rng {
    pub const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut value = self.state;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^ (value >> 31)
    }

    pub fn below(&mut self, bound: u64) -> u64 {
        if bound == 0 {
            0
        } else {
            self.next_u64() % bound
        }
    }

    /// True once in `one_in` draws.
    pub fn chance(&mut self, one_in: u64) -> bool {
        self.below(one_in.max(1)) == 0
    }

    fn subset(&mut self, size: usize, require_one: bool) -> Vec<usize> {
        let mut chosen: Vec<usize> = (0..size).filter(|_| !self.chance(2)).collect();
        if require_one && chosen.is_empty() {
            chosen.push(0);
        }
        chosen
    }
}

/// A run-minted canary: fresh per declared field, distinct across the round.
///
/// The value is a pure function of `(seed, case, purpose)`, so the same case
/// always plants the same canaries, and two rounds never share one.
pub fn mint_canary(seed: u64, case: u64, purpose: u64) -> Canary {
    let mut rng = Rng::new(
        seed ^ case
            .wrapping_mul(0x9e37_79b9_7f4a_7c15)
            .wrapping_add(purpose.wrapping_mul(0x2545_f491_4f6c_dd1d)),
    );
    let hex = format!("{:016x}{:016x}", rng.next_u64(), rng.next_u64());
    Canary::parse(&hex).expect("minted canary is 32 lowercase hex characters")
}

/// One declared field and the canary the plant wrote into it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldCanary {
    pub field: String,
    pub canary: Canary,
}

/// A single structural defect of one saved flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Defect {
    None,
    /// The flow's `run` names another run (POR-08).
    NotRunBound,
    /// The flow recorded a partial acquisition (POR-08).
    Partial,
    /// The original bytes are not in the evidence store (POR-09).
    MissingOriginal,
    /// The flow carries the wrong observation shape for its step (POR-08).
    Shape,
    /// The named decoder does not match the decoding that was applied (POR-09).
    DecoderUnnamed {
        recorded: Option<&'static str>,
    },
    /// The saved body cannot be decoded within the recorded bounds (POR-09).
    Decode(DecodeError),
}

/// One saved flow of the plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowPlan {
    pub id: FlowId,
    pub defect: Defect,
    /// Index into [`DECODING_STACKS`] for an undamaged body.
    pub coding: usize,
    pub sequence: u64,
}

/// What the cleanup flow recorded (POR-11).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanupPlan {
    pub attempted: bool,
    pub removed: Vec<ObjectKey>,
}

/// The test-only HTTP status and reason phrase of one flow.
///
/// Nothing in the product can carry these: [`SavedFlow`] rejects unknown fields
/// and [`Evaluation`] is computed from `SavedObservations` alone. The sidecar
/// exists so a broken reader can be shown to depend on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sidecar {
    pub flow: FlowId,
    pub status: u16,
    pub reason: &'static str,
}

/// One generated round: everything the reference needs, and nothing the oracle
/// produces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub seed: u64,
    pub case: u64,
    /// The primary object's declared fields and their fresh canaries (POR-10).
    pub primary: Vec<FieldCanary>,
    /// The control object's declared fields and their fresh canaries.
    pub control: Vec<FieldCanary>,
    pub object_primary: String,
    pub object_control: String,
    pub owner: String,
    pub other: String,
    pub owner_final: String,
    pub other_final: String,
    /// Primary field indices whose canary the flow's decoded body carries.
    pub f0: Vec<usize>,
    pub f1: Vec<usize>,
    pub f2: Vec<usize>,
    pub f3: Vec<usize>,
    pub f4: Vec<usize>,
    /// Whether F4 carries the control object's canaries.
    pub f4_control: bool,
    pub plant_p_ownership: bool,
    pub plant_p2_ownership: bool,
    pub cleanup: CleanupPlan,
    pub flows: Vec<FlowPlan>,
    pub limits: DecodeLimits,
    pub sidecar: Vec<Sidecar>,
}

impl Plan {
    /// The round's structural complexity, used by the shrinker.
    pub fn complexity(&self) -> usize {
        let defects = self
            .flows
            .iter()
            .filter(|flow| flow.defect != Defect::None)
            .count();
        self.primary.len()
            + self.control.len()
            + 4 * defects
            + self.flows.len().abs_diff(FlowId::REQUIRED.len())
    }

    /// The typed observations this plan describes.
    pub fn observations(&self) -> SavedObservations {
        let mut flows = Vec::with_capacity(self.flows.len());
        for planned in &self.flows {
            let id = planned.id;
            let (body, decoding, decoder) = self.coded_body(planned);
            let mut saved = SavedFlow {
                flow: id,
                run: if planned.defect == Defect::NotRunBound {
                    other_run()
                } else {
                    super::run()
                },
                sequence: planned.sequence,
                completeness: if planned.defect == Defect::Partial {
                    Completeness::Partial
                } else {
                    Completeness::Complete
                },
                decoding,
                decoder,
                original: if planned.defect == Defect::MissingOriginal {
                    None
                } else {
                    Some(artifact(id.as_str()))
                },
                body,
                subject: None,
                plant: None,
                cleanup: None,
            };
            let shape_broken = planned.defect == Defect::Shape;
            match id {
                FlowId::I1 | FlowId::I2 | FlowId::I3 | FlowId::I4 => {
                    if !shape_broken {
                        saved.subject = Some(subject(self.probe(id)));
                    }
                }
                FlowId::P | FlowId::P2 => {
                    if shape_broken {
                        saved.subject = Some(subject("shape-mismatch"));
                    } else {
                        saved.plant = Some(self.plant_detail(id));
                    }
                }
                FlowId::F0 | FlowId::F1 | FlowId::F2 | FlowId::F3 | FlowId::F4 => {
                    if shape_broken {
                        saved.subject = Some(subject("shape-mismatch"));
                    }
                }
                FlowId::C => {
                    if shape_broken {
                        saved.subject = Some(subject("shape-mismatch"));
                    } else {
                        saved.cleanup = Some(self.cleanup_detail());
                    }
                }
            }
            flows.push(saved);
        }
        SavedObservations {
            schema: text(OBSERVATION_SCHEMA),
            oracle: OracleRef {
                id: text(ORACLE_ID),
                version: text(ORACLE_VERSION),
            },
            run: super::run(),
            round: 1,
            limits: self.limits,
            flows,
        }
    }

    /// The field names a set of primary indices crosses.
    pub fn field_names(&self, indices: &[usize]) -> Vec<String> {
        indices
            .iter()
            .map(|index| self.primary[*index].field.clone())
            .collect()
    }

    fn probe(&self, id: FlowId) -> &str {
        match id {
            FlowId::I1 => &self.owner,
            FlowId::I3 => &self.owner_final,
            FlowId::I2 => &self.other,
            _ => &self.other_final,
        }
    }

    fn object_for(&self, id: FlowId) -> &str {
        match id {
            FlowId::P => &self.object_primary,
            _ => &self.object_control,
        }
    }

    /// The plant the document records: the plan's declared fields verbatim, so
    /// a duplicated field name or a reused canary is a real recorded value.
    fn plant_detail(&self, id: FlowId) -> PlantDetail {
        let (owned, fields) = match id {
            FlowId::P => (self.plant_p_ownership, &self.primary),
            _ => (self.plant_p2_ownership, &self.control),
        };
        PlantDetail {
            object: owned.then(|| object(self.object_for(id))),
            canaries: fields
                .iter()
                .map(|planted| PlantedCanary {
                    field: field(&planted.field),
                    canary: planted.canary.clone(),
                })
                .collect(),
        }
    }

    fn cleanup_detail(&self) -> CleanupDetail {
        CleanupDetail {
            attempted: self.cleanup.attempted,
            removed: self.cleanup.removed.clone(),
        }
    }

    fn decoded_body(&self, id: FlowId) -> Vec<u8> {
        match id {
            FlowId::I1 | FlowId::I2 | FlowId::I3 | FlowId::I4 => {
                json_body(&[("subject", self.probe(id))])
            }
            FlowId::P => json_body(&[("object", &self.object_primary)]),
            FlowId::P2 => json_body(&[("object", &self.object_control)]),
            FlowId::F0 => self.read_body(&self.f0, true),
            FlowId::F1 => self.read_body(&self.f1, false),
            FlowId::F2 => self.read_body(&self.f2, true),
            FlowId::F3 => self.read_body(&self.f3, true),
            FlowId::F4 => self.read_body(&self.f4, self.f4_control),
            FlowId::C => json_body(&[("removed", "run-owned")]),
        }
    }

    fn read_body(&self, indices: &[usize], control: bool) -> Vec<u8> {
        let mut members: Vec<(&str, &str)> = indices
            .iter()
            .map(|index| {
                (
                    self.primary[*index].field.as_str(),
                    self.primary[*index].canary.as_str(),
                )
            })
            .collect();
        if control {
            for planted in &self.control {
                members.push((planted.field.as_str(), planted.canary.as_str()));
            }
        }
        json_body(&members)
    }

    fn coded_body(&self, planned: &FlowPlan) -> (Vec<u8>, Decoding, Option<DecoderName>) {
        let payload = self.decoded_body(planned.id);
        if let Defect::Decode(kind) = planned.defect {
            return self.defective_body(kind, &payload);
        }
        let (decoding, name) = DECODING_STACKS[planned.coding];
        let name = match planned.defect {
            Defect::DecoderUnnamed { recorded } => recorded,
            _ => name,
        };
        (encode(decoding, &payload), decoding, name.map(decoder))
    }

    /// The saved bytes of a flow whose body must fail the frozen bounds.
    ///
    /// `OverLimit` needs a narrow size bound, so it is only generated through
    /// [`with_decode_defect`], which records one.
    fn defective_body(
        &self,
        kind: DecodeError,
        payload: &[u8],
    ) -> (Vec<u8>, Decoding, Option<DecoderName>) {
        match kind {
            DecodeError::OverLimit => {
                let mut body = payload.to_vec();
                let target = self.limits.max_decoded_bytes as usize + 1;
                body.resize(target.max(payload.len() + 1), b' ');
                (body, Decoding::default(), None)
            }
            DecodeError::ExpansionRatio => (gzip(&vec![b' '; 4096]), GZIP, Some(decoder("gzip"))),
            DecodeError::Truncated => {
                // The complete stream is missing its last trailer byte.
                let mut coded = gzip(payload);
                coded.pop();
                (coded, GZIP, Some(decoder("gzip")))
            }
            DecodeError::Corrupt => {
                let mut coded = gzip(payload);
                coded[0] = 0x00;
                (coded, GZIP, Some(decoder("gzip")))
            }
        }
    }
}

fn other_run() -> RunId {
    RunId::try_from("R-2".to_owned()).expect("run id")
}

fn decoder(name: &str) -> DecoderName {
    DecoderName::try_from(name.to_owned()).expect("registered decoder name")
}

fn json_body(members: &[(&str, &str)]) -> Vec<u8> {
    let rendered: Vec<String> = members
        .iter()
        .map(|(name, value)| format!("\"{name}\":\"{value}\""))
        .collect();
    format!("{{{}}}", rendered.join(",")).into_bytes()
}

/// Apply the named pipeline in the order the record names it.
fn encode(decoding: Decoding, payload: &[u8]) -> Vec<u8> {
    let mut body = if decoding.json_string_body {
        escaped_json(payload)
    } else {
        payload.to_vec()
    };
    match decoding.content {
        ContentCoding::Identity => {}
        ContentCoding::Gzip => body = gzip(&body),
        ContentCoding::Deflate => body = zlib(&body),
    }
    if decoding.transfer == TransferCoding::Chunked {
        body = chunked(&body, &[3, 5, 7]);
    }
    body
}

/// Give one flow a decode defect, with the decode bounds that defect needs.
pub fn with_decode_defect(mut plan: Plan, id: FlowId, kind: DecodeError) -> Plan {
    plan.limits = match kind {
        DecodeError::OverLimit => DecodeLimits::new(1024, 100),
        DecodeError::ExpansionRatio => DecodeLimits::new(1_048_576, 4),
        DecodeError::Truncated | DecodeError::Corrupt => DecodeLimits::default(),
    };
    if let Some(planned) = plan.flows.iter_mut().find(|planned| planned.id == id) {
        planned.defect = Defect::Decode(kind);
    }
    plan
}

/// Give one flow a structural defect.
pub fn with_defect(mut plan: Plan, id: FlowId, defect: Defect) -> Plan {
    if let Some(planned) = plan.flows.iter_mut().find(|planned| planned.id == id) {
        planned.defect = defect;
    }
    plan
}

/// Drive every flow of a plan through one coding stack.
pub fn coded_with(mut plan: Plan, coding: usize) -> Plan {
    for planned in &mut plan.flows {
        planned.coding = coding;
    }
    plan
}

// ---------------------------------------------------------------------------
// The independent frozen reference
// ---------------------------------------------------------------------------

/// What the reference expects the round to record about cleanup (POR-11).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedCleanup {
    pub attempted: bool,
    pub authorized: Vec<String>,
    pub unauthorized: Vec<String>,
    pub owed: Vec<String>,
    pub uncertain_plants: Vec<FlowId>,
    pub contradictory: bool,
}

/// What the frozen specification requires of one round.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expected {
    pub result: Verdict,
    pub exposure: Option<Exposure>,
    pub after_owner_read: Option<bool>,
    pub fields_crossed: Vec<String>,
    pub reasons: Vec<&'static str>,
    /// Predicted detail values derived from the plan.
    pub causes: Vec<IncompleteCause>,
    pub cleanup: ExpectedCleanup,
}

impl Expected {
    /// A readable difference against a real evaluation, or `None` when the
    /// frozen predicate holds.
    pub fn difference(&self, actual: &Evaluation) -> Option<String> {
        let reasons: Vec<&str> = actual
            .reason_codes
            .iter()
            .map(|code| code.as_str())
            .collect();
        let fields: Vec<String> = actual
            .fields_crossed
            .iter()
            .map(|name| name.as_str().to_owned())
            .collect();
        let mut differences = Vec::new();
        if actual.result != self.result {
            differences.push(format!("result {:?} != {:?}", actual.result, self.result));
        }
        if actual.exposure != self.exposure {
            differences.push(format!(
                "exposure {:?} != {:?}",
                actual.exposure, self.exposure
            ));
        }
        if actual.after_owner_read != self.after_owner_read {
            differences.push(format!(
                "after_owner_read {:?} != {:?}",
                actual.after_owner_read, self.after_owner_read
            ));
        }
        if fields != self.fields_crossed {
            differences.push(format!("fields {fields:?} != {:?}", self.fields_crossed));
        }
        if reasons != self.reasons {
            differences.push(format!("reasons {reasons:?} != {:?}", self.reasons));
        }
        let object_names =
            |objects: &[ObjectKey]| objects.iter().map(|key| key.as_str().to_owned()).collect();
        let cleanup = ExpectedCleanup {
            attempted: actual.cleanup.attempted,
            authorized: object_names(&actual.cleanup.authorized),
            unauthorized: object_names(&actual.cleanup.unauthorized),
            owed: object_names(&actual.cleanup.owed),
            uncertain_plants: actual.cleanup.uncertain_plants.clone(),
            contradictory: actual.cleanup.contradictory,
        };
        if cleanup != self.cleanup {
            differences.push(format!("cleanup {cleanup:?} != {:?}", self.cleanup));
        }

        // The contract freezes reason precedence, not the order of details.
        // Match each occurrence so missing, additional and repeated details fail.
        let mut unmatched = actual.evidence.clone();
        let all_matched = self.causes.iter().all(|expected| {
            let Some(index) = unmatched.iter().position(|actual| actual == expected) else {
                return false;
            };
            unmatched.swap_remove(index);
            true
        });
        if !all_matched || !unmatched.is_empty() {
            differences.push(format!("causes {:?} != {:?}", actual.evidence, self.causes));
        }
        if differences.is_empty() {
            None
        } else {
            Some(differences.join("; "))
        }
    }
}

fn frozen_order(mut reasons: Vec<&'static str>) -> Vec<&'static str> {
    reasons.sort_by_key(|reason| {
        FROZEN_REASONS
            .iter()
            .position(|frozen| frozen == reason)
            .expect("every reason is frozen")
    });
    reasons.dedup();
    reasons
}

fn plan_objects(plan: &Plan, id: FlowId) -> Option<&str> {
    let owned = match id {
        FlowId::P => plan.plant_p_ownership,
        FlowId::P2 => plan.plant_p2_ownership,
        _ => return None,
    };
    owned.then(|| plan.object_for(id))
}

/// The subject a probe resolves, when the saved flow can carry one.
fn saved_subject<'a>(
    plan: &'a Plan,
    present: &BTreeMap<FlowId, &FlowPlan>,
    id: FlowId,
) -> Option<&'a str> {
    let planned = present.get(&id)?;
    if planned.defect != Defect::None {
        return None;
    }
    Some(plan.probe(id))
}

/// The object a saved plant established, when its response carries one.
fn saved_plant_object<'a>(
    plan: &'a Plan,
    present: &BTreeMap<FlowId, &FlowPlan>,
    id: FlowId,
) -> Option<&'a str> {
    let planned = present.get(&id)?;
    if planned.defect == Defect::Shape {
        return None;
    }
    plan_objects(plan, id)
}

/// The frozen `web.private-object-read.v1` predicate, derived from the plan.
///
/// The rules are read off the contract, in its own order:
///
/// * POR-08: every required flow is present, complete and bound to this run.
/// * POR-07: F0 precedes F1 and F3 follows it (the ordered pair behind
///   `after_owner_read`).
/// * POR-03, POR-10: two distinct run-owned objects, each with its own fresh,
///   distinct per-field canaries.
/// * POR-09: every body is decoded by the named, bounded decoder with its
///   original bytes retained.
/// * POR-01, POR-02: the subjects are distinct and stable.
/// * POR-04: F1 shows a primary canary.
/// * POR-05: F4 does not.
/// * `true`/`false`: whether any primary canary occurs in F0, F2 or F3.
/// * exposure: `unauthenticated` when F0 or F3 does, `cross_principal`
///   otherwise; `after_owner_read` when F0 lacks it and F3 has it.
///
/// A check whose own evidence is unusable is not decided: the round falls
/// through to `EVIDENCE_INCOMPLETE`, which is what the frozen precedence says
/// happens to a flow that is missing or truncated.
pub fn reference(plan: &Plan) -> Expected {
    let mut present: BTreeMap<FlowId, &FlowPlan> = BTreeMap::new();
    let mut causes: Vec<IncompleteCause> = Vec::new();
    let mut cleanup_contradictory = false;
    for planned in &plan.flows {
        if present.insert(planned.id, planned).is_some() {
            if planned.id == FlowId::C {
                cleanup_contradictory = true;
            } else {
                causes.push(IncompleteCause::DuplicateFlow(planned.id));
            }
        }
    }
    for id in FlowId::VERDICT_REQUIRED {
        if !present.contains_key(&id) {
            causes.push(IncompleteCause::MissingFlow(id));
        }
    }

    let usable = |id: FlowId| {
        present
            .get(&id)
            .is_some_and(|flow| flow.defect == Defect::None)
    };

    for planned in present.values() {
        let flow = planned.id;
        if flow == FlowId::C {
            continue;
        }
        let cause = match planned.defect {
            Defect::None => continue,
            Defect::NotRunBound => IncompleteCause::NotBoundToRun { flow },
            Defect::Partial => IncompleteCause::FlowNotComplete {
                flow,
                recorded: Completeness::Partial,
            },
            Defect::MissingOriginal => IncompleteCause::OriginalNotRetained { flow },
            Defect::Shape => IncompleteCause::FlowShapeMismatch { flow },
            Defect::DecoderUnnamed { recorded } => IncompleteCause::DecoderNotNamed {
                flow,
                recorded: recorded.map(decoder),
                expected: DECODING_STACKS[planned.coding].1.map(decoder),
            },
            Defect::Decode(error) => IncompleteCause::Decode { flow, error },
        };
        causes.push(cause);
    }

    // POR-07: only the ordered pair behind the exposure note is frozen.
    for (before, after) in [(FlowId::F0, FlowId::F1), (FlowId::F1, FlowId::F3)] {
        if usable(before) && usable(after) {
            let first = present[&before].sequence;
            let second = present[&after].sequence;
            if second <= first {
                causes.push(IncompleteCause::FlowOrder {
                    flow: after,
                    after: before,
                });
            }
        }
    }

    // POR-03, POR-10: the plants own distinct objects and carry their own
    // fresh, distinct per-field canaries. A plant whose own record is unusable
    // contributes no canaries to the predicate.
    let mut primary_canaries: Vec<&FieldCanary> = Vec::new();
    let mut control_canaries: Vec<&FieldCanary> = Vec::new();
    for id in [FlowId::P, FlowId::P2] {
        if !usable(id) {
            continue;
        }
        let (owned, fields) = match id {
            FlowId::P => (plan.plant_p_ownership, &plan.primary),
            _ => (plan.plant_p2_ownership, &plan.control),
        };
        if !owned {
            causes.push(IncompleteCause::PlantOwnershipUnestablished { flow: id });
            continue;
        }
        if fields.is_empty() {
            causes.push(IncompleteCause::PlantCanaryMissing { flow: id });
            continue;
        }
        // POR-10 is a property of the recorded per-field canaries themselves,
        // so it is read off the plan's declared fields rather than off a flag.
        let mut names: BTreeSet<&str> = BTreeSet::new();
        let mut values: BTreeSet<&str> = BTreeSet::new();
        let mut distinct = true;
        for planted in fields {
            if !names.insert(planted.field.as_str()) {
                causes.push(IncompleteCause::PlantFieldDuplicated {
                    flow: id,
                    field: field(&planted.field),
                });
                distinct = false;
            }
            if !values.insert(planted.canary.as_str()) {
                causes.push(IncompleteCause::PlantCanaryNotDistinct { flow: id });
                distinct = false;
            }
        }
        if distinct {
            match id {
                FlowId::P => primary_canaries.extend(fields.iter()),
                _ => control_canaries.extend(fields.iter()),
            }
        }
    }
    let shared_canary = primary_canaries.iter().any(|first| {
        control_canaries
            .iter()
            .any(|second| first.canary == second.canary)
    });
    if shared_canary && !primary_canaries.is_empty() && !control_canaries.is_empty() {
        causes.push(IncompleteCause::PlantCanaryNotDistinctAcrossObjects);
    }
    if plan.object_primary == plan.object_control
        && saved_plant_object(plan, &present, FlowId::P).is_some()
        && saved_plant_object(plan, &present, FlowId::P2).is_some()
    {
        causes.push(IncompleteCause::PlantObjectsNotDistinct);
    }

    // Which recorded canary a read's decoded body carries. The read bodies
    // carry the primary canaries the plan names at the indices above, and - for
    // F0, F2, F3 and (when the plan says so) F4 - every control canary too, so
    // a body can carry a primary canary value through a control value. That is
    // exactly what POR-06 has to ignore, and what a shared canary makes visible.
    let carries = |indices: &[usize], carries_control: bool, planted: &FieldCanary| {
        indices
            .iter()
            .any(|index| plan.primary[*index].canary == planted.canary)
            || (carries_control
                && plan
                    .control
                    .iter()
                    .any(|control| control.canary == planted.canary))
    };

    let mut reasons: Vec<&'static str> = Vec::new();

    // POR-01.
    let owner_first = saved_subject(plan, &present, FlowId::I1);
    let other_first = saved_subject(plan, &present, FlowId::I2);
    if let (Some(owner), Some(other)) = (owner_first, other_first)
        && owner == other
    {
        reasons.push("SAME_SUBJECT");
    }

    // POR-04: the owner read must show an admitted primary canary before a
    // treatment read can support any result. F1's body never carries a control
    // canary, so its own indices decide this.
    if !primary_canaries.is_empty() && usable(FlowId::F1) && plan.f1.is_empty() {
        reasons.push("OBSERVER_INVALID");
    }

    // POR-05: F4 must not carry an admitted primary canary. The guard on
    // `primary_canaries` is pinned by `a_dropped_plant_is_not_a_specificity_finding`:
    // a plant whose own canaries were dropped is a completeness failure, not a
    // specificity finding.
    if !primary_canaries.is_empty()
        && usable(FlowId::F4)
        && primary_canaries
            .iter()
            .any(|planted| carries(&plan.f4, plan.f4_control, planted))
    {
        reasons.push("CANARY_NOT_SPECIFIC");
    }

    // POR-02.
    let stable = saved_subject(plan, &present, FlowId::I1).is_some()
        && saved_subject(plan, &present, FlowId::I2).is_some()
        && saved_subject(plan, &present, FlowId::I3).is_some()
        && saved_subject(plan, &present, FlowId::I4).is_some();
    if stable && (plan.owner_final != plan.owner || plan.other_final != plan.other) {
        reasons.push("SESSION_DRIFT");
    }

    // A present, correctly shaped cleanup record is contradictory even if its
    // body cannot support a removal. This is cleanup telemetry, not a verdict
    // input.
    cleanup_contradictory |= present
        .get(&FlowId::C)
        .is_some_and(|flow| flow.defect != Defect::Shape)
        && !plan.cleanup.attempted
        && !plan.cleanup.removed.is_empty();

    if !causes.is_empty() {
        reasons.push("EVIDENCE_INCOMPLETE");
    }

    let cleanup = expected_cleanup(plan, &present, &usable, cleanup_contradictory);

    if !reasons.is_empty() {
        return Expected {
            result: Verdict::Invalid,
            exposure: None,
            after_owner_read: None,
            fields_crossed: Vec::new(),
            reasons: frozen_order(reasons),
            causes,
            cleanup,
        };
    }

    // The conclusive branch: every required flow is usable, so every recorded
    // canary is measured, field by field (POR-10).
    let mut crossed: BTreeSet<String> = BTreeSet::new();
    let mut unauthenticated = false;
    let mut primary_in_f0 = false;
    let mut primary_in_f3 = false;
    for planted in &primary_canaries {
        let in_f0 = carries(&plan.f0, true, planted);
        let in_f2 = carries(&plan.f2, true, planted);
        let in_f3 = carries(&plan.f3, true, planted);
        primary_in_f0 |= in_f0;
        primary_in_f3 |= in_f3;
        if in_f0 || in_f2 || in_f3 {
            crossed.insert(planted.field.clone());
        }
        if in_f0 || in_f3 {
            unauthenticated = true;
        }
    }

    if crossed.is_empty() {
        return Expected {
            result: Verdict::False,
            exposure: None,
            after_owner_read: Some(false),
            fields_crossed: Vec::new(),
            reasons,
            causes,
            cleanup,
        };
    }

    Expected {
        result: Verdict::True,
        exposure: Some(if unauthenticated {
            Exposure::Unauthenticated
        } else {
            Exposure::CrossPrincipal
        }),
        after_owner_read: Some(!primary_in_f0 && primary_in_f3),
        fields_crossed: crossed.into_iter().collect(),
        reasons,
        causes,
        cleanup,
    }
}

fn expected_cleanup(
    plan: &Plan,
    present: &BTreeMap<FlowId, &FlowPlan>,
    usable: &impl Fn(FlowId) -> bool,
    contradictory: bool,
) -> ExpectedCleanup {
    let mut established: BTreeSet<String> = BTreeSet::new();
    for id in [FlowId::P, FlowId::P2] {
        if usable(id)
            && let Some(name) = plan_objects(plan, id)
        {
            established.insert(name.to_owned());
        }
    }

    let cleanup_usable = usable(FlowId::C);
    let removed: BTreeSet<String> = if cleanup_usable {
        plan.cleanup
            .removed
            .iter()
            .map(|key| key.as_str().to_owned())
            .collect()
    } else {
        BTreeSet::new()
    };
    let attempted = cleanup_usable && plan.cleanup.attempted;

    let authorized: Vec<String> = removed.intersection(&established).cloned().collect();
    let unauthorized: Vec<String> = removed.difference(&established).cloned().collect();
    let owed: Vec<String> = if attempted {
        established.difference(&removed).cloned().collect()
    } else {
        established.iter().cloned().collect()
    };
    let uncertain_plants: Vec<FlowId> = [FlowId::P, FlowId::P2]
        .into_iter()
        .filter(|id| present.contains_key(id) && present[id].defect != Defect::Shape)
        .filter(|id| plan_objects(plan, *id).is_none() || !usable(*id))
        .collect();

    ExpectedCleanup {
        attempted,
        authorized,
        unauthorized,
        owed,
        uncertain_plants,
        contradictory,
    }
}

// ---------------------------------------------------------------------------
// Generation
// ---------------------------------------------------------------------------

/// Generate the round of one `(seed, case)` pair.
///
/// The draw decides, in this order: the number of declared fields on each
/// object, the fresh per-field canaries, which primary canaries each treatment
/// read carries (a fifth of the rounds carry none at all, so the budget covers
/// `false`), and the named coding of each saved body. Two rounds in three stop
/// there: a clean round with valid setup. The third round carries exactly one
/// deliberate break, so a single numbered check is the only reason for a
/// difference from the frozen predicate.
///
/// Every field of every case gets its own fresh canary, so no round can be
/// satisfied by stale content, and the four seeds cover every coding stack and
/// both treatments.
pub fn generate(seed: u64, case: u64) -> Plan {
    let mut rng = Rng::new(
        seed ^ case
            .wrapping_mul(0x9e37_79b9_7f4a_7c15)
            .wrapping_add(0x5c0f_0000_0000_0001),
    );

    let primary_count = 1 + rng.below(3) as usize;
    let control_count = 1 + rng.below(2) as usize;
    let primary: Vec<FieldCanary> = (0..primary_count)
        .map(|index| FieldCanary {
            field: FIELD_NAMES[index].to_owned(),
            canary: mint_canary(seed, case, 0x100 + index as u64),
        })
        .collect();
    let control: Vec<FieldCanary> = (0..control_count)
        .map(|index| FieldCanary {
            field: FIELD_NAMES[index].to_owned(),
            canary: mint_canary(seed, case, 0x200 + index as u64),
        })
        .collect();
    {
        // Every field of every round gets its own fresh canary; only the
        // deliberate POR-03/POR-10 breaks reuse one.
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        for planted in primary.iter().chain(&control) {
            assert!(
                seen.insert(planted.canary.as_str()),
                "a round must mint distinct canaries"
            );
        }
    }

    // A fifth of the rounds measure no exposure at all.
    let (f0, f2, f3) = if rng.chance(5) {
        (Vec::new(), Vec::new(), Vec::new())
    } else {
        (
            rng.subset(primary_count, false),
            rng.subset(primary_count, false),
            rng.subset(primary_count, false),
        )
    };

    let object_primary = format!("object-primary-{seed:x}-{case:x}");
    let object_control = format!("object-control-{seed:x}-{case:x}");
    let mut plan = Plan {
        seed,
        case,
        primary,
        control,
        object_primary: object_primary.clone(),
        object_control: object_control.clone(),
        owner: "subject-owner".to_owned(),
        other: "subject-other".to_owned(),
        owner_final: "subject-owner".to_owned(),
        other_final: "subject-other".to_owned(),
        f0,
        f1: rng.subset(primary_count, true),
        f2,
        f3,
        f4: Vec::new(),
        f4_control: !rng.chance(4),
        plant_p_ownership: true,
        plant_p2_ownership: true,
        cleanup: CleanupPlan {
            attempted: true,
            removed: vec![object(&object_primary), object(&object_control)],
        },
        flows: FlowId::REQUIRED
            .iter()
            .map(|id| FlowPlan {
                id: *id,
                defect: Defect::None,
                coding: rng.below(DECODING_STACKS.len() as u64) as usize,
                sequence: super::sequence(*id),
            })
            .collect(),
        limits: DecodeLimits::default(),
        sidecar: FlowId::REQUIRED
            .iter()
            .map(|id| {
                let (status, reason) = if rng.chance(2) {
                    (200_u16, "OK")
                } else {
                    [
                        (403_u16, "Forbidden"),
                        (404, "Not Found"),
                        (500, "Internal Server Error"),
                        (201, "Created"),
                    ][rng.below(4) as usize]
                };
                Sidecar {
                    flow: *id,
                    status,
                    reason,
                }
            })
            .collect(),
    };

    if rng.chance(3) {
        plan = break_one(&mut rng, plan);
    }
    plan
}

/// Apply exactly one documented break to an otherwise-valid round.
fn break_one(rng: &mut Rng, mut plan: Plan) -> Plan {
    let target = FlowId::REQUIRED[rng.below(FlowId::REQUIRED.len() as u64) as usize];
    match rng.below(18) {
        // POR-01: two labels for one subject.
        0 => {
            plan.other = plan.owner.clone();
            plan.other_final = plan.owner.clone();
        }
        // POR-02: a session that changed mid-run.
        1 => plan.owner_final = "subject-owner-drifted".to_owned(),
        2 => plan.other_final = "subject-other-drifted".to_owned(),
        // POR-04: a broken owner observer.
        3 => plan.f1 = Vec::new(),
        // POR-05: a response unrelated to the named object echoes the canary.
        4 => plan.f4 = vec![0],
        // POR-03: a plant that established no run ownership.
        5 => plan.plant_p_ownership = false,
        6 => plan.plant_p2_ownership = false,
        // POR-03: one canary value on both objects.
        7 => plan.control[0].canary = plan.primary[0].canary.clone(),
        // POR-10: one canary in two fields, then two canaries in one field.
        8 => {
            let field = plan.primary[0].field.clone();
            plan.primary.push(FieldCanary {
                field,
                canary: mint_canary(plan.seed, plan.case, 0x800),
            });
        }
        9 => {
            let canary = plan.primary[0].canary.clone();
            plan.primary.push(FieldCanary {
                field: FIELD_NAMES[2].to_owned(),
                canary,
            });
        }
        // POR-03: both plants resolved to one object.
        10 => plan.object_control = plan.object_primary.clone(),
        // POR-11: a cleanup record that claims removals without attempting
        // them, and one that reaches for an object this run never created.
        11 => plan.cleanup.attempted = false,
        12 => plan.cleanup.removed.push(object(FOREIGN_OBJECT)),
        // POR-08, POR-09: one flow that cannot carry a result.
        13 => {
            let coding = plan
                .flows
                .iter()
                .find(|flow| flow.id == target)
                .expect("flow present")
                .coding;
            let wrong_name = DECODING_STACKS[coding].1.is_none().then_some("gzip");
            let defect = [
                Defect::NotRunBound,
                Defect::Partial,
                Defect::MissingOriginal,
                Defect::Shape,
                Defect::DecoderUnnamed {
                    recorded: wrong_name,
                },
            ][rng.below(5) as usize];
            plan = with_defect(plan, target, defect);
        }
        14 => {
            let kind = [
                DecodeError::OverLimit,
                DecodeError::ExpansionRatio,
                DecodeError::Truncated,
                DecodeError::Corrupt,
            ][rng.below(4) as usize];
            plan = with_decode_defect(plan, target, kind);
        }
        // POR-08: a missing or duplicated required flow.
        15 => plan.flows.retain(|flow| flow.id != target),
        16 => {
            let duplicate = plan
                .flows
                .iter()
                .find(|flow| flow.id == target)
                .expect("flow present")
                .clone();
            plan.flows.push(duplicate);
        }
        // POR-07: the ordered pair behind the exposure note is reversed.
        _ => {
            let (before, after) = if target == FlowId::F2 {
                (FlowId::F1, FlowId::F3)
            } else if rng.chance(2) {
                (FlowId::F0, FlowId::F1)
            } else {
                (FlowId::F1, FlowId::F3)
            };
            let sequence = super::sequence(before);
            let planned = plan
                .flows
                .iter_mut()
                .find(|flow| flow.id == after)
                .expect("flow present");
            planned.sequence = sequence;
        }
    }
    plan
}

/// Change the round's flow list in place.
fn keep_flows(plan: &mut Plan, change: impl FnOnce(&mut Vec<FlowPlan>)) {
    change(&mut plan.flows);
}

/// The ordinary suite's fixed budget of generated rounds.
pub fn cases() -> Vec<Plan> {
    let mut plans = Vec::with_capacity(CASE_BUDGET);
    for seed in SEEDS {
        for case in 0..CASES_PER_SEED {
            plans.push(generate(seed, case));
        }
    }
    plans
}

// ---------------------------------------------------------------------------
// A valid baseline round and the single-check breaks
// ---------------------------------------------------------------------------

/// A valid setup round that measures `unauthenticated` exposure after the
/// owner read: one declared field, F1 and F3 carry its canary, F0 and F2 do
/// not, F4 carries only the control object's canary.
pub fn baseline_round() -> Plan {
    let seed = 0xa11c_e001;
    let case = 1;
    let primary = FieldCanary {
        field: FIELD_NAMES[0].to_owned(),
        canary: mint_canary(seed, case, 0x100),
    };
    let control = FieldCanary {
        field: FIELD_NAMES[0].to_owned(),
        canary: mint_canary(seed, case, 0x200),
    };
    Plan {
        seed,
        case,
        primary: vec![primary],
        control: vec![control],
        object_primary: "object-primary".to_owned(),
        object_control: "object-control".to_owned(),
        owner: "subject-owner".to_owned(),
        other: "subject-other".to_owned(),
        owner_final: "subject-owner".to_owned(),
        other_final: "subject-other".to_owned(),
        f0: Vec::new(),
        f1: vec![0],
        f2: Vec::new(),
        f3: vec![0],
        f4: Vec::new(),
        f4_control: true,
        plant_p_ownership: true,
        plant_p2_ownership: true,
        cleanup: CleanupPlan {
            attempted: true,
            removed: vec![object("object-primary"), object("object-control")],
        },
        flows: FlowId::REQUIRED
            .iter()
            .map(|id| FlowPlan {
                id: *id,
                defect: Defect::None,
                coding: 0,
                sequence: super::sequence(*id),
            })
            .collect(),
        limits: DecodeLimits::default(),
        sidecar: FlowId::REQUIRED
            .iter()
            .map(|id| Sidecar {
                flow: *id,
                status: 403,
                reason: "Forbidden",
            })
            .collect(),
    }
}

/// Break exactly one numbered check of an otherwise-valid round.
///
/// `POR-06` is a matching rule rather than a setup rule: its break removes the
/// exposure signal, and the frozen result is `false`. `POR-11` is recorded
/// separately and its break must not move the verdict at all.
pub fn break_check(check: &str) -> Plan {
    let plan = baseline_round();
    match check {
        "POR-01" => Plan {
            other: plan.owner.clone(),
            other_final: plan.owner.clone(),
            ..plan
        },
        "POR-02" => Plan {
            other_final: "subject-other-drifted".to_owned(),
            ..plan
        },
        "POR-03" => Plan {
            object_control: plan.object_primary.clone(),
            ..plan
        },
        "POR-04" => Plan {
            f1: Vec::new(),
            f2: vec![0],
            ..plan
        },
        "POR-05" => Plan {
            f4: vec![0],
            ..plan
        },
        "POR-06" => Plan {
            f3: Vec::new(),
            ..plan
        },
        "POR-07" => {
            let sequence = super::sequence(FlowId::F1);
            let mut plan = plan;
            for planned in &mut plan.flows {
                if planned.id == FlowId::F3 {
                    planned.sequence = sequence;
                }
            }
            plan
        }
        "POR-08" => {
            let mut plan = plan;
            plan.flows.retain(|flow| flow.id != FlowId::I3);
            plan
        }
        "POR-09" => with_defect(plan, FlowId::F2, Defect::MissingOriginal),
        "POR-10" => {
            let mut plan = plan;
            plan.primary.push(FieldCanary {
                field: FIELD_NAMES[0].to_owned(),
                canary: mint_canary(plan.seed, plan.case, 0x901),
            });
            plan
        }
        "POR-11" => Plan {
            cleanup: CleanupPlan {
                removed: vec![
                    object("object-primary"),
                    object("object-control"),
                    object(FOREIGN_OBJECT),
                ],
                ..plan.cleanup
            },
            ..plan
        },
        other => panic!("no break for {other}"),
    }
}

/// Break every frozen setup check at once, to pin the invalid precedence.
pub fn break_all_precedence() -> Plan {
    let plan = baseline_round();
    let plan = Plan {
        other: plan.owner.clone(),
        f1: Vec::new(),
        f2: vec![0],
        f4: vec![0],
        other_final: "subject-other-drifted".to_owned(),
        ..plan
    };
    with_defect(plan, FlowId::F0, Defect::MissingOriginal)
}

// ---------------------------------------------------------------------------
// The test-only status-sensitive mutant
// ---------------------------------------------------------------------------

/// A deliberately broken reader: `true` whenever a treatment read carried
/// HTTP 200 and `false` otherwise.
///
/// It reads only the test-only [`Sidecar`], which the product cannot see, so it
/// is exactly the INV-08 mistake the first property has to kill. It is defined
/// here, never in the product crate.
pub fn status_mutant(plan: &Plan) -> Verdict {
    let treatment_200 = plan
        .sidecar
        .iter()
        .any(|sidecar| matches!(sidecar.flow, FlowId::F2 | FlowId::F3) && sidecar.status == 200);
    if treatment_200 {
        Verdict::True
    } else {
        Verdict::False
    }
}

/// Whether a verdict function disagrees with the frozen reference on one round.
pub fn disagrees_with_reference(plan: &Plan, candidate: impl Fn(&Plan) -> Verdict) -> bool {
    candidate(plan) != reference(plan).result
}

/// Shrink the status-mutant counterexample to the generator's simplest round.
///
/// This is a structural shrink over the documented scan, not a byte-level
/// delta debug: it keeps the failing plan with the lowest [`Plan::complexity`]
/// and, among equals, the earliest `(seed, case)`.
pub fn minimize_status_mutant() -> (u64, u64, Plan) {
    let mut best: Option<(usize, u64, u64, Plan)> = None;
    for case in 0..MUTANT_SHRINK_CASES {
        let plan = generate(MUTANT_SHRINK_SEED, case);
        if !disagrees_with_reference(&plan, status_mutant) {
            continue;
        }
        let key = (plan.complexity(), plan.seed, plan.case);
        let better = best
            .as_ref()
            .is_none_or(|current| (key.0, key.1, key.2) < (current.0, current.1, current.2));
        if better {
            best = Some((key.0, key.1, key.2, plan));
        }
    }
    let (_, seed, case, plan) =
        best.expect("the status mutant must disagree with the reference on some case");
    (seed, case, plan)
}
