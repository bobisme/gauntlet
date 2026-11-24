//! Compiled `scourge.claim-template.v1` templates and pure slot resolution.
//!
//! A claim template fixes what a lead's claim means: the slots it needs, the
//! ordered recipe of registered operations, the controls, the oracle, the
//! cleanup and the retest variants. The frozen shape is
//! [`schemas/claim-template.v1.schema.json`](../../../schemas/claim-template.v1.schema.json)
//! and the contract is [`docs/adr/claim-template-schema.md`](../../../docs/adr/claim-template-schema.md).
//! The registry below is the compiled copy of the one template M1 ships; a test
//! compares it field by field with the frozen example, so it cannot drift.
//!
//! # What this module cannot do
//!
//! It is pure. It opens no socket, starts no process, reads no file, touches no
//! credential and dispatches nothing. Every operation, resource, session and
//! selector value is an inert registered identifier that is only compared,
//! recorded and hashed; nothing here interprets one as a request. A refusal
//! happens before anything could be sent, and a resolved experiment is data.
//!
//! # Frozen rules this module owns
//!
//! * INV-36 and §6.2: the operations the verifier performs as the object's
//!   owner come from an operator-declared property. Property slots are
//!   operator-only, so a lead-supplied or `--slot` value for one is
//!   `SLOT_CONFLICT` (F-38).
//! * INV-37 and §6.2: if a template permits a lead-supplied selector for a read
//!   operation — the slot named `read` declared with kind `selector` and the
//!   `lead` supplier — the resolved method must be `GET` or `HEAD`; any other
//!   method, and any operation the trusted registry does not know, is
//!   `METHOD_REFUSED` before traffic (F-39). The shipped template declares
//!   `read` as an operator-only property slot, so it can never reach that
//!   guard.
//! * INV-40: cleanup removes only objects this run created, so the template's
//!   cleanup step carries the `plant` effect class.
//! * §6.2 and §6.9: the record says who supplied each slot, and the experiment
//!   digest binds every frozen field — template, engagement and property
//!   revisions and digests, resolved values and suppliers, principal bindings,
//!   oracle identity, decoder and limits, and the effect profile — while it
//!   binds no per-run canary and no run nonce. Those belong to the run and its
//!   evidence (§6.9, [`crate::domain::Run`]).
//!
//! # Refusals
//!
//! Every refusal is one frozen [`crate::wire::ErrorCode`], so the exit code is
//! the one in `error_exits` (§8.5): `SLOT_CONFLICT` and `USAGE_ERROR` exit 2,
//! `INPUT_AMBIGUOUS` and `OBJECT_NOT_FOUND` 3, `ORACLE_UNAVAILABLE` 5,
//! `SCOPE_REFUSED` and `METHOD_REFUSED` 8, and an unencodable declaration is
//! `INTEGRITY_FAILURE` 6. A missing slot is not a refusal: [`Resolution::Incomplete`]
//! carries the form `verify --plan` prints, and the effectful command reports
//! `SLOTS_INCOMPLETE` (exit 5).

use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    fmt,
    str::FromStr,
    sync::LazyLock,
};

use serde::{Deserialize, Serialize};

use crate::{
    DeclarationError,
    canonical::{self, JsonError, Sha256Digest},
    declaration::{self, check_safe_integer, objects, string_enum, unique_nonempty},
    engagement::{
        GroupRef, IdentityProbe, Label, ManifestRevision, OperationRef, Property, Prose,
        ResourceRef, SessionRef,
    },
    ids::{LeadId, WireText, text_type},
    wire::{ActionEffect, ErrorCode, ReasonCode, SlotSource, VersionedDigest, VersionedId},
};

/// The compiled oracle contract this build ships.
const ORACLE_CONTRACT: &str = "oracle.web.private-object-read.v1";

/// The oracle identity as a verification record writes it (`oracle.id`).
const ORACLE_ID: &str = "web.private-object-read";

/// The oracle version as a verification record writes it (`oracle.version`).
const ORACLE_VERSION: &str = "1";

/// SHA-256 of the canonical JSON of the `web.private-object-read.v1` entry in
/// the frozen oracle registry. A test recomputes it from that file, so the
/// experiment cannot bind an oracle digest the contract does not describe.
const ORACLE_DIGEST: &str = "6204d1555ec9b69800baf6dc77cf07af01d1435a8ef2dec91f73840c581b7a39";

/// The bounded body decoder identity frozen by the verification record shape
/// (`flow.decoder`), so the experiment pins the same one the flows will name.
const DECODER_ID: &str = "http-body";

/// The decoder version that matches [`DECODER_ID`].
const DECODER_VERSION: &str = "1";

/// Conservative compiled decoded-size bound: 1 MiB. The verifier applies it
/// and may narrow it, never raise it (§6.5, POR-09).
pub const DEFAULT_MAX_DECODED_BYTES: u64 = 1_048_576;

/// Conservative compiled expansion-ratio bound: 100x.
pub const DEFAULT_MAX_EXPANSION_RATIO: u64 = 100;

/// The slot name this build's safe-method guard watches (INV-37).
const READ_SLOT: &str = "read";

/// The supplier identity recorded for an operator-side slot value.
const OPERATOR: &str = "operator";

text_type!(ClaimClass, "claim class", valid_claim_class);
text_type!(SlotName, "claim slot name", valid_slot_name);
text_type!(StepId, "template step reference", valid_ref_name);
text_type!(ControlId, "template control reference", valid_ref_name);
text_type!(
    /// A registered oracle reference, as written in a claim template.
    OracleRef,
    "registered oracle reference",
    |value: &str| declaration::registered_ref(value, "oracle")
);

fn valid_kebab(value: &str) -> bool {
    !value.is_empty()
        && value.starts_with(|character: char| character.is_ascii_lowercase())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

/// `^[a-z][a-z0-9-]*/[a-z][a-z0-9-]*$`, the frozen `claim_class` pattern.
fn valid_claim_class(value: &str) -> bool {
    match value.split_once('/') {
        Some((class, proposition)) => valid_kebab(class) && valid_kebab(proposition),
        None => false,
    }
}

/// `^[a-z][a-z0-9_]{0,63}$`, the frozen `slot_name` pattern.
fn valid_slot_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.starts_with(|character: char| character.is_ascii_lowercase())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn valid_ref_name_part(part: &str) -> bool {
    !part.is_empty()
        && part.starts_with(|character: char| character.is_ascii_lowercase())
        && part
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

/// `^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]{0,31}){0,4}$`, the frozen `ref_name`.
///
/// Every dot-segment is validated and the split is consumed to the end, so a
/// sixth segment, or anything after the fifth, is a refusal rather than an
/// unvalidated tail. The first segment is unbounded; the other four are at most
/// 32 bytes. The frozen `$defs/ref_name` in
/// `schemas/claim-template.v1.schema.json` is the same pattern, and a test
/// compares this decision with it over a candidate matrix.
fn valid_ref_name(value: &str) -> bool {
    let mut parts = value.split('.');
    let Some(first) = parts.next() else {
        return false;
    };
    if !valid_ref_name_part(first) {
        return false;
    }
    let mut segments = 0;
    for part in parts {
        segments += 1;
        if segments > 4 || !(1..=32).contains(&part.len()) || !valid_ref_name_part(part) {
            return false;
        }
    }
    true
}

fn wire(value: &str) -> WireText {
    WireText::try_from(value.to_owned()).expect("a registered reference is wire text")
}

fn unique<T: Eq + std::hash::Hash>(items: &[T]) -> bool {
    let mut seen = HashSet::with_capacity(items.len());
    items.iter().all(|item| seen.insert(item))
}

/// The schema has exactly two supplier values, so a supplier list is unique when
/// it is nonempty and either one entry or two different entries.
fn unique_suppliers(suppliers: &[SuppliedBy]) -> bool {
    match suppliers {
        [] => false,
        [one] => matches!(one, SuppliedBy::Operator | SuppliedBy::Lead),
        [first, second] => first != second,
        [_, _, ..] => false,
    }
}

// -- The frozen schema shape ------------------------------------------------

string_enum! {
    // The frozen `slots.*.kind` values.
    pub enum SlotKind {
        Principal => "principal",
        Property => "property",
        Policy => "policy",
        Observation => "observation",
        Artifact => "artifact",
        Selector => "selector",
    }
}

impl SlotKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Principal => "principal",
            Self::Property => "property",
            Self::Policy => "policy",
            Self::Observation => "observation",
            Self::Artifact => "artifact",
            Self::Selector => "selector",
        }
    }
}

string_enum! {
    // The frozen `slots.*.supplied_by` values.
    pub enum SuppliedBy {
        Operator => "operator",
        Lead => "lead",
    }
}

impl SuppliedBy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Operator => OPERATOR,
            Self::Lead => "lead",
        }
    }
}

string_enum! {
    // The frozen `oracle.scope` values.
    pub enum OracleScope {
        ObjectRead => "object_read",
        StateChange => "state_change",
        CollectionDisclosure => "collection_disclosure",
        Existence => "existence",
    }
}

string_enum! {
    // The frozen `retest_variants.*.result_dimension` values.
    pub enum RetestDimension {
        SecurityProperty => "security_property",
        LegitimatePath => "legitimate_path",
    }
}

string_enum! {
    // The one schema tag this build compiles.
    pub enum TemplateSchemaVersion {
        V1 => "scourge.claim-template.v1",
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlotDeclaration {
    pub kind: SlotKind,
    pub supplied_by: Vec<SuppliedBy>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecipeStep {
    pub id: StepId,
    pub operation: OperationRef,
    pub slots: Vec<SlotName>,
    pub effect: ActionEffect,
    pub controls: Vec<ControlId>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Control {
    pub step: StepId,
    pub rules_out: Prose,
    pub reason_code: ReasonCode,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplateOracle {
    pub id: OracleRef,
    pub scope: OracleScope,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cleanup {
    pub step: StepId,
    pub evidence_required: Prose,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetestVariant {
    pub step: StepId,
    pub result_dimension: RetestDimension,
}

/// One `scourge.claim-template.v1` document, exactly as the schema defines it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimTemplate {
    pub schema_version: TemplateSchemaVersion,
    pub claim_class: ClaimClass,
    pub template_version: u64,
    #[serde(deserialize_with = "objects")]
    pub slots: BTreeMap<SlotName, SlotDeclaration>,
    pub recipe: Vec<RecipeStep>,
    #[serde(deserialize_with = "objects")]
    pub controls: BTreeMap<ControlId, Control>,
    pub oracle: TemplateOracle,
    pub cleanup: Cleanup,
    #[serde(deserialize_with = "objects")]
    pub retest_variants: BTreeMap<SlotName, RetestVariant>,
}

/// The class and oracle pairs the frozen contracts register. The schema pins
/// `oracle.web.private-object-read.v1` to the object-read class and scope, and
/// the template ADR requires class and scope to agree; `web.forbidden-state-change.v1`
/// is the registered state-change oracle (M2, not shipped as a template here).
const ORACLE_BINDINGS: &[(&str, &str, OracleScope)] = &[
    (
        "web-authz/private-object-read",
        "oracle.web.private-object-read.v1",
        OracleScope::ObjectRead,
    ),
    (
        "web-authz/state-change",
        "oracle.web.forbidden-state-change.v1",
        OracleScope::StateChange,
    ),
];

fn registered_oracle_scope(claim_class: &ClaimClass, oracle: &OracleRef) -> Option<OracleScope> {
    ORACLE_BINDINGS
        .iter()
        .find(|(class, reference, _)| {
            *class == claim_class.as_str() && *reference == oracle.as_str()
        })
        .map(|(_, _, scope)| *scope)
}

/// The declared-property operation a property slot resolves to. `None` means
/// the declared property fixes no such operation.
fn property_operation<'a>(property: &'a Property, slot: &SlotName) -> Option<&'a OperationRef> {
    match slot.as_str() {
        "read" => Some(&property.read),
        "plant" => Some(&property.plant.operation),
        "remove" => Some(&property.remove),
        "write" => property.write.as_ref().map(|write| &write.operation),
        _ => None,
    }
}

// A template's exact canonical bytes are a frozen artifact, so it is hashed
// like any other immutable declaration.
impl canonical::sealed::Sealed for ClaimTemplate {}

/// A property slot must name one of the four operation references a declared
/// property can fix, so resolution can never bind an operation the operator did
/// not declare.
fn registered_property_slot(slot: &SlotName) -> bool {
    matches!(slot.as_str(), "read" | "plant" | "remove" | "write")
}

impl ClaimTemplate {
    pub fn parse_json(input: &[u8]) -> Result<Self, TemplateError> {
        Ok(declaration::parse_json(input, "claim template")?)
    }

    /// Check the rules the schema cannot state but the ADR requires: property
    /// slots are operator-only, the recipe covers exactly the declared slots,
    /// controls are bidirectional, cleanup removes run-created state and both
    /// retest dimensions are present.
    pub fn validate(&self) -> Result<(), TemplateError> {
        if self.template_version == 0 {
            return Err(issue("template_version", TemplateIssue::InvalidVersion));
        }
        check_safe_integer(self.template_version, "template_version")?;

        if self.slots.is_empty() {
            return Err(issue("slots", TemplateIssue::InvalidEntries));
        }
        for (name, declaration) in &self.slots {
            if !unique_suppliers(&declaration.supplied_by) {
                return Err(issue("slots", TemplateIssue::InvalidEntries));
            }
            match declaration.kind {
                SlotKind::Property => {
                    if declaration.supplied_by != [SuppliedBy::Operator] {
                        return Err(issue("slots", TemplateIssue::PropertySlotNotOperatorOnly));
                    }
                    if !registered_property_slot(name) {
                        return Err(issue("slots", TemplateIssue::UnknownPropertySlot));
                    }
                }
                SlotKind::Principal if !matches!(name.as_str(), "owner" | "other") => {
                    return Err(issue("slots", TemplateIssue::UnknownPrincipalSlot));
                }
                _ => {}
            }
        }

        if self.recipe.is_empty() {
            return Err(issue("recipe", TemplateIssue::InvalidEntries));
        }
        let mut steps = BTreeSet::new();
        let mut bound = BTreeSet::new();
        for step in &self.recipe {
            if !steps.insert(&step.id) {
                return Err(issue("recipe", TemplateIssue::DuplicateStep));
            }
            if !unique_nonempty(&step.slots) || !unique(&step.controls) {
                return Err(issue("recipe", TemplateIssue::InvalidEntries));
            }
            for name in &step.slots {
                if !self.slots.contains_key(name) {
                    return Err(issue("recipe", TemplateIssue::SlotNotDeclared));
                }
                bound.insert(name);
            }
            for control in &step.controls {
                match self.controls.get(control) {
                    None => return Err(issue("recipe", TemplateIssue::UnknownControl)),
                    Some(declared) if declared.step != step.id => {
                        return Err(issue("recipe", TemplateIssue::ControlOnAnotherStep));
                    }
                    Some(_) => {}
                }
            }
        }
        if bound != self.slots.keys().collect() {
            return Err(issue("recipe", TemplateIssue::SlotCoverage));
        }

        if self.controls.is_empty() {
            return Err(issue("controls", TemplateIssue::InvalidEntries));
        }
        for (name, control) in &self.controls {
            let Some(step) = self.recipe.iter().find(|step| step.id == control.step) else {
                return Err(issue("controls", TemplateIssue::UnknownStep));
            };
            if !step.controls.contains(name) {
                return Err(issue("controls", TemplateIssue::ControlNotOnStep));
            }
        }

        if registered_oracle_scope(&self.claim_class, &self.oracle.id) != Some(self.oracle.scope) {
            return Err(issue("oracle", TemplateIssue::UnregisteredOracle));
        }

        let Some(cleanup) = self.recipe.iter().find(|step| step.id == self.cleanup.step) else {
            return Err(issue("cleanup", TemplateIssue::UnknownStep));
        };
        if cleanup.effect != ActionEffect::Plant {
            return Err(issue("cleanup", TemplateIssue::CleanupEffect));
        }

        if self.retest_variants.is_empty() {
            return Err(issue("retest_variants", TemplateIssue::InvalidEntries));
        }
        let mut dimensions = Vec::new();
        for variant in self.retest_variants.values() {
            if !self.recipe.iter().any(|step| step.id == variant.step) {
                return Err(issue("retest_variants", TemplateIssue::UnknownStep));
            }
            if !dimensions.contains(&variant.result_dimension) {
                dimensions.push(variant.result_dimension);
            }
        }
        if dimensions.len() != 2 {
            return Err(issue("retest_variants", TemplateIssue::RetestDimensions));
        }
        Ok(())
    }

    pub fn versioned_id(&self) -> VersionedId {
        VersionedId {
            id: wire(self.claim_class.as_str()),
            version: wire(&self.template_version.to_string()),
        }
    }
}

// -- Errors -----------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum TemplateIssue {
    #[error("template version must be at least 1")]
    InvalidVersion,
    #[error("a property slot must be operator-only")]
    PropertySlotNotOperatorOnly,
    #[error("a property slot names no operation a declared property fixes")]
    UnknownPropertySlot,
    #[error("a principal slot names no registered principal role")]
    UnknownPrincipalSlot,
    #[error("recipe step ID is repeated")]
    DuplicateStep,
    #[error(
        "a recipe step binds no declared slot, or the recipe does not cover every declared slot"
    )]
    SlotNotDeclared,
    #[error("the recipe does not bind exactly the declared slots")]
    SlotCoverage,
    #[error("a recipe step names a control that is not declared")]
    UnknownControl,
    #[error("a recipe step names a control that belongs to another step")]
    ControlOnAnotherStep,
    #[error("a control names a step that does not declare it")]
    ControlNotOnStep,
    #[error("a reference names no recipe step")]
    UnknownStep,
    #[error("the class and oracle are not a registered pair, or the scope differs")]
    UnregisteredOracle,
    #[error("cleanup removes run-created state, which is the plant effect class")]
    CleanupEffect,
    #[error("both retest result dimensions are required")]
    RetestDimensions,
    #[error("entries must be nonempty and unique")]
    InvalidEntries,
    #[error("the compiled registry is not ordered by claim class and template version")]
    UnorderedRegistry,
    #[error("two compiled templates share a claim class or an oracle identity")]
    DuplicateRegistryEntry,
}

/// A compiled-template failure. Parse failures keep the declaration diagnostic;
/// validation failures name a schema-owned stanza, never input text.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum TemplateError {
    #[error(transparent)]
    Declaration(#[from] DeclarationError),
    #[error("claim template {stanza}: {issue}")]
    Template {
        stanza: &'static str,
        issue: TemplateIssue,
    },
}

fn issue(stanza: &'static str, issue: TemplateIssue) -> TemplateError {
    TemplateError::Template { stanza, issue }
}

// -- The compiled registry --------------------------------------------------

/// The frozen run limits that bound every decoding step of the experiment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecodeLimits {
    pub max_decoded_bytes: u64,
    pub max_expansion_ratio: u64,
}

impl DecodeLimits {
    pub const DEFAULT: Self = Self {
        max_decoded_bytes: DEFAULT_MAX_DECODED_BYTES,
        max_expansion_ratio: DEFAULT_MAX_EXPANSION_RATIO,
    };
}

/// The bounded decoder an experiment's observations are measured through.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecoderBinding {
    pub identity: VersionedId,
    pub limits: DecodeLimits,
}

/// A validated template with the run parameters the experiment must bind.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompiledTemplate {
    pub template: ClaimTemplate,
    pub oracle: VersionedDigest,
    pub decoder: DecoderBinding,
}

impl CompiledTemplate {
    /// A compiled template is validated on construction, and its oracle identity
    /// is checked against the contract reference the template names, so the two
    /// cannot disagree.
    pub fn new(
        template: ClaimTemplate,
        oracle: VersionedDigest,
        decoder: DecoderBinding,
    ) -> Result<Self, TemplateError> {
        template.validate()?;
        if oracle_identity(&template.oracle.id).as_ref()
            != Some(&VersionedId {
                id: oracle.id.clone(),
                version: oracle.version.clone(),
            })
        {
            return Err(issue("oracle", TemplateIssue::UnregisteredOracle));
        }
        Ok(Self {
            template,
            oracle,
            decoder,
        })
    }

    pub fn claim_class(&self) -> &ClaimClass {
        &self.template.claim_class
    }

    pub fn versioned_id(&self) -> VersionedId {
        self.template.versioned_id()
    }

    /// Every non-`none` effect class the recipe carries, in first-use order.
    pub fn effect_profile(&self) -> Vec<ActionEffect> {
        let mut effects = Vec::new();
        for step in &self.template.recipe {
            if step.effect != ActionEffect::None && !effects.contains(&step.effect) {
                effects.push(step.effect);
            }
        }
        effects
    }
}

/// `oracle.web.private-object-read.v1` names identity `web.private-object-read`
/// version `1`, the form a verification record stores.
fn oracle_identity(reference: &OracleRef) -> Option<VersionedId> {
    let (id, version) = reference
        .as_str()
        .strip_prefix("oracle.")?
        .rsplit_once(".v")?;
    if id.is_empty() || version.is_empty() || !version.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    Some(VersionedId {
        id: wire(id),
        version: wire(version),
    })
}

fn oracle_binding() -> VersionedDigest {
    VersionedDigest {
        id: wire(ORACLE_ID),
        version: wire(ORACLE_VERSION),
        digest: Sha256Digest::from_str(ORACLE_DIGEST)
            .expect("the compiled oracle digest is a SHA-256 digest"),
    }
}

fn decoder_binding() -> DecoderBinding {
    DecoderBinding {
        identity: VersionedId {
            id: wire(DECODER_ID),
            version: wire(DECODER_VERSION),
        },
        limits: DecodeLimits::DEFAULT,
    }
}

fn claim_class(value: &str) -> ClaimClass {
    ClaimClass::from_str(value).expect("a compiled claim class is registered")
}

fn slot_name(value: &str) -> SlotName {
    SlotName::from_str(value).expect("a compiled slot name is registered")
}

fn step_id(value: &str) -> StepId {
    StepId::from_str(value).expect("a compiled step reference is registered")
}

fn control_id(value: &str) -> ControlId {
    ControlId::from_str(value).expect("a compiled control reference is registered")
}

fn oracle_ref(value: &str) -> OracleRef {
    OracleRef::from_str(value).expect("a compiled oracle reference is registered")
}

fn operation(value: &str) -> OperationRef {
    OperationRef::from_str(value).expect("a compiled operation reference is registered")
}

fn prose(value: &str) -> Prose {
    Prose::from_str(value).expect("compiled prose is a safe declaration statement")
}

fn reason_code(value: &str) -> ReasonCode {
    ReasonCode::from_str(value).expect("a compiled reason code is registered")
}

fn recipe_step(
    id: &str,
    operation_id: &str,
    slots: &[&str],
    effect: ActionEffect,
    controls: &[&str],
) -> RecipeStep {
    RecipeStep {
        id: step_id(id),
        operation: operation(operation_id),
        slots: slots.iter().map(|name| slot_name(name)).collect(),
        effect,
        controls: controls.iter().map(|name| control_id(name)).collect(),
    }
}

fn control(step: &str, rules_out: &str, code: &str) -> Control {
    Control {
        step: step_id(step),
        rules_out: prose(rules_out),
        reason_code: reason_code(code),
    }
}

/// The compiled `web-authz/private-object-read` template. It is the frozen
/// example, and a test compares the two field by field.
fn private_object_read() -> ClaimTemplate {
    let operator_only = [SuppliedBy::Operator];
    let either = [SuppliedBy::Operator, SuppliedBy::Lead];
    ClaimTemplate {
        schema_version: TemplateSchemaVersion::V1,
        claim_class: claim_class("web-authz/private-object-read"),
        template_version: 1,
        slots: BTreeMap::from([
            (
                slot_name("owner"),
                SlotDeclaration {
                    kind: SlotKind::Principal,
                    supplied_by: either.to_vec(),
                },
            ),
            (
                slot_name("other"),
                SlotDeclaration {
                    kind: SlotKind::Principal,
                    supplied_by: either.to_vec(),
                },
            ),
            (
                slot_name("read"),
                SlotDeclaration {
                    kind: SlotKind::Property,
                    supplied_by: operator_only.to_vec(),
                },
            ),
            (
                slot_name("plant"),
                SlotDeclaration {
                    kind: SlotKind::Property,
                    supplied_by: operator_only.to_vec(),
                },
            ),
            (
                slot_name("remove"),
                SlotDeclaration {
                    kind: SlotKind::Property,
                    supplied_by: operator_only.to_vec(),
                },
            ),
        ]),
        recipe: vec![
            recipe_step(
                "probe.owner.first",
                "operation.probe.identity",
                &["owner"],
                ActionEffect::None,
                &["control.distinct_subject"],
            ),
            recipe_step(
                "probe.other.first",
                "operation.probe.identity",
                &["other"],
                ActionEffect::None,
                &[],
            ),
            recipe_step(
                "plant.first",
                "operation.plant.object",
                &["owner", "plant"],
                ActionEffect::Plant,
                &["control.plant_established"],
            ),
            recipe_step(
                "plant.second",
                "operation.plant.object",
                &["owner", "plant"],
                ActionEffect::Plant,
                &[],
            ),
            recipe_step(
                "read.anonymous.first",
                "operation.read.object",
                &["read"],
                ActionEffect::Observe,
                &[],
            ),
            recipe_step(
                "read.owner.first",
                "operation.read.object",
                &["owner", "read"],
                ActionEffect::Observe,
                &["control.observer_valid"],
            ),
            recipe_step(
                "read.other.first",
                "operation.read.object",
                &["other", "read"],
                ActionEffect::Observe,
                &[],
            ),
            recipe_step(
                "read.anonymous.last",
                "operation.read.object",
                &["read"],
                ActionEffect::Observe,
                &[],
            ),
            recipe_step(
                "read.other.second",
                "operation.read.object",
                &["other", "read"],
                ActionEffect::Observe,
                &["control.canary_specific"],
            ),
            recipe_step(
                "probe.owner.last",
                "operation.probe.identity",
                &["owner"],
                ActionEffect::None,
                &["control.session_stable"],
            ),
            recipe_step(
                "probe.other.last",
                "operation.probe.identity",
                &["other"],
                ActionEffect::None,
                &[],
            ),
            recipe_step(
                "cleanup.objects",
                "operation.cleanup.objects",
                &["owner", "plant", "remove"],
                ActionEffect::Plant,
                &["control.cleanup_recorded"],
            ),
        ],
        controls: BTreeMap::from([
            (
                control_id("control.distinct_subject"),
                control(
                    "probe.owner.first",
                    "Two session labels describing one subject",
                    "SAME_SUBJECT",
                ),
            ),
            (
                control_id("control.plant_established"),
                control(
                    "plant.first",
                    "A plant whose response does not establish that this run created the object",
                    "PLANT_UNCONFIRMED",
                ),
            ),
            (
                control_id("control.observer_valid"),
                control(
                    "read.owner.first",
                    "A broken observer, a substitute login page or a missing object",
                    "OBSERVER_INVALID",
                ),
            ),
            (
                control_id("control.canary_specific"),
                control(
                    "read.other.second",
                    "The first object's canary appearing in a response about another object",
                    "CANARY_NOT_SPECIFIC",
                ),
            ),
            (
                control_id("control.session_stable"),
                control(
                    "probe.owner.last",
                    "A subject or session that changed during the run",
                    "SESSION_DRIFT",
                ),
            ),
            (
                control_id("control.cleanup_recorded"),
                control(
                    "cleanup.objects",
                    "A removal the run cannot attribute to its own creation",
                    "CLEANUP_UNCONFIRMED",
                ),
            ),
        ]),
        oracle: TemplateOracle {
            id: oracle_ref(ORACLE_CONTRACT),
            scope: OracleScope::ObjectRead,
        },
        cleanup: Cleanup {
            step: step_id("cleanup.objects"),
            evidence_required: prose(
                "The plant response and the removal response for each object the run created",
            ),
        },
        retest_variants: BTreeMap::from([
            (
                slot_name("security_property"),
                RetestVariant {
                    step: step_id("read.other.first"),
                    result_dimension: RetestDimension::SecurityProperty,
                },
            ),
            (
                slot_name("legitimate_path"),
                RetestVariant {
                    step: step_id("read.owner.first"),
                    result_dimension: RetestDimension::LegitimatePath,
                },
            ),
        ]),
    }
}

/// The compiled registry. A template is compiled data and typed code; there is
/// no loader, expression language or plugin interface (§6.2).
static REGISTRY: LazyLock<Vec<CompiledTemplate>> = LazyLock::new(|| {
    let compiled =
        CompiledTemplate::new(private_object_read(), oracle_binding(), decoder_binding())
            .expect("the compiled claim-template registry is frozen and well formed");
    let registry = vec![compiled];
    validate_registry(&registry)
        .expect("the compiled claim-template registry is ordered and unique");
    registry
});

/// The registry is ordered by claim class and template version, and no two
/// entries share a claim class or an oracle identity.
fn validate_registry(registry: &[CompiledTemplate]) -> Result<(), TemplateError> {
    let mut classes = BTreeSet::new();
    let mut oracles = BTreeSet::new();
    let mut previous: Option<(&ClaimClass, u64)> = None;
    for compiled in registry {
        let template = &compiled.template;
        if !classes.insert(template.claim_class.clone())
            || !oracles.insert((compiled.oracle.id.clone(), compiled.oracle.version.clone()))
        {
            return Err(issue("registry", TemplateIssue::DuplicateRegistryEntry));
        }
        if let Some((class, version)) = previous
            && (template.claim_class.as_str(), template.template_version)
                <= (class.as_str(), version)
        {
            return Err(issue("registry", TemplateIssue::UnorderedRegistry));
        }
        previous = Some((&template.claim_class, template.template_version));
    }
    Ok(())
}

/// The compiled templates and the one pure resolution entry point.
pub struct Templates;

impl Templates {
    pub fn registry() -> &'static [CompiledTemplate] {
        &REGISTRY
    }

    pub fn template(claim_class: &ClaimClass) -> Option<&'static CompiledTemplate> {
        Self::registry()
            .iter()
            .find(|compiled| &compiled.template.claim_class == claim_class)
    }

    /// Resolve a lead's claim against an accepted engagement revision. The
    /// shipped template permits no lead-supplied read selector, so no operation
    /// registry is consulted; a future template that does permit one is
    /// refused rather than assumed safe ([`Templates::resolve_with`] takes the
    /// trusted projection).
    pub fn resolve(claim: &Claim, manifest: &ManifestRevision) -> Result<Resolution, ResolveError> {
        Self::resolve_in(Self::registry(), claim, manifest, &NoMethods)
    }

    /// Resolve against the trusted operation registry's read-only projection.
    /// The projection returns inert method names and performs no dispatch.
    pub fn resolve_with(
        claim: &Claim,
        manifest: &ManifestRevision,
        methods: &dyn OperationMethods,
    ) -> Result<Resolution, ResolveError> {
        Self::resolve_in(Self::registry(), claim, manifest, methods)
    }

    fn resolve_in(
        registry: &[CompiledTemplate],
        claim: &Claim,
        manifest: &ManifestRevision,
        methods: &dyn OperationMethods,
    ) -> Result<Resolution, ResolveError> {
        let compiled = registry
            .iter()
            .find(|compiled| compiled.template.claim_class == claim.class)
            .ok_or_else(|| ResolveError::UnsupportedClass {
                supported: registry
                    .iter()
                    .map(|compiled| compiled.template.claim_class.clone())
                    .collect(),
            })?;
        let template = &compiled.template;

        if claim.engagement.revision != manifest.revision()
            || &claim.engagement.digest != manifest.digest()
        {
            return Err(ResolveError::EngagementMismatch {
                supplied: claim.engagement.revision,
                engaged: manifest.revision(),
            });
        }

        for supplied in claim.lead_slots.iter().chain(claim.overrides.iter()) {
            if !template.slots.contains_key(&supplied.name) {
                return Err(ResolveError::UnknownSlot {
                    declared: template.slots.keys().cloned().collect(),
                });
            }
        }
        let lead = index(&claim.lead_slots)?;
        let operator = index(&claim.overrides)?;
        for name in lead.keys() {
            if operator.contains_key(name) {
                return Err(ResolveError::AmbiguousSlot {
                    slot: (*name).clone(),
                });
            }
        }
        for name in lead.keys() {
            check_supplier(template, name, SuppliedBy::Lead)?;
        }
        for name in operator.keys() {
            check_supplier(template, name, SuppliedBy::Operator)?;
        }

        let property = match &claim.property {
            Some(label) => Some(manifest.properties().get(label).ok_or_else(|| {
                ResolveError::UndeclaredProperty {
                    property: label.clone(),
                }
            })?),
            None => None,
        };

        for effect in compiled.effect_profile() {
            if !manifest.settings().allow_effects.contains(&effect) {
                return Err(ResolveError::EffectNotAllowed { effect });
            }
        }

        let mut slots: BTreeMap<SlotName, SlotBinding> = BTreeMap::new();
        let mut missing = Vec::new();
        let mut principal_labels: BTreeMap<SlotName, Label> = BTreeMap::new();
        for (name, declaration) in &template.slots {
            let entered = supply(claim, &lead, &operator, name);
            if declaration.kind == SlotKind::Property {
                let fixed = property.and_then(|property| property_operation(property, name));
                let Some(fixed) = fixed else {
                    missing.push(MissingSlot {
                        name: name.clone(),
                        kind: declaration.kind,
                        supplied_by: declaration.supplied_by.clone(),
                        reason: if property.is_none() {
                            MissingReason::NoPropertySelected
                        } else {
                            MissingReason::PropertyFixesNothing
                        },
                    });
                    continue;
                };
                slots.insert(
                    name.clone(),
                    SlotBinding {
                        value: wire(fixed.as_str()),
                        source: SlotSource::Engagement,
                        supplied_by: wire(OPERATOR),
                        digest: Sha256Digest::of(fixed.as_str().as_bytes()),
                    },
                );
                continue;
            }
            let Some((value, source, supplier)) = entered else {
                missing.push(MissingSlot {
                    name: name.clone(),
                    kind: declaration.kind,
                    supplied_by: declaration.supplied_by.clone(),
                    reason: MissingReason::NotSupplied,
                });
                continue;
            };
            if declaration.kind == SlotKind::Principal {
                let label = Label::try_from(value.as_str().to_owned())
                    .map_err(|_| ResolveError::MalformedValue { slot: name.clone() })?;
                if !manifest.principals().contains_key(&label) {
                    return Err(ResolveError::UndeclaredPrincipal { principal: label });
                }
                principal_labels.insert(name.clone(), label);
            }
            slots.insert(
                name.clone(),
                SlotBinding {
                    value: value.clone(),
                    source,
                    supplied_by: supplier,
                    digest: Sha256Digest::of(value.as_str().as_bytes()),
                },
            );
        }

        // Two principal slots bound to one declared principal is not a
        // testable pair, and neither is one instrument session bound twice.
        let mut distinct = BTreeSet::new();
        for label in principal_labels.values() {
            if !distinct.insert(label) {
                return Err(ResolveError::SamePrincipal {
                    principal: label.clone(),
                });
            }
        }
        let mut sessions = BTreeSet::new();
        for label in principal_labels.values() {
            let principal = manifest
                .principals()
                .get(label)
                .expect("a bound principal label is declared");
            if !sessions.insert(&principal.session) {
                return Err(ResolveError::SamePrincipal {
                    principal: label.clone(),
                });
            }
            if let Some(verifier_session) = &principal.verifier_session
                && !sessions.insert(verifier_session)
            {
                return Err(ResolveError::SamePrincipal {
                    principal: label.clone(),
                });
            }
        }

        check_read_method(template, &slots, methods)?;

        if !missing.is_empty() {
            return Ok(Resolution::Incomplete(MissingSlots {
                template: compiled.versioned_id(),
                claim_class: template.claim_class.clone(),
                resolved: slots,
                missing,
            }));
        }

        let property = match (&claim.property, property) {
            (Some(label), Some(declaration)) => Some(PropertyBinding {
                label: label.clone(),
                resource: declaration.resource.clone(),
                digest: property_digest(declaration)?,
            }),
            _ => None,
        };
        let mut principals = BTreeMap::new();
        for (name, label) in &principal_labels {
            let principal = manifest
                .principals()
                .get(label)
                .expect("a bound principal label is declared");
            principals.insert(
                name.clone(),
                BoundPrincipal {
                    principal: label.clone(),
                    session: principal.session.clone(),
                    verifier_session: principal.verifier_session.clone(),
                    groups: principal.groups.clone(),
                    identity_probe: principal.identity_probe.clone(),
                },
            );
        }

        Ok(Resolution::Ready(FrozenExperiment {
            template: compiled.versioned_id(),
            engagement: EngagementBinding {
                revision: manifest.revision(),
                digest: manifest.digest().clone(),
            },
            property,
            slots,
            principals,
            oracle: compiled.oracle.clone(),
            decoder: compiled.decoder.clone(),
            effects: compiled.effect_profile(),
        }))
    }
}

fn index(values: &[SlotValue]) -> Result<BTreeMap<&SlotName, &WireText>, ResolveError> {
    let mut index = BTreeMap::new();
    for value in values {
        if index.insert(&value.name, &value.value).is_some() {
            return Err(ResolveError::DuplicateSlot {
                slot: value.name.clone(),
            });
        }
    }
    Ok(index)
}

/// A supplier may supply a slot only when the template says so, and no channel
/// may supply a property slot: the declared property fixes those (INV-36).
fn check_supplier(
    template: &ClaimTemplate,
    name: &SlotName,
    supplied: SuppliedBy,
) -> Result<(), ResolveError> {
    let declaration = template
        .slots
        .get(name)
        .expect("a supplied slot name is declared");
    if declaration.kind == SlotKind::Property || !declaration.supplied_by.contains(&supplied) {
        return Err(ResolveError::SlotConflict {
            slot: name.clone(),
            supplied,
        });
    }
    Ok(())
}

fn supply<'a>(
    claim: &Claim,
    lead: &'a BTreeMap<&SlotName, &WireText>,
    operator: &'a BTreeMap<&SlotName, &WireText>,
    name: &SlotName,
) -> Option<(&'a WireText, SlotSource, WireText)> {
    if let Some(value) = lead.get(name) {
        return Some((value, SlotSource::Lead, wire(claim.lead.as_str())));
    }
    operator
        .get(name)
        .map(|value| (*value, SlotSource::Engagement, wire(OPERATOR)))
}

fn property_digest(property: &Property) -> Result<Sha256Digest, ResolveError> {
    let bytes = canonical::to_vec(property)?;
    Ok(Sha256Digest::of(&bytes))
}

/// INV-37. A template that declares its `read` slot as a lead-supplied selector
/// must resolve to `GET` or `HEAD`. An unregistered operation, and a value that
/// is not a registered operation reference, has no established safe method, so
/// it is refused too. Nothing is sent either way, and the guard runs before an
/// incomplete form is returned so a refusal is never hidden by a missing slot.
fn check_read_method(
    template: &ClaimTemplate,
    slots: &BTreeMap<SlotName, SlotBinding>,
    methods: &dyn OperationMethods,
) -> Result<(), ResolveError> {
    let read = slot_name(READ_SLOT);
    let Some(declaration) = template.slots.get(&read) else {
        return Ok(());
    };
    if declaration.kind != SlotKind::Selector
        || !declaration.supplied_by.contains(&SuppliedBy::Lead)
    {
        return Ok(());
    }
    let Some(binding) = slots.get(&read) else {
        return Ok(());
    };
    let Ok(operation) = OperationRef::from_str(binding.value.as_str()) else {
        return Err(ResolveError::MethodRefused { slot: read });
    };
    match methods.method(&operation) {
        Some(method) if method.is_safe_read() => Ok(()),
        _ => Err(ResolveError::MethodRefused { slot: read }),
    }
}

// -- Lead input -------------------------------------------------------------

/// The engagement revision and digest a claim was written against. The command
/// checks the engagement revision before a run (§6.1 step 3); resolution checks
/// that the claim and the accepted manifest still agree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EngagementPin {
    pub revision: u64,
    pub digest: Sha256Digest,
}

/// One inert slot value, named by the template's slot and valued by a
/// registered identifier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlotValue {
    pub name: SlotName,
    pub value: WireText,
}

/// A lead's untrusted claim. `lead_slots` is the lead's own input and
/// `overrides` is the operator's `--slot`; the two channels are distinct types
/// so no input can claim a supplier it was not given.
///
/// Whether the operator is allowed to pass an override at all is the caller's
/// boundary, not this module's: in the isolated tier the broker refuses operator
/// actions from the worker (§3.3, INV-39).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Claim {
    pub class: ClaimClass,
    pub engagement: EngagementPin,
    pub lead: LeadId,
    /// The declared property the lead selected, when it named one.
    pub property: Option<Label>,
    pub lead_slots: Vec<SlotValue>,
    pub overrides: Vec<SlotValue>,
}

// -- Outcome ----------------------------------------------------------------

string_enum! {
    // Why a declared slot is still unfilled.
    pub enum MissingReason {
        NotSupplied => "not_supplied",
        NoPropertySelected => "no_property_selected",
        PropertyFixesNothing => "property_fixes_nothing",
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MissingSlot {
    pub name: SlotName,
    pub kind: SlotKind,
    pub supplied_by: Vec<SuppliedBy>,
    pub reason: MissingReason,
}

/// The form `verify --plan` prints for an unfilled claim: what is resolved, and
/// what remains, with the reason and who may supply it. Nothing here is frozen.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MissingSlots {
    pub template: VersionedId,
    pub claim_class: ClaimClass,
    pub resolved: BTreeMap<SlotName, SlotBinding>,
    pub missing: Vec<MissingSlot>,
}

/// Either the frozen experiment or the precise slots that are still missing.
#[allow(
    clippy::large_enum_variant,
    reason = "one resolution is produced per plan or verify, and the caller takes the frozen experiment by value"
)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Resolution {
    Ready(FrozenExperiment),
    Incomplete(MissingSlots),
}

impl Resolution {
    pub fn ready(self) -> Result<FrozenExperiment, MissingSlots> {
        match self {
            Self::Ready(experiment) => Ok(experiment),
            Self::Incomplete(missing) => Err(missing),
        }
    }
}

// -- The frozen experiment --------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EngagementBinding {
    pub revision: u64,
    pub digest: Sha256Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PropertyBinding {
    pub label: Label,
    pub resource: ResourceRef,
    pub digest: Sha256Digest,
}

/// The provenance of one resolved slot, in the frozen verification-record shape
/// (`slot`): the inert value, the frozen `slot_source`, the supplier identity,
/// and the digest of the exact value bytes.
///
/// A property slot records `engagement`: the operator declared the property the
/// value comes from. A principal or other slot the operator passed as `--slot`
/// records `engagement` too, because `slot_source` has exactly one operator-side
/// variant; a lead-supplied value records `lead` and the lead's own identity. A
/// value's supplier is therefore never something the input claims, it is the
/// channel that carried it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlotBinding {
    pub value: WireText,
    pub source: SlotSource,
    pub supplied_by: WireText,
    pub digest: Sha256Digest,
}

/// The instrument-side binding of one principal role. Sessions are opaque
/// credential references; no secret enters the record (INV-23).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundPrincipal {
    pub principal: Label,
    pub session: SessionRef,
    pub verifier_session: Option<SessionRef>,
    pub groups: Option<Vec<GroupRef>>,
    pub identity_probe: IdentityProbe,
}

/// The frozen test. Every field is bound by the experiment digest; per-run data
/// (canaries, the run nonce) belongs to the run and its evidence instead (§6.9).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrozenExperiment {
    pub template: VersionedId,
    pub engagement: EngagementBinding,
    pub property: Option<PropertyBinding>,
    pub slots: BTreeMap<SlotName, SlotBinding>,
    pub principals: BTreeMap<SlotName, BoundPrincipal>,
    pub oracle: VersionedDigest,
    pub decoder: DecoderBinding,
    pub effects: Vec<ActionEffect>,
}

impl FrozenExperiment {
    /// The canonical bytes the evidence store retains and the digest that binds
    /// them. Keys are sorted, so the same frozen test always yields the same
    /// bytes and the same digest.
    pub fn freeze(&self) -> Result<(Vec<u8>, Sha256Digest), JsonError> {
        let bytes = canonical::to_vec(self)?;
        let digest = Sha256Digest::of(&bytes);
        Ok((bytes, digest))
    }

    /// Read retained bytes with their trusted digest, rejecting non-canonical
    /// bytes and unknown fields (INV-44, §6.9).
    pub fn from_canonical_bytes(bytes: &[u8], expected: &Sha256Digest) -> Result<Self, JsonError> {
        if &Sha256Digest::of(bytes) != expected {
            return Err(JsonError::DigestMismatch);
        }
        canonical::from_canonical_slice(bytes)
    }
}

impl canonical::sealed::Sealed for FrozenExperiment {}

// -- Refusals ---------------------------------------------------------------

/// A resolution refusal. Nothing has been sent, and the frozen error code says
/// which exit the command uses (§8.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResolveError {
    /// No compiled template measures this claim class.
    UnsupportedClass { supported: Vec<ClaimClass> },
    /// The claim names a slot the template does not declare.
    UnknownSlot { declared: Vec<SlotName> },
    /// One channel supplied the same slot twice.
    DuplicateSlot { slot: SlotName },
    /// Both channels supplied one slot.
    AmbiguousSlot { slot: SlotName },
    /// The property fixes the slot, or the template does not permit that supplier.
    SlotConflict {
        slot: SlotName,
        supplied: SuppliedBy,
    },
    /// A slot value is not a registered identifier of its kind.
    MalformedValue { slot: SlotName },
    /// The claim names a property the engagement does not declare.
    UndeclaredProperty { property: Label },
    /// The claim names a principal the engagement does not declare.
    UndeclaredPrincipal { principal: Label },
    /// Two principal slots name one principal, or one instrument session.
    SamePrincipal { principal: Label },
    /// The claim was written against another engagement revision.
    EngagementMismatch { supplied: u64, engaged: u64 },
    /// The engagement does not allow an effect the template needs.
    EffectNotAllowed { effect: ActionEffect },
    /// INV-37: the resolved read method is not safe, or is not established.
    MethodRefused { slot: SlotName },
    /// The declared property could not be encoded canonically.
    Canonical(JsonError),
}

impl ResolveError {
    /// The frozen error code, and with it the exit code from `error_exits`.
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::UnsupportedClass { .. } => ErrorCode::OracleUnavailable,
            Self::UnknownSlot { .. } | Self::MalformedValue { .. } => ErrorCode::UsageError,
            Self::DuplicateSlot { .. } | Self::AmbiguousSlot { .. } => ErrorCode::InputAmbiguous,
            Self::SlotConflict { .. } => ErrorCode::SlotConflict,
            Self::UndeclaredProperty { .. } | Self::UndeclaredPrincipal { .. } => {
                ErrorCode::ObjectNotFound
            }
            Self::SamePrincipal { .. } => ErrorCode::InputAmbiguous,
            Self::EngagementMismatch { .. } | Self::EffectNotAllowed { .. } => {
                ErrorCode::ScopeRefused
            }
            Self::MethodRefused { .. } => ErrorCode::MethodRefused,
            Self::Canonical(_) => ErrorCode::IntegrityFailure,
        }
    }

    pub fn exit_code(&self) -> u8 {
        self.code().exit_code()
    }
}

fn join<'a>(items: impl IntoIterator<Item = &'a str>) -> String {
    items.into_iter().collect::<Vec<_>>().join(", ")
}

impl fmt::Display for ResolveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedClass { supported } => write!(
                formatter,
                "no compiled template measures this claim class; supported classes are {}",
                join(supported.iter().map(|class| class.as_str()))
            ),
            Self::UnknownSlot { declared } => write!(
                formatter,
                "the claim names a slot the template does not declare; declared slots are {}",
                join(declared.iter().map(|slot| slot.as_str()))
            ),
            Self::DuplicateSlot { slot } => {
                write!(formatter, "slot {} is supplied twice", slot.as_str())
            }
            Self::AmbiguousSlot { slot } => write!(
                formatter,
                "slot {} is supplied by both the claim and an override",
                slot.as_str()
            ),
            Self::SlotConflict { slot, supplied } => write!(
                formatter,
                "slot {} may not be supplied by the {}: the declared property fixes it or the template does not permit that supplier",
                slot.as_str(),
                supplied.as_str()
            ),
            Self::MalformedValue { slot } => write!(
                formatter,
                "slot {} is not a registered identifier of its declared kind",
                slot.as_str()
            ),
            Self::UndeclaredProperty { property } => {
                write!(
                    formatter,
                    "property {} is not declared in the engagement",
                    property.as_str()
                )
            }
            Self::UndeclaredPrincipal { principal } => write!(
                formatter,
                "principal {} is not declared in the engagement",
                principal.as_str()
            ),
            Self::SamePrincipal { principal } => write!(
                formatter,
                "principal {} is bound to more than one principal slot",
                principal.as_str()
            ),
            Self::EngagementMismatch { supplied, engaged } => write!(
                formatter,
                "the claim is written against engagement revision {supplied}, not the accepted revision {engaged}"
            ),
            Self::EffectNotAllowed { effect } => {
                write!(
                    formatter,
                    "the engagement does not allow the {effect:?} effect"
                )
            }
            Self::MethodRefused { slot } => write!(
                formatter,
                "slot {} does not resolve to a safe read method, so the run is refused",
                slot.as_str()
            ),
            Self::Canonical(error) => {
                write!(formatter, "the declared property is not canonical: {error}")
            }
        }
    }
}

impl std::error::Error for ResolveError {}

impl From<JsonError> for ResolveError {
    fn from(error: JsonError) -> Self {
        Self::Canonical(error)
    }
}

// -- The trusted operation registry's read-only projection ------------------

string_enum! {
    // The HTTP method a registered operation resolves to.
    pub enum Method {
        Get => "GET",
        Head => "HEAD",
        Post => "POST",
        Put => "PUT",
        Patch => "PATCH",
        Delete => "DELETE",
        Options => "OPTIONS",
        Trace => "TRACE",
        Connect => "CONNECT",
    }
}

impl Method {
    /// The methods a lead-supplied read selector may resolve to (INV-37).
    pub fn is_safe_read(self) -> bool {
        matches!(self, Self::Get | Self::Head)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Head => "HEAD",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Patch => "PATCH",
            Self::Delete => "DELETE",
            Self::Options => "OPTIONS",
            Self::Trace => "TRACE",
            Self::Connect => "CONNECT",
        }
    }
}

/// The trusted operation registry's read-only projection. It answers with an
/// inert method name; it sends nothing. An operation this build does not
/// register answers `None`, and the guard refuses rather than assuming safety.
pub trait OperationMethods {
    fn method(&self, operation: &OperationRef) -> Option<Method>;
}

/// No registered operation is known. The shipped template never consults this,
/// because it permits no lead-supplied read selector.
pub struct NoMethods;

impl OperationMethods for NoMethods {
    fn method(&self, _operation: &OperationRef) -> Option<Method> {
        None
    }
}

#[cfg(test)]
mod tests;
