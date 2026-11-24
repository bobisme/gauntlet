//! Unit tests for the compiled claim-template registry and pure resolution.
//!
//! Every test here is offline. The compiled registry is compared with the frozen
//! example, refusals are checked against the frozen error-code table, and the
//! experiment digest is checked field by field and against per-run stability.

use std::{cell::Cell, collections::BTreeMap, str::FromStr};

use serde_json::{Value, json};

use super::*;
use crate::{
    engagement::{EngagementDraft, PassPin, PassRef, SelectorRef},
    ids::RunNonce,
    wire::ErrorCode,
};

const ENGAGEMENT: &[u8] =
    include_bytes!("../../../../fixtures/target/schema-examples/engagement.toml");
const CLAIM_TEMPLATE: &[u8] = include_bytes!(
    "../../../../fixtures/target/schema-examples/claim-template-private-object-read.json"
);
const ORACLE_REGISTRY: &[u8] =
    include_bytes!("../../../../docs/contracts/oracle-specifications.v1.json");
const VERIFICATION_RECORD: &[u8] =
    include_bytes!("../../../../fixtures/contracts/scourge-v1/verification-record.json");
const CONTRACT_REGISTRY: &[u8] = include_bytes!("../../../../docs/contracts/scourge-v1.json");
const CLAIM_TEMPLATE_SCHEMA: &[u8] =
    include_bytes!("../../../../schemas/claim-template.v1.schema.json");

const PRIVATE_OBJECT_READ: &str = "web-authz/private-object-read";
const STATE_CHANGE: &str = "web-authz/state-change";

fn pass_ref() -> PassRef {
    PassRef::from_str("pass.development-fixture").unwrap()
}

fn pass_digest() -> Sha256Digest {
    Sha256Digest::of(b"fixture pass")
}

fn accept(draft: EngagementDraft) -> ManifestRevision {
    draft
        .accept(PassPin {
            reference: &pass_ref(),
            digest: &pass_digest(),
        })
        .unwrap()
}

fn manifest() -> ManifestRevision {
    accept(EngagementDraft::parse_toml(ENGAGEMENT).unwrap())
}

fn label(value: &str) -> Label {
    Label::from_str(value).unwrap()
}

fn slot(value: &str) -> SlotName {
    SlotName::from_str(value).unwrap()
}

fn class(value: &str) -> ClaimClass {
    ClaimClass::from_str(value).unwrap()
}

fn value(name: &str, value: &str) -> SlotValue {
    SlotValue {
        name: slot(name),
        value: wire(value),
    }
}

fn base_claim(engagement: &ManifestRevision) -> Claim {
    Claim {
        class: class(PRIVATE_OBJECT_READ),
        engagement: EngagementPin {
            revision: engagement.revision(),
            digest: engagement.digest().clone(),
        },
        lead: LeadId::from_str("L-worker").unwrap(),
        property: Some(label("orders")),
        lead_slots: vec![value("owner", "alice"), value("other", "bob")],
        overrides: Vec::new(),
    }
}

fn frozen(engagement: &ManifestRevision) -> FrozenExperiment {
    Templates::resolve(&base_claim(engagement), engagement)
        .unwrap()
        .ready()
        .expect("the complete claim resolves")
}

fn digest_of(experiment: &FrozenExperiment) -> Sha256Digest {
    experiment.freeze().unwrap().1
}

fn resolve_error(claim: &Claim, engagement: &ManifestRevision) -> ResolveError {
    Templates::resolve(claim, engagement).unwrap_err()
}

fn template_error(document: &Value) -> TemplateError {
    let bytes = serde_json::to_vec(document).unwrap();
    match ClaimTemplate::parse_json(&bytes) {
        Ok(template) => template.validate().unwrap_err(),
        Err(error) => error,
    }
}

fn frozen_document() -> Value {
    canonical::parse(CLAIM_TEMPLATE).unwrap()
}

fn template_issue(document: &Value) -> TemplateIssue {
    match template_error(document) {
        TemplateError::Template { issue, .. } => issue,
        TemplateError::Declaration(error) => panic!("expected a template issue, got {error}"),
    }
}

fn oracle(name: &str, version: &str, digest_seed: &[u8]) -> VersionedDigest {
    VersionedDigest {
        id: wire(name),
        version: wire(version),
        digest: Sha256Digest::of(digest_seed),
    }
}

/// A synthetic template of a registered class that permits a lead-supplied read
/// selector and fixes a `write` property slot. It exists only to exercise the
/// generic resolver: F-39's method guard and a property that fixes no operation
/// for a slot the template needs.
fn state_change_template() -> ClaimTemplate {
    let either = vec![SuppliedBy::Operator, SuppliedBy::Lead];
    ClaimTemplate {
        schema_version: TemplateSchemaVersion::V1,
        claim_class: class(STATE_CHANGE),
        template_version: 1,
        slots: BTreeMap::from([
            (
                slot("owner"),
                SlotDeclaration {
                    kind: SlotKind::Principal,
                    supplied_by: either.clone(),
                },
            ),
            (
                slot("read"),
                SlotDeclaration {
                    kind: SlotKind::Selector,
                    supplied_by: either,
                },
            ),
            (
                slot("write"),
                SlotDeclaration {
                    kind: SlotKind::Property,
                    supplied_by: vec![SuppliedBy::Operator],
                },
            ),
        ]),
        recipe: vec![
            recipe_step(
                "probe.owner",
                "operation.probe.identity",
                &["owner"],
                ActionEffect::None,
                &[],
            ),
            recipe_step(
                "observe",
                "operation.read.object",
                &["read"],
                ActionEffect::Observe,
                &["control.observer_valid"],
            ),
            recipe_step(
                "plant.write",
                "operation.plant.object",
                &["owner", "write"],
                ActionEffect::Plant,
                &[],
            ),
            recipe_step(
                "cleanup.objects",
                "operation.cleanup.objects",
                &["owner"],
                ActionEffect::Plant,
                &["control.cleanup_recorded"],
            ),
        ],
        controls: BTreeMap::from([
            (
                control_id("control.observer_valid"),
                control("observe", "A broken observer", "OBSERVER_INVALID"),
            ),
            (
                control_id("control.cleanup_recorded"),
                control(
                    "cleanup.objects",
                    "A removal the run cannot attribute",
                    "CLEANUP_UNCONFIRMED",
                ),
            ),
        ]),
        oracle: TemplateOracle {
            id: oracle_ref("oracle.web.forbidden-state-change.v1"),
            scope: OracleScope::StateChange,
        },
        cleanup: Cleanup {
            step: step_id("cleanup.objects"),
            evidence_required: prose("The plant and removal responses"),
        },
        retest_variants: BTreeMap::from([
            (
                slot("security_property"),
                RetestVariant {
                    step: step_id("observe"),
                    result_dimension: RetestDimension::SecurityProperty,
                },
            ),
            (
                slot("legitimate_path"),
                RetestVariant {
                    step: step_id("probe.owner"),
                    result_dimension: RetestDimension::LegitimatePath,
                },
            ),
        ]),
    }
}

fn state_change_compiled() -> CompiledTemplate {
    CompiledTemplate::new(
        state_change_template(),
        oracle(
            "web.forbidden-state-change",
            "1",
            b"synthetic state-change oracle",
        ),
        decoder_binding(),
    )
    .expect("the synthetic template is well formed")
}

fn state_change_claim(engagement: &ManifestRevision) -> Claim {
    Claim {
        class: class(STATE_CHANGE),
        engagement: EngagementPin {
            revision: engagement.revision(),
            digest: engagement.digest().clone(),
        },
        lead: LeadId::from_str("L-worker").unwrap(),
        property: Some(label("orders")),
        lead_slots: vec![
            value("owner", "alice"),
            value("read", "operation.orders.read"),
        ],
        overrides: Vec::new(),
    }
}

/// A read-only operation registry projection that records every lookup.
struct Registry {
    methods: BTreeMap<String, Method>,
    calls: Cell<usize>,
}

impl Registry {
    fn new(methods: &[(&str, Method)]) -> Self {
        Self {
            methods: methods
                .iter()
                .map(|(name, method)| ((*name).to_owned(), *method))
                .collect(),
            calls: Cell::new(0),
        }
    }

    fn calls(&self) -> usize {
        self.calls.get()
    }
}

impl OperationMethods for Registry {
    fn method(&self, operation: &OperationRef) -> Option<Method> {
        self.calls.set(self.calls.get() + 1);
        self.methods.get(operation.as_str()).copied()
    }
}

fn state_change_resolution(claim: &Claim, methods: &Registry) -> Result<Resolution, ResolveError> {
    let registry = [state_change_compiled()];
    Templates::resolve_in(&registry, claim, &manifest(), methods)
}

// -- The compiled registry --------------------------------------------------

#[test]
fn the_compiled_registry_is_the_frozen_example() {
    let registry = Templates::registry();
    assert_eq!(registry.len(), 1);
    let compiled = &registry[0];
    let frozen: Value = frozen_document();
    let compiled: Value =
        canonical::parse(&canonical::to_vec(&compiled.template).unwrap()).unwrap();
    assert_eq!(compiled, frozen);

    let template = &Templates::template(&class(PRIVATE_OBJECT_READ))
        .unwrap()
        .template;
    assert_eq!(template.schema_version, TemplateSchemaVersion::V1);
    assert_eq!(template.claim_class.as_str(), PRIVATE_OBJECT_READ);
    assert_eq!(template.template_version, 1);
    assert_eq!(
        template.versioned_id(),
        VersionedId {
            id: wire(PRIVATE_OBJECT_READ),
            version: wire("1"),
        }
    );
    assert_eq!(
        template.oracle,
        TemplateOracle {
            id: oracle_ref(ORACLE_CONTRACT),
            scope: OracleScope::ObjectRead,
        }
    );
    assert!(Templates::template(&class(STATE_CHANGE)).is_none());
}

#[test]
fn the_compiled_recipe_keeps_its_frozen_order() {
    let template = &Templates::registry()[0].template;
    let steps: Vec<&str> = template
        .recipe
        .iter()
        .map(|step| step.id.as_str())
        .collect();
    assert_eq!(
        steps,
        [
            "probe.owner.first",
            "probe.other.first",
            "plant.first",
            "plant.second",
            "read.anonymous.first",
            "read.owner.first",
            "read.other.first",
            "read.anonymous.last",
            "read.other.second",
            "probe.owner.last",
            "probe.other.last",
            "cleanup.objects",
        ]
    );
    let operations: Vec<&str> = template
        .recipe
        .iter()
        .map(|step| step.operation.as_str())
        .collect();
    assert_eq!(
        operations,
        [
            "operation.probe.identity",
            "operation.probe.identity",
            "operation.plant.object",
            "operation.plant.object",
            "operation.read.object",
            "operation.read.object",
            "operation.read.object",
            "operation.read.object",
            "operation.read.object",
            "operation.probe.identity",
            "operation.probe.identity",
            "operation.cleanup.objects",
        ]
    );
    let effects: Vec<ActionEffect> = template.recipe.iter().map(|step| step.effect).collect();
    assert_eq!(
        effects,
        [
            ActionEffect::None,
            ActionEffect::None,
            ActionEffect::Plant,
            ActionEffect::Plant,
            ActionEffect::Observe,
            ActionEffect::Observe,
            ActionEffect::Observe,
            ActionEffect::Observe,
            ActionEffect::Observe,
            ActionEffect::None,
            ActionEffect::None,
            ActionEffect::Plant,
        ]
    );
    assert_eq!(
        Templates::registry()[0].effect_profile(),
        vec![ActionEffect::Plant, ActionEffect::Observe]
    );
}

#[test]
fn the_registry_must_be_unique_and_ordered() {
    let object_read = &Templates::registry()[0];
    validate_registry(Templates::registry()).unwrap();

    let duplicated = [object_read.clone(), object_read.clone()];
    assert_eq!(
        validate_registry(&duplicated).unwrap_err(),
        issue("registry", TemplateIssue::DuplicateRegistryEntry)
    );

    let unordered = [state_change_compiled(), object_read.clone()];
    assert_eq!(
        validate_registry(&unordered).unwrap_err(),
        issue("registry", TemplateIssue::UnorderedRegistry)
    );
    validate_registry(&[object_read.clone(), state_change_compiled()]).unwrap();
}

#[test]
fn the_compiled_oracle_and_decoder_match_the_frozen_records() {
    let oracles: Value = canonical::parse(ORACLE_REGISTRY).unwrap();
    let entry = &oracles["oracles"]["web.private-object-read.v1"];
    let bytes = canonical::to_vec(entry).unwrap();
    assert_eq!(Sha256Digest::of(&bytes).as_str(), ORACLE_DIGEST);

    let record: Value = canonical::parse(VERIFICATION_RECORD).unwrap();
    assert_eq!(record["template"]["id"], "web-authz/private-object-read");
    assert_eq!(record["template"]["version"], "1");
    assert_eq!(record["oracle"]["id"], ORACLE_ID);
    assert_eq!(record["oracle"]["version"], ORACLE_VERSION);
    assert_eq!(record["rounds"][0]["flows"][0]["decoder"]["id"], DECODER_ID);
    assert_eq!(
        record["rounds"][0]["flows"][0]["decoder"]["version"],
        DECODER_VERSION
    );

    let compiled = &Templates::registry()[0];
    assert_eq!(compiled.oracle.id.as_str(), ORACLE_ID);
    assert_eq!(compiled.oracle.version.as_str(), ORACLE_VERSION);
    assert_eq!(compiled.oracle.digest.as_str(), ORACLE_DIGEST);
    assert_eq!(compiled.decoder.identity.id.as_str(), DECODER_ID);
    assert_eq!(compiled.decoder.identity.version.as_str(), DECODER_VERSION);
}

#[test]
fn a_compiled_oracle_identity_must_match_its_contract_reference() {
    let decoder = decoder_binding();
    let mismatched = CompiledTemplate::new(
        private_object_read(),
        oracle("web.private-object-reader", "1", b"other"),
        decoder.clone(),
    );
    assert_eq!(
        mismatched.unwrap_err(),
        issue("oracle", TemplateIssue::UnregisteredOracle)
    );
    let wrong_version = CompiledTemplate::new(
        private_object_read(),
        oracle(ORACLE_ID, "2", b"other"),
        decoder,
    );
    assert_eq!(
        wrong_version.unwrap_err(),
        issue("oracle", TemplateIssue::UnregisteredOracle)
    );
}

// -- Schema tags, literals and the ADR rules --------------------------------

#[test]
fn the_template_parser_is_strict() {
    let text = String::from_utf8(CLAIM_TEMPLATE.to_vec()).unwrap();

    let duplicate = text.replacen(
        "\"claim_class\": \"web-authz/private-object-read\",",
        "\"claim_class\": \"web-authz/private-object-read\",\n  \"claim_class\": \"web-authz/private-object-read\",",
        1,
    );
    assert!(matches!(
        ClaimTemplate::parse_json(duplicate.as_bytes()),
        Err(TemplateError::Declaration(_))
    ));

    let extra = text.replacen(
        "\"schema_version\": \"scourge.claim-template.v1\",",
        "\"schema_version\": \"scourge.claim-template.v1\",\n  \"request\": \"GET /orders\",",
        1,
    );
    assert!(matches!(
        ClaimTemplate::parse_json(extra.as_bytes()),
        Err(TemplateError::Declaration(_))
    ));

    let wrong_tag = text.replacen("scourge.claim-template.v1", "scourge.claim-template.v2", 1);
    assert!(matches!(
        ClaimTemplate::parse_json(wrong_tag.as_bytes()),
        Err(TemplateError::Declaration(_))
    ));

    // A registered operation reference is the only shape an inert operation may take.
    let mut document = frozen_document();
    document["recipe"][0]["operation"] = json!("GET /orders");
    assert!(matches!(
        ClaimTemplate::parse_json(&serde_json::to_vec(&document).unwrap()),
        Err(TemplateError::Declaration(_))
    ));
}

// -- The frozen `ref_name` and `reason_code` patterns ------------------------

type ReferenceSetter = fn(&mut Value, &str);

fn set_recipe_id(document: &mut Value, value: &str) {
    document["recipe"][0]["id"] = json!(value);
}

fn set_recipe_control(document: &mut Value, value: &str) {
    document["recipe"][0]["controls"][0] = json!(value);
}

fn set_control_key(document: &mut Value, value: &str) {
    let controls = document["controls"].as_object_mut().unwrap();
    let body = controls.remove("control.distinct_subject").unwrap();
    controls.insert(value.to_owned(), body);
}

fn set_control_step(document: &mut Value, value: &str) {
    document["controls"]["control.distinct_subject"]["step"] = json!(value);
}

fn set_cleanup_step(document: &mut Value, value: &str) {
    document["cleanup"]["step"] = json!(value);
}

fn set_retest_step(document: &mut Value, value: &str) {
    document["retest_variants"]["security_property"]["step"] = json!(value);
}

/// Every place a claim template carries a `ref_name`.
const REFERENCE_POSITIONS: &[(&str, ReferenceSetter)] = &[
    ("recipe[].id", set_recipe_id),
    ("recipe[].controls[]", set_recipe_control),
    ("controls key", set_control_key),
    ("controls[].step", set_control_step),
    ("cleanup.step", set_cleanup_step),
    ("retest_variants[].step", set_retest_step),
];

/// A frozen schema pattern as a decision over a whole value.
///
/// The checked-in patterns anchor the start with `^` and the end with Python's
/// lookahead guard, `(?![\s\S])`, rather than `$` (Python's `$` also matches
/// before a trailing newline). Rust's regex engine has no lookaround, but its
/// `$` is a strict end-of-haystack anchor, so the guard is replaced with `$`.
/// The result is still a search, but it is anchored at both ends.
fn frozen_pattern(name: &str) -> regex::Regex {
    let schema: Value = canonical::parse(CLAIM_TEMPLATE_SCHEMA).unwrap();
    let pattern = schema["$defs"][name]["pattern"].as_str().unwrap();
    let anchored = pattern
        .strip_suffix("(?![\\s\\S])")
        .map(|head| format!("{head}$"))
        .expect("the frozen patterns end with an end-of-string guard");
    regex::Regex::new(&anchored).unwrap()
}

/// A 32-byte segment, the longest the pattern allows after the first.
fn segment32() -> String {
    format!("s{}", "0".repeat(31))
}

/// `[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]{0,31}){0,4}` at its maximum: five
/// segments whose four dotted parts are each exactly 32 bytes.
fn longest_reference() -> String {
    let segment = segment32();
    format!("a.{segment}.{segment}.{segment}.{segment}")
}

fn reference_candidates() -> Vec<String> {
    let segment = segment32();
    let mut candidates = vec![
        String::new(),
        ".".to_owned(),
        "a".to_owned(),
        "a.".to_owned(),
        ".a".to_owned(),
        "a..b".to_owned(),
        "a.b".to_owned(),
        "a.b.c.d.e".to_owned(),
        "a.b.c.d.e.f".to_owned(),
        "a.b.c.d.e.f.g".to_owned(),
        "a.b.c.d.e.f.g.h".to_owned(),
        "a.b.c.d.e.f.GET /admin".to_owned(),
        "a.b.c.d.e.f.https://attacker.example/x".to_owned(),
        "a.b.c.d.e.f.6".to_owned(),
        "a.b.c.d.e.f.A".to_owned(),
        "a.b.c.d.e.f._".to_owned(),
        "a.b.c.d.e.f.b-c".to_owned(),
        "a.b.c.d.e.f.b c".to_owned(),
        "a.b.c.d.e.f.b\n".to_owned(),
        "a.b.c.d.e.f.bé".to_owned(),
        "A".to_owned(),
        "a_b.c9.d_0.e.f".to_owned(),
        format!("{}.b", "a".repeat(64)),
        longest_reference(),
        longest_reference() + ".f",
        format!("a.{segment}.{segment}.{segment}.{segment}{}", "0"),
    ];
    for parts in 0..=8 {
        candidates.push(
            (0..parts)
                .map(|index| format!("p{index}"))
                .collect::<Vec<_>>()
                .join("."),
        );
    }
    candidates
}

#[test]
fn template_references_are_exactly_the_frozen_ref_name() {
    let pattern = frozen_pattern("ref_name");
    let mut accepted = 0;
    let mut rejected = 0;
    for candidate in reference_candidates() {
        let expected = pattern.is_match(&candidate);
        assert_eq!(
            StepId::from_str(&candidate).is_ok(),
            expected,
            "step reference {candidate:?} disagrees with $defs/ref_name"
        );
        assert_eq!(
            ControlId::from_str(&candidate).is_ok(),
            expected,
            "control reference {candidate:?} disagrees with $defs/ref_name"
        );
        if expected {
            accepted += 1;
        } else {
            rejected += 1;
        }
    }
    assert!(
        accepted >= 8 && rejected >= 20,
        "the matrix must exercise both verdicts: {accepted} accepted, {rejected} rejected"
    );
}

#[test]
fn the_longest_valid_reference_is_accepted_and_its_neighbours_are_not() {
    let longest = longest_reference();
    assert_eq!(longest.len(), 133);
    assert!(StepId::from_str(&longest).is_ok());
    assert!(ControlId::from_str(&longest).is_ok());
    // One byte over the 32-byte segment bound, in each dotted position.
    for prefix in ["a", "a.b", "a.b.c", "a.b.c.d"] {
        let over = format!("{prefix}.s{}", "0".repeat(32));
        assert!(
            StepId::from_str(&over).is_err(),
            "{over:?} is one byte too long"
        );
    }
    // A sixth segment is refused even when every earlier segment is minimal.
    assert!(StepId::from_str("a.b.c.d.e.f").is_err());
    assert!(ControlId::from_str("a.b.c.d.e.f").is_err());

    // The longest form is accepted from a document and still validates, so the
    // bound is one the parser reaches rather than a dead branch.
    let step = longest;
    let control = format!("z.{}", &step[2..]);
    let mut document = frozen_document();
    let body = document["controls"]["control.distinct_subject"].clone();
    set_recipe_id(&mut document, &step);
    document["recipe"][0]["controls"] = json!([&control]);
    document["controls"]
        .as_object_mut()
        .unwrap()
        .remove("control.distinct_subject");
    let mut body = body;
    body["step"] = json!(step);
    document["controls"][&control] = body;
    let template = ClaimTemplate::parse_json(&serde_json::to_vec(&document).unwrap()).unwrap();
    template.validate().unwrap();
}

#[test]
fn template_references_past_the_fifth_segment_are_refused_everywhere() {
    let invalid = [
        // Six, seven and eight well-formed segments.
        "a.b.c.d.e.f",
        "a.b.c.d.e.f.g",
        "a.b.c.d.e.f.g.h",
        // A sixth segment that is itself request-shaped or URL-shaped.
        "a.b.c.d.e.f.GET /admin",
        "a.b.c.d.e.f.https://attacker.example/x",
        // A sixth segment with a shape no segment may take.
        "a.b.c.d.e.f.6",
        "a.b.c.d.e.f.B",
        "a.b.c.d.e.f.b-c",
    ];
    for &(position, set) in REFERENCE_POSITIONS {
        for value in invalid {
            let mut document = frozen_document();
            set(&mut document, value);
            assert!(
                matches!(
                    ClaimTemplate::parse_json(&serde_json::to_vec(&document).unwrap()),
                    Err(TemplateError::Declaration(_))
                ),
                "{position} accepted {value:?}"
            );
        }
    }
}

#[test]
fn reason_codes_are_exactly_the_frozen_bounds() {
    let pattern = frozen_pattern("reason_code");
    let mut candidates = vec![
        String::new(),
        "A".to_owned(),
        "AB".to_owned(),
        "1A".to_owned(),
        "_A".to_owned(),
        "Ab".to_owned(),
        "A-".to_owned(),
        "A B".to_owned(),
        "AB\n".to_owned(),
        "ÄB".to_owned(),
        "A_".to_owned(),
    ];
    for length in 0..=70 {
        candidates.push("A".repeat(length));
    }
    let mut accepted = 0;
    let mut rejected = 0;
    for candidate in candidates {
        let expected = pattern.is_match(&candidate);
        assert_eq!(
            ReasonCode::from_str(&candidate).is_ok(),
            expected,
            "reason code {:?} ({} bytes) disagrees with $defs/reason_code",
            candidate,
            candidate.len()
        );
        if expected {
            accepted += 1;
        } else {
            rejected += 1;
        }
    }
    assert!(
        accepted >= 60 && rejected >= 15,
        "the matrix must exercise both verdicts: {accepted} accepted, {rejected} rejected"
    );

    // The two boundaries named by the contract.
    assert!(ReasonCode::from_str("AB").is_ok());
    assert!(ReasonCode::from_str(&format!("A{}", "B".repeat(63))).is_ok());
    assert!(ReasonCode::from_str("A").is_err());
    assert!(ReasonCode::from_str(&format!("A{}", "B".repeat(64))).is_err());
}

#[test]
fn template_controls_reject_reason_codes_outside_the_frozen_bound() {
    let accepted = [
        "AB".to_owned(),
        format!("A{}", "B".repeat(63)),
        "SAME_SUBJECT".to_owned(),
    ];
    for code in &accepted {
        let mut document = frozen_document();
        document["controls"]["control.distinct_subject"]["reason_code"] = json!(code);
        let template = ClaimTemplate::parse_json(&serde_json::to_vec(&document).unwrap())
            .unwrap_or_else(|error| {
                panic!("a {}-byte reason code must parse: {error}", code.len())
            });
        template.validate().unwrap();
    }

    let refused = [
        "A".to_owned(),
        "a".to_owned(),
        format!("A{}", "B".repeat(64)),
    ];
    for code in &refused {
        let mut document = frozen_document();
        document["controls"]["control.distinct_subject"]["reason_code"] = json!(code);
        assert!(
            matches!(
                ClaimTemplate::parse_json(&serde_json::to_vec(&document).unwrap()),
                Err(TemplateError::Declaration(_))
            ),
            "a {}-byte reason code {:?} must be refused",
            code.len(),
            code
        );
    }
}

#[test]
fn every_frozen_oracle_reason_code_is_inside_the_bound() {
    let registry: Value = canonical::parse(ORACLE_REGISTRY).unwrap();
    let mut codes = BTreeSet::new();
    for oracle in registry["oracles"].as_object().unwrap().values() {
        for flow in oracle["flows"].as_array().unwrap() {
            if let Some(code) = flow["failure_code"].as_str() {
                codes.insert(code.to_owned());
            }
        }
        let predicate = &oracle["predicate"];
        for code in predicate["invalid_precedence"].as_array().unwrap() {
            codes.insert(code.as_str().unwrap().to_owned());
        }
        codes.extend(
            oracle["invalid_reasons"]
                .as_object()
                .unwrap()
                .keys()
                .cloned(),
        );
    }
    assert_eq!(
        codes,
        BTreeSet::from([
            "CANARY_NOT_SPECIFIC".to_owned(),
            "EVIDENCE_INCOMPLETE".to_owned(),
            "OBSERVER_INVALID".to_owned(),
            "OWNER_VIEW_LOST".to_owned(),
            "SAME_SUBJECT".to_owned(),
            "SESSION_DRIFT".to_owned(),
        ])
    );
    for code in codes {
        let registered = ReasonCode::from_str(&code)
            .unwrap_or_else(|error| panic!("frozen oracle code {code:?} is refused: {error}"));
        assert_eq!(registered.as_str(), code);
    }
}

#[test]
fn template_validation_enforces_the_frozen_rules() {
    let mut document = frozen_document();
    document["slots"]["read"]["supplied_by"] = json!(["lead", "operator"]);
    assert_eq!(
        template_issue(&document),
        TemplateIssue::PropertySlotNotOperatorOnly
    );

    let mut document = frozen_document();
    document["template_version"] = json!(0);
    assert_eq!(template_issue(&document), TemplateIssue::InvalidVersion);

    let mut document = frozen_document();
    document["slots"]["read"]["supplied_by"] = json!([]);
    assert_eq!(template_issue(&document), TemplateIssue::InvalidEntries);

    let mut document = frozen_document();
    document["slots"]["read"]["supplied_by"] = json!(["operator", "operator"]);
    assert_eq!(template_issue(&document), TemplateIssue::InvalidEntries);

    let mut document = frozen_document();
    document["recipe"][1]["id"] = json!("probe.owner.first");
    assert_eq!(template_issue(&document), TemplateIssue::DuplicateStep);

    let mut document = frozen_document();
    document["recipe"][0]["slots"] = json!(["owner", "missing"]);
    assert_eq!(template_issue(&document), TemplateIssue::SlotNotDeclared);

    let mut document = frozen_document();
    document["recipe"][11]["slots"] = json!(["owner", "plant"]);
    assert_eq!(template_issue(&document), TemplateIssue::SlotCoverage);

    let mut document = frozen_document();
    document["recipe"][1]["controls"] = json!(["control.missing"]);
    assert_eq!(template_issue(&document), TemplateIssue::UnknownControl);

    let mut document = frozen_document();
    document["recipe"][1]["controls"] = json!(["control.distinct_subject"]);
    assert_eq!(
        template_issue(&document),
        TemplateIssue::ControlOnAnotherStep
    );

    let mut document = frozen_document();
    document["controls"]["control.distinct_subject"]["step"] = json!("probe.other.first");
    assert_eq!(
        template_issue(&document),
        TemplateIssue::ControlOnAnotherStep
    );

    let mut document = frozen_document();
    document["controls"]["control.unlisted"] = json!({
        "step": "probe.other.first",
        "rules_out": "Nothing in particular",
        "reason_code": "UNLISTED",
    });
    assert_eq!(template_issue(&document), TemplateIssue::ControlNotOnStep);

    let mut document = frozen_document();
    document["controls"]["control.unlisted"] = json!({
        "step": "missing.step",
        "rules_out": "Nothing in particular",
        "reason_code": "UNLISTED",
    });
    assert_eq!(template_issue(&document), TemplateIssue::UnknownStep);

    let mut document = frozen_document();
    document["cleanup"]["step"] = json!("read.other.first");
    assert_eq!(template_issue(&document), TemplateIssue::CleanupEffect);

    let mut document = frozen_document();
    document["cleanup"]["step"] = json!("missing.step");
    assert_eq!(template_issue(&document), TemplateIssue::UnknownStep);

    let mut document = frozen_document();
    document["retest_variants"]
        .as_object_mut()
        .unwrap()
        .remove("legitimate_path");
    assert_eq!(template_issue(&document), TemplateIssue::RetestDimensions);

    let mut document = frozen_document();
    document["retest_variants"]["security_property"]["step"] = json!("missing.step");
    assert_eq!(template_issue(&document), TemplateIssue::UnknownStep);

    let mut document = frozen_document();
    document["oracle"]["scope"] = json!("existence");
    assert_eq!(template_issue(&document), TemplateIssue::UnregisteredOracle);

    let mut document = frozen_document();
    document["claim_class"] = json!("web-authz/existence");
    assert_eq!(template_issue(&document), TemplateIssue::UnregisteredOracle);

    let mut document = frozen_document();
    document["oracle"]["id"] = json!("oracle.web.private-object-read.v2");
    assert_eq!(template_issue(&document), TemplateIssue::UnregisteredOracle);
}

#[test]
fn property_and_principal_slots_are_registered_roles() {
    let mut document = frozen_document();
    document["slots"]["payload"] = json!({"kind": "property", "supplied_by": ["operator"]});
    assert_eq!(
        template_issue(&document),
        TemplateIssue::UnknownPropertySlot
    );

    let mut document = frozen_document();
    document["slots"]["viewer"] = json!({"kind": "principal", "supplied_by": ["operator"]});
    assert_eq!(
        template_issue(&document),
        TemplateIssue::UnknownPrincipalSlot
    );
}

#[test]
fn the_synthetic_template_is_well_formed_and_guarded() {
    let compiled = state_change_compiled();
    compiled.template.validate().unwrap();
    assert_eq!(
        compiled.effect_profile(),
        vec![ActionEffect::Observe, ActionEffect::Plant]
    );
    assert_eq!(
        registered_oracle_scope(
            &class(STATE_CHANGE),
            &oracle_ref("oracle.web.forbidden-state-change.v1")
        ),
        Some(OracleScope::StateChange)
    );
    assert_eq!(
        registered_oracle_scope(
            &class("web-authz/collection-disclosure"),
            &oracle_ref("oracle.web.private-object-read.v1")
        ),
        None
    );
}

// -- Resolution: the declared property and the principal pair ----------------

#[test]
fn resolve_binds_the_declared_property_and_the_principal_pair() {
    let engagement = manifest();
    let experiment = frozen(&engagement);

    assert_eq!(experiment.template.id.as_str(), PRIVATE_OBJECT_READ);
    assert_eq!(experiment.template.version.as_str(), "1");
    assert_eq!(experiment.engagement.revision, engagement.revision());
    assert_eq!(&experiment.engagement.digest, engagement.digest());

    let orders = engagement.properties().get(&label("orders")).unwrap();
    let property = experiment.property.as_ref().unwrap();
    assert_eq!(property.label.as_str(), "orders");
    assert_eq!(property.resource.as_str(), "resource.orders");
    assert_eq!(
        &property.digest,
        &Sha256Digest::of(&canonical::to_vec(orders).unwrap())
    );

    for (name, operation) in [
        ("read", "operation.orders.read"),
        ("plant", "operation.orders.create"),
        ("remove", "operation.orders.delete"),
    ] {
        let bound = &experiment.slots[&slot(name)];
        assert_eq!(bound.value.as_str(), operation);
        assert_eq!(bound.source, SlotSource::Engagement);
        assert_eq!(bound.supplied_by.as_str(), "operator");
        assert_eq!(&bound.digest, &Sha256Digest::of(operation.as_bytes()));
        OperationRef::from_str(bound.value.as_str()).unwrap();
    }
    for (name, principal) in [("owner", "alice"), ("other", "bob")] {
        let bound = &experiment.slots[&slot(name)];
        assert_eq!(bound.value.as_str(), principal);
        assert_eq!(bound.source, SlotSource::Lead);
        assert_eq!(bound.supplied_by.as_str(), "L-worker");
        assert_eq!(&bound.digest, &Sha256Digest::of(principal.as_bytes()));
    }
    assert_eq!(experiment.slots.len(), 5);

    let owner = &experiment.principals[&slot("owner")];
    assert_eq!(owner.principal.as_str(), "alice");
    assert_eq!(owner.session.as_str(), "session.alice");
    assert_eq!(
        owner.verifier_session.as_ref().unwrap().as_str(),
        "session.alice.verify"
    );
    assert_eq!(owner.groups.as_ref().unwrap()[0].as_str(), "group.tenant-a");
    assert_eq!(
        owner.identity_probe.operation.as_str(),
        "operation.identity.probe"
    );
    assert_eq!(
        owner.identity_probe.subject.as_str(),
        "selector.identity.subject"
    );
    assert_eq!(
        experiment.principals[&slot("other")].principal.as_str(),
        "bob"
    );
    assert_eq!(experiment.principals.len(), 2);

    assert_eq!(experiment.oracle.id.as_str(), ORACLE_ID);
    assert_eq!(experiment.oracle.version.as_str(), ORACLE_VERSION);
    assert_eq!(experiment.oracle.digest.as_str(), ORACLE_DIGEST);
    assert_eq!(experiment.decoder.identity.id.as_str(), DECODER_ID);
    assert_eq!(experiment.decoder.limits, DecodeLimits::DEFAULT);
    assert_eq!(
        experiment.effects,
        vec![ActionEffect::Plant, ActionEffect::Observe]
    );

    // Every value the experiment carries is inert registered text.
    let (bytes, _) = experiment.freeze().unwrap();
    let text = String::from_utf8(bytes).unwrap();
    for forbidden in [
        "://",
        "curl ",
        "Authorization",
        "Cookie",
        "password",
        "\\u0000",
    ] {
        assert!(
            !text.contains(forbidden),
            "the experiment must carry no {forbidden}"
        );
    }
}

#[test]
fn an_operator_override_is_recorded_as_an_engagement_slot() {
    let engagement = manifest();
    let mut claim = base_claim(&engagement);
    claim.lead_slots = vec![value("owner", "alice")];
    claim.overrides = vec![value("other", "bob")];
    let experiment = Templates::resolve(&claim, &engagement)
        .unwrap()
        .ready()
        .unwrap();
    let other = &experiment.slots[&slot("other")];
    assert_eq!(other.value.as_str(), "bob");
    assert_eq!(other.source, SlotSource::Engagement);
    assert_eq!(other.supplied_by.as_str(), "operator");
}

#[test]
fn unfilled_principal_slots_are_returned_as_a_form() {
    let engagement = manifest();
    let mut claim = base_claim(&engagement);
    claim.lead_slots.clear();
    let Resolution::Incomplete(form) = Templates::resolve(&claim, &engagement).unwrap() else {
        panic!("an unfilled claim is not frozen");
    };
    let missing: Vec<&str> = form.missing.iter().map(|slot| slot.name.as_str()).collect();
    assert_eq!(missing, ["other", "owner"]);
    for slot in &form.missing {
        assert_eq!(slot.kind, SlotKind::Principal);
        assert_eq!(
            slot.supplied_by,
            vec![SuppliedBy::Operator, SuppliedBy::Lead]
        );
        assert_eq!(slot.reason, MissingReason::NotSupplied);
    }
    assert_eq!(form.template.id.as_str(), PRIVATE_OBJECT_READ);
    assert_eq!(form.claim_class.as_str(), PRIVATE_OBJECT_READ);
    // What is resolved keeps its provenance, and no principal is bound.
    assert_eq!(
        form.resolved[&slot("read")].value.as_str(),
        "operation.orders.read"
    );
    assert_eq!(
        form.resolved[&slot("read")].supplied_by.as_str(),
        "operator"
    );
    assert_eq!(form.resolved.len(), 3);
}

#[test]
fn a_claim_without_a_property_selection_reports_the_property_slots() {
    let engagement = manifest();
    let mut claim = base_claim(&engagement);
    claim.property = None;
    let Resolution::Incomplete(form) = Templates::resolve(&claim, &engagement).unwrap() else {
        panic!("an unfilled claim is not frozen");
    };
    let missing: Vec<(&str, MissingReason)> = form
        .missing
        .iter()
        .map(|slot| (slot.name.as_str(), slot.reason))
        .collect();
    assert_eq!(
        missing,
        [
            ("plant", MissingReason::NoPropertySelected),
            ("read", MissingReason::NoPropertySelected),
            ("remove", MissingReason::NoPropertySelected),
        ]
    );
    for slot in &form.missing {
        assert_eq!(slot.kind, SlotKind::Property);
        assert_eq!(slot.supplied_by, vec![SuppliedBy::Operator]);
    }
    assert_eq!(form.resolved.len(), 2);
}

#[test]
fn a_property_that_fixes_no_operation_leaves_that_slot_missing() {
    let engagement = manifest();
    let mut claim = state_change_claim(&engagement);
    claim.property = Some(label("invoices"));
    let methods = Registry::new(&[("operation.orders.read", Method::Get)]);
    let Resolution::Incomplete(form) = state_change_resolution(&claim, &methods).unwrap() else {
        panic!("the write slot cannot be fixed by this property");
    };
    assert_eq!(form.missing.len(), 1);
    assert_eq!(form.missing[0].name.as_str(), "write");
    assert_eq!(form.missing[0].kind, SlotKind::Property);
    assert_eq!(form.missing[0].reason, MissingReason::PropertyFixesNothing);
    assert_eq!(
        form.resolved[&slot("read")].value.as_str(),
        "operation.orders.read"
    );
}

// -- INV-36: property slots are operator-only -------------------------------

#[test]
fn a_lead_supplied_property_slot_is_a_slot_conflict() {
    let engagement = manifest();
    for name in ["read", "plant", "remove"] {
        let mut claim = base_claim(&engagement);
        claim.lead_slots.push(value(name, "operation.orders.read"));
        let error = resolve_error(&claim, &engagement);
        assert_eq!(
            error,
            ResolveError::SlotConflict {
                slot: slot(name),
                supplied: SuppliedBy::Lead,
            },
            "{name}"
        );
        assert_eq!(error.code(), ErrorCode::SlotConflict);
        assert_eq!(error.exit_code(), 2);
    }
}

#[test]
fn an_operator_override_of_a_property_slot_is_a_slot_conflict() {
    let engagement = manifest();
    for name in ["read", "plant", "remove"] {
        let mut claim = base_claim(&engagement);
        claim.overrides.push(value(name, "operation.invoices.read"));
        let error = resolve_error(&claim, &engagement);
        assert_eq!(
            error,
            ResolveError::SlotConflict {
                slot: slot(name),
                supplied: SuppliedBy::Operator,
            },
            "{name}"
        );
        assert_eq!(error.code(), ErrorCode::SlotConflict);
        assert_eq!(error.exit_code(), 2);
    }
}

#[test]
fn operator_authority_comes_from_the_channel_not_the_value() {
    let engagement = manifest();
    let orders = engagement.properties().get(&label("orders")).unwrap();
    // A lead that repeats the operator's own value, or claims an operator
    // supplier, is still the lead: the value does not carry authority.
    let mut claim = base_claim(&engagement);
    claim.lead_slots = vec![
        value("owner", "alice"),
        value("other", "bob"),
        value("read", orders.read.as_str()),
        value("plant", orders.plant.operation.as_str()),
        value("remove", orders.remove.as_str()),
    ];
    let error = resolve_error(&claim, &engagement);
    assert_eq!(
        error,
        ResolveError::SlotConflict {
            slot: slot("plant"),
            supplied: SuppliedBy::Lead,
        }
    );
    assert_eq!(error.exit_code(), 2);
}

#[test]
fn a_slot_the_template_reserves_for_the_lead_is_not_operator_writable() {
    let engagement = manifest();
    let mut template = state_change_template();
    template.slots.get_mut(&slot("read")).unwrap().supplied_by = vec![SuppliedBy::Lead];
    let compiled = CompiledTemplate::new(
        template,
        oracle(
            "web.forbidden-state-change",
            "1",
            b"synthetic state-change oracle",
        ),
        decoder_binding(),
    )
    .unwrap();
    let registry = [compiled];
    let mut claim = state_change_claim(&engagement);
    claim.lead_slots = vec![value("owner", "alice")];
    claim.overrides = vec![value("read", "operation.orders.read")];
    let methods = Registry::new(&[("operation.orders.read", Method::Get)]);
    let error = Templates::resolve_in(&registry, &claim, &engagement, &methods).unwrap_err();
    assert_eq!(
        error,
        ResolveError::SlotConflict {
            slot: slot("read"),
            supplied: SuppliedBy::Operator,
        }
    );
}

// -- Duplicate, ambiguous and unknown input --------------------------------

#[test]
fn duplicate_and_ambiguous_slot_input_is_refused() {
    let engagement = manifest();

    let mut claim = base_claim(&engagement);
    claim.lead_slots.push(value("owner", "bob"));
    let error = resolve_error(&claim, &engagement);
    assert_eq!(
        error,
        ResolveError::DuplicateSlot {
            slot: slot("owner")
        }
    );
    assert_eq!(error.code(), ErrorCode::InputAmbiguous);
    assert_eq!(error.exit_code(), 3);

    let mut claim = base_claim(&engagement);
    claim.overrides.push(value("owner", "alice"));
    let error = resolve_error(&claim, &engagement);
    assert_eq!(
        error,
        ResolveError::AmbiguousSlot {
            slot: slot("owner")
        }
    );
    assert_eq!(error.code(), ErrorCode::InputAmbiguous);
    assert_eq!(error.exit_code(), 3);

    // Equal values on two channels are still two suppliers for one slot.
    let mut claim = base_claim(&engagement);
    claim.lead_slots = vec![value("owner", "alice")];
    claim.overrides = vec![value("owner", "alice"), value("other", "bob")];
    assert_eq!(
        resolve_error(&claim, &engagement),
        ResolveError::AmbiguousSlot {
            slot: slot("owner")
        }
    );
}

#[test]
fn an_unknown_slot_name_is_a_usage_error() {
    let engagement = manifest();
    let mut claim = base_claim(&engagement);
    claim
        .lead_slots
        .push(value("payload", "operation.orders.read"));
    let error = resolve_error(&claim, &engagement);
    assert_eq!(
        error,
        ResolveError::UnknownSlot {
            declared: Templates::registry()[0]
                .template
                .slots
                .keys()
                .cloned()
                .collect(),
        }
    );
    assert_eq!(error.code(), ErrorCode::UsageError);
    assert_eq!(error.exit_code(), 2);
}

// -- Principals, properties and scope ---------------------------------------

#[test]
fn the_principal_pair_must_be_declared_and_distinct() {
    let engagement = manifest();

    let mut claim = base_claim(&engagement);
    claim.lead_slots = vec![value("owner", "alice"), value("other", "alice")];
    let error = resolve_error(&claim, &engagement);
    assert_eq!(
        error,
        ResolveError::SamePrincipal {
            principal: label("alice")
        }
    );
    assert_eq!(error.code(), ErrorCode::InputAmbiguous);
    assert_eq!(error.exit_code(), 3);

    let mut claim = base_claim(&engagement);
    claim.lead_slots = vec![value("owner", "alice"), value("other", "carol")];
    let error = resolve_error(&claim, &engagement);
    assert_eq!(
        error,
        ResolveError::UndeclaredPrincipal {
            principal: label("carol")
        }
    );
    assert_eq!(error.code(), ErrorCode::ObjectNotFound);
    assert_eq!(error.exit_code(), 3);

    let mut claim = base_claim(&engagement);
    claim.property = Some(label("missing"));
    let error = resolve_error(&claim, &engagement);
    assert_eq!(
        error,
        ResolveError::UndeclaredProperty {
            property: label("missing")
        }
    );
    assert_eq!(error.code(), ErrorCode::ObjectNotFound);

    let mut claim = base_claim(&engagement);
    claim.lead_slots = vec![value("owner", "Alice"), value("other", "bob")];
    let error = resolve_error(&claim, &engagement);
    assert_eq!(
        error,
        ResolveError::MalformedValue {
            slot: slot("owner")
        }
    );
    assert_eq!(error.code(), ErrorCode::UsageError);
}

#[test]
fn a_claim_written_against_another_engagement_revision_is_scope_refused() {
    let engagement = manifest();

    let mut claim = base_claim(&engagement);
    claim.engagement.revision += 1;
    let error = resolve_error(&claim, &engagement);
    assert_eq!(
        error,
        ResolveError::EngagementMismatch {
            supplied: engagement.revision() + 1,
            engaged: engagement.revision(),
        }
    );
    assert_eq!(error.code(), ErrorCode::ScopeRefused);
    assert_eq!(error.exit_code(), 8);

    let mut claim = base_claim(&engagement);
    claim.engagement.digest = Sha256Digest::of(b"another revision");
    assert!(matches!(
        resolve_error(&claim, &engagement),
        ResolveError::EngagementMismatch { .. }
    ));

    // An amendment of the same declaration is a different engagement revision.
    let amended = engagement
        .amend(
            EngagementDraft::parse_toml(ENGAGEMENT).unwrap(),
            PassPin {
                reference: &pass_ref(),
                digest: &pass_digest(),
            },
        )
        .unwrap();
    let error = resolve_error(&base_claim(&amended), &engagement);
    assert!(matches!(error, ResolveError::EngagementMismatch { .. }));
}

#[test]
fn an_engagement_that_does_not_allow_an_effect_is_scope_refused() {
    let engagement = manifest();
    let mut document: Value = canonical::parse(engagement.canonical_bytes()).unwrap();
    let mut declaration = document["declaration"].take();
    declaration["engagement"]["allow_effects"] = json!(["observe"]);
    let restricted =
        accept(EngagementDraft::parse_json(&serde_json::to_vec(&declaration).unwrap()).unwrap());
    let error = resolve_error(&base_claim(&restricted), &restricted);
    assert_eq!(
        error,
        ResolveError::EffectNotAllowed {
            effect: ActionEffect::Plant
        }
    );
    assert_eq!(error.code(), ErrorCode::ScopeRefused);
    assert_eq!(error.exit_code(), 8);
}

#[test]
fn a_class_with_no_compiled_template_is_oracle_unavailable() {
    let engagement = manifest();
    let mut claim = base_claim(&engagement);
    claim.class = class("web-authz/collection-disclosure");
    let error = resolve_error(&claim, &engagement);
    assert_eq!(
        error,
        ResolveError::UnsupportedClass {
            supported: vec![class(PRIVATE_OBJECT_READ)],
        }
    );
    assert_eq!(error.code(), ErrorCode::OracleUnavailable);
    assert_eq!(error.exit_code(), 5);
}

// -- INV-37: the generic safe-method guard ---------------------------------

#[test]
fn a_lead_supplied_read_selector_must_resolve_to_a_safe_method() {
    let engagement = manifest();
    let claim = state_change_claim(&engagement);

    for method in [Method::Get, Method::Head] {
        let methods = Registry::new(&[("operation.orders.read", method)]);
        let experiment = state_change_resolution(&claim, &methods)
            .unwrap()
            .ready()
            .expect("a safe read method resolves");
        assert_eq!(
            experiment.slots[&slot("read")].value.as_str(),
            "operation.orders.read"
        );
        assert_eq!(experiment.slots[&slot("read")].source, SlotSource::Lead);
        assert_eq!(methods.calls(), 1);
    }

    for method in [
        Method::Post,
        Method::Put,
        Method::Patch,
        Method::Delete,
        Method::Options,
        Method::Trace,
        Method::Connect,
    ] {
        let methods = Registry::new(&[("operation.orders.read", method)]);
        let error = state_change_resolution(&claim, &methods).unwrap_err();
        assert_eq!(
            error,
            ResolveError::MethodRefused { slot: slot("read") },
            "{}",
            method.as_str()
        );
        assert_eq!(error.code(), ErrorCode::MethodRefused);
        assert_eq!(error.exit_code(), 8);
        // Nothing is sent: the guard only read the method name.
        assert_eq!(methods.calls(), 1);
        assert!(!method.is_safe_read());
    }

    // An operation the trusted registry does not know has no safe method either.
    let methods = Registry::new(&[]);
    assert!(matches!(
        state_change_resolution(&claim, &methods).unwrap_err(),
        ResolveError::MethodRefused { .. }
    ));
}

#[test]
fn the_method_guard_runs_before_a_missing_slot_form() {
    let engagement = manifest();
    let mut claim = state_change_claim(&engagement);
    claim.property = None;
    claim.lead_slots[1] = value("read", "operation.orders.delete");
    let methods = Registry::new(&[("operation.orders.delete", Method::Delete)]);
    assert_eq!(
        state_change_resolution(&claim, &methods).unwrap_err(),
        ResolveError::MethodRefused { slot: slot("read") }
    );
}

#[test]
fn the_shipped_template_never_consults_the_operation_registry() {
    let engagement = manifest();
    let methods = Registry::new(&[("operation.orders.read", Method::Delete)]);
    let experiment = Templates::resolve_with(&base_claim(&engagement), &engagement, &methods)
        .unwrap()
        .ready()
        .unwrap();
    assert_eq!(methods.calls(), 0);
    assert_eq!(
        experiment.slots[&slot("read")].source,
        SlotSource::Engagement
    );
}

// -- Canonical bytes, digest sensitivity and per-run exclusion -------------

#[test]
fn the_frozen_experiment_has_deterministic_canonical_bytes() {
    let engagement = manifest();
    let experiment = frozen(&engagement);
    let (bytes, digest) = experiment.freeze().unwrap();
    let (again, repeated) = frozen(&engagement).freeze().unwrap();
    assert_eq!(bytes, again);
    assert_eq!(digest, repeated);
    assert_eq!(digest.as_str().len(), 64);
    assert!(
        digest
            .as_str()
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );

    let loaded = FrozenExperiment::from_canonical_bytes(&bytes, &digest).unwrap();
    assert_eq!(loaded, experiment);

    let spaced = [b" ".as_slice(), &bytes].concat();
    assert_eq!(
        FrozenExperiment::from_canonical_bytes(&spaced, &Sha256Digest::of(&spaced)).unwrap_err(),
        JsonError::NonCanonical
    );
    assert_eq!(
        FrozenExperiment::from_canonical_bytes(&bytes, &Sha256Digest::of(b"another")).unwrap_err(),
        JsonError::DigestMismatch
    );

    let mut document: Value = canonical::parse(&bytes).unwrap();
    document["canary"] = json!("0123456789abcdef0123456789abcdef");
    let unknown = canonical::to_vec(&document).unwrap();
    assert_eq!(
        FrozenExperiment::from_canonical_bytes(&unknown, &Sha256Digest::of(&unknown)).unwrap_err(),
        JsonError::InvalidShape
    );
}

#[test]
fn the_frozen_experiment_binds_every_field_and_nothing_per_run() {
    let engagement = manifest();
    let experiment = frozen(&engagement);
    let (bytes, reference) = experiment.freeze().unwrap();
    let document: Value = canonical::parse(&bytes).unwrap();

    let keys: Vec<&str> = document
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        [
            "decoder",
            "effects",
            "engagement",
            "oracle",
            "principals",
            "property",
            "slots",
            "template",
        ]
    );
    assert_eq!(
        document["slots"]["read"],
        json!({
            "value": "operation.orders.read",
            "source": "engagement",
            "supplied_by": "operator",
            "digest": Sha256Digest::of(b"operation.orders.read").as_str(),
        })
    );
    assert_eq!(
        document["principals"]["owner"],
        json!({
            "principal": "alice",
            "session": "session.alice",
            "verifier_session": "session.alice.verify",
            "groups": ["group.tenant-a"],
            "identity_probe": {
                "operation": "operation.identity.probe",
                "subject": "selector.identity.subject",
            },
        })
    );
    assert_eq!(
        document["decoder"],
        json!({
            "identity": {"id": DECODER_ID, "version": DECODER_VERSION},
            "limits": {
                "max_decoded_bytes": DEFAULT_MAX_DECODED_BYTES,
                "max_expansion_ratio": DEFAULT_MAX_EXPANSION_RATIO,
            },
        })
    );
    assert_eq!(
        document["oracle"],
        json!({
            "id": ORACLE_ID,
            "version": ORACLE_VERSION,
            "digest": ORACLE_DIGEST,
        })
    );
    assert_eq!(document["effects"], json!(["plant", "observe"]));

    // No per-run field exists, so a fresh canary and nonce cannot reach the
    // digest: the same claim resolves to the same bytes afterwards.
    let text = String::from_utf8(bytes).unwrap();
    assert!(!text.contains("canary"));
    assert!(!text.contains("nonce"));
    let canary = "0123456789abcdef0123456789abcdef";
    let nonce = RunNonce::from_str(canary).unwrap();
    let (after, after_digest) = frozen(&engagement).freeze().unwrap();
    assert_eq!(after, text.as_bytes());
    assert_eq!(after_digest, reference);
    assert!(!text.contains(canary));
    assert!(!text.contains(nonce.as_str()));
}

#[test]
fn every_frozen_field_changes_the_experiment_digest() {
    let engagement = manifest();
    let base = frozen(&engagement);
    let reference = digest_of(&base);

    fn changes(
        base: &FrozenExperiment,
        reference: &Sha256Digest,
        field: &str,
        mutate: impl FnOnce(&mut FrozenExperiment),
    ) {
        let mut copy = base.clone();
        mutate(&mut copy);
        assert_ne!(digest_of(&copy), *reference, "the digest must bind {field}");
    }

    changes(&base, &reference, "template.id", |experiment| {
        experiment.template.id = wire("web-authz/state-change");
    });
    changes(&base, &reference, "template.version", |experiment| {
        experiment.template.version = wire("2");
    });
    changes(&base, &reference, "engagement.revision", |experiment| {
        experiment.engagement.revision += 1;
    });
    changes(&base, &reference, "engagement.digest", |experiment| {
        experiment.engagement.digest = Sha256Digest::of(b"other engagement");
    });
    changes(&base, &reference, "property presence", |experiment| {
        experiment.property = None;
    });
    changes(&base, &reference, "property.label", |experiment| {
        experiment.property.as_mut().unwrap().label = label("invoices");
    });
    changes(&base, &reference, "property.resource", |experiment| {
        experiment.property.as_mut().unwrap().resource =
            ResourceRef::from_str("resource.invoices").unwrap();
    });
    changes(&base, &reference, "property.digest", |experiment| {
        experiment.property.as_mut().unwrap().digest = Sha256Digest::of(b"other property");
    });

    for name in ["owner", "other", "read", "plant", "remove"] {
        let key = slot(name);
        changes(&base, &reference, "slot value", |experiment| {
            experiment.slots.get_mut(&key).unwrap().value = wire("operation.other.read");
        });
        changes(&base, &reference, "slot source", |experiment| {
            let source = &mut experiment.slots.get_mut(&key).unwrap().source;
            *source = match source {
                SlotSource::Lead => SlotSource::Engagement,
                _ => SlotSource::Lead,
            };
        });
        changes(&base, &reference, "slot supplier", |experiment| {
            experiment.slots.get_mut(&key).unwrap().supplied_by = wire("another-supplier");
        });
        changes(&base, &reference, "slot digest", |experiment| {
            experiment.slots.get_mut(&key).unwrap().digest = Sha256Digest::of(b"other value");
        });
    }

    for name in ["owner", "other"] {
        let key = slot(name);
        changes(&base, &reference, "principal label", |experiment| {
            experiment.principals.get_mut(&key).unwrap().principal = label("carol");
        });
        changes(&base, &reference, "principal session", |experiment| {
            experiment.principals.get_mut(&key).unwrap().session =
                SessionRef::from_str("session.carol").unwrap();
        });
        changes(
            &base,
            &reference,
            "principal verifier session",
            |experiment| {
                experiment
                    .principals
                    .get_mut(&key)
                    .unwrap()
                    .verifier_session = None;
            },
        );
        changes(&base, &reference, "principal groups", |experiment| {
            experiment.principals.get_mut(&key).unwrap().groups =
                Some(vec![GroupRef::from_str("group.tenant-c").unwrap()]);
        });
        changes(
            &base,
            &reference,
            "principal identity probe operation",
            |experiment| {
                experiment
                    .principals
                    .get_mut(&key)
                    .unwrap()
                    .identity_probe
                    .operation = OperationRef::from_str("operation.identity.probe.other").unwrap();
            },
        );
        changes(
            &base,
            &reference,
            "principal identity probe subject",
            |experiment| {
                experiment
                    .principals
                    .get_mut(&key)
                    .unwrap()
                    .identity_probe
                    .subject = SelectorRef::from_str("selector.identity.other").unwrap();
            },
        );
    }

    changes(&base, &reference, "oracle.id", |experiment| {
        experiment.oracle.id = wire("web.forbidden-state-change");
    });
    changes(&base, &reference, "oracle.version", |experiment| {
        experiment.oracle.version = wire("2");
    });
    changes(&base, &reference, "oracle.digest", |experiment| {
        experiment.oracle.digest = Sha256Digest::of(b"other oracle");
    });
    changes(&base, &reference, "decoder.id", |experiment| {
        experiment.decoder.identity.id = wire("http-body-v2");
    });
    changes(&base, &reference, "decoder.version", |experiment| {
        experiment.decoder.identity.version = wire("2");
    });
    changes(&base, &reference, "decoder size limit", |experiment| {
        experiment.decoder.limits.max_decoded_bytes += 1;
    });
    changes(&base, &reference, "decoder ratio limit", |experiment| {
        experiment.decoder.limits.max_expansion_ratio += 1;
    });
    changes(&base, &reference, "effect profile", |experiment| {
        experiment.effects.push(ActionEffect::Mutate);
    });
    changes(&base, &reference, "effect order", |experiment| {
        experiment.effects.reverse();
    });

    // Sample a few digests to show they are distinct and stable.
    let mut seen = BTreeSet::new();
    for experiment in [base.clone(), {
        let mut copy = base.clone();
        copy.engagement.revision += 1;
        copy
    }] {
        assert!(seen.insert(digest_of(&experiment).as_str().to_owned()));
    }
}

// -- Refusal codes ---------------------------------------------------------

#[test]
fn refusal_codes_come_from_the_frozen_exit_table() {
    let engagement = manifest();
    let mapping = |claim: Claim| resolve_error(&claim, &engagement).code();
    let table: Value = canonical::parse(CONTRACT_REGISTRY).unwrap();

    let mut unsupported = base_claim(&engagement);
    unsupported.class = class("web-authz/existence");
    let mut conflict = base_claim(&engagement);
    conflict
        .lead_slots
        .push(value("read", "operation.orders.read"));
    let mut ambiguous = base_claim(&engagement);
    ambiguous.lead_slots.push(value("owner", "bob"));
    let mut usage = base_claim(&engagement);
    usage
        .lead_slots
        .push(value("payload", "operation.orders.read"));
    let mut missing_property = base_claim(&engagement);
    missing_property.property = Some(label("missing"));
    let mut scope = base_claim(&engagement);
    scope.engagement.revision += 1;

    let cases = [
        (mapping(unsupported), ErrorCode::OracleUnavailable, 5),
        (mapping(conflict), ErrorCode::SlotConflict, 2),
        (mapping(ambiguous), ErrorCode::InputAmbiguous, 3),
        (mapping(usage), ErrorCode::UsageError, 2),
        (mapping(missing_property), ErrorCode::ObjectNotFound, 3),
        (mapping(scope), ErrorCode::ScopeRefused, 8),
    ];
    for (code, expected, exit) in cases {
        assert_eq!(code, expected);
        assert_eq!(code.exit_code(), exit);
    }
    assert_eq!(table["error_exits"]["SLOTS_INCOMPLETE"], 5);
    assert_eq!(table["error_exits"]["METHOD_REFUSED"], 8);
    assert_eq!(table["error_exits"]["INTEGRITY_FAILURE"], 6);

    // A missing slot is an outcome, not a refusal.
    let mut incomplete = base_claim(&engagement);
    incomplete.lead_slots.clear();
    assert!(matches!(
        Templates::resolve(&incomplete, &engagement).unwrap(),
        Resolution::Incomplete(_)
    ));
}
