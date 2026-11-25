//! Offline mutation qualification for the frozen POR checks.
//!
//! Cases replay checked-in saved rounds or derive a named witness from the
//! no-exposure round. These observations are synthetic test evidence.
use std::{collections::BTreeMap, io::Write};

use flate2::{Compression, write::GzEncoder};
use scourge_core::{canonical, ids::RunId};
use serde_json::{Value, json};

use super::{Completeness, Evaluation, Exposure, InvalidReason, Verdict, evaluate, try_evaluate};
use crate::{
    ClaimClass, CleanupDetail, ContentCoding, Decoding, Dispatch, FlowId, ObjectKey, PlantDetail,
    PlantedCanary, SavedFlow, SavedObservations, dispatch, registry, scope,
};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Check {
    DistinctSubjects,
    StableSubjects,
    FreshPlants,
    OwnerControl,
    SpecificControl,
    ExactCanary,
    ReadOrder,
    FlowCompleteness,
    BoundedDecode,
    PerFieldCanaries,
    CleanupAuthority,
    ObjectScope,
}

const MUTANTS: [(Check, &str); 12] = [
    (Check::DistinctSubjects, "POR-01"),
    (Check::StableSubjects, "POR-02"),
    (Check::FreshPlants, "POR-03"),
    (Check::OwnerControl, "POR-04"),
    (Check::SpecificControl, "POR-05"),
    (Check::ExactCanary, "POR-06"),
    (Check::ReadOrder, "POR-07"),
    (Check::FlowCompleteness, "POR-08"),
    (Check::BoundedDecode, "POR-09"),
    (Check::PerFieldCanaries, "POR-10"),
    (Check::CleanupAuthority, "POR-11"),
    (Check::ObjectScope, "POR-12"),
];

pub(super) struct Mutation<'a> {
    pub(super) check: Check,
    // The status-dependent mutant has an input that the production oracle
    // cannot read. This sidecar is attached only to the named test witness.
    pub(super) statuses: &'a BTreeMap<FlowId, u16>,
}

const NEGATIVE: &[u8] = include_bytes!("../../tests/fixtures/observations/false-no-exposure.json");
const SAME_SUBJECT: &[u8] =
    include_bytes!("../../tests/fixtures/observations/invalid-same-subject.json");
const MISSING_FLOW: &[u8] =
    include_bytes!("../../tests/fixtures/observations/invalid-missing-flow.json");
const PRIMED: &[u8] =
    include_bytes!("../../tests/fixtures/observations/true-unauthenticated-after-owner-read.json");
const GROUND_TRUTH: &str = include_str!("../../../../fixtures/target/referee/ground-truth.json");

struct ExpectedRound {
    result: Verdict,
    reason: Option<InvalidReason>,
    exposure: Option<Exposure>,
    after_owner_read: Option<bool>,
    fields: &'static [&'static str],
    unauthorized_cleanup: Option<ObjectKey>,
}

impl ExpectedRound {
    fn negative() -> Self {
        Self {
            result: Verdict::False,
            reason: None,
            exposure: None,
            after_owner_read: Some(false),
            fields: &[],
            unauthorized_cleanup: None,
        }
    }

    fn invalid(reason: InvalidReason) -> Self {
        Self {
            result: Verdict::Invalid,
            reason: Some(reason),
            after_owner_read: None,
            ..Self::negative()
        }
    }

    fn exposed(
        exposure: Exposure,
        after_owner_read: bool,
        fields: &'static [&'static str],
    ) -> Self {
        Self {
            result: Verdict::True,
            exposure: Some(exposure),
            after_owner_read: Some(after_owner_read),
            fields,
            ..Self::negative()
        }
    }

    fn matches(&self, answer: &Evaluation) -> bool {
        let reasons = answer.reason_codes.iter().map(|reason| reason.as_str());
        let fields = answer.fields_crossed.iter().map(|field| field.as_str());
        answer.result == self.result
            && reasons.eq(self.reason.map(InvalidReason::code))
            && answer.exposure == self.exposure
            && answer.after_owner_read == self.after_owner_read
            && fields.eq(self.fields.iter().copied())
            && answer
                .cleanup
                .unauthorized
                .iter()
                .eq(self.unauthorized_cleanup.iter())
            && self
                .unauthorized_cleanup
                .as_ref()
                .is_none_or(|object| !answer.cleanup.authorized.contains(object))
    }
}

enum Replay {
    Round {
        observations: Box<SavedObservations>,
        statuses: BTreeMap<FlowId, u16>,
        expected: ExpectedRound,
    },
    Scope(ClaimClass),
}

struct Fixture {
    plan_case: &'static str,
    witness: &'static str,
    replay: Replay,
}

impl Fixture {
    fn round(
        plan_case: &'static str,
        witness: &'static str,
        observations: SavedObservations,
        expected: ExpectedRound,
    ) -> Self {
        // Generated observations use the same saved-input parser as committed rounds.
        let observations =
            load(&serde_json::to_vec(&observations).expect("serialize replay round"));
        Self {
            plan_case,
            witness,
            replay: Replay::Round {
                observations: Box::new(observations),
                statuses: BTreeMap::new(),
                expected,
            },
        }
    }

    fn with_statuses(mut self, statuses: [(FlowId, u16); 3]) -> Self {
        let Replay::Round {
            statuses: sidecar, ..
        } = &mut self.replay
        else {
            unreachable!("only round fixtures carry HTTP semantics");
        };
        *sidecar = statuses.into();
        self
    }

    fn scope(plan_case: &'static str, witness: &'static str, claim_class: ClaimClass) -> Self {
        Self {
            plan_case,
            witness,
            replay: Replay::Scope(claim_class),
        }
    }

    fn passes(&self, check: Option<Check>, boundary: &Value) -> bool {
        match &self.replay {
            Replay::Round {
                observations,
                statuses,
                expected,
            } => {
                let answer = match check {
                    Some(check) => try_evaluate(observations, Some(&Mutation { check, statuses })),
                    None => evaluate(observations),
                };
                assert_ne!(
                    answer.result,
                    Verdict::Error,
                    "{}/{} could not be evaluated",
                    self.plan_case,
                    self.witness
                );
                let matches = expected.matches(&answer);
                if check.is_none() {
                    assert!(
                        matches,
                        "{}/{} baseline got {answer:?}",
                        self.plan_case, self.witness
                    );
                }
                matches
            }
            Replay::Scope(claim_class) => {
                let class_name = claim_class.claim_class();
                let answer = match check {
                    Some(Check::ObjectScope) => scope::dispatch_without_scope_check(class_name),
                    _ => dispatch(class_name),
                };
                let Dispatch::OracleUnavailable {
                    claim_class: refused_class,
                    oracle,
                    result,
                    timing,
                    supported_claim_classes,
                    unsupported_scope_names,
                } = answer
                else {
                    return false;
                };
                refused_class == *claim_class
                    && oracle == registry::ORACLE_ID
                    && boundary["dispatch_result"] == result
                    && boundary["dispatch_timing"] == timing
                    && supported_claim_classes == [ClaimClass::PrivateObjectRead]
                    && boundary["unsupported_claim_classes"] == json!(unsupported_scope_names)
            }
        }
    }
}

fn load(bytes: &[u8]) -> SavedObservations {
    canonical::from_slice(bytes).expect("valid saved observations")
}

fn flow(observations: &mut SavedObservations, id: FlowId) -> &mut SavedFlow {
    observations
        .flows
        .iter_mut()
        .find(|saved| saved.flow == id)
        .expect("fixture flow present")
}

fn plant(observations: &mut SavedObservations, id: FlowId) -> &mut PlantDetail {
    flow(observations, id)
        .plant
        .as_mut()
        .expect("fixture plant")
}

fn cleanup(observations: &mut SavedObservations) -> &mut CleanupDetail {
    flow(observations, FlowId::C)
        .cleanup
        .as_mut()
        .expect("fixture cleanup")
}

fn from_negative(change: impl FnOnce(&mut SavedObservations)) -> SavedObservations {
    let mut observations = load(NEGATIVE);
    change(&mut observations);
    observations
}

fn owner_body(observations: &mut SavedObservations) -> Vec<u8> {
    flow(observations, FlowId::F1).body.clone()
}

fn exposure_in(other: FlowId) -> SavedObservations {
    from_negative(|observations| flow(observations, other).body = owner_body(observations))
}

fn catalog_result(ground_truth: &Value, family: &str, mode: &str, plan_case: &str) -> &'static str {
    let entry = &ground_truth[family][mode];
    assert!(
        entry["plan_cases"]
            .as_array()
            .unwrap()
            .contains(&json!(plan_case))
    );
    match entry["expected"]["oracle"].as_str() {
        Some("true") => "true",
        Some("invalid") => "invalid",
        other => panic!("unrecognized oracle result for {plan_case}: {other:?}"),
    }
}

fn catalog_invalid(
    ground_truth: &Value,
    mode: &str,
    plan_case: &str,
    reason: InvalidReason,
) -> ExpectedRound {
    assert_eq!(
        catalog_result(ground_truth, "decoys", mode, plan_case),
        "invalid"
    );
    assert_eq!(
        ground_truth["decoys"][mode]["expected"]["reason"],
        reason.code()
    );
    ExpectedRound::invalid(reason)
}

fn fixtures() -> Vec<Fixture> {
    let ground_truth = canonical::parse(GROUND_TRUTH.as_bytes()).expect("fixture ground truth");
    let incomplete = || ExpectedRound::invalid(InvalidReason::EvidenceIncomplete);
    let cross_principal = || ExpectedRound::exposed(Exposure::CrossPrincipal, false, &["label"]);
    let warm_exposure = || ExpectedRound::exposed(Exposure::Unauthenticated, true, &["label"]);

    assert_eq!(
        catalog_result(&ground_truth, "flaws", "forbidden_body", "F-05"),
        "true"
    );
    assert_eq!(
        catalog_result(&ground_truth, "flaws", "shared_private_cache", "F-37"),
        "true"
    );
    assert_eq!(
        ground_truth["flaws"]["shared_private_cache"]["expected"]["qualification"],
        "after_owner_read"
    );
    assert_eq!(
        ground_truth["decoys"]["stale_snapshot"]["expected"]["fresh_canary_present"],
        false
    );

    let mut lost_plant = from_negative(|observations| {
        plant(observations, FlowId::P).object = None;
    });
    let unowned = cleanup(&mut lost_plant).removed[0].clone();

    vec![
        Fixture::round(
            "F-01",
            "same-stable-subject",
            load(SAME_SUBJECT),
            catalog_invalid(
                &ground_truth,
                "same_subject",
                "F-01",
                InvalidReason::SameSubject,
            ),
        ),
        Fixture::round(
            "F-07",
            "owner-subject-switch",
            from_negative(|observations| {
                flow(observations, FlowId::I3).subject =
                    flow(observations, FlowId::I2).subject.clone();
            }),
            catalog_invalid(
                &ground_truth,
                "session_expiry",
                "F-07",
                InvalidReason::SessionDrift,
            ),
        ),
        Fixture::round(
            "F-09",
            "reused-plant-canary",
            from_negative(|observations| {
                let reused = plant(observations, FlowId::P).canaries[0].canary.clone();
                plant(observations, FlowId::P2).canaries[0].canary = reused;
            }),
            incomplete(),
        ),
        Fixture::round(
            "F-27",
            "same-object-in-both-plants",
            from_negative(|observations| {
                let object = plant(observations, FlowId::P).object.clone();
                plant(observations, FlowId::P2).object = object;
                cleanup(observations).removed.truncate(1);
            }),
            incomplete(),
        ),
        Fixture::round(
            "F-03",
            "login-page",
            from_negative(|observations| {
                flow(observations, FlowId::F1).body = b"<html>Sign in</html>".to_vec();
            }),
            catalog_invalid(
                &ground_truth,
                "login_page",
                "F-03",
                InvalidReason::ObserverInvalid,
            ),
        ),
        Fixture::round(
            "F-08",
            "unrelated-object-echo",
            from_negative(|observations| {
                let echoed = owner_body(observations);
                flow(observations, FlowId::F2).body = echoed.clone();
                flow(observations, FlowId::F4).body = echoed;
            }),
            catalog_invalid(
                &ground_truth,
                "canary_echo",
                "F-08",
                InvalidReason::CanaryNotSpecific,
            ),
        ),
        Fixture::round(
            "F-05",
            "403-with-primary-canary",
            from_negative(|observations| {
                for treatment in [FlowId::F0, FlowId::F2, FlowId::F3] {
                    flow(observations, treatment).body = owner_body(observations);
                }
            }),
            ExpectedRound::exposed(Exposure::Unauthenticated, false, &["label"]),
        )
        .with_statuses([(FlowId::F0, 403), (FlowId::F2, 403), (FlowId::F3, 403)]),
        Fixture::round(
            "F-06",
            "successful-stale-snapshot",
            from_negative(|observations| {
                flow(observations, FlowId::F2).body =
                    br#"{"secret":"44444444444444444444444444444444"}"#.to_vec();
            }),
            ExpectedRound::negative(),
        )
        .with_statuses([(FlowId::F0, 404), (FlowId::F2, 200), (FlowId::F3, 404)]),
        Fixture::round("F-37", "warm-cache-in-order", load(PRIMED), warm_exposure()),
        Fixture::round(
            "F-37",
            "warm-cache-before-owner-read",
            {
                let mut observations = load(PRIMED);
                flow(&mut observations, FlowId::F3).sequence =
                    flow(&mut observations, FlowId::F0).sequence;
                observations
            },
            incomplete(),
        ),
        Fixture::round(
            "F-09",
            "foreign-run-treatment",
            {
                let mut observations = exposure_in(FlowId::F2);
                flow(&mut observations, FlowId::F2).run =
                    RunId::try_from("R-9".to_owned()).expect("prior run ID");
                observations
            },
            incomplete(),
        ),
        Fixture::round(
            "F-11",
            "missing-treatment",
            load(MISSING_FLOW),
            incomplete(),
        ),
        Fixture::round(
            "F-11",
            "partial-treatment",
            {
                let mut observations = exposure_in(FlowId::F2);
                flow(&mut observations, FlowId::F2).completeness = Completeness::Partial;
                observations
            },
            incomplete(),
        ),
        Fixture::round(
            "F-42",
            "gzip-treatment",
            {
                let mut observations = exposure_in(FlowId::F2);
                let treatment = flow(&mut observations, FlowId::F2);
                let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
                encoder
                    .write_all(&treatment.body)
                    .expect("encode canary body");
                treatment.body = encoder.finish().expect("gzip fixture");
                treatment.decoding = Decoding {
                    content: ContentCoding::Gzip,
                    ..Decoding::default()
                };
                treatment.decoder = treatment.decoding.decoder_name();
                observations
            },
            cross_principal(),
        ),
        Fixture::round(
            "F-42",
            "over-decoded-limit",
            {
                let mut observations = exposure_in(FlowId::F2);
                observations.limits.max_decoded_bytes = 128;
                flow(&mut observations, FlowId::F2).body.resize(256, b'x');
                observations
            },
            incomplete(),
        ),
        Fixture::round(
            "F-42",
            "original-not-retained",
            {
                let mut observations = exposure_in(FlowId::F2);
                flow(&mut observations, FlowId::F2).original = None;
                observations
            },
            incomplete(),
        ),
        Fixture::round(
            "F-47",
            "only-the-second-field-remains-visible",
            from_negative(|observations| {
                let second_canary =
                    crate::Canary::parse("33333333333333333333333333333333").expect("test canary");
                let second_field = crate::FieldName::from(
                    scourge_core::ids::WireText::try_from("detail".to_owned()).expect("field name"),
                );
                plant(observations, FlowId::P).canaries.push(PlantedCanary {
                    field: second_field,
                    canary: second_canary,
                });
                let mut owner: Value =
                    serde_json::from_slice(&owner_body(observations)).expect("owner fixture body");
                let remaining = json!("33333333333333333333333333333333");
                owner["detail"] = remaining.clone();
                flow(observations, FlowId::F1).body = owner.to_string().into_bytes();
                flow(observations, FlowId::F2).body =
                    json!({"detail": remaining}).to_string().into_bytes();
            }),
            ExpectedRound::exposed(Exposure::CrossPrincipal, false, &["detail"]),
        ),
        Fixture::round(
            "F-27",
            "removal-without-plant-ownership",
            lost_plant,
            ExpectedRound {
                unauthorized_cleanup: Some(unowned),
                ..incomplete()
            },
        ),
        Fixture::scope("F-03", "existence-dispatch", ClaimClass::Existence),
        Fixture::scope(
            "F-08",
            "collection-dispatch",
            ClaimClass::CollectionDisclosure,
        ),
    ]
}

#[test]
fn frozen_por_mutation_suite() {
    let frozen: Value = serde_json::from_str(registry::ORACLE_SPECIFICATION).expect("oracle spec");
    let oracle = &frozen["oracles"][registry::ORACLE_CONTRACT_KEY];
    let numbered_checks = oracle["numbered_checks"]
        .as_array()
        .expect("frozen POR checks");
    let boundary = &oracle["scope_boundary"];
    assert_eq!(numbered_checks.len(), MUTANTS.len());
    let fixtures = fixtures();
    for fixture in &fixtures {
        assert!(
            fixture.passes(None, boundary),
            "{}/{} failed against the original oracle",
            fixture.plan_case,
            fixture.witness
        );
    }

    let mut results = Vec::new();
    let mut survivors = Vec::new();
    for (((check, id), contract), compiled) in MUTANTS
        .into_iter()
        .zip(numbered_checks)
        .zip(registry::NUMBERED_CHECKS)
    {
        assert_eq!(contract["id"], id);
        assert_eq!(compiled.id, id);
        let failed: Vec<_> = fixtures
            .iter()
            .filter(|fixture| !fixture.passes(Some(check), boundary))
            .collect();
        let registered = contract["killed_by"]
            .as_array()
            .expect("frozen witness cases");
        let killed = failed
            .iter()
            .any(|fixture| registered.contains(&json!(fixture.plan_case)));
        if !killed {
            survivors.push(id);
        }
        if check == Check::ExactCanary {
            assert!(
                failed
                    .iter()
                    .any(|fixture| matches!(fixture.plan_case, "F-03" | "F-05")),
                "the status-dependent mutant must fail F-03 or F-05"
            );
        }
        results.push(json!({
            "check": id,
            "killed": killed,
            "failed_fixtures": failed.iter().map(|fixture| json!({
                "plan_case": fixture.plan_case,
                "witness": fixture.witness,
            })).collect::<Vec<_>>(),
        }));
    }
    println!(
        "{}",
        json!({
            "schema_version": "scourge.oracle-mutation.v1",
            "oracle": registry::ORACLE_CONTRACT_KEY,
            "mode": "offline_saved_observations_and_scope_dispatch",
            "fixture_count": fixtures.len(),
            "mutant_count": MUTANTS.len(),
            "killed": MUTANTS.len() - survivors.len(),
            "survivors": survivors,
            "results": results,
        })
    );
    assert!(
        survivors.is_empty(),
        "POR mutants without a frozen witness: {survivors:?}"
    );
}
