//! One test per frozen numbered check, POR-01..POR-12.
//!
//! Each test violates exactly the behavior its check adds, and asserts that the
//! oracle's answer changes. Removing that behavior from the implementation must
//! make the test fail; that is the mutation gate (INV-09, plan
//! `plan.evaluation.md` §9).

mod common;

use scourge_verify::{
    FlowId, IncompleteCause, InvalidReason, PlantDetail, PlantedCanary, Verdict, evaluate,
};

fn reasons(evaluation: &scourge_verify::Evaluation) -> Vec<&str> {
    evaluation
        .reason_codes
        .iter()
        .map(|code| code.as_str())
        .collect()
}

fn has_cause(evaluation: &scourge_verify::Evaluation, cause: &IncompleteCause) -> bool {
    evaluation.evidence.contains(cause)
}

#[test]
fn por_01_initial_subjects_must_differ() {
    // Distinct subjects are the baseline: a conclusive verdict.
    assert_eq!(evaluate(&common::observations()).result, Verdict::False);

    let mut observations = common::observations();
    common::saved_mut(&mut observations, FlowId::I2).subject = Some(common::subject(common::OWNER));
    common::saved_mut(&mut observations, FlowId::I4).subject = Some(common::subject(common::OWNER));

    let evaluation = evaluate(&observations);
    assert_eq!(evaluation.result, Verdict::Invalid);
    assert_eq!(
        reasons(&evaluation),
        vec![InvalidReason::SameSubject.code()]
    );
}

#[test]
fn por_02_final_subjects_must_equal_their_initial_subjects() {
    let mut observations = common::observations();
    common::saved_mut(&mut observations, FlowId::I3).subject =
        Some(common::subject("subject-expired"));

    let evaluation = evaluate(&observations);
    assert_eq!(evaluation.result, Verdict::Invalid);
    assert_eq!(
        reasons(&evaluation),
        vec![InvalidReason::SessionDrift.code()]
    );

    let mut observations = common::observations();
    common::saved_mut(&mut observations, FlowId::I4).subject =
        Some(common::subject("subject-expired"));

    let evaluation = evaluate(&observations);
    assert_eq!(
        reasons(&evaluation),
        vec![InvalidReason::SessionDrift.code()]
    );
}

#[test]
fn por_03_plants_must_be_distinct_run_owned_objects_with_distinct_canaries() {
    let mut observations = common::observations();
    common::saved_mut(&mut observations, FlowId::P2)
        .plant
        .as_mut()
        .expect("plant")
        .object = Some(common::object(common::PRIMARY_OBJECT));

    let evaluation = evaluate(&observations);
    assert!(
        has_cause(&evaluation, &IncompleteCause::PlantObjectsNotDistinct),
        "{:?}",
        evaluation.evidence
    );

    let mut observations = common::observations();
    common::saved_mut(&mut observations, FlowId::P2)
        .plant
        .as_mut()
        .expect("plant")
        .canaries = vec![PlantedCanary {
        field: common::field("label"),
        canary: common::primary(),
    }];

    let evaluation = evaluate(&observations);
    assert!(
        has_cause(
            &evaluation,
            &IncompleteCause::PlantCanaryNotDistinctAcrossObjects
        ),
        "{:?}",
        evaluation.evidence
    );

    let mut observations = common::observations();
    common::saved_mut(&mut observations, FlowId::P)
        .plant
        .as_mut()
        .expect("plant")
        .canaries = Vec::new();

    let evaluation = evaluate(&observations);
    assert!(
        has_cause(
            &evaluation,
            &IncompleteCause::PlantCanaryMissing { flow: FlowId::P }
        ),
        "{:?}",
        evaluation.evidence
    );
    assert_eq!(evaluation.result, Verdict::Invalid);
}

#[test]
fn por_04_f1_must_contain_the_primary_canary_first() {
    let mut observations = common::observations();
    common::saved_mut(&mut observations, FlowId::F1).body = b"<html>login page</html>".to_vec();
    common::show(&mut observations, FlowId::F2, &common::primary());
    common::show(&mut observations, FlowId::F3, &common::primary());

    let evaluation = evaluate(&observations);

    assert_eq!(
        evaluation.result,
        Verdict::Invalid,
        "an exposure seen without a usable owner read supports no verdict"
    );
    assert_eq!(
        reasons(&evaluation),
        vec![InvalidReason::ObserverInvalid.code()]
    );
}

#[test]
fn por_05_f4_must_not_contain_the_primary_canary() {
    let mut observations = common::observations();
    common::show(&mut observations, FlowId::F4, &common::primary());
    common::show(&mut observations, FlowId::F2, &common::primary());

    let evaluation = evaluate(&observations);

    assert_eq!(evaluation.result, Verdict::Invalid);
    assert_eq!(
        reasons(&evaluation),
        vec![InvalidReason::CanaryNotSpecific.code()]
    );
}

#[test]
fn por_06_only_the_exact_current_primary_canary_counts() {
    // A stale value that is not this run's canary cannot support a result.
    let mut observations = common::observations();
    common::show(&mut observations, FlowId::F2, &common::canary(0x44));
    assert_eq!(evaluate(&observations).result, Verdict::False);

    // Nor can a truncated 31-character value: the frozen canary form is 32
    // lowercase hexadecimal characters and only that value is this run's.
    let mut observations = common::observations();
    let current = common::primary();
    let prefix = &current.as_str()[..31];
    common::saved_mut(&mut observations, FlowId::F2).body =
        format!("{{\"secret\":\"{prefix}\"}}").into_bytes();
    assert_eq!(evaluate(&observations).result, Verdict::False);

    // Matching is documented as a byte-substring test, not a token-boundary
    // test: a longer ASCII token that embeds the exact current canary counts,
    // because the canary bytes were disclosed. This asserts the real semantics
    // rather than claiming a superset rejection the code does not perform.
    let mut observations = common::observations();
    common::saved_mut(&mut observations, FlowId::F2).body =
        format!("{{\"secret\":\"{}ff\"}}", current.as_str()).into_bytes();
    let evaluation = evaluate(&observations);
    assert_eq!(evaluation.result, Verdict::True);
    assert_eq!(
        evaluation.fields_crossed,
        vec![common::field(common::FIELD)]
    );

    // The exact current canary does count.
    let mut observations = common::observations();
    common::show(&mut observations, FlowId::F2, &common::primary());
    assert_eq!(evaluate(&observations).result, Verdict::True);
}

#[test]
fn por_07_only_f0_before_f1_and_f1_before_f3_are_frozen() {
    // F0 must precede F1.
    let mut observations = common::observations();
    common::saved_mut(&mut observations, FlowId::F1).sequence = common::sequence(FlowId::F0);

    let evaluation = evaluate(&observations);

    assert_eq!(evaluation.result, Verdict::Invalid);
    assert!(
        has_cause(
            &evaluation,
            &IncompleteCause::FlowOrder {
                flow: FlowId::F1,
                after: FlowId::F0,
            }
        ),
        "{:?}",
        evaluation.evidence
    );

    // F3 must follow F1.
    let mut observations = common::observations();
    common::saved_mut(&mut observations, FlowId::F3).sequence = common::sequence(FlowId::F1);

    let evaluation = evaluate(&observations);

    assert_eq!(evaluation.result, Verdict::Invalid);
    assert!(
        has_cause(
            &evaluation,
            &IncompleteCause::FlowOrder {
                flow: FlowId::F3,
                after: FlowId::F1,
            }
        ),
        "{:?}",
        evaluation.evidence
    );
}

#[test]
fn por_07_freezes_no_order_between_unrelated_flows() {
    // Regression for th-mocv1y: the controls planted first, in reverse of the
    // list order, are still a valid round.
    let mut observations = common::observations();
    common::saved_mut(&mut observations, FlowId::P).sequence = 4;
    common::saved_mut(&mut observations, FlowId::P2).sequence = 3;

    let evaluation = evaluate(&observations);

    assert_eq!(evaluation.result, Verdict::False);
    assert!(evaluation.evidence.is_empty(), "{:?}", evaluation.evidence);

    // Two unrelated reads that share one acquisition tick are conclusive.
    let mut observations = common::observations();
    common::saved_mut(&mut observations, FlowId::F2).sequence = 8;
    common::saved_mut(&mut observations, FlowId::F3).sequence = 8;

    let evaluation = evaluate(&observations);

    assert_eq!(evaluation.result, Verdict::False);
    assert!(evaluation.evidence.is_empty(), "{:?}", evaluation.evidence);

    // A tie between F0 and F2 is also outside the frozen order.
    let mut observations = common::observations();
    common::saved_mut(&mut observations, FlowId::F2).sequence = common::sequence(FlowId::F0);

    let evaluation = evaluate(&observations);

    assert_eq!(evaluation.result, Verdict::False);
    assert!(evaluation.evidence.is_empty(), "{:?}", evaluation.evidence);

    // And so is a reversed F2/F3 pair, as long as F3 still follows F1.
    let mut observations = common::observations();
    common::saved_mut(&mut observations, FlowId::F2).sequence = 8;
    common::saved_mut(&mut observations, FlowId::F3).sequence = 7;

    let evaluation = evaluate(&observations);

    assert_eq!(evaluation.result, Verdict::False);
    assert!(evaluation.evidence.is_empty(), "{:?}", evaluation.evidence);
}

#[test]
fn por_08_every_required_flow_must_be_present_and_run_bound() {
    let mut observations = common::observations();
    common::remove_flow(&mut observations, FlowId::I3);

    let evaluation = evaluate(&observations);
    assert_eq!(evaluation.result, Verdict::Invalid);
    assert!(has_cause(
        &evaluation,
        &IncompleteCause::MissingFlow(FlowId::I3)
    ));

    let mut observations = common::observations();
    common::saved_mut(&mut observations, FlowId::F4).run =
        scourge_core::ids::RunId::try_from("R-9".to_owned()).expect("run id");

    let evaluation = evaluate(&observations);
    assert!(has_cause(
        &evaluation,
        &IncompleteCause::NotBoundToRun { flow: FlowId::F4 }
    ));
}

#[test]
fn por_09_decoding_must_be_named_and_bounded_and_originals_retained() {
    let mut observations = common::observations();
    common::saved_mut(&mut observations, FlowId::F2).original = None;

    let evaluation = evaluate(&observations);

    assert_eq!(evaluation.result, Verdict::Invalid);
    assert!(has_cause(
        &evaluation,
        &IncompleteCause::OriginalNotRetained { flow: FlowId::F2 }
    ));
}

#[test]
fn por_10_every_declared_field_needs_its_own_canary() {
    let mut observations = common::observations();
    common::saved_mut(&mut observations, FlowId::P).plant = Some(PlantDetail {
        object: Some(common::object(common::PRIMARY_OBJECT)),
        canaries: vec![
            PlantedCanary {
                field: common::field("label"),
                canary: common::canary(0x33),
            },
            PlantedCanary {
                field: common::field("label"),
                canary: common::canary(0x44),
            },
        ],
    });

    let evaluation = evaluate(&observations);

    assert_eq!(evaluation.result, Verdict::Invalid);
    assert!(evaluation.evidence.iter().any(|cause| matches!(
        cause,
        IncompleteCause::PlantFieldDuplicated {
            flow: FlowId::P,
            ..
        }
    )));
}

#[test]
fn por_11_cleanup_authority_comes_from_the_plant_response() {
    let mut observations = common::observations();
    common::saved_mut(&mut observations, FlowId::C)
        .cleanup
        .as_mut()
        .expect("cleanup")
        .removed = vec![
        common::object(common::PRIMARY_OBJECT),
        common::object("object-not-created-by-this-run"),
    ];

    let evaluation = evaluate(&observations);

    assert_eq!(
        evaluation.result,
        Verdict::False,
        "cleanup is recorded separately from the verdict"
    );
    assert_eq!(
        evaluation.cleanup.authorized,
        vec![common::object(common::PRIMARY_OBJECT)]
    );
    assert_eq!(
        evaluation.cleanup.unauthorized,
        vec![common::object("object-not-created-by-this-run")]
    );
    assert_eq!(
        evaluation.cleanup.owed,
        vec![common::object(common::CONTROL_OBJECT)]
    );
    assert!(evaluation.cleanup.uncertain_plants.is_empty());
}

#[test]
fn por_11_an_unestablished_plant_grants_no_cleanup_authority() {
    let mut observations = common::observations();
    common::saved_mut(&mut observations, FlowId::P)
        .plant
        .as_mut()
        .expect("plant")
        .object = None;

    let evaluation = evaluate(&observations);

    assert_eq!(evaluation.cleanup.uncertain_plants, vec![FlowId::P]);
    assert_eq!(
        evaluation.cleanup.authorized,
        vec![common::object(common::CONTROL_OBJECT)],
        "only the established object may be removed"
    );
    assert_eq!(
        evaluation.cleanup.unauthorized,
        vec![common::object(common::PRIMARY_OBJECT)]
    );
}

#[test]
fn por_11_an_unrun_cleanup_owes_every_established_object() {
    let mut observations = common::observations();
    let cleanup = common::saved_mut(&mut observations, FlowId::C)
        .cleanup
        .as_mut()
        .expect("cleanup");
    cleanup.attempted = false;
    cleanup.removed = Vec::new();

    let evaluation = evaluate(&observations);

    assert!(!evaluation.cleanup.attempted);
    assert!(evaluation.cleanup.authorized.is_empty());
    assert!(evaluation.cleanup.unauthorized.is_empty());
    assert_eq!(
        evaluation.cleanup.owed,
        vec![
            common::object(common::CONTROL_OBJECT),
            common::object(common::PRIMARY_OBJECT)
        ]
    );
}

#[test]
fn por_11_a_cleanup_that_claims_removals_without_attempting_them_is_separate() {
    let mut observations = common::observations();
    common::saved_mut(&mut observations, FlowId::C)
        .cleanup
        .as_mut()
        .expect("cleanup")
        .attempted = false;

    let evaluation = evaluate(&observations);

    assert_eq!(evaluation.result, Verdict::False);
    assert!(evaluation.cleanup.contradictory);
    assert!(evaluation.evidence.is_empty());
}

#[test]
fn por_11_missing_partial_and_failed_cleanup_preserve_earned_verdicts() {
    for expected in [Verdict::False, Verdict::True] {
        let mut baseline = common::observations();
        if expected == Verdict::True {
            let primary = common::primary();
            common::show(&mut baseline, FlowId::F2, &primary);
        }
        assert_eq!(evaluate(&baseline).result, expected);

        let mut missing = baseline.clone();
        common::remove_flow(&mut missing, FlowId::C);
        let evaluation = evaluate(&missing);
        assert_eq!(evaluation.result, expected);
        assert!(!evaluation.cleanup.attempted);
        assert_eq!(evaluation.cleanup.owed.len(), 2);

        let mut partial = baseline.clone();
        common::saved_mut(&mut partial, FlowId::C).completeness =
            scourge_core::wire::Completeness::Partial;
        let evaluation = evaluate(&partial);
        assert_eq!(evaluation.result, expected);
        assert!(!evaluation.cleanup.attempted);
        assert_eq!(evaluation.cleanup.owed.len(), 2);

        let mut failed = baseline;
        let cleanup = common::saved_mut(&mut failed, FlowId::C)
            .cleanup
            .as_mut()
            .expect("cleanup");
        cleanup.attempted = false;
        cleanup.removed.clear();
        let evaluation = evaluate(&failed);
        assert_eq!(evaluation.result, expected);
        assert!(!evaluation.cleanup.attempted);
        assert_eq!(evaluation.cleanup.owed.len(), 2);
        assert!(!evaluation.cleanup.contradictory);
    }
}

#[test]
fn por_08_every_predicate_flow_remains_verdict_required() {
    for flow in FlowId::VERDICT_REQUIRED {
        let mut observations = common::observations();
        common::remove_flow(&mut observations, flow);
        let evaluation = evaluate(&observations);
        assert_eq!(evaluation.result, Verdict::Invalid, "missing {flow:?}");
        assert_eq!(
            reasons(&evaluation),
            vec![InvalidReason::EvidenceIncomplete.code()],
            "missing {flow:?}"
        );
    }
}
