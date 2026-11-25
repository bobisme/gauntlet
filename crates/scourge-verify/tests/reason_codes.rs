//! Every frozen invalid reason code, its evidence detail and its precedence.

mod common;

use scourge_core::wire::Completeness;
use scourge_verify::{FlowId, IncompleteCause, InvalidReason, Verdict, evaluate};

fn codes(evaluation: &scourge_verify::Evaluation) -> Vec<&str> {
    evaluation
        .reason_codes
        .iter()
        .map(|code| code.as_str())
        .collect()
}

#[test]
fn same_subject_is_invalid_not_false() {
    let mut observations = common::observations();
    common::saved_mut(&mut observations, FlowId::I2).subject = Some(common::subject(common::OWNER));
    // Keep the round otherwise stable so only the identity collision applies.
    common::saved_mut(&mut observations, FlowId::I4).subject = Some(common::subject(common::OWNER));

    let evaluation = evaluate(&observations);

    assert_eq!(evaluation.result, Verdict::Invalid);
    assert_eq!(codes(&evaluation), vec!["SAME_SUBJECT"]);
    assert_eq!(evaluation.exposure, None);
    assert_eq!(evaluation.after_owner_read, None);
}

#[test]
fn observer_invalid_is_invalid_not_false() {
    let mut observations = common::observations();
    common::saved_mut(&mut observations, FlowId::F1).body = b"<html>login page</html>".to_vec();

    let evaluation = evaluate(&observations);

    assert_eq!(evaluation.result, Verdict::Invalid);
    assert_eq!(codes(&evaluation), vec!["OBSERVER_INVALID"]);
    assert_eq!(evaluation.after_owner_read, None);
}

#[test]
fn canary_not_specific_is_invalid_not_false() {
    let mut observations = common::observations();
    common::show(&mut observations, FlowId::F4, &common::primary());

    let evaluation = evaluate(&observations);

    assert_eq!(evaluation.result, Verdict::Invalid);
    assert_eq!(codes(&evaluation), vec!["CANARY_NOT_SPECIFIC"]);
}

#[test]
fn session_drift_is_invalid_not_false() {
    let mut observations = common::observations();
    common::saved_mut(&mut observations, FlowId::I3).subject = Some(common::subject(common::OTHER));

    let evaluation = evaluate(&observations);

    assert_eq!(evaluation.result, Verdict::Invalid);
    assert_eq!(codes(&evaluation), vec!["SESSION_DRIFT"]);
}

#[test]
fn final_other_subject_drift_is_also_session_drift() {
    let mut observations = common::observations();
    common::saved_mut(&mut observations, FlowId::I4).subject = Some(common::subject(common::OWNER));

    let evaluation = evaluate(&observations);

    assert_eq!(codes(&evaluation), vec!["SESSION_DRIFT"]);
}

#[test]
fn a_missing_flow_is_evidence_incomplete() {
    let mut observations = common::observations();
    common::remove_flow(&mut observations, FlowId::F2);

    let evaluation = evaluate(&observations);

    assert_eq!(evaluation.result, Verdict::Invalid);
    assert_eq!(codes(&evaluation), vec!["EVIDENCE_INCOMPLETE"]);
    assert_eq!(
        evaluation.evidence,
        vec![IncompleteCause::MissingFlow(FlowId::F2)]
    );
}

#[test]
fn an_incomplete_flow_is_evidence_incomplete() {
    let mut observations = common::observations();
    common::saved_mut(&mut observations, FlowId::F3).completeness = Completeness::Partial;

    let evaluation = evaluate(&observations);

    assert_eq!(codes(&evaluation), vec!["EVIDENCE_INCOMPLETE"]);
    assert_eq!(
        evaluation.evidence,
        vec![IncompleteCause::FlowNotComplete {
            flow: FlowId::F3,
            recorded: Completeness::Partial,
        }]
    );
}

#[test]
fn precedence_is_frozen_and_reported_in_order() {
    let mut observations = common::observations();
    // Every frozen invalid reason at once.
    common::saved_mut(&mut observations, FlowId::I2).subject = Some(common::subject(common::OWNER));
    common::saved_mut(&mut observations, FlowId::F1).body = b"login page".to_vec();
    common::show(&mut observations, FlowId::F4, &common::primary());
    common::saved_mut(&mut observations, FlowId::I3).subject = Some(common::subject(common::OTHER));
    common::remove_flow(&mut observations, FlowId::F2);

    let evaluation = evaluate(&observations);

    assert_eq!(evaluation.result, Verdict::Invalid);
    assert_eq!(
        codes(&evaluation),
        vec![
            "SAME_SUBJECT",
            "OBSERVER_INVALID",
            "CANARY_NOT_SPECIFIC",
            "SESSION_DRIFT",
            "EVIDENCE_INCOMPLETE",
        ]
    );
    assert_eq!(
        evaluation.primary_reason(),
        Some(&InvalidReason::SameSubject.reason_code())
    );
}

#[test]
fn observer_invalid_precedes_canary_not_specific() {
    let mut observations = common::observations();
    common::saved_mut(&mut observations, FlowId::F1).body = b"login page".to_vec();
    common::show(&mut observations, FlowId::F4, &common::primary());

    let evaluation = evaluate(&observations);

    assert_eq!(
        codes(&evaluation),
        vec!["OBSERVER_INVALID", "CANARY_NOT_SPECIFIC"]
    );
}

#[test]
fn canary_not_specific_precedes_session_drift() {
    let mut observations = common::observations();
    common::show(&mut observations, FlowId::F4, &common::primary());
    common::saved_mut(&mut observations, FlowId::I3).subject = Some(common::subject(common::OTHER));

    let evaluation = evaluate(&observations);

    assert_eq!(
        codes(&evaluation),
        vec!["CANARY_NOT_SPECIFIC", "SESSION_DRIFT"]
    );
}

#[test]
fn session_drift_precedes_evidence_incomplete() {
    let mut observations = common::observations();
    common::saved_mut(&mut observations, FlowId::I3).subject = Some(common::subject(common::OTHER));
    common::remove_flow(&mut observations, FlowId::F0);

    let evaluation = evaluate(&observations);

    assert_eq!(
        codes(&evaluation),
        vec!["SESSION_DRIFT", "EVIDENCE_INCOMPLETE"]
    );
}

#[test]
fn a_duplicate_flow_is_evidence_incomplete() {
    let mut observations = common::observations();
    let duplicate = common::flow(FlowId::F2);
    observations.flows.push(duplicate);

    let evaluation = evaluate(&observations);

    assert_eq!(codes(&evaluation), vec!["EVIDENCE_INCOMPLETE"]);
    assert!(
        evaluation
            .evidence
            .contains(&IncompleteCause::DuplicateFlow(FlowId::F2))
    );
}

#[test]
fn a_flow_from_another_run_is_evidence_incomplete() {
    let mut observations = common::observations();
    common::saved_mut(&mut observations, FlowId::F2).run =
        scourge_core::ids::RunId::try_from("R-2".to_owned()).expect("run id");

    let evaluation = evaluate(&observations);

    assert_eq!(codes(&evaluation), vec!["EVIDENCE_INCOMPLETE"]);
    assert_eq!(
        evaluation.evidence,
        vec![IncompleteCause::NotBoundToRun { flow: FlowId::F2 }]
    );
}

#[test]
fn a_wrong_observation_shape_for_a_step_is_evidence_incomplete() {
    let mut observations = common::observations();
    common::saved_mut(&mut observations, FlowId::F3).plant =
        common::saved(&observations, FlowId::P).plant.clone();

    let evaluation = evaluate(&observations);

    assert_eq!(codes(&evaluation), vec!["EVIDENCE_INCOMPLETE"]);
    assert_eq!(
        evaluation.evidence,
        vec![IncompleteCause::FlowShapeMismatch { flow: FlowId::F3 }]
    );
}

#[test]
fn a_plant_without_established_ownership_is_evidence_incomplete() {
    let mut observations = common::observations();
    common::saved_mut(&mut observations, FlowId::P)
        .plant
        .as_mut()
        .expect("plant")
        .object = None;

    let evaluation = evaluate(&observations);

    assert_eq!(codes(&evaluation), vec!["EVIDENCE_INCOMPLETE"]);
    assert!(evaluation.evidence.iter().any(|cause| matches!(
        cause,
        IncompleteCause::PlantOwnershipUnestablished { flow: FlowId::P }
    )));
}
