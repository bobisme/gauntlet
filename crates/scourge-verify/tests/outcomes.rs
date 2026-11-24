//! Every frozen outcome: `true`, `false`, `invalid` and `error`.

mod common;

use scourge_core::wire::Exposure;
use scourge_verify::{Evaluation, FaultCause, FlowId, PlantedCanary, Verdict, evaluate, supervise};

#[test]
fn false_when_no_treatment_read_shows_the_primary_canary() {
    let observations = common::observations();
    let evaluation = evaluate(&observations);

    assert_eq!(evaluation.result, Verdict::False);
    assert_eq!(evaluation.exposure, None);
    assert_eq!(evaluation.after_owner_read, Some(false));
    assert!(evaluation.fields_crossed.is_empty());
    assert!(evaluation.reason_codes.is_empty());
    assert!(evaluation.evidence.is_empty());
    assert!(evaluation.is_conclusive());
    assert!(!evaluation.is_true());
}

#[test]
fn true_unauthenticated_exposure_before_the_owner_read() {
    let mut observations = common::observations();
    common::show(&mut observations, FlowId::F0, &common::primary());

    let evaluation = evaluate(&observations);

    assert_eq!(evaluation.result, Verdict::True);
    assert_eq!(evaluation.exposure, Some(Exposure::Unauthenticated));
    assert_eq!(evaluation.after_owner_read, Some(false));
    assert_eq!(
        evaluation.fields_crossed,
        vec![common::field(common::FIELD)]
    );
    assert!(evaluation.reason_codes.is_empty());
    assert!(evaluation.is_true());
}

#[test]
fn true_unauthenticated_exposure_after_the_owner_read() {
    let mut observations = common::observations();
    common::show(&mut observations, FlowId::F3, &common::primary());

    let evaluation = evaluate(&observations);

    assert_eq!(evaluation.result, Verdict::True);
    assert_eq!(evaluation.exposure, Some(Exposure::Unauthenticated));
    assert_eq!(
        evaluation.after_owner_read,
        Some(true),
        "F0 lacks the canary and F3 contains it"
    );
}

#[test]
fn true_cross_principal_exposure() {
    let mut observations = common::observations();
    common::show(&mut observations, FlowId::F2, &common::primary());

    let evaluation = evaluate(&observations);

    assert_eq!(evaluation.result, Verdict::True);
    assert_eq!(evaluation.exposure, Some(Exposure::CrossPrincipal));
    assert_eq!(evaluation.after_owner_read, Some(false));
}

#[test]
fn unauthenticated_takes_precedence_over_cross_principal() {
    let mut observations = common::observations();
    common::show(&mut observations, FlowId::F0, &common::primary());
    common::show(&mut observations, FlowId::F2, &common::primary());

    let evaluation = evaluate(&observations);

    assert_eq!(evaluation.result, Verdict::True);
    assert_eq!(evaluation.exposure, Some(Exposure::Unauthenticated));
    assert_eq!(evaluation.after_owner_read, Some(false));
}

#[test]
fn reporting_is_per_declared_field() {
    let mut observations = common::observations();
    let secondary_canary = common::canary(0x33);
    common::saved_mut(&mut observations, FlowId::P)
        .plant
        .as_mut()
        .expect("plant")
        .canaries
        .push(PlantedCanary {
            field: common::field("note"),
            canary: secondary_canary.clone(),
        });
    let mut owner_read = common::body_with(&common::primary());
    owner_read.extend_from_slice(secondary_canary.as_str().as_bytes());
    common::saved_mut(&mut observations, FlowId::F1).body = owner_read;
    common::show(&mut observations, FlowId::F2, &secondary_canary);

    let evaluation = evaluate(&observations);

    assert_eq!(evaluation.result, Verdict::True);
    assert_eq!(evaluation.exposure, Some(Exposure::CrossPrincipal));
    assert_eq!(
        evaluation.fields_crossed,
        vec![common::field("note")],
        "only the crossed field is reported"
    );
}

#[test]
fn stale_content_cannot_support_a_result() {
    let mut observations = common::observations();
    let stale = common::canary(0x44);
    common::show(&mut observations, FlowId::F2, &stale);
    common::show(&mut observations, FlowId::F3, &stale);

    let evaluation = evaluate(&observations);

    assert_eq!(evaluation.result, Verdict::False);
    assert_eq!(evaluation.exposure, None);
}

#[test]
fn error_when_the_saved_observations_name_another_oracle_version() {
    let mut observations = common::observations();
    observations.oracle.version = common::text("2");

    let evaluation = evaluate(&observations);

    assert_eq!(evaluation.result, Verdict::Error);
    assert_eq!(
        evaluation.fault,
        Some(FaultCause::UnregisteredOracleVersion)
    );
    assert_eq!(evaluation.after_owner_read, None);
    assert!(evaluation.reason_codes.is_empty());
    assert!(!evaluation.is_true());
    assert!(!evaluation.is_conclusive());
}

#[test]
fn error_when_the_saved_observations_declare_another_schema() {
    let mut observations = common::observations();
    observations.schema = common::text("scourge.oracle-observations.v2");

    let evaluation = evaluate(&observations);

    assert_eq!(evaluation.result, Verdict::Error);
    assert_eq!(
        evaluation.fault,
        Some(FaultCause::UnregisteredObservationSchema)
    );
}

#[test]
fn instrument_unavailability_is_error_not_a_verdict() {
    let evaluation = Evaluation::fault(FaultCause::InstrumentUnavailable);

    assert_eq!(evaluation.result, Verdict::Error);
    assert_eq!(evaluation.fault, Some(FaultCause::InstrumentUnavailable));
    assert_eq!(evaluation.exposure, None);
    assert_eq!(evaluation.after_owner_read, None);
    assert!(evaluation.fields_crossed.is_empty());
    assert!(!evaluation.is_true());
}

#[test]
fn a_crash_in_the_oracle_body_is_error() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let evaluation = supervise(|| panic!("simulated oracle crash"));
    std::panic::set_hook(previous);

    assert_eq!(evaluation.result, Verdict::Error);
    assert_eq!(evaluation.fault, Some(FaultCause::OraclePanic));
    assert_eq!(evaluation.after_owner_read, None);
    assert!(evaluation.reason_codes.is_empty());
    assert!(!evaluation.is_true());
    assert!(!evaluation.is_conclusive());
}
