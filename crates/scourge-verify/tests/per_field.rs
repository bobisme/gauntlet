//! Per-field treatments, partial owner reads and the round-level note.
//!
//! POR-03 and POR-10 plant a distinct canary in every declared field, so a
//! treatment read can carry a canary the owner read F1 did not show. Those
//! canaries are evidence: they must be reported, they must never produce a
//! `false`, and one field's presence in F0 must keep the round-level
//! `after_owner_read` note false for another field seen only in F3.

mod common;

use scourge_core::wire::Exposure;
use scourge_verify::{FlowId, InvalidReason, Verdict, evaluate};

const LABEL: &str = "label";
const NOTE: &str = "note";

#[test]
fn a_primary_canary_in_f0_that_f1_did_not_show_is_never_false() {
    // Regression for th-5jiysb: the owner read shows `label`, F0 carries the
    // `note` canary. Before the fix this evaluated to `false` with no fields.
    let mut observations = common::observations();
    let note = common::canary(0x33);
    common::plant_primary(&mut observations, NOTE, &note);
    common::saved_mut(&mut observations, FlowId::F0).body = common::body_with_field(NOTE, &note);

    let evaluation = evaluate(&observations);

    assert_eq!(
        evaluation.result,
        Verdict::True,
        "a planted canary in F0 is an exposure even when F1 did not show that field"
    );
    assert_eq!(evaluation.exposure, Some(Exposure::Unauthenticated));
    assert_eq!(evaluation.fields_crossed, vec![common::field(NOTE)]);
    assert_eq!(
        evaluation.after_owner_read,
        Some(false),
        "F0 itself carried a primary canary"
    );
    assert!(evaluation.reason_codes.is_empty());
    assert!(evaluation.evidence.is_empty());
}

#[test]
fn a_primary_canary_in_f2_that_f1_did_not_show_is_true_cross_principal() {
    // Regression for th-5jiysb, cross-principal variant.
    let mut observations = common::observations();
    let note = common::canary(0x33);
    common::plant_primary(&mut observations, NOTE, &note);
    common::saved_mut(&mut observations, FlowId::F2).body = common::body_with_field(NOTE, &note);

    let evaluation = evaluate(&observations);

    assert_eq!(evaluation.result, Verdict::True);
    assert_eq!(evaluation.exposure, Some(Exposure::CrossPrincipal));
    assert_eq!(evaluation.fields_crossed, vec![common::field(NOTE)]);
    assert_eq!(evaluation.after_owner_read, Some(false));
}

#[test]
fn a_partial_f1_treatment_is_reported_and_keeps_the_unauthenticated_downgrade_out() {
    // Regression for the severity downgrade in th-5jiysb: F1 and F2 show
    // `label`, F0 carries `note`. The exposure is unauthenticated, not
    // cross_principal, and both fields are reported.
    let mut observations = common::observations();
    let note = common::canary(0x33);
    common::plant_primary(&mut observations, NOTE, &note);
    common::saved_mut(&mut observations, FlowId::F2).body =
        common::body_with_field(LABEL, &common::primary());
    common::saved_mut(&mut observations, FlowId::F0).body = common::body_with_field(NOTE, &note);

    let evaluation = evaluate(&observations);

    assert_eq!(evaluation.result, Verdict::True);
    assert_eq!(evaluation.exposure, Some(Exposure::Unauthenticated));
    assert_eq!(
        evaluation.fields_crossed,
        vec![common::field(LABEL), common::field(NOTE)]
    );
}

#[test]
fn false_requires_every_primary_canary_absent_from_every_treatment_read() {
    let mut observations = common::observations();
    let note = common::canary(0x33);
    common::plant_primary(&mut observations, NOTE, &note);
    common::saved_mut(&mut observations, FlowId::F1).body =
        common::body_with_all(&[&common::primary(), &note]);

    let evaluation = evaluate(&observations);

    assert_eq!(
        evaluation.result,
        Verdict::False,
        "the owner read shows both fields and no treatment read shows either"
    );
    assert_eq!(evaluation.exposure, None);
    assert_eq!(evaluation.after_owner_read, Some(false));
    assert!(evaluation.fields_crossed.is_empty());
}

#[test]
fn one_treatment_hit_blocks_false_for_every_other_field() {
    let mut observations = common::observations();
    let note = common::canary(0x33);
    common::plant_primary(&mut observations, NOTE, &note);
    common::saved_mut(&mut observations, FlowId::F1).body =
        common::body_with_all(&[&common::primary(), &note]);
    // The stale value is not this run's canary and cannot support a result on
    // its own; the real `note` canary in F2 still makes the round conclusive.
    common::saved_mut(&mut observations, FlowId::F0).body =
        common::body_with(&common::canary(0x44));
    common::saved_mut(&mut observations, FlowId::F2).body = common::body_with_field(NOTE, &note);

    let evaluation = evaluate(&observations);

    assert_eq!(evaluation.result, Verdict::True);
    assert_eq!(evaluation.exposure, Some(Exposure::CrossPrincipal));
    assert_eq!(evaluation.fields_crossed, vec![common::field(NOTE)]);
}

#[test]
fn a_partial_f1_canary_in_f3_notes_the_exposure_as_after_the_owner_read() {
    let mut observations = common::observations();
    let note = common::canary(0x33);
    common::plant_primary(&mut observations, NOTE, &note);
    common::saved_mut(&mut observations, FlowId::F3).body = common::body_with_field(NOTE, &note);

    let evaluation = evaluate(&observations);

    assert_eq!(evaluation.result, Verdict::True);
    assert_eq!(evaluation.exposure, Some(Exposure::Unauthenticated));
    assert_eq!(evaluation.fields_crossed, vec![common::field(NOTE)]);
    assert_eq!(
        evaluation.after_owner_read,
        Some(true),
        "no primary canary is in F0 and one is in F3"
    );
}

#[test]
fn after_owner_read_is_a_round_level_note_not_a_per_canary_one() {
    // Regression for th-33yc3s: F0 already carried `label`, so the exposure did
    // not appear only after the owner read even though `note` did.
    let mut observations = common::observations();
    let note = common::canary(0x33);
    common::plant_primary(&mut observations, NOTE, &note);
    common::saved_mut(&mut observations, FlowId::F1).body =
        common::body_with_all(&[&common::primary(), &note]);
    common::saved_mut(&mut observations, FlowId::F0).body =
        common::body_with_field(LABEL, &common::primary());
    common::saved_mut(&mut observations, FlowId::F3).body = common::body_with_field(NOTE, &note);

    let evaluation = evaluate(&observations);

    assert_eq!(evaluation.result, Verdict::True);
    assert_eq!(evaluation.exposure, Some(Exposure::Unauthenticated));
    assert_eq!(
        evaluation.fields_crossed,
        vec![common::field(LABEL), common::field(NOTE)]
    );
    assert_eq!(
        evaluation.after_owner_read,
        Some(false),
        "F0 carried a primary canary, so the exposure was not only after the owner read"
    );
}

#[test]
fn a_treatment_canary_with_no_owner_read_canary_stays_observer_invalid() {
    // The frozen precedence is unchanged: POR-04 gates every treatment, so a
    // round whose owner read shows no primary canary is invalid, never `true`
    // and never `false`.
    let mut observations = common::observations();
    let note = common::canary(0x33);
    common::plant_primary(&mut observations, NOTE, &note);
    common::saved_mut(&mut observations, FlowId::F1).body = common::body_with(&common::control());
    common::saved_mut(&mut observations, FlowId::F0).body = common::body_with_field(NOTE, &note);
    common::saved_mut(&mut observations, FlowId::F2).body = common::body_with_field(NOTE, &note);

    let evaluation = evaluate(&observations);

    assert_eq!(evaluation.result, Verdict::Invalid);
    assert_eq!(
        evaluation
            .reason_codes
            .iter()
            .map(|code| code.as_str())
            .collect::<Vec<_>>(),
        vec![InvalidReason::ObserverInvalid.code()]
    );
    assert_eq!(evaluation.exposure, None);
    assert_eq!(evaluation.after_owner_read, None);
    assert!(evaluation.fields_crossed.is_empty());
}
