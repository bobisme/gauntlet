//! Saved observations: the file the verifier records is the only input.
//!
//! These tests load committed evidence-shaped documents, so the oracle path is
//! exercised from bytes rather than from test constructors. They also pin the
//! input surface: no HTTP status and no policy rule can reach the predicate.

mod common;

use scourge_core::{canonical, wire::Exposure};
use scourge_verify::{Evaluation, FlowId, IncompleteCause, SavedObservations, Verdict, evaluate};

const TRUE: &[u8] =
    include_bytes!("fixtures/observations/true-unauthenticated-after-owner-read.json");
const FALSE: &[u8] = include_bytes!("fixtures/observations/false-no-exposure.json");
const MISSING: &[u8] = include_bytes!("fixtures/observations/invalid-missing-flow.json");
const SAME: &[u8] = include_bytes!("fixtures/observations/invalid-same-subject.json");
const PARTIAL_F1: &[u8] = include_bytes!("fixtures/observations/partial-f1-f0-field-exposure.json");

fn load(bytes: &[u8]) -> SavedObservations {
    canonical::from_slice(bytes).expect("saved observations decode")
}

fn document(bytes: &[u8]) -> serde_json::Value {
    canonical::parse(bytes).expect("fixture is JSON")
}

#[test]
fn a_saved_true_round_measures_unauthenticated_exposure_after_the_owner_read() {
    let evaluation = evaluate(&load(TRUE));

    assert_eq!(evaluation.result, Verdict::True);
    assert_eq!(evaluation.exposure, Some(Exposure::Unauthenticated));
    assert_eq!(evaluation.after_owner_read, Some(true));
    assert_eq!(evaluation.fields_crossed.len(), 1);
}

#[test]
fn a_saved_false_round_reports_no_exposure() {
    let evaluation = evaluate(&load(FALSE));

    assert_eq!(evaluation.result, Verdict::False);
    assert_eq!(evaluation.exposure, None);
    assert_eq!(evaluation.after_owner_read, Some(false));
}

#[test]
fn a_saved_round_that_lacks_a_required_flow_is_incomplete() {
    let observations = load(MISSING);
    assert_eq!(observations.flows.len(), 11);

    let evaluation = evaluate(&observations);

    assert_eq!(evaluation.result, Verdict::Invalid);
    assert_eq!(evaluation.reason_codes[0].as_str(), "EVIDENCE_INCOMPLETE");
    assert!(
        evaluation
            .evidence
            .contains(&IncompleteCause::MissingFlow(FlowId::F2))
    );
}

#[test]
fn a_saved_round_with_one_subject_is_invalid() {
    let evaluation = evaluate(&load(SAME));

    assert_eq!(evaluation.result, Verdict::Invalid);
    assert_eq!(evaluation.reason_codes[0].as_str(), "SAME_SUBJECT");
}

#[test]
fn saved_bodies_round_trip_byte_exact() {
    let observations = load(TRUE);
    let encoded = serde_json::to_vec_pretty(&observations).expect("encode");
    let decoded = load(&encoded);

    assert_eq!(decoded, observations);
    let original = document(TRUE);
    assert_eq!(
        original["flows"][4]["body"],
        document(&encoded)["flows"][4]["body"],
        "the saved original bytes are retained exactly"
    );
}

#[test]
fn the_oracle_signature_takes_observations_only() {
    // A compile-time pin: one argument, typed observations in, evaluation out.
    // There is no status argument and no policy argument (INV-08).
    let oracle: fn(&SavedObservations) -> Evaluation = evaluate;
    let evaluation = oracle(&load(FALSE));

    assert_eq!(evaluation.result, Verdict::False);
}

#[test]
fn an_http_status_field_is_rejected_at_the_boundary() {
    let mut flow_scoped = document(TRUE);
    flow_scoped["flows"][5]["status"] = serde_json::json!(200);
    assert!(
        serde_json::from_value::<SavedObservations>(flow_scoped).is_err(),
        "a saved flow can carry no status"
    );

    let mut document_scoped = document(TRUE);
    document_scoped["status"] = serde_json::json!(200);
    assert!(
        serde_json::from_value::<SavedObservations>(document_scoped).is_err(),
        "a saved round can carry no status"
    );

    let mut status_code = document(TRUE);
    status_code["flows"][2]["status_code"] = serde_json::json!(403);
    assert!(serde_json::from_value::<SavedObservations>(status_code).is_err());
}

#[test]
fn a_policy_field_is_rejected_at_the_boundary() {
    let mut policy_rule = document(TRUE);
    policy_rule["policy_rule"] = serde_json::json!({ "readers": "public" });
    assert!(
        serde_json::from_value::<SavedObservations>(policy_rule).is_err(),
        "the oracle never reads a policy rule"
    );

    let mut readers = document(TRUE);
    readers["flows"][7]["readers"] = serde_json::json!("authenticated");
    assert!(serde_json::from_value::<SavedObservations>(readers).is_err());
}

#[test]
fn the_saved_document_has_no_status_or_policy_key_anywhere() {
    for fixture in [TRUE, FALSE, MISSING, SAME] {
        let mut stack = vec![document(fixture)];
        while let Some(value) = stack.pop() {
            match value {
                serde_json::Value::Object(members) => {
                    for (key, member) in members {
                        assert!(
                            !matches!(
                                key.as_str(),
                                "status" | "status_code" | "policy" | "policy_rule" | "readers"
                            ),
                            "the saved surface exposes {key}"
                        );
                        stack.push(member);
                    }
                }
                serde_json::Value::Array(items) => stack.extend(items),
                _ => {}
            }
        }
    }
}

#[test]
fn a_malformed_canary_or_hex_body_is_rejected() {
    let mut canary = document(TRUE);
    canary["flows"][2]["plant"]["canaries"][0]["canary"] =
        serde_json::json!("0123456789ABCDEF0123456789ABCDEF");
    assert!(
        serde_json::from_value::<SavedObservations>(canary).is_err(),
        "a canary is 32 lowercase hexadecimal characters"
    );

    let mut short_canary = document(TRUE);
    short_canary["flows"][2]["plant"]["canaries"][0]["canary"] = serde_json::json!("abc");
    assert!(serde_json::from_value::<SavedObservations>(short_canary).is_err());

    let mut hex = document(TRUE);
    hex["flows"][0]["body"] = serde_json::json!("abc");
    assert!(
        serde_json::from_value::<SavedObservations>(hex).is_err(),
        "an odd-length hex body is rejected"
    );

    let mut non_hex = document(TRUE);
    non_hex["flows"][0]["body"] = serde_json::json!("zz");
    assert!(serde_json::from_value::<SavedObservations>(non_hex).is_err());
}

#[test]
fn a_saved_round_for_another_oracle_version_is_error_not_a_report() {
    let mut other = document(TRUE);
    other["oracle"]["id"] = serde_json::json!("web.forbidden-state-change");
    let observations: SavedObservations =
        serde_json::from_value(other).expect("the document shape still decodes");

    let evaluation = evaluate(&observations);

    assert_eq!(evaluation.result, Verdict::Error);
    assert_eq!(evaluation.after_owner_read, None);
}

#[test]
fn an_unsupported_coding_is_rejected_as_typed_input() {
    // A coding the decoder cannot undo is refused by the typed boundary, not
    // silently treated as identity and not recorded as a policy decision.
    for (member, value) in [
        ("content", "br"),
        ("content", "gzip, br"),
        ("content", "GZIP"),
        ("transfer", "gzip"),
        ("transfer", "chunked, gzip"),
    ] {
        let mut flow_scoped = document(FALSE);
        flow_scoped["flows"][5]["decoding"][member] = serde_json::json!(value);
        let error = serde_json::from_value::<SavedObservations>(flow_scoped).err();
        assert!(
            error.is_some(),
            "an unsupported {member} coding {value:?} must not decode"
        );
    }

    // The decoding block is closed: no extra key can steer decoding.
    let mut extra = document(FALSE);
    extra["flows"][5]["decoding"]["brotli"] = serde_json::json!(true);
    assert!(serde_json::from_value::<SavedObservations>(extra).is_err());
}

#[test]
fn the_typed_coding_enums_are_closed() {
    // Both codings are exhaustive enums with no catch-all: `decode` cannot be
    // handed an unnamed coding, and the decoder names are derived from them.
    let decodings = [
        scourge_verify::Decoding::default(),
        scourge_verify::Decoding {
            transfer: scourge_verify::TransferCoding::Chunked,
            content: scourge_verify::ContentCoding::Gzip,
            json_string_body: true,
        },
    ];
    for decoding in decodings {
        let document = serde_json::to_value(decoding).expect("decoding serializes");
        let round_trip: scourge_verify::Decoding =
            serde_json::from_value(document).expect("typed decoding round-trips");
        assert_eq!(round_trip, decoding);
    }
}

#[test]
fn a_saved_round_whose_f1_masked_a_field_still_reports_the_f0_exposure() {
    // A document-shaped regression for th-5jiysb: the primary plant carries a
    // `label` and a `note` canary, the owner read shows only `label`, and F0
    // carries `note`. The round is conclusive, unauthenticated and reports the
    // masked field; it is never `false`.
    let evaluation = evaluate(&load(PARTIAL_F1));

    assert_eq!(evaluation.result, Verdict::True);
    assert_eq!(evaluation.exposure, Some(Exposure::Unauthenticated));
    assert_eq!(
        evaluation.fields_crossed,
        vec![common::field("note")],
        "the field the owner read masked is the crossed field"
    );
    assert_eq!(evaluation.after_owner_read, Some(false));
    assert!(evaluation.reason_codes.is_empty());
    assert!(evaluation.evidence.is_empty());
}
