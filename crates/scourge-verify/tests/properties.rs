//! M1.5.7: deterministic properties of `web.private-object-read.v1`.
//!
//! `Oracle.evaluate` is pure (plan §11.3), so its specification can be checked
//! over generated observations as well as over the hand-written fixtures. Every
//! test here runs in the ordinary suite against a fixed, documented case budget
//! ([`property::CASE_BUDGET`]: four seeds of twenty-four rounds) and needs no
//! network, no target, no credential and no new dependency.
//!
//! The properties:
//!
//! 1. [`true_is_exactly_the_frozen_conjunction`] - the result is `true` exactly
//!    when the frozen predicate holds; and
//!    [`a_single_broken_check_never_verifies`] - breaking one numbered check
//!    never yields `true`.
//! 2. [`a_failed_setup_check_is_invalid_never_false`] and
//!    [`the_frozen_precedence_orders_every_invalid_reason`] - every failed setup
//!    check is `invalid` with the frozen reason and precedence, never `false`.
//! 3. [`a_status_or_policy_sidecar_cannot_be_an_input`] - a test-only HTTP
//!    status/reason sidecar cannot reach the typed oracle and the status and
//!    policy fields stay impossible inputs;
//!    [`the_first_property_kills_a_status_sensitive_mutant`] proves property 1
//!    has teeth against a deliberately broken reader.
//! 4. [`every_coding_carries_the_same_verdict_and_fields`] and
//!    [`an_undecodable_body_is_evidence_incomplete`] - identity, gzip, deflate,
//!    chunked and escaped-JSON bodies carry equivalent canaries to equivalent
//!    verdicts. Invalid bytes or mismatched decoder metadata are
//!    `EVIDENCE_INCOMPLETE`.
//! 5. [`exposure_and_the_note_follow_the_treatment_reads`] - the exposure and
//!    `after_owner_read` note follow F0, F2 and F3 exactly, across multi-field
//!    rounds.
//! 6. [`unsupported_claim_classes_are_refused_before_evaluation`] - the
//!    collection and existence/status classes get `ORACLE_UNAVAILABLE` before
//!    anything is evaluated.
//!
//! Independence: the expected answer comes from
//! [`generated::reference`](common::property::reference), which derives the
//! frozen predicate from the generated plan and never calls `evaluate`.
//!
//! Two harness faults the budget found are pinned as their own tests:
//! [`chunked_framing_states_the_bytes_it_writes`] and
//! [`a_dropped_plant_is_not_a_specificity_finding`]. A third pinned regression
//! is the minimized status-mutant counterexample in
//! [`property::PINNED_MUTANT_CASE`].

mod common;

use std::collections::BTreeSet;

use scourge_core::wire::Exposure;
use scourge_verify::{
    ClaimClass, DecodeError, DecoderName, Decoding, Dispatch, FlowId, IncompleteCause,
    SavedObservations, TransferCoding, Verdict, decode, dispatch, evaluate, registry,
};

use common::property;

fn reasons(evaluation: &scourge_verify::Evaluation) -> Vec<String> {
    evaluation
        .reason_codes
        .iter()
        .map(|code| code.as_str().to_owned())
        .collect()
}

fn fields(evaluation: &scourge_verify::Evaluation) -> Vec<String> {
    evaluation
        .fields_crossed
        .iter()
        .map(|name| name.as_str().to_owned())
        .collect()
}

/// Compare one round against the frozen reference and describe the round on
/// failure, so a failing seed is reproducible with
/// [`property::generate`].
fn agrees(plan: &property::Plan) -> scourge_verify::Evaluation {
    let expected = property::reference(plan);
    let actual = evaluate(&plan.observations());
    if let Some(difference) = expected.difference(&actual) {
        panic!(
            "seed {} case {}: {difference}\nround: {plan:?}",
            plan.seed, plan.case
        );
    }
    actual
}

fn is_frozen_order(codes: &[String]) -> bool {
    let positions: Vec<usize> = codes
        .iter()
        .map(|code| {
            property::FROZEN_REASONS
                .iter()
                .position(|frozen| frozen == code)
                .unwrap_or_else(|| panic!("{code} is not a frozen reason code"))
        })
        .collect();
    positions.windows(2).all(|pair| pair[0] < pair[1])
}

// ---------------------------------------------------------------------------
// 1. true iff every frozen condition holds
// ---------------------------------------------------------------------------

#[test]
fn true_is_exactly_the_frozen_conjunction() {
    let (mut true_cases, mut false_cases, mut invalid_cases) = (0, 0, 0);
    for plan in property::cases() {
        let evaluation = agrees(&plan);
        match evaluation.result {
            Verdict::True => true_cases += 1,
            Verdict::False => false_cases += 1,
            Verdict::Invalid => invalid_cases += 1,
            Verdict::Error => panic!(
                "seed {} case {}: no error is expected",
                plan.seed, plan.case
            ),
        }
    }

    assert_eq!(
        true_cases + false_cases + invalid_cases,
        property::CASE_BUDGET,
        "every generated round must produce a verdict"
    );
    for (name, count) in [
        ("true", true_cases),
        ("false", false_cases),
        ("invalid", invalid_cases),
    ] {
        assert!(count > 0, "the budget must cover {name} rounds");
    }
}

#[test]
fn a_single_broken_check_never_verifies() {
    // The baseline really is a `true` round, so each break isolates one check.
    let baseline = property::baseline_round();
    assert_eq!(agrees(&baseline).result, Verdict::True);

    // Each break of an otherwise-valid round, with the frozen answer it must
    // produce. POR-06 is a matching rule, so its break removes the exposure
    // signal and the frozen answer is `false`; POR-11 is recorded separately
    // and is asserted below.
    let expectations: [(&str, Verdict, &[&str]); 10] = [
        ("POR-01", Verdict::Invalid, &["SAME_SUBJECT"]),
        ("POR-02", Verdict::Invalid, &["SESSION_DRIFT"]),
        ("POR-03", Verdict::Invalid, &["EVIDENCE_INCOMPLETE"]),
        ("POR-04", Verdict::Invalid, &["OBSERVER_INVALID"]),
        ("POR-05", Verdict::Invalid, &["CANARY_NOT_SPECIFIC"]),
        ("POR-06", Verdict::False, &[]),
        ("POR-07", Verdict::Invalid, &["EVIDENCE_INCOMPLETE"]),
        ("POR-08", Verdict::Invalid, &["EVIDENCE_INCOMPLETE"]),
        ("POR-09", Verdict::Invalid, &["EVIDENCE_INCOMPLETE"]),
        ("POR-10", Verdict::Invalid, &["EVIDENCE_INCOMPLETE"]),
    ];

    for (check, expected_result, expected_reasons) in expectations {
        let plan = property::break_check(check);
        let evaluation = agrees(&plan);
        assert_eq!(
            evaluation.result, expected_result,
            "breaking {check} must give {expected_result:?}"
        );
        assert_ne!(
            evaluation.result,
            Verdict::True,
            "breaking {check} must never verify"
        );
        assert_eq!(
            reasons(&evaluation),
            expected_reasons.to_vec(),
            "breaking {check} must report the frozen reason"
        );
    }

    // POR-06 also means that a stale value the target already held cannot stand
    // in for this run's canary.
    let mut observations = property::break_check("POR-06").observations();
    let stale = property::mint_canary(0x5717, 1, 0x77);
    common::saved_mut(&mut observations, FlowId::F2).body = common::body_with(&stale);
    assert_eq!(
        evaluate(&observations).result,
        Verdict::False,
        "only the exact current canary can support a verdict"
    );

    // POR-11: cleanup authority is recorded separately and its break must not
    // move the verdict at all.
    let plan = property::break_check("POR-11");
    let evaluation = agrees(&plan);
    assert_eq!(
        evaluation.result,
        Verdict::True,
        "an unauthorized removal attempt is recorded, not measured as exposure"
    );
    assert_eq!(
        evaluation.cleanup.unauthorized,
        vec![common::object(property::FOREIGN_OBJECT)],
        "a removal without plant-established ownership is reported"
    );
    assert!(
        !evaluation
            .cleanup
            .authorized
            .contains(&common::object(property::FOREIGN_OBJECT)),
        "cleanup must never authorize an object this run did not create"
    );
    assert!(evaluation.cleanup.owed.is_empty());
}

#[test]
fn cleanup_only_authorizes_objects_established_by_a_usable_plant() {
    // The saved cleanup lists the primary object, but P established no ownership.
    let unestablished = property::generate(0x5343_0002, 0);
    let evaluation = agrees(&unestablished);
    assert_eq!(
        evaluation.evidence,
        [IncompleteCause::PlantOwnershipUnestablished { flow: FlowId::P }]
    );
    assert!(evaluation.cleanup.attempted);
    assert_eq!(
        evaluation.cleanup.authorized,
        [common::object(&unestablished.object_control)]
    );
    assert_eq!(
        evaluation.cleanup.unauthorized,
        [common::object(&unestablished.object_primary)]
    );
    assert!(evaluation.cleanup.owed.is_empty());
    assert_eq!(evaluation.cleanup.uncertain_plants, [FlowId::P]);

    // Changing P2's response to name P's object leaves the saved removals intact.
    let aliased = property::generate(0x5343_0001, 20);
    let evaluation = agrees(&aliased);
    assert_eq!(
        evaluation.evidence,
        [IncompleteCause::PlantObjectsNotDistinct]
    );
    assert!(evaluation.cleanup.attempted);
    assert_eq!(
        evaluation.cleanup.authorized,
        [common::object("object-primary-53430001-14")]
    );
    assert_eq!(
        evaluation.cleanup.unauthorized,
        [common::object("object-control-53430001-14")]
    );
    assert!(evaluation.cleanup.owed.is_empty());
    assert!(evaluation.cleanup.uncertain_plants.is_empty());

    // An unusable plant cannot authorize cleanup even when it names an object.
    let plan = property::with_defect(
        property::baseline_round(),
        FlowId::P,
        property::Defect::MissingOriginal,
    );
    let evaluation = agrees(&plan);
    assert_eq!(
        evaluation.cleanup.unauthorized,
        [common::object(&plan.object_primary)]
    );
    assert_eq!(evaluation.cleanup.uncertain_plants, [FlowId::P]);
}

#[test]
fn cleanup_owes_objects_without_a_usable_removal() {
    let mut plan = property::baseline_round();
    plan.cleanup.removed = vec![common::object(&plan.object_primary)];
    let evaluation = agrees(&plan);
    assert!(evaluation.cleanup.attempted);
    assert_eq!(
        evaluation.cleanup.authorized,
        [common::object(&plan.object_primary)]
    );
    assert_eq!(
        evaluation.cleanup.owed,
        [common::object(&plan.object_control)]
    );

    plan.cleanup.attempted = false;
    let evaluation = agrees(&plan);
    assert_eq!(evaluation.result, Verdict::True);
    assert!(evaluation.cleanup.contradictory);
    assert!(evaluation.evidence.is_empty());
    assert!(!evaluation.cleanup.attempted);
    assert_eq!(
        evaluation.cleanup.owed,
        [
            common::object(&plan.object_control),
            common::object(&plan.object_primary)
        ]
    );

    let plan = property::with_defect(plan, FlowId::C, property::Defect::Partial);
    let evaluation = agrees(&plan);
    assert_eq!(evaluation.result, Verdict::True);
    assert!(!evaluation.cleanup.attempted);
    assert!(evaluation.cleanup.contradictory);
    assert!(evaluation.cleanup.authorized.is_empty());
    assert!(evaluation.cleanup.unauthorized.is_empty());
    assert_eq!(
        evaluation.cleanup.owed,
        [
            common::object(&plan.object_control),
            common::object(&plan.object_primary)
        ]
    );
}

// ---------------------------------------------------------------------------
// 2. a failed setup check is invalid with the frozen precedence
// ---------------------------------------------------------------------------

#[test]
fn a_failed_setup_check_is_invalid_never_false() {
    let mut failed = 0;
    for plan in property::cases() {
        let expected = property::reference(&plan);
        let evaluation = agrees(&plan);
        let codes = reasons(&evaluation);

        if expected.reasons.is_empty() {
            assert_ne!(
                evaluation.result,
                Verdict::Invalid,
                "seed {} case {}: a valid round cannot be invalid",
                plan.seed,
                plan.case
            );
            assert!(codes.is_empty());
            continue;
        }

        failed += 1;
        assert_eq!(
            evaluation.result,
            Verdict::Invalid,
            "seed {} case {}: a failed setup check is never false or true",
            plan.seed,
            plan.case
        );
        assert_eq!(
            codes,
            expected
                .reasons
                .iter()
                .map(|reason| (*reason).to_owned())
                .collect::<Vec<String>>(),
            "seed {} case {}: the frozen reason codes must be reported exactly",
            plan.seed,
            plan.case
        );
        assert!(is_frozen_order(&codes));
        assert_eq!(evaluation.exposure, None);
        assert_eq!(evaluation.after_owner_read, None);
        assert!(evaluation.fields_crossed.is_empty());
    }
    assert!(
        failed > 0,
        "the budget must generate rounds with a failed setup check"
    );
}

#[test]
fn the_frozen_precedence_orders_every_invalid_reason() {
    // All five reasons at once: the frozen list is the report order.
    let plan = property::break_all_precedence();
    let evaluation = agrees(&plan);

    assert_eq!(evaluation.result, Verdict::Invalid);
    assert_eq!(reasons(&evaluation), property::FROZEN_REASONS.to_vec());

    // Every generated multi-reason round is reported in that same order.
    for plan in property::cases() {
        let evaluation = agrees(&plan);
        assert!(is_frozen_order(&reasons(&evaluation)));
    }
}

// ---------------------------------------------------------------------------
// 3. a status or policy sidecar cannot be an input
// ---------------------------------------------------------------------------

#[test]
fn a_status_or_policy_sidecar_cannot_be_an_input() {
    // A compile-time pin: one argument, typed observations in, evaluation out.
    // There is no status argument and no policy argument (INV-08).
    let oracle: fn(&SavedObservations) -> scourge_verify::Evaluation = evaluate;
    assert_eq!(
        oracle(&property::baseline_round().observations()).result,
        Verdict::True
    );

    // The sidecar is test-only: flipping every value cannot move the typed
    // result, because the oracle's only argument is the saved observations.
    for plan in property::cases().into_iter().step_by(12) {
        let baseline = evaluate(&plan.observations());
        let mut changed = plan.clone();
        for sidecar in &mut changed.sidecar {
            sidecar.status = if sidecar.status == 200 { 403 } else { 200 };
            sidecar.reason = "Changed";
        }
        assert_eq!(
            evaluate(&changed.observations()),
            baseline,
            "seed {} case {}: an HTTP status is not an oracle input (INV-08)",
            plan.seed,
            plan.case
        );
    }

    // And there is nowhere to put one: every level rejects an unknown field.
    let document = serde_json::to_value(property::baseline_round().observations())
        .expect("observations serialize");
    let injections = [
        ("", "status"),
        ("", "reason"),
        ("", "policy_rule"),
        ("/flows/4", "status"),
        ("/flows/4", "reason_phrase"),
        ("/flows/4", "policy"),
        ("/flows/4/decoding", "status_code"),
        ("/flows/2/plant", "status"),
        ("/flows/2/plant/canaries/0", "readers"),
        ("/flows/11/cleanup", "policy_rule"),
    ];
    for (pointer, key) in injections {
        let mut injected = document.clone();
        let target = injected
            .pointer_mut(pointer)
            .unwrap_or_else(|| panic!("{pointer} is a saved-observation object"))
            .as_object_mut()
            .unwrap_or_else(|| panic!("{pointer} is a saved-observation object"));
        target.insert(key.to_owned(), serde_json::json!("injected"));
        let bytes = serde_json::to_vec(&injected).expect("encode");
        assert!(
            scourge_core::canonical::from_slice::<SavedObservations>(&bytes).is_err(),
            "{pointer}/{key} must not be loadable"
        );
    }

    // A loaded round has no status or policy key anywhere in its surface.
    let saved = serde_json::to_value(property::baseline_round().observations())
        .expect("observations serialize");
    let mut stack = vec![saved];
    while let Some(value) = stack.pop() {
        match value {
            serde_json::Value::Object(members) => {
                for (key, member) in members {
                    assert!(
                        !matches!(
                            key.as_str(),
                            "status"
                                | "status_code"
                                | "reason"
                                | "reason_phrase"
                                | "policy"
                                | "policy_rule"
                                | "readers"
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

#[test]
fn the_first_property_kills_a_status_sensitive_mutant() {
    // The mutant reads the HTTP status sidecar. Property 1 must fail for it.
    let mut killed = 0;
    for plan in property::cases() {
        if property::disagrees_with_reference(&plan, property::status_mutant) {
            killed += 1;
        }
    }
    assert!(
        killed > 0,
        "a status-sensitive reader must fail the first property"
    );

    // The shipped oracle passes that same property on that same budget.
    for plan in property::cases() {
        agrees(&plan);
    }

    // The counterexample is minimized and pinned, so the regression cannot
    // silently disappear.
    let (seed, case, plan) = property::minimize_status_mutant();
    assert_eq!(
        (seed, case),
        property::PINNED_MUTANT_CASE,
        "the minimized status-mutant counterexample moved"
    );
    let expected = property::reference(&plan);
    assert!(
        property::disagrees_with_reference(&plan, property::status_mutant),
        "the mutant must still be killed by seed {seed} case {case}"
    );
    let actual = agrees(&plan);
    assert_eq!(
        actual.result, expected.result,
        "the shipped oracle, not the mutant, agrees with the frozen reference"
    );
    assert_eq!(plan.primary.len(), 1, "the counterexample is minimized");
    assert_eq!(plan.control.len(), 1, "the counterexample is minimized");
    assert!(
        plan.flows
            .iter()
            .all(|flow| flow.defect == property::Defect::None),
        "the counterexample carries no unrelated defect"
    );
    eprintln!(
        "minimized status-sensitive counterexample: seed {seed} case {case} (reference {:?})",
        expected.result
    );
}

#[test]
fn a_seed_reproduces_its_round_exactly() {
    for plan in property::cases() {
        assert_eq!(
            property::generate(plan.seed, plan.case),
            plan,
            "seed {} case {} must regenerate the same round",
            plan.seed,
            plan.case
        );
    }
}

#[test]
fn chunked_framing_states_the_bytes_it_writes() {
    // Found by the generated budget: a decoded body can be shorter than the
    // first requested chunk, and a framing helper that announces the requested
    // size makes such a body undecodable. Every one of these must round-trip.
    let decoding = Decoding {
        transfer: TransferCoding::Chunked,
        ..Decoding::default()
    };
    for body in [
        b"".as_slice(),
        b"a".as_slice(),
        b"{}".as_slice(),
        b"0123456789".as_slice(),
    ] {
        let coded = common::chunked(body, &[3, 5, 7]);
        let decoded = decode(&coded, decoding, scourge_verify::DecodeLimits::default())
            .expect("a short chunked body must decode");
        assert_eq!(decoded.bytes, body);
    }
}

#[test]
fn a_dropped_plant_is_not_a_specificity_finding() {
    // Found by the generated budget: when the primary plant's canaries are
    // dropped for a POR-10 break, an echoed canary in F4 is not evidence about
    // object specificity. The round is incomplete, and only that.
    let mut plan = property::break_check("POR-10");
    plan.f4 = vec![0];

    let evaluation = agrees(&plan);
    assert_eq!(evaluation.result, Verdict::Invalid);
    assert_eq!(reasons(&evaluation), vec!["EVIDENCE_INCOMPLETE"]);
}

// ---------------------------------------------------------------------------
// 4. every coding carries the same canaries; undecodable bodies are incomplete
// ---------------------------------------------------------------------------

#[test]
fn every_coding_carries_the_same_verdict_and_fields() {
    let mut checked = 0;
    for plan in property::cases().into_iter().step_by(12) {
        let undamaged = plan
            .flows
            .iter()
            .all(|flow| flow.defect == property::Defect::None);
        let identity = evaluate(&property::coded_with(plan.clone(), 0).observations());

        for (index, (decoding, name)) in property::DECODING_STACKS.into_iter().enumerate() {
            let evaluation = evaluate(&property::coded_with(plan.clone(), index).observations());
            assert_eq!(
                evaluation.result, identity.result,
                "seed {} case {}: {decoding:?} changed the verdict",
                plan.seed, plan.case
            );
            assert_eq!(evaluation.exposure, identity.exposure);
            assert_eq!(evaluation.after_owner_read, identity.after_owner_read);
            assert_eq!(evaluation.fields_crossed, identity.fields_crossed);

            if undamaged {
                let named: Vec<&str> = evaluation
                    .decoders
                    .iter()
                    .map(|name| name.as_str())
                    .collect();
                let expected: Vec<&str> = name.into_iter().collect();
                assert_eq!(
                    named, expected,
                    "the record must name the decoder it applied (POR-09)"
                );
            }
            checked += 1;
        }
    }
    assert!(
        checked >= property::DECODING_STACKS.len(),
        "every coding stack must be exercised"
    );
}

#[test]
fn a_decoder_name_mismatch_is_evidence_incomplete_with_the_original_retained() {
    let flow = FlowId::F3;
    let gzip = property::DECODING_STACKS
        .iter()
        .position(|(_, name)| *name == Some("gzip"))
        .expect("frozen gzip decoder");
    for (coding, recorded, expected) in [
        (gzip, None, Some("gzip")),
        (gzip, Some("deflate"), Some("gzip")),
        (0, Some("gzip"), None),
    ] {
        let baseline = property::coded_with(property::baseline_round(), coding);
        let original = baseline.observations();
        assert_eq!(agrees(&baseline).result, Verdict::True);

        let damaged = property::with_defect(
            baseline,
            flow,
            property::Defect::DecoderUnnamed { recorded },
        );
        let damaged_observations = damaged.observations();
        let original_flow = common::saved(&original, flow);
        let damaged_flow = common::saved(&damaged_observations, flow);
        assert!(damaged_flow.original.is_some());
        assert_eq!(damaged_flow.original, original_flow.original);
        assert_eq!(damaged_flow.body, original_flow.body);

        let evaluation = agrees(&damaged);
        assert_eq!(evaluation.result, Verdict::Invalid);
        assert_eq!(reasons(&evaluation), ["EVIDENCE_INCOMPLETE"]);
        let [
            IncompleteCause::DecoderNotNamed {
                flow: at,
                recorded: actual_recorded,
                expected: actual_expected,
            },
        ] = evaluation.evidence.as_slice()
        else {
            panic!(
                "expected exactly one naming failure, got {:?}",
                evaluation.evidence
            );
        };
        assert_eq!(*at, flow);
        assert_eq!(actual_recorded.as_ref().map(DecoderName::as_str), recorded);
        assert_eq!(actual_expected.as_ref().map(DecoderName::as_str), expected);
    }
}

#[test]
fn an_undecodable_body_is_evidence_incomplete() {
    let mut checked = 0;
    for plan in property::cases().into_iter().step_by(24) {
        for flow in [FlowId::I1, FlowId::P, FlowId::F1, FlowId::F2, FlowId::F4] {
            for kind in [
                DecodeError::OverLimit,
                DecodeError::ExpansionRatio,
                DecodeError::Truncated,
                DecodeError::Corrupt,
            ] {
                let damaged = property::with_decode_defect(plan.clone(), flow, kind);
                let evaluation = agrees(&damaged);
                assert_eq!(
                    evaluation.result,
                    Verdict::Invalid,
                    "a {kind:?} body in {flow:?} is evidence, never a verdict"
                );
                assert!(
                    reasons(&evaluation).contains(&"EVIDENCE_INCOMPLETE".to_owned()),
                    "the round must stay incomplete"
                );
                assert!(
                    evaluation
                        .evidence
                        .contains(&IncompleteCause::Decode { flow, error: kind }),
                    "the round must record the {kind:?} failure of {flow:?}"
                );
                checked += 1;
            }
        }
    }
    assert!(checked > 0);
}

// ---------------------------------------------------------------------------
// 5. exposure and after_owner_read follow F0, F2 and F3
// ---------------------------------------------------------------------------

#[test]
fn exposure_and_the_note_follow_the_treatment_reads() {
    // Two declared fields so a round can cross one field in F0 and another in
    // F3. Field 0 is `label`, field 1 is `note`.
    for mask in 0..8_u8 {
        let mut plan = property::baseline_round();
        plan.primary.push(property::FieldCanary {
            field: property::FIELD_NAMES[1].to_owned(),
            canary: property::mint_canary(plan.seed, plan.case, 0x102),
        });
        plan.f1 = vec![0];
        plan.f0 = if mask & 0b001 != 0 {
            vec![1]
        } else {
            Vec::new()
        };
        plan.f2 = if mask & 0b010 != 0 {
            vec![0]
        } else {
            Vec::new()
        };
        plan.f3 = if mask & 0b100 != 0 {
            vec![1]
        } else {
            Vec::new()
        };

        let mut crossed: BTreeSet<String> = BTreeSet::new();
        if mask & 0b001 != 0 {
            crossed.insert(plan.primary[1].field.clone());
        }
        if mask & 0b010 != 0 {
            crossed.insert(plan.primary[0].field.clone());
        }
        if mask & 0b100 != 0 {
            crossed.insert(plan.primary[1].field.clone());
        }
        let crossed: Vec<String> = crossed.into_iter().collect();
        let exposure = if !crossed.is_empty() {
            Some(if mask & 0b101 != 0 {
                Exposure::Unauthenticated
            } else {
                Exposure::CrossPrincipal
            })
        } else {
            None
        };
        let after_owner_read = Some(mask & 0b100 != 0 && mask & 0b001 == 0);

        let expected = property::reference(&plan);
        assert_eq!(expected.result != Verdict::False, !crossed.is_empty());
        assert_eq!(expected.exposure, exposure, "mask {mask:03b}");
        assert_eq!(
            expected.after_owner_read, after_owner_read,
            "mask {mask:03b}"
        );

        let evaluation = agrees(&plan);
        assert_eq!(
            evaluation.result,
            if crossed.is_empty() {
                Verdict::False
            } else {
                Verdict::True
            },
            "mask {mask:03b}"
        );
        assert_eq!(evaluation.exposure, exposure, "mask {mask:03b}");
        assert_eq!(fields(&evaluation), crossed, "mask {mask:03b}");
        assert_eq!(
            evaluation.after_owner_read, after_owner_read,
            "mask {mask:03b}"
        );
    }

    // Over the whole budget: one field exposed in F0 must keep the round-level
    // note false even when another field is exposed in F3.
    for plan in property::cases() {
        let evaluation = agrees(&plan);
        if !evaluation.is_conclusive() {
            continue;
        }
        let in_f0 = !plan.f0.is_empty();
        let in_f2 = !plan.f2.is_empty();
        let in_f3 = !plan.f3.is_empty();
        let mut crossed: BTreeSet<String> = BTreeSet::new();
        for index in plan.f0.iter().chain(&plan.f2).chain(&plan.f3) {
            crossed.insert(plan.primary[*index].field.clone());
        }
        let crossed: Vec<String> = crossed.into_iter().collect();

        assert_eq!(
            evaluation.result,
            if crossed.is_empty() {
                Verdict::False
            } else {
                Verdict::True
            },
            "seed {} case {}",
            plan.seed,
            plan.case
        );
        assert_eq!(fields(&evaluation), crossed);
        assert_eq!(
            evaluation.exposure,
            if crossed.is_empty() {
                None
            } else if in_f0 || in_f3 {
                Some(Exposure::Unauthenticated)
            } else {
                Some(Exposure::CrossPrincipal)
            },
            "seed {} case {}",
            plan.seed,
            plan.case
        );
        assert_eq!(
            evaluation.after_owner_read,
            Some(!in_f0 && in_f3),
            "seed {} case {}",
            plan.seed,
            plan.case
        );
        let _ = in_f2;
    }
}

// ---------------------------------------------------------------------------
// 6. unsupported classes are refused before evaluation
// ---------------------------------------------------------------------------

#[test]
fn unsupported_claim_classes_are_refused_before_evaluation() {
    // The gate takes a claim-class name and nothing else: there is no
    // observations argument, so a refused lead cannot have been evaluated.
    let gate: fn(&str) -> Dispatch = dispatch;

    for class in ClaimClass::REGISTERED {
        match gate(class.claim_class()) {
            Dispatch::InClass(supported) => {
                assert_eq!(class, ClaimClass::PrivateObjectRead);
                assert_eq!(supported, ClaimClass::PrivateObjectRead);
            }
            Dispatch::OracleUnavailable {
                claim_class,
                oracle,
                result,
                timing,
                supported_claim_classes,
                unsupported_scope_names,
            } => {
                assert_ne!(class, ClaimClass::PrivateObjectRead);
                assert_eq!(claim_class, class);
                assert_eq!(result, "ORACLE_UNAVAILABLE");
                assert_eq!(oracle, "web.private-object-read");
                assert_eq!(timing, "before target traffic");
                assert_eq!(supported_claim_classes, &[ClaimClass::PrivateObjectRead]);
                assert_eq!(
                    unsupported_scope_names,
                    &["collection_disclosure", "object_existence_or_status"]
                );
            }
            Dispatch::Unregistered => panic!("{class:?} is a registered claim class"),
        }
    }

    for name in ["web-authz/collection-disclosure", "web-authz/existence"] {
        assert_eq!(
            gate(name).result_code(),
            Some(registry::ORACLE_UNAVAILABLE),
            "{name} is out of this oracle's class"
        );
    }
    assert_eq!(registry::ORACLE_UNAVAILABLE, "ORACLE_UNAVAILABLE");
    assert_eq!(gate("web-authz/made-up"), Dispatch::Unregistered);
}
