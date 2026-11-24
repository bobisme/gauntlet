//! POR-12: the out-of-class boundary, decided before any target traffic.

use scourge_verify::{ClaimClass, Dispatch, ORACLE_CONTRACT_KEY, dispatch, registry};

const ORACLE_UNAVAILABLE_CODE: &str = "ORACLE_UNAVAILABLE";

#[test]
fn the_shipped_class_is_in_class() {
    assert_eq!(
        dispatch("web-authz/private-object-read"),
        Dispatch::InClass(ClaimClass::PrivateObjectRead)
    );
    assert_eq!(registry::SUPPORTED_CLAIM_CLASSES.len(), 1);
    assert_eq!(
        ClaimClass::PrivateObjectRead.oracle_scope(),
        "object_read",
        "the scope the frozen checker requires for this class"
    );
    assert_eq!(ORACLE_CONTRACT_KEY, "web.private-object-read.v1");
}

#[test]
fn a_collection_disclosure_lead_gets_oracle_unavailable() {
    let answer = dispatch("web-authz/collection-disclosure");

    assert_eq!(answer.result_code(), Some("ORACLE_UNAVAILABLE"));
    assert_eq!(
        answer.supported_claim_classes(),
        Some(&registry::SUPPORTED_CLAIM_CLASSES[..])
    );
    match answer {
        Dispatch::OracleUnavailable {
            claim_class,
            oracle,
            timing,
            unsupported_scope_names,
            ..
        } => {
            assert_eq!(claim_class, ClaimClass::CollectionDisclosure);
            assert_eq!(oracle, "web.private-object-read");
            assert_eq!(timing, "before target traffic");
            assert_eq!(
                unsupported_scope_names,
                &["collection_disclosure", "object_existence_or_status"]
            );
        }
        other => panic!("a collection lead must not be planned: {other:?}"),
    }
}

#[test]
fn an_existence_or_status_lead_gets_oracle_unavailable() {
    let answer = dispatch("web-authz/existence");

    assert_eq!(answer.result_code(), Some("ORACLE_UNAVAILABLE"));
    match answer {
        Dispatch::OracleUnavailable { claim_class, .. } => {
            assert_eq!(claim_class, ClaimClass::Existence);
            assert_eq!(claim_class.oracle_scope(), "existence");
        }
        other => panic!("an existence lead must not be planned: {other:?}"),
    }
}

#[test]
fn a_class_measured_by_another_oracle_is_not_planned_here() {
    let answer = dispatch("web-authz/state-change");

    assert_eq!(answer.result_code(), Some("ORACLE_UNAVAILABLE"));
    match answer {
        Dispatch::OracleUnavailable { claim_class, .. } => {
            assert_eq!(claim_class, ClaimClass::StateChange);
        }
        other => panic!("a state-change lead must not be planned by this oracle: {other:?}"),
    }
}

#[test]
fn por_12_collection_and_existence_leads_are_never_evaluated() {
    // The oracle's input type cannot name a claim class, and the gate refuses
    // before any observation is read. Neither lead becomes a negative.
    let oracle: fn(&scourge_verify::SavedObservations) -> scourge_verify::Evaluation =
        scourge_verify::evaluate;
    let _ = oracle;
    for claim_class in ["web-authz/collection-disclosure", "web-authz/existence"] {
        let answer = dispatch(claim_class);
        assert_eq!(answer.result_code(), Some(ORACLE_UNAVAILABLE_CODE));
        assert!(matches!(answer, Dispatch::OracleUnavailable { .. }));
    }
}

#[test]
fn an_unregistered_class_matches_no_template() {
    let answer = dispatch("web-authz/idor");

    assert_eq!(answer, Dispatch::Unregistered);
    assert_eq!(answer.result_code(), None);
    assert_eq!(answer.supported_claim_classes(), None);
}

#[test]
fn claim_class_and_scope_pairs_follow_the_registry() {
    let expected = [
        ("web-authz/private-object-read", "object_read"),
        ("web-authz/collection-disclosure", "collection_disclosure"),
        ("web-authz/existence", "existence"),
        ("web-authz/state-change", "state_change"),
    ];
    assert_eq!(ClaimClass::REGISTERED.len(), expected.len());
    for (claim_class, scope) in expected {
        let class = ClaimClass::from_claim_class(claim_class).expect("registered class");
        assert_eq!(class.claim_class(), claim_class);
        assert_eq!(class.oracle_scope(), scope);
    }
}
