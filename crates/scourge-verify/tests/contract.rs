//! The code registration must equal the frozen contract, field by field.

mod common;

use scourge_core::wire::{Exposure, OracleResult};
use scourge_verify::{
    ClaimClass, FlowId, InvalidReason, ORACLE_CONTRACT_KEY, ORACLE_ID, ORACLE_VERSION, Verdict,
    registry,
};

fn contract() -> serde_json::Value {
    serde_json::from_str(registry::ORACLE_SPECIFICATION).expect("the frozen contract is JSON")
}

fn oracle() -> serde_json::Value {
    contract()["oracles"][ORACLE_CONTRACT_KEY].clone()
}

fn strings(value: &serde_json::Value) -> Vec<String> {
    value
        .as_array()
        .expect("array")
        .iter()
        .map(|entry| entry.as_str().expect("string").to_owned())
        .collect()
}

#[test]
fn the_contract_registers_this_oracle_identity() {
    assert_eq!(
        ORACLE_CONTRACT_KEY,
        format!("{ORACLE_ID}.v{ORACLE_VERSION}"),
        "the record identity and the registry key describe one version"
    );
    assert!(oracle().is_object(), "the registry key resolves");
    assert_eq!(oracle()["observer"], "cross-principal-canary");
}

#[test]
fn required_flows_match_the_frozen_order() {
    let frozen = strings(&oracle()["required_flows"]);
    let implemented: Vec<&str> = FlowId::REQUIRED.iter().map(|flow| flow.as_str()).collect();
    assert_eq!(frozen, implemented);
    assert_eq!(
        FlowId::REQUIRED,
        registry::REQUIRED_FLOWS,
        "one canonical order"
    );
}

#[test]
fn every_frozen_flow_failure_code_is_a_registered_invalid_reason() {
    let codes: Vec<&str> = InvalidReason::PRECEDENCE
        .iter()
        .map(|reason| reason.code())
        .collect();
    for flow in oracle()["flows"].as_array().expect("flows") {
        match &flow["failure_code"] {
            serde_json::Value::Null => {}
            serde_json::Value::String(code) => {
                assert!(codes.contains(&code.as_str()), "{code} is frozen");
            }
            other => panic!("unexpected failure_code {other}"),
        }
    }
}

#[test]
fn invalid_precedence_matches_the_frozen_order() {
    let frozen = strings(&oracle()["predicate"]["invalid_precedence"]);
    let implemented: Vec<&str> = InvalidReason::PRECEDENCE
        .iter()
        .map(|reason| reason.code())
        .collect();
    assert_eq!(frozen, implemented);
    for (position, reason) in InvalidReason::PRECEDENCE.iter().enumerate() {
        assert_eq!(reason.precedence(), position);
        assert_eq!(reason.reason_code().as_str(), reason.code());
    }
}

#[test]
fn the_result_domain_matches_the_frozen_domain() {
    let frozen = strings(&contract()["result_domain"]);
    let implemented: Vec<&str> = [
        Verdict::True,
        Verdict::False,
        Verdict::Invalid,
        Verdict::Error,
    ]
    .iter()
    .map(|verdict| verdict.as_str())
    .collect();
    assert_eq!(frozen, implemented);
    assert_eq!(Verdict::True.oracle_result(), OracleResult::True);
    assert_eq!(Verdict::False.oracle_result(), OracleResult::False);
    assert_eq!(Verdict::Invalid.oracle_result(), OracleResult::Invalid);
    assert_eq!(Verdict::Error.oracle_result(), OracleResult::Error);
}

#[test]
fn exposure_names_match_the_frozen_names() {
    let document = oracle();
    let exposures = document["predicate"]["exposure"]
        .as_object()
        .expect("exposure object");
    let mut names: Vec<&str> = exposures.keys().map(String::as_str).collect();
    names.sort_unstable();
    assert_eq!(
        names,
        vec!["after_owner_read", "cross_principal", "unauthenticated"]
    );
    // The two exposure values the wire contract registers.
    assert_eq!(
        serde_json::to_value(Exposure::Unauthenticated).expect("serialize"),
        serde_json::json!("unauthenticated")
    );
    assert_eq!(
        serde_json::to_value(Exposure::CrossPrincipal).expect("serialize"),
        serde_json::json!("cross_principal")
    );
}

#[test]
fn numbered_checks_match_the_frozen_inventory() {
    let document = oracle();
    let frozen = document["numbered_checks"].as_array().expect("checks");
    assert_eq!(frozen.len(), registry::NUMBERED_CHECKS.len());
    for (entry, registered) in frozen.iter().zip(registry::NUMBERED_CHECKS) {
        assert_eq!(entry["id"], registered.id);
        assert_eq!(entry["kind"], kind_name(registered.kind));
        assert!(
            !entry["killed_by"].as_array().expect("killed_by").is_empty(),
            "{} lists a killing fixture",
            registered.id
        );
    }
}

fn kind_name(kind: registry::CheckKind) -> &'static str {
    match kind {
        registry::CheckKind::Identity => "identity",
        registry::CheckKind::Correlation => "correlation",
        registry::CheckKind::Control => "control",
        registry::CheckKind::Completeness => "completeness",
        registry::CheckKind::Scope => "scope",
    }
}

#[test]
fn known_misses_match_the_frozen_list() {
    let frozen = strings(&oracle()["known_misses"]);
    assert_eq!(frozen, registry::KNOWN_MISSES);
}

#[test]
fn the_scope_boundary_matches_the_frozen_boundary() {
    let boundary = &oracle()["scope_boundary"];
    assert_eq!(
        strings(&boundary["unsupported_claim_classes"]),
        registry::UNSUPPORTED_SCOPE_NAMES
    );
    assert_eq!(boundary["dispatch_result"], registry::ORACLE_UNAVAILABLE);
    assert_eq!(boundary["dispatch_timing"], registry::DISPATCH_TIMING);
    assert_eq!(
        registry::SUPPORTED_CLAIM_CLASSES,
        [ClaimClass::PrivateObjectRead]
    );
    assert_eq!(
        registry::UNSUPPORTED_CLAIM_CLASSES,
        [ClaimClass::CollectionDisclosure, ClaimClass::Existence]
    );
}

#[test]
fn the_frozen_oracle_digest_is_pinned() {
    let digest = registry::oracle_digest();
    assert_eq!(digest.as_str().len(), 64);
    // A change to the frozen oracle entry changes this digest, which fails here
    // until the oracle implementation is revisited deliberately.
    assert_eq!(digest.as_str(), FROZEN_ORACLE_DIGEST);
}

const FROZEN_ORACLE_DIGEST: &str =
    "6204d1555ec9b69800baf6dc77cf07af01d1435a8ef2dec91f73840c581b7a39";
