//! The code registration must equal the frozen contract, field by field.

mod common;

use scourge_core::wire::{Exposure, OracleResult};
use scourge_verify::{
    ClaimClass, FlowId, InvalidReason, ORACLE_CONTRACT_KEY, ORACLE_ID, ORACLE_VERSION, Verdict,
    registry,
};

const ORACLE_GUIDE: &str = include_str!("../../../docs/oracles/web.private-object-read.v1.md");

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

fn table_rows_in_section(guide: &str, heading: &str, next_heading: &str) -> Vec<Vec<String>> {
    let start = guide
        .find(heading)
        .unwrap_or_else(|| panic!("guide contains {heading}"));
    let rest = &guide[start + heading.len()..];
    let end = rest
        .find(next_heading)
        .unwrap_or_else(|| panic!("guide section {heading} ends at {next_heading}"));
    rest[..end]
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            let row = line.strip_prefix('|')?;
            let cells = row
                .split('|')
                .map(|cell| cell.trim().trim_matches('`').to_owned())
                .filter(|cell| !cell.is_empty())
                .collect::<Vec<_>>();
            let first = cells.first()?;
            (!first.starts_with("---")
                && ![
                    "Flow",
                    "Result",
                    "Code",
                    "Check",
                    "Known miss",
                    "Admitted `readers` audience",
                    "Unsupported claim class",
                ]
                .contains(&first.as_str()))
            .then_some(cells)
        })
        .collect()
}

fn first_cells_in_section(guide: &str, heading: &str, next_heading: &str) -> Vec<String> {
    table_rows_in_section(guide, heading, next_heading)
        .into_iter()
        .map(|row| row[0].clone())
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
    let documented = table_rows_in_section(ORACLE_GUIDE, "## Flows", "## Result predicate");
    let exact = oracle()["flows"]
        .as_array()
        .expect("flows")
        .iter()
        .map(|flow| {
            vec![
                flow["id"].as_str().unwrap().to_owned(),
                flow["principal"].as_str().unwrap().to_owned(),
                flow["action"].as_str().unwrap().to_owned(),
                flow["control"].as_str().unwrap().to_owned(),
                flow["failure_code"].as_str().unwrap_or("—").to_owned(),
            ]
        })
        .collect::<Vec<_>>();
    assert_eq!(documented, exact, "guide flow table is an exact projection");
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
fn published_guide_lists_exactly_the_registered_invalid_reasons() {
    let implemented: Vec<String> = InvalidReason::PRECEDENCE
        .iter()
        .map(|reason| reason.code().to_owned())
        .collect();
    assert_eq!(
        first_cells_in_section(
            ORACLE_GUIDE,
            "## Invalid reason codes",
            "## Numbered checks"
        ),
        implemented,
        "guide reason-code table and code enumeration must stay in lockstep"
    );
    let documented = table_rows_in_section(
        ORACLE_GUIDE,
        "## Invalid reason codes",
        "## Numbered checks",
    );
    let document = oracle();
    let reasons = document["invalid_reasons"].as_object().unwrap();
    let exact = InvalidReason::PRECEDENCE
        .iter()
        .map(|reason| {
            vec![
                reason.code().to_owned(),
                reasons[reason.code()].as_str().unwrap().to_owned(),
            ]
        })
        .collect::<Vec<_>>();
    assert_eq!(documented, exact, "guide reason definitions are exact");
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
    let predicate = &oracle()["predicate"];
    assert_eq!(
        table_rows_in_section(ORACLE_GUIDE, "## Result predicate", "## Invalid reason codes"),
        vec![
            vec!["true".to_owned(), predicate["true"].as_str().unwrap().to_owned()],
            vec!["false".to_owned(), predicate["false"].as_str().unwrap().to_owned()],
            vec![
                "invalid".to_owned(),
                "the first applicable reason in the precedence table below; invalid is never converted to false".to_owned(),
            ],
            vec!["error".to_owned(), predicate["error"].as_str().unwrap().to_owned()],
        ],
        "guide result predicates are exact"
    );
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

#[test]
fn published_guide_lists_exactly_the_registered_numbered_checks() {
    let implemented: Vec<String> = registry::NUMBERED_CHECKS
        .iter()
        .map(|check| check.id.to_owned())
        .collect();
    assert_eq!(
        first_cells_in_section(ORACLE_GUIDE, "## Numbered checks", "## Policy and exposure"),
        implemented,
        "guide check table and oracle enumeration must stay in lockstep"
    );
    let documented =
        table_rows_in_section(ORACLE_GUIDE, "## Numbered checks", "## Policy and exposure");
    let exact = oracle()["numbered_checks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|check| {
            vec![
                check["id"].as_str().unwrap().to_owned(),
                check["check"].as_str().unwrap().to_owned(),
                check["killed_by"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|value| value.as_str().unwrap())
                    .collect::<Vec<_>>()
                    .join(", "),
            ]
        })
        .collect::<Vec<_>>();
    assert_eq!(documented, exact, "guide numbered checks are exact");
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
    assert_eq!(
        first_cells_in_section(
            ORACLE_GUIDE,
            "## Known misses",
            "## Development-fixture example"
        ),
        registry::KNOWN_MISSES,
        "guide known misses are the exact registered set"
    );
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
    let exact = registry::UNSUPPORTED_SCOPE_NAMES
        .iter()
        .map(|name| {
            vec![
                (*name).to_owned(),
                registry::ORACLE_UNAVAILABLE.to_owned(),
                registry::DISPATCH_TIMING.to_owned(),
            ]
        })
        .collect::<Vec<_>>();
    assert_eq!(
        table_rows_in_section(
            ORACLE_GUIDE,
            "## Scope boundary: separate claim classes",
            "## Known misses"
        ),
        exact,
        "guide unsupported classes are the exact frozen set"
    );
}

#[test]
fn published_policy_table_is_the_exact_supported_rule_matrix() {
    assert_eq!(
        table_rows_in_section(
            ORACLE_GUIDE,
            "## Policy and exposure",
            "## Scope boundary: separate claim classes"
        ),
        [
            ["owner", "Not allowed", "Not allowed"],
            [
                "group",
                "Allowed only when the principals share a declared group",
                "Not allowed",
            ],
            ["authenticated", "Allowed", "Not allowed"],
            ["public", "Allowed", "Allowed"],
        ]
        .map(|row| row.map(str::to_owned).to_vec())
        .to_vec(),
        "guide policy rows must fail drift in either direction"
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
