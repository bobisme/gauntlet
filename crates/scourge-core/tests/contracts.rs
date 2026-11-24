use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use scourge_core::{
    canonical::{self, CanonicalJson, JsonError, Sha256Digest},
    domain::{Experiment, Run},
    ids::{ArtifactId, LeadId, RequestKey, RunId, SessionName, VerificationId},
    wire::{
        self, AccountingV1, Checkpoint, Cleanup, DiagnosticV1, Effect, ErrorCode, OracleResult,
        PublicationIntentV1, RequestInputV1, ResponseV1, RetestMode, RunState, Timestamp,
        VerificationV1,
    },
};

const RECORD: &[u8] =
    include_bytes!("../../../fixtures/contracts/scourge-v1/verification-record.json");
const INTENT: &[u8] =
    include_bytes!("../../../fixtures/contracts/scourge-v1/publication-intent.json");
const REQUEST: &[u8] = include_bytes!("../../../fixtures/contracts/scourge-v1/request-input.json");
const RESPONSES: &[u8] = include_bytes!("../../../fixtures/contracts/scourge-v1/responses.json");
const DIAGNOSTIC: &[u8] =
    include_bytes!("../../../fixtures/contracts/scourge-v1/stderr-event.json");
const REGISTRY: &[u8] = include_bytes!("../../../docs/contracts/scourge-v1.json");

fn round_trip<T: CanonicalJson + DeserializeOwned>(bytes: &[u8]) -> T {
    let typed: T = canonical::from_slice(bytes).unwrap();
    let encoded = canonical::to_vec(&typed).unwrap();
    assert_eq!(canonical::parse(bytes), canonical::parse(&encoded));
    canonical::from_canonical_slice(&encoded).unwrap()
}

#[test]
fn frozen_contract_examples_round_trip() {
    let intent: PublicationIntentV1 = round_trip(INTENT);
    let record: VerificationV1 = round_trip(RECORD);
    let event: DiagnosticV1 = round_trip(DIAGNOSTIC);
    let request: RequestInputV1 = round_trip(REQUEST);
    let data: Value = canonical::parse(RECORD).unwrap();
    let _: AccountingV1 = round_trip(&canonical::to_vec(&data["accounting"]).unwrap());
    assert_eq!(record.result, OracleResult::Invalid);
    assert_eq!(record.effects, Effect::Observed);
    assert_eq!(record.cleanup, Cleanup::Unknown);
    assert_eq!(intent.run_id, record.run_id);
    assert_eq!(event.run_id.unwrap().as_str(), "R-4");
    assert_eq!(request.verify_arguments().unwrap().rounds, 2);

    let examples: Vec<Value> = canonical::from_slice(RESPONSES).unwrap();
    for example in examples {
        let response = canonical::to_vec(&example["response"]).unwrap();
        let typed: ResponseV1 = round_trip(&response);
        let exit = typed.error.map_or(0, |error| error.code.exit_code());
        assert_eq!(Value::from(exit), example["exit"]);
    }
}

#[test]
fn retest_fields_and_full_u64_counts_round_trip() {
    let mut data = canonical::parse(RECORD).unwrap();
    data["kind"] = json!("retest");
    data["rounds"][0]["phase"] = json!("retest_candidate");
    data["retest"] = json!({
        "mode": "paired",
        "baseline_record": "V-baseline",
        "baseline_digest": "1".repeat(64),
        "property_result": "no_violation_within_tested_scope",
        "functional_result": "preserved_within_tested_scope",
        "paired_baseline_target": data["target"],
        "intermittent_sampling": {
            "baseline_true": 2,
            "baseline_rounds": 10,
            "planned_rounds": 80,
            "completed_rounds": 80,
            "rate_lower_bound": "0.0370",
            "miss_threshold": "0.05",
            "miss_probability": "0.048"
        },
    });
    data["sequence"] = json!(u64::MAX);
    data["prev_record_digest"] = json!("0".repeat(64));
    let bytes = wire::to_vec(&data).unwrap();
    let typed: VerificationV1 = wire::from_slice(&bytes).unwrap();
    assert_eq!(wire::to_vec(&typed).unwrap(), bytes);
    assert_eq!(typed.sequence, u64::MAX);
    assert_eq!(canonical::to_vec(&typed), Err(JsonError::UnsafeNumber));
    assert_eq!(
        canonical::from_digest::<VerificationV1>(&bytes, &Sha256Digest::of(&bytes)),
        Err(JsonError::UnsafeNumber)
    );
    let sampling = typed.retest.unwrap().intermittent_sampling.unwrap();
    assert_eq!(sampling.rate_lower_bound.as_str(), "0.0370");

    let bytes = br#"{"schema":"scourge.request-input.v1","command":"retest","arguments":{"finding_id":"L-1","engagement_revision":null,"mode":"sequential","rounds":null}}"#;
    let request: RequestInputV1 = round_trip(bytes);
    assert_eq!(
        request.retest_arguments().unwrap().mode,
        RetestMode::Sequential
    );
    assert!(request.verify_arguments().is_err());
}

#[test]
fn generated_exit_table_matches_every_registry_code() {
    let registry = canonical::parse(REGISTRY).unwrap();
    for (code, expected) in registry["error_exits"].as_object().unwrap() {
        let typed: ErrorCode = serde_json::from_value(json!(code)).unwrap();
        assert_eq!(Value::from(typed.exit_code()), *expected);
    }
    assert!(canonical::from_slice::<ErrorCode>(br#""UNREGISTERED_ERROR""#).is_err());
}

#[test]
fn versions_and_nullable_fields_are_exact() {
    let mut intent = canonical::parse(INTENT).unwrap();
    for field in intent.as_object().unwrap().keys() {
        let mut missing = intent.clone();
        missing.as_object_mut().unwrap().remove(field);
        let bytes = canonical::to_vec(&missing).unwrap();
        assert_eq!(
            canonical::from_slice::<PublicationIntentV1>(&bytes),
            Err(JsonError::InvalidShape)
        );
    }
    intent["schema"] = json!("scourge.publication-intent.v2");
    let bytes = canonical::to_vec(&intent).unwrap();
    assert_eq!(
        canonical::from_slice::<PublicationIntentV1>(&bytes),
        Err(JsonError::InvalidShape)
    );

    let mut record = canonical::parse(RECORD).unwrap();
    record["rounds"][0]["flows"][0]
        .as_object_mut()
        .unwrap()
        .remove("decoder");
    let bytes = canonical::to_vec(&record).unwrap();
    assert_eq!(
        canonical::from_slice::<VerificationV1>(&bytes),
        Err(JsonError::InvalidShape)
    );

    let bytes = br#"{"engagement":"orders-api","sequence":0,"record_digest":null,"unknown":true}"#;
    assert_eq!(
        canonical::from_slice::<Checkpoint>(bytes),
        Err(JsonError::InvalidShape)
    );
}

#[test]
fn enums_and_literal_tags_require_exact_json_strings() {
    assert_eq!(
        wire::from_slice::<RunState>(br#""finalized""#),
        Ok(RunState::Finalized)
    );
    assert_eq!(
        wire::to_vec(&RunState::Finalized).unwrap(),
        br#""finalized""#
    );
    assert_eq!(
        wire::from_slice::<RunState>(br#"{"finalized":null}"#),
        Err(JsonError::InvalidShape)
    );
    assert!(serde_json::from_slice::<RunState>(br#"{"finalized":null}"#).is_err());
    assert_eq!(
        wire::from_slice::<ErrorCode>(br#"{"USAGE_ERROR":null}"#),
        Err(JsonError::InvalidShape)
    );

    let mut request = canonical::parse(REQUEST).unwrap();
    request["schema"] = json!({"scourge.request-input.v1": null});
    assert_eq!(
        RequestInputV1::read(&wire::to_vec(&request).unwrap()),
        Err(JsonError::InvalidShape)
    );

    let mut retest = json!({
        "schema": "scourge.request-input.v1",
        "command": "retest",
        "arguments": {"finding_id":"L-1","engagement_revision":null,"mode":"sequential","rounds":null}
    });
    assert!(RequestInputV1::read(&wire::to_vec(&retest).unwrap()).is_ok());
    retest["arguments"]["mode"] = json!({"sequential": null});
    assert_eq!(
        RequestInputV1::read(&wire::to_vec(&retest).unwrap()),
        Err(JsonError::InvalidShape)
    );

    for (pointer, tagged) in [
        ("/schema", json!({"scourge.verification.v1": null})),
        ("/result", json!({"true": null})),
        ("/rounds/0/result", json!({"true": null})),
        ("/accounting/schema", json!({"scourge.accounting.v1": null})),
    ] {
        let mut record = canonical::parse(RECORD).unwrap();
        *record.pointer_mut(pointer).unwrap() = tagged;
        let bytes = canonical::to_vec(&record).unwrap();
        assert_eq!(
            canonical::from_canonical_slice::<VerificationV1>(&bytes),
            Err(JsonError::InvalidShape),
            "{pointer}"
        );
    }
}

#[test]
fn named_wire_shapes_require_json_objects_at_every_depth() {
    let checkpoint = br#"{"engagement":"orders-api","record_digest":null,"sequence":0}"#;
    let checkpoint: Checkpoint = round_trip(checkpoint);
    assert_eq!(checkpoint.sequence, 0);
    assert_eq!(
        wire::from_slice::<Checkpoint>(br#"["orders-api",null,0]"#),
        Err(JsonError::InvalidShape)
    );
    assert!(serde_json::from_slice::<Checkpoint>(br#"["orders-api",null,0]"#).is_err());

    let request = canonical::parse(REQUEST).unwrap();
    let positional = json!([request["arguments"], request["command"], request["schema"]]);
    let bytes = wire::to_vec(&positional).unwrap();
    assert_eq!(RequestInputV1::read(&bytes), Err(JsonError::InvalidShape));
    let mut args_array = request;
    args_array["arguments"] = json!([null, "L-1", null, 2]);
    assert_eq!(
        RequestInputV1::read(&wire::to_vec(&args_array).unwrap()),
        Err(JsonError::InvalidShape)
    );

    let mut record = canonical::parse(RECORD).unwrap();
    let template = &record["template"];
    record["template"] = json!([template["id"], template["version"]]);
    let bytes = canonical::to_vec(&record).unwrap();
    assert_eq!(
        canonical::from_canonical_slice::<VerificationV1>(&bytes),
        Err(JsonError::InvalidShape)
    );

    let mut intent = canonical::parse(INTENT).unwrap();
    intent["expected_head"] = json!(["orders-api", null, 0]);
    let bytes = canonical::to_vec(&intent).unwrap();
    assert_eq!(
        canonical::from_canonical_slice::<PublicationIntentV1>(&bytes),
        Err(JsonError::InvalidShape)
    );
}

#[test]
fn response_extensions_preserve_data_and_cannot_shadow_a_wire_field() {
    let examples: Vec<Value> = canonical::from_slice(RESPONSES).unwrap();
    let mut example = examples[0]["response"].clone();
    example["projection"] = json!({"internal": "extension-content"});
    let mut typed: ResponseV1 = round_trip(&canonical::to_vec(&example).unwrap());
    assert_eq!(typed.extensions["projection"], example["projection"]);
    assert!(!format!("{typed:?}").contains("extension-content"));
    typed.extensions.insert("ok".into(), json!(false));
    assert_eq!(canonical::to_vec(&typed), Err(JsonError::DuplicateKey));

    example.as_object_mut().unwrap().remove("error");
    let encoded = canonical::to_vec(&example).unwrap();
    assert_eq!(
        canonical::from_slice::<ResponseV1>(&encoded),
        Err(JsonError::InvalidShape)
    );
}

#[test]
fn normalized_request_reader_uses_the_exact_command_argument_shape() {
    let mut input = canonical::parse(REQUEST).unwrap();
    input["arguments"]["rounds"] = json!(0);
    assert_eq!(
        RequestInputV1::read(&canonical::to_vec(&input).unwrap()),
        Err(JsonError::InvalidShape)
    );
    input["arguments"]["rounds"] = json!(2);
    input["arguments"]["lead_id"] = json!("R-1");
    assert_eq!(
        RequestInputV1::read(&canonical::to_vec(&input).unwrap()),
        Err(JsonError::InvalidShape)
    );

    input["command"] = json!("verify v2");
    let envelope = RequestInputV1::read(&canonical::to_vec(&input).unwrap()).unwrap();
    assert!(envelope.verify_arguments().is_err());
    assert!(envelope.retest_arguments().is_err());
}

#[test]
fn canonical_bytes_match_sorted_compact_utf8_with_array_order_intact() {
    let input = br#"{ "z": 0, "a": [{"z":true, "a":"\u00e9"}, 9007199254740991, 0.125] }"#;
    let value = canonical::parse(input).unwrap();
    let canonical = r#"{"a":[{"a":"é","z":true},9007199254740991,0.125],"z":0}"#;
    assert_eq!(canonical::to_vec(&value).unwrap(), canonical.as_bytes());
    assert_eq!(
        canonical::from_canonical_slice(input),
        Err::<Value, _>(JsonError::NonCanonical)
    );
    assert_eq!(
        canonical::from_canonical_slice(canonical.as_bytes()),
        Ok(value)
    );
    assert_eq!(
        canonical::parse(b"18446744073709551616"),
        Err(JsonError::UnsafeNumber)
    );
    assert_eq!(canonical::parse(b"null true"), Err(JsonError::Malformed));
    assert_eq!(canonical::parse(b"\"\xff\""), Err(JsonError::Malformed));
}

#[test]
fn evidence_accepts_exact_boundary_integers_and_rejects_outside_in_both_directions() {
    let safe = br#"{"counts":[-9007199254740991,9007199254740991]}"#;
    let parsed: Value = canonical::from_canonical_slice(safe).unwrap();
    assert_eq!(canonical::to_vec(&parsed).unwrap(), safe);

    // The first document is the unsafe-integer fixture in evidence/run.py.
    for unsafe_input in [
        br#"{"value":9007199254740992}"#.as_slice(),
        br#"{"counts":[{"value":-9007199254740992}]}"#,
        br#"{"counts":[{"value":9007199254740992}]}"#,
    ] {
        assert_eq!(canonical::parse(unsafe_input), Err(JsonError::UnsafeNumber));
        assert_eq!(
            canonical::from_canonical_slice::<Value>(unsafe_input),
            Err(JsonError::UnsafeNumber)
        );
        assert_eq!(
            canonical::from_digest::<Value>(unsafe_input, &Sha256Digest::of(unsafe_input)),
            Err(JsonError::UnsafeNumber)
        );
        let wire_value: Value = wire::from_slice(unsafe_input).unwrap();
        assert_eq!(canonical::to_vec(&wire_value), Err(JsonError::UnsafeNumber));
    }
    for number in [
        "9007199254740992.0",
        "-9007199254740992.0",
        "9.007199254740992e15",
    ] {
        assert_eq!(
            canonical::parse(number.as_bytes()),
            Err(JsonError::UnsafeNumber)
        );
    }

    let decimal = br#"{"counter":"9007199254740992"}"#;
    let parsed = canonical::parse(decimal).unwrap();
    assert_eq!(canonical::to_vec(&parsed).unwrap(), decimal);
}

#[test]
fn evidence_accepts_real_nested_null_and_rejects_nonfinite_tokens() {
    let intent: PublicationIntentV1 = canonical::from_slice(INTENT).unwrap();
    assert!(intent.artifact_id.is_none());
    let encoded = canonical::to_vec(&intent).unwrap();
    assert_eq!(
        canonical::parse(&encoded).unwrap().get("artifact_id"),
        Some(&Value::Null)
    );

    for nonfinite in ["NaN", "Infinity", "-Infinity", "1e999"] {
        let bytes = format!(r#"{{"nested":[null,{nonfinite}]}}"#);
        assert_eq!(
            canonical::parse(bytes.as_bytes()),
            Err(JsonError::Malformed)
        );
    }
}

#[test]
fn raw_and_canonical_digests_each_bind_their_exact_bytes() {
    let intent: PublicationIntentV1 = canonical::from_slice(INTENT).unwrap();
    let record: VerificationV1 = canonical::from_digest(RECORD, &intent.record_digest).unwrap();
    let encoded = canonical::to_vec(&record).unwrap();
    let expected_canonical = "2bf8f5b90bc55ce509023b4d12b1313735017a64ead3290f901896811d87e86c";
    assert_eq!(Sha256Digest::of(&encoded).as_str(), expected_canonical);
    assert_eq!(
        canonical::from_digest::<VerificationV1>(&encoded, &intent.record_digest),
        Err(JsonError::DigestMismatch)
    );
    assert_eq!(
        canonical::from_digest::<VerificationV1>(b"{", &intent.record_digest),
        Err(JsonError::DigestMismatch)
    );
}

#[test]
fn duplicate_members_are_rejected_before_typed_decoding() {
    for bytes in [
        br#"{"schema":"first","schema":"second"}"#.as_slice(),
        br#"{"principals":[{"session":"first","\u0073ession":"second"}]}"#,
        br#"{"limits":{"budget":{"ceiling":1,"ceiling":2}}}"#,
    ] {
        assert_eq!(canonical::parse(bytes), Err(JsonError::DuplicateKey));
    }
    let suspicious = br#"{"schema":"scourge.request-input.v1","command":"future","arguments":{"nested":{"x":1,"x":2}}}"#;
    assert_eq!(
        RequestInputV1::read(suspicious),
        Err(JsonError::DuplicateKey)
    );
}

#[test]
fn execution_identity_is_independent_of_frozen_input_bytes() {
    let sample = br#"{
        "template":{"id":"a/template","version":"1"},
        "slots":{},"principals":{},
        "oracle":{"id":"an.oracle","version":"1","digest":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"},
        "limits":{"rounds":2}
    }"#;
    let experiment: Experiment = round_trip(sample);
    let (bytes, digest) = experiment.freeze().unwrap();
    assert_eq!(experiment.freeze(), Ok((bytes, digest.clone())));
    let first = Run::declare("orders-api".parse().unwrap(), digest.clone());
    let second = Run::declare("orders-api".parse().unwrap(), digest.clone());
    assert_eq!(first.experiment_digest, digest);
    assert_eq!(first.experiment_digest, second.experiment_digest);
    assert_ne!(first.id, second.id);
    assert_ne!(first.request_key, second.request_key);
    assert_eq!(first.state, RunState::Declared);
    let decoded: Run = round_trip(&canonical::to_vec(&first).unwrap());
    assert_eq!(decoded, first);

    let mut experiment = experiment;
    experiment.limits.insert(
        "nested".parse().unwrap(),
        json!([{"max": 9_007_199_254_740_992_u64}]),
    );
    assert_eq!(experiment.freeze(), Err(JsonError::UnsafeNumber));
}

#[test]
fn owned_and_foreign_identities_remain_distinct_and_errors_hide_input() {
    assert!(LeadId::generate().as_str().starts_with("L-"));
    assert!(RunId::generate().as_str().starts_with("R-"));
    assert!(VerificationId::generate().as_str().starts_with("V-"));
    assert!(RequestKey::generate().as_str().starts_with("rk_"));
    assert!("R-1".parse::<LeadId>().is_err());
    assert!("rk_".parse::<RequestKey>().is_err());
    assert_eq!(
        "opaque:artifact/17".parse::<ArtifactId>().unwrap().as_str(),
        "opaque:artifact/17"
    );
    let session: SessionName = "a-session".parse().unwrap();
    assert_eq!(session.as_str(), "a-session");
    assert!(!format!("{session:?}").contains("a-session"));
    let error = "input-that-must-not-appear".parse::<RunId>().unwrap_err();
    assert_eq!(error.to_string(), "invalid run ID");
    assert!(
        "2024-02-29T12:00:00.000000001Z"
            .parse::<Timestamp>()
            .is_ok()
    );
    assert!("2025-02-29T12:00:00Z".parse::<Timestamp>().is_err());
    assert!(
        "2024-02-29T12:00:00.0000000001Z"
            .parse::<Timestamp>()
            .is_err()
    );
}
