//! Request-key equality is exact equality of the normalized
//! `scourge.request-input.v1` object. These tests pin every exclusion and
//! every preservation rule in the frozen cross-lane contract.

use serde_json::{Value, json};

use scourge_core::{
    canonical::{self, JsonError, Sha256Digest},
    request::{DEFAULT_RETEST_MODE, DEFAULT_VERIFY_ROUNDS, Invocation, NormalizedInput, Surface},
};

const FIXTURE: &[u8] = include_bytes!("../../../fixtures/contracts/scourge-v1/request-input.json");

fn normalize(command: &str, arguments: Value) -> NormalizedInput {
    Invocation::new(command, arguments).normalize().unwrap()
}

fn bytes(command: &str, arguments: Value) -> Vec<u8> {
    normalize(command, arguments).to_bytes().unwrap()
}

#[test]
fn the_frozen_example_is_the_normalized_verify_request() {
    let stored = NormalizedInput::read(FIXTURE).unwrap();
    let invocation = normalize("verify", json!({ "lead_id": "L-1" }));
    assert_eq!(stored, invocation);
    assert_eq!(stored.command(), "verify");
    assert_eq!(
        stored.arguments(),
        json!({
            "lead_id": "L-1",
            "lead_revision": null,
            "engagement_revision": null,
            "rounds": 2
        })
        .as_object()
        .unwrap()
    );
    assert_eq!(
        stored.digest().unwrap(),
        Sha256Digest::of(&stored.to_bytes().unwrap())
    );
}

#[test]
fn aliases_and_internal_whitespace_resolve_to_one_command_path() {
    let expected = bytes("status", json!({}));
    for alias in ["", "status", "tldr", "brief", "onboard"] {
        assert_eq!(bytes(alias, json!({})), expected, "{alias:?}");
        assert_eq!(normalize(alias, json!({})).command(), "status");
    }
    assert_eq!(bytes("   status  ", json!({})), expected);
    assert_eq!(
        normalize("run   show", json!({ "id": "R-1" })),
        normalize("run show", json!({ "id": "R-1" }))
    );
    // A semantically different command path is not an alias.
    assert_ne!(
        bytes("show", json!({"id": "R-1"})),
        bytes("list", json!({"id": "R-1"}))
    );
}

#[test]
fn stable_cli_defaults_normalize_identically_to_explicit_values() {
    assert_eq!(DEFAULT_VERIFY_ROUNDS, 2);
    assert_eq!(
        normalize("verify", json!({ "lead_id": "L-1" })),
        normalize("verify", json!({ "lead_id": "L-1", "rounds": 2 }))
    );
    assert_eq!(
        normalize("verify", json!({ "lead_id": "L-1" })),
        normalize(
            "verify",
            json!({ "lead_id": "L-1", "lead_revision": null, "engagement_revision": null, "rounds": 2 })
        )
    );
    assert_eq!(DEFAULT_RETEST_MODE, "sequential");
    assert_eq!(
        normalize("retest", json!({ "finding_id": "L-1" })),
        normalize(
            "retest",
            json!({ "finding_id": "L-1", "mode": "sequential", "rounds": null })
        )
    );
    // An explicit non-default value is a different request.
    assert_ne!(
        normalize("verify", json!({ "lead_id": "L-1" })),
        normalize("verify", json!({ "lead_id": "L-1", "rounds": 3 }))
    );
    assert_ne!(
        normalize("retest", json!({ "finding_id": "L-1" })),
        normalize("retest", json!({ "finding_id": "L-1", "mode": "paired" }))
    );
    assert_ne!(
        normalize("verify", json!({ "lead_id": "L-1" })),
        normalize("verify", json!({ "lead_id": "L-1", "lead_revision": 2 }))
    );
    assert_ne!(
        normalize("retest", json!({ "finding_id": "L-1" })),
        normalize("retest", json!({ "finding_id": "L-1", "rounds": 20 }))
    );
}

#[test]
fn json_object_member_order_is_irrelevant_at_every_depth() {
    let first = canonical::parse(
        br#"{"lead_id":"L-1","engagement_revision":null,"rounds":2,"lead_revision":null}"#,
    )
    .unwrap();
    let second = canonical::parse(
        br#"{"rounds":2,"lead_revision":null,"lead_id":"L-1","engagement_revision":null}"#,
    )
    .unwrap();
    assert_eq!(
        normalize("verify", first),
        normalize("verify", second),
        "argument member order must not change the request"
    );
    let nested_a = canonical::parse(br#"{"kind":"summary","filter":{"a":1,"b":[2,3]}}"#).unwrap();
    let nested_b = canonical::parse(br#"{"filter":{"b":[2,3],"a":1},"kind":"summary"}"#).unwrap();
    assert_eq!(normalize("report", nested_a), normalize("report", nested_b));
}

#[test]
fn array_order_and_string_contents_are_preserved() {
    assert_ne!(
        bytes("report", json!({ "ids": [1, 2] })),
        bytes("report", json!({ "ids": [2, 1] }))
    );
    assert_ne!(
        bytes("report", json!({ "ids": [{"a": 1}, {"a": 2}] })),
        bytes("report", json!({ "ids": [{"a": 2}, {"a": 1}] }))
    );
    assert_eq!(
        normalize("report", json!({ "ids": [{"a": 1, "b": 2}] })),
        normalize("report", json!({ "ids": [{"b": 2, "a": 1}] }))
    );
    assert_ne!(
        bytes("report", json!({ "kind": "summary" })),
        bytes("report", json!({ "kind": "summary " }))
    );
    assert_ne!(
        bytes("report", json!({ "kind": "Summary" })),
        bytes("report", json!({ "kind": "summary" }))
    );
    assert_ne!(
        bytes("report", json!({ "kind": "sum mary" })),
        bytes("report", json!({ "kind": "sum  mary" }))
    );
    assert_ne!(
        bytes("report", json!({ "count": 2 })),
        bytes("report", json!({ "count": "2" }))
    );
    assert_eq!(
        Invocation::new("retest", json!({ "finding_id": "L-1", "rounds": "2" })).normalize(),
        Err(JsonError::InvalidShape)
    );
}

#[test]
fn presentation_path_actor_and_key_are_outside_equality() {
    let arguments = json!({ "lead_id": "L-1", "rounds": 2 });
    let plain = Invocation::new("verify", arguments.clone());
    let decorated = Invocation {
        command: "verify".into(),
        arguments: arguments.clone(),
        surface: Surface {
            format: Some("json".parse().unwrap()),
            workspace: Some("/work/orders".parse().unwrap()),
            actor: Some("another-agent".parse().unwrap()),
        },
    };
    assert_eq!(plain.normalize().unwrap(), decorated.normalize().unwrap());
    assert!(
        !String::from_utf8(decorated.normalize().unwrap().to_bytes().unwrap())
            .unwrap()
            .contains("/work/orders")
    );

    // Presentation values are not arguments, and an argument named like one is
    // rejected rather than normalized away.
    let with_format_argument = json!({ "lead_id": "L-1", "format": "json" });
    assert_eq!(
        Invocation::new("verify", with_format_argument).normalize(),
        Err(JsonError::InvalidShape)
    );
    // The key itself is not an input, so a fresh key cannot change the object.
    let store_input = normalize("verify", arguments);
    assert_eq!(
        store_input,
        normalize("verify", json!({ "lead_id": "L-1" }))
    );
}

#[test]
fn one_typed_member_of_difference_is_enough() {
    let base = normalize("verify", json!({ "lead_id": "L-1" }));
    for other in [
        normalize("verify", json!({ "lead_id": "L-2" })),
        normalize("verify", json!({ "lead_id": "L-01" })),
        normalize("verify", json!({ "lead_id": "L-1", "rounds": 20 })),
        normalize(
            "verify",
            json!({ "lead_id": "L-1", "engagement_revision": 4 }),
        ),
        normalize("retest", json!({ "finding_id": "L-1" })),
        normalize("report", json!({ "lead_id": "L-1" })),
    ] {
        assert_ne!(base, other);
        assert_ne!(
            base.to_bytes().unwrap(),
            other.to_bytes().unwrap(),
            "{other:?}"
        );
    }
    assert_eq!(normalize("verify", json!({ "lead_id": "L-1" })), base);
}

#[test]
fn argument_shapes_are_typed_before_anything_is_compared() {
    for (command, arguments) in [
        ("verify", json!({ "lead_id": "L-1", "rounds": 0 })),
        ("verify", json!({ "lead_id": "L-1", "rounds": -1 })),
        ("verify", json!({ "rounds": 2 })),
        ("verify", json!({ "lead_id": 1 })),
        ("verify", json!({ "lead_id": "L-1", "unknown": null })),
        ("verify", json!([["L-1"]])),
        ("retest", json!({ "lead_id": "L-1" })),
        ("retest", json!({ "finding_id": "L-1", "mode": "random" })),
        (
            "retest",
            json!({ "finding_id": "L-1", "engagement_revision": "2" }),
        ),
    ] {
        assert_eq!(
            Invocation::new(command, arguments.clone()).normalize(),
            Err(JsonError::InvalidShape),
            "{command} {arguments}"
        );
    }
    // A canonical command path is not an argument shape: an unregistered
    // command keeps the base envelope, which nothing interprets.
    assert!(
        Invocation::new("future", json!({ "nested": [1, 2] }))
            .normalize()
            .is_ok()
    );
    assert_eq!(
        Invocation::new("future", json!("not an object")).normalize(),
        Err(JsonError::InvalidShape)
    );
}

#[test]
fn normalized_bytes_are_canonical_sorted_and_stable() {
    let input = normalize(
        "verify",
        json!({ "rounds": 4, "lead_id": "L-1", "engagement_revision": 3 }),
    );
    let bytes = input.to_bytes().unwrap();
    assert_eq!(
        String::from_utf8(bytes.clone()).unwrap(),
        concat!(
            r#"{"arguments":{"engagement_revision":3,"lead_id":"L-1","#,
            r#""lead_revision":null,"rounds":4},"#,
            r#""command":"verify","schema":"scourge.request-input.v1"}"#
        )
    );
    assert_eq!(input.to_bytes().unwrap(), bytes);
    assert_eq!(input.digest().unwrap(), Sha256Digest::of(&bytes));
    assert_eq!(NormalizedInput::read(&bytes).unwrap(), input);
    // A stored object is required to be canonical to be read back as a digest.
    assert_eq!(
        canonical::from_canonical_slice::<Value>(&bytes).unwrap(),
        canonical::parse(&bytes).unwrap()
    );
}

#[test]
fn only_canonical_stored_bytes_are_trusted_as_the_accepted_request() {
    let input = normalize("verify", json!({ "lead_id": "L-1" }));
    let bytes = input.to_bytes().unwrap();

    // Freshly normalized bytes are authoritative. The frozen fixture is a
    // human-formatted example, so it is readable but is not canonical bytes.
    assert_eq!(NormalizedInput::read_canonical(&bytes).unwrap(), input);
    assert_eq!(NormalizedInput::read(FIXTURE).unwrap(), input);
    assert_eq!(
        NormalizedInput::read_canonical(FIXTURE),
        Err(JsonError::NonCanonical)
    );

    // Semantically equal bytes in another member order are readable, but they
    // are not the canonical object a request key binds.
    let reordered = format!(
        r#"{{"command":"verify","schema":"scourge.request-input.v1","arguments":{}}}"#,
        r#"{"rounds":2,"lead_id":"L-1","lead_revision":null,"engagement_revision":null}"#
    )
    .into_bytes();
    assert_eq!(
        canonical::parse(&reordered).unwrap(),
        canonical::parse(&bytes).unwrap()
    );
    assert_eq!(NormalizedInput::read(&reordered).unwrap(), input);
    assert_eq!(
        NormalizedInput::read_canonical(&reordered),
        Err(JsonError::NonCanonical)
    );

    // Insignificant whitespace is equally untrusted.
    let padded = format!(" {}\n", String::from_utf8(bytes.clone()).unwrap()).into_bytes();
    assert!(NormalizedInput::read_canonical(&padded).is_err());

    // A canonical document of the wrong argument shape is still refused, so
    // canonicality alone never substitutes for typed validation.
    let wrong_shape =
        br#"{"arguments":{"lead_id":1},"command":"verify","schema":"scourge.request-input.v1"}"#;
    assert!(canonical::from_canonical_slice::<Value>(wrong_shape).is_ok());
    assert_eq!(
        NormalizedInput::read_canonical(wrong_shape),
        Err(JsonError::InvalidShape)
    );
}
