//! Mutation and non-vacuity witnesses.
//!
//! Each case is a "this would have failed if" guard for one fuzz target: the
//! target would silently accept everything, or run the wrong parser, and the
//! shared invariant functions in `fuzz/src/lib.rs` would keep passing. The
//! witnesses pin the exact typed outcome at the contract boundary, so a loosened
//! schema, a swapped fixture or a duplicate-key check that stopped firing fails
//! here even when no corpus entry changes.
//!
//! The first section guards the entry contract itself: an entry replaced by an
//! immediate return, or wired to another target's parsers, must fail the same
//! replay the suite runs.

use std::{fs, path::Path};

use scourge_core::{
    DeclarationIssue,
    canonical::{self, JsonError},
    engagement::EngagementDraft,
    policy::PolicyRule,
    request::NormalizedInput,
    teapot::{
        CancelAcknowledgment, ExecutableKind, MacroOutcome, NativeOutput,
        hostile::{self, ActionReply},
    },
    template::{ClaimTemplate, TemplateError},
    wire::{self, DiagnosticCode},
};
use scourge_parser_fuzz::{BODY_LIMITS, Decision, Outcome};
use scourge_verify::{ContentCoding, DecodeError, Decoding, SavedObservations, TransferCoding};
use serde_json::Value;

// One shared replay module, compiled into both test binaries; each binary
// uses a different part of it.
#[allow(dead_code)]
mod support;

const CORPUS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/corpus");

fn seed(target: &str, name: &str) -> Vec<u8> {
    fs::read(Path::new(CORPUS).join(target).join(name)).unwrap()
}

// -- The entry contract -----------------------------------------------------

#[test]
fn an_entry_that_returns_immediately_fails_the_replay() {
    // The mutation the review reproduced: return before touching a parser. The
    // replay must fail for every target, not stay green on 30 tests.
    let no_op: scourge_parser_fuzz::Entry = |_| Outcome::default();
    for (target, entry) in scourge_parser_fuzz::ENTRIES {
        assert!(
            support::replay(target, *entry).is_ok(),
            "{target} must replay its own entry cleanly"
        );
        let error = support::replay(target, no_op).unwrap_err();
        assert!(
            error.contains("the entry recorded no decision"),
            "{target}: {error}"
        );
    }
}

#[test]
fn an_entry_wired_to_another_target_fails_the_replay() {
    // A target that keeps calling a parser, but the wrong one, must fail the
    // stage contract instead of quietly checking something else.
    for (index, (target, _)) in scourge_parser_fuzz::ENTRIES.iter().enumerate() {
        let wrong =
            scourge_parser_fuzz::ENTRIES[(index + 1) % scourge_parser_fuzz::ENTRIES.len()].1;
        let error = support::replay(target, wrong)
            .expect_err("a foreign entry must not satisfy another target's contract");
        assert!(error.contains("the entry contract is"), "{target}: {error}");
    }
}

#[test]
fn the_body_matrix_covers_every_coding_combination() {
    // A shrunk matrix would silently stop exercising a coding while the trace
    // still looked complete.
    let matrix = scourge_parser_fuzz::BODY_MATRIX;
    let mut combinations = std::collections::BTreeSet::new();
    for (stage, transfer, content, json_string_body) in matrix {
        assert!(
            combinations.insert((
                format!("{transfer:?}"),
                format!("{content:?}"),
                *json_string_body
            )),
            "{stage} repeats a coding combination"
        );
    }
    assert_eq!(
        combinations.len(),
        2 * 3 * 2,
        "two transfers times three contents times both body forms"
    );
    let stages = matrix.iter().map(|(stage, ..)| *stage).collect::<Vec<_>>();
    assert_eq!(scourge_parser_fuzz::stages("body_decoder").unwrap(), stages);
}

// -- Canonical JSON ---------------------------------------------------------

#[test]
fn duplicate_members_that_last_one_wins_would_accept_are_rejected() {
    // A parser that keeps the last value accepts every one of these.
    for duplicate in [
        r#"{"a":1,"a":1}"#,
        r#"{"outer":[{"key":0,"key":1}]}"#,
        r#"{"outer":[{"key":0,"k\u0065y":1}]}"#,
        r#"{"a":[{"b":1,"b":2}]}"#,
        r#"{"outer":[{"\u00e9":1,"é":2}]}"#,
    ] {
        assert_eq!(
            canonical::parse(duplicate.as_bytes()),
            Err(JsonError::DuplicateKey),
            "{duplicate}"
        );
        // The machine envelope path applies the same guard before decoding.
        assert_eq!(
            wire::from_slice::<Value>(duplicate.as_bytes()),
            Err(JsonError::DuplicateKey),
            "{duplicate}"
        );
    }
}

#[test]
fn canonical_form_is_not_merely_valid_syntax() {
    // Valid JSON that is not stored canonically is rejected as evidence, while
    // the same document in canonical bytes is accepted.
    for non_canonical in [
        r#"{ "b":2, "a":1 }"#,
        r#"{"b":2,"a":1}"#,
        "{\"a\":1}\n",
        r#"{"a":1.50}"#,
    ] {
        assert_eq!(
            canonical::from_canonical_slice::<Value>(non_canonical.as_bytes()),
            Err(JsonError::NonCanonical),
            "{non_canonical}"
        );
    }
    let canonical = canonical::to_vec(&canonical::parse(br#"{"b":2,"a":1}"#).unwrap()).unwrap();
    assert_eq!(canonical, br#"{"a":1,"b":2}"#);
    assert!(canonical::from_canonical_slice::<Value>(&canonical).is_ok());
}

#[test]
fn integers_outside_the_evidence_range_are_rejected() {
    // The frozen range is ±(2^53−1); a parser that stores them as floats would
    // silently lose precision on a stored record.
    for unsafe_number in [
        r#"9007199254740992"#,
        r#"-9007199254740992"#,
        r#"1e60"#,
        r#"{"a":18446744073709551616}"#,
    ] {
        assert_eq!(
            canonical::parse(unsafe_number.as_bytes()),
            Err(JsonError::UnsafeNumber),
            "{unsafe_number}"
        );
    }
    assert_eq!(
        canonical::parse(b"9007199254740991").unwrap(),
        9007199254740991u64
    );
}

// -- Declarations -----------------------------------------------------------

#[test]
fn every_declaration_parser_names_a_schema_stanza() {
    let read = |name: &str| seed("declarations", name);
    for name in [
        "policy-rule-missing-audience.json",
        "policy-rule-unknown-field.json",
        "engagement-unknown-field.json",
        "engagement-duplicate.json",
        "engagement-duplicate.toml",
        "duplicate-escaped.json",
        "truncated.json",
        "bad-utf8.json",
        "manifest-missing-parent.json",
    ] {
        let bytes = read(name);
        for name in [
            EngagementDraft::parse_json(&bytes)
                .map(|_| ())
                .map_err(|error| error.stanza().to_owned()),
            EngagementDraft::parse_toml(&bytes)
                .map(|_| ())
                .map_err(|error| error.stanza().to_owned()),
            PolicyRule::parse_json(&bytes)
                .map(|_| ())
                .map_err(|error| error.stanza().to_owned()),
            ClaimTemplate::parse_json(&bytes)
                .map(|_| ())
                .map_err(|error| match error {
                    TemplateError::Declaration(error) => error.stanza().to_owned(),
                    TemplateError::Template { stanza, .. } => stanza.to_owned(),
                }),
        ]
        .into_iter()
        .filter_map(Result::err)
        {
            assert!(
                scourge_core::is_schema_stanza(&name),
                "stanza {name:?} must be schema-owned text"
            );
        }
    }
}

#[test]
fn a_stanza_never_echoes_supplied_text() {
    // A hostile member name sits exactly where the duplicate is found, so a
    // diagnostic that interpolated the key would leak it.
    let hostile = concat!(
        r#"{"property":{"evil\"key\n\t<>":{"read":"operation.x"},"#,
        r#""evil\"key\n\t<>":{"read":"operation.x"}}}"#
    );
    let error = EngagementDraft::parse_json(hostile.as_bytes()).unwrap_err();
    assert_eq!(error.issue(), DeclarationIssue::DuplicateKey);
    assert_eq!(error.stanza(), "property.*");
    assert!(
        !error.to_string().contains("evil"),
        "diagnostic echoed supplied text: {error}"
    );
}

#[test]
fn the_three_declaration_shapes_are_not_interchangeable() {
    // Each frozen document is accepted by its own parser only. This is the
    // wrong-parser witness for `scourge.engagement.v1`,
    // `scourge.policy-rule.v1` and `scourge.claim-template.v1`.
    for (name, accepted) in [
        ("engagement.json", "engagement"),
        ("engagement.toml", "engagement"),
        ("policy-rule-orders.json", "policy"),
        ("claim-template-private-object-read.json", "template"),
    ] {
        let bytes = seed("declarations", name);
        let engagement = EngagementDraft::parse_json(&bytes).is_ok()
            || EngagementDraft::parse_toml(&bytes).is_ok();
        let policy = PolicyRule::parse_json(&bytes).is_ok();
        let template = ClaimTemplate::parse_json(&bytes).is_ok();
        assert_eq!(
            (engagement, policy, template),
            (
                accepted == "engagement",
                accepted == "policy",
                accepted == "template"
            ),
            "{name}"
        );
    }
}

#[test]
fn policy_rules_require_an_audience_and_a_known_shape() {
    let missing =
        PolicyRule::parse_json(&seed("declarations", "policy-rule-missing-audience.json"))
            .unwrap_err();
    assert_eq!(
        (missing.stanza(), missing.issue()),
        ("readers/writers", DeclarationIssue::MissingAudience)
    );
    let unknown = PolicyRule::parse_json(&seed("declarations", "policy-rule-unknown-field.json"))
        .unwrap_err();
    assert_eq!(
        (unknown.stanza(), unknown.issue()),
        ("*", DeclarationIssue::InvalidShape)
    );
    // The accepted rule still parses, so the two rejections above are not a
    // parser that refuses every policy rule.
    assert!(PolicyRule::parse_json(&seed("declarations", "policy-rule-orders.json")).is_ok());
}

#[test]
fn a_claim_template_with_an_unknown_member_is_rejected() {
    // `template_extension` is identifier-shaped, so a shape-only stanza check
    // would accept a leak of exactly this key. The schema owns the extension
    // rules: an unlisted member is `*`, and the supplied key never reaches the
    // diagnostic.
    let mut value: Value = serde_json::from_slice(&seed(
        "declarations",
        "claim-template-private-object-read.json",
    ))
    .unwrap();
    value["template_extension"] = Value::Bool(true);
    let bytes = serde_json::to_vec(&value).unwrap();

    let error = ClaimTemplate::parse_json(&bytes).unwrap_err();
    let stanza = match &error {
        TemplateError::Declaration(error) => {
            assert_eq!(error.issue(), DeclarationIssue::InvalidShape);
            error.stanza()
        }
        TemplateError::Template { stanza, .. } => stanza,
    };
    assert_eq!(stanza, "*", "an unlisted member is the wildcard stanza");
    assert!(
        !error.to_string().contains("template_extension"),
        "diagnostic echoed the supplied key: {error}"
    );
    assert!(scourge_core::is_schema_stanza(stanza));
    // The scanner is what makes the wildcard requirement real: an
    // identifier-shaped leak is not schema-owned text.
    assert!(!scourge_core::is_schema_stanza("template_extension"));

    // The shared entry observes the same rejection for the same bytes.
    let entry = support::entry("declarations").unwrap();
    match support::decision(&entry(&bytes), "claim-template") {
        Decision::Rejected(error) => {
            assert!(error.starts_with("*: "), "entry recorded {error:?}");
            assert!(!error.contains("template_extension"), "{error}");
        }
        other => panic!("claim-template recorded {other:?}"),
    }
}

// -- Teapot output ----------------------------------------------------------

/// The seeded envelope each frozen output shape must accept.
const OUTPUT_SEEDS: [(NativeOutput, &str); 18] = [
    (NativeOutput::Version, "describe.json"),
    (NativeOutput::ProxyStatus, "describe-status.json"),
    (NativeOutput::SessionCheck, "check-session.json"),
    (NativeOutput::MacroDryRun, "dry-run.json"),
    // The captured `requests send` reply is a live send; it is schema-valid for
    // the dry-run spec too, which is why the two share this seed and differ
    // only at the trailing shape parser.
    (NativeOutput::SendDryRun, "send.json"),
    (NativeOutput::PassShow, "units-left.json"),
    (NativeOutput::JobsList, "list-jobs.json"),
    (NativeOutput::RulesList, "rules-list.json"),
    (NativeOutput::InterceptStatus, "intercept-status.json"),
    (NativeOutput::InterceptRules, "intercept-rules.json"),
    (NativeOutput::ScriptsList, "scripts-list.json"),
    (NativeOutput::SessionShow, "session-show.json"),
    (NativeOutput::ConfigList, "config-list.json"),
    (NativeOutput::Send, "send.json"),
    (NativeOutput::MacroRun, "macro-run.json"),
    (NativeOutput::MacroReplay, "macro-replay.json"),
    (NativeOutput::ReadFlow, "flows-show.json"),
    (NativeOutput::JobStop, "jobs-stop.json"),
];

/// The captured reply each live action parses, with the parameters it was
/// recorded with. Everything but `send.json` is separate from the passive seeds.
const ACTION_SEEDS: [(NativeOutput, &str); 5] = [
    (NativeOutput::Send, "send.json"),
    (NativeOutput::MacroRun, "macro-run.json"),
    (NativeOutput::MacroReplay, "macro-replay.json"),
    (NativeOutput::ReadFlow, "flows-show.json"),
    (NativeOutput::JobStop, "jobs-stop.json"),
];

/// Whether two shapes are parsed by the same frozen result schema, and so may
/// accept each other's capture. The trailing shape parser is what separates a
/// live action from its dry run.
fn shares_contract(a: NativeOutput, b: NativeOutput) -> bool {
    a == b
        || (is_rule_list(a) && is_rule_list(b))
        || matches!(
            (a, b),
            (NativeOutput::Send, NativeOutput::SendDryRun)
                | (NativeOutput::SendDryRun, NativeOutput::Send)
        )
        || matches!(
            (a, b),
            (NativeOutput::MacroRun, NativeOutput::MacroDryRun)
                | (NativeOutput::MacroDryRun, NativeOutput::MacroRun)
        )
}

#[test]
fn each_teapot_shape_parses_only_its_own_contract() {
    // `rules list` and `intercept rules list` share one frozen `rules` contract,
    // and each live action shares its schema with the matching dry run, so those
    // pairs accept each other's capture; nothing else overlaps. A shape wired to
    // the wrong fixture, or a schema loosened to accept any object, changes this
    // matrix.
    for (output, file) in OUTPUT_SEEDS {
        let bytes = seed("teapot_output", file);
        let value: Value = wire::from_slice(&bytes).unwrap();
        for candidate in NativeOutput::ALL {
            let expected = shares_contract(candidate, output);
            let decoded = candidate
                .decode(ExecutableKind::Native, Some(0), &bytes, b"")
                .is_ok();
            assert_eq!(decoded, expected, "{} parsing {file}", candidate.name());
            assert_eq!(
                candidate.accepts_strict(&value),
                expected,
                "{} strict-parsing {file}",
                candidate.name()
            );
        }
    }
}

fn is_rule_list(output: NativeOutput) -> bool {
    matches!(
        output,
        NativeOutput::RulesList | NativeOutput::InterceptRules
    )
}

#[test]
fn malformed_teapot_output_never_passes_any_shape() {
    for (output, _) in OUTPUT_SEEDS {
        for name in [
            "invalid-schema.json",
            "duplicate-escaped.json",
            "bad-utf8.json",
            "truncated.json",
            "depth-limit.json",
            "native-error.json",
            "wrapper-diagnostic.json",
        ] {
            let bytes = seed("teapot_output", name);
            let error = output
                .decode(ExecutableKind::Native, Some(0), &bytes, b"")
                .unwrap_err();
            assert!(
                matches!(
                    error.diagnostic().unwrap().code,
                    DiagnosticCode::InvalidNativeOutput
                        | DiagnosticCode::NativeFailure
                        | DiagnosticCode::WrongListener
                        | DiagnosticCode::TransportUnavailable
                ),
                "{} accepting {name}",
                output.name()
            );
        }
    }
}

#[test]
fn teapot_passes_require_a_zero_exit_and_a_clean_wrapper_stream() {
    for (output, file) in OUTPUT_SEEDS {
        let bytes = seed("teapot_output", file);
        output
            .decode(ExecutableKind::Native, Some(0), &bytes, b"")
            .unwrap();
        for status in [Some(1), Some(2), Some(126), None] {
            assert!(
                output
                    .decode(ExecutableKind::Native, status, &bytes, b"")
                    .is_err(),
                "{} passed exit {status:?}",
                output.name()
            );
        }
        assert!(
            output
                .decode(
                    ExecutableKind::Wrapper,
                    Some(0),
                    &bytes,
                    scourge_parser_fuzz::DIAGNOSTIC_EVENT,
                )
                .is_err(),
            "{} passed a wrapper-only failure",
            output.name()
        );
        // The same envelope forwarded by a wrapper is the same evidence.
        let forwarded = wire::to_vec(&wire::from_slice::<Value>(&bytes).unwrap()).unwrap();
        assert_eq!(
            output
                .decode(ExecutableKind::Wrapper, Some(0), &forwarded, b"")
                .unwrap()
                .envelope(),
            &wire::from_slice::<Value>(&bytes).unwrap()
        );
    }
}

// -- Oracle records ---------------------------------------------------------

#[test]
fn an_unregistered_oracle_never_produces_a_verdict() {
    let bytes = seed("oracle_observations", "false-no-exposure.json");
    for (pointer, replacement) in [
        ("/oracle/version", "2"),
        ("/oracle/id", "web.unsupported.v1"),
        ("/schema", "scourge.oracle-observations.v2"),
    ] {
        let mut value: Value = serde_json::from_slice(&bytes).unwrap();
        *value.pointer_mut(pointer).unwrap() = Value::String(replacement.to_owned());
        let observations: SavedObservations =
            canonical::from_slice(&serde_json::to_vec(&value).unwrap()).unwrap();
        let evaluation = scourge_verify::evaluate(&observations);
        assert_eq!(
            evaluation.result,
            scourge_verify::Verdict::Error,
            "{pointer}"
        );
        assert!(evaluation.fault.is_some(), "{pointer}");
        assert!(evaluation.reason_codes.is_empty(), "{pointer}");
        assert!(evaluation.exposure.is_none(), "{pointer}");
    }
}

#[test]
fn a_truncated_flow_is_incomplete_never_false() {
    let bytes = seed("oracle_observations", "false-no-exposure.json");
    let mut value: Value = serde_json::from_slice(&bytes).unwrap();
    let flows = value["flows"].as_array_mut().unwrap();
    flows.retain(|flow| flow["flow"] != "F2");
    let observations: SavedObservations =
        canonical::from_slice(&serde_json::to_vec(&value).unwrap()).unwrap();
    let evaluation = scourge_verify::evaluate(&observations);
    assert_eq!(evaluation.result, scourge_verify::Verdict::Invalid);
    assert_eq!(evaluation.reason_codes[0].as_str(), "EVIDENCE_INCOMPLETE");
}

// -- Body decoding ----------------------------------------------------------

#[test]
fn the_body_decoder_types_every_boundary() {
    let decode = |bytes: &[u8], decoding: Decoding| {
        scourge_verify::decode(bytes, decoding, BODY_LIMITS).map(|body| body.bytes)
    };
    let plain = Decoding::default();

    // Accepted codings round-trip to the same payload.
    assert_eq!(
        decode(
            &seed("body_decoder", "gzip.bin"),
            Decoding {
                transfer: TransferCoding::Identity,
                content: ContentCoding::Gzip,
                json_string_body: false,
            },
        ),
        Ok(br#"{"text":"fixture"}"#.to_vec())
    );
    // An identity body is the payload; the same bytes named gzip are not.
    assert_eq!(
        decode(&seed("body_decoder", "identity.bin"), plain),
        Ok(br#"{"text":"fixture"}"#.to_vec())
    );
    assert_eq!(
        decode(
            &seed("body_decoder", "gzip.bin"),
            Decoding {
                transfer: TransferCoding::Identity,
                content: ContentCoding::Deflate,
                json_string_body: false,
            },
        ),
        Err(DecodeError::Corrupt)
    );
    // Size boundary: one byte over the recorded bound is a typed refusal.
    assert_eq!(
        decode(&seed("body_decoder", "size-plus-one.bin"), plain),
        Err(DecodeError::OverLimit)
    );
    // Ratio boundary: a small compressed body that expands past the bound.
    assert_eq!(
        decode(
            &seed("body_decoder", "gzip-ratio.bin"),
            Decoding {
                transfer: TransferCoding::Identity,
                content: ContentCoding::Gzip,
                json_string_body: false,
            },
        ),
        Err(DecodeError::ExpansionRatio)
    );
    // Undecodable codings are typed, not panics and not silent truncation.
    for (name, transfer, content, error) in [
        (
            "gzip-truncated.bin",
            TransferCoding::Identity,
            ContentCoding::Gzip,
            DecodeError::Truncated,
        ),
        (
            "chunked-truncated.bin",
            TransferCoding::Chunked,
            ContentCoding::Identity,
            DecodeError::Truncated,
        ),
        (
            "chunked-overflow.bin",
            TransferCoding::Chunked,
            ContentCoding::Identity,
            DecodeError::Corrupt,
        ),
    ] {
        assert_eq!(
            decode(
                &seed("body_decoder", name),
                Decoding {
                    transfer,
                    content,
                    json_string_body: false,
                },
            ),
            Err(error),
            "{name}"
        );
    }
    // A JSON-string wrapper accepts exactly one string and rejects trailing
    // bytes, so a wrapper cannot smuggle an undecoded canary past the match.
    let wrapper = Decoding {
        transfer: TransferCoding::Identity,
        content: ContentCoding::Identity,
        json_string_body: true,
    };
    assert_eq!(
        decode(&seed("body_decoder", "invalid-surrogate.bin"), wrapper),
        Err(DecodeError::Corrupt)
    );
    assert_eq!(
        decode(br#""ok" trailing"#, wrapper),
        Err(DecodeError::Corrupt)
    );
    assert_eq!(decode(br#""ok""#, wrapper), Ok(b"ok".to_vec()));
}

#[test]
fn stored_requests_and_wire_envelopes_agree() {
    // The two readers of one request document must not diverge: a shape one
    // rejects is rejected by the other with the same typed error.
    for name in [
        "request-input.json",
        "request-retest.json",
        "request-zero-rounds.json",
        "request-overflow.json",
        "duplicate-escaped.json",
        "bad-utf8.json",
        "truncated.json",
        "depth-limit.json",
    ] {
        let bytes = seed("wire_contracts", name);
        let request = scourge_core::wire::RequestInputV1::read(&bytes);
        let normalized = NormalizedInput::read(&bytes);
        assert_eq!(request.as_ref().err(), normalized.as_ref().err(), "{name}");
        assert_eq!(request.is_ok(), normalized.is_ok(), "{name}");
    }
}

// -- Live action replies ----------------------------------------------------

/// The trusted parameters one action shape's capture was recorded with.
fn trusted(shape: NativeOutput) -> scourge_core::teapot::hostile::Trusted<'static> {
    scourge_parser_fuzz::action_cases()
        .into_iter()
        .find(|(_, candidate, _)| *candidate == shape)
        .map(|(_, _, trusted)| trusted)
        .unwrap_or_else(|| panic!("{} has no action parameters", shape.name()))
}

fn parsed(
    shape: NativeOutput,
    bytes: &[u8],
) -> Result<ActionReply, scourge_core::teapot::InvocationError> {
    hostile::action_reply(shape, Some(0), bytes, b"", trusted(shape))
}

fn mutate(file: &str, pointer: &str, replacement: Value) -> Vec<u8> {
    let mut document: Value = serde_json::from_slice(&seed("teapot_output", file)).unwrap();
    *document
        .pointer_mut(pointer)
        .unwrap_or_else(|| panic!("{file} has {pointer}")) = replacement;
    serde_json::to_vec(&document).unwrap()
}

#[test]
fn live_action_replies_are_typed_not_defaulted() {
    // Every live action parses its captured reply into the typed shape the
    // adapter returns. A parser replaced by a default, or wired to another
    // command's reply, cannot satisfy these fields.
    for (stage, shape, _) in scourge_parser_fuzz::action_cases() {
        let file = ACTION_SEEDS
            .iter()
            .find(|(candidate, _)| *candidate == shape)
            .unwrap()
            .1;
        let reply = parsed(shape, &seed("teapot_output", file))
            .unwrap_or_else(|error| panic!("{stage}: {error}"));
        match (shape, reply) {
            (NativeOutput::Send, ActionReply::Sent(sent)) => {
                assert_eq!(sent.flow, Some(3));
                assert_eq!(sent.hops.len(), 1);
                assert!(sent.dispatch().was_sent());
                assert_eq!(
                    sent.session.name.as_ref().map(|name| name.as_str()),
                    Some("alice")
                );
                assert_eq!(sent.status, Some(200));
                assert!(sent.relogin.is_none());
            }
            (NativeOutput::MacroRun, ActionReply::Macro(run)) => {
                assert_eq!(run.name, "plant");
                assert_eq!(run.outcome, MacroOutcome::Completed);
                assert_eq!(run.units, 2);
                assert_eq!(run.steps.len(), 2);
                assert_eq!(run.step(2).unwrap().flow, Some(5));
            }
            (NativeOutput::MacroReplay, ActionReply::Replay(receipt)) => {
                assert_eq!(receipt.replay.step, 2);
                assert_eq!(receipt.replay.steps_in_macro, 2);
                assert_eq!(receipt.replay.preparatory.len(), 1);
                assert_eq!(receipt.replay.replayed.step, 2);
                assert_eq!(receipt.status, Some(201));
                assert_eq!(receipt.replay.replaced, ["json:note"]);
            }
            (NativeOutput::ReadFlow, ActionReply::Flow(flow)) => {
                assert_eq!(flow.id, 3);
                assert_eq!(flow.origin, "replay");
                assert_eq!(flow.destination.as_deref(), Some("http://127.0.0.1:39381"));
                let body = flow.response.body.as_ref().unwrap();
                assert_eq!(body.bytes.as_deref().map(<[u8]>::len), Some(16));
                assert!(body.whole);
                assert!(!flow.head_cut);
            }
            (NativeOutput::JobStop, ActionReply::Stopped(acknowledgment)) => {
                assert_eq!(acknowledgment, CancelAcknowledgment::StopPending);
            }
            (shape, _) => panic!("{} parsed into the wrong shape", shape.name()),
        }
    }
}

#[test]
fn live_action_replies_refuse_contradictory_bytes() {
    // One case per guard the trailing shape parser applies. Each would pass a
    // schema-only check: the reply is well-formed and matches the frozen result
    // schema, but it is not the evidence the call claims.
    for (shape, file, pointer, replacement) in [
        // `requests send`: a dry run, no hop, a hop list past the follow bound,
        // an ambiguous per-send flow, a status that is not the last hop's, and a
        // session that is not the one the call bound.
        (
            NativeOutput::Send,
            "send.json",
            "/sent/dry_run",
            Value::Bool(true),
        ),
        (
            NativeOutput::Send,
            "send.json",
            "/sent/hops",
            Value::Array(vec![]),
        ),
        (
            NativeOutput::Send,
            "send.json",
            "/sent/flow",
            Value::from(4),
        ),
        (
            NativeOutput::Send,
            "send.json",
            "/sent/status",
            Value::from(201),
        ),
        (
            NativeOutput::Send,
            "send.json",
            "/sent/session/name",
            Value::from("mallory"),
        ),
        (
            NativeOutput::Send,
            "send.json",
            "/sent/hops/0/outcome",
            Value::from("unknown"),
        ),
        // `macros run`: a dry run, a step count that disagrees with `units`, a
        // planned outcome, another macro's name, and a state-change list that
        // does not match the steps.
        (
            NativeOutput::MacroRun,
            "macro-run.json",
            "/run/dry_run",
            Value::Bool(true),
        ),
        (
            NativeOutput::MacroRun,
            "macro-run.json",
            "/run/units",
            Value::from(3),
        ),
        (
            NativeOutput::MacroRun,
            "macro-run.json",
            "/run/outcome",
            Value::from("planned"),
        ),
        (
            NativeOutput::MacroRun,
            "macro-run.json",
            "/run/name",
            Value::from("other"),
        ),
        (
            NativeOutput::MacroRun,
            "macro-run.json",
            "/run/state_changing",
            Value::Array(vec![Value::from(1)]),
        ),
        // `flows replay`: a derived flow, a flow/status that is not the
        // replayed step's, the wrong step, and no preparatory step.
        (
            NativeOutput::MacroReplay,
            "macro-replay.json",
            "/flow/parent",
            Value::from(1),
        ),
        (
            NativeOutput::MacroReplay,
            "macro-replay.json",
            "/flow/id",
            Value::from(6),
        ),
        (
            NativeOutput::MacroReplay,
            "macro-replay.json",
            "/flow/macro_replay/step",
            Value::from(3),
        ),
        (
            NativeOutput::MacroReplay,
            "macro-replay.json",
            "/flow/macro_replay/preparatory",
            Value::Array(vec![]),
        ),
        // `flows show`: another row, a missing origin, a body window that
        // disagrees with the bytes, and an undecodable body.
        (
            NativeOutput::ReadFlow,
            "flows-show.json",
            "/flow/id",
            Value::from(4),
        ),
        (
            NativeOutput::ReadFlow,
            "flows-show.json",
            "/flow/state",
            Value::from(""),
        ),
        (
            NativeOutput::ReadFlow,
            "flows-show.json",
            "/flow/response_body_info/shown",
            Value::from(15),
        ),
        (
            NativeOutput::ReadFlow,
            "flows-show.json",
            "/flow/response_body_base64",
            Value::from("AAAA"),
        ),
        (
            NativeOutput::ReadFlow,
            "flows-show.json",
            "/flow/origin",
            Value::from(""),
        ),
        // `jobs stop`: another job's acknowledgment, a bounded wait that is not
        // the frozen one, an engine that was not running, no job row, two rows,
        // and a terminal state with no new stop.
        (
            NativeOutput::JobStop,
            "jobs-stop.json",
            "/stopped/jobs/0/id",
            Value::from(40),
        ),
        (
            NativeOutput::JobStop,
            "jobs-stop.json",
            "/stopped/wait_secs",
            Value::from(9),
        ),
        (
            NativeOutput::JobStop,
            "jobs-stop.json",
            "/stopped/engine_running",
            Value::Bool(false),
        ),
        (
            NativeOutput::JobStop,
            "jobs-stop.json",
            "/stopped/jobs",
            Value::Array(vec![]),
        ),
        (
            NativeOutput::JobStop,
            "jobs-stop.json",
            "/stopped/jobs/0/state",
            Value::from("completed"),
        ),
    ] {
        let bytes = mutate(file, pointer, replacement.clone());
        assert!(
            parsed(shape, &bytes).is_err(),
            "{} accepted {file} with {pointer} = {replacement}",
            shape.name()
        );
    }

    // Two rows for one stop request, and a signal or non-zero exit, are refusals
    // too. Neither can become an acknowledgment.
    let mut two_rows: Value =
        serde_json::from_slice(&seed("teapot_output", "jobs-stop.json")).unwrap();
    let row = two_rows["stopped"]["jobs"][0].clone();
    two_rows["stopped"]["jobs"] = Value::Array(vec![row.clone(), row]);
    assert!(
        parsed(
            NativeOutput::JobStop,
            &serde_json::to_vec(&two_rows).unwrap()
        )
        .is_err()
    );
    let stop = seed("teapot_output", "jobs-stop.json");
    assert!(
        hostile::action_reply(
            NativeOutput::JobStop,
            Some(1),
            &stop,
            b"",
            trusted(NativeOutput::JobStop)
        )
        .is_err()
    );
    assert!(
        hostile::action_reply(
            NativeOutput::JobStop,
            None,
            &stop,
            b"",
            trusted(NativeOutput::JobStop)
        )
        .is_err()
    );

    // A reply for another action never becomes this action's reply, even when
    // both are schema-valid: the trusted parameters and the shape must agree.
    let run = seed("teapot_output", "macro-run.json");
    assert!(
        hostile::action_reply(
            NativeOutput::Send,
            Some(0),
            &run,
            b"",
            trusted(NativeOutput::Send)
        )
        .is_err()
    );
    assert!(
        hostile::action_reply(
            NativeOutput::MacroRun,
            Some(0),
            &stop,
            b"",
            trusted(NativeOutput::MacroRun)
        )
        .is_err()
    );
}

/// The three passive replies behind the 26-stage `teapot_output` trace, proven to
/// fire on untrusted drift rather than to accept unconditionally.
#[test]
fn passive_reply_checks_fire_on_drift() {
    let (project, engine) = scourge_parser_fuzz::fixture_engine();
    let bytes = seed("teapot_output", "describe.json");
    let valid = bytes.clone();
    assert!(
        hostile::version_contract(&project, &engine, Some(0), &valid, b"").is_ok(),
        "captured describe reply satisfies the engine binding"
    );

    // Engine identity drift (project, instance, enforcement, protocol, CLI
    // routing) is a typed contract error, never a pass.
    let drift = |mutate: &mut dyn FnMut(&mut serde_json::Value)| {
        let mut value: serde_json::Value = serde_json::from_slice(&valid).unwrap();
        mutate(&mut value);
        let bytes = serde_json::to_vec(&value).unwrap();
        hostile::version_contract(&project, &engine, Some(0), &bytes, b"")
    };
    assert!(
        drift(&mut |v| {
            v["result"]["engine"]["project"] = serde_json::json!("/tmp/wrong-project");
        })
        .is_err()
    );
    assert!(
        drift(&mut |v| {
            v["result"]["engine"]["instance"] = serde_json::json!("wrong-instance-padding");
        })
        .is_err()
    );
    assert!(
        drift(&mut |v| {
            v["result"]["engine"]["enforced"] = serde_json::json!(true);
        })
        .is_err()
    );
    assert!(
        drift(&mut |v| {
            v["result"]["protocol"] = serde_json::json!(2);
        })
        .is_err()
    );
    assert!(
        drift(&mut |v| {
            v["result"]["answered_by"] = serde_json::json!("cli");
        })
        .is_err()
    );
}

/// The bounded-page and pass-ceiling reads reject a page past the limit, an
/// ambiguous ceiling or a non-array ceiling, and accept the captured replies.
#[test]
fn bounded_reply_reads_fire_on_drift() {
    let (_, _) = scourge_parser_fuzz::fixture_engine();
    let list_bytes = seed("teapot_output", "list-jobs.json");
    let list: serde_json::Value = serde_json::from_slice(&list_bytes).unwrap();

    // A captured jobs page of one row passes the limit of one.
    assert!(hostile::jobs_page(1, None, Some(0), &list_bytes, b"").is_ok());

    // A page past the limit of one is a typed contract error.
    let mut over_limit = list.clone();
    let first = over_limit["jobs"][0].clone();
    over_limit["jobs"].as_array_mut().unwrap().push(first);
    assert!(
        hostile::jobs_page(
            1,
            None,
            Some(0),
            &serde_json::to_vec(&over_limit).unwrap(),
            b""
        )
        .is_err()
    );

    // Two requests ceilings make the pass-ceiling read ambiguous.
    let pass_bytes = seed("teapot_output", "units-left.json");
    let mut ambiguous = serde_json::from_slice::<serde_json::Value>(&pass_bytes).unwrap();
    ambiguous["pass"]["ceilings"] = serde_json::json!([
        {"counter": "requests", "left": 1},
        {"counter": "requests", "left": 2}
    ]);
    assert!(
        hostile::request_units_left(Some(0), &serde_json::to_vec(&ambiguous).unwrap(), b"")
            .is_err()
    );

    // A missing ceilings field fails closed rather than passing by default.
    let mut missing = serde_json::from_slice::<serde_json::Value>(&pass_bytes).unwrap();
    missing["pass"].as_object_mut().unwrap().remove("ceilings");
    assert!(
        hostile::request_units_left(Some(0), &serde_json::to_vec(&missing).unwrap(), b"").is_err()
    );

    // The captured pass reply passes the ceiling read.
    assert!(hostile::request_units_left(Some(0), &pass_bytes, b"").is_ok());
}
